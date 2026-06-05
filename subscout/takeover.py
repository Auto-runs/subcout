"""Subdomain takeover detection.

A "takeover" happens when a subdomain has a dangling DNS record (usually a
CNAME) pointing at a third-party service that no longer hosts anything for it -
so an attacker can register that resource and serve content from the victim's
subdomain.

Detection here is heuristic and deliberately conservative (it reports
*candidates*, never a guaranteed takeover):

  1. The subdomain's CNAME points at a known service (fingerprint match), AND
  2. either the service shows its characteristic "unclaimed" response body, or
     the CNAME target does not resolve to an address (classic dangling record).

Always verify candidates manually before reporting. Fingerprint data is based
on the community "can-i-take-over-xyz" project (service patterns paraphrased).
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

import aiohttp

from subscout.config import Config
from subscout.models import Subdomain

logger = logging.getLogger("subscout")


@dataclass(frozen=True)
class Fingerprint:
    service: str
    cname_patterns: tuple[str, ...]   # substrings expected in the CNAME target
    body_signatures: tuple[str, ...]  # strings expected in the unclaimed page
    nxdomain: bool = False            # True if a dangling record simply NXDOMAINs


# Compact, high-confidence subset. Extend freely - this is just a starting set.
FINGERPRINTS: tuple[Fingerprint, ...] = (
    Fingerprint("GitHub Pages", ("github.io",),
                ("There isn't a GitHub Pages site here",)),
    Fingerprint("Amazon S3", ("amazonaws.com",),
                ("NoSuchBucket", "The specified bucket does not exist")),
    Fingerprint("Heroku", ("herokudns.com", "herokuapp.com", "herokussl.com"),
                ("No such app", "herokucdn.com/error-pages/no-such-app.html")),
    Fingerprint("Fastly", ("fastly.net",),
                ("Fastly error: unknown domain",)),
    Fingerprint("Shopify", ("myshopify.com",),
                ("Sorry, this shop is currently unavailable",)),
    Fingerprint("Surge.sh", ("surge.sh",),
                ("project not found",)),
    Fingerprint("Tumblr", ("domains.tumblr.com",),
                ("Whatever you were looking for doesn't currently exist",)),
    Fingerprint("Pantheon", ("pantheonsite.io",),
                ("The gods are wise, but do not know of the site",)),
    Fingerprint("Wordpress", ("wordpress.com",),
                ("Do you want to register",)),
    Fingerprint("Ghost", ("ghost.io",),
                ("The thing you were looking for is no longer here",)),
    Fingerprint("Netlify", ("netlify.app", "netlify.com"),
                ("Not Found - Request ID",)),
    Fingerprint("Azure", ("azurewebsites.net", "cloudapp.net", "trafficmanager.net"),
                ("404 Web Site not found",), nxdomain=True),
    Fingerprint("Bitbucket", ("bitbucket.io",),
                ("Repository not found",)),
    Fingerprint("Readthedocs", ("readthedocs.io",),
                ("unknown to Read the Docs",)),
)


def match_fingerprints(cname: str | None) -> list[Fingerprint]:
    """Return fingerprints whose CNAME pattern appears in *cname*."""
    if not cname:
        return []
    target = cname.lower().rstrip(".")
    return [
        fp for fp in FINGERPRINTS
        if any(pat in target for pat in fp.cname_patterns)
    ]


class TakeoverDetector:
    def __init__(self, config: Config) -> None:
        self.config = config
        self._sem = asyncio.Semaphore(config.http_concurrency)

    async def _check(self, session: aiohttp.ClientSession, sub: Subdomain) -> None:
        fingerprints = match_fingerprints(sub.cname)
        if not fingerprints:
            return

        # Dangling record: CNAME to a known service but no address resolves.
        if not sub.a_records and not sub.aaaa_records:
            for fp in fingerprints:
                if fp.nxdomain:
                    sub.takeover = True
                    sub.takeover_service = fp.service
                    logger.warning(
                        "possible takeover (dangling): %s -> %s [%s]",
                        sub.name, sub.cname, fp.service,
                    )
                    return

        # Otherwise fetch the page and look for the service's unclaimed signature.
        body = await self._fetch_body(session, sub.name)
        if not body:
            return
        for fp in fingerprints:
            if any(sig.lower() in body.lower() for sig in fp.body_signatures):
                sub.takeover = True
                sub.takeover_service = fp.service
                logger.warning(
                    "possible takeover: %s -> %s [%s]",
                    sub.name, sub.cname, fp.service,
                )
                return

    async def _fetch_body(self, session: aiohttp.ClientSession, host: str) -> str | None:
        for scheme in ("https", "http"):
            try:
                async with session.get(
                    f"{scheme}://{host}", allow_redirects=True, ssl=False
                ) as resp:
                    raw = await resp.content.read(64 * 1024)
                    return raw.decode("utf-8", "replace")
            except Exception as exc:  # noqa: BLE001
                logger.debug("takeover fetch %s://%s failed: %s", scheme, host, exc)
        return None

    async def check_all(self, subdomains: list[Subdomain]) -> list[Subdomain]:
        """Check resolved subdomains; return the takeover candidates found."""
        targets = [s for s in subdomains if s.cname]
        if not targets:
            return []
        logger.info("takeover: checking %d host(s) with a CNAME", len(targets))
        timeout = aiohttp.ClientTimeout(total=self.config.timeout)
        headers = {"User-Agent": self.config.user_agent}
        connector = aiohttp.TCPConnector(limit=self.config.http_concurrency, ssl=False)

        async def guarded(sub: Subdomain) -> None:
            async with self._sem:
                await self._check(session, sub)

        async with aiohttp.ClientSession(
            timeout=timeout, headers=headers, connector=connector
        ) as session:
            await asyncio.gather(*(guarded(s) for s in targets))

        return [s for s in subdomains if s.takeover]
