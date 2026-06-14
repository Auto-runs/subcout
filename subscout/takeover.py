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
import json
import logging
from dataclasses import dataclass
from pathlib import Path

import aiohttp

from subscout.config import Config
from subscout.models import Subdomain

logger = logging.getLogger("subscout")

# External fingerprint catalog (based on the community "can-i-take-over-xyz"
# project, service patterns paraphrased). Editing JSON beats editing code:
# anyone can extend coverage without touching Python.
DATA_FILE = Path(__file__).with_name("data") / "takeover_fingerprints.json"


@dataclass(frozen=True)
class Fingerprint:
    service: str
    cname_patterns: tuple[str, ...]   # substrings expected in the CNAME target
    body_signatures: tuple[str, ...]  # strings expected in the unclaimed page
    nxdomain: bool = False            # True if a dangling record simply NXDOMAINs


# Minimal high-confidence fallback used only if the JSON catalog is missing or
# unreadable, so detection never silently turns into a no-op.
_FALLBACK: tuple[Fingerprint, ...] = (
    Fingerprint("GitHub Pages", ("github.io",),
                ("There isn't a GitHub Pages site here",)),
    Fingerprint("Amazon S3", ("amazonaws.com",),
                ("NoSuchBucket", "The specified bucket does not exist")),
    Fingerprint("Heroku", ("herokudns.com", "herokuapp.com", "herokussl.com"),
                ("No such app", "herokucdn.com/error-pages/no-such-app.html")),
    Fingerprint("Microsoft Azure",
                ("azurewebsites.net", "cloudapp.net", "trafficmanager.net"),
                ("404 Web Site not found",), nxdomain=True),
)


def _load_fingerprints(path: Path = DATA_FILE) -> tuple[Fingerprint, ...]:
    """Load fingerprints from the JSON catalog; fall back on any error."""
    try:
        specs = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        logger.warning("takeover: could not load %s (%s); using fallback set", path, exc)
        return _FALLBACK

    out: list[Fingerprint] = []
    for spec in specs:
        service = (spec.get("service") or "").strip()
        cnames = tuple(c.lower() for c in spec.get("cname", []) if c)
        if not service or not cnames:
            continue
        out.append(Fingerprint(
            service=service,
            cname_patterns=cnames,
            body_signatures=tuple(spec.get("fingerprint", []) or ()),
            nxdomain=bool(spec.get("nxdomain", False)),
        ))
    if not out:
        logger.warning("takeover: empty catalog at %s; using fallback set", path)
        return _FALLBACK
    logger.debug("takeover: loaded %d fingerprint(s)", len(out))
    return tuple(out)


# Loaded once at import time.
FINGERPRINTS: tuple[Fingerprint, ...] = _load_fingerprints()


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
