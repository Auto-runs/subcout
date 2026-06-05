"""Lightweight asynchronous HTTP prober.

For each resolved subdomain we try HTTPS first, then HTTP, and record the
status code, final URL, page title, and Server header. This is deliberately
minimal - it identifies live web hosts without hammering them.
"""
from __future__ import annotations

import asyncio
import logging
import re

import aiohttp

from subscout.config import Config
from subscout.fingerprint import fingerprint
from subscout.models import Subdomain

logger = logging.getLogger("subscout")

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_TITLE_MAX = 300
_BODY_READ_LIMIT = 64 * 1024  # only read enough bytes to find a <title>


def _extract_title(html: str) -> str | None:
    match = _TITLE_RE.search(html)
    if not match:
        return None
    title = re.sub(r"\s+", " ", match.group(1)).strip()
    return title[:_TITLE_MAX] or None


class Prober:
    def __init__(self, config: Config) -> None:
        self.config = config
        self._sem = asyncio.Semaphore(config.http_concurrency)

    async def _probe_url(
        self, session: aiohttp.ClientSession, url: str, sub: Subdomain
    ) -> bool:
        try:
            async with session.get(url, allow_redirects=True, ssl=False) as resp:
                sub.http_status = resp.status
                sub.http_url = str(resp.url)
                sub.server = resp.headers.get("Server")
                length = resp.headers.get("Content-Length")
                sub.content_length = int(length) if length and length.isdigit() else None

                body = ""
                ctype = resp.headers.get("Content-Type", "")
                if "html" in ctype.lower():
                    raw = await resp.content.read(_BODY_READ_LIMIT)
                    body = raw.decode("utf-8", "replace")
                    sub.title = _extract_title(body)

                # Fingerprint CDN/WAF/tech from headers (+ body when we have it).
                sub.cdn, sub.technologies = fingerprint(dict(resp.headers), body)
                return True
        except Exception as exc:  # noqa: BLE001 - one dead host must not stop us
            logger.debug("probe %s failed: %s", url, exc)
            return False

    async def _probe_one(self, session: aiohttp.ClientSession, sub: Subdomain) -> None:
        async with self._sem:
            for scheme in ("https", "http"):
                if await self._probe_url(session, f"{scheme}://{sub.name}", sub):
                    return

    async def probe_all(self, subdomains: list[Subdomain]) -> None:
        """HTTP-probe every (resolved) subdomain in place, concurrently."""
        timeout = aiohttp.ClientTimeout(total=self.config.timeout)
        headers = {"User-Agent": self.config.user_agent}
        connector = aiohttp.TCPConnector(limit=self.config.http_concurrency, ssl=False)
        async with aiohttp.ClientSession(
            timeout=timeout, headers=headers, connector=connector
        ) as session:
            await asyncio.gather(*(self._probe_one(session, s) for s in subdomains))
