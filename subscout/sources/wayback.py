"""Wayback Machine CDX index - extracts hosts from archived URLs (no key)."""
from __future__ import annotations

import aiohttp

from subscout.sources.base import Source, register
from subscout.utils import extract_hosts


@register
class Wayback(Source):
    name = "wayback"

    async def fetch(self, session: aiohttp.ClientSession, domain: str) -> set[str]:
        url = (
            "https://web.archive.org/cdx/search/cdx"
            f"?url=*.{domain}/*&output=text&fl=original&collapse=urlkey&limit=50000"
        )
        text = await self._get_text(session, url)
        if not text:
            return set()
        return extract_hosts(text, domain)
