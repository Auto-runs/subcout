"""RapidDNS.io scrape (no key; HTML response parsed for hostnames)."""
from __future__ import annotations

import aiohttp

from subscout.sources.base import Source, register
from subscout.utils import extract_hosts


@register
class RapidDNS(Source):
    name = "rapiddns"

    async def fetch(self, session: aiohttp.ClientSession, domain: str) -> set[str]:
        url = f"https://rapiddns.io/subdomain/{domain}?full=1"
        text = await self._get_text(session, url)
        if not text:
            return set()
        return extract_hosts(text, domain)
