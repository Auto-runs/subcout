"""CommonCrawl URL index - mines archived URLs for hostnames (keyless).

Queries the latest known CC index collection. The endpoint streams JSON lines;
we extract host tokens from each record's URL.
"""
from __future__ import annotations

import aiohttp

from subscout.sources.base import Source, register
from subscout.utils import extract_hosts


@register
class CommonCrawl(Source):
    name = "commoncrawl"

    # A recent, stable index. Override by editing if it ages out.
    INDEX = "CC-MAIN-2024-10"

    async def fetch(self, session: aiohttp.ClientSession, domain: str) -> set[str]:
        url = (
            f"https://index.commoncrawl.org/{self.INDEX}-index"
            f"?url=*.{domain}&output=json&fl=url&limit=20000"
        )
        text = await self._get_text(session, url)
        if not text:
            return set()
        return extract_hosts(text, domain)
