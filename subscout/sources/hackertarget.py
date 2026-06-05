"""HackerTarget hostsearch API (free tier, no key; rate limited)."""
from __future__ import annotations

import aiohttp

from subscout.sources.base import Source, register


@register
class HackerTarget(Source):
    name = "hackertarget"

    async def fetch(self, session: aiohttp.ClientSession, domain: str) -> set[str]:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        text = await self._get_text(session, url)
        if not text or "API count exceeded" in text or "error" in text.lower():
            return set()

        results: set[str] = set()
        for line in text.splitlines():
            host = line.split(",", 1)[0].strip()
            if host:
                results.add(host)
        return results
