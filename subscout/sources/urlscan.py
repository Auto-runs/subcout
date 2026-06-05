"""urlscan.io search - extracts hostnames from scanned-page results (keyless)."""
from __future__ import annotations

import aiohttp

from subscout.sources.base import Source, register


@register
class UrlScan(Source):
    name = "urlscan"

    async def fetch(self, session: aiohttp.ClientSession, domain: str) -> set[str]:
        url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=10000"
        data = await self._get_json(session, url)
        if not isinstance(data, dict):
            return set()

        results: set[str] = set()
        for item in data.get("results", []):
            page = item.get("page") or {}
            for key in ("domain", "apexDomain"):
                value = page.get(key)
                if value:
                    results.add(value)
        return results
