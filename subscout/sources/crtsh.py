"""crt.sh - Certificate Transparency log search (no API key required)."""
from __future__ import annotations

import aiohttp

from subscout.sources.base import Source, register


@register
class CrtSh(Source):
    name = "crtsh"

    async def fetch(self, session: aiohttp.ClientSession, domain: str) -> set[str]:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        data = await self._get_json(session, url)
        if not data:
            return set()

        results: set[str] = set()
        for entry in data:
            # name_value can hold several newline-separated names.
            for field in ("name_value", "common_name"):
                value = entry.get(field)
                if value:
                    results.update(value.split("\n"))
        return results
