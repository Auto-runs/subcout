"""Anubis-DB via jldc.me mirror (no key required)."""
from __future__ import annotations

import aiohttp

from subscout.sources.base import Source, register


@register
class Anubis(Source):
    name = "anubis"

    async def fetch(self, session: aiohttp.ClientSession, domain: str) -> set[str]:
        url = f"https://jldc.me/anubis/subdomains/{domain}"
        data = await self._get_json(session, url)
        if not isinstance(data, list):
            return set()
        return {str(item) for item in data if item}
