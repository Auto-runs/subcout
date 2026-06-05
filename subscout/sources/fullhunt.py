"""FullHunt attack-surface dataset (needs SUBSCOUT_FULLHUNT_KEY)."""
from __future__ import annotations

import aiohttp

from subscout.sources.base import Source, register


@register
class FullHunt(Source):
    name = "fullhunt"
    requires_key = True

    def enabled(self) -> bool:
        return bool(self.config.fullhunt_key)

    async def fetch(self, session: aiohttp.ClientSession, domain: str) -> set[str]:
        url = f"https://fullhunt.io/api/v1/domain/{domain}/subdomains"
        headers = {"X-API-KEY": self.config.fullhunt_key or ""}
        data = await self._get_json(session, url, headers=headers)
        if not isinstance(data, dict):
            return set()
        return {str(h) for h in data.get("hosts", []) or [] if h}
