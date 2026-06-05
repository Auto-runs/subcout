"""AlienVault OTX passive DNS (no key required for this endpoint)."""
from __future__ import annotations

import aiohttp

from subscout.sources.base import Source, register


@register
class AlienVaultOTX(Source):
    name = "alienvault"

    async def fetch(self, session: aiohttp.ClientSession, domain: str) -> set[str]:
        url = (
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
        )
        data = await self._get_json(session, url)
        if not data:
            return set()

        results: set[str] = set()
        for record in data.get("passive_dns", []):
            hostname = record.get("hostname")
            if hostname:
                results.add(hostname)
        return results
