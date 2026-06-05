"""LeakIX subdomain/host dataset (optional SUBSCOUT_LEAKIX_KEY raises limits)."""
from __future__ import annotations

import aiohttp

from subscout.sources.base import Source, register


@register
class LeakIX(Source):
    name = "leakix"

    async def fetch(self, session: aiohttp.ClientSession, domain: str) -> set[str]:
        url = f"https://leakix.net/api/subdomains/{domain}"
        headers = {"Accept": "application/json"}
        if self.config.leakix_key:
            headers["api-key"] = self.config.leakix_key
        data = await self._get_json(session, url, headers=headers)
        if not isinstance(data, list):
            return set()
        out: set[str] = set()
        for entry in data:
            if isinstance(entry, dict):
                host = entry.get("subdomain") or entry.get("fqdn")
                if host:
                    out.add(str(host))
        return out
