"""VirusTotal subdomains (optional; needs SUBSCOUT_VIRUSTOTAL_KEY).

Demonstrates the key-gated source pattern: when no key is configured the
source disables itself instead of failing.
"""
from __future__ import annotations

import aiohttp

from subscout.sources.base import Source, register


@register
class VirusTotal(Source):
    name = "virustotal"
    requires_key = True

    def enabled(self) -> bool:
        return bool(self.config.virustotal_key)

    async def fetch(self, session: aiohttp.ClientSession, domain: str) -> set[str]:
        results: set[str] = set()
        headers = {"x-apikey": self.config.virustotal_key or ""}
        url = (
            f"https://www.virustotal.com/api/v3/domains/{domain}"
            "/subdomains?limit=40"
        )
        # Follow VT's cursor-based pagination, but cap it so we stay polite.
        for _ in range(25):
            data = await self._get_json(session, url, headers=headers)
            if not data:
                break
            for item in data.get("data", []):
                name = item.get("id")
                if name:
                    results.add(name)
            url = (data.get("links") or {}).get("next")
            if not url:
                break
        return results
