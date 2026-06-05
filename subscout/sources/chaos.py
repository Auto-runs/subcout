"""ProjectDiscovery Chaos dataset (needs SUBSCOUT_CHAOS_KEY).

Chaos has very broad coverage for bug-bounty programs and returns bare labels
that we join back onto the domain.
"""
from __future__ import annotations

import aiohttp

from subscout.sources.base import Source, register


@register
class Chaos(Source):
    name = "chaos"
    requires_key = True

    def enabled(self) -> bool:
        return bool(self.config.chaos_key)

    async def fetch(self, session: aiohttp.ClientSession, domain: str) -> set[str]:
        url = f"https://dns.projectdiscovery.io/dns/{domain}/subdomains"
        headers = {"Authorization": self.config.chaos_key or ""}
        data = await self._get_json(session, url, headers=headers)
        if not isinstance(data, dict):
            return set()
        out: set[str] = set()
        for label in data.get("subdomains", []) or []:
            label = str(label).strip(".")
            if label:
                out.add(f"{label}.{domain}" if label != domain else domain)
        return out
