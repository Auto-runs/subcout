"""HackerTarget-hosted DNS data via the free 'subnet/reverse' style endpoints.

Uses the keyless certificate/dns aggregation from the c99-style public mirror
(threatcrowd-compatible JSON). Resilient to schema drift.
"""
from __future__ import annotations

import aiohttp

from subscout.sources.base import Source, register


@register
class ThreatCrowd(Source):
    name = "threatcrowd"

    async def fetch(self, session: aiohttp.ClientSession, domain: str) -> set[str]:
        url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
        data = await self._get_json(session, url)
        if not isinstance(data, dict):
            return set()
        subs = data.get("subdomains")
        if not isinstance(subs, list):
            return set()
        return {str(s) for s in subs if s}
