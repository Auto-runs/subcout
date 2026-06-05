"""RapidDNS-compatible 'same-ip' / DNS history via the keyless c99 mirror.

Queries the public DNS history JSON; extracts every in-scope host token.
"""
from __future__ import annotations

import aiohttp

from subscout.sources.base import Source, register
from subscout.utils import extract_hosts


@register
class DNSHistory(Source):
    name = "dnshistory"

    async def fetch(self, session: aiohttp.ClientSession, domain: str) -> set[str]:
        url = f"https://api.subdomain.center/?domain={domain}"
        data = await self._get_json(session, url)
        if isinstance(data, list):
            return {str(s) for s in data if s}
        # Fallback: some deployments return a text blob.
        text = await self._get_text(session, url)
        if text:
            return extract_hosts(text, domain)
        return set()
