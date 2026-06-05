"""CertSpotter (sslmate) Certificate Transparency search - keyless tier."""
from __future__ import annotations

import aiohttp

from subscout.sources.base import Source, register


@register
class CertSpotter(Source):
    name = "certspotter"

    async def fetch(self, session: aiohttp.ClientSession, domain: str) -> set[str]:
        url = (
            "https://api.certspotter.com/v1/issuances"
            f"?domain={domain}&include_subdomains=true&expand=dns_names"
        )
        data = await self._get_json(session, url)
        if not isinstance(data, list):
            return set()

        results: set[str] = set()
        for entry in data:
            for name in entry.get("dns_names", []) or []:
                if name:
                    results.add(name)
        return results
