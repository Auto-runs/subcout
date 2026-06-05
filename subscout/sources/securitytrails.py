"""SecurityTrails subdomains (needs SUBSCOUT_SECURITYTRAILS_KEY).

Returns bare labels for a domain; we join them back onto the apex.
"""
from __future__ import annotations

import aiohttp

from subscout.sources.base import Source, register


@register
class SecurityTrails(Source):
    name = "securitytrails"
    requires_key = True

    def enabled(self) -> bool:
        return bool(self.config.securitytrails_key)

    async def fetch(self, session: aiohttp.ClientSession, domain: str) -> set[str]:
        url = (
            f"https://api.securitytrails.com/v1/domain/{domain}"
            "/subdomains?children_only=false"
        )
        headers = {"APIKEY": self.config.securitytrails_key or ""}
        data = await self._get_json(session, url, headers=headers)
        if not isinstance(data, dict):
            return set()
        out: set[str] = set()
        for label in data.get("subdomains", []) or []:
            label = str(label).strip(".")
            if label:
                out.add(f"{label}.{domain}")
        return out
