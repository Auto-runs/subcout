"""Censys certificates search (needs SUBSCOUT_CENSYS_ID + SUBSCOUT_CENSYS_SECRET).

Searches the certificates index for the domain and harvests every name in the
certificate subject/SAN fields. Paginated via Censys cursors.
"""
from __future__ import annotations

import base64

import aiohttp

from subscout.sources.base import Source, register


@register
class Censys(Source):
    name = "censys"
    requires_key = True

    def enabled(self) -> bool:
        return bool(self.config.censys_id and self.config.censys_secret)

    def _auth_header(self) -> dict:
        raw = f"{self.config.censys_id}:{self.config.censys_secret}".encode()
        token = base64.b64encode(raw).decode()
        return {"Authorization": f"Basic {token}", "Accept": "application/json"}

    async def fetch(self, session: aiohttp.ClientSession, domain: str) -> set[str]:
        out: set[str] = set()
        headers = self._auth_header()
        cursor: str | None = None
        for _ in range(10):  # cap pagination so we stay polite
            url = (
                "https://search.censys.io/api/v2/certificates/search"
                f"?q=names:{domain}&per_page=100"
            )
            if cursor:
                url += f"&cursor={cursor}"
            data = await self._get_json(session, url, headers=headers)
            if not isinstance(data, dict):
                break
            result = data.get("result", {})
            for hit in result.get("hits", []) or []:
                for name in hit.get("names", []) or []:
                    if name:
                        out.add(str(name))
            cursor = (result.get("links") or {}).get("next")
            if not cursor:
                break
        return out
