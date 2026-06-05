"""BufferOver.run TLS/DNS dataset.

The free endpoint is rate-limited; an API key (SUBSCOUT_BUFFEROVER_KEY) raises
limits. Records look like "<ip>,<hostname>" so we take the hostname side.
"""
from __future__ import annotations

import aiohttp

from subscout.sources.base import Source, register


@register
class BufferOver(Source):
    name = "bufferover"

    def _headers(self) -> dict:
        key = self.config.bufferover_key
        return {"x-api-key": key} if key else {}

    @staticmethod
    def _collect(data, out: set[str]) -> None:
        if not isinstance(data, dict):
            return
        for key in ("FDNS_A", "RDNS", "FDNS_CNAME"):
            for row in data.get(key) or []:
                # rows are "<value>,<hostname>" or plain hostname
                host = str(row).split(",")[-1].strip()
                if host:
                    out.add(host)

    async def fetch(self, session: aiohttp.ClientSession, domain: str) -> set[str]:
        out: set[str] = set()
        for url in (
            f"https://tls.bufferover.run/dns?q=.{domain}",
            f"https://dns.bufferover.run/dns?q=.{domain}",
        ):
            data = await self._get_json(session, url, headers=self._headers())
            self._collect(data, out)
        return out
