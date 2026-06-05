"""Digitorus (certificatedetails.com) Certificate Transparency search - keyless."""
from __future__ import annotations

import aiohttp

from subscout.sources.base import Source, register
from subscout.utils import extract_hosts


@register
class Digitorus(Source):
    name = "digitorus"

    async def fetch(self, session: aiohttp.ClientSession, domain: str) -> set[str]:
        url = f"https://certificatedetails.com/{domain}"
        text = await self._get_text(session, url)
        if not text:
            return set()
        return extract_hosts(text, domain)
