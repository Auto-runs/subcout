"""Active DNS brute-forcing.

Generates ``<word>.<domain>`` candidates from a wordlist and resolves them
through the shared resolver, which already handles concurrency limits and
wildcard-DNS filtering. Only names that genuinely resolve are returned.

This is "active" recon: it sends DNS queries that (indirectly) touch the
target's authoritative nameservers. Only run it against authorized targets.
"""
from __future__ import annotations

import logging

from subscout.config import Config
from subscout.models import Subdomain
from subscout.resolver import Resolver
from subscout.utils import is_valid_hostname

logger = logging.getLogger("subscout")


class BruteForcer:
    def __init__(self, config: Config, resolver: Resolver, words: list[str]) -> None:
        self.config = config
        self.resolver = resolver
        self.words = words

    def _candidates(self, domain: str) -> list[str]:
        out: list[str] = []
        for word in self.words:
            name = f"{word}.{domain}"
            if is_valid_hostname(name):
                out.append(name)
        return out

    async def run(
        self,
        domain: str,
        wildcard_ips: set[str],
        wildcard_cnames: set[str] | None = None,
    ) -> list[Subdomain]:
        candidates = self._candidates(domain)
        if not candidates:
            return []
        logger.info("brute-forcing %d candidate(s) under %s", len(candidates), domain)
        hits = await self.resolver.resolve_names(
            candidates, "bruteforce", wildcard_ips, wildcard_cnames
        )
        logger.info("brute-force: %d live host(s) under %s", len(hits), domain)
        return hits
