"""Source health checking.

Passive-source catalogs rot over time: providers shut down, change endpoints,
or start requiring keys. ``--health-check-sources`` probes every source so you
know which ones are actually pulling their weight before you rely on them.

Two signals are combined per source:

  * **reachability** - a direct request to the source's endpoint (for sources
    that expose one), classifying the host as reachable / unreachable.
  * **data** - the number of in-scope names the source returns for a known
    high-signal probe domain.

Status is deliberately honest: a reachable source that returns nothing is
reported as ``no-data`` (it may be dead, or simply have no records for the
probe domain) rather than falsely flagged ``dead``.
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass

import aiohttp

from subscout.config import Config
from subscout.sources.base import SourceProvider
from subscout.utils import clean_candidate

logger = logging.getLogger("subscout")

# Status values, ordered worst-to-best for sorting/reporting.
STATUS_SKIP = "skip"            # disabled (missing API key)
STATUS_UNREACHABLE = "dead"     # endpoint did not respond
STATUS_ERROR = "error"          # raised while fetching
STATUS_NO_DATA = "no-data"      # reachable but returned nothing for probe domain
STATUS_OK = "ok"                # returned in-scope names


@dataclass
class HealthResult:
    name: str
    status: str
    count: int
    elapsed: float
    detail: str = ""

    @property
    def symbol(self) -> str:
        return {
            STATUS_OK: "[OK]  ",
            STATUS_NO_DATA: "[--]  ",
            STATUS_UNREACHABLE: "[DEAD]",
            STATUS_ERROR: "[ERR] ",
            STATUS_SKIP: "[SKIP]",
        }.get(self.status, "[?]   ")


class HealthChecker:
    def __init__(self, config: Config) -> None:
        self.config = config

    async def _probe_reachable(
        self, session: aiohttp.ClientSession, url: str
    ) -> bool | None:
        """Return True/False reachability, or None if we couldn't decide."""
        try:
            async with session.get(url, allow_redirects=True, ssl=False) as resp:
                # Any HTTP response (even 4xx/5xx) means the endpoint is alive.
                return resp.status < 600
        except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
            return False
        except Exception:  # noqa: BLE001
            return None

    async def _check_one(
        self,
        session: aiohttp.ClientSession,
        provider: SourceProvider,
        domain: str,
    ) -> HealthResult:
        source = provider.create(self.config)
        if not source.enabled():
            return HealthResult(provider.name, STATUS_SKIP, 0, 0.0, "missing API key")

        start = time.monotonic()
        reachable: bool | None = None
        url = source.health_url(domain)
        if url:
            reachable = await self._probe_reachable(session, url)

        count = 0
        errored = False
        try:
            raw = await asyncio.wait_for(
                source.fetch(session, domain), timeout=self.config.timeout
            )
            count = sum(1 for r in raw if clean_candidate(r, domain))
        except (asyncio.TimeoutError, aiohttp.ClientError):
            errored = True
        except Exception as exc:  # noqa: BLE001
            errored = True
            logger.debug("health: %s raised %s", provider.name, exc)

        elapsed = time.monotonic() - start

        if count > 0:
            return HealthResult(provider.name, STATUS_OK, count, elapsed,
                                f"{count} name(s)")
        if reachable is False:
            return HealthResult(provider.name, STATUS_UNREACHABLE, 0, elapsed,
                                "endpoint unreachable")
        if errored:
            return HealthResult(provider.name, STATUS_ERROR, 0, elapsed,
                                "fetch error")
        return HealthResult(provider.name, STATUS_NO_DATA, 0, elapsed,
                            "reachable, no data")

    async def check(
        self, providers: list[SourceProvider], domain: str
    ) -> list[HealthResult]:
        timeout = aiohttp.ClientTimeout(total=self.config.timeout)
        headers = {"User-Agent": self.config.user_agent}
        sem = asyncio.Semaphore(self.config.source_concurrency)

        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
            async def guarded(p: SourceProvider) -> HealthResult:
                async with sem:
                    return await self._check_one(session, p, domain)

            results = await asyncio.gather(*(guarded(p) for p in providers))

        return sorted(results, key=lambda r: (r.status != STATUS_OK, r.name))


def format_report(results: list[HealthResult]) -> str:
    """Render a human-readable health report."""
    lines = []
    for r in results:
        lines.append(f"{r.symbol} {r.name:<24} {r.elapsed:6.2f}s  {r.detail}")
    counts: dict[str, int] = {}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1
    summary = ", ".join(f"{counts[k]} {k}" for k in sorted(counts))
    lines.append("")
    lines.append(f"{len(results)} source(s): {summary}")
    return "\n".join(lines)
