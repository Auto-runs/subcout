"""Async rate limiting and retry helpers shared by data sources.

`RateLimiter` is a simple token-bucket: it permits up to *rate* acquisitions per
second, smoothing bursts so we stay polite to each upstream API. A rate of 0
disables limiting (the common case for keyless endpoints we hit once or twice).

`retry_request` wraps an async HTTP call with bounded exponential backoff,
retrying only on transient conditions (configurable status codes / exceptions).
"""
from __future__ import annotations

import asyncio
import logging
import time

logger = logging.getLogger("subscout")


class RateLimiter:
    """Token-bucket limiter. ``rate`` is max permits per second (0 = unlimited)."""

    def __init__(self, rate: float) -> None:
        self.rate = max(0.0, rate)
        self._tokens = 1.0
        self._updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        if self.rate <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            # Refill proportionally to elapsed time, capped at a 1-token burst.
            self._tokens = min(1.0, self._tokens + (now - self._updated) * self.rate)
            self._updated = now
            if self._tokens < 1.0:
                wait = (1.0 - self._tokens) / self.rate
                await asyncio.sleep(wait)
                self._tokens = 0.0
                self._updated = time.monotonic()
            else:
                self._tokens -= 1.0


async def retry_request(
    func,
    *,
    retries: int = 2,
    backoff_base: float = 0.5,
    retry_statuses=(429, 500, 502, 503, 504),
    label: str = "request",
):
    """Call async *func* with bounded exponential backoff.

    *func* must be a zero-arg coroutine factory returning either a status-bearing
    result ``(status, value)`` or raising. It is retried when it raises or when
    the returned status is in *retry_statuses*. Returns the final ``(status,
    value)`` tuple (which may still be a failure after exhausting retries).
    """
    attempt = 0
    while True:
        try:
            status, value = await func()
            if status in retry_statuses and attempt < retries:
                delay = backoff_base * (2 ** attempt)
                logger.debug("%s: HTTP %s, retrying in %.1fs", label, status, delay)
                await asyncio.sleep(delay)
                attempt += 1
                continue
            return status, value
        except Exception as exc:  # noqa: BLE001 - transient network errors
            if attempt >= retries:
                logger.debug("%s: giving up after %d retries: %s", label, attempt, exc)
                return None, None
            delay = backoff_base * (2 ** attempt)
            logger.debug("%s: %s, retrying in %.1fs", label, exc, delay)
            await asyncio.sleep(delay)
            attempt += 1
