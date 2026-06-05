"""Tests for the rate limiter and retry/backoff helper."""
import asyncio
import time

from subscout.ratelimit import RateLimiter, retry_request


def test_ratelimiter_unlimited_is_noop():
    rl = RateLimiter(0)
    start = time.monotonic()
    asyncio.run(_acquire_many(rl, 5))
    assert time.monotonic() - start < 0.1


async def _acquire_many(rl, n):
    for _ in range(n):
        await rl.acquire()


def test_ratelimiter_throttles():
    # rate=20/sec -> after the initial burst token, subsequent acquires wait.
    rl = RateLimiter(20)
    start = time.monotonic()
    asyncio.run(_acquire_many(rl, 4))
    elapsed = time.monotonic() - start
    # 3 throttled acquires at ~0.05s each => at least ~0.1s total (slack for CI)
    assert elapsed >= 0.1


def test_retry_succeeds_after_transient_status():
    calls = {"n": 0}

    async def func():
        calls["n"] += 1
        if calls["n"] < 3:
            return 503, None
        return 200, "ok"

    status, value = asyncio.run(retry_request(
        func, retries=3, backoff_base=0.0, label="t"))
    assert status == 200 and value == "ok"
    assert calls["n"] == 3


def test_retry_gives_up_and_returns_last_status():
    async def func():
        return 500, None

    status, value = asyncio.run(retry_request(
        func, retries=2, backoff_base=0.0, label="t"))
    assert status == 500 and value is None


def test_retry_handles_exceptions():
    async def func():
        raise RuntimeError("boom")

    status, value = asyncio.run(retry_request(
        func, retries=1, backoff_base=0.0, label="t"))
    assert status is None and value is None
