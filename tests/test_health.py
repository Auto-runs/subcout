"""Tests for source health checking."""
import asyncio

from subscout.config import Config
from subscout.health import (
    STATUS_OK,
    STATUS_SKIP,
    STATUS_UNREACHABLE,
    HealthChecker,
    HealthResult,
    format_report,
)
from subscout.sources.base import SourceProvider


class _Resp:
    def __init__(self, status):
        self.status = status

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False


class _FakeSession:
    """Minimal aiohttp-like session for reachability probes."""

    def __init__(self, status=200, raise_on_get=False):
        self.status = status
        self.raise_on_get = raise_on_get

    def get(self, url, **kw):
        if self.raise_on_get:
            raise OSError("connection refused")
        return _Resp(self.status)


class _FakeSource:
    def __init__(self, *, enabled=True, names=(), url=None, raise_fetch=False):
        self._enabled = enabled
        self._names = set(names)
        self._url = url
        self._raise = raise_fetch

    def enabled(self):
        return self._enabled

    def health_url(self, domain):
        return self._url

    async def fetch(self, session, domain):
        if self._raise:
            raise RuntimeError("boom")
        return set(self._names)


def _provider(name, source):
    return SourceProvider(name=name, requires_key=False, factory=lambda cfg: source)


def _check(source, domain="example.com", session=None):
    hc = HealthChecker(Config(timeout=2.0))
    session = session or _FakeSession()
    return asyncio.run(hc._check_one(session, _provider("s", source), domain))


def test_ok_when_names_returned():
    r = _check(_FakeSource(names={"a.example.com", "b.example.com"}))
    assert r.status == STATUS_OK
    assert r.count == 2


def test_skip_when_disabled():
    r = _check(_FakeSource(enabled=False))
    assert r.status == STATUS_SKIP


def test_unreachable_when_endpoint_fails():
    src = _FakeSource(names=set(), url="https://dead.example/api")
    r = _check(src, session=_FakeSession(raise_on_get=True))
    assert r.status == STATUS_UNREACHABLE


def test_out_of_scope_names_not_counted():
    # Names outside the probe domain are discarded by clean_candidate.
    r = _check(_FakeSource(names={"evil.com", "ok.example.com"}))
    assert r.status == STATUS_OK
    assert r.count == 1


def test_format_report_has_summary():
    results = [
        HealthResult("a", STATUS_OK, 3, 0.1, "3 name(s)"),
        HealthResult("b", STATUS_SKIP, 0, 0.0, "missing API key"),
    ]
    report = format_report(results)
    assert "2 source(s)" in report
    assert "[OK]" in report and "[SKIP]" in report
