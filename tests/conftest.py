"""Shared pytest fixtures and lightweight stubs.

subscout's only hard third-party deps are aiohttp and dnspython. They are not
needed for unit-testing the pure logic (parsing, scope, mutation, pipeline
orchestration), so we install minimal stand-ins at import time. This keeps the
suite runnable anywhere (CI included) without network or native DNS.

Tests that exercise real HTTP/DNS belong in an integration suite run manually
against authorized targets - see README.
"""
from __future__ import annotations

import sys
import types

import pytest


def _install_stubs() -> None:
    if "aiohttp" not in sys.modules:
        aiohttp = types.ModuleType("aiohttp")

        class _Session:  # replaced per-test where a real fake is needed
            def __init__(self, **kw):
                pass

            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

        aiohttp.ClientSession = _Session
        aiohttp.ClientTimeout = lambda **k: None
        aiohttp.TCPConnector = lambda **k: None
        aiohttp.ClientError = type("ClientError", (Exception,), {})
        sys.modules["aiohttp"] = aiohttp

    if "dns" not in sys.modules:
        dns = types.ModuleType("dns")
        da = types.ModuleType("dns.asyncresolver")
        dr = types.ModuleType("dns.resolver")
        drev = types.ModuleType("dns.reversename")
        da.Resolver = lambda **k: types.SimpleNamespace(
            nameservers=[], rotate=False, timeout=0, lifetime=0
        )
        for name in ("NXDOMAIN", "NoAnswer", "NoNameservers"):
            setattr(dr, name, type(name, (Exception,), {}))
        drev.from_address = lambda ip: types.SimpleNamespace(to_text=lambda: ip + ".in-addr.arpa.")
        dns.asyncresolver = da
        dns.resolver = dr
        dns.reversename = drev
        sys.modules.update({
            "dns": dns,
            "dns.asyncresolver": da,
            "dns.resolver": dr,
            "dns.reversename": drev,
        })


_install_stubs()


class FakeResolver:
    """In-memory resolver driven by a {name: (a_records, cname)} map."""

    def __init__(self, dns_map, wildcard=(set(), set())):
        self.dns_map = dns_map
        self._wildcard = wildcard

    async def detect_wildcard(self, root):
        return self._wildcard

    async def validate_resolvers(self):
        return 1

    async def resolve_all(self, subs, wildcard_ips, wildcard_cnames=None):
        wildcard_cnames = wildcard_cnames or set()
        for s in subs:
            rec = self.dns_map.get(s.name)
            if not rec:
                continue
            ips, cname = rec
            if cname and cname in wildcard_cnames:
                continue
            if wildcard_ips and not cname and ips and set(ips).issubset(wildcard_ips):
                continue
            s.resolved = True
            s.a_records = list(ips)
            s.cname = cname

    async def resolve_names(self, names, label, wildcard_ips, wildcard_cnames=None):
        from subscout.models import Subdomain
        subs = [Subdomain(name=n, sources={label}) for n in names]
        await self.resolve_all(subs, wildcard_ips, wildcard_cnames)
        return [s for s in subs if s.resolved]

    async def reverse_sweep(self, ips):
        """PTR map: reuse dns_map - any (ips, cname) whose IP matches yields the
        name as its PTR target. Driven by an optional `ptr` attribute."""
        ptr = getattr(self, "ptr", {})
        return {ip: ptr[ip] for ip in ips if ip in ptr}


@pytest.fixture
def fake_resolver():
    return FakeResolver


class FakeSource:
    """A passive source returning canned data keyed by enumerated root."""

    requires_key = False

    def __init__(self, name, data):
        self.name = name
        self.data = data

    def enabled(self):
        return True

    async def fetch(self, session, root):
        return set(self.data.get(root, set()))


@pytest.fixture
def fake_source():
    return FakeSource
