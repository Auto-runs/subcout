"""Tests for resolver wildcard filtering and resolver health-checking."""
import asyncio

from subscout.config import Config
from subscout.models import Subdomain
from subscout.resolver import Resolver


def test_wildcard_ip_filtered(fake_resolver):
    dns_map = {
        "real.example.com": (["10.0.0.9"], None),
        "junk.example.com": (["1.2.3.4"], None),
    }
    r = fake_resolver(dns_map, wildcard=({"1.2.3.4"}, set()))
    subs = [Subdomain(name="real.example.com"), Subdomain(name="junk.example.com")]
    asyncio.run(r.resolve_all(subs, {"1.2.3.4"}, set()))
    assert {s.name for s in subs if s.resolved} == {"real.example.com"}


def test_healthcheck_drops_liar():
    cfg = Config(nameservers=["1.1.1.1", "6.6.6.6", "8.8.8.8"])
    r = Resolver(cfg)

    async def fake_probe(ns):
        return ns in ("1.1.1.1", "8.8.8.8")

    r._probe_resolver = fake_probe
    kept = asyncio.run(r.validate_resolvers())
    assert kept == 2
    assert set(r._resolver.nameservers) == {"1.1.1.1", "8.8.8.8"}


def test_healthcheck_keeps_original_when_all_fail():
    cfg = Config(nameservers=["1.1.1.1", "8.8.8.8"])
    r = Resolver(cfg)

    async def fake_probe(ns):
        return False

    r._probe_resolver = fake_probe
    kept = asyncio.run(r.validate_resolvers())
    assert kept == 2
    assert set(r._resolver.nameservers) == {"1.1.1.1", "8.8.8.8"}
