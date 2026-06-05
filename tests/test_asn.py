"""Tests for ASN/netblock reverse-DNS sweep."""
import asyncio

from subscout.asn import ASNSweeper, _expand_cidr
from subscout.config import Config
from subscout.models import Subdomain


def test_expand_cidr_basic():
    ips = _expand_cidr("192.0.2.0/30", max_hosts=100)
    # /30 has 2 usable hosts
    assert "192.0.2.1" in ips
    assert "192.0.2.2" in ips


def test_expand_cidr_capped():
    ips = _expand_cidr("10.0.0.0/16", max_hosts=50)
    assert len(ips) == 50


def test_expand_cidr_invalid():
    assert _expand_cidr("not-a-cidr", max_hosts=10) == []


def test_seed_ips_from_resolved_only():
    cfg = Config()
    sweeper = ASNSweeper(cfg, resolver=None)
    subs = [
        Subdomain(name="a.example.com", resolved=True, a_records=["1.1.1.1", "2.2.2.2"]),
        Subdomain(name="b.example.com", resolved=False, a_records=["3.3.3.3"]),
        Subdomain(name="c.example.com", resolved=True, a_records=["1.1.1.1"]),
    ]
    seeds = sweeper._seed_ips(subs)
    assert set(seeds) == {"1.1.1.1", "2.2.2.2"}   # dedup + only resolved


def test_run_no_seeds_returns_empty(fake_resolver):
    cfg = Config()
    sweeper = ASNSweeper(cfg, resolver=fake_resolver({}))
    out = asyncio.run(sweeper.run([], "example.com"))
    assert out == []
