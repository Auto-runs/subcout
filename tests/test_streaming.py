"""Tests for the streaming discovery callback."""
import asyncio

from subscout.config import Config
from subscout.engine import Engine


def test_on_discover_fires_once_per_live_name(fake_resolver, fake_source):
    dns_map = {
        "api.example.com": (["10.0.0.1"], None),
        "dev.example.com": (["10.0.0.2"], None),
    }
    passive = {"example.com": {"api.example.com", "dev.example.com", "dead.example.com"}}

    seen = []

    def on_discover(sub):
        seen.append(sub.name)

    cfg = Config(resolve=True, detect_wildcard=False)
    eng = Engine(cfg, sources=[fake_source("crtsh", passive)],
                 resolver=fake_resolver(dns_map), on_discover=on_discover)
    asyncio.run(eng.run("example.com"))

    # only resolved names are streamed, each exactly once
    assert sorted(seen) == ["api.example.com", "dev.example.com"]
    assert len(seen) == len(set(seen))


def test_no_callback_is_fine(fake_resolver, fake_source):
    dns_map = {"api.example.com": (["10.0.0.1"], None)}
    passive = {"example.com": {"api.example.com"}}
    cfg = Config(resolve=True, detect_wildcard=False)
    eng = Engine(cfg, sources=[fake_source("crtsh", passive)],
                 resolver=fake_resolver(dns_map))
    res = asyncio.run(eng.run("example.com"))
    assert {s.name for s in res} == {"api.example.com"}
