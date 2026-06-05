"""End-to-end engine pipeline tests (offline, fake resolver + sources)."""
import asyncio

from subscout.config import Config
from subscout.engine import Engine


def _run(cfg, sources, resolver, domain="example.com"):
    eng = Engine(cfg, sources=sources, resolver=resolver)
    return asyncio.run(eng.run(domain))


def test_full_pipeline_scope_brute_permute_recursion(fake_resolver, fake_source):
    dns_map = {
        "api.example.com": (["10.0.0.1"], None),
        "dev.example.com": (["10.0.0.2"], None),
        "shop.example.com": (["10.0.0.3"], None),
        "admin.example.com": (["10.0.0.4"], None),        # brute only
        "shop-dev.example.com": (["10.0.0.5"], None),     # permutation only
        "internal.api.example.com": (["10.0.0.6"], None),  # recursion only
    }
    crt = {
        "example.com": {"api.example.com", "shop.example.com", "evil.com"},
        "api.example.com": {"internal.api.example.com"},
    }
    us = {"example.com": {"dev.example.com"}}
    cfg = Config(resolve=True, bruteforce=True, permutations=True, recursive=True,
                 recursion_depth=1, detect_wildcard=False)
    res = _run(cfg, [fake_source("crtsh", crt), fake_source("urlscan", us)],
               fake_resolver(dns_map))
    names = {s.name for s in res}

    assert "evil.com" not in names                       # scope guard
    assert {"api.example.com", "dev.example.com"} <= names  # passive
    assert "admin.example.com" in names                  # brute-force
    assert "shop-dev.example.com" in names               # permutation
    assert "internal.api.example.com" in names           # recursion

    by = {s.name: s.sources for s in res}
    assert "bruteforce" in by["admin.example.com"]
    assert "permutation" in by["shop-dev.example.com"]


def test_iterative_mutation_finds_derived_compound(fake_resolver, fake_source):
    # passive yields 'edge' + 'api'; only the derived feedback loop builds
    # 'edge-api', which no static wordlist contains as a compound.
    dns_map = {
        "api.example.com": (["10.0.0.1"], None),
        "edge.example.com": (["10.0.0.2"], None),
        "edge-api.example.com": (["10.0.0.3"], None),
        "api-edge.example.com": (["10.0.0.4"], None),
    }
    passive = {"example.com": {"api.example.com", "edge.example.com"}}
    cfg = Config(resolve=True, permutations=True, bruteforce=False,
                 detect_wildcard=False, derive_wordlist=True, mutation_rounds=3,
                 include_default_wordlist=False)
    res = _run(cfg, [fake_source("crtsh", passive)], fake_resolver(dns_map))
    names = {s.name for s in res}
    assert "edge-api.example.com" in names or "api-edge.example.com" in names


def test_only_resolved_filter(fake_resolver, fake_source):
    dns_map = {"live.example.com": (["10.0.0.1"], None)}
    passive = {"example.com": {"live.example.com", "dead.example.com"}}
    cfg = Config(resolve=True, only_resolved=True, detect_wildcard=False)
    res = _run(cfg, [fake_source("crtsh", passive)], fake_resolver(dns_map))
    names = {s.name for s in res}
    assert names == {"live.example.com"}
