"""Tests for engine resume / checkpoint integration."""
import asyncio
import json

from subscout.config import Config
from subscout.engine import Engine


def _run(cfg, sources, resolver, domain="example.com"):
    eng = Engine(cfg, sources=sources, resolver=resolver)
    return asyncio.run(eng.run(domain))


def test_checkpoint_is_written(tmp_path, fake_resolver, fake_source):
    path = str(tmp_path / "cp.jsonl")
    dns_map = {
        "api.example.com": (["10.0.0.1"], None),
        "dev.example.com": (["10.0.0.2"], None),
    }
    passive = {"example.com": {"api.example.com", "dev.example.com", "dead.example.com"}}
    cfg = Config(resolve=True, detect_wildcard=False, checkpoint_path=path)
    _run(cfg, [fake_source("crtsh", passive)], fake_resolver(dns_map))

    lines = [json.loads(ln) for ln in open(path).read().splitlines() if ln.strip()]
    names = {rec["name"] for rec in lines}
    # only confirmed live hosts are checkpointed
    assert names == {"api.example.com", "dev.example.com"}


def test_resume_preloads_and_does_not_reemit(tmp_path, fake_resolver, fake_source):
    path = tmp_path / "cp.jsonl"
    # Pre-seed the checkpoint with a previously-found host.
    path.write_text(json.dumps({
        "name": "old.example.com", "sources": ["crtsh"],
        "resolved": True, "a_records": ["10.0.0.9"],
    }) + "\n")

    dns_map = {"new.example.com": (["10.0.0.1"], None)}
    passive = {"example.com": {"new.example.com"}}

    seen = []
    cfg = Config(resolve=True, detect_wildcard=False, checkpoint_path=str(path))
    eng = Engine(cfg, sources=[fake_source("crtsh", passive)],
                 resolver=fake_resolver(dns_map),
                 on_discover=lambda s: seen.append(s.name))
    res = asyncio.run(eng.run("example.com"))

    names = {s.name for s in res}
    # resumed host is present in results...
    assert "old.example.com" in names
    assert "new.example.com" in names
    # ...but was NOT re-emitted (only the newly-found host streams)
    assert seen == ["new.example.com"]


def test_resume_ignores_out_of_scope_records(tmp_path, fake_resolver, fake_source):
    path = tmp_path / "cp.jsonl"
    path.write_text(json.dumps({
        "name": "host.other.com", "resolved": True, "a_records": ["1.1.1.1"],
    }) + "\n")
    cfg = Config(resolve=True, detect_wildcard=False, checkpoint_path=str(path))
    res = _run(cfg, [fake_source("crtsh", {"example.com": set()})],
               fake_resolver({}))
    assert "host.other.com" not in {s.name for s in res}
