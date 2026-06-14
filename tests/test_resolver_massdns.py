"""Tests that the resolver routes large batches through massdns when available."""
import asyncio
import stat

from subscout.config import Config
from subscout.resolver import Resolver


def _fake_massdns(tmp_path, body: str):
    script = tmp_path / "massdns"
    script.write_text("#!/bin/sh\ncat <<'EOF'\n" + body + "EOF\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return str(script)


def test_resolve_names_uses_massdns(tmp_path):
    binary = _fake_massdns(tmp_path, "www.t.com. A 1.2.3.4\napi.t.com. A 5.6.7.8\n")
    cfg = Config(use_massdns=True, massdns_path=binary, massdns_min_names=1)
    r = Resolver(cfg)
    assert r._massdns_bin == binary

    hits = asyncio.run(r.resolve_names(["www.t.com", "api.t.com"], "brute", set(), set()))
    names = {h.name: h.a_records for h in hits}
    assert names == {"www.t.com": ["1.2.3.4"], "api.t.com": ["5.6.7.8"]}


def test_massdns_wildcard_filter_applies(tmp_path):
    binary = _fake_massdns(tmp_path, "junk.t.com. A 10.0.0.1\nreal.t.com. A 1.2.3.4\n")
    cfg = Config(use_massdns=True, massdns_path=binary, massdns_min_names=1)
    r = Resolver(cfg)
    # 10.0.0.1 is a known wildcard IP -> junk.t.com must be filtered out.
    hits = asyncio.run(
        r.resolve_names(["junk.t.com", "real.t.com"], "brute", {"10.0.0.1"}, set())
    )
    assert {h.name for h in hits} == {"real.t.com"}


def test_massdns_failure_falls_back(tmp_path):
    # Binary that exits non-zero -> massdns path returns None -> python fallback,
    # which under the test stubs simply yields no hits (and must not crash).
    script = tmp_path / "massdns"
    script.write_text("#!/bin/sh\nexit 1\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    cfg = Config(use_massdns=True, massdns_path=str(script), massdns_min_names=1)
    r = Resolver(cfg)
    hits = asyncio.run(r.resolve_names(["a.t.com"], "brute", set(), set()))
    assert hits == []


def test_small_batch_skips_massdns(tmp_path):
    binary = _fake_massdns(tmp_path, "www.t.com. A 1.2.3.4\n")
    cfg = Config(use_massdns=True, massdns_path=binary, massdns_min_names=500)
    r = Resolver(cfg)
    # Below threshold -> Python path (stubbed DNS yields nothing), not massdns.
    hits = asyncio.run(r.resolve_names(["www.t.com"], "brute", set(), set()))
    assert hits == []
