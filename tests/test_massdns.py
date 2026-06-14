"""Tests for the optional massdns accelerator."""
import asyncio
import stat

import pytest

from subscout.massdns import MassDNS, _parse_simple, find_massdns


def test_parse_simple_groups_records():
    out = _parse_simple(
        "www.example.com. A 1.2.3.4\n"
        "www.example.com. A 5.6.7.8\n"
        "blog.example.com. CNAME ghost.example.io.\n"
        "junk line without enough fields\n"
        "ns.example.com. NS something.\n"  # ignored type
    )
    assert out["www.example.com"] == (["1.2.3.4", "5.6.7.8"], None)
    assert out["blog.example.com"] == ([], "ghost.example.io")
    assert "ns.example.com" not in out  # NS is not A/CNAME -> not recorded


def test_find_massdns_missing(tmp_path):
    # A path that does not exist returns None.
    assert find_massdns(str(tmp_path / "nope")) is None


def _fake_massdns(tmp_path, body: str) -> str:
    script = tmp_path / "massdns"
    script.write_text("#!/bin/sh\ncat <<'EOF'\n" + body + "EOF\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return str(script)


def test_resolve_invokes_binary(tmp_path):
    binary = _fake_massdns(
        tmp_path,
        "www.t.com. A 1.2.3.4\napi.t.com. CNAME x.cdn.net.\n",
    )
    assert find_massdns(binary) == binary
    md = MassDNS(binary, ["1.1.1.1"])
    out = asyncio.run(md.resolve(["www.t.com", "api.t.com"]))
    assert out["www.t.com"] == (["1.2.3.4"], None)
    assert out["api.t.com"] == ([], "x.cdn.net")


def test_resolve_no_resolvers_raises(tmp_path):
    md = MassDNS(_fake_massdns(tmp_path, ""), [])
    with pytest.raises(RuntimeError):
        asyncio.run(md.resolve(["a.com"]))


def test_resolve_empty_names_is_noop(tmp_path):
    md = MassDNS(_fake_massdns(tmp_path, ""), ["1.1.1.1"])
    assert asyncio.run(md.resolve([])) == {}


def test_nonzero_exit_raises(tmp_path):
    script = tmp_path / "massdns"
    script.write_text("#!/bin/sh\nexit 3\n")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    md = MassDNS(str(script), ["1.1.1.1"])
    with pytest.raises(RuntimeError):
        asyncio.run(md.resolve(["a.com"]))
