"""Tests for resume / checkpointing."""
from subscout.checkpoint import Checkpoint
from subscout.models import Subdomain


def _sub(name, **kw):
    s = Subdomain(name=name, sources=set(kw.get("sources", {"crtsh"})))
    s.resolved = kw.get("resolved", True)
    s.a_records = kw.get("a_records", ["1.2.3.4"])
    s.cname = kw.get("cname")
    return s


def test_append_then_load_roundtrip(tmp_path):
    path = str(tmp_path / "cp.jsonl")
    cp = Checkpoint(path)
    cp.append(_sub("a.example.com"))
    cp.append(_sub("b.example.com", a_records=["9.9.9.9"], cname="x.cdn.net"))
    cp.close()

    loaded = Checkpoint(path).load()
    assert set(loaded) == {"a.example.com", "b.example.com"}
    assert loaded["a.example.com"].resolved is True
    assert loaded["a.example.com"].a_records == ["1.2.3.4"]
    assert loaded["b.example.com"].cname == "x.cdn.net"
    assert "crtsh" in loaded["a.example.com"].sources


def test_load_missing_file_is_empty(tmp_path):
    assert Checkpoint(str(tmp_path / "nope.jsonl")).load() == {}


def test_load_skips_corrupt_lines(tmp_path):
    path = tmp_path / "cp.jsonl"
    path.write_text(
        '{"name": "ok.example.com", "resolved": true}\n'
        "not json at all\n"
        '{"no_name": 1}\n'
    )
    loaded = Checkpoint(str(path)).load()
    assert set(loaded) == {"ok.example.com"}


def test_last_record_wins(tmp_path):
    path = tmp_path / "cp.jsonl"
    path.write_text(
        '{"name": "a.example.com", "a_records": ["1.1.1.1"]}\n'
        '{"name": "a.example.com", "a_records": ["2.2.2.2"]}\n'
    )
    loaded = Checkpoint(str(path)).load()
    assert loaded["a.example.com"].a_records == ["2.2.2.2"]
