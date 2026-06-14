"""Tests for JSONL output."""
import json

from subscout.models import Subdomain
from subscout.output import write


def test_jsonl_one_object_per_line(tmp_path):
    subs = [
        Subdomain(name="a.example.com", sources={"crtsh"}),
        Subdomain(name="b.example.com", sources={"wayback"}),
    ]
    subs[0].resolved = True
    subs[0].a_records = ["1.2.3.4"]
    path = tmp_path / "out.jsonl"

    write(subs, "jsonl", str(path))

    lines = path.read_text().strip().splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first["name"] == "a.example.com"
    assert first["a_records"] == ["1.2.3.4"]
    # Compact (no indentation / spaces after separators).
    assert ": " not in lines[0]
