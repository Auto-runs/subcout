"""Result formatting and writing: plain text, JSON, and CSV."""
from __future__ import annotations

import csv
import io
import json
import sys
from typing import TextIO

from subscout.models import Subdomain


def _open(path: str | None) -> tuple[TextIO, bool]:
    """Return (stream, should_close). A path of None or '-' means stdout."""
    if path is None or path == "-":
        return sys.stdout, False
    return open(path, "w", encoding="utf-8", newline=""), True


def write_txt(subdomains: list[Subdomain], path: str | None) -> None:
    stream, close = _open(path)
    try:
        for sub in subdomains:
            stream.write(sub.name + "\n")
    finally:
        if close:
            stream.close()


def write_json(subdomains: list[Subdomain], path: str | None) -> None:
    payload = [s.to_dict() for s in subdomains]
    stream, close = _open(path)
    try:
        json.dump(payload, stream, indent=2)
        stream.write("\n")
    finally:
        if close:
            stream.close()


def write_csv(subdomains: list[Subdomain], path: str | None) -> None:
    columns = [
        "name", "sources", "resolved", "a_records", "aaaa_records",
        "cname", "http_status", "http_url", "title", "server", "content_length",
        "cdn", "technologies", "takeover", "takeover_service",
    ]
    stream, close = _open(path)
    try:
        writer = csv.writer(stream)
        writer.writerow(columns)
        for sub in subdomains:
            d = sub.to_dict()
            writer.writerow([
                d["name"],
                ";".join(d["sources"]),
                d["resolved"],
                ";".join(d["a_records"]),
                ";".join(d["aaaa_records"]),
                d["cname"] or "",
                d["http_status"] if d["http_status"] is not None else "",
                d["http_url"] or "",
                d["title"] or "",
                d["server"] or "",
                d["content_length"] if d["content_length"] is not None else "",
                d["cdn"] or "",
                ";".join(d["technologies"]),
                d["takeover"],
                d["takeover_service"] or "",
            ])
    finally:
        if close:
            stream.close()


_WRITERS = {"txt": write_txt, "json": write_json, "csv": write_csv}


def write(subdomains: list[Subdomain], fmt: str, path: str | None) -> None:
    writer = _WRITERS.get(fmt)
    if writer is None:
        raise ValueError(f"unknown output format: {fmt}")
    writer(subdomains, path)


def render_table(subdomains: list[Subdomain]) -> str:
    """Human-friendly summary table for resolved/probed results (to stderr)."""
    if not subdomains:
        return "(no results)"
    buf = io.StringIO()
    for sub in subdomains:
        bits = [sub.name]
        if sub.a_records:
            bits.append("[" + ",".join(sub.a_records[:3]) + "]")
        if sub.cname:
            bits.append(f"CNAME->{sub.cname}")
        if sub.http_status is not None:
            bits.append(f"HTTP {sub.http_status}")
        if sub.cdn:
            bits.append(f"CDN:{sub.cdn}")
        if sub.technologies:
            bits.append("tech:" + ",".join(sub.technologies[:4]))
        if sub.title:
            bits.append(f'"{sub.title}"')
        if sub.takeover:
            bits.append(f"[!] TAKEOVER? ({sub.takeover_service})")
        buf.write(" ".join(bits) + "\n")
    return buf.getvalue()
