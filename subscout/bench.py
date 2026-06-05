"""Head-to-head benchmark harness: subscout vs subfinder / amass / bbot.

This produces the **evidence** behind any "we're faster / find more" claim.
It runs each available tool against the same target(s), measures wall-clock
time, counts unique resolvable subdomains, and computes overlap so you can see
exactly what each tool found that the others missed.

Run it only against AUTHORIZED targets. External tools are auto-detected; any
that are not installed are skipped (so this is useful even with just subscout).

Usage:
    python -m subscout.bench example.com
    python -m subscout.bench -l targets.txt --tools subscout,subfinder,amass
    python -m subscout.bench example.com --json report.json
"""
from __future__ import annotations

import argparse
import asyncio
import json
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field

from subscout.cli import build_config, build_parser
from subscout.config import Config
from subscout.engine import Engine
from subscout.sources.base import get_sources
from subscout.utils import in_scope, normalize_domain, setup_logging


@dataclass
class ToolResult:
    tool: str
    seconds: float
    found: set[str] = field(default_factory=set)
    ok: bool = True
    note: str = ""

    @property
    def count(self) -> int:
        return len(self.found)


# ---- runners ----------------------------------------------------------

async def run_subscout(domain: str, cfg: Config) -> ToolResult:
    providers = get_sources(None)
    sources = [p.create(cfg) for p in providers]
    engine = Engine(cfg, sources)
    start = time.perf_counter()
    subs = await engine.run(domain)
    elapsed = time.perf_counter() - start
    names = {s.name for s in subs if (s.resolved or not cfg.resolve)}
    return ToolResult("subscout", elapsed, names)


def _run_cmd(cmd: list[str], timeout: int) -> tuple[bool, str, str]:
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False
        )
        return proc.returncode == 0, proc.stdout, proc.stderr
    except FileNotFoundError:
        return False, "", "not installed"
    except subprocess.TimeoutExpired:
        return False, "", "timed out"


def _filter_scope(lines: str, domain: str) -> set[str]:
    out: set[str] = set()
    for ln in lines.splitlines():
        h = normalize_domain(ln)
        if h and in_scope(h, domain):
            out.add(h)
    return out


def run_external(tool: str, domain: str, timeout: int) -> ToolResult:
    binary = {"subfinder": "subfinder", "amass": "amass", "bbot": "bbot"}.get(tool)
    if not binary or not shutil.which(binary):
        return ToolResult(tool, 0.0, ok=False, note="not installed")

    if tool == "subfinder":
        cmd = [binary, "-silent", "-d", domain]
    elif tool == "amass":
        cmd = [binary, "enum", "-passive", "-d", domain]
    else:  # bbot
        cmd = [binary, "-t", domain, "-f", "subdomain-enum", "-y", "--silent"]

    start = time.perf_counter()
    ok, out, err = _run_cmd(cmd, timeout)
    elapsed = time.perf_counter() - start
    if not ok and not out:
        return ToolResult(tool, elapsed, ok=False, note=err.strip()[:80] or "failed")
    return ToolResult(tool, elapsed, _filter_scope(out, domain))


# ---- reporting --------------------------------------------------------

def report(domain: str, results: list[ToolResult]) -> dict:
    live = [r for r in results if r.ok]
    union: set[str] = set()
    for r in live:
        union |= r.found

    rows = []
    for r in results:
        if not r.ok:
            rows.append({"tool": r.tool, "status": r.note or "skipped"})
            continue
        others = set()
        for o in live:
            if o.tool != r.tool:
                others |= o.found
        unique = r.found - others
        rows.append({
            "tool": r.tool,
            "count": r.count,
            "seconds": round(r.seconds, 2),
            "unique_finds": len(unique),
            "rate_per_sec": round(r.count / r.seconds, 1) if r.seconds > 0 else None,
        })
    return {"target": domain, "union_total": len(union), "tools": rows}


def print_report(rep: dict) -> None:
    print(f"\n=== {rep['target']}  (union of all tools: {rep['union_total']}) ===")
    header = f"{'tool':<12} {'found':>7} {'time(s)':>9} {'uniq':>6} {'found/s':>9}"
    print(header)
    print("-" * len(header))
    for row in rep["tools"]:
        if "count" not in row:
            print(f"{row['tool']:<12} {'-- ' + row['status']:>33}")
            continue
        rate = row["rate_per_sec"] if row["rate_per_sec"] is not None else "-"
        print(f"{row['tool']:<12} {row['count']:>7} {row['seconds']:>9} "
              f"{row['unique_finds']:>6} {str(rate):>9}")


def build_bench_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="subscout.bench",
        description="Benchmark subscout against other recon tools (authorized targets only).",
    )
    p.add_argument("domains", nargs="*")
    p.add_argument("-l", "--list", metavar="FILE")
    p.add_argument("--tools", default="subscout,subfinder,amass,bbot",
                   help="comma-separated tools to compare")
    p.add_argument("--timeout", type=int, default=600, help="per-tool timeout (s)")
    p.add_argument("--json", metavar="FILE", help="write a JSON report")
    p.add_argument("--passive-only", action="store_true",
                   help="fair comparison: subscout passive-only (no brute/permute)")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_bench_parser().parse_args(argv)
    setup_logging(quiet=True)

    domains = list(args.domains)
    if args.list:
        with open(args.list, encoding="utf-8") as fh:
            domains += [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
    domains = [normalize_domain(d) for d in domains if normalize_domain(d)]
    if not domains:
        print("no domains given", file=sys.stderr)
        return 2

    tools = [t.strip() for t in args.tools.split(",") if t.strip()]

    # subscout config: passive + resolve (fair vs passive tools), or full power.
    base_args = build_parser().parse_args([domains[0]])
    cfg = build_config(base_args)
    cfg.resolve = True
    if args.passive_only:
        cfg.bruteforce = cfg.permutations = cfg.recursive = False

    all_reports = []
    for domain in domains:
        results: list[ToolResult] = []
        for tool in tools:
            if tool == "subscout":
                results.append(asyncio.run(run_subscout(domain, cfg)))
            else:
                results.append(run_external(tool, domain, args.timeout))
        rep = report(domain, results)
        print_report(rep)
        all_reports.append(rep)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(all_reports, fh, indent=2)
        print(f"\nreport written to {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
