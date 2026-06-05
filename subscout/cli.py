"""Command-line interface for subscout."""
from __future__ import annotations

import argparse
import asyncio
import sys

from subscout import __version__
from subscout.config import Config
from subscout.engine import Engine
from subscout.models import Subdomain
from subscout.output import render_table, write
from subscout.sources.base import all_sources, get_sources
from subscout.utils import normalize_domain, setup_logging

DISCLAIMER = (
    "subscout is for AUTHORIZED reconnaissance only. Only scan domains you own "
    "or that are explicitly in scope for a bug bounty / pentest engagement."
)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="subscout",
        description="Modular passive subdomain reconnaissance for authorized testing.",
        epilog=DISCLAIMER,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("domains", nargs="*", help="one or more root domains (e.g. example.com)")
    p.add_argument("-l", "--list", metavar="FILE",
                   help="file with one root domain per line")

    p.add_argument("-s", "--sources", metavar="NAMES",
                   help="comma-separated subset of sources (default: all)")
    p.add_argument("--list-sources", action="store_true",
                   help="print available sources and exit")

    p.add_argument("-o", "--output", metavar="FILE", default=None,
                   help="write results to FILE (default: stdout)")
    p.add_argument("-f", "--format", choices=["txt", "json", "csv"], default="txt",
                   help="output format")

    res = p.add_mutually_exclusive_group()
    res.add_argument("--resolve", dest="resolve", action="store_true", default=True,
                     help="resolve DNS for discovered names")
    res.add_argument("--no-resolve", dest="resolve", action="store_false",
                     help="skip DNS resolution (passive only)")

    p.add_argument("--only-resolved", action="store_true",
                   help="keep only names that resolve in DNS")
    p.add_argument("--probe", action="store_true",
                   help="HTTP(S) probe resolved hosts (status, title, server)")
    p.add_argument("--no-wildcard-filter", dest="detect_wildcard",
                   action="store_false", default=True,
                   help="do not filter wildcard-DNS false positives")

    active = p.add_argument_group("active enumeration (authorized targets only)")
    active.add_argument("-b", "--brute", dest="bruteforce", action="store_true",
                        help="active DNS brute-force using a wordlist")
    active.add_argument("-w", "--wordlist", metavar="FILE",
                        help="custom wordlist file (merged with built-in list)")
    active.add_argument("--no-default-wordlist", dest="include_default_wordlist",
                        action="store_false", default=True,
                        help="use only the custom wordlist, not the built-in one")
    active.add_argument("-p", "--permutations", action="store_true",
                        help="mutate known names (altdns-style) and resolve them")
    active.add_argument("--mutation-rounds", type=int, default=2, metavar="N",
                        help="iterative permutation rounds (feedback loop)")
    active.add_argument("--no-derive-wordlist", dest="derive_wordlist",
                        action="store_false", default=True,
                        help="do not mine a target-specific wordlist from finds")
    active.add_argument("-r", "--recursive", action="store_true",
                        help="re-enumerate discovered subdomains as new roots")
    active.add_argument("--depth", type=int, default=1, metavar="N",
                        help="recursion depth (with --recursive)")
    active.add_argument("--max-recursive-roots", type=int, default=50, metavar="N",
                        help="cap on recursive roots per level")
    active.add_argument("--permutation-limit", type=int, default=100_000, metavar="N",
                        help="cap on permutation candidates per root")
    active.add_argument("--takeover", action="store_true",
                        help="check resolved hosts for subdomain-takeover candidates")
    active.add_argument("--asn", dest="asn_sweep", action="store_true",
                        help="ASN/netblock reverse-DNS sweep (find hosts beyond public sources)")
    active.add_argument("--asn-max-hosts", type=int, default=8192, metavar="N",
                        help="cap on IPs swept per netblock")
    active.add_argument("--asn-max-blocks", type=int, default=20, metavar="N",
                        help="cap on netblocks swept")
    active.add_argument("--tls-grab", dest="tls_grab", action="store_true",
                        help="connect to live hosts on 443 and harvest cert SAN names")
    active.add_argument("--all", dest="all_features", action="store_true",
                        help="enable brute + permutations + recursive + probe + "
                             "takeover + asn + tls-grab")

    p.add_argument("--timeout", type=float, default=20.0, help="per-request timeout (s)")
    p.add_argument("--dns-timeout", type=float, default=5.0, help="per-DNS-query timeout (s)")
    p.add_argument("--dns-concurrency", type=int, default=200)
    p.add_argument("--http-concurrency", type=int, default=50)
    p.add_argument("--source-concurrency", type=int, default=20)
    p.add_argument("--source-rate-limit", type=float, default=0.0,
                   help="max requests/sec per source (0 = unlimited)")
    p.add_argument("--wildcard-probes", type=int, default=5,
                   help="random labels probed for wildcard detection")
    p.add_argument("--no-fast-resolve", dest="fast_resolve", action="store_false",
                   default=True, help="query A+AAAA+CNAME separately (slower, exhaustive)")
    p.add_argument("--resolvers", metavar="IPS",
                   help="comma-separated DNS resolver IPs")
    p.add_argument("--resolvers-file", metavar="FILE",
                   help="newline-separated resolver IPs (for mass resolution)")
    p.add_argument("--no-validate-resolvers", dest="validate_resolvers",
                   action="store_false", default=True,
                   help="skip resolver health-check (use all resolvers as-is)")
    p.add_argument("--stream", action="store_true",
                   help="print live subdomains to stderr as they are discovered")

    p.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    p.add_argument("-q", "--quiet", action="store_true", help="errors only")
    p.add_argument("--version", action="version", version=f"subscout {__version__}")
    return p


def collect_domains(args: argparse.Namespace) -> list[str]:
    raw: list[str] = list(args.domains)
    if args.list:
        with open(args.list, encoding="utf-8") as fh:
            raw.extend(line for line in (ln.strip() for ln in fh) if line and not line.startswith("#"))
    seen: dict[str, None] = {}
    for item in raw:
        norm = normalize_domain(item)
        if norm:
            seen.setdefault(norm, None)
    return list(seen)


def build_config(args: argparse.Namespace) -> Config:
    all_on = getattr(args, "all_features", False)
    cfg = Config(
        timeout=args.timeout,
        dns_query_timeout=args.dns_timeout,
        dns_concurrency=args.dns_concurrency,
        http_concurrency=args.http_concurrency,
        source_concurrency=args.source_concurrency,
        wildcard_probes=args.wildcard_probes,
        fast_resolve=args.fast_resolve,
        resolve=args.resolve,
        probe=args.probe or all_on,
        only_resolved=args.only_resolved,
        detect_wildcard=args.detect_wildcard,
        bruteforce=args.bruteforce or all_on,
        wordlist_path=args.wordlist,
        include_default_wordlist=args.include_default_wordlist,
        permutations=args.permutations or all_on,
        permutation_limit=args.permutation_limit,
        mutation_rounds=args.mutation_rounds,
        derive_wordlist=args.derive_wordlist,
        recursive=args.recursive or all_on,
        recursion_depth=args.depth,
        recursion_max_roots=args.max_recursive_roots,
        takeover=args.takeover or all_on,
        validate_resolvers=args.validate_resolvers,
        resolvers_file=args.resolvers_file,
        asn_sweep=args.asn_sweep or all_on,
        asn_max_hosts=args.asn_max_hosts,
        asn_max_blocks=args.asn_max_blocks,
        tls_grab=args.tls_grab or all_on,
        stream=args.stream,
        source_rate_limit=args.source_rate_limit,
    )
    if args.resolvers:
        cfg.nameservers = [r.strip() for r in args.resolvers.split(",") if r.strip()]
    return cfg


async def _run(domains: list[str], cfg: Config, source_names: list[str] | None) -> list[Subdomain]:
    providers = get_sources(source_names)
    sources = [p.create(cfg) for p in providers]

    on_discover = None
    if cfg.stream:
        def on_discover(sub: Subdomain) -> None:
            ips = ",".join(sub.a_records[:3]) if sub.a_records else ""
            suffix = f" [{ips}]" if ips else ""
            sys.stderr.write(f"[+] {sub.name}{suffix}\n")
            sys.stderr.flush()

    engine = Engine(cfg, sources, on_discover=on_discover)

    merged: dict[str, Subdomain] = {}
    for domain in domains:
        for sub in await engine.run(domain):
            if sub.name in merged:
                merged[sub.name].merge(sub)
            else:
                merged[sub.name] = sub
    return sorted(merged.values(), key=lambda s: s.name)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logger = setup_logging(verbose=args.verbose, quiet=args.quiet)

    if args.list_sources:
        providers = sorted(all_sources(), key=lambda p: p.name)
        for p in providers:
            tag = " (needs API key)" if p.requires_key else ""
            print(f"{p.name}{tag}")
        keyless = sum(1 for p in providers if not p.requires_key)
        print(f"\n{len(providers)} sources total ({keyless} keyless, "
              f"{len(providers) - keyless} key-gated)")
        return 0

    domains = collect_domains(args)
    if not domains:
        logger.error("no domains given. Pass a domain or use -l FILE. See --help.")
        return 2

    cfg = build_config(args)
    try:
        source_names = (
            [s.strip() for s in args.sources.split(",") if s.strip()]
            if args.sources else None
        )
        results = asyncio.run(_run(domains, cfg, source_names))
    except ValueError as exc:
        logger.error("%s", exc)
        return 2
    except KeyboardInterrupt:
        logger.error("interrupted")
        return 130

    write(results, args.format, args.output)

    show_detail = cfg.resolve or cfg.probe or cfg.bruteforce or cfg.permutations or cfg.takeover
    if args.output and show_detail:
        sys.stderr.write("\n" + render_table(results) + "\n")
    takeovers = sum(1 for s in results if s.takeover)
    if takeovers:
        logger.warning("%d possible takeover candidate(s) - verify manually", takeovers)
    logger.info("done: %d subdomain(s)", len(results))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
