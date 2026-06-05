"""Recon orchestration engine.

Pipeline per root domain:

    passive sources -> resolve -> active brute-force -> permutations

with optional **recursive** enumeration (discovered subdomains become new roots,
bounded by depth + a per-level cap) and an optional **HTTP probe** and
**takeover** pass at the end. A single top-level scope guard keeps every result
inside the original target domain.
"""
from __future__ import annotations

import asyncio
import logging

import aiohttp

from subscout.brute import BruteForcer
from subscout.config import Config
from subscout.models import Subdomain
from subscout.permute import Permuter
from subscout.prober import Prober
from subscout.resolver import Resolver
from subscout.sources.base import Source
from subscout.takeover import TakeoverDetector
from subscout.utils import clean_candidate, in_scope
from subscout.wordlists import derive_words_from_names, load_wordlist

logger = logging.getLogger("subscout")


class Engine:
    def __init__(
        self,
        config: Config,
        sources: list[Source],
        resolver: Resolver | None = None,
        on_discover=None,
    ) -> None:
        self.config = config
        self.sources = [s for s in sources if s.enabled()]
        self._resolver = resolver  # injectable for testing
        # Optional callback invoked once per newly-confirmed live subdomain, as
        # soon as it is discovered (enables streaming output on large scans).
        self._on_discover = on_discover
        skipped = [s.name for s in sources if not s.enabled()]
        if skipped:
            logger.info("skipping sources without an API key: %s", ", ".join(skipped))

        # Per-run state (reset in run()).
        self.scope_root = ""
        self.found: dict[str, Subdomain] = {}
        self._attempted: set[str] = set()
        self._streamed: set[str] = set()

    # ---- helpers -------------------------------------------------------

    def _emit(self, sub: Subdomain) -> None:
        """Fire the discovery callback once per live name (de-duplicated)."""
        if self._on_discover is None:
            return
        if sub.resolved and sub.name not in self._streamed:
            self._streamed.add(sub.name)
            try:
                self._on_discover(sub)
            except Exception as exc:  # noqa: BLE001 - never let output break a scan
                logger.debug("on_discover callback failed: %s", exc)

    def _resolver_or_create(self) -> Resolver:
        if self._resolver is None:
            self._resolver = Resolver(self.config)
        return self._resolver

    def _load_resolvers_file(self, resolver: Resolver) -> None:
        """Load a newline-separated resolver list, replacing the defaults."""
        path = self.config.resolvers_file
        if not path:
            return
        try:
            with open(path, encoding="utf-8") as fh:
                ips = [
                    ln.strip() for ln in fh
                    if ln.strip() and not ln.strip().startswith("#")
                ]
        except OSError as exc:
            logger.error("could not read resolvers file %s: %s", path, exc)
            return
        if ips:
            resolver._resolver.nameservers = ips
            logger.info("loaded %d resolver(s) from %s", len(ips), path)

    def _add(self, name: str) -> Subdomain:
        sub = self.found.get(name)
        if sub is None:
            sub = Subdomain(name=name)
            self.found[name] = sub
        return sub

    @staticmethod
    def _copy_resolution(dst: Subdomain, src: Subdomain) -> None:
        dst.resolved = src.resolved
        dst.a_records = src.a_records
        dst.aaaa_records = src.aaaa_records
        dst.cname = src.cname
        dst.sources |= src.sources

    def _needs_dns(self) -> bool:
        c = self.config
        return any((
            c.resolve, c.only_resolved, c.probe, c.bruteforce,
            c.permutations, c.takeover, c.recursive, c.asn_sweep, c.tls_grab,
        ))

    # ---- passive -------------------------------------------------------

    async def _gather_passive(self, root: str) -> dict[str, set[str]]:
        """Run every enabled source for *root*; return name -> set(sources)."""
        timeout = aiohttp.ClientTimeout(total=self.config.timeout)
        headers = {"User-Agent": self.config.user_agent}
        sem = asyncio.Semaphore(self.config.source_concurrency)
        result: dict[str, set[str]] = {}

        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
            async def run(source: Source) -> tuple[str, set[str]]:
                async with sem:
                    try:
                        return source.name, await source.fetch(session, root)
                    except Exception as exc:  # noqa: BLE001
                        logger.warning("source %s crashed: %s", source.name, exc)
                        return source.name, set()

            for coro in asyncio.as_completed([run(s) for s in self.sources]):
                source_name, raw_names = await coro
                kept = 0
                for raw in raw_names:
                    name = clean_candidate(raw, root)
                    # Stay inside the *original* target, not just this sub-root.
                    if not name or not in_scope(name, self.scope_root):
                        continue
                    result.setdefault(name, set()).add(source_name)
                    kept += 1
                logger.info("%-14s %d name(s) under %s", source_name + ":", kept, root)

        return result

    # ---- per-root enumeration -----------------------------------------

    async def _enumerate_root(
        self, resolver: Resolver | None, root: str, words: list[str]
    ) -> list[Subdomain]:
        """Enumerate one root; return the subdomains that resolved this pass."""
        wildcard_ips: set[str] = set()
        wildcard_cnames: set[str] = set()
        if resolver and self.config.detect_wildcard:
            wildcard_ips, wildcard_cnames = await resolver.detect_wildcard(root)

        resolved_now: list[Subdomain] = []

        # 1) passive
        for name, srcs in (await self._gather_passive(root)).items():
            self._add(name).sources |= srcs

        # 2) resolve everything we have not tried yet
        if resolver:
            pending = [s for s in self.found.values() if s.name not in self._attempted]
            self._attempted.update(s.name for s in pending)
            await resolver.resolve_all(pending, wildcard_ips, wildcard_cnames)
            for s in pending:
                if s.resolved:
                    resolved_now.append(s)
                    self._emit(s)

        # 3) active brute-force
        if resolver and self.config.bruteforce and words:
            brute = BruteForcer(self.config, resolver, words)
            for hit in await brute.run(root, wildcard_ips, wildcard_cnames):
                sub = self._add(hit.name)
                self._copy_resolution(sub, hit)
                self._attempted.add(sub.name)
                resolved_now.append(sub)
                self._emit(sub)

        # 4) permutations of what we know under this root, run in iterative
        #    rounds: each round can surface new live names whose labels feed the
        #    next round's mutations (BBOT-style feedback loop). Runs as long as
        #    we have a base wordlist OR derivation is enabled to build one.
        if resolver and self.config.permutations and (words or self.config.derive_wordlist):
            await self._permute_rounds(resolver, root, words, wildcard_ips,
                                       wildcard_cnames, resolved_now)

        return resolved_now

    async def _permute_rounds(
        self, resolver, root, words, wildcard_ips, wildcard_cnames, resolved_now,
    ) -> None:
        rounds = max(1, self.config.mutation_rounds)
        for rnd in range(rounds):
            known = {
                s.name for s in self.found.values()
                if s.name == root or s.name.endswith("." + root)
            }
            # Enrich the wordlist with labels mined from what we've found so far.
            round_words = words
            if self.config.derive_wordlist:
                derived = derive_words_from_names(known, root)
                if derived:
                    round_words = list(dict.fromkeys(list(words) + derived))

            permuter = Permuter(self.config, resolver, round_words)
            hits = await permuter.run(known, root, wildcard_ips, wildcard_cnames)

            new_hits = 0
            for hit in hits:
                if hit.name in self._attempted and hit.name in self.found \
                        and self.found[hit.name].resolved:
                    continue
                sub = self._add(hit.name)
                was_resolved = sub.resolved
                self._copy_resolution(sub, hit)
                self._attempted.add(sub.name)
                resolved_now.append(sub)
                if not was_resolved:
                    new_hits += 1
                self._emit(sub)

            logger.info("permutation round %d/%d: %d new live host(s)",
                        rnd + 1, rounds, new_hits)
            if new_hits == 0:
                break  # converged - no point running more rounds

    def _recursion_targets(
        self, resolved_now: list[Subdomain], visited: set[str]
    ) -> list[str]:
        seen: dict[str, None] = {}
        for sub in resolved_now:
            if sub.name not in visited and sub.name != self.scope_root:
                seen.setdefault(sub.name, None)
        return list(seen)

    # ---- public entrypoint --------------------------------------------

    async def run(self, domain: str) -> list[Subdomain]:
        self.scope_root = domain
        self.found = {}
        self._attempted = set()
        self._streamed = set()

        resolver = self._resolver_or_create() if self._needs_dns() else None
        if resolver is not None:
            self._load_resolvers_file(resolver)
            if self.config.validate_resolvers:
                await resolver.validate_resolvers()

        words: list[str] = []
        if self.config.bruteforce or self.config.permutations:
            words = load_wordlist(
                self.config.wordlist_path, self.config.include_default_wordlist
            )
            logger.info("loaded %d wordlist entries", len(words))

        logger.info("enumerating %s with %d source(s)", domain, len(self.sources))

        visited_roots: set[str] = set()
        queue: list[tuple[str, int]] = [(domain, 0)]

        while queue:
            root, depth = queue.pop(0)
            if root in visited_roots:
                continue
            visited_roots.add(root)

            resolved_now = await self._enumerate_root(resolver, root, words)

            if self.config.recursive and depth < self.config.recursion_depth:
                targets = self._recursion_targets(resolved_now, visited_roots)
                capped = targets[: self.config.recursion_max_roots]
                if capped:
                    logger.info(
                        "recursion depth %d: queueing %d new root(s)",
                        depth + 1, len(capped),
                    )
                for child in capped:
                    queue.append((child, depth + 1))

        subdomains = sorted(self.found.values(), key=lambda s: s.name)
        logger.info("%d unique subdomain(s) discovered", len(subdomains))
        resolved = sum(1 for s in subdomains if s.resolved)
        if resolver:
            logger.info("%d subdomain(s) resolved", resolved)

        if self.config.only_resolved:
            subdomains = [s for s in subdomains if s.resolved]

        # ASN / netblock reverse-DNS sweep: discover hosts beyond public sources.
        if self.config.asn_sweep and resolver:
            from subscout.asn import ASNSweeper
            new = await ASNSweeper(self.config, resolver).run(subdomains, domain)
            added = 0
            for hit in new:
                if hit.name not in self.found:
                    added += 1
                sub = self._add(hit.name)
                sub.resolved = True
                sub.sources |= hit.sources
                for ip in hit.a_records:
                    if ip not in sub.a_records:
                        sub.a_records.append(ip)
                self._emit(sub)
            if added:
                logger.info("asn: added %d new host(s)", added)
                subdomains = sorted(self.found.values(), key=lambda s: s.name)
                if self.config.only_resolved:
                    subdomains = [s for s in subdomains if s.resolved]

        # TLS certificate grab: read SANs from live hosts to find siblings.
        if self.config.tls_grab and resolver:
            from subscout.tlsgrab import TLSGrabber
            grabbed = await TLSGrabber(self.config).grab_all(subdomains, domain)
            # Only keep newly-seen names; resolve them to confirm + filter wildcards.
            fresh = [g for g in grabbed if g.name not in self.found]
            if fresh:
                wc_ips, wc_cn = (set(), set())
                if self.config.detect_wildcard:
                    wc_ips, wc_cn = await resolver.detect_wildcard(domain)
                await resolver.resolve_all(fresh, wc_ips, wc_cn)
                added = 0
                for g in fresh:
                    keep = g.resolved or not self.config.only_resolved
                    if not keep:
                        continue
                    sub = self._add(g.name)
                    sub.sources |= g.sources
                    if g.resolved:
                        self._copy_resolution(sub, g)
                        self._emit(sub)
                    added += 1
                if added:
                    logger.info("tls: added %d new host(s)", added)
                    subdomains = sorted(self.found.values(), key=lambda s: s.name)
                    if self.config.only_resolved:
                        subdomains = [s for s in subdomains if s.resolved]

        if self.config.probe:
            targets = [s for s in subdomains if s.resolved]
            logger.info("probing %d live host(s) over HTTP(S)", len(targets))
            await Prober(self.config).probe_all(targets)

        if self.config.takeover:
            candidates = await TakeoverDetector(self.config).check_all(subdomains)
            logger.info("takeover: %d candidate(s) found", len(candidates))

        return subdomains
