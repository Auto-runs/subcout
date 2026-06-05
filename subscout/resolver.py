"""Asynchronous DNS resolution: fast, accurate, wildcard-aware.

Speed model
-----------
The naive approach issues three queries per name (CNAME, A, AAAA). That triples
DNS traffic and latency. In ``fast_resolve`` mode we instead issue a **single A
query** and read the CNAME straight out of the answer chain - DNS already
returns the CNAME records alongside the A answer, so a separate CNAME query is
redundant. AAAA is only queried when explicitly needed. Combined with a high
concurrency limit and resolver rotation, this is the main throughput win.

Accuracy model
---------------
Wildcard DNS (``*.example.com`` -> fixed IP) is the classic false-positive
source. We probe several random labels - and, for multi-level wildcards, random
labels under a random sub-level - and treat any returned IPs (and wildcard CNAME
targets) as "wildcard" answers used to filter bogus hits later.
"""
from __future__ import annotations

import asyncio
import logging
import secrets

import dns.asyncresolver
import dns.resolver
import dns.reversename

from subscout.config import Config
from subscout.models import Subdomain

logger = logging.getLogger("subscout")


class Resolver:
    def __init__(self, config: Config) -> None:
        self.config = config
        self._resolver = dns.asyncresolver.Resolver(configure=False)
        self._resolver.nameservers = list(config.nameservers)
        # Rotate across nameservers to spread load and dodge per-resolver limits.
        self._resolver.rotate = True
        self._resolver.timeout = config.dns_query_timeout
        self._resolver.lifetime = config.dns_query_timeout
        self._sem = asyncio.Semaphore(config.dns_concurrency)

    # ---- resolver trust (puredns-style) -------------------------------

    async def _probe_resolver(self, ns: str) -> bool:
        """Return True if nameserver *ns* behaves honestly.

        A trustworthy resolver must:
          1. resolve a known-good anchor name to a plausible A record, and
          2. return NO answer for a random non-existent name. A resolver that
             hands back an IP for ``<random>.com`` is hijacking NXDOMAIN
             (captive portal / ad injector / poisoned) and would flood active
             enumeration with false positives - so we drop it.
        """
        probe = dns.asyncresolver.Resolver(configure=False)
        probe.nameservers = [ns]
        probe.timeout = self.config.dns_query_timeout
        probe.lifetime = self.config.dns_query_timeout

        # 1) anchor must resolve
        try:
            ans = await probe.resolve("dns.google", "A")
            if not list(ans):
                return False
        except Exception:  # noqa: BLE001
            return False

        # 2) bogus name must NOT resolve
        bogus = f"{secrets.token_hex(12)}.com"
        try:
            await probe.resolve(bogus, "A")
            return False  # answered a non-existent name -> lying resolver
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return True
        except Exception:  # noqa: BLE001 - timeout/servfail: treat as untrusted
            return False

    async def validate_resolvers(self) -> int:
        """Health-check configured resolvers; keep only trustworthy ones.

        Returns the number of resolvers retained. If every resolver fails the
        check we keep the original list (better to run than to abort).
        """
        candidates = list(self._resolver.nameservers)
        if not candidates:
            return 0
        results = await asyncio.gather(*(self._probe_resolver(ns) for ns in candidates))
        trusted = [ns for ns, ok in zip(candidates, results) if ok]
        if trusted:
            self._resolver.nameservers = trusted
            logger.info(
                "resolver health-check: %d/%d trusted (%s)",
                len(trusted), len(candidates), ", ".join(trusted),
            )
            return len(trusted)
        logger.warning(
            "resolver health-check: none passed; keeping original %d resolver(s)",
            len(candidates),
        )
        return len(candidates)

    # ---- low-level queries --------------------------------------------

    async def _resolve_chain(self, name: str) -> tuple[list[str], str | None]:
        """Single A-record query. Returns (A records, first CNAME target).

        The CNAME is pulled from the response chain, so we avoid a second query.
        """
        try:
            answer = await self._resolver.resolve(name, "A")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return [], None
        except Exception as exc:  # noqa: BLE001 - resolution must never abort the run
            logger.debug("dns A %s failed: %s", name, exc)
            return [], None

        a_records = [r.address for r in answer]

        cname: str | None = None
        # The full chase is available via answer.chaining_result.cnames.
        try:
            cnames = answer.chaining_result.cnames
            if cnames:
                # rrset name is the alias; its target is the canonical name.
                target = cnames[0].to_rdataset()[0].target.to_text().rstrip(".")
                cname = target
        except Exception:  # noqa: BLE001 - chaining info is best-effort
            cname = None
        return a_records, cname

    async def _query(self, name: str, rdtype: str) -> list[str]:
        try:
            answer = await self._resolver.resolve(name, rdtype)
            return [r.to_text().rstrip(".") for r in answer]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return []
        except Exception as exc:  # noqa: BLE001
            logger.debug("dns %s %s failed: %s", rdtype, name, exc)
            return []

    async def reverse_lookup(self, ip: str) -> list[str]:
        """PTR lookup for a single IP. Returns hostnames (may be empty)."""
        try:
            rev_name = dns.reversename.from_address(ip)
        except Exception:  # noqa: BLE001 - malformed IP
            return []
        async with self._sem:
            return await self._query(rev_name.to_text(), "PTR")

    async def reverse_sweep(self, ips) -> dict[str, list[str]]:
        """PTR-resolve many IPs concurrently. Returns {ip: [hostnames]}."""
        ips = list(ips)
        results: dict[str, list[str]] = {}

        async def one(ip: str) -> None:
            hosts = await self.reverse_lookup(ip)
            if hosts:
                results[ip] = hosts

        await asyncio.gather(*(one(ip) for ip in ips))
        return results

    # ---- wildcard detection -------------------------------------------

    async def detect_wildcard(self, domain: str) -> tuple[set[str], set[str]]:
        """Detect wildcard DNS at *domain* and one level below.

        Returns (wildcard_ips, wildcard_cnames). Empty sets mean no wildcard.
        """
        probes = max(1, self.config.wildcard_probes)
        names: list[str] = [f"{secrets.token_hex(8)}.{domain}" for _ in range(probes)]
        # Multi-level: random label under a random sub-level (catches *.*.domain).
        sub = secrets.token_hex(6)
        names += [f"{secrets.token_hex(6)}.{sub}.{domain}" for _ in range(max(1, probes // 2))]

        wildcard_ips: set[str] = set()
        wildcard_cnames: set[str] = set()

        async def probe(n: str) -> None:
            async with self._sem:
                a, cname = await self._resolve_chain(n)
            wildcard_ips.update(a)
            if cname:
                wildcard_cnames.add(cname)

        await asyncio.gather(*(probe(n) for n in names))

        if wildcard_ips or wildcard_cnames:
            logger.info(
                "wildcard DNS detected for %s (ips=%s cnames=%s) - results filtered",
                domain,
                ", ".join(sorted(wildcard_ips)) or "-",
                ", ".join(sorted(wildcard_cnames)) or "-",
            )
        return wildcard_ips, wildcard_cnames

    # ---- resolution ----------------------------------------------------

    async def _resolve_one(
        self, sub: Subdomain, wildcard_ips: set[str], wildcard_cnames: set[str]
    ) -> None:
        async with self._sem:
            a, cname = await self._resolve_chain(sub.name)
            aaaa = (
                await self._query(sub.name, "AAAA")
                if (not self.config.fast_resolve and not a)
                else []
            )

        sub.a_records = a
        sub.aaaa_records = aaaa
        sub.cname = cname
        has_records = bool(a or aaaa or cname)

        if not has_records:
            sub.resolved = False
            return

        # Wildcard filter: a hit is bogus if its IPs are all known wildcard IPs
        # (and it has no distinguishing CNAME), or its CNAME is a wildcard CNAME.
        if wildcard_cnames and cname and cname in wildcard_cnames:
            sub.resolved = False
            logger.debug("filtered wildcard CNAME hit: %s", sub.name)
            return
        if (
            wildcard_ips
            and not cname
            and a
            and set(a).issubset(wildcard_ips)
        ):
            sub.resolved = False
            logger.debug("filtered wildcard hit: %s", sub.name)
            return

        sub.resolved = True

    async def resolve_all(
        self,
        subdomains: list[Subdomain],
        wildcard_ips: set[str],
        wildcard_cnames: set[str] | None = None,
    ) -> None:
        """Resolve every subdomain in place, concurrently."""
        wildcard_cnames = wildcard_cnames or set()
        await asyncio.gather(
            *(self._resolve_one(s, wildcard_ips, wildcard_cnames) for s in subdomains)
        )

    async def resolve_names(
        self,
        names,
        source_label: str,
        wildcard_ips: set[str],
        wildcard_cnames: set[str] | None = None,
    ) -> list[Subdomain]:
        """Resolve raw hostnames and return only the ones that actually resolve.

        Used by the active modules (brute-force, permutations) where we generate
        a large set of candidate names and only care about live hits.
        """
        subs = [Subdomain(name=n, sources={source_label}) for n in names]
        await self.resolve_all(subs, wildcard_ips, wildcard_cnames)
        return [s for s in subs if s.resolved]
