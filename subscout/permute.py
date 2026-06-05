"""Permutation / mutation engine (altdns / gotator style).

Takes the subdomains we already know and mutates them to guess close neighbours
that no passive source has listed - e.g. from ``api.example.com`` it derives
``api-dev.example.com``, ``dev-api.example.com``, ``api2.example.com``,
``staging.api.example.com``. The candidates are then resolved; only live hits
are kept.

This is where a tool stops being a thin wrapper around public data and starts
actually discovering hidden assets.
"""
from __future__ import annotations

import logging
import re

from subscout.config import Config
from subscout.models import Subdomain
from subscout.resolver import Resolver
from subscout.utils import is_valid_hostname

logger = logging.getLogger("subscout")

_TRAILING_NUM = re.compile(r"^(.*?)(\d+)$")


def _rebuild(labels: list[str], domain: str) -> str:
    labels = [label for label in labels if label]
    return ".".join(labels + [domain])


def _numeric_variants(label: str) -> set[str]:
    """Increment/decrement a trailing number and add small numeric suffixes."""
    out: set[str] = set()
    match = _TRAILING_NUM.match(label)
    if match:
        prefix, num = match.group(1), match.group(2)
        value = int(num)
        width = len(num)
        for delta in (1, -1, 2):
            nv = value + delta
            if nv >= 0:
                out.add(f"{prefix}{str(nv).zfill(width)}")
    else:
        for n in (1, 2, 3, 0):
            out.add(f"{label}{n}")
    return out


def generate_permutations(
    known_names: set[str],
    words: list[str],
    domain: str,
    max_results: int = 100_000,
) -> list[str]:
    """Generate mutated candidate hostnames from *known_names* within *domain*."""
    suffix = "." + domain
    word_set = list(dict.fromkeys(w.lower() for w in words if w))
    results: set[str] = set()

    for name in known_names:
        name = name.lower()
        if name == domain or not name.endswith(suffix):
            continue
        sub = name[: -len(suffix)]
        labels = sub.split(".")
        first, rest = labels[0], labels[1:]

        for w in word_set:
            # Insert a word as a brand-new leftmost label.
            results.add(_rebuild([w] + labels, domain))
            # Dash-join variants on the leftmost label.
            results.add(_rebuild([f"{first}-{w}"] + rest, domain))
            results.add(_rebuild([f"{w}-{first}"] + rest, domain))
            # Replace the leftmost label entirely (keeps deeper structure).
            if rest:
                results.add(_rebuild([w] + rest, domain))

        # Numeric mutations on the leftmost label.
        for variant in _numeric_variants(first):
            results.add(_rebuild([variant] + rest, domain))

    # Drop invalids and the inputs themselves, then cap deterministically.
    cleaned = sorted(
        n for n in results
        if n not in known_names and n != domain and is_valid_hostname(n)
    )
    if len(cleaned) > max_results:
        logger.info("permutations capped at %d (generated %d)", max_results, len(cleaned))
        cleaned = cleaned[:max_results]
    return cleaned


class Permuter:
    def __init__(self, config: Config, resolver: Resolver, words: list[str]) -> None:
        self.config = config
        self.resolver = resolver
        self.words = words

    async def run(
        self,
        known_names: set[str],
        domain: str,
        wildcard_ips: set[str],
        wildcard_cnames: set[str] | None = None,
    ) -> list[Subdomain]:
        candidates = generate_permutations(
            known_names, self.words, domain, self.config.permutation_limit
        )
        if not candidates:
            return []
        logger.info("permutations: testing %d candidate(s) under %s", len(candidates), domain)
        hits = await self.resolver.resolve_names(
            candidates, "permutation", wildcard_ips, wildcard_cnames
        )
        logger.info("permutations: %d live host(s) under %s", len(hits), domain)
        return hits
