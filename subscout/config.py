"""Runtime configuration for subscout.

API keys are read from environment variables so you never hardcode secrets.
All keys are optional - sources that need a missing key are skipped gracefully.

Supported environment variables:
    SUBSCOUT_VIRUSTOTAL_KEY
    SUBSCOUT_SECURITYTRAILS_KEY
    SUBSCOUT_SHODAN_KEY
    SUBSCOUT_CHAOS_KEY        (ProjectDiscovery Chaos)
    SUBSCOUT_BUFFEROVER_KEY
    SUBSCOUT_FULLHUNT_KEY
    SUBSCOUT_LEAKIX_KEY
    SUBSCOUT_CENSYS_ID / SUBSCOUT_CENSYS_SECRET
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env(*names: str) -> str | None:
    for name in names:
        value = os.environ.get(name)
        if value:
            return value.strip()
    return None


@dataclass
class Config:
    """Tunable settings for a recon run."""

    # Networking
    timeout: float = 20.0           # per-request timeout (seconds)
    dns_concurrency: int = 200      # max concurrent DNS lookups
    http_concurrency: int = 50      # max concurrent HTTP probes
    source_concurrency: int = 20    # max sources fetched in parallel
    user_agent: str = "subscout/0.4 (+authorized-recon)"
    retries: int = 2

    # Per-source politeness: cap request rate and retry transient failures with
    # exponential backoff so we never hammer (or get banned by) a data source.
    source_rate_limit: float = 0.0  # max requests/sec per source (0 = unlimited)
    backoff_base: float = 0.5       # first retry delay (seconds), doubled each try
    retry_statuses: tuple = (429, 500, 502, 503, 504)

    # DNS performance / accuracy
    dns_query_timeout: float = 5.0  # per-DNS-query timeout (separate from HTTP)
    fast_resolve: bool = True       # single A query + CNAME from answer chain
    wildcard_probes: int = 5        # random labels probed per wildcard test

    # Behaviour
    resolve: bool = True            # resolve DNS for discovered names
    probe: bool = False             # HTTP probe resolved names
    only_resolved: bool = False     # drop names that do not resolve
    detect_wildcard: bool = True    # filter wildcard DNS false positives

    # Active enumeration
    bruteforce: bool = False        # active DNS brute-force from a wordlist
    wordlist_path: str | None = None
    include_default_wordlist: bool = True
    permutations: bool = False      # mutate known names and resolve them
    permutation_limit: int = 100_000
    # Target-derived intelligence (BBOT-style): mine labels from discovered
    # names to build a target-specific wordlist, and mutate iteratively.
    derive_wordlist: bool = True    # enrich wordlist from discovered subdomains
    mutation_rounds: int = 2        # iterative permutation rounds (feedback loop)

    # Resolver trust (puredns-style): health-check resolvers and drop any that
    # are poisoned / hijacked / lying before using them for mass resolution.
    validate_resolvers: bool = True
    resolvers_file: str | None = None  # newline-separated resolver IPs
    # Use the bundled curated public-resolver list when no custom list is given.
    use_bundled_resolvers: bool = False

    # massdns acceleration (optional): when the binary is available, large
    # active-resolution batches are pushed through it for native throughput;
    # otherwise everything falls back to the async Python resolver.
    use_massdns: bool = True            # auto-use massdns if found
    massdns_path: str | None = None     # explicit binary path (else search PATH)
    massdns_min_names: int = 500        # only accelerate batches at/above this size

    # Resume / checkpointing: persist confirmed live hosts so an interrupted
    # large scan can be re-run without losing (or re-emitting) prior work.
    checkpoint_path: str | None = None

    # Recursive enumeration (re-enumerate discovered subdomains as new roots)
    recursive: bool = False
    recursion_depth: int = 1        # how many levels deep to recurse
    recursion_max_roots: int = 50   # safety cap on recursive roots per level

    # Subdomain takeover detection
    takeover: bool = False

    # ASN / netblock reverse-DNS sweep: find IP ranges owned by the target org
    # and PTR-resolve them to discover hosts no public source lists.
    asn_sweep: bool = False
    asn_max_hosts: int = 8192       # safety cap on IPs swept per netblock
    asn_max_blocks: int = 20        # safety cap on netblocks swept

    # TLS certificate grabbing: connect to live hosts on 443 and read SANs.
    tls_grab: bool = False
    tls_port: int = 443

    # Output behaviour
    stream: bool = False            # print live hosts as they are discovered

    # Resolvers used for DNS lookups (public, override as needed)
    nameservers: list[str] = field(
        default_factory=lambda: ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
    )

    # Optional API keys (read from env)
    virustotal_key: str | None = field(default_factory=lambda: _env("SUBSCOUT_VIRUSTOTAL_KEY"))
    securitytrails_key: str | None = field(default_factory=lambda: _env("SUBSCOUT_SECURITYTRAILS_KEY"))
    shodan_key: str | None = field(default_factory=lambda: _env("SUBSCOUT_SHODAN_KEY"))
    chaos_key: str | None = field(default_factory=lambda: _env("SUBSCOUT_CHAOS_KEY"))
    bufferover_key: str | None = field(default_factory=lambda: _env("SUBSCOUT_BUFFEROVER_KEY"))
    fullhunt_key: str | None = field(default_factory=lambda: _env("SUBSCOUT_FULLHUNT_KEY"))
    leakix_key: str | None = field(default_factory=lambda: _env("SUBSCOUT_LEAKIX_KEY"))
    censys_id: str | None = field(default_factory=lambda: _env("SUBSCOUT_CENSYS_ID"))
    censys_secret: str | None = field(default_factory=lambda: _env("SUBSCOUT_CENSYS_SECRET"))
    bevigil_key: str | None = field(default_factory=lambda: _env("SUBSCOUT_BEVIGIL_KEY"))
