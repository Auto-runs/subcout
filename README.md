# subscout

A modular subdomain **reconnaissance engine** for **authorized** security
testing (your own assets, or targets explicitly in scope for a bug bounty /
pentest engagement).

It combines passive enumeration, active DNS brute-forcing, name permutations,
recursive enumeration, DNS resolution (with wildcard filtering), HTTP probing,
ASN/netblock reverse-DNS sweeps, TLS certificate harvesting, technology
fingerprinting, and subdomain-takeover detection - in one clean, extensible
Python package.

> [!IMPORTANT]
> Passive enumeration is harmless, but **brute-force, permutations, probing,
> ASN sweeps and TLS grabbing are active** - they send traffic that touches the
> target's infrastructure. Only run them against domains you own or are
> explicitly authorized to test. You are responsible for staying in scope and
> respecting each data source's terms of service and rate limits.

## What it does

```
        passive sources ─┐
                         ├─► merge + scope guard ─► resolve (wildcard filter)
   active brute-force ───┤                              │
   name permutations ────┤                              ▼
   ASN reverse-DNS ──────┤                   recurse on discoveries (bounded)
   TLS cert SANs ────────┘                              │
                                                         ▼
                            HTTP probe + fingerprint  +  takeover detection
```

### Features

- **30+ passive sources** (and growing via JSON) - keyless CT-log, DNS-dataset,
  and web-archive sources (crt.sh, CertSpotter, HackerTarget, AlienVault OTX,
  Anubis, RapidDNS, Wayback, urlscan.io, CommonCrawl, ThreatCrowd, BufferOver,
  subdomain.center, Digitorus, SiteDossier, ShrewdEye, c99, ...) plus key-gated
  ones that auto-skip when no key is set (Chaos, SecurityTrails, Censys,
  FullHunt, LeakIX, VirusTotal, Shodan, BeVigil). Run `subscout --list-sources`
  to see the live count. Every source is deduplicated by endpoint - no padding.
- **Active DNS brute-force** (`--brute`) with a built-in wordlist (or your own).
- **Permutations / mutations** (`--permutations`) - altdns/gotator-style: turns
  `api.example.com` into `api-dev`, `dev-api`, `api2`, `staging.api`, ... and
  resolves them. This is how you find assets no public source has listed.
- **Target-derived wordlist + iterative mutation** (BBOT-style feedback loop) -
  mines labels from names already discovered (e.g. `prod`, `v2`, `edge`,
  internal codenames), builds a target-specific wordlist, and re-mutates over
  multiple rounds (`--mutation-rounds`) until it stops finding new hosts. This
  surfaces compound names like `edge-api` that no static wordlist contains.
- **Recursive enumeration** (`--recursive`) - discovered subdomains become new
  roots, bounded by `--depth` and a per-level cap.
- **ASN / netblock reverse-DNS sweep** (`--asn`) - discovers the IP ranges that
  resolved hosts live in (via RDAP), then PTR-resolves those ranges to find
  in-scope hosts that no certificate log or DNS dataset ever listed. Bounded by
  `--asn-max-hosts` / `--asn-max-blocks`.
- **TLS certificate harvesting** (`--tls-grab`) - connects to live hosts on 443
  and reads the certificate's Subject Alternative Names, surfacing sibling
  hostnames issued on the same cert.
- **Technology fingerprinting** - the HTTP probe infers the CDN/WAF (Cloudflare,
  Akamai, Fastly, CloudFront, ...) and stack (nginx, WordPress, Django, React,
  ...) from headers and body, recorded in `json`/`csv` output.
- **Per-source rate-limiting + retry/backoff** - each source has its own
  token-bucket (`--source-rate-limit`) and transient failures (429/5xx, network
  errors) are retried with exponential backoff, so you stay polite and resilient.
- **Streaming output** (`--stream`) - prints live subdomains to stderr the moment
  they're confirmed, so large scans give immediate feedback.
- **Trusted-resolver validation** (puredns-style) - health-checks every DNS
  resolver before mass resolution and drops any that hijack NXDOMAIN (captive
  portals / poisoned / lying resolvers), so brute-force stays fast *and* clean.
  Load a big resolver list with `--resolvers-file`.
- **Wildcard-DNS detection** - random-label probes (including multi-level
  `*.*.domain`) filter wildcard false positives, by IP *and* by CNAME target.
- **Fast resolver** - single A-query per name with the CNAME read straight from
  the answer chain (1 query instead of 3), resolver rotation, and high
  concurrency (200 by default). Tune with `--dns-concurrency` / `--dns-timeout`.
- **Scope guard** - every result is constrained to the original target domain.
- **HTTP probe** (`--probe`) - status, final URL, page title, Server header.
- **Subdomain takeover detection** (`--takeover`) - flags dangling CNAMEs that
  point at unclaimed third-party services (GitHub Pages, S3, Heroku, ...).
- **Clean output** - `txt` (pipe-friendly), `json`, or `csv`.
- **Declarative source catalog** - most sources are defined as JSON entries in
  `subscout/sources/data/sources.json`, so the catalog scales to dozens/hundreds
  of sources **without writing code**. Coded plugins handle the complex cases.
- **Built-in benchmark harness** (`subscout-bench`) - run head-to-head against
  subfinder / amass / bbot and get hard numbers: count, time, unique finds.

## Adding sources without code

Most sources are just a JSON object. Append one to
`subscout/sources/data/sources.json` and it is picked up automatically:

```json
{
  "name": "mysource",
  "url": "https://api.example.com/subs?domain={domain}",
  "parse": "json_objects",
  "fields": ["hostname"],
  "headers": {"x-apikey": "$MYKEY"},
  "requires_key": "$MYKEY"
}
```

Parsers available: `text_hosts`, `text_lines`, `json_list`, `json_objects`,
`json_hosts`. Use `"join_domain": true` for sources that return bare labels.
For non-trivial logic (pagination, multi-endpoint), write a coded plugin instead
(subclass `Source`, decorate with `@register`).

## Benchmarking (prove it)

```bash
# Compare against whatever is installed (missing tools are skipped)
python -m subscout.bench example.com --tools subscout,subfinder,amass,bbot

# Fair passive-only comparison, write a JSON report
python -m subscout.bench -l targets.txt --passive-only --json report.json
```

Output shows, per tool: subdomains found, wall-clock time, unique finds (what
only that tool saw), and discovery rate per second.

## Install

Requires Python 3.10+.

```bash
cd subscout
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
# or install as a command:  pip install .
```

## Usage

```bash
# Passive only, no DNS (quietest)
python -m subscout example.com --no-resolve

# Passive + resolve, keep only live names
python -m subscout example.com --only-resolved

# Active: passive + brute-force + permutations
python -m subscout example.com --brute --permutations --only-resolved

# Recursive, 2 levels deep
python -m subscout example.com --brute --recursive --depth 2

# Everything: brute + permutations + recursive + probe + takeover + asn + tls
python -m subscout example.com --all -f json -o results.json

# Deep active recon with streaming feedback + a big resolver list
python -m subscout example.com --brute --permutations --asn --tls-grab \
    --stream --resolvers-file resolvers.txt --only-resolved

# Custom wordlist (merged with the built-in one)
python -m subscout example.com --brute --wordlist /path/to/dns-wordlist.txt

# Several domains / a file of domains / pick sources
python -m subscout a.com b.com
python -m subscout -l scope.txt -o subs.txt
python -m subscout example.com -s crtsh,certspotter,wayback
python -m subscout --list-sources
```

If installed via `pip install .`, replace `python -m subscout` with `subscout`.

### Flags

| Flag | Purpose |
|------|---------|
| `--no-resolve` | passive only, skip DNS |
| `--only-resolved` | drop names that don't resolve |
| `-b, --brute` | active DNS brute-force from a wordlist |
| `-w, --wordlist FILE` | custom wordlist (merged with built-in) |
| `--no-default-wordlist` | use only the custom wordlist |
| `-p, --permutations` | mutate known names and resolve them |
| `--mutation-rounds N` | iterative permutation rounds (feedback loop, default 2) |
| `--no-derive-wordlist` | don't mine a target-specific wordlist from finds |
| `-r, --recursive` / `--depth N` | recurse into discoveries, N levels |
| `--max-recursive-roots N` | cap recursive roots per level (default 50) |
| `--permutation-limit N` | cap permutation candidates per root |
| `--asn` | ASN/netblock reverse-DNS sweep (hosts beyond public sources) |
| `--tls-grab` | harvest cert SAN names from live hosts on 443 |
| `--probe` | HTTP(S) probe resolved hosts (+ CDN/tech fingerprint) |
| `--takeover` | flag subdomain-takeover candidates |
| `--stream` | print live subdomains to stderr as they're found |
| `--all` | brute + permutations + recursive + probe + takeover + asn + tls |
| `--no-wildcard-filter` | keep wildcard-DNS hits |
| `--wildcard-probes N` | random labels probed for wildcard detection |
| `--no-fast-resolve` | query A+AAAA+CNAME separately (slower, exhaustive) |
| `--source-rate-limit R` | max requests/sec per source (0 = unlimited) |
| `-f {txt,json,csv}` / `-o FILE` | output format / file |
| `--resolvers 1.1.1.1,8.8.8.8` | custom DNS resolvers |
| `--resolvers-file FILE` | newline-separated resolver IPs for mass resolution |
| `--no-validate-resolvers` | skip resolver health-check |
| `--timeout`, `--dns-timeout`, `--dns-concurrency`, `--http-concurrency`, `--source-concurrency` | tuning |
| `-v` / `-q` | verbose / quiet |

### Optional API keys

Set in the environment to unlock key-gated sources (skipped silently if unset):

```bash
export SUBSCOUT_CHAOS_KEY=...          # ProjectDiscovery Chaos
export SUBSCOUT_SECURITYTRAILS_KEY=...
export SUBSCOUT_VIRUSTOTAL_KEY=...
export SUBSCOUT_FULLHUNT_KEY=...
export SUBSCOUT_LEAKIX_KEY=...
export SUBSCOUT_BUFFEROVER_KEY=...
export SUBSCOUT_CENSYS_ID=...  SUBSCOUT_CENSYS_SECRET=...
export SUBSCOUT_SHODAN_KEY=...         # reserved for future source
```

## Add a new source

Create `subscout/sources/mysource.py`:

```python
import aiohttp
from subscout.sources.base import Source, register

@register
class MySource(Source):
    name = "mysource"

    async def fetch(self, session: aiohttp.ClientSession, domain: str) -> set[str]:
        data = await self._get_json(session, f"https://api.example/{domain}")
        return {row["host"] for row in (data or [])}
```

Import it in `subscout/sources/__init__.py` and it shows up automatically. For
key-gated sources, set `requires_key = True` and override `enabled()`.

## Project layout

```
subscout/
  cli.py        # argparse + orchestration entrypoint
  engine.py     # recursive pipeline: passive -> resolve -> brute -> permute -> asn -> tls
  resolver.py   # async DNS + wildcard detection + health-check + reverse DNS
  brute.py      # active DNS brute-force
  permute.py    # altdns/gotator-style name mutations
  asn.py        # ASN/netblock discovery + reverse-DNS sweep
  tlsgrab.py    # TLS certificate SAN harvesting
  takeover.py   # dangling-CNAME takeover detection + fingerprint DB
  prober.py     # async HTTP probing
  fingerprint.py# CDN/WAF/tech signature detection
  ratelimit.py  # token-bucket rate limiter + retry/backoff
  wordlists.py  # built-in wordlist + target-derived mining
  bench.py      # head-to-head benchmark harness
  output.py     # txt / json / csv writers
  config.py     # tunables + env-based API keys
  models.py     # Subdomain dataclass
  utils.py      # normalisation, scope guard, host extraction
  sources/      # passive data sources (coded plugins + JSON catalog)
```

## How this compares to the big tools

Honest positioning: mature tools like **subfinder**, **amass**, and **BBOT**
have far more data sources, Go/massdns performance at huge scale, and years of
battle-testing behind large communities. subscout doesn't claim to beat them on
raw coverage or speed at massive scale - that needs a live benchmark (see
`subscout-bench`), and Go + massdns still has a native edge for millions of names.

Where subscout is genuinely competitive is **technique coverage in one clean,
hackable package**: passive (30+ sources, JSON-extensible) + active brute-force +
target-derived iterative mutations + recursion + ASN reverse-DNS + TLS SAN
harvesting + trusted-resolver validation + wildcard handling + HTTP
fingerprinting + takeover detection - with a strict scope guard on by default.
It's small enough to read in an afternoon and extend in minutes, which is exactly
why building your own is worthwhile.

To push raw coverage further, add sources (JSON entries) and plug in a large
resolver list + wordlist (e.g. SecLists).

## Development

```bash
pip install -e ".[dev]"
ruff check subscout tests     # lint
pytest                        # 51 unit tests, no network required
```

CI (GitHub Actions) runs ruff + pytest on Python 3.10/3.11/3.12 for every push
and pull request. The test suite stubs DNS/HTTP so it runs anywhere; real
network behaviour is validated manually against authorized targets.

## License

MIT. Provided for lawful, authorized use only.
