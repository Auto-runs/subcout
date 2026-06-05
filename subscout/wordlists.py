"""Built-in subdomain wordlist + loader for active brute-forcing.

The embedded list is intentionally compact (common, high-signal labels) so the
tool works out of the box. For serious work, point `--wordlist` at a large list
(e.g. SecLists' DNS wordlists). Loading merges the built-in list with any custom
file unless `--no-default-wordlist` is used.
"""
from __future__ import annotations

import logging
import re

logger = logging.getLogger("subscout")

# Curated common subdomain labels. Deduplicated, lowercase, no dots.
DEFAULT_WORDLIST: tuple[str, ...] = (
    "www", "mail", "smtp", "pop", "pop3", "imap", "webmail", "email", "mx",
    "ns", "ns1", "ns2", "ns3", "ns4", "dns", "dns1", "dns2", "mx1", "mx2",
    "ftp", "sftp", "ssh", "vpn", "remote", "gateway", "gw", "proxy", "router",
    "api", "api1", "api2", "apis", "api-dev", "api-staging", "api-prod",
    "rest", "graphql", "grpc", "ws", "websocket", "gateway-api",
    "dev", "development", "devel", "test", "testing", "qa", "uat", "stage",
    "staging", "stg", "prod", "production", "preprod", "demo", "sandbox",
    "beta", "alpha", "canary", "preview", "next", "new", "old", "legacy",
    "admin", "administrator", "adm", "manage", "manager", "management",
    "console", "control", "controlpanel", "cpanel", "panel", "dashboard",
    "portal", "account", "accounts", "auth", "sso", "login", "signin",
    "oauth", "id", "identity", "idp", "secure", "security",
    "app", "apps", "application", "web", "web1", "web2", "mobile", "m",
    "static", "assets", "cdn", "img", "images", "media", "video", "videos",
    "files", "file", "download", "downloads", "upload", "uploads", "share",
    "docs", "doc", "documentation", "wiki", "kb", "help", "support",
    "helpdesk", "ticket", "tickets", "status", "uptime", "health",
    "blog", "news", "press", "forum", "forums", "community", "social",
    "shop", "store", "cart", "checkout", "pay", "payment", "payments",
    "billing", "invoice", "order", "orders", "ecommerce",
    "db", "database", "sql", "mysql", "postgres", "postgresql", "mssql",
    "oracle", "mongo", "mongodb", "redis", "memcached", "cassandra",
    "elastic", "elasticsearch", "kibana", "logstash", "grafana", "prometheus",
    "git", "gitlab", "github", "bitbucket", "svn", "repo", "repos", "code",
    "ci", "cd", "jenkins", "build", "deploy", "deployment", "pipeline",
    "registry", "docker", "k8s", "kubernetes", "rancher", "nexus", "artifactory",
    "internal", "intranet", "corp", "corporate", "private", "local", "lan",
    "office", "hr", "finance", "legal", "sales", "marketing", "crm", "erp",
    "monitor", "monitoring", "metrics", "logs", "log", "syslog", "stats",
    "analytics", "tracking", "track", "data", "datalake", "warehouse", "bi",
    "backup", "backups", "bak", "archive", "old-site", "temp", "tmp",
    "smtp2", "mail2", "ns0", "owa", "exchange", "lync", "sip", "voip", "pbx",
    "cloud", "aws", "azure", "gcp", "s3", "storage", "bucket", "object",
    "lb", "loadbalancer", "edge", "origin", "cache", "varnish", "nginx",
    "test1", "test2", "dev1", "dev2", "demo1", "demo2", "v1", "v2", "v3",
    "client", "clients", "customer", "customers", "partner", "partners",
    "vendor", "service", "services", "svc", "micro", "ms", "node", "worker",
    "jobs", "queue", "broker", "kafka", "rabbitmq", "mq", "event", "events",
    "notify", "notification", "notifications", "push", "sms", "voice",
    "chat", "im", "meet", "conference", "webinar", "stream", "live", "rtmp",
)


def load_wordlist(
    path: str | None = None, include_default: bool = True
) -> list[str]:
    """Return a clean, de-duplicated wordlist.

    Combines the built-in list (unless disabled) with an optional file. Each
    line in the file is treated as one label; blanks and comments are skipped.
    """
    words: dict[str, None] = {}

    if include_default:
        for w in DEFAULT_WORDLIST:
            words.setdefault(w, None)

    if path:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    label = line.strip().lower()
                    if not label or label.startswith("#"):
                        continue
                    # A wordlist holds labels, not full hosts; keep first label.
                    label = label.lstrip(".").split(".", 1)[0]
                    if label:
                        words.setdefault(label, None)
        except OSError as exc:
            logger.error("could not read wordlist %s: %s", path, exc)

    return list(words)


# Token splitter for mining labels: break on non-alphanumeric and on the
# digit<->letter boundary so "api2v3" -> {"api", "2", "v", "3"} and
# "prod-api-v2" -> {"prod", "api", "v2", "v", "2"}.
_SPLIT = re.compile(r"[^a-z0-9]+")
_DIGIT_BOUNDARY = re.compile(r"(?<=[a-z])(?=\d)|(?<=\d)(?=[a-z])")
_NUMERIC = re.compile(r"^\d+$")


def derive_words_from_names(names, root: str, min_len: int = 2) -> list[str]:
    """Mine candidate labels from already-discovered hostnames (BBOT-style).

    Splits every sub-label of every in-scope name into tokens and returns the
    unique set, ordered by frequency (most common first). This produces a
    *target-specific* wordlist that often beats a generic one because real
    naming conventions (``corp``, ``v2``, ``edge``, internal codenames) recur.
    """
    suffix = "." + root
    freq: dict[str, int] = {}

    for raw in names:
        name = str(raw).lower().strip(".")
        if name == root:
            continue
        if name.endswith(suffix):
            sub = name[: -len(suffix)]
        elif name.endswith(root):
            continue
        else:
            sub = name
        for label in sub.split("."):
            # whole label is itself a useful token
            _bump(freq, label, min_len)
            # split into sub-tokens on separators
            for tok in _SPLIT.split(label):
                _bump(freq, tok, min_len)
                # split letter/digit boundaries
                for piece in _DIGIT_BOUNDARY.split(tok):
                    _bump(freq, piece, min_len)

    return sorted(freq, key=lambda w: (-freq[w], w))


def _bump(freq: dict[str, int], token: str, min_len: int) -> None:
    token = token.strip("-_")
    if not token or len(token) < min_len:
        return
    if _NUMERIC.match(token) and len(token) > 3:
        return  # skip long pure-number noise like years/ids
    freq[token] = freq.get(token, 0) + 1
