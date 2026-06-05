"""Shared helpers: logging, domain normalisation, and scope enforcement."""
from __future__ import annotations

import logging
import re
import sys

# A reasonably strict hostname label pattern. Allows '*' so we can recognise
# (and later strip / handle) wildcard entries that some sources return.
_LABEL = r"(?:[a-zA-Z0-9_*](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9])?)"
_HOSTNAME_RE = re.compile(rf"^(?:{_LABEL}\.)+{_LABEL}$")


def setup_logging(verbose: bool = False, quiet: bool = False) -> logging.Logger:
    """Configure and return the package logger.

    Logs go to stderr so stdout stays clean for piping results.
    """
    logger = logging.getLogger("subscout")
    logger.handlers.clear()

    if quiet:
        level = logging.ERROR
    elif verbose:
        level = logging.DEBUG
    else:
        level = logging.INFO

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False
    return logger


def normalize_domain(value: str) -> str:
    """Lowercase, strip scheme/port/paths and trailing dots from a host."""
    value = value.strip().lower()
    # Drop a scheme if someone pasted a URL.
    value = re.sub(r"^[a-z]+://", "", value)
    # Drop anything after the authority (path, query) and any port.
    value = value.split("/")[0].split("?")[0].split("#")[0]
    value = value.split(":")[0]
    # Strip a leading wildcard / leading dot and trailing dot.
    if value.startswith("*."):
        value = value[2:]
    return value.strip(".")


def is_valid_hostname(name: str) -> bool:
    """Return True if *name* looks like a valid DNS hostname (<=253 chars)."""
    if not name or len(name) > 253:
        return False
    return bool(_HOSTNAME_RE.match(name))


def in_scope(name: str, root: str) -> bool:
    """True if *name* is *root* itself or a subdomain of *root*.

    This is the scope guard: it prevents a misbehaving source from leaking
    unrelated domains into your results.
    """
    name = name.lower().strip(".")
    root = root.lower().strip(".")
    return name == root or name.endswith("." + root)


def extract_hosts(text: str, root: str) -> set[str]:
    """Pull every `<something>.<root>` token out of arbitrary text/HTML.

    Useful for sources that return HTML pages or URL lists rather than JSON.
    """
    pattern = re.compile(
        rf"(?:[a-zA-Z0-9_*](?:[a-zA-Z0-9_-]{{0,61}}[a-zA-Z0-9])?\.)+{re.escape(root)}",
        re.IGNORECASE,
    )
    return set(pattern.findall(text))


def clean_candidate(raw: str, root: str) -> str | None:
    """Normalise a raw source result and keep it only if it is valid + in scope."""
    name = normalize_domain(raw)
    if not name or "*" in name:
        return None
    if not is_valid_hostname(name):
        return None
    if not in_scope(name, root):
        return None
    return name
