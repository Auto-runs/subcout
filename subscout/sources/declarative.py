"""Declarative (data-driven) sources.

A declarative source is described by a small JSON object, not Python code. This
lets the catalog grow to dozens/hundreds of sources without writing a class for
each one - the same approach mature tools use to stay maintainable.

Schema (one object per source in ``data/sources.json``):

    {
      "name": "hackertarget",          # unique id
      "url": "https://api.../{domain}",# {domain} is substituted
      "method": "GET",                 # GET (default) or POST
      "parse": "json_list",            # how to read the response (see below)
      "json_path": ["passive_dns"],    # for json_* parsers: keys to descend
      "fields": ["hostname"],          # for json_objects: object keys to read
      "headers": {"x-apikey": "$VT"},  # $NAME -> config attr / env (optional)
      "requires_key": "$VT",           # if set, source disables when key absent
      "split": ",",                    # for text parsers: take first column
      "paginate": {...}                # optional, see _paginate
    }

Parsers:
    text_hosts   - regex-extract every <sub>.<domain> token from the body
    text_lines   - one host per line (optionally take column [split][0])
    json_list    - JSON array of strings (after descending json_path)
    json_objects - JSON array of objects; read each object's `fields`
    json_hosts   - regex-extract hosts from the raw JSON text (schema-agnostic)
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

import aiohttp

from subscout.config import Config
from subscout.ratelimit import retry_request
from subscout.sources.base import Source, SourceProvider, register_provider
from subscout.utils import extract_hosts

logger = logging.getLogger("subscout")

DATA_FILE = Path(__file__).with_name("data") / "sources.json"

# Map a "$NAME" token to a Config attribute (falls back to env var SUBSCOUT_NAME).
_KEY_ATTRS = {
    "$VT": "virustotal_key",
    "$SECURITYTRAILS": "securitytrails_key",
    "$SHODAN": "shodan_key",
    "$CHAOS": "chaos_key",
    "$BUFFEROVER": "bufferover_key",
    "$FULLHUNT": "fullhunt_key",
    "$LEAKIX": "leakix_key",
    "$CENSYS_ID": "censys_id",
    "$CENSYS_SECRET": "censys_secret",
    "$BEVIGIL": "bevigil_key",
}


def _resolve_token(token: Any, config: Config) -> Any:
    """Resolve a "$NAME" token to its configured value; pass through otherwise."""
    if isinstance(token, str) and token.startswith("$"):
        attr = _KEY_ATTRS.get(token)
        if attr:
            return getattr(config, attr, None)
        return os.environ.get("SUBSCOUT_" + token[1:].upper())
    return token


class DeclarativeSource(Source):
    """A Source whose behaviour is driven entirely by a spec dict."""

    def __init__(self, config: Config, spec: dict) -> None:
        super().__init__(config)
        self.spec = spec
        self.name = spec["name"]
        self._requires = spec.get("requires_key")

    def enabled(self) -> bool:
        if not self._requires:
            return True
        return bool(_resolve_token(self._requires, self.config))

    def health_url(self, domain: str) -> str | None:
        """Resolve the spec URL for *domain* (with key substitution) for probing."""
        try:
            url = self.spec["url"].format(domain=domain)
        except (KeyError, IndexError):
            return None
        return self._substitute_url_tokens(url)

    def _headers(self) -> dict:
        out = {}
        for k, v in (self.spec.get("headers") or {}).items():
            resolved = _resolve_token(v, self.config)
            if resolved:
                out[k] = resolved
        return out

    def _parse(self, body: str, domain: str) -> set[str]:
        kind = self.spec.get("parse", "text_hosts")

        if kind == "text_hosts":
            return extract_hosts(body, domain)

        if kind == "text_lines":
            out: set[str] = set()
            split = self.spec.get("split")
            for line in body.splitlines():
                cell = line.split(split, 1)[0].strip() if split else line.strip()
                if cell:
                    out.add(cell)
            return out

        if kind == "json_hosts":
            return extract_hosts(body, domain)

        # JSON structured parsers
        try:
            data = json.loads(body)
        except (ValueError, TypeError):
            return set()

        for key in self.spec.get("json_path", []) or []:
            if isinstance(data, dict):
                data = data.get(key)
            else:
                data = None
            if data is None:
                return set()

        out = set()
        if kind == "json_list":
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, str) and item:
                        out.add(item)
        elif kind == "json_objects":
            fields = self.spec.get("fields", []) or []
            if isinstance(data, list):
                for obj in data:
                    if not isinstance(obj, dict):
                        continue
                    for f in fields:
                        val = obj.get(f)
                        if isinstance(val, str) and val:
                            out.add(val)
                        elif isinstance(val, list):
                            out.update(v for v in val if isinstance(v, str) and v)
        return out

    def _postprocess(self, hosts: set[str], domain: str) -> set[str]:
        """Optionally join bare labels onto the domain (for sources that return
        ``["www", "api"]`` rather than full hostnames)."""
        if not self.spec.get("join_domain"):
            return hosts
        out: set[str] = set()
        for h in hosts:
            h = h.strip(".")
            if not h:
                continue
            out.add(h if h.endswith(domain) else f"{h}.{domain}")
        return out

    async def fetch(self, session: aiohttp.ClientSession, domain: str) -> set[str]:
        url = self.spec["url"].format(domain=domain)
        url = self._substitute_url_tokens(url)
        if url is None:
            return set()
        method = self.spec.get("method", "GET").upper()
        headers = self._headers()
        kw: dict = {}
        if headers:
            kw["headers"] = headers

        async def call():
            await self._limiter.acquire()
            async with session.request(method, url, **kw) as resp:
                if resp.status == 200:
                    return resp.status, await resp.text()
                return resp.status, None

        status, body = await retry_request(
            call,
            retries=self.config.retries,
            backoff_base=self.config.backoff_base,
            retry_statuses=self.config.retry_statuses,
            label=f"{self.name} {url}",
        )
        if status != 200 or body is None:
            logger.debug("%s: %s -> HTTP %s", self.name, url, status)
            return set()

        return self._postprocess(self._parse(body, domain), domain)

    def _substitute_url_tokens(self, url: str) -> str | None:
        """Replace any "$NAME" key tokens embedded in the URL (e.g. ?key=$SHODAN).

        Returns None if a referenced key is unset, so the source self-skips
        instead of sending a malformed request.
        """
        for token in _KEY_ATTRS:
            if token in url:
                value = _resolve_token(token, self.config)
                if not value:
                    logger.debug("%s: missing %s, skipping", self.name, token)
                    return None
                url = url.replace(token, str(value))
        return url


def load_declarative_sources(path: Path = DATA_FILE) -> int:
    """Register every source defined in the JSON catalog. Returns the count."""
    try:
        specs = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        logger.debug("no declarative source catalog at %s", path)
        return 0
    except ValueError as exc:
        logger.error("invalid source catalog %s: %s", path, exc)
        return 0

    count = 0
    for spec in specs:
        name = spec.get("name")
        if not name:
            continue
        provider = SourceProvider(
            name=name,
            requires_key=bool(spec.get("requires_key")),
            factory=lambda cfg, s=spec: DeclarativeSource(cfg, s),
        )
        try:
            register_provider(provider)
            count += 1
        except ValueError:
            # A coded source already claimed this name; coded wins.
            logger.debug("declarative source %s skipped (name taken)", name)
    logger.debug("loaded %d declarative source(s)", count)
    return count
