"""Base class and registry for passive subdomain sources.

Two ways to add a source:

1. **Coded** - subclass `Source`, set a `name`, implement `fetch`, decorate
   with `@register`. Use this for sources with non-trivial logic (pagination,
   auth dances, multi-endpoint merging).

2. **Declarative** - add an entry to ``sources/data/sources.json`` and it is
   loaded automatically (see ``subscout.sources.declarative``). Use this for
   the common case (one GET, extract hosts). This is what lets the source
   catalog scale to dozens/hundreds without writing code.

Both paths feed the same registry, which stores lightweight `SourceProvider`
descriptors so listing/instantiation works uniformly.
"""
from __future__ import annotations

import abc
import logging
from dataclasses import dataclass
from typing import Callable, Iterable, Type

import aiohttp

from subscout.config import Config
from subscout.ratelimit import RateLimiter, retry_request

logger = logging.getLogger("subscout")


@dataclass(frozen=True)
class SourceProvider:
    """A registry entry that can describe and instantiate a source."""

    name: str
    requires_key: bool
    factory: Callable[[Config], "Source"]

    def create(self, config: Config) -> "Source":
        return self.factory(config)


# Registry keyed by lowercase source name.
_REGISTRY: dict[str, SourceProvider] = {}


def register_provider(provider: SourceProvider) -> SourceProvider:
    """Register a SourceProvider (used by both coded and declarative sources)."""
    key = provider.name.lower()
    if key in _REGISTRY:
        raise ValueError(f"duplicate source name: {provider.name!r}")
    _REGISTRY[key] = provider
    return provider


def register(cls: Type["Source"]) -> Type["Source"]:
    """Class decorator that registers a coded Source subclass."""
    register_provider(
        SourceProvider(
            name=cls.name,
            requires_key=cls.requires_key,
            factory=lambda cfg, c=cls: c(cfg),
        )
    )
    return cls


def all_sources() -> list[SourceProvider]:
    return list(_REGISTRY.values())


def get_sources(names: Iterable[str] | None = None) -> list[SourceProvider]:
    """Return source providers, optionally filtered by a list of names."""
    if not names:
        return all_sources()
    wanted = {n.lower() for n in names}
    unknown = wanted - set(_REGISTRY)
    if unknown:
        raise ValueError(f"unknown source(s): {', '.join(sorted(unknown))}")
    return [_REGISTRY[n] for n in wanted]


class Source(abc.ABC):
    """A passive data source that yields candidate subdomains for a domain."""

    #: Short, unique identifier used on the CLI and in result metadata.
    name: str = "base"
    #: Set to True for sources that require an API key.
    requires_key: bool = False

    def __init__(self, config: Config) -> None:
        self.config = config
        self._limiter = RateLimiter(config.source_rate_limit)

    def enabled(self) -> bool:
        """Override to disable a source when its API key is missing."""
        return True

    def health_url(self, domain: str) -> str | None:
        """Return a representative endpoint URL for reachability checks.

        Used by ``--health-check-sources`` to probe whether the upstream
        endpoint is alive. Coded sources may override; returning None means
        "no single URL to probe" (the checker then relies on a fetch count).
        """
        return None

    @abc.abstractmethod
    async def fetch(self, session: aiohttp.ClientSession, domain: str) -> set[str]:
        """Return a set of raw candidate hostnames for *domain*.

        Implementations should never raise; on error they log and return an
        empty set so one flaky source cannot abort the whole run.
        """
        raise NotImplementedError

    # ---- small shared HTTP helpers -------------------------------------

    async def _get_text(self, session: aiohttp.ClientSession, url: str, **kw) -> str | None:
        async def call():
            await self._limiter.acquire()
            async with session.get(url, **kw) as resp:
                if resp.status == 200:
                    return resp.status, await resp.text()
                return resp.status, None

        status, value = await retry_request(
            call,
            retries=self.config.retries,
            backoff_base=self.config.backoff_base,
            retry_statuses=self.config.retry_statuses,
            label=f"{self.name} {url}",
        )
        if status != 200:
            logger.debug("%s: %s -> HTTP %s", self.name, url, status)
        return value

    async def _get_json(self, session: aiohttp.ClientSession, url: str, **kw):
        async def call():
            await self._limiter.acquire()
            async with session.get(url, **kw) as resp:
                if resp.status == 200:
                    return resp.status, await resp.json(content_type=None)
                return resp.status, None

        status, value = await retry_request(
            call,
            retries=self.config.retries,
            backoff_base=self.config.backoff_base,
            retry_statuses=self.config.retry_statuses,
            label=f"{self.name} {url}",
        )
        if status != 200:
            logger.debug("%s: %s -> HTTP %s", self.name, url, status)
        return value
