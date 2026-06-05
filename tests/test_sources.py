"""Tests for the source registry and declarative source parsing."""
import asyncio

import pytest

from subscout.config import Config
from subscout.sources.base import all_sources, get_sources
from subscout.sources.declarative import DeclarativeSource


def test_registry_unique_and_populated():
    providers = all_sources()
    names = [p.name for p in providers]
    assert len(names) == len(set(names)), "duplicate source names"
    assert len(names) >= 30


def test_get_sources_unknown_raises():
    with pytest.raises(ValueError):
        get_sources(["definitely-not-a-source"])


def test_provider_create():
    s = get_sources(["crtsh"])[0].create(Config())
    assert s.name == "crtsh"


# ---- declarative parser tests use a per-test fake session ----

class _Resp:
    def __init__(self, status, body):
        self.status = status
        self._body = body

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return False

    async def text(self):
        return self._body


class _Session:
    def __init__(self, status, body):
        self._status = status
        self._body = body

    def request(self, method, url, **kw):
        return _Resp(self._status, self._body)


def _fetch(spec, status, body, cfg=None, domain="example.com"):
    src = DeclarativeSource(cfg or Config(), spec)
    return asyncio.run(src.fetch(_Session(status, body), domain))


def test_text_lines_split():
    spec = {"name": "t", "url": "http://x/{domain}", "parse": "text_lines", "split": ","}
    out = _fetch(spec, 200, "api.example.com,1.2.3.4\nwww.example.com,5.6.7.8\n")
    assert out == {"api.example.com", "www.example.com"}


def test_json_objects_list_field():
    spec = {"name": "t", "url": "http://x/{domain}", "parse": "json_objects",
            "fields": ["dns_names"]}
    out = _fetch(spec, 200, '[{"dns_names":["a.example.com","b.example.com"]}]')
    assert {"a.example.com", "b.example.com"} <= out


def test_json_list_join_domain():
    spec = {"name": "t", "url": "http://x/{domain}", "parse": "json_list",
            "json_path": ["subdomains"], "join_domain": True}
    out = _fetch(spec, 200, '{"subdomains":["www","api"]}')
    assert out == {"www.example.com", "api.example.com"}


def test_non_200_is_empty():
    spec = {"name": "t", "url": "http://x/{domain}", "parse": "text_hosts"}
    assert _fetch(spec, 500, "boom") == set()


def test_requires_key_disables_without_key():
    spec = {"name": "t", "url": "u", "requires_key": "$VT", "headers": {"x-apikey": "$VT"}}
    src = DeclarativeSource(Config(), spec)
    assert src.enabled() is False
    cfg = Config()
    cfg.virustotal_key = "KEY"
    src2 = DeclarativeSource(cfg, spec)
    assert src2.enabled() is True
    assert src2._headers() == {"x-apikey": "KEY"}
