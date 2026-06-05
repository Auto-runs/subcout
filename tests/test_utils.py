"""Tests for normalisation, scope guard, and host extraction."""
from subscout.utils import (
    clean_candidate,
    extract_hosts,
    in_scope,
    is_valid_hostname,
    normalize_domain,
)


def test_normalize_strips_scheme_port_path():
    assert normalize_domain("https://API.Example.com:443/path?x=1") == "api.example.com"
    assert normalize_domain("*.example.com.") == "example.com"


def test_scope_guard_rejects_suffix_trick():
    assert in_scope("a.example.com", "example.com")
    assert in_scope("example.com", "example.com")
    assert not in_scope("evil-example.com", "example.com")
    assert not in_scope("notexample.com", "example.com")
    assert not in_scope("example.com.evil.com", "example.com")


def test_hostname_validation():
    assert is_valid_hostname("a.b.example.com")
    assert not is_valid_hostname("bad_host..com")
    assert not is_valid_hostname("")
    assert not is_valid_hostname("x" * 254)


def test_clean_candidate():
    assert clean_candidate("dev.example.com", "example.com") == "dev.example.com"
    assert clean_candidate("https://shop.example.com/cart", "example.com") == "shop.example.com"
    assert clean_candidate("*.*.example.com", "example.com") is None
    assert clean_candidate("other.com", "example.com") is None


def test_extract_hosts():
    text = "see http://a.example.com/x and b.example.com, evil.com and c.sub.example.com."
    assert extract_hosts(text, "example.com") == {
        "a.example.com", "b.example.com", "c.sub.example.com",
    }
