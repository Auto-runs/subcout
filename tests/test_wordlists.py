"""Tests for the wordlist loader and target-derived mining."""
from subscout.wordlists import (
    DEFAULT_WORDLIST,
    derive_words_from_names,
    load_wordlist,
)


def test_load_merges_and_dedupes(tmp_path):
    f = tmp_path / "wl.txt"
    f.write_text("# comment\nadmin\nADMIN\ncustomword\nsub.with.dots\n\n")
    words = load_wordlist(str(f), include_default=True)
    assert "customword" in words
    assert "sub" in words and "sub.with.dots" not in words
    assert words.count("admin") == 1
    assert len(words) > len(DEFAULT_WORDLIST)


def test_load_custom_only(tmp_path):
    f = tmp_path / "wl.txt"
    f.write_text("customword\n")
    only = load_wordlist(str(f), include_default=False)
    assert "customword" in only and "www" not in only


def test_derive_mines_tokens_and_boundaries():
    names = {
        "prod-api-v2.example.com",
        "dev.corp.example.com",
        "edge-cache.example.com",
        "api.example.com",
        "example.com",
    }
    words = derive_words_from_names(names, "example.com")
    for expected in ("prod", "api", "v2", "corp", "dev", "edge", "cache"):
        assert expected in words


def test_derive_frequency_ordering():
    names = {"api.example.com", "api-x.example.com", "corp.example.com"}
    words = derive_words_from_names(names, "example.com")
    assert words.index("api") < words.index("corp")


def test_derive_ignores_apex_and_long_numbers():
    words = derive_words_from_names({"20231231.example.com", "example.com"}, "example.com")
    assert "20231231" not in words
