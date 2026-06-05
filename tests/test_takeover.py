"""Tests for subdomain-takeover fingerprint matching."""
from subscout.takeover import FINGERPRINTS, match_fingerprints


def test_known_services_match():
    assert any(fp.service == "GitHub Pages" for fp in match_fingerprints("u.github.io"))
    assert any(fp.service == "Amazon S3" for fp in match_fingerprints("x.s3.amazonaws.com"))
    assert any(fp.service == "Heroku" for fp in match_fingerprints("a.herokudns.com"))


def test_no_match_cases():
    assert match_fingerprints("example.com") == []
    assert match_fingerprints(None) == []
    assert match_fingerprints("") == []


def test_fingerprint_db_wellformed():
    assert len(FINGERPRINTS) >= 10
    for fp in FINGERPRINTS:
        assert fp.service and fp.cname_patterns
