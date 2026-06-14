"""Tests for subdomain-takeover fingerprint matching."""
from subscout.takeover import DATA_FILE, FINGERPRINTS, _load_fingerprints, match_fingerprints


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


def test_db_loaded_from_json_is_large():
    # The external catalog should be substantially bigger than the fallback.
    loaded = _load_fingerprints(DATA_FILE)
    assert len(loaded) >= 40
    services = {fp.service for fp in loaded}
    assert {"Vercel", "Netlify", "Microsoft Azure"} <= services


def test_missing_catalog_uses_fallback(tmp_path):
    fallback = _load_fingerprints(tmp_path / "does-not-exist.json")
    assert len(fallback) >= 1
    assert any(fp.service == "GitHub Pages" for fp in fallback)


def test_nxdomain_flag_present_for_azure():
    azure = [fp for fp in FINGERPRINTS if fp.service == "Microsoft Azure"]
    assert azure and azure[0].nxdomain is True
