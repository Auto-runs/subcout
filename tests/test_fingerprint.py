"""Tests for HTTP technology / CDN fingerprinting."""
from subscout.fingerprint import fingerprint


def test_cloudflare_and_php_and_react():
    cdn, tech = fingerprint(
        {"Server": "cloudflare", "CF-RAY": "abc", "X-Powered-By": "PHP/8.1"},
        '<html><div id="root"></div></html>',
    )
    assert cdn == "Cloudflare"
    assert "PHP" in tech
    assert "React" in tech


def test_plain_nginx_no_cdn():
    cdn, tech = fingerprint({"Server": "nginx"}, "")
    assert cdn is None
    assert tech == ["nginx"]


def test_wordpress_from_body():
    cdn, tech = fingerprint({}, '<link href="/wp-content/themes/x.css">')
    assert "WordPress" in tech


def test_empty_inputs():
    cdn, tech = fingerprint({}, "")
    assert cdn is None
    assert tech == []


def test_results_sorted_and_unique():
    cdn, tech = fingerprint({"Server": "nginx", "X-Powered-By": "Express"}, "")
    assert tech == sorted(tech)
    assert len(tech) == len(set(tech))
