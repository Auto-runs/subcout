"""Tests for TLS certificate SAN extraction."""
from subscout.tlsgrab import extract_cert_names


def test_extracts_san_dns_and_cn():
    cert = {
        "subjectAltName": (
            ("DNS", "a.example.com"),
            ("DNS", "*.x.example.com"),
            ("IP Address", "10.0.0.1"),
        ),
        "subject": ((("commonName", "b.example.com"),),),
    }
    names = extract_cert_names(cert)
    assert "a.example.com" in names
    assert "x.example.com" in names      # wildcard de-wildcarded to apex
    assert "b.example.com" in names      # commonName picked up
    assert all("*" not in n for n in names)
    # IP-Address SAN entries are ignored
    assert "10.0.0.1" not in names


def test_empty_cert():
    assert extract_cert_names({}) == set()


def test_only_san():
    cert = {"subjectAltName": (("DNS", "only.example.com"),)}
    assert extract_cert_names(cert) == {"only.example.com"}
