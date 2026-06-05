"""Tests for the permutation generator."""
from subscout.permute import generate_permutations


def test_basic_mutations():
    out = set(generate_permutations({"api.example.com"}, ["dev", "staging"], "example.com"))
    assert "dev.api.example.com" in out
    assert "api-dev.example.com" in out
    assert "dev-api.example.com" in out
    assert "staging.api.example.com" in out


def test_numeric_variants():
    out = set(generate_permutations({"api1.example.com"}, [], "example.com"))
    assert "api2.example.com" in out


def test_inputs_and_apex_excluded():
    out = set(generate_permutations({"api.example.com"}, ["dev"], "example.com"))
    assert "api.example.com" not in out
    assert "example.com" not in out
    assert all(n.endswith(".example.com") for n in out)


def test_limit_is_respected():
    out = generate_permutations(
        {"a.example.com"}, [f"w{i}" for i in range(1000)], "example.com", max_results=50
    )
    assert len(out) == 50
