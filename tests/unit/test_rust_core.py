"""
tests.unit.test_rust_core
=========================

Parity tests that verify the optional Rust native extension (_core) produces
identical results to the pure-Python fallbacks in gnat.ingest._ioc_classifier.

Tests are structured in two layers:

1. Pure-Python tests — always run; exercise the ``_py_*`` functions directly.
2. Rust-parity tests — skipped automatically when the Rust wheel is not
   installed; compare every ``_py_*`` result against the Rust equivalent.

This ensures:
* The Python fallbacks are always correct (no silent regressions).
* When the Rust extension IS installed, it is provably equivalent.
"""

from __future__ import annotations

import pytest

from gnat.ingest._ioc_classifier import (
    RUST_AVAILABLE,
    _py_classify_ioc,
    _py_classify_ioc_batch,
    _py_defang,
    _py_extract_pattern_value,
    _py_refang,
    classify_ioc,
    classify_ioc_batch,
    defang,
    extract_pattern_value,
    refang,
)

# ---------------------------------------------------------------------------
# Fixtures / shared data
# ---------------------------------------------------------------------------

CLASSIFY_CASES: list[tuple[str, str]] = [
    # SHA-256
    ("a" * 64, "sha256"),
    ("0" * 64, "sha256"),
    # SHA-1
    ("b" * 40, "sha1"),
    # MD5
    ("c" * 32, "md5"),
    # IPv4 (with and without CIDR)
    ("1.2.3.4", "ip"),
    ("192.168.0.1", "ip"),
    ("255.255.255.255", "ip"),
    ("10.0.0.0/8", "ip"),
    # IPv6 (simple heuristic — colons + hex)
    ("2001:db8::1", "ipv6"),
    ("::1", "ipv6"),
    # URL
    ("http://example.com/path", "url"),
    ("https://evil.com/malware", "url"),
    ("HTTP://CAPS.COM", "url"),
    # Email
    ("user@example.com", "email"),
    ("admin@corp.internal", "email"),
    # Domain
    ("evil.com", "domain"),
    ("subdomain.example.org", "domain"),
    ("deep.sub.domain.co.uk", "domain"),
    # Unknown
    ("not-an-ioc", "unknown"),
    ("", "unknown"),
    ("just-text", "unknown"),
]

DEFANG_CASES: list[tuple[str, str]] = [
    ("hxxp://evil[.]com/path", "http://evil.com/path"),
    ("hxxps://secure[.]example[.]com", "https://secure.example.com"),
    ("192[.]168[.]0[.]1", "192.168.0.1"),
    # Already clean — should be unchanged
    ("http://already.clean.com", "http://already.clean.com"),
    # Mixed case hxxp
    ("HXXP://test.com", "http://test.com"),
    ("HXXPS://test.com", "https://test.com"),
]

REFANG_CASES: list[tuple[str, str]] = [
    ("http://evil.com/path", "hxxp://evil[.]com/path"),
    ("https://example.com", "hxxps://example[.]com"),
    ("192.168.0.1", "192[.]168[.]0[.]1"),
]

EXTRACT_CASES: list[tuple[str, str | None]] = [
    ("[ipv4-addr:value = '1.2.3.4']", "1.2.3.4"),
    ("[domain-name:value = 'evil.com']", "evil.com"),
    ("[url:value = 'https://bad.example.com/payload']", "https://bad.example.com/payload"),
    # No quoted value → None
    ("[ipv4-addr:value = 1.2.3.4]", None),
    ("no pattern here", None),
    ("", None),
]


# ---------------------------------------------------------------------------
# Pure-Python tests (always run)
# ---------------------------------------------------------------------------


class TestPyClassifyIoc:
    @pytest.mark.parametrize("value,expected", CLASSIFY_CASES)
    def test_classify(self, value: str, expected: str) -> None:
        assert _py_classify_ioc(value) == expected

    def test_sha256_case_insensitive(self) -> None:
        assert _py_classify_ioc("A" * 64) == "sha256"
        assert _py_classify_ioc("f" * 64) == "sha256"

    def test_ip_octet_boundaries(self) -> None:
        assert _py_classify_ioc("0.0.0.0") == "ip"
        assert _py_classify_ioc("256.0.0.1") == "unknown"


class TestPyDefang:
    @pytest.mark.parametrize("value,expected", DEFANG_CASES)
    def test_defang(self, value: str, expected: str) -> None:
        assert _py_defang(value) == expected

    def test_strips_whitespace(self) -> None:
        assert _py_defang("  hxxp://evil[.]com  ") == "http://evil.com"


class TestPyRefang:
    def test_http_to_hxxp(self) -> None:
        result = _py_refang("http://evil.com")
        assert "hxxp://" in result

    def test_https_to_hxxps(self) -> None:
        result = _py_refang("https://evil.com")
        assert "hxxps://" in result

    def test_dot_replaced(self) -> None:
        result = _py_refang("evil.com")
        assert "[.]" in result
        assert "." not in result.replace("[.]", "")


class TestPyExtractPatternValue:
    @pytest.mark.parametrize("pattern,expected", EXTRACT_CASES)
    def test_extract(self, pattern: str, expected: str | None) -> None:
        assert _py_extract_pattern_value(pattern) == expected


class TestPyClassifyIocBatch:
    def test_batch_matches_single(self) -> None:
        values = [v for v, _ in CLASSIFY_CASES]
        expected = [_py_classify_ioc(v) for v in values]
        assert _py_classify_ioc_batch(values) == expected

    def test_empty_list(self) -> None:
        assert _py_classify_ioc_batch([]) == []

    def test_preserves_order(self) -> None:
        values = ["1.2.3.4", "evil.com", "unknown-thing"]
        result = _py_classify_ioc_batch(values)
        assert result == ["ip", "domain", "unknown"]


# ---------------------------------------------------------------------------
# Public API tests (uses whichever backend is active)
# ---------------------------------------------------------------------------


class TestPublicApi:
    """Smoke-tests the public classify_ioc / defang / refang / extract_pattern_value
    functions without caring which backend is used."""

    def test_classify_ip(self) -> None:
        assert classify_ioc("1.2.3.4") == "ip"

    def test_classify_domain(self) -> None:
        assert classify_ioc("evil.com") == "domain"

    def test_classify_unknown(self) -> None:
        assert classify_ioc("not-an-ioc") == "unknown"

    def test_defang_hxxp(self) -> None:
        assert defang("hxxp://evil[.]com") == "http://evil.com"

    def test_refang_http(self) -> None:
        result = refang("http://evil.com")
        assert "hxxp://" in result

    def test_extract_ipv4_pattern(self) -> None:
        assert extract_pattern_value("[ipv4-addr:value = '1.2.3.4']") == "1.2.3.4"

    def test_extract_none(self) -> None:
        assert extract_pattern_value("no pattern") is None

    def test_batch_classify(self) -> None:
        results = classify_ioc_batch(["1.2.3.4", "evil.com", "unknown"])
        assert results == ["ip", "domain", "unknown"]


# ---------------------------------------------------------------------------
# Rust-parity tests (skipped when Rust wheel not installed)
# ---------------------------------------------------------------------------

rust_only = pytest.mark.skipif(not RUST_AVAILABLE, reason="Rust _core extension not installed")


@rust_only
class TestRustParityClassifyIoc:
    """Verify that the Rust classify_ioc matches pure Python for every test case."""

    @pytest.mark.parametrize("value,expected", CLASSIFY_CASES)
    def test_parity(self, value: str, expected: str) -> None:
        py_result = _py_classify_ioc(value)
        rust_result = classify_ioc(value)  # dispatches to Rust when RUST_AVAILABLE
        assert rust_result == py_result, (
            f"Rust/Python mismatch for {value!r}: Rust={rust_result!r}, Python={py_result!r}"
        )


@rust_only
class TestRustParityDefang:
    @pytest.mark.parametrize("value,_expected", DEFANG_CASES)
    def test_parity(self, value: str, _expected: str) -> None:
        assert defang(value) == _py_defang(value)


@rust_only
class TestRustParityRefang:
    @pytest.mark.parametrize("value,_expected", REFANG_CASES)
    def test_parity(self, value: str, _expected: str) -> None:
        assert refang(value) == _py_refang(value)


@rust_only
class TestRustParityExtract:
    @pytest.mark.parametrize("pattern,_expected", EXTRACT_CASES)
    def test_parity(self, pattern: str, _expected: str | None) -> None:
        assert extract_pattern_value(pattern) == _py_extract_pattern_value(pattern)


@rust_only
class TestRustParityBatch:
    def test_batch_parity(self) -> None:
        values = [v for v, _ in CLASSIFY_CASES]
        py_results = _py_classify_ioc_batch(values)
        rust_results = classify_ioc_batch(values)
        assert rust_results == py_results

    def test_empty_batch(self) -> None:
        assert classify_ioc_batch([]) == []
