# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
tests/unit/plugins/test_huntgnat.py
======================================

Conformance test suite for HuntGNAT Phase 1 — Pattern → Rule Translation.

Coverage follows §5.8 of the HuntGNAT execution plan:
1. Hash patterns → Sigma + YARA
2. Compound domain + URL → Sigma, Suricata, Snort
3. Host-only process → Suricata/Snort raise UntranslatableError
4. All rules carry translator_version and hash
5. 25+ representative patterns across all target languages
"""

from __future__ import annotations

import pytest

from gnat.plugins.huntgnat.errors import UntranslatableError
from gnat.plugins.huntgnat.models import RuleLanguage, TranslationResult
from gnat.plugins.huntgnat.parser import STIXPatternParseError, parse_pattern
from gnat.plugins.huntgnat.translate import translate, translate_all

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _assert_result(result: TranslationResult, language: RuleLanguage) -> None:
    """Verify the structural contract of a TranslationResult."""
    assert isinstance(result, TranslationResult)
    assert result.language == language
    assert result.rule_body, "rule_body must be non-empty"
    assert result.translator_version, "translator_version must be set"
    assert result.rule_hash, "rule_hash must be computed"
    assert len(result.rule_hash) == 64, "rule_hash must be SHA-256 hex"


# ===========================================================================
# Parser tests
# ===========================================================================


class TestSTIXPatternParser:
    def test_simple_hash(self):
        ast = parse_pattern("[file:hashes.'SHA-256' = 'abc123']")
        assert len(ast.observations) == 1
        cmps = ast.observations[0].expression.iter_comparisons()
        assert cmps[0].object_path.object_type == "file"
        assert cmps[0].object_path.property_path == ["hashes", "SHA-256"]
        assert cmps[0].value == "abc123"

    def test_domain_name(self):
        ast = parse_pattern("[domain-name:value = 'evil.com']")
        c = ast.observations[0].expression.iter_comparisons()[0]
        assert c.object_path.object_type == "domain-name"
        assert c.value == "evil.com"

    def test_ipv4_addr(self):
        ast = parse_pattern("[ipv4-addr:value = '1.2.3.4']")
        c = ast.observations[0].expression.iter_comparisons()[0]
        assert c.object_path.object_type == "ipv4-addr"

    def test_ipv6_addr(self):
        ast = parse_pattern("[ipv6-addr:value = '2001:db8::1']")
        c = ast.observations[0].expression.iter_comparisons()[0]
        assert c.object_path.object_type == "ipv6-addr"

    def test_url(self):
        ast = parse_pattern("[url:value = 'https://evil.com/payload']")
        c = ast.observations[0].expression.iter_comparisons()[0]
        assert c.value == "https://evil.com/payload"

    def test_process_command_line(self):
        ast = parse_pattern("[process:command_line = 'powershell -enc']")
        c = ast.observations[0].expression.iter_comparisons()[0]
        assert c.object_path.property_path == ["command_line"]

    def test_file_name(self):
        ast = parse_pattern("[file:name = 'malware.exe']")
        c = ast.observations[0].expression.iter_comparisons()[0]
        assert c.value == "malware.exe"

    def test_registry_key(self):
        ast = parse_pattern("[windows-registry-key:key = 'HKLM\\\\Software\\\\Evil']")
        c = ast.observations[0].expression.iter_comparisons()[0]
        assert c.object_path.object_type == "windows-registry-key"

    def test_compound_and(self):
        ast = parse_pattern("[file:hashes.'MD5' = 'aaa' AND file:name = 'bad.exe']")
        expr = ast.observations[0].expression
        assert expr.operator == "AND"
        assert len(expr.iter_comparisons()) == 2

    def test_compound_or(self):
        ast = parse_pattern("[domain-name:value = 'a.com' OR domain-name:value = 'b.com']")
        expr = ast.observations[0].expression
        assert expr.operator == "OR"
        assert len(expr.iter_comparisons()) == 2

    def test_multiple_observations_or(self):
        ast = parse_pattern("[ipv4-addr:value = '1.1.1.1'] OR [domain-name:value = 'x.com']")
        assert len(ast.observations) == 2
        assert ast.operator == "OR"

    def test_multiple_observations_and(self):
        ast = parse_pattern("[file:name = 'a'] AND [process:name = 'b']")
        assert len(ast.observations) == 2
        assert ast.operator == "AND"

    def test_in_operator(self):
        ast = parse_pattern("[file:hashes.'MD5' IN ('aaa', 'bbb', 'ccc')]")
        c = ast.observations[0].expression.iter_comparisons()[0]
        assert c.operator == "IN"
        assert c.value == ["aaa", "bbb", "ccc"]

    def test_like_operator(self):
        ast = parse_pattern("[process:command_line LIKE '%powershell%']")
        c = ast.observations[0].expression.iter_comparisons()[0]
        assert c.operator == "LIKE"

    def test_matches_operator(self):
        ast = parse_pattern("[process:name MATCHES '^cmd\\.exe$']")
        c = ast.observations[0].expression.iter_comparisons()[0]
        assert c.operator == "MATCHES"

    def test_nested_property_path(self):
        ast = parse_pattern("[network-traffic:dst_ref.value = '1.2.3.4']")
        c = ast.observations[0].expression.iter_comparisons()[0]
        assert c.object_path.property_path == ["dst_ref", "value"]

    def test_empty_pattern_raises(self):
        with pytest.raises(STIXPatternParseError, match="empty"):
            parse_pattern("")

    def test_malformed_pattern_raises(self):
        with pytest.raises(STIXPatternParseError):
            parse_pattern("this is not a STIX pattern")

    def test_within_qualifier_raises(self):
        with pytest.raises(STIXPatternParseError, match="Phase 2"):
            parse_pattern("[file:name = 'x'] WITHIN 5 SECONDS")


# ===========================================================================
# Sigma translator tests
# ===========================================================================


class TestSigmaTranslator:
    def test_hash_indicator(self):
        r = translate(
            "[file:hashes.'SHA-256' = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']",
            "sigma",
            indicator_name="Empty file",
        )
        _assert_result(r, RuleLanguage.SIGMA)
        assert "title: Empty file" in r.rule_body
        assert "category: file_event" in r.rule_body
        assert "Hashes:" in r.rule_body
        assert "condition: selection" in r.rule_body

    def test_domain_indicator(self):
        r = translate(
            "[domain-name:value = 'evil.example.com']",
            "sigma",
            indicator_name="C2 domain",
        )
        _assert_result(r, RuleLanguage.SIGMA)
        assert "category: dns" in r.rule_body
        assert "DestinationHostname" in r.rule_body
        assert "evil.example.com" in r.rule_body

    def test_ip_indicator(self):
        r = translate("[ipv4-addr:value = '198.51.100.42']", "sigma")
        _assert_result(r, RuleLanguage.SIGMA)
        assert "category: firewall" in r.rule_body
        assert "198.51.100.42" in r.rule_body

    def test_process_indicator(self):
        r = translate(
            "[process:command_line LIKE '%powershell -enc%']",
            "sigma",
        )
        _assert_result(r, RuleLanguage.SIGMA)
        assert "category: process_creation" in r.rule_body
        assert "CommandLine" in r.rule_body
        assert "contains" in r.rule_body

    def test_url_indicator(self):
        r = translate("[url:value = 'https://evil.com/payload']", "sigma")
        _assert_result(r, RuleLanguage.SIGMA)
        assert "category: proxy" in r.rule_body

    def test_compound_and(self):
        r = translate(
            "[file:hashes.'SHA-256' = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' AND file:name = 'payload.exe']",
            "sigma",
        )
        _assert_result(r, RuleLanguage.SIGMA)
        assert "Hashes:" in r.rule_body
        assert "TargetFilename:" in r.rule_body

    def test_multiple_observations_or(self):
        r = translate(
            "[ipv4-addr:value = '1.1.1.1'] OR [ipv4-addr:value = '2.2.2.2']",
            "sigma",
        )
        _assert_result(r, RuleLanguage.SIGMA)
        assert "selection_1" in r.rule_body
        assert "selection_2" in r.rule_body
        assert "or" in r.rule_body

    def test_in_operator(self):
        r = translate(
            "[file:hashes.'MD5' IN ('aaa11111222233334444555566667777', 'bbb11111222233334444555566667777')]",
            "sigma",
        )
        _assert_result(r, RuleLanguage.SIGMA)
        assert "aaa11111222233334444555566667777" in r.rule_body
        assert "bbb11111222233334444555566667777" in r.rule_body

    def test_indicator_id_in_tags(self):
        r = translate(
            "[domain-name:value = 'x.com']",
            "sigma",
            indicator_id="indicator--abc-123",
        )
        assert "stix.indicator.indicator--abc-123" in r.rule_body

    def test_registry_indicator(self):
        r = translate(
            "[windows-registry-key:key = 'HKLM\\\\Software\\\\Evil']",
            "sigma",
        )
        _assert_result(r, RuleLanguage.SIGMA)
        assert "category: registry_event" in r.rule_body


# ===========================================================================
# YARA translator tests
# ===========================================================================


class TestYaraHashTranslator:
    def test_sha256_hash(self):
        r = translate(
            "[file:hashes.'SHA-256' = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']",
            "yara",
            indicator_name="Empty file",
        )
        _assert_result(r, RuleLanguage.YARA)
        assert 'import "hash"' in r.rule_body
        assert "hash.sha256" in r.rule_body
        assert "e3b0c44298fc1c149afbf4c8996fb924" in r.rule_body
        assert "rule Empty_file" in r.rule_body

    def test_md5_hash(self):
        r = translate(
            "[file:hashes.'MD5' = 'd41d8cd98f00b204e9800998ecf8427e']",
            "yara",
        )
        _assert_result(r, RuleLanguage.YARA)
        assert "hash.md5" in r.rule_body

    def test_sha1_hash(self):
        r = translate(
            "[file:hashes.'SHA-1' = 'da39a3ee5e6b4b0d3255bfef95601890afd80709']",
            "yara",
        )
        _assert_result(r, RuleLanguage.YARA)
        assert "hash.sha1" in r.rule_body

    def test_non_hash_pattern_raises(self):
        with pytest.raises(UntranslatableError, match="no file:hashes"):
            translate("[domain-name:value = 'evil.com']", "yara")

    def test_wrong_hash_length_raises(self):
        with pytest.raises(UntranslatableError, match="hex chars"):
            translate("[file:hashes.'SHA-256' = 'tooshort']", "yara")

    def test_multiple_hashes_or(self):
        r = translate(
            "[file:hashes.'SHA-256' = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'] "
            "OR "
            "[file:hashes.'MD5' = 'd41d8cd98f00b204e9800998ecf8427e']",
            "yara",
        )
        _assert_result(r, RuleLanguage.YARA)
        assert "hash.sha256" in r.rule_body
        assert "hash.md5" in r.rule_body
        assert " or" in r.rule_body

    def test_indicator_id_in_meta(self):
        r = translate(
            "[file:hashes.'SHA-256' = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']",
            "yara",
            indicator_id="indicator--xyz",
        )
        assert 'stix_indicator = "indicator--xyz"' in r.rule_body


# ===========================================================================
# Suricata translator tests
# ===========================================================================


class TestSuricataTranslator:
    def test_domain_rule(self):
        r = translate("[domain-name:value = 'evil.com']", "suricata")
        _assert_result(r, RuleLanguage.SURICATA)
        assert "alert dns" in r.rule_body
        assert "evil.com" in r.rule_body
        assert "sid:" in r.rule_body

    def test_ip_dst_rule(self):
        r = translate("[ipv4-addr:value = '198.51.100.42']", "suricata")
        _assert_result(r, RuleLanguage.SURICATA)
        assert "-> 198.51.100.42" in r.rule_body

    def test_url_rule(self):
        r = translate("[url:value = '/malware/payload']", "suricata")
        _assert_result(r, RuleLanguage.SURICATA)
        assert "alert http" in r.rule_body
        assert "/malware/payload" in r.rule_body

    def test_host_only_raises(self):
        with pytest.raises(UntranslatableError, match="host-only"):
            translate("[process:command_line = 'cmd.exe']", "suricata")

    def test_file_hash_raises(self):
        with pytest.raises(UntranslatableError, match="host-only"):
            translate(
                "[file:hashes.'SHA-256' = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']",
                "suricata",
            )

    def test_network_traffic_dst(self):
        r = translate("[network-traffic:dst_ref.value = '10.0.0.1']", "suricata")
        _assert_result(r, RuleLanguage.SURICATA)
        assert "-> 10.0.0.1" in r.rule_body


# ===========================================================================
# Snort translator tests
# ===========================================================================


class TestSnortTranslator:
    def test_domain_rule(self):
        r = translate("[domain-name:value = 'evil.com']", "snort")
        _assert_result(r, RuleLanguage.SNORT)
        assert "alert dns" in r.rule_body
        assert "evil.com" in r.rule_body
        assert "gid:1" in r.rule_body

    def test_ip_rule(self):
        r = translate("[ipv4-addr:value = '198.51.100.42']", "snort")
        _assert_result(r, RuleLanguage.SNORT)
        assert "-> 198.51.100.42" in r.rule_body

    def test_host_only_raises(self):
        with pytest.raises(UntranslatableError, match="host-only"):
            translate("[file:name = 'malware.exe']", "snort")


# ===========================================================================
# translate_all
# ===========================================================================


class TestTranslateAll:
    def test_hash_pattern_produces_sigma_and_yara(self):
        results = translate_all(
            "[file:hashes.'SHA-256' = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']",
        )
        assert isinstance(results["sigma"], TranslationResult)
        assert isinstance(results["yara"], TranslationResult)
        assert isinstance(results["suricata"], UntranslatableError)
        assert isinstance(results["snort"], UntranslatableError)

    def test_domain_pattern_produces_sigma_suricata_snort(self):
        results = translate_all("[domain-name:value = 'evil.com']")
        assert isinstance(results["sigma"], TranslationResult)
        assert isinstance(results["yara"], UntranslatableError)
        assert isinstance(results["suricata"], TranslationResult)
        assert isinstance(results["snort"], TranslationResult)

    def test_ip_pattern_three_languages(self):
        results = translate_all("[ipv4-addr:value = '1.2.3.4']")
        ok_count = sum(1 for r in results.values() if isinstance(r, TranslationResult))
        assert ok_count == 3  # sigma, suricata, snort

    def test_all_results_have_metadata(self):
        results = translate_all(
            "[domain-name:value = 'evil.com']",
            indicator_id="indicator--test",
        )
        for _lang, result in results.items():
            if isinstance(result, TranslationResult):
                assert result.indicator_id == "indicator--test"


# ===========================================================================
# SPL/KQL/EQL — explicit error for Phase 1
# ===========================================================================


class TestTranspileNotYetAvailable:
    def test_spl_raises(self):
        with pytest.raises(UntranslatableError, match="pySigma"):
            translate("[domain-name:value = 'x.com']", "spl")

    def test_kql_raises(self):
        with pytest.raises(UntranslatableError, match="pySigma"):
            translate("[domain-name:value = 'x.com']", "kql")

    def test_eql_raises(self):
        with pytest.raises(UntranslatableError, match="pySigma"):
            translate("[domain-name:value = 'x.com']", "eql")

    def test_unknown_language_raises(self):
        with pytest.raises(ValueError, match="unknown"):
            translate("[domain-name:value = 'x.com']", "pascal")
