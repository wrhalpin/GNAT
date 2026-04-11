# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
tests/unit/test_stix_helpers.py
==================================

Unit tests for :mod:`gnat.utils.stix_helpers`, including the Phase 1 Wave 1
additions: ``make_observed_data_envelope``, ``osv_to_stix_vulnerability``,
``cvss_to_external_reference``, ``make_indicator_pattern``, and
``x509_fingerprint_pattern``.
"""

from __future__ import annotations

import pytest

from gnat.utils.stix_helpers import (
    cvss_to_external_reference,
    extract_objects,
    filter_by_type,
    make_bundle,
    make_indicator_pattern,
    make_observed_data_envelope,
    osv_to_stix_vulnerability,
    utcnow,
    validate_stix_id,
    x509_fingerprint_pattern,
)

# ---------------------------------------------------------------------------
# Existing helpers (regression)
# ---------------------------------------------------------------------------


class TestCoreHelpers:
    def test_utcnow_is_iso_z(self):
        ts = utcnow()
        assert ts.endswith("Z")
        assert "T" in ts

    def test_make_bundle_wraps_objects(self):
        b = make_bundle([{"type": "indicator", "id": "indicator--x"}])
        assert b["type"] == "bundle"
        assert b["spec_version"] == "2.1"
        assert len(b["objects"]) == 1

    def test_extract_and_filter(self):
        b = make_bundle(
            [
                {"type": "indicator", "id": "indicator--a"},
                {"type": "malware", "id": "malware--b"},
            ]
        )
        objs = extract_objects(b)
        assert len(objs) == 2
        mal = filter_by_type(objs, "malware")
        assert len(mal) == 1
        assert mal[0]["id"] == "malware--b"

    def test_validate_stix_id_accepts_uuid(self):
        assert validate_stix_id("indicator--11111111-1111-1111-1111-111111111111")

    def test_validate_stix_id_rejects_non_uuid(self):
        assert not validate_stix_id("indicator--not-a-uuid")
        assert not validate_stix_id("no-double-dash")


# ---------------------------------------------------------------------------
# make_observed_data_envelope
# ---------------------------------------------------------------------------


class TestObservedDataEnvelope:
    def test_shape(self):
        env = make_observed_data_envelope(
            first_observed="2026-01-01T00:00:00Z",
            last_observed="2026-01-01T00:00:01Z",
            number_observed=3,
            object_refs=["file--11111111-1111-1111-1111-111111111111"],
            source_name="joe_sandbox",
        )
        assert env["type"] == "observed-data"
        assert env["spec_version"] == "2.1"
        assert env["first_observed"] == "2026-01-01T00:00:00Z"
        assert env["number_observed"] == 3
        assert env["x_source_name"] == "joe_sandbox"
        assert validate_stix_id(env["id"])

    def test_deterministic_id(self):
        kwargs = {
            "first_observed": "2026-01-01T00:00:00Z",
            "last_observed": "2026-01-01T00:00:01Z",
            "object_refs": ["file--11111111-1111-1111-1111-111111111111"],
            "source_name": "joe_sandbox",
        }
        a = make_observed_data_envelope(**kwargs)
        b = make_observed_data_envelope(**kwargs)
        assert a["id"] == b["id"]

    def test_x_extensions_are_prefixed(self):
        env = make_observed_data_envelope(
            first_observed="2026-01-01T00:00:00Z",
            last_observed="2026-01-01T00:00:01Z",
            x_extensions={"score": 80, "x_already_prefixed": True},
        )
        assert env["x_score"] == 80
        assert env["x_already_prefixed"] is True

    def test_number_observed_minimum(self):
        env = make_observed_data_envelope(
            first_observed="2026-01-01T00:00:00Z",
            last_observed="2026-01-01T00:00:01Z",
            number_observed=0,
        )
        assert env["number_observed"] == 1

    def test_object_refs_sorted(self):
        env = make_observed_data_envelope(
            first_observed="2026-01-01T00:00:00Z",
            last_observed="2026-01-01T00:00:01Z",
            object_refs=[
                "file--bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
                "file--aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            ],
        )
        assert env["object_refs"][0].endswith("a" * 12)


# ---------------------------------------------------------------------------
# cvss_to_external_reference
# ---------------------------------------------------------------------------


class TestCvssExternalReference:
    def test_basic(self):
        ref = cvss_to_external_reference(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8
        )
        assert ref["source_name"] == "cvss"
        assert "AV:N" in ref["external_id"]
        assert "9.8" in ref["description"]

    def test_without_score(self):
        ref = cvss_to_external_reference("CVSS:3.1/AV:N", cvss_version="3.1")
        assert "3.1" in ref["description"]


# ---------------------------------------------------------------------------
# make_indicator_pattern
# ---------------------------------------------------------------------------


class TestIndicatorPattern:
    def test_ipv4(self):
        p = make_indicator_pattern("ipv4-addr", "1.2.3.4")
        assert p == "[ipv4-addr:value = '1.2.3.4']"

    def test_domain(self):
        p = make_indicator_pattern("domain-name", "evil.example")
        assert p == "[domain-name:value = 'evil.example']"

    def test_file_sha256(self):
        p = make_indicator_pattern("file:sha256", "deadbeef")
        assert p == "[file:hashes.'SHA-256' = 'deadbeef']"

    def test_file_md5(self):
        p = make_indicator_pattern("file:md5", "cafebabe")
        assert p == "[file:hashes.'MD5' = 'cafebabe']"

    def test_wallet(self):
        p = make_indicator_pattern("x-cryptocurrency-wallet", "bc1qxyz")
        assert "x-cryptocurrency-wallet" in p

    def test_escapes_single_quotes(self):
        p = make_indicator_pattern("domain-name", "foo'bar")
        assert r"foo\'bar" in p

    def test_unknown_type_raises(self):
        with pytest.raises(ValueError):
            make_indicator_pattern("nope", "value")


# ---------------------------------------------------------------------------
# x509_fingerprint_pattern
# ---------------------------------------------------------------------------


class TestX509FingerprintPattern:
    def test_sha1(self):
        p = x509_fingerprint_pattern(sha1="aabbcc")
        assert "SHA-1" in p
        assert "aabbcc" in p

    def test_sha256(self):
        p = x509_fingerprint_pattern(sha256="ddeeff")
        assert "SHA-256" in p

    def test_ja3(self):
        p = x509_fingerprint_pattern(ja3="abc123")
        assert "ja3" in p
        assert "abc123" in p

    def test_combined_or(self):
        p = x509_fingerprint_pattern(sha1="aa", sha256="bb", ja3="cc")
        assert " OR " in p
        assert p.count("[") == 3

    def test_empty_raises(self):
        with pytest.raises(ValueError):
            x509_fingerprint_pattern()


# ---------------------------------------------------------------------------
# osv_to_stix_vulnerability
# ---------------------------------------------------------------------------


class TestOsvToStixVulnerability:
    def test_cve_id(self):
        osv = {
            "id": "CVE-2021-44228",
            "summary": "Log4Shell RCE",
            "details": "Apache Log4j2 JNDI lookup",
            "published": "2021-12-10T00:00:00Z",
            "modified": "2022-05-01T00:00:00Z",
            "affected": [
                {
                    "package": {"ecosystem": "Maven", "name": "org.apache.logging.log4j:log4j-core"},
                    "ranges": [],
                    "versions": ["2.0", "2.14"],
                }
            ],
            "severity": [
                {
                    "type": "CVSS_V3",
                    "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                }
            ],
        }
        stix = osv_to_stix_vulnerability(osv)
        assert stix["type"] == "vulnerability"
        assert stix["name"] == "CVE-2021-44228"
        assert validate_stix_id(stix["id"])
        assert stix["description"] == "Apache Log4j2 JNDI lookup"
        sources = [r["source_name"] for r in stix["external_references"]]
        assert "cve" in sources
        assert "cvss" in sources
        assert stix["x_osv_affected"][0]["ecosystem"] == "Maven"

    def test_ghsa(self):
        osv = {"id": "GHSA-xxxx-yyyy-zzzz", "summary": "GHSA test"}
        stix = osv_to_stix_vulnerability(osv)
        sources = [r["source_name"] for r in stix["external_references"]]
        assert "ghsa" in sources

    def test_deterministic_id(self):
        osv = {"id": "CVE-2023-1"}
        a = osv_to_stix_vulnerability(osv)
        b = osv_to_stix_vulnerability(osv)
        assert a["id"] == b["id"]

    def test_aliases(self):
        osv = {
            "id": "GHSA-1111-2222-3333",
            "aliases": ["CVE-2024-1234"],
        }
        stix = osv_to_stix_vulnerability(osv)
        ids = [r.get("external_id") for r in stix["external_references"]]
        assert "CVE-2024-1234" in ids

    def test_cwe_ids(self):
        osv = {
            "id": "OSV-1",
            "database_specific": {"cwe_ids": ["CWE-79", "CWE-352"]},
        }
        stix = osv_to_stix_vulnerability(osv)
        assert stix["x_cwe_ids"] == ["CWE-79", "CWE-352"]
