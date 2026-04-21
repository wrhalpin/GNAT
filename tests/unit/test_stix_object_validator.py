"""
tests/unit/test_stix_object_validator.py
=========================================
Unit tests for gnat.stix.object_validator — STIX 2.1 object-level validation.
"""

from __future__ import annotations

import pytest

from gnat.stix.object_validator import (
    BundleValidationResult,
    ObjectValidationError,
    ObjectValidationResult,
    validate_bundle,
    validate_object,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_UUID = "1d8d7c3e-abc1-4a7e-9f15-0123456789ab"
_CREATED = "2026-01-01T00:00:00.000Z"


def _base(type_: str, **extra) -> dict:
    """Minimal valid base object for any SDO type."""
    return {
        "type": type_,
        "spec_version": "2.1",
        "id": f"{type_}--{_UUID}",
        "created": _CREATED,
        "modified": _CREATED,
        **extra,
    }


def _indicator(**extra) -> dict:
    return _base(
        "indicator",
        pattern="[ipv4-addr:value = '1.2.3.4']",
        pattern_type="stix",
        valid_from=_CREATED,
        **extra,
    )


# ---------------------------------------------------------------------------
# Import & public API
# ---------------------------------------------------------------------------


class TestPublicAPI:
    def test_validate_object_returns_result(self):
        result = validate_object(_indicator())
        assert isinstance(result, ObjectValidationResult)

    def test_validate_bundle_returns_result(self):
        result = validate_bundle({"type": "bundle", "id": f"bundle--{_UUID}", "objects": []})
        assert isinstance(result, BundleValidationResult)

    def test_valid_object_bool_true(self):
        assert validate_object(_indicator())

    def test_invalid_object_bool_false(self):
        assert not validate_object({"type": "indicator"})

    def test_raise_on_error(self):
        with pytest.raises(ObjectValidationError):
            validate_object({"type": "indicator"}, raise_on_error=True)

    def test_error_message_contains_type_and_id(self):
        try:
            validate_object({"type": "indicator"}, raise_on_error=True)
        except ObjectValidationError as exc:
            assert "indicator" in str(exc)


# ---------------------------------------------------------------------------
# Common required properties
# ---------------------------------------------------------------------------


class TestCommonRequired:
    def test_valid_indicator_passes(self):
        result = validate_object(_indicator())
        assert result.valid, result.errors

    def test_missing_type(self):
        obj = _indicator()
        del obj["type"]
        result = validate_object(obj)
        assert not result.valid
        assert any("type" in e for e in result.errors)

    def test_missing_spec_version(self):
        obj = _indicator()
        del obj["spec_version"]
        result = validate_object(obj)
        assert not result.valid
        assert any("spec_version" in e for e in result.errors)

    def test_missing_id(self):
        obj = _indicator()
        del obj["id"]
        result = validate_object(obj)
        assert not result.valid
        assert any("'id'" in e for e in result.errors)

    def test_missing_created(self):
        obj = _indicator()
        del obj["created"]
        result = validate_object(obj)
        assert not result.valid

    def test_missing_modified(self):
        obj = _indicator()
        del obj["modified"]
        result = validate_object(obj)
        assert not result.valid

    def test_multiple_missing_fields_all_reported(self):
        result = validate_object({"type": "indicator"})
        # Should report spec_version, id, created, modified, pattern, pattern_type, valid_from
        assert len(result.errors) >= 4


# ---------------------------------------------------------------------------
# ID format validation
# ---------------------------------------------------------------------------


class TestIDFormat:
    def test_valid_id_accepted(self):
        obj = _indicator()
        assert validate_object(obj).valid

    def test_id_wrong_prefix(self):
        obj = _indicator()
        obj["id"] = f"malware--{_UUID}"
        result = validate_object(obj)
        assert not result.valid
        assert any("prefix" in e for e in result.errors)

    def test_id_not_uuid4(self):
        obj = _indicator()
        obj["id"] = "indicator--not-a-uuid"
        result = validate_object(obj)
        assert not result.valid

    def test_id_not_string(self):
        obj = _indicator()
        obj["id"] = 12345
        result = validate_object(obj)
        assert not result.valid

    def test_id_uuid_v3_rejected(self):
        # UUID4 requires variant bits 8,9,a,b and version 4
        obj = _indicator()
        obj["id"] = "indicator--550e8400-e29b-31d4-a716-446655440000"  # version 1 UUID
        result = validate_object(obj)
        assert not result.valid


# ---------------------------------------------------------------------------
# Timestamp validation
# ---------------------------------------------------------------------------


class TestTimestamps:
    def test_valid_timestamp_z(self):
        assert validate_object(_indicator()).valid

    def test_timestamp_with_millis(self):
        obj = _indicator()
        obj["created"] = "2026-01-15T12:34:56.789Z"
        assert validate_object(obj).valid

    def test_timestamp_missing_z(self):
        obj = _indicator()
        obj["created"] = "2026-01-01T00:00:00"
        result = validate_object(obj)
        assert not result.valid

    def test_timestamp_not_string(self):
        obj = _indicator()
        obj["created"] = 1234567890
        result = validate_object(obj)
        assert not result.valid

    def test_valid_from_validated(self):
        obj = _indicator()
        obj["valid_from"] = "BAD"
        result = validate_object(obj)
        assert not result.valid

    def test_valid_until_validated(self):
        obj = _indicator()
        obj["valid_until"] = "not-a-timestamp"
        result = validate_object(obj)
        assert not result.valid


# ---------------------------------------------------------------------------
# Per-type required properties
# ---------------------------------------------------------------------------


class TestTypeRequired:
    def test_indicator_requires_pattern(self):
        obj = _indicator()
        del obj["pattern"]
        result = validate_object(obj)
        assert not result.valid
        assert any("pattern" in e for e in result.errors)

    def test_indicator_requires_pattern_type(self):
        obj = _indicator()
        del obj["pattern_type"]
        result = validate_object(obj)
        assert not result.valid

    def test_indicator_requires_valid_from(self):
        obj = _indicator()
        del obj["valid_from"]
        result = validate_object(obj)
        assert not result.valid

    def test_malware_requires_name_and_is_family(self):
        obj = _base("malware")
        result = validate_object(obj)
        errors = " ".join(result.errors)
        assert "name" in errors
        assert "is_family" in errors

    def test_malware_valid(self):
        obj = _base("malware", name="WannaCry", is_family=False)
        assert validate_object(obj).valid

    def test_relationship_requires_source_and_target(self):
        obj = _base("relationship", relationship_type="uses")
        result = validate_object(obj)
        errors = " ".join(result.errors)
        assert "source_ref" in errors
        assert "target_ref" in errors

    def test_relationship_valid(self):
        obj = _base(
            "relationship",
            relationship_type="uses",
            source_ref=f"threat-actor--{_UUID}",
            target_ref=f"malware--{_UUID}",
        )
        assert validate_object(obj).valid

    def test_observed_data_requires_refs(self):
        obj = _base(
            "observed-data", first_observed=_CREATED, last_observed=_CREATED, number_observed=1
        )
        result = validate_object(obj)
        assert any("object_refs" in e for e in result.errors)

    def test_report_requires_published_and_object_refs(self):
        obj = _base("report", name="My Report")
        result = validate_object(obj)
        errors = " ".join(result.errors)
        assert "published" in errors
        assert "object_refs" in errors

    def test_attack_pattern_valid(self):
        obj = _base("attack-pattern", name="Spear Phishing")
        assert validate_object(obj).valid

    def test_vulnerability_valid(self):
        obj = _base("vulnerability", name="CVE-2026-1234")
        assert validate_object(obj).valid

    def test_identity_valid(self):
        obj = _base("identity", name="ACME Corp")
        assert validate_object(obj).valid


# ---------------------------------------------------------------------------
# SCOs
# ---------------------------------------------------------------------------


class TestSCOs:
    def _sco(self, type_: str, **extra) -> dict:
        return {
            "type": type_,
            "spec_version": "2.1",
            "id": f"{type_}--{_UUID}",
            "created": _CREATED,
            "modified": _CREATED,
            **extra,
        }

    def test_ipv4_valid(self):
        obj = self._sco("ipv4-addr", value="1.2.3.4")
        assert validate_object(obj).valid

    def test_ipv4_missing_value(self):
        obj = self._sco("ipv4-addr")
        result = validate_object(obj)
        assert not result.valid

    def test_domain_name_valid(self):
        obj = self._sco("domain-name", value="evil.example.com")
        assert validate_object(obj).valid

    def test_url_valid(self):
        obj = self._sco("url", value="https://evil.example.com/path")
        assert validate_object(obj).valid

    def test_autonomous_system_requires_number(self):
        obj = self._sco("autonomous-system")
        result = validate_object(obj)
        assert any("number" in e for e in result.errors)

    def test_software_requires_name(self):
        obj = self._sco("software")
        result = validate_object(obj)
        assert any("name" in e for e in result.errors)


# ---------------------------------------------------------------------------
# Boolean properties
# ---------------------------------------------------------------------------


class TestBooleanProperties:
    def test_is_family_bool_accepted(self):
        obj = _base("malware", name="X", is_family=True)
        assert validate_object(obj).valid

    def test_is_family_string_rejected(self):
        obj = _base("malware", name="X", is_family="true")
        result = validate_object(obj)
        assert not result.valid
        assert any("is_family" in e for e in result.errors)

    def test_is_family_int_rejected(self):
        obj = _base("malware", name="X", is_family=1)
        result = validate_object(obj)
        assert not result.valid

    def test_revoked_bool_accepted(self):
        obj = _indicator(revoked=True)
        assert validate_object(obj).valid


# ---------------------------------------------------------------------------
# Integer properties
# ---------------------------------------------------------------------------


class TestIntegerProperties:
    def test_confidence_int_accepted(self):
        obj = _indicator(confidence=85)
        assert validate_object(obj).valid

    def test_confidence_string_rejected(self):
        obj = _indicator(confidence="high")
        result = validate_object(obj)
        assert not result.valid

    def test_confidence_bool_rejected(self):
        obj = _indicator(confidence=True)  # bool is subclass of int — must be rejected
        result = validate_object(obj)
        assert not result.valid

    def test_confidence_above_100_rejected(self):
        obj = _indicator(confidence=101)
        result = validate_object(obj)
        assert not result.valid
        assert any("100" in e for e in result.errors)

    def test_confidence_below_0_rejected(self):
        obj = _indicator(confidence=-1)
        result = validate_object(obj)
        assert not result.valid

    def test_number_observed_int_accepted(self):
        obj = _base(
            "observed-data",
            first_observed=_CREATED,
            last_observed=_CREATED,
            number_observed=5,
            object_refs=[f"ipv4-addr--{_UUID}"],
        )
        assert validate_object(obj).valid

    def test_number_observed_float_rejected(self):
        obj = _base(
            "observed-data",
            first_observed=_CREATED,
            last_observed=_CREATED,
            number_observed=5.0,
            object_refs=[f"ipv4-addr--{_UUID}"],
        )
        result = validate_object(obj)
        assert not result.valid


# ---------------------------------------------------------------------------
# Open vocabulary
# ---------------------------------------------------------------------------


class TestOpenVocabulary:
    def test_known_indicator_type_no_warning(self):
        obj = _indicator(indicator_types=["malicious-activity"])
        result = validate_object(obj)
        assert result.valid
        assert not result.warnings

    def test_unknown_indicator_type_warning(self):
        obj = _indicator(indicator_types=["custom-type"])
        result = validate_object(obj)
        assert result.valid  # still valid in non-strict mode
        assert result.warnings

    def test_unknown_indicator_type_strict_error(self):
        obj = _indicator(indicator_types=["custom-type"])
        result = validate_object(obj, strict=True)
        assert not result.valid
        assert any("indicator_types" in e for e in result.errors)

    def test_malware_types_list(self):
        obj = _base("malware", name="X", is_family=False, malware_types=["ransomware", "trojan"])
        result = validate_object(obj)
        assert result.valid
        assert not result.warnings

    def test_pattern_type_stix_no_warning(self):
        # _indicator() already sets pattern_type="stix"
        obj = _indicator()
        result = validate_object(obj)
        assert result.valid
        assert not result.warnings

    def test_pattern_type_yara_no_warning(self):
        obj = _base(
            "indicator",
            pattern="[ipv4-addr:value = '1.2.3.4']",
            pattern_type="yara",
            valid_from=_CREATED,
        )
        result = validate_object(obj)
        assert result.valid

    def test_pattern_type_custom_warning(self):
        obj = _base(
            "indicator",
            pattern="[ipv4-addr:value = '1.2.3.4']",
            pattern_type="my-custom-lang",
            valid_from=_CREATED,
        )
        result = validate_object(obj)
        assert result.valid  # open vocab — only warn
        assert result.warnings

    def test_relationship_type_uses_no_warning(self):
        obj = _base(
            "relationship",
            relationship_type="uses",
            source_ref=f"threat-actor--{_UUID}",
            target_ref=f"malware--{_UUID}",
        )
        result = validate_object(obj)
        assert result.valid
        assert not result.warnings

    def test_relationship_type_custom_warning(self):
        obj = _base(
            "relationship",
            relationship_type="custom-rel",
            source_ref=f"threat-actor--{_UUID}",
            target_ref=f"malware--{_UUID}",
        )
        result = validate_object(obj)
        assert result.valid
        assert result.warnings


# ---------------------------------------------------------------------------
# Closed vocabulary
# ---------------------------------------------------------------------------


class TestClosedVocabulary:
    def test_spec_version_21_accepted(self):
        assert validate_object(_indicator()).valid

    def test_spec_version_20_accepted(self):
        obj = _indicator()
        obj["spec_version"] = "2.0"
        assert validate_object(obj).valid

    def test_spec_version_30_rejected(self):
        obj = _indicator()
        obj["spec_version"] = "3.0"
        result = validate_object(obj)
        assert not result.valid
        assert any("spec_version" in e for e in result.errors)


# ---------------------------------------------------------------------------
# _ref / _refs format validation
# ---------------------------------------------------------------------------


class TestRefFormat:
    def test_valid_source_ref(self):
        obj = _base(
            "relationship",
            relationship_type="uses",
            source_ref=f"threat-actor--{_UUID}",
            target_ref=f"malware--{_UUID}",
        )
        assert validate_object(obj).valid

    def test_invalid_source_ref(self):
        obj = _base(
            "relationship",
            relationship_type="uses",
            source_ref="not-a-valid-ref",
            target_ref=f"malware--{_UUID}",
        )
        result = validate_object(obj)
        assert not result.valid
        assert any("source_ref" in e for e in result.errors)

    def test_invalid_object_refs_list_entry(self):
        obj = _base("note", content="test", object_refs=["bad-ref", f"indicator--{_UUID}"])
        result = validate_object(obj)
        assert not result.valid
        assert any("object_refs[0]" in e for e in result.errors)

    def test_valid_object_refs(self):
        obj = _base("note", content="test", object_refs=[f"indicator--{_UUID}"])
        assert validate_object(obj).valid


# ---------------------------------------------------------------------------
# Custom types
# ---------------------------------------------------------------------------


class TestCustomTypes:
    def test_x_prefix_custom_type_allowed(self):
        obj = {
            "type": "x-my-company-custom",
            "spec_version": "2.1",
            "id": f"x-my-company-custom--{_UUID}",
            "created": _CREATED,
            "modified": _CREATED,
        }
        result = validate_object(obj, allow_custom=True)
        assert result.valid

    def test_unknown_type_without_x_prefix_warns(self):
        obj = {
            "type": "custom-no-x",
            "spec_version": "2.1",
            "id": f"custom-no-x--{_UUID}",
            "created": _CREATED,
            "modified": _CREATED,
        }
        result = validate_object(obj, allow_custom=True)
        # Valid but should warn about missing x- prefix
        assert result.warnings

    def test_unknown_type_disallowed_when_allow_custom_false(self):
        obj = {
            "type": "x-my-custom",
            "spec_version": "2.1",
            "id": f"x-my-custom--{_UUID}",
            "created": _CREATED,
            "modified": _CREATED,
        }
        result = validate_object(obj, allow_custom=False)
        assert not result.valid


# ---------------------------------------------------------------------------
# Bundle validation
# ---------------------------------------------------------------------------


class TestBundleValidation:
    def _bundle(self, *objects) -> dict:
        return {
            "type": "bundle",
            "id": f"bundle--{_UUID}",
            "objects": list(objects),
        }

    def test_empty_bundle_valid(self):
        result = validate_bundle(self._bundle())
        assert result.valid

    def test_bundle_with_valid_objects(self):
        result = validate_bundle(self._bundle(_indicator()))
        assert result.valid

    def test_bundle_with_invalid_object_fails(self):
        result = validate_bundle(self._bundle({"type": "indicator"}))
        assert not result.valid
        assert len(result.object_results) == 1
        assert not result.object_results[0].valid

    def test_bundle_missing_id(self):
        bundle = {"type": "bundle", "objects": []}
        result = validate_bundle(bundle)
        assert not result.valid
        assert any("id" in e for e in result.bundle_errors)

    def test_bundle_wrong_type(self):
        bundle = {"type": "indicator", "id": f"bundle--{_UUID}", "objects": []}
        result = validate_bundle(bundle)
        assert not result.valid

    def test_bundle_all_errors_flat(self):
        bundle = self._bundle({"type": "indicator"}, {"type": "malware"})
        result = validate_bundle(bundle)
        assert not result.valid
        assert len(result.all_errors) >= 2

    def test_bundle_all_warnings_flat(self):
        obj = _indicator(indicator_types=["custom-type"])
        result = validate_bundle(self._bundle(obj))
        assert result.valid
        assert result.all_warnings

    def test_bundle_objects_not_list(self):
        bundle = {"type": "bundle", "id": f"bundle--{_UUID}", "objects": "bad"}
        result = validate_bundle(bundle)
        assert not result.valid

    def test_bundle_bool_input(self):
        result = validate_bundle(True)
        assert not result.valid


# ---------------------------------------------------------------------------
# Marking definition
# ---------------------------------------------------------------------------


class TestMarkingDefinition:
    def test_tlp_marking_valid(self):
        obj = {
            "type": "marking-definition",
            "id": f"marking-definition--{_UUID}",
            "created": _CREATED,
            "definition_type": "tlp",
            "definition": {"tlp": "green"},
        }
        assert validate_object(obj).valid

    def test_marking_definition_missing_definition_type(self):
        obj = {
            "type": "marking-definition",
            "id": f"marking-definition--{_UUID}",
            "created": _CREATED,
        }
        result = validate_object(obj)
        assert not result.valid

    def test_invalid_definition_type(self):
        obj = {
            "type": "marking-definition",
            "id": f"marking-definition--{_UUID}",
            "created": _CREATED,
            "definition_type": "custom",
            "definition": {},
        }
        result = validate_object(obj)
        assert not result.valid


# ---------------------------------------------------------------------------
# gnat.stix __init__ re-exports
# ---------------------------------------------------------------------------


class TestInitExports:
    def test_validate_object_importable_from_package(self):
        from gnat.stix import validate_object as vo

        assert vo is not None

    def test_validate_bundle_importable_from_package(self):
        from gnat.stix import validate_bundle as vb

        assert vb is not None

    def test_object_validation_error_importable(self):
        from gnat.stix import ObjectValidationError

        assert ObjectValidationError is not None

    def test_result_classes_importable(self):
        from gnat.stix import BundleValidationResult, ObjectValidationResult

        assert ObjectValidationResult and BundleValidationResult

    def test_validator_classes_importable(self):
        from gnat.stix import STIXBundleValidator, STIXObjectValidator

        assert STIXObjectValidator and STIXBundleValidator
