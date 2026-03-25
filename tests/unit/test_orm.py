"""
tests/unit/test_orm.py
======================

Unit tests for the CTM-SAK STIX ORM base layer and all domain objects.
"""

import uuid
import pytest

from ctm_sak.orm.base import STIXBase, _utcnow
from ctm_sak.orm.indicator import Indicator
from ctm_sak.orm.threat_actor import ThreatActor
from ctm_sak.orm.malware import Malware
from ctm_sak.orm.vulnerability import Vulnerability
from ctm_sak.orm.attack_pattern import AttackPattern
from ctm_sak.orm.observable import (
    Observable, IPv4Address, DomainName, URL, FileObject, EmailAddress,
)
from ctm_sak.orm.relationship import Relationship


# ---------------------------------------------------------------------------
# STIXBase
# ---------------------------------------------------------------------------

class TestSTIXBase:

    def test_auto_generates_id(self):
        obj = STIXBase()
        assert obj.id.startswith("stix-object--")
        uuid.UUID(obj.id.split("--")[1])   # raises if invalid UUID

    def test_explicit_id(self):
        obj = STIXBase(id="indicator--abc")
        assert obj.id == "indicator--abc"

    def test_spec_version_default(self):
        assert STIXBase().spec_version == "2.1"

    def test_setattr_stores_in_properties(self):
        obj = STIXBase()
        obj.custom_field = "hello"
        assert obj._properties["custom_field"] == "hello"

    def test_getattr_reads_from_properties(self):
        obj = STIXBase(colour="blue")
        assert obj.colour == "blue"

    def test_getattr_missing_raises_attribute_error(self):
        obj = STIXBase()
        with pytest.raises(AttributeError):
            _ = obj.nonexistent_field

    def test_to_dict_contains_core_fields(self):
        obj = STIXBase()
        d = obj.to_dict()
        assert d["type"] == "stix-object"
        assert d["spec_version"] == "2.1"
        assert "id" in d
        assert "created" in d
        assert "modified" in d

    def test_to_dict_includes_extra_properties(self):
        obj = STIXBase(name="test", score=5)
        d = obj.to_dict()
        assert d["name"] == "test"
        assert d["score"] == 5

    def test_from_dict_round_trip(self):
        original = STIXBase(name="round-trip", score=99)
        d = original.to_dict()
        restored = STIXBase.from_dict(d)
        assert restored.name == "round-trip"
        assert restored.score == 99

    def test_to_stix_bundle_structure(self):
        obj = STIXBase()
        bundle = obj.to_stix_bundle()
        assert bundle["type"] == "bundle"
        assert bundle["spec_version"] == "2.1"
        assert len(bundle["objects"]) == 1
        assert bundle["objects"][0] == obj.to_dict()

    def test_merge_updates_properties(self):
        obj = STIXBase(name="old")
        obj._merge({"name": "new", "added": True})
        assert obj.name == "new"
        assert obj.added is True

    def test_crud_requires_client(self):
        obj = STIXBase()
        with pytest.raises(RuntimeError, match="No client bound"):
            obj.select()
        with pytest.raises(RuntimeError):
            obj.save()
        with pytest.raises(RuntimeError):
            obj.delete()

    def test_repr(self):
        obj = STIXBase(id="stix-object--123")
        assert "123" in repr(obj)


# ---------------------------------------------------------------------------
# Domain Objects — type strings and defaults
# ---------------------------------------------------------------------------

class TestIndicator:

    def test_stix_type(self):
        assert Indicator.stix_type == "indicator"

    def test_id_prefix(self):
        ind = Indicator()
        assert ind.id.startswith("indicator--")

    def test_default_pattern_type(self):
        ind = Indicator()
        assert ind.pattern_type == "stix"

    def test_default_indicator_types(self):
        ind = Indicator()
        assert ind.indicator_types == []

    def test_explicit_kwargs(self):
        ind = Indicator(
            name="Bad IP",
            pattern="[ipv4-addr:value = '1.2.3.4']",
            indicator_types=["malicious-activity"],
        )
        assert ind.name == "Bad IP"
        assert ind.indicator_types == ["malicious-activity"]

    def test_to_dict_type_field(self):
        assert Indicator().to_dict()["type"] == "indicator"

    def test_id_assignment(self):
        ind = Indicator()
        ind.id = "indicator--custom-id"
        assert ind.id == "indicator--custom-id"


class TestThreatActor:
    def test_stix_type(self):
        assert ThreatActor.stix_type == "threat-actor"

    def test_default_threat_actor_types(self):
        assert ThreatActor().threat_actor_types == []


class TestMalware:
    def test_stix_type(self):
        assert Malware.stix_type == "malware"

    def test_defaults(self):
        m = Malware()
        assert m.is_family is False
        assert m.malware_types == []


class TestVulnerability:
    def test_stix_type(self):
        assert Vulnerability.stix_type == "vulnerability"

    def test_name_kwarg(self):
        v = Vulnerability(name="CVE-2024-12345")
        assert v.name == "CVE-2024-12345"


class TestAttackPattern:
    def test_stix_type(self):
        assert AttackPattern.stix_type == "attack-pattern"


class TestObservables:
    def test_ipv4_type(self):
        assert IPv4Address.stix_type == "ipv4-addr"

    def test_domain_type(self):
        assert DomainName.stix_type == "domain-name"

    def test_url_type(self):
        assert URL.stix_type == "url"

    def test_file_type(self):
        assert FileObject.stix_type == "file"

    def test_email_type(self):
        assert EmailAddress.stix_type == "email-addr"

    def test_value_kwarg(self):
        ip = IPv4Address(value="192.168.1.1")
        assert ip.value == "192.168.1.1"


class TestRelationship:
    def test_stix_type(self):
        assert Relationship.stix_type == "relationship"

    def test_relationship_fields(self):
        rel = Relationship(
            relationship_type="indicates",
            source_ref="indicator--abc",
            target_ref="malware--xyz",
        )
        assert rel.relationship_type == "indicates"
        assert rel.source_ref == "indicator--abc"
        assert rel.target_ref == "malware--xyz"

    def test_to_dict_round_trip(self):
        rel = Relationship(
            relationship_type="uses",
            source_ref="threat-actor--a",
            target_ref="attack-pattern--b",
        )
        d = rel.to_dict()
        restored = Relationship.from_dict(d)
        assert restored.relationship_type == "uses"
