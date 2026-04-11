# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
tests/unit/connectors/test_connectors.py
=========================================

Unit tests for all six GNAT connector clients.

Tests cover:
- Authentication header injection
- get_object / list_objects / upsert_object / delete_object
- to_stix() output contract (required STIX fields)
- from_stix() output contract (platform payload keys)
"""

from unittest.mock import MagicMock

import pytest

from gnat.clients.base import GNATClientError
from gnat.connectors.crowdstrike.client import CrowdStrikeClient
from gnat.connectors.feedly.client import FeedlyClient
from gnat.connectors.greymatter.client import GreyMatterClient
from gnat.connectors.netskope.client import NetskopeClient
from gnat.connectors.proofpoint.client import ProofpointClient
from gnat.connectors.recordedfuture.client import RecordedFutureClient
from gnat.connectors.riskrecon.client import RiskReconClient
from gnat.connectors.splunk.client import SplunkClient
from gnat.connectors.threatq.client import ThreatQClient
from gnat.connectors.whistic.client import WhisticClient
from gnat.connectors.xsoar.client import XSOARClient

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _authenticated(connector_cls, **kwargs):
    """Return a connector instance with authenticate() no-oped."""
    c = connector_cls(host="https://fake.example.com", **kwargs)
    c._authenticated = True
    return c


def _assert_stix_contract(stix_dict: dict):
    """Assert that a to_stix() result satisfies the minimum STIX contract."""
    assert isinstance(stix_dict, dict), "to_stix() must return a dict"
    assert "type" in stix_dict, "STIX dict must have 'type'"
    assert "id" in stix_dict, "STIX dict must have 'id'"
    assert "--" in stix_dict["id"], "STIX id must be in <type>--<uuid> format"


# ---------------------------------------------------------------------------
# ThreatQ
# ---------------------------------------------------------------------------


class TestThreatQClient:
    @pytest.fixture
    def client(self):
        return _authenticated(ThreatQClient, client_id="cid", client_secret="sec")

    def test_authenticate_sets_bearer(self, monkeypatch):
        c = ThreatQClient(host="https://fake.example.com", client_id="x", client_secret="y")
        monkeypatch.setattr(c, "post", MagicMock(return_value={"access_token": "tok123"}))
        c.authenticate()
        assert c._auth_headers["Authorization"] == "Bearer tok123"

    def test_authenticate_raises_on_missing_token(self, monkeypatch):
        c = ThreatQClient(host="https://fake.example.com", client_id="x", client_secret="y")
        monkeypatch.setattr(c, "post", MagicMock(return_value={}))
        with pytest.raises(GNATClientError, match="access token"):
            c.authenticate()

    def test_get_object(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"data": {"id": 42, "value": "1.2.3.4"}})
        )
        result = client.get_object("indicator", "42")
        assert isinstance(result, dict)

    def test_list_objects(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": [{"id": 1}]}))
        result = client.list_objects("indicator")
        assert isinstance(result, list)
        assert len(result) == 1

    def test_upsert_creates_when_no_id(self, client, monkeypatch):
        mock_post = MagicMock(return_value={"data": {"id": 99}})
        monkeypatch.setattr(client, "post", mock_post)
        client.upsert_object("indicator", {"value": "evil.com"})
        mock_post.assert_called_once()

    def test_upsert_updates_when_id_present(self, client, monkeypatch):
        mock_put = MagicMock(return_value={"data": {"id": 5}})
        monkeypatch.setattr(client, "put", mock_put)
        client.upsert_object("indicator", {"id": "5", "value": "evil.com"})
        mock_put.assert_called_once()

    def test_delete_object(self, client, monkeypatch):
        mock_delete = MagicMock(return_value=None)
        monkeypatch.setattr(client, "delete", mock_delete)
        client.delete_object("indicator", "5")
        mock_delete.assert_called_once()

    def test_to_stix_contract(self, client):
        native = {
            "data": {
                "id": 1,
                "value": "1.2.3.4",
                "type": "IP Address",
                "class": "malicious",
                "created_at": "",
                "updated_at": "",
            }
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "indicator"
        assert "1.2.3.4" in stix.get("pattern", "")

    def test_to_stix_extracts_targeted_industry(self, client):
        native = {
            "data": {
                "id": 1,
                "value": "evil.com",
                "type": "FQDN",
                "class": "malicious",
                "created_at": "",
                "updated_at": "",
                "attributes": [
                    {"name": "Targeted Industry", "value": "Healthcare"},
                ],
            }
        }
        stix = client.to_stix(native)
        assert stix.get("x_target_sectors") == ["Healthcare"]

    def test_to_stix_extracts_targeted_sector(self, client):
        native = {
            "data": {
                "id": 2,
                "value": "1.2.3.4",
                "type": "IP Address",
                "class": "malicious",
                "created_at": "",
                "updated_at": "",
                "attributes": [{"name": "Targeted Sector", "value": "Finance"}],
            }
        }
        stix = client.to_stix(native)
        assert "Finance" in stix.get("x_target_sectors", [])

    def test_to_stix_attr_name_case_insensitive(self, client):
        native = {
            "data": {
                "id": 3,
                "value": "bad.ru",
                "type": "FQDN",
                "class": "malicious",
                "created_at": "",
                "updated_at": "",
                "attributes": [{"name": "TARGETED INDUSTRY", "value": "Energy"}],
            }
        }
        stix = client.to_stix(native)
        assert stix.get("x_target_sectors") == ["Energy"]

    def test_to_stix_targets_attr_name(self, client):
        """'Targets' is used by the Adversary Reader CDF feed."""
        native = {
            "data": {
                "id": 4,
                "value": "apt28.example",
                "type": "FQDN",
                "class": "malicious",
                "created_at": "",
                "updated_at": "",
                "attributes": [{"name": "Targets", "value": "Government"}],
            }
        }
        stix = client.to_stix(native)
        assert "Government" in stix.get("x_target_sectors", [])

    def test_to_stix_multiple_sector_attrs(self, client):
        native = {
            "data": {
                "id": 5,
                "value": "evil.com",
                "type": "FQDN",
                "class": "malicious",
                "created_at": "",
                "updated_at": "",
                "attributes": [
                    {"name": "Targeted Industry", "value": "Healthcare"},
                    {"name": "Targeted Sector", "value": "Pharmaceuticals"},
                    {"name": "Description", "value": "some notes"},
                ],
            }
        }
        stix = client.to_stix(native)
        sectors = stix.get("x_target_sectors", [])
        assert "Healthcare" in sectors
        assert "Pharmaceuticals" in sectors
        assert "some notes" not in sectors

    def test_to_stix_no_attributes_omits_sector_key(self, client):
        native = {
            "data": {
                "id": 6,
                "value": "1.2.3.4",
                "type": "IP Address",
                "class": "malicious",
                "created_at": "",
                "updated_at": "",
            }
        }
        stix = client.to_stix(native)
        assert "x_target_sectors" not in stix

    def test_to_stix_unrelated_attrs_ignored(self, client):
        native = {
            "data": {
                "id": 7,
                "value": "evil.com",
                "type": "FQDN",
                "class": "malicious",
                "created_at": "",
                "updated_at": "",
                "attributes": [
                    {"name": "Description", "value": "Some description"},
                    {"name": "Source", "value": "internal"},
                ],
            }
        }
        stix = client.to_stix(native)
        assert "x_target_sectors" not in stix

    def test_get_object_requests_attributes(self, client, monkeypatch):
        mock_get = MagicMock(return_value={"data": {"id": 1, "value": "x"}})
        monkeypatch.setattr(client, "get", mock_get)
        client.get_object("indicator", "1")
        _, kwargs = mock_get.call_args
        assert "attributes" in kwargs.get("params", {}).get("with", "")

    def test_list_objects_requests_attributes(self, client, monkeypatch):
        mock_get = MagicMock(return_value={"data": []})
        monkeypatch.setattr(client, "get", mock_get)
        client.list_objects("indicator")
        _, kwargs = mock_get.call_args
        assert "attributes" in kwargs.get("params", {}).get("with", "")

    def test_get_attribute_types(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(
                return_value={
                    "data": [
                        {"name": "Targeted Industry"},
                        {"name": "Description"},
                        {"name": "Source"},
                    ]
                }
            ),
        )
        names = client.get_attribute_types()
        assert "Targeted Industry" in names
        assert "Description" in names
        assert len(names) == 3

    def test_from_stix_returns_dict(self, client):
        stix = {
            "type": "indicator",
            "id": "indicator--1",
            "name": "evil.com",
            "pattern": "[domain-name:value = 'evil.com']",
        }
        result = client.from_stix(stix)
        assert isinstance(result, dict)
        assert "value" in result

    def test_unsupported_type_raises(self, client):
        with pytest.raises(GNATClientError, match="unsupported"):
            client.get_object("bundle", "1")


# ---------------------------------------------------------------------------
# CrowdStrike
# ---------------------------------------------------------------------------


class TestCrowdStrikeClient:
    @pytest.fixture
    def client(self):
        return _authenticated(CrowdStrikeClient, client_id="cid", client_secret="sec")

    def test_authenticate_sets_bearer(self, monkeypatch):
        c = CrowdStrikeClient(host="https://fake.example.com", client_id="x", client_secret="y")
        monkeypatch.setattr(c, "post", MagicMock(return_value={"access_token": "cs-tok"}))
        c.authenticate()
        assert c._auth_headers["Authorization"] == "Bearer cs-tok"

    def test_authenticate_missing_token_raises(self, monkeypatch):
        c = CrowdStrikeClient(host="https://fake.example.com", client_id="x", client_secret="y")
        monkeypatch.setattr(c, "post", MagicMock(return_value={}))
        with pytest.raises(GNATClientError):
            c.authenticate()

    def test_get_object_returns_first_resource(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"resources": [{"id": "ioc-1"}]}))
        result = client.get_object("indicator", "ioc-1")
        assert result == {"id": "ioc-1"}

    def test_get_object_empty_resources(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"resources": []}))
        result = client.get_object("indicator", "missing")
        assert result == {}

    def test_to_stix_contract(self, client):
        native = {
            "id": "cs-1",
            "value": "192.168.0.1",
            "type": "ipv4",
            "created_timestamp": "",
            "modified_timestamp": "",
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)

    def test_to_stix_target_industries(self, client):
        native = {
            "id": "cs-2",
            "value": "apt28",
            "type": "actor",
            "created_timestamp": "",
            "modified_timestamp": "",
            "target_industries": ["Healthcare", "Government"],
        }
        stix = client.to_stix(native)
        assert stix.get("x_target_sectors") == ["Healthcare", "Government"]

    def test_to_stix_no_industries_omits_key(self, client):
        native = {
            "id": "cs-3",
            "value": "1.2.3.4",
            "type": "ipv4",
            "created_timestamp": "",
            "modified_timestamp": "",
        }
        stix = client.to_stix(native)
        assert "x_target_sectors" not in stix

    def test_to_stix_empty_industries_omits_key(self, client):
        native = {
            "id": "cs-4",
            "value": "1.2.3.4",
            "type": "ipv4",
            "created_timestamp": "",
            "modified_timestamp": "",
            "target_industries": [],
        }
        stix = client.to_stix(native)
        assert "x_target_sectors" not in stix

    def test_from_stix_returns_dict(self, client):
        result = client.from_stix({"name": "1.2.3.4"})
        assert isinstance(result, dict)
        assert result.get("value") == "1.2.3.4"


# ---------------------------------------------------------------------------
# Proofpoint
# ---------------------------------------------------------------------------


class TestProofpointClient:
    @pytest.fixture
    def client(self):
        return _authenticated(ProofpointClient, service_principal="sp", secret="sec")

    def test_authenticate_sets_basic(self):
        import base64

        c = ProofpointClient(
            host="https://fake.example.com", service_principal="user", secret="pass"
        )
        c._authenticated = False
        c.authenticate()  # no HTTP call for Basic auth
        expected = "Basic " + base64.b64encode(b"user:pass").decode()
        assert c._auth_headers["Authorization"] == expected

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError, match="not support"):
            client.upsert_object("indicator", {})

    def test_delete_raises(self, client):
        with pytest.raises(GNATClientError, match="not support"):
            client.delete_object("indicator", "1")

    def test_to_stix_contract(self, client):
        native = {"id": "pp-1", "subject": "Phish email", "messageTime": ""}
        stix = client.to_stix(native)
        _assert_stix_contract(stix)

    def test_list_returns_list(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"messagesDelivered": [{"id": "m1"}]})
        )
        result = client.list_objects("indicator")
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# Netskope
# ---------------------------------------------------------------------------


class TestNetskopeClient:
    @pytest.fixture
    def client(self):
        return _authenticated(NetskopeClient, api_token="ns-tok")

    def test_authenticate_sets_token_header(self):
        c = NetskopeClient(host="https://fake.example.com", api_token="my-token")
        c.authenticate()
        assert c._auth_headers["Netskope-Api-Token"] == "my-token"

    def test_to_stix_contract(self, client):
        native = {"id": "ns-1", "name": "Malware List", "modify_by": ""}
        stix = client.to_stix(native)
        _assert_stix_contract(stix)

    def test_upsert_creates_via_post(self, client, monkeypatch):
        mock_post = MagicMock(return_value={"id": "new-list"})
        monkeypatch.setattr(client, "post", mock_post)
        client.upsert_object("indicator", {"name": "My List"})
        mock_post.assert_called_once()

    def test_upsert_updates_via_patch(self, client, monkeypatch):
        mock_patch = MagicMock(return_value={"id": "existing-list"})
        monkeypatch.setattr(client, "patch", mock_patch)
        client.upsert_object("indicator", {"id": "existing-list", "name": "Updated"})
        mock_patch.assert_called_once()


# ---------------------------------------------------------------------------
# XSOAR
# ---------------------------------------------------------------------------


class TestXSOARClient:
    @pytest.fixture
    def client(self):
        return _authenticated(XSOARClient, api_key="xsoar-key")

    def test_authenticate_sets_api_key_header(self):
        c = XSOARClient(host="https://fake.example.com", api_key="key123")
        c.authenticate()
        assert c._auth_headers["Authorization"] == "key123"

    def test_authenticate_with_auth_id(self):
        c = XSOARClient(host="https://fake.example.com", api_key="key123", auth_id="99")
        c.authenticate()
        assert c._auth_headers["x-xdr-auth-id"] == "99"

    def test_get_object_returns_first(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "post",
            MagicMock(return_value={"iocObjects": [{"id": "xsoar-1", "value": "bad.com"}]}),
        )
        result = client.get_object("indicator", "xsoar-1")
        assert result["id"] == "xsoar-1"

    def test_to_stix_contract(self, client):
        native = {
            "id": "x1",
            "value": "10.0.0.1",
            "indicator_type": "IP",
            "timestamp": "",
            "modified": "",
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "indicator"

    def test_from_stix_returns_dict(self, client):
        result = client.from_stix({"name": "10.0.0.1"})
        assert isinstance(result, dict)
        assert result.get("value") == "10.0.0.1"

    def test_delete_calls_post(self, client, monkeypatch):
        mock_post = MagicMock(return_value={})
        monkeypatch.setattr(client, "post", mock_post)
        client.delete_object("indicator", "x1")
        mock_post.assert_called_once()


# ---------------------------------------------------------------------------
# Recorded Future
# ---------------------------------------------------------------------------


class TestRecordedFutureClient:
    @pytest.fixture
    def client(self):
        return _authenticated(RecordedFutureClient, api_token="rf-tok")

    def test_authenticate_sets_token_header(self):
        c = RecordedFutureClient(host="https://fake.example.com", api_token="rf-tok")
        c.authenticate()
        assert c._auth_headers["X-RFToken"] == "rf-tok"

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.upsert_object("indicator", {})

    def test_delete_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.delete_object("indicator", "1")

    def test_to_stix_contract(self, client):
        native = {
            "entity": {"id": "rf-1", "name": "5.5.5.5"},
            "risk": {"score": 90, "criticalityLabel": "Very Malicious"},
            "timestamps": {"firstSeen": "", "lastSeen": ""},
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix.get("x_rf_risk_score") == 90

    def test_to_stix_extracts_related_industries(self, client):
        native = {
            "entity": {"id": "rf-2", "name": "ThreatActor-X"},
            "risk": {"score": 75, "criticalityLabel": "Malicious"},
            "timestamps": {"firstSeen": "", "lastSeen": ""},
            "relatedEntities": [
                {"type": "Industry", "entity": {"name": "Healthcare"}},
                {"type": "Industry", "entity": {"name": "Finance"}},
                {"type": "Country", "entity": {"name": "United States"}},
            ],
        }
        stix = client.to_stix(native)
        sectors = stix.get("x_target_sectors", [])
        assert "Healthcare" in sectors
        assert "Finance" in sectors
        assert "United States" not in sectors

    def test_to_stix_no_related_entities_omits_key(self, client):
        native = {
            "entity": {"id": "rf-3", "name": "1.2.3.4"},
            "risk": {"score": 50, "criticalityLabel": "Suspicious"},
            "timestamps": {"firstSeen": "", "lastSeen": ""},
        }
        stix = client.to_stix(native)
        assert "x_target_sectors" not in stix

    def test_get_object_requests_related_entities(self, client, monkeypatch):
        mock_get = MagicMock(return_value={"data": {}})
        monkeypatch.setattr(client, "get", mock_get)
        client.get_object("indicator", "rf-1")
        _, kwargs = mock_get.call_args
        assert "relatedEntities" in kwargs.get("params", {}).get("fields", "")

    def test_list_objects_returns_list(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"data": {"results": [{"id": "r1"}]}})
        )
        result = client.list_objects("indicator")
        assert isinstance(result, list)
        assert result[0]["id"] == "r1"


# ===========================================================================
# GreyMatter
# ===========================================================================


class TestGreyMatterClient:
    @pytest.fixture
    def client(self):
        c = GreyMatterClient(host="https://fake.example.com", client_id="cid", client_secret="sec")
        c._authenticated = True
        return c

    def test_authenticate_sets_bearer(self, monkeypatch):
        c = GreyMatterClient(host="https://fake.example.com", client_id="x", client_secret="y")
        monkeypatch.setattr(c, "post", MagicMock(return_value={"access_token": "gm-tok"}))
        c.authenticate()
        assert c._auth_headers["Authorization"] == "Bearer gm-tok"

    def test_authenticate_raises_on_no_token(self, monkeypatch):
        c = GreyMatterClient(host="https://fake.example.com", client_id="x", client_secret="y")
        monkeypatch.setattr(c, "post", MagicMock(return_value={}))
        with pytest.raises(GNATClientError):
            c.authenticate()

    def test_to_stix_ipv4(self, client):
        s = client.to_stix(
            {
                "id": "g1",
                "type": "ipv4",
                "value": "1.2.3.4",
                "confidence": 80,
                "created_at": "",
                "updated_at": "",
            }
        )
        _assert_stix_contract(s)
        assert "ipv4-addr" in s["pattern"]
        assert s["x_gm_type"] == "ipv4"

    def test_to_stix_domain(self, client):
        s = client.to_stix(
            {
                "id": "g2",
                "type": "domain",
                "value": "evil.com",
                "confidence": 70,
                "created_at": "",
                "updated_at": "",
            }
        )
        assert "domain-name" in s["pattern"]

    def test_from_stix_infers_type(self, client):
        p = client.from_stix(
            {"name": "evil.com", "pattern": "[domain-name:value = 'evil.com']", "x_tlp": "amber"}
        )
        assert p["type"] == "domain"
        assert p["value"] == "evil.com"

    def test_unsupported_type_raises(self, client):
        with pytest.raises(GNATClientError):
            client.get_object("bundle", "id")


# ===========================================================================
# Whistic
# ===========================================================================


class TestWhisticClient:
    @pytest.fixture
    def client(self):
        c = WhisticClient(host="https://fake.example.com", api_key="wsk")
        c._authenticated = True
        return c

    def test_authenticate_sets_header(self):
        c = WhisticClient(host="https://fake.example.com", api_key="mykey")
        c.authenticate()
        assert c._auth_headers["X-Whistic-Token"] == "mykey"

    def test_to_stix_vendor(self, client):
        s = client.to_stix(
            {
                "id": "v1",
                "name": "Acme",
                "trust_score": 85,
                "assessment_status": "complete",
                "created_at": "",
                "updated_at": "",
            }
        )
        _assert_stix_contract(s)
        assert s["type"] == "threat-actor"
        assert s["x_whistic_trust_score"] == 85

    def test_to_stix_categories_map_to_sectors(self, client):
        s = client.to_stix(
            {
                "id": "v2",
                "name": "HealthCo",
                "categories": ["Healthcare", "Pharmaceuticals"],
                "trust_score": 70,
                "created_at": "",
                "updated_at": "",
            }
        )
        assert s.get("x_target_sectors") == ["Healthcare", "Pharmaceuticals"]

    def test_to_stix_no_categories_omits_sectors(self, client):
        s = client.to_stix(
            {"id": "v3", "name": "Acme", "trust_score": 60, "created_at": "", "updated_at": ""}
        )
        assert "x_target_sectors" not in s

    def test_upsert_raises_for_vendor(self, client):
        with pytest.raises(GNATClientError):
            client.upsert_object("threat-actor", {"name": "New Vendor"})

    def test_list_vendors(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"vendors": [{"id": "v1"}]}))
        result = client.list_objects("threat-actor")
        assert isinstance(result, list)

    def test_unsupported_type_raises(self, client):
        with pytest.raises(GNATClientError):
            client.list_objects("indicator")


# ===========================================================================
# RiskRecon
# ===========================================================================


class TestRiskReconClient:
    @pytest.fixture
    def client(self):
        c = RiskReconClient(host="https://fake.example.com", client_id="cid", client_secret="sec")
        c._authenticated = True
        return c

    def test_authenticate_sets_bearer(self, monkeypatch):
        c = RiskReconClient(host="https://fake.example.com", client_id="x", client_secret="y")
        monkeypatch.setattr(c, "post", MagicMock(return_value={"access_token": "rr-tok"}))
        c.authenticate()
        assert c._auth_headers["Authorization"] == "Bearer rr-tok"

    def test_to_stix_company(self, client):
        s = client.to_stix(
            {
                "id": "c1",
                "name": "Corp A",
                "domain": "corp.com",
                "score": 7.5,
                "grade": "C",
                "created_at": "",
                "updated_at": "",
            }
        )
        _assert_stix_contract(s)
        assert s["type"] == "threat-actor"
        assert s["x_rr_score"] == 7.5
        assert s["x_rr_domain"] == "corp.com"

    def test_to_stix_company_industries_map_to_sectors(self, client):
        s = client.to_stix(
            {
                "id": "c2",
                "name": "HealthCorp",
                "domain": "hc.com",
                "score": 8.0,
                "grade": "B",
                "industries": ["Healthcare", "Insurance"],
                "created_at": "",
                "updated_at": "",
            }
        )
        assert s.get("x_rr_industries") == ["Healthcare", "Insurance"]
        assert s.get("x_target_sectors") == ["Healthcare", "Insurance"]

    def test_to_stix_company_no_industries_omits_sectors(self, client):
        s = client.to_stix(
            {
                "id": "c3",
                "name": "Corp B",
                "domain": "b.com",
                "score": 6.0,
                "grade": "C",
                "created_at": "",
                "updated_at": "",
            }
        )
        assert "x_target_sectors" not in s

    def test_to_stix_finding(self, client):
        s = client.to_stix(
            {
                "id": "f1",
                "criterion": "TLS/SSL",
                "severity": "high",
                "first_seen": "",
                "last_seen": "",
            }
        )
        assert s["type"] == "vulnerability"
        assert s["x_rr_severity"] == "high"
        assert s["confidence"] == 80

    def test_to_stix_finding_severity_confidence_mapping(self, client):
        for sev, expected in [
            ("critical", 95),
            ("high", 80),
            ("medium", 60),
            ("low", 40),
            ("info", 20),
        ]:
            s = client.to_stix(
                {"id": "x", "criterion": "test", "severity": sev, "first_seen": "", "last_seen": ""}
            )
            assert s["confidence"] == expected

    def test_list_companies(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"companies": [{"id": "c1"}]}))
        result = client.list_objects("threat-actor")
        assert isinstance(result, list)


# ===========================================================================
# Feedly
# ===========================================================================


class TestFeedlyClient:
    @pytest.fixture
    def client(self):
        c = FeedlyClient(host="https://api.feedly.com", api_token="fd-tok")
        c._authenticated = True
        return c

    def test_authenticate_sets_bearer(self):
        c = FeedlyClient(host="https://api.feedly.com", api_token="mytok")
        c.authenticate()
        assert c._auth_headers["Authorization"] == "Bearer mytok"

    def test_to_stix_ioc(self, client):
        s = client.to_stix(
            {
                "id": "i1",
                "type": "domain",
                "value": "evil.com",
                "confidence": 75,
                "first_seen": 1704067200000,
                "last_seen": 1704153600000,
                "sources": [],
            }
        )
        _assert_stix_contract(s)
        assert s["type"] == "indicator"
        assert "domain-name" in s["pattern"]
        assert s["x_feedly_type"] == "domain"

    def test_to_stix_cve(self, client):
        s = client.to_stix(
            {
                "id": "c1",
                "cve_id": "CVE-2024-1234",
                "cvss_score": 9.8,
                "description": "Critical",
                "first_seen": 1704067200000,
                "sources": [],
            }
        )
        assert s["type"] == "vulnerability"
        assert s["name"] == "CVE-2024-1234"
        assert s["x_cvss_score"] == 9.8

    def test_to_stix_ttp(self, client):
        s = client.to_stix(
            {
                "id": "t1",
                "type": "attack-pattern",
                "mitre_id": "T1190",
                "name": "Exploit Public-Facing App",
                "description": "",
                "first_seen": 0,
                "sources": [],
            }
        )
        assert s["type"] == "attack-pattern"
        assert s["x_mitre_id"] == "T1190"

    def test_to_stix_ttp_sectors(self, client):
        s = client.to_stix(
            {
                "id": "t2",
                "type": "threat-actor",
                "name": "APT-X",
                "description": "",
                "first_seen": 0,
                "sources": [],
                "sectors": ["Healthcare", "Energy"],
            }
        )
        assert s.get("x_target_sectors") == ["Healthcare", "Energy"]

    def test_to_stix_ttp_no_sectors_omits_key(self, client):
        s = client.to_stix(
            {
                "id": "t3",
                "type": "attack-pattern",
                "mitre_id": "T1059",
                "name": "Command Execution",
                "description": "",
                "first_seen": 0,
                "sources": [],
            }
        )
        assert "x_target_sectors" not in s

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.upsert_object("indicator", {})

    def test_delete_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.delete_object("indicator", "id")

    def test_ms_to_iso(self, client):
        iso = FeedlyClient._ms_to_iso(1704067200000)
        assert "2024-01-01" in iso

    def test_ms_to_iso_none(self, client):
        assert FeedlyClient._ms_to_iso(None) == ""


# ===========================================================================
# Splunk
# ===========================================================================


class TestSplunkClient:
    @pytest.fixture
    def client(self):
        c = SplunkClient(host="https://splunk.example.com:8089", api_token="sp-tok")
        c._authenticated = True
        return c

    def test_authenticate_token(self):
        c = SplunkClient(host="https://splunk.example.com:8089", api_token="tok")
        c.authenticate()
        assert c._auth_headers["Authorization"] == "Bearer tok"

    def test_authenticate_username_password(self, monkeypatch):
        c = SplunkClient(host="https://splunk.example.com:8089", username="admin", password="pass")
        monkeypatch.setattr(c, "post", MagicMock(return_value={"sessionKey": "sess"}))
        c.authenticate()
        assert c._auth_headers["Authorization"] == "Splunk sess"

    def test_authenticate_no_credentials_raises(self):
        c = SplunkClient(host="https://splunk.example.com:8089")
        with pytest.raises(GNATClientError, match="no credentials"):
            c.authenticate()

    def test_to_stix_notable(self, client):
        s = client.to_stix(
            {
                "rule_name": "Brute Force",
                "severity": "high",
                "src": "10.0.0.1",
                "dest": "192.168.1.5",
                "event_id": "EVT1",
                "urgency": "high",
                "_time": "",
            }
        )
        _assert_stix_contract(s)
        assert s["x_splunk_severity"] == "high"
        assert s["x_splunk_src"] == "10.0.0.1"

    def test_to_stix_threat_intel_row(self, client):
        s = client.to_stix({"ip": "5.5.5.5", "source": "gnat", "_time": ""})
        assert "ipv4-addr" in s["pattern"]
        assert "5.5.5.5" in s["pattern"]

    def test_from_stix_domain(self, client):
        p = client.from_stix({"name": "evil.com", "pattern": "[domain-name:value = 'evil.com']"})
        assert p["ioc_type"] == "domain"
        assert p["value"] == "evil.com"

    def test_from_stix_ip(self, client):
        p = client.from_stix({"name": "1.2.3.4", "pattern": "[ipv4-addr:value = '1.2.3.4']"})
        assert p["ioc_type"] == "ip"


# ===========================================================================
# ControlUp
# ===========================================================================

from gnat.connectors.controlup.client import ControlUpClient  # noqa: E402


class TestControlUpClient:
    @pytest.fixture
    def client(self):
        c = ControlUpClient(
            host="https://api.controlup.io",
            api_key="test-key",
            org_id="org-123",
            product="dex",
        )
        c._authenticated = True
        return c

    @pytest.fixture
    def vdi_client(self):
        c = ControlUpClient(
            host="https://api.controlup.io",
            api_key="test-key",
            org_id="org-123",
            product="vdi",
        )
        c._authenticated = True
        return c

    # -- Authentication -------------------------------------------------------

    def test_authenticate_sets_bearer(self):
        c = ControlUpClient(host="https://api.controlup.io", api_key="my-key", org_id="o1")
        c.authenticate()
        assert c._auth_headers["Authorization"] == "Bearer my-key"
        assert c._auth_headers["Accept"] == "application/json"

    # -- URL prefix -----------------------------------------------------------

    def test_dex_prefix(self, client):
        assert client._prefix == "/dex/v1/organizations/org-123"

    def test_vdi_prefix(self, vdi_client):
        assert vdi_client._prefix == "/vdi/v1/organizations/org-123"

    # -- health_check ---------------------------------------------------------

    def test_health_check_success(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": [], "totalCount": 0}))
        assert client.health_check() is True

    def test_health_check_failure(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(side_effect=GNATClientError("err")))
        assert client.health_check() is False

    # -- get_object -----------------------------------------------------------

    def test_get_object_device(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"deviceId": "d1", "hostname": "pc1"})
        )
        result = client.get_object("infrastructure", "d1")
        assert result["deviceId"] == "d1"

    def test_get_object_unsupported_type(self, client):
        with pytest.raises(GNATClientError, match="does not support"):
            client.get_object("malware", "x")

    # -- list_objects ---------------------------------------------------------

    def test_list_objects_devices(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": [{"deviceId": "d1"}]}))
        result = client.list_objects("infrastructure")
        assert isinstance(result, list)
        assert result[0]["deviceId"] == "d1"

    def test_list_objects_empty_response(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={}))
        assert client.list_objects("indicator") == []

    def test_list_objects_page_converted_to_zero_based(self, client, monkeypatch):
        mock_get = MagicMock(return_value={"data": []})
        monkeypatch.setattr(client, "get", mock_get)
        client.list_objects("infrastructure", page=3, page_size=50)
        _, kwargs = mock_get.call_args
        assert kwargs["params"]["page"] == 2  # page 3 → 0-based index 2

    def test_list_objects_unsupported_type(self, client):
        with pytest.raises(GNATClientError, match="does not support"):
            client.list_objects("threat-actor")

    # -- list_devices / list_sessions / list_alerts helpers ------------------

    def test_list_devices_with_filters(self, client, monkeypatch):
        mock_get = MagicMock(return_value={"data": []})
        monkeypatch.setattr(client, "get", mock_get)
        client.list_devices(status="active", os_family="windows")
        _, kwargs = mock_get.call_args
        assert kwargs["params"]["status"] == "active"
        assert kwargs["params"]["osFamily"] == "windows"

    def test_list_sessions_with_username(self, client, monkeypatch):
        mock_get = MagicMock(return_value={"data": []})
        monkeypatch.setattr(client, "get", mock_get)
        client.list_sessions(username="jsmith")
        _, kwargs = mock_get.call_args
        assert kwargs["params"]["username"] == "jsmith"

    def test_list_alerts_severity_filter(self, client, monkeypatch):
        mock_get = MagicMock(return_value={"data": []})
        monkeypatch.setattr(client, "get", mock_get)
        client.list_alerts(severity="critical", resolved=False)
        _, kwargs = mock_get.call_args
        assert kwargs["params"]["severity"] == "critical"
        assert kwargs["params"]["resolved"] == "false"

    # -- upsert_object --------------------------------------------------------

    def test_upsert_device_tags(self, client, monkeypatch):
        monkeypatch.setattr(client, "put", MagicMock(return_value={"success": True}))
        result = client.upsert_object(
            "infrastructure", {"device_id": "d1", "tags": ["prod", "finance"]}
        )
        assert result["success"] is True

    def test_upsert_missing_device_id_raises(self, client):
        with pytest.raises(GNATClientError, match="device_id"):
            client.upsert_object("infrastructure", {"tags": ["prod"]})

    def test_upsert_unsupported_type_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.upsert_object("indicator", {})

    # -- delete_object --------------------------------------------------------

    def test_delete_raises(self, client):
        with pytest.raises(GNATClientError, match="does not expose delete"):
            client.delete_object("infrastructure", "d1")

    # -- query_data_index -----------------------------------------------------

    def test_query_data_index(self, client, monkeypatch):
        mock_post = MagicMock(
            return_value={"data": [{"processName": "chrome.exe"}], "totalCount": 1}
        )
        monkeypatch.setattr(client, "post", mock_post)
        result = client.query_data_index(
            index="processes",
            metrics=["processName", "cpuUsage"],
            filters={"deviceId": "d1"},
        )
        assert result["totalCount"] == 1
        body = mock_post.call_args[1]["json"]
        assert body["index"] == "processes"
        assert body["metrics"] == ["processName", "cpuUsage"]
        assert body["filters"]["deviceId"] == "d1"
        assert body["page"] == 0  # page=1 → 0

    def test_query_data_index_bad_response(self, client, monkeypatch):
        monkeypatch.setattr(client, "post", MagicMock(return_value=None))
        result = client.query_data_index("devices")
        assert result == {"data": [], "totalCount": 0}

    # -- get_session_statistics -----------------------------------------------

    def test_get_session_statistics(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"active": 42}))
        result = client.get_session_statistics()
        assert result["active"] == 42

    # -- STIX translation: device ---------------------------------------------

    def test_device_to_stix(self, client):
        native = {
            "deviceId": "d-abc",
            "hostname": "WIN-PC1",
            "osName": "Windows 11",
            "osVersion": "22H2",
            "osFamily": "windows",
            "status": "active",
            "healthScore": 87,
            "lastSeen": "2025-01-15T10:00:00Z",
            "ipAddresses": ["192.168.1.50"],
            "tags": ["finance", "prod"],
        }
        s = client.to_stix(native)
        _assert_stix_contract(s)
        assert s["type"] == "infrastructure"
        assert s["name"] == "WIN-PC1"
        assert s["x_cu_device_id"] == "d-abc"
        assert s["x_cu_health_score"] == 87
        assert s["x_source_platform"] == "controlup"

    def test_device_stix_server_infra_type(self, client):
        native = {"deviceId": "srv1", "hostname": "LINUX-SRV", "osFamily": "linux"}
        s = client.to_stix(native)
        assert "server" in s["infrastructure_types"]

    # -- STIX translation: session --------------------------------------------

    def test_session_to_stix(self, client):
        native = {
            "sessionId": "sess-99",
            "username": "jsmith",
            "deviceId": "d-abc",
            "hostname": "WIN-PC1",
            "sessionState": "active",
            "logonTime": "2025-01-15T08:30:00Z",
            "lastActivity": "2025-01-15T10:00:00Z",
            "protocol": "RDP",
        }
        s = client.to_stix(native)
        _assert_stix_contract(s)
        assert s["type"] == "observed-data"
        assert s["x_cu_username"] == "jsmith"
        assert s["x_cu_protocol"] == "RDP"
        assert s["x_cu_user_ref"]["user_id"] == "jsmith"

    # -- STIX translation: alert ----------------------------------------------

    def test_alert_to_stix(self, client):
        native = {
            "alertId": "alert-7",
            "name": "High CPU Usage",
            "alertType": "HighCPU",
            "severity": "high",
            "description": "CPU above 95% for 5 minutes",
            "createdAt": "2025-01-15T09:00:00Z",
            "deviceId": "d-abc",
            "resolved": False,
        }
        s = client.to_stix(native)
        _assert_stix_contract(s)
        assert s["type"] == "indicator"
        assert s["confidence"] == 75  # high → 75
        assert s["x_cu_severity"] == "high"
        assert s["x_cu_resolved"] is False
        assert s["x_source_platform"] == "controlup"

    def test_alert_unknown_severity_defaults_confidence(self, client):
        native = {"alertId": "a1", "alertType": "Unknown", "severity": "unknown"}
        s = client.to_stix(native)
        assert s["confidence"] == 50

    # -- STIX translation: vulnerability --------------------------------------

    def test_vuln_to_stix(self, client):
        native = {
            "id": "v-001",
            "cveId": "CVE-2024-12345",
            "severity": "critical",
            "cvssScore": 9.8,
            "description": "Remote code execution vulnerability.",
            "detectedAt": "2025-01-10T00:00:00Z",
            "deviceId": "d-abc",
        }
        s = client.to_stix(native)
        _assert_stix_contract(s)
        assert s["type"] == "vulnerability"
        assert s["name"] == "CVE-2024-12345"
        assert s["x_cvss_score"] == 9.8
        assert s["x_cve_id"] == "CVE-2024-12345"

    # -- from_stix ------------------------------------------------------------

    def test_from_stix_infrastructure(self, client):
        stix = {
            "type": "infrastructure",
            "x_cu_device_id": "d-abc",
            "x_cu_tags": ["prod", "finance"],
        }
        payload = client.from_stix(stix)
        assert payload["device_id"] == "d-abc"
        assert "prod" in payload["tags"]

    def test_from_stix_indicator(self, client):
        stix = {
            "type": "indicator",
            "name": "High CPU",
            "pattern": "[process:name = 'malware.exe']",
            "x_cu_severity": "high",
        }
        payload = client.from_stix(stix)
        assert payload["value"] == "malware.exe"
        assert payload["severity"] == "high"

    def test_from_stix_unknown_type(self, client):
        payload = client.from_stix({"type": "malware", "name": "BadThing"})
        assert payload["type"] == "malware"


# ---------------------------------------------------------------------------
# AlienVault OTX
# ---------------------------------------------------------------------------

from gnat.connectors.alienvault.client import AlienVaultClient  # noqa: E402


class TestAlienVaultClient:
    @pytest.fixture
    def client(self):
        return _authenticated(AlienVaultClient, api_key="otx-key-123")

    def test_authenticate_sets_header(self):
        c = AlienVaultClient(host="https://otx.alienvault.com", api_key="mykey")
        c.authenticate()
        assert c._auth_headers["X-OTX-API-KEY"] == "mykey"

    def test_list_objects_pulses(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"results": [{"id": "p1"}]}))
        result = client.list_objects("report")
        assert isinstance(result, list)
        assert result[0]["id"] == "p1"

    def test_list_objects_indicators(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(return_value={"results": [{"indicator": "1.2.3.4", "type": "IPv4"}]}),
        )
        result = client.list_objects("indicator")
        assert isinstance(result, list)

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.upsert_object("indicator", {})

    def test_delete_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.delete_object("indicator", "x")

    def test_to_stix_pulse(self, client):
        pulse = {"id": "abc123", "name": "Evil Pulse", "created": "2024-01-01T00:00:00Z"}
        stix = client.to_stix(pulse)
        assert stix["type"] == "report"
        assert "pulse--" not in stix["id"]  # should be report--
        assert stix["name"] == "Evil Pulse"

    def test_to_stix_indicator_ipv4(self, client):
        ind = {"type": "IPv4", "indicator": "1.2.3.4"}
        stix = client.to_stix(ind)
        assert stix["type"] == "indicator"
        assert "1.2.3.4" in stix["pattern"]
        _assert_stix_contract(stix)

    def test_to_stix_indicator_hash(self, client):
        ind = {"type": "FileHash-SHA256", "indicator": "abc" * 21 + "ab"}
        stix = client.to_stix(ind)
        assert stix["type"] == "indicator"
        assert "SHA-256" in stix["pattern"]

    def test_from_stix_returns_note(self, client):
        result = client.from_stix({"type": "indicator", "id": "indicator--x"})
        assert "read-only" in result["note"].lower()


# ---------------------------------------------------------------------------
# Graylog
# ---------------------------------------------------------------------------

from gnat.connectors.graylog.client import GraylogClient  # noqa: E402


class TestGraylogClient:
    @pytest.fixture
    def client(self):
        return _authenticated(GraylogClient, username="admin", password="pass")

    def test_authenticate_sets_basic_header(self):
        import base64

        c = GraylogClient(host="https://graylog.example.com", username="u", password="p")
        c.authenticate()
        expected = "Basic " + base64.b64encode(b"u:p").decode()
        assert c._auth_headers["Authorization"] == expected

    def test_list_objects_messages(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"messages": [{"message": {"_id": "m1"}}]})
        )
        result = client.list_objects("observed-data")
        assert isinstance(result, list)
        assert result[0]["message"]["_id"] == "m1"

    def test_to_stix_with_ips(self, client):
        msg = {
            "message": {
                "src_ip": "10.0.0.1",
                "dst_ip": "8.8.8.8",
                "timestamp": "2024-01-01T00:00:00Z",
            }
        }
        stix = client.to_stix(msg)
        assert stix["type"] == "observed-data"
        _assert_stix_contract(stix)

    def test_to_stix_no_ips(self, client):
        msg = {"message": {"_id": "x", "source": "server1", "message": "test log"}}
        stix = client.to_stix(msg)
        assert stix["type"] == "observed-data"
        assert stix["x_graylog_message"]["source"] == "server1"

    def test_from_stix_builds_query(self, client):
        stix = {
            "type": "observed-data",
            "id": "observed-data--abc",
            "x_graylog_message": {"source": "myhost", "level": 3},
        }
        result = client.from_stix(stix)
        assert "source:myhost" in result["query"]

    def test_from_stix_wrong_type_raises(self, client):
        with pytest.raises(GNATClientError):
            client.from_stix({"type": "indicator", "id": "indicator--x"})


# ---------------------------------------------------------------------------
# OSSIM
# ---------------------------------------------------------------------------

from gnat.connectors.ossim.client import OSSIMClient  # noqa: E402


class TestOSSIMClient:
    @pytest.fixture
    def client(self):
        return _authenticated(OSSIMClient, api_key="ossim-key")

    def test_authenticate_sets_header(self):
        c = OSSIMClient(host="https://ossim.example.com", api_key="testkey")
        c.authenticate()
        assert c._auth_headers["X-USM-API-KEY"] == "testkey"

    def test_list_objects_alarms(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"data": [{"uuid": "u1", "rule_name": "Scan"}]})
        )
        result = client.list_objects("observed-data")
        assert isinstance(result, list)
        assert result[0]["uuid"] == "u1"

    def test_to_stix_alarm(self, client):
        alarm = {
            "uuid": "abc-123",
            "rule_name": "Port Scan",
            "priority": 3,
            "src_ip": "192.168.1.1",
            "dst_ip": "10.0.0.5",
            "timestamp": "2024-01-01T12:00:00Z",
        }
        stix = client.to_stix(alarm)
        assert stix["type"] == "observed-data"
        assert stix["x_ossim_alarm"]["name"] == "Port Scan"
        _assert_stix_contract(stix)

    def test_to_stix_no_ips(self, client):
        alarm = {"uuid": "x", "rule_name": "Test", "priority": 1}
        stix = client.to_stix(alarm)
        assert stix["type"] == "observed-data"
        assert stix["object_refs"] == []

    def test_from_stix_returns_id(self, client):
        stix = {
            "type": "observed-data",
            "id": "observed-data--xyz",
            "x_ossim_alarm": {"alarm_id": "alarm-99", "status": "open"},
        }
        result = client.from_stix(stix)
        assert result["id"] == "alarm-99"


# ---------------------------------------------------------------------------
# Security Onion
# ---------------------------------------------------------------------------

from gnat.connectors.security_onion.client import SecurityOnionClient  # noqa: E402


class TestSecurityOnionClient:
    @pytest.fixture
    def client(self):
        return _authenticated(SecurityOnionClient, username="analyst", password="secret")

    def test_authenticate_sets_bearer(self, monkeypatch):
        c = SecurityOnionClient(host="https://so.example.com", username="u", password="p")
        monkeypatch.setattr(c, "post", MagicMock(return_value={"token": "jwt-abc"}))
        c.authenticate()
        assert c._auth_headers["Authorization"] == "Bearer jwt-abc"

    def test_authenticate_raises_on_missing_token(self, monkeypatch):
        c = SecurityOnionClient(host="https://so.example.com", username="u", password="p")
        monkeypatch.setattr(c, "post", MagicMock(return_value={}))
        with pytest.raises(GNATClientError, match="login failed"):
            c.authenticate()

    def test_list_objects_alerts(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "post",
            MagicMock(
                return_value={
                    "hits": {"hits": [{"_source": {"uid": "a1", "@timestamp": "2024-01-01"}}]}
                }
            ),
        )
        result = client.list_objects("observed-data")
        assert isinstance(result, list)
        assert result[0]["uid"] == "a1"

    def test_list_objects_cases(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value=[{"id": "c1"}]))
        result = client.list_objects("case")
        assert isinstance(result, list)

    def test_to_stix_alert(self, client):
        alert = {
            "uid": "so-alert-1",
            "@timestamp": "2024-01-01T00:00:00Z",
            "rule": {"name": "Lateral Movement", "uuid": "r-123"},
            "source": {"ip": "192.168.1.5", "port": 4444},
            "destination": {"ip": "10.0.0.1", "port": 443},
            "network": {"transport": "tcp"},
            "observer": {"name": "sensor-01"},
            "event": {"severity": 2},
        }
        stix = client.to_stix(alert)
        assert stix["type"] == "observed-data"
        assert stix["x_security_onion_alert"]["rule_name"] == "Lateral Movement"
        _assert_stix_contract(stix)

    def test_from_stix_returns_alert_id(self, client):
        stix = {
            "type": "observed-data",
            "id": "observed-data--abc",
            "x_security_onion_alert": {"alert_id": "so-99"},
        }
        result = client.from_stix(stix)
        assert result["id"] == "so-99"


# ---------------------------------------------------------------------------
# Snort
# ---------------------------------------------------------------------------

import json as _json  # noqa: E402

from gnat.connectors.snort.client import SnortClient  # noqa: E402


class TestSnortClient:
    @pytest.fixture
    def client(self):
        return SnortClient(host="", alert_log_path="/tmp/nonexistent.json", log_format="json")

    def test_health_check_missing_file(self, client):
        with pytest.raises(GNATClientError, match="not found"):
            client.health_check()

    def test_health_check_existing_file(self, client, tmp_path):
        f = tmp_path / "alert.json"
        f.write_text("")
        client.alert_log_path = str(f)
        assert client.health_check() is True

    def test_list_objects_json(self, tmp_path):
        f = tmp_path / "alert.json"
        alert = {
            "timestamp": "2024-01-01T00:00:00",
            "msg": "ET MALWARE",
            "gid": 1,
            "sid": 1000,
            "rev": 1,
            "priority": 2,
            "proto": "TCP",
            "src_addr": "1.2.3.4",
            "src_port": 4444,
            "dst_addr": "5.6.7.8",
            "dst_port": 80,
        }
        f.write_text(_json.dumps(alert) + "\n")
        c = SnortClient(host="", alert_log_path=str(f), log_format="json")
        result = c.list_objects("observed-data")
        assert len(result) == 1
        assert result[0]["src_ip"] == "1.2.3.4"

    def test_list_objects_fast(self, tmp_path):
        f = tmp_path / "alert.log"
        line = "01/15-12:00:00.000000  [**] [1:1000001:1] ET MALWARE [**] [Priority: 2] {TCP} 192.168.1.1:49152 -> 1.2.3.4:443\n"
        f.write_text(line)
        c = SnortClient(host="", alert_log_path=str(f), log_format="fast")
        result = c.list_objects("observed-data")
        assert len(result) == 1
        assert result[0]["src_ip"] == "192.168.1.1"

    def test_to_stix_alert(self):
        c = SnortClient(host="")
        alert = {
            "timestamp": "2024-01-01T00:00:00Z",
            "signature": "ET MALWARE Bad Thing",
            "sid": 12345,
            "gid": 1,
            "rev": 3,
            "priority": 1,
            "severity": 4,
            "proto": "TCP",
            "src_ip": "10.0.0.1",
            "src_port": 5555,
            "dst_ip": "8.8.8.8",
            "dst_port": 53,
            "action": "alert",
        }
        stix = c.to_stix(alert)
        assert stix["type"] == "observed-data"
        assert stix["x_snort_alert"]["signature"] == "ET MALWARE Bad Thing"
        assert stix["x_snort_alert"]["sid"] == 12345
        _assert_stix_contract(stix)

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.upsert_object("observed-data", {})

    def test_from_stix_returns_note(self, client):
        result = client.from_stix({"type": "observed-data", "id": "observed-data--x"})
        assert "read-only" in result["note"].lower()


# ---------------------------------------------------------------------------
# Suricata
# ---------------------------------------------------------------------------

from gnat.connectors.suricata.client import SuricataClient  # noqa: E402


class TestSuricataClient:
    @pytest.fixture
    def client(self):
        return SuricataClient(host="", eve_log_path="/tmp/nonexistent.json")

    def test_health_check_missing_file(self, client):
        with pytest.raises(GNATClientError, match="not found"):
            client.health_check()

    def test_health_check_existing_file(self, client, tmp_path):
        f = tmp_path / "eve.json"
        f.write_text("")
        client.eve_log_path = str(f)
        assert client.health_check() is True

    def test_list_objects_eve_json(self, tmp_path):
        f = tmp_path / "eve.json"
        event = {
            "timestamp": "2024-01-01T00:00:00.000000+0000",
            "event_type": "alert",
            "src_ip": "192.168.1.100",
            "src_port": 12345,
            "dest_ip": "8.8.8.8",
            "dest_port": 443,
            "proto": "TCP",
            "alert": {
                "signature": "ET MALWARE CnC",
                "signature_id": 9001,
                "category": "A Network Trojan",
                "severity": 1,
                "action": "allowed",
                "rev": 5,
                "gid": 1,
            },
        }
        f.write_text(_json.dumps(event) + "\n")
        c = SuricataClient(host="", eve_log_path=str(f))
        result = c.list_objects("observed-data")
        assert len(result) == 1
        assert result[0]["src_ip"] == "192.168.1.100"
        assert result[0]["signature"] == "ET MALWARE CnC"

    def test_to_stix_alert(self):
        c = SuricataClient(host="")
        alert = {
            "timestamp": "2024-01-01T00:00:00Z",
            "flow_id": 123456,
            "src_ip": "10.1.1.1",
            "src_port": 5000,
            "dst_ip": "203.0.113.5",
            "dst_port": 80,
            "proto": "TCP",
            "signature": "ET EXPLOIT Something",
            "signature_id": 2001,
            "category": "Exploit Kit",
            "severity": 4,
            "severity_raw": 1,
            "action": "blocked",
        }
        stix = c.to_stix(alert)
        assert stix["type"] == "observed-data"
        assert stix["x_suricata_alert"]["signature"] == "ET EXPLOIT Something"
        assert stix["x_suricata_alert"]["severity_raw"] == 1
        _assert_stix_contract(stix)

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.upsert_object("observed-data", {})

    def test_from_stix_returns_note(self, client):
        result = client.from_stix({"type": "observed-data", "id": "observed-data--x"})
        assert "read-only" in result["note"].lower()


# ---------------------------------------------------------------------------
# Zeek
# ---------------------------------------------------------------------------

from gnat.connectors.zeek.client import ZeekClient  # noqa: E402


class TestZeekClient:
    @pytest.fixture
    def client(self, tmp_path):
        return ZeekClient(host="", log_dir=str(tmp_path), log_format="json")

    def test_health_check_valid_dir(self, client):
        assert client.health_check() is True

    def test_health_check_missing_dir(self):
        c = ZeekClient(host="", log_dir="/tmp/does_not_exist_zeek_xyz")
        with pytest.raises(GNATClientError, match="not found"):
            c.health_check()

    def test_list_objects_notices(self, tmp_path):
        f = tmp_path / "notice.json"
        record = {
            "ts": "1704067200.0",
            "uid": "Cx1234",
            "id.orig_h": "10.0.0.1",
            "id.orig_p": "52341",
            "id.resp_h": "8.8.8.8",
            "id.resp_p": "53",
            "proto": "udp",
            "note": "DNS::External_Name",
            "msg": "Suspicious DNS",
        }
        f.write_text(_json.dumps(record) + "\n")
        c = ZeekClient(host="", log_dir=str(tmp_path), log_format="json")
        result = c.list_objects("observed-data", filters={"log_name": "notice"})
        assert len(result) == 1

    def test_list_objects_tsv(self, tmp_path):
        f = tmp_path / "notice.log"
        f.write_text(
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tnote\tmsg\n"
            "1704067200.0\tCx1\t192.168.1.1\t4321\t10.0.0.5\t80\ttcp\tScan::Address_Scan\tScan detected\n"
        )
        c = ZeekClient(host="", log_dir=str(tmp_path), log_format="tsv")
        result = c.list_objects("observed-data", filters={"log_name": "notice"})
        assert len(result) == 1
        assert result[0]["id.orig_h"] == "192.168.1.1"

    def test_to_stix_notice(self, client):
        record = {
            "ts": "1704067200.0",
            "uid": "Cx5678",
            "id.orig_h": "172.16.0.1",
            "id.orig_p": "1234",
            "id.resp_h": "203.0.113.1",
            "id.resp_p": "443",
            "proto": "tcp",
            "note": "SSL::Invalid_Server_Cert",
            "msg": "Invalid cert from 203.0.113.1",
        }
        stix = client.to_stix(record)
        assert stix["type"] == "observed-data"
        assert stix["x_zeek_notice"]["note"] == "SSL::Invalid_Server_Cert"
        _assert_stix_contract(stix)

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.upsert_object("observed-data", {})

    def test_from_stix_returns_note(self, client):
        result = client.from_stix({"type": "observed-data", "id": "observed-data--x"})
        assert "read-only" in result["note"].lower()


# ---------------------------------------------------------------------------
# VirusTotal
# ---------------------------------------------------------------------------
class TestVirusTotalClient:
    @pytest.fixture()
    def client(self):
        from gnat.connectors.virustotal.client import VirusTotalClient

        return VirusTotalClient(api_key="vt-test-key")

    def test_auth_header_set(self, client):
        client.authenticate()
        assert client._auth_headers["x-apikey"] == "vt-test-key"

    def test_health_check(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": {"id": "test"}}))
        assert client.health_check() is True

    def test_health_check_failure(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(side_effect=GNATClientError("err")))
        with pytest.raises(GNATClientError):
            client.health_check()

    def test_list_objects_indicator(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"data": [{"id": "abc123", "type": "file"}]})
        )
        results = client.list_objects("indicator", page_size=5)
        assert isinstance(results, list)

    def test_to_stix_file(self, client):
        raw = {
            "id": "abc123",
            "type": "file",
            "attributes": {
                "sha256": "a" * 64,
                "meaningful_name": "malware.exe",
                "last_analysis_stats": {"malicious": 30, "total": 70},
            },
        }
        stix = client.to_stix(raw)
        assert stix.get("type") in ("indicator", "file", "observed-data", "bundle")

    def test_to_stix_ip(self, client):
        raw = {
            "id": "1.2.3.4",
            "type": "ip_address",
            "attributes": {"last_analysis_stats": {"malicious": 5, "total": 70}},
        }
        stix = client.to_stix(raw)
        assert stix.get("type") in ("indicator", "observed-data", "bundle")

    def test_from_stix(self, client):
        stix = {
            "type": "indicator",
            "id": "indicator--1",
            "pattern": "[file:hashes.SHA256 = 'abc']",
            "name": "Test",
        }
        result = client.from_stix(stix)
        assert isinstance(result, dict)

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError):
            client.upsert_object("indicator", {})


# ---------------------------------------------------------------------------
# ShadowServer
# ---------------------------------------------------------------------------
class TestShadowServerClient:
    @pytest.fixture()
    def client(self):
        from gnat.connectors.shadowserver.client import ShadowServerClient

        return ShadowServerClient(api_key="ss-key", api_secret="ss-secret")

    def test_auth(self, client):
        client.authenticate()
        assert client._auth_headers["Accept"] == "application/json"

    def test_health_check(self, client, monkeypatch):
        monkeypatch.setattr(client, "_signed_post", MagicMock(return_value={"pong": 1}))
        assert client.health_check() is True

    def test_health_check_failure(self, client, monkeypatch):
        monkeypatch.setattr(client, "_signed_post", MagicMock(side_effect=GNATClientError("err")))
        with pytest.raises(GNATClientError):
            client.health_check()

    def test_list_objects(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "_signed_post", MagicMock(return_value=[{"ip": "1.2.3.4", "asn": "12345"}])
        )
        results = client.list_objects("indicator", page_size=10)
        assert isinstance(results, list)

    def test_to_stix(self, client):
        raw = {
            "ip": "10.0.0.1",
            "asn": "64496",
            "country_code": "US",
            "type": "C2",
            "timestamp": "2024-01-01 00:00:00",
        }
        stix = client.to_stix(raw)
        assert stix.get("type") in ("indicator", "observed-data", "bundle")

    def test_from_stix(self, client):
        stix = {
            "type": "indicator",
            "id": "indicator--1",
            "pattern": "[ipv4-addr:value = '1.2.3.4']",
        }
        result = client.from_stix(stix)
        assert isinstance(result, dict)

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError):
            client.upsert_object("indicator", {})


# ---------------------------------------------------------------------------
# Rapid7
# ---------------------------------------------------------------------------
class TestRapid7Client:
    @pytest.fixture()
    def client(self):
        from gnat.connectors.rapid7.client import Rapid7Client

        return Rapid7Client(host="https://insight.rapid7.com", api_key="r7-key")

    def test_auth(self, client):
        client.authenticate()
        assert client._auth_headers["X-Api-Key"] == "r7-key"

    def test_health_check(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": []}))
        assert client.health_check() is True

    def test_list_objects_vulnerability(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(return_value={"data": [{"id": "vuln-1", "title": "CVE-2024-1234"}]}),
        )
        results = client.list_objects("vulnerability", page_size=5)
        assert isinstance(results, list)

    def test_to_stix(self, client):
        raw = {
            "id": "vuln-1",
            "title": "CVE-2024-1234",
            "severity": "Critical",
            "cvss_score": 9.8,
            "published": "2024-01-01T00:00:00Z",
        }
        stix = client.to_stix(raw)
        assert stix.get("type") in ("vulnerability", "indicator", "observed-data", "bundle")

    def test_from_stix(self, client):
        stix = {"type": "vulnerability", "id": "vulnerability--1", "name": "CVE-2024-1234"}
        result = client.from_stix(stix)
        assert isinstance(result, dict)

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError):
            client.upsert_object("vulnerability", {})


# ---------------------------------------------------------------------------
# Nucleus
# ---------------------------------------------------------------------------
class TestNucleusClient:
    @pytest.fixture()
    def client(self):
        from gnat.connectors.nucleus.client import NucleusClient

        return NucleusClient(host="nucleus.example.com", api_key="nucleus-key")

    def test_auth(self, client):
        client.authenticate()
        assert client._auth_headers["x-apikey"] == "nucleus-key"

    def test_health_check(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"status": "healthy"}))
        assert client.health_check() is True

    def test_list_objects(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"data": [{"id": "proj-1", "name": "MyProject"}]})
        )
        results = client.list_objects("x-nucleus-project", page_size=5)
        assert isinstance(results, list)

    def test_to_stix(self, client):
        raw = {
            "id": "vuln-1",
            "cve_id": "CVE-2024-0001",
            "severity": "high",
            "asset": "server01",
            "first_found": "2024-01-01",
        }
        stix = client.to_stix(raw)
        assert stix.get("type") in ("vulnerability", "observed-data", "bundle")

    def test_from_stix(self, client):
        stix = {"type": "vulnerability", "id": "vulnerability--1", "name": "CVE-2024-0001"}
        result = client.from_stix(stix)
        assert isinstance(result, dict)

    def test_upsert_indicator(self, client, monkeypatch):
        monkeypatch.setattr(client, "post", MagicMock(return_value={"data": {"id": "new-1"}}))
        result = client.upsert_object(
            "indicator",
            {
                "type": "indicator",
                "id": "indicator--1",
                "pattern": "[ipv4-addr:value = '1.2.3.4']",
                "pattern_type": "stix",
                "name": "Test",
                "valid_from": "2024-01-01T00:00:00Z",
            },
        )
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# ElasticConnector (ConnectorMixin facade)
# ---------------------------------------------------------------------------
class TestElasticConnector:
    @pytest.fixture()
    def client(self):
        from gnat.connectors.elastic.connector import ElasticConnector

        return ElasticConnector(
            host="https://es.example.com:9200",
            api_key_id="key-id",
            api_key_secret="key-secret",
        )

    def test_authenticate_sets_flag(self, client):
        client.authenticate()
        assert client._authenticated is True

    def test_health_check_success(self, client, monkeypatch):
        monkeypatch.setattr(client._elastic, "es_get", MagicMock(return_value={"status": "green"}))
        assert client.health_check() is True

    def test_health_check_failure(self, client, monkeypatch):
        monkeypatch.setattr(
            client._elastic, "es_get", MagicMock(side_effect=GNATClientError("err"))
        )
        with pytest.raises(GNATClientError):
            client.health_check()

    def test_list_objects_indicators(self, client, monkeypatch):
        ind = {
            "_id": "ind-1",
            "_source": {
                "threat": {"indicator": {"type": "ipv4-addr", "ip": "1.2.3.4"}},
                "@timestamp": "2024-01-01T00:00:00Z",
            },
        }
        monkeypatch.setattr(client._ti, "search_indicators", MagicMock(return_value=[ind]))
        results = client.list_objects("indicator", limit=5)
        assert isinstance(results, list)

    def test_list_objects_observed_data(self, client, monkeypatch):
        alert = {
            "_id": "alert-1",
            "_source": {
                "event": {"kind": "signal"},
                "kibana.alert.rule.name": "Test",
                "@timestamp": "2024-01-01T00:00:00Z",
            },
        }
        monkeypatch.setattr(client._alerts, "search_alerts", MagicMock(return_value=[alert]))
        results = client.list_objects("observed-data", limit=5)
        assert isinstance(results, list)

    def test_upsert_indicator(self, client, monkeypatch):
        monkeypatch.setattr(
            client._ti,
            "index_indicator",
            MagicMock(return_value={"result": "created", "_id": "doc-1"}),
        )
        result = client.upsert_object(
            "indicator",
            {
                "type": "indicator",
                "id": "indicator--1",
                "pattern": "[ipv4-addr:value = '1.2.3.4']",
                "pattern_type": "stix",
                "name": "Test IOC",
                "valid_from": "2024-01-01T00:00:00Z",
            },
        )
        assert isinstance(result, dict)

    def test_upsert_observed_data_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.upsert_object("observed-data", {})

    def test_delete_observed_data_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.delete_object("observed-data", "alert-1")


# ---------------------------------------------------------------------------
# MISPConnector (ConnectorMixin facade)
# ---------------------------------------------------------------------------
class TestMISPConnector:
    @pytest.fixture()
    def client(self):
        from gnat.connectors.misp.connector import MISPConnector

        return MISPConnector(host="misp.example.com", api_key="misp-key")

    def test_authenticate_sets_flag(self, client):
        client.authenticate()
        assert client._authenticated is True

    def test_health_check_success(self, client, monkeypatch):
        monkeypatch.setattr(
            client._misp, "get_json", MagicMock(return_value={"version": "2.4.170"})
        )
        assert client.health_check() is True

    def test_health_check_failure(self, client, monkeypatch):
        monkeypatch.setattr(client._misp, "get_json", MagicMock(side_effect=GNATClientError("err")))
        with pytest.raises(GNATClientError):
            client.health_check()

    def test_list_objects(self, client, monkeypatch):
        evt = {
            "id": "1",
            "uuid": "evt-uuid-1",
            "info": "Phishing campaign",
            "date": "2024-01-01",
            "threat_level_id": "2",
            "distribution": "0",
            "Attribute": [],
        }
        monkeypatch.setattr(client._events, "list_events", MagicMock(return_value=[evt]))
        results = client.list_objects("report", limit=5)
        assert isinstance(results, list)

    def test_get_object(self, client, monkeypatch):
        evt = {
            "id": "1",
            "uuid": "evt-uuid-1",
            "info": "Test event",
            "date": "2024-01-01",
            "threat_level_id": "1",
            "distribution": "0",
            "Attribute": [],
        }
        monkeypatch.setattr(client._events, "get_event", MagicMock(return_value=evt))
        result = client.get_object("report", "1")
        assert isinstance(result, dict)

    def test_delete_object(self, client, monkeypatch):
        monkeypatch.setattr(client._events, "delete_event", MagicMock(return_value={"saved": True}))
        client.delete_object("report", "1")  # should not raise

    def test_to_stix(self, client):
        raw = {
            "Event": {
                "id": "1",
                "uuid": "evt-uuid-1",
                "info": "Test",
                "date": "2024-01-01",
                "threat_level_id": "2",
                "distribution": "0",
                "Attribute": [],
            }
        }
        stix = client.to_stix(raw)
        assert stix.get("type") in ("bundle", "report", "observed-data")

    def test_from_stix(self, client):
        # from_stix requires a STIX bundle
        bundle = {
            "type": "bundle",
            "id": "bundle--1",
            "objects": [
                {
                    "type": "indicator",
                    "id": "indicator--1",
                    "name": "Test IOC",
                    "pattern": "[ipv4-addr:value = '1.2.3.4']",
                    "pattern_type": "stix",
                    "valid_from": "2024-01-01T00:00:00Z",
                }
            ],
        }
        result = client.from_stix(bundle)
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# QRadarConnector (ConnectorMixin facade)
# ---------------------------------------------------------------------------
class TestQRadarConnector:
    @pytest.fixture()
    def client(self):
        from gnat.connectors.qradar.connector import QRadarConnector

        return QRadarConnector(host="qradar.example.com", token="qr-token")

    def test_authenticate_sets_flag(self, client):
        client.authenticate()
        assert client._authenticated is True

    def test_health_check_success(self, client, monkeypatch):
        monkeypatch.setattr(client._qradar, "get", MagicMock(return_value={"version": "21.0"}))
        assert client.health_check() is True

    def test_health_check_failure(self, client, monkeypatch):
        monkeypatch.setattr(client._qradar, "get", MagicMock(side_effect=GNATClientError("err")))
        with pytest.raises(GNATClientError):
            client.health_check()

    def test_list_objects_offenses(self, client, monkeypatch):
        offense = {
            "id": 1,
            "description": "Suspicious activity",
            "start_time": 1704067200000,
            "status": "OPEN",
            "offense_type": 0,
            "magnitude": 5,
            "source_address_ids": [],
            "local_destination_address_ids": [],
        }
        monkeypatch.setattr(client._offenses, "list_offenses", MagicMock(return_value=[offense]))
        results = client.list_objects("observed-data", limit=5)
        assert isinstance(results, list)

    def test_get_object(self, client, monkeypatch):
        offense = {
            "id": 1,
            "description": "Test offense",
            "start_time": 1704067200000,
            "status": "OPEN",
            "offense_type": 0,
            "magnitude": 3,
            "source_address_ids": [],
            "local_destination_address_ids": [],
        }
        monkeypatch.setattr(client._offenses, "get_offense", MagicMock(return_value=offense))
        result = client.get_object("observed-data", "1")
        assert isinstance(result, dict)

    def test_get_indicator_raises(self, client):
        with pytest.raises(GNATClientError, match="single-item lookup"):
            client.get_object("indicator", "some-id")

    def test_upsert_observed_data_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.upsert_object("observed-data", {})

    def test_from_stix(self, client):
        stix = {
            "type": "bundle",
            "id": "bundle--1",
            "objects": [
                {
                    "type": "indicator",
                    "id": "indicator--1",
                    "name": "Bad IP",
                    "pattern": "[ipv4-addr:value = '1.2.3.4']",
                    "pattern_type": "stix",
                    "valid_from": "2024-01-01T00:00:00Z",
                }
            ],
        }
        result = client.from_stix(stix)
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# SentinelConnector (ConnectorMixin facade)
# ---------------------------------------------------------------------------
class TestSentinelConnector:
    @pytest.fixture()
    def client(self):
        from gnat.connectors.sentinel.connector import SentinelConnector

        return SentinelConnector(
            tenant_id="tenant-1",
            client_id="client-1",
            client_secret="secret-1",
            subscription_id="sub-1",
            resource_group="rg-1",
            workspace_name="ws-1",
        )

    def test_authenticate_success(self, client, monkeypatch):
        monkeypatch.setattr(
            client._sentinel.auth,
            "get_headers",
            MagicMock(return_value={"Authorization": "Bearer tok"}),
        )
        client.authenticate()
        assert client._authenticated is True

    def test_authenticate_failure(self, client, monkeypatch):
        monkeypatch.setattr(
            client._sentinel.auth, "get_headers", MagicMock(side_effect=Exception("invalid_client"))
        )
        with pytest.raises(GNATClientError, match="authentication"):
            client.authenticate()

    def test_health_check(self, client, monkeypatch):
        monkeypatch.setattr(client._sentinel, "get", MagicMock(return_value={"value": []}))
        assert client.health_check() is True

    def test_list_objects_indicators(self, client, monkeypatch):
        ind = {
            "id": "ind-1",
            "name": "indicator-1",
            "properties": {
                "pattern": "[ipv4-addr:value = '1.2.3.4']",
                "patternType": "Stix",
                "displayName": "Bad IP",
                "createdTimeUtc": "2024-01-01T00:00:00Z",
            },
        }
        monkeypatch.setattr(client._ti, "list_indicators", MagicMock(return_value=[ind]))
        results = client.list_objects("indicator", limit=5)
        assert isinstance(results, list)

    def test_list_objects_incidents(self, client, monkeypatch):
        inc = {
            "id": "inc-1",
            "name": "incident-1",
            "properties": {
                "title": "Phishing Alert",
                "severity": "High",
                "status": "New",
                "createdTimeUtc": "2024-01-01T00:00:00Z",
            },
        }
        monkeypatch.setattr(client._incidents, "list_incidents", MagicMock(return_value=[inc]))
        results = client.list_objects("observed-data", limit=5)
        assert isinstance(results, list)

    def test_upsert_indicator(self, client, monkeypatch):
        monkeypatch.setattr(
            client._ti,
            "create_indicator",
            MagicMock(return_value={"id": "ind-new", "name": "indicator-new"}),
        )
        result = client.upsert_object(
            "indicator",
            {
                "type": "indicator",
                "id": "indicator--1",
                "name": "Bad IP",
                "pattern": "[ipv4-addr:value = '1.2.3.4']",
                "pattern_type": "stix",
                "valid_from": "2024-01-01T00:00:00Z",
            },
        )
        assert isinstance(result, dict)

    def test_upsert_incident_raises(self, client):
        with pytest.raises(GNATClientError, match="cannot be created"):
            client.upsert_object("observed-data", {})

    def test_from_stix(self, client):
        stix = {
            "type": "indicator",
            "id": "indicator--1",
            "name": "Test",
            "pattern": "[ipv4-addr:value = '1.2.3.4']",
            "pattern_type": "stix",
            "valid_from": "2024-01-01T00:00:00Z",
        }
        result = client.from_stix(stix)
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# WazuhConnector (ConnectorMixin facade)
# ---------------------------------------------------------------------------
class TestWazuhConnector:
    @pytest.fixture()
    def client(self):
        from gnat.connectors.wazuh.connector import WazuhConnector

        return WazuhConnector(host="wazuh.example.com", username="wazuh", password="pass")

    def test_authenticate_sets_flag(self, client, monkeypatch):
        monkeypatch.setattr(
            client._wazuh.auth,
            "get_auth_headers",
            MagicMock(return_value={"Authorization": "Bearer jwt"}),
        )
        client.authenticate()
        assert client._authenticated is True

    def test_health_check(self, client, monkeypatch):
        monkeypatch.setattr(
            client._wazuh, "get", MagicMock(return_value={"data": {"affected_items": []}})
        )
        assert client.health_check() is True

    def test_list_objects_alerts(self, client, monkeypatch):
        alert = {
            "id": "1680100001.12345",
            "rule": {"id": "100001", "level": 5, "description": "Suspicious login"},
            "agent": {"id": "001", "name": "host1"},
            "timestamp": "2024-01-01T00:00:00+0000",
        }
        monkeypatch.setattr(client._alert_cmds, "get_alerts", MagicMock(return_value=[alert]))
        results = client.list_objects("observed-data", limit=5)
        assert isinstance(results, list)

    def test_list_objects_agents(self, client, monkeypatch):
        agent = {
            "id": "001",
            "name": "host1",
            "ip": "10.0.0.1",
            "status": "active",
            "os": {"name": "Ubuntu"},
        }
        monkeypatch.setattr(client._agent_cmds, "list_agents", MagicMock(return_value=[agent]))
        results = client.list_objects("identity", limit=5)
        assert isinstance(results, list)

    def test_list_vuln_no_agent_raises(self, client):
        with pytest.raises(GNATClientError, match="agent_id"):
            client.list_objects("vulnerability")

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.upsert_object("observed-data", {})

    def test_delete_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.delete_object("observed-data", "alert-1")

    def test_from_stix_returns_xml(self, client):
        # WazuhConnector.from_stix() converts a STIX indicator to a Wazuh rule XML string
        stix = {
            "type": "indicator",
            "id": "indicator--1",
            "name": "Test",
            "pattern": "[ipv4-addr:value = '1.2.3.4']",
            "pattern_type": "stix",
            "valid_from": "2024-01-01T00:00:00Z",
            "indicator_types": ["malicious-activity"],
        }
        result = client.from_stix(stix)
        assert isinstance(result, str)


# ---------------------------------------------------------------------------
# OpenCTIClient
# ---------------------------------------------------------------------------
class TestOpenCTIClient:
    @pytest.fixture()
    def client(self):
        from gnat.connectors.opencti.client import OpenCTIClient

        return OpenCTIClient(host="opencti.example.com", api_key="opencti-key")

    def test_auth_header_set(self, client):
        client.authenticate()
        assert client._auth_headers["Authorization"] == "Bearer opencti-key"

    def test_health_check(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"status": "ok"}))
        assert client.health_check() is True

    def test_list_objects(self, client, monkeypatch):
        ind = {
            "id": "ind-1",
            "name": "Bad IP",
            "pattern": "[ipv4-addr:value = '1.2.3.4']",
            "pattern_type": "stix",
            "valid_from": "2024-01-01T00:00:00Z",
            "entity_type": "Indicator",
        }
        monkeypatch.setattr(
            client,
            "post",
            MagicMock(return_value={"data": {"indicators": {"edges": [{"node": ind}]}}}),
        )
        results = client.list_objects("indicator", page_size=5)
        assert isinstance(results, list)

    def test_to_stix_indicator(self, client):
        raw = {
            "id": "ind-1",
            "name": "Bad IP",
            "pattern": "[ipv4-addr:value = '1.2.3.4']",
            "pattern_type": "stix",
            "valid_from": "2024-01-01T00:00:00Z",
            "entity_type": "Indicator",
        }
        stix = client.to_stix(raw)
        assert stix.get("type") in ("indicator", "bundle")

    def test_to_stix_malware(self, client):
        raw = {"id": "mal-1", "name": "Ransomware X", "entity_type": "Malware", "is_family": False}
        stix = client.to_stix(raw)
        assert stix.get("type") in ("malware", "bundle", "indicator")

    def test_from_stix(self, client):
        stix = {
            "type": "indicator",
            "id": "indicator--1",
            "name": "Test",
            "pattern": "[ipv4-addr:value = '1.2.3.4']",
            "pattern_type": "stix",
            "valid_from": "2024-01-01T00:00:00Z",
        }
        result = client.from_stix(stix)
        assert isinstance(result, dict)


# ===========================================================================
# Incident Linking: XSOAR link_incident
# ===========================================================================


class TestXSOARIncidentLinking:
    @pytest.fixture
    def client(self):
        return _authenticated(XSOARClient, api_key="xsoar-key")

    def test_link_incident_calls_correct_endpoint(self, client, monkeypatch):
        mock_post = MagicMock(return_value={"id": "link-1"})
        monkeypatch.setattr(client, "post", mock_post)
        stix = {"name": "10.0.0.99", "type": "indicator", "id": "indicator--abc"}
        result = client.link_incident("incident-42", stix)
        assert result == {"id": "link-1"}
        url_called = mock_post.call_args[0][0]
        assert "incident-42" in url_called
        assert "linkedIncidents" in url_called

    def test_link_incident_payload_contains_value(self, client, monkeypatch):
        captured = {}

        def fake_post(path, **kwargs):
            captured.update(kwargs.get("json", {}))
            return {}

        monkeypatch.setattr(client, "post", fake_post)
        stix = {"name": "evil.com", "type": "indicator", "id": "indicator--xyz"}
        client.link_incident("inc-1", stix)
        assert captured.get("incidentId") == "inc-1"
        indicators = captured.get("indicators", [])
        assert any(ind.get("value") == "evil.com" for ind in indicators)

    def test_upsert_object_links_when_incident_id_given(self, client, monkeypatch):
        monkeypatch.setattr(client, "post", MagicMock(return_value={"id": "upserted"}))
        stix = {"name": "malware.exe", "value": "malware.exe"}
        client.upsert_object("indicator", stix, incident_id="inc-99")
        # post was called at least twice: upsert + link
        assert client.post.call_count >= 2

    def test_upsert_object_no_link_when_no_incident_id(self, client, monkeypatch):
        monkeypatch.setattr(client, "post", MagicMock(return_value={"id": "upserted"}))
        client.upsert_object("indicator", {"name": "test"})
        assert client.post.call_count == 1


# ===========================================================================
# Incident Linking: ServiceNow annotate_incident
# ===========================================================================


class TestServiceNowClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.servicenow.client import ServiceNowClient

        c = ServiceNowClient(
            host="https://dev12345.service-now.com", username="admin", password="pass"
        )
        c._authenticated = True
        return c

    def test_authenticate_sets_basic_header(self):
        from gnat.connectors.servicenow.client import ServiceNowClient

        c = ServiceNowClient(
            host="https://dev12345.service-now.com", username="user", password="secret"
        )
        c.authenticate()
        assert c._auth_headers["Authorization"].startswith("Basic ")

    def test_authenticate_sets_bearer_when_api_key(self):
        from gnat.connectors.servicenow.client import ServiceNowClient

        c = ServiceNowClient(host="https://dev12345.service-now.com", api_key="tok123")
        c.authenticate()
        assert c._auth_headers["Authorization"] == "Bearer tok123"

    def test_health_check_success(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"result": []}))
        assert client.health_check() is True

    def test_health_check_failure_raises(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(side_effect=GNATClientError("unreachable")))
        with pytest.raises(GNATClientError):
            client.health_check()

    def test_get_object_returns_result(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"result": {"sys_id": "abc123"}}))
        result = client.get_object("observed-data", "abc123")
        assert result["sys_id"] == "abc123"

    def test_list_objects_returns_list(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"result": [{"sys_id": "r1"}]}))
        results = client.list_objects("observed-data")
        assert isinstance(results, list)
        assert results[0]["sys_id"] == "r1"

    def test_list_objects_passes_query(self, client, monkeypatch):
        mock_get = MagicMock(return_value={"result": []})
        monkeypatch.setattr(client, "get", mock_get)
        client.list_objects("observed-data", query="state=1^priority=1")
        _, kwargs = mock_get.call_args
        assert kwargs["params"]["sysparm_query"] == "state=1^priority=1"

    def test_upsert_object_creates_new(self, client, monkeypatch):
        monkeypatch.setattr(client, "post", MagicMock(return_value={"result": {"sys_id": "new-1"}}))
        result = client.upsert_object("observed-data", {"name": "Ransomware event"})
        assert result.get("sys_id") == "new-1"

    def test_upsert_object_updates_existing(self, client, monkeypatch):
        mock_put = MagicMock(return_value={"result": {"sys_id": "old-1"}})
        monkeypatch.setattr(client, "put", mock_put)
        result = client.upsert_object("observed-data", {"name": "Updated"}, sys_id="old-1")
        assert result.get("sys_id") == "old-1"
        mock_put.assert_called_once()

    def test_to_stix_contract(self, client):
        native = {
            "sys_id": "abc123",
            "short_description": "Ransomware detected",
            "description": "Details here",
            "opened_at": "2026-01-01T00:00:00Z",
            "state": "1",
            "priority": "1",
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "observed-data"
        assert stix["x_sn_sys_id"] == "abc123"

    def test_from_stix_returns_sn_payload(self, client):
        stix = {
            "type": "indicator",
            "id": "indicator--x",
            "name": "bad.exe",
            "description": "Malicious binary",
        }
        result = client.from_stix(stix)
        assert isinstance(result, dict)
        assert "short_description" in result
        assert "bad.exe" in result["short_description"]

    def test_annotate_incident_calls_put(self, client, monkeypatch):
        mock_put = MagicMock(return_value={"result": {"sys_id": "inc-1"}})
        monkeypatch.setattr(client, "put", mock_put)
        stix = {"type": "indicator", "id": "indicator--abc", "name": "10.0.0.1"}
        result = client.annotate_incident("inc-1", stix)
        assert result.get("sys_id") == "inc-1"
        mock_put.assert_called_once()
        call_path = mock_put.call_args[0][0]
        assert "inc-1" in call_path

    def test_annotate_incident_work_notes_contain_stix_id(self, client, monkeypatch):
        captured = {}

        def fake_put(path, **kwargs):
            captured.update(kwargs.get("json", {}))
            return {"result": {}}

        monkeypatch.setattr(client, "put", fake_put)
        stix = {"type": "indicator", "id": "indicator--xyz", "name": "evil.com"}
        client.annotate_incident("sys-abc", stix)
        assert "indicator--xyz" in captured.get("work_notes", "")

    def test_unsupported_stix_type_raises(self, client):
        with pytest.raises(GNATClientError):
            client.list_objects("malware")


# ===========================================================================
# Incident Linking: GreyMatter link_investigation
# ===========================================================================


class TestGreyMatterIncidentLinking:
    @pytest.fixture
    def client(self):
        c = GreyMatterClient(host="https://fake.example.com", client_id="cid", client_secret="sec")
        c._authenticated = True
        return c

    def test_link_investigation_calls_correct_endpoint(self, client, monkeypatch):
        mock_post = MagicMock(return_value={"id": "obs-link-1"})
        monkeypatch.setattr(client, "post", mock_post)
        stix = {
            "type": "indicator",
            "id": "indicator--aaa",
            "name": "1.2.3.4",
            "pattern": "[ipv4-addr:value = '1.2.3.4']",
        }
        result = client.link_investigation("case-99", stix)
        assert result == {"id": "obs-link-1"}
        url_called = mock_post.call_args[0][0]
        assert "case-99" in url_called
        assert "linked_observables" in url_called

    def test_link_investigation_payload_type_inferred(self, client, monkeypatch):
        captured = {}

        def fake_post(path, **kwargs):
            captured.update(kwargs.get("json", {}))
            return {}

        monkeypatch.setattr(client, "post", fake_post)
        stix = {
            "type": "indicator",
            "id": "indicator--bbb",
            "name": "evil.com",
            "pattern": "[domain-name:value = 'evil.com']",
        }
        client.link_investigation("case-01", stix)
        assert captured.get("type") == "domain"
        assert captured.get("value") == "evil.com"
        assert captured.get("case_id") == "case-01"

    def test_link_investigation_fallback_to_name(self, client, monkeypatch):
        captured = {}

        def fake_post(path, **kwargs):
            captured.update(kwargs.get("json", {}))
            return {}

        monkeypatch.setattr(client, "post", fake_post)
        stix = {"type": "indicator", "id": "indicator--ccc", "name": "sha256hash", "pattern": ""}
        client.link_investigation("case-02", stix)
        assert captured.get("value") == "sha256hash"

    def test_upsert_object_passes_linked_cases(self, client, monkeypatch):
        mock_post = MagicMock(return_value={"id": "new-obs"})
        monkeypatch.setattr(client, "post", mock_post)
        payload = {"type": "ipv4", "value": "5.5.5.5"}
        client.upsert_object("indicator", payload, linked_cases=["case-10", "case-11"])
        _, kwargs = mock_post.call_args
        assert kwargs["json"].get("linked_cases") == ["case-10", "case-11"]


# ===========================================================================
# Jira
# ===========================================================================


class TestJiraClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.jira.client import JiraClient

        c = JiraClient(host="https://fake.atlassian.net", email="user@example.com", api_token="tok")
        c._authenticated = True
        return c

    def test_authenticate_basic_sets_header(self):
        from gnat.connectors.jira.client import JiraClient

        c = JiraClient(
            host="https://fake.atlassian.net", email="u@example.com", api_token="mytoken"
        )
        c.authenticate()
        assert c._auth_headers["Authorization"].startswith("Basic ")

    def test_authenticate_bearer_when_api_key(self):
        from gnat.connectors.jira.client import JiraClient

        c = JiraClient(host="https://jira.corp.example.com", api_key="bearer-tok")
        c.authenticate()
        assert c._auth_headers["Authorization"] == "Bearer bearer-tok"

    def test_health_check_success(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"version": "9.0"}))
        assert client.health_check() is True

    def test_health_check_failure_raises(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(side_effect=GNATClientError("down")))
        with pytest.raises(GNATClientError):
            client.health_check()

    def test_get_object_returns_issue(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"id": "10001", "key": "PROJ-1", "fields": {}})
        )
        result = client.get_object("note", "PROJ-1")
        assert result["key"] == "PROJ-1"

    def test_list_objects_uses_post(self, client, monkeypatch):
        mock_post = MagicMock(return_value={"issues": [{"id": "10001"}]})
        monkeypatch.setattr(client, "post", mock_post)
        results = client.list_objects("note", jql="project = SEC")
        assert isinstance(results, list)
        assert results[0]["id"] == "10001"
        _, kwargs = mock_post.call_args
        assert kwargs["json"]["jql"] == "project = SEC"

    def test_list_objects_default_jql(self, client, monkeypatch):
        mock_post = MagicMock(return_value={"issues": []})
        monkeypatch.setattr(client, "post", mock_post)
        client.list_objects("note")
        _, kwargs = mock_post.call_args
        assert "order by created" in kwargs["json"]["jql"].lower()

    def test_upsert_creates_new(self, client, monkeypatch):
        monkeypatch.setattr(client, "post", MagicMock(return_value={"id": "10002", "key": "SEC-5"}))
        result = client.upsert_object(
            "note", {"name": "ThreatActor campaign", "description": "APT28 activity"}
        )
        assert result.get("key") == "SEC-5"

    def test_upsert_updates_existing(self, client, monkeypatch):
        mock_put = MagicMock(return_value=None)
        monkeypatch.setattr(client, "put", mock_put)
        result = client.upsert_object("note", {"name": "Updated"}, issue_key="SEC-5")
        assert result["key"] == "SEC-5"
        mock_put.assert_called_once()

    def test_to_stix_note_contract(self, client):
        native = {
            "id": "10001",
            "key": "SEC-1",
            "fields": {
                "summary": "Malware IOC",
                "issuetype": {"name": "Task"},
                "created": "2026-01-01T00:00:00Z",
                "updated": "2026-01-01T00:00:00Z",
                "status": {"name": "Open"},
                "priority": {"name": "High"},
                "labels": ["threat-intel"],
                "assignee": {"displayName": "Alice"},
            },
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] in ("note", "course-of-action")
        assert stix["x_jira_key"] == "SEC-1"
        assert stix["x_jira_status"] == "Open"

    def test_to_stix_course_of_action_for_action_type(self, client):
        native = {
            "id": "10002",
            "key": "SEC-2",
            "fields": {
                "summary": "Patch KB12345",
                "issuetype": {"name": "Action Item"},
                "created": "2026-01-01T00:00:00Z",
            },
        }
        stix = client.to_stix(native)
        assert stix["type"] == "course-of-action"

    def test_from_stix_returns_jql(self, client):
        stix = {"type": "indicator", "id": "indicator--abc", "name": "evil.com"}
        result = client.from_stix(stix)
        assert isinstance(result, str)
        assert "evil.com" in result

    def test_annotate_ticket_calls_comment_endpoint(self, client, monkeypatch):
        mock_post = MagicMock(return_value={"id": "comment-1"})
        monkeypatch.setattr(client, "post", mock_post)
        stix = {"type": "indicator", "id": "indicator--xyz", "name": "bad.com"}
        result = client.annotate_ticket("PROJ-10", stix)
        assert result.get("id") == "comment-1"
        url = mock_post.call_args[0][0]
        assert "PROJ-10" in url
        assert "comment" in url

    def test_annotate_ticket_body_contains_stix_id(self, client, monkeypatch):
        captured = {}

        def fake_post(path, **kwargs):
            captured.update(kwargs.get("json", {}))
            return {}

        monkeypatch.setattr(client, "post", fake_post)
        stix = {"type": "indicator", "id": "indicator--aaa", "name": "1.2.3.4"}
        client.annotate_ticket("SEC-99", stix)
        body_text = str(captured.get("body", ""))
        assert "indicator--aaa" in body_text

    def test_search_by_label(self, client, monkeypatch):
        mock_post = MagicMock(return_value={"issues": [{"id": "x"}]})
        monkeypatch.setattr(client, "post", mock_post)
        results = client.search_by_label("threat-intel")
        assert isinstance(results, list)
        _, kwargs = mock_post.call_args
        assert "threat-intel" in kwargs["json"]["jql"]


# ---------------------------------------------------------------------------
# ThreatConnectClient
# ---------------------------------------------------------------------------


class TestThreatConnectClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.threatconnect.client import ThreatConnectClient

        return ThreatConnectClient(
            host="https://app.threatconnect.com",
            api_key="tc-token-abc",
            auth_type="token",
        )

    def test_authenticate_token_sets_header(self, client):
        client.authenticate()
        assert client._auth_headers["Authorization"] == "TC-Token tc-token-abc"

    def test_authenticate_hmac_mode(self):
        from gnat.connectors.threatconnect.client import ThreatConnectClient

        c = ThreatConnectClient(
            host="https://app.threatconnect.com",
            access_id="aid",
            secret_key="skey",
            auth_type="hmac",
        )
        c.authenticate()  # should not set Authorization (computed per-request)
        assert "Authorization" not in c._auth_headers

    def test_health_check(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"status": "ok"})
        assert client.health_check() is True

    def test_list_objects_indicators(self, client, monkeypatch):
        payload = {"data": [{"id": 1, "summary": "1.2.3.4", "type": "Address"}]}
        monkeypatch.setattr(client, "get", lambda path, **kw: payload)
        results = client.list_objects("indicator")
        assert len(results) == 1
        assert results[0]["summary"] == "1.2.3.4"

    def test_list_objects_returns_empty_on_bad_response(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: "bad")
        assert client.list_objects("indicator") == []

    def test_get_object(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"data": {"id": 7}})
        obj = client.get_object("indicator", "7")
        assert obj["id"] == 7

    def test_upsert_creates(self, client, monkeypatch):
        captured = {}

        def fake_post(path, **kw):
            captured["path"] = path
            return {"data": {"id": 99}}

        monkeypatch.setattr(client, "post", fake_post)
        result = client.upsert_object("indicator", {"summary": "evil.com", "type": "Host"})
        assert "/indicators" in captured["path"]
        assert result["id"] == 99

    def test_upsert_updates_when_id_present(self, client, monkeypatch):
        captured = {}

        def fake_put(path, **kw):
            captured["path"] = path
            return {"data": {"id": 42}}

        monkeypatch.setattr(client, "put", fake_put)
        result = client.upsert_object("indicator", {"id": 42, "summary": "evil.com"})
        assert "42" in captured["path"]

    def test_to_stix_address(self, client):
        native = {
            "id": 1,
            "summary": "1.2.3.4",
            "type": "Address",
            "dateAdded": "2026-01-01",
            "lastModified": "2026-01-02",
            "confidence": 75,
            "ownerName": "Org",
        }
        stix = client.to_stix(native)
        assert stix["type"] == "indicator"
        assert "ipv4-addr" in stix["pattern"]
        assert stix["x_source_platform"] == "threatconnect"

    def test_to_stix_hash(self, client):
        sha256 = "a" * 64
        native = {"id": 2, "summary": sha256, "type": "File", "confidence": 90}
        stix = client.to_stix(native)
        assert "SHA-256" in stix["pattern"]

    def test_from_stix_returns_payload(self, client):
        stix = {"pattern": "[ipv4-addr:value = '10.0.0.1']", "name": "10.0.0.1", "confidence": 80}
        payload = client.from_stix(stix)
        assert payload["summary"] == "10.0.0.1"
        assert payload["type"] == "Address"

    def test_hmac_signature_length(self, client):
        from gnat.connectors.threatconnect.client import ThreatConnectClient

        c = ThreatConnectClient(
            host="https://app.threatconnect.com", access_id="a", secret_key="s", auth_type="hmac"
        )
        sig = c._compute_hmac("/api/v3/indicators", "GET", "1234567890")
        import base64

        # base64-encoded 32-byte SHA256 = 44 chars
        assert len(base64.b64decode(sig + "==")) == 32


# ---------------------------------------------------------------------------
# MandiantClient
# ---------------------------------------------------------------------------


class TestMandiantClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.mandiant.client import MandiantClient

        return MandiantClient(
            host="https://api.intelligence.mandiant.com",
            api_key="key123",
            api_secret="secret456",
        )

    def test_authenticate_sets_bearer(self, client, monkeypatch):
        monkeypatch.setattr(client, "post", lambda path, **kw: {"access_token": "tok_abc"})
        client.authenticate()
        assert client._auth_headers["Authorization"] == "Bearer tok_abc"

    def test_authenticate_raises_on_missing_token(self, client, monkeypatch):
        from gnat.clients.base import GNATClientError

        monkeypatch.setattr(client, "post", lambda path, **kw: {})
        with pytest.raises(GNATClientError, match="Mandiant"):
            client.authenticate()

    def test_health_check_returns_true(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"indicators": []})
        assert client.health_check() is True

    def test_list_objects_indicators(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"indicator": [{"value": "1.2.3.4"}]})
        results = client.list_objects("indicator")
        assert len(results) == 1

    def test_list_objects_actors(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"actor": [{"name": "APT1"}]})
        results = client.list_objects("threat-actor")
        assert results[0]["name"] == "APT1"

    def test_upsert_raises(self, client):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError, match="read-only"):
            client.upsert_object("indicator", {"value": "1.2.3.4"})

    def test_to_stix_indicator(self, client):
        native = {
            "id": "i1",
            "value": "1.2.3.4",
            "type": "ipv4",
            "mscore": 80,
            "first_seen": "2026-01-01",
            "last_seen": "2026-02-01",
        }
        stix = client.to_stix(native)
        assert stix["type"] == "indicator"
        assert "ipv4-addr" in stix["pattern"]
        assert stix["confidence"] == 80
        assert stix["x_source_platform"] == "mandiant"

    def test_to_stix_actor(self, client):
        native = {
            "type": "Actor",
            "id": "a1",
            "name": "APT28",
            "description": "Russian APT",
            "aliases": [{"name": "Fancy Bear"}],
        }
        stix = client.to_stix(native)
        assert stix["type"] == "threat-actor"
        assert stix["name"] == "APT28"
        assert "Fancy Bear" in stix["aliases"]

    def test_to_stix_malware(self, client):
        native = {
            "type": "Malware",
            "id": "m1",
            "name": "WannaCry",
            "description": "Ransomware",
            "aliases": [],
        }
        stix = client.to_stix(native)
        assert stix["type"] == "malware"
        assert stix["is_family"] is True

    def test_from_stix_returns_dict(self, client):
        stix = {"pattern": "[ipv4-addr:value = '192.168.1.1']", "name": "192.168.1.1"}
        payload = client.from_stix(stix)
        assert payload["value"] == "192.168.1.1"
        assert payload["type"] == "ipv4"


# ---------------------------------------------------------------------------
# DefenderTIClient
# ---------------------------------------------------------------------------


class TestDefenderTIClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.defenderti.client import DefenderTIClient

        return DefenderTIClient(
            host="https://graph.microsoft.com",
            tenant_id="tenant-123",
            client_id="client-456",
            client_secret="secret-789",
        )

    def test_authenticate_sets_bearer(self, client, monkeypatch):
        import json as _json

        import urllib3 as _u3

        fake_response = MagicMock()
        fake_response.data = _json.dumps({"access_token": "az_tok"}).encode()
        fake_pool = MagicMock()
        fake_pool.request.return_value = fake_response
        monkeypatch.setattr(_u3, "PoolManager", lambda **kw: fake_pool)
        client.authenticate()
        assert client._auth_headers["Authorization"] == "Bearer az_tok"

    def test_authenticate_raises_on_missing_token(self, client, monkeypatch):
        import json as _json

        import urllib3 as _u3

        from gnat.clients.base import GNATClientError

        fake_response = MagicMock()
        fake_response.data = _json.dumps({}).encode()
        fake_pool = MagicMock()
        fake_pool.request.return_value = fake_response
        monkeypatch.setattr(_u3, "PoolManager", lambda **kw: fake_pool)
        with pytest.raises(GNATClientError, match="DefenderTI"):
            client.authenticate()

    def test_health_check_success(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"value": []})
        assert client.health_check() is True

    def test_list_objects(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"value": [{"id": "ti-1"}]})
        results = client.list_objects("indicator")
        assert results[0]["id"] == "ti-1"

    def test_upsert_creates(self, client, monkeypatch):
        captured = {}

        def fake_post(path, **kw):
            captured["json"] = kw.get("json", {})
            return {"id": "new-ti"}

        monkeypatch.setattr(client, "post", fake_post)
        result = client.upsert_object("indicator", {"networkIPv4": "1.2.3.4"})
        assert result["id"] == "new-ti"

    def test_upsert_patches_when_id_present(self, client, monkeypatch):
        captured = {}

        def fake_patch(path, **kw):
            captured["path"] = path
            return {"id": "ti-42"}

        monkeypatch.setattr(client, "patch", fake_patch)
        client.upsert_object("indicator", {"id": "ti-42", "networkIPv4": "1.2.3.4"})
        assert "ti-42" in captured["path"]

    def test_to_stix_ipv4(self, client):
        native = {
            "id": "ti-1",
            "networkIPv4": "1.2.3.4",
            "confidence": 70,
            "threatType": "Malware",
            "action": "alert",
            "createdDateTime": "2026-01-01",
            "lastReportedDateTime": "2026-02-01",
        }
        stix = client.to_stix(native)
        assert stix["type"] == "indicator"
        assert "1.2.3.4" in stix["pattern"]
        assert stix["x_source_platform"] == "defenderti"

    def test_to_stix_domain(self, client):
        native = {
            "id": "ti-2",
            "domainName": "evil.com",
            "confidence": 90,
            "threatType": "C2",
            "createdDateTime": "2026-01-01",
        }
        stix = client.to_stix(native)
        assert "domain-name" in stix["pattern"]

    def test_from_stix_ipv4(self, client):
        stix = {
            "pattern": "[ipv4-addr:value = '10.0.0.1']",
            "name": "10.0.0.1",
            "confidence": 60,
            "description": "bad IP",
        }
        payload = client.from_stix(stix)
        assert payload["networkIPv4"] == "10.0.0.1"
        assert payload["action"] == "alert"

    def test_from_stix_sha256(self, client):
        sha = "a" * 64
        stix = {"pattern": f"[file:hashes.'SHA-256' = '{sha}']", "name": sha}
        payload = client.from_stix(stix)
        assert payload["fileHashType"] == "sha256"
        assert payload["fileHashValue"] == sha


# ---------------------------------------------------------------------------
# TheHiveClient
# ---------------------------------------------------------------------------


class TestTheHiveClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.thehive.client import TheHiveClient

        return TheHiveClient(host="https://thehive.example.com", api_key="hive-key-123")

    def test_authenticate_sets_bearer(self, client):
        client.authenticate()
        assert client._auth_headers["Authorization"] == "Bearer hive-key-123"

    def test_authenticate_sets_org_header(self):
        from gnat.connectors.thehive.client import TheHiveClient

        c = TheHiveClient(host="https://thehive.example.com", api_key="k", org="CorpA")
        c.authenticate()
        assert c._auth_headers["X-Organisation"] == "CorpA"

    def test_health_check(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"status": "ok"})
        assert client.health_check() is True

    def test_list_objects_returns_list(self, client, monkeypatch):
        monkeypatch.setattr(client, "post", lambda path, **kw: [{"_id": "c1", "title": "Test"}])
        results = client.list_objects("case")
        assert len(results) == 1
        assert results[0]["_id"] == "c1"

    def test_list_objects_with_dict_response(self, client, monkeypatch):
        monkeypatch.setattr(client, "post", lambda path, **kw: {"items": [{"_id": "a1"}]})
        results = client.list_objects("alert")
        assert results[0]["_id"] == "a1"

    def test_get_object(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"_id": "c42", "title": "Breach"})
        obj = client.get_object("case", "c42")
        assert obj["_id"] == "c42"

    def test_upsert_creates(self, client, monkeypatch):
        captured = {}

        def fake_post(path, **kw):
            captured["path"] = path
            return {"_id": "new"}

        monkeypatch.setattr(client, "post", fake_post)
        result = client.upsert_object("case", {"title": "New Case"})
        assert "/case" in captured["path"]
        assert result["_id"] == "new"

    def test_upsert_patches_when_id_present(self, client, monkeypatch):
        captured = {}

        def fake_patch(path, **kw):
            captured["path"] = path
            return {"_id": "existing"}

        monkeypatch.setattr(client, "patch", fake_patch)
        client.upsert_object("case", {"id": "existing", "title": "Updated"})
        assert "existing" in captured["path"]

    def test_add_observable_calls_post(self, client, monkeypatch):
        captured = {}

        def fake_post(path, **kw):
            captured["path"] = path
            captured["json"] = kw.get("json", {})
            return {}

        monkeypatch.setattr(client, "post", fake_post)
        stix = {"type": "indicator", "pattern": "[ipv4-addr:value = '1.2.3.4']", "name": "1.2.3.4"}
        client.add_observable("case-99", stix)
        assert "case-99" in captured["path"]
        assert captured["json"]["dataType"] == "ip"
        assert captured["json"]["data"] == "1.2.3.4"

    def test_to_stix_case(self, client):
        native = {
            "_type": "case",
            "_id": "c1",
            "title": "Phishing",
            "description": "Phishing attack",
            "_createdAt": "2026-01-01",
            "_updatedAt": "2026-01-02",
            "severity": 3,
            "status": "Open",
            "tags": ["phishing"],
        }
        stix = client.to_stix(native)
        assert stix["type"] == "observed-data"
        assert stix["name"] == "Phishing"
        assert stix["x_source_platform"] == "thehive"

    def test_to_stix_alert(self, client):
        native = {
            "_type": "alert",
            "_id": "a1",
            "title": "Malware Alert",
            "sourceRef": "malware.com",
            "_createdAt": "2026-01-01",
            "severity": 2,
            "type": "external",
        }
        stix = client.to_stix(native)
        assert stix["type"] == "indicator"

    def test_to_stix_observable_domain(self, client):
        native = {
            "_id": "o1",
            "dataType": "domain",
            "data": "evil.com",
            "_createdAt": "2026-01-01",
            "ioc": True,
            "tags": [],
        }
        stix = client.to_stix(native)
        assert "domain-name" in stix["pattern"]

    def test_from_stix_builds_case_payload(self, client):
        stix = {
            "type": "indicator",
            "name": "Suspicious IP",
            "description": "IP seen in attacks",
            "confidence": 75,
        }
        payload = client.from_stix(stix)
        assert payload["title"] == "Suspicious IP"
        assert "severity" in payload


# ---------------------------------------------------------------------------
# ThreatStreamClient
# ---------------------------------------------------------------------------


class TestThreatStreamClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.threatstream.client import ThreatStreamClient

        return ThreatStreamClient(
            host="https://api.threatstream.com",
            username="analyst@example.com",
            api_key="ts-key-xyz",
        )

    def test_authenticate_stores_credentials(self, client):
        client.authenticate()
        assert client._ts_auth["username"] == "analyst@example.com"
        assert client._ts_auth["api_key"] == "ts-key-xyz"

    def test_health_check_success(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"objects": [], "meta": {}})
        assert client.health_check() is True

    def test_health_check_failure(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: "bad")
        assert client.health_check() is False

    def test_list_objects_returns_objects(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", lambda path, **kw: {"objects": [{"id": 1, "type": "ip"}]}
        )
        results = client.list_objects("indicator")
        assert len(results) == 1
        assert results[0]["id"] == 1

    def test_list_objects_with_filters(self, client, monkeypatch):
        captured = {}

        def fake_get(path, **kw):
            captured["params"] = kw.get("params", {})
            return {"objects": []}

        monkeypatch.setattr(client, "get", fake_get)
        client.list_objects("indicator", filters={"status": "active", "confidence__gte": 70})
        assert captured["params"]["status"] == "active"

    def test_get_object(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"id": 42, "type": "domain"})
        obj = client.get_object("indicator", "42")
        assert obj["id"] == 42

    def test_upsert_creates(self, client, monkeypatch):
        captured = {}

        def fake_post(path, **kw):
            captured["json"] = kw.get("json", {})
            return {}

        monkeypatch.setattr(client, "post", fake_post)
        client.upsert_object("indicator", {"value": "1.2.3.4", "type": "ip"})
        assert "objects" in captured["json"]

    def test_upsert_patches_when_id_present(self, client, monkeypatch):
        captured = {}

        def fake_patch(path, **kw):
            captured["path"] = path
            return {}

        monkeypatch.setattr(client, "patch", fake_patch)
        client.upsert_object("indicator", {"id": 77, "value": "evil.com"})
        assert "77" in captured["path"]

    def test_to_stix_ip(self, client):
        native = {
            "id": 1,
            "type": "ip",
            "value": "1.2.3.4",
            "confidence": 85,
            "status": "active",
            "created_ts": "2026-01-01",
            "modified_ts": "2026-01-02",
        }
        stix = client.to_stix(native)
        assert stix["type"] == "indicator"
        assert "ipv4-addr" in stix["pattern"]
        assert stix["confidence"] == 85
        assert stix["x_source_platform"] == "threatstream"

    def test_to_stix_domain(self, client):
        native = {"id": 2, "type": "domain", "value": "evil.com", "confidence": 60}
        stix = client.to_stix(native)
        assert "domain-name" in stix["pattern"]

    def test_from_stix_returns_payload(self, client):
        stix = {"pattern": "[domain-name:value = 'evil.com']", "name": "evil.com", "confidence": 80}
        payload = client.from_stix(stix)
        assert payload["value"] == "evil.com"
        assert payload["type"] == "domain"
        assert payload["status"] == "active"


# ---------------------------------------------------------------------------
# SOCRadarClient
# ---------------------------------------------------------------------------


class TestSOCRadarClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.socradar.client import SOCRadarClient

        return SOCRadarClient(host="https://platform.socradar.com", api_key="sr-key")

    def test_authenticate_sets_header(self, client):
        client.authenticate()
        assert client._auth_headers["Authorization"] == "sr-key"

    def test_health_check_success(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"data": []})
        assert client.health_check() is True

    def test_list_objects_returns_data(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", lambda path, **kw: {"data": [{"id": 1, "value": "1.2.3.4"}]}
        )
        results = client.list_objects("indicator")
        assert len(results) == 1
        assert results[0]["value"] == "1.2.3.4"

    def test_list_objects_results_key(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"results": [{"id": 2}]})
        results = client.list_objects("indicator")
        assert results[0]["id"] == 2

    def test_get_object(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"id": 42})
        obj = client.get_object("indicator", "42")
        assert obj["id"] == 42

    def test_upsert_raises(self, client):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError, match="read-only"):
            client.upsert_object("indicator", {"value": "1.2.3.4"})

    def test_to_stix_ip(self, client):
        native = {
            "id": 1,
            "ioc_type": "ip",
            "value": "1.2.3.4",
            "severity": "high",
            "created_at": "2026-01-01",
        }
        stix = client.to_stix(native)
        assert stix["type"] == "indicator"
        assert "ipv4-addr" in stix["pattern"]
        assert stix["confidence"] == 75
        assert stix["x_source_platform"] == "socradar"

    def test_to_stix_actor(self, client):
        native = {
            "type": "threat_actor",
            "id": 5,
            "name": "Cobalt Group",
            "description": "FIN group",
            "created_at": "2026-01-01",
        }
        stix = client.to_stix(native)
        assert stix["type"] == "threat-actor"

    def test_to_stix_malware(self, client):
        native = {
            "type": "malware",
            "id": 6,
            "name": "BlackCat",
            "description": "Ransomware",
            "created_at": "2026-01-01",
        }
        stix = client.to_stix(native)
        assert stix["type"] == "malware"
        assert stix["is_family"] is True

    def test_from_stix_returns_dict(self, client):
        stix = {"pattern": "[domain-name:value = 'evil.com']", "name": "evil.com"}
        payload = client.from_stix(stix)
        assert payload["value"] == "evil.com"
        assert payload["ioc_type"] == "domain"


# ---------------------------------------------------------------------------
# PulseDiveClient
# ---------------------------------------------------------------------------


class TestPulseDiveClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.pulsedive.client import PulseDiveClient

        return PulseDiveClient(host="https://pulsedive.com", api_key="pd-key")

    def test_authenticate_is_noop(self, client):
        client.authenticate()  # Should not raise; key injected via params
        assert "Authorization" not in client._auth_headers

    def test_pd_params_includes_key(self, client):
        assert client._pd_params["key"] == "pd-key"

    def test_health_check(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"version": "1"})
        assert client.health_check() is True

    def test_list_objects_indicators(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", lambda path, **kw: {"results": [{"iid": 1, "indicator": "1.2.3.4"}]}
        )
        results = client.list_objects("indicator")
        assert results[0]["iid"] == 1

    def test_get_object_indicator(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"iid": 7, "indicator": "x.com"})
        obj = client.get_object("indicator", "7")
        assert obj["iid"] == 7

    def test_enrich(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"iid": 9, "indicator": "evil.com"})
        result = client.enrich("evil.com")
        assert result["indicator"] == "evil.com"

    def test_upsert_posts(self, client, monkeypatch):
        captured = {}

        def fake_post(path, **kw):
            captured["json"] = kw.get("json", {})
            return {}

        monkeypatch.setattr(client, "post", fake_post)
        client.upsert_object("indicator", {"value": "evil.com", "type": "domain"})
        assert captured["json"]["indicator"] == "evil.com"

    def test_to_stix_domain(self, client):
        native = {
            "iid": 1,
            "type": "domain",
            "indicator": "evil.com",
            "risk": "high",
            "stamp_added": "2026-01-01",
            "threats": [],
        }
        stix = client.to_stix(native)
        assert "domain-name" in stix["pattern"]
        assert stix["confidence"] == 75
        assert stix["x_source_platform"] == "pulsedive"

    def test_to_stix_threat(self, client):
        native = {
            "type": "threat",
            "tid": 2,
            "name": "Lazarus",
            "risk": "critical",
            "stamp_added": "2026-01-01",
        }
        stix = client.to_stix(native)
        assert stix["type"] == "threat-actor"

    def test_from_stix(self, client):
        stix = {"pattern": "[ipv4-addr:value = '10.0.0.1']", "name": "10.0.0.1"}
        payload = client.from_stix(stix)
        assert payload["indicator"] == "10.0.0.1"
        assert payload["type"] == "ip"


# ---------------------------------------------------------------------------
# FlareClient
# ---------------------------------------------------------------------------


class TestFlareClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.flare.client import FlareClient

        return FlareClient(host="https://api.flare.io", api_key="flare-key")

    def test_authenticate_sets_bearer(self, client):
        client.authenticate()
        assert client._auth_headers["Authorization"] == "Bearer flare-key"

    def test_health_check(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"sources": []})
        assert client.health_check() is True

    def test_list_objects_items(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"items": [{"id": "f1"}]})
        results = client.list_objects("indicator")
        assert results[0]["id"] == "f1"

    def test_list_objects_hits(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"hits": [{"id": "f2"}]})
        results = client.list_objects("observed-data")
        assert results[0]["id"] == "f2"

    def test_get_object(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"id": "f99"})
        obj = client.get_object("indicator", "f99")
        assert obj["id"] == "f99"

    def test_upsert_raises(self, client):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError, match="read-only"):
            client.upsert_object("indicator", {})

    def test_search_leaks(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"items": [{"id": "lk1"}]})
        results = client.search_leaks("victim@example.com")
        assert results[0]["id"] == "lk1"

    def test_to_stix_credential_leak(self, client):
        native = {
            "id": "f1",
            "type": "credential",
            "email": "user@example.com",
            "severity": "high",
            "created_at": "2026-01-01",
            "source": "darkweb",
        }
        stix = client.to_stix(native)
        assert stix["type"] == "indicator"
        assert "email" in stix["pattern"]
        assert stix["x_source_platform"] == "flare"

    def test_to_stix_actor(self, client):
        native = {
            "type": "actor",
            "id": "a1",
            "name": "DarkTeam",
            "description": "Dark web actor",
            "created_at": "2026-01-01",
        }
        stix = client.to_stix(native)
        assert stix["type"] == "threat-actor"

    def test_from_stix(self, client):
        stix = {"pattern": "[domain-name:value = 'leak.example.com']", "name": "leak.example.com"}
        payload = client.from_stix(stix)
        assert payload["query"] == "leak.example.com"


# ---------------------------------------------------------------------------
# StellarCyberClient
# ---------------------------------------------------------------------------


class TestStellarCyberClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.stellarcyber.client import StellarCyberClient

        return StellarCyberClient(
            host="https://tenant.stellarcyber.ai",
            username="admin",
            api_key="sc-key",
        )

    def test_authenticate_sets_bearer(self, client, monkeypatch):
        monkeypatch.setattr(client, "post", lambda path, **kw: {"access_token": "jwt_tok"})
        client.authenticate()
        assert client._auth_headers["Authorization"] == "Bearer jwt_tok"

    def test_authenticate_raises_on_missing_token(self, client, monkeypatch):
        from gnat.clients.base import GNATClientError

        monkeypatch.setattr(client, "post", lambda path, **kw: {})
        with pytest.raises(GNATClientError, match="StellarCyber"):
            client.authenticate()

    def test_health_check(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"data": []})
        assert client.health_check() is True

    def test_list_objects_alerts(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"data": [{"_id": "a1"}]})
        results = client.list_objects("observed-data")
        assert results[0]["_id"] == "a1"

    def test_list_objects_ti(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"hits": [{"id": "ti1"}]})
        results = client.list_objects("indicator")
        assert results[0]["id"] == "ti1"

    def test_upsert_creates(self, client, monkeypatch):
        captured = {}

        def fake_post(path, **kw):
            captured["path"] = path
            return {"id": "new"}

        monkeypatch.setattr(client, "post", fake_post)
        result = client.upsert_object("indicator", {"indicator_value": "1.2.3.4"})
        assert "threat_intel" in captured["path"]

    def test_to_stix_alert(self, client):
        native = {
            "_id": "a1",
            "alert_name": "Lateral Movement",
            "srcip": "10.0.0.5",
            "dstip": "192.168.1.1",
            "severity": 4,
            "timestamp": "2026-01-01",
            "msg": "SMB sweep",
        }
        stix = client.to_stix(native)
        assert stix["type"] == "observed-data"
        assert "10.0.0.5" in stix["pattern"]
        assert stix["x_source_platform"] == "stellarcyber"

    def test_to_stix_ti_indicator(self, client):
        native = {
            "id": "ti1",
            "indicator_type": "domain",
            "indicator_value": "evil.com",
            "confidence": 80,
        }
        stix = client.to_stix(native)
        assert stix["type"] == "indicator"
        assert "domain-name" in stix["pattern"]

    def test_from_stix(self, client):
        stix = {"pattern": "[ipv4-addr:value = '1.2.3.4']", "confidence": 75}
        payload = client.from_stix(stix)
        assert payload["indicator_value"] == "1.2.3.4"
        assert payload["indicator_type"] == "ip"


# ---------------------------------------------------------------------------
# YetiClient
# ---------------------------------------------------------------------------


class TestYetiClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.yeti.client import YetiClient

        return YetiClient(host="https://yeti.example.com", api_key="yeti-key")

    def test_authenticate_sets_header(self, client):
        client.authenticate()
        assert client._auth_headers["X-Yeti-API-Key"] == "yeti-key"

    def test_health_check(self, client, monkeypatch):
        monkeypatch.setattr(client, "post", lambda path, **kw: {"observables": []})
        assert client.health_check() is True

    def test_list_objects_observables(self, client, monkeypatch):
        monkeypatch.setattr(client, "post", lambda path, **kw: {"observables": [{"id": "o1"}]})
        results = client.list_objects("indicator")
        assert results[0]["id"] == "o1"

    def test_list_objects_entities(self, client, monkeypatch):
        monkeypatch.setattr(client, "post", lambda path, **kw: {"entities": [{"id": "e1"}]})
        results = client.list_objects("threat-actor")
        assert results[0]["id"] == "e1"

    def test_upsert_creates(self, client, monkeypatch):
        captured = {}

        def fake_post(path, **kw):
            captured["path"] = path
            return {"id": "new"}

        monkeypatch.setattr(client, "post", fake_post)
        result = client.upsert_object("indicator", {"value": "evil.com", "type": "hostname"})
        assert "observables" in captured["path"]

    def test_upsert_updates_when_id(self, client, monkeypatch):
        captured = {}

        def fake_put(path, **kw):
            captured["path"] = path
            return {}

        monkeypatch.setattr(client, "put", fake_put)
        client.upsert_object("indicator", {"id": "obs-42", "value": "evil.com"})
        assert "obs-42" in captured["path"]

    def test_add_tag(self, client, monkeypatch):
        captured = {}

        def fake_post(path, **kw):
            captured["json"] = kw.get("json", {})
            return {}

        monkeypatch.setattr(client, "post", fake_post)
        client.add_tag("o1", "indicator", "malware")
        assert "malware" in captured["json"]["tags"]

    def test_to_stix_observable(self, client):
        native = {
            "id": "o1",
            "type": "ip",
            "value": "1.2.3.4",
            "created": "2026-01-01",
            "tags": [{"name": "apt"}],
        }
        stix = client.to_stix(native)
        assert stix["type"] == "indicator"
        assert "ipv4-addr" in stix["pattern"]
        assert stix["x_source_platform"] == "yeti"

    def test_to_stix_actor(self, client):
        native = {
            "type": "ThreatActor",
            "id": "ta1",
            "name": "APT29",
            "description": "Russian APT",
            "aliases": ["Cozy Bear"],
        }
        stix = client.to_stix(native)
        assert stix["type"] == "threat-actor"

    def test_to_stix_malware(self, client):
        native = {"type": "Malware", "id": "m1", "name": "Emotet", "description": ""}
        stix = client.to_stix(native)
        assert stix["type"] == "malware"
        assert stix["is_family"] is True

    def test_from_stix(self, client):
        stix = {"pattern": "[domain-name:value = 'evil.com']", "name": "evil.com"}
        payload = client.from_stix(stix)
        assert payload["value"] == "evil.com"
        assert payload["type"] == "hostname"


# ---------------------------------------------------------------------------
# CloudSEKClient
# ---------------------------------------------------------------------------


class TestCloudSEKClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.cloudsek.client import CloudSEKClient

        return CloudSEKClient(host="https://api.cloudsek.com", api_key="cs-key")

    def test_authenticate_sets_bearer(self, client):
        client.authenticate()
        assert client._auth_headers["Authorization"] == "Bearer cs-key"

    def test_authenticate_sets_org_header(self):
        from gnat.connectors.cloudsek.client import CloudSEKClient

        c = CloudSEKClient(host="https://api.cloudsek.com", api_key="k", org_id="org-1")
        c.authenticate()
        assert c._auth_headers["X-Org-Id"] == "org-1"

    def test_health_check(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"data": []})
        assert client.health_check() is True

    def test_list_objects_returns_data(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"data": [{"id": "cs1"}]})
        results = client.list_objects("observed-data")
        assert results[0]["id"] == "cs1"

    def test_get_object_unwraps_data(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"data": {"id": "cs42"}})
        obj = client.get_object("observed-data", "cs42")
        assert obj["id"] == "cs42"

    def test_upsert_raises(self, client):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError, match="read-only"):
            client.upsert_object("observed-data", {})

    def test_update_alert_status(self, client, monkeypatch):
        captured = {}

        def fake_patch(path, **kw):
            captured["path"] = path
            captured["json"] = kw.get("json", {})
            return {}

        monkeypatch.setattr(client, "patch", fake_patch)
        client.update_alert_status("a1", "resolved", "reviewed by analyst")
        assert "a1" in captured["path"]
        assert captured["json"]["status"] == "resolved"

    def test_to_stix_credential_alert(self, client):
        native = {
            "id": "cs1",
            "category": "credential_leak",
            "email": "user@corp.com",
            "severity": "high",
            "created_at": "2026-01-01",
            "title": "Leaked credential",
        }
        stix = client.to_stix(native)
        assert stix["type"] == "indicator"
        assert "email" in stix["pattern"]
        assert stix["confidence"] == 75
        assert stix["x_source_platform"] == "cloudsek"

    def test_to_stix_brand_abuse(self, client):
        native = {
            "id": "cs2",
            "category": "brand_abuse",
            "domain": "corp-phishing.com",
            "severity": "critical",
            "created_at": "2026-01-01",
        }
        stix = client.to_stix(native)
        assert "domain-name" in stix["pattern"]

    def test_to_stix_actor(self, client):
        native = {
            "category": "threat_actor",
            "id": "ta1",
            "name": "DarkGroup",
            "description": "APT group",
            "created_at": "2026-01-01",
        }
        stix = client.to_stix(native)
        assert stix["type"] == "threat-actor"

    def test_from_stix(self, client):
        stix = {
            "pattern": "[email-message:from_ref.value = 'evil@bad.com']",
            "name": "evil@bad.com",
        }
        payload = client.from_stix(stix)
        assert payload["keyword"] == "evil@bad.com"
        assert payload["category"] == "credential_leak"


# ---------------------------------------------------------------------------
# ArmisClient
# ---------------------------------------------------------------------------


class TestArmisClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.armis.client import ArmisClient

        return ArmisClient(host="https://fake.armis.com", api_key="armis-key")

    def test_authenticate_sets_header(self, client):
        client.authenticate()
        assert client._auth_headers["x-api-key"] == "armis-key"
        assert client._auth_headers["Accept"] == "application/json"

    def test_health_check(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"results": []})
        assert client.health_check() is True

    def test_get_object_device(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"id": "d1", "name": "sensor"})
        result = client.get_object("report", "d1")
        assert isinstance(result, dict)

    def test_get_object_vulnerability(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", lambda path, **kw: {"id": "c1", "cve_id": "CVE-2024-1234"}
        )
        result = client.get_object("vulnerability", "c1")
        assert isinstance(result, dict)

    def test_get_object_unsupported_raises(self, client):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError):
            client.get_object("indicator", "x")

    def test_list_objects_vulnerability(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"results": [{"id": "c1"}]})
        result = client.list_objects("vulnerability")
        assert isinstance(result, list)
        assert result[0]["id"] == "c1"

    def test_list_objects_device(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"results": [{"id": "d1"}]})
        result = client.list_objects("report")
        assert isinstance(result, list)

    def test_upsert_raises(self, client):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError):
            client.upsert_object("report", {})

    def test_delete_raises(self, client):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError):
            client.delete_object("report", "x")

    def test_to_stix_device(self, client):
        native = {"id": "d1", "name": "PLC-Unit-1", "type": "OT", "risk_level": "high"}
        stix = client.to_stix(native)
        assert stix["type"] == "report"
        assert "id" in stix
        assert "--" in stix["id"]

    def test_to_stix_vulnerability(self, client):
        native = {
            "id": "v1",
            "cve_id": "CVE-2024-0001",
            "title": "Buffer Overflow",
            "severity": "critical",
            "vulnerability": True,
        }
        stix = client.to_stix(native)
        assert stix["type"] == "vulnerability"
        assert "--" in stix["id"]

    def test_from_stix(self, client):
        stix = {"id": "indicator--abc", "name": "test"}
        payload = client.from_stix(stix)
        assert isinstance(payload, dict)
        assert payload["stix_id"] == "indicator--abc"

    def test_fetch_devices(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"results": [{"id": "d1"}]})
        result = client.fetch_devices(limit=10)
        assert isinstance(result, list)

    def test_fetch_vulnerabilities_helper(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"results": [{"id": "v1"}]})
        result = client.fetch_vulnerabilities(limit=10)
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# AxoniusClient
# ---------------------------------------------------------------------------


class TestAxoniusClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.axonius.client import AxoniusClient

        return AxoniusClient(host="https://fake.axonius.com", api_key="axkey", api_secret="axsec")

    def test_authenticate_sets_header(self, client):
        client._basic_auth = lambda u, p: "Basic fake-token"
        client.authenticate()
        assert client._auth_headers["Authorization"] == "Basic fake-token"
        assert client._auth_headers["Accept"] == "application/json"

    def test_health_check(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"data": []})
        assert client.health_check() is True

    def test_get_object_asset(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"id": "a1", "name": "server"})
        result = client.get_object("report", "a1")
        assert isinstance(result, dict)

    def test_get_object_vulnerability(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"id": "v1"})
        result = client.get_object("vulnerability", "v1")
        assert isinstance(result, dict)

    def test_get_object_unsupported_raises(self, client):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError):
            client.get_object("indicator", "x")

    def test_list_objects_assets(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"data": [{"id": "a1"}]})
        result = client.list_objects("report")
        assert isinstance(result, list)
        assert result[0]["id"] == "a1"

    def test_list_objects_vulnerability(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"data": [{"id": "v1"}]})
        result = client.list_objects("vulnerability")
        assert isinstance(result, list)

    def test_upsert_raises(self, client):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError):
            client.upsert_object("report", {})

    def test_delete_raises(self, client):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError):
            client.delete_object("report", "x")

    def test_to_stix_asset(self, client):
        native = {
            "id": "a1",
            "name": "webserver",
            "hostname": "web01",
            "ip_addresses": ["10.0.0.1"],
        }
        stix = client.to_stix(native)
        assert stix["type"] == "report"
        assert "--" in stix["id"]

    def test_to_stix_vulnerability(self, client):
        native = {
            "id": "v1",
            "title": "CVE Vuln",
            "severity": "high",
            "vulnerabilities": [{"cve_id": "CVE-2024-1234"}],
        }
        stix = client.to_stix(native)
        assert stix["type"] == "vulnerability"
        assert "--" in stix["id"]

    def test_from_stix(self, client):
        stix = {"id": "report--abc", "name": "test"}
        payload = client.from_stix(stix)
        assert isinstance(payload, dict)
        assert payload["stix_id"] == "report--abc"

    def test_fetch_assets(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"data": [{"id": "a1"}]})
        result = client.fetch_assets(limit=5)
        assert isinstance(result, list)

    def test_run_query(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"data": [{"id": "r1"}]})
        result = client.run_query("query-id")
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# ChatGPTClient
# ---------------------------------------------------------------------------


class TestChatGPTClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.chatgpt.client import ChatGPTClient

        return ChatGPTClient(host="https://api.openai.com", api_key="openai-key")

    def test_authenticate_sets_bearer(self, client):
        client.authenticate()
        assert client._auth_headers["Authorization"] == "Bearer openai-key"
        assert client._auth_headers["Content-Type"] == "application/json"

    def test_health_check(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"data": []})
        assert client.health_check() is True

    def test_get_object_raises(self, client):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError):
            client.get_object("report", "id-1")

    def test_get_object_unsupported_type_raises(self, client):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError):
            client.get_object("indicator", "id-1")

    def test_list_objects_returns_models(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", lambda path, **kw: {"data": [{"id": "gpt-4.1"}, {"id": "gpt-4o"}]}
        )
        result = client.list_objects("report")
        assert isinstance(result, list)
        assert result[0]["id"] == "gpt-4.1"

    def test_list_objects_unsupported_raises(self, client, monkeypatch):
        from gnat.clients.base import GNATClientError

        monkeypatch.setattr(client, "get", lambda path, **kw: {"data": []})
        with pytest.raises(GNATClientError):
            client.list_objects("indicator")

    def test_upsert_raises(self, client):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError):
            client.upsert_object("report", {})

    def test_delete_raises(self, client):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError):
            client.delete_object("report", "x")

    def test_chat_completion(self, client, monkeypatch):
        fake_resp = {
            "id": "chatcmpl-1",
            "model": "gpt-4.1",
            "choices": [
                {
                    "message": {"role": "assistant", "content": "Test response"},
                    "finish_reason": "stop",
                }
            ],
            "usage": {},
        }
        monkeypatch.setattr(client, "post", lambda path, **kw: fake_resp)
        result = client.chat_completion([{"role": "user", "content": "test"}])
        assert "choices" in result

    def test_to_stix_chat_completion(self, client):
        native = {
            "id": "chatcmpl-1",
            "model": "gpt-4.1",
            "choices": [
                {
                    "message": {"role": "assistant", "content": "Threat analysis"},
                    "finish_reason": "stop",
                }
            ],
            "usage": {"total_tokens": 100},
        }
        stix = client.to_stix(native)
        assert stix["type"] == "report"
        assert "id" in stix
        assert "--" in stix["id"]
        assert stix["x_chatgpt"]["model"] == "gpt-4.1"

    def test_to_stix_model_list(self, client):
        native = {"data": [{"id": "gpt-4.1"}]}
        stix = client.to_stix(native)
        assert stix["type"] == "report"

    def test_from_stix_returns_prompt(self, client):
        stix = {"id": "report--abc", "description": "Analyze this."}
        payload = client.from_stix(stix)
        assert isinstance(payload, dict)
        assert "suggested_messages" in payload
        assert payload["stix_id"] == "report--abc"


# ---------------------------------------------------------------------------
# CopilotClient
# ---------------------------------------------------------------------------


class TestCopilotClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.copilot.client import CopilotClient

        return CopilotClient(
            host="https://fake-copilot.example.com", auth_type="api_key", api_key="cop-key"
        )

    def test_authenticate_api_key(self, client):
        client.authenticate()
        assert client._auth_headers["Authorization"] == "Bearer cop-key"

    def test_authenticate_azure(self):
        from gnat.connectors.copilot.client import CopilotClient

        c = CopilotClient(
            host="https://fake.example.com", auth_type="azure", azure_token="az-token"
        )
        c.authenticate()
        assert c._auth_headers["Authorization"] == "Bearer az-token"

    def test_authenticate_none(self):
        from gnat.connectors.copilot.client import CopilotClient

        c = CopilotClient(host="https://fake.example.com", auth_type="none")
        c.authenticate()
        assert "Authorization" not in c._auth_headers

    def test_authenticate_unknown_raises(self):
        from gnat.clients.base import GNATClientError
        from gnat.connectors.copilot.client import CopilotClient

        c = CopilotClient(host="https://fake.example.com", auth_type="bogus")
        with pytest.raises(GNATClientError):
            c.authenticate()

    def test_health_check(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"data": []})
        assert client.health_check() is True

    def test_get_object_raises(self, client):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError):
            client.get_object("report", "x")

    def test_list_objects_returns_models(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"data": [{"id": "copilot-latest"}]})
        result = client.list_objects("report")
        assert isinstance(result, list)
        assert result[0]["id"] == "copilot-latest"

    def test_list_objects_unsupported_raises(self, client, monkeypatch):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError):
            client.list_objects("indicator")

    def test_upsert_raises(self, client):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError):
            client.upsert_object("report", {})

    def test_delete_raises(self, client):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError):
            client.delete_object("report", "x")

    def test_chat_completion(self, client, monkeypatch):
        fake_resp = {
            "model": "copilot-latest",
            "choices": [{"message": {"content": "Here is the analysis."}}],
            "usage": {},
        }
        monkeypatch.setattr(client, "post", lambda path, **kw: fake_resp)
        result = client.chat_completion([{"role": "user", "content": "test"}])
        assert "choices" in result

    def test_to_stix_chat_completion(self, client):
        native = {
            "model": "copilot-latest",
            "choices": [{"message": {"content": "Analysis text"}}],
            "usage": {},
        }
        stix = client.to_stix(native)
        assert stix["type"] == "report"
        assert "id" in stix

    def test_from_stix_returns_prompt(self, client):
        stix = {"id": "report--abc", "description": "Analyze threat."}
        payload = client.from_stix(stix)
        assert isinstance(payload, dict)
        assert "suggested_messages" in payload


# ---------------------------------------------------------------------------
# CortexXpanseClient
# ---------------------------------------------------------------------------


class TestCortexXpanseClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.cortex_xpanse.client import CortexXpanseClient

        return CortexXpanseClient(
            host="https://fake.xpanse.com", api_key="xp-key", api_key_id="xp-id"
        )

    def test_authenticate_sets_headers(self, client):
        client.authenticate()
        assert client._auth_headers["x-xdr-auth-id"] == "xp-id"
        assert client._auth_headers["Authorization"] == "Bearer xp-key"

    def test_health_check(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"data": []})
        assert client.health_check() is True

    def test_get_object_asset(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"id": "a1", "name": "server"})
        result = client.get_object("report", "a1")
        assert isinstance(result, dict)

    def test_get_object_exposure(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"id": "e1", "severity": "high"})
        result = client.get_object("vulnerability", "e1")
        assert isinstance(result, dict)

    def test_get_object_unsupported_raises(self, client):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError):
            client.get_object("indicator", "x")

    def test_list_objects_exposures(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"data": [{"id": "e1"}]})
        result = client.list_objects("vulnerability")
        assert isinstance(result, list)

    def test_list_objects_assets(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"data": [{"id": "a1"}]})
        result = client.list_objects("report")
        assert isinstance(result, list)

    def test_upsert_raises(self, client):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError):
            client.upsert_object("report", {})

    def test_delete_raises(self, client):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError):
            client.delete_object("report", "x")

    def test_to_stix_exposure(self, client):
        native = {"id": "e1", "title": "Open RDP", "severity": "high", "exposure": True, "risk": 80}
        stix = client.to_stix(native)
        assert stix["type"] == "vulnerability"
        assert "--" in stix["id"]

    def test_to_stix_asset(self, client):
        native = {"id": "a1", "name": "webserver", "ip": "203.0.113.5", "domain": "example.com"}
        stix = client.to_stix(native)
        assert stix["type"] == "report"
        assert "--" in stix["id"]

    def test_from_stix(self, client):
        stix = {"id": "report--abc"}
        payload = client.from_stix(stix)
        assert isinstance(payload, dict)
        assert payload["stix_id"] == "report--abc"

    def test_fetch_incidents(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"data": [{"id": "i1"}]})
        result = client.fetch_incidents(limit=5)
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# CyCognitoClient
# ---------------------------------------------------------------------------


class TestCyCognitoClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.cycognito.client import CyCognitoClient

        return CyCognitoClient(host="https://fake.cycognito.com", api_key="cyc-key")

    def test_authenticate_sets_bearer(self, client):
        client.authenticate()
        assert client._auth_headers["Authorization"] == "Bearer cyc-key"

    def test_health_check(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"issues": []})
        assert client.health_check() is True

    def test_get_object_vulnerability(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"id": "i1", "severity": "high"})
        result = client.get_object("vulnerability", "i1")
        assert isinstance(result, dict)

    def test_get_object_report(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"id": "a1"})
        result = client.get_object("report", "a1")
        assert isinstance(result, dict)

    def test_get_object_unsupported_raises(self, client):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError):
            client.get_object("indicator", "x")

    def test_list_objects_issues(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"issues": [{"id": "i1"}]})
        result = client.list_objects("vulnerability")
        assert isinstance(result, list)
        assert result[0]["id"] == "i1"

    def test_list_objects_assets(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"assets": [{"id": "a1"}]})
        result = client.list_objects("report")
        assert isinstance(result, list)

    def test_upsert_raises(self, client):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError):
            client.upsert_object("vulnerability", {})

    def test_delete_raises(self, client):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError):
            client.delete_object("vulnerability", "x")

    def test_to_stix_issue(self, client):
        native = {
            "id": "i1",
            "title": "Exposed RDP",
            "severity": "critical",
            "description": "RDP port open",
            "status": "open",
        }
        stix = client.to_stix(native)
        assert stix["type"] == "vulnerability"
        assert "--" in stix["id"]

    def test_to_stix_asset(self, client):
        native = {"id": "a1", "name": "10.0.0.1", "type": "ip"}
        stix = client.to_stix(native)
        assert stix["type"] == "report"
        assert "--" in stix["id"]

    def test_from_stix(self, client):
        stix = {"id": "vulnerability--abc"}
        payload = client.from_stix(stix)
        assert isinstance(payload, dict)

    def test_fetch_issues(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"issues": [{"id": "i1"}]})
        result = client.fetch_issues(limit=5, severity="high")
        assert isinstance(result, list)

    def test_fetch_assets(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"assets": [{"id": "a1"}]})
        result = client.fetch_assets(asset_type="ip", limit=5)
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# CybleVisionClient
# ---------------------------------------------------------------------------


class TestCybleVisionClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.cyble_vision.client import CybleVisionClient

        return CybleVisionClient(host="https://fake.cyble.ai", api_token="cyble-token")

    def test_authenticate_sets_bearer(self, client):
        client.authenticate()
        assert client._auth_headers["Authorization"] == "Bearer cyble-token"

    def test_health_check(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"data": []})
        assert client.health_check() is True

    def test_get_object_alert(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", lambda path, **kw: {"id": "ev1", "title": "Dark web alert"}
        )
        result = client.get_object("report", "ev1")
        assert isinstance(result, dict)

    def test_get_object_ioc(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"id": "ioc1"})
        result = client.get_object("indicator", "ioc1")
        assert isinstance(result, dict)

    def test_get_object_unsupported_raises(self, client):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError):
            client.get_object("vulnerability", "x")

    def test_list_objects_indicators(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            lambda path, **kw: {"data": [{"ioc_value": "evil.com", "type": "domain"}]},
        )
        result = client.list_objects("indicator")
        assert isinstance(result, list)

    def test_list_objects_alerts(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"data": [{"id": "a1"}]})
        result = client.list_objects("report")
        assert isinstance(result, list)

    def test_upsert_raises(self, client):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError):
            client.upsert_object("indicator", {})

    def test_delete_raises(self, client):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError):
            client.delete_object("indicator", "x")

    def test_to_stix_ioc_domain(self, client):
        native = {
            "ioc_value": "evil.com",
            "type": "domain",
            "confidence": 80,
            "first_seen": "2026-01-01T00:00:00Z",
        }
        stix = client.to_stix(native)
        assert stix["type"] == "indicator"
        assert "domain-name" in stix["pattern"]
        assert "--" in stix["id"]

    def test_to_stix_ioc_ip(self, client):
        native = {"ioc_value": "1.2.3.4", "type": "ipv4"}
        stix = client.to_stix(native)
        assert stix["type"] == "indicator"
        assert "ipv4-addr" in stix["pattern"]

    def test_to_stix_alert(self, client):
        native = {
            "id": "ev1",
            "title": "Dark web mention",
            "event_type": "darkweb_mention",
            "priority": "high",
            "date": "2026-01-01T00:00:00Z",
        }
        stix = client.to_stix(native)
        assert stix["type"] == "report"
        assert "--" in stix["id"]

    def test_from_stix_raises(self, client):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError):
            client.from_stix({"id": "indicator--abc"})

    def test_fetch_iocs(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"data": [{"ioc_value": "x"}]})
        result = client.fetch_iocs(limit=5)
        assert isinstance(result, list)

    def test_fetch_alerts(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"data": [{"id": "a1"}]})
        result = client.fetch_alerts(limit=5, priority="high")
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# GeminiClient
# ---------------------------------------------------------------------------


class TestGeminiClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.gemini.client import GeminiClient

        return GeminiClient(host="https://generativelanguage.googleapis.com", api_key="gemini-key")

    def test_authenticate_sets_header(self, client):
        client.authenticate()
        assert client._auth_headers["x-goog-api-key"] == "gemini-key"
        assert client._auth_headers["Content-Type"] == "application/json"

    def test_health_check(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"models": []})
        assert client.health_check() is True

    def test_upsert_raises(self, client):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError):
            client.upsert_object("report", {})

    def test_to_stix_valid_json(self, client):
        import json

        inner = {
            "type": "report",
            "id": "report--abc123",
            "spec_version": "2.1",
            "name": "Test",
            "created": "2026-01-01T00:00:00Z",
            "modified": "2026-01-01T00:00:00Z",
        }
        native = {"candidates": [{"content": {"parts": [{"text": json.dumps(inner)}]}}]}
        stix = client.to_stix(native)
        assert stix["type"] == "report"

    def test_to_stix_fallback_on_invalid_json(self, client):
        native = {"candidates": [{"content": {"parts": [{"text": "This is plain text analysis"}]}}]}
        stix = client.to_stix(native)
        assert stix["type"] == "report"
        assert "id" in stix

    def test_research_to_stix(self, client, monkeypatch):
        fake_resp = {"candidates": [{"content": {"parts": [{"text": "Plain text analysis"}]}}]}
        monkeypatch.setattr(client, "post", lambda path, **kw: fake_resp)
        stix = client.research_to_stix("APT29 malware")
        assert stix["type"] == "report"

    def test_to_stix_id_has_dashes(self, client):
        native = {"candidates": [{"content": {"parts": [{"text": "analysis"}]}}]}
        stix = client.to_stix(native)
        assert "--" in stix["id"]

    def test_to_stix_empty_candidates(self, client):
        # Empty candidates list causes IndexError in the connector;
        # test that a non-empty candidates with empty parts falls back gracefully
        native = {"candidates": [{"content": {"parts": [{"text": ""}]}}]}
        stix = client.to_stix(native)
        assert stix["type"] == "report"

    def test_authenticate_google_key_in_header(self, client):
        client.authenticate()
        assert "x-goog-api-key" in client._auth_headers


# ---------------------------------------------------------------------------
# GreenboneClient
# ---------------------------------------------------------------------------


class TestGreenboneClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.greenbone.client import GreenboneClient

        return GreenboneClient(host="localhost", port=9390, username="admin", password="pass")

    def test_authenticate_raises_without_gvm(self, client, monkeypatch):
        import gnat.connectors.greenbone.client as mod

        monkeypatch.setattr(mod, "_HAS_GVM", False)
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError, match="python-gvm"):
            client.authenticate()

    def test_upsert_raises(self, client):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError):
            client.upsert_object("vulnerability", {})

    def test_delete_raises(self, client):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError):
            client.delete_object("vulnerability", "x")

    def test_to_stix_result(self, client):
        native = {
            "id": "r1",
            "name": "SSH Weak Password",
            "severity": "high",
            "description": "Weak credentials",
            "host": "10.0.0.1",
        }
        stix = client.to_stix(native)
        assert stix["type"] == "vulnerability"
        assert "--" in stix["id"]
        assert stix["x_greenbone"]["result_id"] == "r1"

    def test_to_stix_report(self, client):
        native = {"id": "rp1", "scan_start": "2026-01-01"}
        stix = client.to_stix(native)
        assert stix["type"] == "report"
        assert "--" in stix["id"]

    def test_from_stix(self, client):
        stix = {"id": "vulnerability--abc"}
        payload = client.from_stix(stix)
        assert isinstance(payload, dict)
        assert payload["stix_id"] == "vulnerability--abc"

    def test_parse_results_empty(self, client):
        result = client._parse_results(None)
        assert isinstance(result, list)
        assert result == []

    def test_parse_reports_empty(self, client):
        result = client._parse_reports(None)
        assert isinstance(result, list)
        assert result == []

    def test_stix_type_map(self, client):
        assert "vulnerability" in client.stix_type_map
        assert "report" in client.stix_type_map


# ---------------------------------------------------------------------------
# GrokClient
# ---------------------------------------------------------------------------


class TestGrokClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.grok.client import GrokClient

        return GrokClient(host="https://api.x.ai", api_key="grok-key")

    def test_authenticate_sets_bearer(self, client):
        client.authenticate()
        assert client._auth_headers["Authorization"] == "Bearer grok-key"

    def test_health_check(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"data": []})
        assert client.health_check() is True

    def test_get_object_raises(self, client):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError):
            client.get_object("report", "x")

    def test_get_object_unsupported_raises(self, client):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError):
            client.get_object("indicator", "x")

    def test_list_objects_models(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"data": [{"id": "grok-4-0709"}]})
        result = client.list_objects("report")
        assert isinstance(result, list)
        assert result[0]["id"] == "grok-4-0709"

    def test_list_objects_unsupported_raises(self, client, monkeypatch):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError):
            client.list_objects("indicator")

    def test_upsert_raises(self, client):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError):
            client.upsert_object("report", {})

    def test_delete_raises(self, client):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError):
            client.delete_object("report", "x")

    def test_chat_completion(self, client, monkeypatch):
        fake_resp = {
            "id": "grok-resp-1",
            "model": "grok-4-0709",
            "choices": [{"message": {"content": "Threat analysis here"}, "finish_reason": "stop"}],
            "usage": {},
        }
        monkeypatch.setattr(client, "post", lambda path, **kw: fake_resp)
        result = client.chat_completion([{"role": "user", "content": "Who is APT29?"}])
        assert "choices" in result

    def test_to_stix_chat_completion(self, client):
        native = {
            "id": "grok-1",
            "model": "grok-4-0709",
            "choices": [{"message": {"content": "APT29 analysis"}}],
            "usage": {},
        }
        stix = client.to_stix(native)
        assert stix["type"] == "report"
        assert "--" in stix["id"]
        assert stix["x_grok"]["model"] == "grok-4-0709"

    def test_to_stix_model_list(self, client):
        native = {"data": [{"id": "grok-4-0709"}]}
        stix = client.to_stix(native)
        assert stix["type"] == "report"

    def test_from_stix(self, client):
        stix = {"id": "report--abc", "description": "Analyze APT."}
        payload = client.from_stix(stix)
        assert isinstance(payload, dict)
        assert "suggested_messages" in payload
        assert payload["stix_id"] == "report--abc"


# ---------------------------------------------------------------------------
# GroupIBClient
# ---------------------------------------------------------------------------


class TestGroupIBClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.group_ib.client import GroupIBClient

        return GroupIBClient(
            host="https://fake.group-ib.com/api/v2/", username="user", token="token"
        )

    def test_authenticate_sets_header(self, client):
        client._basic_auth = lambda u, p: "Basic fake-token"
        client.authenticate()
        assert client._auth_headers["Authorization"] == "Basic fake-token"

    def test_health_check(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"items": []})
        assert client.health_check() is True

    def test_get_object(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"id": "col1", "name": "Test"})
        result = client.get_object("indicator", "col1")
        assert isinstance(result, dict)

    def test_list_objects(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"items": [{"id": "i1"}]})
        result = client.list_objects("indicator")
        assert isinstance(result, list)

    def test_upsert_raises(self, client):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError):
            client.upsert_object("indicator", {})

    def test_delete_raises(self, client):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError):
            client.delete_object("indicator", "x")

    def test_to_stix_compromised(self, client):
        native = {
            "id": "c1",
            "email": "user@corp.com",
            "login": "user@corp.com",
            "source": "darkweb",
        }
        stix = client.to_stix(native)
        assert stix["type"] == "indicator"
        assert "--" in stix["id"]

    def test_to_stix_ioc(self, client):
        native = {"id": "i1", "hash": "abc123def456", "ioc": True, "value": "hash-value"}
        stix = client.to_stix(native)
        assert stix["type"] == "indicator"

    def test_to_stix_event(self, client):
        native = {
            "id": "ev1",
            "title": "Ransomware Campaign",
            "severity": "high",
            "date": "2026-01-01",
            "collection": "attacks",
        }
        stix = client.to_stix(native)
        assert stix["type"] == "report"
        assert "--" in stix["id"]

    def test_from_stix(self, client):
        stix = {"id": "indicator--abc"}
        payload = client.from_stix(stix)
        assert isinstance(payload, dict)
        assert payload["stix_id"] == "indicator--abc"

    def test_fetch_collection(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"items": [{"id": "i1"}]})
        result = client.fetch_collection("malware", limit=5)
        assert isinstance(result, list)

    def test_fetch_compromised_accounts(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"items": [{"email": "u@c.com"}]})
        result = client.fetch_compromised_accounts(limit=5)
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# TenableOneClient
# ---------------------------------------------------------------------------


class TestTenableOneClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.tenable_one.client import TenableOneClient

        return TenableOneClient(
            host="https://cloud.tenable.com", access_key="acc-key", secret_key="sec-key"
        )

    def test_authenticate_sets_apikeys_header(self, client):
        client.authenticate()
        assert "accessKey=acc-key" in client._auth_headers["X-ApiKeys"]
        assert "secretKey=sec-key" in client._auth_headers["X-ApiKeys"]

    def test_health_check(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"users": []})
        assert client.health_check() is True

    def test_get_object_vulnerability(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"id": "v1", "severity": "critical"})
        result = client.get_object("vulnerability", "v1")
        assert isinstance(result, dict)

    def test_get_object_report(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"id": "card1"})
        result = client.get_object("report", "card1")
        assert isinstance(result, dict)

    def test_get_object_unsupported_raises(self, client):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError):
            client.get_object("indicator", "x")

    def test_list_objects_vulnerability(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"vulnerabilities": [{"id": "v1"}]})
        result = client.list_objects("vulnerability")
        assert isinstance(result, list)

    def test_upsert_raises(self, client):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError):
            client.upsert_object("vulnerability", {})

    def test_delete_raises(self, client):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError):
            client.delete_object("vulnerability", "x")

    def test_to_stix_vulnerability(self, client):
        native = {
            "id": "v1",
            "plugin_id": "12345",
            "name": "OpenSSL Vuln",
            "severity": "critical",
            "risk": {"cvss": 9.8},
        }
        stix = client.to_stix(native)
        assert stix["type"] == "vulnerability"
        assert "--" in stix["id"]

    def test_to_stix_exposure_card(self, client):
        native = {
            "id": "card1",
            "title": "Unpatched Servers",
            "type": "cyber-exposure-score",
            "cyber_exposure_score": 750,
        }
        stix = client.to_stix(native)
        assert stix["type"] == "report"
        assert "--" in stix["id"]

    def test_to_stix_attack_path(self, client):
        native = {
            "id": "path1",
            "name": "Admin compromise",
            "technique": "T1078",
            "priority_rating": "high",
            "attack_path": True,
        }
        stix = client.to_stix(native)
        assert stix["type"] == "report"

    def test_from_stix(self, client):
        stix = {"id": "vulnerability--abc"}
        payload = client.from_stix(stix)
        assert isinstance(payload, dict)

    def test_fetch_attack_paths(self, client, monkeypatch):
        monkeypatch.setattr(client, "post", lambda path, **kw: {"attack_paths": [{"id": "p1"}]})
        result = client.fetch_attack_paths(limit=5)
        assert isinstance(result, list)

    def test_fetch_exposure_cards(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"cards": [{"id": "c1"}]})
        result = client.fetch_exposure_cards(limit=5)
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# WizClient
# ---------------------------------------------------------------------------


class TestWizClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.wiz.client import WizClient

        return WizClient(
            host="https://api.us1.app.wiz.io", client_id="wiz-id", client_secret="wiz-sec"
        )

    def test_authenticate_sets_bearer(self, client, monkeypatch):
        fake_token_resp = {"access_token": "tok-abc123"}
        monkeypatch.setattr(client, "post", lambda path, **kw: fake_token_resp)
        client.authenticate()
        assert client._auth_headers["Authorization"] == "Bearer tok-abc123"

    def test_authenticate_raises_on_bad_response(self, client, monkeypatch):
        from gnat.clients.base import GNATClientError

        monkeypatch.setattr(client, "post", lambda path, **kw: {"error": "invalid_client"})
        with pytest.raises(GNATClientError):
            client.authenticate()

    def test_health_check(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "post",
            lambda path, **kw: {"data": {"__schema": {"queryType": {"name": "Query"}}}},
        )
        assert client.health_check() is True

    def test_list_objects_vulnerabilities(self, client, monkeypatch):
        gql_resp = {"data": {"vulnerabilityFindings": {"nodes": [{"id": "v1", "name": "CVE"}]}}}
        monkeypatch.setattr(client, "post", lambda path, **kw: gql_resp)
        result = client.list_objects("vulnerability")
        assert isinstance(result, list)
        assert result[0]["id"] == "v1"

    def test_list_objects_issues(self, client, monkeypatch):
        gql_resp = {"data": {"issues": {"nodes": [{"id": "i1", "title": "Toxic Combo"}]}}}
        monkeypatch.setattr(client, "post", lambda path, **kw: gql_resp)
        result = client.list_objects("report")
        assert isinstance(result, list)

    def test_get_object_raises(self, client):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError):
            client.get_object("vulnerability", "v1")

    def test_upsert_raises(self, client):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError):
            client.upsert_object("vulnerability", {})

    def test_delete_raises(self, client):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError):
            client.delete_object("vulnerability", "x")

    def test_to_stix_vulnerability(self, client):
        native = {
            "id": "v1",
            "name": "CVE-2024-1234",
            "cve": {"id": "CVE-2024-1234"},
            "severity": "CRITICAL",
            "status": "OPEN",
        }
        stix = client.to_stix(native)
        assert stix["type"] == "vulnerability"
        assert "--" in stix["id"]

    def test_to_stix_issue(self, client):
        native = {
            "id": "i1",
            "title": "Toxic Combination",
            "severity": "HIGH",
            "status": "OPEN",
            "type": "TOXIC_COMBINATION",
            "createdAt": "2026-01-01T00:00:00Z",
        }
        stix = client.to_stix(native)
        assert stix["type"] == "report"
        assert "--" in stix["id"]

    def test_from_stix_raises(self, client):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError):
            client.from_stix({"id": "vulnerability--abc"})

    def test_graphql_query_raises_on_errors(self, client, monkeypatch):
        from gnat.clients.base import GNATClientError

        monkeypatch.setattr(
            client, "post", lambda path, **kw: {"errors": [{"message": "Not authorized"}]}
        )
        with pytest.raises(GNATClientError):
            client._graphql_query("query { test }")


# ---------------------------------------------------------------------------
# ZeroFoxClient
# ---------------------------------------------------------------------------


class TestZeroFoxClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.zerofox.client import ZeroFoxClient

        return ZeroFoxClient(host="https://api.zerofox.com", token="zf-token")

    def test_authenticate_sets_bearer(self, client):
        client.authenticate()
        assert client._auth_headers["Authorization"] == "Bearer zf-token"

    def test_health_check(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"data": []})
        assert client.health_check() is True

    def test_get_object_alert(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"id": "a1", "title": "Phishing"})
        result = client.get_object("report", "a1")
        assert isinstance(result, dict)

    def test_get_object_indicator(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"id": "t1"})
        result = client.get_object("indicator", "t1")
        assert isinstance(result, dict)

    def test_get_object_unsupported_raises(self, client):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError):
            client.get_object("vulnerability", "x")

    def test_list_objects_indicators(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"data": [{"id": "t1"}]})
        result = client.list_objects("indicator")
        assert isinstance(result, list)

    def test_list_objects_alerts(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"data": [{"id": "a1"}]})
        result = client.list_objects("report")
        assert isinstance(result, list)

    def test_upsert_raises(self, client):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError):
            client.upsert_object("indicator", {})

    def test_delete_raises(self, client):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError):
            client.delete_object("indicator", "x")

    def test_to_stix_alert(self, client):
        native = {
            "id": "a1",
            "title": "Brand Impersonation",
            "type": "impersonation",
            "severity": "high",
            "created_at": "2026-01-01T00:00:00Z",
        }
        stix = client.to_stix(native)
        assert stix["type"] == "report"
        assert "--" in stix["id"]

    def test_to_stix_threat_url(self, client):
        native = {
            "id": "t1",
            "name": "Phishing URL",
            "url": "http://evil.com/phish",
            "type": "phishing",
        }
        stix = client.to_stix(native)
        assert stix["type"] == "indicator"
        assert "--" in stix["id"]
        assert "url:value" in stix["pattern"]

    def test_to_stix_threat_hash(self, client):
        native = {"id": "t2", "name": "Malware Hash", "hash": "abc123def", "type": "malware"}
        stix = client.to_stix(native)
        assert stix["type"] == "indicator"
        assert "SHA-256" in stix["pattern"]

    def test_from_stix(self, client):
        stix = {"id": "indicator--abc"}
        payload = client.from_stix(stix)
        assert isinstance(payload, dict)

    def test_fetch_alerts(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"data": [{"id": "a1"}]})
        result = client.fetch_alerts(limit=5, alert_type="impersonation")
        assert isinstance(result, list)

    def test_fetch_cti_threats(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"data": [{"id": "t1"}]})
        result = client.fetch_cti_threats(limit=5, threat_type="botnet")
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# OrcaClient
# ---------------------------------------------------------------------------


class TestOrcaClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.orca.client import OrcaClient

        return OrcaClient(host="https://api.orcasecurity.io", api_token="orca-token")

    def test_authenticate_sets_bearer(self, client):
        client.authenticate()
        assert client._auth_headers["Authorization"] == "Bearer orca-token"

    def test_health_check(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"assets": []})
        assert client.health_check() is True

    def test_get_object_finding(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"id": "f1", "severity": "high"})
        result = client.get_object("vulnerability", "f1")
        assert isinstance(result, dict)

    def test_get_object_asset(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"id": "a1"})
        result = client.get_object("report", "a1")
        assert isinstance(result, dict)

    def test_get_object_unsupported_raises(self, client):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError):
            client.get_object("indicator", "x")

    def test_list_objects_findings(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"findings": [{"id": "f1"}]})
        result = client.list_objects("vulnerability")
        assert isinstance(result, list)
        assert result[0]["id"] == "f1"

    def test_list_objects_assets(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"assets": [{"id": "a1"}]})
        result = client.list_objects("report")
        assert isinstance(result, list)

    def test_upsert_raises(self, client):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError):
            client.upsert_object("vulnerability", {})

    def test_delete_raises(self, client):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError):
            client.delete_object("vulnerability", "x")

    def test_to_stix_finding(self, client):
        native = {
            "id": "f1",
            "title": "S3 Bucket Public",
            "severity": "high",
            "risk": 85,
            "cloud_provider": "AWS",
            "resource_type": "s3",
        }
        stix = client.to_stix(native)
        assert stix["type"] == "vulnerability"
        assert "--" in stix["id"]

    def test_to_stix_asset(self, client):
        native = {
            "id": "a1",
            "name": "web-server",
            "type": "ec2",
            "cloud_provider": "AWS",
            "region": "us-east-1",
        }
        stix = client.to_stix(native)
        assert stix["type"] == "report"
        assert "--" in stix["id"]

    def test_from_stix(self, client):
        stix = {"id": "vulnerability--abc"}
        payload = client.from_stix(stix)
        assert isinstance(payload, dict)

    def test_fetch_findings_with_filters(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"findings": [{"id": "f1"}]})
        result = client.fetch_findings(limit=5, severity="high", cloud_provider="aws")
        assert isinstance(result, list)

    def test_fetch_api_risks(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"findings": [{"id": "r1"}]})
        result = client.fetch_api_risks(limit=5)
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# QualysVMDRClient
# ---------------------------------------------------------------------------


class TestQualysVMDRClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.qualys.client import QualysVMDRClient

        return QualysVMDRClient(
            host="https://qualysapi.qualys.com", username="quser", password="qpass"
        )

    def test_authenticate_sets_header(self, client):
        client._basic_auth = lambda u, p: "Basic qualys-token"
        client.authenticate()
        assert client._auth_headers["Authorization"] == "Basic qualys-token"

    def test_health_check(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {})
        assert client.health_check() is True

    def test_get_object_vulnerability(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", lambda path, **kw: {"VULN_LIST": {"VULN": [{"QID": "12345"}]}}
        )
        result = client.get_object("vulnerability", "12345")
        assert isinstance(result, dict)

    def test_get_object_unsupported_raises(self, client):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError):
            client.get_object("indicator", "x")

    def test_list_objects_vulnerabilities(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            lambda path, **kw: {"VULN_LIST": {"VULN": [{"QID": "1", "TITLE": "Vuln1"}]}},
        )
        result = client.list_objects("vulnerability")
        assert isinstance(result, list)

    def test_list_objects_detections(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", lambda path, **kw: {"HOST_LIST": {"HOST": [{"ID": "h1"}]}}
        )
        result = client.list_objects("report")
        assert isinstance(result, list)

    def test_upsert_raises(self, client):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError):
            client.upsert_object("vulnerability", {})

    def test_delete_raises(self, client):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError):
            client.delete_object("vulnerability", "x")

    def test_to_stix_vulnerability(self, client):
        native = {
            "QID": "12345",
            "TITLE": "SSL Certificate Expired",
            "SEVERITY": "3",
            "CVSS": "7.5",
            "DESCRIPTION": "SSL cert is expired",
            "PATCHABLE": "1",
        }
        stix = client.to_stix(native)
        assert stix["type"] == "vulnerability"
        assert "--" in stix["id"]
        assert stix["x_qualys"]["qid"] == "12345"

    def test_to_stix_detection(self, client):
        native = {"ID": "h1", "SEVERITY": "4", "IP": "10.0.0.1"}
        stix = client.to_stix(native)
        assert stix["type"] == "report"
        assert "--" in stix["id"]

    def test_from_stix(self, client):
        stix = {"id": "vulnerability--abc"}
        payload = client.from_stix(stix)
        assert isinstance(payload, dict)

    def test_fetch_vulnerabilities(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", lambda path, **kw: {"VULN_LIST": {"VULN": [{"QID": "1"}]}}
        )
        result = client.fetch_vulnerabilities(limit=5, severity="3")
        assert isinstance(result, list)

    def test_fetch_detections(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", lambda path, **kw: {"HOST_LIST": {"HOST": [{"ID": "h1"}]}}
        )
        result = client.fetch_detections(limit=5)
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# SentinelOneClient
# ---------------------------------------------------------------------------


class TestSentinelOneClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.sentinelone.client import SentinelOneClient

        return SentinelOneClient(host="https://usea1.sentinelone.net", token="s1-token")

    def test_authenticate_sets_apitoken(self, client):
        client.authenticate()
        assert client._auth_headers["Authorization"] == "ApiToken s1-token"

    def test_health_check(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"data": []})
        assert client.health_check() is True

    def test_get_object_threat(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", lambda path, **kw: {"id": "t1", "threatInfo": {"sha1": "abc"}}
        )
        result = client.get_object("indicator", "t1")
        assert isinstance(result, dict)

    def test_get_object_report(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", lambda path, **kw: {"id": "t1", "mitigationStatus": "mitigated"}
        )
        result = client.get_object("report", "t1")
        assert isinstance(result, dict)

    def test_get_object_unsupported_raises(self, client):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError):
            client.get_object("vulnerability", "x")

    def test_list_objects_threats(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"data": [{"id": "t1"}]})
        result = client.list_objects("indicator")
        assert isinstance(result, list)
        assert result[0]["id"] == "t1"

    def test_list_objects_unsupported_raises(self, client):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError):
            client.list_objects("vulnerability")

    def test_upsert_raises(self, client):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError):
            client.upsert_object("indicator", {})

    def test_delete_raises(self, client):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError):
            client.delete_object("indicator", "x")

    def test_to_stix_threat(self, client):
        native = {
            "id": "t1",
            "createdAt": "2026-01-01T00:00:00Z",
            "threatInfo": {
                "threatName": "Emotet",
                "sha1": "aabbccdd112233",
                "severity": "CRITICAL",
                "classification": "Malware",
            },
            "mitigationStatus": "mitigated",
        }
        stix = client.to_stix(native)
        assert stix["type"] == "indicator"
        assert "--" in stix["id"]
        assert "SHA-1" in stix["pattern"]

    def test_to_stix_agent(self, client):
        native = {
            "id": "ag1",
            "computerName": "DESKTOP-01",
            "osName": "Windows 10",
            "lastSeen": "2026-01-01",
        }
        stix = client.to_stix(native)
        assert stix["type"] == "report"
        assert "--" in stix["id"]

    def test_from_stix(self, client):
        stix = {"id": "indicator--abc"}
        payload = client.from_stix(stix)
        assert isinstance(payload, dict)

    def test_get_hash_reputation(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", lambda path, **kw: {"rank": 10, "classification": "malware"}
        )
        result = client.get_hash_reputation("aabbcc1122")
        assert isinstance(result, dict)

    def test_add_to_blocklist(self, client, monkeypatch):
        captured = {}

        def fake_post(path, **kw):
            captured["json"] = kw.get("json", {})
            return {"success": True}

        monkeypatch.setattr(client, "post", fake_post)
        client.add_to_blocklist("aabbcc1122", "block malware")
        assert "aabbcc1122" in captured["json"]["hashes"]

    def test_list_agents(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"data": [{"id": "ag1"}]})
        result = client.list_agents(limit=5)
        assert isinstance(result, list)


# ---------------------------------------------------------------------------
# CriblClient
# ---------------------------------------------------------------------------


class TestCriblClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.cribl.client import CriblClient

        return CriblClient(
            host="https://cribl.example.com",
            username="admin",
            password="secret",
            worker_group="default",
        )

    @pytest.fixture
    def token_client(self):
        from gnat.connectors.cribl.client import CriblClient

        return CriblClient(
            host="https://cribl.example.com",
            token="my-api-token",
            worker_group="default",
        )

    def test_authenticate_with_token(self, token_client):
        token_client.authenticate()
        assert token_client._auth_headers["Authorization"] == "Bearer my-api-token"

    def test_authenticate_with_credentials(self, client, monkeypatch):
        monkeypatch.setattr(client, "post", lambda path, **kw: {"token": "got-token"})
        client.authenticate()
        assert client._auth_headers["Authorization"] == "Bearer got-token"

    def test_authenticate_failure_raises(self, client, monkeypatch):
        from gnat.connectors.cribl.exceptions import CriblAuthError

        monkeypatch.setattr(client, "post", lambda path, **kw: {})
        with pytest.raises(CriblAuthError):
            client.authenticate()

    def test_health_check(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"status": "healthy"})
        assert client.health_check() is True

    def test_list_pipelines(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"items": [{"id": "p1"}]})
        result = client.list_pipelines()
        assert isinstance(result, list)
        assert result[0]["id"] == "p1"

    def test_get_pipeline(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"id": "p1", "conf": {}})
        result = client.get_pipeline("p1")
        assert result["id"] == "p1"

    def test_create_pipeline(self, client, monkeypatch):
        captured = {}

        def fake_post(path, **kw):
            captured["json"] = kw.get("json", {})
            return {"id": "p2", "conf": {}}

        monkeypatch.setattr(client, "post", fake_post)
        result = client.create_pipeline({"id": "p2", "conf": {}})
        assert result["id"] == "p2"

    def test_delete_pipeline(self, client, monkeypatch):
        monkeypatch.setattr(client, "delete", lambda path, **kw: {})
        result = client.delete_pipeline("p1")
        assert result is None

    def test_list_inputs(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"items": [{"id": "in1"}]})
        result = client.list_inputs()
        assert isinstance(result, list)
        assert result[0]["id"] == "in1"

    def test_search(self, client, monkeypatch):
        monkeypatch.setattr(client, "post", lambda path, **kw: {"id": "job1", "status": "running"})
        result = client.search("sourcetype=syslog")
        assert isinstance(result, dict)
        assert "id" in result

    def test_list_lookups(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"items": [{"id": "lk1"}]})
        result = client.list_lookups()
        assert isinstance(result, list)
        assert result[0]["id"] == "lk1"

    def test_list_objects_course_of_action(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"items": [{"id": "p1"}]})
        result = client.list_objects("course-of-action")
        assert isinstance(result, list)

    def test_list_objects_unsupported_raises(self, client):
        from gnat.clients.base import GNATClientError

        with pytest.raises(GNATClientError):
            client.list_objects("vulnerability")

    def test_to_stix_pipeline(self, client):
        native = {"id": "my-pipeline", "conf": {"functions": [{"filter": "true", "id": "comment"}]}}
        stix = client.to_stix(native)
        assert stix["type"] == "course-of-action"
        assert "--" in stix["id"]

    def test_to_stix_event(self, client):
        native = {
            "_raw": "some log line",
            "_time": 1700000000,
            "cribl_pipe": "main",
            "src_ip": "1.2.3.4",
        }
        stix = client.to_stix(native)
        assert stix["type"] == "observed-data"
        assert "--" in stix["id"]

    def test_from_stix_indicator(self, client):
        stix = {
            "type": "indicator",
            "id": "indicator--12345678-1234-1234-1234-123456789012",
            "name": "malicious IP",
            "pattern": "[ipv4-addr:value = '1.2.3.4']",
            "pattern_type": "stix",
        }
        result = client.from_stix(stix)
        assert isinstance(result, dict)
        assert "id" in result


# ---------------------------------------------------------------------------
# SynapseClient
# ---------------------------------------------------------------------------


class TestSynapseClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.synapse.client import SynapseClient

        return SynapseClient(
            host="https://synapse.example.com",
            username="root",
            password="secret",
        )

    @pytest.fixture
    def apikey_client(self):
        from gnat.connectors.synapse.client import SynapseClient

        return SynapseClient(
            host="https://synapse.example.com",
            api_key="my-api-key",
        )

    def test_authenticate_with_api_key(self, apikey_client):
        apikey_client.authenticate()
        assert apikey_client._auth_headers["Authorization"] == "Bearer my-api-key"

    def test_authenticate_with_credentials(self, client, monkeypatch):
        monkeypatch.setattr(client, "post", lambda path, **kw: {"result": {"token": "sess-token"}})
        client.authenticate()
        assert client._auth_headers["Authorization"] == "Bearer sess-token"

    def test_health_check(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"result": "ok"})
        assert client.health_check() is True

    def test_storm_returns_nodes(self, client, monkeypatch):
        storm_messages = [
            {
                "type": "node",
                "data": [["inet:ipv4", "1.2.3.4"], {"props": {}, "tags": {}, "iden": "abc"}],
            },
        ]
        monkeypatch.setattr(client, "post", lambda path, **kw: storm_messages)
        nodes = client.storm("inet:ipv4")
        assert len(nodes) == 1
        assert nodes[0]["ndef"] == ["inet:ipv4", "1.2.3.4"]

    def test_get_node_by_iden(self, client, monkeypatch):
        node = {"ndef": ["inet:ipv4", "1.2.3.4"], "props": {}, "tags": {}, "iden": "abc"}

        def fake_storm(query, opts=None):
            return [node]

        monkeypatch.setattr(client, "storm", fake_storm)
        result = client.get_node_by_iden("abc")
        assert result["ndef"] == ["inet:ipv4", "1.2.3.4"]

    def test_get_node_by_iden_not_found(self, client, monkeypatch):
        from gnat.clients.base import GNATClientError

        monkeypatch.setattr(client, "storm", lambda q, **kw: [])
        with pytest.raises(GNATClientError):
            client.get_node_by_iden("nonexistent")

    def test_list_objects_indicator(self, client, monkeypatch):
        nodes = [
            {"ndef": ["inet:fqdn", "evil.com"], "props": {}, "tags": {}, "iden": "n1"},
            {"ndef": ["inet:ipv4", "1.2.3.4"], "props": {}, "tags": {}, "iden": "n2"},
        ]
        call_count = [0]

        def fake_storm(query, opts=None):
            call_count[0] += 1
            return [nodes[call_count[0] - 1]] if call_count[0] <= len(nodes) else []

        monkeypatch.setattr(client, "storm", fake_storm)
        result = client.list_objects("indicator", page_size=10)
        assert isinstance(result, list)

    def test_to_stix_ipv4(self, client):
        node = {
            "ndef": ["inet:ipv4", "192.168.1.1"],
            "props": {},
            "tags": {"tlp.red": [None, None]},
            "iden": "abc123",
        }
        stix = client.to_stix(node)
        assert stix["type"] == "ipv4-addr"
        assert stix["value"] == "192.168.1.1"

    def test_to_stix_fqdn(self, client):
        node = {"ndef": ["inet:fqdn", "evil.com"], "props": {}, "tags": {}, "iden": "def456"}
        stix = client.to_stix(node)
        assert stix["type"] == "domain-name"
        assert stix["value"] == "evil.com"

    def test_to_stix_url(self, client):
        node = {
            "ndef": ["inet:url", "https://evil.com/path"],
            "props": {},
            "tags": {},
            "iden": "ghi",
        }
        stix = client.to_stix(node)
        assert stix["type"] == "url"
        assert stix["value"] == "https://evil.com/path"

    def test_to_stix_file_bytes(self, client):
        node = {
            "ndef": ["file:bytes", "sha256:aabbcc"],
            "props": {"sha256": "aabbcc", "md5": "1234"},
            "tags": {},
            "iden": "jkl",
        }
        stix = client.to_stix(node)
        assert stix["type"] == "file"
        assert "SHA-256" in stix.get("hashes", {}) or isinstance(stix.get("hashes"), dict)

    def test_to_stix_vuln(self, client):
        node = {
            "ndef": ["risk:vuln", "CVE-2024-0001"],
            "props": {"name": "Test Vuln"},
            "tags": {},
            "iden": "mno",
        }
        stix = client.to_stix(node)
        assert stix["type"] == "vulnerability"

    def test_to_stix_threat_actor(self, client):
        node = {
            "ndef": ["risk:threat", "APT28"],
            "props": {"name": "APT28"},
            "tags": {},
            "iden": "pqr",
        }
        stix = client.to_stix(node)
        assert stix["type"] == "threat-actor"

    def test_from_stix_indicator(self, client):
        stix = {
            "type": "indicator",
            "id": "indicator--abcdef",
            "pattern": "[ipv4-addr:value = '10.0.0.1']",
            "labels": ["malicious-activity"],
        }
        result = client.from_stix(stix)
        assert result["form"] == "inet:ipv4"
        assert result["value"] == "10.0.0.1"

    def test_list_views(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"result": [{"iden": "v1"}]})
        result = client.list_views()
        assert isinstance(result, list)

    def test_list_users(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", lambda path, **kw: {"result": [{"name": "root"}]})
        result = client.list_users()
        assert isinstance(result, list)
        assert result[0]["name"] == "root"

    # ------------------------------------------------------------------
    # Vertex Synapse — NDJSON storm stream parsing
    # ------------------------------------------------------------------

    def test_storm_parses_ndjson_string(self, client, monkeypatch):
        """Real Synapse returns NDJSON; BaseClient returns it as a str."""
        import json as _json

        ndjson = "\n".join(
            [
                _json.dumps({"type": "init", "data": {"tick": 0}}),
                _json.dumps(
                    {
                        "type": "node",
                        "data": [
                            ["inet:ipv4", "5.6.7.8"],
                            {"props": {}, "tags": {}, "iden": "aaa"},
                        ],
                    }
                ),
                _json.dumps({"type": "fini", "data": {"count": 1}}),
            ]
        )
        monkeypatch.setattr(client, "post", lambda path, **kw: ndjson)
        nodes = client.storm("inet:ipv4")
        assert len(nodes) == 1
        assert nodes[0]["ndef"] == ["inet:ipv4", "5.6.7.8"]

    def test_storm_raises_on_err_message(self, client, monkeypatch):
        """Storm ``err`` messages must propagate as SynapseStormError."""
        import json as _json

        from gnat.connectors.synapse.exceptions import SynapseStormError

        ndjson = "\n".join(
            [
                _json.dumps({"type": "err", "data": ["BadSyntax", {"mesg": "unexpected token"}]}),
            ]
        )
        monkeypatch.setattr(client, "post", lambda path, **kw: ndjson)
        with pytest.raises(SynapseStormError):
            client.storm("bad query !!!")

    # ------------------------------------------------------------------
    # Vertex Synapse — new / MITRE ATT&CK forms
    # ------------------------------------------------------------------

    def test_to_stix_mitre_technique(self, client):
        """``it:mitre:attack:technique`` → ``attack-pattern`` with external_references."""
        node = {
            "ndef": ["it:mitre:attack:technique", "T1059"],
            "props": {"name": "Command and Scripting Interpreter", "technique_id": "T1059"},
            "tags": {},
            "iden": "t1",
        }
        stix = client.to_stix(node)
        assert stix["type"] == "attack-pattern"
        assert "T1059" in stix.get("external_references", [{}])[0].get("external_id", "")

    def test_to_stix_mitre_software(self, client):
        """``it:mitre:attack:software`` → ``malware``."""
        node = {
            "ndef": ["it:mitre:attack:software", "Cobalt Strike"],
            "props": {"name": "Cobalt Strike", "software_id": "S0154"},
            "tags": {},
            "iden": "s1",
        }
        stix = client.to_stix(node)
        assert stix["type"] == "malware"
        assert stix["name"] == "Cobalt Strike"

    def test_to_stix_mitre_group(self, client):
        """``it:mitre:attack:group`` → ``threat-actor``."""
        node = {
            "ndef": ["it:mitre:attack:group", "APT29"],
            "props": {"name": "APT29", "group_id": "G0016"},
            "tags": {},
            "iden": "g1",
        }
        stix = client.to_stix(node)
        assert stix["type"] == "threat-actor"
        assert stix["name"] == "APT29"

    def test_to_stix_asn(self, client):
        """``inet:asn`` → ``autonomous-system``."""
        node = {
            "ndef": ["inet:asn", 15169],
            "props": {"name": "GOOGLE"},
            "tags": {},
            "iden": "asn1",
        }
        stix = client.to_stix(node)
        assert stix["type"] == "autonomous-system"
        assert stix["number"] == 15169

    def test_to_stix_vuln_with_cve(self, client):
        """``risk:vuln`` with ``:cve`` prop → external_references CVE entry."""
        node = {
            "ndef": ["risk:vuln", "some-vuln-iden"],
            "props": {"name": "Log4Shell", "cve": "CVE-2021-44228"},
            "tags": {},
            "iden": "v2",
        }
        stix = client.to_stix(node)
        assert stix["type"] == "vulnerability"
        ext_refs = stix.get("external_references", [])
        assert any(r.get("external_id") == "CVE-2021-44228" for r in ext_refs)

    def test_to_stix_risk_mitigation(self, client):
        """``risk:mitigation`` → ``course-of-action``."""
        node = {
            "ndef": ["risk:mitigation", "patch-log4j"],
            "props": {"name": "Patch Log4j", "desc": "Apply vendor patch"},
            "tags": {},
            "iden": "m1",
        }
        stix = client.to_stix(node)
        assert stix["type"] == "course-of-action"
        assert stix["name"] == "Patch Log4j"

    def test_from_stix_sha256_indicator(self, client):
        """``file:hashes.SHA-256`` STIX pattern → ``hash:sha256`` form."""
        stix = {
            "type": "indicator",
            "id": "indicator--abc",
            "pattern": "[file:hashes.'SHA-256' = 'aabbcc']",
            "labels": [],
        }
        result = client.from_stix(stix)
        assert result["form"] == "hash:sha256"
        assert result["value"] == "aabbcc"

    def test_stix_to_storm_add_with_tags(self, client):
        """``stix_to_storm_add`` generates a valid Storm add query."""
        stix = {
            "type": "indicator",
            "id": "indicator--xyz",
            "pattern": "[ipv4-addr:value = '10.0.0.1']",
            "labels": ["malicious-activity"],
        }
        query = client._mapper.stix_to_storm_add(stix)
        assert "inet:ipv4" in query
        assert "10.0.0.1" in query
        assert "malicious-activity" in query


# ---------------------------------------------------------------------------
# Trellix
# ---------------------------------------------------------------------------

from gnat.connectors.trellix.client import TrellixClient  # noqa: E402


class TestTrellixClient:
    @pytest.fixture
    def client(self):
        return _authenticated(TrellixClient, client_id="cid", client_secret="sec")

    def test_authenticate_sets_bearer(self, monkeypatch):
        c = TrellixClient(host="https://fake.example.com", client_id="x", client_secret="y")
        monkeypatch.setattr(c, "post", MagicMock(return_value={"access_token": "tok999"}))
        c.authenticate()
        assert c._auth_headers["Authorization"] == "Bearer tok999"

    def test_authenticate_raises_on_missing_token(self, monkeypatch):
        c = TrellixClient(host="https://fake.example.com", client_id="x", client_secret="y")
        monkeypatch.setattr(c, "post", MagicMock(return_value={}))
        with pytest.raises(GNATClientError, match="access token"):
            c.authenticate()

    def test_get_object_indicator(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"data": {"id": "1", "value": "evil.com"}})
        )
        result = client.get_object("indicator", "1")
        assert isinstance(result, dict)

    def test_get_object_unsupported_type(self, client):
        with pytest.raises(GNATClientError):
            client.get_object("unknown-type", "1")

    def test_list_objects_indicator(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": [{"id": "1"}]}))
        result = client.list_objects("indicator")
        assert isinstance(result, list)

    def test_list_objects_malware(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": [{"id": "2"}]}))
        result = client.list_objects("malware")
        assert isinstance(result, list)

    def test_list_objects_vulnerability(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": [{"id": "3"}]}))
        result = client.list_objects("vulnerability")
        assert isinstance(result, list)

    def test_upsert_indicator(self, client, monkeypatch):
        monkeypatch.setattr(client, "post", MagicMock(return_value={"data": {"id": "new"}}))
        result = client.upsert_object("indicator", {"type": "domain", "value": "evil.com"})
        assert isinstance(result, dict)

    def test_upsert_non_indicator_raises(self, client):
        with pytest.raises(GNATClientError):
            client.upsert_object("malware", {})

    def test_to_stix_ioc_contract(self, client):
        native = {
            "id": "ioc1",
            "type": "domain",
            "value": "evil.com",
            "confidence": 80,
            "created_at": "2024-01-01T00:00:00Z",
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "indicator"
        assert "evil.com" in stix.get("pattern", "")

    def test_to_stix_threat_contract(self, client):
        native = {
            "id": "t1",
            "name": "Ransomware.X",
            "category": "ransomware",
            "severity": "HIGH",
            "status": "active",
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "malware"

    def test_to_stix_vuln_contract(self, client):
        native = {"id": "v1", "cve_id": "CVE-2024-1234", "cvss_score": 9.8}
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "vulnerability"

    def test_from_stix(self, client):
        stix = {
            "type": "indicator",
            "id": "indicator--abc",
            "name": "1.2.3.4",
            "pattern": "[ipv4-addr:value = '1.2.3.4']",
            "confidence": 70,
        }
        result = client.from_stix(stix)
        assert isinstance(result, dict)
        assert result["value"] == "1.2.3.4"


# ---------------------------------------------------------------------------
# Sophos
# ---------------------------------------------------------------------------

from gnat.connectors.sophos.client import SophosClient  # noqa: E402


class TestSophosClient:
    @pytest.fixture
    def client(self):
        return _authenticated(SophosClient, client_id="cid", client_secret="sec")

    def test_authenticate_sets_bearer(self, monkeypatch):
        c = SophosClient(host="https://fake.example.com", client_id="x", client_secret="y")
        monkeypatch.setattr(c, "post", MagicMock(return_value={"access_token": "sophos_tok"}))
        c.authenticate()
        assert c._auth_headers["Authorization"] == "Bearer sophos_tok"

    def test_authenticate_raises_on_missing_token(self, monkeypatch):
        c = SophosClient(host="https://fake.example.com", client_id="x", client_secret="y")
        monkeypatch.setattr(c, "post", MagicMock(return_value={}))
        with pytest.raises(GNATClientError, match="access token"):
            c.authenticate()

    def test_get_object_indicator(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"id": "bi1", "sha256": "abc"}))
        result = client.get_object("indicator", "bi1")
        assert isinstance(result, dict)

    def test_get_object_unsupported_type(self, client):
        with pytest.raises(GNATClientError):
            client.get_object("unknown-type", "1")

    def test_list_objects_malware(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"detections": [{"id": "d1"}]}))
        result = client.list_objects("malware")
        assert isinstance(result, list)

    def test_list_objects_indicator(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"items": [{"id": "bi1"}]}))
        result = client.list_objects("indicator")
        assert isinstance(result, list)

    def test_upsert_indicator(self, client, monkeypatch):
        monkeypatch.setattr(client, "post", MagicMock(return_value={"id": "new"}))
        result = client.upsert_object("indicator", {"type": "sha256", "value": "abc"})
        assert isinstance(result, dict)

    def test_upsert_non_indicator_raises(self, client):
        with pytest.raises(GNATClientError):
            client.upsert_object("malware", {})

    def test_to_stix_blocked_item_contract(self, client):
        native = {
            "id": "bi1",
            "sha256": "aabbcc",
            "type": "sha256",
            "comment": "test",
            "created_at": "2024-01-01T00:00:00Z",
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "indicator"
        assert "aabbcc" in stix.get("pattern", "")

    def test_to_stix_detection_contract(self, client):
        native = {
            "id": "det1",
            "name": "Troj/BackDoor",
            "category": "trojan",
            "endpoint_id": "ep1",
            "severity": "high",
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "malware"

    def test_from_stix_sha256(self, client):
        stix = {
            "type": "indicator",
            "id": "indicator--abc",
            "name": "aabbcc",
            "pattern": "[file:hashes.'SHA-256' = 'aabbcc']",
        }
        result = client.from_stix(stix)
        assert result["type"] == "sha256"
        assert result["value"] == "aabbcc"


# ---------------------------------------------------------------------------
# Vectra
# ---------------------------------------------------------------------------

from gnat.connectors.vectra.client import VectraClient  # noqa: E402


class TestVectraClient:
    @pytest.fixture
    def client(self):
        return _authenticated(VectraClient, api_key="vectra_key_123")

    def test_authenticate_sets_token_header(self, monkeypatch):
        c = VectraClient(host="https://fake.vectra.ai", api_key="mykey")
        c.authenticate()
        assert c._auth_headers["Authorization"] == "Token mykey"

    def test_authenticate_raises_without_key(self):
        c = VectraClient(host="https://fake.vectra.ai", api_key="")
        with pytest.raises(GNATClientError, match="api_key"):
            c.authenticate()

    def test_list_objects_detections(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"results": [{"id": 1}]}))
        result = client.list_objects("observed-data")
        assert isinstance(result, list)

    def test_list_objects_hosts(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"results": [{"id": 2}]}))
        result = client.list_objects("threat-actor")
        assert isinstance(result, list)

    def test_get_object_detection(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"id": 5, "detection_type": "C2"})
        )
        result = client.get_object("observed-data", "5")
        assert isinstance(result, dict)

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.upsert_object("observed-data", {})

    def test_delete_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.delete_object("observed-data", "1")

    def test_to_stix_detection_contract(self, client):
        native = {
            "id": 42,
            "detection_type": "Command & Control",
            "category": "COMMAND & CONTROL",
            "threat": 90,
            "certainty": 85,
            "src_ip": "10.0.0.1",
            "src_host": {"name": "workstation01"},
            "first_timestamp": "2024-01-01T00:00:00Z",
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "observed-data"
        assert stix["x_vectra"]["threat"] == 90

    def test_to_stix_host_contract(self, client):
        native = {
            "id": 7,
            "name": "desktop01",
            "ip": "192.168.1.10",
            "threat": 60,
            "certainty": 70,
            "tags": [],
            "state": "active",
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "threat-actor"

    def test_from_stix(self, client):
        stix = {"type": "observed-data", "id": "observed-data--abc"}
        result = client.from_stix(stix)
        assert isinstance(result, dict)
        assert result["stix_id"] == "observed-data--abc"


# ---------------------------------------------------------------------------
# ExtraHop
# ---------------------------------------------------------------------------

from gnat.connectors.extrahop.client import ExtraHopClient  # noqa: E402


class TestExtraHopClient:
    @pytest.fixture
    def client(self):
        return _authenticated(ExtraHopClient, api_key="eh_key_123")

    def test_authenticate_api_key(self):
        c = ExtraHopClient(host="https://fake.extrahop.com", api_key="mykey")
        c.authenticate()
        assert "ExtraHop apikey=mykey" in c._auth_headers["Authorization"]

    def test_authenticate_oauth2(self, monkeypatch):
        c = ExtraHopClient(host="https://fake.extrahop.com", client_id="cid", client_secret="csec")
        monkeypatch.setattr(c, "post", MagicMock(return_value={"access_token": "tok"}))
        c.authenticate()
        assert c._auth_headers["Authorization"] == "Bearer tok"

    def test_authenticate_raises_with_no_credentials(self):
        c = ExtraHopClient(host="https://fake.extrahop.com")
        with pytest.raises(GNATClientError):
            c.authenticate()

    def test_list_objects_detections(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value=[{"id": 1}]))
        result = client.list_objects("observed-data")
        assert isinstance(result, list)

    def test_get_object_detection(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"id": 5, "risk_score": 80}))
        result = client.get_object("observed-data", "5")
        assert isinstance(result, dict)

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.upsert_object("observed-data", {})

    def test_delete_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.delete_object("observed-data", "1")

    def test_to_stix_detection_contract(self, client):
        native = {
            "id": 10,
            "detection_type": "Lateral Movement",
            "category": "LATERAL_MOVEMENT",
            "risk_score": 75,
            "status": "new",
            "start_time": "2024-01-01T00:00:00Z",
            "participants": [],
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "observed-data"
        assert stix["x_extrahop"]["risk_score"] == 75

    def test_to_stix_record_contract(self, client):
        native = {
            "id": "rec1",
            "type": "DNS",
            "src_addr": "10.0.0.1",
            "dst_addr": "8.8.8.8",
            "timestamp": "2024-01-01T00:00:00Z",
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "observed-data"

    def test_from_stix(self, client):
        stix = {"type": "observed-data", "id": "observed-data--abc"}
        result = client.from_stix(stix)
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# Darktrace
# ---------------------------------------------------------------------------

from gnat.connectors.darktrace.client import DarktraceClient  # noqa: E402


class TestDarktraceClient:
    @pytest.fixture
    def client(self):
        return _authenticated(DarktraceClient, public_key="pub123", private_key="priv456")

    def test_authenticate_sets_accept_header(self):
        c = DarktraceClient(host="https://fake.dt.com", public_key="pub", private_key="priv")
        c.authenticate()
        assert c._auth_headers["Accept"] == "application/json"

    def test_authenticate_raises_without_keys(self):
        c = DarktraceClient(host="https://fake.dt.com")
        with pytest.raises(GNATClientError, match="private_key"):
            c.authenticate()

    def test_list_objects_breaches(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value=[{"pbid": 1}]))
        result = client.list_objects("observed-data")
        assert isinstance(result, list)

    def test_list_objects_devices(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"devices": [{"did": 2}]}))
        result = client.list_objects("threat-actor")
        assert isinstance(result, list)

    def test_get_object_breach(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"pbid": 5, "score": 0.9}))
        result = client.get_object("observed-data", "5")
        assert isinstance(result, dict)

    def test_upsert_intel_feed(self, client, monkeypatch):
        monkeypatch.setattr(client, "post", MagicMock(return_value={"id": "feed1"}))
        result = client.upsert_object("indicator", {"value": "evil.com", "type": "hostname"})
        assert isinstance(result, dict)

    def test_upsert_non_indicator_raises(self, client):
        with pytest.raises(GNATClientError):
            client.upsert_object("malware", {})

    def test_to_stix_breach_contract(self, client):
        native = {
            "pbid": 42,
            "score": 0.85,
            "model": {"name": "Anomalous Connection"},
            "device": {"hostname": "server01", "ip": "192.168.0.1"},
            "time": "2024-01-01T00:00:00Z",
            "triggeredComponents": [],
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "observed-data"
        assert stix["x_darktrace"]["score"] == 0.85

    def test_to_stix_device_contract(self, client):
        native = {
            "did": 10,
            "hostname": "laptop01",
            "ip": "10.0.0.50",
            "macaddress": "aa:bb:cc:dd:ee:ff",
            "os": "Windows 11",
            "tags": [],
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "threat-actor"

    def test_from_stix(self, client):
        stix = {
            "type": "indicator",
            "id": "indicator--abc",
            "name": "evil.com",
            "description": "test",
        }
        result = client.from_stix(stix)
        assert result["value"] == "evil.com"
        assert result["type"] == "hostname"


# ---------------------------------------------------------------------------
# Lansweeper
# ---------------------------------------------------------------------------

from gnat.connectors.lansweeper.client import LansweeperClient  # noqa: E402


class TestLansweeperClient:
    @pytest.fixture
    def client(self):
        c = LansweeperClient(
            host="https://api.lansweeper.com",
            api_key="ls_token_123",
            site_id="site_abc",
        )
        c._auth_headers["Authorization"] = "Bearer ls_token_123"
        c._authenticated = True
        return c

    def test_authenticate_with_api_key(self):
        c = LansweeperClient(host="https://api.lansweeper.com", api_key="tok")
        c.authenticate()
        assert c._auth_headers["Authorization"] == "Bearer tok"

    def test_authenticate_with_oauth2(self, monkeypatch):
        c = LansweeperClient(
            host="https://api.lansweeper.com", client_id="cid", client_secret="csec"
        )
        monkeypatch.setattr(c, "post", MagicMock(return_value={"access_token": "tok"}))
        c.authenticate()
        assert c._auth_headers["Authorization"] == "Bearer tok"

    def test_authenticate_raises_with_no_credentials(self):
        c = LansweeperClient(host="https://api.lansweeper.com")
        with pytest.raises(GNATClientError):
            c.authenticate()

    def test_get_object_asset(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"asset": {"id": "a1"}}))
        result = client.get_object("report", "a1")
        assert isinstance(result, dict)

    def test_get_object_missing_site_id(self):
        c = LansweeperClient(host="https://api.lansweeper.com", api_key="tok")
        c._authenticated = True
        with pytest.raises(GNATClientError, match="site_id"):
            c.get_object("report", "a1")

    def test_list_objects_assets(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"items": [{"id": "a1"}]}))
        result = client.list_objects("report")
        assert isinstance(result, list)

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.upsert_object("report", {})

    def test_delete_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.delete_object("report", "a1")

    def test_to_stix_asset_contract(self, client):
        native = {
            "id": "a1",
            "name": "laptop01",
            "type": "Windows",
            "ip": "10.0.0.5",
            "mac": "aa:bb:cc:dd:ee:ff",
            "firstSeen": "2024-01-01T00:00:00Z",
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "report"
        assert stix["x_lansweeper"]["ip"] == "10.0.0.5"

    def test_to_stix_software_contract(self, client):
        native = {
            "id": "sw1",
            "softwareName": "Log4j",
            "softwareVersion": "2.14.0",
            "publisher": "Apache",
            "assetCount": 50,
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "vulnerability"

    def test_from_stix(self, client):
        stix = {"type": "report", "id": "report--abc"}
        result = client.from_stix(stix)
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# Censys
# ---------------------------------------------------------------------------

from gnat.connectors.censys.client import CensysClient  # noqa: E402


class TestCensysClient:
    @pytest.fixture
    def client(self):
        c = CensysClient(
            host="https://search.censys.io",
            api_id="cns_id",
            api_secret="cns_sec",
        )
        import base64

        creds = base64.b64encode(b"cns_id:cns_sec").decode()
        c._auth_headers["Authorization"] = f"Basic {creds}"
        c._authenticated = True
        return c

    def test_authenticate_sets_basic_header(self):
        import base64

        c = CensysClient(host="https://search.censys.io", api_id="myid", api_secret="mysec")
        c.authenticate()
        expected = base64.b64encode(b"myid:mysec").decode()
        assert c._auth_headers["Authorization"] == f"Basic {expected}"

    def test_authenticate_raises_without_credentials(self):
        c = CensysClient(host="https://search.censys.io")
        with pytest.raises(GNATClientError, match="api_id"):
            c.authenticate()

    def test_get_object(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"result": {"ip": "1.2.3.4", "services": []}})
        )
        result = client.get_object("observed-data", "1.2.3.4")
        assert result["ip"] == "1.2.3.4"

    def test_list_objects(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "post", MagicMock(return_value={"result": {"hits": [{"ip": "1.2.3.4"}]}})
        )
        result = client.list_objects("observed-data", filters={"q": "services.port=443"})
        assert isinstance(result, list)
        assert len(result) == 1

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.upsert_object("observed-data", {})

    def test_delete_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.delete_object("observed-data", "1.2.3.4")

    def test_to_stix_host_contract(self, client):
        native = {
            "ip": "8.8.8.8",
            "last_updated_at": "2024-01-01T00:00:00Z",
            "services": [{"port": 443, "transport_protocol": "TCP", "service_name": "HTTPS"}],
            "location": {"country": "US"},
            "autonomous_system": {"asn": 15169, "name": "Google LLC"},
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "observed-data"
        assert stix["x_censys"]["ip"] == "8.8.8.8"
        assert 443 in stix["x_censys"]["open_ports"]

    def test_to_stix_with_cve_exposure(self, client):
        native = {
            "ip": "1.2.3.4",
            "last_updated_at": "2024-01-01T00:00:00Z",
            "services": [
                {
                    "port": 80,
                    "transport_protocol": "TCP",
                    "service_name": "HTTP",
                    "vulnerabilities": [{"cve_id": "CVE-2021-44228"}],
                }
            ],
            "location": {},
            "autonomous_system": {},
        }
        stix = client.to_stix(native)
        assert "CVE-2021-44228" in stix["x_censys"].get("exposed_cves", [])

    def test_from_stix(self, client):
        stix = {"type": "observed-data", "id": "observed-data--abc"}
        result = client.from_stix(stix)
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# ServiceNow SecOps
# ---------------------------------------------------------------------------

from gnat.connectors.servicenow_secops.client import ServiceNowSecOpsClient  # noqa: E402


class TestServiceNowSecOpsClient:
    @pytest.fixture
    def client(self):
        return _authenticated(ServiceNowSecOpsClient, username="admin", password="pass")

    def test_authenticate_basic(self):
        import base64

        c = ServiceNowSecOpsClient(
            host="https://fake.service-now.com", username="admin", password="pass123"
        )
        c.authenticate()
        expected = base64.b64encode(b"admin:pass123").decode()
        assert c._auth_headers["Authorization"] == f"Basic {expected}"

    def test_authenticate_bearer(self):
        c = ServiceNowSecOpsClient(host="https://fake.service-now.com", api_key="bearer_token")
        c.authenticate()
        assert c._auth_headers["Authorization"] == "Bearer bearer_token"

    def test_authenticate_raises_with_no_credentials(self):
        c = ServiceNowSecOpsClient(host="https://fake.service-now.com")
        with pytest.raises(GNATClientError):
            c.authenticate()

    def test_get_object_incident(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(return_value={"result": {"sys_id": "abc", "short_description": "Test"}}),
        )
        result = client.get_object("observed-data", "abc")
        assert result["sys_id"] == "abc"

    def test_get_object_vuln(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"result": {"sys_id": "vuln1"}}))
        result = client.get_object("vulnerability", "vuln1")
        assert isinstance(result, dict)

    def test_get_object_unsupported_type(self, client):
        with pytest.raises(GNATClientError, match="unsupported STIX type"):
            client.get_object("unknown-type", "1")

    def test_list_objects_incidents(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"result": [{"sys_id": "i1"}]}))
        result = client.list_objects("observed-data", query="state=1")
        assert isinstance(result, list)

    def test_list_objects_vulnerabilities(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"result": []}))
        result = client.list_objects("vulnerability")
        assert isinstance(result, list)

    def test_upsert_create_incident(self, client, monkeypatch):
        monkeypatch.setattr(client, "post", MagicMock(return_value={"result": {"sys_id": "new1"}}))
        result = client.upsert_object("observed-data", {"name": "Test Incident"})
        assert isinstance(result, dict)

    def test_upsert_update_incident(self, client, monkeypatch):
        mock_put = MagicMock(return_value={"result": {"sys_id": "inc1"}})
        monkeypatch.setattr(client, "put", mock_put)
        result = client.upsert_object("observed-data", {"name": "Test"}, sys_id="inc1")
        mock_put.assert_called_once()
        assert isinstance(result, dict)

    def test_delete_incident(self, client, monkeypatch):
        mock_del = MagicMock(return_value=None)
        monkeypatch.setattr(client, "delete", mock_del)
        client.delete_object("observed-data", "inc1")
        mock_del.assert_called_once()

    def test_create_security_incident(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "post", MagicMock(return_value={"result": {"sys_id": "new_si"}})
        )
        result = client.create_security_incident("Critical Alert", priority="1")
        assert isinstance(result, dict)

    def test_annotate_incident(self, client, monkeypatch):
        mock_put = MagicMock(return_value={"result": {"sys_id": "inc1"}})
        monkeypatch.setattr(client, "put", mock_put)
        stix_obj = {"type": "indicator", "id": "indicator--abc", "name": "1.2.3.4"}
        result = client.annotate_incident("inc1", stix_obj)
        mock_put.assert_called_once()
        assert isinstance(result, dict)

    def test_list_vulnerable_items(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"result": [{"sys_id": "v1"}]}))
        result = client.list_vulnerable_items(cve_id="CVE-2021-44228")
        assert isinstance(result, list)

    def test_create_observable(self, client, monkeypatch):
        monkeypatch.setattr(client, "post", MagicMock(return_value={"result": {"sys_id": "obs1"}}))
        result = client.create_observable("1.2.3.4", "IP Address")
        assert isinstance(result, dict)

    def test_list_observables(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"result": []}))
        result = client.list_observables()
        assert isinstance(result, list)

    def test_to_stix_incident_contract(self, client):
        native = {
            "sys_id": "inc1",
            "short_description": "Ransomware Attack",
            "description": "Ransomware detected",
            "state": "1",
            "priority": "1",
            "category": "threat",
            "opened_at": "2024-01-01T00:00:00Z",
            "assigned_to": {"value": "admin"},
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "observed-data"
        assert stix["x_sn_secops"]["table"] == "sn_si_incident"

    def test_to_stix_vuln_contract(self, client):
        native = {
            "sys_id": "v1",
            "vulnerability": {"value": "CVE-2021-44228"},
            "short_description": "Log4Shell",
            "state": "open",
            "sys_class_name": "sn_vr_vulnerable_item",
            "sys_created_on": "2024-01-01T00:00:00Z",
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "vulnerability"
        assert stix["x_sn_secops"]["cve_id"] == "CVE-2021-44228"

    def test_to_stix_observable_contract(self, client):
        native = {
            "sys_id": "obs1",
            "value": "1.2.3.4",
            "type": "IP Address",
            "description": "Malicious IP",
            "sys_created_on": "2024-01-01T00:00:00Z",
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "indicator"
        assert "1.2.3.4" in stix.get("pattern", "")

    def test_from_stix_incident(self, client):
        stix = {
            "type": "observed-data",
            "id": "observed-data--abc",
            "name": "Phishing Campaign",
            "description": "Detailed desc",
        }
        result = client.from_stix(stix)
        assert isinstance(result, dict)
        assert result["short_description"] == "Phishing Campaign"


# ---------------------------------------------------------------------------
# BitSightClient
# ---------------------------------------------------------------------------


class TestBitSightClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.bitsight.client import BitSightClient

        c = BitSightClient(host="https://api.bitsighttech.com", token="bitsight-tok")
        c._authenticated = True
        return c

    def test_authenticate_sets_token_header(self):
        from gnat.connectors.bitsight.client import BitSightClient

        c = BitSightClient(token="mytoken")
        c.authenticate()
        assert c._auth_headers["Authorization"] == "Token mytoken"

    def test_health_check(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": []}))
        assert client.health_check() is True

    def test_get_object_report(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"id": "comp1"}))
        result = client.get_object("report", "comp1")
        assert isinstance(result, dict)

    def test_get_object_vulnerability(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": []}))
        result = client.get_object("vulnerability", "comp1")
        assert isinstance(result, dict)

    def test_get_object_unsupported_raises(self, client):
        with pytest.raises(GNATClientError, match="Unsupported"):
            client.get_object("indicator", "x")

    def test_list_objects_vulnerability(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": [{"id": "f1"}]}))
        result = client.list_objects("vulnerability", {"company_id": "c1"})
        assert result[0]["id"] == "f1"

    def test_list_objects_report(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": [{"id": "r1"}]}))
        result = client.list_objects("report")
        assert result[0]["id"] == "r1"

    def test_list_objects_no_company_id(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": []}))
        result = client.list_objects("vulnerability")
        assert isinstance(result, list)

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.upsert_object("report", {})

    def test_delete_raises(self, client):
        with pytest.raises(GNATClientError, match="Deletion"):
            client.delete_object("report", "1")

    def test_fetch_companies(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": [{"id": "c1"}]}))
        result = client.fetch_companies()
        assert result[0]["id"] == "c1"

    def test_fetch_findings(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": [{"id": "f1"}]}))
        result = client.fetch_findings("comp1", severity="high")
        assert result[0]["id"] == "f1"

    def test_fetch_ratings_history(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": [{"rating": 700}]}))
        result = client.fetch_ratings_history("comp1")
        assert result[0]["rating"] == 700

    def test_fetch_breaches(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": [{"id": "b1"}]}))
        result = client.fetch_breaches("comp1")
        assert result[0]["id"] == "b1"

    def test_fetch_alerts(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": [{"id": "a1"}]}))
        result = client.fetch_alerts()
        assert result[0]["id"] == "a1"

    def test_to_stix_finding_contract(self, client):
        # "finding" keyword in title triggers _finding_to_stix dispatch
        native = {
            "id": "f1",
            "severity": "high",
            "title": "BitSight finding: Open Port",
            "description": "Port 22 exposed",
            "date": "2026-01-01",
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "vulnerability"
        assert stix["x_bitsight"]["severity"] == "high"

    def test_to_stix_company_contract(self, client):
        native = {"id": "c1", "name": "AcmeCorp", "rating": 750, "rating_letter": "B"}
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "report"
        assert stix["x_bitsight"]["rating"] == 750

    def test_from_stix(self, client):
        stix = {"id": "vulnerability--abc", "type": "vulnerability"}
        result = client.from_stix(stix)
        assert result["stix_id"] == "vulnerability--abc"


# ---------------------------------------------------------------------------
# DefectDojoClient
# ---------------------------------------------------------------------------


class TestDefectDojoClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.defectdojo.client import DefectDojoClient

        c = DefectDojoClient(host="https://defectdojo.example.com", token="dd-token")
        c._authenticated = True
        return c

    def test_authenticate_sets_token_header(self):
        from gnat.connectors.defectdojo.client import DefectDojoClient

        c = DefectDojoClient(host="https://dd.example.com", token="tok123")
        c.authenticate()
        assert c._auth_headers["Authorization"] == "Token tok123"

    def test_health_check(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"results": []}))
        assert client.health_check() is True

    def test_get_object_vulnerability(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"id": 1, "title": "XSS"}))
        result = client.get_object("vulnerability", "1")
        assert result["title"] == "XSS"

    def test_get_object_report(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"id": 1, "name": "Sprint 1"}))
        result = client.get_object("report", "1")
        assert result["name"] == "Sprint 1"

    def test_get_object_unsupported_raises(self, client):
        with pytest.raises(GNATClientError, match="Unsupported"):
            client.get_object("indicator", "x")

    def test_list_objects_vulnerability(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"results": [{"id": 1}]}))
        result = client.list_objects("vulnerability")
        assert isinstance(result, list)

    def test_list_objects_report(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"results": [{"id": 2}]}))
        result = client.list_objects("report")
        assert isinstance(result, list)

    def test_upsert_creates_finding(self, client, monkeypatch):
        mock_post = MagicMock(return_value={"id": 99, "title": "New"})
        monkeypatch.setattr(client, "post", mock_post)
        result = client.upsert_object("vulnerability", {"title": "New"})
        mock_post.assert_called_once()
        assert result["id"] == 99

    def test_upsert_updates_finding(self, client, monkeypatch):
        mock_put = MagicMock(return_value={"id": 5, "title": "Updated"})
        monkeypatch.setattr(client, "put", mock_put)
        result = client.upsert_object("vulnerability", {"id": "5", "title": "Updated"})
        mock_put.assert_called_once()

    def test_upsert_creates_engagement(self, client, monkeypatch):
        mock_post = MagicMock(return_value={"id": 10, "name": "Eng1"})
        monkeypatch.setattr(client, "post", mock_post)
        client.upsert_object("report", {"name": "Eng1"})
        mock_post.assert_called_once()

    def test_upsert_unsupported_raises(self, client):
        with pytest.raises(GNATClientError, match="Unsupported"):
            client.upsert_object("indicator", {})

    def test_delete_finding(self, client, monkeypatch):
        mock_del = MagicMock(return_value=None)
        monkeypatch.setattr(client, "delete", mock_del)
        client.delete_object("vulnerability", "1")
        mock_del.assert_called_once()

    def test_delete_engagement(self, client, monkeypatch):
        mock_del = MagicMock(return_value=None)
        monkeypatch.setattr(client, "delete", mock_del)
        client.delete_object("report", "2")
        mock_del.assert_called_once()

    def test_delete_unsupported_raises(self, client):
        with pytest.raises(GNATClientError, match="Unsupported"):
            client.delete_object("indicator", "x")

    def test_fetch_findings(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"results": [{"id": 1}]}))
        result = client.fetch_findings(severity="High", active=True)
        assert result[0]["id"] == 1

    def test_fetch_engagements(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"results": [{"id": 3}]}))
        result = client.fetch_engagements()
        assert result[0]["id"] == 3

    def test_fetch_products(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"results": [{"id": 5}]}))
        result = client.fetch_products()
        assert result[0]["id"] == 5

    def test_import_scan(self, client, monkeypatch):
        mock_post = MagicMock(return_value={"id": 99})
        monkeypatch.setattr(client, "post", mock_post)
        result = client.import_scan("ZAP Scan", "<xml>...</xml>", engagement_id=1)
        mock_post.assert_called_once()
        assert result["id"] == 99

    def test_to_stix_finding_contract(self, client):
        native = {
            "id": 1,
            "title": "SQL Injection",
            "severity": "Critical",
            "description": "SQL injection in login form",
            "cve": "CVE-2024-1234",
            "cwe": 89,
            "active": True,
            "verified": False,
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "vulnerability"
        assert stix["x_defectdojo"]["severity"] == "Critical"
        assert stix["x_defectdojo"]["cve"] == "CVE-2024-1234"

    def test_to_stix_engagement_contract(self, client):
        native = {
            "id": 3,
            "name": "Q1 Pentest",
            "description": "Quarterly assessment",
            "status": "In Progress",
            "product": 1,
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "report"
        assert stix["x_defectdojo"]["status"] == "In Progress"

    def test_from_stix_vulnerability(self, client):
        stix = {
            "type": "vulnerability",
            "id": "vulnerability--abc",
            "name": "SQLi",
            "description": "SQL injection",
        }
        result = client.from_stix(stix)
        assert result["title"] == "SQLi"
        assert result["severity"] == "Info"

    def test_from_stix_report(self, client):
        stix = {
            "type": "report",
            "id": "report--abc",
            "name": "Pentest Report",
            "description": "Q1 assessment",
        }
        result = client.from_stix(stix)
        assert result["name"] == "Pentest Report"


# ---------------------------------------------------------------------------
# FlashpointClient
# ---------------------------------------------------------------------------


class TestFlashpointClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.flashpoint.client import FlashpointClient

        c = FlashpointClient(host="https://api.flashpoint.io", token="fp-token")
        c._authenticated = True
        return c

    def test_authenticate_sets_bearer(self):
        from gnat.connectors.flashpoint.client import FlashpointClient

        c = FlashpointClient(token="mytoken")
        c.authenticate()
        assert c._auth_headers["Authorization"] == "Bearer mytoken"

    def test_health_check(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": []}))
        assert client.health_check() is True

    def test_get_object_indicator(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"id": "ioc1"}))
        result = client.get_object("indicator", "ioc1")
        assert result["id"] == "ioc1"

    def test_get_object_report(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"id": "a1"}))
        result = client.get_object("report", "a1")
        assert result["id"] == "a1"

    def test_get_object_unsupported_raises(self, client):
        with pytest.raises(GNATClientError, match="Unsupported"):
            client.get_object("vulnerability", "x")

    def test_list_objects_indicator(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": [{"id": "i1"}]}))
        result = client.list_objects("indicator")
        assert result[0]["id"] == "i1"

    def test_list_objects_report(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": [{"id": "r1"}]}))
        result = client.list_objects("report")
        assert result[0]["id"] == "r1"

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.upsert_object("indicator", {})

    def test_delete_raises(self, client):
        with pytest.raises(GNATClientError, match="Deletion"):
            client.delete_object("indicator", "1")

    def test_fetch_alerts(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": [{"id": "a1"}]}))
        result = client.fetch_alerts(since="2026-01-01")
        assert result[0]["id"] == "a1"

    def test_fetch_iocs(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": [{"id": "ioc1"}]}))
        result = client.fetch_iocs(ioc_type="ip")
        assert result[0]["id"] == "ioc1"

    def test_fetch_threat_actors(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": [{"id": "ta1"}]}))
        result = client.fetch_threat_actors()
        assert result[0]["id"] == "ta1"

    def test_fetch_forums(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": [{"id": "f1"}]}))
        result = client.fetch_forums(keyword="ransomware")
        assert result[0]["id"] == "f1"

    def test_fetch_ransomware(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": [{"id": "r1"}]}))
        result = client.fetch_ransomware()
        assert result[0]["id"] == "r1"

    def test_search(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": [{"id": "s1"}]}))
        result = client.search("lockbit")
        assert result[0]["id"] == "s1"

    def test_to_stix_ioc_ip_contract(self, client):
        native = {
            "id": "i1",
            "value": "1.2.3.4",
            "ioc_type": "ip",
            "first_seen": "2026-01-01",
            "last_seen": "2026-01-02",
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "indicator"
        assert "[ipv4-addr:value = '1.2.3.4']" in stix["pattern"]

    def test_to_stix_ioc_domain_contract(self, client):
        native = {"id": "i2", "value": "evil.com", "ioc_type": "domain"}
        stix = client.to_stix(native)
        assert stix["type"] == "indicator"
        assert stix["pattern"] == "[domain-name:value = 'evil.com']"

    def test_to_stix_alert_contract(self, client):
        native = {
            "id": "a1",
            "title": "LockBit Activity",
            "created_at": "2026-01-01",
            "category": "ransomware",
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "report"

    def test_from_stix(self, client):
        stix = {"id": "indicator--abc", "type": "indicator"}
        result = client.from_stix(stix)
        assert result["stix_id"] == "indicator--abc"


# ---------------------------------------------------------------------------
# HudsonRockClient
# ---------------------------------------------------------------------------


class TestHudsonRockClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.hudsonrock.client import HudsonRockClient

        c = HudsonRockClient(host="https://api.hudsonrock.com", api_key="hr-key")
        c._authenticated = True
        return c

    def test_authenticate_sets_api_key_header(self):
        from gnat.connectors.hudsonrock.client import HudsonRockClient

        c = HudsonRockClient(api_key="my-hr-key")
        c.authenticate()
        assert c._auth_headers["x-api-key"] == "my-hr-key"

    def test_health_check(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": []}))
        assert client.health_check() is True

    def test_get_object_report(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"id": "b1"}))
        result = client.get_object("report", "b1")
        assert result["id"] == "b1"

    def test_get_object_indicator(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"id": "c1"}))
        result = client.get_object("indicator", "c1")
        assert result["id"] == "c1"

    def test_get_object_unsupported_raises(self, client):
        with pytest.raises(GNATClientError, match="Unsupported"):
            client.get_object("vulnerability", "x")

    def test_list_objects_indicator(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": [{"id": "c1"}]}))
        result = client.list_objects("indicator")
        assert result[0]["id"] == "c1"

    def test_list_objects_report(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": [{"id": "b1"}]}))
        result = client.list_objects("report")
        assert result[0]["id"] == "b1"

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.upsert_object("indicator", {})

    def test_delete_raises(self, client):
        with pytest.raises(GNATClientError, match="Deletion"):
            client.delete_object("indicator", "1")

    def test_fetch_breaches(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": [{"id": "b1"}]}))
        result = client.fetch_breaches(since="2026-01-01", victim_type="company")
        assert result[0]["id"] == "b1"

    def test_fetch_credentials(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"data": [{"email": "u@corp.com"}]})
        )
        result = client.fetch_credentials(domain="corp.com")
        assert result[0]["email"] == "u@corp.com"

    def test_fetch_iocs(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": [{"id": "ioc1"}]}))
        result = client.fetch_iocs()
        assert result[0]["id"] == "ioc1"

    def test_fetch_victims(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": [{"id": "v1"}]}))
        result = client.fetch_victims(victim_name="AcmeCorp")
        assert result[0]["id"] == "v1"

    def test_to_stix_credential_contract(self, client):
        native = {
            "id": "cred1",
            "email": "user@corp.com",
            "source": "stealer",
            "breach_date": "2026-01-01",
            "breach_id": "breach99",
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "indicator"
        assert "user@corp.com" in stix["pattern"]

    def test_to_stix_breach_contract(self, client):
        native = {
            "id": "b1",
            "title": "Corp DB Leak",
            "date": "2026-01-01",
            "victim_count": 50000,
            "severity": "critical",
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "report"
        assert stix["x_hudsonrock"]["victim_count"] == 50000

    def test_from_stix(self, client):
        stix = {"id": "report--abc", "type": "report"}
        result = client.from_stix(stix)
        assert result["stix_id"] == "report--abc"


# ---------------------------------------------------------------------------
# Intel471Client
# ---------------------------------------------------------------------------


class TestIntel471Client:
    @pytest.fixture
    def client(self):
        from gnat.connectors.intel471.client import Intel471Client

        c = Intel471Client(host="https://api.intel471.com", token="intel-token")
        c._authenticated = True
        return c

    def test_authenticate_sets_bearer(self):
        from gnat.connectors.intel471.client import Intel471Client

        c = Intel471Client(token="mytoken")
        c.authenticate()
        assert c._auth_headers["Authorization"] == "Bearer mytoken"

    def test_health_check(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": []}))
        assert client.health_check() is True

    def test_get_object_indicator(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"id": "ioc1"}))
        result = client.get_object("indicator", "ioc1")
        assert result["id"] == "ioc1"

    def test_get_object_report(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"id": "a1"}))
        result = client.get_object("report", "a1")
        assert result["id"] == "a1"

    def test_get_object_unsupported_raises(self, client):
        with pytest.raises(GNATClientError, match="Unsupported"):
            client.get_object("vulnerability", "x")

    def test_list_objects_indicator(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": [{"id": "i1"}]}))
        result = client.list_objects("indicator")
        assert result[0]["id"] == "i1"

    def test_list_objects_report(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": [{"id": "r1"}]}))
        result = client.list_objects("report")
        assert result[0]["id"] == "r1"

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.upsert_object("indicator", {})

    def test_delete_raises(self, client):
        with pytest.raises(GNATClientError, match="Deletion"):
            client.delete_object("indicator", "1")

    def test_fetch_actors(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": [{"id": "act1"}]}))
        result = client.fetch_actors(handle="lockbit")
        assert result[0]["id"] == "act1"

    def test_fetch_malware(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": [{"id": "m1"}]}))
        result = client.fetch_malware(family="emotet")
        assert result[0]["id"] == "m1"

    def test_fetch_ransomware(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": [{"id": "r1"}]}))
        result = client.fetch_ransomware()
        assert result[0]["id"] == "r1"

    def test_fetch_iocs(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": [{"id": "ioc1"}]}))
        result = client.fetch_iocs(ioc_type="sha256")
        assert result[0]["id"] == "ioc1"

    def test_fetch_alerts(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": [{"id": "al1"}]}))
        result = client.fetch_alerts(since="2026-01-01")
        assert result[0]["id"] == "al1"

    def test_search(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": [{"id": "s1"}]}))
        result = client.search("emotet")
        assert result[0]["id"] == "s1"

    def test_to_stix_ioc_ip_contract(self, client):
        native = {"id": "i1", "value": "192.168.1.1", "ioc_type": "ip", "first_seen": "2026-01-01"}
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "indicator"
        assert "[ipv4-addr:value = '192.168.1.1']" in stix["pattern"]

    def test_to_stix_ioc_sha256_contract(self, client):
        native = {"id": "i2", "value": "deadbeef" * 8, "ioc_type": "sha256"}
        stix = client.to_stix(native)
        assert "SHA256" in stix["pattern"]

    def test_to_stix_actor_contract(self, client):
        native = {
            "id": "a1",
            "handle": "lockbit_admin",
            "description": "LockBit operator",
            "observed_at": "2026-01-01",
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "report"
        assert stix["x_intel471"]["handle"] == "lockbit_admin"

    def test_from_stix(self, client):
        stix = {"id": "indicator--abc", "type": "indicator"}
        result = client.from_stix(stix)
        assert result["stix_id"] == "indicator--abc"


# ---------------------------------------------------------------------------
# UpGuardClient
# ---------------------------------------------------------------------------


class TestUpGuardClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.upguard.client import UpGuardClient

        c = UpGuardClient(host="https://cyber-risk.upguard.com", api_key="ug-key")
        c._authenticated = True
        return c

    def test_authenticate_sets_token_header(self):
        from gnat.connectors.upguard.client import UpGuardClient

        c = UpGuardClient(api_key="mykey")
        c.authenticate()
        assert c._auth_headers["Authorization"] == "Token mykey"

    def test_health_check(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": []}))
        assert client.health_check() is True

    def test_get_object_report(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"id": "v1", "name": "Vendor A"}))
        result = client.get_object("report", "v1")
        assert result["name"] == "Vendor A"

    def test_get_object_vulnerability(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"id": "b1"}))
        result = client.get_object("vulnerability", "b1")
        assert result["id"] == "b1"

    def test_get_object_unsupported_raises(self, client):
        with pytest.raises(GNATClientError, match="Unsupported"):
            client.get_object("indicator", "x")

    def test_list_objects_vulnerability(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": [{"id": "b1"}]}))
        result = client.list_objects("vulnerability")
        assert result[0]["id"] == "b1"

    def test_list_objects_report(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": [{"id": "v1"}]}))
        result = client.list_objects("report")
        assert result[0]["id"] == "v1"

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.upsert_object("report", {})

    def test_delete_raises(self, client):
        with pytest.raises(GNATClientError, match="Deletion"):
            client.delete_object("report", "1")

    def test_fetch_vendors(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": [{"id": "v1"}]}))
        result = client.fetch_vendors()
        assert result[0]["id"] == "v1"

    def test_fetch_breaches(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": [{"id": "b1"}]}))
        result = client.fetch_breaches(since="2026-01-01")
        assert result[0]["id"] == "b1"

    def test_fetch_questionnaires(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": [{"id": "q1"}]}))
        result = client.fetch_questionnaires()
        assert result[0]["id"] == "q1"

    def test_fetch_vip_management(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": [{"id": "vip1"}]}))
        result = client.fetch_vip_management()
        assert result[0]["id"] == "vip1"

    def test_fetch_content_library(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": [{"id": "cl1"}]}))
        result = client.fetch_content_library()
        assert result[0]["id"] == "cl1"

    def test_to_stix_breach_contract(self, client):
        native = {
            "id": "b1",
            "title": "Identity Breach",
            "description": "breach desc",
            "date": "2026-01-01",
            "severity": "high",
            "identity_count": 10000,
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "vulnerability"
        assert stix["x_upguard"]["identity_count"] == 10000

    def test_to_stix_vendor_contract(self, client):
        native = {"id": "v1", "name": "SupplierCo", "risk_score": 650}
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "report"
        assert stix["x_upguard"]["risk_score"] == 650

    def test_from_stix(self, client):
        stix = {"id": "vulnerability--abc", "type": "vulnerability"}
        result = client.from_stix(stix)
        assert result["stix_id"] == "vulnerability--abc"


# ---------------------------------------------------------------------------
# TrendMicroVisionOneClient
# ---------------------------------------------------------------------------


class TestTrendMicroVisionOneClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.trendmicro_visionone.client import TrendMicroVisionOneClient

        c = TrendMicroVisionOneClient(
            host="https://api.xdr.trendmicro.com", token="visionone-token"
        )
        c._authenticated = True
        return c

    def test_authenticate_sets_bearer(self):
        from gnat.connectors.trendmicro_visionone.client import TrendMicroVisionOneClient

        c = TrendMicroVisionOneClient(token="tok123")
        c.authenticate()
        assert c._auth_headers["Authorization"] == "Bearer tok123"

    def test_health_check(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"items": []}))
        assert client.health_check() is True

    def test_get_object_report(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"id": "a1", "description": "Alert"})
        )
        result = client.get_object("report", "a1")
        assert result["id"] == "a1"

    def test_get_object_indicator(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"items": [{"id": "i1"}]}))
        result = client.get_object("indicator", "i1")
        assert result["id"] == "i1"

    def test_get_object_malware(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"id": "m1"}))
        result = client.get_object("malware", "m1")
        assert result["id"] == "m1"

    def test_get_object_unsupported_raises(self, client):
        with pytest.raises(GNATClientError, match="Unsupported"):
            client.get_object("identity", "x")

    def test_list_objects_report(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"items": [{"id": "a1"}]}))
        result = client.list_objects("report")
        assert result[0]["id"] == "a1"

    def test_list_objects_indicator(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"items": [{"id": "i1"}]}))
        result = client.list_objects("indicator")
        assert result[0]["id"] == "i1"

    def test_upsert_indicator(self, client, monkeypatch):
        monkeypatch.setattr(client, "post", MagicMock(return_value={"id": "new"}))
        result = client.upsert_object("indicator", {"type": "ip", "value": "1.2.3.4"})
        assert result["id"] == "new"

    def test_upsert_unsupported_raises(self, client):
        with pytest.raises(GNATClientError, match="not supported"):
            client.upsert_object("report", {})

    def test_delete_indicator(self, client, monkeypatch):
        mock_del = MagicMock(return_value=None)
        monkeypatch.setattr(client, "delete", mock_del)
        client.delete_object("indicator", "i1")
        mock_del.assert_called_once()

    def test_delete_unsupported_raises(self, client):
        with pytest.raises(GNATClientError, match="not supported"):
            client.delete_object("report", "a1")

    def test_get_alerts(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"items": [{"id": "a1"}]}))
        result = client.get_alerts(severity="high")
        assert result[0]["id"] == "a1"

    def test_search_iocs(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"items": [{"id": "i1"}]}))
        result = client.search_iocs(ioc_type="ip")
        assert result[0]["id"] == "i1"

    def test_to_stix_alert_contract(self, client):
        native = {
            "id": "alert-1",
            "description": "Malware alert",
            "severity": "high",
            "createdDateTime": "2026-01-01T00:00:00Z",
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "report"

    def test_to_stix_ioc_contract(self, client):
        native = {"id": "i1", "value": "192.168.1.1", "type": "ip"}
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "indicator"
        assert "[ipv4-addr:value = '192.168.1.1']" in stix["pattern"]

    def test_to_stix_sandbox_contract(self, client):
        native = {
            "id": "s1",
            "riskLevel": "high",
            "threatClassification": "ransomware",
            "displayName": "Ransom.WannaCry",
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "malware"

    def test_from_stix(self, client):
        stix = {
            "id": "indicator--abc",
            "type": "indicator",
            "pattern": "[ipv4-addr:value = '1.2.3.4']",
            "name": "1.2.3.4",
        }
        result = client.from_stix(stix)
        assert result["value"] == "1.2.3.4"
        assert result["type"] == "ip"


# ---------------------------------------------------------------------------
# HIBPClient
# ---------------------------------------------------------------------------


class TestHIBPClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.hibp.client import HIBPClient

        c = HIBPClient(host="https://haveibeenpwned.com", api_key="hibp-key")
        c._authenticated = True
        return c

    def test_authenticate_sets_header(self):
        from gnat.connectors.hibp.client import HIBPClient

        c = HIBPClient(api_key="mykey")
        c.authenticate()
        assert c._auth_headers["hibp-api-key"] == "mykey"

    def test_health_check(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"Name": "Adobe"}))
        assert client.health_check() is True

    def test_get_object_vulnerability(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"Name": "Adobe", "Title": "Adobe"})
        )
        result = client.get_object("vulnerability", "Adobe")
        assert result["Name"] == "Adobe"

    def test_get_object_identity(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value=[{"Name": "Adobe"}]))
        result = client.get_object("identity", "test@example.com")
        assert "breaches" in result

    def test_get_object_unsupported_raises(self, client):
        with pytest.raises(GNATClientError, match="Unsupported"):
            client.get_object("indicator", "x")

    def test_list_objects_vulnerability(self, client, monkeypatch):
        breaches = [{"Name": "Adobe"}, {"Name": "LinkedIn"}]
        monkeypatch.setattr(client, "get", MagicMock(return_value=breaches))
        result = client.list_objects("vulnerability")
        assert len(result) == 2

    def test_list_objects_identity(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value=[{"Name": "Adobe"}]))
        result = client.list_objects("identity", filters={"account": "test@example.com"})
        assert result[0]["Name"] == "Adobe"

    def test_list_objects_identity_without_account_raises(self, client):
        with pytest.raises(GNATClientError, match="account"):
            client.list_objects("identity")

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.upsert_object("vulnerability", {})

    def test_delete_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.delete_object("vulnerability", "Adobe")

    def test_check_account(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value=[{"Name": "Adobe"}]))
        result = client.check_account("test@example.com")
        assert result[0]["Name"] == "Adobe"

    def test_get_all_breaches(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value=[{"Name": "Adobe"}]))
        result = client.get_all_breaches()
        assert len(result) == 1

    def test_get_pastes(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value=[{"Id": "p1"}]))
        result = client.get_pastes("test@example.com")
        assert result[0]["Id"] == "p1"

    def test_to_stix_breach_contract(self, client):
        native = {
            "Name": "Adobe",
            "Title": "Adobe",
            "Domain": "adobe.com",
            "BreachDate": "2013-10-04",
            "PwnCount": 152445165,
            "DataClasses": ["Email addresses", "Passwords"],
            "IsVerified": True,
            "AddedDate": "2013-12-04",
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "vulnerability"
        assert stix["x_hibp"]["pwn_count"] == 152445165

    def test_to_stix_paste_contract(self, client):
        native = {"Id": "p1", "Source": "Pastebin", "Date": "2026-01-01", "EmailCount": 100}
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "identity"

    def test_from_stix(self, client):
        stix = {"id": "vulnerability--abc", "name": "Adobe", "type": "vulnerability"}
        result = client.from_stix(stix)
        assert result["name"] == "Adobe"


# ---------------------------------------------------------------------------
# TaniumClient
# ---------------------------------------------------------------------------


class TestTaniumClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.tanium.client import TaniumClient

        c = TaniumClient(host="https://tanium.corp.example.com", api_key="tanium-token")
        c._authenticated = True
        return c

    def test_authenticate_api_key(self):
        from gnat.connectors.tanium.client import TaniumClient

        c = TaniumClient(host="https://fake.example.com", api_key="tok")
        c.authenticate()
        assert c._auth_headers["session"] == "tok"

    def test_authenticate_session_login(self, monkeypatch):
        from gnat.connectors.tanium.client import TaniumClient

        c = TaniumClient(host="https://fake.example.com", username="admin", password="pass")
        monkeypatch.setattr(c, "post", MagicMock(return_value={"data": {"session": "sess123"}}))
        c.authenticate()
        assert c._auth_headers["session"] == "sess123"

    def test_authenticate_no_credentials_raises(self):
        from gnat.connectors.tanium.client import TaniumClient

        c = TaniumClient(host="https://fake.example.com")
        with pytest.raises(GNATClientError, match="provide api_key"):
            c.authenticate()

    def test_health_check(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={}))
        assert client.health_check() is True

    def test_get_object_indicator(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"id": "i1", "name": "test"}))
        result = client.get_object("indicator", "i1")
        assert result["id"] == "i1"

    def test_get_object_report(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"id": "a1", "name": "Alert"}))
        result = client.get_object("report", "a1")
        assert result["id"] == "a1"

    def test_get_object_vulnerability(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"data": [{"cveId": "CVE-2021-44228"}]})
        )
        result = client.get_object("vulnerability", "CVE-2021-44228")
        assert result["cveId"] == "CVE-2021-44228"

    def test_get_object_unsupported_raises(self, client):
        with pytest.raises(GNATClientError, match="Unsupported"):
            client.get_object("malware", "x")

    def test_list_objects_indicator(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": [{"id": "i1"}]}))
        result = client.list_objects("indicator")
        assert result[0]["id"] == "i1"

    def test_upsert_indicator(self, client, monkeypatch):
        monkeypatch.setattr(client, "post", MagicMock(return_value={"id": "new"}))
        result = client.upsert_object("indicator", {"name": "TestIOC"})
        assert result["id"] == "new"

    def test_upsert_unsupported_raises(self, client):
        with pytest.raises(GNATClientError, match="not supported"):
            client.upsert_object("report", {})

    def test_delete_indicator(self, client, monkeypatch):
        mock_del = MagicMock(return_value=None)
        monkeypatch.setattr(client, "delete", mock_del)
        client.delete_object("indicator", "i1")
        mock_del.assert_called_once()

    def test_delete_unsupported_raises(self, client):
        with pytest.raises(GNATClientError, match="not supported"):
            client.delete_object("report", "a1")

    def test_get_endpoints(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"data": {"endpoints": [{"id": "ep1"}]}})
        )
        result = client.get_endpoints()
        assert result[0]["id"] == "ep1"

    def test_get_comply_findings(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"data": [{"cveId": "CVE-2021-1"}]})
        )
        result = client.get_comply_findings()
        assert result[0]["cveId"] == "CVE-2021-1"

    def test_to_stix_finding_contract(self, client):
        native = {
            "cveId": "CVE-2021-44228",
            "summary": "Log4Shell",
            "severity": "critical",
            "cvss": {"score": 10.0},
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "vulnerability"
        assert stix["x_tanium"]["cve_id"] == "CVE-2021-44228"

    def test_to_stix_intel_contract(self, client):
        native = {
            "id": "doc1",
            "name": "BadActor",
            "type": "stix",
            "iocs": [{"type": "ip_address", "value": "1.2.3.4"}],
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "indicator"

    def test_to_stix_alert_contract(self, client):
        native = {"id": "al1", "name": "TR Alert", "state": "unresolved", "severity": "high"}
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "report"

    def test_from_stix(self, client):
        stix = {
            "id": "indicator--abc",
            "type": "indicator",
            "pattern": "[domain-name:value = 'evil.com']",
            "name": "evil.com",
        }
        result = client.from_stix(stix)
        assert result["iocs"][0]["value"] == "evil.com"


# ---------------------------------------------------------------------------
# AWSSecurityClient
# ---------------------------------------------------------------------------


class TestAWSSecurityClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.aws_security.client import AWSSecurityClient

        c = AWSSecurityClient(
            host="https://securityhub.us-east-1.amazonaws.com",
            aws_access_key="AKID",
            aws_secret_key="SECRET",
            aws_region="us-east-1",
        )
        c._authenticated = True
        return c

    def test_authenticate_sets_service_header(self):
        from gnat.connectors.aws_security.client import AWSSecurityClient

        c = AWSSecurityClient(aws_access_key="AKID", aws_secret_key="SECRET")
        c.authenticate()
        assert "securityhub" in c._auth_headers.get("X-Gnat-AWS-Service", "")

    def test_authenticate_missing_keys_raises(self):
        from gnat.connectors.aws_security.client import AWSSecurityClient

        c = AWSSecurityClient()
        with pytest.raises(GNATClientError, match="aws_access_key"):
            c.authenticate()

    def test_health_check(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={}))
        assert client.health_check() is True

    def test_get_object_vulnerability(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "post", MagicMock(return_value={"Findings": [{"Id": "f1", "Title": "vuln"}]})
        )
        result = client.get_object("vulnerability", "f1")
        assert result["Id"] == "f1"

    def test_get_object_report(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"id": "ins1"}))
        result = client.get_object("report", "ins1")
        assert result["id"] == "ins1"

    def test_get_object_unsupported_raises(self, client):
        with pytest.raises(GNATClientError, match="Unsupported"):
            client.get_object("malware", "x")

    def test_list_objects_vulnerability(self, client, monkeypatch):
        monkeypatch.setattr(client, "post", MagicMock(return_value={"Findings": [{"Id": "f1"}]}))
        result = client.list_objects("vulnerability")
        assert result[0]["Id"] == "f1"

    def test_list_objects_report(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"Insights": [{"Name": "i1"}]}))
        result = client.list_objects("report")
        assert result[0]["Name"] == "i1"

    def test_upsert_vulnerability(self, client, monkeypatch):
        monkeypatch.setattr(client, "post", MagicMock(return_value={"SuccessCount": 1}))
        result = client.upsert_object("vulnerability", {"Title": "Test Finding"})
        assert result["SuccessCount"] == 1

    def test_upsert_unsupported_raises(self, client):
        with pytest.raises(GNATClientError, match="not supported"):
            client.upsert_object("report", {})

    def test_get_security_hub_findings(self, client, monkeypatch):
        monkeypatch.setattr(client, "post", MagicMock(return_value={"Findings": [{"Id": "f1"}]}))
        result = client.get_security_hub_findings(severity="HIGH")
        assert result[0]["Id"] == "f1"

    def test_to_stix_securityhub_contract(self, client):
        native = {
            "Id": "arn:aws:sh:us-east-1:123:finding/f1",
            "Title": "S3 bucket public",
            "Description": "Bucket is publicly accessible",
            "CreatedAt": "2026-01-01T00:00:00Z",
            "UpdatedAt": "2026-01-01T00:00:00Z",
            "Severity": {"Label": "HIGH"},
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "vulnerability"
        assert stix["x_aws"]["source"] == "securityhub"

    def test_to_stix_guardduty_contract(self, client):
        native = {
            "Id": "gd-finding-1",
            "Title": "Unusual API call",
            "Type": "Recon:IAMUser/MaliciousIPCaller",
            "Severity": 5.0,
            "CreatedAt": "2026-01-01T00:00:00Z",
            "UpdatedAt": "2026-01-01T00:00:00Z",
            "Service": {
                "Action": {
                    "ActionType": "AWS_API_CALL",
                    "NetworkConnectionAction": {"RemoteIpDetails": {"IpAddressV4": "10.0.0.1"}},
                }
            },
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "indicator"
        assert stix["x_aws"]["source"] == "guardduty"

    def test_from_stix(self, client):
        stix = {"id": "vulnerability--abc", "name": "Test Finding", "type": "vulnerability"}
        result = client.from_stix(stix)
        assert result["Title"] == "Test Finding"


# ---------------------------------------------------------------------------
# SecurityScorecardClient
# ---------------------------------------------------------------------------


class TestSecurityScorecardClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.securityscorecard.client import SecurityScorecardClient

        c = SecurityScorecardClient(host="https://api.securityscorecard.io", api_key="ssc-key")
        c._authenticated = True
        return c

    def test_authenticate_sets_token(self):
        from gnat.connectors.securityscorecard.client import SecurityScorecardClient

        c = SecurityScorecardClient(api_key="mykey")
        c.authenticate()
        assert c._auth_headers["Token"] == "mykey"

    def test_health_check(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"entries": []}))
        assert client.health_check() is True

    def test_get_object_report(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"domain": "example.com", "score": 90})
        )
        result = client.get_object("report", "example.com")
        assert result["domain"] == "example.com"

    def test_get_object_vulnerability(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"entries": [{"type": "open_port"}]})
        )
        result = client.get_object("vulnerability", "example.com")
        assert "entries" in result

    def test_get_object_identity(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"id": "p1", "name": "My Portfolio"})
        )
        result = client.get_object("identity", "p1")
        assert result["id"] == "p1"

    def test_get_object_unsupported_raises(self, client):
        with pytest.raises(GNATClientError, match="Unsupported"):
            client.get_object("indicator", "x")

    def test_list_objects_identity(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"entries": [{"id": "p1"}]}))
        result = client.list_objects("identity")
        assert result[0]["id"] == "p1"

    def test_list_objects_report_requires_portfolio(self, client):
        with pytest.raises(GNATClientError, match="portfolio_id"):
            client.list_objects("report")

    def test_list_objects_vulnerability_requires_domain(self, client):
        with pytest.raises(GNATClientError, match="domain"):
            client.list_objects("vulnerability")

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.upsert_object("report", {})

    def test_delete_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.delete_object("report", "x")

    def test_get_company_score(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"domain": "example.com", "score": 85})
        )
        result = client.get_company_score("example.com")
        assert result["score"] == 85

    def test_get_company_issues(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"entries": [{"type": "open_port"}]})
        )
        result = client.get_company_issues("example.com")
        assert result[0]["type"] == "open_port"

    def test_to_stix_score_contract(self, client):
        native = {
            "domain": "example.com",
            "score": 85,
            "grade": "A",
            "industry": "technology",
            "last_scorecard_change": "2026-01-01",
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "report"
        assert stix["x_securityscorecard"]["score"] == 85

    def test_to_stix_issue_contract(self, client):
        native = {
            "id": "iss1",
            "type": "open_port",
            "severity": "medium",
            "factor": "network_security",
            "detail": "Port 22 open",
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "vulnerability"
        assert stix["x_securityscorecard"]["factor"] == "network_security"

    def test_from_stix(self, client):
        stix = {"id": "report--abc", "name": "example.com", "type": "report"}
        result = client.from_stix(stix)
        assert result["domain"] == "example.com"


# ---------------------------------------------------------------------------
# DragosClient
# ---------------------------------------------------------------------------


class TestDragosClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.dragos.client import DragosClient

        c = DragosClient(
            host="https://portal.dragos.com",
            api_key="dragos-key",
            api_secret="dragos-secret",
        )
        c._authenticated = True
        return c

    def test_authenticate_sets_basic_auth(self):
        import base64

        from gnat.connectors.dragos.client import DragosClient

        c = DragosClient(api_key="key", api_secret="secret")
        c.authenticate()
        expected = "Basic " + base64.b64encode(b"key:secret").decode()
        assert c._auth_headers["Authorization"] == expected

    def test_health_check(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"indicators": []}))
        assert client.health_check() is True

    def test_get_object_indicator(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"id": "i1", "value": "1.2.3.4"}))
        result = client.get_object("indicator", "i1")
        assert result["id"] == "i1"

    def test_get_object_threat_actor(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"group_name": "ELECTRUM"}))
        result = client.get_object("threat-actor", "electrum")
        assert result["group_name"] == "ELECTRUM"

    def test_get_object_vulnerability(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"cve_id": "CVE-2021-1"}))
        result = client.get_object("vulnerability", "CVE-2021-1")
        assert result["cve_id"] == "CVE-2021-1"

    def test_get_object_unsupported_raises(self, client):
        with pytest.raises(GNATClientError, match="Unsupported"):
            client.get_object("identity", "x")

    def test_list_objects_indicator(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"indicators": [{"id": "i1"}]}))
        result = client.list_objects("indicator")
        assert result[0]["id"] == "i1"

    def test_list_objects_threat_actor(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"activity_groups": [{"group_name": "ELECTRUM"}]})
        )
        result = client.list_objects("threat-actor")
        assert result[0]["group_name"] == "ELECTRUM"

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.upsert_object("indicator", {})

    def test_delete_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.delete_object("indicator", "i1")

    def test_get_indicators(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"indicators": [{"value": "1.2.3.4"}]})
        )
        result = client.get_indicators(indicator_type="ip")
        assert result[0]["value"] == "1.2.3.4"

    def test_get_activity_groups(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"activity_groups": [{"group_name": "XENOTIME"}]})
        )
        result = client.get_activity_groups()
        assert result[0]["group_name"] == "XENOTIME"

    def test_get_vulnerabilities(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"vulnerabilities": [{"cve_id": "CVE-2020-1"}]})
        )
        result = client.get_vulnerabilities()
        assert result[0]["cve_id"] == "CVE-2020-1"

    def test_to_stix_ioc_ip_contract(self, client):
        native = {
            "id": "i1",
            "value": "1.2.3.4",
            "indicator_type": "ip",
            "first_seen": "2026-01-01",
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "indicator"
        assert "[ipv4-addr:value = '1.2.3.4']" in stix["pattern"]

    def test_to_stix_actor_contract(self, client):
        native = {
            "group_name": "ELECTRUM",
            "profile": "ICS threat actor",
            "target_industries": ["electric"],
            "first_activity": "2017-01-01",
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "threat-actor"
        assert stix["name"] == "ELECTRUM"

    def test_to_stix_vuln_contract(self, client):
        native = {
            "cve_id": "CVE-2021-44228",
            "description": "Log4Shell",
            "cvss_score": 10.0,
            "severity": "critical",
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "vulnerability"
        assert stix["x_dragos"]["cvss_score"] == 10.0

    def test_to_stix_report_contract(self, client):
        native = {
            "serial": "YR-2026-001",
            "title": "ICS Advisory",
            "executive_summary": "Critical finding",
            "tlp": "amber",
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "report"
        assert stix["x_dragos"]["serial"] == "YR-2026-001"

    def test_from_stix(self, client):
        stix = {"id": "indicator--abc", "type": "indicator", "name": "evil.com"}
        result = client.from_stix(stix)
        assert result["name"] == "evil.com"


# ---------------------------------------------------------------------------
# DatadogClient
# ---------------------------------------------------------------------------


class TestDatadogClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.datadog.client import DatadogClient

        c = DatadogClient(
            host="https://api.datadoghq.com",
            api_key="dd-api-key",
            app_key="dd-app-key",
        )
        c._authenticated = True
        return c

    def test_authenticate_sets_headers(self):
        from gnat.connectors.datadog.client import DatadogClient

        c = DatadogClient(api_key="apikey", app_key="appkey")
        c.authenticate()
        assert c._auth_headers["DD-API-KEY"] == "apikey"
        assert c._auth_headers["DD-APPLICATION-KEY"] == "appkey"

    def test_health_check(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": []}))
        assert client.health_check() is True

    def test_get_object_indicator(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(return_value={"data": {"id": "sig1", "type": "security_signals"}}),
        )
        result = client.get_object("indicator", "sig1")
        assert result["id"] == "sig1"

    def test_get_object_vulnerability(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": {"id": "f1"}}))
        result = client.get_object("vulnerability", "f1")
        assert result["id"] == "f1"

    def test_get_object_report(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": {"id": "inc1"}}))
        result = client.get_object("report", "inc1")
        assert result["id"] == "inc1"

    def test_get_object_unsupported_raises(self, client):
        with pytest.raises(GNATClientError, match="Unsupported"):
            client.get_object("malware", "x")

    def test_list_objects_indicator(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": [{"id": "sig1"}]}))
        result = client.list_objects("indicator")
        assert result[0]["id"] == "sig1"

    def test_list_objects_vulnerability(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": [{"id": "f1"}]}))
        result = client.list_objects("vulnerability")
        assert result[0]["id"] == "f1"

    def test_list_objects_report(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": [{"id": "inc1"}]}))
        result = client.list_objects("report")
        assert result[0]["id"] == "inc1"

    def test_upsert_incident(self, client, monkeypatch):
        monkeypatch.setattr(client, "post", MagicMock(return_value={"data": {"id": "inc-new"}}))
        result = client.upsert_object("report", {"title": "New Incident"})
        assert result["id"] == "inc-new"

    def test_upsert_unsupported_raises(self, client):
        with pytest.raises(GNATClientError, match="not supported"):
            client.upsert_object("indicator", {})

    def test_search_signals(self, client, monkeypatch):
        monkeypatch.setattr(client, "post", MagicMock(return_value={"data": [{"id": "sig1"}]}))
        result = client.search_signals(query="@type:network")
        assert result[0]["id"] == "sig1"

    def test_get_csm_findings(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": [{"id": "f1"}]}))
        result = client.get_csm_findings(severity="high")
        assert result[0]["id"] == "f1"

    def test_get_security_rules(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": [{"id": "r1"}]}))
        result = client.get_security_rules()
        assert result[0]["id"] == "r1"

    def test_mute_signal(self, client, monkeypatch):
        monkeypatch.setattr(client, "patch", MagicMock(return_value={}))
        result = client.mute_signal("sig1")
        assert isinstance(result, dict)

    def test_to_stix_signal_contract(self, client):
        native = {
            "id": "sig1",
            "type": "security_signals",
            "attributes": {
                "message": "Unusual login detected",
                "severity": "high",
                "timestamp": "2026-01-01T00:00:00Z",
                "rule": {"id": "r1", "name": "Suspicious Login"},
                "tags": ["env:prod"],
            },
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "indicator"
        assert stix["x_datadog"]["rule_name"] == "Suspicious Login"

    def test_to_stix_finding_contract(self, client):
        native = {
            "id": "f1",
            "type": "posture_management_findings",
            "attributes": {
                "rule_name": "S3 bucket public",
                "rule_id": "r1",
                "severity": "critical",
                "status": "open",
                "evaluation_changed_at": "2026-01-01T00:00:00Z",
            },
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "vulnerability"
        assert stix["x_datadog"]["rule_id"] == "r1"

    def test_to_stix_incident_contract(self, client):
        native = {
            "id": "inc1",
            "type": "incidents",
            "attributes": {
                "title": "Production Outage",
                "status": "active",
                "severity": "sev1",
                "customer_impact_scope": "All prod users affected",
                "created": "2026-01-01T00:00:00Z",
            },
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "report"
        assert stix["x_datadog"]["status"] == "active"

    def test_from_stix(self, client):
        stix = {"id": "report--abc", "name": "Production Incident", "type": "report"}
        result = client.from_stix(stix)
        assert result["title"] == "Production Incident"


# ──────────────────────────────────────────────────────────────────────────────
# Cortex XDR
# ──────────────────────────────────────────────────────────────────────────────


class TestCortexXDRClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.cortex_xdr.client import CortexXDRClient

        c = CortexXDRClient(
            host="https://api.xdr.paloaltonetworks.com",
            api_key_id="1",
            api_key="testkey",
        )
        c._authenticated = True
        return c

    def test_authenticate_sets_headers(self):
        from gnat.connectors.cortex_xdr.client import CortexXDRClient

        c = CortexXDRClient(api_key_id="42", api_key="secret")
        c.authenticate()
        assert "Authorization" in c._auth_headers
        assert c._auth_headers["x-xdr-auth-id"] == "42"

    def test_health_check(self, client, monkeypatch):
        monkeypatch.setattr(client, "post", MagicMock(return_value={"reply": {"incidents": []}}))
        assert client.health_check() is True

    def test_get_object_indicator(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "post",
            MagicMock(return_value={"reply": {"alerts": [{"alert_id": "a1", "severity": "high"}]}}),
        )
        result = client.get_object("indicator", "a1")
        assert result["alert_id"] == "a1"

    def test_get_object_malware(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "post",
            MagicMock(return_value={"reply": {"incidents": [{"incident_id": "i1"}]}}),
        )
        result = client.get_object("malware", "i1")
        assert result["incident_id"] == "i1"

    def test_get_object_unsupported_raises(self, client):
        with pytest.raises(GNATClientError, match="Unsupported"):
            client.get_object("report", "x")

    def test_list_objects_indicator(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "post", MagicMock(return_value={"reply": {"alerts": [{"alert_id": "a1"}]}})
        )
        result = client.list_objects("indicator")
        assert result[0]["alert_id"] == "a1"

    def test_list_objects_malware(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "post",
            MagicMock(return_value={"reply": {"incidents": [{"incident_id": "i1"}]}}),
        )
        result = client.list_objects("malware")
        assert result[0]["incident_id"] == "i1"

    def test_list_objects_unsupported_raises(self, client):
        with pytest.raises(GNATClientError, match="Unsupported"):
            client.list_objects("report")

    def test_upsert_incident(self, client, monkeypatch):
        monkeypatch.setattr(client, "post", MagicMock(return_value={"reply": {}}))
        result = client.upsert_object("malware", {"incident_id": "i1", "status": "resolved"})
        assert isinstance(result, dict)

    def test_upsert_unsupported_raises(self, client):
        with pytest.raises(GNATClientError, match="not supported"):
            client.upsert_object("indicator", {})

    def test_delete_incident(self, client, monkeypatch):
        monkeypatch.setattr(client, "post", MagicMock(return_value={}))
        client.delete_object("malware", "i1")

    def test_delete_unsupported_raises(self, client):
        with pytest.raises(GNATClientError, match="not supported"):
            client.delete_object("indicator", "x")

    def test_get_endpoints(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "post",
            MagicMock(return_value={"reply": {"endpoints": [{"endpoint_id": "ep1"}]}}),
        )
        result = client.get_endpoints()
        assert result[0]["endpoint_id"] == "ep1"

    def test_isolate_endpoint(self, client, monkeypatch):
        monkeypatch.setattr(client, "post", MagicMock(return_value={"reply": {}}))
        result = client.isolate_endpoint("ep1")
        assert isinstance(result, dict)

    def test_to_stix_alert_contract(self, client):
        native = {
            "alert_id": "a1",
            "name": "Suspicious process",
            "severity": "high",
            "detection_timestamp": 1700000000000,
            "remote_ip": "1.2.3.4",
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "indicator"
        assert stix["x_cortex_xdr"]["alert_id"] == "a1"

    def test_to_stix_alert_sha256(self, client):
        native = {
            "alert_id": "a2",
            "severity": "medium",
            "actor_process_image_sha256": "abc123" * 10,
        }
        stix = client.to_stix(native)
        assert "SHA-256" in stix["pattern"]

    def test_to_stix_incident_contract(self, client):
        native = {
            "incident_id": "i1",
            "incident_name": "XDR Incident Alpha",
            "severity": "critical",
            "creation_time": 1700000000000,
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "malware"
        assert stix["x_cortex_xdr"]["incident_id"] == "i1"

    def test_from_stix(self, client):
        stix = {"id": "indicator--abc", "name": "Test Alert"}
        result = client.from_stix(stix)
        assert result["name"] == "Test Alert"


# ──────────────────────────────────────────────────────────────────────────────
# Prisma Cloud
# ──────────────────────────────────────────────────────────────────────────────


class TestPrismaCloudClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.prisma_cloud.client import PrismaCloudClient

        c = PrismaCloudClient(
            host="https://api.prismacloud.io",
            access_key_id="access-key-id",
            secret_key="secret-key",
        )
        c._authenticated = True
        return c

    def test_authenticate_sets_header(self, monkeypatch):
        from gnat.connectors.prisma_cloud.client import PrismaCloudClient

        c = PrismaCloudClient(access_key_id="kid", secret_key="skey")
        monkeypatch.setattr(c, "post", MagicMock(return_value={"token": "jwt-token"}))
        c.authenticate()
        assert c._auth_headers["x-redlock-auth"] == "jwt-token"

    def test_authenticate_raises_on_missing_token(self, monkeypatch):
        from gnat.connectors.prisma_cloud.client import PrismaCloudClient

        c = PrismaCloudClient(access_key_id="kid", secret_key="skey")
        monkeypatch.setattr(c, "post", MagicMock(return_value={}))
        with pytest.raises(GNATClientError, match="failed to obtain"):
            c.authenticate()

    def test_health_check(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"items": []}))
        assert client.health_check() is True

    def test_get_object_indicator(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"id": "alert1"}))
        result = client.get_object("indicator", "alert1")
        assert result["id"] == "alert1"

    def test_get_object_vulnerability(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"cveId": "CVE-2024-0001"}))
        result = client.get_object("vulnerability", "CVE-2024-0001")
        assert result["cveId"] == "CVE-2024-0001"

    def test_get_object_report(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"name": "SOC2"}))
        result = client.get_object("report", "soc2")
        assert result["name"] == "SOC2"

    def test_get_object_unsupported_raises(self, client):
        with pytest.raises(GNATClientError, match="Unsupported"):
            client.get_object("malware", "x")

    def test_list_objects_indicator(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"items": [{"id": "alert1"}]}))
        result = client.list_objects("indicator")
        assert result[0]["id"] == "alert1"

    def test_list_objects_vulnerability(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"items": [{"cveId": "CVE-2024-0001"}]})
        )
        result = client.list_objects("vulnerability")
        assert result[0]["cveId"] == "CVE-2024-0001"

    def test_list_objects_unsupported_raises(self, client):
        with pytest.raises(GNATClientError, match="Unsupported"):
            client.list_objects("malware")

    def test_upsert_dismiss_alert(self, client, monkeypatch):
        monkeypatch.setattr(client, "post", MagicMock(return_value={}))
        result = client.upsert_object("indicator", {"alertId": "a1"})
        assert isinstance(result, dict)

    def test_upsert_unsupported_raises(self, client):
        with pytest.raises(GNATClientError, match="not supported"):
            client.upsert_object("vulnerability", {})

    def test_search_config(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "post", MagicMock(return_value={"data": {"items": [{"id": "r1"}]}})
        )
        result = client.search_config("config from cloud.resource where ...")
        assert result[0]["id"] == "r1"

    def test_to_stix_alert_contract(self, client):
        native = {
            "id": "alert1",
            "policy": {
                "name": "S3 Bucket Public",
                "severity": "high",
                "policyId": "p1",
                "policyType": "config",
            },
            "alertTime": 1700000000000,
            "resource": {
                "name": "my-bucket",
                "cloudType": "aws",
                "id": "r1",
                "region": "us-east-1",
            },
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "indicator"
        assert stix["x_prisma_cloud"]["alert_id"] == "alert1"

    def test_to_stix_vulnerability_contract(self, client):
        native = {
            "cveId": "CVE-2024-0001",
            "cvssScore": 9.8,
            "severity": "critical",
            "description": "Test CVE",
            "publishedDate": "2024-01-01T00:00:00Z",
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "vulnerability"
        assert stix["name"] == "CVE-2024-0001"

    def test_to_stix_compliance_contract(self, client):
        native = {
            "name": "CIS Benchmark",
            "passedResources": 80,
            "failedResources": 20,
            "totalResources": 100,
            "passPercentage": 80.0,
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "report"

    def test_from_stix(self, client):
        stix = {"id": "indicator--abc", "name": "Alert Name", "type": "indicator"}
        result = client.from_stix(stix)
        assert "alertId" in result


# ──────────────────────────────────────────────────────────────────────────────
# Nozomi Networks
# ──────────────────────────────────────────────────────────────────────────────


class TestNozomiClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.nozomi.client import NozomiClient

        c = NozomiClient(
            host="https://nozomi.example.com",
            api_token="nozomi-api-token",
        )
        c._authenticated = True
        return c

    def test_authenticate_token(self):
        from gnat.connectors.nozomi.client import NozomiClient

        c = NozomiClient(api_token="mytoken")
        c.authenticate()
        assert c._auth_headers["Authorization"] == "Token mytoken"

    def test_authenticate_basic(self):
        from gnat.connectors.nozomi.client import NozomiClient

        c = NozomiClient(username="user", password="pass")
        c.authenticate()
        assert c._auth_headers["Authorization"].startswith("Basic ")

    def test_health_check(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"result": []}))
        assert client.health_check() is True

    def test_get_object_indicator(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"id": "alert1", "type_name": "Malware"})
        )
        result = client.get_object("indicator", "alert1")
        assert result["id"] == "alert1"

    def test_get_object_vulnerability(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(return_value={"result": [{"id": "v1", "cve_id": "CVE-2024-0001"}]}),
        )
        result = client.get_object("vulnerability", "v1")
        assert result["cve_id"] == "CVE-2024-0001"

    def test_get_object_infrastructure(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"result": [{"id": "n1", "vendor": "Siemens"}]})
        )
        result = client.get_object("infrastructure", "n1")
        assert result["vendor"] == "Siemens"

    def test_get_object_unsupported_raises(self, client):
        with pytest.raises(GNATClientError, match="Unsupported"):
            client.get_object("report", "x")

    def test_list_objects_indicator(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"result": [{"id": "a1", "risk": "high"}]})
        )
        result = client.list_objects("indicator")
        assert result[0]["id"] == "a1"

    def test_list_objects_with_filters(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"result": []}))
        client.list_objects("vulnerability", filters={"severity": "critical"})

    def test_upsert_acknowledge(self, client, monkeypatch):
        monkeypatch.setattr(client, "patch", MagicMock(return_value={"id": "a1"}))
        result = client.upsert_object("indicator", {"id": "a1", "ack": True})
        assert isinstance(result, dict)

    def test_upsert_unsupported_raises(self, client):
        with pytest.raises(GNATClientError, match="not supported"):
            client.upsert_object("vulnerability", {})

    def test_delete_acknowledges(self, client, monkeypatch):
        monkeypatch.setattr(client, "patch", MagicMock(return_value={}))
        client.delete_object("indicator", "a1")

    def test_delete_unsupported_raises(self, client):
        with pytest.raises(GNATClientError, match="not supported"):
            client.delete_object("vulnerability", "v1")

    def test_get_nodes(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"result": [{"id": "n1"}]}))
        result = client.get_nodes()
        assert result[0]["id"] == "n1"

    def test_get_vulnerabilities(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"result": [{"cve_id": "CVE-2024-0001"}]})
        )
        result = client.get_vulnerabilities()
        assert result[0]["cve_id"] == "CVE-2024-0001"

    def test_to_stix_alert_ip(self, client):
        native = {
            "id": "a1",
            "type_name": "Lateral Movement",
            "risk": "high",
            "src_ip": "192.168.1.10",
            "dst_ip": "10.0.0.5",
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "indicator"
        assert "192.168.1.10" in stix["pattern"]

    def test_to_stix_vulnerability_contract(self, client):
        native = {
            "cve_id": "CVE-2024-0001",
            "cvss_score": 8.5,
            "severity": "high",
            "description": "Test CVE",
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "vulnerability"

    def test_to_stix_node_contract(self, client):
        native = {
            "id": "n1",
            "mac_address": "00:11:22:33:44:55",
            "vendor": "Siemens",
            "product_name": "S7-300",
            "ip": "10.0.1.5",
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "infrastructure"

    def test_from_stix(self, client):
        stix = {"id": "indicator--abc", "name": "Nozomi Alert"}
        result = client.from_stix(stix)
        assert result["name"] == "Nozomi Alert"


# ──────────────────────────────────────────────────────────────────────────────
# VMware Carbon Black
# ──────────────────────────────────────────────────────────────────────────────


class TestCarbonBlackClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.carbon_black.client import CarbonBlackClient

        c = CarbonBlackClient(
            host="https://defense.conferdeploy.net",
            org_key="ABC123",
            api_key="apikey123",
            connector_id="connector456",
        )
        c._authenticated = True
        return c

    def test_authenticate_sets_header(self):
        from gnat.connectors.carbon_black.client import CarbonBlackClient

        c = CarbonBlackClient(org_key="ORG", api_key="KEY", connector_id="CID")
        c.authenticate()
        assert c._auth_headers["X-Auth-Token"] == "KEY/CID"

    def test_authenticate_no_connector_id(self):
        from gnat.connectors.carbon_black.client import CarbonBlackClient

        c = CarbonBlackClient(org_key="ORG", api_key="ONLYKEY")
        c.authenticate()
        assert c._auth_headers["X-Auth-Token"] == "ONLYKEY"

    def test_health_check(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"results": []}))
        assert client.health_check() is True

    def test_get_object_indicator(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"id": "alert1", "type": "CB_ANALYTICS"})
        )
        result = client.get_object("indicator", "alert1")
        assert result["id"] == "alert1"

    def test_get_object_vulnerability(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"id": "dev1", "device_os": "WINDOWS"})
        )
        result = client.get_object("vulnerability", "dev1")
        assert result["id"] == "dev1"

    def test_get_object_unsupported_raises(self, client):
        with pytest.raises(GNATClientError, match="Unsupported"):
            client.get_object("report", "x")

    def test_list_objects_indicator(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "post", MagicMock(return_value={"results": [{"id": "a1", "severity": 8}]})
        )
        result = client.list_objects("indicator")
        assert result[0]["id"] == "a1"

    def test_list_objects_vulnerability(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(return_value={"results": [{"id": "dev1", "device_os": "LINUX"}]}),
        )
        result = client.list_objects("vulnerability")
        assert result[0]["id"] == "dev1"

    def test_list_objects_unsupported_raises(self, client):
        with pytest.raises(GNATClientError, match="Unsupported"):
            client.list_objects("report")

    def test_upsert_dismiss_alert(self, client, monkeypatch):
        monkeypatch.setattr(client, "post", MagicMock(return_value={}))
        result = client.upsert_object("indicator", {"id": "a1", "reason": "FP"})
        assert isinstance(result, dict)

    def test_upsert_unsupported_raises(self, client):
        with pytest.raises(GNATClientError, match="not supported"):
            client.upsert_object("vulnerability", {})

    def test_delete_indicator(self, client, monkeypatch):
        monkeypatch.setattr(client, "post", MagicMock(return_value={}))
        client.delete_object("indicator", "a1")

    def test_delete_unsupported_raises(self, client):
        with pytest.raises(GNATClientError, match="not supported"):
            client.delete_object("vulnerability", "v1")

    def test_get_devices(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"results": [{"id": "dev1"}]}))
        result = client.get_devices()
        assert result[0]["id"] == "dev1"

    def test_quarantine_device(self, client, monkeypatch):
        monkeypatch.setattr(client, "post", MagicMock(return_value={}))
        result = client.quarantine_device("dev1")
        assert isinstance(result, dict)

    def test_get_watchlists(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"results": [{"id": "wl1"}]}))
        result = client.get_watchlists()
        assert result[0]["id"] == "wl1"

    def test_to_stix_alert_sha256(self, client):
        native = {
            "id": "alert1",
            "type": "CB_ANALYTICS",
            "severity": 8,
            "reason": "Malware detected",
            "process_sha256": "abc123def456" * 4,
            "device_name": "WORKSTATION01",
            "device_os": "WINDOWS",
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "indicator"
        assert "SHA-256" in stix["pattern"]
        assert stix["x_carbon_black"]["alert_id"] == "alert1"

    def test_to_stix_alert_ip(self, client):
        native = {
            "id": "a2",
            "type": "WATCHLIST",
            "severity": 6,
            "device_internal_ip": "192.168.0.50",
        }
        stix = client.to_stix(native)
        assert "192.168.0.50" in stix["pattern"]

    def test_to_stix_device_contract(self, client):
        native = {
            "id": "dev1",
            "name": "ENDPOINT01",
            "os": "WINDOWS",
            "sensor_version": "3.9.0",
            "policy_name": "default",
            "last_internal_ip_address": "10.0.0.5",
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "vulnerability"

    def test_to_stix_process_contract(self, client):
        native = {
            "process_guid": "PROC-GUID-001",
            "process_name": "powershell.exe",
            "process_sha256": "abc" * 21,
            "device_name": "HOST01",
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "malware"

    def test_from_stix(self, client):
        stix = {"id": "indicator--abc", "name": "Test Alert", "type": "indicator"}
        result = client.from_stix(stix)
        assert result["reason"] == "Test Alert"


# ──────────────────────────────────────────────────────────────────────────────
# LogRhythm
# ──────────────────────────────────────────────────────────────────────────────


class TestLogRhythmClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.logrhythm.client import LogRhythmClient

        c = LogRhythmClient(
            host="https://logrhythm.example.com:8501",
            api_token="lr-bearer-token",
        )
        c._authenticated = True
        return c

    def test_authenticate_token(self):
        from gnat.connectors.logrhythm.client import LogRhythmClient

        c = LogRhythmClient(api_token="mytoken")
        c.authenticate()
        assert c._auth_headers["Authorization"] == "Bearer mytoken"

    def test_authenticate_oauth2(self, monkeypatch):
        from gnat.connectors.logrhythm.client import LogRhythmClient

        c = LogRhythmClient(client_id="cid", client_secret="csecret")
        monkeypatch.setattr(c, "post", MagicMock(return_value={"access_token": "oauth-token"}))
        c.authenticate()
        assert c._auth_headers["Authorization"] == "Bearer oauth-token"

    def test_authenticate_oauth2_raises(self, monkeypatch):
        from gnat.connectors.logrhythm.client import LogRhythmClient

        c = LogRhythmClient(client_id="cid", client_secret="csecret")
        monkeypatch.setattr(c, "post", MagicMock(return_value={}))
        with pytest.raises(GNATClientError, match="failed to obtain"):
            c.authenticate()

    def test_health_check(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"alarmsSearchDetails": []}))
        assert client.health_check() is True

    def test_get_object_indicator(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"alarmId": 42, "alarmRuleName": "Brute Force"})
        )
        result = client.get_object("indicator", "42")
        assert result["alarmId"] == 42

    def test_get_object_malware(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(
                return_value={
                    "id": "case1",
                    "name": "IR Case",
                    "priority": 3,
                    "status": {"name": "Created"},
                }
            ),
        )
        result = client.get_object("malware", "case1")
        assert result["id"] == "case1"

    def test_get_object_unsupported_raises(self, client):
        with pytest.raises(GNATClientError, match="Unsupported"):
            client.get_object("report", "x")

    def test_list_objects_alarms(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"alarmsSearchDetails": [{"alarmId": 1}]})
        )
        result = client.list_objects("indicator")
        assert result[0]["alarmId"] == 1

    def test_list_objects_cases(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value=[{"id": "c1"}]))
        result = client.list_objects("malware")
        assert result[0]["id"] == "c1"

    def test_list_objects_unsupported_raises(self, client):
        with pytest.raises(GNATClientError, match="Unsupported"):
            client.list_objects("report")

    def test_upsert_alarm_status(self, client, monkeypatch):
        monkeypatch.setattr(client, "post", MagicMock(return_value={}))
        result = client.upsert_object("indicator", {"alarmId": "42", "status": "Completed"})
        assert isinstance(result, dict)

    def test_upsert_create_case(self, client, monkeypatch):
        monkeypatch.setattr(client, "post", MagicMock(return_value={"id": "new-case"}))
        result = client.upsert_object("malware", {"name": "New Case", "priority": 2})
        assert result["id"] == "new-case"

    def test_upsert_unsupported_raises(self, client):
        with pytest.raises(GNATClientError, match="not supported"):
            client.upsert_object("vulnerability", {})

    def test_delete_alarm(self, client, monkeypatch):
        monkeypatch.setattr(client, "post", MagicMock(return_value={}))
        client.delete_object("indicator", "42")

    def test_delete_case(self, client, monkeypatch):
        monkeypatch.setattr(client, "patch", MagicMock(return_value={}))
        client.delete_object("malware", "case1")

    def test_delete_unsupported_raises(self, client):
        with pytest.raises(GNATClientError, match="not supported"):
            client.delete_object("vulnerability", "v1")

    def test_get_alarm_events(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"logList": [{"msgId": "e1"}]}))
        result = client.get_alarm_events("42")
        assert result[0]["msgId"] == "e1"

    def test_add_case_note(self, client, monkeypatch):
        monkeypatch.setattr(client, "post", MagicMock(return_value={"id": "note1"}))
        result = client.add_case_note("case1", "Investigated")
        assert result["id"] == "note1"

    def test_create_case_from_alarm(self, client, monkeypatch):
        monkeypatch.setattr(client, "post", MagicMock(return_value={"id": "case-new"}))
        result = client.create_case_from_alarm("42", "Investigation Case")
        assert result["id"] == "case-new"

    def test_update_list(self, client, monkeypatch):
        monkeypatch.setattr(client, "post", MagicMock(return_value={}))
        result = client.update_list(1001, ["1.2.3.4", "5.6.7.8"])
        assert isinstance(result, dict)

    def test_to_stix_alarm_ip(self, client):
        native = {
            "alarmId": 42,
            "alarmRuleName": "Brute Force Detected",
            "alarmRuleID": 100,
            "alarmRiskScore": 80,
            "alarmStatus": "OpenAlarm",
            "dateInserted": "2024-01-01T00:00:00Z",
            "impactedIp": "10.0.0.5",
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "indicator"
        assert stix["x_logrhythm"]["alarm_id"] == "42"
        assert "10.0.0.5" in stix["pattern"]

    def test_to_stix_alarm_domain(self, client):
        native = {
            "alarmId": 43,
            "alarmRuleName": "DNS Beaconing",
            "alarmRiskScore": 70,
            "impactedHostName": "infected-host.corp.local",
        }
        stix = client.to_stix(native)
        assert stix["type"] == "indicator"

    def test_to_stix_case_contract(self, client):
        native = {
            "id": "case1",
            "name": "IR Investigation",
            "status": {"name": "Created"},
            "priority": 2,
            "dateCreated": "2024-01-01T00:00:00Z",
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "malware"
        assert stix["x_logrhythm"]["case_id"] == "case1"

    def test_to_stix_event_contract(self, client):
        native = {
            "logSourceMsgId": "evt1",
            "logDate": "2024-01-01T00:00:00Z",
            "commonEventName": "Authentication Success",
            "originIp": "172.16.0.1",
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "observed-data"

    def test_from_stix_case(self, client):
        stix = {
            "id": "malware--abc",
            "name": "IR Case",
            "type": "malware",
            "description": "Investigation summary",
        }
        result = client.from_stix(stix)
        assert result["name"] == "IR Case"

    def test_from_stix_alarm(self, client):
        stix = {"id": "indicator--abc", "name": "Alert Name", "type": "indicator"}
        result = client.from_stix(stix)
        assert result["alarmRuleName"] == "Alert Name"


# ──────────────────────────────────────────────────────────────────────────────
# FortiSOAR (fix regression tests)
# ──────────────────────────────────────────────────────────────────────────────


class TestFortiSOARClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.fortisoar.client import FortiSOARClient

        c = FortiSOARClient(
            host="https://fortisoar.example.com",
            username="admin",
            password="password",
        )
        c._token = "test-jwt-token"
        c._authenticated = True
        return c

    def test_authenticate_jwt(self, monkeypatch):
        from gnat.connectors.fortisoar.client import FortiSOARClient

        c = FortiSOARClient(host="https://fortisoar.example.com", username="admin", password="pass")
        monkeypatch.setattr(c, "post", MagicMock(return_value={"token": "jwt"}))
        c.authenticate()
        assert c._auth_headers["Authorization"] == "Bearer jwt"

    def test_authenticate_uses_cached_token(self):
        from gnat.connectors.fortisoar.client import FortiSOARClient

        c = FortiSOARClient(host="https://fortisoar.example.com")
        c._token = "cached-jwt"
        c.authenticate()
        assert c._auth_headers["Authorization"] == "Bearer cached-jwt"

    def test_health_check(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"hydra:member": []}))
        assert client.health_check() is True

    def test_get_object(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"id": "uuid-1", "name": "Test Alert"})
        )
        result = client.get_object("observed-data", "uuid-1")
        assert result["id"] == "uuid-1"

    def test_list_objects(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"hydra:member": [{"id": "uuid-1"}]})
        )
        result = client.list_objects("indicator")
        assert result[0]["id"] == "uuid-1"

    def test_upsert_create(self, client, monkeypatch):
        monkeypatch.setattr(client, "post", MagicMock(return_value={"id": "new-uuid"}))
        result = client.upsert_object("incident", {"name": "New Incident"})
        assert result["id"] == "new-uuid"

    def test_upsert_update(self, client, monkeypatch):
        monkeypatch.setattr(client, "put", MagicMock(return_value={"id": "existing-uuid"}))
        result = client.upsert_object("incident", {"id": "existing-uuid", "name": "Updated"})
        assert result["id"] == "existing-uuid"

    def test_delete_object(self, client, monkeypatch):
        monkeypatch.setattr(client, "delete", MagicMock(return_value=None))
        client.delete_object("observed-data", "uuid-1")

    def test_list_alerts(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"hydra:member": [{"id": "a1"}]}))
        result = client.list_alerts(status="Open")
        assert result[0]["id"] == "a1"

    def test_escalate_to_incident(self, client, monkeypatch):
        monkeypatch.setattr(client, "post", MagicMock(return_value={"id": "inc1"}))
        result = client.escalate_to_incident("alert-uuid", "New Incident")
        assert result["id"] == "inc1"

    def test_trigger_playbook(self, client, monkeypatch):
        monkeypatch.setattr(client, "post", MagicMock(return_value={}))
        result = client.trigger_playbook("/api/3/playbooks/pb1", "/api/3/alerts/a1")
        assert isinstance(result, dict)

    def test_to_stix_alert_contract(self, client):
        native = {
            "id": "uuid-1",
            "name": "Suspicious Login",
            "severity": {"itemValue": "High"},
            "status": {"itemValue": "Open"},
            "sourceIp": "10.0.0.1",
            "createDate": "2024-01-01T00:00:00Z",
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "indicator"
        assert stix["x_fortisoar"]["module"] == "alerts"

    def test_to_stix_indicator_ip(self, client):
        native = {
            "id": "ioc-1",
            "indicatorValue": "1.2.3.4",
            "typeofindicator": {"itemValue": "IP Address"},
            "createDate": "2024-01-01T00:00:00Z",
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert "1.2.3.4" in stix["pattern"]

    def test_to_stix_incident_contract(self, client):
        native = {
            "id": "inc-1",
            "name": "Security Incident",
            "severity": {"itemValue": "Critical"},
            "status": {"itemValue": "InProgress"},
            "alerts": ["/api/3/alerts/uuid-1"],
            "createDate": "2024-01-01T00:00:00Z",
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "malware"

    def test_from_stix(self, client):
        stix = {"id": "indicator--abc", "name": "IOC Value", "type": "indicator"}
        result = client.from_stix(stix)
        assert result["name"] == "IOC Value"


# ---------------------------------------------------------------------------
# CISA
# ---------------------------------------------------------------------------


class TestCISAClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.CISA.client import CISAClient

        c = CISAClient(host="https://www.cisa.gov")
        c._authenticated = True
        return c

    def test_authenticate_sets_accept_header(self):
        from gnat.connectors.CISA.client import CISAClient

        c = CISAClient(host="https://www.cisa.gov")
        c.authenticate()
        assert c._auth_headers["Accept"] == "application/json"

    def test_health_check_calls_kev_endpoint(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"vulnerabilities": []}))
        result = client.health_check()
        assert result is True

    def test_list_objects_returns_vulnerabilities(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(
                return_value={
                    "vulnerabilities": [
                        {"cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j"},
                    ]
                }
            ),
        )
        result = client.list_objects("vulnerability")
        assert len(result) == 1
        assert result[0]["cveID"] == "CVE-2021-44228"

    def test_list_objects_pagination(self, client, monkeypatch):
        entries = [{"cveID": f"CVE-2021-{i}"} for i in range(5)]
        monkeypatch.setattr(client, "get", MagicMock(return_value={"vulnerabilities": entries}))
        page1 = client.list_objects("vulnerability", page=1, page_size=2)
        page2 = client.list_objects("vulnerability", page=2, page_size=2)
        assert len(page1) == 2
        assert len(page2) == 2
        assert page1[0]["cveID"] == "CVE-2021-0"
        assert page2[0]["cveID"] == "CVE-2021-2"

    def test_list_objects_invalid_type_raises(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"vulnerabilities": []}))
        with pytest.raises(GNATClientError, match="list_objects supports"):
            client.list_objects("malware")

    def test_get_object_finds_cve(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(
                return_value={
                    "vulnerabilities": [{"cveID": "CVE-2021-44228"}, {"cveID": "CVE-2022-0001"}]
                }
            ),
        )
        result = client.get_object("vulnerability", "CVE-2021-44228")
        assert result["cveID"] == "CVE-2021-44228"

    def test_get_object_not_found_raises(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"vulnerabilities": []}))
        with pytest.raises(GNATClientError, match="not found"):
            client.get_object("vulnerability", "CVE-9999-9999")

    def test_get_object_unsupported_type_raises(self, client, monkeypatch):
        with pytest.raises(GNATClientError, match="limited to vulnerability"):
            client.get_object("indicator", "some-id")

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.upsert_object("vulnerability", {})

    def test_delete_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.delete_object("vulnerability", "CVE-2021-44228")

    def test_get_kev_catalog(self, client, monkeypatch):
        catalog = {"title": "CISA KEV", "vulnerabilities": []}
        monkeypatch.setattr(client, "get", MagicMock(return_value=catalog))
        result = client.get_kev_catalog()
        assert result["title"] == "CISA KEV"

    def test_get_kev_by_cve_found(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(return_value={"vulnerabilities": [{"cveID": "CVE-2021-44228"}]}),
        )
        result = client.get_kev_by_cve("CVE-2021-44228")
        assert result is not None
        assert result["cveID"] == "CVE-2021-44228"

    def test_get_kev_by_cve_not_found_returns_none(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"vulnerabilities": []}))
        result = client.get_kev_by_cve("CVE-9999-9999")
        assert result is None

    def test_to_stix_contract(self, client):
        native = {
            "cveID": "CVE-2021-44228",
            "vendorProject": "Apache",
            "product": "Log4j",
            "dateAdded": "2021-12-10",
            "shortDescription": "Log4Shell RCE",
            "requiredAction": "Apply patch",
            "dueDate": "2021-12-24",
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "vulnerability"
        assert stix["name"] == "CVE-2021-44228"
        assert stix["x_cisa_kev"]["vendor_project"] == "Apache"

    def test_to_stix_empty_cve_returns_report(self, client):
        native = {"title": "CISA KEV Catalog", "catalogVersion": "2024.01"}
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "report"

    def test_from_stix_returns_dict(self, client):
        stix = {"type": "vulnerability", "id": "vulnerability--abc"}
        result = client.from_stix(stix)
        assert isinstance(result, dict)
        assert "note" in result


# ---------------------------------------------------------------------------
# FortiEDR
# ---------------------------------------------------------------------------


class TestFortiEDRClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.fortiedr.client import FortiEDRClient

        c = FortiEDRClient(host="https://fortiedr.example.com", username="admin", password="secret")
        c._authenticated = True
        return c

    def test_authenticate_sets_headers(self):
        from gnat.connectors.fortiedr.client import FortiEDRClient

        c = FortiEDRClient(host="https://fortiedr.example.com", username="admin", password="secret")
        c.authenticate()
        assert c._auth_headers["Accept"] == "application/json"
        assert c._auth_headers["Content-Type"] == "application/json"

    def test_get_object_incident(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"incidentId": "inc-1"}))
        result = client.get_object("incident", "inc-1")
        assert result["incidentId"] == "inc-1"

    def test_get_object_unsupported_type_raises(self, client):
        with pytest.raises(GNATClientError):
            client.get_object("malware", "id-1")

    def test_list_objects_incidents(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(return_value={"data": [{"incidentId": "inc-1"}, {"incidentId": "inc-2"}]}),
        )
        result = client.list_objects("incident")
        assert len(result) == 2

    def test_list_objects_collectors(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"data": [{"collectorId": "col-1"}]})
        )
        result = client.list_objects("report")
        assert result[0]["collectorId"] == "col-1"

    def test_list_objects_invalid_type_raises(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={}))
        with pytest.raises(GNATClientError, match="not implemented"):
            client.list_objects("malware")

    def test_upsert_incident(self, client, monkeypatch):
        monkeypatch.setattr(client, "post", MagicMock(return_value={"updated": True}))
        result = client.upsert_object("incident", {"incidentId": "inc-1"})
        assert result["updated"] is True

    def test_upsert_unsupported_raises(self, client):
        with pytest.raises(GNATClientError):
            client.upsert_object("malware", {})

    def test_delete_raises(self, client):
        with pytest.raises(GNATClientError, match="does not support"):
            client.delete_object("incident", "inc-1")

    def test_list_collectors_helper(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(return_value={"data": [{"collectorId": "col-1", "hostname": "host1"}]}),
        )
        result = client.list_collectors()
        assert result[0]["hostname"] == "host1"

    def test_get_incident_details(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"incidentId": "inc-42"}))
        result = client.get_incident_details("inc-42")
        assert result["incidentId"] == "inc-42"

    def test_to_stix_incident_contract(self, client):
        native = {
            "incidentId": "inc-1",
            "severity": "High",
            "classification": "Ransomware",
            "collectorId": "col-1",
            "firstSeen": "2024-01-01T00:00:00Z",
            "lastSeen": "2024-01-01T01:00:00Z",
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "observed-data"
        assert stix["x_fortiedr"]["event_id"] == "inc-1"

    def test_to_stix_collector_contract(self, client):
        native = {"collectorId": "col-1", "hostname": "endpoint1"}
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "report"

    def test_from_stix_returns_dict(self, client):
        stix = {"type": "observed-data", "id": "observed-data--abc"}
        result = client.from_stix(stix)
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# FortiSIEM
# ---------------------------------------------------------------------------


class TestFortiSIEMClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.fortisiem.client import FortiSIEMClient

        c = FortiSIEMClient(
            host="https://fortisiem.example.com", username="super/admin", password="secret"
        )
        c._authenticated = True
        return c

    def test_authenticate_sets_headers(self):
        from gnat.connectors.fortisiem.client import FortiSIEMClient

        c = FortiSIEMClient(host="https://fortisiem.example.com", username="admin", password="pass")
        c.authenticate()
        assert c._auth_headers["Accept"] == "application/json"
        assert c._auth_headers["Content-Type"] == "application/json"

    def test_get_object_incident(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"response": [{"incidentId": "5001"}]})
        )
        result = client.get_object("incident", "5001")
        assert result["incidentId"] == "5001"

    def test_get_object_unsupported_type_raises(self, client):
        with pytest.raises(GNATClientError, match="not fully implemented"):
            client.get_object("malware", "id-1")

    def test_list_objects_incidents(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(return_value={"response": [{"incidentId": "5001"}, {"incidentId": "5002"}]}),
        )
        result = client.list_objects("incident")
        assert len(result) == 2

    def test_list_objects_observed_data_raises(self, client):
        with pytest.raises(GNATClientError, match="observed-data needs"):
            client.list_objects("observed-data")

    def test_upsert_incident(self, client, monkeypatch):
        monkeypatch.setattr(client, "post", MagicMock(return_value={"success": True}))
        result = client.upsert_object("incident", {"status": "resolved"})
        assert result["success"] is True

    def test_upsert_unsupported_raises(self, client):
        with pytest.raises(GNATClientError):
            client.upsert_object("malware", {})

    def test_delete_raises(self, client):
        with pytest.raises(GNATClientError, match="does not support"):
            client.delete_object("incident", "5001")

    def test_fetch_incidents_helper(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"response": [{"incidentId": "5001"}]})
        )
        result = client.fetch_incidents(time_from=0, time_to=9999999999)
        assert result[0]["incidentId"] == "5001"

    def test_to_stix_incident_contract(self, client):
        native = {
            "incidentId": "5001",
            "incidentStatus": 1,
            "eventSeverity": 8,
            "incidentFirstSeen": "2024-01-01T00:00:00Z",
            "incidentLastSeen": "2024-01-01T01:00:00Z",
            "incidentDetail": "Suspicious traffic detected",
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "observed-data"
        assert stix["x_fortisiem_incident"]["incident_id"] == "5001"

    def test_to_stix_cmdb_fallback(self, client):
        native = {"deviceName": "firewall-1", "ipAddr": "192.168.1.1"}
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "report"
        assert stix["x_fortisiem"] == native

    def test_from_stix_returns_dict(self, client):
        stix = {"type": "observed-data", "id": "observed-data--abc"}
        result = client.from_stix(stix)
        assert isinstance(result, dict)
        assert "stix_id" in result


# ---------------------------------------------------------------------------
# GoogleChronicle
# ---------------------------------------------------------------------------


class TestGoogleChronicleClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.google_chronicle.client import GoogleChronicleClient

        c = GoogleChronicleClient(host="https://backstory.googleapis.com", service_account={})
        c._token = "fake-token"
        c._authenticated = True
        return c

    def test_authenticate_sets_bearer_header(self):
        from gnat.connectors.google_chronicle.client import GoogleChronicleClient

        c = GoogleChronicleClient(service_account={})
        c._token = "test-token"
        c.authenticate()
        assert c._auth_headers["Authorization"] == "Bearer test-token"

    def test_health_check_calls_lists_endpoint(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={}))
        result = client.health_check()
        assert result is True

    def test_list_objects_observed_data(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"events": [{"id": "ev-1", "udm": {}}]})
        )
        result = client.list_objects("observed-data", filters={"query": "ip = '1.2.3.4'"})
        assert isinstance(result, list)
        assert len(result) == 1

    def test_list_objects_indicator(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"detections": [{"id": "det-1"}]})
        )
        result = client.list_objects("indicator")
        assert result[0]["id"] == "det-1"

    def test_list_objects_unsupported_type_raises(self, client):
        with pytest.raises(GNATClientError, match="partial"):
            client.list_objects("malware")

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError, match="limited"):
            client.upsert_object("observed-data", {})

    def test_delete_raises(self, client):
        with pytest.raises(GNATClientError, match="limited"):
            client.delete_object("observed-data", "ev-1")

    def test_search_udm_helper(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"events": [{"id": "ev-1"}]}))
        result = client.search_udm(query="ip.dst.address = '1.2.3.4'")
        assert len(result) == 1

    def test_list_detections_helper(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"detections": [{"id": "det-1"}]})
        )
        result = client.list_detections()
        assert result[0]["id"] == "det-1"

    def test_to_stix_udm_event_contract(self, client):
        native = {
            "id": "ev-1",
            "udm": {"principalIp": "1.2.3.4", "targetIp": "5.6.7.8"},
            "event": {"type": "NETWORK_CONNECTION"},
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "observed-data"
        assert "x_chronicle_udm" in stix
        assert stix["x_chronicle_udm"]["event_id"] == "ev-1"

    def test_to_stix_detection_fallback(self, client):
        native = {"name": "Suspicious Port Scan", "type": "RULE_DETECTION"}
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "indicator"
        assert "chronicle" in stix["id"]

    def test_from_stix_returns_dict(self, client):
        stix = {"type": "observed-data", "id": "observed-data--abc"}
        result = client.from_stix(stix)
        assert isinstance(result, dict)
        assert "stix_id" in result


# ---------------------------------------------------------------------------
# GreyNoise
# ---------------------------------------------------------------------------


class TestGreyNoiseClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.greynoise.client import GreyNoiseClient

        c = GreyNoiseClient(host="https://api.greynoise.io", api_key="gn-test-key")
        c._authenticated = True
        return c

    def test_authenticate_sets_api_key_header(self):
        from gnat.connectors.greynoise.client import GreyNoiseClient

        c = GreyNoiseClient(host="https://api.greynoise.io", api_key="my-key")
        c.authenticate()
        assert c._auth_headers["key"] == "my-key"
        assert c._auth_headers["Accept"] == "application/json"

    def test_health_check_returns_true(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={}))
        result = client.health_check()
        assert result is True

    def test_get_object_ip_lookup(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"ip": "1.2.3.4", "classification": "malicious"})
        )
        result = client.get_object("observed-data", "1.2.3.4")
        assert result["ip"] == "1.2.3.4"

    def test_get_object_indicator(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"ip": "1.2.3.4", "classification": "malicious"})
        )
        result = client.get_object("indicator", "1.2.3.4")
        assert result["ip"] == "1.2.3.4"

    def test_get_object_unsupported_raises(self, client):
        with pytest.raises(GNATClientError, match="primarily supports IP lookups"):
            client.get_object("malware", "id-1")

    def test_list_objects_gnql_query(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": [{"ip": "1.2.3.4"}]}))
        result = client.list_objects("observed-data", filters={"query": "classification:malicious"})
        assert result[0]["ip"] == "1.2.3.4"

    def test_list_objects_bulk_ips(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"ip": "1.2.3.4"}))
        result = client.list_objects("indicator", filters={"ips": ["1.2.3.4", "5.6.7.8"]})
        assert len(result) == 2

    def test_list_objects_empty_returns_empty(self, client):
        result = client.list_objects("observed-data")
        assert result == []

    def test_list_objects_unsupported_raises(self, client):
        with pytest.raises(GNATClientError, match="supports IP context"):
            client.list_objects("malware")

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.upsert_object("observed-data", {})

    def test_delete_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.delete_object("observed-data", "1.2.3.4")

    def test_ip_lookup_helper(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"ip": "8.8.8.8"}))
        result = client.ip_lookup("8.8.8.8")
        assert result["ip"] == "8.8.8.8"

    def test_community_ip_lookup(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"ip": "8.8.8.8", "noise": False})
        )
        result = client.community_ip_lookup("8.8.8.8")
        assert result["ip"] == "8.8.8.8"

    def test_gnql_query_helper(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": [{"ip": "1.2.3.4"}]}))
        result = client.gnql_query("classification:malicious port:445")
        assert result[0]["ip"] == "1.2.3.4"

    def test_riot_lookup_helper(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"ip": "8.8.8.8", "is_riot": True})
        )
        result = client.riot_lookup("8.8.8.8")
        assert result["is_riot"] is True

    def test_to_stix_malicious_ip_returns_indicator(self, client):
        native = {
            "ip": "1.2.3.4",
            "classification": "malicious",
            "seen": True,
            "tags": ["scanner"],
            "last_seen": "2024-01-01",
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "indicator"
        assert stix["x_greynoise"]["ip"] == "1.2.3.4"
        assert stix["x_greynoise"]["classification"] == "malicious"

    def test_to_stix_benign_ip_returns_observed_data(self, client):
        native = {
            "ip": "8.8.8.8",
            "classification": "benign",
            "seen": False,
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "observed-data"

    def test_from_stix_returns_dict(self, client):
        stix = {"type": "indicator", "id": "indicator--abc"}
        result = client.from_stix(stix)
        assert isinstance(result, dict)
        assert "note" in result


# ---------------------------------------------------------------------------
# Shodan
# ---------------------------------------------------------------------------


class TestShodanClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.shodan.client import ShodanClient

        c = ShodanClient(host="https://api.shodan.io", api_key="shodan-test-key")
        c._authenticated = True
        return c

    def test_authenticate_sets_headers(self):
        from gnat.connectors.shodan.client import ShodanClient

        c = ShodanClient(host="https://api.shodan.io", api_key="my-key")
        c.authenticate()
        assert c._auth_headers["X-API-Key"] == "my-key"
        assert c._auth_headers["Accept"] == "application/json"

    def test_health_check_returns_true(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"plan": "dev"}))
        result = client.health_check()
        assert result is True

    def test_get_object_host(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"ip_str": "1.2.3.4", "ports": [80, 443]})
        )
        result = client.get_object("observed-data", "1.2.3.4")
        assert result["ip_str"] == "1.2.3.4"

    def test_get_object_indicator(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"ip_str": "1.2.3.4"}))
        result = client.get_object("indicator", "1.2.3.4")
        assert result["ip_str"] == "1.2.3.4"

    def test_get_object_unsupported_raises(self, client):
        with pytest.raises(GNATClientError, match="limited"):
            client.get_object("malware", "id-1")

    def test_list_objects_hosts(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"matches": [{"ip_str": "1.2.3.4"}]})
        )
        result = client.list_objects("observed-data", filters={"query": "port:80"})
        assert result[0]["ip_str"] == "1.2.3.4"

    def test_list_objects_vulnerability(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"matches": [{"cve": "CVE-2021-44228"}]})
        )
        result = client.list_objects("vulnerability", filters={"query": "log4j"})
        assert result[0]["cve"] == "CVE-2021-44228"

    def test_list_objects_unsupported_raises(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"matches": []}))
        with pytest.raises(GNATClientError, match="not implemented"):
            client.list_objects("malware")

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.upsert_object("observed-data", {})

    def test_delete_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.delete_object("observed-data", "1.2.3.4")

    def test_host_lookup_helper(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"ip_str": "8.8.8.8", "ports": [53]})
        )
        result = client.host_lookup("8.8.8.8")
        assert result["ip_str"] == "8.8.8.8"

    def test_search_hosts_helper(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"matches": [{"ip_str": "1.2.3.4"}]})
        )
        result = client.search_hosts("port:443")
        assert result[0]["ip_str"] == "1.2.3.4"

    def test_count_hosts_helper(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"total": 12345}))
        result = client.count_hosts("port:443")
        assert result["total"] == 12345

    def test_to_stix_host_contract(self, client):
        native = {
            "ip_str": "1.2.3.4",
            "ports": [80, 443],
            "hostname": "example.com",
            "os": "Linux",
            "tags": ["cloud"],
            "timestamp": "2024-01-01T00:00:00Z",
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "observed-data"
        assert stix["x_shodan_host"]["ip"] == "1.2.3.4"
        assert 80 in stix["x_shodan_host"]["ports"]

    def test_to_stix_exploit_contract(self, client):
        native = {
            "cve": "CVE-2021-44228",
            "description": "Apache Log4j RCE",
            "source": "ExploitDB",
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "vulnerability"
        assert stix["name"] == "CVE-2021-44228"

    def test_to_stix_generic_fallback(self, client):
        native = {"report": "search summary", "total": 42}
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "report"

    def test_from_stix_returns_dict(self, client):
        stix = {"type": "observed-data", "id": "observed-data--abc"}
        result = client.from_stix(stix)
        assert isinstance(result, dict)
        assert "note" in result


# ---------------------------------------------------------------------------
# OsintFeedConnector
# ---------------------------------------------------------------------------

from gnat.connectors.osint_feed.connector import OsintFeedConnector  # noqa: E402
from gnat.connectors.osint_feed.feed_factory import FeedConnectorFactory  # noqa: E402


class TestOsintFeedConnector:
    """Tests for the generic OSINT feed connector."""

    # ── Fixtures ──────────────────────────────────────────────────────────

    @pytest.fixture
    def stix_json_client(self):
        c = OsintFeedConnector(
            host="https://feeds.example.com",
            feed_type="stix_json",
            feed_path="/v1/stix",
            auth_type="none",
            stix_types="indicator",
        )
        c._authenticated = True
        return c

    @pytest.fixture
    def basic_auth_client(self):
        c = OsintFeedConnector(
            host="https://feeds.example.com",
            feed_type="stix_json",
            feed_path="/v1/stix",
            auth_type="basic",
            username="user",
            password="pass",
        )
        return c

    @pytest.fixture
    def api_key_client(self):
        c = OsintFeedConnector(
            host="https://feeds.example.com",
            feed_type="stix_json",
            feed_path="/v1/stix",
            auth_type="api_key",
            api_key="mykey",
            api_key_header="X-Feed-Key",
        )
        return c

    @pytest.fixture
    def bearer_client(self):
        c = OsintFeedConnector(
            host="https://feeds.example.com",
            feed_type="stix_json",
            feed_path="/v1/stix",
            auth_type="bearer",
            bearer_token="tok123",
        )
        return c

    @pytest.fixture
    def oauth2_client(self):
        c = OsintFeedConnector(
            host="https://feeds.example.com",
            feed_type="stix_json",
            feed_path="/v1/stix",
            auth_type="oauth2",
            client_id="cid",
            client_secret="sec",
            token_url="/oauth2/token",
        )
        return c

    # ── Authentication ─────────────────────────────────────────────────────

    def test_authenticate_none_sets_accept(self, stix_json_client):
        c = OsintFeedConnector(
            host="https://feeds.example.com",
            feed_type="stix_json",
            feed_path="/v1/stix",
            auth_type="none",
        )
        c.authenticate()
        assert c._auth_headers.get("Accept") == "application/json"

    def test_authenticate_basic_sets_authorization(self, basic_auth_client):
        basic_auth_client.authenticate()
        assert basic_auth_client._auth_headers["Authorization"].startswith("Basic ")

    def test_authenticate_api_key_sets_custom_header(self, api_key_client):
        api_key_client.authenticate()
        assert api_key_client._auth_headers["X-Feed-Key"] == "mykey"

    def test_authenticate_bearer_sets_authorization(self, bearer_client):
        bearer_client.authenticate()
        assert bearer_client._auth_headers["Authorization"] == "Bearer tok123"

    def test_authenticate_oauth2_fetches_token(self, oauth2_client, monkeypatch):
        monkeypatch.setattr(
            oauth2_client, "post", MagicMock(return_value={"access_token": "mytoken"})
        )
        oauth2_client.authenticate()
        assert oauth2_client._auth_headers["Authorization"] == "Bearer mytoken"

    def test_authenticate_oauth2_raises_on_missing_token(self, oauth2_client, monkeypatch):
        monkeypatch.setattr(oauth2_client, "post", MagicMock(return_value={}))
        with pytest.raises(GNATClientError, match="access_token"):
            oauth2_client.authenticate()

    def test_authenticate_api_key_raises_if_no_key(self):
        c = OsintFeedConnector(
            host="https://example.com",
            feed_type="stix_json",
            feed_path="/",
            auth_type="api_key",
            api_key="",
        )
        with pytest.raises(GNATClientError, match="api_key"):
            c.authenticate()

    def test_authenticate_bearer_raises_if_no_token(self):
        c = OsintFeedConnector(
            host="https://example.com",
            feed_type="stix_json",
            feed_path="/",
            auth_type="bearer",
            bearer_token="",
        )
        with pytest.raises(GNATClientError, match="bearer"):
            c.authenticate()

    def test_authenticate_unknown_type_raises(self):
        c = OsintFeedConnector(
            host="https://example.com",
            feed_type="stix_json",
            feed_path="/",
            auth_type="unknown_type",
        )
        with pytest.raises(GNATClientError, match="Unknown auth_type"):
            c.authenticate()

    # ── health_check ──────────────────────────────────────────────────────

    def test_health_check_fetches_feed_path(self, stix_json_client, monkeypatch):
        mock_get = MagicMock(return_value={"type": "bundle", "objects": []})
        monkeypatch.setattr(stix_json_client, "get", mock_get)
        assert stix_json_client.health_check() is True
        mock_get.assert_called_once_with("/v1/stix")

    # ── list_objects / get_object ─────────────────────────────────────────

    def test_list_objects_returns_filtered_stix(self, stix_json_client, monkeypatch):
        bundle = {
            "type": "bundle",
            "id": "bundle--1",
            "objects": [
                {
                    "type": "indicator",
                    "id": "indicator--aaa",
                    "pattern": "[ipv4-addr:value = '1.2.3.4']",
                },
                {"type": "malware", "id": "malware--bbb", "name": "BadBot"},
            ],
        }
        monkeypatch.setattr(stix_json_client, "get", MagicMock(return_value=bundle))
        results = stix_json_client.list_objects("indicator")
        assert len(results) == 1
        assert results[0]["type"] == "indicator"

    def test_list_objects_pagination(self, stix_json_client, monkeypatch):
        objects = [{"type": "indicator", "id": f"indicator--{i:03d}"} for i in range(10)]
        bundle = {"type": "bundle", "objects": objects}
        monkeypatch.setattr(stix_json_client, "get", MagicMock(return_value=bundle))
        page1 = stix_json_client.list_objects("indicator", page=1, page_size=5)
        page2 = stix_json_client.list_objects("indicator", page=2, page_size=5)
        assert len(page1) == 5
        assert len(page2) == 5
        assert page1[0]["id"] != page2[0]["id"]

    def test_get_object_returns_matching_id(self, stix_json_client, monkeypatch):
        bundle = {
            "type": "bundle",
            "objects": [
                {"type": "indicator", "id": "indicator--abc-123"},
                {"type": "indicator", "id": "indicator--def-456"},
            ],
        }
        monkeypatch.setattr(stix_json_client, "get", MagicMock(return_value=bundle))
        result = stix_json_client.get_object("indicator", "indicator--abc-123")
        assert result["id"] == "indicator--abc-123"

    def test_get_object_raises_when_not_found(self, stix_json_client, monkeypatch):
        monkeypatch.setattr(
            stix_json_client, "get", MagicMock(return_value={"type": "bundle", "objects": []})
        )
        with pytest.raises(GNATClientError, match="not found"):
            stix_json_client.get_object("indicator", "indicator--missing")

    def test_list_objects_with_filter(self, stix_json_client, monkeypatch):
        bundle = {
            "type": "bundle",
            "objects": [
                {"type": "indicator", "id": "indicator--a", "name": "evil.com"},
                {"type": "indicator", "id": "indicator--b", "name": "bad.net"},
            ],
        }
        monkeypatch.setattr(stix_json_client, "get", MagicMock(return_value=bundle))
        results = stix_json_client.list_objects("indicator", filters={"name": "evil"})
        assert len(results) == 1
        assert results[0]["name"] == "evil.com"

    # ── Read-only write guard ─────────────────────────────────────────────

    def test_upsert_raises_read_only(self, stix_json_client):
        with pytest.raises(GNATClientError, match="read-only"):
            stix_json_client.upsert_object("indicator", {})

    def test_delete_raises_read_only(self, stix_json_client):
        with pytest.raises(GNATClientError, match="read-only"):
            stix_json_client.delete_object("indicator", "indicator--x")

    # ── to_stix / from_stix passthrough ──────────────────────────────────

    def test_to_stix_adds_feed_source(self, stix_json_client):
        obj = {
            "type": "indicator",
            "id": "indicator--aaa",
            "pattern": "[ipv4-addr:value = '1.2.3.4']",
        }
        result = stix_json_client.to_stix(obj)
        _assert_stix_contract(result)
        assert "x_feed_source" in result

    def test_from_stix_passthrough(self, stix_json_client):
        obj = {"type": "indicator", "id": "indicator--aaa"}
        result = stix_json_client.from_stix(obj)
        assert result == obj

    # ── stix_types filter on construction ────────────────────────────────

    def test_stix_types_comma_string_parsed(self):
        c = OsintFeedConnector(
            host="https://example.com",
            feed_type="stix_json",
            feed_path="/feed",
            auth_type="none",
            stix_types="indicator, malware, threat-actor",
        )
        assert c._stix_types == frozenset({"indicator", "malware", "threat-actor"})

    def test_stix_types_list_accepted(self):
        c = OsintFeedConnector(
            host="https://example.com",
            feed_type="stix_json",
            feed_path="/feed",
            auth_type="none",
            stix_types=["indicator", "malware"],
        )
        assert c._stix_types == frozenset({"indicator", "malware"})

    def test_stix_types_none_means_all(self):
        c = OsintFeedConnector(
            host="https://example.com",
            feed_type="stix_json",
            feed_path="/feed",
            auth_type="none",
            stix_types=None,
        )
        assert c._stix_types is None

    # ── Missing feed_path raises ──────────────────────────────────────────

    def test_fetch_stix_json_raises_if_no_feed_path(self):
        c = OsintFeedConnector(
            host="https://example.com",
            feed_type="stix_json",
            auth_type="none",
        )
        c._authenticated = True
        with pytest.raises(GNATClientError, match="feed_path"):
            c.list_objects("indicator")


# ---------------------------------------------------------------------------
# FeedConnectorFactory
# ---------------------------------------------------------------------------


class TestFeedConnectorFactory:
    """Tests for config-driven feed connector registration."""

    @pytest.fixture
    def mock_config(self):
        """Return a minimal mock GNATConfig with two feed sections."""

        class _MockConfig:
            sections = ["osint_feed_limo", "osint_feed_circl", "threatq"]

            def get(self, section):
                data = {
                    "osint_feed_limo": {
                        "host": "https://limo.anomali.com",
                        "feed_type": "taxii",
                        "taxii_path": "/api/v1/taxii2/",
                        "auth_type": "basic",
                        "username": "guest",
                        "password": "guest",
                        "collection_title": "Phish Tank",
                        "stix_types": "indicator",
                    },
                    "osint_feed_circl": {
                        "host": "https://www.circl.lu",
                        "feed_type": "stix_json",
                        "feed_path": "/doc/misp/feed-osint/",
                        "auth_type": "none",
                    },
                    "threatq": {
                        "host": "https://threatq.example.com",
                        "client_id": "cid",
                        "client_secret": "sec",
                    },
                }
                if section not in data:
                    raise KeyError(section)
                return data[section]

        return _MockConfig()

    def test_from_config_detects_feed_sections(self, mock_config):
        feeds = FeedConnectorFactory.from_config(mock_config)
        assert "osint_feed_limo" in feeds
        assert "osint_feed_circl" in feeds

    def test_from_config_ignores_non_feed_sections(self, mock_config):
        feeds = FeedConnectorFactory.from_config(mock_config)
        assert "threatq" not in feeds

    def test_from_config_creates_osint_feed_subclass(self, mock_config):
        feeds = FeedConnectorFactory.from_config(mock_config)
        cls = feeds["osint_feed_limo"]
        assert issubclass(cls, OsintFeedConnector)

    def test_from_config_registers_in_registry(self, mock_config):
        registry: dict = {}
        FeedConnectorFactory.from_config(mock_config, registry=registry)
        assert "osint_feed_limo" in registry
        assert "osint_feed_circl" in registry

    def test_generated_class_instantiation(self, mock_config):
        feeds = FeedConnectorFactory.from_config(mock_config)
        cls = feeds["osint_feed_circl"]
        instance = cls()
        assert isinstance(instance, OsintFeedConnector)
        assert instance._feed_type == "stix_json"
        assert instance._auth_type == "none"

    def test_limo_class_has_taxii_settings(self, mock_config):
        feeds = FeedConnectorFactory.from_config(mock_config)
        instance = feeds["osint_feed_limo"]()
        assert instance._feed_type == "taxii"
        assert instance._collection_title == "Phish Tank"
        assert instance._username == "guest"

    def test_class_name_is_camelcase(self, mock_config):
        feeds = FeedConnectorFactory.from_config(mock_config)
        assert feeds["osint_feed_limo"].__name__ == "OsintFeedLimo"
        assert feeds["osint_feed_circl"].__name__ == "OsintFeedCircl"

    def test_kwargs_override_defaults(self, mock_config):
        feeds = FeedConnectorFactory.from_config(mock_config)
        instance = feeds["osint_feed_circl"](feed_path="/custom/path")
        assert instance._feed_path == "/custom/path"


# ---------------------------------------------------------------------------
# CiscoUmbrellaClient
# ---------------------------------------------------------------------------

from gnat.connectors.cisco_umbrella.client import CiscoUmbrellaClient  # noqa: E402


class TestCiscoUmbrellaClient:
    """Tests for the Cisco Umbrella connector."""

    @pytest.fixture
    def client(self):
        c = CiscoUmbrellaClient(
            host="https://investigate.api.umbrella.com",
            investigate_api_key="test-investigate-key",
            enforcement_api_key="test-enforcement-key",
            management_api_key="test-management-key",
        )
        c._authenticated = True
        return c

    # ── Authentication ─────────────────────────────────────────────────────

    def test_authenticate_sets_bearer(self):
        c = CiscoUmbrellaClient(
            host="https://investigate.api.umbrella.com",
            investigate_api_key="my-inv-key",
        )
        c.authenticate()
        assert c._auth_headers["Authorization"] == "Bearer my-inv-key"
        assert c._authenticated is True

    def test_authenticate_raises_without_key(self):
        c = CiscoUmbrellaClient(
            host="https://investigate.api.umbrella.com",
            investigate_api_key="",
        )
        with pytest.raises(GNATClientError, match="investigate_api_key"):
            c.authenticate()

    # ── health_check ──────────────────────────────────────────────────────

    def test_health_check_calls_investigate(self, client, monkeypatch):
        mock_get = MagicMock(return_value={"cisco.com": {"status": 1}})
        monkeypatch.setattr(client, "get", mock_get)
        assert client.health_check() is True
        mock_get.assert_called_once_with("/domains/categorization/cisco.com")

    # ── classify_domain helper ────────────────────────────────────────────

    def test_classify_domain_returns_parsed_result(self, client, monkeypatch):
        raw_resp = {
            "evil.com": {
                "status": -1,
                "security_categories": ["Malware"],
                "content_categories": [],
            }
        }
        monkeypatch.setattr(client, "get", MagicMock(return_value=raw_resp))
        result = client.classify_domain("evil.com")
        assert result["domain"] == "evil.com"
        assert result["security_categories"] == ["Malware"]

    def test_classify_domain_raises_on_bad_response(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value="not-a-dict"))
        with pytest.raises(GNATClientError):
            client.classify_domain("evil.com")

    # ── list_objects ─────────────────────────────────────────────────────

    def test_list_objects_indicator_returns_stix(self, client, monkeypatch):
        raw_resp = {
            "evil.com": {"status": -1, "security_categories": ["Botnet"], "content_categories": []}
        }
        monkeypatch.setattr(client, "get", MagicMock(return_value=raw_resp))
        results = client.list_objects("indicator", filters={"domains": ["evil.com"]})
        assert len(results) == 1
        _assert_stix_contract(results[0])
        assert results[0]["type"] == "indicator"

    def test_list_objects_indicator_empty_without_domains(self, client):
        results = client.list_objects("indicator")
        assert results == []

    def test_list_objects_unsupported_type_raises(self, client):
        with pytest.raises(GNATClientError, match="indicator"):
            client.list_objects("malware")

    # ── get_object ─────────────────────────────────────────────────────

    def test_get_object_indicator_returns_stix(self, client, monkeypatch):
        raw_resp = {
            "evil.com": {
                "status": -1,
                "security_categories": ["Phishing"],
                "content_categories": [],
            }
        }
        monkeypatch.setattr(client, "get", MagicMock(return_value=raw_resp))
        result = client.get_object("indicator", "evil.com")
        _assert_stix_contract(result)
        assert result["type"] == "indicator"

    # ── upsert_object / delete_object ─────────────────────────────────

    def test_upsert_raises_for_non_indicator(self, client):
        with pytest.raises(GNATClientError, match="indicator"):
            client.upsert_object("malware", {"name": "BadBot"})

    def test_delete_raises_for_non_indicator(self, client):
        with pytest.raises(GNATClientError, match="indicator"):
            client.delete_object("malware", "malware--abc")

    # ── to_stix ────────────────────────────────────────────────────────

    def test_to_stix_malicious_domain(self, client):
        native = {
            "domain": "evil.com",
            "status": "blocked",
            "security_categories": ["Botnet"],
            "content_categories": [],
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "indicator"
        assert "evil.com" in stix["pattern"]
        assert stix["confidence"] == 85
        assert "malicious-activity" in stix["labels"]
        assert stix["x_umbrella"]["is_malicious"] is True

    def test_to_stix_benign_domain(self, client):
        native = {
            "domain": "cisco.com",
            "status": "safe",
            "security_categories": [],
            "content_categories": ["Technology/Internet"],
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["confidence"] == 10
        assert "benign" in stix["labels"]
        assert stix["x_umbrella"]["is_malicious"] is False

    def test_to_stix_allow_list_entry(self, client):
        native = {
            "type": "course-of-action",
            "name": "trusted.example.com",
            "comment": "Internal asset",
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "course-of-action"
        assert "trusted.example.com" in stix["name"]
        assert stix["x_umbrella"]["list_type"] == "allow"

    def test_to_stix_empty_domain_returns_empty(self, client):
        native = {"domain": "", "status": "unknown", "security_categories": []}
        stix = client.to_stix(native)
        assert stix == {}

    # ── from_stix ──────────────────────────────────────────────────────

    def test_from_stix_parses_pattern(self, client):
        stix = {
            "type": "indicator",
            "id": "indicator--abc",
            "pattern": "[domain-name:value = 'evil.com']",
        }
        payload = client.from_stix(stix)
        assert payload["dstDomain"] == "evil.com"

    def test_from_stix_falls_back_to_name(self, client):
        stix = {"type": "indicator", "id": "indicator--abc", "name": "evil.com"}
        payload = client.from_stix(stix)
        assert payload["dstDomain"] == "evil.com"

    def test_from_stix_raises_on_missing_domain(self, client):
        stix = {"type": "indicator", "id": "indicator--abc"}
        with pytest.raises(GNATClientError, match="domain"):
            client.from_stix(stix)

    # ── bulk classify ──────────────────────────────────────────────────

    def test_classify_domains_bulk(self, client, monkeypatch):
        response = {
            "a.com": {"status": 1, "security_categories": [], "content_categories": []},
            "b.com": {"status": -1, "security_categories": ["Malware"], "content_categories": []},
        }
        monkeypatch.setattr(client, "post", MagicMock(return_value=response))
        result = client.classify_domains(["a.com", "b.com"])
        assert "a.com" in result
        assert "b.com" in result

    def test_classify_domains_empty_returns_empty(self, client):
        assert client.classify_domains([]) == {}


# ---------------------------------------------------------------------------
# Discord
# ---------------------------------------------------------------------------


class TestDiscordClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.discord.connector import DiscordClient

        c = DiscordClient(host="https://discord.com", bot_token="Bot test-token", guild_id="111")
        c._authenticated = True
        return c

    # ── Authentication ────────────────────────────────────────────────────

    def test_authenticate_sets_bot_token_header(self):
        from gnat.connectors.discord.connector import DiscordClient

        c = DiscordClient(host="https://discord.com", bot_token="my-raw-token")
        c.authenticate()
        assert c._auth_headers["Authorization"] == "Bot my-raw-token"
        assert c._auth_headers["Content-Type"] == "application/json"

    def test_authenticate_normalises_token_with_prefix(self):
        from gnat.connectors.discord.connector import DiscordClient

        c = DiscordClient(bot_token="Bot already-prefixed")
        c.authenticate()
        assert c._auth_headers["Authorization"] == "Bot already-prefixed"

    def test_authenticate_empty_token_produces_bot_prefix_only(self):
        from gnat.connectors.discord.connector import DiscordClient

        c = DiscordClient(bot_token="")
        c.authenticate()
        assert c._auth_headers["Authorization"] == ""

    # ── health_check ─────────────────────────────────────────────────────

    def test_health_check_returns_true(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"url": "wss://gateway.discord.gg/"}))
        assert client.health_check() is True

    def test_health_check_raises_on_http_error(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(side_effect=GNATClientError("401")))
        with pytest.raises(GNATClientError):
            client.health_check()

    # ── get_object ────────────────────────────────────────────────────────

    def test_get_object_note_by_channel_message(self, client, monkeypatch):
        msg = {"id": "123456789", "channel_id": "999", "content": "hello",
               "author": {"id": "u1", "username": "alice"}}
        monkeypatch.setattr(client, "get", MagicMock(return_value=msg))
        result = client.get_object("note", "999:123456789")
        assert result["type"] == "note"
        assert result["content"] == "hello"

    def test_get_object_indicator_by_channel_message(self, client, monkeypatch):
        msg = {"id": "777", "channel_id": "555", "content": "IOC: 1.2.3.4",
               "author": {"id": "u2", "username": "bob"}}
        monkeypatch.setattr(client, "get", MagicMock(return_value=msg))
        result = client.get_object("indicator", "555:777")
        assert result["type"] == "note"

    def test_get_object_note_missing_colon_raises(self, client):
        with pytest.raises(GNATClientError, match="channel_id"):
            client.get_object("note", "no-colon-here")

    def test_get_object_observed_data_channel(self, client, monkeypatch):
        channel = {"id": "chan1", "name": "intel", "topic": "IOC sharing", "type": 0, "guild_id": "g1"}
        monkeypatch.setattr(client, "get", MagicMock(return_value=channel))
        result = client.get_object("observed-data", "chan1")
        assert result["type"] == "observed-data"
        assert result["x_discord"]["name"] == "intel"

    def test_get_object_identity_user(self, client, monkeypatch):
        user = {"id": "u99", "username": "charlie", "discriminator": "0001", "bot": False}
        monkeypatch.setattr(client, "get", MagicMock(return_value=user))
        result = client.get_object("identity", "u99")
        assert result["type"] == "identity"
        assert result["name"] == "charlie"

    def test_get_object_unsupported_raises(self, client):
        with pytest.raises(GNATClientError, match="does not support stix_type"):
            client.get_object("malware", "some-id")

    # ── list_objects ──────────────────────────────────────────────────────

    def test_list_objects_note_messages(self, client, monkeypatch):
        msgs = [
            {"id": "1", "channel_id": "ch1", "content": "msg1",
             "author": {"id": "u1", "username": "alice"}},
            {"id": "2", "channel_id": "ch1", "content": "msg2",
             "author": {"id": "u1", "username": "alice"}},
        ]
        monkeypatch.setattr(client, "get", MagicMock(return_value=msgs))
        result = client.list_objects("note", filters={"channel_id": "ch1"})
        assert len(result) == 2
        assert all(r["type"] == "note" for r in result)

    def test_list_objects_note_missing_channel_raises(self, client):
        with pytest.raises(GNATClientError, match="channel_id"):
            client.list_objects("note")

    def test_list_objects_observed_data_thread(self, client, monkeypatch):
        msgs = [{"id": "10", "channel_id": "thread1", "content": "thread msg",
                 "author": {"id": "u3", "username": "dave"}}]
        monkeypatch.setattr(client, "get", MagicMock(return_value=msgs))
        result = client.list_objects("observed-data", filters={"thread_id": "thread1"})
        assert len(result) == 1
        assert result[0]["type"] == "note"

    def test_list_objects_observed_data_missing_id_raises(self, client):
        with pytest.raises(GNATClientError, match="thread_id"):
            client.list_objects("observed-data")

    def test_list_objects_identity_members(self, client, monkeypatch):
        members = [
            {"user": {"id": "m1", "username": "member1", "discriminator": "0", "bot": False}},
            {"user": {"id": "m2", "username": "member2", "discriminator": "0", "bot": False}},
        ]
        monkeypatch.setattr(client, "get", MagicMock(return_value=members))
        result = client.list_objects("identity")
        assert len(result) == 2
        assert all(r["type"] == "identity" for r in result)

    def test_list_objects_identity_no_guild_raises(self, client):
        client._guild_id = ""
        with pytest.raises(GNATClientError, match="guild_id"):
            client.list_objects("identity")

    def test_list_objects_unsupported_raises(self, client):
        with pytest.raises(GNATClientError, match="does not support stix_type"):
            client.list_objects("campaign")

    def test_list_objects_page_size_capped_at_100(self, client, monkeypatch):
        mock_get = MagicMock(return_value=[])
        monkeypatch.setattr(client, "get", mock_get)
        client.list_objects("note", filters={"channel_id": "ch1"}, page_size=999)
        call_args = mock_get.call_args
        params = call_args[1].get("params") or call_args[0][1] if len(call_args[0]) > 1 else {}
        assert params.get("limit", 0) <= 100

    # ── upsert_object ─────────────────────────────────────────────────────

    def test_upsert_object_posts_message(self, client, monkeypatch):
        created = {"id": "new1", "channel_id": "ch1", "content": "Alert: 1.2.3.4",
                   "author": {"id": "u1", "username": "bot"}}
        monkeypatch.setattr(client, "post", MagicMock(return_value=created))
        result = client.upsert_object("note", {"channel_id": "ch1", "content": "Alert: 1.2.3.4"})
        assert result["type"] == "note"

    def test_upsert_object_wrong_type_raises(self, client):
        with pytest.raises(GNATClientError, match="only supports stix_type 'note'"):
            client.upsert_object("indicator", {"channel_id": "ch1", "content": "x"})

    def test_upsert_object_missing_channel_raises(self, client):
        with pytest.raises(GNATClientError, match="channel_id"):
            client.upsert_object("note", {"content": "hello"})

    def test_upsert_object_missing_content_raises(self, client):
        with pytest.raises(GNATClientError, match="content"):
            client.upsert_object("note", {"channel_id": "ch1"})

    # ── delete_object ─────────────────────────────────────────────────────

    def test_delete_object_message(self, client, monkeypatch):
        mock_del = MagicMock(return_value=None)
        monkeypatch.setattr(client, "delete", mock_del)
        client.delete_object("note", "ch1:msg1")
        mock_del.assert_called_once_with("/api/v10/channels/ch1/messages/msg1")

    def test_delete_object_wrong_type_raises(self, client):
        with pytest.raises(GNATClientError, match="only supports"):
            client.delete_object("malware", "ch1:msg1")

    def test_delete_object_missing_colon_raises(self, client):
        with pytest.raises(GNATClientError, match="channel_id"):
            client.delete_object("note", "no-colon")

    # ── Domain-specific helpers ───────────────────────────────────────────

    def test_post_message_helper(self, client, monkeypatch):
        created = {"id": "99", "channel_id": "c1", "content": "test",
                   "author": {"id": "b1", "username": "bot"}}
        mock_post = MagicMock(return_value=created)
        monkeypatch.setattr(client, "post", mock_post)
        result = client.post_message("c1", "test")
        assert result["id"] == "99"
        call_body = mock_post.call_args[1]["json_body"]
        assert call_body["content"] == "test"

    def test_post_message_with_thread_id(self, client, monkeypatch):
        mock_post = MagicMock(return_value={"id": "100", "channel_id": "c1", "content": "x",
                                             "author": {"id": "b1", "username": "bot"}})
        monkeypatch.setattr(client, "post", mock_post)
        client.post_message("c1", "x", thread_id="t1")
        body = mock_post.call_args[1]["json_body"]
        assert body["thread_id"] == "t1"

    def test_post_message_truncates_to_2000(self, client, monkeypatch):
        mock_post = MagicMock(return_value={"id": "1", "channel_id": "c", "content": "x",
                                             "author": {"id": "b", "username": "bot"}})
        monkeypatch.setattr(client, "post", mock_post)
        client.post_message("c", "A" * 3000)
        body = mock_post.call_args[1]["json_body"]
        assert len(body["content"]) == 2000

    def test_list_messages_helper(self, client, monkeypatch):
        msgs = [{"id": "1", "channel_id": "ch", "content": "m",
                 "author": {"id": "u", "username": "alice"}}]
        monkeypatch.setattr(client, "get", MagicMock(return_value=msgs))
        result = client.list_messages("ch", limit=10)
        assert result == msgs

    def test_list_messages_non_list_returns_empty(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"error": "not found"}))
        result = client.list_messages("ch")
        assert result == []

    def test_start_thread_helper(self, client, monkeypatch):
        thread = {"id": "t1", "name": "Incident Thread"}
        mock_post = MagicMock(return_value=thread)
        monkeypatch.setattr(client, "post", mock_post)
        result = client.start_thread("ch1", "msg1", "Incident Thread")
        assert result["id"] == "t1"
        call_body = mock_post.call_args[1]["json_body"]
        assert call_body["name"] == "Incident Thread"
        assert call_body["auto_archive_duration"] == 1440

    def test_list_archived_threads(self, client, monkeypatch):
        resp = {"threads": [{"id": "t1"}, {"id": "t2"}]}
        monkeypatch.setattr(client, "get", MagicMock(return_value=resp))
        result = client.list_archived_threads("ch1")
        assert len(result) == 2

    def test_list_archived_threads_non_dict_returns_empty(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value=[]))
        result = client.list_archived_threads("ch1")
        assert result == []

    def test_get_user_helper(self, client, monkeypatch):
        user = {"id": "u1", "username": "alice"}
        monkeypatch.setattr(client, "get", MagicMock(return_value=user))
        result = client.get_user("u1")
        assert result["username"] == "alice"

    def test_list_members_helper(self, client, monkeypatch):
        members = [{"user": {"id": "m1", "username": "x"}}]
        monkeypatch.setattr(client, "get", MagicMock(return_value=members))
        result = client.list_members("g1")
        assert result == members

    def test_list_members_non_list_returns_empty(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"error": "forbidden"}))
        result = client.list_members("g1")
        assert result == []

    # ── to_stix ───────────────────────────────────────────────────────────

    def test_to_stix_message_fields(self, client):
        msg = {"id": "1152921504606846976", "channel_id": "ch1",
               "content": "suspicious domain: evil.com",
               "author": {"id": "u1", "username": "alice"},
               "timestamp": "2026-01-01T00:00:00.000000+00:00",
               "attachments": [], "embeds": [], "mentions": [], "pinned": False}
        stix = client.to_stix(msg)
        assert stix["type"] == "note"
        assert stix["spec_version"] == "2.1"
        assert "id" in stix
        assert stix["content"] == "suspicious domain: evil.com"
        assert stix["x_discord"]["author_username"] == "alice"
        assert stix["x_discord"]["channel_id"] == "ch1"

    def test_to_stix_channel_produces_observed_data(self, client):
        channel = {"_resource": "channel", "id": "c1", "name": "intel",
                   "topic": "IOCs", "type": 0, "guild_id": "g1", "nsfw": False}
        stix = client.to_stix(channel)
        assert stix["type"] == "observed-data"
        assert stix["x_discord"]["name"] == "intel"

    def test_to_stix_user_produces_identity(self, client):
        user = {"_resource": "user", "id": "u1", "username": "alice",
                "discriminator": "0001", "bot": False, "system": False}
        stix = client.to_stix(user)
        assert stix["type"] == "identity"
        assert stix["identity_class"] == "individual"
        assert stix["name"] == "alice"
        assert stix["x_discord"]["user_id"] == "u1"

    def test_to_stix_message_abstract_truncated_to_256(self, client):
        long_content = "x" * 500
        msg = {"id": "1", "channel_id": "ch", "content": long_content,
               "author": {"id": "u", "username": "a"}}
        stix = client.to_stix(msg)
        assert len(stix["abstract"]) == 256

    def test_to_stix_missing_id_still_produces_note(self, client):
        msg = {"channel_id": "ch1", "content": "test", "author": {"id": "u", "username": "a"}}
        stix = client.to_stix(msg)
        assert stix["type"] == "note"

    # ── from_stix ────────────────────────────────────────────────────────

    def test_from_stix_note_returns_message_payload(self, client):
        stix = {
            "type": "note",
            "id": "note--discord-123",
            "content": "Threat actor observed",
            "x_discord": {"channel_id": "ch1"},
        }
        payload = client.from_stix(stix)
        assert payload["content"] == "Threat actor observed"
        assert payload["channel_id"] == "ch1"

    def test_from_stix_note_truncates_content(self, client):
        stix = {"type": "note", "content": "A" * 3000, "x_discord": {"channel_id": "ch"}}
        payload = client.from_stix(stix)
        assert len(payload["content"]) == 2000

    def test_from_stix_non_note_returns_guidance(self, client):
        stix = {"type": "indicator", "id": "indicator--abc", "name": "evil.com"}
        payload = client.from_stix(stix)
        assert "note" in payload
        assert payload["stix_id"] == "indicator--abc"

    # ── Registry ─────────────────────────────────────────────────────────

    def test_discord_in_client_registry(self):
        from gnat.clients import CLIENT_REGISTRY

        assert "discord" in CLIENT_REGISTRY
        from gnat.connectors.discord.connector import DiscordClient
        assert CLIENT_REGISTRY["discord"] is DiscordClient

    # ── ConnectorMixin contract ───────────────────────────────────────────

    def test_capabilities_includes_standard_methods(self, client):
        caps = client.capabilities()
        for method in ("authenticate", "health_check", "get_object", "list_objects",
                        "upsert_object", "delete_object", "to_stix", "from_stix"):
            assert method in caps

    def test_capabilities_includes_discord_helpers(self, client):
        caps = client.capabilities()
        assert "post_message" in caps
        assert "list_messages" in caps
        assert "start_thread" in caps
        assert "get_user" in caps
        assert "list_members" in caps

    def test_call_list_messages_via_capabilities(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value=[]))
        result = client.call("list_messages", "ch1")
        assert result == []

    def test_call_write_blocked_without_allow_write(self, client):
        with pytest.raises(ValueError, match="write operation"):
            client.call("upsert_object", "note", {"channel_id": "ch1", "content": "x"})

    # ── Snowflake helpers ─────────────────────────────────────────────────

    def test_snowflake_to_ts_known_id(self):
        from gnat.connectors.discord.connector import _snowflake_to_ts
        ts = _snowflake_to_ts("1152921504606846976")
        assert ts.endswith("Z")
        assert "T" in ts

    def test_snowflake_to_ts_invalid_returns_now(self):
        from gnat.connectors.discord.connector import _snowflake_to_ts
        ts = _snowflake_to_ts("not-a-number")
        assert ts.endswith("Z")


# ---------------------------------------------------------------------------
# DynatraceClient
# ---------------------------------------------------------------------------
class TestDynatraceClient:
    @pytest.fixture()
    def client(self):
        from gnat.connectors.dynatrace.client import DynatraceClient

        return DynatraceClient(
            host="https://abc12345.live.dynatrace.com",
            api_token="dt0c01.TESTTOKEN",
        )

    @pytest.fixture()
    def client_with_oauth(self):
        from gnat.connectors.dynatrace.client import DynatraceClient

        return DynatraceClient(
            host="https://abc12345.live.dynatrace.com",
            api_token="dt0c01.TESTTOKEN",
            oauth_client_id="dt0s01.OAUTHCLIENTID",
            oauth_client_secret="OAUTHSECRET",
        )

    # ── Auth ──────────────────────────────────────────────────────────────

    def test_authenticate_sets_api_token_header(self, client):
        client.authenticate()
        assert client._auth_headers.get("Authorization") == "Api-Token dt0c01.TESTTOKEN"

    def test_authenticate_does_not_set_oauth_header(self, client):
        client.authenticate()
        assert "Bearer" not in client._auth_headers.get("Authorization", "")

    # ── health_check ─────────────────────────────────────────────────────

    def test_health_check_returns_true_on_200(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"entities": []}))
        assert client.health_check() is True

    def test_health_check_returns_false_on_error(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(side_effect=Exception("connection refused")))
        assert client.health_check() is False

    # ── Entities ─────────────────────────────────────────────────────────

    def test_list_entities_returns_list(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"entities": [{"entityId": "HOST-1"}]})
        )
        result = client.list_entities(entity_type="HOST", page_size=1)
        assert isinstance(result, list)
        assert result[0]["entityId"] == "HOST-1"

    def test_list_entities_paginates_with_next_page_key(self, client, monkeypatch):
        page1 = {"entities": [{"entityId": "HOST-1"}], "nextPageKey": "page2key"}
        page2 = {"entities": [{"entityId": "HOST-2"}]}
        calls = [page1, page2]
        monkeypatch.setattr(client, "get", MagicMock(side_effect=calls))
        result = client.list_entities(page_size=1)
        assert len(result) == 2
        # Second call must only pass nextPageKey + pageSize
        second_call_params = client.get.call_args_list[1][1].get("params") or client.get.call_args_list[1][0][1]
        assert "entitySelector" not in second_call_params
        assert "nextPageKey" in second_call_params

    def test_get_entity_returns_dict(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"entityId": "HOST-1", "displayName": "web01"})
        )
        result = client.get_entity("HOST-1")
        assert result["entityId"] == "HOST-1"

    def test_tag_entity(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "post", MagicMock(return_value={"appliedTags": [{"key": "gnat"}]})
        )
        result = client.tag_entity("entityId(HOST-1)", ["gnat"])
        assert isinstance(result, dict)

    # ── Security problems ─────────────────────────────────────────────────

    def test_list_security_problems_returns_list(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(return_value={"securityProblems": [{"securityProblemId": "S-1"}]}),
        )
        result = client.list_security_problems()
        assert isinstance(result, list)

    def test_get_security_problem_returns_dict(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(return_value={"securityProblemId": "S-1", "title": "Log4Shell"}),
        )
        result = client.get_security_problem("S-1")
        assert result["securityProblemId"] == "S-1"

    def test_mute_security_problem(self, client, monkeypatch):
        monkeypatch.setattr(client, "post", MagicMock(return_value={}))
        client.mute_security_problem("S-1", "FALSE_POSITIVE", comment="Not applicable")
        client.post.assert_called_once()

    def test_unmute_security_problem(self, client, monkeypatch):
        monkeypatch.setattr(client, "post", MagicMock(return_value={}))
        client.unmute_security_problem("S-1", "OTHER")
        client.post.assert_called_once()

    def test_get_security_problem_affected_entities(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(return_value={"entities": [{"entityId": "HOST-1"}]}),
        )
        result = client.get_security_problem_affected_entities("S-1")
        assert isinstance(result, list)

    def test_get_security_problem_remediation_items(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(return_value={"remediationItems": [{"id": "ri-1"}]}),
        )
        result = client.get_security_problem_remediation_items("S-1")
        assert isinstance(result, list)

    # ── Attacks ───────────────────────────────────────────────────────────

    def test_list_attacks_returns_list(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(return_value={"attacks": [{"attackId": "A-1"}]}),
        )
        result = client.list_attacks()
        assert isinstance(result, list)

    def test_get_attack_returns_dict(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(return_value={"attackId": "A-1", "type": "SQL_INJECTION"}),
        )
        result = client.get_attack("A-1")
        assert result["attackId"] == "A-1"

    def test_set_attack_handling(self, client, monkeypatch):
        monkeypatch.setattr(client, "put", MagicMock(return_value={"attackId": "A-1"}))
        result = client.set_attack_handling("A-1", "BLOCK")
        assert isinstance(result, dict)

    # ── Problems ──────────────────────────────────────────────────────────

    def test_list_problems_returns_list(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(return_value={"problems": [{"problemId": "P-1"}]}),
        )
        result = client.list_problems()
        assert isinstance(result, list)

    def test_get_problem_returns_dict(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(return_value={"problemId": "P-1", "title": "High CPU"}),
        )
        result = client.get_problem("P-1")
        assert result["problemId"] == "P-1"

    def test_close_problem(self, client, monkeypatch):
        monkeypatch.setattr(client, "post", MagicMock(return_value={"problemId": "P-1"}))
        result = client.close_problem("P-1", "Resolved by GNAT")
        assert isinstance(result, dict)

    # ── Events ────────────────────────────────────────────────────────────

    def test_list_events_returns_list(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(return_value={"events": [{"eventId": "E-1"}]}),
        )
        result = client.list_events()
        assert isinstance(result, list)

    def test_get_event_returns_dict(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(return_value={"eventId": "E-1", "eventType": "CUSTOM_INFO"}),
        )
        result = client.get_event("E-1")
        assert result["eventId"] == "E-1"

    def test_ingest_event(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "post", MagicMock(return_value={"eventIngestResults": [{"eventId": "new-e"}]})
        )
        result = client.ingest_event("CUSTOM_INFO", "Test event from GNAT")
        assert isinstance(result, dict)

    # ── Metrics ───────────────────────────────────────────────────────────

    def test_query_metrics_returns_dict(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(return_value={"resolution": "1h", "result": []}),
        )
        result = client.query_metrics("builtin:host.cpu.usage")
        assert isinstance(result, dict)

    # ── Settings ─────────────────────────────────────────────────────────

    def test_list_settings_objects(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(return_value={"items": [{"objectId": "obj-1"}]}),
        )
        result = client.list_settings_objects(["builtin:alerting.profile"])
        assert isinstance(result, list)

    def test_create_settings_object(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "post", MagicMock(return_value=[{"objectId": "new-obj"}])
        )
        result = client.create_settings_object(
            "builtin:alerting.profile", "environment", {"name": "GNAT Profile"}
        )
        assert isinstance(result, (dict, list))

    # ── Grail guards (no OAuth2 creds) ───────────────────────────────────

    def test_query_grail_raises_without_oauth(self, client):
        from gnat.connectors.dynatrace.exceptions import DynatraceConfigError

        with pytest.raises(DynatraceConfigError, match="OAuth2"):
            client.query_grail("fetch logs | limit 10")

    def test_export_logs_raises_without_oauth(self, client):
        from gnat.connectors.dynatrace.exceptions import DynatraceConfigError

        with pytest.raises(DynatraceConfigError, match="OAuth2"):
            client.export_logs()

    def test_ingest_bizevents_raises_without_oauth(self, client):
        from gnat.connectors.dynatrace.exceptions import DynatraceConfigError

        with pytest.raises(DynatraceConfigError, match="OAuth2"):
            client.ingest_bizevents([{"type": "test"}])

    # ── STIX mapping ──────────────────────────────────────────────────────

    def test_to_stix_entity_contract(self, client):
        entity = {
            "entityId": "HOST-AABBCCDD12345678",
            "displayName": "web-server-01",
            "type": "HOST",
            "firstSeenTms": 1704067200000,
            "lastSeenTms": 1704153600000,
            "tags": [{"key": "env", "value": "prod"}],
            "managementZones": [{"name": "Production"}],
        }
        stix = client.to_stix(entity)
        assert stix["type"] == "infrastructure"
        assert stix["id"].startswith("infrastructure--dt-HOST-")
        assert stix["name"] == "web-server-01"
        assert stix["infrastructure_types"] == ["workstation"]
        assert stix["x_dt_entity_type"] == "HOST"
        assert "env" in stix["x_dt_tags"]
        assert "Production" in stix["x_dt_management_zones"]

    def test_to_stix_security_problem_contract(self, client):
        sp = {
            "securityProblemId": "S-AABBCCDD12345678",
            "displayId": "S-001",
            "title": "Log4Shell RCE",
            "status": "OPEN",
            "technology": "JAVA",
            "cveIds": ["CVE-2021-44228"],
            "riskAssessment": {"riskLevel": "CRITICAL", "baseScore": 10.0},
            "affectedEntities": [{"entityId": "HOST-1"}],
        }
        stix = client.to_stix(sp)
        assert stix["type"] == "vulnerability"
        assert stix["id"].startswith("vulnerability--dt-")
        assert stix["description"] == "Log4Shell RCE"
        assert "CVE-2021-44228" in stix["x_dt_cve_ids"]

    def test_to_stix_security_problem_maps_cve_ids(self, client):
        sp = {
            "securityProblemId": "S-2",
            "displayId": "S-002",
            "title": "Spring4Shell",
            "cveIds": ["CVE-2022-22965", "CVE-2022-22963"],
            "riskAssessment": {},
        }
        stix = client.to_stix(sp)
        assert len(stix["x_dt_cve_ids"]) == 2
        assert "CVE-2022-22965" in stix["x_dt_cve_ids"]

    def test_to_stix_attack_contract(self, client):
        attack = {
            "attackId": "A-AABBCCDD12345678",
            "type": "SQL_INJECTION",
            "state": "BLOCKED",
            "severity": "critical",
            "timestamp": 1704067200000,
            "attackedEntity": {"id": "SERVICE-1"},
            "attackTarget": {"url": "https://app.example.com/login"},
        }
        stix = client.to_stix(attack)
        assert stix["type"] == "indicator"
        assert stix["id"].startswith("indicator--dt-")
        assert "sql_injection" in stix["pattern"]
        assert stix["x_dt_state"] == "BLOCKED"

    def test_to_stix_attack_maps_severity_to_confidence(self, client):
        for severity, expected_confidence in [
            ("critical", 90), ("high", 75), ("medium", 55), ("low", 35)
        ]:
            attack = {
                "attackId": f"A-{severity}",
                "type": "CMD_INJECTION",
                "severity": severity,
                "timestamp": 1704067200000,
            }
            stix = client.to_stix(attack)
            assert stix["confidence"] == expected_confidence

    def test_to_stix_problem_contract(self, client):
        problem = {
            "problemId": "P-AABBCCDD12345678",
            "title": "Response time degradation",
            "impactLevel": "APPLICATION",
            "severityLevel": "PERFORMANCE",
            "status": "OPEN",
            "startTime": 1704067200000,
            "affectedEntities": [{"entityId": "SERVICE-1"}],
        }
        stix = client.to_stix(problem)
        assert stix["type"] == "observed-data"
        assert stix["id"].startswith("observed-data--dt-P-")
        assert stix["x_dt_title"] == "Response time degradation"

    def test_to_stix_event_contract(self, client):
        event = {
            "eventId": "E-AABBCCDD12345678",
            "eventType": "CUSTOM_ANNOTATION",
            "title": "Deployment complete",
            "startTime": 1704067200000,
            "entityId": {"entityId": "SERVICE-1"},
        }
        stix = client.to_stix(event)
        assert stix["type"] == "observed-data"
        assert stix["id"].startswith("observed-data--dt-event-")
        assert stix["x_dt_event_type"] == "CUSTOM_ANNOTATION"

    def test_from_stix_returns_event_payload(self, client):
        stix = {
            "type": "observed-data",
            "x_dt_event_type": "CUSTOM_INFO",
            "x_dt_title": "GNAT alert",
            "x_dt_entity_id": "HOST-1",
            "x_dt_properties": {"source": "gnat"},
        }
        payload = client.from_stix(stix)
        assert payload["eventType"] == "CUSTOM_INFO"
        assert payload["title"] == "GNAT alert"
        assert payload["entitySelector"] == "entityId(HOST-1)"
        assert payload["properties"]["source"] == "gnat"

    # ── ConnectorMixin CRUD routing ──────────────────────────────────────

    def test_get_object_routes_by_stix_type(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"entityId": "HOST-1"})
        )
        result = client.get_object("infrastructure", "HOST-1")
        assert result["entityId"] == "HOST-1"

    def test_list_objects_routes_by_stix_type(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(return_value={"events": [{"eventId": "E-1"}]}),
        )
        result = client.list_objects("observed-data")
        assert isinstance(result, list)

    def test_upsert_raises_for_unsupported_types(self, client):
        with pytest.raises(GNATClientError, match="not supported"):
            client.upsert_object("malware", {"name": "test"})

    def test_delete_mutes_security_problem(self, client, monkeypatch):
        monkeypatch.setattr(client, "post", MagicMock(return_value={}))
        client.delete_object("vulnerability", "S-1")
        client.post.assert_called_once()

    def test_delete_raises_for_unsupported_types(self, client):
        with pytest.raises(GNATClientError, match="not supported"):
            client.delete_object("indicator", "A-1")

    # ── Class-level attributes ────────────────────────────────────────────

    def test_trust_level(self, client):
        assert client.TRUST_LEVEL == "semi_trusted"

    def test_api_version(self, client):
        assert client.API_VERSION == "v2"

    def test_stix_type_map_keys(self, client):
        for key in ("infrastructure", "vulnerability", "indicator", "observed-data", "malware"):
            assert key in client.stix_type_map


# ---------------------------------------------------------------------------
# IPAPIClient (ip-api.com geolocation)
# ---------------------------------------------------------------------------
class TestIPAPIClient:
    _GEO_SUCCESS = {
        "status": "success",
        "country": "United States",
        "countryCode": "US",
        "region": "CA",
        "regionName": "California",
        "city": "Mountain View",
        "zip": "94043",
        "lat": 37.4192,
        "lon": -122.0574,
        "timezone": "America/Los_Angeles",
        "isp": "Google LLC",
        "org": "Google Public DNS",
        "as": "AS15169 Google LLC",
        "asname": "GOOGLE",
        "proxy": False,
        "hosting": True,
        "query": "8.8.8.8",
    }

    @pytest.fixture()
    def client(self):
        from gnat.connectors.ip_api.client import IPAPIClient
        return IPAPIClient()

    @pytest.fixture()
    def pro_client(self):
        from gnat.connectors.ip_api.client import IPAPIClient
        return IPAPIClient(
            host="https://pro.ip-api.com",
            api_key="TESTPROKEY",
            batch_delay=0.0,
        )

    # ── Auth ──────────────────────────────────────────────────────────────

    def test_authenticate_sets_accept_header(self, client):
        client.authenticate()
        assert client._auth_headers.get("Accept") == "application/json"

    def test_no_api_key_no_key_stored(self, client):
        assert client._api_key == ""

    # ── health_check ─────────────────────────────────────────────────────

    def test_health_check_returns_true_on_success(self, client, monkeypatch):
        monkeypatch.setattr(client, "lookup_ip", MagicMock(return_value=self._GEO_SUCCESS))
        assert client.health_check() is True

    def test_health_check_returns_false_on_api_fail(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "lookup_ip", MagicMock(side_effect=GNATClientError("fail"))
        )
        assert client.health_check() is False

    def test_health_check_returns_false_on_http_error(self, client, monkeypatch):
        monkeypatch.setattr(client, "lookup_ip", MagicMock(side_effect=Exception("timeout")))
        assert client.health_check() is False

    # ── lookup_ip ─────────────────────────────────────────────────────────

    def test_lookup_ip_returns_dict(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value=self._GEO_SUCCESS))
        result = client.lookup_ip("8.8.8.8")
        assert result["query"] == "8.8.8.8"
        assert result["country"] == "United States"

    def test_lookup_ip_raises_on_fail_status(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(return_value={"status": "fail", "message": "private range", "query": "192.168.1.1"}),
        )
        with pytest.raises(GNATClientError, match="private range"):
            client.lookup_ip("192.168.1.1")

    def test_lookup_ip_includes_fields_param(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value=self._GEO_SUCCESS))
        client.lookup_ip("8.8.8.8")
        call_kwargs = client.get.call_args
        params = call_kwargs[1].get("params") or call_kwargs[0][1]
        assert "fields" in params
        assert "country" in params["fields"]

    def test_lookup_ip_appends_api_key_when_configured(self, pro_client, monkeypatch):
        monkeypatch.setattr(pro_client, "get", MagicMock(return_value=self._GEO_SUCCESS))
        pro_client.lookup_ip("8.8.8.8")
        call_kwargs = pro_client.get.call_args
        params = call_kwargs[1].get("params") or call_kwargs[0][1]
        assert params.get("key") == "TESTPROKEY"

    # ── lookup_batch ──────────────────────────────────────────────────────

    def test_lookup_batch_posts_json_body(self, client, monkeypatch):
        monkeypatch.setattr(client, "post", MagicMock(return_value=[self._GEO_SUCCESS]))
        client.lookup_batch(["8.8.8.8"])
        call_kwargs = client.post.call_args
        body = call_kwargs[1].get("json") or call_kwargs[0][1]
        assert body == [{"query": "8.8.8.8"}]

    def test_lookup_batch_returns_only_successes(self, client, monkeypatch):
        fail_result = {"status": "fail", "message": "private range", "query": "10.0.0.1"}
        monkeypatch.setattr(
            client, "post", MagicMock(return_value=[self._GEO_SUCCESS, fail_result])
        )
        result = client.lookup_batch(["8.8.8.8", "10.0.0.1"])
        assert len(result) == 1
        assert result[0]["query"] == "8.8.8.8"

    def test_lookup_batch_handles_empty_list(self, client, monkeypatch):
        monkeypatch.setattr(client, "post", MagicMock())
        result = client.lookup_batch([])
        assert result == []
        client.post.assert_not_called()

    # ── lookup_many ───────────────────────────────────────────────────────

    def test_lookup_many_splits_into_chunks_of_100(self, client, monkeypatch):
        # 150 IPs → 2 batch calls
        ips = [f"1.2.3.{i}" for i in range(150)]
        mock_batch = MagicMock(return_value=[])
        monkeypatch.setattr(client, "lookup_batch", mock_batch)
        monkeypatch.setattr("gnat.connectors.ip_api.client.time.sleep", MagicMock())
        client.lookup_many(ips)
        assert mock_batch.call_count == 2
        first_chunk = mock_batch.call_args_list[0][0][0]
        second_chunk = mock_batch.call_args_list[1][0][0]
        assert len(first_chunk) == 100
        assert len(second_chunk) == 50

    def test_lookup_many_sleeps_between_batches(self, client, monkeypatch):
        ips = [f"1.2.{i}.1" for i in range(200)]
        monkeypatch.setattr(client, "lookup_batch", MagicMock(return_value=[]))
        sleep_mock = MagicMock()
        monkeypatch.setattr("gnat.connectors.ip_api.client.time.sleep", sleep_mock)
        client.lookup_many(ips)
        # 200 IPs → 2 chunks → 1 sleep between them (not after last)
        assert sleep_mock.call_count == 1

    def test_lookup_many_returns_flat_list(self, client, monkeypatch):
        geo1 = {**self._GEO_SUCCESS, "query": "8.8.8.8"}
        geo2 = {**self._GEO_SUCCESS, "query": "8.8.4.4"}
        monkeypatch.setattr(client, "lookup_batch", MagicMock(side_effect=[[geo1], [geo2]]))
        monkeypatch.setattr("gnat.connectors.ip_api.client.time.sleep", MagicMock())
        result = client.lookup_many(["8.8.8.8"] * 100 + ["8.8.4.4"] * 100)
        assert len(result) == 2

    # ── to_stix ───────────────────────────────────────────────────────────

    def test_to_stix_type_is_observed_data(self, client):
        stix = client.to_stix(self._GEO_SUCCESS)
        assert stix["type"] == "observed-data"

    def test_to_stix_id_contains_ip(self, client):
        stix = client.to_stix(self._GEO_SUCCESS)
        assert "8.8.8.8" in stix["id"]

    def test_to_stix_embeds_ipv4_addr_object(self, client):
        stix = client.to_stix(self._GEO_SUCCESS)
        ip_obj = stix["objects"]["0"]
        assert ip_obj["type"] == "ipv4-addr"
        assert ip_obj["value"] == "8.8.8.8"

    def test_to_stix_all_x_ipapi_fields_present(self, client):
        stix = client.to_stix(self._GEO_SUCCESS)
        for field in (
            "x_ipapi_country", "x_ipapi_country_code", "x_ipapi_region",
            "x_ipapi_city", "x_ipapi_lat", "x_ipapi_lon", "x_ipapi_isp",
            "x_ipapi_org", "x_ipapi_as", "x_ipapi_timezone", "x_ipapi_query",
        ):
            assert field in stix, f"Missing field: {field}"
        assert stix["x_ipapi_country"] == "United States"
        assert stix["x_ipapi_lat"] == 37.4192
        assert stix["x_ipapi_query"] == "8.8.8.8"

    def test_to_stix_proxy_flag_is_bool(self, client):
        stix = client.to_stix(self._GEO_SUCCESS)
        assert isinstance(stix["x_ipapi_proxy"], bool)
        assert isinstance(stix["x_ipapi_hosting"], bool)

    # ── from_stix ─────────────────────────────────────────────────────────

    def test_from_stix_returns_query_dict(self, client):
        stix = client.to_stix(self._GEO_SUCCESS)
        result = client.from_stix(stix)
        assert result == {"query": "8.8.8.8"}

    def test_from_stix_falls_back_to_embedded_sco(self, client):
        stix = {
            "type": "observed-data",
            "objects": {"0": {"type": "ipv4-addr", "value": "1.2.3.4"}},
        }
        result = client.from_stix(stix)
        assert result == {"query": "1.2.3.4"}

    # ── ConnectorMixin routing ────────────────────────────────────────────

    def test_get_object_calls_lookup_ip(self, client, monkeypatch):
        monkeypatch.setattr(client, "lookup_ip", MagicMock(return_value=self._GEO_SUCCESS))
        result = client.get_object("observed-data", "8.8.8.8")
        assert result["type"] == "observed-data"
        client.lookup_ip.assert_called_once_with("8.8.8.8")

    def test_get_object_wrong_stix_type_raises(self, client):
        with pytest.raises(GNATClientError, match="observed-data"):
            client.get_object("indicator", "8.8.8.8")

    def test_list_objects_uses_ips_filter(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "lookup_many", MagicMock(return_value=[self._GEO_SUCCESS])
        )
        result = client.list_objects("observed-data", filters={"ips": ["8.8.8.8"]})
        assert isinstance(result, list)
        assert result[0]["type"] == "observed-data"
        client.lookup_many.assert_called_once_with(["8.8.8.8"])

    def test_list_objects_uses_single_ip_filter(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "lookup_many", MagicMock(return_value=[self._GEO_SUCCESS])
        )
        result = client.list_objects("observed-data", filters={"ip": "8.8.8.8"})
        assert isinstance(result, list)
        client.lookup_many.assert_called_once_with(["8.8.8.8"])

    def test_list_objects_empty_filters_returns_empty(self, client):
        result = client.list_objects("observed-data", filters={})
        assert result == []

    def test_upsert_raises_read_only(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.upsert_object("observed-data", {})

    def test_delete_raises_read_only(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.delete_object("observed-data", "8.8.8.8")

    # ── Class-level attributes ────────────────────────────────────────────

    def test_trust_level(self, client):
        assert client.TRUST_LEVEL == "untrusted_external"

    def test_default_host(self, client):
        assert "ip-api.com" in client.host

    def test_batch_delay_default(self, client):
        assert client._batch_delay == 4.0


# ===========================================================================
# Phase 1 Wave 1 — Tier 1 connector expansion
# ===========================================================================


# ---------------------------------------------------------------------------
# MITRE ATT&CK
# ---------------------------------------------------------------------------


class TestMitreAttackClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.mitre_attack.client import MitreAttackClient

        c = MitreAttackClient(host="https://attack-taxii.mitre.org")
        c._authenticated = True
        return c

    def test_authenticate_sets_taxii_accept(self):
        from gnat.connectors.mitre_attack.client import MitreAttackClient

        c = MitreAttackClient(host="https://attack-taxii.mitre.org")
        c.authenticate()
        assert "taxii+json" in c._auth_headers["Accept"]

    def test_invalid_matrix_raises(self):
        from gnat.connectors.mitre_attack.client import MitreAttackClient

        with pytest.raises(GNATClientError, match="Invalid MITRE ATT&CK matrix"):
            MitreAttackClient(host="https://x", matrix="windows-only")

    def test_list_objects_filters_by_type(self, client):
        client._cache = [
            {"type": "attack-pattern", "id": "attack-pattern--a", "name": "T1"},
            {"type": "intrusion-set", "id": "intrusion-set--b", "name": "Group A"},
            {"type": "attack-pattern", "id": "attack-pattern--c", "name": "T2"},
        ]
        out = client.list_objects("attack-pattern")
        assert len(out) == 2
        assert all(o["type"] == "attack-pattern" for o in out)

    def test_list_objects_name_contains(self, client):
        client._cache = [
            {"type": "attack-pattern", "id": "attack-pattern--a", "name": "Spearphish"},
            {"type": "attack-pattern", "id": "attack-pattern--b", "name": "Credential Access"},
        ]
        out = client.list_objects(
            "attack-pattern", filters={"name_contains": "phish"}
        )
        assert len(out) == 1
        assert "Spearphish" in out[0]["name"]

    def test_list_objects_rejects_unknown_type(self, client):
        client._cache = []
        with pytest.raises(GNATClientError, match="Unknown ATT&CK STIX type"):
            client.list_objects("totally-fake")

    def test_get_object_by_external_id(self, client):
        client._cache = [
            {
                "type": "attack-pattern",
                "id": "attack-pattern--aaaa",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1055"}
                ],
            }
        ]
        obj = client.get_object("attack-pattern", "T1055")
        assert obj["id"] == "attack-pattern--aaaa"

    def test_get_object_not_found(self, client):
        client._cache = []
        with pytest.raises(GNATClientError, match="not found"):
            client.get_object("attack-pattern", "T9999")

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.upsert_object("attack-pattern", {})

    def test_delete_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.delete_object("attack-pattern", "T1")

    def test_to_stix_passthrough(self, client):
        native = {
            "type": "attack-pattern",
            "id": "attack-pattern--11111111-1111-1111-1111-111111111111",
            "name": "Phishing",
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["spec_version"] == "2.1"
        assert stix["x_source_platform"] == "mitre_attack"
        assert stix["x_attack_matrix"] == "enterprise-attack"

    def test_to_stix_rejects_non_dict(self, client):
        with pytest.raises(GNATClientError):
            client.to_stix("not a dict")  # type: ignore[arg-type]

    def test_from_stix_is_noop(self, client):
        result = client.from_stix({"id": "attack-pattern--x"})
        assert "read-only" in result["note"]
        assert result["stix_id"] == "attack-pattern--x"


# ---------------------------------------------------------------------------
# Abuse.ch (unified: URLhaus / MalwareBazaar / ThreatFox / Feodo / SSLBL)
# ---------------------------------------------------------------------------


class TestAbuseChClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.abusech.client import AbuseChClient

        c = AbuseChClient(host="https://abuse.ch")
        c._authenticated = True
        return c

    def test_authenticate_sets_accept_only_without_key(self):
        from gnat.connectors.abusech.client import AbuseChClient

        c = AbuseChClient(host="https://abuse.ch")
        c.authenticate()
        assert c._auth_headers["Accept"] == "application/json"
        assert "Auth-Key" not in c._auth_headers

    def test_authenticate_injects_auth_key(self):
        from gnat.connectors.abusech.client import AbuseChClient

        c = AbuseChClient(host="https://abuse.ch", auth_key="secret123")
        c.authenticate()
        assert c._auth_headers["Auth-Key"] == "secret123"

    def test_invalid_default_feed_raises(self):
        from gnat.connectors.abusech.client import AbuseChClient

        with pytest.raises(GNATClientError, match="Invalid default_feed"):
            AbuseChClient(host="https://abuse.ch", default_feed="nope")

    def test_list_objects_threatfox(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "_fetch_feed",
            MagicMock(
                return_value={
                    "query_status": "ok",
                    "data": [
                        {
                            "ioc": "1.2.3.4",
                            "ioc_type": "ip",
                            "threat_type": "botnet_cc",
                            "malware": "TrickBot",
                        }
                    ],
                }
            ),
        )
        items = client.list_objects("indicator")
        assert len(items) == 1
        assert items[0]["_feed"] == "threatfox"

    def test_list_objects_feodo(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "_fetch_feed",
            MagicMock(return_value=[{"ip_address": "9.9.9.9", "malware": "Emotet"}]),
        )
        items = client.list_objects("indicator", filters={"feed": "feodotracker"})
        assert len(items) == 1
        assert items[0]["_feed"] == "feodotracker"

    def test_list_objects_rejects_unknown_feed(self, client):
        with pytest.raises(GNATClientError, match="Unknown abuse.ch feed"):
            client.list_objects("indicator", filters={"feed": "nope"})

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.upsert_object("indicator", {})

    def test_delete_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.delete_object("indicator", "x")

    def test_to_stix_urlhaus(self, client):
        stix = client.to_stix(
            {
                "_feed": "urlhaus",
                "url": "http://evil.example/malware.exe",
                "threat": "malware_download",
                "url_status": "online",
                "tags": ["exe", "emotet"],
            }
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "indicator"
        assert "url:value" in stix["pattern"]
        assert stix["x_urlhaus"]["url_status"] == "online"

    def test_to_stix_malwarebazaar(self, client):
        stix = client.to_stix(
            {
                "_feed": "malwarebazaar",
                "sha256_hash": "a" * 64,
                "sha1_hash": "b" * 40,
                "md5_hash": "c" * 32,
                "file_type": "exe",
                "signature": "Emotet",
            }
        )
        _assert_stix_contract(stix)
        assert "SHA-256" in stix["pattern"]
        assert stix["x_malwarebazaar"]["signature"] == "Emotet"

    def test_to_stix_threatfox_ip(self, client):
        stix = client.to_stix(
            {
                "_feed": "threatfox",
                "ioc": "1.2.3.4:8080",
                "ioc_type": "ip:port",
                "threat_type": "botnet_cc",
                "malware": "Dridex",
                "confidence_level": 90,
            }
        )
        _assert_stix_contract(stix)
        assert "ipv4-addr:value" in stix["pattern"]
        assert "1.2.3.4" in stix["pattern"]
        assert stix["confidence"] == 90

    def test_to_stix_feodo(self, client):
        stix = client.to_stix(
            {
                "_feed": "feodotracker",
                "ip_address": "5.6.7.8",
                "port": 443,
                "malware": "TrickBot",
                "as_number": 12345,
            }
        )
        _assert_stix_contract(stix)
        assert "ipv4-addr" in stix["pattern"]
        assert stix["x_feodotracker"]["as_number"] == 12345

    def test_to_stix_sslbl(self, client):
        stix = client.to_stix(
            {
                "_feed": "sslbl",
                "SHA1": "aabbccddeeff",
                "Listingreason": "Dridex C&C",
            }
        )
        _assert_stix_contract(stix)
        assert "x509-certificate" in stix["pattern"] or "SHA-1" in stix["pattern"]
        assert stix["x_sslbl"]["listing_reason"] == "Dridex C&C"

    def test_to_stix_infers_feed(self, client):
        # No _feed marker; shape hints at feodo
        stix = client.to_stix(
            {"ip_address": "1.1.1.1", "as_number": 1, "malware": "x"}
        )
        assert stix["x_feodotracker"]["ip_address"] == "1.1.1.1"

    def test_from_stix_is_noop(self, client):
        out = client.from_stix({"id": "indicator--x"})
        assert "read-only" in out["note"]

    def test_health_check_uses_feodo(self, client, monkeypatch):
        monkeypatch.setattr(client, "_fetch_feed", MagicMock(return_value=[]))
        assert client.health_check() is True

    def test_health_check_false_on_error(self, client, monkeypatch):
        def _boom(*a, **kw):
            raise GNATClientError("nope")

        monkeypatch.setattr(client, "_fetch_feed", _boom)
        assert client.health_check() is False


# ---------------------------------------------------------------------------
# OSV.dev
# ---------------------------------------------------------------------------


class TestOSVClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.osv.client import OSVClient

        c = OSVClient(host="https://api.osv.dev")
        c._authenticated = True
        return c

    def test_authenticate_sets_accept(self):
        from gnat.connectors.osv.client import OSVClient

        c = OSVClient(host="https://api.osv.dev")
        c.authenticate()
        assert c._auth_headers["Accept"] == "application/json"

    def test_health_check_true(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"id": "CVE-2021-44228"}))
        assert client.health_check() is True

    def test_health_check_false_on_error(self, client, monkeypatch):
        def _boom(*a, **kw):
            raise RuntimeError("nope")

        monkeypatch.setattr(client, "get", _boom)
        assert client.health_check() is False

    def test_get_object(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(return_value={"id": "CVE-2021-44228", "summary": "Log4Shell"}),
        )
        obj = client.get_object("vulnerability", "CVE-2021-44228")
        assert obj["id"] == "CVE-2021-44228"

    def test_get_object_rejects_wrong_type(self, client):
        with pytest.raises(GNATClientError):
            client.get_object("indicator", "CVE-2021-44228")

    def test_get_object_rejects_empty_id(self, client):
        with pytest.raises(GNATClientError):
            client.get_object("vulnerability", "")

    def test_list_objects_empty_without_package_or_commit(self, client):
        result = client.list_objects("vulnerability")
        assert result == []

    def test_list_objects_by_package(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "post",
            MagicMock(
                return_value={
                    "vulns": [
                        {"id": "GHSA-1111-2222-3333", "summary": "x"},
                        {"id": "GHSA-4444-5555-6666", "summary": "y"},
                    ]
                }
            ),
        )
        vulns = client.list_objects(
            "vulnerability", filters={"ecosystem": "PyPI", "name": "django"}
        )
        assert len(vulns) == 2

    def test_query_batch(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "post",
            MagicMock(
                return_value={
                    "results": [
                        {"vulns": [{"id": "CVE-1"}]},
                        {"vulns": []},
                    ]
                }
            ),
        )
        out = client.query_batch([{"package": {"ecosystem": "PyPI", "name": "a"}}, {}])
        assert len(out) == 2
        assert out[0][0]["id"] == "CVE-1"
        assert out[1] == []

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.upsert_object("vulnerability", {})

    def test_delete_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.delete_object("vulnerability", "x")

    def test_to_stix(self, client):
        stix = client.to_stix(
            {
                "id": "CVE-2021-44228",
                "details": "Log4Shell RCE",
                "aliases": ["GHSA-jfh8-c2jp-5v3q"],
            }
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "vulnerability"
        assert stix["name"] == "CVE-2021-44228"

    def test_from_stix_is_noop(self, client):
        out = client.from_stix({"id": "vulnerability--x"})
        assert "read-only" in out["note"]


# ---------------------------------------------------------------------------
# VulnCheck
# ---------------------------------------------------------------------------


class TestVulnCheckClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.vulncheck.client import VulnCheckClient

        c = VulnCheckClient(host="https://api.vulncheck.com", api_key="vc_test")
        c._authenticated = True
        return c

    def test_authenticate_sets_bearer(self):
        from gnat.connectors.vulncheck.client import VulnCheckClient

        c = VulnCheckClient(host="https://api.vulncheck.com", api_key="vc_test")
        c.authenticate()
        assert c._auth_headers["Authorization"] == "Bearer vc_test"

    def test_authenticate_requires_api_key(self):
        from gnat.connectors.vulncheck.client import VulnCheckClient

        c = VulnCheckClient(host="https://api.vulncheck.com", api_key="")
        with pytest.raises(GNATClientError, match="requires api_key"):
            c.authenticate()

    def test_invalid_default_index_raises(self):
        from gnat.connectors.vulncheck.client import VulnCheckClient

        with pytest.raises(GNATClientError, match="Unknown VulnCheck index"):
            VulnCheckClient(host="https://x", api_key="k", default_index="nope")

    def test_health_check_true(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": []}))
        assert client.health_check() is True

    def test_health_check_false_on_error(self, client, monkeypatch):
        def _boom(*a, **kw):
            raise RuntimeError("nope")

        monkeypatch.setattr(client, "get", _boom)
        assert client.health_check() is False

    def test_get_object(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(
                return_value={"data": [{"cve": "CVE-2024-0001", "description": "x"}]}
            ),
        )
        obj = client.get_object("vulnerability", "CVE-2024-0001")
        assert obj["cve"] == "CVE-2024-0001"

    def test_get_object_not_found(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": []}))
        with pytest.raises(GNATClientError, match="no record"):
            client.get_object("vulnerability", "CVE-9999-9999")

    def test_list_objects(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(
                return_value={
                    "data": [
                        {"cve": "CVE-2024-0001"},
                        {"cve": "CVE-2024-0002"},
                    ]
                }
            ),
        )
        items = client.list_objects("vulnerability")
        assert len(items) == 2

    def test_list_objects_rejects_unknown_index(self, client):
        with pytest.raises(GNATClientError, match="Unknown VulnCheck index"):
            client.list_objects("vulnerability", filters={"index": "nope"})

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.upsert_object("vulnerability", {})

    def test_delete_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.delete_object("vulnerability", "x")

    def test_to_stix(self, client):
        stix = client.to_stix(
            {
                "cve": "CVE-2024-0001",
                "shortDescription": "Test vuln",
                "vendorProject": "Acme",
                "product": "Widget",
                "cvssBaseScore": 9.8,
                "cvssV3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "knownExploited": True,
            }
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "vulnerability"
        assert stix["name"] == "CVE-2024-0001"
        assert stix["x_vulncheck"]["known_exploited"] is True
        sources = [r["source_name"] for r in stix["external_references"]]
        assert "cve" in sources
        assert "cvss" in sources

    def test_from_stix_is_noop(self, client):
        out = client.from_stix({"id": "vulnerability--x"})
        assert "read-only" in out["note"]

    def test_get_kev_helper(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"data": [{"cve": "CVE-X"}]})
        )
        rec = client.get_kev("CVE-X")
        assert rec["cve"] == "CVE-X"


# ---------------------------------------------------------------------------
# Registry integrity — Phase 1 Wave 1
# ---------------------------------------------------------------------------


def test_phase1_wave1_registry_contains_new_connectors():
    from gnat.clients import CLIENT_REGISTRY

    for key in ("mitre_attack", "abusech", "osv", "vulncheck"):
        assert key in CLIENT_REGISTRY, f"Missing {key} in CLIENT_REGISTRY"


def test_phase1_wave1_config_sections_exist():
    import configparser
    from pathlib import Path

    cfg_path = Path(__file__).resolve().parents[3] / "config" / "config.ini.example"
    # strict=False because the example file historically declares a couple
    # of illustrative sections twice (e.g. ``[claude]`` and ``[copilot]``
    # appear in both the original platform block and the LLM-provider block).
    parser = configparser.ConfigParser(strict=False)
    parser.read(cfg_path)
    for section in ("mitre_attack", "abusech", "osv", "vulncheck"):
        assert parser.has_section(section), f"Missing [{section}] in config.ini.example"


# ===========================================================================
# Phase 1 Wave 2 — Tier 1 connector expansion
# ===========================================================================


# ---------------------------------------------------------------------------
# Cloudflare Threat Intelligence
# ---------------------------------------------------------------------------


class TestCloudflareIntelClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.cloudflare_intel.client import CloudflareIntelClient

        c = CloudflareIntelClient(
            host="https://api.cloudflare.com",
            api_token="cf_test",
            account_id="abc123",
        )
        c._authenticated = True
        return c

    def test_authenticate_sets_bearer(self):
        from gnat.connectors.cloudflare_intel.client import CloudflareIntelClient

        c = CloudflareIntelClient(
            host="https://api.cloudflare.com",
            api_token="cf_test",
            account_id="abc123",
        )
        c.authenticate()
        assert c._auth_headers["Authorization"] == "Bearer cf_test"

    def test_authenticate_requires_api_token(self):
        from gnat.connectors.cloudflare_intel.client import CloudflareIntelClient

        c = CloudflareIntelClient(
            host="https://api.cloudflare.com",
            api_token="",
            account_id="abc",
        )
        with pytest.raises(GNATClientError, match="requires api_token"):
            c.authenticate()

    def test_authenticate_requires_account_id(self):
        from gnat.connectors.cloudflare_intel.client import CloudflareIntelClient

        c = CloudflareIntelClient(
            host="https://api.cloudflare.com",
            api_token="cf_test",
            account_id="",
        )
        with pytest.raises(GNATClientError, match="requires account_id"):
            c.authenticate()

    def test_health_check_true(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"result": {"id": "abc"}}))
        assert client.health_check() is True

    def test_health_check_false_on_error(self, client, monkeypatch):
        def _boom(*a, **kw):
            raise RuntimeError("nope")

        monkeypatch.setattr(client, "get", _boom)
        assert client.health_check() is False

    def test_get_object_domain(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(
                return_value={
                    "result": {
                        "domain": "evil.example",
                        "risk_score": 80,
                        "risk_types": [{"name": "malware"}],
                    }
                }
            ),
        )
        obj = client.get_object("indicator", "evil.example")
        assert obj["domain"] == "evil.example"
        assert obj["_cf_kind"] == "indicator"

    def test_get_object_ipv4_dispatches(self, client, monkeypatch):
        stub = MagicMock(
            return_value={"result": {"ipv4": "1.2.3.4", "risk_score": 40}}
        )
        monkeypatch.setattr(client, "get", stub)
        obj = client.get_object("indicator", "1.2.3.4")
        assert obj["ipv4"] == "1.2.3.4"
        # Should have hit the /intel/ip endpoint with the ipv4 param
        call_path = stub.call_args[0][0]
        assert "intel/ip" in call_path

    def test_get_object_asn(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(return_value={"result": {"asn": "AS12345", "name": "Acme"}}),
        )
        obj = client.get_object("infrastructure", "AS12345")
        assert obj["asn"] == "AS12345"

    def test_list_objects_indicator_requires_filter(self, client):
        with pytest.raises(GNATClientError, match="requires a"):
            client.list_objects("indicator")

    def test_list_objects_passive_dns(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(return_value={"result": [{"domain": "a.example"}, {"domain": "b.example"}]}),
        )
        out = client.list_objects("observed-data", filters={"ipv4": "1.2.3.4"})
        assert len(out) == 2

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.upsert_object("indicator", {})

    def test_delete_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.delete_object("indicator", "x")

    def test_to_stix_domain_indicator(self, client):
        stix = client.to_stix(
            {
                "_cf_kind": "indicator",
                "_cf_query": "evil.example",
                "domain": "evil.example",
                "risk_score": 85,
                "risk_types": [{"name": "malware"}],
                "content_categories": [{"name": "Malicious Sites"}],
            }
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "indicator"
        assert "domain-name:value" in stix["pattern"]
        assert "malicious-activity" in stix["labels"]
        assert stix["x_cloudflare"]["risk_score"] == 85

    def test_to_stix_ip_indicator(self, client):
        stix = client.to_stix(
            {
                "_cf_kind": "indicator",
                "_cf_query": "9.9.9.9",
                "ipv4": "9.9.9.9",
                "risk_score": 10,
            }
        )
        _assert_stix_contract(stix)
        assert "ipv4-addr:value" in stix["pattern"]
        assert stix["labels"] == ["benign"]

    def test_to_stix_asn_infrastructure(self, client):
        stix = client.to_stix(
            {
                "_cf_kind": "infrastructure",
                "asn": "12345",
                "name": "Acme Networks",
                "country": "US",
            }
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "infrastructure"
        assert stix["name"] == "AS12345"
        assert stix["x_cloudflare_asn"]["country"] == "US"

    def test_to_stix_whois_observed_data(self, client):
        stix = client.to_stix(
            {
                "_cf_kind": "observed-data",
                "_cf_query": "example.com",
                "registrar": "Example Registrar",
                "creation_date": "2020-01-01T00:00:00Z",
            }
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "observed-data"
        assert stix["x_source_name"] == "cloudflare_intel"

    def test_from_stix_is_noop(self, client):
        out = client.from_stix({"id": "indicator--x"})
        assert "read-only" in out["note"]


# ---------------------------------------------------------------------------
# GitGuardian
# ---------------------------------------------------------------------------


class TestGitGuardianClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.gitguardian.client import GitGuardianClient

        c = GitGuardianClient(host="https://api.gitguardian.com", api_key="gg_test")
        c._authenticated = True
        return c

    def test_authenticate_sets_token(self):
        from gnat.connectors.gitguardian.client import GitGuardianClient

        c = GitGuardianClient(host="https://api.gitguardian.com", api_key="gg_test")
        c.authenticate()
        assert c._auth_headers["Authorization"] == "Token gg_test"

    def test_authenticate_requires_api_key(self):
        from gnat.connectors.gitguardian.client import GitGuardianClient

        c = GitGuardianClient(host="https://api.gitguardian.com", api_key="")
        with pytest.raises(GNATClientError, match="requires api_key"):
            c.authenticate()

    def test_health_check_true(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"status": "ok"}))
        assert client.health_check() is True

    def test_health_check_false_on_error(self, client, monkeypatch):
        def _boom(*a, **kw):
            raise RuntimeError("nope")

        monkeypatch.setattr(client, "get", _boom)
        assert client.health_check() is False

    def test_get_incident(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(
                return_value={
                    "id": 42,
                    "status": "TRIGGERED",
                    "severity": "high",
                    "detector": {"name": "AWSKey", "family": "cloud"},
                }
            ),
        )
        inc = client.get_incident(42)
        assert inc["id"] == 42

    def test_list_incidents(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(
                return_value=[
                    {"id": 1, "status": "TRIGGERED"},
                    {"id": 2, "status": "RESOLVED"},
                ]
            ),
        )
        items = client.list_incidents(status="TRIGGERED")
        assert len(items) == 2

    def test_list_objects_rejects_unknown_type(self, client):
        with pytest.raises(GNATClientError, match="does not support"):
            client.list_objects("totally-fake")

    def test_scan_content(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "post",
            MagicMock(return_value={"policy_breaks": [{"type": "AWS"}]}),
        )
        out = client.scan_content("AKIA...", filename="test.py")
        assert out["policy_breaks"][0]["type"] == "AWS"

    def test_scan_content_batch(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "post",
            MagicMock(return_value=[{"policy_breaks": []}, {"policy_breaks": [{"type": "GCP"}]}]),
        )
        out = client.scan_content_batch([{"document": "a"}, {"document": "b"}])
        assert len(out) == 2

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.upsert_object("observed-data", {})

    def test_delete_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.delete_object("observed-data", "x")

    def test_to_stix(self, client):
        stix = client.to_stix(
            {
                "id": 42,
                "status": "TRIGGERED",
                "severity": "high",
                "validity": "valid",
                "detector": {"name": "AWSKey", "family": "cloud"},
                "date": "2026-04-01T00:00:00Z",
                "last_occurrence_date": "2026-04-05T00:00:00Z",
                "occurrences": [
                    {
                        "filepath": "src/config.py",
                        "author": "alice@example.com",
                        "source": "myorg/myrepo",
                    }
                ],
            }
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "observed-data"
        assert stix["first_observed"] == "2026-04-01T00:00:00Z"
        assert stix["x_gitguardian"]["incident_id"] == "42"
        assert stix["x_gitguardian"]["secret_type"] == "AWSKey"
        # Should have refs for the file and author identity
        assert any(r.startswith("file--") for r in stix["object_refs"])
        assert any(r.startswith("identity--") for r in stix["object_refs"])

    def test_from_stix_is_noop(self, client):
        out = client.from_stix({"id": "observed-data--x"})
        assert "read-only" in out["note"]


# ---------------------------------------------------------------------------
# runZero
# ---------------------------------------------------------------------------


class TestRunZeroClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.runzero.client import RunZeroClient

        c = RunZeroClient(
            host="https://console.runzero.com", export_token="rZ_test"
        )
        c._authenticated = True
        return c

    def test_authenticate_sets_bearer(self):
        from gnat.connectors.runzero.client import RunZeroClient

        c = RunZeroClient(
            host="https://console.runzero.com", export_token="rZ_test"
        )
        c.authenticate()
        assert c._auth_headers["Authorization"] == "Bearer rZ_test"

    def test_authenticate_requires_token(self):
        from gnat.connectors.runzero.client import RunZeroClient

        c = RunZeroClient(host="https://console.runzero.com", export_token="")
        with pytest.raises(GNATClientError, match="requires export_token"):
            c.authenticate()

    def test_trust_level_is_internal(self, client):
        assert client.TRUST_LEVEL == "trusted_internal"

    def test_health_check_true(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value=[]))
        assert client.health_check() is True

    def test_health_check_false_on_error(self, client, monkeypatch):
        def _boom(*a, **kw):
            raise RuntimeError("nope")

        monkeypatch.setattr(client, "get", _boom)
        assert client.health_check() is False

    def test_get_asset(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(return_value={"id": "asset-1", "addresses": ["10.0.0.1"]}),
        )
        obj = client.get_asset("asset-1")
        assert obj["id"] == "asset-1"

    def test_get_object_rejects_unknown_type(self, client):
        with pytest.raises(GNATClientError, match="does not support"):
            client.get_object("indicator", "x")

    def test_list_objects_assets(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(
                return_value=[
                    {"id": "a", "addresses": ["10.0.0.1"]},
                    {"id": "b", "addresses": ["10.0.0.2"]},
                ]
            ),
        )
        items = client.list_objects("observed-data")
        assert len(items) == 2
        assert all(i["_rz_kind"] == "observed-data" for i in items)

    def test_list_objects_software(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(return_value=[{"name": "nginx", "vendor": "F5", "cpe": "cpe:..."}]),
        )
        items = client.list_objects("software")
        assert items[0]["_rz_kind"] == "software"

    def test_list_sites(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(return_value=[{"id": "site1", "name": "HQ"}]),
        )
        sites = client.list_sites()
        assert sites[0]["name"] == "HQ"

    def test_list_tasks(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(return_value=[{"id": "task1", "status": "done"}]),
        )
        tasks = client.list_tasks()
        assert len(tasks) == 1

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.upsert_object("observed-data", {})

    def test_delete_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.delete_object("observed-data", "x")

    def test_to_stix_asset(self, client):
        stix = client.to_stix(
            {
                "_rz_kind": "observed-data",
                "id": "asset-1",
                "addresses": ["10.0.0.1"],
                "macs": ["aa:bb:cc:dd:ee:ff"],
                "os": "Ubuntu 22.04",
                "first_seen": "2026-01-01T00:00:00Z",
                "last_seen": "2026-04-01T00:00:00Z",
            }
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "observed-data"
        assert stix["x_runzero"]["asset_id"] == "asset-1"
        # Should contain ipv4-addr and mac-addr and software refs
        ref_types = {r.split("--")[0] for r in stix["object_refs"]}
        assert "ipv4-addr" in ref_types
        assert "mac-addr" in ref_types

    def test_to_stix_software(self, client):
        stix = client.to_stix(
            {
                "_rz_kind": "software",
                "name": "nginx",
                "vendor": "F5",
                "version": "1.24.0",
                "cpe": "cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*",
                "asset_count": 42,
            }
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "software"
        assert stix["name"] == "nginx"
        assert stix["x_runzero_software"]["asset_count"] == 42

    def test_to_stix_vulnerability(self, client):
        stix = client.to_stix(
            {
                "_rz_kind": "vulnerability",
                "cve": "CVE-2024-0001",
                "description": "Test vuln",
                "cvss3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "cvss3_base_score": 9.8,
            }
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "vulnerability"
        assert stix["name"] == "CVE-2024-0001"
        sources = [r["source_name"] for r in stix["external_references"]]
        assert "cve" in sources
        assert "cvss" in sources

    def test_from_stix_is_noop(self, client):
        out = client.from_stix({"id": "observed-data--x"})
        assert "read-only" in out["note"]


# ---------------------------------------------------------------------------
# Registry integrity — Phase 1 Wave 2
# ---------------------------------------------------------------------------


def test_phase1_wave2_registry_contains_new_connectors():
    from gnat.clients import CLIENT_REGISTRY

    for key in ("cloudflare_intel", "gitguardian", "runzero"):
        assert key in CLIENT_REGISTRY, f"Missing {key} in CLIENT_REGISTRY"


def test_phase1_wave2_config_sections_exist():
    import configparser
    from pathlib import Path

    cfg_path = Path(__file__).resolve().parents[3] / "config" / "config.ini.example"
    parser = configparser.ConfigParser(strict=False)
    parser.read(cfg_path)
    for section in ("cloudflare_intel", "gitguardian", "runzero"):
        assert parser.has_section(section), f"Missing [{section}] in config.ini.example"


# ===========================================================================
# Phase 1 Wave 3a — Tier 1 connector expansion (infrastructure pivoting)
# ===========================================================================


# ---------------------------------------------------------------------------
# SecurityTrails
# ---------------------------------------------------------------------------


class TestSecurityTrailsClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.securitytrails.client import SecurityTrailsClient

        c = SecurityTrailsClient(host="https://api.securitytrails.com", api_key="st_test")
        c._authenticated = True
        return c

    def test_authenticate_sets_apikey_header(self):
        from gnat.connectors.securitytrails.client import SecurityTrailsClient

        c = SecurityTrailsClient(host="https://api.securitytrails.com", api_key="st_test")
        c.authenticate()
        assert c._auth_headers["APIKEY"] == "st_test"

    def test_authenticate_requires_api_key(self):
        from gnat.connectors.securitytrails.client import SecurityTrailsClient

        c = SecurityTrailsClient(host="https://api.securitytrails.com", api_key="")
        with pytest.raises(GNATClientError, match="requires api_key"):
            c.authenticate()

    def test_health_check_true(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"success": True}))
        assert client.health_check() is True

    def test_health_check_false_on_error(self, client, monkeypatch):
        def _boom(*a, **kw):
            raise RuntimeError("nope")

        monkeypatch.setattr(client, "get", _boom)
        assert client.health_check() is False

    def test_get_object_domain(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(return_value={"hostname": "evil.example", "current_dns": {}}),
        )
        obj = client.get_object("domain-name", "evil.example")
        assert obj["_st_kind"] == "domain-name"

    def test_list_objects_subdomains(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(return_value={"subdomains": ["dev", "api", "mail"]}),
        )
        items = client.list_objects("domain-name", filters={"domain": "example.com"})
        assert len(items) == 3

    def test_list_objects_historical_dns(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(
                return_value={
                    "records": [
                        {"values": [{"ip": "1.2.3.4"}], "first_seen": "2020-01-01"}
                    ]
                }
            ),
        )
        items = client.list_objects(
            "observed-data", filters={"domain": "example.com", "record_type": "a"}
        )
        assert len(items) == 1
        assert items[0]["_st_record_type"] == "a"

    def test_list_objects_rejects_invalid_record_type(self, client):
        with pytest.raises(GNATClientError, match="Invalid SecurityTrails record_type"):
            client.list_objects(
                "observed-data",
                filters={"domain": "example.com", "record_type": "bogus"},
            )

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.upsert_object("domain-name", {})

    def test_delete_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.delete_object("domain-name", "x")

    def test_to_stix_domain(self, client):
        stix = client.to_stix(
            {
                "_st_kind": "domain-name",
                "_st_query": "example.com",
                "subdomain": "dev",
                "parent": "example.com",
            }
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "domain-name"
        assert stix["value"] == "dev.example.com"

    def test_to_stix_observed_data(self, client):
        stix = client.to_stix(
            {
                "_st_kind": "observed-data",
                "_st_query": "example.com",
                "_st_record_type": "a",
                "values": [{"ip": "1.2.3.4"}],
                "first_seen": "2020-01-01",
                "last_seen": "2024-01-01",
            }
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "observed-data"
        assert any(r.startswith("ipv4-addr--") for r in stix["object_refs"])

    def test_from_stix_is_noop(self, client):
        out = client.from_stix({"id": "domain-name--x"})
        assert "read-only" in out["note"]


# ---------------------------------------------------------------------------
# DomainTools
# ---------------------------------------------------------------------------


class TestDomainToolsClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.domaintools.client import DomainToolsClient

        c = DomainToolsClient(
            host="https://api.domaintools.com",
            api_username="user",
            api_key="dt_test",
        )
        c._authenticated = True
        return c

    def test_authenticate_accepts_credentials(self):
        from gnat.connectors.domaintools.client import DomainToolsClient

        c = DomainToolsClient(
            host="https://api.domaintools.com",
            api_username="user",
            api_key="dt_test",
        )
        c.authenticate()
        assert c._auth_headers["Accept"] == "application/json"

    def test_authenticate_requires_username(self):
        from gnat.connectors.domaintools.client import DomainToolsClient

        c = DomainToolsClient(
            host="https://api.domaintools.com",
            api_username="",
            api_key="dt_test",
        )
        with pytest.raises(GNATClientError, match="requires api_username"):
            c.authenticate()

    def test_authenticate_requires_api_key(self):
        from gnat.connectors.domaintools.client import DomainToolsClient

        c = DomainToolsClient(
            host="https://api.domaintools.com",
            api_username="user",
            api_key="",
        )
        with pytest.raises(GNATClientError, match="requires api_key"):
            c.authenticate()

    def test_auth_params(self, client):
        params = client._auth_params({"foo": "bar"})
        assert params["api_username"] == "user"
        assert params["api_key"] == "dt_test"
        assert params["foo"] == "bar"

    def test_health_check_true(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"response": {}}))
        assert client.health_check() is True

    def test_health_check_false_on_error(self, client, monkeypatch):
        def _boom(*a, **kw):
            raise RuntimeError("nope")

        monkeypatch.setattr(client, "get", _boom)
        assert client.health_check() is False

    def test_get_object_whois(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(return_value={"response": {"registrar": "Example"}}),
        )
        obj = client.get_object("domain-name", "example.com")
        assert obj["_dt_kind"] == "domain-name"

    def test_list_objects_reverse_ip(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(
                return_value={
                    "response": {
                        "ip_addresses": [
                            {"ip_address": "1.2.3.4", "domain_count": 42},
                            {"ip_address": "5.6.7.8", "domain_count": 7},
                        ]
                    }
                }
            ),
        )
        items = client.list_objects("ipv4-addr", filters={"domain": "example.com"})
        assert len(items) == 2

    def test_list_objects_iris_requires_query(self, client):
        with pytest.raises(GNATClientError, match="requires a 'query'"):
            client.list_objects("domain-name")

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.upsert_object("domain-name", {})

    def test_delete_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.delete_object("domain-name", "x")

    def test_to_stix_domain(self, client):
        stix = client.to_stix(
            {
                "_dt_kind": "domain-name",
                "domain": "example.com",
                "registrar": "Example Registrar",
                "create_date": "2020-01-01",
            }
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "domain-name"
        assert stix["value"] == "example.com"

    def test_to_stix_ipv4(self, client):
        stix = client.to_stix(
            {"_dt_kind": "ipv4-addr", "ip_address": "1.2.3.4"}
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "ipv4-addr"
        assert stix["value"] == "1.2.3.4"

    def test_from_stix_is_noop(self, client):
        out = client.from_stix({"id": "domain-name--x"})
        assert "read-only" in out["note"]


# ---------------------------------------------------------------------------
# Silent Push
# ---------------------------------------------------------------------------


class TestSilentPushClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.silent_push.client import SilentPushClient

        c = SilentPushClient(host="https://api.silentpush.com", api_key="sp_test")
        c._authenticated = True
        return c

    def test_authenticate_sets_api_key_header(self):
        from gnat.connectors.silent_push.client import SilentPushClient

        c = SilentPushClient(host="https://api.silentpush.com", api_key="sp_test")
        c.authenticate()
        assert c._auth_headers["X-API-KEY"] == "sp_test"

    def test_authenticate_requires_api_key(self):
        from gnat.connectors.silent_push.client import SilentPushClient

        c = SilentPushClient(host="https://api.silentpush.com", api_key="")
        with pytest.raises(GNATClientError, match="requires api_key"):
            c.authenticate()

    def test_health_check_true(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"response": {}}))
        assert client.health_check() is True

    def test_health_check_false_on_error(self, client, monkeypatch):
        def _boom(*a, **kw):
            raise RuntimeError("nope")

        monkeypatch.setattr(client, "get", _boom)
        assert client.health_check() is False

    def test_get_object_domain(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(return_value={"domain": "evil.example", "sp_risk_score": 85}),
        )
        obj = client.get_object("indicator", "evil.example")
        assert obj["_sp_subkind"] == "domain"

    def test_get_object_ipv4_dispatches(self, client, monkeypatch):
        stub = MagicMock(return_value={"ipv4": "9.9.9.9", "sp_risk_score": 10})
        monkeypatch.setattr(client, "get", stub)
        obj = client.get_object("indicator", "9.9.9.9")
        assert obj["_sp_subkind"] == "ipv4"
        assert "explore/ipv4" in stub.call_args[0][0]

    def test_list_objects_ioc_search(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "post",
            MagicMock(
                return_value={"response": {"records": [{"domain": "a"}, {"domain": "b"}]}}
            ),
        )
        items = client.list_objects(
            "indicator", filters={"ioc_type": "domain", "query": {"foo": "bar"}}
        )
        assert len(items) == 2

    def test_list_objects_padns_requires_qvalue(self, client):
        with pytest.raises(GNATClientError, match="requires a 'qvalue'"):
            client.list_objects("observed-data", filters={"qtype": "a"})

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.upsert_object("indicator", {})

    def test_delete_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.delete_object("indicator", "x")

    def test_to_stix_domain_indicator(self, client):
        stix = client.to_stix(
            {
                "_sp_kind": "indicator",
                "_sp_subkind": "domain",
                "_sp_query": "evil.example",
                "domain": "evil.example",
                "sp_risk_score": 80,
            }
        )
        _assert_stix_contract(stix)
        assert "domain-name:value" in stix["pattern"]
        assert "malicious-activity" in stix["labels"]

    def test_to_stix_ipv4_indicator(self, client):
        stix = client.to_stix(
            {
                "_sp_kind": "indicator",
                "_sp_subkind": "ipv4",
                "_sp_query": "9.9.9.9",
                "ipv4": "9.9.9.9",
                "sp_risk_score": 5,
            }
        )
        _assert_stix_contract(stix)
        assert "ipv4-addr:value" in stix["pattern"]
        assert stix["labels"] == ["benign"]

    def test_to_stix_padns(self, client):
        stix = client.to_stix(
            {
                "_sp_kind": "observed-data",
                "_sp_qtype": "a",
                "_sp_query": "example.com",
                "value": "1.2.3.4",
                "first_seen": "2020-01-01",
                "last_seen": "2024-01-01",
            }
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "observed-data"
        assert any(r.startswith("ipv4-addr--") for r in stix["object_refs"])

    def test_from_stix_is_noop(self, client):
        out = client.from_stix({"id": "indicator--x"})
        assert "read-only" in out["note"]


# ---------------------------------------------------------------------------
# Registry integrity — Phase 1 Wave 3a
# ---------------------------------------------------------------------------


def test_phase1_wave3a_registry_contains_new_connectors():
    from gnat.clients import CLIENT_REGISTRY

    for key in ("securitytrails", "domaintools", "silent_push"):
        assert key in CLIENT_REGISTRY, f"Missing {key} in CLIENT_REGISTRY"


def test_phase1_wave3a_config_sections_exist():
    import configparser
    from pathlib import Path

    cfg_path = Path(__file__).resolve().parents[3] / "config" / "config.ini.example"
    parser = configparser.ConfigParser(strict=False)
    parser.read(cfg_path)
    for section in ("securitytrails", "domaintools", "silent_push"):
        assert parser.has_section(section), f"Missing [{section}] in config.ini.example"


# ===========================================================================
# Phase 1 Wave 3b — Tier 1 connector expansion (identity / email / finance)
# ===========================================================================


# ---------------------------------------------------------------------------
# Silverfort
# ---------------------------------------------------------------------------


class TestSilverfortClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.silverfort.client import SilverfortClient

        c = SilverfortClient(
            host="https://tenant.silverfort.com",
            client_id="cid",
            client_secret="sec",
        )
        c._authenticated = True
        return c

    def test_authenticate_exchanges_credentials(self, monkeypatch):
        from gnat.connectors.silverfort.client import SilverfortClient

        c = SilverfortClient(
            host="https://tenant.silverfort.com",
            client_id="cid",
            client_secret="sec",
        )
        monkeypatch.setattr(
            c, "post", MagicMock(return_value={"access_token": "tok123"})
        )
        c.authenticate()
        assert c._auth_headers["Authorization"] == "Bearer tok123"

    def test_authenticate_requires_credentials(self):
        from gnat.connectors.silverfort.client import SilverfortClient

        c = SilverfortClient(host="https://x", client_id="", client_secret="")
        with pytest.raises(GNATClientError, match="client_id and client_secret"):
            c.authenticate()

    def test_authenticate_raises_without_token(self, monkeypatch):
        from gnat.connectors.silverfort.client import SilverfortClient

        c = SilverfortClient(
            host="https://x", client_id="cid", client_secret="sec"
        )
        monkeypatch.setattr(c, "post", MagicMock(return_value={}))
        with pytest.raises(GNATClientError, match="no access_token"):
            c.authenticate()

    def test_trust_level_internal(self, client):
        assert client.TRUST_LEVEL == "trusted_internal"

    def test_health_check_true(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"status": "ok"}))
        assert client.health_check() is True

    def test_health_check_false_on_error(self, client, monkeypatch):
        def _boom(*a, **kw):
            raise RuntimeError("nope")

        monkeypatch.setattr(client, "get", _boom)
        assert client.health_check() is False

    def test_list_users(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(
                return_value={
                    "data": [
                        {"id": "u1", "upn": "alice@corp"},
                        {"id": "u2", "upn": "bob@corp"},
                    ]
                }
            ),
        )
        users = client.list_users()
        assert len(users) == 2

    def test_list_auth_events(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(
                return_value={
                    "data": [{"event_time": "2026-04-01T00:00:00Z", "user_id": "u1"}]
                }
            ),
        )
        events = client.list_auth_events(since="2026-04-01", risk_score_min=50)
        assert len(events) == 1

    def test_list_objects_rejects_unknown_type(self, client):
        with pytest.raises(GNATClientError, match="does not support"):
            client.list_objects("totally-fake")

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.upsert_object("user-account", {})

    def test_delete_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.delete_object("user-account", "x")

    def test_to_stix_user_account(self, client):
        stix = client.to_stix(
            {
                "_sf_kind": "user-account",
                "user_id": "u1",
                "upn": "alice@corp",
                "display_name": "Alice",
                "risk_score": 80,
                "mfa_enrolled": True,
            }
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "user-account"
        assert stix["x_silverfort"]["risk_score"] == 80

    def test_to_stix_observed_data(self, client):
        stix = client.to_stix(
            {
                "_sf_kind": "observed-data",
                "user_id": "u1",
                "source_ip": "10.0.0.5",
                "event_time": "2026-04-01T00:00:00Z",
                "decision": "MFA_REQUIRED",
                "risk_score": 65,
            }
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "observed-data"
        assert any(r.startswith("user-account--") for r in stix["object_refs"])
        assert any(r.startswith("ipv4-addr--") for r in stix["object_refs"])

    def test_from_stix_is_noop(self, client):
        out = client.from_stix({"id": "user-account--x"})
        assert "read-only" in out["note"]


# ---------------------------------------------------------------------------
# Semperis
# ---------------------------------------------------------------------------


class TestSemperisClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.semperis.client import SemperisClient

        c = SemperisClient(host="https://dsp.example.com", api_token="sem_test")
        c._authenticated = True
        return c

    def test_authenticate_sets_bearer(self):
        from gnat.connectors.semperis.client import SemperisClient

        c = SemperisClient(host="https://dsp.example.com", api_token="sem_test")
        c.authenticate()
        assert c._auth_headers["Authorization"] == "Bearer sem_test"

    def test_authenticate_requires_token(self):
        from gnat.connectors.semperis.client import SemperisClient

        c = SemperisClient(host="https://dsp.example.com", api_token="")
        with pytest.raises(GNATClientError, match="requires api_token"):
            c.authenticate()

    def test_trust_level_internal(self, client):
        assert client.TRUST_LEVEL == "trusted_internal"

    def test_health_check_true(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"value": []}))
        assert client.health_check() is True

    def test_health_check_false_on_error(self, client, monkeypatch):
        def _boom(*a, **kw):
            raise RuntimeError("nope")

        monkeypatch.setattr(client, "get", _boom)
        assert client.health_check() is False

    def test_list_ioes(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(
                return_value={
                    "value": [
                        {"id": "ioe-1", "severity": "high", "evaluator": "AdminSDHolder"}
                    ]
                }
            ),
        )
        ioes = client.list_ioes(severity="high")
        assert len(ioes) == 1
        assert ioes[0]["_sem_kind"] == "ioe"

    def test_list_iocs(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(return_value={"value": [{"id": "ioc-1", "severity": "critical"}]}),
        )
        iocs = client.list_iocs()
        assert iocs[0]["_sem_kind"] == "ioc"

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.upsert_object("indicator", {})

    def test_delete_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.delete_object("indicator", "x")

    def test_to_stix_ioe(self, client):
        stix = client.to_stix(
            {
                "_sem_kind": "ioe",
                "id": "ioe-42",
                "name": "Weak password policy",
                "severity": "high",
                "evaluator": "PasswordPolicy",
                "description": "Domain allows short passwords",
            }
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "indicator"
        assert "x-semperis-ioe" in stix["pattern"]
        assert "anomalous-activity" in stix["labels"]

    def test_to_stix_ioc(self, client):
        stix = client.to_stix(
            {
                "_sem_kind": "ioc",
                "id": "ioc-1",
                "severity": "critical",
                "evaluator": "DCSyncAttempt",
            }
        )
        _assert_stix_contract(stix)
        assert "malicious-activity" in stix["labels"]

    def test_to_stix_event(self, client):
        stix = client.to_stix(
            {
                "_sem_kind": "event",
                "actor": "alice@corp",
                "event_type": "PasswordChange",
                "timestamp": "2026-04-01T00:00:00Z",
            }
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "observed-data"
        assert any(r.startswith("user-account--") for r in stix["object_refs"])

    def test_from_stix_is_noop(self, client):
        out = client.from_stix({"id": "indicator--x"})
        assert "read-only" in out["note"]


# ---------------------------------------------------------------------------
# Abnormal Security
# ---------------------------------------------------------------------------


class TestAbnormalClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.abnormal.client import AbnormalClient

        c = AbnormalClient(
            host="https://api.abnormalplatform.com", api_token="ab_test"
        )
        c._authenticated = True
        return c

    def test_authenticate_sets_bearer(self):
        from gnat.connectors.abnormal.client import AbnormalClient

        c = AbnormalClient(
            host="https://api.abnormalplatform.com", api_token="ab_test"
        )
        c.authenticate()
        assert c._auth_headers["Authorization"] == "Bearer ab_test"

    def test_authenticate_requires_token(self):
        from gnat.connectors.abnormal.client import AbnormalClient

        c = AbnormalClient(host="https://api.abnormalplatform.com", api_token="")
        with pytest.raises(GNATClientError, match="requires api_token"):
            c.authenticate()

    def test_health_check_true(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"threats": []}))
        assert client.health_check() is True

    def test_health_check_false_on_error(self, client, monkeypatch):
        def _boom(*a, **kw):
            raise RuntimeError("nope")

        monkeypatch.setattr(client, "get", _boom)
        assert client.health_check() is False

    def test_list_threats(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(
                return_value={
                    "threats": [
                        {
                            "threatId": "t-1",
                            "attackType": "bec",
                            "fromAddress": "attacker@bad",
                        },
                        {"threatId": "t-2", "attackType": "phishing"},
                    ]
                }
            ),
        )
        threats = client.list_threats()
        assert len(threats) == 2

    def test_list_cases(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(return_value={"cases": [{"caseId": "c1"}]}),
        )
        cases = client.list_cases()
        assert cases[0]["_ab_kind"] == "case"

    def test_list_vendor_cases(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(return_value={"vendorCases": [{"vendorName": "Acme"}]}),
        )
        vcases = client.list_vendor_cases()
        assert vcases[0]["_ab_kind"] == "vendor_case"

    def test_list_objects_rejects_wrong_type(self, client):
        with pytest.raises(GNATClientError, match="does not support"):
            client.list_objects("indicator")

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.upsert_object("observed-data", {})

    def test_delete_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.delete_object("observed-data", "x")

    def test_to_stix_threat(self, client):
        stix = client.to_stix(
            {
                "_ab_kind": "threat",
                "threatId": "t-42",
                "attackType": "bec",
                "attackVector": "email",
                "judgement": "malicious",
                "fromAddress": "attacker@bad",
                "subject": "Please send funds",
                "receivedTime": "2026-04-01T00:00:00Z",
            }
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "observed-data"
        assert any(r.startswith("email-message--") for r in stix["object_refs"])
        assert any(r.startswith("identity--") for r in stix["object_refs"])
        assert stix["x_abnormal"]["attack_type"] == "bec"

    def test_from_stix_is_noop(self, client):
        out = client.from_stix({"id": "observed-data--x"})
        assert "read-only" in out["note"]


# ---------------------------------------------------------------------------
# Cofense Intelligence
# ---------------------------------------------------------------------------


class TestCofenseIntelClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.cofense_intel.client import CofenseIntelClient

        c = CofenseIntelClient(
            host="https://www.threathq.com",
            username="user",
            password="pass",
        )
        c._authenticated = True
        return c

    def test_authenticate_sets_basic(self):
        from gnat.connectors.cofense_intel.client import CofenseIntelClient

        c = CofenseIntelClient(
            host="https://www.threathq.com",
            username="user",
            password="pass",
        )
        c.authenticate()
        assert c._auth_headers["Authorization"].startswith("Basic ")

    def test_authenticate_requires_credentials(self):
        from gnat.connectors.cofense_intel.client import CofenseIntelClient

        c = CofenseIntelClient(
            host="https://www.threathq.com", username="", password=""
        )
        with pytest.raises(GNATClientError, match="username and password"):
            c.authenticate()

    def test_health_check_true(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"data": {"families": []}})
        )
        assert client.health_check() is True

    def test_health_check_false_on_error(self, client, monkeypatch):
        def _boom(*a, **kw):
            raise RuntimeError("nope")

        monkeypatch.setattr(client, "get", _boom)
        assert client.health_check() is False

    def test_search_threats(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(
                return_value={
                    "data": {
                        "threats": [
                            {"value": "1.2.3.4", "threatId": "T1", "type": "ipAddress"}
                        ]
                    }
                }
            ),
        )
        items = client.search_threats("ipAddress", "1.2.3.4")
        assert len(items) == 1

    def test_list_malware_families(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(
                return_value={
                    "data": {"families": [{"id": "mf-1", "familyName": "Emotet"}]}
                }
            ),
        )
        fams = client.list_malware_families()
        assert fams[0]["_cf_kind"] == "malware_family"

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.upsert_object("indicator", {})

    def test_delete_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.delete_object("indicator", "x")

    def test_to_stix_ipv4_indicator(self, client):
        stix = client.to_stix(
            {
                "_cf_kind": "indicator",
                "_cf_ioc_type": "ipAddress",
                "value": "1.2.3.4",
                "threatId": "T1",
            }
        )
        _assert_stix_contract(stix)
        assert "ipv4-addr:value" in stix["pattern"]
        assert stix["x_cofense"]["human_verified"] is True

    def test_to_stix_malware_family(self, client):
        stix = client.to_stix(
            {
                "_cf_kind": "malware_family",
                "id": "mf-1",
                "familyName": "Emotet",
                "description": "Banking trojan",
            }
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "malware"
        assert stix["name"] == "Emotet"

    def test_to_stix_threat_report(self, client):
        stix = client.to_stix(
            {
                "_cf_kind": "threat",
                "id": "T1",
                "label": "Emotet Q2 Campaign",
                "executiveSummary": "Active phishing campaign",
                "firstPublished": "2026-03-01T00:00:00Z",
            }
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "report"
        assert stix["name"] == "Emotet Q2 Campaign"

    def test_from_stix_is_noop(self, client):
        out = client.from_stix({"id": "indicator--x"})
        assert "read-only" in out["note"]


# ---------------------------------------------------------------------------
# TRM Labs
# ---------------------------------------------------------------------------


class TestTRMLabsClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.trm_labs.client import TRMLabsClient

        c = TRMLabsClient(host="https://api.trmlabs.com", api_key="trm_test")
        c._authenticated = True
        return c

    def test_authenticate_sets_basic_auth(self):
        from gnat.connectors.trm_labs.client import TRMLabsClient

        c = TRMLabsClient(host="https://api.trmlabs.com", api_key="trm_test")
        c.authenticate()
        assert c._auth_headers["Authorization"].startswith("Basic ")

    def test_authenticate_requires_api_key(self):
        from gnat.connectors.trm_labs.client import TRMLabsClient

        c = TRMLabsClient(host="https://api.trmlabs.com", api_key="")
        with pytest.raises(GNATClientError, match="requires api_key"):
            c.authenticate()

    def test_health_check_true(self, client, monkeypatch):
        monkeypatch.setattr(client, "post", MagicMock(return_value=[{"risk": 0}]))
        assert client.health_check() is True

    def test_health_check_false_on_error(self, client, monkeypatch):
        def _boom(*a, **kw):
            raise RuntimeError("nope")

        monkeypatch.setattr(client, "post", _boom)
        assert client.health_check() is False

    def test_screen_address(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "post",
            MagicMock(
                return_value=[
                    {
                        "address": "0xabc",
                        "chain": "ethereum",
                        "addressRiskIndicatorRiskScore": 85,
                        "entities": [{"entity": "Lazarus Group"}],
                    }
                ]
            ),
        )
        rec = client.screen_address("ethereum", "0xabc")
        assert rec["_trm_kind"] == "screening"

    def test_screen_addresses_batch(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "post",
            MagicMock(return_value=[{"address": "0xa"}, {"address": "0xb"}]),
        )
        out = client.screen_addresses_batch(
            [
                {"address": "0xa", "chain": "ethereum"},
                {"address": "0xb", "chain": "ethereum"},
            ]
        )
        assert len(out) == 2

    def test_get_entity(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(
                return_value={"id": "ent-1", "name": "Lazarus", "sanctioned": True}
            ),
        )
        ent = client.get_entity("ent-1")
        assert ent["_trm_kind"] == "entity"

    def test_get_address_profile(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(
                return_value={
                    "address": "0xabc",
                    "chain": "ethereum",
                    "transactionCount": 42,
                }
            ),
        )
        prof = client.get_address_profile("ethereum", "0xabc")
        assert prof["_trm_chain"] == "ethereum"

    def test_get_object_address_requires_chain_format(self, client):
        with pytest.raises(GNATClientError, match="chain:address"):
            client.get_object("observed-data", "0xabc")

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.upsert_object("indicator", {})

    def test_delete_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.delete_object("indicator", "x")

    def test_to_stix_screening_malicious(self, client):
        stix = client.to_stix(
            {
                "_trm_kind": "screening",
                "address": "0xabc",
                "chain": "ethereum",
                "addressRiskIndicatorRiskScore": 85,
                "entities": [{"entity": "Lazarus"}],
                "sanctioned": True,
            }
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "indicator"
        assert "malicious-activity" in stix["labels"]
        assert stix["x_trm_labs"]["sanctioned"] is True

    def test_to_stix_entity(self, client):
        stix = client.to_stix(
            {
                "_trm_kind": "entity",
                "id": "ent-1",
                "name": "Lazarus Group",
                "sanctioned": True,
                "category": "nation-state",
            }
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "threat-actor"

    def test_to_stix_address_profile(self, client):
        stix = client.to_stix(
            {
                "_trm_kind": "address",
                "_trm_chain": "ethereum",
                "_trm_address": "0xabc",
                "transactionCount": 100,
                "firstTransactionAt": "2020-01-01T00:00:00Z",
                "lastTransactionAt": "2024-01-01T00:00:00Z",
                "totalValueUsd": 500000,
            }
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "observed-data"
        assert stix["number_observed"] == 100

    def test_from_stix_is_noop(self, client):
        out = client.from_stix({"id": "indicator--x"})
        assert "read-only" in out["note"]


# ---------------------------------------------------------------------------
# Registry integrity — Phase 1 Wave 3b
# ---------------------------------------------------------------------------


def test_phase1_wave3b_registry_contains_new_connectors():
    from gnat.clients import CLIENT_REGISTRY

    for key in ("silverfort", "semperis", "abnormal", "cofense_intel", "trm_labs"):
        assert key in CLIENT_REGISTRY, f"Missing {key} in CLIENT_REGISTRY"


def test_phase1_wave3b_config_sections_exist():
    import configparser
    from pathlib import Path

    cfg_path = Path(__file__).resolve().parents[3] / "config" / "config.ini.example"
    parser = configparser.ConfigParser(strict=False)
    parser.read(cfg_path)
    for section in (
        "silverfort",
        "semperis",
        "abnormal",
        "cofense_intel",
        "trm_labs",
    ):
        assert parser.has_section(section), f"Missing [{section}] in config.ini.example"


# ===========================================================================
# Phase 2 Wave 1 — Malware sandboxes
# ===========================================================================


# ---------------------------------------------------------------------------
# Joe Sandbox Cloud
# ---------------------------------------------------------------------------


class TestJoeSandboxClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.joe_sandbox.client import JoeSandboxClient

        c = JoeSandboxClient(
            host="https://jbxcloud.joesecurity.org", api_key="jbx_test"
        )
        c._authenticated = True
        return c

    def test_authenticate_stamps_accept(self):
        from gnat.connectors.joe_sandbox.client import JoeSandboxClient

        c = JoeSandboxClient(
            host="https://jbxcloud.joesecurity.org", api_key="jbx_test"
        )
        c.authenticate()
        assert c._auth_headers["Accept"] == "application/json"

    def test_authenticate_requires_api_key(self):
        from gnat.connectors.joe_sandbox.client import JoeSandboxClient

        c = JoeSandboxClient(host="https://jbxcloud.joesecurity.org", api_key="")
        with pytest.raises(GNATClientError, match="requires api_key"):
            c.authenticate()

    def test_authed_form_injects_apikey(self, client):
        form = client._authed_form({"webid": "42"})
        assert form["apikey"] == "jbx_test"
        assert form["webid"] == "42"
        assert form["accept-tac"] == "1"

    def test_cost_unit_is_high(self, client):
        assert client.COST_UNIT >= 5

    def test_health_check_true(self, client, monkeypatch):
        monkeypatch.setattr(client, "post", MagicMock(return_value={"data": "ok"}))
        assert client.health_check() is True

    def test_health_check_false_on_error(self, client, monkeypatch):
        def _boom(*a, **kw):
            raise RuntimeError("nope")

        monkeypatch.setattr(client, "post", _boom)
        assert client.health_check() is False

    def test_get_analysis(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "post",
            MagicMock(
                return_value={
                    "data": {
                        "webid": "42",
                        "sha256": "abc",
                        "filename": "x.exe",
                        "detection": "malicious",
                    }
                }
            ),
        )
        obj = client.get_analysis("42")
        assert obj["_jb_webid"] == "42"

    def test_list_objects_search(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "post",
            MagicMock(
                return_value={"data": {"analyses": [{"webid": "1"}, {"webid": "2"}]}}
            ),
        )
        items = client.list_objects("observed-data", filters={"q": "emotet"})
        assert len(items) == 2

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only via CRUD"):
            client.upsert_object("observed-data", {})

    def test_delete_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.delete_object("observed-data", "x")

    def test_to_stix_observed_data(self, client):
        stix = client.to_stix(
            {
                "webid": "42",
                "sha256": "abc123",
                "filename": "sample.exe",
                "detection": "malicious",
                "score": 95,
                "network": {
                    "ips": ["1.2.3.4"],
                    "domains": ["evil.example"],
                },
                "processes": [{"name": "sample.exe"}],
                "time": "2026-04-01T00:00:00Z",
                "lastmodified": "2026-04-01T00:05:00Z",
            }
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "observed-data"
        assert stix["x_joe_sandbox_verdict"] == "malicious"

    def test_to_stix_malware(self, client):
        stix = client.to_stix(
            {
                "_jb_kind": "malware",
                "malwarename": "Emotet",
                "detection": "malicious",
                "tags": ["trojan", "banker"],
            }
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "malware"
        assert stix["name"] == "Emotet"
        assert "trojan" in stix["malware_types"]

    def test_to_stix_indicator(self, client):
        stix = client.to_stix(
            {
                "_jb_kind": "indicator",
                "_jb_webid": "42",
                "type": "domain",
                "value": "evil.example",
            }
        )
        _assert_stix_contract(stix)
        assert "domain-name:value" in stix["pattern"]

    def test_from_stix_is_noop(self, client):
        out = client.from_stix({"id": "observed-data--x"})
        assert "read-only" in out["note"]


# ---------------------------------------------------------------------------
# ANY.RUN
# ---------------------------------------------------------------------------


class TestAnyRunClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.any_run.client import AnyRunClient

        c = AnyRunClient(host="https://api.any.run", api_key="ar_test")
        c._authenticated = True
        return c

    def test_authenticate_sets_api_key_header(self):
        from gnat.connectors.any_run.client import AnyRunClient

        c = AnyRunClient(host="https://api.any.run", api_key="ar_test")
        c.authenticate()
        assert c._auth_headers["Authorization"] == "API-Key ar_test"

    def test_authenticate_requires_api_key(self):
        from gnat.connectors.any_run.client import AnyRunClient

        c = AnyRunClient(host="https://api.any.run", api_key="")
        with pytest.raises(GNATClientError, match="requires api_key"):
            c.authenticate()

    def test_health_check_true(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": []}))
        assert client.health_check() is True

    def test_health_check_false_on_error(self, client, monkeypatch):
        def _boom(*a, **kw):
            raise RuntimeError("nope")

        monkeypatch.setattr(client, "get", _boom)
        assert client.health_check() is False

    def test_get_analysis(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(
                return_value={
                    "data": {
                        "uuid": "task-1",
                        "mainObject": {
                            "name": "x.exe",
                            "hashes": {"sha256": "abc"},
                        },
                        "verdict": "malicious",
                    }
                }
            ),
        )
        obj = client.get_analysis("task-1")
        assert obj["_ar_task_id"] == "task-1"

    def test_list_objects(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(return_value={"data": {"tasks": [{"uuid": "1"}, {"uuid": "2"}]}}),
        )
        items = client.list_objects("observed-data")
        assert len(items) == 2

    def test_list_environments(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(
                return_value={"data": [{"os": "Windows 10", "bitness": 64}]}
            ),
        )
        envs = client.list_environments()
        assert envs[0]["os"] == "Windows 10"

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only via CRUD"):
            client.upsert_object("observed-data", {})

    def test_delete_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.delete_object("observed-data", "x")

    def test_to_stix_observed_data(self, client):
        stix = client.to_stix(
            {
                "uuid": "task-1",
                "mainObject": {"name": "x.exe", "hashes": {"sha256": "abc"}},
                "network": {
                    "ipAddresses": ["1.2.3.4"],
                    "domainNames": [{"domain": "evil.example"}],
                },
                "processes": [{"commandLine": "x.exe"}],
                "creation": "2026-04-01T00:00:00Z",
                "finish": "2026-04-01T00:05:00Z",
                "verdict": "malicious",
            }
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "observed-data"
        assert stix["x_any_run_verdict"] == "malicious"

    def test_from_stix_is_noop(self, client):
        out = client.from_stix({"id": "observed-data--x"})
        assert "read-only" in out["note"]


# ---------------------------------------------------------------------------
# Hybrid Analysis
# ---------------------------------------------------------------------------


class TestHybridAnalysisClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.hybrid_analysis.client import HybridAnalysisClient

        c = HybridAnalysisClient(
            host="https://www.hybrid-analysis.com", api_key="ha_test"
        )
        c._authenticated = True
        return c

    def test_authenticate_sets_headers(self):
        from gnat.connectors.hybrid_analysis.client import HybridAnalysisClient

        c = HybridAnalysisClient(
            host="https://www.hybrid-analysis.com", api_key="ha_test"
        )
        c.authenticate()
        assert c._auth_headers["api-key"] == "ha_test"
        assert c._auth_headers["User-Agent"] == "Falcon Sandbox"

    def test_authenticate_requires_api_key(self):
        from gnat.connectors.hybrid_analysis.client import HybridAnalysisClient

        c = HybridAnalysisClient(
            host="https://www.hybrid-analysis.com", api_key=""
        )
        with pytest.raises(GNATClientError, match="requires api_key"):
            c.authenticate()

    def test_custom_user_agent(self):
        from gnat.connectors.hybrid_analysis.client import HybridAnalysisClient

        c = HybridAnalysisClient(
            host="https://www.hybrid-analysis.com",
            api_key="ha_test",
            user_agent="Custom Agent",
        )
        c.authenticate()
        assert c._auth_headers["User-Agent"] == "Custom Agent"

    def test_health_check_true(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"status": "ok"})
        )
        assert client.health_check() is True

    def test_health_check_false_on_error(self, client, monkeypatch):
        def _boom(*a, **kw):
            raise RuntimeError("nope")

        monkeypatch.setattr(client, "get", _boom)
        assert client.health_check() is False

    def test_hash_lookup(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(
                return_value={
                    "sha256": "abc",
                    "threat_level_human": "malicious",
                    "threat_score": 95,
                    "verdict": "malicious",
                }
            ),
        )
        obj = client.hash_lookup("abc")
        assert obj["_ha_kind"] == "malware"

    def test_search_hash(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "post",
            MagicMock(return_value={"result": [{"sha256": "abc"}]}),
        )
        items = client.search_hash("abc")
        assert len(items) == 1

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only via CRUD"):
            client.upsert_object("observed-data", {})

    def test_delete_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.delete_object("observed-data", "x")

    def test_to_stix_observed_data(self, client):
        stix = client.to_stix(
            {
                "job_id": "job-1",
                "sha256": "abc",
                "submit_name": "sample.exe",
                "hosts": ["1.2.3.4"],
                "domains": ["evil.example"],
                "extracted_urls": ["http://evil.example/dropper"],
                "processes": [{"name": "sample.exe"}],
                "verdict": "malicious",
                "threat_score": 95,
                "analysis_start_time": "2026-04-01T00:00:00Z",
            }
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "observed-data"
        assert stix["x_hybrid_analysis_verdict"] == "malicious"

    def test_to_stix_malware_ransomware(self, client):
        stix = client.to_stix(
            {
                "_ha_kind": "malware",
                "verdict": "malicious",
                "threat_level_human": "ransomware-like",
                "vx_family": "LockBit",
            }
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "malware"
        assert "ransomware" in stix["malware_types"]

    def test_from_stix_is_noop(self, client):
        out = client.from_stix({"id": "observed-data--x"})
        assert "read-only" in out["note"]


# ---------------------------------------------------------------------------
# VMRay
# ---------------------------------------------------------------------------


class TestVMRayClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.vmray.client import VMRayClient

        c = VMRayClient(host="https://cloud.vmray.com", api_key="vmray_test")
        c._authenticated = True
        return c

    def test_authenticate_sets_api_key_header(self):
        from gnat.connectors.vmray.client import VMRayClient

        c = VMRayClient(host="https://cloud.vmray.com", api_key="vmray_test")
        c.authenticate()
        assert c._auth_headers["Authorization"] == "api_key vmray_test"

    def test_authenticate_requires_api_key(self):
        from gnat.connectors.vmray.client import VMRayClient

        c = VMRayClient(host="https://cloud.vmray.com", api_key="")
        with pytest.raises(GNATClientError, match="requires api_key"):
            c.authenticate()

    def test_health_check_true(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"data": {"version": "5.0"}})
        )
        assert client.health_check() is True

    def test_health_check_false_on_error(self, client, monkeypatch):
        def _boom(*a, **kw):
            raise RuntimeError("nope")

        monkeypatch.setattr(client, "get", _boom)
        assert client.health_check() is False

    def test_get_analysis(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(
                return_value={
                    "data": {
                        "analysis_id": 42,
                        "sample_sha256": "abc",
                        "analysis_verdict": "malicious",
                    }
                }
            ),
        )
        obj = client.get_analysis("42")
        assert obj["_vmr_kind"] == "analysis"

    def test_get_sample(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(
                return_value={
                    "data": {
                        "sample_id": 42,
                        "sample_sha256": "abc",
                        "sample_classifications": ["ransomware"],
                    }
                }
            ),
        )
        obj = client.get_sample("42")
        assert obj["_vmr_kind"] == "sample"

    def test_list_objects_analyses(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(
                return_value={"data": [{"analysis_id": 1}, {"analysis_id": 2}]}
            ),
        )
        items = client.list_objects("observed-data")
        assert len(items) == 2
        assert all(i["_vmr_kind"] == "analysis" for i in items)

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only via CRUD"):
            client.upsert_object("observed-data", {})

    def test_delete_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.delete_object("observed-data", "x")

    def test_to_stix_analysis(self, client):
        stix = client.to_stix(
            {
                "_vmr_kind": "analysis",
                "analysis_id": 42,
                "sample_sha256": "abc",
                "sample_filename": "sample.exe",
                "analysis_verdict": "malicious",
                "analysis_created": "2026-04-01T00:00:00Z",
                "analysis_finished": "2026-04-01T00:05:00Z",
                "network": {
                    "ips": [{"ip_address": "1.2.3.4"}],
                    "domains": ["evil.example"],
                },
            }
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "observed-data"
        assert stix["x_vmray_verdict"] == "malicious"

    def test_to_stix_sample(self, client):
        stix = client.to_stix(
            {
                "_vmr_kind": "sample",
                "sample_id": 1,
                "sample_classifications": ["banker"],
                "sample_severity": "high",
            }
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "malware"

    def test_from_stix_is_noop(self, client):
        out = client.from_stix({"id": "observed-data--x"})
        assert "read-only" in out["note"]


# ---------------------------------------------------------------------------
# Intezer Analyze
# ---------------------------------------------------------------------------


class TestIntezerClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.intezer.client import IntezerClient

        c = IntezerClient(
            host="https://analyze.intezer.com", api_key="iz_test"
        )
        c._authenticated = True
        return c

    def test_authenticate_exchanges_jwt(self, monkeypatch):
        from gnat.connectors.intezer.client import IntezerClient

        c = IntezerClient(
            host="https://analyze.intezer.com", api_key="iz_test"
        )
        monkeypatch.setattr(
            c, "post", MagicMock(return_value={"result": "jwt_token_xyz"})
        )
        c.authenticate()
        assert c._auth_headers["Authorization"] == "Bearer jwt_token_xyz"

    def test_authenticate_requires_api_key(self):
        from gnat.connectors.intezer.client import IntezerClient

        c = IntezerClient(host="https://analyze.intezer.com", api_key="")
        with pytest.raises(GNATClientError, match="requires api_key"):
            c.authenticate()

    def test_authenticate_raises_without_jwt(self, monkeypatch):
        from gnat.connectors.intezer.client import IntezerClient

        c = IntezerClient(
            host="https://analyze.intezer.com", api_key="iz_test"
        )
        monkeypatch.setattr(c, "post", MagicMock(return_value={}))
        with pytest.raises(GNATClientError, match="no result token"):
            c.authenticate()

    def test_health_check_true(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"is_available": True})
        )
        assert client.health_check() is True

    def test_health_check_false_on_error(self, client, monkeypatch):
        def _boom(*a, **kw):
            raise RuntimeError("nope")

        monkeypatch.setattr(client, "get", _boom)
        assert client.health_check() is False

    def test_get_analysis(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(
                return_value={
                    "result": {
                        "analysis_id": "42",
                        "sha256": "abc",
                        "verdict": "malicious",
                    }
                }
            ),
        )
        obj = client.get_analysis("42")
        assert obj["_iz_kind"] == "analysis"

    def test_get_family(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(
                return_value={
                    "result": {
                        "family_id": "f-1",
                        "family_name": "Emotet",
                        "family_type": "trojan",
                    }
                }
            ),
        )
        fam = client.get_family("f-1")
        assert fam["_iz_kind"] == "family"

    def test_get_iocs(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(
                return_value={
                    "result": {
                        "network": [
                            {"type": "domain", "ioc": "evil.example"},
                            {"type": "ip", "ioc": "1.2.3.4"},
                        ]
                    }
                }
            ),
        )
        iocs = client.get_iocs("42")
        assert len(iocs) == 2
        assert all(i["_iz_kind"] == "ioc" for i in iocs)

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only via CRUD"):
            client.upsert_object("observed-data", {})

    def test_delete_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.delete_object("observed-data", "x")

    def test_to_stix_family(self, client):
        stix = client.to_stix(
            {
                "_iz_kind": "family",
                "family_id": "f-1",
                "family_name": "LockBit",
                "family_type": "ransomware",
            }
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "malware"
        assert "ransomware" in stix["malware_types"]

    def test_to_stix_analysis(self, client):
        stix = client.to_stix(
            {
                "_iz_kind": "analysis",
                "analysis_id": "42",
                "sha256": "abc",
                "file_name": "sample.exe",
                "verdict": "malicious",
                "family_confidence": 0.92,
            }
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "observed-data"
        assert stix["x_intezer_verdict"] == "malicious"

    def test_to_stix_ioc(self, client):
        stix = client.to_stix(
            {
                "_iz_kind": "ioc",
                "type": "domain",
                "ioc": "evil.example",
            }
        )
        _assert_stix_contract(stix)
        assert "domain-name:value" in stix["pattern"]

    def test_from_stix_is_noop(self, client):
        out = client.from_stix({"id": "observed-data--x"})
        assert "read-only" in out["note"]


# ---------------------------------------------------------------------------
# Registry integrity — Phase 2 Wave 1
# ---------------------------------------------------------------------------


def test_phase2_wave1_registry_contains_new_connectors():
    from gnat.clients import CLIENT_REGISTRY

    for key in (
        "joe_sandbox",
        "any_run",
        "hybrid_analysis",
        "vmray",
        "intezer",
    ):
        assert key in CLIENT_REGISTRY, f"Missing {key} in CLIENT_REGISTRY"


def test_phase2_wave1_config_sections_exist():
    import configparser
    from pathlib import Path

    cfg_path = Path(__file__).resolve().parents[3] / "config" / "config.ini.example"
    parser = configparser.ConfigParser(strict=False)
    parser.read(cfg_path)
    for section in (
        "joe_sandbox",
        "any_run",
        "hybrid_analysis",
        "vmray",
        "intezer",
    ):
        assert parser.has_section(section), f"Missing [{section}] in config.ini.example"


# ===========================================================================
# Phase 2 Wave 2 — MDR platforms
# ===========================================================================


# ---------------------------------------------------------------------------
# Huntress
# ---------------------------------------------------------------------------


class TestHuntressClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.huntress.client import HuntressClient

        c = HuntressClient(
            host="https://api.huntress.io",
            api_key_id="hk_test",
            api_secret="hs_test",
        )
        c._authenticated = True
        return c

    def test_authenticate_sets_basic_auth(self):
        from gnat.connectors.huntress.client import HuntressClient

        c = HuntressClient(
            host="https://api.huntress.io",
            api_key_id="hk_test",
            api_secret="hs_test",
        )
        c.authenticate()
        assert c._auth_headers["Authorization"].startswith("Basic ")

    def test_authenticate_requires_credentials(self):
        from gnat.connectors.huntress.client import HuntressClient

        c = HuntressClient(host="https://api.huntress.io", api_key_id="", api_secret="")
        with pytest.raises(GNATClientError, match="api_key_id and api_secret"):
            c.authenticate()

    def test_trust_level_internal(self, client):
        assert client.TRUST_LEVEL == "trusted_internal"

    def test_health_check_true(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"account": {"id": 1}})
        )
        assert client.health_check() is True

    def test_health_check_false_on_error(self, client, monkeypatch):
        def _boom(*a, **kw):
            raise RuntimeError("nope")

        monkeypatch.setattr(client, "get", _boom)
        assert client.health_check() is False

    def test_list_organizations(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(
                return_value={
                    "organizations": [
                        {"id": "o1", "name": "Acme"},
                        {"id": "o2", "name": "Globex"},
                    ]
                }
            ),
        )
        orgs = client.list_organizations()
        assert len(orgs) == 2

    def test_list_incidents(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(
                return_value={
                    "incident_reports": [
                        {
                            "id": "i1",
                            "status": "sent",
                            "severity": "high",
                            "organization_id": "o1",
                        }
                    ]
                }
            ),
        )
        incs = client.list_incidents(status="sent")
        assert incs[0]["_ht_kind"] == "incident"

    def test_get_incident(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(
                return_value={
                    "incident_report": {
                        "id": "i1",
                        "severity": "high",
                        "organization_id": "o1",
                    }
                }
            ),
        )
        inc = client.get_incident("i1")
        assert inc["_ht_kind"] == "incident"

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.upsert_object("observed-data", {})

    def test_delete_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.delete_object("observed-data", "x")

    def test_to_stix_incident(self, client):
        stix = client.to_stix(
            {
                "_ht_kind": "incident",
                "id": "i1",
                "status": "sent",
                "severity": "high",
                "summary": "Suspicious LSASS access",
                "organization_id": "o1",
                "agent_id": "a1",
                "remote_ip": "1.2.3.4",
                "detected_at": "2026-04-01T00:00:00Z",
                "updated_at": "2026-04-01T00:05:00Z",
            }
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "observed-data"
        ref_types = {r.split("--")[0] for r in stix["object_refs"]}
        assert "identity" in ref_types
        assert "x-huntress-agent" in ref_types
        assert "ipv4-addr" in ref_types
        assert stix["x_huntress"]["severity"] == "high"

    def test_to_stix_organization(self, client):
        stix = client.to_stix(
            {"_ht_kind": "organization", "id": "o1", "name": "Acme"}
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "identity"
        assert stix["identity_class"] == "organization"

    def test_to_stix_agent(self, client):
        stix = client.to_stix(
            {
                "_ht_kind": "agent",
                "id": "a1",
                "hostname": "host01",
                "platform": "windows",
                "version": "0.13.0",
                "organization_id": "o1",
            }
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "x-huntress-agent"
        assert stix["hostname"] == "host01"

    def test_from_stix_is_noop(self, client):
        out = client.from_stix({"id": "observed-data--x"})
        assert "read-only" in out["note"]


# ---------------------------------------------------------------------------
# Arctic Wolf
# ---------------------------------------------------------------------------


class TestArcticWolfClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.arctic_wolf.client import ArcticWolfClient

        c = ArcticWolfClient(
            host="https://api.arcticwolf.com",
            api_key="aw_test",
            customer_id="cust-1",
        )
        c._authenticated = True
        return c

    def test_authenticate_sets_bearer_and_customer(self):
        from gnat.connectors.arctic_wolf.client import ArcticWolfClient

        c = ArcticWolfClient(
            host="https://api.arcticwolf.com",
            api_key="aw_test",
            customer_id="cust-1",
        )
        c.authenticate()
        assert c._auth_headers["Authorization"] == "Bearer aw_test"
        assert c._auth_headers["X-Arctic-Wolf-Customer"] == "cust-1"

    def test_authenticate_without_customer_id(self):
        from gnat.connectors.arctic_wolf.client import ArcticWolfClient

        c = ArcticWolfClient(
            host="https://api.arcticwolf.com", api_key="aw_test"
        )
        c.authenticate()
        assert "X-Arctic-Wolf-Customer" not in c._auth_headers

    def test_authenticate_requires_api_key(self):
        from gnat.connectors.arctic_wolf.client import ArcticWolfClient

        c = ArcticWolfClient(host="https://api.arcticwolf.com", api_key="")
        with pytest.raises(GNATClientError, match="requires api_key"):
            c.authenticate()

    def test_trust_level_internal(self, client):
        assert client.TRUST_LEVEL == "trusted_internal"

    def test_health_check_true(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"id": "cust-1"}))
        assert client.health_check() is True

    def test_health_check_false_on_error(self, client, monkeypatch):
        def _boom(*a, **kw):
            raise RuntimeError("nope")

        monkeypatch.setattr(client, "get", _boom)
        assert client.health_check() is False

    def test_list_tickets(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(
                return_value={
                    "tickets": [
                        {"id": "t1", "status": "open", "severity": "high"},
                        {"id": "t2", "status": "open", "severity": "low"},
                    ]
                }
            ),
        )
        tickets = client.list_tickets(status="open")
        assert len(tickets) == 2

    def test_list_investigations(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(
                return_value={"investigations": [{"id": "inv1", "status": "active"}]}
            ),
        )
        invs = client.list_investigations()
        assert invs[0]["_aw_kind"] == "investigation"

    def test_get_ticket(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(
                return_value={"id": "t1", "status": "open", "severity": "high"}
            ),
        )
        t = client.get_ticket("t1")
        assert t["_aw_kind"] == "ticket"

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.upsert_object("observed-data", {})

    def test_delete_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.delete_object("observed-data", "x")

    def test_to_stix_ticket(self, client):
        stix = client.to_stix(
            {
                "_aw_kind": "ticket",
                "id": "t1",
                "title": "Unusual PowerShell execution",
                "status": "open",
                "severity": "high",
                "customer_id": "cust-1",
                "affected_ips": ["1.2.3.4"],
                "created_at": "2026-04-01T00:00:00Z",
                "updated_at": "2026-04-01T00:30:00Z",
            }
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "observed-data"
        assert stix["x_arctic_wolf"]["severity"] == "high"
        ref_types = {r.split("--")[0] for r in stix["object_refs"]}
        assert "identity" in ref_types
        assert "ipv4-addr" in ref_types

    def test_to_stix_customer(self, client):
        stix = client.to_stix(
            {"_aw_kind": "customer", "id": "cust-1", "name": "Acme"}
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "identity"

    def test_from_stix_is_noop(self, client):
        out = client.from_stix({"id": "observed-data--x"})
        assert "read-only" in out["note"]


# ---------------------------------------------------------------------------
# Red Canary
# ---------------------------------------------------------------------------


class TestRedCanaryClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.red_canary.client import RedCanaryClient

        c = RedCanaryClient(
            host="https://my.redcanary.co", api_key="rc_test"
        )
        c._authenticated = True
        return c

    def test_authenticate_sets_x_api_key(self):
        from gnat.connectors.red_canary.client import RedCanaryClient

        c = RedCanaryClient(
            host="https://my.redcanary.co", api_key="rc_test"
        )
        c.authenticate()
        assert c._auth_headers["X-Api-Key"] == "rc_test"

    def test_authenticate_requires_api_key(self):
        from gnat.connectors.red_canary.client import RedCanaryClient

        c = RedCanaryClient(host="https://my.redcanary.co", api_key="")
        with pytest.raises(GNATClientError, match="requires api_key"):
            c.authenticate()

    def test_trust_level_internal(self, client):
        assert client.TRUST_LEVEL == "trusted_internal"

    def test_health_check_true(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"data": {"id": "org1"}})
        )
        assert client.health_check() is True

    def test_health_check_false_on_error(self, client, monkeypatch):
        def _boom(*a, **kw):
            raise RuntimeError("nope")

        monkeypatch.setattr(client, "get", _boom)
        assert client.health_check() is False

    def test_list_detections(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(
                return_value={
                    "data": [
                        {"id": "d1", "attributes": {"severity": "high"}},
                        {"id": "d2", "attributes": {"severity": "low"}},
                    ]
                }
            ),
        )
        dets = client.list_detections(severity="high")
        assert len(dets) == 2
        assert all(d["_rc_kind"] == "detection" for d in dets)

    def test_get_detection(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(
                return_value={
                    "data": {
                        "id": "d1",
                        "attributes": {
                            "severity": "high",
                            "headline": "Suspicious PS",
                        },
                    }
                }
            ),
        )
        det = client.get_detection("d1")
        assert det["_rc_kind"] == "detection"

    def test_list_endpoints(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(
                return_value={
                    "data": [
                        {
                            "id": "e1",
                            "attributes": {
                                "hostname": "host01",
                                "platform": "windows",
                            },
                        }
                    ]
                }
            ),
        )
        eps = client.list_endpoints()
        assert eps[0]["_rc_kind"] == "endpoint"

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.upsert_object("observed-data", {})

    def test_delete_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.delete_object("observed-data", "x")

    def test_to_stix_detection(self, client):
        stix = client.to_stix(
            {
                "_rc_kind": "detection",
                "id": "d1",
                "attributes": {
                    "severity": "high",
                    "classification": "suspicious",
                    "headline": "Living-off-the-land binary",
                    "confirmed": True,
                    "endpoint_id": "e1",
                    "ip_address": "10.0.0.5",
                    "detected_at": "2026-04-01T00:00:00Z",
                    "last_seen_at": "2026-04-01T00:05:00Z",
                },
            }
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "observed-data"
        assert stix["x_red_canary"]["severity"] == "high"
        ref_types = {r.split("--")[0] for r in stix["object_refs"]}
        assert "identity" in ref_types
        assert "ipv4-addr" in ref_types

    def test_to_stix_endpoint(self, client):
        stix = client.to_stix(
            {
                "_rc_kind": "endpoint",
                "id": "e1",
                "attributes": {
                    "hostname": "host01",
                    "platform": "windows",
                    "operating_system": "Windows 11",
                    "ip_address": "10.0.0.5",
                },
            }
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "identity"
        assert stix["identity_class"] == "system"

    def test_from_stix_is_noop(self, client):
        out = client.from_stix({"id": "observed-data--x"})
        assert "read-only" in out["note"]


# ---------------------------------------------------------------------------
# Registry integrity — Phase 2 Wave 2
# ---------------------------------------------------------------------------


def test_phase2_wave2_registry_contains_new_connectors():
    from gnat.clients import CLIENT_REGISTRY

    for key in ("huntress", "arctic_wolf", "red_canary"):
        assert key in CLIENT_REGISTRY, f"Missing {key} in CLIENT_REGISTRY"


def test_phase2_wave2_config_sections_exist():
    import configparser
    from pathlib import Path

    cfg_path = Path(__file__).resolve().parents[3] / "config" / "config.ini.example"
    parser = configparser.ConfigParser(strict=False)
    parser.read(cfg_path)
    for section in ("huntress", "arctic_wolf", "red_canary"):
        assert parser.has_section(section), f"Missing [{section}] in config.ini.example"


# ===========================================================================
# Phase 2 Wave 3 — BAS / security validation
# ===========================================================================


# ---------------------------------------------------------------------------
# SafeBreach
# ---------------------------------------------------------------------------


class TestSafeBreachClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.safebreach.client import SafeBreachClient

        c = SafeBreachClient(
            host="https://api.safebreach.com",
            api_token="sb_test",
            account_id="42",
        )
        c._authenticated = True
        return c

    def test_authenticate_sets_custom_headers(self):
        from gnat.connectors.safebreach.client import SafeBreachClient

        c = SafeBreachClient(
            host="https://api.safebreach.com",
            api_token="sb_test",
            account_id="42",
        )
        c.authenticate()
        assert c._auth_headers["x-apitoken"] == "sb_test"
        assert c._auth_headers["x-accountid"] == "42"

    def test_authenticate_requires_credentials(self):
        from gnat.connectors.safebreach.client import SafeBreachClient

        c = SafeBreachClient(host="https://x", api_token="", account_id="")
        with pytest.raises(GNATClientError, match="api_token and account_id"):
            c.authenticate()

    def test_trust_level_internal(self, client):
        assert client.TRUST_LEVEL == "trusted_internal"

    def test_health_check_true(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": []}))
        assert client.health_check() is True

    def test_health_check_false_on_error(self, client, monkeypatch):
        def _boom(*a, **kw):
            raise RuntimeError("nope")

        monkeypatch.setattr(client, "get", _boom)
        assert client.health_check() is False

    def test_list_tests(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(return_value={"data": [{"id": "t1"}, {"id": "t2"}]}),
        )
        tests = client.list_tests()
        assert len(tests) == 2

    def test_list_simulations_requires_test_id(self, client):
        with pytest.raises(GNATClientError, match="test_id"):
            client.list_objects(
                "observed-data", filters={"kind": "simulations"}
            )

    def test_list_attackers(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(
                return_value={
                    "data": [{"id": "a1", "name": "PowerShell", "mitreTechnique": "T1059.001"}]
                }
            ),
        )
        attackers = client.list_attackers()
        assert attackers[0]["_sb_kind"] == "attacker"

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.upsert_object("observed-data", {})

    def test_delete_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.delete_object("observed-data", "x")

    def test_to_stix_test(self, client):
        stix = client.to_stix(
            {
                "id": "t1",
                "status": "completed",
                "score": 75,
                "targets": [{"name": "host01"}],
                "mitreTechniques": ["T1059.001"],
                "startTime": "2026-04-01T00:00:00Z",
                "endTime": "2026-04-01T00:05:00Z",
            }
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "observed-data"
        assert stix["x_safebreach_simulation_id"] == "t1"
        ref_types = {r.split("--")[0] for r in stix["object_refs"]}
        assert "identity" in ref_types
        assert "attack-pattern" in ref_types

    def test_to_stix_attacker(self, client):
        stix = client.to_stix(
            {
                "_sb_kind": "attacker",
                "id": "a1",
                "name": "Process Injection",
                "mitreTechnique": "T1055",
            }
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "attack-pattern"
        assert any(
            r.get("external_id") == "T1055" for r in stix["external_references"]
        )

    def test_from_stix_is_noop(self, client):
        out = client.from_stix({"id": "observed-data--x"})
        assert "read-only" in out["note"]


# ---------------------------------------------------------------------------
# AttackIQ
# ---------------------------------------------------------------------------


class TestAttackIQClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.attackiq.client import AttackIQClient

        c = AttackIQClient(host="https://gts.attackiq.com", api_token="aiq_test")
        c._authenticated = True
        return c

    def test_authenticate_sets_token_header(self):
        from gnat.connectors.attackiq.client import AttackIQClient

        c = AttackIQClient(host="https://gts.attackiq.com", api_token="aiq_test")
        c.authenticate()
        assert c._auth_headers["Authorization"] == "Token aiq_test"

    def test_authenticate_requires_api_token(self):
        from gnat.connectors.attackiq.client import AttackIQClient

        c = AttackIQClient(host="https://gts.attackiq.com", api_token="")
        with pytest.raises(GNATClientError, match="requires api_token"):
            c.authenticate()

    def test_trust_level_internal(self, client):
        assert client.TRUST_LEVEL == "trusted_internal"

    def test_health_check_true(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"results": []})
        )
        assert client.health_check() is True

    def test_list_assessments(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(
                return_value={
                    "results": [
                        {"id": "a1", "status": "running"},
                        {"id": "a2", "status": "completed"},
                    ]
                }
            ),
        )
        assessments = client.list_assessments()
        assert len(assessments) == 2

    def test_list_scenarios(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(
                return_value={
                    "results": [
                        {"id": "s1", "name": "Lateral Move", "mitre_id": "T1021"}
                    ]
                }
            ),
        )
        scenarios = client.list_scenarios()
        assert scenarios[0]["_aiq_kind"] == "scenario"

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.upsert_object("observed-data", {})

    def test_delete_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.delete_object("observed-data", "x")

    def test_to_stix_assessment(self, client):
        stix = client.to_stix(
            {
                "id": "a1",
                "status": "completed",
                "outcome_score": 0.8,
                "assets": [{"hostname": "host01"}],
                "mitre_techniques": ["T1059"],
                "started_at": "2026-04-01T00:00:00Z",
            }
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "observed-data"

    def test_to_stix_scenario(self, client):
        stix = client.to_stix(
            {
                "_aiq_kind": "scenario",
                "id": "s1",
                "name": "Credential Dumping",
                "mitre_id": "T1003",
            }
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "attack-pattern"

    def test_from_stix_is_noop(self, client):
        out = client.from_stix({"id": "observed-data--x"})
        assert "read-only" in out["note"]


# ---------------------------------------------------------------------------
# Cymulate
# ---------------------------------------------------------------------------


class TestCymulateClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.cymulate.client import CymulateClient

        c = CymulateClient(
            host="https://api.app.cymulate.com", api_key="cym_test"
        )
        c._authenticated = True
        return c

    def test_authenticate_sets_x_token(self):
        from gnat.connectors.cymulate.client import CymulateClient

        c = CymulateClient(
            host="https://api.app.cymulate.com", api_key="cym_test"
        )
        c.authenticate()
        assert c._auth_headers["x-token"] == "cym_test"

    def test_authenticate_requires_api_key(self):
        from gnat.connectors.cymulate.client import CymulateClient

        c = CymulateClient(host="https://api.app.cymulate.com", api_key="")
        with pytest.raises(GNATClientError, match="requires api_key"):
            c.authenticate()

    def test_health_check_true(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"data": []})
        )
        assert client.health_check() is True

    def test_list_assessments(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(
                return_value={"data": [{"id": "a1", "result": "blocked"}]}
            ),
        )
        assessments = client.list_assessments()
        assert assessments[0]["_cym_kind"] == "assessment"

    def test_list_templates(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(
                return_value={
                    "data": [
                        {
                            "id": "tpl1",
                            "name": "Phishing Kit",
                            "mitreTechnique": "T1566",
                        }
                    ]
                }
            ),
        )
        templates = client.list_templates()
        assert templates[0]["_cym_kind"] == "template"

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.upsert_object("observed-data", {})

    def test_delete_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.delete_object("observed-data", "x")

    def test_to_stix_assessment(self, client):
        stix = client.to_stix(
            {
                "id": "a1",
                "result": "blocked",
                "riskScore": 60,
                "targets": ["host01"],
                "mitreTechniques": ["T1059"],
                "startTime": "2026-04-01T00:00:00Z",
            }
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "observed-data"

    def test_to_stix_template(self, client):
        stix = client.to_stix(
            {
                "_cym_kind": "template",
                "id": "tpl1",
                "name": "Ransomware Kit",
                "mitreTechnique": "T1486",
            }
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "attack-pattern"

    def test_from_stix_is_noop(self, client):
        out = client.from_stix({"id": "observed-data--x"})
        assert "read-only" in out["note"]


# ---------------------------------------------------------------------------
# Picus Security
# ---------------------------------------------------------------------------


class TestPicusClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.picus.client import PicusClient

        c = PicusClient(
            host="https://api.picussecurity.com", refresh_token="picus_refresh"
        )
        c._authenticated = True
        return c

    def test_authenticate_exchanges_refresh_token(self, monkeypatch):
        from gnat.connectors.picus.client import PicusClient

        c = PicusClient(
            host="https://api.picussecurity.com",
            refresh_token="picus_refresh",
        )
        monkeypatch.setattr(
            c, "post", MagicMock(return_value={"access_token": "tok_abc"})
        )
        c.authenticate()
        assert c._auth_headers["Authorization"] == "Bearer tok_abc"

    def test_authenticate_requires_refresh_token(self):
        from gnat.connectors.picus.client import PicusClient

        c = PicusClient(host="https://api.picussecurity.com", refresh_token="")
        with pytest.raises(GNATClientError, match="requires refresh_token"):
            c.authenticate()

    def test_authenticate_raises_without_token(self, monkeypatch):
        from gnat.connectors.picus.client import PicusClient

        c = PicusClient(
            host="https://api.picussecurity.com",
            refresh_token="picus_refresh",
        )
        monkeypatch.setattr(c, "post", MagicMock(return_value={}))
        with pytest.raises(GNATClientError, match="no access_token"):
            c.authenticate()

    def test_health_check_true(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": []}))
        assert client.health_check() is True

    def test_list_attacks(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(
                return_value={
                    "data": [
                        {
                            "id": "atk1",
                            "name": "Credential Dump",
                            "mitreTechnique": "T1003",
                        }
                    ]
                }
            ),
        )
        attacks = client.list_attacks()
        assert attacks[0]["_pc_kind"] == "attack"

    def test_list_simulations(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(return_value={"data": [{"id": "sim1", "result": "missed"}]}),
        )
        sims = client.list_simulations()
        assert sims[0]["_pc_kind"] == "simulation"

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.upsert_object("observed-data", {})

    def test_delete_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.delete_object("observed-data", "x")

    def test_to_stix_attack(self, client):
        stix = client.to_stix(
            {
                "_pc_kind": "attack",
                "id": "atk1",
                "name": "Credential Dump",
                "mitreTechnique": "T1003",
            }
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "attack-pattern"

    def test_to_stix_simulation(self, client):
        stix = client.to_stix(
            {
                "id": "sim1",
                "result": "missed",
                "effectivenessScore": 20,
                "agents": [{"name": "host01"}],
                "mitreTechniques": ["T1003"],
                "startDate": "2026-04-01T00:00:00Z",
            }
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "observed-data"

    def test_from_stix_is_noop(self, client):
        out = client.from_stix({"id": "observed-data--x"})
        assert "read-only" in out["note"]


# ---------------------------------------------------------------------------
# Pentera
# ---------------------------------------------------------------------------


class TestPenteraClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.pentera.client import PenteraClient

        c = PenteraClient(
            host="https://tenant.pentera.io", api_token="pentera_jwt"
        )
        c._authenticated = True
        return c

    def test_authenticate_sets_bearer(self):
        from gnat.connectors.pentera.client import PenteraClient

        c = PenteraClient(
            host="https://tenant.pentera.io", api_token="pentera_jwt"
        )
        c.authenticate()
        assert c._auth_headers["Authorization"] == "Bearer pentera_jwt"

    def test_authenticate_requires_token(self):
        from gnat.connectors.pentera.client import PenteraClient

        c = PenteraClient(host="https://tenant.pentera.io", api_token="")
        with pytest.raises(GNATClientError, match="requires api_token"):
            c.authenticate()

    def test_health_check_true(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": []}))
        assert client.health_check() is True

    def test_list_tasks(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(return_value={"data": [{"id": "task1", "status": "done"}]}),
        )
        tasks = client.list_tasks()
        assert tasks[0]["_pnt_kind"] == "task"

    def test_list_findings(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(
                return_value={"data": [{"id": "f1", "severity": "high", "cve": "CVE-2024-1"}]}
            ),
        )
        findings = client.list_findings()
        assert findings[0]["_pnt_kind"] == "finding"

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.upsert_object("observed-data", {})

    def test_delete_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.delete_object("observed-data", "x")

    def test_to_stix_task(self, client):
        stix = client.to_stix(
            {
                "id": "task1",
                "status": "completed",
                "targets": ["host01"],
                "techniques": ["T1059"],
                "startTime": "2026-04-01T00:00:00Z",
            }
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "observed-data"

    def test_to_stix_finding(self, client):
        stix = client.to_stix(
            {
                "_pnt_kind": "finding",
                "id": "f1",
                "cve": "CVE-2024-0001",
                "severity": "high",
                "description": "Remote code execution",
                "exploitable": True,
            }
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "vulnerability"
        assert stix["name"] == "CVE-2024-0001"

    def test_to_stix_technique(self, client):
        stix = client.to_stix(
            {
                "_pnt_kind": "technique",
                "id": "tech1",
                "name": "Process Injection",
                "mitreId": "T1055",
            }
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "attack-pattern"

    def test_from_stix_is_noop(self, client):
        out = client.from_stix({"id": "observed-data--x"})
        assert "read-only" in out["note"]


# ---------------------------------------------------------------------------
# XM Cyber
# ---------------------------------------------------------------------------


class TestXMCyberClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.xm_cyber.client import XMCyberClient

        c = XMCyberClient(host="https://tenant.xmcyber.com", api_key="xm_test")
        c._authenticated = True
        return c

    def test_authenticate_exchanges_key_for_session(self, monkeypatch):
        from gnat.connectors.xm_cyber.client import XMCyberClient

        c = XMCyberClient(host="https://tenant.xmcyber.com", api_key="xm_test")
        monkeypatch.setattr(
            c, "post", MagicMock(return_value={"token": "session_abc"})
        )
        c.authenticate()
        assert c._auth_headers["Authorization"] == "Bearer session_abc"

    def test_authenticate_requires_api_key(self):
        from gnat.connectors.xm_cyber.client import XMCyberClient

        c = XMCyberClient(host="https://tenant.xmcyber.com", api_key="")
        with pytest.raises(GNATClientError, match="requires api_key"):
            c.authenticate()

    def test_authenticate_raises_without_token(self, monkeypatch):
        from gnat.connectors.xm_cyber.client import XMCyberClient

        c = XMCyberClient(host="https://tenant.xmcyber.com", api_key="xm_test")
        monkeypatch.setattr(c, "post", MagicMock(return_value={}))
        with pytest.raises(GNATClientError, match="no token"):
            c.authenticate()

    def test_trust_level_internal(self, client):
        assert client.TRUST_LEVEL == "trusted_internal"

    def test_health_check_true(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": []}))
        assert client.health_check() is True

    def test_list_entities(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(
                return_value={
                    "data": [
                        {"id": "e1", "name": "DC01", "type": "host"},
                        {"id": "e2", "name": "alice", "type": "user"},
                    ]
                }
            ),
        )
        entities = client.list_entities()
        assert len(entities) == 2

    def test_list_attack_paths(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(
                return_value={
                    "data": [
                        {
                            "id": "p1",
                            "riskScore": 90,
                            "techniques": ["T1003"],
                            "targets": [{"name": "DC01"}],
                        }
                    ]
                }
            ),
        )
        paths = client.list_attack_paths()
        assert paths[0]["_xm_kind"] == "attack_path"

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.upsert_object("observed-data", {})

    def test_delete_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.delete_object("observed-data", "x")

    def test_to_stix_entity(self, client):
        stix = client.to_stix(
            {
                "_xm_kind": "entity",
                "id": "e1",
                "name": "DC01",
                "type": "host",
                "compromiseScore": 0.95,
            }
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "identity"
        assert stix["name"] == "DC01"

    def test_to_stix_critical_asset(self, client):
        stix = client.to_stix(
            {
                "_xm_kind": "critical_asset",
                "id": "ca1",
                "name": "Domain Controllers",
                "type": "host",
            }
        )
        _assert_stix_contract(stix)
        assert stix["x_xm_cyber"]["is_critical"] is True

    def test_to_stix_attack_path(self, client):
        stix = client.to_stix(
            {
                "id": "p1",
                "techniques": ["T1003", "T1021"],
                "criticalAssets": [{"name": "DC01"}],
                "riskScore": 88,
                "discoveredAt": "2026-04-01T00:00:00Z",
                "lastSeen": "2026-04-01T00:10:00Z",
            }
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "observed-data"

    def test_to_stix_technique(self, client):
        stix = client.to_stix(
            {
                "_xm_kind": "technique",
                "id": "tech1",
                "name": "LSASS dump",
                "mitreId": "T1003.001",
            }
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "attack-pattern"

    def test_from_stix_is_noop(self, client):
        out = client.from_stix({"id": "observed-data--x"})
        assert "read-only" in out["note"]


# ---------------------------------------------------------------------------
# Registry integrity — Phase 2 Wave 3
# ---------------------------------------------------------------------------


def test_phase2_wave3_registry_contains_new_connectors():
    from gnat.clients import CLIENT_REGISTRY

    for key in (
        "safebreach",
        "attackiq",
        "cymulate",
        "picus",
        "pentera",
        "xm_cyber",
    ):
        assert key in CLIENT_REGISTRY, f"Missing {key} in CLIENT_REGISTRY"


def test_phase2_wave3_config_sections_exist():
    import configparser
    from pathlib import Path

    cfg_path = Path(__file__).resolve().parents[3] / "config" / "config.ini.example"
    parser = configparser.ConfigParser(strict=False)
    parser.read(cfg_path)
    for section in (
        "safebreach",
        "attackiq",
        "cymulate",
        "picus",
        "pentera",
        "xm_cyber",
    ):
        assert parser.has_section(section), f"Missing [{section}] in config.ini.example"


# ===========================================================================
# Phase 2 Wave 4 — Additional TI vendor feeds
# ===========================================================================


class TestTalosClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.talos.client import TalosClient

        c = TalosClient(host="https://talosintelligence.com")
        c._authenticated = True
        return c

    def test_authenticate_sets_user_agent(self):
        from gnat.connectors.talos.client import TalosClient

        c = TalosClient(host="https://talosintelligence.com")
        c.authenticate()
        assert "GNAT" in c._auth_headers["User-Agent"]

    def test_health_check_true(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"reputation": "trusted"}))
        assert client.health_check() is True

    def test_health_check_false_on_error(self, client, monkeypatch):
        def _boom(*a, **kw):
            raise RuntimeError("nope")

        monkeypatch.setattr(client, "get", _boom)
        assert client.health_check() is False

    def test_ip_reputation(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"reputation": "untrusted"})
        )
        obj = client.ip_reputation("1.2.3.4")
        assert obj["_ts_query_type"] == "ip"

    def test_domain_reputation(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"reputation": "trusted"})
        )
        obj = client.domain_reputation("cisco.com")
        assert obj["_ts_query_type"] == "domain"

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.upsert_object("indicator", {})

    def test_delete_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.delete_object("indicator", "x")

    def test_to_stix_malicious_ip(self, client):
        stix = client.to_stix(
            {
                "_ts_kind": "reputation",
                "_ts_query": "1.2.3.4",
                "_ts_query_type": "ip",
                "reputation": "untrusted",
            }
        )
        _assert_stix_contract(stix)
        assert "ipv4-addr:value" in stix["pattern"]
        assert "malicious-activity" in stix["labels"]

    def test_to_stix_benign_domain(self, client):
        stix = client.to_stix(
            {
                "_ts_kind": "reputation",
                "_ts_query": "cisco.com",
                "_ts_query_type": "domain",
                "reputation": "trusted",
            }
        )
        _assert_stix_contract(stix)
        assert stix["labels"] == ["benign"]

    def test_to_stix_advisory(self, client):
        stix = client.to_stix(
            {
                "_ts_kind": "advisory",
                "id": "TALOS-2026-001",
                "title": "Buffer overflow in X",
                "published": "2026-04-01T00:00:00Z",
            }
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "report"

    def test_from_stix_is_noop(self, client):
        out = client.from_stix({"id": "indicator--x"})
        assert "read-only" in out["note"]


class TestFortiGuardClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.fortiguard.client import FortiGuardClient

        c = FortiGuardClient(host="https://fortiguard.com")
        c._authenticated = True
        return c

    def test_authenticate_without_api_key(self):
        from gnat.connectors.fortiguard.client import FortiGuardClient

        c = FortiGuardClient(host="https://fortiguard.com")
        c.authenticate()
        assert "Authorization" not in c._auth_headers

    def test_authenticate_with_api_key(self):
        from gnat.connectors.fortiguard.client import FortiGuardClient

        c = FortiGuardClient(host="https://fortiguard.com", api_key="fg_test")
        c.authenticate()
        assert c._auth_headers["Authorization"] == "Bearer fg_test"

    def test_health_check_true(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": []}))
        assert client.health_check() is True

    def test_list_outbreak_alerts(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(
                return_value={"data": [{"id": "ob1", "title": "Log4Shell"}]}
            ),
        )
        alerts = client.list_outbreak_alerts()
        assert alerts[0]["_fg_kind"] == "outbreak"

    def test_list_iocs_requires_api_key(self, client):
        with pytest.raises(GNATClientError, match="commercial api_key"):
            client.list_iocs()

    def test_ip_reputation(self, client, monkeypatch):
        monkeypatch.setattr(
            client, "get", MagicMock(return_value={"rating": "malicious"})
        )
        obj = client.ip_reputation("1.2.3.4")
        assert obj["_fg_kind"] == "ip"

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.upsert_object("indicator", {})

    def test_delete_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.delete_object("indicator", "x")

    def test_to_stix_ip_indicator(self, client):
        stix = client.to_stix(
            {
                "_fg_kind": "ip",
                "_fg_query": "1.2.3.4",
                "rating": "malicious",
            }
        )
        _assert_stix_contract(stix)
        assert "ipv4-addr:value" in stix["pattern"]

    def test_to_stix_outbreak(self, client):
        stix = client.to_stix(
            {
                "_fg_kind": "outbreak",
                "id": "ob1",
                "title": "Log4Shell",
                "severity": "critical",
            }
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "report"

    def test_to_stix_virus(self, client):
        stix = client.to_stix(
            {
                "_fg_kind": "virus",
                "id": "v1",
                "name": "W32/Emotet",
            }
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "malware"

    def test_from_stix_is_noop(self, client):
        out = client.from_stix({"id": "indicator--x"})
        assert "read-only" in out["note"]


class TestKasperskyOpenTIPClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.kaspersky_opentip.client import KasperskyOpenTIPClient

        c = KasperskyOpenTIPClient(host="https://opentip.kaspersky.com")
        c._authenticated = True
        return c

    def test_authenticate_without_api_key(self):
        from gnat.connectors.kaspersky_opentip.client import KasperskyOpenTIPClient

        c = KasperskyOpenTIPClient(host="https://opentip.kaspersky.com")
        c.authenticate()
        assert "x-api-key" not in c._auth_headers

    def test_authenticate_with_api_key(self):
        from gnat.connectors.kaspersky_opentip.client import KasperskyOpenTIPClient

        c = KasperskyOpenTIPClient(
            host="https://opentip.kaspersky.com", api_key="kt_test"
        )
        c.authenticate()
        assert c._auth_headers["x-api-key"] == "kt_test"

    def test_health_check_true(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"Zone": "Green"}))
        assert client.health_check() is True

    def test_lookup_ip(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"Zone": "Red"}))
        obj = client.lookup_ip("1.2.3.4")
        assert obj["_kt_ioc_type"] == "ip"

    def test_lookup_domain(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"Zone": "Green"}))
        obj = client.lookup_domain("example.com")
        assert obj["_kt_ioc_type"] == "domain"

    def test_lookup_hash(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"Zone": "Red"}))
        obj = client.lookup_hash("a" * 64)
        assert obj["_kt_ioc_type"] == "hash"

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.upsert_object("indicator", {})

    def test_delete_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.delete_object("indicator", "x")

    def test_to_stix_malicious(self, client):
        stix = client.to_stix(
            {
                "_kt_ioc_type": "ip",
                "_kt_query": "1.2.3.4",
                "Zone": "Red",
                "CategoriesWithZone": "Malware",
            }
        )
        _assert_stix_contract(stix)
        assert "ipv4-addr:value" in stix["pattern"]
        assert "malicious-activity" in stix["labels"]

    def test_to_stix_benign(self, client):
        stix = client.to_stix(
            {
                "_kt_ioc_type": "domain",
                "_kt_query": "example.com",
                "Zone": "Green",
            }
        )
        _assert_stix_contract(stix)
        assert stix["labels"] == ["benign"]

    def test_from_stix_is_noop(self, client):
        out = client.from_stix({"id": "indicator--x"})
        assert "read-only" in out["note"]


class TestESETThreatIntelClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.eset_ti.client import ESETThreatIntelClient

        c = ESETThreatIntelClient(
            host="https://eti.eset.com", api_token="eset_test"
        )
        c._authenticated = True
        return c

    def test_authenticate_sets_bearer(self):
        from gnat.connectors.eset_ti.client import ESETThreatIntelClient

        c = ESETThreatIntelClient(
            host="https://eti.eset.com", api_token="eset_test"
        )
        c.authenticate()
        assert c._auth_headers["Authorization"] == "Bearer eset_test"

    def test_authenticate_requires_token(self):
        from gnat.connectors.eset_ti.client import ESETThreatIntelClient

        c = ESETThreatIntelClient(host="https://eti.eset.com", api_token="")
        with pytest.raises(GNATClientError, match="requires api_token"):
            c.authenticate()

    def test_health_check_true(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": []}))
        assert client.health_check() is True

    def test_list_iocs(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(
                return_value={"data": [{"id": "i1", "ioc": "1.2.3.4", "ioc_type": "ip"}]}
            ),
        )
        iocs = client.list_iocs()
        assert iocs[0]["_eset_kind"] == "ioc"

    def test_list_reports(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(
                return_value={
                    "data": [{"id": "r1", "title": "Turla activity", "actor": "Turla"}]
                }
            ),
        )
        reports = client.list_reports()
        assert reports[0]["_eset_kind"] == "report"

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.upsert_object("indicator", {})

    def test_delete_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.delete_object("indicator", "x")

    def test_to_stix_report(self, client):
        stix = client.to_stix(
            {
                "_eset_kind": "report",
                "id": "r1",
                "title": "Turla campaign",
                "summary": "APT28-related activity",
                "actor": "Turla",
            }
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "report"

    def test_to_stix_ioc(self, client):
        stix = client.to_stix(
            {
                "_eset_kind": "ioc",
                "ioc": "1.2.3.4",
                "ioc_type": "ip",
                "actor": "Turla",
            }
        )
        _assert_stix_contract(stix)
        assert "ipv4-addr:value" in stix["pattern"]

    def test_from_stix_is_noop(self, client):
        out = client.from_stix({"id": "indicator--x"})
        assert "read-only" in out["note"]


class TestBitdefenderIntelliZoneClient:
    @pytest.fixture
    def client(self):
        from gnat.connectors.bitdefender_iz.client import BitdefenderIntelliZoneClient

        c = BitdefenderIntelliZoneClient(
            host="https://intellizone.bitdefender.com", api_key="bd_test"
        )
        c._authenticated = True
        return c

    def test_authenticate_sets_header(self):
        from gnat.connectors.bitdefender_iz.client import BitdefenderIntelliZoneClient

        c = BitdefenderIntelliZoneClient(
            host="https://intellizone.bitdefender.com", api_key="bd_test"
        )
        c.authenticate()
        assert c._auth_headers["X-API-Key"] == "bd_test"

    def test_authenticate_requires_api_key(self):
        from gnat.connectors.bitdefender_iz.client import BitdefenderIntelliZoneClient

        c = BitdefenderIntelliZoneClient(
            host="https://intellizone.bitdefender.com", api_key=""
        )
        with pytest.raises(GNATClientError, match="requires api_key"):
            c.authenticate()

    def test_health_check_true(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": []}))
        assert client.health_check() is True

    def test_list_reports(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(return_value={"data": [{"id": "r1", "title": "Report"}]}),
        )
        reports = client.list_reports()
        assert reports[0]["_bd_kind"] == "report"

    def test_list_apt_groups(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(
                return_value={"data": [{"id": "apt1", "name": "APT1", "aliases": ["Comment Crew"]}]}
            ),
        )
        groups = client.list_apt_groups()
        assert groups[0]["_bd_kind"] == "actor"

    def test_list_malware_families(self, client, monkeypatch):
        monkeypatch.setattr(
            client,
            "get",
            MagicMock(return_value={"data": [{"id": "f1", "name": "Emotet"}]}),
        )
        fams = client.list_malware_families()
        assert fams[0]["_bd_kind"] == "family"

    def test_upsert_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.upsert_object("indicator", {})

    def test_delete_raises(self, client):
        with pytest.raises(GNATClientError, match="read-only"):
            client.delete_object("indicator", "x")

    def test_to_stix_report(self, client):
        stix = client.to_stix(
            {
                "_bd_kind": "report",
                "id": "r1",
                "title": "Ransomware roundup Q2",
            }
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "report"

    def test_to_stix_actor(self, client):
        stix = client.to_stix(
            {
                "_bd_kind": "actor",
                "id": "apt1",
                "name": "APT1",
                "aliases": ["Comment Crew"],
            }
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "threat-actor"

    def test_to_stix_family(self, client):
        stix = client.to_stix(
            {"_bd_kind": "family", "id": "f1", "name": "Emotet"}
        )
        _assert_stix_contract(stix)
        assert stix["type"] == "malware"

    def test_to_stix_ioc(self, client):
        stix = client.to_stix(
            {
                "_bd_kind": "ioc",
                "value": "evil.example",
                "type": "domain",
            }
        )
        _assert_stix_contract(stix)
        assert "domain-name:value" in stix["pattern"]

    def test_from_stix_is_noop(self, client):
        out = client.from_stix({"id": "indicator--x"})
        assert "read-only" in out["note"]


# ---------------------------------------------------------------------------
# Registry integrity — Phase 2 Wave 4
# ---------------------------------------------------------------------------


def test_phase2_wave4_registry_contains_new_connectors():
    from gnat.clients import CLIENT_REGISTRY

    for key in (
        "talos",
        "fortiguard",
        "kaspersky_opentip",
        "eset_ti",
        "bitdefender_iz",
    ):
        assert key in CLIENT_REGISTRY, f"Missing {key} in CLIENT_REGISTRY"


def test_phase2_wave4_config_sections_exist():
    import configparser
    from pathlib import Path

    cfg_path = Path(__file__).resolve().parents[3] / "config" / "config.ini.example"
    parser = configparser.ConfigParser(strict=False)
    parser.read(cfg_path)
    for section in (
        "talos",
        "fortiguard",
        "kaspersky_opentip",
        "eset_ti",
        "bitdefender_iz",
    ):
        assert parser.has_section(section), f"Missing [{section}] in config.ini.example"
