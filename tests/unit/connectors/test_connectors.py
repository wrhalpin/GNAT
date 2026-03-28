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

import pytest
from unittest.mock import MagicMock

from gnat.clients.base import SAKClientError
from gnat.connectors.greymatter.client import GreyMatterClient
from gnat.connectors.whistic.client import WhisticClient
from gnat.connectors.riskrecon.client import RiskReconClient
from gnat.connectors.feedly.client import FeedlyClient
from gnat.connectors.splunk.client import SplunkClient
from gnat.connectors.threatq.client import ThreatQClient
from gnat.connectors.proofpoint.client import ProofpointClient
from gnat.connectors.netskope.client import NetskopeClient
from gnat.connectors.crowdstrike.client import CrowdStrikeClient
from gnat.connectors.xsoar.client import XSOARClient
from gnat.connectors.recordedfuture.client import RecordedFutureClient


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
    assert "type" in stix_dict,         "STIX dict must have 'type'"
    assert "id" in stix_dict,           "STIX dict must have 'id'"
    assert "--" in stix_dict["id"],      "STIX id must be in <type>--<uuid> format"


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
        with pytest.raises(SAKClientError, match="access token"):
            c.authenticate()

    def test_get_object(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": {"id": 42, "value": "1.2.3.4"}}))
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
        native = {"data": {"id": 1, "value": "1.2.3.4", "type": "IP Address",
                            "class": "malicious", "created_at": "", "updated_at": ""}}
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "indicator"
        assert "1.2.3.4" in stix.get("pattern", "")

    def test_to_stix_extracts_targeted_industry(self, client):
        native = {"data": {
            "id": 1, "value": "evil.com", "type": "FQDN", "class": "malicious",
            "created_at": "", "updated_at": "",
            "attributes": [
                {"name": "Targeted Industry", "value": "Healthcare"},
            ],
        }}
        stix = client.to_stix(native)
        assert stix.get("x_target_sectors") == ["Healthcare"]

    def test_to_stix_extracts_targeted_sector(self, client):
        native = {"data": {
            "id": 2, "value": "1.2.3.4", "type": "IP Address", "class": "malicious",
            "created_at": "", "updated_at": "",
            "attributes": [{"name": "Targeted Sector", "value": "Finance"}],
        }}
        stix = client.to_stix(native)
        assert "Finance" in stix.get("x_target_sectors", [])

    def test_to_stix_attr_name_case_insensitive(self, client):
        native = {"data": {
            "id": 3, "value": "bad.ru", "type": "FQDN", "class": "malicious",
            "created_at": "", "updated_at": "",
            "attributes": [{"name": "TARGETED INDUSTRY", "value": "Energy"}],
        }}
        stix = client.to_stix(native)
        assert stix.get("x_target_sectors") == ["Energy"]

    def test_to_stix_targets_attr_name(self, client):
        """'Targets' is used by the Adversary Reader CDF feed."""
        native = {"data": {
            "id": 4, "value": "apt28.example", "type": "FQDN", "class": "malicious",
            "created_at": "", "updated_at": "",
            "attributes": [{"name": "Targets", "value": "Government"}],
        }}
        stix = client.to_stix(native)
        assert "Government" in stix.get("x_target_sectors", [])

    def test_to_stix_multiple_sector_attrs(self, client):
        native = {"data": {
            "id": 5, "value": "evil.com", "type": "FQDN", "class": "malicious",
            "created_at": "", "updated_at": "",
            "attributes": [
                {"name": "Targeted Industry", "value": "Healthcare"},
                {"name": "Targeted Sector",   "value": "Pharmaceuticals"},
                {"name": "Description",        "value": "some notes"},
            ],
        }}
        stix = client.to_stix(native)
        sectors = stix.get("x_target_sectors", [])
        assert "Healthcare" in sectors
        assert "Pharmaceuticals" in sectors
        assert "some notes" not in sectors

    def test_to_stix_no_attributes_omits_sector_key(self, client):
        native = {"data": {"id": 6, "value": "1.2.3.4", "type": "IP Address",
                            "class": "malicious", "created_at": "", "updated_at": ""}}
        stix = client.to_stix(native)
        assert "x_target_sectors" not in stix

    def test_to_stix_unrelated_attrs_ignored(self, client):
        native = {"data": {
            "id": 7, "value": "evil.com", "type": "FQDN", "class": "malicious",
            "created_at": "", "updated_at": "",
            "attributes": [
                {"name": "Description", "value": "Some description"},
                {"name": "Source",      "value": "internal"},
            ],
        }}
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
        monkeypatch.setattr(client, "get", MagicMock(return_value={
            "data": [
                {"name": "Targeted Industry"},
                {"name": "Description"},
                {"name": "Source"},
            ]
        }))
        names = client.get_attribute_types()
        assert "Targeted Industry" in names
        assert "Description" in names
        assert len(names) == 3

    def test_from_stix_returns_dict(self, client):
        stix = {"type": "indicator", "id": "indicator--1", "name": "evil.com",
                 "pattern": "[domain-name:value = 'evil.com']"}
        result = client.from_stix(stix)
        assert isinstance(result, dict)
        assert "value" in result

    def test_unsupported_type_raises(self, client):
        with pytest.raises(SAKClientError, match="unsupported"):
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
        assert "Bearer cs-tok" == c._auth_headers["Authorization"]

    def test_authenticate_missing_token_raises(self, monkeypatch):
        c = CrowdStrikeClient(host="https://fake.example.com", client_id="x", client_secret="y")
        monkeypatch.setattr(c, "post", MagicMock(return_value={}))
        with pytest.raises(SAKClientError):
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
        native = {"id": "cs-1", "value": "192.168.0.1", "type": "ipv4",
                  "created_timestamp": "", "modified_timestamp": ""}
        stix = client.to_stix(native)
        _assert_stix_contract(stix)

    def test_to_stix_target_industries(self, client):
        native = {"id": "cs-2", "value": "apt28", "type": "actor",
                  "created_timestamp": "", "modified_timestamp": "",
                  "target_industries": ["Healthcare", "Government"]}
        stix = client.to_stix(native)
        assert stix.get("x_target_sectors") == ["Healthcare", "Government"]

    def test_to_stix_no_industries_omits_key(self, client):
        native = {"id": "cs-3", "value": "1.2.3.4", "type": "ipv4",
                  "created_timestamp": "", "modified_timestamp": ""}
        stix = client.to_stix(native)
        assert "x_target_sectors" not in stix

    def test_to_stix_empty_industries_omits_key(self, client):
        native = {"id": "cs-4", "value": "1.2.3.4", "type": "ipv4",
                  "created_timestamp": "", "modified_timestamp": "",
                  "target_industries": []}
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
        c = ProofpointClient(host="https://fake.example.com",
                             service_principal="user", secret="pass")
        c._authenticated = False
        c.authenticate()   # no HTTP call for Basic auth
        expected = "Basic " + base64.b64encode(b"user:pass").decode()
        assert c._auth_headers["Authorization"] == expected

    def test_upsert_raises(self, client):
        with pytest.raises(SAKClientError, match="not support"):
            client.upsert_object("indicator", {})

    def test_delete_raises(self, client):
        with pytest.raises(SAKClientError, match="not support"):
            client.delete_object("indicator", "1")

    def test_to_stix_contract(self, client):
        native = {"id": "pp-1", "subject": "Phish email", "messageTime": ""}
        stix = client.to_stix(native)
        _assert_stix_contract(stix)

    def test_list_returns_list(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(
            return_value={"messagesDelivered": [{"id": "m1"}]}
        ))
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
        monkeypatch.setattr(client, "post", MagicMock(
            return_value={"iocObjects": [{"id": "xsoar-1", "value": "bad.com"}]}
        ))
        result = client.get_object("indicator", "xsoar-1")
        assert result["id"] == "xsoar-1"

    def test_to_stix_contract(self, client):
        native = {"id": "x1", "value": "10.0.0.1", "indicator_type": "IP",
                  "timestamp": "", "modified": ""}
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
        with pytest.raises(SAKClientError, match="read-only"):
            client.upsert_object("indicator", {})

    def test_delete_raises(self, client):
        with pytest.raises(SAKClientError, match="read-only"):
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
                {"type": "Country",  "entity": {"name": "United States"}},
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
        monkeypatch.setattr(client, "get", MagicMock(
            return_value={"data": {"results": [{"id": "r1"}]}}
        ))
        result = client.list_objects("indicator")
        assert isinstance(result, list)
        assert result[0]["id"] == "r1"


# ===========================================================================
# GreyMatter
# ===========================================================================

class TestGreyMatterClient:

    @pytest.fixture
    def client(self):
        c = GreyMatterClient(host="https://fake.example.com",
                             client_id="cid", client_secret="sec")
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
        with pytest.raises(SAKClientError):
            c.authenticate()

    def test_to_stix_ipv4(self, client):
        s = client.to_stix({"id": "g1", "type": "ipv4", "value": "1.2.3.4",
                             "confidence": 80, "created_at": "", "updated_at": ""})
        _assert_stix_contract(s)
        assert "ipv4-addr" in s["pattern"]
        assert s["x_gm_type"] == "ipv4"

    def test_to_stix_domain(self, client):
        s = client.to_stix({"id": "g2", "type": "domain", "value": "evil.com",
                             "confidence": 70, "created_at": "", "updated_at": ""})
        assert "domain-name" in s["pattern"]

    def test_from_stix_infers_type(self, client):
        p = client.from_stix({"name": "evil.com",
                               "pattern": "[domain-name:value = 'evil.com']",
                               "x_tlp": "amber"})
        assert p["type"] == "domain"
        assert p["value"] == "evil.com"

    def test_unsupported_type_raises(self, client):
        with pytest.raises(SAKClientError):
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
        s = client.to_stix({"id": "v1", "name": "Acme", "trust_score": 85,
                             "assessment_status": "complete",
                             "created_at": "", "updated_at": ""})
        _assert_stix_contract(s)
        assert s["type"] == "threat-actor"
        assert s["x_whistic_trust_score"] == 85

    def test_to_stix_categories_map_to_sectors(self, client):
        s = client.to_stix({"id": "v2", "name": "HealthCo",
                             "categories": ["Healthcare", "Pharmaceuticals"],
                             "trust_score": 70, "created_at": "", "updated_at": ""})
        assert s.get("x_target_sectors") == ["Healthcare", "Pharmaceuticals"]

    def test_to_stix_no_categories_omits_sectors(self, client):
        s = client.to_stix({"id": "v3", "name": "Acme",
                             "trust_score": 60, "created_at": "", "updated_at": ""})
        assert "x_target_sectors" not in s

    def test_upsert_raises_for_vendor(self, client):
        with pytest.raises(SAKClientError):
            client.upsert_object("threat-actor", {"name": "New Vendor"})

    def test_list_vendors(self, client, monkeypatch):
        monkeypatch.setattr(client, "get",
                            MagicMock(return_value={"vendors": [{"id": "v1"}]}))
        result = client.list_objects("threat-actor")
        assert isinstance(result, list)

    def test_unsupported_type_raises(self, client):
        with pytest.raises(SAKClientError):
            client.list_objects("indicator")


# ===========================================================================
# RiskRecon
# ===========================================================================

class TestRiskReconClient:

    @pytest.fixture
    def client(self):
        c = RiskReconClient(host="https://fake.example.com",
                            client_id="cid", client_secret="sec")
        c._authenticated = True
        return c

    def test_authenticate_sets_bearer(self, monkeypatch):
        c = RiskReconClient(host="https://fake.example.com", client_id="x", client_secret="y")
        monkeypatch.setattr(c, "post", MagicMock(return_value={"access_token": "rr-tok"}))
        c.authenticate()
        assert c._auth_headers["Authorization"] == "Bearer rr-tok"

    def test_to_stix_company(self, client):
        s = client.to_stix({"id": "c1", "name": "Corp A", "domain": "corp.com",
                             "score": 7.5, "grade": "C",
                             "created_at": "", "updated_at": ""})
        _assert_stix_contract(s)
        assert s["type"] == "threat-actor"
        assert s["x_rr_score"] == 7.5
        assert s["x_rr_domain"] == "corp.com"

    def test_to_stix_company_industries_map_to_sectors(self, client):
        s = client.to_stix({"id": "c2", "name": "HealthCorp", "domain": "hc.com",
                             "score": 8.0, "grade": "B",
                             "industries": ["Healthcare", "Insurance"],
                             "created_at": "", "updated_at": ""})
        assert s.get("x_rr_industries") == ["Healthcare", "Insurance"]
        assert s.get("x_target_sectors") == ["Healthcare", "Insurance"]

    def test_to_stix_company_no_industries_omits_sectors(self, client):
        s = client.to_stix({"id": "c3", "name": "Corp B", "domain": "b.com",
                             "score": 6.0, "grade": "C",
                             "created_at": "", "updated_at": ""})
        assert "x_target_sectors" not in s

    def test_to_stix_finding(self, client):
        s = client.to_stix({"id": "f1", "criterion": "TLS/SSL",
                             "severity": "high", "first_seen": "", "last_seen": ""})
        assert s["type"] == "vulnerability"
        assert s["x_rr_severity"] == "high"
        assert s["confidence"] == 80

    def test_to_stix_finding_severity_confidence_mapping(self, client):
        for sev, expected in [("critical", 95), ("high", 80),
                               ("medium", 60), ("low", 40), ("info", 20)]:
            s = client.to_stix({"id": "x", "criterion": "test",
                                 "severity": sev, "first_seen": "", "last_seen": ""})
            assert s["confidence"] == expected

    def test_list_companies(self, client, monkeypatch):
        monkeypatch.setattr(client, "get",
                            MagicMock(return_value={"companies": [{"id": "c1"}]}))
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
        s = client.to_stix({"id": "i1", "type": "domain", "value": "evil.com",
                             "confidence": 75, "first_seen": 1704067200000,
                             "last_seen": 1704153600000, "sources": []})
        _assert_stix_contract(s)
        assert s["type"] == "indicator"
        assert "domain-name" in s["pattern"]
        assert s["x_feedly_type"] == "domain"

    def test_to_stix_cve(self, client):
        s = client.to_stix({"id": "c1", "cve_id": "CVE-2024-1234",
                             "cvss_score": 9.8, "description": "Critical",
                             "first_seen": 1704067200000, "sources": []})
        assert s["type"] == "vulnerability"
        assert s["name"] == "CVE-2024-1234"
        assert s["x_cvss_score"] == 9.8

    def test_to_stix_ttp(self, client):
        s = client.to_stix({"id": "t1", "type": "attack-pattern",
                             "mitre_id": "T1190", "name": "Exploit Public-Facing App",
                             "description": "", "first_seen": 0, "sources": []})
        assert s["type"] == "attack-pattern"
        assert s["x_mitre_id"] == "T1190"

    def test_to_stix_ttp_sectors(self, client):
        s = client.to_stix({"id": "t2", "type": "threat-actor",
                             "name": "APT-X", "description": "",
                             "first_seen": 0, "sources": [],
                             "sectors": ["Healthcare", "Energy"]})
        assert s.get("x_target_sectors") == ["Healthcare", "Energy"]

    def test_to_stix_ttp_no_sectors_omits_key(self, client):
        s = client.to_stix({"id": "t3", "type": "attack-pattern",
                             "mitre_id": "T1059", "name": "Command Execution",
                             "description": "", "first_seen": 0, "sources": []})
        assert "x_target_sectors" not in s

    def test_upsert_raises(self, client):
        with pytest.raises(SAKClientError, match="read-only"):
            client.upsert_object("indicator", {})

    def test_delete_raises(self, client):
        with pytest.raises(SAKClientError, match="read-only"):
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
        c = SplunkClient(host="https://splunk.example.com:8089",
                         username="admin", password="pass")
        monkeypatch.setattr(c, "post", MagicMock(return_value={"sessionKey": "sess"}))
        c.authenticate()
        assert c._auth_headers["Authorization"] == "Splunk sess"

    def test_authenticate_no_credentials_raises(self):
        c = SplunkClient(host="https://splunk.example.com:8089")
        with pytest.raises(SAKClientError, match="no credentials"):
            c.authenticate()

    def test_to_stix_notable(self, client):
        s = client.to_stix({"rule_name": "Brute Force", "severity": "high",
                             "src": "10.0.0.1", "dest": "192.168.1.5",
                             "event_id": "EVT1", "urgency": "high", "_time": ""})
        _assert_stix_contract(s)
        assert s["x_splunk_severity"] == "high"
        assert s["x_splunk_src"] == "10.0.0.1"

    def test_to_stix_threat_intel_row(self, client):
        s = client.to_stix({"ip": "5.5.5.5", "source": "gnat", "_time": ""})
        assert "ipv4-addr" in s["pattern"]
        assert "5.5.5.5" in s["pattern"]

    def test_from_stix_domain(self, client):
        p = client.from_stix({"name": "evil.com",
                               "pattern": "[domain-name:value = 'evil.com']"})
        assert p["ioc_type"] == "domain"
        assert p["value"] == "evil.com"

    def test_from_stix_ip(self, client):
        p = client.from_stix({"name": "1.2.3.4",
                               "pattern": "[ipv4-addr:value = '1.2.3.4']"})
        assert p["ioc_type"] == "ip"


# ===========================================================================
# ControlUp
# ===========================================================================

from gnat.connectors.controlup.client import ControlUpClient


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
        monkeypatch.setattr(client, "get", MagicMock(side_effect=SAKClientError("err")))
        assert client.health_check() is False

    # -- get_object -----------------------------------------------------------

    def test_get_object_device(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"deviceId": "d1", "hostname": "pc1"}))
        result = client.get_object("infrastructure", "d1")
        assert result["deviceId"] == "d1"

    def test_get_object_unsupported_type(self, client):
        with pytest.raises(SAKClientError, match="does not support"):
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
        assert kwargs["params"]["page"] == 2   # page 3 → 0-based index 2

    def test_list_objects_unsupported_type(self, client):
        with pytest.raises(SAKClientError, match="does not support"):
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
        result = client.upsert_object("infrastructure", {"device_id": "d1", "tags": ["prod", "finance"]})
        assert result["success"] is True

    def test_upsert_missing_device_id_raises(self, client):
        with pytest.raises(SAKClientError, match="device_id"):
            client.upsert_object("infrastructure", {"tags": ["prod"]})

    def test_upsert_unsupported_type_raises(self, client):
        with pytest.raises(SAKClientError, match="read-only"):
            client.upsert_object("indicator", {})

    # -- delete_object --------------------------------------------------------

    def test_delete_raises(self, client):
        with pytest.raises(SAKClientError, match="does not expose delete"):
            client.delete_object("infrastructure", "d1")

    # -- query_data_index -----------------------------------------------------

    def test_query_data_index(self, client, monkeypatch):
        mock_post = MagicMock(return_value={"data": [{"processName": "chrome.exe"}], "totalCount": 1})
        monkeypatch.setattr(client, "post", mock_post)
        result = client.query_data_index(
            index="processes",
            metrics=["processName", "cpuUsage"],
            filters={"deviceId": "d1"},
        )
        assert result["totalCount"] == 1
        body = mock_post.call_args[1]["json_body"]
        assert body["index"] == "processes"
        assert body["metrics"] == ["processName", "cpuUsage"]
        assert body["filters"]["deviceId"] == "d1"
        assert body["page"] == 0   # page=1 → 0

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
            "deviceId":   "d-abc",
            "hostname":   "WIN-PC1",
            "osName":     "Windows 11",
            "osVersion":  "22H2",
            "osFamily":   "windows",
            "status":     "active",
            "healthScore": 87,
            "lastSeen":   "2025-01-15T10:00:00Z",
            "ipAddresses": ["192.168.1.50"],
            "tags":       ["finance", "prod"],
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
            "sessionId":    "sess-99",
            "username":     "jsmith",
            "deviceId":     "d-abc",
            "hostname":     "WIN-PC1",
            "sessionState": "active",
            "logonTime":    "2025-01-15T08:30:00Z",
            "lastActivity": "2025-01-15T10:00:00Z",
            "protocol":     "RDP",
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
            "alertId":     "alert-7",
            "name":        "High CPU Usage",
            "alertType":   "HighCPU",
            "severity":    "high",
            "description": "CPU above 95% for 5 minutes",
            "createdAt":   "2025-01-15T09:00:00Z",
            "deviceId":    "d-abc",
            "resolved":    False,
        }
        s = client.to_stix(native)
        _assert_stix_contract(s)
        assert s["type"] == "indicator"
        assert s["confidence"] == 75   # high → 75
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
            "id":          "v-001",
            "cveId":       "CVE-2024-12345",
            "severity":    "critical",
            "cvssScore":   9.8,
            "description": "Remote code execution vulnerability.",
            "detectedAt":  "2025-01-10T00:00:00Z",
            "deviceId":    "d-abc",
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
            "type":            "infrastructure",
            "x_cu_device_id":  "d-abc",
            "x_cu_tags":       ["prod", "finance"],
        }
        payload = client.from_stix(stix)
        assert payload["device_id"] == "d-abc"
        assert "prod" in payload["tags"]

    def test_from_stix_indicator(self, client):
        stix = {
            "type":         "indicator",
            "name":         "High CPU",
            "pattern":      "[process:name = 'malware.exe']",
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

from gnat.connectors.alienvault.client import AlienVaultClient


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
        monkeypatch.setattr(client, "get", MagicMock(return_value={"results": [{"indicator": "1.2.3.4", "type": "IPv4"}]}))
        result = client.list_objects("indicator")
        assert isinstance(result, list)

    def test_upsert_raises(self, client):
        with pytest.raises(SAKClientError, match="read-only"):
            client.upsert_object("indicator", {})

    def test_delete_raises(self, client):
        with pytest.raises(SAKClientError, match="read-only"):
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

from gnat.connectors.graylog.client import GraylogClient


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
        monkeypatch.setattr(client, "get", MagicMock(return_value={"messages": [{"message": {"_id": "m1"}}]}))
        result = client.list_objects("observed-data")
        assert isinstance(result, list)
        assert result[0]["message"]["_id"] == "m1"

    def test_to_stix_with_ips(self, client):
        msg = {"message": {"src_ip": "10.0.0.1", "dst_ip": "8.8.8.8", "timestamp": "2024-01-01T00:00:00Z"}}
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
        with pytest.raises(SAKClientError):
            client.from_stix({"type": "indicator", "id": "indicator--x"})


# ---------------------------------------------------------------------------
# OSSIM
# ---------------------------------------------------------------------------

from gnat.connectors.ossim.client import OSSIMClient


class TestOSSIMClient:

    @pytest.fixture
    def client(self):
        return _authenticated(OSSIMClient, api_key="ossim-key")

    def test_authenticate_sets_header(self):
        c = OSSIMClient(host="https://ossim.example.com", api_key="testkey")
        c.authenticate()
        assert c._auth_headers["X-USM-API-KEY"] == "testkey"

    def test_list_objects_alarms(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"data": [{"uuid": "u1", "rule_name": "Scan"}]}))
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

from gnat.connectors.security_onion.client import SecurityOnionClient


class TestSecurityOnionClient:

    @pytest.fixture
    def client(self):
        return _authenticated(SecurityOnionClient, username="analyst", password="secret")

    def test_authenticate_sets_bearer(self, monkeypatch):
        c = SecurityOnionClient(
            host="https://so.example.com", username="u", password="p"
        )
        monkeypatch.setattr(c, "post", MagicMock(return_value={"token": "jwt-abc"}))
        c.authenticate()
        assert c._auth_headers["Authorization"] == "Bearer jwt-abc"

    def test_authenticate_raises_on_missing_token(self, monkeypatch):
        c = SecurityOnionClient(
            host="https://so.example.com", username="u", password="p"
        )
        monkeypatch.setattr(c, "post", MagicMock(return_value={}))
        with pytest.raises(SAKClientError, match="login failed"):
            c.authenticate()

    def test_list_objects_alerts(self, client, monkeypatch):
        monkeypatch.setattr(client, "post", MagicMock(return_value={
            "hits": {"hits": [{"_source": {"uid": "a1", "@timestamp": "2024-01-01"}}]}
        }))
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

import json as _json
import tempfile
import os

from gnat.connectors.snort.client import SnortClient


class TestSnortClient:

    @pytest.fixture
    def client(self):
        return SnortClient(host="", alert_log_path="/tmp/nonexistent.json", log_format="json")

    def test_health_check_missing_file(self, client):
        with pytest.raises(SAKClientError, match="not found"):
            client.health_check()

    def test_health_check_existing_file(self, client, tmp_path):
        f = tmp_path / "alert.json"
        f.write_text("")
        client.alert_log_path = str(f)
        assert client.health_check() is True

    def test_list_objects_json(self, tmp_path):
        f = tmp_path / "alert.json"
        alert = {"timestamp": "2024-01-01T00:00:00", "msg": "ET MALWARE", "gid": 1,
                 "sid": 1000, "rev": 1, "priority": 2, "proto": "TCP",
                 "src_addr": "1.2.3.4", "src_port": 4444, "dst_addr": "5.6.7.8", "dst_port": 80}
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
            "sid": 12345, "gid": 1, "rev": 3,
            "priority": 1, "severity": 4,
            "proto": "TCP",
            "src_ip": "10.0.0.1", "src_port": 5555,
            "dst_ip": "8.8.8.8", "dst_port": 53,
            "action": "alert",
        }
        stix = c.to_stix(alert)
        assert stix["type"] == "observed-data"
        assert stix["x_snort_alert"]["signature"] == "ET MALWARE Bad Thing"
        assert stix["x_snort_alert"]["sid"] == 12345
        _assert_stix_contract(stix)

    def test_upsert_raises(self, client):
        with pytest.raises(SAKClientError, match="read-only"):
            client.upsert_object("observed-data", {})

    def test_from_stix_returns_note(self, client):
        result = client.from_stix({"type": "observed-data", "id": "observed-data--x"})
        assert "read-only" in result["note"].lower()


# ---------------------------------------------------------------------------
# Suricata
# ---------------------------------------------------------------------------

from gnat.connectors.suricata.client import SuricataClient


class TestSuricataClient:

    @pytest.fixture
    def client(self):
        return SuricataClient(host="", eve_log_path="/tmp/nonexistent.json")

    def test_health_check_missing_file(self, client):
        with pytest.raises(SAKClientError, match="not found"):
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
            }
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
        with pytest.raises(SAKClientError, match="read-only"):
            client.upsert_object("observed-data", {})

    def test_from_stix_returns_note(self, client):
        result = client.from_stix({"type": "observed-data", "id": "observed-data--x"})
        assert "read-only" in result["note"].lower()


# ---------------------------------------------------------------------------
# Zeek
# ---------------------------------------------------------------------------

from gnat.connectors.zeek.client import ZeekClient


class TestZeekClient:

    @pytest.fixture
    def client(self, tmp_path):
        return ZeekClient(host="", log_dir=str(tmp_path), log_format="json")

    def test_health_check_valid_dir(self, client):
        assert client.health_check() is True

    def test_health_check_missing_dir(self):
        c = ZeekClient(host="", log_dir="/tmp/does_not_exist_zeek_xyz")
        with pytest.raises(SAKClientError, match="not found"):
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
        with pytest.raises(SAKClientError, match="read-only"):
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
        monkeypatch.setattr(client, "get", MagicMock(side_effect=SAKClientError("err")))
        with pytest.raises(SAKClientError):
            client.health_check()

    def test_list_objects_indicator(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(
            return_value={"data": [{"id": "abc123", "type": "file"}]}))
        results = client.list_objects("indicator", page_size=5)
        assert isinstance(results, list)

    def test_to_stix_file(self, client):
        raw = {"id": "abc123", "type": "file",
               "attributes": {"sha256": "a" * 64, "meaningful_name": "malware.exe",
                              "last_analysis_stats": {"malicious": 30, "total": 70}}}
        stix = client.to_stix(raw)
        assert stix.get("type") in ("indicator", "file", "observed-data", "bundle")

    def test_to_stix_ip(self, client):
        raw = {"id": "1.2.3.4", "type": "ip_address",
               "attributes": {"last_analysis_stats": {"malicious": 5, "total": 70}}}
        stix = client.to_stix(raw)
        assert stix.get("type") in ("indicator", "observed-data", "bundle")

    def test_from_stix(self, client):
        stix = {"type": "indicator", "id": "indicator--1",
                "pattern": "[file:hashes.SHA256 = 'abc']", "name": "Test"}
        result = client.from_stix(stix)
        assert isinstance(result, dict)

    def test_upsert_raises(self, client):
        with pytest.raises(SAKClientError):
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
        monkeypatch.setattr(client, "_signed_post",
                            MagicMock(return_value={"pong": 1}))
        assert client.health_check() is True

    def test_health_check_failure(self, client, monkeypatch):
        monkeypatch.setattr(client, "_signed_post",
                            MagicMock(side_effect=SAKClientError("err")))
        with pytest.raises(SAKClientError):
            client.health_check()

    def test_list_objects(self, client, monkeypatch):
        monkeypatch.setattr(client, "_signed_post",
                            MagicMock(return_value=[{"ip": "1.2.3.4", "asn": "12345"}]))
        results = client.list_objects("indicator", page_size=10)
        assert isinstance(results, list)

    def test_to_stix(self, client):
        raw = {"ip": "10.0.0.1", "asn": "64496", "country_code": "US",
               "type": "C2", "timestamp": "2024-01-01 00:00:00"}
        stix = client.to_stix(raw)
        assert stix.get("type") in ("indicator", "observed-data", "bundle")

    def test_from_stix(self, client):
        stix = {"type": "indicator", "id": "indicator--1",
                "pattern": "[ipv4-addr:value = '1.2.3.4']"}
        result = client.from_stix(stix)
        assert isinstance(result, dict)

    def test_upsert_raises(self, client):
        with pytest.raises(SAKClientError):
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
        monkeypatch.setattr(client, "get", MagicMock(
            return_value={"data": [{"id": "vuln-1", "title": "CVE-2024-1234"}]}))
        results = client.list_objects("vulnerability", page_size=5)
        assert isinstance(results, list)

    def test_to_stix(self, client):
        raw = {"id": "vuln-1", "title": "CVE-2024-1234", "severity": "Critical",
               "cvss_score": 9.8, "published": "2024-01-01T00:00:00Z"}
        stix = client.to_stix(raw)
        assert stix.get("type") in ("vulnerability", "indicator", "observed-data", "bundle")

    def test_from_stix(self, client):
        stix = {"type": "vulnerability", "id": "vulnerability--1", "name": "CVE-2024-1234"}
        result = client.from_stix(stix)
        assert isinstance(result, dict)

    def test_upsert_raises(self, client):
        with pytest.raises(SAKClientError):
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
        monkeypatch.setattr(client, "get", MagicMock(
            return_value={"data": [{"id": "proj-1", "name": "MyProject"}]}))
        results = client.list_objects("x-nucleus-project", page_size=5)
        assert isinstance(results, list)

    def test_to_stix(self, client):
        raw = {"id": "vuln-1", "cve_id": "CVE-2024-0001", "severity": "high",
               "asset": "server01", "first_found": "2024-01-01"}
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
            {"type": "indicator", "id": "indicator--1",
             "pattern": "[ipv4-addr:value = '1.2.3.4']",
             "pattern_type": "stix", "name": "Test", "valid_from": "2024-01-01T00:00:00Z"})
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
        monkeypatch.setattr(client._elastic, "es_get",
                            MagicMock(side_effect=SAKClientError("err")))
        with pytest.raises(SAKClientError):
            client.health_check()

    def test_list_objects_indicators(self, client, monkeypatch):
        ind = {"_id": "ind-1", "_source": {"threat": {"indicator": {"type": "ipv4-addr",
               "ip": "1.2.3.4"}}, "@timestamp": "2024-01-01T00:00:00Z"}}
        monkeypatch.setattr(client._ti, "search_indicators", MagicMock(return_value=[ind]))
        results = client.list_objects("indicator", limit=5)
        assert isinstance(results, list)

    def test_list_objects_observed_data(self, client, monkeypatch):
        alert = {"_id": "alert-1", "_source": {"event": {"kind": "signal"},
                 "kibana.alert.rule.name": "Test", "@timestamp": "2024-01-01T00:00:00Z"}}
        monkeypatch.setattr(client._alerts, "search_alerts", MagicMock(return_value=[alert]))
        results = client.list_objects("observed-data", limit=5)
        assert isinstance(results, list)

    def test_upsert_indicator(self, client, monkeypatch):
        monkeypatch.setattr(client._ti, "index_indicator",
                            MagicMock(return_value={"result": "created", "_id": "doc-1"}))
        result = client.upsert_object("indicator",
                                      {"type": "indicator", "id": "indicator--1",
                                       "pattern": "[ipv4-addr:value = '1.2.3.4']",
                                       "pattern_type": "stix", "name": "Test IOC",
                                       "valid_from": "2024-01-01T00:00:00Z"})
        assert isinstance(result, dict)

    def test_upsert_observed_data_raises(self, client):
        with pytest.raises(SAKClientError, match="read-only"):
            client.upsert_object("observed-data", {})

    def test_delete_observed_data_raises(self, client):
        with pytest.raises(SAKClientError, match="read-only"):
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
        monkeypatch.setattr(client._misp, "get_json",
                            MagicMock(return_value={"version": "2.4.170"}))
        assert client.health_check() is True

    def test_health_check_failure(self, client, monkeypatch):
        monkeypatch.setattr(client._misp, "get_json",
                            MagicMock(side_effect=SAKClientError("err")))
        with pytest.raises(SAKClientError):
            client.health_check()

    def test_list_objects(self, client, monkeypatch):
        evt = {"id": "1", "uuid": "evt-uuid-1", "info": "Phishing campaign",
               "date": "2024-01-01", "threat_level_id": "2",
               "distribution": "0", "Attribute": []}
        monkeypatch.setattr(client._events, "list_events", MagicMock(return_value=[evt]))
        results = client.list_objects("report", limit=5)
        assert isinstance(results, list)

    def test_get_object(self, client, monkeypatch):
        evt = {"id": "1", "uuid": "evt-uuid-1", "info": "Test event",
               "date": "2024-01-01", "threat_level_id": "1",
               "distribution": "0", "Attribute": []}
        monkeypatch.setattr(client._events, "get_event", MagicMock(return_value=evt))
        result = client.get_object("report", "1")
        assert isinstance(result, dict)

    def test_delete_object(self, client, monkeypatch):
        monkeypatch.setattr(client._events, "delete_event",
                            MagicMock(return_value={"saved": True}))
        client.delete_object("report", "1")  # should not raise

    def test_to_stix(self, client):
        raw = {"Event": {"id": "1", "uuid": "evt-uuid-1", "info": "Test",
                          "date": "2024-01-01", "threat_level_id": "2",
                          "distribution": "0", "Attribute": []}}
        stix = client.to_stix(raw)
        assert stix.get("type") in ("bundle", "report", "observed-data")

    def test_from_stix(self, client):
        # from_stix requires a STIX bundle
        bundle = {"type": "bundle", "id": "bundle--1", "objects": [
            {"type": "indicator", "id": "indicator--1", "name": "Test IOC",
             "pattern": "[ipv4-addr:value = '1.2.3.4']",
             "pattern_type": "stix", "valid_from": "2024-01-01T00:00:00Z"}
        ]}
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
        monkeypatch.setattr(client._qradar, "get",
                            MagicMock(side_effect=SAKClientError("err")))
        with pytest.raises(SAKClientError):
            client.health_check()

    def test_list_objects_offenses(self, client, monkeypatch):
        offense = {"id": 1, "description": "Suspicious activity",
                   "start_time": 1704067200000, "status": "OPEN",
                   "offense_type": 0, "magnitude": 5,
                   "source_address_ids": [], "local_destination_address_ids": []}
        monkeypatch.setattr(client._offenses, "list_offenses", MagicMock(return_value=[offense]))
        results = client.list_objects("observed-data", limit=5)
        assert isinstance(results, list)

    def test_get_object(self, client, monkeypatch):
        offense = {"id": 1, "description": "Test offense",
                   "start_time": 1704067200000, "status": "OPEN",
                   "offense_type": 0, "magnitude": 3,
                   "source_address_ids": [], "local_destination_address_ids": []}
        monkeypatch.setattr(client._offenses, "get_offense", MagicMock(return_value=offense))
        result = client.get_object("observed-data", "1")
        assert isinstance(result, dict)

    def test_get_indicator_raises(self, client):
        with pytest.raises(SAKClientError, match="single-item lookup"):
            client.get_object("indicator", "some-id")

    def test_upsert_observed_data_raises(self, client):
        with pytest.raises(SAKClientError, match="read-only"):
            client.upsert_object("observed-data", {})

    def test_from_stix(self, client):
        stix = {"type": "bundle", "id": "bundle--1", "objects": [
            {"type": "indicator", "id": "indicator--1", "name": "Bad IP",
             "pattern": "[ipv4-addr:value = '1.2.3.4']",
             "pattern_type": "stix", "valid_from": "2024-01-01T00:00:00Z"}
        ]}
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
        monkeypatch.setattr(client._sentinel.auth, "get_headers",
                            MagicMock(return_value={"Authorization": "Bearer tok"}))
        client.authenticate()
        assert client._authenticated is True

    def test_authenticate_failure(self, client, monkeypatch):
        monkeypatch.setattr(client._sentinel.auth, "get_headers",
                            MagicMock(side_effect=Exception("invalid_client")))
        with pytest.raises(SAKClientError, match="authentication"):
            client.authenticate()

    def test_health_check(self, client, monkeypatch):
        monkeypatch.setattr(client._sentinel, "get",
                            MagicMock(return_value={"value": []}))
        assert client.health_check() is True

    def test_list_objects_indicators(self, client, monkeypatch):
        ind = {"id": "ind-1", "name": "indicator-1",
               "properties": {"pattern": "[ipv4-addr:value = '1.2.3.4']",
                              "patternType": "Stix", "displayName": "Bad IP",
                              "createdTimeUtc": "2024-01-01T00:00:00Z"}}
        monkeypatch.setattr(client._ti, "list_indicators", MagicMock(return_value=[ind]))
        results = client.list_objects("indicator", limit=5)
        assert isinstance(results, list)

    def test_list_objects_incidents(self, client, monkeypatch):
        inc = {"id": "inc-1", "name": "incident-1",
               "properties": {"title": "Phishing Alert", "severity": "High",
                              "status": "New", "createdTimeUtc": "2024-01-01T00:00:00Z"}}
        monkeypatch.setattr(client._incidents, "list_incidents", MagicMock(return_value=[inc]))
        results = client.list_objects("observed-data", limit=5)
        assert isinstance(results, list)

    def test_upsert_indicator(self, client, monkeypatch):
        monkeypatch.setattr(client._ti, "create_indicator",
                            MagicMock(return_value={"id": "ind-new", "name": "indicator-new"}))
        result = client.upsert_object("indicator",
                                       {"type": "indicator", "id": "indicator--1",
                                        "name": "Bad IP",
                                        "pattern": "[ipv4-addr:value = '1.2.3.4']",
                                        "pattern_type": "stix",
                                        "valid_from": "2024-01-01T00:00:00Z"})
        assert isinstance(result, dict)

    def test_upsert_incident_raises(self, client):
        with pytest.raises(SAKClientError, match="cannot be created"):
            client.upsert_object("observed-data", {})

    def test_from_stix(self, client):
        stix = {"type": "indicator", "id": "indicator--1", "name": "Test",
                "pattern": "[ipv4-addr:value = '1.2.3.4']",
                "pattern_type": "stix", "valid_from": "2024-01-01T00:00:00Z"}
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
        monkeypatch.setattr(client._wazuh.auth, "get_auth_headers",
                            MagicMock(return_value={"Authorization": "Bearer jwt"}))
        client.authenticate()
        assert client._authenticated is True

    def test_health_check(self, client, monkeypatch):
        monkeypatch.setattr(client._wazuh, "get",
                            MagicMock(return_value={"data": {"affected_items": []}}))
        assert client.health_check() is True

    def test_list_objects_alerts(self, client, monkeypatch):
        alert = {"id": "1680100001.12345",
                 "rule": {"id": "100001", "level": 5, "description": "Suspicious login"},
                 "agent": {"id": "001", "name": "host1"},
                 "timestamp": "2024-01-01T00:00:00+0000"}
        monkeypatch.setattr(client._alert_cmds, "get_alerts", MagicMock(return_value=[alert]))
        results = client.list_objects("observed-data", limit=5)
        assert isinstance(results, list)

    def test_list_objects_agents(self, client, monkeypatch):
        agent = {"id": "001", "name": "host1", "ip": "10.0.0.1",
                 "status": "active", "os": {"name": "Ubuntu"}}
        monkeypatch.setattr(client._agent_cmds, "list_agents", MagicMock(return_value=[agent]))
        results = client.list_objects("identity", limit=5)
        assert isinstance(results, list)

    def test_list_vuln_no_agent_raises(self, client):
        with pytest.raises(SAKClientError, match="agent_id"):
            client.list_objects("vulnerability")

    def test_upsert_raises(self, client):
        with pytest.raises(SAKClientError, match="read-only"):
            client.upsert_object("observed-data", {})

    def test_delete_raises(self, client):
        with pytest.raises(SAKClientError, match="read-only"):
            client.delete_object("observed-data", "alert-1")

    def test_from_stix_returns_xml(self, client):
        # WazuhConnector.from_stix() converts a STIX indicator to a Wazuh rule XML string
        stix = {"type": "indicator", "id": "indicator--1", "name": "Test",
                "pattern": "[ipv4-addr:value = '1.2.3.4']",
                "pattern_type": "stix", "valid_from": "2024-01-01T00:00:00Z",
                "indicator_types": ["malicious-activity"]}
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
        ind = {"id": "ind-1", "name": "Bad IP",
               "pattern": "[ipv4-addr:value = '1.2.3.4']",
               "pattern_type": "stix", "valid_from": "2024-01-01T00:00:00Z",
               "entity_type": "Indicator"}
        monkeypatch.setattr(client, "post", MagicMock(
            return_value={"data": {"indicators": {"edges": [{"node": ind}]}}}))
        results = client.list_objects("indicator", page_size=5)
        assert isinstance(results, list)

    def test_to_stix_indicator(self, client):
        raw = {"id": "ind-1", "name": "Bad IP",
               "pattern": "[ipv4-addr:value = '1.2.3.4']",
               "pattern_type": "stix", "valid_from": "2024-01-01T00:00:00Z",
               "entity_type": "Indicator"}
        stix = client.to_stix(raw)
        assert stix.get("type") in ("indicator", "bundle")

    def test_to_stix_malware(self, client):
        raw = {"id": "mal-1", "name": "Ransomware X",
               "entity_type": "Malware",
               "is_family": False}
        stix = client.to_stix(raw)
        assert stix.get("type") in ("malware", "bundle", "indicator")

    def test_from_stix(self, client):
        stix = {"type": "indicator", "id": "indicator--1", "name": "Test",
                "pattern": "[ipv4-addr:value = '1.2.3.4']",
                "pattern_type": "stix", "valid_from": "2024-01-01T00:00:00Z"}
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
        c = ServiceNowClient(host="https://dev12345.service-now.com",
                             username="admin", password="pass")
        c._authenticated = True
        return c

    def test_authenticate_sets_basic_header(self):
        from gnat.connectors.servicenow.client import ServiceNowClient
        c = ServiceNowClient(host="https://dev12345.service-now.com",
                             username="user", password="secret")
        c.authenticate()
        assert c._auth_headers["Authorization"].startswith("Basic ")

    def test_authenticate_sets_bearer_when_api_key(self):
        from gnat.connectors.servicenow.client import ServiceNowClient
        c = ServiceNowClient(host="https://dev12345.service-now.com",
                             api_key="tok123")
        c.authenticate()
        assert c._auth_headers["Authorization"] == "Bearer tok123"

    def test_health_check_success(self, client, monkeypatch):
        monkeypatch.setattr(client, "get", MagicMock(return_value={"result": []}))
        assert client.health_check() is True

    def test_health_check_failure_raises(self, client, monkeypatch):
        monkeypatch.setattr(client, "get",
                            MagicMock(side_effect=SAKClientError("unreachable")))
        with pytest.raises(SAKClientError):
            client.health_check()

    def test_get_object_returns_result(self, client, monkeypatch):
        monkeypatch.setattr(client, "get",
                            MagicMock(return_value={"result": {"sys_id": "abc123"}}))
        result = client.get_object("observed-data", "abc123")
        assert result["sys_id"] == "abc123"

    def test_list_objects_returns_list(self, client, monkeypatch):
        monkeypatch.setattr(client, "get",
                            MagicMock(return_value={"result": [{"sys_id": "r1"}]}))
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
        monkeypatch.setattr(client, "post",
                            MagicMock(return_value={"result": {"sys_id": "new-1"}}))
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
            "sys_id":            "abc123",
            "short_description": "Ransomware detected",
            "description":       "Details here",
            "opened_at":         "2026-01-01T00:00:00Z",
            "state":             "1",
            "priority":          "1",
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] == "observed-data"
        assert stix["x_sn_sys_id"] == "abc123"

    def test_from_stix_returns_sn_payload(self, client):
        stix = {"type": "indicator", "id": "indicator--x", "name": "bad.exe",
                "description": "Malicious binary"}
        result = client.from_stix(stix)
        assert isinstance(result, dict)
        assert "short_description" in result
        assert "bad.exe" in result["short_description"]

    def test_annotate_incident_calls_put(self, client, monkeypatch):
        mock_put = MagicMock(return_value={"result": {"sys_id": "inc-1"}})
        monkeypatch.setattr(client, "put", mock_put)
        stix = {"type": "indicator", "id": "indicator--abc",
                "name": "10.0.0.1"}
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
        with pytest.raises(SAKClientError):
            client.list_objects("malware")


# ===========================================================================
# Incident Linking: GreyMatter link_investigation
# ===========================================================================

class TestGreyMatterIncidentLinking:

    @pytest.fixture
    def client(self):
        c = GreyMatterClient(host="https://fake.example.com",
                             client_id="cid", client_secret="sec")
        c._authenticated = True
        return c

    def test_link_investigation_calls_correct_endpoint(self, client, monkeypatch):
        mock_post = MagicMock(return_value={"id": "obs-link-1"})
        monkeypatch.setattr(client, "post", mock_post)
        stix = {"type": "indicator", "id": "indicator--aaa",
                "name": "1.2.3.4",
                "pattern": "[ipv4-addr:value = '1.2.3.4']"}
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
        stix = {"type": "indicator", "id": "indicator--bbb",
                "name": "evil.com",
                "pattern": "[domain-name:value = 'evil.com']"}
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
        stix = {"type": "indicator", "id": "indicator--ccc",
                "name": "sha256hash",
                "pattern": ""}
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
        c = JiraClient(host="https://fake.atlassian.net",
                       email="user@example.com", api_token="tok")
        c._authenticated = True
        return c

    def test_authenticate_basic_sets_header(self):
        from gnat.connectors.jira.client import JiraClient
        c = JiraClient(host="https://fake.atlassian.net",
                       email="u@example.com", api_token="mytoken")
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
        monkeypatch.setattr(client, "get",
                            MagicMock(side_effect=SAKClientError("down")))
        with pytest.raises(SAKClientError):
            client.health_check()

    def test_get_object_returns_issue(self, client, monkeypatch):
        monkeypatch.setattr(client, "get",
                            MagicMock(return_value={"id": "10001", "key": "PROJ-1",
                                                    "fields": {}}))
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
        monkeypatch.setattr(client, "post",
                            MagicMock(return_value={"id": "10002", "key": "SEC-5"}))
        result = client.upsert_object("note",
                                      {"name": "ThreatActor campaign",
                                       "description": "APT28 activity"})
        assert result.get("key") == "SEC-5"

    def test_upsert_updates_existing(self, client, monkeypatch):
        mock_put = MagicMock(return_value=None)
        monkeypatch.setattr(client, "put", mock_put)
        result = client.upsert_object("note", {"name": "Updated"}, issue_key="SEC-5")
        assert result["key"] == "SEC-5"
        mock_put.assert_called_once()

    def test_to_stix_note_contract(self, client):
        native = {
            "id": "10001", "key": "SEC-1",
            "fields": {
                "summary":   "Malware IOC",
                "issuetype": {"name": "Task"},
                "created":   "2026-01-01T00:00:00Z",
                "updated":   "2026-01-01T00:00:00Z",
                "status":    {"name": "Open"},
                "priority":  {"name": "High"},
                "labels":    ["threat-intel"],
                "assignee":  {"displayName": "Alice"},
            }
        }
        stix = client.to_stix(native)
        _assert_stix_contract(stix)
        assert stix["type"] in ("note", "course-of-action")
        assert stix["x_jira_key"] == "SEC-1"
        assert stix["x_jira_status"] == "Open"

    def test_to_stix_course_of_action_for_action_type(self, client):
        native = {
            "id": "10002", "key": "SEC-2",
            "fields": {
                "summary":   "Patch KB12345",
                "issuetype": {"name": "Action Item"},
                "created":   "2026-01-01T00:00:00Z",
            }
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
