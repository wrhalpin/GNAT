"""
tests/unit/connectors/test_connectors.py
=========================================

Unit tests for all six CTM-SAK connector clients.

Tests cover:
- Authentication header injection
- get_object / list_objects / upsert_object / delete_object
- to_stix() output contract (required STIX fields)
- from_stix() output contract (platform payload keys)
"""

import pytest
from unittest.mock import MagicMock

from ctm_sak.clients.base import SAKClientError
from ctm_sak.connectors.greymatter.client import GreyMatterClient
from ctm_sak.connectors.whistic.client import WhisticClient
from ctm_sak.connectors.riskrecon.client import RiskReconClient
from ctm_sak.connectors.feedly.client import FeedlyClient
from ctm_sak.connectors.splunk.client import SplunkClient
from ctm_sak.connectors.threatq.client import ThreatQClient
from ctm_sak.connectors.proofpoint.client import ProofpointClient
from ctm_sak.connectors.netskope.client import NetskopeClient
from ctm_sak.connectors.crowdstrike.client import CrowdStrikeClient
from ctm_sak.connectors.xsoar.client import XSOARClient
from ctm_sak.connectors.recordedfuture.client import RecordedFutureClient


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
        s = client.to_stix({"ip": "5.5.5.5", "source": "ctm-sak", "_time": ""})
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
