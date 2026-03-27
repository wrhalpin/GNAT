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
