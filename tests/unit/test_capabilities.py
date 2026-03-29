"""
tests/unit/test_capabilities.py
=================================

Unit tests for ConnectorMixin.capabilities() and ConnectorMixin.call().
"""

import pytest

from gnat.connectors.base_connector import ConnectorMixin


# ---------------------------------------------------------------------------
# Minimal stub connector used throughout these tests
# ---------------------------------------------------------------------------

class _StubConnector(ConnectorMixin):
    """Minimal concrete connector for testing capability reflection."""

    stix_type_map = {"indicator": "indicators"}

    def authenticate(self):
        self._auth_headers = {"Authorization": "Bearer stub"}

    def health_check(self) -> bool:
        return True

    def get_object(self, stix_type: str, object_id: str):
        return {"id": object_id, "type": stix_type}

    def list_objects(self, stix_type: str, filters=None, page: int = 1,
                     page_size: int = 100):
        return [{"id": "obj-1"}]

    def upsert_object(self, stix_type: str, payload):
        return {"id": "upserted"}

    def delete_object(self, stix_type: str, object_id: str) -> None:
        pass

    def to_stix(self, native_object):
        return {"type": "indicator", "id": f"indicator--{native_object.get('id', '')}",
                "name": "stub"}

    def from_stix(self, stix_dict):
        return {"value": stix_dict.get("name", "")}

    # Extra platform-specific helper
    def search_indicators(self, query: str, limit: int = 10):
        """Search indicators by query string."""
        return []

    def _internal_helper(self):
        """This should NOT appear in capabilities."""
        pass


@pytest.fixture
def connector():
    return _StubConnector()


# ---------------------------------------------------------------------------
# capabilities() — structure and completeness
# ---------------------------------------------------------------------------

class TestCapabilitiesStructure:

    def test_returns_dict(self, connector):
        caps = connector.capabilities()
        assert isinstance(caps, dict)

    def test_standard_methods_present(self, connector):
        caps = connector.capabilities()
        for name in ("authenticate", "health_check", "get_object", "list_objects",
                     "upsert_object", "delete_object", "to_stix", "from_stix"):
            assert name in caps, f"Standard method '{name}' missing from capabilities"

    def test_platform_specific_method_present(self, connector):
        caps = connector.capabilities()
        assert "search_indicators" in caps
        assert caps["search_indicators"]["platform_specific"] is True

    def test_private_methods_excluded(self, connector):
        caps = connector.capabilities()
        assert "_internal_helper" not in caps
        for name in caps:
            assert not name.startswith("_"), f"Private method '{name}' leaked into capabilities"

    def test_http_plumbing_excluded(self, connector):
        """request/get/post/put/delete should not be capabilities."""
        caps = connector.capabilities()
        for name in ("request", "get", "post", "put", "delete", "patch"):
            assert name not in caps, f"HTTP plumbing '{name}' should be excluded"

    def test_meta_methods_excluded(self, connector):
        caps = connector.capabilities()
        assert "capabilities" not in caps
        assert "call" not in caps


class TestCapabilitiesMetadata:

    def test_standard_method_type_read(self, connector):
        caps = connector.capabilities()
        for name in ("health_check", "get_object", "list_objects", "to_stix", "from_stix"):
            assert caps[name]["type"] == "read", f"{name} should be type 'read'"

    def test_standard_method_type_write(self, connector):
        caps = connector.capabilities()
        for name in ("upsert_object", "delete_object"):
            assert caps[name]["type"] == "write", f"{name} should be type 'write'"

    def test_authenticate_type_auth(self, connector):
        caps = connector.capabilities()
        assert caps["authenticate"]["type"] == "auth"

    def test_extra_method_type_helper(self, connector):
        caps = connector.capabilities()
        assert caps["search_indicators"]["type"] == "helper"

    def test_standard_methods_not_platform_specific(self, connector):
        caps = connector.capabilities()
        for name in ("authenticate", "health_check", "get_object", "list_objects",
                     "upsert_object", "delete_object", "to_stix", "from_stix"):
            assert caps[name]["platform_specific"] is False

    def test_signature_is_string(self, connector):
        caps = connector.capabilities()
        for name, meta in caps.items():
            assert isinstance(meta["signature"], str), f"{name} signature is not a str"

    def test_signature_no_leading_self(self, connector):
        caps = connector.capabilities()
        for name, meta in caps.items():
            sig = meta["signature"]
            assert not sig.startswith("(self"), f"{name} signature still has 'self': {sig}"

    def test_doc_is_string(self, connector):
        caps = connector.capabilities()
        for name, meta in caps.items():
            assert isinstance(meta["doc"], str)

    def test_doc_populated_for_documented_method(self, connector):
        caps = connector.capabilities()
        assert caps["search_indicators"]["doc"] != ""
        assert "Search" in caps["search_indicators"]["doc"]

    def test_list_objects_signature_contains_stix_type(self, connector):
        caps = connector.capabilities()
        sig = caps["list_objects"]["signature"]
        assert "stix_type" in sig


# ---------------------------------------------------------------------------
# call() — dispatch and safety
# ---------------------------------------------------------------------------

class TestCall:

    def test_call_read_method_succeeds(self, connector):
        result = connector.call("list_objects", "indicator")
        assert isinstance(result, list)

    def test_call_health_check(self, connector):
        result = connector.call("health_check")
        assert result is True

    def test_call_write_without_allow_write_raises(self, connector):
        with pytest.raises(ValueError, match="write operation"):
            connector.call("upsert_object", "indicator", {"name": "x"})

    def test_call_write_with_allow_write_succeeds(self, connector):
        result = connector.call("upsert_object", "indicator", {"name": "x"},
                                allow_write=True)
        assert isinstance(result, dict)

    def test_call_delete_without_allow_write_raises(self, connector):
        with pytest.raises(ValueError, match="write operation"):
            connector.call("delete_object", "indicator", "obj-1")

    def test_call_unknown_method_raises(self, connector):
        with pytest.raises(ValueError, match="not a known capability"):
            connector.call("nonexistent_method")

    def test_call_private_method_raises(self, connector):
        with pytest.raises(ValueError):
            connector.call("_internal_helper")

    def test_call_platform_specific_method(self, connector):
        result = connector.call("search_indicators", query="apt28", limit=5)
        assert isinstance(result, list)

    def test_call_forwards_kwargs(self, connector):
        """call() must pass kwargs through to the underlying method."""
        collector = {}

        def fake_list(stix_type, filters=None, page=1, page_size=100):
            collector["page_size"] = page_size
            return []

        connector.list_objects = fake_list
        connector.call("list_objects", "indicator", page_size=42)
        assert collector["page_size"] == 42

    def test_call_auth_method_allowed_without_allow_write(self, connector):
        """authenticate() is type=auth, not write — should not require allow_write."""
        connector.call("authenticate")
        assert connector._auth_headers.get("Authorization") == "Bearer stub"


# ---------------------------------------------------------------------------
# Integration: real connector (ThreatQClient) exposes expected capabilities
# ---------------------------------------------------------------------------

class TestCapabilitiesOnRealConnector:

    def test_threatq_has_standard_interface(self):
        from gnat.connectors.threatq.client import ThreatQClient
        c = ThreatQClient(host="https://fake.example.com", client_id="x",
                          client_secret="y")
        caps = c.capabilities()
        for name in ("authenticate", "health_check", "get_object", "list_objects",
                     "upsert_object", "delete_object", "to_stix", "from_stix"):
            assert name in caps

    def test_threatq_extra_method_platform_specific(self):
        from gnat.connectors.threatq.client import ThreatQClient
        c = ThreatQClient(host="https://fake.example.com", client_id="x",
                          client_secret="y")
        caps = c.capabilities()
        # get_attribute_types is a ThreatQ-specific method
        if "get_attribute_types" in caps:
            assert caps["get_attribute_types"]["platform_specific"] is True

    def test_xsoar_link_incident_appears_as_platform_specific(self):
        from gnat.connectors.xsoar.client import XSOARClient
        c = XSOARClient(host="https://fake.example.com", api_key="key")
        caps = c.capabilities()
        assert "link_incident" in caps
        assert caps["link_incident"]["platform_specific"] is True
        assert caps["link_incident"]["type"] == "helper"

    def test_greymatter_link_investigation_appears(self):
        from gnat.connectors.greymatter.client import GreyMatterClient
        c = GreyMatterClient(host="https://fake.example.com",
                             client_id="x", client_secret="y")
        caps = c.capabilities()
        assert "link_investigation" in caps
        assert caps["link_investigation"]["platform_specific"] is True

    def test_servicenow_annotate_incident_appears(self):
        from gnat.connectors.servicenow.client import ServiceNowClient
        c = ServiceNowClient(host="https://fake.example.com", username="u",
                             password="p")
        caps = c.capabilities()
        assert "annotate_incident" in caps
        assert caps["annotate_incident"]["platform_specific"] is True
