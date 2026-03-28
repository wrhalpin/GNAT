"""
tests/connectors/test_misp.py
================================
Unit tests for the GNAT MISP connector.

Coverage
--------
- MISPConfig: validation, INI loading, URL construction
- MISPAuthManager: header construction, verify
- MISPClient: GET/POST, pagination, error mapping, embedded errors
- MISPEventCommands: list, get, create, publish, export stix2, normalise
- MISPAttributeCommands: search, add, bulk add, normalise
- MISPTagCommands: list, attach, TLP helpers
- MISPGalaxyCommands: list, search clusters
- MISPFeedCommands: list, enable, fetch
- MISPSightingCommands: add, bulk, false positive
- MISPSTIXMapper: event→bundle, attribute→stix, stix→misp

Running
-------
    pytest tests/connectors/test_misp.py -v
"""

import configparser
import json
import unittest
from unittest.mock import MagicMock, patch

from gnat.connectors.misp.config import MISPConfig, load_misp_config
from gnat.connectors.misp.exceptions import (
    MISPAuthError,
    MISPAPIError,
    MISPConfigError,
    MISPNotFoundError,
    MISPSTIXError,
    MISPValidationError,
)
from gnat.connectors.misp.auth import MISPAuthManager
from gnat.connectors.misp.client import MISPClient
from gnat.connectors.misp.events import MISPEventCommands
from gnat.connectors.misp.attributes import MISPAttributeCommands
from gnat.connectors.misp.tags import MISPTagCommands
from gnat.connectors.misp.galaxies import MISPGalaxyCommands
from gnat.connectors.misp.feeds import MISPFeedCommands
from gnat.connectors.misp.sightings import MISPSightingCommands
from gnat.connectors.misp.stix_mapper import MISPSTIXMapper


# ── Fixtures ──────────────────────────────────────────────────────────────────

def _make_config(**overrides) -> MISPConfig:
    defaults = dict(url="https://misp.test.local", api_key="test-api-key")
    defaults.update(overrides)
    return MISPConfig(**defaults)


def _make_response(status: int = 200, body=None) -> MagicMock:
    resp = MagicMock()
    resp.status = status
    payload = body if body is not None else {}
    resp.data = json.dumps(payload).encode("utf-8")
    return resp


def _make_client(config: MISPConfig | None = None) -> tuple[MISPClient, MagicMock]:
    cfg = config or _make_config()
    with patch("gnat.connectors.misp.client.urllib3.PoolManager") as pm_cls:
        mock_pm = MagicMock()
        pm_cls.return_value = mock_pm
        client = MISPClient(cfg)
        client._http = mock_pm
        client.auth._http = mock_pm
    return client, mock_pm


_SAMPLE_EVENT = {
    "id": "42", "uuid": "abc-123", "info": "Phishing Campaign",
    "date": "2024-03-10", "threat_level_id": "2", "analysis": "0",
    "distribution": "1", "published": True,
    "attribute_count": "3", "org_id": "1", "orgc_id": "1",
    "timestamp": "1709640000",
    "Tag": [{"name": "tlp:amber"}, {"name": "phishing"}],
    "Attribute": [
        {"id": "101", "uuid": "attr-1", "event_id": "42", "type": "ip-src",
         "category": "Network activity", "value": "1.2.3.4",
         "to_ids": True, "comment": "C2 IP", "timestamp": "1709640000", "Tag": []},
        {"id": "102", "uuid": "attr-2", "event_id": "42", "type": "domain",
         "category": "Network activity", "value": "evil.com",
         "to_ids": True, "comment": "", "timestamp": "1709640000", "Tag": []},
        {"id": "103", "uuid": "attr-3", "event_id": "42", "type": "sha256",
         "category": "Payload delivery", "value": "abc123def456",
         "to_ids": True, "comment": "", "timestamp": "1709640000", "Tag": []},
    ],
}

_SAMPLE_ATTR = {
    "id": "101", "uuid": "attr-1", "event_id": "42", "type": "ip-src",
    "category": "Network activity", "value": "1.2.3.4",
    "to_ids": True, "comment": "C2 IP", "timestamp": "1709640000", "Tag": [],
}


# ═════════════════════════════════════════════════════════════════════════════
# MISPConfig
# ═════════════════════════════════════════════════════════════════════════════

class TestMISPConfig(unittest.TestCase):

    def test_minimal_config(self):
        cfg = _make_config()
        self.assertEqual(cfg.url, "https://misp.test.local")

    def test_trailing_slash_stripped(self):
        cfg = MISPConfig(url="https://misp.test.local/", api_key="k")
        self.assertFalse(cfg.url.endswith("/"))

    def test_endpoint_helper(self):
        cfg = _make_config()
        self.assertEqual(
            cfg.endpoint("events/index.json"),
            "https://misp.test.local/events/index.json",
        )

    def test_base_headers(self):
        cfg = _make_config()
        headers = cfg.base_headers
        self.assertEqual(headers["Authorization"], "test-api-key")
        self.assertEqual(headers["Accept"], "application/json")
        # No 'Bearer' prefix — MISP uses raw key
        self.assertNotIn("Bearer", headers["Authorization"])

    def test_missing_url_raises(self):
        with self.assertRaises(MISPConfigError):
            MISPConfig(url="", api_key="k")

    def test_missing_api_key_raises(self):
        with self.assertRaises(MISPConfigError):
            MISPConfig(url="https://misp.local", api_key="")

    def test_invalid_url_scheme_raises(self):
        with self.assertRaises(MISPConfigError):
            MISPConfig(url="ftp://misp.local", api_key="k")

    def test_load_from_configparser(self):
        parser = configparser.ConfigParser()
        parser.read_dict({
            "misp": {
                "url": "https://misp.corp",
                "api_key": "my-key",
                "verify_ssl": "false",
                "max_results": "50",
                "default_threat_level": "1",
            }
        })
        cfg = load_misp_config(parser)
        self.assertEqual(cfg.url, "https://misp.corp")
        self.assertFalse(cfg.verify_ssl)
        self.assertEqual(cfg.default_threat_level, 1)

    def test_load_missing_section_raises(self):
        with self.assertRaises(MISPConfigError):
            load_misp_config(configparser.ConfigParser())


# ═════════════════════════════════════════════════════════════════════════════
# MISPAuthManager
# ═════════════════════════════════════════════════════════════════════════════

class TestMISPAuthManager(unittest.TestCase):

    def test_get_headers(self):
        cfg = _make_config()
        mock_http = MagicMock()
        auth = MISPAuthManager(cfg, mock_http)
        headers = auth.get_headers()
        self.assertEqual(headers["Authorization"], "test-api-key")

    def test_verify_success(self):
        cfg = _make_config()
        mock_http = MagicMock()
        mock_http.request.return_value = _make_response(200, {"version": "2.4.180"})
        auth = MISPAuthManager(cfg, mock_http)
        result = auth.verify()
        self.assertIsInstance(result, dict)

    def test_verify_401_raises(self):
        cfg = _make_config()
        mock_http = MagicMock()
        mock_http.request.return_value = _make_response(401)
        auth = MISPAuthManager(cfg, mock_http)
        with self.assertRaises(MISPAuthError):
            auth.verify()


# ═════════════════════════════════════════════════════════════════════════════
# MISPClient
# ═════════════════════════════════════════════════════════════════════════════

class TestMISPClient(unittest.TestCase):

    def test_get_json_returns_parsed(self):
        client, mock_http = _make_client()
        mock_http.request.return_value = _make_response(200, {"Event": {"id": "1"}})
        result = client.get_json("events/view/1")
        self.assertEqual(result["Event"]["id"], "1")

    def test_appends_json_suffix(self):
        client, mock_http = _make_client()
        mock_http.request.return_value = _make_response(200, {})
        client.get_json("events/index")
        url = mock_http.request.call_args[0][1]
        self.assertTrue(url.endswith(".json"))

    def test_401_raises_auth_error(self):
        client, mock_http = _make_client()
        mock_http.request.return_value = _make_response(401)
        with self.assertRaises(MISPAuthError):
            client.get_json("events/index")

    def test_403_raises_auth_error(self):
        client, mock_http = _make_client()
        mock_http.request.return_value = _make_response(403)
        with self.assertRaises(MISPAuthError):
            client.get_json("events/index")

    def test_404_raises_not_found(self):
        client, mock_http = _make_client()
        mock_http.request.return_value = _make_response(404, {"message": "Not found"})
        with self.assertRaises(MISPNotFoundError):
            client.get_json("events/view/9999")

    def test_200_with_errors_raises_validation_error(self):
        """MISP returns HTTP 200 but with errors key for validation failures."""
        client, mock_http = _make_client()
        mock_http.request.return_value = _make_response(200, {
            "saved": False, "errors": {"value": ["Value is required"]}
        })
        with self.assertRaises(MISPValidationError):
            client.post_json("attributes/add/1", body={})

    def test_429_retries_then_raises(self):
        client, mock_http = _make_client()
        mock_http.request.return_value = _make_response(429)
        with patch("time.sleep"):
            with self.assertRaises(Exception):
                client.get_json("events/index")

    def test_context_manager(self):
        cfg = _make_config()
        with patch("gnat.connectors.misp.client.urllib3.PoolManager"):
            with MISPClient(cfg) as c:
                self.assertIsInstance(c, MISPClient)

    def test_paginate_stops_when_empty(self):
        client, mock_http = _make_client()
        # First page has items, second is empty
        mock_http.request.side_effect = [
            _make_response(200, {"response": [{"Event": {"id": "1"}}]}),
            _make_response(200, {"response": []}),
        ]
        items = list(client.paginate("events/restSearch", body={"returnFormat": "json"}))
        self.assertEqual(len(items), 1)

    def test_paginate_stops_below_limit(self):
        client, mock_http = _make_client()
        # Returns 2 items when limit is 100 → no next page
        mock_http.request.return_value = _make_response(200, {
            "response": [{"Event": {"id": "1"}}, {"Event": {"id": "2"}}]
        })
        items = list(client.paginate("events/restSearch", page_size=100))
        self.assertEqual(len(items), 2)
        self.assertEqual(mock_http.request.call_count, 1)


# ═════════════════════════════════════════════════════════════════════════════
# MISPEventCommands
# ═════════════════════════════════════════════════════════════════════════════

class TestMISPEventCommands(unittest.TestCase):

    def _make_events(self):
        client, mock_http = _make_client()
        return MISPEventCommands(client), mock_http

    def test_list_events(self):
        events_cmd, mock_http = self._make_events()
        mock_http.request.return_value = _make_response(
            200, {"response": [{"Event": _SAMPLE_EVENT}]}
        )
        results = events_cmd.list_events()
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["info"], "Phishing Campaign")

    def test_get_event(self):
        events_cmd, mock_http = self._make_events()
        mock_http.request.return_value = _make_response(200, {"Event": _SAMPLE_EVENT})
        result = events_cmd.get_event(42)
        self.assertEqual(result["id"], "42")

    def test_create_event(self):
        events_cmd, mock_http = self._make_events()
        mock_http.request.return_value = _make_response(
            200, {"Event": {**_SAMPLE_EVENT, "id": "99"}}
        )
        result = events_cmd.create_event("Test Event", threat_level_id=1)
        self.assertEqual(result["id"], "99")
        body = json.loads(mock_http.request.call_args[1]["body"])
        self.assertEqual(body["Event"]["info"], "Test Event")
        self.assertEqual(body["Event"]["threat_level_id"], 1)

    def test_publish_event(self):
        events_cmd, mock_http = self._make_events()
        mock_http.request.return_value = _make_response(200, {"saved": True})
        events_cmd.publish_event(42)
        url = mock_http.request.call_args[0][1]
        self.assertIn("publish", url)

    def test_export_event_stix2(self):
        events_cmd, mock_http = self._make_events()
        stix_bundle = {"type": "bundle", "id": "bundle--x", "objects": []}
        mock_http.request.return_value = _make_response(200, stix_bundle)
        result = events_cmd.export_event_stix2(42)
        self.assertEqual(result["type"], "bundle")
        body = json.loads(mock_http.request.call_args[1]["body"])
        self.assertEqual(body["returnFormat"], "stix2")

    def test_normalise_event(self):
        result = MISPEventCommands.normalise_event(_SAMPLE_EVENT)
        self.assertEqual(result["id"], "42")
        self.assertEqual(result["uuid"], "abc-123")
        self.assertEqual(result["severity"], 2)   # threat_level 2 → medium
        self.assertEqual(result["severity_label"], "medium")
        self.assertIn("tlp:amber", result["tags"])
        self.assertEqual(result["attribute_count"], 3)

    def test_normalise_threat_levels(self):
        for tl, expected_sev in [(1, 3), (2, 2), (3, 1), (4, 0)]:
            ev = {**_SAMPLE_EVENT, "threat_level_id": str(tl)}
            result = MISPEventCommands.normalise_event(ev)
            self.assertEqual(result["severity"], expected_sev, f"threat_level {tl}")

    def test_unwrap_events_list_format(self):
        response = [{"Event": _SAMPLE_EVENT}]
        result = MISPEventCommands._unwrap_events(response)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["id"], "42")

    def test_unwrap_events_response_format(self):
        response = {"response": [{"Event": _SAMPLE_EVENT}]}
        result = MISPEventCommands._unwrap_events(response)
        self.assertEqual(len(result), 1)


# ═════════════════════════════════════════════════════════════════════════════
# MISPAttributeCommands
# ═════════════════════════════════════════════════════════════════════════════

class TestMISPAttributeCommands(unittest.TestCase):

    def _make_attrs(self):
        client, mock_http = _make_client()
        return MISPAttributeCommands(client), mock_http

    def test_search_attributes(self):
        attrs_cmd, mock_http = self._make_attrs()
        mock_http.request.return_value = _make_response(200, {
            "response": {"Attribute": [_SAMPLE_ATTR]}
        })
        results = attrs_cmd.search_attributes(value="1.2.3.4")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["value"], "1.2.3.4")

    def test_add_attribute(self):
        attrs_cmd, mock_http = self._make_attrs()
        mock_http.request.return_value = _make_response(
            200, {"Attribute": _SAMPLE_ATTR}
        )
        result = attrs_cmd.add_attribute(42, "ip-src", "1.2.3.4")
        self.assertEqual(result["type"], "ip-src")
        body = json.loads(mock_http.request.call_args[1]["body"])
        self.assertEqual(body["Attribute"]["type"], "ip-src")
        self.assertEqual(body["Attribute"]["value"], "1.2.3.4")

    def test_add_hash_attributes(self):
        attrs_cmd, mock_http = self._make_attrs()
        mock_http.request.return_value = _make_response(
            200, {"Attribute": [_SAMPLE_ATTR]}
        )
        results = attrs_cmd.add_hash_attributes(
            42, {"sha256": "abc123", "md5": "def456"}
        )
        body = json.loads(mock_http.request.call_args[1]["body"])
        attr_types = [a["type"] for a in body["Attribute"]]
        self.assertIn("sha256", attr_types)
        self.assertIn("md5", attr_types)

    def test_normalise_attribute(self):
        result = MISPAttributeCommands.normalise_attribute(_SAMPLE_ATTR)
        self.assertEqual(result["id"], "101")
        self.assertEqual(result["type"], "ip-src")
        self.assertEqual(result["value"], "1.2.3.4")
        self.assertTrue(result["to_ids"])
        self.assertEqual(result["stix_type"], "ipv4-addr")

    def test_stix_type_mapping(self):
        for attr_type, expected_stix in [
            ("ip-src", "ipv4-addr"), ("domain", "domain-name"),
            ("url", "url"), ("sha256", "file"), ("email-src", "email-addr"),
        ]:
            attr = {**_SAMPLE_ATTR, "type": attr_type}
            result = MISPAttributeCommands.normalise_attribute(attr)
            self.assertEqual(result["stix_type"], expected_stix, f"type={attr_type}")


# ═════════════════════════════════════════════════════════════════════════════
# MISPTagCommands
# ═════════════════════════════════════════════════════════════════════════════

class TestMISPTagCommands(unittest.TestCase):

    def _make_tags(self):
        client, mock_http = _make_client()
        return MISPTagCommands(client), mock_http

    def test_list_tags(self):
        tags_cmd, mock_http = self._make_tags()
        mock_http.request.return_value = _make_response(200, {
            "Tag": [{"id": "1", "name": "tlp:white"}, {"id": "2", "name": "phishing"}]
        })
        results = tags_cmd.list_tags()
        self.assertEqual(len(results), 2)

    def test_attach_tag(self):
        tags_cmd, mock_http = self._make_tags()
        mock_http.request.return_value = _make_response(200, {"saved": True})
        tags_cmd.attach_tag_to_event("event-uuid", "tlp:green")
        body = json.loads(mock_http.request.call_args[1]["body"])
        self.assertEqual(body["tag"], "tlp:green")

    def test_set_tlp_amber(self):
        tags_cmd, mock_http = self._make_tags()
        mock_http.request.return_value = _make_response(200, {})
        tags_cmd.set_tlp_amber("event-uuid")
        body = json.loads(mock_http.request.call_args[1]["body"])
        self.assertEqual(body["tag"], "tlp:amber")


# ═════════════════════════════════════════════════════════════════════════════
# MISPFeedCommands
# ═════════════════════════════════════════════════════════════════════════════

class TestMISPFeedCommands(unittest.TestCase):

    def _make_feeds(self):
        client, mock_http = _make_client()
        return MISPFeedCommands(client), mock_http

    def test_list_feeds(self):
        feeds_cmd, mock_http = self._make_feeds()
        mock_http.request.return_value = _make_response(200, [
            {"id": "1", "name": "CIRCL", "enabled": True}
        ])
        results = feeds_cmd.list_feeds()
        self.assertEqual(len(results), 1)

    def test_enable_feed(self):
        feeds_cmd, mock_http = self._make_feeds()
        mock_http.request.return_value = _make_response(200, {"Feed": {"id": "1", "enabled": True}})
        result = feeds_cmd.enable_feed(1)
        url = mock_http.request.call_args[0][1]
        self.assertIn("enable", url)


# ═════════════════════════════════════════════════════════════════════════════
# MISPSightingCommands
# ═════════════════════════════════════════════════════════════════════════════

class TestMISPSightingCommands(unittest.TestCase):

    def _make_sightings(self):
        client, mock_http = _make_client()
        return MISPSightingCommands(client), mock_http

    def test_add_sighting_by_id(self):
        sight_cmd, mock_http = self._make_sightings()
        mock_http.request.return_value = _make_response(200, {"saved": True})
        sight_cmd.add_sighting(attribute_id=101)
        body = json.loads(mock_http.request.call_args[1]["body"])
        self.assertEqual(body["id"], "101")
        self.assertEqual(body["type"], "0")

    def test_add_sightings_bulk(self):
        sight_cmd, mock_http = self._make_sightings()
        mock_http.request.return_value = _make_response(200, {})
        sight_cmd.add_sightings_bulk(["1.2.3.4", "evil.com"])
        body = json.loads(mock_http.request.call_args[1]["body"])
        self.assertIn("1.2.3.4", body["values"])

    def test_report_false_positive(self):
        sight_cmd, mock_http = self._make_sightings()
        mock_http.request.return_value = _make_response(200, {})
        sight_cmd.report_false_positive(101)
        body = json.loads(mock_http.request.call_args[1]["body"])
        self.assertEqual(body["type"], "1")


# ═════════════════════════════════════════════════════════════════════════════
# MISPSTIXMapper
# ═════════════════════════════════════════════════════════════════════════════

class TestMISPSTIXMapper(unittest.TestCase):

    def setUp(self):
        self.mapper = MISPSTIXMapper()
        self.normalised_event = MISPEventCommands.normalise_event(_SAMPLE_EVENT)
        self.normalised_attrs = [
            MISPAttributeCommands.normalise_attribute(a)
            for a in _SAMPLE_EVENT["Attribute"]
        ]

    # ── A: Event → STIX bundle ─────────────────────────────────────────────

    def test_event_to_stix_bundle_structure(self):
        bundle = self.mapper.event_to_stix_bundle(
            self.normalised_event, self.normalised_attrs
        )
        self.assertEqual(bundle["type"], "bundle")
        types = {o["type"] for o in bundle["objects"]}
        self.assertIn("report", types)

    def test_event_bundle_contains_scos(self):
        bundle = self.mapper.event_to_stix_bundle(
            self.normalised_event, self.normalised_attrs
        )
        types = {o["type"] for o in bundle["objects"]}
        self.assertIn("ipv4-addr", types)
        self.assertIn("domain-name", types)
        self.assertIn("file", types)

    def test_event_bundle_contains_indicators(self):
        """to_ids=True attributes produce indicator SDOs."""
        bundle = self.mapper.event_to_stix_bundle(
            self.normalised_event, self.normalised_attrs
        )
        types = [o["type"] for o in bundle["objects"]]
        self.assertIn("indicator", types)

    def test_report_sdo_metadata(self):
        bundle = self.mapper.event_to_stix_bundle(
            self.normalised_event, self.normalised_attrs
        )
        report = next(o for o in bundle["objects"] if o["type"] == "report")
        self.assertEqual(report["name"], "Phishing Campaign")
        self.assertIn("x_misp_event", report)
        self.assertEqual(report["x_misp_event"]["event_id"], "42")
        self.assertIn("tlp:amber", report.get("labels", []))

    def test_report_references_all_objects(self):
        bundle = self.mapper.event_to_stix_bundle(
            self.normalised_event, self.normalised_attrs
        )
        report = next(o for o in bundle["objects"] if o["type"] == "report")
        non_report_ids = {o["id"] for o in bundle["objects"] if o["type"] != "report"}
        for ref in report["object_refs"]:
            self.assertIn(ref, non_report_ids)

    # ── C: Attribute → STIX objects ────────────────────────────────────────

    def test_attribute_ip_src_to_ipv4_and_indicator(self):
        attr = MISPAttributeCommands.normalise_attribute(_SAMPLE_ATTR)
        objects = self.mapper.attribute_to_stix_objects(attr)
        types = {o["type"] for o in objects}
        self.assertIn("ipv4-addr", types)
        self.assertIn("indicator", types)

    def test_attribute_domain_to_domain_name(self):
        attr = MISPAttributeCommands.normalise_attribute({
            **_SAMPLE_ATTR, "type": "domain", "value": "evil.com"
        })
        objects = self.mapper.attribute_to_stix_objects(attr)
        types = {o["type"] for o in objects}
        self.assertIn("domain-name", types)
        domain_obj = next(o for o in objects if o["type"] == "domain-name")
        self.assertEqual(domain_obj["value"], "evil.com")

    def test_attribute_sha256_to_file_sco(self):
        attr = MISPAttributeCommands.normalise_attribute({
            **_SAMPLE_ATTR, "type": "sha256", "value": "abc123",
            "category": "Payload delivery",
        })
        objects = self.mapper.attribute_to_stix_objects(attr)
        file_obj = next((o for o in objects if o["type"] == "file"), None)
        self.assertIsNotNone(file_obj)
        self.assertEqual(file_obj["hashes"]["SHA-256"], "abc123")

    def test_attribute_no_to_ids_no_indicator(self):
        attr = MISPAttributeCommands.normalise_attribute({
            **_SAMPLE_ATTR, "to_ids": False
        })
        objects = self.mapper.attribute_to_stix_objects(attr)
        types = {o["type"] for o in objects}
        self.assertNotIn("indicator", types)

    def test_attribute_unsupported_type_returns_empty(self):
        attr = MISPAttributeCommands.normalise_attribute({
            **_SAMPLE_ATTR, "type": "comment", "value": "some note"
        })
        objects = self.mapper.attribute_to_stix_objects(attr)
        self.assertEqual(objects, [])

    def test_ip_port_pipe_stripped(self):
        """ip-src|port value '1.2.3.4|80' → ipv4-addr value '1.2.3.4'."""
        attr = MISPAttributeCommands.normalise_attribute({
            **_SAMPLE_ATTR, "type": "ip-src|port", "value": "1.2.3.4|80"
        })
        objects = self.mapper.attribute_to_stix_objects(attr)
        ip_obj = next((o for o in objects if o["type"] == "ipv4-addr"), None)
        self.assertIsNotNone(ip_obj)
        self.assertEqual(ip_obj["value"], "1.2.3.4")

    def test_vulnerability_attribute_to_stix(self):
        attr = MISPAttributeCommands.normalise_attribute({
            **_SAMPLE_ATTR, "type": "vulnerability", "value": "CVE-2021-44228",
            "category": "External analysis",
        })
        objects = self.mapper.attribute_to_stix_objects(attr)
        vuln = next((o for o in objects if o["type"] == "vulnerability"), None)
        self.assertIsNotNone(vuln)
        self.assertEqual(vuln["name"], "CVE-2021-44228")

    # ── B: STIX bundle → MISP event ────────────────────────────────────────

    def test_stix_bundle_to_misp_event_basic(self):
        bundle = {
            "type": "bundle", "spec_version": "2.1",
            "objects": [
                {"type": "ipv4-addr", "id": "ipv4-addr--1", "value": "9.9.9.9"},
                {"type": "domain-name", "id": "domain-name--1", "value": "evil.com"},
            ]
        }
        result = self.mapper.stix_bundle_to_misp_event(bundle)
        self.assertIn("event", result)
        self.assertIn("attributes", result)
        attr_types = [a["type"] for a in result["attributes"]]
        self.assertIn("ip-src", attr_types)
        self.assertIn("domain", attr_types)

    def test_stix_bundle_uses_report_name(self):
        bundle = {
            "type": "bundle", "spec_version": "2.1",
            "objects": [
                {
                    "type": "report", "id": "report--1",
                    "name": "APT Campaign Analysis",
                    "published": "2024-01-01T00:00:00Z",
                    "object_refs": [], "report_types": ["threat-report"],
                    "created": "2024-01-01T00:00:00Z",
                    "modified": "2024-01-01T00:00:00Z",
                }
            ]
        }
        result = self.mapper.stix_bundle_to_misp_event(bundle)
        self.assertEqual(result["event"]["info"], "APT Campaign Analysis")

    def test_stix_bundle_deduplication(self):
        bundle = {
            "type": "bundle", "spec_version": "2.1",
            "objects": [
                {"type": "ipv4-addr", "id": "ipv4-addr--1", "value": "1.2.3.4"},
                {"type": "ipv4-addr", "id": "ipv4-addr--2", "value": "1.2.3.4"},  # dup
            ]
        }
        result = self.mapper.stix_bundle_to_misp_event(bundle)
        ip_attrs = [a for a in result["attributes"] if a["value"] == "1.2.3.4"]
        self.assertEqual(len(ip_attrs), 1)

    def test_stix_indicator_to_misp_attribute(self):
        bundle = {
            "type": "bundle", "spec_version": "2.1",
            "objects": [{
                "type": "indicator", "id": "indicator--1",
                "name": "C2 IP",
                "pattern": "[ipv4-addr:value = '5.5.5.5']",
                "pattern_type": "stix",
                "valid_from": "2024-01-01T00:00:00Z",
                "description": "Command and control server",
            }]
        }
        result = self.mapper.stix_bundle_to_misp_event(bundle)
        attrs = result["attributes"]
        values = [a["value"] for a in attrs]
        self.assertIn("5.5.5.5", values)

    def test_invalid_bundle_raises(self):
        with self.assertRaises(MISPSTIXError):
            self.mapper.stix_bundle_to_misp_event({"type": "indicator"})


# ═════════════════════════════════════════════════════════════════════════════
# Exception hierarchy
# ═════════════════════════════════════════════════════════════════════════════

class TestMISPExceptions(unittest.TestCase):

    def test_all_inherit_from_base(self):
        from gnat.connectors.misp.exceptions import MISPError
        for cls in [MISPConfigError, MISPAuthError, MISPAPIError,
                    MISPNotFoundError, MISPValidationError, MISPSTIXError]:
            self.assertTrue(issubclass(cls, MISPError))

    def test_api_error_str(self):
        exc = MISPAPIError("msg", 404, "Not found", "/events/view/99")
        s = str(exc)
        self.assertIn("404", s)
        self.assertIn("Not found", s)

    def test_not_found_is_api_error(self):
        self.assertTrue(issubclass(MISPNotFoundError, MISPAPIError))

    def test_validation_is_api_error(self):
        self.assertTrue(issubclass(MISPValidationError, MISPAPIError))


if __name__ == "__main__":
    unittest.main(verbosity=2)
