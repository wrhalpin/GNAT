"""
tests/unit/test_nlp.py
========================
Unit tests for gnat.nlp — QuerySpec, BuiltinParser, NLPQueryEngine,
ClaudeParser (mocked), and SAKClient.natural_language_query().
"""

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from gnat.nlp.query_spec import QuerySpec
from gnat.nlp.builtin import BuiltinParser
from gnat.nlp.parser import NLPQueryEngine


# ---------------------------------------------------------------------------
# QuerySpec
# ---------------------------------------------------------------------------

class TestQuerySpec:

    def test_defaults(self):
        spec = QuerySpec()
        assert spec.entities == []
        assert spec.ioc_types == []
        assert spec.since is None
        assert spec.until is None
        assert spec.platforms == []
        assert spec.limit == 100
        assert spec.raw_query == ""

    def test_to_dict_keys(self):
        spec = QuerySpec(entities=["APT28"], limit=50, raw_query="test")
        d = spec.to_dict()
        assert set(d.keys()) == {
            "entities", "ioc_types", "since", "until",
            "platforms", "limit", "raw_query",
        }

    def test_to_dict_since_iso(self):
        dt = datetime(2026, 1, 15, tzinfo=timezone.utc)
        spec = QuerySpec(since=dt)
        d = spec.to_dict()
        assert "2026-01-15" in d["since"]

    def test_to_dict_since_none(self):
        spec = QuerySpec()
        assert spec.to_dict()["since"] is None


# ---------------------------------------------------------------------------
# BuiltinParser — time extraction
# ---------------------------------------------------------------------------

class TestBuiltinParserTime:

    def setup_method(self):
        self.p = BuiltinParser()

    def test_last_n_days(self):
        spec = self.p.parse("Get everything from the last 7 days")
        assert spec.since is not None
        delta = datetime.now(timezone.utc) - spec.since
        assert 6 <= delta.days <= 8

    def test_last_n_weeks(self):
        spec = self.p.parse("IOCs from the last 2 weeks")
        assert spec.since is not None
        delta = datetime.now(timezone.utc) - spec.since
        assert 13 <= delta.days <= 15

    def test_last_n_months(self):
        spec = self.p.parse("threats in the last 3 months")
        assert spec.since is not None
        delta = datetime.now(timezone.utc) - spec.since
        assert 88 <= delta.days <= 92

    def test_since_iso_date(self):
        spec = self.p.parse("alerts since 2026-01-01")
        assert spec.since == datetime(2026, 1, 1, tzinfo=timezone.utc)

    def test_since_month_name(self):
        spec = self.p.parse("IOCs since January")
        assert spec.since is not None
        assert spec.since.month == 1
        assert spec.since.day == 1

    def test_yesterday(self):
        spec = self.p.parse("what happened yesterday")
        assert spec.since is not None
        yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).date()
        assert spec.since.date() == yesterday

    def test_today(self):
        spec = self.p.parse("today's alerts")
        assert spec.since is not None
        assert spec.since.date() == datetime.now(timezone.utc).date()

    def test_until_date(self):
        spec = self.p.parse("IPs before 2026-03-01")
        assert spec.until == datetime(2026, 3, 1, tzinfo=timezone.utc)

    def test_no_time_gives_none(self):
        spec = self.p.parse("Get all indicators for APT28")
        assert spec.since is None
        assert spec.until is None


# ---------------------------------------------------------------------------
# BuiltinParser — IOC type extraction
# ---------------------------------------------------------------------------

class TestBuiltinParserIOCTypes:

    def setup_method(self):
        self.p = BuiltinParser()

    def test_ip_keyword(self):
        spec = self.p.parse("Give me all IPs for Lazarus Group")
        assert "ip" in spec.ioc_types

    def test_ipv4_keyword(self):
        spec = self.p.parse("Show IPV4 addresses for APT29")
        assert "ip" in spec.ioc_types

    def test_domain_keyword(self):
        spec = self.p.parse("Find domains associated with Cozy Bear")
        assert "domain" in spec.ioc_types

    def test_hash_keyword(self):
        spec = self.p.parse("Get all hashes from last week")
        assert "hash" in spec.ioc_types

    def test_sha256_keyword(self):
        spec = self.p.parse("SHA-256 indicators for WannaCry")
        assert "hash" in spec.ioc_types

    def test_url_keyword(self):
        spec = self.p.parse("List malicious URLs from today")
        assert "url" in spec.ioc_types

    def test_multiple_types(self):
        spec = self.p.parse("Get IPs and domains for Sandworm")
        assert "ip" in spec.ioc_types
        assert "domain" in spec.ioc_types

    def test_no_type_gives_empty_list(self):
        spec = self.p.parse("Everything related to APT28")
        assert spec.ioc_types == []


# ---------------------------------------------------------------------------
# BuiltinParser — entity extraction
# ---------------------------------------------------------------------------

class TestBuiltinParserEntities:

    def setup_method(self):
        self.p = BuiltinParser()

    def test_apt_number(self):
        spec = self.p.parse("IOCs from APT28 last month")
        assert any("APT28" in e or "apt28" in e.lower() for e in spec.entities)

    def test_lazarus_group(self):
        spec = self.p.parse("Lazarus Group IPs since January")
        assert any("lazarus" in e.lower() for e in spec.entities)

    def test_cve(self):
        spec = self.p.parse("exploits for CVE-2024-1234")
        assert "CVE-2024-1234" in spec.entities

    def test_malware_family(self):
        spec = self.p.parse("Cobalt Strike beacons from last 7 days")
        assert any("cobalt" in e.lower() for e in spec.entities)

    def test_ta_pattern(self):
        spec = self.p.parse("activity by TA505 last 30 days")
        assert any("TA505" in e for e in spec.entities)

    def test_no_entities_for_generic_query(self):
        spec = self.p.parse("list all indicators last 7 days")
        # Generic words should not be extracted as entities
        assert "list" not in [e.lower() for e in spec.entities]
        assert "all" not in [e.lower() for e in spec.entities]


# ---------------------------------------------------------------------------
# BuiltinParser — limit extraction
# ---------------------------------------------------------------------------

class TestBuiltinParserLimit:

    def setup_method(self):
        self.p = BuiltinParser()

    def test_top_n(self):
        spec = self.p.parse("Show top 50 indicators")
        assert spec.limit == 50

    def test_first_n(self):
        spec = self.p.parse("Get first 25 results")
        assert spec.limit == 25

    def test_default_limit(self):
        spec = self.p.parse("Everything for APT28")
        assert spec.limit == 100

    def test_custom_default_limit(self):
        spec = self.p.parse("Everything for APT28", default_limit=200)
        assert spec.limit == 200


# ---------------------------------------------------------------------------
# BuiltinParser — raw_query preserved
# ---------------------------------------------------------------------------

def test_raw_query_preserved():
    q = "Get all IPs for Lazarus Group from the last 7 days"
    spec = BuiltinParser().parse(q)
    assert spec.raw_query == q


# ---------------------------------------------------------------------------
# NLPQueryEngine — builtin backend
# ---------------------------------------------------------------------------

class TestNLPQueryEngineBuiltin:

    def test_default_backend_is_builtin(self):
        engine = NLPQueryEngine()
        assert engine.backend == "builtin"

    def test_parse_returns_query_spec(self):
        engine = NLPQueryEngine()
        spec = engine.parse("APT28 domains last 14 days")
        assert isinstance(spec, QuerySpec)
        assert any("apt28" in e.lower() for e in spec.entities)
        assert "domain" in spec.ioc_types

    def test_query_no_connectors_returns_spec(self):
        engine = NLPQueryEngine()
        results = engine.query("APT28 IPs last 7 days")
        assert isinstance(results, list)
        assert len(results) == 1
        assert results[0]["_type"] == "query_spec"

    def test_query_with_connector_calls_list_objects(self):
        engine = NLPQueryEngine()
        mock_connector = MagicMock()
        mock_connector.list_objects.return_value = [
            {"id": "indicator--1", "name": "1.2.3.4"},
        ]
        results = engine.query("APT28 IPs", connectors={"threatq": mock_connector})
        assert any(r.get("_source") == "threatq" for r in results)
        mock_connector.list_objects.assert_called_once()

    def test_query_platform_filter_respected(self):
        engine = NLPQueryEngine()
        mock_tq = MagicMock()
        mock_tq.list_objects.return_value = [{"id": "x"}]
        mock_cs = MagicMock()

        # Manually set spec.platforms to simulate "from threatq" in query
        with patch.object(engine, "parse") as mock_parse:
            spec = QuerySpec(platforms=["threatq"], entities=["APT28"])
            mock_parse.return_value = spec
            results = engine.query("APT28 from threatq",
                                   connectors={"threatq": mock_tq, "crowdstrike": mock_cs})

        mock_tq.list_objects.assert_called_once()
        mock_cs.list_objects.assert_not_called()

    def test_query_connector_failure_logged_not_raised(self):
        engine = NLPQueryEngine()
        bad_connector = MagicMock()
        bad_connector.list_objects.side_effect = Exception("connection refused")
        # Should not raise
        results = engine.query("APT28 IPs", connectors={"bad": bad_connector})
        assert isinstance(results, list)

    def test_claude_backend_raises_without_config(self):
        with pytest.raises(ValueError, match="requires claude_config"):
            NLPQueryEngine(backend="claude", claude_config=None)


# ---------------------------------------------------------------------------
# ClaudeParser — mocked API call
# ---------------------------------------------------------------------------

class TestClaudeParserMocked:

    def _make_claude_config(self):
        from gnat.agents.base import AgentConfig
        return AgentConfig(
            api_key="sk-ant-test", model="claude-sonnet-4-6",
            max_tokens=512, timeout=30, ai_confidence_ceiling=60,
        )

    def test_parse_valid_response(self):
        from gnat.nlp.claude_backend import ClaudeParser
        cfg = self._make_claude_config()
        parser = ClaudeParser(cfg)

        response_json = json.dumps({
            "entities":  ["APT28"],
            "ioc_types": ["ip", "domain"],
            "since":     "2026-01-01T00:00:00Z",
            "until":     None,
            "platforms": ["threatq"],
            "limit":     50,
        })
        mock_response = {"content": [{"type": "text", "text": response_json}]}

        with patch.object(parser._client, "complete", return_value=mock_response):
            spec = parser.parse("APT28 IPs and domains since January")

        assert "APT28" in spec.entities
        assert "ip" in spec.ioc_types
        assert "domain" in spec.ioc_types
        assert spec.since == datetime(2026, 1, 1, tzinfo=timezone.utc)
        assert spec.platforms == ["threatq"]
        assert spec.limit == 50

    def test_parse_falls_back_on_api_error(self):
        from gnat.nlp.claude_backend import ClaudeParser
        cfg = self._make_claude_config()
        parser = ClaudeParser(cfg)

        with patch.object(parser._client, "complete", side_effect=Exception("timeout")):
            spec = parser.parse("APT28 domains last 7 days")

        # Should get a valid spec from the builtin fallback
        assert isinstance(spec, QuerySpec)

    def test_parse_falls_back_on_bad_json(self):
        from gnat.nlp.claude_backend import ClaudeParser
        cfg = self._make_claude_config()
        parser = ClaudeParser(cfg)

        bad_response = {"content": [{"type": "text", "text": "not json at all"}]}
        with patch.object(parser._client, "complete", return_value=bad_response):
            spec = parser.parse("APT28 IPs last 30 days")

        assert isinstance(spec, QuerySpec)

    def test_parse_strips_markdown_fences(self):
        from gnat.nlp.claude_backend import ClaudeParser
        cfg = self._make_claude_config()
        parser = ClaudeParser(cfg)

        fenced = "```json\n{\"entities\":[\"Lazarus\"],\"ioc_types\":[],\"since\":null,\"until\":null,\"platforms\":[],\"limit\":100}\n```"
        mock_response = {"content": [{"type": "text", "text": fenced}]}

        with patch.object(parser._client, "complete", return_value=mock_response):
            spec = parser.parse("Lazarus indicators")

        assert "Lazarus" in spec.entities


# ---------------------------------------------------------------------------
# SAKClient.natural_language_query()
# ---------------------------------------------------------------------------

class TestSAKClientNLQ:

    def test_returns_list_without_connector(self):
        from gnat.client import SAKClient
        cli = SAKClient()
        results = cli.natural_language_query("APT28 domains last 7 days")
        assert isinstance(results, list)

    def test_returns_spec_when_no_connector(self):
        from gnat.client import SAKClient
        cli = SAKClient()
        results = cli.natural_language_query("APT28 IPs last 14 days")
        assert results[0]["_type"] == "query_spec"
        assert "APT28" in str(results[0])

    def test_queries_connected_platform(self):
        from gnat.client import SAKClient
        cli = SAKClient()
        mock_connector = MagicMock()
        mock_connector.list_objects.return_value = [{"id": "ind-1"}]
        cli.client = mock_connector
        cli.target = "threatq"

        results = cli.natural_language_query("APT28 IPs")
        mock_connector.list_objects.assert_called_once()
        assert any(r.get("_source") == "threatq" for r in results)
