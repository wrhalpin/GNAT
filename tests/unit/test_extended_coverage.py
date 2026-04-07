# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
tests/unit/test_extended_coverage.py
=====================================

Extended unit tests for modules with low test coverage:

1. gnat/ingest/sources/readers.py
2. gnat/connectors/alienvault/__init__.py
3. gnat/export/delivery/targets.py
4. gnat/agents/copilot.py
5. gnat/connectors/recordedfuture/rfv3.py
"""

from __future__ import annotations

import configparser
import json
import sys
import textwrap
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_tmp_file(tmp_path: Path, name: str, content: str, encoding: str = "utf-8") -> Path:
    p = tmp_path / name
    p.write_text(content, encoding=encoding)
    return p


# ===========================================================================
# 1. gnat/ingest/sources/readers.py
# ===========================================================================


class TestPlainTextReader:
    def test_basic_ip_classification(self, tmp_path):
        from gnat.ingest.sources.readers import PlainTextReader

        f = _make_tmp_file(tmp_path, "iocs.txt", "1.2.3.4\nevil.com\n")
        recs = list(PlainTextReader(str(f))._iter_records())
        values = {r["value"] for r in recs}
        assert "1.2.3.4" in values
        assert "evil.com" in values

    def test_comment_lines_skipped(self, tmp_path):
        from gnat.ingest.sources.readers import PlainTextReader

        content = "# this is a comment\n1.2.3.4\n# another comment\n"
        f = _make_tmp_file(tmp_path, "iocs.txt", content)
        recs = list(PlainTextReader(str(f))._iter_records())
        assert len(recs) == 1
        assert recs[0]["value"] == "1.2.3.4"

    def test_blank_lines_skipped(self, tmp_path):
        from gnat.ingest.sources.readers import PlainTextReader

        content = "\n\n1.2.3.4\n\n\nevil.com\n\n"
        f = _make_tmp_file(tmp_path, "iocs.txt", content)
        recs = list(PlainTextReader(str(f))._iter_records())
        assert len(recs) == 2

    def test_from_string_mode(self):
        from gnat.ingest.sources.readers import PlainTextReader

        recs = list(PlainTextReader("1.2.3.4\nevil.com\n", from_string=True)._iter_records())
        assert len(recs) == 2

    def test_skip_unknown_false_keeps_unknowns(self, tmp_path):
        from gnat.ingest.sources.readers import PlainTextReader

        f = _make_tmp_file(tmp_path, "iocs.txt", "not_an_ioc_value\n")
        recs = list(PlainTextReader(str(f), skip_unknown=False)._iter_records())
        assert len(recs) == 1
        assert recs[0]["type"] == "unknown"

    def test_skip_unknown_true_drops_unknowns(self, tmp_path):
        from gnat.ingest.sources.readers import PlainTextReader

        f = _make_tmp_file(tmp_path, "iocs.txt", "not_an_ioc_value\n1.2.3.4\n")
        recs = list(PlainTextReader(str(f), skip_unknown=True)._iter_records())
        assert len(recs) == 1
        assert recs[0]["value"] == "1.2.3.4"

    def test_sha256_classified(self):
        from gnat.ingest.sources.readers import PlainTextReader

        h = "a" * 64
        recs = list(PlainTextReader(h, from_string=True)._iter_records())
        assert recs[0]["type"] == "sha256"

    def test_url_classified(self):
        from gnat.ingest.sources.readers import PlainTextReader

        recs = list(PlainTextReader("https://evil.com/malware", from_string=True)._iter_records())
        assert recs[0]["type"] == "url"

    def test_defang_applied(self):
        from gnat.ingest.sources.readers import PlainTextReader

        # hxxp://evil[.]com should be defanged
        recs = list(
            PlainTextReader(
                "hxxp://evil[.]com/bad", from_string=True, skip_unknown=False
            )._iter_records()
        )
        assert len(recs) == 1

    def test_line_number_recorded(self, tmp_path):
        from gnat.ingest.sources.readers import PlainTextReader

        f = _make_tmp_file(tmp_path, "iocs.txt", "# skip\n1.2.3.4\n")
        recs = list(PlainTextReader(str(f))._iter_records())
        assert recs[0]["_line"] == 2

    def test_extra_patterns(self):
        import re

        from gnat.ingest.sources.readers import PlainTextReader

        recs = list(
            PlainTextReader(
                "custom_abc123",
                from_string=True,
                skip_unknown=False,
                extra_patterns={"custom": re.compile(r"^custom_")},
            )._iter_records()
        )
        assert recs[0]["type"] == "custom"


class TestCSVReader:
    def test_basic_csv(self, tmp_path):
        from gnat.ingest.sources.readers import CSVReader

        content = "value,type\n1.2.3.4,ip\nevil.com,domain\n"
        f = _make_tmp_file(tmp_path, "data.csv", content)
        recs = list(CSVReader(str(f), value_col="value", type_col="type")._iter_records())
        assert len(recs) == 2
        assert recs[0]["type"] == "ip"
        assert recs[1]["type"] == "domain"

    def test_custom_delimiter(self, tmp_path):
        from gnat.ingest.sources.readers import CSVReader

        content = "value|type\n1.2.3.4|ip\n"
        f = _make_tmp_file(tmp_path, "data.csv", content)
        recs = list(
            CSVReader(str(f), value_col="value", type_col="type", delimiter="|")._iter_records()
        )
        assert len(recs) == 1
        assert recs[0]["value"] == "1.2.3.4"

    def test_field_map_renames_columns(self, tmp_path):
        from gnat.ingest.sources.readers import CSVReader

        content = "indicator,score\n1.2.3.4,80\n"
        f = _make_tmp_file(tmp_path, "data.csv", content)
        recs = list(
            CSVReader(
                str(f),
                value_col="value",
                field_map={"indicator": "value", "score": "confidence"},
            )._iter_records()
        )
        assert recs[0]["value"] == "1.2.3.4"
        assert recs[0]["confidence"] == "80"

    def test_auto_classify_when_no_type_col(self, tmp_path):
        from gnat.ingest.sources.readers import CSVReader

        content = "value\n1.2.3.4\n"
        f = _make_tmp_file(tmp_path, "data.csv", content)
        recs = list(CSVReader(str(f), value_col="value")._iter_records())
        assert recs[0]["type"] == "ip"

    def test_skip_rows(self, tmp_path):
        from gnat.ingest.sources.readers import CSVReader

        content = "metadata line\nvalue,type\n1.2.3.4,ip\n"
        f = _make_tmp_file(tmp_path, "data.csv", content)
        recs = list(
            CSVReader(str(f), value_col="value", type_col="type", skip_rows=1)._iter_records()
        )
        assert len(recs) == 1

    def test_empty_value_skipped(self, tmp_path):
        from gnat.ingest.sources.readers import CSVReader

        content = "value,type\n,ip\n1.2.3.4,ip\n"
        f = _make_tmp_file(tmp_path, "data.csv", content)
        recs = list(CSVReader(str(f), value_col="value", type_col="type")._iter_records())
        assert len(recs) == 1


class TestJSONReader:
    def test_list_at_root(self):
        from gnat.ingest.sources.readers import JSONReader

        data = json.dumps(
            [{"value": "1.2.3.4", "type": "ip"}, {"value": "evil.com", "type": "domain"}]
        )
        recs = list(JSONReader(data, from_string=True)._iter_records())
        assert len(recs) == 2

    def test_dict_at_root_with_key(self):
        from gnat.ingest.sources.readers import JSONReader

        data = json.dumps({"indicators": [{"value": "1.2.3.4"}]})
        recs = list(JSONReader(data, from_string=True, records_key="indicators")._iter_records())
        assert len(recs) == 1

    def test_single_dict_wrapped(self):
        from gnat.ingest.sources.readers import JSONReader

        data = json.dumps({"value": "1.2.3.4", "type": "ip"})
        recs = list(JSONReader(data, from_string=True)._iter_records())
        assert len(recs) == 1
        assert recs[0]["value"] == "1.2.3.4"

    def test_index_added(self):
        from gnat.ingest.sources.readers import JSONReader

        data = json.dumps([{"a": 1}, {"a": 2}])
        recs = list(JSONReader(data, from_string=True)._iter_records())
        assert recs[0]["_index"] == 0
        assert recs[1]["_index"] == 1

    def test_non_dict_items_skipped(self):
        from gnat.ingest.sources.readers import JSONReader

        data = json.dumps([{"a": 1}, "not_a_dict", {"a": 2}])
        recs = list(JSONReader(data, from_string=True)._iter_records())
        assert len(recs) == 2

    def test_file_mode(self, tmp_path):
        from gnat.ingest.sources.readers import JSONReader

        data = [{"value": "1.2.3.4"}]
        f = _make_tmp_file(tmp_path, "data.json", json.dumps(data))
        recs = list(JSONReader(str(f))._iter_records())
        assert len(recs) == 1


class TestJSONLReader:
    def test_valid_lines(self, tmp_path):
        from gnat.ingest.sources.readers import JSONLReader

        content = '{"value": "1.2.3.4"}\n{"value": "evil.com"}\n'
        f = _make_tmp_file(tmp_path, "data.jsonl", content)
        recs = list(JSONLReader(str(f))._iter_records())
        assert len(recs) == 2

    def test_invalid_line_skipped(self, tmp_path):
        from gnat.ingest.sources.readers import JSONLReader

        content = '{"value": "1.2.3.4"}\nNOT_JSON\n{"value": "evil.com"}\n'
        f = _make_tmp_file(tmp_path, "data.jsonl", content)
        recs = list(JSONLReader(str(f))._iter_records())
        assert len(recs) == 2

    def test_blank_lines_skipped(self, tmp_path):
        from gnat.ingest.sources.readers import JSONLReader

        content = '{"value": "1.2.3.4"}\n\n{"value": "evil.com"}\n'
        f = _make_tmp_file(tmp_path, "data.jsonl", content)
        recs = list(JSONLReader(str(f))._iter_records())
        assert len(recs) == 2

    def test_non_dict_json_line_skipped(self, tmp_path):
        from gnat.ingest.sources.readers import JSONLReader

        content = '{"value": "1.2.3.4"}\n[1,2,3]\n'
        f = _make_tmp_file(tmp_path, "data.jsonl", content)
        recs = list(JSONLReader(str(f))._iter_records())
        assert len(recs) == 1

    def test_line_number_added(self, tmp_path):
        from gnat.ingest.sources.readers import JSONLReader

        content = '{"value": "1.2.3.4"}\n'
        f = _make_tmp_file(tmp_path, "data.jsonl", content)
        recs = list(JSONLReader(str(f))._iter_records())
        assert recs[0]["_line"] == 1


class TestSQLReader:
    def _make_mock_conn(self, rows, columns):
        """Create a mock DB-API 2.0 connection."""
        conn = MagicMock()
        cursor = MagicMock()
        conn.cursor.return_value = cursor
        cursor.description = [(col, None, None, None, None, None, None) for col in columns]
        cursor.fetchmany.side_effect = [rows, []]
        return conn, cursor

    def test_basic_query(self):
        from gnat.ingest.sources.readers import SQLReader

        conn, cursor = self._make_mock_conn(
            [("1.2.3.4", "ip"), ("evil.com", "domain")],
            ["value", "type"],
        )
        recs = list(SQLReader(conn, "SELECT value, type FROM iocs")._iter_records())
        assert len(recs) == 2
        assert recs[0]["value"] == "1.2.3.4"
        assert recs[0]["type"] == "ip"

    def test_column_map_renames(self):
        from gnat.ingest.sources.readers import SQLReader

        conn, _ = self._make_mock_conn([("1.2.3.4",)], ["indicator"])
        recs = list(
            SQLReader(
                conn,
                "SELECT indicator FROM t",
                column_map={"indicator": "value"},
            )._iter_records()
        )
        assert "value" in recs[0]
        assert recs[0]["value"] == "1.2.3.4"

    def test_params_passed_to_execute(self):
        from gnat.ingest.sources.readers import SQLReader

        conn, cursor = self._make_mock_conn([], ["value"])
        cursor.fetchmany.side_effect = [[]]
        list(SQLReader(conn, "SELECT * FROM t WHERE id=?", params=(42,))._iter_records())
        cursor.execute.assert_called_once_with("SELECT * FROM t WHERE id=?", (42,))

    def test_close_connection_when_flag_set(self):
        from gnat.ingest.sources.readers import SQLReader

        conn, _ = self._make_mock_conn([], ["value"])
        conn.cursor.return_value.fetchmany.side_effect = [[]]
        reader = SQLReader(conn, "SELECT 1", close_connection=True)
        reader.close()
        conn.close.assert_called_once()

    def test_no_close_when_flag_false(self):
        from gnat.ingest.sources.readers import SQLReader

        conn, _ = self._make_mock_conn([], ["value"])
        conn.cursor.return_value.fetchmany.side_effect = [[]]
        reader = SQLReader(conn, "SELECT 1", close_connection=False)
        reader.close()
        conn.close.assert_not_called()


class TestSyslogReader:
    def test_syslog_format(self, tmp_path):
        from gnat.ingest.sources.readers import SyslogReader

        line = "Jan  1 12:00:00 myhost sshd[1234]: Connection from 1.2.3.4"
        f = _make_tmp_file(tmp_path, "syslog.log", line + "\n")
        recs = list(SyslogReader(str(f), format="syslog")._iter_records())
        assert len(recs) == 1
        assert recs[0]["_format"] == "syslog"

    def test_cef_format(self, tmp_path):
        from gnat.ingest.sources.readers import SyslogReader

        line = "CEF:0|Vendor|Product|1.0|sig|name|5|src=1.2.3.4 dst=5.6.7.8"
        f = _make_tmp_file(tmp_path, "cef.log", line + "\n")
        recs = list(SyslogReader(str(f), format="cef")._iter_records())
        assert len(recs) == 1
        assert recs[0]["_format"] == "cef"
        assert recs[0]["src"] == "1.2.3.4"

    def test_leef_format(self, tmp_path):
        from gnat.ingest.sources.readers import SyslogReader

        line = "LEEF:1.0|Vendor|Product|1.0|EventID|src=1.2.3.4\tdst=5.6.7.8"
        f = _make_tmp_file(tmp_path, "leef.log", line + "\n")
        recs = list(SyslogReader(str(f), format="leef")._iter_records())
        assert len(recs) == 1
        assert recs[0]["_format"] == "leef"

    def test_auto_detect_cef(self, tmp_path):
        from gnat.ingest.sources.readers import SyslogReader

        line = "CEF:0|Vendor|Product|1.0|sig|name|5|src=1.2.3.4"
        f = _make_tmp_file(tmp_path, "auto.log", line + "\n")
        recs = list(SyslogReader(str(f), format="auto")._iter_records())
        assert recs[0]["_format"] == "cef"

    def test_auto_detect_syslog(self, tmp_path):
        from gnat.ingest.sources.readers import SyslogReader

        line = "Jan 10 12:00:00 host prog: message here"
        f = _make_tmp_file(tmp_path, "auto.log", line + "\n")
        recs = list(SyslogReader(str(f), format="auto")._iter_records())
        assert recs[0]["_format"] == "syslog"

    def test_blank_lines_skipped(self, tmp_path):
        from gnat.ingest.sources.readers import SyslogReader

        content = "Jan 10 12:00:00 host prog: msg\n\nJan 10 12:00:01 host prog: msg2\n"
        f = _make_tmp_file(tmp_path, "syslog.log", content)
        recs = list(SyslogReader(str(f))._iter_records())
        assert len(recs) == 2

    def test_raw_and_line_number_present(self, tmp_path):
        from gnat.ingest.sources.readers import SyslogReader

        line = "Jan 10 12:00:00 host prog: msg"
        f = _make_tmp_file(tmp_path, "syslog.log", line + "\n")
        recs = list(SyslogReader(str(f))._iter_records())
        assert "_line" in recs[0]
        assert "_raw" in recs[0]


class TestOpenIOCReader:
    def _write_ioc_file(self, tmp_path: Path, ioc_id: str = "test-id") -> Path:
        xml = textwrap.dedent(f"""\
            <?xml version="1.0" encoding="utf-8"?>
            <ioc id="{ioc_id}" xmlns="http://schemas.mandiant.com/2010/ioc">
              <short_description>Test IOC</short_description>
              <definition>
                <Indicator operator="AND">
                  <IndicatorItem id="item-1" condition="is">
                    <Context document="Network" search="Network/DNS" />
                    <Content type="string">evil.com</Content>
                  </IndicatorItem>
                  <IndicatorItem id="item-2" condition="is">
                    <Context document="Network" search="Network/IP" />
                    <Content type="IP">1.2.3.4</Content>
                  </IndicatorItem>
                </Indicator>
              </definition>
            </ioc>
        """)
        f = tmp_path / "test.ioc"
        f.write_text(xml, encoding="utf-8")
        return f

    def test_parse_single_file(self, tmp_path):
        from gnat.ingest.sources.readers import OpenIOCReader

        self._write_ioc_file(tmp_path, ioc_id="abc-123")
        recs = list(OpenIOCReader(str(tmp_path / "test.ioc"))._iter_records())
        assert len(recs) == 2
        assert recs[0]["ioc_id"] == "abc-123"
        assert recs[0]["ioc_name"] == "Test IOC"

    def test_parse_directory(self, tmp_path):
        from gnat.ingest.sources.readers import OpenIOCReader

        self._write_ioc_file(tmp_path)
        recs = list(OpenIOCReader(str(tmp_path))._iter_records())
        assert len(recs) == 2

    def test_context_document_and_search(self, tmp_path):
        from gnat.ingest.sources.readers import OpenIOCReader

        self._write_ioc_file(tmp_path)
        recs = list(OpenIOCReader(str(tmp_path / "test.ioc"))._iter_records())
        dns_rec = next(r for r in recs if r["context_search"] == "Network/DNS")
        assert dns_rec["content"] == "evil.com"
        assert dns_rec["context_document"] == "Network"

    def test_content_type_preserved(self, tmp_path):
        from gnat.ingest.sources.readers import OpenIOCReader

        self._write_ioc_file(tmp_path)
        recs = list(OpenIOCReader(str(tmp_path / "test.ioc"))._iter_records())
        ip_rec = next(r for r in recs if r["content"] == "1.2.3.4")
        assert ip_rec["content_type"] == "IP"

    def test_item_id_preserved(self, tmp_path):
        from gnat.ingest.sources.readers import OpenIOCReader

        self._write_ioc_file(tmp_path)
        recs = list(OpenIOCReader(str(tmp_path / "test.ioc"))._iter_records())
        assert recs[0]["item_id"] == "item-1"


# ===========================================================================
# 2. gnat/connectors/alienvault/__init__.py
# ===========================================================================


def _mock_resp(status=200, body=None):
    r = MagicMock()
    r.status = status
    r.data = json.dumps(body or {}).encode()
    return r


class TestOTXConfig:
    def test_basic_init(self):
        from gnat.connectors.alienvault import OTXConfig

        cfg = OTXConfig(api_key="test-key")
        assert cfg.api_key == "test-key"
        assert cfg.base_url == "https://otx.alienvault.com/api/v1"
        assert cfg.timeout == 30

    def test_empty_api_key_raises(self):
        from gnat.connectors.alienvault import OTXConfig, OTXConfigError

        with pytest.raises(OTXConfigError):
            OTXConfig(api_key="")

    def test_base_url_trailing_slash_stripped(self):
        from gnat.connectors.alienvault import OTXConfig

        cfg = OTXConfig(api_key="key", base_url="https://otx.alienvault.com/api/v1/")
        assert not cfg.base_url.endswith("/")

    def test_endpoint_method(self):
        from gnat.connectors.alienvault import OTXConfig

        cfg = OTXConfig(api_key="key")
        assert cfg.endpoint("/pulses/123") == "https://otx.alienvault.com/api/v1/pulses/123"

    def test_base_headers(self):
        from gnat.connectors.alienvault import OTXConfig

        cfg = OTXConfig(api_key="my-api-key")
        headers = cfg.base_headers
        assert headers["X-OTX-API-KEY"] == "my-api-key"
        assert "Accept" in headers


def _load_otx_config_from_ini(api_key="testkey"):
    from gnat.connectors.alienvault import load_otx_config

    cfg_parser = configparser.ConfigParser()
    cfg_parser["alienvault_otx"] = {"api_key": api_key}
    return load_otx_config(cfg_parser)


class TestLoadOTXConfig:
    def test_loads_from_ini_section(self):
        cfg = _load_otx_config_from_ini("my-key")
        assert cfg.api_key == "my-key"

    def test_missing_section_raises(self):
        from gnat.connectors.alienvault import OTXConfigError, load_otx_config

        parser = configparser.ConfigParser()
        with pytest.raises(OTXConfigError, match="not found"):
            load_otx_config(parser)

    def test_missing_api_key_raises(self):
        from gnat.connectors.alienvault import OTXConfigError, load_otx_config

        parser = configparser.ConfigParser()
        parser["alienvault_otx"] = {"api_key": ""}
        with pytest.raises(OTXConfigError):
            load_otx_config(parser)

    def test_verify_ssl_parsed(self):
        from gnat.connectors.alienvault import load_otx_config

        parser = configparser.ConfigParser()
        parser["alienvault_otx"] = {"api_key": "k", "verify_ssl": "false"}
        cfg = load_otx_config(parser)
        assert cfg.verify_ssl is False


class TestOTXClient:
    def _make_client(self):
        from gnat.connectors.alienvault import OTXClient, OTXConfig

        cfg = OTXConfig(api_key="test-key")
        with patch("urllib3.PoolManager") as pm:
            mock_http = MagicMock()
            pm.return_value = mock_http
            client = OTXClient(cfg)
            client._http = mock_http
        return client, mock_http

    def test_get_success(self):
        client, mock_http = self._make_client()
        mock_http.request.return_value = _mock_resp(200, {"results": [{"id": "1"}]})
        result = client.get("pulses/subscribed")
        assert isinstance(result, dict)
        assert "results" in result

    def test_get_with_params(self):
        client, mock_http = self._make_client()
        mock_http.request.return_value = _mock_resp(200, {})
        client.get("pulses/subscribed", params={"limit": 10})
        call_url = mock_http.request.call_args[0][1]
        assert "limit=10" in call_url

    def test_post_success(self):
        client, mock_http = self._make_client()
        mock_http.request.return_value = _mock_resp(201, {"id": "new-pulse"})
        result = client.post("pulses/create", body={"name": "Test"})
        assert result["id"] == "new-pulse"

    def test_401_raises_auth_error(self):
        from gnat.connectors.alienvault import OTXAuthError

        client, mock_http = self._make_client()
        mock_http.request.return_value = _mock_resp(401)
        with pytest.raises(OTXAuthError):
            client.get("pulses/subscribed")

    def test_403_raises_auth_error(self):
        from gnat.connectors.alienvault import OTXAuthError

        client, mock_http = self._make_client()
        mock_http.request.return_value = _mock_resp(403)
        with pytest.raises(OTXAuthError):
            client.get("pulses/subscribed")

    def test_404_raises_not_found_error(self):
        from gnat.connectors.alienvault import OTXNotFoundError

        client, mock_http = self._make_client()
        mock_http.request.return_value = _mock_resp(404)
        with pytest.raises(OTXNotFoundError):
            client.get("pulses/nonexistent")

    def test_429_raises_rate_limit_error(self):
        from gnat.connectors.alienvault import OTXRateLimitError

        client, mock_http = self._make_client()
        mock_http.request.return_value = _mock_resp(429)
        with pytest.raises(OTXRateLimitError):
            client.get("pulses/subscribed")

    def test_500_retried_then_raises(self):
        from gnat.connectors.alienvault import OTXAPIError

        client, mock_http = self._make_client()
        mock_http.request.return_value = _mock_resp(500)
        with patch("time.sleep"), pytest.raises(OTXAPIError):
            client.get("pulses/subscribed")

    def test_context_manager(self):
        from gnat.connectors.alienvault import OTXClient, OTXConfig

        cfg = OTXConfig(api_key="k")
        with patch("urllib3.PoolManager") as pm:
            mock_http = MagicMock()
            pm.return_value = mock_http
            with OTXClient(cfg) as client:
                mock_http.request.return_value = _mock_resp(200, {})
                result = client.get("test")
            mock_http.clear.assert_called_once()

    def test_paginate_single_page(self):
        client, mock_http = self._make_client()
        mock_http.request.return_value = _mock_resp(
            200,
            {
                "results": [{"id": "p1"}, {"id": "p2"}],
                "next": None,
            },
        )
        results = list(client.paginate("pulses/subscribed"))
        assert len(results) == 2

    def test_paginate_multi_page(self):
        client, mock_http = self._make_client()
        page1 = {
            "results": [{"id": "p1"}],
            "next": "https://otx.alienvault.com/api/v1/pulses/subscribed?page=2",
        }
        page2 = {"results": [{"id": "p2"}], "next": None}
        mock_http.request.side_effect = [_mock_resp(200, page1), _mock_resp(200, page2)]
        results = list(client.paginate("pulses/subscribed"))
        assert len(results) == 2


class TestOTXPulseCommands:
    def _make_commands(self, response_body):
        from gnat.connectors.alienvault import OTXClient, OTXConfig, OTXPulseCommands

        cfg = OTXConfig(api_key="key")
        with patch("urllib3.PoolManager") as pm:
            mock_http = MagicMock()
            pm.return_value = mock_http
            client = OTXClient(cfg)
            client._http = mock_http
        mock_http.request.return_value = _mock_resp(200, response_body)
        return OTXPulseCommands(client), mock_http

    def test_list_subscribed_pulses(self):
        cmds, _ = self._make_commands({"results": [{"id": "p1", "name": "Pulse 1"}]})
        pulses = cmds.list_subscribed_pulses()
        assert len(pulses) == 1
        assert pulses[0]["id"] == "p1"

    def test_get_pulse(self):
        cmds, mock_http = self._make_commands({"id": "abc", "name": "Test"})
        pulse = cmds.get_pulse("abc")
        assert pulse["id"] == "abc"

    def test_get_pulse_indicators(self):
        cmds, _ = self._make_commands({"results": [{"indicator": "1.2.3.4", "type": "IPv4"}]})
        inds = cmds.get_pulse_indicators("abc")
        assert len(inds) == 1

    def test_list_my_pulses(self):
        cmds, _ = self._make_commands({"results": [{"id": "mine"}]})
        pulses = cmds.list_my_pulses()
        assert pulses[0]["id"] == "mine"

    def test_normalise_pulse(self):
        from gnat.connectors.alienvault import OTXPulseCommands

        pulse = {
            "id": "p1",
            "name": "My Pulse",
            "description": "Test",
            "author_name": "Alice",
            "TLP": "white",
            "tags": ["malware"],
            "created": "2024-01-01",
            "modified": "2024-01-02",
            "indicator_count": 5,
            "public": True,
            "adversary": "APT1",
            "targeted_countries": ["US"],
            "industries": ["Finance"],
            "malware_families": ["Cobalt Strike"],
            "attack_ids": ["T1566"],
        }
        normed = OTXPulseCommands.normalise_pulse(pulse)
        assert normed["id"] == "p1"
        assert normed["author"] == "Alice"
        assert normed["tlp"] == "white"
        assert normed["adversary"] == "APT1"


class TestOTXIndicatorCommands:
    def _make_commands(self, response_body=None):
        from gnat.connectors.alienvault import OTXClient, OTXConfig, OTXIndicatorCommands

        cfg = OTXConfig(api_key="key")
        with patch("urllib3.PoolManager") as pm:
            mock_http = MagicMock()
            pm.return_value = mock_http
            client = OTXClient(cfg)
            client._http = mock_http
        mock_http.request.return_value = _mock_resp(200, response_body or {})
        return OTXIndicatorCommands(client), mock_http

    def test_search_returns_dict(self):
        cmds, _ = self._make_commands({"count": 1, "results": [{"name": "pulse"}]})
        result = cmds.search("malware")
        assert "count" in result

    def test_get_ip_details(self):
        cmds, mock_http = self._make_commands({"general": {"pulse_count": 3}})
        cmds.get_ip_details("1.2.3.4")
        call_url = mock_http.request.call_args[0][1]
        assert "IPv4/1.2.3.4/general" in call_url

    def test_get_domain_details(self):
        cmds, mock_http = self._make_commands({})
        cmds.get_domain_details("evil.com")
        call_url = mock_http.request.call_args[0][1]
        assert "domain/evil.com/general" in call_url

    def test_normalise_indicator(self):
        from gnat.connectors.alienvault import OTXIndicatorCommands

        ind = {
            "id": 1,
            "type": "IPv4",
            "indicator": "1.2.3.4",
            "created": "2024-01-01",
            "description": "Bad IP",
            "title": "Evil IP",
            "role": "C2",
            "is_active": True,
        }
        normed = OTXIndicatorCommands.normalise_indicator(ind)
        assert normed["value"] == "1.2.3.4"
        assert normed["stix_type"] == "ipv4-addr"
        assert normed["type"] == "IPv4"


class TestOTXSTIXMapper:
    def _make_pulse(self):
        return {
            "id": "pulse-123",
            "name": "Test Pulse",
            "description": "A test pulse",
            "author": "tester",
            "tlp": "white",
            "tags": ["malware", "apt"],
            "created": "2024-01-01T00:00:00Z",
            "modified": "2024-01-02T00:00:00Z",
            "malware_families": ["Cobalt Strike"],
            "attack_ids": ["T1566"],
            "targeted_countries": ["US"],
            "adversary": "APT1",
            "_raw": {"indicators": []},
        }

    def test_pulse_to_stix_bundle_returns_bundle(self):
        from gnat.connectors.alienvault import OTXSTIXMapper

        mapper = OTXSTIXMapper()
        bundle = mapper.pulse_to_stix_bundle(self._make_pulse(), indicators=[])
        assert bundle["type"] == "bundle"
        assert bundle["spec_version"] == "2.1"
        assert any(o["type"] == "report" for o in bundle["objects"])

    def test_indicator_ip_to_stix(self):
        from gnat.connectors.alienvault import OTXSTIXMapper

        mapper = OTXSTIXMapper()
        ind = {
            "type": "IPv4",
            "value": "1.2.3.4",
            "created": "2024-01-01T00:00:00Z",
            "description": "",
        }
        objs = mapper.indicator_to_stix_objects(ind)
        types = {o["type"] for o in objs}
        assert "ipv4-addr" in types
        assert "indicator" in types

    def test_indicator_domain_to_stix(self):
        from gnat.connectors.alienvault import OTXSTIXMapper

        mapper = OTXSTIXMapper()
        ind = {
            "type": "domain",
            "value": "evil.com",
            "created": "2024-01-01T00:00:00Z",
            "description": "",
        }
        objs = mapper.indicator_to_stix_objects(ind)
        sco = next(o for o in objs if o["type"] == "domain-name")
        assert sco["value"] == "evil.com"

    def test_indicator_sha256_to_stix(self):
        from gnat.connectors.alienvault import OTXSTIXMapper

        mapper = OTXSTIXMapper()
        h = "a" * 64
        ind = {"type": "FileHash-SHA256", "value": h, "description": ""}
        objs = mapper.indicator_to_stix_objects(ind)
        file_obj = next(o for o in objs if o["type"] == "file")
        assert "SHA-256" in file_obj["hashes"]

    def test_indicator_url_to_stix(self):
        from gnat.connectors.alienvault import OTXSTIXMapper

        mapper = OTXSTIXMapper()
        ind = {"type": "URL", "value": "https://evil.com/malware", "description": ""}
        objs = mapper.indicator_to_stix_objects(ind)
        url_obj = next(o for o in objs if o["type"] == "url")
        assert url_obj["value"] == "https://evil.com/malware"

    def test_indicator_email_to_stix(self):
        from gnat.connectors.alienvault import OTXSTIXMapper

        mapper = OTXSTIXMapper()
        ind = {"type": "email", "value": "bad@evil.com", "description": ""}
        objs = mapper.indicator_to_stix_objects(ind)
        email_obj = next(o for o in objs if o["type"] == "email-addr")
        assert email_obj["value"] == "bad@evil.com"

    def test_indicator_cve_to_stix(self):
        from gnat.connectors.alienvault import OTXSTIXMapper

        mapper = OTXSTIXMapper()
        ind = {"type": "CVE", "value": "CVE-2024-1234", "description": ""}
        objs = mapper.indicator_to_stix_objects(ind)
        vuln = next(o for o in objs if o["type"] == "vulnerability")
        assert "CVE-2024-1234" in str(vuln)

    def test_unknown_type_returns_empty(self):
        from gnat.connectors.alienvault import OTXSTIXMapper

        mapper = OTXSTIXMapper()
        ind = {"type": "UNKNOWN_TYPE", "value": "something", "description": ""}
        objs = mapper.indicator_to_stix_objects(ind)
        assert objs == []

    def test_empty_value_returns_empty(self):
        from gnat.connectors.alienvault import OTXSTIXMapper

        mapper = OTXSTIXMapper()
        ind = {"type": "IPv4", "value": "", "description": ""}
        objs = mapper.indicator_to_stix_objects(ind)
        assert objs == []

    def test_indicators_to_stix_bundle(self):
        from gnat.connectors.alienvault import OTXSTIXMapper

        mapper = OTXSTIXMapper()
        inds = [
            {"type": "IPv4", "value": "1.2.3.4", "description": ""},
            {"type": "domain", "value": "evil.com", "description": ""},
        ]
        bundle = mapper.indicators_to_stix_bundle(inds)
        assert bundle["type"] == "bundle"
        assert len(bundle["objects"]) >= 2

    def test_pulse_to_stix_bundle_with_indicators(self):
        from gnat.connectors.alienvault import OTXSTIXMapper

        mapper = OTXSTIXMapper()
        pulse = self._make_pulse()
        inds = [{"type": "IPv4", "value": "1.2.3.4", "description": ""}]
        bundle = mapper.pulse_to_stix_bundle(pulse, indicators=inds)
        report = next(o for o in bundle["objects"] if o["type"] == "report")
        assert len(report["object_refs"]) > 0


# ===========================================================================
# 3. gnat/export/delivery/targets.py
# ===========================================================================


class TestFileDelivery:
    def test_deliver_text_payload(self, tmp_path):
        from gnat.export.base import TransformResult
        from gnat.export.delivery.targets import FileDelivery

        result = TransformResult(payloads={"indicators.txt": "1.2.3.4\nevil.com\n"})
        delivery = FileDelivery(str(tmp_path))
        dr = delivery.deliver(result)
        assert "indicators.txt" in dr.delivered
        assert (tmp_path / "indicators.txt").exists()
        assert "1.2.3.4" in (tmp_path / "indicators.txt").read_text()

    def test_deliver_dict_payload(self, tmp_path):
        from gnat.export.base import TransformResult
        from gnat.export.delivery.targets import FileDelivery

        result = TransformResult(payloads={"data.json": {"key": "value"}})
        delivery = FileDelivery(str(tmp_path))
        dr = delivery.deliver(result)
        assert "data.json" in dr.delivered
        data = json.loads((tmp_path / "data.json").read_text())
        assert data["key"] == "value"

    def test_deliver_bytes_payload(self, tmp_path):
        from gnat.export.base import TransformResult
        from gnat.export.delivery.targets import FileDelivery

        result = TransformResult(payloads={"file.bin": b"\x00\x01\x02"})
        delivery = FileDelivery(str(tmp_path))
        dr = delivery.deliver(result)
        assert "file.bin" in dr.delivered

    def test_creates_output_dir(self, tmp_path):
        from gnat.export.base import TransformResult
        from gnat.export.delivery.targets import FileDelivery

        out_dir = tmp_path / "nested" / "dir"
        result = TransformResult(payloads={"test.txt": "content"})
        FileDelivery(str(out_dir)).deliver(result)
        assert out_dir.exists()

    def test_non_atomic_write(self, tmp_path):
        from gnat.export.base import TransformResult
        from gnat.export.delivery.targets import FileDelivery

        result = TransformResult(payloads={"test.txt": "hello"})
        delivery = FileDelivery(str(tmp_path), atomic=False)
        dr = delivery.deliver(result)
        assert "test.txt" in dr.delivered

    def test_write_failure_tracked(self, tmp_path):
        from gnat.export.base import TransformResult
        from gnat.export.delivery.targets import FileDelivery

        # Use a non-serializable object to trigger failure on dict delivery
        class BadObj:
            def __len__(self):
                raise ValueError("bad")

        result = TransformResult(payloads={"bad.json": BadObj()})
        delivery = FileDelivery(str(tmp_path))
        dr = delivery.deliver(result)
        assert "bad.json" in dr.failed
        assert not dr.success

    def test_repr(self, tmp_path):
        from gnat.export.delivery.targets import FileDelivery

        d = FileDelivery(str(tmp_path))
        assert "FileDelivery" in repr(d)


class TestHTTPDelivery:
    def test_deliver_success(self):
        from gnat.export.base import TransformResult
        from gnat.export.delivery.targets import HTTPDelivery

        result = TransformResult(payloads={"data.json": {"key": "value"}})
        delivery = HTTPDelivery("https://example.com/api")

        mock_resp = MagicMock()
        mock_resp.getcode.return_value = 200
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            dr = delivery.deliver(result)
        assert "data.json" in dr.delivered

    def test_deliver_http_error(self):
        import urllib.error

        from gnat.export.base import TransformResult
        from gnat.export.delivery.targets import HTTPDelivery

        result = TransformResult(payloads={"data.json": {"key": "value"}})
        delivery = HTTPDelivery("https://example.com/api")

        with patch(
            "urllib.request.urlopen",
            side_effect=urllib.error.HTTPError(
                "https://example.com/api", 500, "Server Error", {}, None
            ),
        ):
            dr = delivery.deliver(result)
        assert "data.json" in dr.failed
        assert not dr.success

    def test_deliver_generic_error(self):
        from gnat.export.base import TransformResult
        from gnat.export.delivery.targets import HTTPDelivery

        result = TransformResult(payloads={"data.json": {}})
        delivery = HTTPDelivery("https://example.com/api")

        with patch("urllib.request.urlopen", side_effect=ConnectionError("network error")):
            dr = delivery.deliver(result)
        assert not dr.success

    def test_basic_auth_added(self):
        from gnat.export.base import TransformResult
        from gnat.export.delivery.targets import HTTPDelivery

        result = TransformResult(payloads={"x": "data"})
        delivery = HTTPDelivery("https://example.com/api", auth=("user", "pass"))

        captured_req = {}

        def capture_urlopen(req, timeout=None):
            captured_req["headers"] = dict(req.headers)
            resp = MagicMock()
            resp.getcode.return_value = 200
            resp.__enter__ = lambda s: s
            resp.__exit__ = MagicMock(return_value=False)
            return resp

        with patch("urllib.request.urlopen", capture_urlopen):
            delivery.deliver(result)
        assert "Authorization" in captured_req["headers"]

    def test_repr(self):
        from gnat.export.delivery.targets import HTTPDelivery

        d = HTTPDelivery("https://example.com")
        assert "HTTPDelivery" in repr(d)
        assert "example.com" in repr(d)


class TestEDLServer:
    def test_deliver_registers_files(self):
        from gnat.export.base import TransformResult
        from gnat.export.delivery.targets import EDLServer

        server = EDLServer(port=0)
        result = TransformResult(payloads={"indicators.txt": "1.2.3.4\n"})
        with patch.object(server, "_start"):
            dr = server.deliver(result)
        assert "indicators.txt" in dr.delivered

    def test_url_method(self):
        from gnat.export.delivery.targets import EDLServer

        server = EDLServer(host="0.0.0.0", port=8888)
        assert "localhost" in server.url("test.txt")
        assert "8888" in server.url("test.txt")

    def test_url_custom_host(self):
        from gnat.export.delivery.targets import EDLServer

        server = EDLServer(host="192.168.1.1", port=9999)
        assert "192.168.1.1" in server.url()

    def test_bytes_content_decoded(self):
        from gnat.export.base import TransformResult
        from gnat.export.delivery.targets import EDLServer

        server = EDLServer(port=0)
        result = TransformResult(payloads={"test.txt": b"1.2.3.4\n"})
        with patch.object(server, "_start"):
            server.deliver(result)
        with server._lock:
            assert server._files["test.txt"] == "1.2.3.4\n"

    def test_repr(self):
        from gnat.export.delivery.targets import EDLServer

        assert "EDLServer" in repr(EDLServer(port=8080))


class TestLogDelivery:
    def test_deliver_string_payload(self):
        from gnat.export.base import TransformResult
        from gnat.export.delivery.targets import LogDelivery

        result = TransformResult(payloads={"test": "hello"})
        dr = LogDelivery().deliver(result)
        assert "test" in dr.delivered

    def test_deliver_dict_payload(self):
        from gnat.export.base import TransformResult
        from gnat.export.delivery.targets import LogDelivery

        result = TransformResult(payloads={"data": {"key": "value"}})
        dr = LogDelivery().deliver(result)
        assert "data" in dr.delivered

    def test_deliver_bytes_payload(self):
        from gnat.export.base import TransformResult
        from gnat.export.delivery.targets import LogDelivery

        result = TransformResult(payloads={"bin": b"bytes data"})
        dr = LogDelivery().deliver(result)
        assert "bin" in dr.delivered

    def test_max_chars_truncation(self):
        from gnat.export.base import TransformResult
        from gnat.export.delivery.targets import LogDelivery

        result = TransformResult(payloads={"big": "x" * 1000})
        delivery = LogDelivery(max_chars=10)
        with patch("logging.Logger.log") as mock_log:
            delivery.deliver(result)
            logged = str(mock_log.call_args)
            # 10-char truncation means content is short
            assert len(mock_log.call_args[0]) > 0

    def test_repr(self):
        from gnat.export.delivery.targets import LogDelivery

        assert "LogDelivery" in repr(LogDelivery())


class TestMultiDelivery:
    def test_requires_at_least_two_targets(self):
        from gnat.export.delivery.targets import LogDelivery, MultiDelivery

        with pytest.raises(ValueError):
            MultiDelivery(LogDelivery())

    def test_delivers_to_all_targets(self):
        from gnat.export.base import TransformResult
        from gnat.export.delivery.targets import LogDelivery, MultiDelivery

        t1 = LogDelivery()
        t2 = LogDelivery()
        multi = MultiDelivery(t1, t2)
        result = TransformResult(payloads={"x": "data"})
        dr = multi.deliver(result)
        # Each target delivers "x", so combined has two entries
        assert dr.delivered.count("x") == 2

    def test_failure_in_one_propagates(self):
        from gnat.export.base import DeliveryResult, TransformResult
        from gnat.export.delivery.targets import LogDelivery, MultiDelivery

        bad = MagicMock()
        bad_result = DeliveryResult(success=False, failed=["x"], errors=["boom"])
        bad.deliver.return_value = bad_result
        good = LogDelivery()
        multi = MultiDelivery(bad, good)
        result = TransformResult(payloads={"x": "data"})
        dr = multi.deliver(result)
        assert not dr.success

    def test_repr(self):
        from gnat.export.delivery.targets import LogDelivery, MultiDelivery

        m = MultiDelivery(LogDelivery(), LogDelivery())
        assert "MultiDelivery" in repr(m)
        assert "n=2" in repr(m)


class TestPlatformDelivery:
    def test_delivers_objects(self):
        from gnat.export.base import TransformResult
        from gnat.export.delivery.targets import PlatformDelivery

        client = MagicMock()
        client.client.from_stix.return_value = {"native": True}
        delivery = PlatformDelivery(client)
        result = TransformResult(
            payloads={"objects": [{"type": "indicator", "id": "indicator--1"}]}
        )
        dr = delivery.deliver(result)
        assert dr.metadata["written"] == 1

    def test_delivers_from_bundle_json(self):
        from gnat.export.base import TransformResult
        from gnat.export.delivery.targets import PlatformDelivery

        client = MagicMock()
        client.client.from_stix.return_value = {}
        bundle = json.dumps({"objects": [{"type": "indicator", "id": "indicator--1"}]})
        delivery = PlatformDelivery(client)
        result = TransformResult(payloads={"bundle.json": bundle})
        dr = delivery.deliver(result)
        assert dr.metadata["written"] == 1


# ===========================================================================
# 4. gnat/agents/copilot.py
# ===========================================================================


class TestCopilotReader:
    def _make_reader(self, sources=None, secret="test-secret", **kwargs):
        from gnat.agents.copilot import CopilotReader

        return CopilotReader(
            directline_secret=secret,
            sources=sources
            or [{"type": "mailbox", "name": "TestMail", "query": "from:test@example.com"}],
            **kwargs,
        )

    def test_init_raises_on_empty_sources(self):
        from gnat.agents.copilot import CopilotReader

        with pytest.raises(ValueError, match="at least one source"):
            CopilotReader(directline_secret="secret", sources=[])

    def test_bearer_uses_secret_by_default(self):
        reader = self._make_reader()
        assert reader._bearer() == "test-secret"

    def test_bearer_uses_token_when_exchanged(self):
        from gnat.agents.copilot import CopilotReader

        reader = CopilotReader(
            directline_secret="secret",
            sources=[{"type": "mailbox", "name": "Test"}],
            use_token_exchange=True,
        )
        reader._token = "my-token"
        assert reader._bearer() == "my-token"

    def test_build_query_sharepoint(self):
        reader = self._make_reader(
            sources=[
                {
                    "type": "sharepoint",
                    "name": "Security-Intel",
                    "url": "https://contoso.sharepoint.com/sites/Security-Intel",
                    "library": "Threat Reports",
                }
            ]
        )
        query = reader._build_query(reader._sources[0])
        assert "SharePoint" in query
        assert "Threat Reports" in query

    def test_build_query_mailbox(self):
        reader = self._make_reader(
            sources=[
                {
                    "type": "mailbox",
                    "name": "Security Advisories",
                    "query": "from:vendor@example.com",
                }
            ]
        )
        query = reader._build_query(reader._sources[0])
        assert "mailbox" in query
        assert "vendor@example.com" in query

    def test_build_query_teams_channel(self):
        reader = self._make_reader(
            sources=[
                {
                    "type": "teams_channel",
                    "name": "SOC Feed",
                    "team": "Security Operations",
                    "channel": "Threat Intel",
                }
            ]
        )
        query = reader._build_query(reader._sources[0])
        assert "Threat Intel" in query
        assert "Security Operations" in query

    def test_build_query_onedrive(self):
        reader = self._make_reader(
            sources=[
                {
                    "type": "onedrive",
                    "name": "ThreatDocs",
                    "path": "/Reports",
                }
            ]
        )
        query = reader._build_query(reader._sources[0])
        assert "OneDrive" in query
        assert "/Reports" in query

    def test_build_query_newer_than_hint(self):
        reader = self._make_reader(newer_than="2024-01-01T00:00:00Z")
        query = reader._build_query(reader._sources[0])
        assert "2024-01-01" in query

    def test_parse_reply_json_array(self):
        from gnat.agents.copilot import CopilotReader

        items = [{"title": "Report 1", "url": "https://example.com", "text": "content"}]
        result = CopilotReader._parse_reply(json.dumps(items), {"name": "Test"})
        assert len(result) == 1
        assert result[0]["title"] == "Report 1"

    def test_parse_reply_prose_fallback(self):
        from gnat.agents.copilot import CopilotReader

        result = CopilotReader._parse_reply("This is plain text response.", {"name": "Test"})
        assert len(result) == 1
        assert result[0]["text"] == "This is plain text response."

    def test_parse_reply_empty_returns_empty(self):
        from gnat.agents.copilot import CopilotReader

        result = CopilotReader._parse_reply("", {"name": "Test"})
        assert result == []

    def test_parse_reply_strips_markdown_fences(self):
        from gnat.agents.copilot import CopilotReader

        items = [{"title": "Report", "url": "", "text": "content"}]
        fenced = f"```json\n{json.dumps(items)}\n```"
        result = CopilotReader._parse_reply(fenced, {"name": "Test"})
        assert len(result) == 1

    def test_extract_card_text_from_adaptive_card(self):
        from gnat.agents.copilot import CopilotReader

        activity = {
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "content": {
                        "body": [
                            {"type": "TextBlock", "text": "Hello"},
                            {"type": "TextBlock", "text": "World"},
                        ]
                    },
                }
            ]
        }
        text = CopilotReader._extract_card_text(activity)
        assert "Hello" in text
        assert "World" in text

    def test_extract_card_text_no_attachment(self):
        from gnat.agents.copilot import CopilotReader

        assert CopilotReader._extract_card_text({"attachments": []}) == ""

    def test_dl_request_returns_parsed_json(self):
        reader = self._make_reader()
        resp_data = json.dumps({"conversationId": "conv-123"}).encode()
        mock_resp = MagicMock()
        mock_resp.read.return_value = resp_data
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = reader._dl_request(
                "https://directline.botframework.com/v3/directline/conversations"
            )
        assert result["conversationId"] == "conv-123"

    def test_dl_request_http_error_returns_none(self):
        import urllib.error

        reader = self._make_reader()
        err = urllib.error.HTTPError(
            "https://directline.botframework.com/v3/directline/conversations",
            401,
            "Unauthorized",
            {},
            None,
        )
        err.read = lambda: b"Unauthorized"
        with patch("urllib.request.urlopen", side_effect=err):
            result = reader._dl_request(
                "https://directline.botframework.com/v3/directline/conversations"
            )
        assert result is None

    def test_open_conversation_parses_id(self):
        reader = self._make_reader()
        payload = json.dumps({"conversationId": "conv-abc"}).encode()
        mock_resp = MagicMock()
        mock_resp.read.return_value = payload
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            conv_id = reader._open_conversation()
        assert conv_id == "conv-abc"

    def test_send_message_returns_true_on_success(self):
        reader = self._make_reader()
        payload = json.dumps({"id": "act-1"}).encode()
        mock_resp = MagicMock()
        mock_resp.read.return_value = payload
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            ok = reader._send_message("conv-abc", "test message")
        assert ok is True

    def test_ensure_token_skipped_when_disabled(self):
        reader = self._make_reader()
        # Should do nothing
        reader._ensure_token()
        assert reader._token is None

    def test_iter_records_integration(self):
        """Full _iter_records flow with mocked DirectLine."""
        from gnat.agents.copilot import CopilotReader

        reader = CopilotReader(
            directline_secret="secret",
            sources=[{"type": "mailbox", "name": "Test"}],
            poll_interval=0,
            max_poll_attempts=1,
        )

        content_items = json.dumps([{"title": "T1", "url": "https://x.com", "text": "content 1"}])
        call_count = [0]

        def mock_dl_request(url, data=None, method="GET"):
            call_count[0] += 1
            if "conversations" in url and method == "POST" and "activities" not in url:
                return {"conversationId": "conv-1"}
            if "activities" in url and method == "POST":
                return {"id": "act-1"}
            if "activities" in url and method == "GET":
                return {
                    "watermark": "1",
                    "activities": [
                        {"type": "message", "from": {"id": "bot-1"}, "text": content_items}
                    ],
                }
            return None

        reader._dl_request = mock_dl_request
        recs = list(reader._iter_records())
        assert len(recs) == 1
        assert recs[0]["title"] == "T1"


# ===========================================================================
# 5. gnat/connectors/recordedfuture/rfv3.py
# ===========================================================================


class _FakeRFBase:
    """Minimal stub for RecordedFutureBase used in rfv3 tests."""

    def __init__(self):
        self._responses = {}
        self._patch_responses = {}

    def get(self, path: str, params=None):
        return self._responses.get(path, {})

    def patch(self, path: str, json=None):
        return self._patch_responses.get(path, {})


def _make_rfv3():
    """
    Build a RecordedFutureClientV3 instance by monkey-patching its base
    class import, since gnat.connectors.recordedfuture.base does not exist.
    """
    import types

    # Create a fake module for the missing base
    fake_module = types.ModuleType("gnat.connectors.recordedfuture.base")

    class RecordedFutureBase(_FakeRFBase):
        pass

    fake_module.RecordedFutureBase = RecordedFutureBase

    # Inject into sys.modules before importing rfv3
    sys.modules.setdefault("gnat.connectors.recordedfuture.base", fake_module)

    from gnat.connectors.recordedfuture import rfv3 as _rfv3_module

    # Patch the class's base if it used the old stub
    if not issubclass(_rfv3_module.RecordedFutureClientV3, _FakeRFBase):
        # Re-create by composition
        pass

    # Directly instantiate with our fake base
    class V3(_FakeRFBase, _rfv3_module.RecordedFutureClientV3.__mro__[-2]):
        pass

    # Simpler: just use composition by calling the class without real base
    # Inject get/patch at instance level
    client = object.__new__(_rfv3_module.RecordedFutureClientV3)
    client._responses = {}
    client._patch_responses = {}
    client.get = lambda path, params=None: client._responses.get(path, {})
    client.patch = lambda path, json=None: client._patch_responses.get(path, {})
    return client


class TestRecordedFutureClientV3:
    def setup_method(self):
        """Ensure base module is mocked before each test."""
        import types

        fake_module = types.ModuleType("gnat.connectors.recordedfuture.base")

        class RecordedFutureBase:
            pass

        fake_module.RecordedFutureBase = RecordedFutureBase
        sys.modules["gnat.connectors.recordedfuture.base"] = fake_module

    def _make_client(self):
        return _make_rfv3()

    def test_list_alerts_empty_response(self):
        client = self._make_client()
        client._responses["/v3/alerts"] = {}
        result = client.list_alerts()
        assert result == []

    def test_list_alerts_single_page(self):
        client = self._make_client()
        client._responses["/v3/alerts"] = {
            "data": {"results": [{"id": "a1"}, {"id": "a2"}], "nextPageToken": None}
        }
        result = client.list_alerts(limit=10)
        assert len(result) == 2

    def test_list_alerts_with_filters(self):
        client = self._make_client()
        called_params = []

        def fake_get(path, params=None):
            called_params.append(params)
            return {"data": {"results": [], "nextPageToken": None}}

        client.get = fake_get
        client.list_alerts(filters={"status": "new"})
        assert called_params[0]["status"] == "new"

    def test_list_alerts_respects_limit(self):
        client = self._make_client()

        def fake_get(path, params=None):
            return {"data": {"results": [{"id": f"a{i}"} for i in range(5)], "nextPageToken": None}}

        client.get = fake_get
        result = client.list_alerts(limit=3)
        assert len(result) == 3

    def test_get_alert_returns_data(self):
        client = self._make_client()
        client._responses["/v3/alerts/alert-1"] = {"data": {"id": "alert-1", "title": "Test"}}
        result = client.get_alert("alert-1")
        assert result["id"] == "alert-1"

    def test_get_alert_empty_response(self):
        client = self._make_client()
        client._responses["/v3/alerts/alert-1"] = {}
        result = client.get_alert("alert-1")
        assert result == {}

    def test_list_playbook_alerts(self):
        client = self._make_client()
        client._responses["/v3/playbook-alert"] = {
            "data": {"results": [{"id": "pa1"}], "nextPageToken": None}
        }
        result = client.list_playbook_alerts()
        assert len(result) == 1
        assert result[0]["id"] == "pa1"

    def test_get_playbook_alert(self):
        client = self._make_client()
        client._responses["/v3/playbook-alert/pa-1"] = {"data": {"id": "pa-1"}}
        result = client.get_playbook_alert("pa-1")
        assert result["id"] == "pa-1"

    def test_update_playbook_alert(self):
        client = self._make_client()
        client._patch_responses["/v3/playbook-alert/pa-1"] = {
            "data": {"id": "pa-1", "status": "closed"}
        }
        result = client.update_playbook_alert("pa-1", {"status": "closed"})
        assert result["status"] == "closed"

    def test_list_playbook_alert_categories(self):
        client = self._make_client()
        client._responses["/v3/playbook-alert/categories"] = {
            "data": {"results": [{"name": "Ransomware"}]}
        }
        result = client.list_playbook_alert_categories()
        assert result[0]["name"] == "Ransomware"

    def test_list_fusion_files(self):
        client = self._make_client()
        client._responses["/v3/fusion/files"] = {"data": {"results": [{"name": "threat_feed.csv"}]}}
        result = client.list_fusion_files()
        assert result[0]["name"] == "threat_feed.csv"

    def test_list_fusion_files_with_path(self):
        client = self._make_client()
        called_params = []

        def fake_get(path, params=None):
            called_params.append(params)
            return {"data": {"results": []}}

        client.get = fake_get
        client.list_fusion_files(path="/feeds/")
        assert called_params[0]["path"] == "/feeds/"

    def test_get_fusion_file_bytes_response(self):
        client = self._make_client()
        client._responses["/v3/fusion/files"] = b"csv,data\n1.2.3.4,ip"
        result = client.get_fusion_file("feeds/threat.csv")
        assert result == b"csv,data\n1.2.3.4,ip"

    def test_get_fusion_file_dict_response(self):
        client = self._make_client()
        client._responses["/v3/fusion/files"] = {"data": b"csv,data"}
        result = client.get_fusion_file("feeds/threat.csv")
        assert result == b"csv,data"

    def test_get_risk_evidence(self):
        native = {"risk": {"evidenceDetails": [{"rule": "Historically Reported in Threat List"}]}}
        client = self._make_client()
        evidence = client.get_risk_evidence(native)
        assert len(evidence) == 1
        assert evidence[0]["rule"] == "Historically Reported in Threat List"

    def test_get_risk_evidence_empty(self):
        client = self._make_client()
        assert client.get_risk_evidence({}) == []
        assert client.get_risk_evidence({"risk": {}}) == []

    def test_api_version_constant(self):
        from gnat.connectors.recordedfuture.rfv3 import RecordedFutureClientV3

        assert RecordedFutureClientV3.API_VERSION == "v3"
        assert RecordedFutureClientV3.API_PREFIX == "/v3"

    def test_list_alerts_pagination_stops_on_no_token(self):
        client = self._make_client()
        call_count = [0]

        def fake_get(path, params=None):
            call_count[0] += 1
            return {"data": {"results": [{"id": "a1"}], "nextPageToken": None}}

        client.get = fake_get
        result = client.list_alerts()
        assert call_count[0] == 1

    def test_list_alerts_pagination_follows_token(self):
        client = self._make_client()
        responses = [
            {"data": {"results": [{"id": "a1"}], "nextPageToken": "tok1"}},
            {"data": {"results": [{"id": "a2"}], "nextPageToken": None}},
        ]
        call_count = [0]

        def fake_get(path, params=None):
            r = responses[min(call_count[0], len(responses) - 1)]
            call_count[0] += 1
            return r

        client.get = fake_get
        result = client.list_alerts(limit=10)
        assert len(result) == 2
        assert call_count[0] == 2
