"""
tests/unit/ingest/test_ingest.py
=================================

Unit tests for the GNAT ingestion layer.

Covers:
- SourceReader base behaviour (context manager, open/close, read_all)
- DeduplicationCache fingerprinting
- IngestPipeline fluent API, filters, transforms, dedup, run()
- PlainTextReader (IOC classification, defang, skip_unknown)
- CSVReader (column mapping, field_map, delimiter)
- JSONReader (array, object-wrapped, from_string)
- JSONLReader (valid lines, parse errors)
- STIXBundleReader (type filter, bundle vs list)
- SQLReader (mocked dbapi2 cursor)
- MISPReader (event + attribute extraction, to_ids filter)
- SyslogReader (syslog / CEF / LEEF / auto-detect)
- OpenIOCReader (XML parsing)
- FlatIOCMapper (all IOC types, unknown skip)
- STIXPassthroughMapper (type routing, type_filter)
- MISPAttributeMapper (to_ids, unknown types, composite values)
- CEFMapper (field extraction)
- SQLRowMapper (column bindings, class routing)
- RSSEntryMapper (CVE, IP, URL, hash extraction)
- EmailIOCMapper (ips/domains/urls/hashes)
- OpenIOCMapper (search→pattern mapping)
- NVDCVEMapper (1.x and 2.x formats)
"""

import json
import sqlite3
import textwrap
from unittest.mock import MagicMock

import pytest

from gnat.ingest.base import (
    DeduplicationCache,
    IngestResult,
    RawRecord,
    RecordMapper,
    SourceReader,
)
from gnat.ingest.pipeline.pipeline import IngestPipeline
from gnat.ingest.sources.readers import (
    CSVReader,
    JSONLReader,
    JSONReader,
    MISPReader,
    OpenIOCReader,
    PlainTextReader,
    SQLReader,
    STIXBundleReader,
    SyslogReader,
)
from gnat.ingest.mappers.mappers import (
    CEFMapper,
    EmailIOCMapper,
    FlatIOCMapper,
    MISPAttributeMapper,
    NVDCVEMapper,
    OpenIOCMapper,
    RSSEntryMapper,
    SQLRowMapper,
    STIXPassthroughMapper,
)
from gnat.orm.indicator import Indicator
from gnat.orm.malware import Malware
from gnat.orm.vulnerability import Vulnerability


# ===========================================================================
# Helpers
# ===========================================================================

def _records(reader: SourceReader):
    """Collect all records from a reader without context manager."""
    reader.open()
    recs = list(reader._iter_records())
    reader.close()
    return recs


def _map(mapper: RecordMapper, record: RawRecord):
    """Collect all objects produced by mapping a single record."""
    return list(mapper.map(record))


# ===========================================================================
# Base classes
# ===========================================================================

class TestSourceReaderBase:

    def test_context_manager_calls_open_close(self):
        class DummyReader(SourceReader):
            events = []
            def open(self):
                super().open()
                self.events.append("open")
            def close(self):
                self.events.append("close")
                super().close()
            def _iter_records(self):
                yield {"x": 1}

        r = DummyReader()
        with r as ctx:
            assert ctx is r
            records = list(r)
        assert r.events == ["open", "close"]
        assert records == [{"x": 1}]

    def test_read_all_returns_list(self):
        class SimpleReader(SourceReader):
            def _iter_records(self):
                for i in range(3):
                    yield {"n": i}

        assert SimpleReader().read_all() == [{"n": 0}, {"n": 1}, {"n": 2}]

    def test_repr_contains_class_name(self):
        class MyReader(SourceReader):
            def _iter_records(self): return iter([])
        assert "MyReader" in repr(MyReader())


class TestDeduplicationCache:

    def _make_indicator(self, stix_id: str) -> Indicator:
        ind = Indicator()
        ind.id = stix_id
        return ind

    def test_first_occurrence_not_duplicate(self):
        cache = DeduplicationCache()
        ind = self._make_indicator("indicator--aaa")
        assert cache.is_duplicate(ind) is False

    def test_second_occurrence_is_duplicate(self):
        cache = DeduplicationCache()
        ind = self._make_indicator("indicator--bbb")
        cache.is_duplicate(ind)
        assert cache.is_duplicate(ind) is True

    def test_different_ids_not_duplicate(self):
        cache = DeduplicationCache()
        a = self._make_indicator("indicator--111")
        b = self._make_indicator("indicator--222")
        cache.is_duplicate(a)
        assert cache.is_duplicate(b) is False

    def test_custom_key_fields(self):
        cache = DeduplicationCache(key_fields=["name"])
        ind1 = Indicator(name="evil.com")
        ind2 = Indicator(name="evil.com")   # same name, different auto-uuid
        assert cache.is_duplicate(ind1) is False
        assert cache.is_duplicate(ind2) is True

    def test_clear_resets_cache(self):
        cache = DeduplicationCache()
        ind = self._make_indicator("indicator--ccc")
        cache.is_duplicate(ind)
        cache.clear()
        assert cache.is_duplicate(ind) is False

    def test_len(self):
        cache = DeduplicationCache()
        for i in range(5):
            cache.is_duplicate(self._make_indicator(f"indicator--{i:032d}"))
        assert len(cache) == 5


# ===========================================================================
# IngestPipeline
# ===========================================================================

class TestIngestPipeline:

    def _simple_reader(self, records):
        class R(SourceReader):
            def __init__(self, recs):
                super().__init__(source_id="test")
                self._recs = recs
            def _iter_records(self):
                yield from self._recs
        return R(records)

    def _simple_mapper(self):
        class M(RecordMapper):
            def map(self, record):
                if record.get("value"):
                    yield Indicator(name=record["value"],
                                    pattern=f"[ipv4-addr:value = '{record['value']}']",
                                    pattern_type="stix")
        return M()

    def test_raises_without_reader(self):
        with pytest.raises(RuntimeError, match="reader"):
            list(IngestPipeline().map_with(self._simple_mapper()).iter_objects())

    def test_raises_without_mapper(self):
        with pytest.raises(RuntimeError, match="mapper"):
            list(IngestPipeline().read_from(self._simple_reader([])).iter_objects())

    def test_iter_objects_yields_stix(self):
        records = [{"value": f"10.0.0.{i}"} for i in range(3)]
        objs = list(
            IngestPipeline()
            .read_from(self._simple_reader(records))
            .map_with(self._simple_mapper())
            .iter_objects()
        )
        assert len(objs) == 3
        assert all(isinstance(o, Indicator) for o in objs)

    def test_run_returns_ingest_result(self):
        records = [{"value": "1.2.3.4"}, {"value": ""}]
        result = (
            IngestPipeline()
            .read_from(self._simple_reader(records))
            .map_with(self._simple_mapper())
            .run()
        )
        assert isinstance(result, IngestResult)
        assert result.total_records == 2
        assert result.mapped_objects == 1

    def test_filter_drops_objects(self):
        records = [{"value": "1.1.1.1"}, {"value": "2.2.2.2"}]
        objs = list(
            IngestPipeline()
            .read_from(self._simple_reader(records))
            .map_with(self._simple_mapper())
            .filter(lambda o: "1.1.1.1" in o.pattern)
            .iter_objects()
        )
        assert len(objs) == 1

    def test_transform_modifies_objects(self):
        records = [{"value": "3.3.3.3"}]
        def add_tag(obj):
            obj.x_tagged = True
            return obj
        objs = list(
            IngestPipeline()
            .read_from(self._simple_reader(records))
            .map_with(self._simple_mapper())
            .transform(add_tag)
            .iter_objects()
        )
        assert objs[0].x_tagged is True

    def test_dedup_skips_duplicates(self):
        records = [{"value": "5.5.5.5"}, {"value": "5.5.5.5"}]
        result = (
            IngestPipeline()
            .read_from(self._simple_reader(records))
            .map_with(self._simple_mapper())
            .deduplicate(key_fields=["name"])
            .run()
        )
        assert result.skipped_duplicates == 1
        assert result.mapped_objects == 2

    def test_write_to_calls_save(self):
        records = [{"value": "9.9.9.9"}]
        mock_client = MagicMock()
        mock_client.client = MagicMock()

        class SaveMapper(RecordMapper):
            def map(self, record):
                ind = Indicator(client=mock_client, name=record["value"],
                                pattern="[ipv4-addr:value = '9.9.9.9']",
                                pattern_type="stix")
                ind.save = MagicMock()
                yield ind

        result = (
            IngestPipeline()
            .read_from(self._simple_reader(records))
            .map_with(SaveMapper())
            .write_to(mock_client)
            .run()
        )
        assert result.written_objects == 1

    def test_mapper_exception_recorded_as_error(self):
        class BrokenMapper(RecordMapper):
            def map(self, record):
                raise ValueError("boom")
                yield  # make it a generator

        result = (
            IngestPipeline()
            .read_from(self._simple_reader([{"x": 1}]))
            .map_with(BrokenMapper())
            .run()
        )
        assert len(result.errors) == 1
        assert "boom" in result.errors[0]


# ===========================================================================
# PlainTextReader
# ===========================================================================

class TestPlainTextReader:

    def test_classifies_ipv4(self):
        recs = _records(PlainTextReader("192.168.1.1", from_string=True))
        assert len(recs) == 1
        assert recs[0]["type"] == "ip"
        assert recs[0]["value"] == "192.168.1.1"

    def test_classifies_domain(self):
        recs = _records(PlainTextReader("evil.example.com", from_string=True))
        assert recs[0]["type"] == "domain"

    def test_classifies_url(self):
        recs = _records(PlainTextReader("https://evil.com/path", from_string=True))
        assert recs[0]["type"] == "url"

    def test_classifies_md5(self):
        recs = _records(PlainTextReader("d41d8cd98f00b204e9800998ecf8427e", from_string=True))
        assert recs[0]["type"] == "md5"

    def test_classifies_sha256(self):
        h = "a" * 64
        recs = _records(PlainTextReader(h, from_string=True))
        assert recs[0]["type"] == "sha256"

    def test_classifies_email(self):
        recs = _records(PlainTextReader("bad@evil.com", from_string=True))
        assert recs[0]["type"] == "email"

    def test_skips_comments(self):
        text = "# This is a comment\n1.2.3.4"
        recs = _records(PlainTextReader(text, from_string=True))
        assert len(recs) == 1

    def test_skips_empty_lines(self):
        text = "\n\n1.2.3.4\n\n"
        recs = _records(PlainTextReader(text, from_string=True))
        assert len(recs) == 1

    def test_defangs_hxxp(self):
        recs = _records(PlainTextReader("hxxps://evil.com/page", from_string=True))
        assert recs[0]["value"].startswith("https://")

    def test_defangs_dotted(self):
        recs = _records(PlainTextReader("192[.]168[.]1[.]1", from_string=True))
        assert recs[0]["value"] == "192.168.1.1"

    def test_skip_unknown_default(self):
        recs = _records(PlainTextReader("not_an_ioc_xyz", from_string=True))
        assert len(recs) == 0

    def test_keep_unknown_when_disabled(self):
        recs = _records(PlainTextReader("not_an_ioc_xyz", from_string=True, skip_unknown=False))
        assert len(recs) == 1
        assert recs[0]["type"] == "unknown"

    def test_reads_file(self, tmp_path):
        f = tmp_path / "iocs.txt"
        f.write_text("1.2.3.4\nevil.com\n")
        recs = _records(PlainTextReader(str(f)))
        assert len(recs) == 2

    def test_multiline(self):
        text = "1.1.1.1\n2.2.2.2\n3.3.3.3"
        recs = _records(PlainTextReader(text, from_string=True))
        assert len(recs) == 3


# ===========================================================================
# CSVReader
# ===========================================================================

class TestCSVReader:

    def test_basic_csv(self, tmp_path):
        f = tmp_path / "iocs.csv"
        f.write_text("value,type,confidence\n1.2.3.4,ip,90\nevil.com,domain,70\n")
        recs = _records(CSVReader(str(f)))
        assert len(recs) == 2
        assert recs[0]["value"] == "1.2.3.4"
        assert recs[0]["type"] == "ip"

    def test_field_map_renames_columns(self, tmp_path):
        f = tmp_path / "iocs.csv"
        f.write_text("indicator,confidence_score\n5.5.5.5,85\n")
        recs = _records(CSVReader(str(f), value_col="indicator",
                                  field_map={"confidence_score": "confidence"}))
        assert "confidence" in recs[0]
        assert recs[0]["confidence"] == "85"

    def test_tsv_delimiter(self, tmp_path):
        f = tmp_path / "iocs.tsv"
        f.write_text("value\ttype\n6.6.6.6\tip\n")
        recs = _records(CSVReader(str(f), delimiter="\t"))
        assert recs[0]["value"] == "6.6.6.6"

    def test_skips_empty_value_rows(self, tmp_path):
        f = tmp_path / "iocs.csv"
        f.write_text("value,type\n,domain\n7.7.7.7,ip\n")
        recs = _records(CSVReader(str(f)))
        assert len(recs) == 1

    def test_auto_classifies_when_no_type_col(self, tmp_path):
        f = tmp_path / "iocs.csv"
        f.write_text("ioc\nevil.org\n")
        recs = _records(CSVReader(str(f), value_col="ioc"))
        assert recs[0]["type"] == "domain"


# ===========================================================================
# JSONReader
# ===========================================================================

class TestJSONReader:

    def test_array_of_objects(self, tmp_path):
        data = [{"value": "1.1.1.1"}, {"value": "2.2.2.2"}]
        f = tmp_path / "data.json"
        f.write_text(json.dumps(data))
        recs = _records(JSONReader(str(f)))
        assert len(recs) == 2

    def test_object_with_key(self, tmp_path):
        data = {"indicators": [{"value": "3.3.3.3"}]}
        f = tmp_path / "data.json"
        f.write_text(json.dumps(data))
        recs = _records(JSONReader(str(f), records_key="indicators"))
        assert len(recs) == 1
        assert recs[0]["value"] == "3.3.3.3"

    def test_from_string(self):
        raw = json.dumps([{"a": 1}, {"a": 2}])
        recs = _records(JSONReader(raw, from_string=True))
        assert len(recs) == 2

    def test_single_object_wrapped(self, tmp_path):
        data = {"value": "solo"}
        f = tmp_path / "data.json"
        f.write_text(json.dumps(data))
        recs = _records(JSONReader(str(f)))
        assert recs[0]["value"] == "solo"

    def test_index_field_added(self, tmp_path):
        f = tmp_path / "data.json"
        f.write_text(json.dumps([{"x": 1}]))
        recs = _records(JSONReader(str(f)))
        assert recs[0]["_index"] == 0


# ===========================================================================
# JSONLReader
# ===========================================================================

class TestJSONLReader:

    def test_valid_jsonl(self, tmp_path):
        f = tmp_path / "data.jsonl"
        f.write_text('{"a": 1}\n{"a": 2}\n{"a": 3}\n')
        recs = _records(JSONLReader(str(f)))
        assert len(recs) == 3

    def test_skips_blank_lines(self, tmp_path):
        f = tmp_path / "data.jsonl"
        f.write_text('{"a": 1}\n\n{"a": 2}\n')
        recs = _records(JSONLReader(str(f)))
        assert len(recs) == 2

    def test_skips_parse_errors(self, tmp_path):
        f = tmp_path / "data.jsonl"
        f.write_text('{"a": 1}\nNOT JSON\n{"a": 3}\n')
        recs = _records(JSONLReader(str(f)))
        assert len(recs) == 2

    def test_adds_line_number(self, tmp_path):
        f = tmp_path / "data.jsonl"
        f.write_text('{"a": 1}\n{"a": 2}\n')
        recs = _records(JSONLReader(str(f)))
        assert recs[0]["_line"] == 1
        assert recs[1]["_line"] == 2


# ===========================================================================
# STIXBundleReader
# ===========================================================================

class TestSTIXBundleReader:

    def _bundle(self, objects):
        return json.dumps({
            "type": "bundle",
            "id": "bundle--test",
            "spec_version": "2.1",
            "objects": objects,
        })

    def test_yields_all_objects(self):
        raw = self._bundle([
            {"type": "indicator", "id": "indicator--1"},
            {"type": "malware",   "id": "malware--1"},
        ])
        recs = _records(STIXBundleReader(raw, from_string=True))
        assert len(recs) == 2

    def test_type_filter(self):
        raw = self._bundle([
            {"type": "indicator", "id": "indicator--1"},
            {"type": "malware",   "id": "malware--1"},
        ])
        recs = _records(STIXBundleReader(raw, from_string=True, stix_types=["indicator"]))
        assert len(recs) == 1
        assert recs[0]["type"] == "indicator"

    def test_skips_bundle_type(self):
        # Top-level bundle object should not be yielded
        raw = json.dumps([{"type": "bundle"}, {"type": "indicator", "id": "i--1"}])
        recs = _records(STIXBundleReader(raw, from_string=True))
        assert all(r["type"] != "bundle" for r in recs)

    def test_reads_file(self, tmp_path):
        f = tmp_path / "bundle.json"
        f.write_text(self._bundle([{"type": "indicator", "id": "indicator--x"}]))
        recs = _records(STIXBundleReader(str(f)))
        assert len(recs) == 1


# ===========================================================================
# SQLReader
# ===========================================================================

class TestSQLReader:

    def test_basic_sqlite(self):
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE iocs (value TEXT, type TEXT, confidence INT)")
        conn.executemany("INSERT INTO iocs VALUES (?,?,?)", [
            ("1.1.1.1", "ip", 90),
            ("evil.com", "domain", 70),
        ])
        conn.commit()

        recs = _records(SQLReader(conn, "SELECT value, type, confidence FROM iocs"))
        assert len(recs) == 2
        assert recs[0]["value"] == "1.1.1.1"
        assert recs[0]["confidence"] == 90

    def test_column_map_renames(self):
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE t (ioc TEXT, score INT)")
        conn.execute("INSERT INTO t VALUES ('5.5.5.5', 80)")
        conn.commit()

        recs = _records(SQLReader(conn, "SELECT ioc, score FROM t",
                                  column_map={"ioc": "value", "score": "confidence"}))
        assert recs[0]["value"] == "5.5.5.5"
        assert recs[0]["confidence"] == 80

    def test_params_binding(self):
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE t (value TEXT, active INT)")
        conn.executemany("INSERT INTO t VALUES (?,?)", [("a.com", 1), ("b.com", 0)])
        conn.commit()

        recs = _records(SQLReader(conn, "SELECT value FROM t WHERE active = ?", params=(1,)))
        assert len(recs) == 1
        assert recs[0]["value"] == "a.com"

    def test_batches_correctly(self):
        conn = sqlite3.connect(":memory:")
        conn.execute("CREATE TABLE t (n INT)")
        conn.executemany("INSERT INTO t VALUES (?)", [(i,) for i in range(50)])
        conn.commit()

        reader = SQLReader(conn, "SELECT n FROM t", batch_size=10)
        recs = _records(reader)
        assert len(recs) == 50


# ===========================================================================
# MISPReader
# ===========================================================================

class TestMISPReader:

    def _event(self, attributes):
        return [{
            "Event": {
                "id": "123",
                "uuid": "evt-uuid",
                "info": "Test Event",
                "threat_level_id": "2",
                "Attribute": attributes,
                "Tag": [{"Tag": {"name": "tlp:amber"}}],
                "Orgc": {"name": "TestOrg"},
            }
        }]

    def test_yields_attributes(self):
        events = self._event([
            {"type": "ip-dst", "value": "8.8.8.8", "uuid": "a1", "to_ids": True,
             "comment": "", "Tag": [], "category": "Network"},
        ])
        reader = MISPReader(events)
        recs = _records(reader)
        assert len(recs) == 1
        assert recs[0]["value"] == "8.8.8.8"

    def test_event_meta_propagated(self):
        events = self._event([
            {"type": "domain", "value": "evil.com", "uuid": "a2", "to_ids": False,
             "comment": "noted", "Tag": [], "category": "Network"},
        ])
        recs = _records(MISPReader(events))
        assert recs[0]["event_id"] == "123"
        assert recs[0]["org"] == "TestOrg"

    def test_attribute_type_filter(self):
        events = self._event([
            {"type": "ip-dst",  "value": "1.1.1.1", "uuid": "a", "to_ids": True, "comment": "", "Tag": [], "category": "N"},
            {"type": "md5",     "value": "d41d8cd98f00b204e9800998ecf8427e", "uuid": "b", "to_ids": True, "comment": "", "Tag": [], "category": "N"},
        ])
        recs = _records(MISPReader(events, attribute_types=["ip-dst"]))
        assert len(recs) == 1
        assert recs[0]["type"] == "ip-dst"


# ===========================================================================
# SyslogReader
# ===========================================================================

class TestSyslogReader:

    def test_syslog_parse(self, tmp_path):
        f = tmp_path / "syslog.log"
        f.write_text("Mar 15 12:00:00 myhost sshd[1234]: Failed password for root\n")
        recs = _records(SyslogReader(str(f), fmt="syslog"))
        assert len(recs) == 1
        assert recs[0]["_format"] == "syslog"

    def test_cef_parse(self, tmp_path):
        cef = "CEF:0|Vendor|Product|1.0|100|Test Event|5|src=1.2.3.4 dst=5.6.7.8 dhost=evil.com\n"
        f = tmp_path / "cef.log"
        f.write_text(cef)
        recs = _records(SyslogReader(str(f), fmt="cef"))
        assert recs[0]["src"] == "1.2.3.4"
        assert recs[0]["dst"] == "5.6.7.8"
        assert recs[0]["dhost"] == "evil.com"

    def test_auto_detect_cef(self, tmp_path):
        f = tmp_path / "mixed.log"
        f.write_text("CEF:0|V|P|1|1|E|5|src=1.1.1.1\nMar 15 syslog message\n")
        recs = _records(SyslogReader(str(f), fmt="auto"))
        assert recs[0]["_format"] == "cef"
        assert recs[1]["_format"] == "syslog"

    def test_leef_parse(self, tmp_path):
        leef = "LEEF:2.0|IBM|QRadar|7.3|1234|src=2.2.2.2\tdst=3.3.3.3\n"
        f = tmp_path / "leef.log"
        f.write_text(leef)
        recs = _records(SyslogReader(str(f), fmt="leef"))
        assert recs[0]["_format"] == "leef"


# ===========================================================================
# OpenIOCReader
# ===========================================================================

class TestOpenIOCReader:

    def _write_ioc(self, tmp_path, search, content):
        xml = textwrap.dedent(f"""<?xml version="1.0" encoding="utf-8"?>
        <ioc id="test-ioc-id" xmlns="http://schemas.mandiant.com/2010/ioc">
          <short_description>Test IOC</short_description>
          <definition>
            <Indicator operator="OR">
              <IndicatorItem id="item-1" condition="is">
                <Context document="FileItem" search="{search}"/>
                <Content type="string">{content}</Content>
              </IndicatorItem>
            </Indicator>
          </definition>
        </ioc>""")
        f = tmp_path / "test.ioc"
        f.write_text(xml)
        return f

    def test_parses_single_file(self, tmp_path):
        f = self._write_ioc(tmp_path, "FileItem/Md5sum", "d41d8cd98f00b204e9800998ecf8427e")
        recs = _records(OpenIOCReader(str(f)))
        assert len(recs) == 1
        assert recs[0]["content"] == "d41d8cd98f00b204e9800998ecf8427e"
        assert recs[0]["context_search"] == "FileItem/Md5sum"

    def test_parses_directory(self, tmp_path):
        self._write_ioc(tmp_path, "Network/DNS", "evil.com")
        self._write_ioc(tmp_path, "FileItem/Sha256sum", "a" * 64)
        # rename so two exist
        iocs = list(tmp_path.glob("*.ioc"))
        iocs[0].rename(tmp_path / "a.ioc")
        recs = _records(OpenIOCReader(str(tmp_path)))
        assert len(recs) >= 1


# ===========================================================================
# FlatIOCMapper
# ===========================================================================

class TestFlatIOCMapper:

    def test_maps_ip(self):
        objs = _map(FlatIOCMapper(), {"value": "1.2.3.4", "type": "ip"})
        assert len(objs) == 1
        assert isinstance(objs[0], Indicator)
        assert "ipv4-addr" in objs[0].pattern

    def test_maps_domain(self):
        objs = _map(FlatIOCMapper(), {"value": "evil.com", "type": "domain"})
        assert "domain-name" in objs[0].pattern

    def test_maps_sha256(self):
        objs = _map(FlatIOCMapper(), {"value": "a" * 64, "type": "sha256"})
        assert "SHA-256" in objs[0].pattern

    def test_maps_url(self):
        objs = _map(FlatIOCMapper(), {"value": "https://evil.com/x", "type": "url"})
        assert "url" in objs[0].pattern

    def test_empty_value_yields_nothing(self):
        assert _map(FlatIOCMapper(), {"value": "", "type": "ip"}) == []

    def test_unknown_type_yields_nothing(self):
        assert _map(FlatIOCMapper(), {"value": "x", "type": "asn"}) == []

    def test_tlp_applied(self):
        objs = _map(FlatIOCMapper(tlp_marking="red"), {"value": "1.1.1.1", "type": "ip"})
        assert objs[0].x_tlp == "red"

    def test_confidence_applied(self):
        objs = _map(FlatIOCMapper(confidence=80), {"value": "1.1.1.1", "type": "ip"})
        assert objs[0].confidence == 80

    def test_custom_value_field(self):
        objs = _map(FlatIOCMapper(value_field="ioc"),
                    {"ioc": "5.5.5.5", "type": "ip"})
        assert objs[0].name == "5.5.5.5"

    def test_extra_stix_fields_applied(self):
        objs = _map(FlatIOCMapper(extra_stix_fields={"x_source": "test"}),
                    {"value": "1.1.1.1", "type": "ip"})
        assert objs[0].x_source == "test"

    def test_carries_through_tags(self):
        objs = _map(FlatIOCMapper(), {"value": "1.1.1.1", "type": "ip", "tags": ["apt"]})
        assert objs[0].x_tags == ["apt"]


# ===========================================================================
# STIXPassthroughMapper
# ===========================================================================

class TestSTIXPassthroughMapper:

    def test_maps_indicator(self):
        rec = {"type": "indicator", "id": "indicator--abc",
               "name": "Test", "pattern": "[ipv4-addr:value = '1.2.3.4']",
               "pattern_type": "stix", "spec_version": "2.1",
               "created": "2024-01-01T00:00:00Z", "modified": "2024-01-01T00:00:00Z"}
        objs = _map(STIXPassthroughMapper(), rec)
        assert isinstance(objs[0], Indicator)
        assert objs[0].id == "indicator--abc"

    def test_maps_malware(self):
        rec = {"type": "malware", "id": "malware--xyz", "spec_version": "2.1",
               "created": "", "modified": "", "name": "BadMalware"}
        objs = _map(STIXPassthroughMapper(), rec)
        assert isinstance(objs[0], Malware)

    def test_type_filter_drops_others(self):
        rec = {"type": "malware", "id": "malware--xyz", "spec_version": "2.1",
               "created": "", "modified": ""}
        assert _map(STIXPassthroughMapper(type_filter=["indicator"]), rec) == []

    def test_tlp_injected(self):
        rec = {"type": "indicator", "id": "indicator--1", "spec_version": "2.1",
               "created": "", "modified": "", "name": "x",
               "pattern": "[ipv4-addr:value='1.1.1.1']", "pattern_type": "stix"}
        objs = _map(STIXPassthroughMapper(tlp_marking="green"), rec)
        assert objs[0].x_tlp == "green"


# ===========================================================================
# MISPAttributeMapper
# ===========================================================================

class TestMISPAttributeMapper:

    def test_maps_ip_dst(self):
        rec = {"type": "ip-dst", "value": "10.0.0.1", "uuid": "u1",
               "to_ids": True, "comment": "", "tags": [], "category": "Network"}
        objs = _map(MISPAttributeMapper(), rec)
        assert isinstance(objs[0], Indicator)
        assert "ipv4-addr" in objs[0].pattern

    def test_maps_vulnerability(self):
        rec = {"type": "vulnerability", "value": "CVE-2024-1234", "uuid": "u2",
               "to_ids": False, "comment": "", "tags": [], "category": "External"}
        objs = _map(MISPAttributeMapper(), rec)
        assert isinstance(objs[0], Vulnerability)
        assert objs[0].name == "CVE-2024-1234"

    def test_require_to_ids_filters(self):
        rec = {"type": "ip-dst", "value": "10.0.0.2", "uuid": "u3",
               "to_ids": False, "comment": "", "tags": [], "category": "N"}
        assert _map(MISPAttributeMapper(require_to_ids=True), rec) == []

    def test_unknown_type_skipped(self):
        rec = {"type": "stix2-pattern", "value": "whatever", "uuid": "u4",
               "to_ids": True, "comment": "", "tags": [], "category": "N"}
        assert _map(MISPAttributeMapper(), rec) == []

    def test_composite_value_split(self):
        rec = {"type": "ip-dst|port", "value": "192.168.1.1|443", "uuid": "u5",
               "to_ids": True, "comment": "", "tags": [], "category": "N"}
        objs = _map(MISPAttributeMapper(), rec)
        assert "192.168.1.1" in objs[0].pattern
        assert "443" not in objs[0].pattern


# ===========================================================================
# CEFMapper
# ===========================================================================

class TestCEFMapper:

    def test_extracts_src(self):
        rec = {"src": "1.2.3.4", "n": "Test", "severity": "5",
               "device_product": "FW", "_format": "cef"}
        objs = _map(CEFMapper(), rec)
        assert any("1.2.3.4" in o.pattern for o in objs)

    def test_extracts_requesturl(self):
        rec = {"requestUrl": "https://evil.com/", "n": "", "severity": "",
               "device_product": "", "_format": "cef"}
        objs = _map(CEFMapper(), rec)
        assert any("url" in o.pattern for o in objs)

    def test_skips_empty_fields(self):
        rec = {"src": "", "dst": "", "_format": "cef"}
        assert _map(CEFMapper(), rec) == []


# ===========================================================================
# SQLRowMapper
# ===========================================================================

class TestSQLRowMapper:

    def test_maps_to_indicator(self):
        rec = {"ioc": "4.4.4.4", "ioc_type": "ip", "notes": "bad IP"}
        objs = _map(SQLRowMapper(value_col="ioc", type_col="ioc_type",
                                 description_col="notes"), rec)
        assert isinstance(objs[0], Indicator)
        assert "4.4.4.4" in objs[0].pattern

    def test_empty_value_yields_nothing(self):
        assert _map(SQLRowMapper(), {"value": ""}) == []

    def test_extra_col_map(self):
        rec = {"value": "5.5.5.5", "type": "ip", "priority": "high"}
        objs = _map(SQLRowMapper(extra_col_map={"priority": "x_priority"}), rec)
        assert objs[0].x_priority == "high"


# ===========================================================================
# RSSEntryMapper
# ===========================================================================

class TestRSSEntryMapper:

    def test_extracts_cve(self):
        rec = {"title": "CVE-2024-99999 Vulnerability", "summary": "",
               "link": "https://example.com", "published": "", "_feed_title": "NVD"}
        objs = _map(RSSEntryMapper(), rec)
        vulns = [o for o in objs if isinstance(o, Vulnerability)]
        assert any("CVE-2024-99999" in v.name for v in vulns)

    def test_extracts_ip_from_summary(self):
        rec = {"title": "Alert", "summary": "Observed traffic from 1.2.3.4",
               "link": "", "published": "", "_feed_title": ""}
        objs = _map(RSSEntryMapper(), rec)
        inds = [o for o in objs if isinstance(o, Indicator)]
        assert any("1.2.3.4" in i.pattern for i in inds)

    def test_extracts_url(self):
        rec = {"title": "", "summary": "Download: https://malware.example.com/payload",
               "link": "", "published": "", "_feed_title": ""}
        objs = _map(RSSEntryMapper(), rec)
        assert any("url" in o.pattern for o in objs if isinstance(o, Indicator))

    def test_no_extract_when_disabled(self):
        rec = {"title": "1.2.3.4", "summary": "https://evil.com",
               "link": "", "published": "", "_feed_title": ""}
        objs = _map(RSSEntryMapper(extract_iocs=False), rec)
        assert all(isinstance(o, Vulnerability) for o in objs)  # only CVEs


# ===========================================================================
# EmailIOCMapper
# ===========================================================================

class TestEmailIOCMapper:

    def _email_record(self):
        return {
            "subject": "Phish",
            "from": "bad@evil.com",
            "to": "victim@example.com",
            "date": "",
            "message_id": "<msg1>",
            "body_text": "Click here",
            "body_html": "",
            "attachments": [],
            "headers": {},
            "urls": ["https://evil.com/payload"],
            "ips": ["10.10.10.10"],
            "domains": ["evil.com"],
            "hashes": ["d41d8cd98f00b204e9800998ecf8427e"],
        }

    def test_extracts_ips(self):
        objs = _map(EmailIOCMapper(ioc_types=["ips"]), self._email_record())
        assert any("10.10.10.10" in o.pattern for o in objs)

    def test_extracts_domains(self):
        objs = _map(EmailIOCMapper(ioc_types=["domains"]), self._email_record())
        assert any("evil.com" in o.pattern for o in objs)

    def test_extracts_urls(self):
        objs = _map(EmailIOCMapper(ioc_types=["urls"]), self._email_record())
        assert any("url" in o.pattern for o in objs)

    def test_extracts_hashes(self):
        objs = _map(EmailIOCMapper(ioc_types=["hashes"]), self._email_record())
        assert any("MD5" in o.pattern for o in objs)

    def test_ioc_types_filter(self):
        objs = _map(EmailIOCMapper(ioc_types=["ips"]), self._email_record())
        # Only IPs — no domains/URLs
        assert all("ipv4-addr" in o.pattern for o in objs)


# ===========================================================================
# OpenIOCMapper
# ===========================================================================

class TestOpenIOCMapper:

    def test_maps_md5(self):
        rec = {"ioc_name": "Test", "ioc_id": "id1", "item_id": "i1",
               "condition": "is", "context_document": "FileItem",
               "context_search": "FileItem/Md5sum",
               "content_type": "string",
               "content": "d41d8cd98f00b204e9800998ecf8427e"}
        objs = _map(OpenIOCMapper(), rec)
        assert "MD5" in objs[0].pattern

    def test_maps_dns(self):
        rec = {"ioc_name": "DNS", "ioc_id": "id2", "item_id": "i2",
               "condition": "is", "context_document": "Network",
               "context_search": "Network/DNS",
               "content_type": "string",
               "content": "evil.com"}
        objs = _map(OpenIOCMapper(), rec)
        assert "domain-name" in objs[0].pattern

    def test_unknown_search_yields_nothing(self):
        rec = {"ioc_name": "Unknown", "ioc_id": "id3", "item_id": "i3",
               "condition": "is", "context_document": "Custom",
               "context_search": "Custom/Field",
               "content_type": "string", "content": "somevalue"}
        assert _map(OpenIOCMapper(), rec) == []

    def test_empty_content_yields_nothing(self):
        rec = {"ioc_name": "N", "ioc_id": "id4", "item_id": "i4",
               "condition": "is", "context_document": "FileItem",
               "context_search": "FileItem/Md5sum",
               "content_type": "string", "content": ""}
        assert _map(OpenIOCMapper(), rec) == []


# ===========================================================================
# NVDCVEMapper
# ===========================================================================

class TestNVDCVEMapper:

    def _nvd1_record(self, cve_id, score):
        return {
            "cve": {
                "CVE_data_meta": {"ID": cve_id},
                "description": {"description_data": [
                    {"lang": "en", "value": "A test vulnerability."}
                ]},
            },
            "impact": {
                "baseMetricV3": {
                    "cvssV3": {"baseScore": score}
                }
            },
            "publishedDate": "2024-01-15T00:00Z",
        }

    def _nvd2_record(self, cve_id, score):
        return {
            "cve": {
                "id": cve_id,
                "descriptions": [{"lang": "en", "value": "A test vuln."}],
                "metrics": {
                    "cvssMetricV31": [{"cvssData": {"baseScore": score}}]
                },
                "published": "2024-01-15T00:00:00",
            }
        }

    def test_nvd_1x_format(self):
        objs = _map(NVDCVEMapper(), self._nvd1_record("CVE-2024-0001", 7.5))
        assert isinstance(objs[0], Vulnerability)
        assert objs[0].name == "CVE-2024-0001"

    def test_nvd_2x_format(self):
        objs = _map(NVDCVEMapper(), self._nvd2_record("CVE-2024-9999", 9.8))
        assert isinstance(objs[0], Vulnerability)
        assert objs[0].name == "CVE-2024-9999"
        assert objs[0].x_cvss_score == 9.8

    def test_no_cve_id_yields_nothing(self):
        assert _map(NVDCVEMapper(), {"cve": {}}) == []

    def test_description_extracted(self):
        objs = _map(NVDCVEMapper(), self._nvd2_record("CVE-2024-1111", 5.0))
        assert "test vuln" in objs[0].description
