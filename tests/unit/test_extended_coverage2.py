"""
tests/unit/test_extended_coverage2.py
=======================================
Extended coverage tests for:
- gnat/reports/renderers.py
- gnat/reports/synthesizer.py
- gnat/reports/generator.py
- gnat/connectors/zeek/client.py
- gnat/connectors/suricata/__init__.py
- gnat/connectors/rapid7/client.py
- gnat/connectors/elastic/es_search.py
- gnat/context/workspace.py
"""

from __future__ import annotations

import configparser
import json
import os
import tempfile
import unittest
from datetime import datetime, timezone
from unittest.mock import MagicMock, mock_open, patch

# ===========================================================================
# Reports – Renderers
# ===========================================================================


class TestMarkdownRenderer(unittest.TestCase):
    def _make_doc(self):
        from gnat.reports.base import ReportConfig, ReportDocument, ReportSection

        cfg = ReportConfig(report_type="daily", workspaces=["ws"])
        doc = ReportDocument(
            title="Test Report",
            report_type="daily",
            period_start=datetime(2024, 1, 1, tzinfo=timezone.utc),
            period_end=datetime(2024, 1, 2, tzinfo=timezone.utc),
            config=cfg,
        )
        sec = ReportSection(
            title="Exec Summary",
            data={},
            narrative="Some narrative.",
            section_type="summary",
            order=1,
        )
        doc.add_section(sec)
        return doc

    def test_render_string_contains_title(self):
        from gnat.reports.renderers import MarkdownRenderer

        doc = self._make_doc()
        md = MarkdownRenderer().render_string(doc)
        self.assertIn("# Test Report", md)
        self.assertIn("Exec Summary", md)

    def test_render_string_contains_period(self):
        from gnat.reports.renderers import MarkdownRenderer

        doc = self._make_doc()
        md = MarkdownRenderer().render_string(doc)
        self.assertIn("2024-01-01", md)

    def test_render_string_narrative(self):
        from gnat.reports.renderers import MarkdownRenderer

        doc = self._make_doc()
        md = MarkdownRenderer().render_string(doc)
        self.assertIn("Some narrative.", md)

    def test_render_writes_file(self):
        from gnat.reports.renderers import MarkdownRenderer

        doc = self._make_doc()
        with tempfile.NamedTemporaryFile(suffix=".md", delete=False, dir=".") as f:
            path = f.name
        try:
            result = MarkdownRenderer().render(doc, path)
            self.assertEqual(result, path)
            self.assertTrue(os.path.getsize(path) > 0)
        finally:
            os.unlink(path)

    def test_render_data_top_actors(self):
        from gnat.reports.base import ReportConfig, ReportDocument, ReportSection
        from gnat.reports.renderers import MarkdownRenderer

        cfg = ReportConfig(report_type="daily", workspaces=["ws"])
        doc = ReportDocument(
            title="T",
            report_type="daily",
            period_start=datetime(2024, 1, 1, tzinfo=timezone.utc),
            period_end=datetime(2024, 1, 2, tzinfo=timezone.utc),
            config=cfg,
        )
        sec = ReportSection(
            title="Actors",
            data={"top_actors": [{"name": "APT1", "motivation": ["espionage"]}]},
            section_type="narrative",
            order=1,
        )
        doc.add_section(sec)
        md = MarkdownRenderer().render_string(doc)
        self.assertIn("APT1", md)

    def test_render_data_critical_vulns(self):
        from gnat.reports.base import ReportConfig, ReportDocument, ReportSection
        from gnat.reports.renderers import MarkdownRenderer

        cfg = ReportConfig(report_type="daily", workspaces=["ws"])
        doc = ReportDocument(
            title="T",
            report_type="daily",
            period_start=datetime(2024, 1, 1, tzinfo=timezone.utc),
            period_end=datetime(2024, 1, 2, tzinfo=timezone.utc),
            config=cfg,
        )
        sec = ReportSection(
            title="Vulns",
            data={"critical_vulns": [{"cve_id": "CVE-2024-1234", "cvss": 9.8, "exploited": True}]},
            section_type="narrative",
            order=1,
        )
        doc.add_section(sec)
        md = MarkdownRenderer().render_string(doc)
        self.assertIn("CVE-2024-1234", md)

    def test_render_data_ioc_by_type(self):
        from gnat.reports.base import ReportConfig, ReportDocument, ReportSection
        from gnat.reports.renderers import MarkdownRenderer

        cfg = ReportConfig(report_type="daily", workspaces=["ws"])
        doc = ReportDocument(
            title="T",
            report_type="daily",
            period_start=datetime(2024, 1, 1, tzinfo=timezone.utc),
            period_end=datetime(2024, 1, 2, tzinfo=timezone.utc),
            config=cfg,
        )
        sec = ReportSection(
            title="IOCs",
            data={"ioc_by_type": {"domain": 5, "ip": 3}},
            section_type="narrative",
            order=1,
        )
        doc.add_section(sec)
        md = MarkdownRenderer().render_string(doc)
        self.assertIn("domain", md)

    def test_render_with_sectors(self):
        from gnat.reports.base import ReportConfig, ReportDocument
        from gnat.reports.renderers import MarkdownRenderer

        cfg = ReportConfig(report_type="daily", workspaces=["ws"], sectors=["Healthcare"])
        doc = ReportDocument(
            title="T",
            report_type="daily",
            period_start=datetime(2024, 1, 1, tzinfo=timezone.utc),
            period_end=datetime(2024, 1, 2, tzinfo=timezone.utc),
            config=cfg,
        )
        md = MarkdownRenderer().render_string(doc)
        self.assertIn("Healthcare", md)


class TestHTMLRenderer(unittest.TestCase):
    def _make_doc(self, with_sector=False):
        from gnat.reports.base import ReportConfig, ReportDocument, ReportSection

        sectors = ["Finance"] if with_sector else []
        cfg = ReportConfig(report_type="daily", workspaces=["ws"], sectors=sectors)
        doc = ReportDocument(
            title="HTML Report",
            report_type="daily",
            period_start=datetime(2024, 1, 1, tzinfo=timezone.utc),
            period_end=datetime(2024, 1, 2, tzinfo=timezone.utc),
            config=cfg,
        )
        sec = ReportSection(
            title="Executive Summary",
            data={"total_new": 42, "total_objects": 100},
            narrative="Key findings here.\n\nMore details.",
            section_type="summary",
            order=1,
        )
        doc.add_section(sec)
        return doc

    def test_html_contains_doctype(self):
        from gnat.reports.renderers import HTMLRenderer

        html = HTMLRenderer()._build(self._make_doc())
        self.assertIn("<!DOCTYPE html>", html)

    def test_html_contains_title(self):
        from gnat.reports.renderers import HTMLRenderer

        html = HTMLRenderer()._build(self._make_doc())
        self.assertIn("HTML Report", html)

    def test_html_contains_section_title(self):
        from gnat.reports.renderers import HTMLRenderer

        html = HTMLRenderer()._build(self._make_doc())
        self.assertIn("Executive Summary", html)

    def test_html_contains_narrative(self):
        from gnat.reports.renderers import HTMLRenderer

        html = HTMLRenderer()._build(self._make_doc())
        self.assertIn("Key findings here.", html)

    def test_html_stat_cards(self):
        from gnat.reports.renderers import HTMLRenderer

        html = HTMLRenderer()._build(self._make_doc())
        self.assertIn("stat-card", html)
        self.assertIn("42", html)

    def test_html_with_sector_badges(self):
        from gnat.reports.renderers import HTMLRenderer

        html = HTMLRenderer()._build(self._make_doc(with_sector=True))
        self.assertIn("Finance", html)
        self.assertIn("badge", html)

    def test_html_render_writes_file(self):
        from gnat.reports.renderers import HTMLRenderer

        doc = self._make_doc()
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False, dir=".") as f:
            path = f.name
        try:
            result = HTMLRenderer().render(doc, path)
            self.assertEqual(result, path)
            with open(path) as fh:
                content = fh.read()
            self.assertIn("<!DOCTYPE html>", content)
        finally:
            os.unlink(path)

    def test_html_table_rendering(self):
        from gnat.reports.base import ReportConfig, ReportDocument, ReportSection
        from gnat.reports.renderers import HTMLRenderer

        cfg = ReportConfig(report_type="daily", workspaces=["ws"])
        doc = ReportDocument(
            title="T",
            report_type="daily",
            period_start=datetime(2024, 1, 1, tzinfo=timezone.utc),
            period_end=datetime(2024, 1, 2, tzinfo=timezone.utc),
            config=cfg,
        )
        sec = ReportSection(
            title="Actors",
            data={"top_actors": [{"name": "APT29", "motivation": ["espionage"]}]},
            section_type="narrative",
            order=1,
        )
        doc.add_section(sec)
        html = HTMLRenderer()._build(doc)
        self.assertIn("APT29", html)
        self.assertIn("<table>", html)

    def test_html_escapes_special_chars(self):
        from gnat.reports.renderers import _esc

        self.assertEqual(_esc("<script>"), "&lt;script&gt;")
        self.assertEqual(_esc("a & b"), "a &amp; b")
        self.assertEqual(_esc('"quoted"'), "&quot;quoted&quot;")

    def test_html_critical_vulns_table(self):
        from gnat.reports.base import ReportConfig, ReportDocument, ReportSection
        from gnat.reports.renderers import HTMLRenderer

        cfg = ReportConfig(report_type="daily", workspaces=["ws"])
        doc = ReportDocument(
            title="T",
            report_type="daily",
            period_start=datetime(2024, 1, 1, tzinfo=timezone.utc),
            period_end=datetime(2024, 1, 2, tzinfo=timezone.utc),
            config=cfg,
        )
        sec = ReportSection(
            title="Vulns",
            data={"critical_vulns": [{"cve_id": "CVE-2024-9999", "cvss": 9.9, "exploited": True}]},
            section_type="narrative",
            order=1,
        )
        doc.add_section(sec)
        html = HTMLRenderer()._build(doc)
        self.assertIn("CVE-2024-9999", html)

    def test_html_ioc_type_table(self):
        from gnat.reports.base import ReportConfig, ReportDocument, ReportSection
        from gnat.reports.renderers import HTMLRenderer

        cfg = ReportConfig(report_type="daily", workspaces=["ws"])
        doc = ReportDocument(
            title="T",
            report_type="daily",
            period_start=datetime(2024, 1, 1, tzinfo=timezone.utc),
            period_end=datetime(2024, 1, 2, tzinfo=timezone.utc),
            config=cfg,
        )
        sec = ReportSection(
            title="IOCs",
            data={"ioc_by_type": {"url": 7}},
            section_type="narrative",
            order=1,
        )
        doc.add_section(sec)
        html = HTMLRenderer()._build(doc)
        self.assertIn("url", html)

    def test_html_sector_distribution_table(self):
        from gnat.reports.base import ReportConfig, ReportDocument, ReportSection
        from gnat.reports.renderers import HTMLRenderer

        cfg = ReportConfig(report_type="daily", workspaces=["ws"])
        doc = ReportDocument(
            title="T",
            report_type="daily",
            period_start=datetime(2024, 1, 1, tzinfo=timezone.utc),
            period_end=datetime(2024, 1, 2, tzinfo=timezone.utc),
            config=cfg,
        )
        sec = ReportSection(
            title="Sectors",
            data={"sector_distribution": {"Healthcare": 15}},
            section_type="narrative",
            order=1,
        )
        doc.add_section(sec)
        html = HTMLRenderer()._build(doc)
        self.assertIn("Healthcare", html)


# ===========================================================================
# Reports – Synthesizer
# ===========================================================================


class TestReportSynthesizer(unittest.TestCase):
    def _make_agg(self):
        from gnat.reports.aggregator import ReportAggregates

        agg = ReportAggregates()
        agg.new_objects = 10
        agg.updated_objects = 5
        agg.window_days = 1
        agg.critical_vulns = [{"cve_id": "CVE-2024-1", "cvss": 9.8, "exploited": True}]
        agg.exploited_vulns = [{"cve_id": "CVE-2024-1"}]
        agg.top_actors = [{"name": "APT1", "motivation": ["espionage"]}]
        agg.actor_count = 1
        agg.vuln_count = 1
        agg.actor_motivations = {"espionage": 1}
        agg.period_over_period = {}
        agg.sector_distribution = {"Healthcare": 5}
        agg.opportunistic_count = 2
        agg.total_objects = 100
        agg.by_type = {"indicator": 60}
        agg.monthly_counts = {}
        agg.cvss_distribution = {}
        agg.ioc_count = 5
        agg.source_breakdown = {}
        return agg

    def _make_config(self, ai_mode_val="assisted"):
        from gnat.reports.base import AIMode, ReportConfig

        mode = AIMode(ai_mode_val)
        return ReportConfig(report_type="daily", workspaces=["ws"], ai_mode=mode)

    def _make_agent_config(self):
        from gnat.agents.base import AgentConfig

        return AgentConfig(api_key="test-key", model="claude-haiku-3")

    def _synth_with_mock(self, report_type="daily", ai_mode="assisted"):
        from gnat.reports.synthesizer import ReportSynthesizer

        cfg = self._make_config(ai_mode)
        acfg = self._make_agent_config()
        with patch("gnat.agents.base.ClaudeClient") as MockClient:
            instance = MockClient.return_value
            instance.complete.return_value = "AI generated narrative text."
            synth = ReportSynthesizer(cfg, acfg)
            synth._client = instance
            agg = self._make_agg()
            sections = synth.synthesize(agg, report_type=report_type)
        return sections

    def test_synthesize_daily_returns_sections(self):
        sections = self._synth_with_mock("daily")
        self.assertIsInstance(sections, list)
        self.assertGreater(len(sections), 0)

    def test_synthesize_daily_has_exec_summary(self):
        sections = self._synth_with_mock("daily")
        titles = [s.title for s in sections]
        self.assertIn("Executive Summary", titles)

    def test_synthesize_trends_returns_sections(self):
        sections = self._synth_with_mock("trends")
        self.assertIsInstance(sections, list)
        self.assertGreater(len(sections), 0)

    def test_synthesize_trends_has_summary(self):
        sections = self._synth_with_mock("trends")
        titles = [s.title for s in sections]
        self.assertIn("Trends Summary", titles)

    def test_synthesize_yearly_returns_sections(self):
        sections = self._synth_with_mock("yearly")
        self.assertIsInstance(sections, list)
        self.assertGreater(len(sections), 0)

    def test_synthesize_yearly_has_year_in_review(self):
        sections = self._synth_with_mock("yearly")
        titles = [s.title for s in sections]
        self.assertIn("Year in Review", titles)

    def test_synthesize_unknown_type_returns_empty(self):
        sections = self._synth_with_mock("unknown_type")
        self.assertEqual(sections, [])

    def test_calls_made_increments(self):
        from gnat.reports.synthesizer import ReportSynthesizer

        cfg = self._make_config()
        acfg = self._make_agent_config()
        with patch("gnat.agents.base.ClaudeClient"):
            synth = ReportSynthesizer(cfg, acfg)
            synth._client = MagicMock()
            synth._client.complete.return_value = "narrative"
            agg = self._make_agg()
            synth.synthesize(agg, "daily")
            self.assertGreater(synth.calls_made, 0)

    def test_synthesize_full_mode_adds_recommendations(self):
        sections = self._synth_with_mock("daily", ai_mode="full")
        titles = [s.title for s in sections]
        self.assertIn("Recommended Actions", titles)

    def test_synthesize_no_actors_skips_highlights(self):
        from gnat.reports.synthesizer import ReportSynthesizer

        cfg = self._make_config()
        acfg = self._make_agent_config()
        with patch("gnat.agents.base.ClaudeClient"):
            synth = ReportSynthesizer(cfg, acfg)
            synth._client = MagicMock()
            synth._client.complete.return_value = "narrative"
            agg = self._make_agg()
            agg.critical_vulns = []
            agg.exploited_vulns = []
            agg.top_actors = []
            sections = synth.synthesize(agg, "daily")
        titles = [s.title for s in sections]
        self.assertNotIn("Threat Highlights", titles)

    def test_section_data_populated(self):
        sections = self._synth_with_mock("daily")
        exec_section = next((s for s in sections if s.title == "Executive Summary"), None)
        self.assertIsNotNone(exec_section)
        self.assertIn("total_new", exec_section.data)


# ===========================================================================
# Reports – Generator (additional coverage)
# ===========================================================================


class TestReportGeneratorAdditional(unittest.TestCase):
    def _make_manager_with_ws(self):
        from gnat.context import FlatFileStore, GlobalContext, GlobalContextRegistry
        from gnat.context.workspace import WorkspaceManager
        from gnat.orm.indicator import Indicator

        store = FlatFileStore(base_dir="./test_ws_rg")
        reg = GlobalContextRegistry()
        cli = MagicMock()
        cli.target = "tq"
        cli.ping.return_value = True
        cli.client = MagicMock()
        reg.register(GlobalContext("tq", cli))
        reg.set_default("tq")
        manager = WorkspaceManager(reg, store=store)
        ws = manager.create("_ctmsak_library")
        ws.add(
            Indicator(
                name="evil.com",
                pattern="[domain-name:value = 'evil.com']",
                pattern_type="stix",
                confidence=70,
                x_target_sectors=["Healthcare"],
                x_source_platform="threatq",
                created="2024-01-01T00:00:00Z",
                modified="2024-01-01T00:00:00Z",
            ),
            mark_dirty=False,
        )
        return manager

    def test_generator_markdown_output(self):
        from gnat.reports.base import AIMode, ReportConfig
        from gnat.reports.generator import ReportGenerator

        manager = self._make_manager_with_ws()
        cfg = ReportConfig(
            report_type="daily",
            workspaces=["_ctmsak_library"],
            ai_mode=AIMode.NONE,
            formats=["markdown"],
            output_dir="./test_rg_out",
        )
        gen = ReportGenerator(manager, cfg)
        result = gen.run()
        self.assertTrue(result.success)
        import shutil

        shutil.rmtree("./test_ws_rg", ignore_errors=True)
        shutil.rmtree("./test_rg_out", ignore_errors=True)

    def test_generator_html_output(self):
        import shutil

        from gnat.reports.base import AIMode, ReportConfig
        from gnat.reports.generator import ReportGenerator

        manager = self._make_manager_with_ws()
        cfg = ReportConfig(
            report_type="daily",
            workspaces=["_ctmsak_library"],
            ai_mode=AIMode.NONE,
            formats=["html"],
            output_dir="./test_rg_html_out",
        )
        gen = ReportGenerator(manager, cfg)
        result = gen.run()
        self.assertTrue(result.success)
        shutil.rmtree("./test_ws_rg", ignore_errors=True)
        shutil.rmtree("./test_rg_html_out", ignore_errors=True)

    def test_report_result_success_false_on_error(self):
        from gnat.reports.generator import ReportResult

        r = ReportResult(
            report_type="daily", title="T", generated_at=datetime.now(timezone.utc),
            formats_rendered=["pdf"],
        )
        r.errors = ["something failed"]
        self.assertFalse(r.success)

    def test_report_result_success_true(self):
        from gnat.reports.generator import ReportResult

        r = ReportResult(
            report_type="daily", title="T", generated_at=datetime.now(timezone.utc),
            formats_rendered=["pdf"],
        )
        self.assertTrue(r.success)

    def test_report_result_output_paths(self):
        from gnat.reports.generator import ReportResult

        r = ReportResult(
            report_type="daily", title="T", generated_at=datetime.now(timezone.utc),
        )
        r.files_written.append("/tmp/report.md")  # nosec B108
        self.assertIn("/tmp/report.md", r.files_written)  # nosec B108


# ===========================================================================
# Zeek Client
# ===========================================================================


class TestZeekClientAdditional(unittest.TestCase):
    def setUp(self):
        from gnat.connectors.zeek.client import ZeekClient

        self.client = ZeekClient(host="", log_dir="/fake/zeek", log_format="tsv")

    def test_authenticate_noop(self):
        self.client.authenticate()  # Should not raise

    def test_health_check_missing_dir(self):
        from gnat.clients.base import GNATClientError

        with self.assertRaises(GNATClientError):
            self.client.health_check()

    def test_health_check_valid_dir(self):
        with patch("pathlib.Path.is_dir", return_value=True):
            result = self.client.health_check()
        self.assertTrue(result)

    def test_get_object_raises(self):
        from gnat.clients.base import GNATClientError

        with self.assertRaises(GNATClientError):
            self.client.get_object("observed-data", "some-id")

    def test_upsert_raises(self):
        from gnat.clients.base import GNATClientError

        with self.assertRaises(GNATClientError):
            self.client.upsert_object("observed-data", {})

    def test_delete_raises(self):
        from gnat.clients.base import GNATClientError

        with self.assertRaises(GNATClientError):
            self.client.delete_object("observed-data", "id")

    def test_from_stix(self):
        result = self.client.from_stix({"id": "observed-data--1234"})
        self.assertEqual(result["stix_id"], "observed-data--1234")
        self.assertIn("note", result)

    def test_iter_tsv_records(self):
        tsv_content = "#fields\tts\tuid\tid.orig_h\tid.orig_p\tnote\tmsg\n1.0\tCxyz\t1.2.3.4\t1234\tTest::Notice\ttest msg\n"
        with (
            patch("pathlib.Path.exists", return_value=True),
            patch("pathlib.Path.open", mock_open(read_data=tsv_content)),
        ):
            records = list(self.client._iter_records("notice"))
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["id.orig_h"], "1.2.3.4")

    def test_iter_tsv_skips_comment_lines(self):
        tsv_content = "#separator \\t\n#fields\tts\tuid\n1.0\tCabc\n"
        with (
            patch("pathlib.Path.exists", return_value=True),
            patch("pathlib.Path.open", mock_open(read_data=tsv_content)),
        ):
            records = list(self.client._iter_records("notice"))
        self.assertEqual(len(records), 1)

    def test_iter_tsv_skips_mismatched_columns(self):
        tsv_content = "#fields\tts\tuid\tid.orig_h\n1.0\tonly_two\n"
        with (
            patch("pathlib.Path.exists", return_value=True),
            patch("pathlib.Path.open", mock_open(read_data=tsv_content)),
        ):
            records = list(self.client._iter_records("notice"))
        self.assertEqual(len(records), 0)

    def test_iter_json_records(self):
        self.client.log_format = "json"
        json_content = '{"ts": 1.0, "uid": "Cxyz", "id.orig_h": "1.2.3.4"}\n{"bad json\n'
        with (
            patch("pathlib.Path.exists", return_value=True),
            patch("pathlib.Path.open", mock_open(read_data=json_content)),
        ):
            records = list(self.client._iter_records("notice"))
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["uid"], "Cxyz")

    def test_parse_notices(self):
        tsv_content = "#fields\tts\tuid\tnote\tmsg\n1.0\tCabc\tTest::Notice\thello\n"
        with (
            patch("pathlib.Path.exists", return_value=True),
            patch("pathlib.Path.open", mock_open(read_data=tsv_content)),
        ):
            records = self.client.parse_notices()
        self.assertEqual(len(records), 1)

    def test_parse_connections(self):
        tsv_content = "#fields\tts\tuid\tid.orig_h\n1.0\tCabc\t10.0.0.1\n"
        with (
            patch("pathlib.Path.exists", return_value=True),
            patch("pathlib.Path.open", mock_open(read_data=tsv_content)),
        ):
            records = self.client.parse_connections()
        self.assertEqual(len(records), 1)

    def test_iter_stix_notices(self):
        tsv_content = "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tnote\tmsg\n"
        tsv_content += "1.0\tCabc\t1.2.3.4\t1234\t5.6.7.8\t80\tTest::Notice\thello\n"
        with (
            patch("pathlib.Path.exists", return_value=True),
            patch("pathlib.Path.open", mock_open(read_data=tsv_content)),
        ):
            stix_objs = list(self.client.iter_stix_notices())
        self.assertEqual(len(stix_objs), 1)
        self.assertEqual(stix_objs[0]["type"], "observed-data")

    def test_iter_stix_connections(self):
        tsv_content = "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n"
        tsv_content += "1.0\tCabc\t1.2.3.4\t1234\t5.6.7.8\t80\ttcp\n"
        with (
            patch("pathlib.Path.exists", return_value=True),
            patch("pathlib.Path.open", mock_open(read_data=tsv_content)),
        ):
            stix_objs = list(self.client.iter_stix_connections())
        self.assertEqual(len(stix_objs), 1)
        self.assertEqual(stix_objs[0]["type"], "observed-data")

    def test_list_objects(self):
        tsv_content = "#fields\tts\tuid\tnote\n1.0\tCabc\tTest::Notice\n"
        with (
            patch("pathlib.Path.exists", return_value=True),
            patch("pathlib.Path.open", mock_open(read_data=tsv_content)),
        ):
            records = self.client.list_objects("observed-data", filters={"limit": 5})
        self.assertEqual(len(records), 1)

    def test_list_available_logs(self):
        mock_files = [MagicMock(name="notice.log"), MagicMock(name="conn.log")]
        mock_files[0].name = "notice.log"
        mock_files[1].name = "conn.log"
        with patch("pathlib.Path.iterdir", return_value=mock_files):
            logs = self.client.list_available_logs()
        self.assertIn("notice", logs)
        self.assertIn("conn", logs)

    def test_list_available_logs_oserror(self):
        with patch("pathlib.Path.iterdir", side_effect=OSError("fail")):
            logs = self.client.list_available_logs()
        self.assertEqual(logs, [])

    def test_to_stix_with_ip_only(self):
        notice = {"id.orig_h": "1.2.3.4", "note": "Test::Notice", "msg": "hello"}
        stix = self.client.to_stix(notice)
        self.assertEqual(stix["type"], "observed-data")

    def test_to_stix_with_ports(self):
        notice = {
            "id.orig_h": "1.2.3.4",
            "id.orig_p": "1234",
            "id.resp_h": "5.6.7.8",
            "id.resp_p": "80",
            "proto": "tcp",
            "note": "Scan::Port_Scan",
        }
        stix = self.client.to_stix(notice)
        self.assertEqual(stix["type"], "observed-data")
        self.assertIn("x_zeek_notice", stix)

    def test_normalise_notice(self):
        from gnat.connectors.zeek.client import ZeekClient

        record = {
            "ts": "1.0",
            "uid": "Cabc",
            "id.orig_h": "1.2.3.4",
            "id.orig_p": "1234",
            "id.resp_h": "5.6.7.8",
            "id.resp_p": "80",
            "proto": "tcp",
            "note": "Test::Notice",
            "msg": "hello",
            "dropped": "T",
        }
        n = ZeekClient._normalise_notice(record)
        self.assertEqual(n["src_ip"], "1.2.3.4")
        self.assertEqual(n["dst_ip"], "5.6.7.8")
        self.assertTrue(n["dropped"])

    def test_conn_to_stix_with_bytes(self):
        conn = {
            "ts": "1.0",
            "uid": "Cabc",
            "id.orig_h": "1.2.3.4",
            "id.orig_p": "5678",
            "id.resp_h": "9.10.11.12",
            "id.resp_p": "443",
            "proto": "tcp",
            "orig_bytes": "1024",
            "resp_bytes": "2048",
        }
        stix = self.client._conn_to_stix(conn)
        self.assertEqual(stix["type"], "observed-data")
        self.assertIn("x_zeek_conn", stix)

    def test_iter_records_missing_file(self):
        from gnat.clients.base import GNATClientError

        with patch("pathlib.Path.exists", return_value=False), self.assertRaises(GNATClientError):
            list(self.client._iter_records("notice"))


# ===========================================================================
# Suricata Client
# ===========================================================================


class TestSuricataClientAdditional(unittest.TestCase):
    def _make_config(self):
        from gnat.connectors.suricata import SuricataConfig

        return SuricataConfig(
            eve_log_path="/fake/eve.json",
            socket_path="/fake/suricata.sock",
            timeout=5,
        )

    def test_config_defaults(self):
        from gnat.connectors.suricata import SuricataConfig

        cfg = SuricataConfig()
        self.assertEqual(cfg.eve_log_path, "/var/log/suricata/eve.json")

    def test_config_empty_eve_log_raises(self):
        from gnat.connectors.suricata import SuricataConfig, SuricataConfigError

        with self.assertRaises(SuricataConfigError):
            SuricataConfig(eve_log_path="")

    def test_load_suricata_config(self):
        from gnat.connectors.suricata import load_suricata_config

        cp = configparser.ConfigParser()
        cp.add_section("suricata")
        cp.set("suricata", "eve_log_path", "/var/log/suricata/eve.json")
        cfg = load_suricata_config(cp)
        self.assertEqual(cfg.eve_log_path, "/var/log/suricata/eve.json")

    def test_load_suricata_config_missing_section(self):
        from gnat.connectors.suricata import SuricataConfigError, load_suricata_config

        cp = configparser.ConfigParser()
        with self.assertRaises(SuricataConfigError):
            load_suricata_config(cp)

    def test_iter_events_file_not_found(self):
        from gnat.connectors.suricata import SuricataEVEReader, SuricataLogError

        cfg = self._make_config()
        reader = SuricataEVEReader(cfg)
        with self.assertRaises(SuricataLogError):
            list(reader.iter_events())

    def test_iter_events_parses_json(self):
        from gnat.connectors.suricata import SuricataEVEReader

        cfg = self._make_config()
        reader = SuricataEVEReader(cfg)
        evt = {"event_type": "alert", "src_ip": "1.2.3.4", "dest_ip": "5.6.7.8"}
        content = json.dumps(evt) + "\n"
        with patch("builtins.open", mock_open(read_data=content)):
            events = list(reader.iter_events())
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["src_ip"], "1.2.3.4")

    def test_iter_events_filters_by_type(self):
        from gnat.connectors.suricata import SuricataEVEReader

        cfg = self._make_config()
        reader = SuricataEVEReader(cfg)
        content = (
            json.dumps({"event_type": "alert", "src_ip": "1.1.1.1"})
            + "\n"
            + json.dumps({"event_type": "flow", "src_ip": "2.2.2.2"})
            + "\n"
        )
        with patch("builtins.open", mock_open(read_data=content)):
            events = list(reader.iter_events(event_type="alert"))
        self.assertEqual(len(events), 1)

    def test_iter_events_skips_bad_json(self):
        from gnat.connectors.suricata import SuricataEVEReader

        cfg = self._make_config()
        reader = SuricataEVEReader(cfg)
        content = "NOT JSON\n" + json.dumps({"event_type": "flow"}) + "\n"
        with patch("builtins.open", mock_open(read_data=content)):
            events = list(reader.iter_events())
        self.assertEqual(len(events), 1)

    def test_iter_alerts(self):
        from gnat.connectors.suricata import SuricataEVEReader

        cfg = self._make_config()
        reader = SuricataEVEReader(cfg)
        content = json.dumps({"event_type": "alert", "alert": {"signature": "ET TEST"}}) + "\n"
        with patch("builtins.open", mock_open(read_data=content)):
            alerts = list(reader.iter_alerts())
        self.assertEqual(len(alerts), 1)

    def test_iter_flows(self):
        from gnat.connectors.suricata import SuricataEVEReader

        cfg = self._make_config()
        reader = SuricataEVEReader(cfg)
        content = json.dumps({"event_type": "flow"}) + "\n"
        with patch("builtins.open", mock_open(read_data=content)):
            flows = list(reader.iter_flows())
        self.assertEqual(len(flows), 1)

    def test_iter_dns(self):
        from gnat.connectors.suricata import SuricataEVEReader

        cfg = self._make_config()
        reader = SuricataEVEReader(cfg)
        content = json.dumps({"event_type": "dns"}) + "\n"
        with patch("builtins.open", mock_open(read_data=content)):
            dns_events = list(reader.iter_dns())
        self.assertEqual(len(dns_events), 1)

    def test_count_alerts(self):
        from gnat.connectors.suricata import SuricataEVEReader

        cfg = self._make_config()
        reader = SuricataEVEReader(cfg)
        content = (
            json.dumps({"event_type": "alert"}) + "\n" + json.dumps({"event_type": "alert"}) + "\n"
        )
        with patch("builtins.open", mock_open(read_data=content)):
            count = reader.count_alerts()
        self.assertEqual(count, 2)

    def test_get_log_size(self):
        from gnat.connectors.suricata import SuricataEVEReader

        cfg = self._make_config()
        reader = SuricataEVEReader(cfg)
        with patch("os.path.getsize", return_value=12345):
            size = reader.get_log_size()
        self.assertEqual(size, 12345)

    def test_get_log_size_oserror(self):
        from gnat.connectors.suricata import SuricataEVEReader

        cfg = self._make_config()
        reader = SuricataEVEReader(cfg)
        with patch("os.path.getsize", side_effect=OSError):
            size = reader.get_log_size()
        self.assertEqual(size, 0)

    def test_normalise_alert(self):
        from gnat.connectors.suricata import SuricataEVEReader

        event = {
            "timestamp": "2024-01-01T00:00:00",
            "src_ip": "1.2.3.4",
            "src_port": 1234,
            "dest_ip": "5.6.7.8",
            "dest_port": 80,
            "proto": "TCP",
            "alert": {
                "signature": "ET TEST",
                "signature_id": 999,
                "category": "Misc",
                "severity": 1,
                "action": "blocked",
                "rev": 1,
                "gid": 1,
            },
        }
        norm = SuricataEVEReader.normalise_alert(event)
        self.assertEqual(norm["src_ip"], "1.2.3.4")
        self.assertEqual(norm["signature"], "ET TEST")
        self.assertEqual(norm["severity"], 4)  # severity 1 maps to 4
        self.assertEqual(norm["action"], "blocked")

    def test_normalise_alert_severity_map(self):
        from gnat.connectors.suricata import SuricataEVEReader

        for raw, expected in [(1, 4), (2, 3), (3, 2), (4, 1)]:
            event = {"alert": {"severity": raw}}
            norm = SuricataEVEReader.normalise_alert(event)
            self.assertEqual(norm["severity"], expected)

    def test_iter_events_from(self):
        from gnat.connectors.suricata import SuricataEVEReader

        cfg = self._make_config()
        reader = SuricataEVEReader(cfg)
        content = json.dumps({"event_type": "alert"}) + "\n"
        with (
            patch("os.path.getsize", return_value=50),
            patch("builtins.open", mock_open(read_data=content)),
        ):
            gen, new_offset = reader.iter_events_from(0)
            events = list(gen)
        self.assertEqual(new_offset, 50)
        self.assertEqual(len(events), 1)

    def test_socket_send_command_not_found(self):
        from gnat.connectors.suricata import SuricataSocketCommands, SuricataSocketError

        cfg = self._make_config()
        sc = SuricataSocketCommands(cfg)
        with patch("socket.socket") as mock_sock:
            mock_sock.return_value.connect.side_effect = FileNotFoundError
            with self.assertRaises(SuricataSocketError):
                sc._send_command("dump-counters")

    def test_socket_is_running_false(self):
        from gnat.connectors.suricata import SuricataSocketCommands, SuricataSocketError

        cfg = self._make_config()
        sc = SuricataSocketCommands(cfg)
        with patch.object(sc, "get_version", side_effect=SuricataSocketError("fail")):
            self.assertFalse(sc.is_running())

    def test_socket_is_running_true(self):
        from gnat.connectors.suricata import SuricataSocketCommands

        cfg = self._make_config()
        sc = SuricataSocketCommands(cfg)
        with patch.object(sc, "get_version", return_value={"return": "OK"}):
            self.assertTrue(sc.is_running())

    def test_stix_mapper_alert_to_bundle(self):
        from gnat.connectors.suricata import SuricataEVEReader, SuricataSTIXMapper

        mapper = SuricataSTIXMapper()
        event = {
            "timestamp": "2024-01-01T00:00:00",
            "src_ip": "1.2.3.4",
            "src_port": 1234,
            "dst_ip": "5.6.7.8",
            "dst_port": 80,
            "proto": "tcp",
            "alert": {"signature": "ET TEST", "signature_id": 1, "severity": 2},
        }
        alert = SuricataEVEReader.normalise_alert(event)
        bundle = mapper.alert_to_stix_bundle(alert)
        self.assertEqual(bundle["type"], "bundle")
        self.assertIn("objects", bundle)

    def test_stix_mapper_alerts_to_bundle(self):
        from gnat.connectors.suricata import SuricataEVEReader, SuricataSTIXMapper

        mapper = SuricataSTIXMapper()
        events = [
            {
                "src_ip": "1.2.3.4",
                "src_port": 1234,
                "dst_ip": "5.6.7.8",
                "dst_port": 80,
                "alert": {"signature": "Test1", "severity": 2},
            },
            {
                "src_ip": "1.2.3.4",
                "src_port": 1234,
                "dst_ip": "9.9.9.9",
                "dst_port": 443,
                "alert": {"signature": "Test2", "severity": 1},
            },
        ]
        alerts = [SuricataEVEReader.normalise_alert(e) for e in events]
        bundle = mapper.alerts_to_stix_bundle(alerts)
        self.assertEqual(bundle["type"], "bundle")

    def test_stix_mapper_no_ips(self):
        from gnat.connectors.suricata import SuricataSTIXMapper

        mapper = SuricataSTIXMapper()
        alert = {"signature": "Test", "severity": 2, "severity_raw": 2}
        bundle = mapper.alert_to_stix_bundle(alert)
        self.assertEqual(bundle["type"], "bundle")


# ===========================================================================
# Rapid7 Client
# ===========================================================================


class TestRapid7ClientAdditional(unittest.TestCase):
    def _make_client(self, product="insightvm"):
        from gnat.connectors.rapid7.client import Rapid7Client

        client = Rapid7Client(
            host="https://us.api.insight.rapid7.com",
            api_key="test-key",
            product=product,
        )
        client._http = MagicMock()
        return client

    def test_authenticate_sets_header(self):
        client = self._make_client()
        client.authenticate()
        self.assertEqual(client._auth_headers["X-Api-Key"], "test-key")

    def test_authenticate_with_account(self):
        from gnat.connectors.rapid7.client import Rapid7Client

        client = Rapid7Client(
            host="https://api.ti.insight.rapid7.com",
            api_key="key",
            product="threat_command",
            account_id="acct123",
        )
        client.authenticate()
        self.assertEqual(client._auth_headers["Account-Id"], "acct123")

    def test_health_check_insightvm(self):
        client = self._make_client("insightvm")
        with patch.object(client, "get", return_value={"data": []}):
            result = client.health_check()
        self.assertTrue(result)

    def test_health_check_tc(self):
        client = self._make_client("threat_command")
        with patch.object(client, "get", return_value={"content": []}):
            result = client.health_check()
        self.assertTrue(result)

    def test_get_object_insightvm_vuln(self):
        client = self._make_client("insightvm")
        with patch.object(client, "get", return_value={"id": "v1", "severity": "critical"}):
            obj = client.get_object("vulnerability", "v1")
        self.assertEqual(obj["id"], "v1")

    def test_get_object_insightvm_asset(self):
        client = self._make_client("insightvm")
        with patch.object(client, "get", return_value={"id": "a1"}):
            obj = client.get_object("asset", "a1")
        self.assertEqual(obj["id"], "a1")

    def test_get_object_insightvm_unknown(self):
        client = self._make_client("insightvm")
        with patch.object(client, "get", return_value={}):
            obj = client.get_object("unknown-type", "id1")
        self.assertEqual(obj, {})

    def test_get_object_tc_indicator(self):
        client = self._make_client("threat_command")
        with patch.object(client, "get", return_value={"value": "evil.com"}):
            obj = client.get_object("indicator", "evil.com")
        self.assertEqual(obj["value"], "evil.com")

    def test_get_object_tc_threat_actor(self):
        client = self._make_client("threat_command")
        with patch.object(client, "get", return_value={"name": "APT1"}):
            obj = client.get_object("threat-actor", "apt1-id")
        self.assertEqual(obj["name"], "APT1")

    def test_get_object_tc_unknown(self):
        client = self._make_client("threat_command")
        with patch.object(client, "get", return_value={}):
            obj = client.get_object("unknown", "id")
        self.assertEqual(obj, {})

    def test_list_objects_insightvm_vulns(self):
        client = self._make_client("insightvm")
        with patch.object(client, "get", return_value={"data": [{"id": "v1"}]}):
            objs = client.list_objects("vulnerability")
        self.assertEqual(len(objs), 1)

    def test_list_objects_insightvm_assets(self):
        client = self._make_client("insightvm")
        with patch.object(client, "get", return_value={"data": [{"id": "a1"}]}):
            objs = client.list_objects("asset")
        self.assertEqual(len(objs), 1)

    def test_list_objects_insightvm_unknown(self):
        client = self._make_client("insightvm")
        objs = client.list_objects("unknown-type")
        self.assertEqual(objs, [])

    def test_list_objects_tc_indicators(self):
        client = self._make_client("threat_command")
        with patch.object(client, "get", return_value={"content": [{"value": "evil.com"}]}):
            objs = client.list_objects("indicator")
        self.assertEqual(len(objs), 1)

    def test_list_objects_tc_threat_actors(self):
        client = self._make_client("threat_command")
        with patch.object(client, "get", return_value={"content": [{"name": "APT1"}]}):
            objs = client.list_objects("threat-actor")
        self.assertEqual(len(objs), 1)

    def test_list_objects_tc_unknown(self):
        client = self._make_client("threat_command")
        objs = client.list_objects("unknown-type")
        self.assertEqual(objs, [])

    def test_upsert_insightvm_raises(self):
        from gnat.clients.base import GNATClientError

        client = self._make_client("insightvm")
        with self.assertRaises(GNATClientError):
            client.upsert_object("vulnerability", {})

    def test_upsert_tc_wrong_type(self):
        from gnat.clients.base import GNATClientError

        client = self._make_client("threat_command")
        with self.assertRaises(GNATClientError):
            client.upsert_object("vulnerability", {})

    def test_upsert_tc_indicator(self):
        client = self._make_client("threat_command")
        with patch.object(client, "post", return_value={"id": "new-ioc"}):
            result = client.upsert_object("indicator", {"value": "evil.com"})
        self.assertEqual(result["id"], "new-ioc")

    def test_delete_insightvm_raises(self):
        from gnat.clients.base import GNATClientError

        client = self._make_client("insightvm")
        with self.assertRaises(GNATClientError):
            client.delete_object("vulnerability", "v1")

    def test_delete_tc(self):
        client = self._make_client("threat_command")
        with patch.object(client, "delete", return_value=None):
            client.delete_object("indicator", "evil.com")  # Should not raise

    def test_vuln_to_stix(self):
        client = self._make_client("insightvm")
        native = {
            "id": "vuln-1",
            "cves": ["CVE-2024-1234"],
            "severity": "critical",
            "cvss": {"v3": {"base_score": 9.8}, "v2": {}},
            "exploits": [{"id": "exp1"}],
            "description": {"text": "A critical vulnerability."},
            "added": "2024-01-01",
            "modified": "2024-01-02",
        }
        stix = client.to_stix(native)
        self.assertEqual(stix["type"], "vulnerability")
        self.assertEqual(stix["x_cve_id"], "CVE-2024-1234")
        self.assertTrue(stix["x_actively_exploited"])
        self.assertEqual(stix["x_cvss_score"], 9.8)

    def test_vuln_to_stix_no_exploits(self):
        client = self._make_client("insightvm")
        native = {"id": "v2", "cves": [], "severity": "low", "cvss": {}, "exploits": []}
        stix = client.to_stix(native)
        self.assertFalse(stix["x_actively_exploited"])

    def test_vuln_to_stix_cvss_fallback_v2(self):
        client = self._make_client("insightvm")
        native = {
            "id": "v3",
            "cves": ["CVE-2024-999"],
            "cvss": {"v3": {}, "v2": {"base_score": 7.5}},
            "exploits": [],
        }
        stix = client.to_stix(native)
        self.assertEqual(stix["x_cvss_score"], 7.5)

    def test_ioc_to_stix(self):
        client = self._make_client("threat_command")
        native = {
            "type": "domains",
            "value": "evil.com",
            "severity": "high",
            "tags": ["malware", "phishing", "Finance"],
            "firstSeen": "2024-01-01",
            "lastSeen": "2024-01-10",
        }
        stix = client.to_stix(native)
        self.assertEqual(stix["type"], "indicator")
        self.assertIn("evil.com", stix["pattern"])
        self.assertEqual(stix["confidence"], 75)

    def test_ioc_to_stix_ipaddresses(self):
        client = self._make_client("threat_command")
        native = {"type": "ipaddresses", "value": "1.2.3.4", "severity": "critical", "tags": []}
        stix = client.to_stix(native)
        self.assertIn("ipv4-addr", stix["pattern"])

    def test_ioc_to_stix_urls(self):
        client = self._make_client("threat_command")
        native = {"type": "urls", "value": "http://evil.com/x", "severity": "medium", "tags": []}
        stix = client.to_stix(native)
        self.assertIn("url", stix["pattern"])

    def test_ioc_to_stix_hashes(self):
        client = self._make_client("threat_command")
        native = {"type": "hashes", "value": "abc123", "severity": "low", "tags": []}
        stix = client.to_stix(native)
        self.assertIn("file", stix["pattern"])

    def test_from_stix(self):
        client = self._make_client()
        stix = {"pattern": "[domain-name:value = 'evil.com']", "name": "evil.com"}
        result = client.from_stix(stix)
        self.assertEqual(result["value"], "evil.com")

    def test_from_stix_no_match(self):
        client = self._make_client()
        stix = {"pattern": "no match here", "name": "fallback"}
        result = client.from_stix(stix)
        self.assertEqual(result["value"], "fallback")


# ===========================================================================
# Elastic – ElasticSearchCommands
# ===========================================================================


class TestElasticSearchCommandsAdditional(unittest.TestCase):
    def _make_commands(self):
        from gnat.connectors.elastic.es_search import ElasticSearchCommands

        client = MagicMock()
        client.config.es_index_alerts = ".alerts-security.*"
        return ElasticSearchCommands(client), client

    def test_cluster_health(self):
        cmds, cli = self._make_commands()
        cli.es_get.return_value = {"status": "green"}
        result = cmds.cluster_health()
        cli.es_get.assert_called_with("_cluster/health")
        self.assertEqual(result["status"], "green")

    def test_cluster_info(self):
        cmds, cli = self._make_commands()
        cli.es_get.return_value = {"cluster_name": "test"}
        result = cmds.cluster_info()
        cli.es_get.assert_called_with("")

    def test_node_stats(self):
        cmds, cli = self._make_commands()
        cli.es_get.return_value = {"nodes": {}}
        result = cmds.node_stats()
        cli.es_get.assert_called_with("_nodes/stats")

    def test_list_indices(self):
        cmds, cli = self._make_commands()
        cli.es_get.return_value = [{"index": "test-idx"}]
        result = cmds.list_indices("test-*")
        self.assertEqual(result[0]["index"], "test-idx")

    def test_list_indices_include_hidden(self):
        cmds, cli = self._make_commands()
        cli.es_get.return_value = []
        cmds.list_indices("*", include_hidden=True)
        call_args = cli.es_get.call_args
        self.assertIn("expand_wildcards", call_args[1]["params"])

    def test_list_indices_non_list_response(self):
        cmds, cli = self._make_commands()
        cli.es_get.return_value = {"error": "bad"}
        result = cmds.list_indices()
        self.assertEqual(result, [])

    def test_get_index_mapping(self):
        cmds, cli = self._make_commands()
        cli.es_get.return_value = {"test-idx": {"mappings": {}}}
        result = cmds.get_index_mapping("test-idx")
        cli.es_get.assert_called_with("test-idx/_mapping")

    def test_get_index_stats(self):
        cmds, cli = self._make_commands()
        cli.es_get.return_value = {"_all": {}}
        cmds.get_index_stats("test-idx")
        cli.es_get.assert_called_with("test-idx/_stats")

    def test_index_exists_true(self):
        cmds, cli = self._make_commands()
        cli.es_get.return_value = {"test-idx": {}}
        self.assertTrue(cmds.index_exists("test-idx"))

    def test_index_exists_false(self):
        cmds, cli = self._make_commands()
        cli.es_get.side_effect = Exception("not found")
        self.assertFalse(cmds.index_exists("nonexistent"))

    def test_doc_count(self):
        cmds, cli = self._make_commands()
        cli.es_count.return_value = 42
        count = cmds.doc_count("test-idx")
        self.assertEqual(count, 42)

    def test_doc_count_with_query(self):
        cmds, cli = self._make_commands()
        cli.es_count.return_value = 5
        q = {"match": {"field": "value"}}
        count = cmds.doc_count("test-idx", query=q)
        cli.es_count.assert_called_with("test-idx", query=q)

    def test_get_document_success(self):
        cmds, cli = self._make_commands()
        cli.es_get.return_value = {"_source": {"field": "value"}}
        doc = cmds.get_document("test-idx", "doc-1")
        self.assertEqual(doc["field"], "value")

    def test_get_document_not_found(self):
        cmds, cli = self._make_commands()
        cli.es_get.side_effect = Exception("not found")
        result = cmds.get_document("test-idx", "nonexistent")
        self.assertIsNone(result)

    def test_index_document_with_id(self):
        cmds, cli = self._make_commands()
        cli.es_put.return_value = {"result": "created"}
        result = cmds.index_document("test-idx", {"field": "val"}, doc_id="d1")
        cli.es_put.assert_called_once()

    def test_index_document_without_id(self):
        cmds, cli = self._make_commands()
        cli.es_post.return_value = {"result": "created", "_id": "auto-id"}
        result = cmds.index_document("test-idx", {"field": "val"})
        cli.es_post.assert_called_once()

    def test_delete_document(self):
        cmds, cli = self._make_commands()
        cli.es_delete.return_value = {"result": "deleted"}
        result = cmds.delete_document("test-idx", "doc-1")
        cli.es_delete.assert_called_once()

    def test_search_alerts_no_filters(self):
        cmds, cli = self._make_commands()
        cli.es_search_hits.return_value = [{"alert": "data"}]
        results = cmds.search_alerts()
        cli.es_search_hits.assert_called_once()
        self.assertEqual(len(results), 1)

    def test_search_alerts_with_filters(self):
        cmds, cli = self._make_commands()
        cli.es_search_hits.return_value = []
        cmds.search_alerts(
            min_severity=50,
            rule_name="TestRule",
            host_name="server1",
            user_name="admin",
            time_range=("2024-01-01", "2024-01-02"),
        )
        call_kwargs = cli.es_search_hits.call_args
        query = call_kwargs[1]["query"]
        self.assertIn("bool", query)

    def test_search_alerts_custom_index(self):
        cmds, cli = self._make_commands()
        cli.es_search_hits.return_value = []
        cmds.search_alerts(index="custom-alerts-*")
        call_args = cli.es_search_hits.call_args
        self.assertEqual(call_args[0][0], "custom-alerts-*")

    def test_search_process_events(self):
        cmds, cli = self._make_commands()
        cli.es_search_hits.return_value = [{"process": {"name": "bash"}}]
        results = cmds.search_process_events(process_name="bash", host_name="host1")
        self.assertEqual(len(results), 1)

    def test_search_process_events_with_time_range(self):
        cmds, cli = self._make_commands()
        cli.es_search_hits.return_value = []
        cmds.search_process_events(time_range=("2024-01-01", "2024-01-02"))
        cli.es_search_hits.assert_called_once()

    def test_search_network_events(self):
        cmds, cli = self._make_commands()
        cli.es_search_hits.return_value = [{"source": {"ip": "1.2.3.4"}}]
        results = cmds.search_network_events(src_ip="1.2.3.4", dest_ip="5.6.7.8", dest_port=443)
        self.assertEqual(len(results), 1)

    def test_search_network_events_with_time(self):
        cmds, cli = self._make_commands()
        cli.es_search_hits.return_value = []
        cmds.search_network_events(time_range=("2024-01-01", "2024-01-02"))
        cli.es_search_hits.assert_called_once()

    def test_aggregate_by_field(self):
        cmds, cli = self._make_commands()
        cli.es_search.return_value = {
            "aggregations": {"top_values": {"buckets": [{"key": "bash", "doc_count": 50}]}}
        }
        buckets = cmds.aggregate_by_field("logs-*", "process.name")
        self.assertEqual(len(buckets), 1)
        self.assertEqual(buckets[0]["key"], "bash")

    def test_aggregate_by_field_empty(self):
        cmds, cli = self._make_commands()
        cli.es_search.return_value = {}
        buckets = cmds.aggregate_by_field("logs-*", "host.name", query={"match_all": {}})
        self.assertEqual(buckets, [])

    def test_bulk_index(self):
        cmds, cli = self._make_commands()
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.data = json.dumps({"errors": False, "items": []}).encode()
        cli._http = MagicMock()
        cli._http.request.return_value = mock_response
        cli.config.es_url.return_value = "http://localhost:9200/test-idx/_bulk"
        cli.auth.get_es_headers.return_value = {"Content-Type": "application/x-ndjson"}
        docs = [{"field": f"value{i}"} for i in range(3)]
        results = cmds.bulk_index("test-idx", docs, batch_size=2)
        self.assertEqual(len(results), 2)

    def test_bulk_index_empty(self):
        cmds, cli = self._make_commands()
        results = cmds.bulk_index("test-idx", [])
        self.assertEqual(results, [])


# ===========================================================================
# Workspace
# ===========================================================================


class TestWorkspaceAdditional(unittest.TestCase):
    def _make_store(self):
        from gnat.context.store import FlatFileStore

        store = FlatFileStore(base_dir="./test_ws_ext_store")
        return store

    def _make_registry(self):
        from gnat.context import GlobalContext, GlobalContextRegistry

        reg = GlobalContextRegistry()
        cli = MagicMock()
        cli.target = "tq"
        cli.ping.return_value = True
        cli.client = MagicMock()
        reg.register(GlobalContext("tq", cli))
        reg.set_default("tq")
        return reg

    def setUp(self):
        self.store = self._make_store()
        self.reg = self._make_registry()
        import shutil

        shutil.rmtree("./test_ws_ext_store", ignore_errors=True)
        self.store = self._make_store()

    def tearDown(self):
        import shutil

        shutil.rmtree("./test_ws_ext_store", ignore_errors=True)

    def test_workspace_creation(self):
        from gnat.context.workspace import Workspace

        ws = Workspace("test-ws", self.reg, self.store)
        self.assertEqual(ws.name, "test-ws")
        self.assertEqual(len(ws), 0)

    def test_workspace_add_object(self):
        from gnat.context.workspace import Workspace
        from gnat.orm.indicator import Indicator

        ws = Workspace("ws1", self.reg, self.store)
        ind = Indicator(
            name="evil.com",
            pattern="[domain-name:value = 'evil.com']",
            pattern_type="stix",
        )
        ws.add(ind)
        self.assertEqual(len(ws), 1)
        self.assertIn(ind.id, ws)

    def test_workspace_add_marks_dirty(self):
        from gnat.context.workspace import Workspace
        from gnat.orm.indicator import Indicator

        ws = Workspace("ws2", self.reg, self.store)
        ind = Indicator(name="x.com", pattern="[domain-name:value = 'x.com']", pattern_type="stix")
        ws.add(ind)
        self.assertIn(ind.id, ws.dirty)

    def test_workspace_add_no_dirty(self):
        from gnat.context.workspace import Workspace
        from gnat.orm.indicator import Indicator

        ws = Workspace("ws3", self.reg, self.store)
        ind = Indicator(name="y.com", pattern="[domain-name:value = 'y.com']", pattern_type="stix")
        ws.add(ind, mark_dirty=False)
        self.assertNotIn(ind.id, ws.dirty)

    def test_workspace_remove(self):
        from gnat.context.workspace import Workspace
        from gnat.orm.indicator import Indicator

        ws = Workspace("ws4", self.reg, self.store)
        ind = Indicator(name="z.com", pattern="[domain-name:value = 'z.com']", pattern_type="stix")
        ws.add(ind)
        ws.remove(ind.id)
        self.assertNotIn(ind.id, ws)

    def test_workspace_get(self):
        from gnat.context.workspace import Workspace
        from gnat.orm.indicator import Indicator

        ws = Workspace("ws5", self.reg, self.store)
        ind = Indicator(name="a.com", pattern="[domain-name:value = 'a.com']", pattern_type="stix")
        ws.add(ind)
        retrieved = ws.get(ind.id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.id, ind.id)

    def test_workspace_get_missing(self):
        from gnat.context.workspace import Workspace

        ws = Workspace("ws6", self.reg, self.store)
        result = ws.get("nonexistent-id")
        self.assertIsNone(result)

    def test_workspace_iter(self):
        from gnat.context.workspace import Workspace
        from gnat.orm.indicator import Indicator

        ws = Workspace("ws7", self.reg, self.store)
        for i in range(3):
            ws.add(
                Indicator(
                    name=f"ind{i}.com",
                    pattern=f"[domain-name:value = 'ind{i}.com']",
                    pattern_type="stix",
                ),
                mark_dirty=False,
            )
        objects = list(ws)
        self.assertEqual(len(objects), 3)

    def test_workspace_filter_by_type(self):
        from gnat.context.workspace import Workspace
        from gnat.orm.indicator import Indicator
        from gnat.orm.malware import Malware

        ws = Workspace("ws8", self.reg, self.store)
        ws.add(
            Indicator(name="x.com", pattern="[domain-name:value='x.com']", pattern_type="stix"),
            mark_dirty=False,
        )
        ws.add(Malware(name="BadMalware", malware_types=["trojan"]), mark_dirty=False)
        indicators = ws.filter(stix_type="indicator")
        self.assertEqual(len(indicators), 1)

    def test_workspace_diff_empty(self):
        from gnat.context.workspace import Workspace

        ws = Workspace("ws9", self.reg, self.store)
        diff = ws.diff()
        self.assertEqual(diff, {})

    def test_workspace_diff_with_changes(self):
        from gnat.context.workspace import Workspace
        from gnat.orm.indicator import Indicator

        ws = Workspace("ws10", self.reg, self.store)
        ind = Indicator(name="b.com", pattern="[domain-name:value = 'b.com']", pattern_type="stix")
        ws.add(ind)
        diff = ws.diff()
        self.assertIn(ind.id, diff)

    def test_workspace_save(self):
        from gnat.context.workspace import Workspace
        from gnat.orm.indicator import Indicator

        ws = Workspace("ws11", self.reg, self.store)
        ind = Indicator(name="c.com", pattern="[domain-name:value = 'c.com']", pattern_type="stix")
        ws.add(ind)
        ws.save()  # Should not raise

    def test_commit_result_success(self):
        from gnat.context.workspace import CommitResult

        r = CommitResult("ws", "tq", dry_run=False)
        self.assertTrue(r.success)
        r.errors.append({"msg": "error"})
        self.assertFalse(r.success)

    def test_commit_result_dry_run(self):
        from gnat.context.workspace import CommitResult

        r = CommitResult("ws", "tq", dry_run=True)
        self.assertTrue(r.dry_run)

    def test_workspace_manager_create_and_open(self):
        from gnat.context.workspace import WorkspaceManager

        manager = WorkspaceManager(self.reg, store=self.store)
        ws = manager.create("new-ws")
        self.assertEqual(ws.name, "new-ws")
        ws2 = manager.open("new-ws")
        self.assertEqual(ws2.name, "new-ws")

    def test_workspace_manager_open_nonexistent(self):
        from gnat.context.workspace import WorkspaceManager

        manager = WorkspaceManager(self.reg, store=self.store)
        with self.assertRaises(KeyError):
            manager.open("nonexistent-ws")

    def test_workspace_manager_get_or_create_new(self):
        from gnat.context.workspace import WorkspaceManager

        manager = WorkspaceManager(self.reg, store=self.store)
        ws = manager.get_or_create("fresh-ws")
        self.assertEqual(ws.name, "fresh-ws")

    def test_workspace_manager_get_or_create_existing(self):
        from gnat.context.workspace import WorkspaceManager

        manager = WorkspaceManager(self.reg, store=self.store)
        manager.create("existing-ws")
        ws = manager.get_or_create("existing-ws")
        self.assertEqual(ws.name, "existing-ws")

    def test_workspace_manager_list(self):
        from gnat.context.workspace import WorkspaceManager

        manager = WorkspaceManager(self.reg, store=self.store)
        manager.create("list-ws-1")
        manager.create("list-ws-2")
        workspaces = manager.list()
        names = [w["name"] for w in workspaces]
        self.assertIn("list-ws-1", names)
        self.assertIn("list-ws-2", names)

    def test_workspace_manager_delete(self):
        from gnat.context.workspace import WorkspaceManager

        manager = WorkspaceManager(self.reg, store=self.store)
        manager.create("delete-ws")
        result = manager.delete("delete-ws")
        self.assertTrue(result)

    def test_workspace_manager_delete_nonexistent(self):
        from gnat.context.workspace import WorkspaceManager

        manager = WorkspaceManager(self.reg, store=self.store)
        result = manager.delete("no-such-ws")
        self.assertFalse(result)

    def test_from_dict_indicator(self):
        from gnat.context.workspace import Workspace
        from gnat.orm.indicator import Indicator

        d = {
            "type": "indicator",
            "id": "indicator--test-1234",
            "name": "test.com",
            "pattern": "[domain-name:value = 'test.com']",
            "pattern_type": "stix",
        }
        obj = Workspace._from_dict(d)
        self.assertIsInstance(obj, Indicator)

    def test_from_dict_unknown_type(self):
        from gnat.context.workspace import Workspace
        from gnat.orm.base import STIXBase

        d = {"type": "x-custom-type", "id": "x-custom-type--1234", "name": "custom"}
        obj = Workspace._from_dict(d)
        self.assertIsInstance(obj, STIXBase)

    def test_workspace_contains(self):
        from gnat.context.workspace import Workspace
        from gnat.orm.indicator import Indicator

        ws = Workspace("ws-contains", self.reg, self.store)
        ind = Indicator(name="d.com", pattern="[domain-name:value='d.com']", pattern_type="stix")
        ws.add(ind)
        self.assertIn(ind.id, ws)
        self.assertNotIn("fake-id", ws)

    def test_workspace_load_from_context(self):
        from gnat.context.workspace import Workspace

        ws = Workspace("ws-load", self.reg, self.store)
        ctx_mock = MagicMock()
        ctx_mock.list_objects.return_value = []
        self.reg._contexts["tq"] = ctx_mock
        ws.load("indicator")
        # Should not raise even with empty response

    def test_workspace_enrich_noop(self):
        from gnat.context.workspace import Workspace
        from gnat.orm.indicator import Indicator

        ws = Workspace("ws-enrich", self.reg, self.store)
        ind = Indicator(name="e.com", pattern="[domain-name:value='e.com']", pattern_type="stix")
        ws.add(ind)
        # enrich with no matching sources — should not raise
        ws.enrich(sources=[])


if __name__ == "__main__":
    unittest.main()
