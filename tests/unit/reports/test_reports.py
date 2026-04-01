"""
tests/unit/reports/test_reports.py
====================================

Unit tests for gnat.reports.

Covers:
- AIMode enum values
- ReportConfig: construction, defaults, window_days inference
- SectorFilter: empty (pass-all), any, all, strict, alias expansion,
  multi-field lookup, unknown field graceful handling
- DataAggregator: volume, by_type, indicators, actors, vulns, TTPs,
  sectors, sources, confidence, time series, period-over-period,
  workspace errors
- ReportDocument: add_section ordering, get_section, has_any_narrative
- MarkdownRenderer: title, sections, narrative, data tables
- HTMLRenderer: DOCTYPE, title, sections, narrative, tables
- PDFRenderer: file created, non-zero size
- ReportGenerator: no-AI pipeline (all formats), AI-assisted (mocked),
  missing agent_config warning, delivery=file output
- ReportJob: execute success, run_count, is_healthy, scheduled via FeedScheduler
- ReportResult: success property, __str__
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from gnat.context import FlatFileStore, GlobalContext, GlobalContextRegistry
from gnat.context.workspace import WorkspaceManager
from gnat.orm.attack_pattern import AttackPattern
from gnat.orm.indicator import Indicator
from gnat.orm.threat_actor import ThreatActor
from gnat.orm.vulnerability import Vulnerability
from gnat.reports import (
    AIMode,
    DataAggregator,
    HTMLRenderer,
    MarkdownRenderer,
    PDFRenderer,
    ReportConfig,
    ReportDocument,
    ReportGenerator,
    ReportJob,
    ReportResult,
    ReportSection,
    SectorFilter,
)
from gnat.reports.renderers import DOCXRenderer

# ===========================================================================
# Fixtures
# ===========================================================================

@pytest.fixture
def tmp_store(tmp_path):
    return FlatFileStore(base_dir=str(tmp_path / "workspaces"))


@pytest.fixture
def manager(tmp_store):
    cli = MagicMock()
    cli.target = "tq"
    cli.ping.return_value = True
    cli.client = MagicMock()
    reg = GlobalContextRegistry()
    reg.register(GlobalContext("tq", cli))
    reg.set_default("tq")
    return WorkspaceManager(reg, store=tmp_store)


@pytest.fixture
def library_ws(manager):
    ws = manager.create("_ctmsak_library")
    _populate(ws)
    return ws


def _populate(ws, n_inds=5, n_actors=2, n_vulns=2, n_ttps=2):
    for i in range(n_inds):
        ws.add(Indicator(
            name=f"evil{i}.com",
            pattern=f"[domain-name:value = 'evil{i}.com']",
            pattern_type="stix",
            confidence=40 + i * 10,
            x_target_sectors=["Healthcare"] if i % 2 == 0 else ["Finance"],
            x_source_platform="threatq",
            created=f"2024-03-{i+1:02d}T00:00:00Z",
            modified=f"2024-03-{i+1:02d}T00:00:00Z",
        ), mark_dirty=False)
    for i in range(n_actors):
        ws.add(ThreatActor(
            name=f"Actor{i}",
            threat_actor_types=["espionage"],
            x_target_sectors=["Healthcare"],
            created=f"2024-03-{i+1:02d}T00:00:00Z",
            modified=f"2024-03-{i+1:02d}T00:00:00Z",
        ), mark_dirty=False)
    for i in range(n_vulns):
        ws.add(Vulnerability(
            name=f"CVE-2024-{i+1000}",
            x_cvss_score=9.0 + i * 0.4,
            x_cve_id=f"CVE-2024-{i+1000}",
            x_actively_exploited=(i == 0),
            created=f"2024-03-{i+1:02d}T00:00:00Z",
            modified=f"2024-03-{i+1:02d}T00:00:00Z",
        ), mark_dirty=False)
    for i in range(n_ttps):
        ws.add(AttackPattern(
            name=f"T{1500+i} Technique",
            x_mitre_id=f"T{1500+i}",
            x_tactic="Initial Access",
            created=f"2024-03-{i+1:02d}T00:00:00Z",
            modified=f"2024-03-{i+1:02d}T00:00:00Z",
        ), mark_dirty=False)


def _daily_config(tmp_path, **kwargs):
    defaults = {
        "report_type": "daily",
        "workspaces": ["_ctmsak_library"],
        "ai_mode": AIMode.NONE,
        "formats": ["markdown"],
        "delivery": ["file"],
        "output_dir": str(tmp_path / "reports"),
        "window_days": 365,
    }
    defaults.update(kwargs)
    return ReportConfig(**defaults)


def _make_doc(config=None):
    now = datetime.now(timezone.utc)
    doc = ReportDocument(
        title="Test Report",
        report_type="daily",
        generated_at=now,
        period_start=now - timedelta(days=1),
        period_end=now,
        config=config,
    )
    doc.add_section(ReportSection(
        title="Executive Summary",
        data={"total_new": 5},
        narrative="APT29 targeted healthcare. Three critical CVEs identified.",
        section_type="summary",
        order=1,
    ))
    doc.add_section(ReportSection(
        title="Vulnerabilities",
        data={"critical_vulns": [
            {"cve_id": "CVE-2024-1234", "cvss": 9.8, "exploited": True,
             "name": "CVE-2024-1234", "description": "RCE"}
        ]},
        section_type="table",
        order=2,
    ))
    return doc


# ===========================================================================
# AIMode
# ===========================================================================

class TestAIMode:
    def test_values(self):
        assert AIMode.NONE.value == "none"
        assert AIMode.ASSISTED.value == "assisted"
        assert AIMode.FULL.value == "full"


# ===========================================================================
# ReportConfig
# ===========================================================================

class TestReportConfig:

    def test_defaults(self):
        cfg = ReportConfig(report_type="daily")
        assert cfg.workspaces == ["_ctmsak_library"]
        assert cfg.ai_mode == AIMode.ASSISTED
        assert cfg.sectors == []
        assert "pdf" in cfg.formats
        assert "html" in cfg.formats
        assert cfg.window_days == 1

    def test_window_days_inferred_daily(self):
        assert ReportConfig(report_type="daily").window_days == 1

    def test_window_days_inferred_trends(self):
        assert ReportConfig(report_type="trends").window_days == 30

    def test_window_days_inferred_yearly(self):
        assert ReportConfig(report_type="yearly").window_days == 365

    def test_window_days_explicit_overrides(self):
        cfg = ReportConfig(report_type="trends", window_days=90)
        assert cfg.window_days == 90

    def test_from_ini_missing_section(self, tmp_path):
        ini = tmp_path / "config.ini"
        ini.write_text("[DEFAULT]\ntimeout = 30\n")
        with pytest.raises(KeyError):
            ReportConfig.from_ini("report.nonexistent", str(ini))

    def test_from_ini_loads_values(self, tmp_path):
        ini = tmp_path / "config.ini"
        ini.write_text(
            "[report.daily_test]\n"
            "report_type = daily\n"
            "workspaces = _ctmsak_library, analyst-ws\n"
            "sectors = Healthcare, Opportunistic\n"
            "ai_mode = none\n"
            "formats = pdf, html\n"
            "delivery = email, file\n"
            "email_to = soc@example.com\n"
            "org_name = Test Org\n"
        )
        cfg = ReportConfig.from_ini("report.daily_test", str(ini))
        assert cfg.report_type == "daily"
        assert "_ctmsak_library" in cfg.workspaces
        assert "analyst-ws" in cfg.workspaces
        assert "Healthcare" in cfg.sectors
        assert cfg.ai_mode == AIMode.NONE
        assert "pdf" in cfg.formats
        assert cfg.org_name == "Test Org"


# ===========================================================================
# SectorFilter
# ===========================================================================

class TestSectorFilter:

    def _objects(self):
        """Create three test objects with different sector tags."""
        ind1 = Indicator(name="a.com",
            pattern="[domain-name:value = 'a.com']", pattern_type="stix",
            x_target_sectors=["Healthcare", "Opportunistic"])
        ind2 = Indicator(name="b.com",
            pattern="[domain-name:value = 'b.com']", pattern_type="stix",
            x_target_sectors=["Finance"])
        ind3 = Indicator(name="c.com",
            pattern="[domain-name:value = 'c.com']", pattern_type="stix")
        # ind3 has no sector tag
        return [ind1, ind2, ind3]

    def test_empty_sectors_passes_all(self):
        f = SectorFilter(sectors=[])
        objs = self._objects()
        assert len(f.apply(objs)) == len(objs)

    def test_any_match(self):
        f = SectorFilter(sectors=["Healthcare"], match="any")
        filtered = f.apply(self._objects())
        names = [o.name for o in filtered]
        assert "a.com" in names  # tagged Healthcare

    def test_any_includes_untagged_non_strict(self):
        f = SectorFilter(sectors=["Healthcare"], match="any", strict=False)
        filtered = f.apply(self._objects())
        names = [o.name for o in filtered]
        assert "c.com" in names  # untagged — passes in non-strict

    def test_strict_excludes_untagged(self):
        f = SectorFilter(sectors=["Healthcare"], match="any", strict=True)
        filtered = f.apply(self._objects())
        names = [o.name for o in filtered]
        assert "c.com" not in names
        assert "a.com" in names

    def test_strict_excludes_wrong_sector(self):
        f = SectorFilter(sectors=["Healthcare"], match="any", strict=True)
        filtered = f.apply(self._objects())
        names = [o.name for o in filtered]
        assert "b.com" not in names

    def test_all_match_requires_all_sectors(self):
        f = SectorFilter(sectors=["Healthcare", "Opportunistic"], match="all")
        filtered = f.apply(self._objects())
        names = [o.name for o in filtered]
        assert "a.com" in names  # has both
        assert "b.com" not in names  # has only Finance

    def test_alias_expansion(self):
        f = SectorFilter(
            sectors=["health"],
            aliases={"health": ["Healthcare", "Health", "Medical"]},
        )
        filtered = f.apply(self._objects())
        names = [o.name for o in filtered]
        assert "a.com" in names

    def test_opportunistic_matching(self):
        f = SectorFilter(sectors=["Opportunistic"])
        filtered = f.apply(self._objects())
        names = [o.name for o in filtered]
        assert "a.com" in names  # has Opportunistic tag


# ===========================================================================
# DataAggregator
# ===========================================================================

class TestDataAggregator:

    def test_volume_metrics(self, manager, library_ws, tmp_path):
        cfg = _daily_config(tmp_path)
        agg = DataAggregator(manager, cfg).run()
        assert agg.total_objects > 0
        assert agg.window_days == 365

    def test_by_type_breakdown(self, manager, library_ws, tmp_path):
        cfg = _daily_config(tmp_path)
        agg = DataAggregator(manager, cfg).run()
        assert "indicator" in agg.by_type
        assert "threat-actor" in agg.by_type
        assert "vulnerability" in agg.by_type
        assert "attack-pattern" in agg.by_type

    def test_indicator_count(self, manager, library_ws, tmp_path):
        cfg = _daily_config(tmp_path)
        agg = DataAggregator(manager, cfg).run()
        assert agg.indicator_count == 5
        assert "domain" in agg.ioc_by_type

    def test_actor_count(self, manager, library_ws, tmp_path):
        cfg = _daily_config(tmp_path)
        agg = DataAggregator(manager, cfg).run()
        assert agg.actor_count == 2
        assert "espionage" in agg.actor_motivations

    def test_vulnerability_metrics(self, manager, library_ws, tmp_path):
        cfg = _daily_config(tmp_path)
        agg = DataAggregator(manager, cfg).run()
        assert agg.vuln_count == 2
        assert len(agg.critical_vulns) >= 1
        assert len(agg.exploited_vulns) >= 1

    def test_ttp_count(self, manager, library_ws, tmp_path):
        cfg = _daily_config(tmp_path)
        agg = DataAggregator(manager, cfg).run()
        assert agg.ttp_count == 2
        assert "Initial Access" in agg.tactic_distribution

    def test_sector_distribution(self, manager, library_ws, tmp_path):
        cfg = _daily_config(tmp_path)
        agg = DataAggregator(manager, cfg).run()
        assert "Healthcare" in agg.sector_distribution

    def test_source_breakdown(self, manager, library_ws, tmp_path):
        cfg = _daily_config(tmp_path)
        agg = DataAggregator(manager, cfg).run()
        assert "threatq" in agg.source_breakdown

    def test_confidence_stats(self, manager, library_ws, tmp_path):
        cfg = _daily_config(tmp_path)
        agg = DataAggregator(manager, cfg).run()
        assert agg.avg_confidence > 0
        assert agg.confidence_distribution

    def test_sector_filter_applied(self, manager, library_ws, tmp_path):
        cfg = _daily_config(tmp_path, sectors=["Healthcare"])
        sf = SectorFilter(sectors=["Healthcare"], strict=True)
        agg_filtered = DataAggregator(manager, cfg, sector_filter=sf).run()
        agg_all = DataAggregator(manager, _daily_config(tmp_path)).run()
        assert agg_filtered.total_objects <= agg_all.total_objects

    def test_missing_workspace_logs_warning(self, manager, tmp_path):
        cfg = _daily_config(tmp_path, workspaces=["nonexistent"])
        agg = DataAggregator(manager, cfg).run()
        assert agg.total_objects == 0

    def test_time_series_for_long_window(self, manager, library_ws, tmp_path):
        cfg = _daily_config(tmp_path, window_days=30)
        agg = DataAggregator(manager, cfg).run()
        # monthly_counts populated for windows > 2 days
        assert isinstance(agg.daily_counts, list)

    def test_period_over_period_for_trends(self, manager, library_ws, tmp_path):
        cfg = ReportConfig(
            report_type="trends", workspaces=["_ctmsak_library"],
            ai_mode=AIMode.NONE, formats=["markdown"], delivery=["file"],
            output_dir=str(tmp_path / "r"), window_days=30,
        )
        agg = DataAggregator(manager, cfg).run()
        assert "current_total" in agg.period_over_period


# ===========================================================================
# ReportDocument
# ===========================================================================

class TestReportDocument:

    def test_add_section_sorts_by_order(self):
        doc = _make_doc()
        doc.add_section(ReportSection(title="Last", data={}, order=99))
        doc.add_section(ReportSection(title="First", data={}, order=0))
        assert doc.sections[0].title == "First"
        assert doc.sections[-1].title == "Last"

    def test_get_section_case_insensitive(self):
        doc = _make_doc()
        s = doc.get_section("executive summary")
        assert s is not None
        assert s.title == "Executive Summary"

    def test_get_section_missing_returns_none(self):
        assert _make_doc().get_section("Nonexistent") is None

    def test_has_any_narrative_true(self):
        doc = _make_doc()
        assert doc.has_any_narrative

    def test_has_any_narrative_false(self):
        now = datetime.now(timezone.utc)
        doc = ReportDocument(
            title="x", report_type="daily", generated_at=now,
            period_start=now, period_end=now,
        )
        doc.add_section(ReportSection(title="Data", data={"k": 1}, order=1))
        assert not doc.has_any_narrative


# ===========================================================================
# MarkdownRenderer
# ===========================================================================

class TestMarkdownRenderer:

    def test_title_in_output(self, tmp_path):
        doc = _make_doc()
        path = str(tmp_path / "r.md")
        MarkdownRenderer().render(doc, path)
        with open(path) as f:
            assert "# Test Report" in f.read()

    def test_sections_present(self, tmp_path):
        doc = _make_doc()
        path = str(tmp_path / "r.md")
        MarkdownRenderer().render(doc, path)
        with open(path) as f:
            content = f.read()
        assert "## Executive Summary" in content
        assert "## Vulnerabilities" in content

    def test_narrative_included(self, tmp_path):
        doc = _make_doc()
        path = str(tmp_path / "r.md")
        MarkdownRenderer().render(doc, path)
        with open(path) as f:
            assert "APT29 targeted healthcare" in f.read()

    def test_data_table_rendered(self, tmp_path):
        doc = _make_doc()
        path = str(tmp_path / "r.md")
        MarkdownRenderer().render(doc, path)
        with open(path) as f:
            content = f.read()
        assert "CVE-2024-1234" in content

    def test_render_string(self):
        doc = _make_doc()
        md = MarkdownRenderer().render_string(doc)
        assert "# Test Report" in md
        assert "Executive Summary" in md


# ===========================================================================
# HTMLRenderer
# ===========================================================================

class TestHTMLRenderer:

    def test_valid_html(self, tmp_path):
        doc = _make_doc()
        path = str(tmp_path / "r.html")
        HTMLRenderer().render(doc, path)
        with open(path) as f:
            content = f.read()
        assert "<!DOCTYPE html>" in content
        assert "</html>" in content

    def test_title_in_html(self, tmp_path):
        doc = _make_doc()
        path = str(tmp_path / "r.html")
        HTMLRenderer().render(doc, path)
        with open(path) as f:
            assert "Test Report" in f.read()

    def test_sections_in_html(self, tmp_path):
        doc = _make_doc()
        path = str(tmp_path / "r.html")
        HTMLRenderer().render(doc, path)
        with open(path) as f:
            content = f.read()
        assert "Executive Summary" in content
        assert "Vulnerabilities" in content

    def test_narrative_in_html(self, tmp_path):
        doc = _make_doc()
        path = str(tmp_path / "r.html")
        HTMLRenderer().render(doc, path)
        with open(path) as f:
            assert "APT29 targeted healthcare" in f.read()

    def test_sector_badges_when_config_has_sectors(self, tmp_path):
        cfg = ReportConfig(report_type="daily", sectors=["Healthcare"])
        doc = _make_doc(config=cfg)
        path = str(tmp_path / "r.html")
        HTMLRenderer().render(doc, path)
        with open(path) as f:
            assert "Healthcare" in f.read()


# ===========================================================================
# PDFRenderer
# ===========================================================================

_reportlab_available = True
try:
    import reportlab  # noqa: F401
except ImportError:
    _reportlab_available = False


class TestPDFRenderer:

    def test_creates_file(self, tmp_path):
        if not _reportlab_available:
            pytest.skip("reportlab not installed")
        doc = _make_doc()
        path = str(tmp_path / "r.pdf")
        PDFRenderer().render(doc, path)
        assert os.path.exists(path)

    def test_non_empty(self, tmp_path):
        if not _reportlab_available:
            pytest.skip("reportlab not installed")
        doc = _make_doc()
        path = str(tmp_path / "r.pdf")
        PDFRenderer().render(doc, path)
        assert os.path.getsize(path) > 500

    def test_creates_parent_dir(self, tmp_path):
        if not _reportlab_available:
            pytest.skip("reportlab not installed")
        doc = _make_doc()
        path = str(tmp_path / "subdir" / "nested" / "r.pdf")
        PDFRenderer().render(doc, path)
        assert os.path.exists(path)


# ===========================================================================
# DOCXRenderer
# ===========================================================================

class TestDOCXRenderer:

    def test_creates_file(self, tmp_path):
        doc = _make_doc()
        path = str(tmp_path / "r.docx")
        DOCXRenderer().render(doc, path)
        assert os.path.exists(path)

    def test_non_empty(self, tmp_path):
        doc = _make_doc()
        path = str(tmp_path / "r.docx")
        DOCXRenderer().render(doc, path)
        assert os.path.getsize(path) > 1000

    def test_creates_parent_dir(self, tmp_path):
        doc = _make_doc()
        path = str(tmp_path / "subdir" / "nested" / "r.docx")
        DOCXRenderer().render(doc, path)
        assert os.path.exists(path)

    def test_is_valid_zip(self, tmp_path):
        """DOCX files are ZIP archives — verify basic structure."""
        import zipfile
        doc = _make_doc()
        path = str(tmp_path / "r.docx")
        DOCXRenderer().render(doc, path)
        assert zipfile.is_zipfile(path)
        with zipfile.ZipFile(path) as zf:
            names = zf.namelist()
        assert "word/document.xml" in names

    def test_title_in_content(self, tmp_path):
        """Title text should appear in the document XML."""
        import zipfile
        doc = _make_doc()
        path = str(tmp_path / "r.docx")
        DOCXRenderer().render(doc, path)
        with zipfile.ZipFile(path) as zf:
            xml = zf.read("word/document.xml").decode("utf-8")
        assert "Test Report" in xml

    def test_missing_python_docx_raises(self, tmp_path):
        import sys
        from unittest.mock import patch
        with patch.dict(sys.modules, {"docx": None}), pytest.raises(ImportError, match="python-docx"):
            DOCXRenderer().render(_make_doc(), str(tmp_path / "r.docx"))


# ===========================================================================
# ReportGenerator
# ===========================================================================

class TestReportGenerator:

    def test_no_ai_all_formats(self, manager, library_ws, tmp_path):
        cfg = _daily_config(tmp_path, formats=["markdown", "html", "docx"])
        result = ReportGenerator(manager, cfg).run()
        assert result.success
        assert set(result.formats_rendered) == {"markdown", "html", "docx"}
        assert len(result.files_written) == 3

    def test_no_ai_zero_calls(self, manager, library_ws, tmp_path):
        cfg = _daily_config(tmp_path)
        result = ReportGenerator(manager, cfg).run()
        assert result.ai_calls_made == 0

    def test_objects_analysed_count(self, manager, library_ws, tmp_path):
        cfg = _daily_config(tmp_path)
        result = ReportGenerator(manager, cfg).run()
        assert result.objects_analysed > 0

    def test_files_written_to_output_dir(self, manager, library_ws, tmp_path):
        outdir = str(tmp_path / "out")
        cfg = _daily_config(tmp_path, output_dir=outdir)
        result = ReportGenerator(manager, cfg).run()
        for fp in result.files_written:
            assert fp.startswith(outdir)
            assert os.path.exists(fp)

    def test_ai_assisted_calls_synthesizer(self, manager, library_ws, tmp_path):
        from gnat.agents.base import AgentConfig, ClaudeClient
        mock_resp = {"content": [{"type": "text",
                                   "text": "Narrative for this section."}]}
        with patch.object(ClaudeClient, "complete", return_value=mock_resp):
            cfg = _daily_config(tmp_path, ai_mode=AIMode.ASSISTED)
            result = ReportGenerator(
                manager, cfg, agent_config=AgentConfig(api_key="x")
            ).run()
        assert result.ai_calls_made > 0
        assert "markdown" in result.formats_rendered

    def test_ai_missing_agent_config_falls_back(self, manager, library_ws, tmp_path):
        cfg = _daily_config(tmp_path, ai_mode=AIMode.ASSISTED)
        result = ReportGenerator(manager, cfg, agent_config=None).run()
        # Should succeed without AI
        assert result.success
        assert result.ai_calls_made == 0

    def test_unknown_format_logged(self, manager, library_ws, tmp_path):
        cfg = _daily_config(tmp_path, formats=["markdown", "unknown_fmt"])
        result = ReportGenerator(manager, cfg).run()
        assert "markdown" in result.formats_rendered
        assert "unknown_fmt" not in result.formats_rendered

    def test_sector_filter_applied(self, manager, library_ws, tmp_path):
        cfg_all = _daily_config(tmp_path)
        cfg_hc  = _daily_config(tmp_path, sectors=["Healthcare"], sector_strict=True)
        result_all = ReportGenerator(manager, cfg_all).run()
        result_hc  = ReportGenerator(manager, cfg_hc).run()
        assert result_hc.objects_analysed <= result_all.objects_analysed

    def test_trends_report(self, manager, library_ws, tmp_path):
        cfg = ReportConfig(
            report_type="trends", workspaces=["_ctmsak_library"],
            ai_mode=AIMode.NONE, formats=["markdown", "html"],
            delivery=["file"], output_dir=str(tmp_path / "trends"),
            window_days=30,
        )
        result = ReportGenerator(manager, cfg).run()
        assert result.success
        assert "markdown" in result.formats_rendered

    def test_yearly_report(self, manager, library_ws, tmp_path):
        cfg = ReportConfig(
            report_type="yearly", workspaces=["_ctmsak_library"],
            ai_mode=AIMode.NONE, formats=["markdown"],
            delivery=["file"], output_dir=str(tmp_path / "yearly"),
            window_days=365,
        )
        result = ReportGenerator(manager, cfg).run()
        assert result.success


# ===========================================================================
# ReportResult
# ===========================================================================

class TestReportResult:

    def test_success_true_when_formats_rendered(self):
        r = ReportResult(
            report_type="daily", title="T",
            generated_at=datetime.now(timezone.utc),
            formats_rendered=["pdf"],
        )
        assert r.success

    def test_success_false_when_errors(self):
        r = ReportResult(
            report_type="daily", title="T",
            generated_at=datetime.now(timezone.utc),
            formats_rendered=["pdf"],
            errors=["Something failed"],
        )
        assert not r.success

    def test_success_false_when_no_formats(self):
        r = ReportResult(
            report_type="daily", title="T",
            generated_at=datetime.now(timezone.utc),
        )
        assert not r.success

    def test_str_representation(self):
        r = ReportResult(
            report_type="daily", title="T",
            generated_at=datetime.now(timezone.utc),
            formats_rendered=["pdf", "html"],
            objects_analysed=50,
        )
        s = str(r)
        assert "daily" in s
        assert "50" in s


# ===========================================================================
# ReportJob
# ===========================================================================

class TestReportJob:

    def test_execute_success(self, manager, library_ws, tmp_path):
        cfg = _daily_config(tmp_path)
        job = ReportJob(manager=manager, config=cfg)
        rec = job.execute()
        assert rec.status == "success"
        assert job.run_count == 1
        assert job.is_healthy

    def test_run_count_increments(self, manager, library_ws, tmp_path):
        cfg = _daily_config(tmp_path)
        job = ReportJob(manager=manager, config=cfg)
        job.execute()
        job.execute()
        assert job.run_count == 2

    def test_on_success_callback(self, manager, library_ws, tmp_path):
        fired = []
        cfg = _daily_config(tmp_path)
        job = ReportJob(
            manager=manager, config=cfg,
            on_success=lambda rec: fired.append(rec.status),
        )
        job.execute()
        assert fired == ["success"]

    def test_disabled_returns_skipped(self, manager, library_ws, tmp_path):
        cfg = _daily_config(tmp_path)
        job = ReportJob(manager=manager, config=cfg)
        job.enabled = False
        rec = job.execute()
        assert rec.status == "skipped"

    def test_schedule_via_feedscheduler(self, manager, library_ws, tmp_path):
        import time

        from gnat.schedule import FeedScheduler

        fired = []
        cfg = ReportConfig(
            report_type="daily", workspaces=["_ctmsak_library"],
            ai_mode=AIMode.NONE, formats=["markdown"], delivery=["file"],
            output_dir=str(tmp_path / "sched"), window_days=365,
        )
        job = ReportJob(
            manager=manager, config=cfg, job_id="sched-test",
            on_success=lambda rec: fired.append(rec.run_number),
        )
        sched = FeedScheduler()
        sched.add(job)
        sched.start(run_immediately=True)
        time.sleep(0.5)
        sched.stop()
        assert len(fired) >= 1

    def test_yearly_default_cron(self, manager, library_ws, tmp_path):
        """ReportJob for yearly should use cron, not a 365-day interval."""
        cfg = ReportConfig(
            report_type="yearly", workspaces=["_ctmsak_library"],
            ai_mode=AIMode.NONE, formats=["markdown"],
            delivery=["file"], output_dir=str(tmp_path / "yearly"),
        )
        job = ReportJob(manager=manager, config=cfg)
        # cron should be set; interval_seconds should be None
        assert job.cron == "0 6 1 1 *"
        assert job.interval_seconds is None

    def test_daily_default_interval(self, manager, library_ws, tmp_path):
        """ReportJob for daily should use 86400-second interval by default."""
        cfg = ReportConfig(
            report_type="daily", workspaces=["_ctmsak_library"],
            ai_mode=AIMode.NONE, formats=["markdown"],
            delivery=["file"], output_dir=str(tmp_path / "daily"),
        )
        job = ReportJob(manager=manager, config=cfg)
        assert job.interval_seconds == 86400
        assert job.cron is None

    def test_custom_schedule_overrides_default(self, manager, library_ws, tmp_path):
        """Explicit schedule in ReportConfig takes precedence over defaults."""
        cfg = ReportConfig(
            report_type="yearly", workspaces=["_ctmsak_library"],
            ai_mode=AIMode.NONE, formats=["markdown"],
            delivery=["file"], output_dir=str(tmp_path / "yearly"),
            schedule="0 8 1 1 *",
        )
        job = ReportJob(manager=manager, config=cfg)
        assert job.cron == "0 8 1 1 *"


# ===========================================================================
# EmailDelivery body_html population (item #7)
# ===========================================================================

class TestEmailBodyHTML:

    def test_html_file_used_as_body(self, manager, library_ws, tmp_path):
        """When an HTML file is rendered, _extract_email_body_html returns its content."""
        from gnat.reports.generator import ReportGenerator

        cfg = ReportConfig(
            report_type="daily", workspaces=["_ctmsak_library"],
            ai_mode=AIMode.NONE, formats=["html"],
            delivery=["file"], output_dir=str(tmp_path / "out"),
        )
        gen = ReportGenerator(manager, cfg)
        result = gen.run()
        assert "html" in result.formats_rendered

        from gnat.reports.base import ReportDocument
        _now = result.generated_at
        doc = ReportDocument(
            title="T", report_type="daily",
            generated_at=_now, period_start=_now, period_end=_now,
        )
        body = gen._extract_email_body_html(result, doc)
        assert body.startswith("<!DOCTYPE html") or "<html" in body

    def test_no_html_file_uses_executive_summary(self, manager, library_ws, tmp_path):
        """Without an HTML file, falls back to executive summary from doc."""
        from gnat.reports.base import ReportDocument, ReportSection
        from gnat.reports.generator import ReportGenerator

        cfg = ReportConfig(
            report_type="daily", workspaces=["_ctmsak_library"],
            ai_mode=AIMode.NONE, formats=["markdown"],
            delivery=["file"], output_dir=str(tmp_path / "out"),
        )
        gen = ReportGenerator(manager, cfg)
        result = gen.run()
        # No HTML file in this run
        html_files = [f for f in result.files_written if f.endswith(".html")]
        assert html_files == []

        _now = result.generated_at
        doc = ReportDocument(
            title="Daily Report", report_type="daily",
            generated_at=_now, period_start=_now, period_end=_now,
        )
        doc.add_section(ReportSection(
            title="Executive Summary",
            narrative="Key findings: 3 new threat actors observed.",
            section_type="narrative",
        ))

        body = gen._extract_email_body_html(result, doc)
        assert "Key findings" in body
        assert "<html" in body.lower()

    def test_no_html_no_doc_returns_empty(self, manager, library_ws, tmp_path):
        """With no HTML file and no doc, returns empty string."""
        from gnat.reports.generator import ReportGenerator

        cfg = ReportConfig(
            report_type="daily", workspaces=["_ctmsak_library"],
            ai_mode=AIMode.NONE, formats=["markdown"],
            delivery=["file"], output_dir=str(tmp_path / "out"),
        )
        gen = ReportGenerator(manager, cfg)
        result = gen.run()
        assert gen._extract_email_body_html(result, None) == ""

    def test_executive_summary_capped_at_2000_chars(self, manager, library_ws, tmp_path):
        """Executive summary is truncated at 2000 characters."""
        from gnat.reports.base import ReportDocument, ReportSection
        from gnat.reports.generator import ReportGenerator

        cfg = ReportConfig(
            report_type="daily", workspaces=["_ctmsak_library"],
            ai_mode=AIMode.NONE, formats=["markdown"],
            delivery=["file"], output_dir=str(tmp_path / "out"),
        )
        gen = ReportGenerator(manager, cfg)
        result = gen.run()

        long_narrative = "x" * 5000
        _now = result.generated_at
        doc = ReportDocument(
            title="Daily Report", report_type="daily",
            generated_at=_now, period_start=_now, period_end=_now,
        )
        doc.add_section(ReportSection(
            title="Executive Summary",
            narrative=long_narrative,
            section_type="narrative",
        ))
        body = gen._extract_email_body_html(result, doc)
        # The snippet is capped at 2000 chars before HTML wrapping
        assert long_narrative[:2000] in body
        assert long_narrative[2001:] not in body
