"""
Unit tests for gnat.dissemination.export
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from gnat.dissemination.export import ExportFormat, ExportResult, ExportService

# ── Fixtures ──────────────────────────────────────────────────────────────────


def _make_report(
    report_id: str = "rpt-001",
    title: str = "Test Report",
    status: str = "published",
    stix_bundle_json: str | None = None,
    executive_summary: str = "Executive summary text.",
) -> MagicMock:
    r = MagicMock()
    r.id = report_id
    r.title = title
    r.status = MagicMock(value=status)
    r.report_type = MagicMock(value="incident")
    r.classification = MagicMock(label="amber")
    r.stix_bundle_json = stix_bundle_json
    r.executive_summary = executive_summary
    r.ordered_sections = []
    r.to_dict = lambda: {"id": report_id, "title": title, "status": status}
    return r


def _make_store(report: MagicMock | None = None) -> MagicMock:
    store = MagicMock()
    store.get = lambda rid: report if (report and report.id == rid) else None
    return store


class TestExportFormat:
    def test_values(self):
        assert ExportFormat.STIX.value == "stix"
        assert ExportFormat.PDF.value == "pdf"
        assert ExportFormat.JSON.value == "json"


class TestExportResult:
    def test_to_dict(self):
        result = ExportResult(
            report_id="r1",
            format=ExportFormat.STIX,
            path="/tmp/out.json",
            size_bytes=1024,
            checksum="abc123",
            exported_at=datetime(2025, 1, 1, tzinfo=timezone.utc),
        )
        d = result.to_dict()
        assert d["report_id"] == "r1"
        assert d["format"] == "stix"
        assert d["size_bytes"] == 1024
        assert d["checksum"] == "abc123"
        assert "exported_at" in d


class TestExportService:
    def test_export_not_found_raises(self):
        store = _make_store(None)
        service = ExportService(store)
        with (
            pytest.raises(ValueError, match="not found"),
            tempfile.NamedTemporaryFile(delete=False) as f,
        ):
            service.export("missing-id", ExportFormat.JSON, f.name)

    def test_export_json(self):
        report = _make_report()
        store = _make_store(report)
        service = ExportService(store)
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            tmp = f.name
        try:
            result = service.export("rpt-001", ExportFormat.JSON, tmp)
            assert result.format == ExportFormat.JSON
            assert result.size_bytes > 0
            assert len(result.checksum) == 64  # SHA-256 hex
            assert os.path.exists(tmp)
        finally:
            os.unlink(tmp)

    def test_export_stix_uses_cached_bundle(self):
        bundle = {"type": "bundle", "id": "bundle--x", "objects": []}
        report = _make_report(stix_bundle_json=json.dumps(bundle))
        store = _make_store(report)
        service = ExportService(store)
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            tmp = f.name
        try:
            result = service.export("rpt-001", ExportFormat.STIX, tmp)
            assert result.format == ExportFormat.STIX
            content = Path(tmp).read_text()
            assert "bundle" in content
        finally:
            os.unlink(tmp)

    def test_export_stix_generates_when_no_cache(self):
        report = _make_report(stix_bundle_json=None)
        store = _make_store(report)
        service = ExportService(store)
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            tmp = f.name
        try:
            with patch(
                "gnat.dissemination.export.report_to_stix_bundle",
                return_value={"type": "bundle", "id": "b-1", "objects": []},
            ):
                result = service.export("rpt-001", ExportFormat.STIX, tmp)
            assert result.format == ExportFormat.STIX
        finally:
            os.unlink(tmp)

    def test_export_pdf_fallback(self):
        report = _make_report()
        store = _make_store(report)
        service = ExportService(store)
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
            tmp = f.name
        try:
            result = service.export("rpt-001", ExportFormat.PDF, tmp)
            assert result.format == ExportFormat.PDF
            assert result.size_bytes > 0
        finally:
            os.unlink(tmp)

    def test_export_checksum_matches_file(self):
        import hashlib

        report = _make_report()
        store = _make_store(report)
        service = ExportService(store)
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            tmp = f.name
        try:
            result = service.export("rpt-001", ExportFormat.JSON, tmp)
            with open(tmp, "rb") as fh:
                actual_checksum = hashlib.sha256(fh.read()).hexdigest()
            assert result.checksum == actual_checksum
        finally:
            os.unlink(tmp)

    def test_export_unsupported_format_raises(self):
        report = _make_report()
        store = _make_store(report)
        service = ExportService(store)
        with tempfile.NamedTemporaryFile(delete=False) as f:
            tmp = f.name
        try:
            with pytest.raises((ValueError, AttributeError)):
                service.export("rpt-001", "xml", tmp)  # type: ignore[arg-type]
        finally:
            import contextlib

            with contextlib.suppress(Exception):
                os.unlink(tmp)

    def test_export_stix_bundle_in_memory(self):
        bundle = {"type": "bundle", "id": "b-1", "objects": []}
        report = _make_report(stix_bundle_json=json.dumps(bundle))
        store = _make_store(report)
        service = ExportService(store)
        result = service.export_stix_bundle("rpt-001")
        assert result["type"] == "bundle"

    def test_export_stix_bundle_not_found(self):
        store = _make_store(None)
        service = ExportService(store)
        with pytest.raises(ValueError, match="not found"):
            service.export_stix_bundle("no-such-id")

    def test_export_stix_bundle_generates_when_no_cache(self):
        report = _make_report(stix_bundle_json=None)
        store = _make_store(report)
        service = ExportService(store)
        with patch(
            "gnat.dissemination.export.report_to_stix_bundle",
            return_value={"type": "bundle", "id": "b-gen", "objects": []},
        ):
            result = service.export_stix_bundle("rpt-001")
        assert result["id"] == "b-gen"
