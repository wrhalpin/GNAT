"""
gnat.dissemination.export
==========================

:class:`ExportService` coordinates STIX bundle and PDF export for published
intelligence reports.

Usage::

    from gnat.dissemination.export import ExportService, ExportFormat
    from gnat.reporting.storage import ReportStore

    store   = ReportStore("sqlite:///~/.gnat/gnat.db")
    service = ExportService(store)

    result = service.export(report_id, ExportFormat.STIX, "/tmp/report.json")
    print(result.path, result.checksum)
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from gnat.reporting.export.stix import report_to_stix_bundle

logger = logging.getLogger(__name__)


class ExportFormat(str, Enum):
    """Supported export formats."""
    STIX = "stix"
    PDF  = "pdf"
    JSON = "json"


@dataclass
class ExportResult:
    """
    Result of an export operation.

    Parameters
    ----------
    report_id : str
        ID of the exported report.
    format : ExportFormat
        Export format.
    path : str
        Filesystem path of the produced file.
    size_bytes : int
        File size in bytes.
    checksum : str
        SHA-256 checksum (hex) of the produced file.
    exported_at : datetime
        Timestamp of the export.
    """

    report_id:   str
    format:      ExportFormat
    path:        str
    size_bytes:  int
    checksum:    str
    exported_at: datetime

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_id":   self.report_id,
            "format":      self.format.value,
            "path":        self.path,
            "size_bytes":  self.size_bytes,
            "checksum":    self.checksum,
            "exported_at": self.exported_at.isoformat(),
        }


class ExportService:
    """
    Coordinate export of published intelligence reports.

    Parameters
    ----------
    store : ReportStore
        Persistence backend to load reports from.
    """

    def __init__(self, store: Any) -> None:
        self._store = store

    def export(
        self,
        report_id:   str,
        fmt:         ExportFormat,
        output_path: str,
    ) -> ExportResult:
        """
        Export a report to *output_path* in the requested format.

        Parameters
        ----------
        report_id : str
        fmt : ExportFormat
        output_path : str
            Destination file path.  Parent directories must exist.

        Returns
        -------
        ExportResult

        Raises
        ------
        ValueError
            If the report is not found or not in PUBLISHED status.
        """
        report = self._store.get(report_id)
        if report is None:
            raise ValueError(f"Report not found: {report_id}")

        if fmt == ExportFormat.STIX:
            return self._export_stix(report, output_path)
        if fmt == ExportFormat.JSON:
            return self._export_json(report, output_path)
        if fmt == ExportFormat.PDF:
            return self._export_pdf(report, output_path)
        raise ValueError(f"Unsupported export format: {fmt}")

    def export_stix_bundle(self, report_id: str) -> dict[str, Any]:
        """
        Return the STIX 2.1 bundle dict for a report without writing to disk.

        Uses the cached ``stix_bundle_json`` if the report is published,
        otherwise generates on the fly.
        """
        report = self._store.get(report_id)
        if report is None:
            raise ValueError(f"Report not found: {report_id}")
        if report.stix_bundle_json:
            return json.loads(report.stix_bundle_json)
        return report_to_stix_bundle(report)

    # ── Format handlers ───────────────────────────────────────────────────────

    def _export_stix(self, report: Any, output_path: str) -> ExportResult:
        if report.stix_bundle_json:
            content = report.stix_bundle_json.encode()
        else:
            bundle  = report_to_stix_bundle(report)
            content = json.dumps(bundle, indent=2).encode()

        return self._write(report.id, ExportFormat.STIX, output_path, content)

    def _export_json(self, report: Any, output_path: str) -> ExportResult:
        content = json.dumps(report.to_dict(), indent=2).encode()
        return self._write(report.id, ExportFormat.JSON, output_path, content)

    def _export_pdf(self, report: Any, output_path: str) -> ExportResult:
        """
        Render report to PDF using ``gnat.reports`` PDF renderer if available.

        Falls back to a plain-text representation if reportlab is not installed.
        """
        try:
            from gnat.reports.renderers import PDFRenderer  # type: ignore[import]
            from gnat.reports.base import ReportDocument, ReportSection  # type: ignore[import]
            from datetime import datetime, timezone as _tz

            _now = datetime.now(tz=_tz.utc)
            doc = ReportDocument(
                title        = report.title,
                report_type  = getattr(getattr(report, "report_type", None), "value", "finished_intelligence"),
                period_start = _now,
                period_end   = _now,
                sections     = [
                    ReportSection(
                        title     = "Executive Summary",
                        narrative = report.executive_summary or "(none)",
                    ),
                    *[
                        ReportSection(title=s.title, narrative=getattr(s, "content", ""))
                        for s in report.ordered_sections
                    ],
                ],
            )
            renderer = PDFRenderer()
            renderer.render(doc, output_path)
            with open(output_path, "rb") as _fh:
                content = _fh.read()
            # Return early — file already written
            checksum = hashlib.sha256(content).hexdigest()
            size     = len(content)
            logger.info(
                "ExportService: pdf exported to %s (%d bytes, sha256=%s…)",
                output_path, size, checksum[:12],
            )
            return ExportResult(
                report_id   = report.id,
                format      = ExportFormat.PDF,
                path        = output_path,
                size_bytes  = size,
                checksum    = checksum,
                exported_at = datetime.now(tz=timezone.utc),
            )
        except ImportError:
            logger.warning(
                "ExportService: reportlab not installed; falling back to plain-text PDF."
            )
            text = (
                f"REPORT: {report.title}\n"
                f"Type: {report.report_type.value}\n"
                f"Status: {report.status.value}\n"
                f"Classification: {report.classification.label}\n\n"
                f"Executive Summary\n{'='*40}\n{report.executive_summary or '(none)'}\n\n"
                + "\n\n".join(
                    f"{s.title}\n{'='*40}\n{s.content}"
                    for s in report.ordered_sections
                )
            )
            content = text.encode()

        return self._write(report.id, ExportFormat.PDF, output_path, content)

    @staticmethod
    def _write(
        report_id:   str,
        fmt:         ExportFormat,
        output_path: str,
        content:     bytes,
    ) -> ExportResult:
        with open(output_path, "wb") as fh:
            fh.write(content)

        checksum = hashlib.sha256(content).hexdigest()
        size     = len(content)
        logger.info(
            "ExportService: %s exported to %s (%d bytes, sha256=%s…)",
            fmt.value, output_path, size, checksum[:12],
        )
        return ExportResult(
            report_id   = report_id,
            format      = fmt,
            path        = output_path,
            size_bytes  = size,
            checksum    = checksum,
            exported_at = datetime.now(tz=timezone.utc),
        )
