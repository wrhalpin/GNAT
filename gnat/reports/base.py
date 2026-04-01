"""
gnat.reports.base
=====================

Shared foundations for all GNAT report types.

Key types
---------
:class:`AIMode`
    Three-value enum controlling AI involvement per report.

:class:`ReportConfig`
    Full configuration for one report generation run — workspaces,
    sector filter, AI mode, output formats, scheduling, delivery.
    Loaded from INI ``[report.<name>]`` sections.

:class:`ReportSection`
    A named section of a report with a title, data payload (computed
    by the aggregator), and optional AI-generated narrative.

:class:`ReportDocument`
    The assembled report — ordered list of sections plus metadata.

:class:`ReportResult`
    Outcome of one report generation run, carried by ``RunRecord.result``.

:class:`SectorFilter`
    Filters STIX objects by the canonical ``x_target_sectors`` field,
    with alias expansion for cross-platform normalisation.

INI configuration
-----------------
::

    [report.daily_healthcare]
    report_type    = daily
    workspaces     = _ctmsak_library, analyst-workspace
    sectors        = Healthcare, Insurance, Hospitals and Health Centers, Opportunistic
    sector_match   = any
    ai_mode        = assisted
    formats        = pdf, html, markdown
    delivery       = email, sharepoint
    email_to       = soc-team@example.com
    sharepoint_url = https://contoso.sharepoint.com/sites/Security/ThreatReports
    schedule       = 0 6 * * *   # 06:00 daily

    [sector_aliases]
    healthcare = Healthcare, Health, Medical, H-ISAC, Hospitals and Health Centers
    financial  = Financial Services, Finance, Banking, FS-ISAC

    [report.yearly_internal]
    report_type  = yearly
    workspaces   = _ctmsak_library
    ai_mode      = full
    formats      = pdf, docx
    delivery     = sharepoint
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from gnat.orm.base import STIXBase


# ---------------------------------------------------------------------------
# AIMode
# ---------------------------------------------------------------------------


class AIMode(enum.Enum):
    """
    Controls how much Claude is involved in report generation.

    none
        Pure data report. No Claude API calls. Tables, counts, lists only.
        Fast, cheap, deterministic. Good for daily operational reports.

    assisted
        Claude writes specific narrative sections (executive summary,
        key findings, recommendations). Data tables are generated directly
        from aggregates. Good default for most reports.

    full
        Claude writes all prose; data tables appear as appendices.
        Best for yearly strategic reports where narrative coherence matters
        more than raw data density.
    """

    NONE = "none"
    ASSISTED = "assisted"
    FULL = "full"


# ---------------------------------------------------------------------------
# ReportConfig
# ---------------------------------------------------------------------------


@dataclass
class ReportConfig:
    """
    Complete configuration for one report generation run.

    Parameters
    ----------
    report_type : str
        One of ``"daily"``, ``"trends"``, ``"yearly"``.
    workspaces : list of str
        Workspace names to draw data from.  ``"_ctmsak_library"`` is the
        typical primary source.
    ai_mode : AIMode
        Level of AI involvement.  Default ``AIMode.ASSISTED``.
    sectors : list of str
        Sector strings to filter by.  Empty list = no sector filter.
    sector_match : str
        ``"any"`` (default) or ``"all"``.
        ``"any"`` includes objects tagged with at least one listed sector.
        ``"all"`` requires all listed sectors to be present.
    sector_strict : bool
        If ``True``, only objects explicitly tagged with a sector are
        included.  If ``False`` (default), untagged objects are also
        included alongside tagged ones.
    formats : list of str
        Output formats: any combination of ``"pdf"``, ``"html"``,
        ``"markdown"``, ``"docx"``.
    delivery : list of str
        Delivery targets: any combination of ``"email"``, ``"sharepoint"``,
        ``"file"``.
    email_to : list of str
        Recipient addresses for email delivery.
    email_subject : str
        Email subject template.  ``{report_type}`` and ``{date}`` are
        substituted at render time.
    sharepoint_url : str
        SharePoint library URL for document upload.
    output_dir : str
        Local directory for file delivery.  Default ``"./reports"``.
    schedule : str
        Cron expression for scheduled generation.  Empty string = manual only.
    window_days : int
        Number of days of data to include.  For daily = 1, trends = 30 or
        90, yearly = 365.  Default inferred from ``report_type``.
    use_research_library : bool
        If ``True``, the AI synthesiser can query the research library for
        relevant entries when writing narrative sections.  Default ``True``.
    title : str
        Report title.  Auto-generated from type and date if omitted.
    org_name : str
        Organisation name included in report header and AI prompts.
    config_name : str
        INI section name this config was loaded from.
    """

    report_type: str
    workspaces: list[str] = field(default_factory=lambda: ["_ctmsak_library"])
    ai_mode: AIMode = AIMode.ASSISTED
    sectors: list[str] = field(default_factory=list)
    sector_match: str = "any"
    sector_strict: bool = False
    formats: list[str] = field(default_factory=lambda: ["pdf", "html"])
    delivery: list[str] = field(default_factory=lambda: ["file"])
    email_to: list[str] = field(default_factory=list)
    email_subject: str = "{report_type} Threat Intelligence Report — {date}"
    sharepoint_url: str = ""
    output_dir: str = "./reports"
    schedule: str = ""
    window_days: int | None = None
    use_research_library: bool = True
    title: str = ""
    org_name: str = ""
    config_name: str = ""

    def __post_init__(self) -> None:
        if self.window_days is None:
            self.window_days = {
                "daily": 1,
                "trends": 30,
                "yearly": 365,
            }.get(self.report_type, 30)

    @classmethod
    def from_ini(cls, section_name: str, config_path: str | None = None) -> ReportConfig:
        """
        Load a ``ReportConfig`` from a ``[report.<name>]`` INI section.

        Parameters
        ----------
        section_name : str
            INI section name, e.g. ``"report.daily_healthcare"``.
        config_path : str, optional
            Explicit path to config.ini.
        """
        from gnat.config import GNATConfig

        cfg = GNATConfig(config_path)
        try:
            s = cfg.get(section_name)
        except KeyError:
            raise KeyError(
                f"No [{section_name}] section in config.ini. "
                "Add a [report.<name>] section — see module docstring for format."
            )

        def _list(key: str, sep: str = ",") -> list[str]:
            raw = s.get(key, "")
            return [v.strip() for v in raw.split(sep) if v.strip()] if raw else []

        ai_raw = s.get("ai_mode", "assisted").lower()
        ai_mode = {
            "none": AIMode.NONE,
            "assisted": AIMode.ASSISTED,
            "full": AIMode.FULL,
        }.get(ai_raw, AIMode.ASSISTED)

        return cls(
            report_type=s.get("report_type", "daily"),
            workspaces=_list("workspaces") or ["_ctmsak_library"],
            ai_mode=ai_mode,
            sectors=_list("sectors"),
            sector_match=s.get("sector_match", "any").lower(),
            sector_strict=s.get("sector_strict", "false").lower() == "true",
            formats=_list("formats") or ["pdf", "html"],
            delivery=_list("delivery") or ["file"],
            email_to=_list("email_to"),
            email_subject=s.get(
                "email_subject", "{report_type} Threat Intelligence Report — {date}"
            ),
            sharepoint_url=s.get("sharepoint_url", ""),
            output_dir=s.get("output_dir", "./reports"),
            schedule=s.get("schedule", ""),
            window_days=int(s.get("window_days", 0)) or None,
            use_research_library=s.get("use_research_library", "true").lower() == "true",
            title=s.get("title", ""),
            org_name=s.get("org_name", ""),
            config_name=section_name,
        )


# ---------------------------------------------------------------------------
# SectorFilter — canonical location is gnat.export.filters; re-exported here
# ---------------------------------------------------------------------------

from gnat.export.filters import SectorFilter as _SectorFilter  # noqa: E402


class SectorFilter(_SectorFilter):
    """
    Filters STIX objects by the canonical ``x_target_sectors`` field.

    This class lives in :mod:`gnat.export.filters` and is re-exported here
    for backwards compatibility.  Prefer importing from the export module
    directly when using in export pipelines.

    Adds :meth:`apply` (list → list) and :meth:`from_config` helpers
    that are specific to the report layer.
    """

    def apply(self, objects: list[STIXBase]) -> list[STIXBase]:
        """Return objects that pass the sector filter (list interface)."""
        return list(self(iter(objects)))

    @classmethod
    def from_config(cls, config: ReportConfig, ini_config_path: str | None = None) -> SectorFilter:
        """Construct from a ``ReportConfig``, loading aliases from INI."""
        return cls.from_ini(
            ini_config_path=ini_config_path,
            sectors=config.sectors,
            match=config.sector_match,
            strict=config.sector_strict,
        )


# ---------------------------------------------------------------------------
# Report document structure
# ---------------------------------------------------------------------------


@dataclass
class ReportSection:
    """
    A single named section in a report.

    Parameters
    ----------
    title : str
        Section heading.
    data : dict
        Computed data payload from the aggregator (counts, lists, etc.).
        Always present regardless of AI mode.
    narrative : str
        AI-generated prose for this section.  Empty string if AI mode
        is ``NONE`` or if synthesis failed.
    section_type : str
        Category tag used by renderers: ``"summary"``, ``"table"``,
        ``"chart_data"``, ``"narrative"``, ``"appendix"``.
    order : int
        Rendering order within the document.
    """

    title: str
    data: dict[str, Any] = field(default_factory=dict)
    narrative: str = ""
    section_type: str = "narrative"
    order: int = 0

    @property
    def has_narrative(self) -> bool:
        return bool(self.narrative.strip())

    @property
    def has_data(self) -> bool:
        return bool(self.data)


@dataclass
class ReportDocument:
    """
    The fully assembled report ready for rendering.

    Parameters
    ----------
    title : str
        Full report title.
    report_type : str
        ``"daily"``, ``"trends"``, or ``"yearly"``.
    generated_at : datetime
        UTC generation timestamp.
    period_start : datetime
        Start of the data window.
    period_end : datetime
        End of the data window.
    sections : list of ReportSection
        Ordered content sections.
    config : ReportConfig
        The configuration used to generate this report.
    metadata : dict
        Additional context: total_objects, sector_filter, etc.
    """

    title: str
    report_type: str
    generated_at: datetime
    period_start: datetime
    period_end: datetime
    sections: list[ReportSection] = field(default_factory=list)
    config: ReportConfig | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def add_section(self, section: ReportSection) -> None:
        self.sections.append(section)
        self.sections.sort(key=lambda s: s.order)

    def get_section(self, title: str) -> ReportSection | None:
        for s in self.sections:
            if s.title.lower() == title.lower():
                return s
        return None

    @property
    def has_any_narrative(self) -> bool:
        return any(s.has_narrative for s in self.sections)


# ---------------------------------------------------------------------------
# ReportResult
# ---------------------------------------------------------------------------


@dataclass
class ReportResult:
    """
    Outcome of one report generation run, stored in ``RunRecord.result``.

    Parameters
    ----------
    report_type : str
    title : str
    generated_at : datetime
    objects_analysed : int
        Total STIX objects included in the report.
    sections_generated : int
    ai_calls_made : int
        Number of Claude API calls during synthesis.
    formats_rendered : list of str
        Formats successfully rendered.
    files_written : list of str
        Absolute paths of output files.
    deliveries_sent : list of str
        Description of successful deliveries.
    errors : list of str
    duration_seconds : float
    """

    report_type: str
    title: str
    generated_at: datetime
    objects_analysed: int = 0
    sections_generated: int = 0
    ai_calls_made: int = 0
    formats_rendered: list[str] = field(default_factory=list)
    files_written: list[str] = field(default_factory=list)
    deliveries_sent: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0

    @property
    def success(self) -> bool:
        return len(self.formats_rendered) > 0 and not self.errors

    def __str__(self) -> str:
        status = "OK" if self.success else "PARTIAL"
        return (
            f"ReportResult[{status}] {self.report_type!r}: "
            f"{self.objects_analysed} objects, "
            f"{self.sections_generated} sections, "
            f"{self.ai_calls_made} AI calls, "
            f"formats={self.formats_rendered}, "
            f"{len(self.errors)} errors"
        )


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)
