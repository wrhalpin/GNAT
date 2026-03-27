"""
gnat.reports.aggregator
===========================

:class:`DataAggregator` — computes all facts and statistics from workspace
STIX data.  No AI calls, no rendering.  Pure data extraction.

The aggregator takes one or more workspaces plus a ``ReportConfig`` and
returns a ``ReportAggregates`` dataclass containing everything the
synthesiser and renderers need.  Separating computation from synthesis
ensures that:

* Reports can be generated with ``ai_mode=NONE`` without touching the API.
* AI synthesis receives compact structured data rather than raw STIX blobs.
* Aggregation failures don't affect already-completed synthesis sections.

All time windows are based on ``obj.created`` or ``obj.modified`` fields.
Objects without parseable timestamps are included in totals but excluded
from time-series calculations.
"""

from __future__ import annotations

import logging
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from gnat.context.workspace import Workspace, WorkspaceManager
    from gnat.orm.base import STIXBase
    from gnat.reports.base import ReportConfig, SectorFilter

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# ReportAggregates — the output of DataAggregator
# ---------------------------------------------------------------------------

@dataclass
class ReportAggregates:
    """
    All computed data for a report, ready for synthesis and rendering.

    Fields are populated by :class:`DataAggregator` and consumed by
    :class:`~gnat.reports.synthesizer.ReportSynthesizer` and the
    renderer classes.

    Everything in this class is a plain Python primitive (int, str, list,
    dict) — no STIX objects, no ORM references.  This keeps the contract
    with the AI layer clean and serialisable.
    """

    # Window
    period_start:     datetime  = field(default_factory=lambda: datetime.now(timezone.utc))
    period_end:       datetime  = field(default_factory=lambda: datetime.now(timezone.utc))
    window_days:      int       = 1

    # Volume
    total_objects:     int  = 0
    new_objects:       int  = 0   # first seen within window
    updated_objects:   int  = 0   # modified within window, created before

    # By STIX type
    by_type:           Dict[str, int]       = field(default_factory=dict)
    new_by_type:       Dict[str, int]       = field(default_factory=dict)

    # Indicators
    indicator_count:   int                  = 0
    ioc_by_type:       Dict[str, int]       = field(default_factory=dict)
    top_indicators:    List[Dict[str, Any]] = field(default_factory=list)
    high_conf_indicators: List[Dict[str, Any]] = field(default_factory=list)

    # Threat actors
    actor_count:       int                  = 0
    top_actors:        List[Dict[str, Any]] = field(default_factory=list)
    actor_motivations: Dict[str, int]       = field(default_factory=dict)

    # Vulnerabilities
    vuln_count:        int                  = 0
    critical_vulns:    List[Dict[str, Any]] = field(default_factory=list)
    exploited_vulns:   List[Dict[str, Any]] = field(default_factory=list)
    cvss_distribution: Dict[str, int]       = field(default_factory=dict)

    # Attack patterns / TTPs
    ttp_count:         int                  = 0
    top_ttps:          List[Dict[str, Any]] = field(default_factory=list)
    tactic_distribution: Dict[str, int]     = field(default_factory=dict)

    # Sectors
    sector_distribution: Dict[str, int]     = field(default_factory=dict)
    opportunistic_count: int                = 0

    # Source platforms
    source_breakdown:  Dict[str, int]       = field(default_factory=dict)
    ai_extracted_count: int                 = 0

    # Confidence
    avg_confidence:    float                = 0.0
    confidence_distribution: Dict[str, int] = field(default_factory=dict)

    # Time series (for trends/yearly)
    daily_counts:      List[Dict[str, Any]] = field(default_factory=list)
    weekly_counts:     List[Dict[str, Any]] = field(default_factory=list)
    monthly_counts:    List[Dict[str, Any]] = field(default_factory=list)

    # Trend comparisons (for trends report)
    period_over_period: Dict[str, Any]      = field(default_factory=dict)

    # Research library context (populated by aggregator if available)
    library_entries_count: int              = 0
    library_topics:    List[str]            = field(default_factory=list)

    # Relationships
    relationship_count: int                 = 0
    relationship_types: Dict[str, int]      = field(default_factory=dict)


# ---------------------------------------------------------------------------
# DataAggregator
# ---------------------------------------------------------------------------

class DataAggregator:
    """
    Computes all statistics and facts for a report from workspace data.

    Parameters
    ----------
    manager : WorkspaceManager
        Used to open named workspaces.
    config : ReportConfig
        Report configuration specifying workspaces, window, sectors, etc.
    sector_filter : SectorFilter, optional
        Pre-constructed sector filter.  Built from config if not provided.
    research_library : ResearchLibrary, optional
        If provided, the aggregator also collects library metadata for
        the synthesiser to use as context.

    Examples
    --------
    ::

        aggregator = DataAggregator(manager, config)
        agg = aggregator.run()
        print(agg.total_objects, agg.top_actors)
    """

    def __init__(
        self,
        manager: "WorkspaceManager",
        config: "ReportConfig",
        sector_filter: Optional["SectorFilter"] = None,
        research_library=None,
    ):
        self._manager = manager
        self._config  = config
        self._sf      = sector_filter
        self._lib     = research_library

    def run(self) -> ReportAggregates:
        """Run aggregation and return a populated ``ReportAggregates``."""
        now     = datetime.now(timezone.utc)
        window  = self._config.window_days or 1
        p_end   = now
        p_start = now - timedelta(days=window)

        agg = ReportAggregates(
            period_start = p_start,
            period_end   = p_end,
            window_days  = window,
        )

        # Collect all objects from configured workspaces
        all_objects = self._collect_objects()
        logger.info(
            "DataAggregator: collected %d objects from %d workspaces",
            len(all_objects), len(self._config.workspaces),
        )

        # Apply sector filter
        if self._sf and self._config.sectors:
            all_objects = self._sf.apply(all_objects)
            logger.info(
                "DataAggregator: %d objects after sector filter", len(all_objects)
            )

        if not all_objects:
            return agg

        # Core volume metrics
        self._compute_volume(agg, all_objects, p_start, p_end)

        # By-type breakdown
        self._compute_by_type(agg, all_objects, p_start)

        # Type-specific aggregations
        self._compute_indicators(agg, all_objects)
        self._compute_actors(agg, all_objects)
        self._compute_vulnerabilities(agg, all_objects)
        self._compute_ttps(agg, all_objects)

        # Cross-cutting
        self._compute_sectors(agg, all_objects)
        self._compute_sources(agg, all_objects)
        self._compute_confidence(agg, all_objects)
        self._compute_relationships(agg, all_objects)

        # Time series (only for windows > 2 days)
        if window > 2:
            self._compute_time_series(agg, all_objects, p_start, p_end)

        # Trend comparison (trends report)
        if self._config.report_type == "trends" and window >= 14:
            self._compute_period_over_period(agg, all_objects, p_start, window)

        # Research library context
        if self._lib and self._config.use_research_library:
            self._collect_library_context(agg)

        return agg

    # ── Object collection ──────────────────────────────────────────────────

    def _collect_objects(self) -> List["STIXBase"]:
        """Load all objects from configured workspaces, deduplicated by id."""
        seen: Dict[str, "STIXBase"] = {}
        for ws_name in self._config.workspaces:
            try:
                ws = self._manager.open(ws_name)
                for obj_id, obj in ws.objects.items():
                    if obj_id not in seen:
                        seen[obj_id] = obj
            except Exception as exc:
                logger.warning(
                    "DataAggregator: could not open workspace %r — %s",
                    ws_name, exc,
                )
        return list(seen.values())

    # ── Core metrics ───────────────────────────────────────────────────────

    def _compute_volume(
        self,
        agg: ReportAggregates,
        objects: List["STIXBase"],
        p_start: datetime,
        p_end: datetime,
    ) -> None:
        agg.total_objects = len(objects)
        for obj in objects:
            created  = _parse_dt(obj._properties.get("created"))
            modified = _parse_dt(obj._properties.get("modified"))
            if created and p_start <= created <= p_end:
                agg.new_objects += 1
            elif modified and p_start <= modified <= p_end:
                agg.updated_objects += 1

    def _compute_by_type(
        self,
        agg: ReportAggregates,
        objects: List["STIXBase"],
        p_start: datetime,
    ) -> None:
        total_counter: Counter = Counter()
        new_counter:   Counter = Counter()
        for obj in objects:
            t = obj.stix_type
            total_counter[t] += 1
            created = _parse_dt(obj._properties.get("created"))
            if created and created >= p_start:
                new_counter[t] += 1
        agg.by_type     = dict(total_counter.most_common())
        agg.new_by_type = dict(new_counter.most_common())

    # ── Indicators ─────────────────────────────────────────────────────────

    def _compute_indicators(
        self, agg: ReportAggregates, objects: List["STIXBase"]
    ) -> None:
        indicators = [o for o in objects if o.stix_type == "indicator"]
        agg.indicator_count = len(indicators)
        if not indicators:
            return

        # IOC type from STIX pattern
        ioc_type_counter: Counter = Counter()
        for ind in indicators:
            pattern = ind._properties.get("pattern", "")
            ioc_type = _ioc_type_from_pattern(pattern)
            ioc_type_counter[ioc_type] += 1

        agg.ioc_by_type = dict(ioc_type_counter.most_common())

        # Top indicators by confidence
        sorted_inds = sorted(
            indicators,
            key=lambda o: o._properties.get("confidence", 0),
            reverse=True,
        )
        agg.top_indicators = [_indicator_summary(ind) for ind in sorted_inds[:20]]
        agg.high_conf_indicators = [
            _indicator_summary(ind) for ind in indicators
            if ind._properties.get("confidence", 0) >= 70
        ][:50]

    # ── Threat actors ──────────────────────────────────────────────────────

    def _compute_actors(
        self, agg: ReportAggregates, objects: List["STIXBase"]
    ) -> None:
        actors = [o for o in objects if o.stix_type == "threat-actor"]
        agg.actor_count = len(actors)
        if not actors:
            return

        motivation_counter: Counter = Counter()
        for actor in actors:
            types = actor._properties.get("threat_actor_types", [])
            if isinstance(types, list):
                for t in types:
                    motivation_counter[t] += 1
            elif isinstance(types, str):
                motivation_counter[types] += 1

        agg.actor_motivations = dict(motivation_counter.most_common())

        # Top actors by relationship count (approximate via alias count)
        agg.top_actors = [_actor_summary(a) for a in actors[:20]]

    # ── Vulnerabilities ────────────────────────────────────────────────────

    def _compute_vulnerabilities(
        self, agg: ReportAggregates, objects: List["STIXBase"]
    ) -> None:
        vulns = [o for o in objects if o.stix_type == "vulnerability"]
        agg.vuln_count = len(vulns)
        if not vulns:
            return

        cvss_buckets: Counter = Counter()
        critical: List[Dict] = []
        exploited: List[Dict] = []

        for v in vulns:
            cvss = v._properties.get("x_cvss_score")
            if cvss is not None:
                try:
                    score = float(cvss)
                    bucket = _cvss_bucket(score)
                    cvss_buckets[bucket] += 1
                    if score >= 9.0:
                        critical.append(_vuln_summary(v))
                except (ValueError, TypeError):
                    pass
            if v._properties.get("x_actively_exploited"):
                exploited.append(_vuln_summary(v))

        agg.cvss_distribution = dict(cvss_buckets)
        agg.critical_vulns    = critical[:20]
        agg.exploited_vulns   = exploited[:20]

    # ── TTPs ───────────────────────────────────────────────────────────────

    def _compute_ttps(
        self, agg: ReportAggregates, objects: List["STIXBase"]
    ) -> None:
        ttps = [o for o in objects if o.stix_type == "attack-pattern"]
        agg.ttp_count = len(ttps)
        if not ttps:
            return

        tactic_counter: Counter = Counter()
        for ttp in ttps:
            tactic = ttp._properties.get("x_tactic", "")
            if tactic:
                tactic_counter[tactic] += 1

        agg.tactic_distribution = dict(tactic_counter.most_common())
        agg.top_ttps = [_ttp_summary(t) for t in ttps[:20]]

    # ── Sectors ────────────────────────────────────────────────────────────

    def _compute_sectors(
        self, agg: ReportAggregates, objects: List["STIXBase"]
    ) -> None:
        sector_counter: Counter = Counter()
        for obj in objects:
            sectors = obj._properties.get("x_target_sectors", [])
            if isinstance(sectors, str):
                sectors = [s.strip() for s in sectors.split(",") if s.strip()]
            for s in (sectors or []):
                sector_counter[s] += 1
                if "opportunistic" in s.lower():
                    agg.opportunistic_count += 1

        agg.sector_distribution = dict(sector_counter.most_common())

    # ── Sources ────────────────────────────────────────────────────────────

    def _compute_sources(
        self, agg: ReportAggregates, objects: List["STIXBase"]
    ) -> None:
        source_counter: Counter = Counter()
        ai_count = 0
        for obj in objects:
            source = (
                obj._properties.get("x_source_platform")
                or obj._properties.get("x_enrichment_source")
                or "unknown"
            )
            source_counter[source] += 1
            if obj._properties.get("x_source_type") == "ai_extracted":
                ai_count += 1
        agg.source_breakdown    = dict(source_counter.most_common())
        agg.ai_extracted_count  = ai_count

    # ── Confidence ─────────────────────────────────────────────────────────

    def _compute_confidence(
        self, agg: ReportAggregates, objects: List["STIXBase"]
    ) -> None:
        scores = []
        dist: Counter = Counter()
        for obj in objects:
            conf = obj._properties.get("confidence")
            if conf is not None:
                try:
                    score = float(conf)
                    scores.append(score)
                    dist[_conf_bucket(score)] += 1
                except (ValueError, TypeError):
                    pass
        agg.avg_confidence           = (sum(scores) / len(scores)) if scores else 0.0
        agg.confidence_distribution  = dict(dist)

    # ── Relationships ──────────────────────────────────────────────────────

    def _compute_relationships(
        self, agg: ReportAggregates, objects: List["STIXBase"]
    ) -> None:
        rels = [o for o in objects if o.stix_type == "relationship"]
        agg.relationship_count = len(rels)
        rel_type_counter: Counter = Counter()
        for r in rels:
            rel_type = r._properties.get("relationship_type", "unknown")
            rel_type_counter[rel_type] += 1
        agg.relationship_types = dict(rel_type_counter.most_common())

    # ── Time series ────────────────────────────────────────────────────────

    def _compute_time_series(
        self,
        agg: ReportAggregates,
        objects: List["STIXBase"],
        p_start: datetime,
        p_end: datetime,
    ) -> None:
        """Bucket objects by day and week."""
        daily:   defaultdict = defaultdict(int)
        weekly:  defaultdict = defaultdict(int)
        monthly: defaultdict = defaultdict(int)

        for obj in objects:
            ts = _parse_dt(obj._properties.get("created"))
            if ts is None or ts < p_start or ts > p_end:
                continue
            day_key   = ts.strftime("%Y-%m-%d")
            week_key  = f"{ts.isocalendar()[0]}-W{ts.isocalendar()[1]:02d}"
            month_key = ts.strftime("%Y-%m")
            daily[day_key]    += 1
            weekly[week_key]  += 1
            monthly[month_key]+= 1

        agg.daily_counts   = [{"date": k, "count": v}
                               for k, v in sorted(daily.items())]
        agg.weekly_counts  = [{"week": k, "count": v}
                               for k, v in sorted(weekly.items())]
        agg.monthly_counts = [{"month": k, "count": v}
                               for k, v in sorted(monthly.items())]

    # ── Period-over-period comparison ──────────────────────────────────────

    def _compute_period_over_period(
        self,
        agg: ReportAggregates,
        objects: List["STIXBase"],
        p_start: datetime,
        window: int,
    ) -> None:
        """Compare current window to the prior window of the same length."""
        prior_end   = p_start
        prior_start = p_start - timedelta(days=window)

        def _count_in_window(start: datetime, end: datetime) -> Dict[str, int]:
            counts: Counter = Counter()
            for obj in objects:
                ts = _parse_dt(obj._properties.get("created"))
                if ts and start <= ts <= end:
                    counts[obj.stix_type] += 1
            return dict(counts)

        current = _count_in_window(p_start, datetime.now(timezone.utc))
        prior   = _count_in_window(prior_start, prior_end)
        all_types = set(current) | set(prior)

        changes = {}
        for t in all_types:
            c, p = current.get(t, 0), prior.get(t, 0)
            delta = c - p
            pct   = ((c - p) / p * 100) if p > 0 else (100.0 if c > 0 else 0.0)
            changes[t] = {
                "current": c, "prior": p, "delta": delta, "pct_change": round(pct, 1)
            }

        agg.period_over_period = {
            "current_total": sum(current.values()),
            "prior_total":   sum(prior.values()),
            "by_type":       changes,
            "window_days":   window,
        }

    # ── Research library ──────────────────────────────────────────────────

    def _collect_library_context(self, agg: ReportAggregates) -> None:
        try:
            entries = self._lib.list_entries(include_stale=False)
            agg.library_entries_count = len(entries)
            agg.library_topics = [e["topic"] for e in entries[:20]]
        except Exception as exc:
            logger.warning("DataAggregator: library context error — %s", exc)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_dt(value: Any) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def _ioc_type_from_pattern(pattern: str) -> str:
    p = pattern.lower()
    if "ipv4-addr" in p: return "ipv4"
    if "ipv6-addr" in p: return "ipv6"
    if "domain-name" in p: return "domain"
    if "url:" in p: return "url"
    if "sha-256" in p or "sha256" in p: return "sha256"
    if "sha-1" in p or "sha1" in p: return "sha1"
    if "md5" in p: return "md5"
    if "email-addr" in p: return "email"
    if "file:name" in p: return "filename"
    if "windows-registry" in p: return "registry"
    return "other"


def _cvss_bucket(score: float) -> str:
    if score >= 9.0: return "Critical (9.0-10.0)"
    if score >= 7.0: return "High (7.0-8.9)"
    if score >= 4.0: return "Medium (4.0-6.9)"
    return "Low (0.0-3.9)"


def _conf_bucket(score: float) -> str:
    if score >= 80: return "High (80-100)"
    if score >= 50: return "Medium (50-79)"
    return "Low (0-49)"


def _indicator_summary(obj: "STIXBase") -> Dict[str, Any]:
    return {
        "name":       obj._properties.get("name", ""),
        "pattern":    obj._properties.get("pattern", "")[:120],
        "confidence": obj._properties.get("confidence", 0),
        "ioc_type":   _ioc_type_from_pattern(obj._properties.get("pattern", "")),
        "source":     obj._properties.get("x_source_platform", ""),
    }


def _actor_summary(obj: "STIXBase") -> Dict[str, Any]:
    return {
        "name":        obj._properties.get("name", ""),
        "aliases":     obj._properties.get("aliases", [])[:5],
        "motivation":  obj._properties.get("threat_actor_types", ["unknown"]),
        "description": (obj._properties.get("description", "") or "")[:200],
    }


def _vuln_summary(obj: "STIXBase") -> Dict[str, Any]:
    return {
        "name":       obj._properties.get("name", ""),
        "cve_id":     obj._properties.get("x_cve_id", ""),
        "cvss":       obj._properties.get("x_cvss_score"),
        "exploited":  obj._properties.get("x_actively_exploited", False),
        "description": (obj._properties.get("description", "") or "")[:200],
    }


def _ttp_summary(obj: "STIXBase") -> Dict[str, Any]:
    return {
        "name":     obj._properties.get("name", ""),
        "mitre_id": obj._properties.get("x_mitre_id", ""),
        "tactic":   obj._properties.get("x_tactic", ""),
        "description": (obj._properties.get("description", "") or "")[:200],
    }
