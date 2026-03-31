"""
gnat.reports.synthesizer
============================

:class:`ReportSynthesizer` — AI narrative generation for report sections.

Architecture
------------
The synthesiser makes one focused Claude API call per section rather than
one large call for the whole report.  This means:

* Failures are section-scoped — one bad API call doesn't abort the report.
* Each section receives only the aggregates relevant to it — keeping
  prompts small and focused produces better output than large blobs.
* Sections can be retried independently.
* ``AIMode.ASSISTED`` generates only the high-value narrative sections;
  ``AIMode.FULL`` generates prose for every section.

Research library context
------------------------
If a ``ResearchLibrary`` is provided and the aggregation found relevant
topics, the synthesiser queries the library for matching entries and
includes analyst notes in the relevant section prompts.  This makes the
narrative more specific — Claude can reference "the APT29 research entry
from March noted new C2 infrastructure" rather than writing generic prose.

All prompts instruct Claude to return plain prose — no JSON, no markdown
headers, no bullet lists unless explicitly appropriate.  The renderers
handle all document structure.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from gnat.agents.base import AgentConfig
    from gnat.reports.aggregator import ReportAggregates
    from gnat.reports.base import ReportConfig, ReportSection

logger = logging.getLogger(__name__)

# Maximum chars of library context to include per section
_MAX_LIB_CONTEXT = 2000


class ReportSynthesizer:
    """
    Generates AI narrative for each report section.

    Parameters
    ----------
    config : ReportConfig
        Report configuration.
    agent_config : AgentConfig
        Claude API configuration.
    research_library : ResearchLibrary, optional
        If provided, relevant research entries are included in prompts.

    Examples
    --------
    ::

        from gnat.agents import AgentConfig
        from gnat.reports.synthesizer import ReportSynthesizer

        synth = ReportSynthesizer(config, AgentConfig.from_ini())
        sections = synth.synthesize(agg, report_type="daily")
        for s in sections:
            print(s.title, "—", s.narrative[:100])
    """

    def __init__(
        self,
        config: ReportConfig,
        agent_config: AgentConfig,
        research_library=None,
    ):
        self._config = config
        self._acfg   = agent_config
        self._lib    = research_library
        self._calls  = 0
        # Import here to avoid circular at module level
        from gnat.agents.base import ClaudeClient
        self._client = ClaudeClient(agent_config)

    @property
    def calls_made(self) -> int:
        return self._calls

    # ── Public API ─────────────────────────────────────────────────────────

    def synthesize(
        self,
        agg: ReportAggregates,
        report_type: str,
    ) -> list[ReportSection]:
        """
        Generate all narrative sections for a report.

        Parameters
        ----------
        agg : ReportAggregates
            Computed data aggregates.
        report_type : str
            ``"daily"``, ``"trends"``, or ``"yearly"``.

        Returns
        -------
        list of ReportSection
            Sections with ``narrative`` populated.
        """

        sections: list[ReportSection] = []

        if report_type == "daily":
            sections = self._synthesize_daily(agg)
        elif report_type == "trends":
            sections = self._synthesize_trends(agg)
        elif report_type == "yearly":
            sections = self._synthesize_yearly(agg)

        return sections

    # ── Daily synthesis ────────────────────────────────────────────────────

    def _synthesize_daily(
        self, agg: ReportAggregates
    ) -> list[ReportSection]:
        from gnat.reports.base import ReportSection

        sections = []

        # Executive summary — always generated in assisted/full mode
        summary = self._call(
            section_title="Executive Summary",
            system=self._system_prompt("daily analyst"),
            user=self._daily_summary_prompt(agg),
        )
        sections.append(ReportSection(
            title="Executive Summary",
            data={"total_new": agg.new_objects,
                  "total_updated": agg.updated_objects,
                  "period": f"{agg.window_days}d"},
            narrative=summary,
            section_type="summary",
            order=1,
        ))

        # Threat highlights — only if there's something notable
        if agg.critical_vulns or agg.exploited_vulns or agg.top_actors:
            highlights = self._call(
                section_title="Threat Highlights",
                system=self._system_prompt("daily analyst"),
                user=self._threat_highlights_prompt(agg),
            )
            sections.append(ReportSection(
                title="Threat Highlights",
                data={
                    "critical_vulns": agg.critical_vulns[:5],
                    "exploited_vulns": agg.exploited_vulns[:5],
                    "top_actors": agg.top_actors[:5],
                },
                narrative=highlights,
                section_type="narrative",
                order=2,
            ))

        # Recommended actions — full mode only
        if self._config.ai_mode.value == "full":
            actions = self._call(
                section_title="Recommended Actions",
                system=self._system_prompt("daily analyst"),
                user=self._recommendations_prompt(agg, report_type="daily"),
            )
            sections.append(ReportSection(
                title="Recommended Actions",
                data={},
                narrative=actions,
                section_type="narrative",
                order=9,
            ))

        return sections

    # ── Trends synthesis ───────────────────────────────────────────────────

    def _synthesize_trends(
        self, agg: ReportAggregates
    ) -> list[ReportSection]:
        from gnat.reports.base import ReportSection
        sections = []

        # Executive summary
        summary = self._call(
            section_title="Trends Summary",
            system=self._system_prompt("trends analyst"),
            user=self._trends_summary_prompt(agg),
        )
        sections.append(ReportSection(
            title="Trends Summary",
            data={"period_over_period": agg.period_over_period,
                  "window_days": agg.window_days},
            narrative=summary,
            section_type="summary",
            order=1,
        ))

        # Threat actor trends
        if agg.actor_count > 0:
            lib_ctx = self._library_context(agg.top_actors[:5])
            actor_trends = self._call(
                section_title="Threat Actor Activity",
                system=self._system_prompt("trends analyst"),
                user=self._actor_trends_prompt(agg, lib_ctx),
            )
            sections.append(ReportSection(
                title="Threat Actor Activity",
                data={"top_actors": agg.top_actors[:10],
                      "motivations": agg.actor_motivations},
                narrative=actor_trends,
                section_type="narrative",
                order=3,
            ))

        # Vulnerability trends
        if agg.vuln_count > 0:
            vuln_trends = self._call(
                section_title="Vulnerability Landscape",
                system=self._system_prompt("trends analyst"),
                user=self._vuln_trends_prompt(agg),
            )
            sections.append(ReportSection(
                title="Vulnerability Landscape",
                data={"critical_count": len(agg.critical_vulns),
                      "exploited_count": len(agg.exploited_vulns),
                      "critical_vulns": agg.critical_vulns[:10],
                      "cvss_distribution": agg.cvss_distribution},
                narrative=vuln_trends,
                section_type="narrative",
                order=4,
            ))

        # Sector targeting
        if agg.sector_distribution:
            sector_analysis = self._call(
                section_title="Sector Targeting",
                system=self._system_prompt("trends analyst"),
                user=self._sector_trends_prompt(agg),
            )
            sections.append(ReportSection(
                title="Sector Targeting",
                data={"sector_distribution": agg.sector_distribution,
                      "opportunistic_count": agg.opportunistic_count},
                narrative=sector_analysis,
                section_type="narrative",
                order=5,
            ))

        # Recommendations
        recommendations = self._call(
            section_title="Recommendations",
            system=self._system_prompt("trends analyst"),
            user=self._recommendations_prompt(agg, report_type="trends"),
        )
        sections.append(ReportSection(
            title="Recommendations",
            data={},
            narrative=recommendations,
            section_type="narrative",
            order=9,
        ))

        return sections

    # ── Yearly synthesis ───────────────────────────────────────────────────

    def _synthesize_yearly(
        self, agg: ReportAggregates
    ) -> list[ReportSection]:
        from gnat.reports.base import ReportSection
        sections = []

        # Year in review — top-level narrative
        year_review = self._call(
            section_title="Year in Review",
            system=self._system_prompt("strategic executive"),
            user=self._year_in_review_prompt(agg),
        )
        sections.append(ReportSection(
            title="Year in Review",
            data={"total_objects": agg.total_objects,
                  "by_type": agg.by_type,
                  "monthly_counts": agg.monthly_counts},
            narrative=year_review,
            section_type="summary",
            order=1,
        ))

        # Threat landscape
        lib_ctx = self._library_context(agg.top_actors[:8])
        threat_landscape = self._call(
            section_title="Threat Landscape",
            system=self._system_prompt("strategic executive"),
            user=self._threat_landscape_prompt(agg, lib_ctx),
        )
        sections.append(ReportSection(
            title="Threat Landscape",
            data={"top_actors": agg.top_actors[:10],
                  "top_ttps": agg.top_ttps[:10],
                  "tactic_distribution": agg.tactic_distribution},
            narrative=threat_landscape,
            section_type="narrative",
            order=2,
        ))

        # Vulnerability year
        if agg.vuln_count > 0:
            vuln_year = self._call(
                section_title="Vulnerability Year in Review",
                system=self._system_prompt("strategic executive"),
                user=self._vuln_year_prompt(agg),
            )
            sections.append(ReportSection(
                title="Vulnerability Year in Review",
                data={"total_vulns": agg.vuln_count,
                      "critical_count": len(agg.critical_vulns),
                      "exploited_count": len(agg.exploited_vulns),
                      "cvss_distribution": agg.cvss_distribution,
                      "exploited_vulns": agg.exploited_vulns[:15]},
                narrative=vuln_year,
                section_type="narrative",
                order=3,
            ))

        # Sector analysis
        if agg.sector_distribution:
            sector_year = self._call(
                section_title="Sector Targeting Analysis",
                system=self._system_prompt("strategic executive"),
                user=self._sector_year_prompt(agg),
            )
            sections.append(ReportSection(
                title="Sector Targeting Analysis",
                data={"sector_distribution": agg.sector_distribution,
                      "opportunistic_count": agg.opportunistic_count},
                narrative=sector_year,
                section_type="narrative",
                order=4,
            ))

        # Intelligence programme performance
        programme = self._call(
            section_title="Intelligence Programme Performance",
            system=self._system_prompt("strategic executive"),
            user=self._programme_performance_prompt(agg),
        )
        sections.append(ReportSection(
            title="Intelligence Programme Performance",
            data={"source_breakdown": agg.source_breakdown,
                  "ai_extracted_count": agg.ai_extracted_count,
                  "avg_confidence": round(agg.avg_confidence, 1),
                  "confidence_distribution": agg.confidence_distribution,
                  "library_entries": agg.library_entries_count},
            narrative=programme,
            section_type="narrative",
            order=5,
        ))

        # Strategic recommendations
        strategic_rec = self._call(
            section_title="Strategic Recommendations",
            system=self._system_prompt("strategic executive"),
            user=self._recommendations_prompt(agg, report_type="yearly"),
        )
        sections.append(ReportSection(
            title="Strategic Recommendations",
            data={},
            narrative=strategic_rec,
            section_type="narrative",
            order=9,
        ))

        return sections

    # ── Claude API call ────────────────────────────────────────────────────

    def _call(
        self,
        section_title: str,
        system: str,
        user: str,
    ) -> str:
        """
        Make one Claude API call for a section.

        Returns the narrative text, or an empty string on error.
        """
        try:
            response = self._client.complete(
                system=system,
                user=user,
                temperature=0.3,
            )
            self._calls += 1
            text = self._client.text_from(response)
            logger.debug(
                "ReportSynthesizer: section %r — %d chars", section_title, len(text)
            )
            return text.strip()
        except RuntimeError as exc:
            logger.error(
                "ReportSynthesizer: API error for section %r — %s",
                section_title, exc,
            )
            return ""

    # ── System prompts ─────────────────────────────────────────────────────

    def _system_prompt(self, audience: str) -> str:
        org = f" for {self._config.org_name}" if self._config.org_name else ""
        sector_ctx = ""
        if self._config.sectors:
            sector_ctx = (
                f"\nThis report focuses on threats targeting the following "
                f"sectors: {', '.join(self._config.sectors)}."
            )
        return (
            f"You are a senior threat intelligence analyst writing a "
            f"professional intelligence report{org} for a {audience} audience."
            f"{sector_ctx}\n\n"
            "Write in clear, professional prose. Be specific and actionable. "
            "Do not use headers, bullet lists, or markdown formatting — "
            "write flowing paragraphs only. Do not pad with generic filler. "
            "If data is limited, say so concisely rather than fabricating detail."
        )

    # ── User prompts ───────────────────────────────────────────────────────

    def _daily_summary_prompt(self, agg: ReportAggregates) -> str:
        return (
            f"Write a concise executive summary (2-3 paragraphs) for a "
            f"daily threat intelligence report covering the last "
            f"{agg.window_days} day(s).\n\n"
            f"Data:\n"
            f"- New objects added: {agg.new_objects}\n"
            f"- Updated objects: {agg.updated_objects}\n"
            f"- Total indicators: {agg.indicator_count} "
            f"(IOC types: {_fmt_dict(agg.ioc_by_type, top=4)})\n"
            f"- Threat actors: {agg.actor_count}\n"
            f"- Vulnerabilities: {agg.vuln_count} "
            f"(critical: {len(agg.critical_vulns)}, "
            f"actively exploited: {len(agg.exploited_vulns)})\n"
            f"- Attack patterns: {agg.ttp_count}\n"
            f"- Sources: {_fmt_dict(agg.source_breakdown, top=5)}\n"
            f"\nFocus on what is operationally significant today."
        )

    def _threat_highlights_prompt(self, agg: ReportAggregates) -> str:
        parts = ["Write 1-2 paragraphs highlighting the most significant "
                 "threats identified in this reporting period.\n"]
        if agg.exploited_vulns:
            parts.append(
                "Actively exploited vulnerabilities: "
                + ", ".join(v.get("cve_id") or v.get("name", "")
                             for v in agg.exploited_vulns[:5])
            )
        if agg.critical_vulns:
            parts.append(
                "Critical CVEs (CVSS 9+): "
                + ", ".join(v.get("cve_id") or v.get("name", "")
                             for v in agg.critical_vulns[:5])
            )
        if agg.top_actors:
            parts.append(
                "Threat actors with recent activity: "
                + ", ".join(a["name"] for a in agg.top_actors[:5])
            )
        return "\n".join(parts)

    def _trends_summary_prompt(self, agg: ReportAggregates) -> str:
        pop = agg.period_over_period
        lines = [
            f"Write a 3-paragraph trends summary for a {agg.window_days}-day "
            f"threat intelligence period.\n",
        ]
        if pop:
            lines.append(
                f"Period-over-period: current total {pop.get('current_total', 0)} "
                f"vs prior {pop.get('prior_total', 0)} objects."
            )
            notable = [
                f"{t}: {v['pct_change']:+.0f}%"
                for t, v in pop.get("by_type", {}).items()
                if abs(v.get("pct_change", 0)) >= 20
            ]
            if notable:
                lines.append("Notable changes: " + ", ".join(notable))
        lines.append(
            f"Actor count: {agg.actor_count}. "
            f"Vulnerability count: {agg.vuln_count} "
            f"({len(agg.exploited_vulns)} exploited). "
            f"IOC types: {_fmt_dict(agg.ioc_by_type, top=4)}."
        )
        return "\n".join(lines)

    def _actor_trends_prompt(
        self, agg: ReportAggregates, lib_ctx: str
    ) -> str:
        actor_names = [a["name"] for a in agg.top_actors[:8]]
        motivations = _fmt_dict(agg.actor_motivations, top=5)
        prompt = (
            f"Write 2-3 paragraphs analysing threat actor activity trends "
            f"over the past {agg.window_days} days.\n\n"
            f"Actors observed: {', '.join(actor_names) or 'none'}\n"
            f"Motivation distribution: {motivations}\n"
        )
        if lib_ctx:
            prompt += f"\nRelevant research library context:\n{lib_ctx}\n"
        prompt += (
            "\nFocus on what has changed, which actors are newly active "
            "or escalating, and what this means for defensive posture."
        )
        return prompt

    def _vuln_trends_prompt(self, agg: ReportAggregates) -> str:
        return (
            f"Write 2-3 paragraphs analysing vulnerability trends over "
            f"the past {agg.window_days} days.\n\n"
            f"Total vulnerabilities: {agg.vuln_count}\n"
            f"CVSS distribution: {_fmt_dict(agg.cvss_distribution)}\n"
            f"Actively exploited: {len(agg.exploited_vulns)}\n"
            f"Notable exploited CVEs: "
            + ", ".join(
                v.get("cve_id") or v.get("name", "")
                for v in agg.exploited_vulns[:8]
            )
            + "\n\nFocus on patching priorities and exploitation velocity."
        )

    def _sector_trends_prompt(self, agg: ReportAggregates) -> str:
        sector_org = self._config.org_name or "your organisation"
        return (
            f"Write 1-2 paragraphs analysing sector targeting trends.\n\n"
            f"Sector distribution: {_fmt_dict(agg.sector_distribution, top=8)}\n"
            f"Opportunistic targeting count: {agg.opportunistic_count}\n\n"
            f"Contextualise for {sector_org}. Note any shifts in which "
            f"sectors are being targeted and what the opportunistic vs "
            f"targeted ratio indicates about adversary intent."
        )

    def _year_in_review_prompt(self, agg: ReportAggregates) -> str:
        return (
            "Write a 3-4 paragraph executive 'Year in Review' narrative "
            "for a threat intelligence annual report.\n\n"
            f"Total intelligence objects collected: {agg.total_objects}\n"
            f"Object type breakdown: {_fmt_dict(agg.by_type)}\n"
            f"Monthly collection trend: "
            + (", ".join(
                f"{m['month']}: {m['count']}"
                for m in agg.monthly_counts[-6:]
            ) if agg.monthly_counts else "insufficient data")
            + "\n\nWrite for a senior management or board audience. "
            "Frame the year's activity in terms of threat environment "
            "evolution, programme maturity, and overall risk posture."
        )

    def _threat_landscape_prompt(
        self, agg: ReportAggregates, lib_ctx: str
    ) -> str:
        actor_names = [a["name"] for a in agg.top_actors[:8]]
        top_ttps    = [t["name"] for t in agg.top_ttps[:6]]
        prompt = (
            "Write 3-4 paragraphs describing the threat landscape "
            "observed over the past year.\n\n"
            f"Threat actors: {', '.join(actor_names) or 'none identified'}\n"
            f"Most observed TTPs: {', '.join(top_ttps) or 'none identified'}\n"
            f"Tactic distribution: {_fmt_dict(agg.tactic_distribution, top=6)}\n"
        )
        if lib_ctx:
            prompt += f"\nKey research context:\n{lib_ctx}\n"
        prompt += (
            "\nDescribe who the primary threat actors were, what techniques "
            "they favoured, and how the threat landscape evolved over the year."
        )
        return prompt

    def _vuln_year_prompt(self, agg: ReportAggregates) -> str:
        return (
            "Write 2-3 paragraphs summarising the vulnerability landscape "
            "for the year.\n\n"
            f"Total vulnerabilities tracked: {agg.vuln_count}\n"
            f"Critical (CVSS 9+): {len(agg.critical_vulns)}\n"
            f"Actively exploited: {len(agg.exploited_vulns)}\n"
            f"CVSS distribution: {_fmt_dict(agg.cvss_distribution)}\n"
            f"Key exploited CVEs: "
            + ", ".join(
                v.get("cve_id") or v.get("name", "")
                for v in agg.exploited_vulns[:10]
            )
            + "\n\nFocus on exploitation velocity, patching discipline, "
            "and which vulnerability classes dominated the year."
        )

    def _sector_year_prompt(self, agg: ReportAggregates) -> str:
        org = self._config.org_name or "the organisation"
        sectors = ", ".join(self._config.sectors[:5]) if self._config.sectors else "all sectors"
        return (
            f"Write 2-3 paragraphs on sector targeting for the year, "
            f"focusing on {sectors}.\n\n"
            f"Sector distribution: {_fmt_dict(agg.sector_distribution, top=10)}\n"
            f"Opportunistic targeting: {agg.opportunistic_count} objects\n\n"
            f"Contextualise for {org}. Describe whether targeting of "
            f"relevant sectors increased or decreased, the split between "
            f"targeted and opportunistic threat activity, and what this "
            f"implies for {org}'s risk exposure."
        )

    def _programme_performance_prompt(self, agg: ReportAggregates) -> str:
        return (
            "Write 2-3 paragraphs evaluating the intelligence programme's "
            "performance over the year.\n\n"
            f"Total objects collected: {agg.total_objects}\n"
            f"Source platform breakdown: {_fmt_dict(agg.source_breakdown, top=6)}\n"
            f"AI-extracted intelligence: {agg.ai_extracted_count} objects\n"
            f"Average confidence score: {agg.avg_confidence:.1f}/100\n"
            f"Confidence distribution: {_fmt_dict(agg.confidence_distribution)}\n"
            f"Research library entries: {agg.library_entries_count}\n\n"
            "Assess the breadth and quality of intelligence collection, "
            "the diversity of sources, and any gaps or areas for improvement."
        )

    def _recommendations_prompt(
        self, agg: ReportAggregates, report_type: str
    ) -> str:
        timeframe = {
            "daily":  "immediate (next 24-48 hours)",
            "trends": "near-term (next 30 days)",
            "yearly": "strategic (next 12 months)",
        }.get(report_type, "near-term")

        sectors = ""
        if self._config.sectors:
            sectors = (
                f"Recommendations should be tailored for organisations "
                f"in: {', '.join(self._config.sectors)}.\n"
            )

        return (
            f"Write 3-5 {timeframe} recommendations based on the "
            f"threat intelligence in this report.\n\n"
            f"{sectors}"
            f"Key data points:\n"
            f"- Exploited vulnerabilities: {len(agg.exploited_vulns)}\n"
            f"- Critical CVEs: {len(agg.critical_vulns)}\n"
            f"- Active threat actors: {agg.actor_count}\n"
            f"- Most common TTPs: "
            + ", ".join(t["name"] for t in agg.top_ttps[:4])
            + "\n\nWrite specific, actionable recommendations. "
            "Each recommendation should have a clear rationale tied "
            "to the threat data above."
        )

    # ── Research library context ───────────────────────────────────────────

    def _library_context(self, actors: list[dict[str, Any]]) -> str:
        """
        Query the research library for entries relevant to top actors
        and return a brief context string for inclusion in prompts.
        """
        if not self._lib or not self._config.use_research_library:
            return ""

        context_parts = []
        seen_topics: set = set()

        for actor in actors[:5]:
            name = actor.get("name", "")
            if not name or name in seen_topics:
                continue
            seen_topics.add(name)
            try:
                entry = self._lib.get(name)
                if entry and entry.is_fresh and entry.note:
                    context_parts.append(
                        f"[{entry.topic}] ({entry.researcher}, "
                        f"{entry.age_hours:.0f}h ago): {entry.note[:300]}"
                    )
            except Exception:
                pass

        if not context_parts:
            # Fall back to searching for any recent relevant entries
            try:
                for topic in (self._config.sectors or [])[:3]:
                    results = self._lib.search(topic, limit=3)
                    for entry in results[:2]:
                        if entry.topic not in seen_topics and entry.note:
                            seen_topics.add(entry.topic)
                            context_parts.append(
                                f"[{entry.topic}]: {entry.note[:200]}"
                            )
            except Exception:
                pass

        ctx = "\n".join(context_parts)
        return ctx[:_MAX_LIB_CONTEXT] if ctx else ""


def _fmt_dict(d: dict[str, Any], top: int = 10) -> str:
    """Format a count dict as a readable string."""
    if not d:
        return "none"
    items = sorted(d.items(), key=lambda x: -x[1])[:top]
    return ", ".join(f"{k}: {v}" for k, v in items)
