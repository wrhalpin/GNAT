# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.agents.research
========================

:class:`ResearchAgent` — a :class:`~gnat.ingest.base.SourceReader` that
uses the Claude API (with web search enabled) to gather threat intelligence
on specific topics or from monitored sources.

Two operating modes
-------------------

**Topic-driven** — given a list of threat topics (actor names, CVEs, malware
families, campaign names), the agent searches the web and returns one
synthesized :class:`~gnat.agents.base.ResearchResult` per topic::

    agent = ResearchAgent(
        config=AgentConfig.from_ini(),
        topics=["APT29", "CVE-2024-12345", "LockBit 3.0"],
    )
    for record in agent:
        print(record["title"], record["topic"])

**Feed-driven** — given a list of monitored source URLs, the agent checks
each source for new threat-relevant content and returns one
:class:`~gnat.agents.base.ResearchResult` per item found.  Designed to
run on a schedule via :class:`~gnat.schedule.job.FeedJob` with
``ctx.last_success_iso`` providing the ``newer_than`` cutoff::

    from gnat.schedule import FeedJob

    def make_agent(ctx):
        return ResearchAgent(
            config=AgentConfig.from_ini(),
            monitored_sources=[
                {"url": "https://unit42.paloaltonetworks.com/", "label": "Unit42"},
                {"url": "https://www.cisa.gov/news-events/cybersecurity-advisories",
                 "label": "CISA Advisories"},
            ],
            newer_than=ctx.last_success_iso,
        )

    job = FeedJob(
        job_id="threat-feed-monitor",
        reader_factory=make_agent,
        mapper_factory=lambda ctx: ParsingAgent(config=AgentConfig.from_ini()),
        interval_seconds=21600,   # every 6 hours
    )

Drop-in with IngestPipeline
-----------------------------
Because :class:`ResearchAgent` implements ``SourceReader``, it works
directly in a standard pipeline::

    pipeline = (IngestPipeline("research")
        .read_from(ResearchAgent(config, topics=["APT29"]))
        .map_with(ParsingAgent(config))
        .write_to(threatq_client))
    result = pipeline.run()

Rate limiting
-------------
Each topic in topic-driven mode makes one Claude API call.  Feed-driven mode
makes one call per batch of sources (the agent decides how to distribute
searches internally).  The ``max_calls_per_run`` parameter caps total API
calls per ``_iter_records`` invocation to prevent runaway cost.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

from gnat.agents.base import ClaudeClient
from gnat.ingest.base import RawRecord, SourceReader

if TYPE_CHECKING:
    from gnat.agents.base import AgentConfig

logger = logging.getLogger(__name__)

_FEED_BATCH_SIZE = 10


def _now_ts() -> str:
    """ISO 8601 timestamp with millisecond precision."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class ResearchAgent(SourceReader):
    """
    AI-powered research agent for threat intelligence.

    Supports topic-driven synthesis and feed-driven monitoring via the
    Claude API (``ClaudeClient``).

    Parameters
    ----------
    config : AgentConfig
        Agent configuration (API key, model, ceiling, etc.).
    topics : list[str], optional
        Threat topics to research (topic-driven mode).
    monitored_sources : list[dict], optional
        Feed sources to monitor (feed-driven mode).
    newer_than : str, optional
        ISO 8601 timestamp; only return items published after this time.
    max_calls_per_run : int, optional
        Cap on the number of API calls per iteration.  ``None`` means unlimited.
    """

    def __init__(
        self,
        config: AgentConfig,
        topics: list[str] | None = None,
        monitored_sources: list[dict[str, Any]] | None = None,
        newer_than: str | None = None,
        max_calls_per_run: int | None = None,
    ) -> None:
        """Initialize ResearchAgent."""
        if topics and monitored_sources:
            raise ValueError(
                "Provide topics or monitored_sources, not both."
            )
        if not topics and not monitored_sources:
            raise ValueError(
                "Provide topics or monitored_sources (at least one is required)."
            )

        super().__init__(source_id="ResearchAgent")
        self._cfg = config
        self._client = ClaudeClient(config)
        self._topics: list[str] = list(topics or [])
        self._monitored_sources: list[dict[str, Any]] = list(monitored_sources or [])
        self._newer_than = newer_than
        self._max_calls = max_calls_per_run

    # ── SourceReader protocol ─────────────────────────────────────────────

    def _iter_records(self) -> Iterator[RawRecord]:
        """Internal helper for iter records."""
        if self._topics:
            yield from self._iter_topic_records()
        else:
            yield from self._iter_feed_records()

    # ── Topic-driven iteration ────────────────────────────────────────────

    def _iter_topic_records(self) -> Iterator[RawRecord]:
        """Internal helper for iter topic records."""
        calls = 0
        for topic in self._topics:
            if self._max_calls is not None and calls >= self._max_calls:
                break
            user_prompt = self._build_topic_prompt(topic)
            try:
                response = self._client.complete(user_prompt)
                calls += 1
            except Exception as exc:
                logger.warning("ResearchAgent: topic %r failed: %s", topic, exc)
                continue

            parsed = self._client.json_from(response)
            if parsed is None:
                # Prose fallback — yield raw text
                text = self._client.text_from(response)
                yield {"topic": topic, "text": text, "metadata": {"mode": "topic"}}
            else:
                yield {
                    "topic": topic,
                    "text": self._flatten_result(parsed),
                    "metadata": {
                        "mode": "topic",
                        "confidence": parsed.get("confidence"),
                        "iocs_mentioned": parsed.get("iocs_mentioned", []),
                        "search_queries_used": parsed.get("search_queries_used", []),
                    },
                }

    def _build_topic_prompt(self, topic: str) -> str:
        """Internal helper for build topic prompt."""
        date_hint = (
            f"\nOnly include information published after {self._newer_than}."
            if self._newer_than
            else ""
        )
        return (
            f"You are a cyber threat intelligence analyst.\n"
            f"Research the following topic and return a JSON object with keys: "
            f"title, summary, key_findings, source_urls, iocs_mentioned, "
            f"ttps_mentioned, actors_mentioned, cves_mentioned, confidence (0-100), "
            f"search_queries_used.\n"
            f"Topic: {topic}{date_hint}"
        )

    # ── Feed-driven iteration ─────────────────────────────────────────────

    def _iter_feed_records(self) -> Iterator[RawRecord]:
        """Internal helper for iter feed records."""
        sources = self._monitored_sources
        for i in range(0, len(sources), _FEED_BATCH_SIZE):
            batch = sources[i : i + _FEED_BATCH_SIZE]
            user_prompt = self._build_feed_prompt(batch)
            try:
                response = self._client.complete(user_prompt)
            except Exception as exc:
                logger.warning("ResearchAgent: feed batch failed: %s", exc)
                continue

            items = self._client.json_from(response) or []
            if not isinstance(items, list):
                items = []
            for item in items:
                yield {
                    "text": item.get("text", item.get("title", "")),
                    "url": item.get("url", ""),
                    "title": item.get("title", ""),
                    "metadata": {"mode": "feed", **item},
                }

    def _build_feed_prompt(self, sources: list[dict[str, Any]]) -> str:
        """Internal helper for build feed prompt."""
        source_lines = "\n".join(
            f"- {s.get('label', s.get('url', ''))}: {s.get('url', '')}"
            for s in sources
        )
        date_hint = (
            f"\nOnly include items published after {self._newer_than}."
            if self._newer_than
            else ""
        )
        return (
            f"You are a cyber threat intelligence analyst monitoring threat feeds.\n"
            f"Check the following sources for new threat-relevant content and return a "
            f"JSON array of objects, each with keys: url, title, text, published_at.\n"
            f"Return an empty array [] if no relevant content is found.{date_hint}\n\n"
            f"Sources:\n{source_lines}"
        )

    # ── Helpers ────────────────────────────────────────────────────────────

    def _flatten_result(self, result: dict[str, Any]) -> str:
        """Convert a structured research result dict to a plain-text string."""
        parts: list[str] = []
        if result.get("summary"):
            parts.append(str(result["summary"]))
        for finding in result.get("key_findings", []):
            parts.append(str(finding))
        for ioc in result.get("iocs_mentioned", []):
            if ioc.get("value"):
                parts.append(str(ioc["value"]))
        for ttp in result.get("ttps_mentioned", []):
            if ttp.get("technique_id"):
                parts.append(str(ttp["technique_id"]))
            if ttp.get("name"):
                parts.append(str(ttp["name"]))
        for actor in result.get("actors_mentioned", []):
            if actor.get("name"):
                parts.append(str(actor["name"]))
        for cve in result.get("cves_mentioned", []):
            if cve.get("cve_id"):
                parts.append(str(cve["cve_id"]))
        return " ".join(parts)

    # ── Legacy helpers (preserved for backward compatibility) ─────────────

    def research_topic(self, topic: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
        """
        Perform deep research on a threat topic using the configured LLM.

        Returns structured output with threat summary, indicators, TTPs, etc.
        """
        user_prompt = (
            f"Research the following threat intelligence topic: {topic}\n\n"
            f"Additional context:\n{json.dumps(context or {}, indent=2)}\n\n"
            "Focus on: threat actors, technical indicators (IOCs), TTPs (MITRE ATT&CK), "
            "targeted sectors, mitigation recommendations, and confidence assessment.\n"
            "Return a JSON object."
        )
        try:
            response = self._client.complete(user_prompt)
            content = self._client.text_from(response)
            structured = self._client.json_from(response) or {"summary": content[:800]}
            return {
                "topic": topic,
                "summary": structured.get("summary", content[:1000]),
                "indicators": structured.get("indicators", []),
                "ttps": structured.get("ttps", []),
                "confidence": structured.get("confidence", 60),
                "timestamp": _now_ts(),
                "raw_response": content,
            }
        except Exception as exc:
            raise RuntimeError(f"Research on topic '{topic}' failed: {exc}") from exc

    def monitor_feeds(self, feeds: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Analyze multiple feed items and return enriched results."""
        results = []
        for item in feeds:
            try:
                prompt = (
                    f"Analyze this threat intelligence feed item:\n"
                    f"{json.dumps(item, indent=2)}\n\n"
                    "Return a JSON object with keys: relevance_score, summary, "
                    "extracted_iocs, ttps, recommended_action."
                )
                response = self._client.complete(prompt)
                analysis = self._client.json_from(response) or {}
                analysis["timestamp"] = _now_ts()
                results.append({"feed_item": item, "analysis": analysis})
            except Exception as exc:  # noqa: BLE001
                logger.warning("LLM analysis failed for feed item: %s", exc)
        return results
