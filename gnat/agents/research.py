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

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List, Optional

from gnat.ingest.base import RawRecord, SourceReader
from gnat.agents.base import AgentConfig, ClaudeClient, ResearchResult
from gnat.agents.prompts import (
    RESEARCH_SYSTEM,
    RESEARCH_TOPIC_USER,
    RESEARCH_TOPIC_USER_NEWER,
    RESEARCH_FEED_SYSTEM,
    RESEARCH_FEED_USER,
    RESEARCH_FEED_NEWER_HINT,
)

logger = logging.getLogger(__name__)

# Web search tool definition for the Claude API
_WEB_SEARCH_TOOL = {
    "type": "web_search_20250305",
    "name": "web_search",
}


class ResearchAgent(SourceReader):
    """
    AI-powered threat intelligence researcher using Claude + web search.

    Implements :class:`~gnat.ingest.base.SourceReader` so it drops
    directly into :class:`~gnat.ingest.pipeline.pipeline.IngestPipeline`
    as the ``read_from`` source.

    Parameters
    ----------
    config : AgentConfig
        Claude API configuration (key, model, limits).
    topics : list of str, optional
        Topic-driven mode — one synthesis per topic.
        Mutually exclusive with ``monitored_sources``.
    monitored_sources : list of dict, optional
        Feed-driven mode — list of ``{"url": "...", "label": "..."}`` dicts.
        Mutually exclusive with ``topics``.
    newer_than : str, optional
        ISO 8601 timestamp.  In topic-driven mode, instructs Claude to focus
        on recent findings.  In feed-driven mode, filters out older content.
        Typically ``ctx.last_success_iso`` from :class:`~gnat.schedule.job.JobRunContext`.
    max_calls_per_run : int
        Maximum Claude API calls per ``_iter_records`` invocation.
        Default ``20``.  Prevents runaway cost on large topic lists.
    label : str
        Human-readable label used in log messages and ``IngestResult``.

    Raises
    ------
    ValueError
        If neither ``topics`` nor ``monitored_sources`` is provided, or
        if both are provided simultaneously.

    Examples
    --------
    Topic-driven::

        from gnat.agents import ResearchAgent, AgentConfig

        agent = ResearchAgent(
            config=AgentConfig.from_ini(),
            topics=["Scattered Spider", "CVE-2024-3400", "Volt Typhoon"],
        )
        for record in agent:
            print(record["title"])   # → "Scattered Spider Threat Summary", …

    Feed-driven with scheduling::

        def make_agent(ctx):
            return ResearchAgent(
                config=AgentConfig.from_ini(),
                monitored_sources=[
                    {"url": "https://securelist.com/", "label": "Kaspersky SecureList"},
                    {"url": "https://www.mandiant.com/resources/blog", "label": "Mandiant Blog"},
                ],
                newer_than=ctx.last_success_iso,
            )
    """

    def __init__(
        self,
        config: AgentConfig,
        topics: Optional[List[str]] = None,
        monitored_sources: Optional[List[Dict[str, str]]] = None,
        newer_than: Optional[str] = None,
        max_calls_per_run: int = 20,
        label: str = "ResearchAgent",
    ):
        super().__init__(source_id=label)
        if topics and monitored_sources:
            raise ValueError(
                "ResearchAgent: provide either 'topics' or 'monitored_sources', not both."
            )
        if not topics and not monitored_sources:
            raise ValueError(
                "ResearchAgent: provide at least one 'topics' or 'monitored_sources'."
            )

        self._config     = config
        self._topics     = topics or []
        self._sources    = monitored_sources or []
        self._newer_than = newer_than
        self._max_calls  = max_calls_per_run
        self._client     = ClaudeClient(config)

    # ── SourceReader interface ─────────────────────────────────────────────

    def _iter_records(self) -> Iterator[RawRecord]:
        """Yield one RawRecord per research result."""
        calls_made = 0

        if self._topics:
            yield from self._iter_topic_records(calls_made)
        else:
            yield from self._iter_feed_records(calls_made)

    # ── Topic-driven mode ──────────────────────────────────────────────────

    def _iter_topic_records(self, calls_made: int) -> Iterator[RawRecord]:
        for topic in self._topics:
            if calls_made >= self._max_calls:
                logger.warning(
                    "ResearchAgent: max_calls_per_run=%d reached, "
                    "skipping remaining topics: %s",
                    self._max_calls,
                    self._topics[self._topics.index(topic):],
                )
                break

            logger.info("ResearchAgent: researching topic %r", topic)
            result = self._research_topic(topic)
            calls_made += 1

            if result is not None:
                yield result.to_raw_record()

    def _research_topic(self, topic: str) -> Optional[ResearchResult]:
        """Call Claude with web search to synthesize a topic summary."""
        newer_hint = ""
        if self._newer_than:
            newer_hint = RESEARCH_TOPIC_USER_NEWER.format(newer_than=self._newer_than)

        user_msg = RESEARCH_TOPIC_USER.format(
            topic=topic,
            newer_than_hint=newer_hint,
        )

        try:
            response = self._client.complete(
                system=RESEARCH_SYSTEM,
                user=user_msg,
                tools=[_WEB_SEARCH_TOOL],
                temperature=0.1,
            )
        except RuntimeError as exc:
            logger.error("ResearchAgent: Claude API error for topic %r: %s", topic, exc)
            return None

        data = self._client.json_from(response)
        if not data or not isinstance(data, dict):
            # Fallback: treat the raw text as the summary
            text = self._client.text_from(response)
            if not text:
                logger.warning("ResearchAgent: empty response for topic %r", topic)
                return None
            return ResearchResult(
                topic=topic,
                title=f"Research: {topic}",
                text=text,
                metadata={"model": self._config.model, "parse_error": True},
            )

        return ResearchResult(
            topic       = topic,
            title       = data.get("title") or f"Research: {topic}",
            text        = self._flatten_result(data),
            source_urls = data.get("source_urls") or [],
            metadata    = {
                "model":               self._config.model,
                "key_findings":        data.get("key_findings", []),
                "iocs_mentioned":      data.get("iocs_mentioned", []),
                "ttps_mentioned":      data.get("ttps_mentioned", []),
                "actors_mentioned":    data.get("actors_mentioned", []),
                "cves_mentioned":      data.get("cves_mentioned", []),
                "confidence":          data.get("confidence", 50),
                "search_queries_used": data.get("search_queries_used", []),
            },
        )

    @staticmethod
    def _flatten_result(data: Dict[str, Any]) -> str:
        """
        Flatten the structured research result into readable text for the
        parsing agent to process downstream.
        """
        parts = []

        if data.get("summary"):
            parts.append(data["summary"])

        if data.get("key_findings"):
            parts.append("\nKey findings:")
            parts.extend(f"- {f}" for f in data["key_findings"])

        if data.get("iocs_mentioned"):
            parts.append("\nIOCs mentioned:")
            for ioc in data["iocs_mentioned"]:
                parts.append(
                    f"- {ioc.get('type', 'unknown')}: {ioc.get('value', '')} "
                    f"({ioc.get('context', '')})"
                )

        if data.get("ttps_mentioned"):
            parts.append("\nTTPs mentioned:")
            for ttp in data["ttps_mentioned"]:
                tid = ttp.get("technique_id", "")
                parts.append(
                    f"- {tid + ' ' if tid else ''}{ttp.get('name', '')} "
                    f"({ttp.get('context', '')})"
                )

        if data.get("actors_mentioned"):
            parts.append("\nThreat actors mentioned:")
            for actor in data["actors_mentioned"]:
                parts.append(f"- {actor.get('name', '')} ({actor.get('context', '')})")

        if data.get("cves_mentioned"):
            parts.append("\nCVEs mentioned:")
            for cve in data["cves_mentioned"]:
                parts.append(
                    f"- {cve.get('cve_id', '')}: {cve.get('description', '')}"
                )

        return "\n".join(parts)

    # ── Feed-driven mode ───────────────────────────────────────────────────

    def _iter_feed_records(self, calls_made: int) -> Iterator[RawRecord]:
        """
        Query Claude to check all configured sources for new content.

        Sources are batched into groups of 10 to stay within a reasonable
        prompt size.  Each batch makes one Claude API call.
        """
        batch_size = 10
        sources = self._sources

        for batch_start in range(0, len(sources), batch_size):
            if calls_made >= self._max_calls:
                logger.warning(
                    "ResearchAgent: max_calls_per_run=%d reached, "
                    "skipping remaining sources",
                    self._max_calls,
                )
                break

            batch = sources[batch_start: batch_start + batch_size]
            logger.info(
                "ResearchAgent: checking %d monitored sources (batch %d)",
                len(batch), batch_start // batch_size + 1,
            )

            items = self._check_sources_batch(batch)
            calls_made += 1

            for item in items:
                yield ResearchResult(
                    topic        = item.get("url", "feed"),
                    title        = item.get("title", ""),
                    text         = item.get("text", item.get("summary", "")),
                    url          = item.get("url", ""),
                    source_urls  = [item.get("url", "")] if item.get("url") else [],
                    metadata     = {
                        "model":        self._config.model,
                        "author":       item.get("author", ""),
                        "published_at": item.get("published_at", ""),
                        "mode":         "feed",
                    },
                ).to_raw_record()

    def _check_sources_batch(
        self, sources: List[Dict[str, str]]
    ) -> List[Dict[str, Any]]:
        """Send one batch of sources to Claude and parse the result list."""
        sources_block = "\n".join(
            f"- {s.get('label', s['url'])}: {s['url']}"
            for s in sources
        )
        newer_hint = ""
        if self._newer_than:
            newer_hint = RESEARCH_FEED_NEWER_HINT.format(newer_than=self._newer_than)

        user_msg = RESEARCH_FEED_USER.format(
            sources_block=sources_block,
            newer_than_hint=newer_hint,
        )

        try:
            response = self._client.complete(
                system=RESEARCH_FEED_SYSTEM,
                user=user_msg,
                tools=[_WEB_SEARCH_TOOL],
                temperature=0.1,
            )
        except RuntimeError as exc:
            logger.error("ResearchAgent: Claude API error for feed batch: %s", exc)
            return []

        data = self._client.json_from(response)
        if data is None or not isinstance(data, list):
            logger.warning(
                "ResearchAgent: feed batch returned non-list response, "
                "raw: %.200s", self._client.text_from(response)
            )
            return []

        logger.info(
            "ResearchAgent: feed batch returned %d items", len(data)
        )
        return data

    def __repr__(self) -> str:  # pragma: no cover
        if self._topics:
            return (
                f"ResearchAgent(mode=topic, topics={self._topics}, "
                f"model={self._config.model!r})"
            )
        return (
            f"ResearchAgent(mode=feed, sources={len(self._sources)}, "
            f"model={self._config.model!r})"
        )
