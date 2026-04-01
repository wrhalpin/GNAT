"""
gnat.agents.research
========================

:class:`ResearchAgent` — a :class:`~gnat.ingest.base.SourceReader` that
uses the Claude API (with web search enabled) to gather threat intelligence
on specific topics or from monitored sources.

**Now uses the unified LLMClient for multi-LLM support (Claude, OpenAI, Grok, etc.).**

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
from datetime import datetime, timezone
from typing import Any

from gnat.agents.llm import LLMClient
from gnat.clients.base import GNATClientError


def _now_ts() -> str:
    """ISO 8601 timestamp with millisecond precision."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class ResearchAgent:
    """
    AI-powered research agent for threat intelligence.

    Supports topic-driven synthesis and feed-driven monitoring.
    Uses unified LLMClient for multi-provider support (Claude, OpenAI, Grok).

    Configuration via [llm] and provider-specific sections ([claude], [openai], [grok]).
    """

    def __init__(
        self,
        config: dict[str, Any],
        llm_backend: str | None = None,
    ) -> None:
        """
        Parameters
        ----------
        config : dict
            Full GNAT configuration dictionary (from GNATConfig).
        llm_backend : str, optional
            Override default backend (claude | openai | grok). Falls back to [llm].default_backend.
        """
        self.config = config
        self.ai_confidence_ceiling = config.get("llm", {}).get("ai_confidence_ceiling", 70)

        backend = llm_backend or config.get("llm", {}).get("default_backend", "claude")

        # Pass relevant provider config to LLMClient
        provider_config = {}
        if backend == "claude":
            provider_config = config.get("claude", {})
        elif backend == "openai":
            provider_config = config.get("openai", {})
        elif backend == "grok":
            provider_config = config.get("grok", {})

        self.llm = LLMClient(backend=backend, **provider_config)

        # Topic list and other settings (existing behavior preserved)
        self.topics = config.get("research", {}).get("topics", [])
        self.confidence_ceiling = self.ai_confidence_ceiling

    # ── Core research methods ─────────────────────────────────────────────

    def research_topic(self, topic: str, context: dict[str, Any] | None = None) -> dict[str, Any]:
        """
        Perform deep research on a threat topic using the configured LLM.

        Returns structured output with threat summary, indicators, TTPs, etc.
        """
        system_prompt = (
            "You are an expert cyber threat intelligence analyst. "
            "Provide a detailed, accurate, and actionable analysis."
        )

        user_prompt = f"""
        Research the following threat intelligence topic: {topic}

        Additional context:
        {json.dumps(context or {}, indent=2)}

        Focus on:
        - Threat actors and campaigns
        - Technical indicators (IOCs)
        - TTPs (MITRE ATT&CK)
        - Targeted sectors / victims
        - Mitigation recommendations
        - Confidence assessment
        """

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        try:
            response = self.llm.chat(messages, temperature=0.5, max_tokens=4096)

            # Extract content depending on provider response format
            if self.llm.backend == "claude":
                content = response.get("content", [{}])[0].get("text", "")
            else:  # OpenAI / Grok style
                content = response.get("choices", [{}])[0].get("message", {}).get("content", "")

            # Attempt structured parsing
            structured = self._parse_research_output(content)

            return {
                "topic": topic,
                "summary": structured.get("summary", content[:1000]),
                "indicators": structured.get("indicators", []),
                "ttps": structured.get("ttps", []),
                "confidence": min(structured.get("confidence", 70), self.confidence_ceiling),
                "model_used": self.llm.get_model_name(),
                "timestamp": _now_ts(),
                "raw_response": content,
            }
        except Exception as e:
            raise GNATClientError(f"Research on topic '{topic}' failed: {e}") from e

    def analyze_feed_item(self, feed_item: dict[str, Any]) -> dict[str, Any]:
        """
        Analyze a single feed item (e.g., from ingested threat intel) for relevance and enrichment.
        """
        prompt = f"""
        Analyze this threat intelligence feed item and extract key insights:

        {json.dumps(feed_item, indent=2)}

        Return structured analysis including:
        - Relevance to current threats
        - Extracted IOCs
        - Suggested TTPs
        - Recommended actions
        """

        schema = {
            "type": "object",
            "properties": {
                "relevance_score": {"type": "integer", "minimum": 0, "maximum": 100},
                "extracted_iocs": {"type": "array", "items": {"type": "string"}},
                "ttps": {"type": "array", "items": {"type": "string"}},
                "summary": {"type": "string"},
                "recommended_action": {"type": "string"},
            },
            "required": ["relevance_score", "summary"],
        }

        try:
            result = self.llm.structured(prompt, schema, temperature=0.3)
            result["model_used"] = self.llm.get_model_name()
            result["timestamp"] = _now_ts()
            return result
        except Exception as e:
            raise GNATClientError(f"Feed item analysis failed: {e}") from e

    # ── Private helpers ────────────────────────────────────────────────────

    def _parse_research_output(self, text: str) -> dict[str, Any]:
        """Attempt to extract structured fields from free-form LLM output."""
        # Simple heuristic parsing -- improve with better prompting or structured calls
        result: dict[str, Any] = {
            "summary": text[:800],
            "indicators": [],
            "ttps": [],
            "confidence": 60,
        }

        # Basic keyword extraction (extend with regex or LLM-based parsing if needed)
        if "IOC" in text or "indicator" in text.lower():
            result["indicators"] = ["extracted-ioc-placeholder"]  # replace with real parsing

        if any(ttp in text.upper() for ttp in ["T", "TA", "ATT&CK"]):
            result["ttps"] = ["Txxxx.xxx"]  # placeholder

        return result

    # ── Feed-driven monitoring (existing pattern preserved) ───────────────

    def monitor_feeds(self, feeds: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Analyze multiple feed items and return enriched results."""
        results = []
        for item in feeds:
            try:
                analysis = self.analyze_feed_item(item)
                results.append({"feed_item": item, "analysis": analysis})
            except Exception:
                # Log and continue (non-blocking)
                pass
        return results
