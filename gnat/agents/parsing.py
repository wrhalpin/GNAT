# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.agents.parsing
=======================

:class:`ParsingAgent` — a :class:`~gnat.ingest.base.RecordMapper` that
uses Claude to extract structured threat intelligence from unstructured text.

It consumes :class:`~gnat.agents.base.ResearchResult` raw records (or any
``RawRecord`` with a ``text`` field) and yields STIX 2.1 ORM objects:

* :class:`~gnat.orm.indicator.Indicator` for each extracted IOC
* :class:`~gnat.orm.attack_pattern.AttackPattern` for each TTP
* :class:`~gnat.orm.threat_actor.ThreatActor` for each actor
* :class:`~gnat.orm.vulnerability.Vulnerability` for each CVE
* A narrative :class:`~gnat.orm.indicator.Indicator` summary object if
  no structured data was found (so the pipeline always has *something* to
  work with)

All produced objects carry:

* ``confidence`` capped at ``AgentConfig.ai_confidence_ceiling`` (default 60)
* ``x_source_type: "ai_extracted"``
* ``x_source_url``: the source document URL
* ``x_source_topic``: the research topic

This lets downstream filters, commit workflows, and analysts identify
AI-extracted intel before it propagates to production platforms or EDLs.

Pipeline usage
--------------
::

    from gnat.agents import ResearchAgent, ParsingAgent, AgentConfig
    from gnat.ingest import IngestPipeline

    config = AgentConfig.from_ini()

    pipeline = (
        IngestPipeline("threat-research")
        .read_from(ResearchAgent(config, topics=["APT29", "Volt Typhoon"]))
        .map_with(ParsingAgent(config))
        .write_to(threatq_client)
    )
    result = pipeline.run()

Standalone usage
----------------
::

    agent  = ParsingAgent(config=AgentConfig.from_ini())
    record = {
        "text":  "<paste of a threat advisory>",
        "url":   "https://example.com/advisory.html",
        "topic": "manual",
    }
    for obj in agent.map(record):
        print(obj.stix_type, obj.name)
"""

from __future__ import annotations

import contextlib
import logging
import re
import uuid
from collections.abc import Iterator
from typing import Any

from gnat.agents.base import AgentConfig, ClaudeClient, ParsedIntel
from gnat.agents.prompts import PARSING_SYSTEM, PARSING_USER
from gnat.ingest.base import RawRecord, RecordMapper

from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from gnat.agents.llm import LLMClient
from gnat.orm.attack_pattern import AttackPattern
from gnat.orm.base import STIXBase
from gnat.orm.indicator import Indicator
from gnat.orm.threat_actor import ThreatActor
from gnat.orm.vulnerability import Vulnerability

logger = logging.getLogger(__name__)

# STIX pattern templates per IOC type
_STIX_PATTERNS: dict[str, str] = {
    "ipv4": "[ipv4-addr:value = '{v}']",
    "ipv6": "[ipv6-addr:value = '{v}']",
    "domain": "[domain-name:value = '{v}']",
    "url": "[url:value = '{v}']",
    "md5": "[file:hashes.MD5 = '{v}']",
    "sha1": "[file:hashes.'SHA-1' = '{v}']",
    "sha256": "[file:hashes.'SHA-256' = '{v}']",
    "email": "[email-addr:value = '{v}']",
    "filename": "[file:name = '{v}']",
    "registry": "[windows-registry-key:key = '{v}']",
}


def _escape(value: str) -> str:
    """Escape single quotes in a STIX pattern value."""
    return value.replace("'", "\\'")


def _refang(value: str) -> str:
    """
    Refang a potentially defanged IOC value.

    Common defanging patterns:
    * ``[.]``  → ``.``
    * ``hxxp`` → ``http``
    * ``[:]``  → ``:``
    * ``[@]``  → ``@``
    """
    value = value.replace("[.]", ".").replace("[:]", ":").replace("[@]", "@")
    value = re.sub(
        r"hxxps?://", lambda m: m.group().replace("xx", "tt"), value, flags=re.IGNORECASE
    )
    return value.strip()


class ParsingAgent(RecordMapper):
    """
    AI-powered threat intelligence extractor using Claude.

    Implements :class:`~gnat.ingest.base.RecordMapper` so it works
    directly in any :class:`~gnat.ingest.pipeline.pipeline.IngestPipeline`
    as the ``map_with`` stage.

    Parameters
    ----------
    config : AgentConfig
        Claude API configuration.
    min_confidence : int
        Skip extraction if the record's pre-existing confidence is below
        this value.  Default ``0`` (process everything).
    max_text_chars : int
        Truncate input text to this length before sending to Claude.
        Prevents exceeding context window on very long documents.
        Default ``40000`` (approx 10K tokens).
    extract_indicators : bool
        Include IOC extraction.  Default ``True``.
    extract_ttps : bool
        Include TTP extraction.  Default ``True``.
    extract_actors : bool
        Include threat actor extraction.  Default ``True``.
    extract_vulnerabilities : bool
        Include CVE extraction.  Default ``True``.
    always_yield_summary : bool
        If ``True`` (default), always yield at least one ``Indicator`` object
        carrying the narrative summary even when no structured data is found.
        Ensures the pipeline always has a record to show for each input.

    Examples
    --------
    ::

        config = AgentConfig.from_ini()
        agent  = ParsingAgent(config, min_confidence=30)

        # In a pipeline:
        pipeline = (IngestPipeline("parse")
            .read_from(ResearchAgent(config, topics=["APT29"]))
            .map_with(agent)
            .write_to(tq_client))

        # Standalone:
        for stix_obj in agent.map({"text": article_text, "url": url, "topic": "APT29"}):
            print(stix_obj.stix_type, stix_obj.name)
    """

    def __init__(
        self,
        config: AgentConfig,
        min_confidence: int = 0,
        max_text_chars: int = 40_000,
        extract_indicators: bool = True,
        extract_ttps: bool = True,
        extract_actors: bool = True,
        extract_vulnerabilities: bool = True,
        always_yield_summary: bool = True,
        label: str = "ParsingAgent",
        llm_client: LLMClient | None = None,
    ):
        """
        Initialize ParsingAgent.

        Parameters
        ----------
        config : AgentConfig
            Claude API configuration.
        llm_client : LLMClient, optional
            Pre-configured :class:`~gnat.agents.llm.LLMClient` instance.
            When supplied, routes API calls through the unified facade
            (supporting multi-backend and fallback chains) instead of the
            legacy ``ClaudeClient``.
        """
        super().__init__()
        self._config = config
        self._min_conf = min_confidence
        self._max_chars = max_text_chars
        self._do_indicators = extract_indicators
        self._do_ttps = extract_ttps
        self._do_actors = extract_actors
        self._do_vulns = extract_vulnerabilities
        self._always_summary = always_yield_summary
        self._client = ClaudeClient(config)
        self._llm: LLMClient | None = llm_client

    # ── RecordMapper interface ─────────────────────────────────────────────

    def map(self, record: RawRecord) -> Iterator[STIXBase]:
        """
        Extract STIX objects from a raw text record.

        Parameters
        ----------
        record : RawRecord
            Must contain a ``text`` key.  Optionally ``url``, ``topic``,
            ``title``, and ``metadata`` keys.

        Yields
        ------
        STIXBase
            One object per extracted entity, plus optionally a summary
            indicator.
        """
        text = record.get("text", "")
        if not text or not text.strip():
            logger.debug("ParsingAgent: empty text record, skipping")
            return

        # Truncate to avoid context window overflow
        if len(text) > self._max_chars:
            logger.debug(
                "ParsingAgent: truncating text from %d to %d chars",
                len(text),
                self._max_chars,
            )
            text = text[: self._max_chars] + "\n\n[TEXT TRUNCATED]"

        source_url = record.get("url", "")
        source_topic = record.get("topic", "")

        intel = self._extract(text, source_url, source_topic)
        if intel is None:
            return

        yielded = 0
        for obj in self._to_stix_objects(intel):
            yield obj
            yielded += 1

        if yielded == 0 and self._always_summary and intel.summary:
            yield self._summary_indicator(intel)

    # ── Extraction ─────────────────────────────────────────────────────────

    def _extract(self, text: str, source_url: str, source_topic: str) -> ParsedIntel | None:
        """Call the configured LLM backend to extract structured intel from text."""
        user_msg = PARSING_USER.format(
            text=text,
            source_url=source_url or "(unknown)",
            source_topic=source_topic or "(unknown)",
        )

        if self._llm is not None:
            # Route through unified LLMClient (multi-backend + fallback)
            try:
                data = self._llm.structured(
                    prompt=user_msg,
                    output_schema={
                        "type": "object",
                        "properties": {
                            "summary": {"type": "string"},
                            "indicators": {"type": "array"},
                            "ttps": {"type": "array"},
                            "actors": {"type": "array"},
                            "vulnerabilities": {"type": "array"},
                            "affected_products": {"type": "array"},
                            "confidence": {"type": "number"},
                        },
                    },
                    temperature=0.1,
                    system=PARSING_SYSTEM,
                )
            except Exception as exc:
                logger.error("ParsingAgent: LLMClient error: %s", exc)
                return None
        else:
            # Legacy ClaudeClient path (backwards compatible)
            try:
                response = self._client.complete(
                    system=PARSING_SYSTEM,
                    user=user_msg,
                    temperature=0.1,
                )
            except RuntimeError as exc:
                logger.error("ParsingAgent: Claude API error: %s", exc)
                return None
            data = self._client.json_from(response)
        if not data or not isinstance(data, dict):
            # For LLMClient path, `response` may not be set; use empty fallback
            text_fallback = ""
            if self._llm is None:
                text_fallback = self._client.text_from(response)  # type: ignore[arg-type]
            if text_fallback:
                return ParsedIntel(
                    summary=text_fallback[:2000],
                    confidence=20,
                    source_url=source_url,
                    source_topic=source_topic,
                    model=self._config.model,
                )
            return None

        raw_confidence = data.get("confidence", 50)
        capped_confidence = min(
            int(raw_confidence),
            self._config.ai_confidence_ceiling,
        )

        return ParsedIntel(
            summary=data.get("summary", ""),
            indicators=data.get("indicators", []) if self._do_indicators else [],
            ttps=data.get("ttps", []) if self._do_ttps else [],
            actors=data.get("actors", []) if self._do_actors else [],
            vulnerabilities=data.get("vulnerabilities", []) if self._do_vulns else [],
            affected_products=data.get("affected_products", []),
            confidence=capped_confidence,
            source_url=source_url,
            source_topic=source_topic,
            model=self._config.model,
        )

    # ── STIX object construction ────────────────────────────────────────────

    def _to_stix_objects(self, intel: ParsedIntel) -> Iterator[STIXBase]:
        """Yield STIX objects for each extracted entity."""
        yield from self._indicators_from(intel)
        yield from self._ttps_from(intel)
        yield from self._actors_from(intel)
        yield from self._vulns_from(intel)

    def _common_fields(self, intel: ParsedIntel) -> dict[str, Any]:
        """Fields added to every AI-extracted STIX object."""
        return {
            "confidence": min(intel.confidence, self._config.ai_confidence_ceiling),
            "x_source_type": "ai_extracted",
            "x_source_url": intel.source_url,
            "x_source_topic": intel.source_topic,
            "x_ai_model": intel.model,
        }

    def _indicators_from(self, intel: ParsedIntel) -> Iterator[Indicator]:
        """Internal helper for indicators from."""
        seen: set = set()
        for ioc in intel.indicators:
            ioc_type = ioc.get("type", "").lower()
            raw_value = ioc.get("value", "").strip()
            if not raw_value or not ioc_type:
                continue

            value = _refang(raw_value)
            dedup_key = (ioc_type, value.lower())
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            pattern_template = _STIX_PATTERNS.get(ioc_type)
            if pattern_template is None:
                logger.debug(
                    "ParsingAgent: unknown IOC type %r for value %r, skipping",
                    ioc_type,
                    value,
                )
                continue

            pattern = pattern_template.format(v=_escape(value))
            context = ioc.get("context", "")

            yield Indicator(
                name=value,
                description=context[:500] if context else f"AI-extracted {ioc_type}",
                pattern=pattern,
                pattern_type="stix",
                indicator_types=["malicious-activity"],
                **self._common_fields(intel),
            )

    def _ttps_from(self, intel: ParsedIntel) -> Iterator[AttackPattern]:
        """Internal helper for ttps from."""
        seen: set = set()
        for ttp in intel.ttps:
            name = ttp.get("name", "").strip()
            if not name:
                continue
            tid = ttp.get("technique_id", "").strip()
            dedup_key = tid.lower() if tid else name.lower()
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            description = ttp.get("context", "")
            if ttp.get("tactic"):
                description = f"Tactic: {ttp['tactic']}. {description}"

            yield AttackPattern(
                name=f"{tid} {name}".strip() if tid else name,
                description=description[:500],
                x_mitre_id=tid,
                **self._common_fields(intel),
            )

    def _actors_from(self, intel: ParsedIntel) -> Iterator[ThreatActor]:
        """Internal helper for actors from."""
        seen: set = set()
        for actor in intel.actors:
            name = actor.get("name", "").strip()
            if not name:
                continue
            if name.lower() in seen:
                continue
            seen.add(name.lower())

            aliases = actor.get("aliases", [])
            motivation = actor.get("motivation", "unknown")
            attribution = actor.get("attribution", "")
            context = actor.get("context", "")

            desc_parts = []
            if attribution:
                desc_parts.append(f"Attribution: {attribution}.")
            if context:
                desc_parts.append(context)
            if intel.affected_products:
                desc_parts.append("Affected products: " + ", ".join(intel.affected_products[:5]))

            yield ThreatActor(
                name=name,
                description=" ".join(desc_parts)[:500],
                threat_actor_types=[motivation],
                aliases=aliases[:10],
                **self._common_fields(intel),
            )

    def _vulns_from(self, intel: ParsedIntel) -> Iterator[Vulnerability]:
        """Internal helper for vulns from."""
        seen: set = set()
        for vuln in intel.vulnerabilities:
            cve_id = vuln.get("cve_id", "").strip()
            name = cve_id or f"Vulnerability-{uuid.uuid4().hex[:8]}"
            if name.lower() in seen:
                continue
            seen.add(name.lower())

            cvss = vuln.get("cvss_score")
            desc = vuln.get("description", "")
            exploit = vuln.get("exploited", False)

            if exploit:
                desc = f"[ACTIVELY EXPLOITED] {desc}"

            obj = Vulnerability(
                name=name,
                description=desc[:500],
                **self._common_fields(intel),
            )
            if cvss is not None:
                with contextlib.suppress(TypeError, ValueError):
                    obj.x_cvss_score = float(cvss)
            if cve_id:
                obj.x_cve_id = cve_id
            obj.x_actively_exploited = exploit

            yield obj

    def _summary_indicator(self, intel: ParsedIntel) -> Indicator:
        """
        Fallback indicator carrying the narrative summary when no structured
        data was extracted.  Ensures the pipeline always has something to show.
        """
        topic = intel.source_topic or "unknown"
        return Indicator(
            name=f"AI Research Summary: {topic}",
            description=intel.summary[:2000],
            pattern=f"[domain-name:value = 'ai-summary.{topic.lower()[:40]}']",
            pattern_type="stix",
            indicator_types=["unknown"],
            confidence=min(20, self._config.ai_confidence_ceiling),
            x_source_type="ai_extracted",
            x_source_url=intel.source_url,
            x_source_topic=intel.source_topic,
            x_ai_model=intel.model,
            x_is_summary=True,
        )

    def __repr__(self) -> str:  # pragma: no cover
        """Return unambiguous string representation."""
        return (
            f"ParsingAgent(model={self._config.model!r}, "
            f"confidence_ceiling={self._config.ai_confidence_ceiling})"
        )
