"""
gnat.agents.base
====================

Shared foundations for the GNAT AI agent layer:

* :class:`AgentConfig`   — loaded from ``[claude]`` / ``[copilot]`` INI sections
* :class:`ResearchResult` — a single sourced document returned by the research agent
* :class:`ParsedIntel`   — structured extraction returned by the parsing agent
* :class:`ClaudeClient`  — thin synchronous HTTP wrapper around the Claude
  ``/v1/messages`` endpoint, used by both ``ResearchAgent`` and ``ParsingAgent``

INI configuration
-----------------

Claude::

    [claude]
    api_key    = sk-ant-...
    model      = claude-sonnet-4-6
    max_tokens = 4096
    timeout    = 120

Copilot (for :class:`~gnat.agents.copilot.CopilotReader`)::

    [copilot]
    directline_secret = <bot-framework-secret>
    tenant_id         = <azure-tenant-id>
    # Optional overrides
    bot_timeout = 60

Confidence ceiling for AI-extracted intel
------------------------------------------
All STIX objects produced by the parsing agent are capped at
``x_ai_confidence_ceiling`` (default 60) and tagged with
``x_source_type: "ai_extracted"`` so analysts can review before
high-confidence workflows propagate them to EDLs.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

@dataclass
class AgentConfig:
    """
    Runtime configuration for AI agents, loaded from the INI file.

    Parameters
    ----------
    api_key : str
        Claude API key (``sk-ant-...``).
    model : str
        Claude model string.  Default ``"claude-sonnet-4-6"``.
    max_tokens : int
        Maximum tokens per API response.  Default ``4096``.
    timeout : int
        HTTP timeout in seconds.  Default ``120``.
    ai_confidence_ceiling : int
        Maximum confidence assigned to AI-extracted STIX objects.
        Default ``60``.  Prevents AI hallucinations propagating to EDLs
        at high confidence without analyst review.
    """

    api_key:               str
    model:                 str = "claude-sonnet-4-6"
    max_tokens:            int = 4096
    timeout:               int = 120
    ai_confidence_ceiling: int = 60

    @classmethod
    def from_ini(cls, config_path: str | None = None) -> AgentConfig:
        """
        Load from the ``[claude]`` section of the GNAT INI file.

        Parameters
        ----------
        config_path : str, optional
            Explicit path to config.ini.  Uses default search order if omitted.

        Raises
        ------
        KeyError
            If the ``[claude]`` section or ``api_key`` key is missing.
        FileNotFoundError
            If no config file is found.
        """
        from gnat.config import GNATConfig
        cfg = GNATConfig(config_path)
        try:
            section = cfg.get("claude")
        except KeyError:
            raise KeyError(
                "No [claude] section in config.ini. Add:\n\n"
                "  [claude]\n"
                "  api_key = sk-ant-...\n"
                "  model   = claude-sonnet-4-6\n"
            )
        if "api_key" not in section:
            raise KeyError(
                "[claude] section found but 'api_key' is missing from config.ini"
            )
        return cls(
            api_key               = section["api_key"],
            model                 = section.get("model", "claude-sonnet-4-6"),
            max_tokens            = int(section.get("max_tokens", 4096)),
            timeout               = int(section.get("timeout", 120)),
            ai_confidence_ceiling = int(section.get("ai_confidence_ceiling", 60)),
        )

    @classmethod
    def from_config(cls, parser: Any) -> AgentConfig:
        """
        Load from an existing :class:`configparser.ConfigParser` instance.

        Parameters
        ----------
        parser : configparser.ConfigParser
            Already-loaded config parser object.

        Raises
        ------
        KeyError
            If the ``[claude]`` section or ``api_key`` key is missing.
        """
        try:
            section = dict(parser.items("claude"))
        except Exception as exc:
            raise KeyError(
                "No [claude] section found in config. Add:\n\n"
                "  [claude]\n"
                "  api_key = sk-ant-...\n"
                "  model   = claude-sonnet-4-6\n"
            ) from exc
        if "api_key" not in section:
            raise KeyError(
                "[claude] section found but 'api_key' is missing from config"
            )
        return cls(
            api_key               = section["api_key"],
            model                 = section.get("model", "claude-sonnet-4-6"),
            max_tokens            = int(section.get("max_tokens", 4096)),
            timeout               = int(section.get("timeout", 120)),
            ai_confidence_ceiling = int(section.get("ai_confidence_ceiling", 60)),
        )


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class ResearchResult:
    """
    A single document / synthesis returned by :class:`~gnat.agents.research.ResearchAgent`.

    In **topic-driven** mode this is one synthesized summary per topic.
    In **feed-driven** mode this is one record per source URL that
    contained relevant new content.

    Attributes
    ----------
    topic : str
        The search query or topic that produced this result.
    text : str
        Full text content — either a synthesis or the raw article body.
    url : str
        Primary source URL.  Empty string for multi-source syntheses.
    title : str
        Document title or auto-generated summary title.
    retrieved_at : datetime
        UTC timestamp when the content was retrieved.
    source_urls : list of str
        All URLs referenced in a synthesis (empty for single-source results).
    metadata : dict
        Additional context: ``search_queries_used``, ``model``, etc.
    """

    topic:        str
    text:         str
    url:          str          = ""
    title:        str          = ""
    retrieved_at: datetime     = field(default_factory=lambda: datetime.now(timezone.utc))
    source_urls:  list[str]    = field(default_factory=list)
    metadata:     dict[str, Any] = field(default_factory=dict)

    def to_raw_record(self) -> dict[str, Any]:
        """Convert to a ``RawRecord`` dict for the ingest pipeline."""
        return {
            "text":         self.text,
            "url":          self.url,
            "title":        self.title,
            "topic":        self.topic,
            "retrieved_at": self.retrieved_at.isoformat(),
            "source_urls":  self.source_urls,
            "metadata":     self.metadata,
        }


@dataclass
class ParsedIntel:
    """
    Structured threat intelligence extracted by :class:`~gnat.agents.parsing.ParsingAgent`.

    Attributes
    ----------
    summary : str
        Narrative summary of the source text — always present.
    indicators : list of dict
        Extracted IOC dicts with ``type``, ``value``, ``context`` keys.
    ttps : list of dict
        MITRE ATT&CK TTP dicts with ``technique_id``, ``name``, ``context``.
    actors : list of dict
        Threat actor dicts with ``name``, ``aliases``, ``motivation``.
    vulnerabilities : list of dict
        CVE dicts with ``cve_id``, ``cvss_score``, ``description``.
    affected_products : list of str
        Product names mentioned as affected.
    confidence : int
        Agent's self-assessed confidence in the extraction (0-100),
        capped by ``AgentConfig.ai_confidence_ceiling``.
    source_url : str
        URL of the source document.
    source_topic : str
        Research topic that surfaced this document.
    model : str
        Claude model that performed the extraction.
    """

    summary:           str
    indicators:        list[dict[str, Any]] = field(default_factory=list)
    ttps:              list[dict[str, Any]] = field(default_factory=list)
    actors:            list[dict[str, Any]] = field(default_factory=list)
    vulnerabilities:   list[dict[str, Any]] = field(default_factory=list)
    affected_products: list[str]            = field(default_factory=list)
    confidence:        int                  = 50
    source_url:        str                  = ""
    source_topic:      str                  = ""
    model:             str                  = ""

    @property
    def has_structured_data(self) -> bool:
        """True if at least one structured extraction category is non-empty."""
        return any([
            self.indicators, self.ttps,
            self.actors, self.vulnerabilities,
        ])

    def total_objects(self) -> int:
        return (len(self.indicators) + len(self.ttps) +
                len(self.actors) + len(self.vulnerabilities))


# ---------------------------------------------------------------------------
# Claude API client
# ---------------------------------------------------------------------------

class ClaudeClient:
    """
    Minimal synchronous HTTP client for the Claude ``/v1/messages`` endpoint.

    Uses only stdlib ``urllib`` — no extra dependencies.  Designed for use
    inside ``SourceReader._iter_records`` and ``RecordMapper.map`` which are
    both synchronous.

    Parameters
    ----------
    config : AgentConfig
        Agent configuration carrying the API key, model, and limits.

    Examples
    --------
    ::

        cfg    = AgentConfig.from_ini()
        client = ClaudeClient(cfg)
        resp   = client.complete(
            system="You are a threat intelligence analyst.",
            user="Summarise the threat actor APT29.",
        )
        text = resp["content"][0]["text"]
    """

    _BASE_URL = "https://api.anthropic.com/v1/messages"
    _API_VERSION = "2023-06-01"

    def __init__(self, config: AgentConfig):
        self._cfg = config

    def complete(
        self,
        user: str,
        system: str = "",
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.2,
    ) -> dict[str, Any]:
        """
        Send a single-turn completion request to Claude.

        Parameters
        ----------
        user : str
            The user message content.
        system : str
            System prompt.
        tools : list of dict, optional
            Claude tool definitions.  Pass
            ``[{"type": "web_search_20250305", "name": "web_search"}]``
            to enable web search in the research agent.
        temperature : float
            Sampling temperature.  Lower = more deterministic.  Default 0.2.

        Returns
        -------
        dict
            Raw Claude API response body.

        Raises
        ------
        RuntimeError
            On HTTP errors or JSON decode failures.
        """
        body: dict[str, Any] = {
            "model":      self._cfg.model,
            "max_tokens": self._cfg.max_tokens,
            "messages":   [{"role": "user", "content": user}],
        }
        if system:
            body["system"] = system
        if tools:
            body["tools"] = tools

        payload = json.dumps(body).encode("utf-8")
        headers = {
            "Content-Type":      "application/json",
            "x-api-key":         self._cfg.api_key,
            "anthropic-version": self._API_VERSION,
        }

        req = urllib.request.Request(
            self._BASE_URL,
            data=payload,
            headers=headers,
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self._cfg.timeout) as resp:  # nosec B310 — hardcoded Anthropic API URL
                raw = resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            body_text = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(
                f"Claude API HTTP {exc.code}: {body_text[:400]}"
            ) from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"Claude API connection error: {exc.reason}") from exc

        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Claude API bad JSON: {raw[:200]}") from exc

    def text_from(self, response: dict[str, Any]) -> str:
        """
        Extract the first text block from a Claude API response.

        Parameters
        ----------
        response : dict
            Raw API response from :meth:`complete`.

        Returns
        -------
        str
            The text content, or empty string if not found.
        """
        for block in response.get("content", []):
            if block.get("type") == "text":
                return block.get("text", "")
        return ""

    def json_from(self, response: dict[str, Any]) -> Any:
        """
        Extract and parse JSON from the first text block of a Claude response.

        Claude is prompted to return only JSON.  This method strips any
        accidental markdown fences before parsing.

        Parameters
        ----------
        response : dict
            Raw API response from :meth:`complete`.

        Returns
        -------
        Any
            Parsed JSON value (dict, list, etc.), or ``None`` on failure.
        """
        text = self.text_from(response)
        # Strip markdown code fences if present
        text = text.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            # Drop first line (``` or ```json) and last line (```)
            text = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            logger.warning("ClaudeClient: JSON parse failed — %s\n%.200s", exc, text)
            return None


# ---------------------------------------------------------------------------
# LLM Provider abstract base
# ---------------------------------------------------------------------------


class LLMProvider(ABC):
    """Abstract base for all LLM providers (keeps GNAT's urllib3-only policy)."""

    @abstractmethod
    def chat(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Return standard OpenAI-style chat completion response."""

    @abstractmethod
    def structured(
        self,
        prompt: str,
        output_schema: Dict[str, Any],
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Return structured JSON output matching the supplied schema."""
