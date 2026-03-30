"""
gnat.nlp.claude_backend
=========================
:class:`ClaudeParser` — structured query extraction via the Claude API.

Uses the same :class:`~gnat.agents.base.ClaudeClient` and
:class:`~gnat.agents.base.AgentConfig` infrastructure as the research and
parsing agents.  Sends the user query to Claude with a JSON-schema prompt
and deserialises the structured response back into a :class:`QuerySpec`.

Requires ``[claude]`` section in ``config.ini``::

    [claude]
    api_key = sk-ant-...
    model   = claude-sonnet-4-6

Falls back to :class:`~gnat.nlp.builtin.BuiltinParser` on any API error so
callers always receive a valid :class:`QuerySpec`.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from gnat.nlp.query_spec import QuerySpec

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """\
You are a threat-intelligence query parser.  Extract structured fields from
the analyst's natural-language query and return ONLY valid JSON matching this
schema — no prose, no markdown fences:

{{
  "entities":  ["<entity name>", ...],
  "ioc_types": ["ip"|"domain"|"hash"|"url"|"email", ...],
  "since":     "<ISO-8601 datetime or null>",
  "until":     "<ISO-8601 datetime or null>",
  "platforms": ["<connector key>", ...],
  "limit":     <integer>
}}

Rules:
- entities: threat actors, malware families, CVE IDs, campaign names.
- ioc_types: only from the allowed set; empty array = all types.
- since/until: resolve relative times against today ({today}).
  "last 30 days" → since = today minus 30 days.
  Month names → first day of that month in the current or previous year.
  Omit if not mentioned (null).
- platforms: GNAT connector keys only (threatq, crowdstrike, splunk, etc.).
  Empty array = all platforms.
- limit: default 100 if not specified.
Return only the JSON object.
"""

_USER_PROMPT = "Query: {query}"


class ClaudeParser:
    """
    NLP query parser backed by the Claude API.

    Parameters
    ----------
    config : AgentConfig
        Claude API credentials and model settings.

    Raises
    ------
    ImportError
        If the ``gnat.agents`` module cannot be loaded (should never happen
        in a standard install).
    """

    def __init__(self, config: Any) -> None:
        from gnat.agents.base import ClaudeClient
        self._client = ClaudeClient(config)
        self._config = config

    def parse(self, query: str, default_limit: int = 100) -> QuerySpec:
        """
        Extract a :class:`QuerySpec` from *query* via the Claude API.

        On any API or parsing error the method logs a warning and
        returns a best-effort :class:`QuerySpec` built from the
        :class:`~gnat.nlp.builtin.BuiltinParser` fallback.

        Parameters
        ----------
        query : str
            Free-text analyst query.
        default_limit : int
            Default result limit forwarded to the prompt.

        Returns
        -------
        QuerySpec
        """
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        system = _SYSTEM_PROMPT.format(today=today)
        user   = _USER_PROMPT.format(query=query)

        try:
            raw = self._client.complete(
                user=user,
                system=system,
            )
            return self._parse_response(raw, query, default_limit)
        except Exception as exc:
            logger.warning(
                "ClaudeParser API call failed (%s); falling back to BuiltinParser", exc
            )
            from gnat.nlp.builtin import BuiltinParser
            return BuiltinParser().parse(query, default_limit=default_limit)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _parse_response(
        self, raw: Any, query: str, default_limit: int
    ) -> QuerySpec:
        """Deserialise Claude's JSON response into a QuerySpec."""
        # ClaudeClient.messages() returns the full response dict
        if isinstance(raw, dict):
            content = raw.get("content", [])
            text = ""
            for block in content:
                if isinstance(block, dict) and block.get("type") == "text":
                    text = block.get("text", "")
                    break
        else:
            text = str(raw)

        # Strip any accidental markdown fences
        text = text.strip()
        if text.startswith("```"):
            text = "\n".join(text.splitlines()[1:])
        if text.endswith("```"):
            text = "\n".join(text.splitlines()[:-1])

        try:
            data: Dict[str, Any] = json.loads(text)
        except json.JSONDecodeError as exc:
            logger.warning("ClaudeParser: JSON decode error (%s); using builtin", exc)
            from gnat.nlp.builtin import BuiltinParser
            return BuiltinParser().parse(query, default_limit=default_limit)

        since = self._parse_dt(data.get("since"))
        until = self._parse_dt(data.get("until"))

        return QuerySpec(
            entities   = [str(e) for e in data.get("entities", [])],
            ioc_types  = [str(t) for t in data.get("ioc_types", [])],
            since      = since,
            until      = until,
            platforms  = [str(p) for p in data.get("platforms", [])],
            limit      = int(data.get("limit", default_limit)),
            raw_query  = query,
        )

    @staticmethod
    def _parse_dt(value: Optional[str]) -> Optional[datetime]:
        if not value:
            return None
        try:
            dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except (ValueError, TypeError):
            return None
