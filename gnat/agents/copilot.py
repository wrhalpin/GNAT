# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.agents.copilot
=======================

:class:`CopilotReader` — a :class:`~gnat.ingest.base.SourceReader` that
queries Microsoft Copilot via the Bot Framework DirectLine API to retrieve
threat-relevant content from configured M365 sources.

Use case
--------
Your threat intelligence arrives via M365 channels — forwarded vendor
advisories in Outlook, threat reports shared in Teams, curated SharePoint
libraries.  Copilot has native access to all of these through Microsoft Graph.
:class:`CopilotReader` delegates source navigation to Copilot and returns
the content as raw text records for the :class:`~gnat.agents.parsing.ParsingAgent`
to extract structured intel from.

Configuration
-------------

INI file::

    [copilot]
    directline_secret = <bot-framework-directline-secret>
    bot_timeout       = 60
    use_token_exchange = true   ; optional — exchange secret for short-lived token

Sources are defined in code (not INI) because they vary per job::

    sources = [
        {
            "type":    "sharepoint",
            "name":    "Security-Intel",
            "url":     "https://contoso.sharepoint.com/sites/Security-Intel",
            "library": "Threat Reports",
        },
        {
            "type":  "mailbox",
            "name":  "Security Advisories",
            "query": "subject:advisory OR subject:threat from:vendor-alerts@contoso.com",
        },
        {
            "type":  "teams_channel",
            "name":  "SOC Intel Feed",
            "team":  "Security Operations",
            "channel": "Threat Intel",
        },
    ]

    reader = CopilotReader(
        directline_secret="...",
        sources=sources,
        newer_than=ctx.last_success_iso,
    )

Source types
------------

+------------------+----------------------------------------------------------+
| type             | Required keys                                            |
+==================+==========================================================+
| ``sharepoint``   | ``name``, ``url``, optionally ``library``                |
+------------------+----------------------------------------------------------+
| ``mailbox``      | ``name``, ``query`` (OWA search syntax)                  |
+------------------+----------------------------------------------------------+
| ``teams_channel``| ``name``, ``team``, ``channel``                          |
+------------------+----------------------------------------------------------+
| ``onedrive``     | ``name``, ``path``                                       |
+------------------+----------------------------------------------------------+

Pipeline usage
--------------
::

    from gnat.agents import CopilotReader, ParsingAgent, AgentConfig
    from gnat.ingest import IngestPipeline
    from gnat.schedule import FeedJob

    def make_reader(ctx):
        return CopilotReader(
            directline_secret=copilot_secret,
            sources=[
                {"type": "sharepoint", "name": "ThreatReports",
                 "url": "https://contoso.sharepoint.com/sites/ThreatReports"},
                {"type": "mailbox", "name": "VendorAdvisories",
                 "query": "from:threatintel@vendor.com"},
            ],
            newer_than=ctx.last_success_iso,
        )

    job = FeedJob(
        job_id="m365-threat-intel",
        reader_factory=make_reader,
        mapper_factory=lambda ctx: ParsingAgent(AgentConfig.from_ini()),
        interval_seconds=3600,
    )

DirectLine protocol
-------------------
The DirectLine v3 API is used:

1. ``POST /v3/directline/conversations``      — open a conversation
2. ``POST /v3/directline/conversations/{id}/activities`` — send message
3. ``GET  /v3/directline/conversations/{id}/activities`` — poll for reply
4. Parse the bot reply and return content as ``RawRecord`` dicts

The full DirectLine async client is in
:mod:`gnat.async_client.connectors`; this reader uses a synchronous
``urllib``-based implementation for compatibility with the sync
``SourceReader`` interface.
"""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from typing import Any

from gnat.agents.prompts import COPILOT_NEWER_HINT, COPILOT_QUERY_TEMPLATE
from gnat.ingest.base import RawRecord, SourceReader
from gnat.utils.url_security import validate_url_scheme

logger = logging.getLogger(__name__)

_DIRECTLINE_BASE = "https://directline.botframework.com/v3/directline"


class CopilotReader(SourceReader):
    """
    Retrieves threat-relevant content from configured M365 sources via
    Microsoft Copilot and the Bot Framework DirectLine API.

    Parameters
    ----------
    directline_secret : str
        Bot Framework DirectLine secret.  From the Azure Bot registration,
        Channels → Direct Line → Secret keys.
    sources : list of dict
        M365 sources to query.  Each dict must have ``type`` and ``name``.
        See module docstring for per-type required keys.
    newer_than : str, optional
        ISO 8601 timestamp.  Only retrieve content published/received after
        this time.  Typically ``ctx.last_success_iso`` from
        :class:`~gnat.schedule.job.JobRunContext`.
    bot_timeout : int
        Seconds to wait for a Copilot response per source query.
        Default ``60``.
    poll_interval : float
        Seconds between DirectLine polling attempts.  Default ``2.0``.
    max_poll_attempts : int
        Maximum polling attempts before giving up on a source.
        Default ``30`` (60 seconds at 2s interval).
    label : str
        Human-readable label for logging and ``IngestResult``.

    Raises
    ------
    ValueError
        If ``sources`` is empty or a source dict is missing required keys.
    """

    #: Refresh the token when fewer than this many seconds remain.
    _TOKEN_REFRESH_BUFFER: int = 300  # 5 minutes
    #: DirectLine tokens are valid for 30 minutes per Microsoft spec.
    _TOKEN_LIFETIME: int = 1800

    def __init__(
        self,
        directline_secret: str,
        sources: list[dict[str, str]],
        newer_than: str | None = None,
        bot_timeout: int = 60,
        poll_interval: float = 2.0,
        max_poll_attempts: int = 30,
        label: str = "CopilotReader",
        use_token_exchange: bool = False,
    ):
        """Initialize CopilotReader."""
        super().__init__(source_id=label)
        if not sources:
            raise ValueError("CopilotReader: at least one source must be configured")
        self._secret = directline_secret
        self._sources = sources
        self._newer_than = newer_than
        self._timeout = bot_timeout
        self._poll_interval = poll_interval
        self._max_polls = max_poll_attempts
        self._use_token_exchange = use_token_exchange
        # Token state (populated on first use when use_token_exchange=True)
        self._token: str | None = None
        self._token_expires_at: float | None = None  # UNIX timestamp

    @classmethod
    def from_ini(
        cls,
        sources: list[dict[str, str]],
        newer_than: str | None = None,
        config_path: str | None = None,
    ) -> CopilotReader:
        """
        Construct from the ``[copilot]`` section of the GNAT INI file.

        Parameters
        ----------
        sources : list of dict
            M365 sources to query (see class docstring).
        newer_than : str, optional
            ISO 8601 cutoff timestamp.
        config_path : str, optional
            Explicit path to config.ini.

        Raises
        ------
        KeyError
            If ``[copilot]`` section or ``directline_secret`` key is missing.
        """
        from gnat.config import GNATConfig

        cfg = GNATConfig(config_path)
        try:
            section = cfg.get("copilot")
        except KeyError:
            raise KeyError(
                "No [copilot] section in config.ini. Add:\n\n"
                "  [copilot]\n"
                "  directline_secret = <your-directline-secret>\n"
            )
        secret = section.get("directline_secret", "")
        if not secret:
            raise KeyError("[copilot] section missing 'directline_secret'")

        use_token_exchange = section.get("use_token_exchange", "false").strip().lower() in (
            "true",
            "1",
            "yes",
        )

        return cls(
            directline_secret=secret,
            sources=sources,
            newer_than=newer_than,
            bot_timeout=int(section.get("bot_timeout", 60)),
            use_token_exchange=use_token_exchange,
        )

    # ── SourceReader interface ─────────────────────────────────────────────

    def _iter_records(self) -> Iterator[RawRecord]:
        """Yield one RawRecord per content item returned by Copilot."""
        for source in self._sources:
            source_type = source.get("type", "unknown")
            source_name = source.get("name", source_type)

            logger.info("CopilotReader: querying %s source %r", source_type, source_name)

            items = self._query_source(source)
            for item in items:
                yield {
                    "text": item.get("text", ""),
                    "url": item.get("url", ""),
                    "title": item.get("title", f"{source_name} content"),
                    "topic": source_name,
                    "retrieved_at": _utcnow_iso(),
                    "source_type": source_type,
                    "author": item.get("author", ""),
                    "date": item.get("date", ""),
                    "metadata": {
                        "m365_source_type": source_type,
                        "m365_source_name": source_name,
                    },
                }

    # ── DirectLine interaction ─────────────────────────────────────────────

    def _query_source(self, source: dict[str, str]) -> list[dict[str, Any]]:
        """
        Open a DirectLine conversation, send a Copilot query for one M365
        source, poll for the reply, and return parsed content items.
        """
        # Ensure we have a valid token (exchange/refresh if configured)
        self._ensure_token()

        # Build the query text for Copilot
        query_text = self._build_query(source)

        # Open conversation
        conv_id = self._open_conversation()
        if not conv_id:
            logger.warning(
                "CopilotReader: failed to open DirectLine conversation for %r",
                source.get("name"),
            )
            return []

        # Send message
        sent = self._send_message(conv_id, query_text)
        if not sent:
            logger.warning(
                "CopilotReader: failed to send message for source %r",
                source.get("name"),
            )
            return []

        # Poll for reply
        reply_text = self._poll_reply(conv_id)
        if not reply_text:
            logger.warning(
                "CopilotReader: no reply from Copilot for source %r",
                source.get("name"),
            )
            return []

        # Parse the JSON array Copilot returns
        return self._parse_reply(reply_text, source)

    def _build_query(self, source: dict[str, str]) -> str:
        """Build the natural-language query sent to Copilot."""
        source_type = source.get("type", "unknown")
        source_name = source.get("name", "")

        newer_hint = ""
        if self._newer_than:
            newer_hint = COPILOT_NEWER_HINT.format(newer_than=self._newer_than)

        # Build a human-readable source descriptor
        if source_type == "sharepoint":
            library = source.get("library", "")
            descriptor = f'SharePoint site "{source_name}"'
            if library:
                descriptor += f', library "{library}"'
        elif source_type == "mailbox":
            query_filter = source.get("query", "")
            descriptor = f'mailbox "{source_name}"'
            if query_filter:
                descriptor += f" (filter: {query_filter})"
        elif source_type == "teams_channel":
            team = source.get("team", "")
            channel = source.get("channel", "")
            descriptor = f'"{source_name}" (Teams channel "{channel}" in team "{team}")'
        elif source_type == "onedrive":
            path = source.get("path", "")
            descriptor = f'OneDrive "{source_name}"'
            if path:
                descriptor += f" at path {path}"
        else:
            descriptor = f'"{source_name}" ({source_type})'

        return COPILOT_QUERY_TEMPLATE.format(
            source_type=source_type,
            source_name=descriptor,
            newer_than_hint=newer_hint,
        )

    # ── Token exchange / refresh ───────────────────────────────────────────

    def _ensure_token(self) -> None:
        """
        Ensure a valid DirectLine token is available.

        When ``use_token_exchange`` is ``True``:

        * First call: exchanges the DirectLine secret for a short-lived token
          via ``POST /v3/directline/tokens/generate``.
        * Subsequent calls: refreshes the token via
          ``POST /v3/directline/tokens/refresh`` if fewer than
          :attr:`_TOKEN_REFRESH_BUFFER` seconds remain before expiry.

        Does nothing when ``use_token_exchange`` is ``False`` (secret is used
        directly as the Bearer value).
        """
        if not self._use_token_exchange:
            return

        now = time.time()

        if self._token is None:
            # First use — exchange secret for token
            token = self._exchange_for_token()
            if token:
                self._token = token
                self._token_expires_at = now + self._TOKEN_LIFETIME
                logger.debug(
                    "CopilotReader: obtained DirectLine token (expires in %ds)",
                    self._TOKEN_LIFETIME,
                )
            else:
                logger.warning("CopilotReader: token exchange failed — falling back to secret")
        elif (
            self._token_expires_at is not None
            and (self._token_expires_at - now) < self._TOKEN_REFRESH_BUFFER
        ):
            # Token expiring soon — refresh it
            new_token = self._refresh_token()
            if new_token:
                self._token = new_token
                self._token_expires_at = now + self._TOKEN_LIFETIME
                logger.debug("CopilotReader: refreshed DirectLine token")
            else:
                logger.warning("CopilotReader: token refresh failed — reusing existing token")

    def _exchange_for_token(self) -> str | None:
        """
        Exchange the DirectLine secret for a short-lived conversation token.

        Calls ``POST /v3/directline/tokens/generate`` with the secret as
        the Bearer credential and returns the ``token`` field from the
        response, or ``None`` on failure.
        """
        resp = self._dl_request(
            f"{_DIRECTLINE_BASE}/tokens/generate",
            data=b"{}",
            method="POST",
        )
        if resp:
            return resp.get("token")
        return None

    def _refresh_token(self) -> str | None:
        """
        Refresh the current DirectLine token before it expires.

        Calls ``POST /v3/directline/tokens/refresh`` with the current token
        as the Bearer credential and returns the new ``token`` value, or
        ``None`` on failure.

        The caller should fall back to the existing token if ``None`` is
        returned (the old token is still valid for a few minutes).
        """
        if not self._token:
            return None
        resp = self._dl_request(
            f"{_DIRECTLINE_BASE}/tokens/refresh",
            data=b"{}",
            method="POST",
        )
        if resp:
            return resp.get("token")
        return None

    def _bearer(self) -> str:
        """
        Return the current bearer value.

        When ``use_token_exchange`` is ``True`` and a token has been obtained,
        the token is returned.  Otherwise the DirectLine secret is used
        (secrets are long-lived and valid as bearer tokens per the DirectLine
        spec).
        """
        if self._use_token_exchange and self._token:
            return self._token
        return self._secret

    # ── DirectLine v3 HTTP calls (sync urllib) ─────────────────────────────

    def _dl_headers(self) -> dict[str, str]:
        """Internal helper for dl headers."""
        return {
            "Authorization": f"Bearer {self._bearer()}",
            "Content-Type": "application/json",
        }

    def _dl_request(
        self,
        url: str,
        data: bytes | None = None,
        method: str = "GET",
    ) -> dict[str, Any] | None:
        """Make a DirectLine API request and return the parsed JSON body."""
        validate_url_scheme(url, allow_http=False)
        req = urllib.request.Request(
            url,
            data=data,
            headers=self._dl_headers(),
            method=method,
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:  # nosec B310  # nosemgrep
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            logger.error("CopilotReader: DirectLine HTTP %d: %.300s", exc.code, body)
            return None
        except (urllib.error.URLError, json.JSONDecodeError) as exc:
            logger.error("CopilotReader: DirectLine request error: %s", exc)
            return None

    def _open_conversation(self) -> str | None:
        """POST /conversations and return the conversation id."""
        resp = self._dl_request(
            f"{_DIRECTLINE_BASE}/conversations",
            data=b"{}",
            method="POST",
        )
        if resp and resp.get("conversationId"):
            return resp["conversationId"]
        return None

    def _send_message(self, conv_id: str, text: str) -> bool:
        """POST an activity (user message) to the conversation."""
        body = json.dumps(
            {
                "type": "message",
                "from": {"id": "gnat-agent", "name": "GNAT"},
                "text": text,
            }
        ).encode("utf-8")

        resp = self._dl_request(
            f"{_DIRECTLINE_BASE}/conversations/{conv_id}/activities",
            data=body,
            method="POST",
        )
        return resp is not None and "id" in resp

    def _poll_reply(self, conv_id: str) -> str | None:
        """
        Poll GET /activities until a bot reply appears, then return its text.

        Copilot may take several seconds to query M365 Graph.  We poll at
        ``poll_interval`` second intervals up to ``max_poll_attempts`` times.
        """
        watermark: str | None = None

        for attempt in range(self._max_polls):
            url = f"{_DIRECTLINE_BASE}/conversations/{conv_id}/activities"
            if watermark:
                url += f"?watermark={watermark}"

            resp = self._dl_request(url)
            if resp is None:
                time.sleep(self._poll_interval)
                continue

            watermark = resp.get("watermark")
            activities = resp.get("activities", [])

            # Look for a bot reply (fromId != gnat-agent)
            for activity in activities:
                from_id = activity.get("from", {}).get("id", "")
                if from_id != "gnat-agent" and activity.get("type") == "message":
                    text = activity.get("text", "")
                    # Copilot sometimes wraps text in an Adaptive Card
                    if not text:
                        text = self._extract_card_text(activity)
                    if text:
                        logger.debug("CopilotReader: got reply after %d polls", attempt + 1)
                        return text

            time.sleep(self._poll_interval)

        logger.warning("CopilotReader: no reply after %d poll attempts", self._max_polls)
        return None

    @staticmethod
    def _extract_card_text(activity: dict[str, Any]) -> str:
        """Extract text from an Adaptive Card attachment if present."""
        for attachment in activity.get("attachments", []):
            if attachment.get("contentType") == "application/vnd.microsoft.card.adaptive":
                content = attachment.get("content", {})
                bodies = content.get("body", [])
                parts = []
                for element in bodies:
                    if element.get("type") == "TextBlock":
                        parts.append(element.get("text", ""))
                return "\n".join(parts)
        return ""

    @staticmethod
    def _parse_reply(reply_text: str, source: dict[str, str]) -> list[dict[str, Any]]:
        """
        Parse the JSON array that Copilot returns.

        Falls back to wrapping the raw text as a single content item if
        the response is not valid JSON — Copilot sometimes returns
        prose when it cannot find structured results.
        """
        text = reply_text.strip()
        # Strip markdown fences
        if text.startswith("```"):
            lines = text.split("\n")
            text = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])

        try:
            data = json.loads(text)
            if isinstance(data, list):
                return data
        except json.JSONDecodeError:
            pass

        # Prose fallback — wrap as single item
        if reply_text.strip():
            return [
                {
                    "title": source.get("name", "M365 content"),
                    "url": "",
                    "text": reply_text.strip(),
                }
            ]
        return []

    def __repr__(self) -> str:  # pragma: no cover
        """Return unambiguous string representation."""
        return f"CopilotReader(sources={len(self._sources)}, newer_than={self._newer_than!r})"


def _utcnow_iso() -> str:
    """Internal helper for utcnow iso."""
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()
