# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.discord.connector
===================================

Discord Bot connector for GNAT threat intelligence workflows.

Authentication
--------------
Bot token via ``Authorization: Bot <token>`` header::

    [discord]
    host      = https://discord.com
    bot_token = Bot your-bot-token-here

Register a Discord application at https://discord.com/developers/applications,
create a Bot user, and copy the token.  Enable the ``MESSAGE CONTENT`` privileged
intent if you need to read message content via the gateway (not required for the
REST API used here).

STIX Type Mapping
-----------------
+------------------+----------------------------------------+
| STIX Type        | Discord Resource                       |
+==================+========================================+
| note             | Channel message                        |
+------------------+----------------------------------------+
| observed-data    | Message thread / channel history       |
+------------------+----------------------------------------+
| indicator        | IOC-bearing message (after extraction) |
+------------------+----------------------------------------+
| identity         | Guild member / user                    |
+------------------+----------------------------------------+

Key Endpoints (Discord REST API v10)
-------------------------------------
* ``GET  /channels/{channel_id}``                       — channel info
* ``GET  /channels/{channel_id}/messages``              — message history
* ``GET  /channels/{channel_id}/messages/{message_id}`` — single message
* ``POST /channels/{channel_id}/messages``              — send message
* ``DELETE /channels/{channel_id}/messages/{msg_id}``  — delete message
* ``GET  /channels/{channel_id}/threads/archived/public`` — archived threads
* ``POST /channels/{channel_id}/messages/{msg_id}/threads`` — start thread
* ``GET  /guilds/{guild_id}/members``                   — guild members
* ``GET  /gateway/bot``                                 — bot info / health

Notes
-----
* The connector focuses on **message ingestion** for threat-intel workflows:
  security channels, incident threads, IOC-sharing DMs.
* ``list_objects("note")`` returns messages from a channel as STIX ``note`` objects.
* ``list_objects("observed-data")`` returns thread history as ``observed-data``.
* ``upsert_object("note", ...)`` posts a message to a channel.
* IOC extraction is delegated to the caller — use ``gnat.nlp`` or a ParsingAgent.
* Rate limits: Discord enforces per-route + global limits.  The connector applies
  a conservative ``?limit=100`` cap.  Callers should catch :class:`~gnat.clients.base.GNATClientError`
  with HTTP 429 and back off.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.stix.version import CURRENT_SPEC_VERSION

_API_BASE = "/api/v10"


def _now_ts() -> str:
    """ISO 8601 UTC timestamp with millisecond precision."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _snowflake_to_ts(snowflake_id: str | int) -> str:
    """Convert a Discord snowflake ID to an ISO 8601 UTC timestamp string."""
    try:
        # Discord epoch: 2015-01-01T00:00:00.000Z = 1420070400000 ms
        ms = (int(snowflake_id) >> 22) + 1420070400000
        dt = datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    except (TypeError, ValueError):
        return _now_ts()


class DiscordClient(BaseClient, ConnectorMixin):
    """
    HTTP client for the Discord REST API v10 (bot context).

    Supports reading channel messages and threads as STIX objects and posting
    analyst notes back to Discord channels.

    Parameters
    ----------
    host : str
        Base URL, default ``"https://discord.com"``.
    bot_token : str
        Discord bot token.  Include the ``Bot `` prefix if desired; the connector
        will normalise it automatically.
    guild_id : str, optional
        Default guild (server) ID used by :meth:`list_members`.
    """

    stix_type_map: dict[str, str] = {
        "note": "message",
        "observed-data": "thread",
        "indicator": "message",
        "identity": "member",
    }

    def __init__(
        self,
        host: str = "https://discord.com",
        bot_token: str = "",
        guild_id: str = "",
        **kwargs: Any,
    ) -> None:
        """Initialize DiscordClient."""
        super().__init__(host=host, **kwargs)
        # Normalise: strip leading "Bot " if caller already included it
        raw = bot_token.strip()
        self._bot_token = raw if raw.startswith("Bot ") else f"Bot {raw}" if raw else ""
        self._guild_id = guild_id

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Set Discord bot token auth header and JSON content-type."""
        self._auth_headers["Authorization"] = self._bot_token
        self._auth_headers["Content-Type"] = "application/json"

    # ── ConnectorMixin — CRUD ─────────────────────────────────────────────

    def health_check(self) -> bool:
        """
        Verify bot connectivity via ``GET /gateway/bot``.

        Returns
        -------
        bool
            ``True`` if the API responds successfully.
        """
        self.get(f"{_API_BASE}/gateway/bot")
        return True

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """
        Fetch a single Discord object by type and id.

        Parameters
        ----------
        stix_type : str
            ``"note"`` or ``"indicator"`` → fetch message by id (``channel_id:message_id``).
            ``"observed-data"`` → fetch channel info by channel id.
            ``"identity"`` → fetch user by user id.
        object_id : str
            For messages: ``"<channel_id>:<message_id>"`` (colon-separated).
            For channels, threads, users: plain id string.
        """
        if stix_type in ("note", "indicator"):
            parts = object_id.split(":", 1)
            if len(parts) != 2:
                raise GNATClientError(
                    f"object_id must be '<channel_id>:<message_id>' for stix_type '{stix_type}'"
                )
            channel_id, message_id = parts
            msg = self.get_message(channel_id, message_id)
            return self.to_stix(msg)

        if stix_type == "observed-data":
            channel = self.get_channel(object_id)
            return self.to_stix({"_resource": "channel", **channel})

        if stix_type == "identity":
            user = self.get_user(object_id)
            return self.to_stix({"_resource": "user", **user})

        raise GNATClientError(
            f"get_object does not support stix_type '{stix_type}' for Discord. "
            "Supported: note, indicator, observed-data, identity."
        )

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        List Discord objects as STIX dicts.

        Parameters
        ----------
        stix_type : str
            - ``"note"`` / ``"indicator"`` — messages from ``filters["channel_id"]``
            - ``"observed-data"`` — messages from a thread ``filters["thread_id"]``
            - ``"identity"`` — guild members (requires :attr:`_guild_id`)
        filters : dict, optional
            ``channel_id``, ``thread_id``, ``before`` (snowflake), ``after`` (snowflake),
            ``guild_id`` overrides default.
        page_size : int
            Max messages per call (Discord max 100, enforced).
        """
        filters = dict(filters or {})
        limit = min(page_size, 100)

        if stix_type in ("note", "indicator"):
            channel_id = filters.get("channel_id", "")
            if not channel_id:
                raise GNATClientError(
                    "list_objects requires filters['channel_id'] for stix_type 'note'/'indicator'."
                )
            messages = self.list_messages(
                channel_id,
                limit=limit,
                before=filters.get("before"),
                after=filters.get("after"),
            )
            return [self.to_stix(m) for m in messages]

        if stix_type == "observed-data":
            thread_id = filters.get("thread_id") or filters.get("channel_id", "")
            if not thread_id:
                raise GNATClientError(
                    "list_objects requires filters['thread_id'] or filters['channel_id'] "
                    "for stix_type 'observed-data'."
                )
            messages = self.list_messages(thread_id, limit=limit)
            return [self.to_stix({"_resource": "thread_message", **m}) for m in messages]

        if stix_type == "identity":
            guild_id = filters.get("guild_id") or self._guild_id
            if not guild_id:
                raise GNATClientError(
                    "list_objects requires filters['guild_id'] or DiscordClient(guild_id=...) "
                    "for stix_type 'identity'."
                )
            members = self.list_members(guild_id, limit=limit)
            return [self.to_stix({"_resource": "user", **m.get("user", m)}) for m in members]

        raise GNATClientError(
            f"list_objects does not support stix_type '{stix_type}' for Discord. "
            "Supported: note, indicator, observed-data, identity."
        )

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """
        Post a message to a Discord channel.

        Parameters
        ----------
        stix_type : str
            Must be ``"note"`` — only message creation is supported.
        payload : dict
            Must contain ``channel_id`` and ``content``.
            Optional: ``thread_id`` (posts into a thread).

        Returns
        -------
        dict
            STIX ``note`` representation of the created message.
        """
        if stix_type != "note":
            raise GNATClientError(
                f"Discord connector upsert_object only supports stix_type 'note', got '{stix_type}'."
            )
        channel_id = payload.get("channel_id", "")
        content = payload.get("content", "")
        if not channel_id or not content:
            raise GNATClientError(
                "upsert_object payload must contain 'channel_id' and 'content'."
            )
        body: dict[str, Any] = {"content": content}
        if "thread_id" in payload:
            body["thread_id"] = payload["thread_id"]
        created = self.post_message(channel_id, content=content, thread_id=payload.get("thread_id"))
        return self.to_stix(created)

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """
        Delete a Discord message.

        Parameters
        ----------
        stix_type : str
            Must be ``"note"`` or ``"indicator"``.
        object_id : str
            ``"<channel_id>:<message_id>"`` (colon-separated).
        """
        if stix_type not in ("note", "indicator"):
            raise GNATClientError(
                f"Discord connector delete_object only supports 'note'/'indicator', got '{stix_type}'."
            )
        parts = object_id.split(":", 1)
        if len(parts) != 2:
            raise GNATClientError(
                "object_id must be '<channel_id>:<message_id>' for delete_object."
            )
        channel_id, message_id = parts
        self.delete_message(channel_id, message_id)

    # ── Discord-specific helpers ──────────────────────────────────────────

    def get_channel(self, channel_id: str) -> dict[str, Any]:
        """Fetch channel metadata by ID."""
        return self.get(f"{_API_BASE}/channels/{channel_id}")

    def get_message(self, channel_id: str, message_id: str) -> dict[str, Any]:
        """Fetch a single message from a channel."""
        return self.get(f"{_API_BASE}/channels/{channel_id}/messages/{message_id}")

    def list_messages(
        self,
        channel_id: str,
        limit: int = 50,
        before: str | None = None,
        after: str | None = None,
        around: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Retrieve message history from a channel or thread.

        Parameters
        ----------
        channel_id : str
            Channel or thread snowflake ID.
        limit : int
            Number of messages (1-100).
        before, after, around : str, optional
            Snowflake IDs for cursor-based pagination.
        """
        params: dict[str, Any] = {"limit": min(limit, 100)}
        if before:
            params["before"] = before
        if after:
            params["after"] = after
        if around:
            params["around"] = around
        result = self.get(f"{_API_BASE}/channels/{channel_id}/messages", params=params)
        return result if isinstance(result, list) else []

    def post_message(
        self,
        channel_id: str,
        content: str,
        thread_id: str | None = None,
        embeds: list[dict] | None = None,
    ) -> dict[str, Any]:
        """
        Post a message to a channel or thread.

        Parameters
        ----------
        channel_id : str
            Target channel snowflake ID.
        content : str
            Message text (up to 2000 characters; truncated silently).
        thread_id : str, optional
            If provided, sends into an existing thread.
        embeds : list, optional
            Discord embed objects appended to the message.
        """
        body: dict[str, Any] = {"content": content[:2000]}
        if thread_id:
            body["thread_id"] = thread_id
        if embeds:
            body["embeds"] = embeds
        return self.post(f"{_API_BASE}/channels/{channel_id}/messages", json_body=body)

    def delete_message(self, channel_id: str, message_id: str) -> None:
        """Delete a message by channel and message snowflake IDs."""
        self.delete(f"{_API_BASE}/channels/{channel_id}/messages/{message_id}")

    def start_thread(
        self,
        channel_id: str,
        message_id: str,
        name: str,
        auto_archive_minutes: int = 1440,
    ) -> dict[str, Any]:
        """
        Create a thread from an existing message.

        Parameters
        ----------
        auto_archive_minutes : int
            60 | 1440 | 4320 | 10080.  Default 1440 (1 day).
        """
        body = {"name": name[:100], "auto_archive_duration": auto_archive_minutes}
        return self.post(
            f"{_API_BASE}/channels/{channel_id}/messages/{message_id}/threads",
            json_body=body,
        )

    def list_archived_threads(self, channel_id: str) -> list[dict[str, Any]]:
        """List public archived threads in a channel."""
        result = self.get(f"{_API_BASE}/channels/{channel_id}/threads/archived/public")
        return result.get("threads", []) if isinstance(result, dict) else []

    def get_user(self, user_id: str) -> dict[str, Any]:
        """Fetch a Discord user by ID."""
        return self.get(f"{_API_BASE}/users/{user_id}")

    def list_members(self, guild_id: str, limit: int = 100) -> list[dict[str, Any]]:
        """List guild members (requires GUILD_MEMBERS privileged intent or admin scope)."""
        result = self.get(f"{_API_BASE}/guilds/{guild_id}/members", params={"limit": min(limit, 1000)})
        return result if isinstance(result, list) else []

    # ── ConnectorMixin — STIX translation ─────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """
        Translate a Discord API object to STIX 2.1.

        Dispatch logic
        --------------
        * Dict contains ``"_resource": "channel"`` → ``observed-data``
        * Dict contains ``"_resource": "user"`` → ``identity``
        * Otherwise (message) → ``note``

        Parameters
        ----------
        native : dict
            Raw Discord API response.  For messages: must contain ``id``.

        Returns
        -------
        dict
            STIX 2.1 object dict.
        """
        resource = native.get("_resource", "message")

        if resource == "channel":
            return self._channel_to_stix(native)
        if resource == "user":
            return self._user_to_stix(native)
        return self._message_to_stix(native)

    def _message_to_stix(self, msg: dict[str, Any]) -> dict[str, Any]:
        """Map a Discord message to a STIX ``note`` object."""
        msg_id = str(msg.get("id", ""))
        channel_id = str(msg.get("channel_id", ""))
        author = msg.get("author") or {}
        author_id = str(author.get("id", ""))
        author_name = author.get("username", "unknown")
        content = msg.get("content", "")
        ts = _snowflake_to_ts(msg_id) if msg_id else _now_ts()

        stix_id = f"note--discord-{msg_id}" if msg_id else f"note--discord-{_now_ts()}"

        return {
            "type": "note",
            "id": stix_id,
            "spec_version": CURRENT_SPEC_VERSION,
            "created": ts,
            "modified": ts,
            "abstract": content[:256] if content else "",
            "content": content,
            "authors": [author_name],
            "x_discord": {
                "message_id": msg_id,
                "channel_id": channel_id,
                "author_id": author_id,
                "author_username": author_name,
                "timestamp": msg.get("timestamp", ts),
                "edited_timestamp": msg.get("edited_timestamp"),
                "attachments": msg.get("attachments", []),
                "embeds": msg.get("embeds", []),
                "mentions": [u.get("username") for u in msg.get("mentions", [])],
                "pinned": msg.get("pinned", False),
                "type": msg.get("type", 0),
            },
        }

    def _channel_to_stix(self, channel: dict[str, Any]) -> dict[str, Any]:
        """Map a Discord channel to a STIX ``observed-data`` object."""
        channel_id = str(channel.get("id", ""))
        now = _now_ts()
        return {
            "type": "observed-data",
            "id": f"observed-data--discord-channel-{channel_id}",
            "spec_version": CURRENT_SPEC_VERSION,
            "created": now,
            "modified": now,
            "first_observed": now,
            "last_observed": now,
            "number_observed": 1,
            "object_refs": [],
            "x_discord": {
                "channel_id": channel_id,
                "name": channel.get("name", ""),
                "topic": channel.get("topic", ""),
                "type": channel.get("type", 0),
                "guild_id": channel.get("guild_id", ""),
                "nsfw": channel.get("nsfw", False),
            },
        }

    def _user_to_stix(self, user: dict[str, Any]) -> dict[str, Any]:
        """Map a Discord user to a STIX ``identity`` object."""
        user_id = str(user.get("id", ""))
        username = user.get("username", "unknown")
        now = _now_ts()
        return {
            "type": "identity",
            "id": f"identity--discord-user-{user_id}",
            "spec_version": CURRENT_SPEC_VERSION,
            "created": now,
            "modified": now,
            "name": username,
            "identity_class": "individual",
            "x_discord": {
                "user_id": user_id,
                "username": username,
                "discriminator": user.get("discriminator", "0"),
                "bot": user.get("bot", False),
                "system": user.get("system", False),
            },
        }

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """
        Convert a STIX object to a Discord message payload.

        Only ``note`` objects are meaningful as outbound messages.
        Other STIX types return a read-only guidance payload.
        """
        stix_type = stix_dict.get("type", "")
        if stix_type == "note":
            content = stix_dict.get("content") or stix_dict.get("abstract", "")
            channel_id = ""
            x_discord = stix_dict.get("x_discord", {})
            if isinstance(x_discord, dict):
                channel_id = x_discord.get("channel_id", "")
            return {"content": content[:2000], "channel_id": channel_id}

        return {
            "note": (
                "Discord connector converts STIX notes to messages. "
                f"stix_type '{stix_type}' is read-only in Discord."
            ),
            "stix_id": stix_dict.get("id", ""),
        }
