# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.agents.claude
==================

Claude (Anthropic) provider for the unified LLMClient.
Uses urllib3 (GNAT standard) – no requests dependency.

Supports:
- Chat completions
- Structured JSON output
- Streaming (server-sent events)
- Tool / function calling (``tool_use``)
- Prompt caching (``cache_control`` on stable system prompts)
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any
from urllib.parse import urljoin

from gnat.agents.base import LLMProvider
from gnat.clients.base import BaseClient, GNATClientError

# Header enabling Anthropic prompt caching (saves cost on repeated system prompts).
_CACHE_BETA_HEADER = "prompt-caching-2024-07-31"


class ClaudeProvider(LLMProvider, BaseClient):
    """
    Anthropic Claude Messages API provider.

    Configuration (from [claude] INI section):
        api_key, model (default: claude-sonnet-4-6)

    Prompt caching is enabled by default when ``cache_system_prompt=True``
    (the default).  Stable system prompts receive
    ``"cache_control": {"type": "ephemeral"}`` which reduces repeated API
    costs by ~90%.
    """

    def __init__(
        self,
        api_key: str,
        model: str = "claude-sonnet-4-6",
        cache_system_prompt: bool = True,
        **kwargs: Any,
    ) -> None:
        """Initialize ClaudeProvider."""
        super().__init__(host="https://api.anthropic.com", **kwargs)
        self._api_key = api_key
        self.model = model
        self._cache_system = cache_system_prompt

    def authenticate(self) -> None:
        """Set Anthropic headers."""
        self._auth_headers["x-api-key"] = self._api_key
        self._auth_headers["anthropic-version"] = "2023-06-01"
        self._auth_headers["Content-Type"] = "application/json"

    def _system_block(self, system_text: str) -> list[dict[str, Any]] | str:
        """Return a system block with cache_control when caching is enabled."""
        if self._cache_system and system_text:
            return [
                {
                    "type": "text",
                    "text": system_text,
                    "cache_control": {"type": "ephemeral"},
                }
            ]
        return system_text

    def chat(
        self,
        messages: list[dict[str, str]],
        temperature: float = 0.7,
        max_tokens: int | None = 4096,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Claude Messages API chat completion."""
        self.authenticate()
        # Separate system messages from the conversation
        filtered: list[dict[str, str]] = []
        system_text = ""
        for m in messages:
            if m.get("role") == "system":
                system_text = m.get("content", "")
            else:
                filtered.append(m)

        extra: dict[str, Any] = {}
        if self._cache_system and system_text:
            extra["anthropic-beta"] = _CACHE_BETA_HEADER
        extra.update(kwargs)

        payload: dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": filtered,
        }
        if system_text:
            payload["system"] = self._system_block(system_text)

        headers: dict[str, str] = {}
        if self._cache_system and system_text:
            headers["anthropic-beta"] = _CACHE_BETA_HEADER

        return self.post("/v1/messages", json=payload, headers=headers)

    def structured(
        self,
        prompt: str,
        output_schema: dict[str, Any],
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Structured output via JSON prompting (cached system prompt)."""
        system = (
            "You are a helpful assistant. Respond ONLY with valid JSON matching this schema:\n"
            f"{json.dumps(output_schema, indent=2)}\n"
            "No extra text, no markdown fences."
        )
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": prompt},
        ]
        response = self.chat(messages, **kwargs)
        content = response["content"][0]["text"]
        try:
            return json.loads(content)
        except json.JSONDecodeError as e:
            raise GNATClientError(f"Claude did not return valid JSON: {e}") from e

    def stream(self, prompt: str, **kwargs: Any) -> Iterator[str]:
        """
        Yield incremental text chunks from a streaming Claude completion.

        Uses server-sent events (``stream: true``).  The response is parsed
        line-by-line; only ``content_block_delta`` events with
        ``delta.type == "text_delta"`` yield text.

        Parameters
        ----------
        prompt : str
            User message.
        **kwargs
            ``system``, ``temperature``, ``max_tokens`` forwarded to the API.
        """
        self.authenticate()
        system_text: str = kwargs.pop("system", "")
        payload: dict[str, Any] = {
            "model": self.model,
            "max_tokens": kwargs.pop("max_tokens", 4096),
            "temperature": kwargs.pop("temperature", 0.7),
            "stream": True,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system_text:
            payload["system"] = self._system_block(system_text)

        headers: dict[str, str] = {
            "x-api-key": self._api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
            "Accept": "text/event-stream",
        }
        if self._cache_system and system_text:
            headers["anthropic-beta"] = _CACHE_BETA_HEADER

        url = urljoin(self.host + "/", "v1/messages")
        response = self._http.request(
            "POST",
            url,
            body=json.dumps(payload).encode("utf-8"),
            headers=headers,
            preload_content=False,
        )
        try:
            if response.status >= 400:
                body_text = response.read().decode("utf-8", errors="replace")
                raise GNATClientError(
                    f"Claude streaming HTTP {response.status}", status=response.status, body=body_text
                )
            for raw_line in response:
                line = raw_line.decode("utf-8").rstrip("\n\r")
                if not line.startswith("data: "):
                    continue
                data_str = line[6:]
                if data_str == "[DONE]":
                    break
                try:
                    event = json.loads(data_str)
                except json.JSONDecodeError:
                    continue
                if event.get("type") == "content_block_delta":
                    delta = event.get("delta", {})
                    if delta.get("type") == "text_delta":
                        yield delta.get("text", "")
        finally:
            response.release_conn()

    def tool_call(
        self,
        prompt: str,
        tools: list[dict[str, Any]],
        **kwargs: Any,
    ) -> dict[str, Any]:
        """
        Invoke Claude tool use and return the first tool result.

        Parameters
        ----------
        prompt : str
            User message.
        tools : list[dict]
            Anthropic tool definitions::

                [{"name": "get_weather",
                  "description": "...",
                  "input_schema": {"type": "object", "properties": {...}}}]

        Returns
        -------
        dict
            ``{"name": str, "input": dict}``

        Raises
        ------
        GNATClientError
            If Claude does not return a ``tool_use`` block.
        """
        self.authenticate()
        payload: dict[str, Any] = {
            "model": self.model,
            "max_tokens": kwargs.get("max_tokens", 4096),
            "temperature": kwargs.get("temperature", 0.0),
            "tools": tools,
            "messages": [{"role": "user", "content": prompt}],
        }
        resp = self.post("/v1/messages", json=payload)
        for block in resp.get("content", []):
            if block.get("type") == "tool_use":
                return {"name": block["name"], "input": block.get("input", {})}
        raise GNATClientError(
            "Claude did not return a tool_use block — check tool definitions and prompt"
        )

    def embed(self, texts: list[str], **kwargs: Any) -> list[list[float]]:
        """
        Not supported by Claude.  Use ``openai`` or ``gemini`` backend for embeddings.

        Raises
        ------
        NotImplementedError
            Always.
        """
        raise NotImplementedError(
            "Claude does not provide an embeddings endpoint. "
            "Initialise LLMClient with backend='openai' or backend='gemini' for embed()."
        )
