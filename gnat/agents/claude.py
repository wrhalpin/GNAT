# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.agents.claude
==================

Claude (Anthropic) provider for the unified LLMClient.
Uses urllib3 (GNAT standard) – no requests dependency.
"""

from __future__ import annotations

import json
from typing import Any

from gnat.agents.base import LLMProvider
from gnat.clients.base import BaseClient, GNATClientError


class ClaudeProvider(LLMProvider, BaseClient):
    """
    Anthropic Claude Messages API provider.

    Configuration (from [claude] INI section):
        api_key, model (default: claude-sonnet-4-6)
    """

    def __init__(
        self,
        api_key: str,
        model: str = "claude-sonnet-4-6",
        **kwargs: Any,
    ) -> None:
        """Initialize ClaudeProvider."""
        super().__init__(host="https://api.anthropic.com", **kwargs)
        self._api_key = api_key
        self.model = model

    def authenticate(self) -> None:
        """Set Anthropic headers."""
        self._auth_headers["x-api-key"] = self._api_key
        self._auth_headers["anthropic-version"] = "2023-06-01"
        self._auth_headers["Content-Type"] = "application/json"

    def chat(
        self,
        messages: list[dict[str, str]],
        temperature: float = 0.7,
        max_tokens: int | None = 4096,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Claude Messages API chat completion."""
        self.authenticate()
        payload = {
            "model": self.model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": messages,
            **kwargs,
        }
        resp = self.post("/v1/messages", json=payload)
        return resp  # returns full Anthropic response (content[0].text, usage, etc.)

    def structured(
        self,
        prompt: str,
        output_schema: dict[str, Any],
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Structured output via XML/JSON prompting (Claude has no native JSON mode)."""
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
