# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.agents.openai_compatible
=============================

OpenAI-compatible provider for LLMClient.

Supports:
- OpenAI (gpt-4o, gpt-4o-mini, o1-mini, etc.)
- Grok / xAI (grok-4, grok-beta, etc.) — fully compatible endpoint

Uses urllib3 via BaseClient (no openai SDK dependency).
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from typing import Any
from urllib.parse import urljoin

from gnat.agents.base import LLMProvider
from gnat.clients.base import BaseClient, GNATClientError


class OpenAICompatibleProvider(LLMProvider, BaseClient):
    """
    Provider for OpenAI-compatible chat completions API.

    Works with:
    - OpenAI: https://api.openai.com/v1
    - Grok/xAI: https://api.x.ai/v1
    - Any other OpenAI-compatible endpoint (Azure OpenAI, local proxies, etc.)

    Configuration examples:

    [openai]
    api_key = sk-...
    model = gpt-4o-mini
    host = https://api.openai.com

    [grok]
    api_key = xai-...
    model = grok-4
    host = https://api.x.ai
    """

    def __init__(
        self,
        provider: str = "openai",  # "openai" or "grok"
        api_key: str = "",
        model: str = "",
        host: str = "",
        **kwargs: Any,
    ) -> None:
        # Set sensible defaults
        """Initialize OpenAICompatibleProvider."""
        if provider == "grok":
            default_host = "https://api.x.ai"
            default_model = "grok-4"
        else:  # openai
            default_host = "https://api.openai.com"
            default_model = "gpt-4o-mini"

        self.provider = provider
        self.model = model or default_model
        self._api_key = api_key

        super().__init__(host=host or default_host, **kwargs)

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Set Bearer token and JSON headers (standard for OpenAI-compatible APIs)."""
        self._auth_headers["Authorization"] = f"Bearer {self._api_key}"
        self._auth_headers["Content-Type"] = "application/json"
        self._auth_headers["Accept"] = "application/json"

    # ── LLMProvider interface ──────────────────────────────────────────────

    def chat(
        self,
        messages: list[dict[str, str]],
        temperature: float = 0.7,
        max_tokens: int | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """
        Perform chat completion using OpenAI-compatible /chat/completions endpoint.
        """
        self.authenticate()

        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
        }
        if max_tokens is not None:
            payload["max_tokens"] = max_tokens

        # Pass through any extra parameters (top_p, frequency_penalty, etc.)
        payload.update({k: v for k, v in kwargs.items() if not k.startswith("_")})

        try:
            resp = self.post("/v1/chat/completions", json=payload)
            return resp
        except Exception as e:
            raise GNATClientError(
                f"{self.provider.capitalize()} chat completion failed: {e}"
            ) from e

    def structured(
        self,
        prompt: str,
        output_schema: dict[str, Any],
        **kwargs: Any,
    ) -> dict[str, Any]:
        """
        Structured output using JSON mode (native on OpenAI and Grok).
        """
        self.authenticate()

        system_prompt = (
            "You are a precise assistant. Respond with valid JSON only, "
            "matching this exact schema. No extra text or markdown.\n\n"
            f"Schema:\n{json.dumps(output_schema, indent=2)}"
        )

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ]

        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": kwargs.get("temperature", 0.0),  # lower temp for structured
            "response_format": {"type": "json_object"},
        }

        try:
            resp = self.post("/v1/chat/completions", json=payload)
            content = resp["choices"][0]["message"]["content"]
            return json.loads(content)
        except (KeyError, json.JSONDecodeError, IndexError) as e:
            raise GNATClientError(
                f"{self.provider.capitalize()} structured output failed: {e}"
            ) from e

    def stream(self, prompt: str, **kwargs: Any) -> Iterator[str]:
        """
        Yield incremental text chunks from a streaming OpenAI-compatible completion.

        Parses server-sent events line by line.  Only ``choices[0].delta.content``
        chunks yield text; ``[DONE]`` terminates the stream.
        """
        self.authenticate()
        system_text: str = kwargs.pop("system", "")
        messages: list[dict[str, Any]] = []
        if system_text:
            messages.append({"role": "system", "content": system_text})
        messages.append({"role": "user", "content": prompt})

        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": kwargs.pop("temperature", 0.7),
            "stream": True,
        }
        if "max_tokens" in kwargs:
            payload["max_tokens"] = kwargs.pop("max_tokens")

        headers: dict[str, str] = dict(self._auth_headers)
        headers["Content-Type"] = "application/json"
        headers["Accept"] = "text/event-stream"

        url = urljoin(self.host + "/", "v1/chat/completions")
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
                    f"{self.provider} streaming HTTP {response.status}",
                    status=response.status,
                    body=body_text,
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
                delta = event.get("choices", [{}])[0].get("delta", {})
                text = delta.get("content")
                if text:
                    yield text
        finally:
            response.release_conn()

    def tool_call(
        self,
        prompt: str,
        tools: list[dict[str, Any]],
        **kwargs: Any,
    ) -> dict[str, Any]:
        """
        Invoke OpenAI function calling and return the first function result.

        Parameters
        ----------
        prompt : str
            User message.
        tools : list[dict]
            OpenAI tool definitions with ``type: "function"`` and ``function`` key.

        Returns
        -------
        dict
            ``{"name": str, "input": dict}``
        """
        self.authenticate()
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "tools": tools,
            "tool_choice": "auto",
            "temperature": kwargs.get("temperature", 0.0),
        }
        resp = self.post("/v1/chat/completions", json=payload)
        tool_calls = resp.get("choices", [{}])[0].get("message", {}).get("tool_calls", [])
        if not tool_calls:
            raise GNATClientError(
                f"{self.provider} did not return any tool_calls — check tool definitions"
            )
        fn = tool_calls[0].get("function", {})
        try:
            arguments = json.loads(fn.get("arguments", "{}"))
        except json.JSONDecodeError:
            arguments = {}
        return {"name": fn.get("name", ""), "input": arguments}

    def embed(self, texts: list[str], **kwargs: Any) -> list[list[float]]:
        """
        Return dense embedding vectors using the OpenAI ``/v1/embeddings`` endpoint.

        Parameters
        ----------
        texts : list[str]
            Input strings to embed (max 2048 tokens per item for most models).
        **kwargs
            ``model`` override (default ``text-embedding-3-small``).

        Returns
        -------
        list[list[float]]
            Embedding vectors in the same order as *texts*.
        """
        self.authenticate()
        embed_model = kwargs.get("model", "text-embedding-3-small")
        payload = {"model": embed_model, "input": texts}
        resp = self.post("/v1/embeddings", json=payload)
        items = sorted(resp.get("data", []), key=lambda x: x.get("index", 0))
        return [item["embedding"] for item in items]

    # ── Convenience methods ────────────────────────────────────────────────

    def get_model_name(self) -> str:
        """Return current model for logging."""
        return self.model
