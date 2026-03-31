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
from typing import Any, Dict, List, Optional

from gnat.clients.base import BaseClient, GNATClientError
from gnat.agents.llm import LLMProvider


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
        provider: str = "openai",   # "openai" or "grok"
        api_key: str = "",
        model: str = "",
        host: str = "",
        **kwargs: Any,
    ) -> None:
        # Set sensible defaults
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
        messages: List[Dict[str, str]],
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Perform chat completion using OpenAI-compatible /chat/completions endpoint.
        """
        self.authenticate()

        payload: Dict[str, Any] = {
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
        output_schema: Dict[str, Any],
        **kwargs: Any,
    ) -> Dict[str, Any]:
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

        payload: Dict[str, Any] = {
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

    # ── Convenience methods ────────────────────────────────────────────────

    def get_model_name(self) -> str:
        """Return current model for logging."""
        return self.model