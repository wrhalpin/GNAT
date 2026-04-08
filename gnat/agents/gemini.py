# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.agents.gemini
==================

Google Gemini provider for the unified LLMClient.

Uses urllib3 via BaseClient (no google-generativeai SDK dependency).
Supports Gemini 2.0 Flash, 1.5 Pro, and any future ``gemini-*`` model.

Configuration (from ``[gemini]`` INI section)::

    [gemini]
    api_key = AIza...
    model   = gemini-2.0-flash
    # Optional:
    # max_output_tokens = 8192
    # temperature       = 0.7

API reference: https://ai.google.dev/api/generate-content
"""

from __future__ import annotations

import json
from typing import Any

from gnat.agents.base import LLMProvider
from gnat.clients.base import BaseClient, GNATClientError

_BASE_URL = "https://generativelanguage.googleapis.com"
_DEFAULT_MODEL = "gemini-2.0-flash"


def _to_gemini_contents(
    messages: list[dict[str, str]],
) -> tuple[list[dict[str, Any]], str]:
    """
    Convert OpenAI-style messages to Gemini ``contents`` + ``systemInstruction``.

    Returns
    -------
    (contents, system_text)
        ``contents`` — list suitable for Gemini ``contents`` field.
        ``system_text`` — text for Gemini ``systemInstruction`` (may be ``""``).
    """
    contents: list[dict[str, Any]] = []
    system_parts: list[str] = []

    for msg in messages:
        role = msg.get("role", "user")
        text = msg.get("content", "")

        if role == "system":
            # Gemini uses a separate systemInstruction field
            system_parts.append(text)
            continue

        # Map "assistant" → "model" (Gemini's name for the AI role)
        gemini_role = "model" if role == "assistant" else "user"
        contents.append({"role": gemini_role, "parts": [{"text": text}]})

    system_text = "\n\n".join(system_parts)
    return contents, system_text


class GeminiProvider(LLMProvider, BaseClient):
    """
    Google Generative Language (Gemini) provider.

    Implements the :class:`~gnat.agents.base.LLMProvider` interface so it
    can be used as a drop-in backend for :class:`~gnat.agents.llm.LLMClient`.

    Parameters
    ----------
    api_key : str
        Google AI API key (starts with ``AIza``).
    model : str
        Gemini model name.  Default ``"gemini-2.0-flash"``.
    max_output_tokens : int, optional
        Maximum tokens in the response.  Default ``8192``.
    """

    def __init__(
        self,
        api_key: str = "",
        model: str = _DEFAULT_MODEL,
        max_output_tokens: int = 8192,
        **kwargs: Any,
    ) -> None:
        """Initialize GeminiProvider."""
        super().__init__(host=_BASE_URL, **kwargs)
        self._api_key = api_key
        self.model = model
        self._max_output_tokens = max_output_tokens

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Set Google AI API key header."""
        self._auth_headers["x-goog-api-key"] = self._api_key
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
        Send a multi-turn chat request to Gemini and return an
        OpenAI-compatible response envelope.

        Parameters
        ----------
        messages : list of dict
            OpenAI-style messages with ``role`` and ``content`` keys.
            ``"system"`` messages are mapped to Gemini's ``systemInstruction``.
        temperature : float
            Sampling temperature.  Default 0.7.
        max_tokens : int, optional
            Override ``max_output_tokens`` for this call.

        Returns
        -------
        dict
            OpenAI-compatible response with ``choices[0].message.content``.
        """
        self.authenticate()
        contents, system_text = _to_gemini_contents(messages)

        payload: dict[str, Any] = {
            "contents": contents,
            "generationConfig": {
                "temperature": temperature,
                "maxOutputTokens": max_tokens or self._max_output_tokens,
            },
        }
        if system_text:
            payload["systemInstruction"] = {"parts": [{"text": system_text}]}

        # Pass through any extra Gemini-specific params
        for k, v in kwargs.items():
            if not k.startswith("_"):
                payload.setdefault("generationConfig", {})[k] = v  # type: ignore[index]

        try:
            resp = self.post(
                f"/v1beta/models/{self.model}:generateContent",
                json=payload,
            )
        except Exception as exc:
            raise GNATClientError(f"Gemini chat failed: {exc}") from exc

        return self._wrap_openai_compat(resp)

    def structured(
        self,
        prompt: str,
        output_schema: dict[str, Any],
        **kwargs: Any,
    ) -> dict[str, Any]:
        """
        Request structured JSON output from Gemini.

        Uses ``response_mime_type: application/json`` in generationConfig
        and includes the schema in the system prompt for reliable JSON output.

        Parameters
        ----------
        prompt : str
            User prompt.
        output_schema : dict
            JSON Schema dict describing the desired output structure.

        Returns
        -------
        dict
            Parsed JSON matching the schema.
        """
        self.authenticate()

        system_text = (
            "You are a precise data extraction assistant. "
            "Respond with valid JSON only, strictly matching this schema.\n\n"
            f"Schema:\n{json.dumps(output_schema, indent=2)}"
        )

        payload: dict[str, Any] = {
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "systemInstruction": {"parts": [{"text": system_text}]},
            "generationConfig": {
                "temperature": kwargs.get("temperature", 0.0),
                "maxOutputTokens": kwargs.get("max_tokens", self._max_output_tokens),
                "response_mime_type": "application/json",
            },
        }

        try:
            resp = self.post(
                f"/v1beta/models/{self.model}:generateContent",
                json=payload,
            )
        except Exception as exc:
            raise GNATClientError(f"Gemini structured output failed: {exc}") from exc

        text = self._extract_text(resp)
        # Strip accidental markdown fences
        text = text.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            text = "\n".join(lines[1:-1] if lines and lines[-1].strip() == "```" else lines[1:])

        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise GNATClientError(
                f"Gemini returned invalid JSON: {exc}\nRaw response: {text[:400]}"
            ) from exc

    def get_model_name(self) -> str:
        """Return the active Gemini model name."""
        return self.model

    # ── Internal helpers ───────────────────────────────────────────────────

    @staticmethod
    def _extract_text(resp: Any) -> str:
        """Pull the first text part from a Gemini generateContent response."""
        if not isinstance(resp, dict):
            return ""
        candidates = resp.get("candidates", [])
        if not candidates:
            return ""
        content = candidates[0].get("content", {})
        parts = content.get("parts", [])
        texts = [p.get("text", "") for p in parts if isinstance(p, dict)]
        return "\n".join(t for t in texts if t)

    def _wrap_openai_compat(self, resp: Any) -> dict[str, Any]:
        """
        Wrap a raw Gemini response in an OpenAI-compatible envelope so
        callers that read ``choices[0]["message"]["content"]`` work unchanged.
        """
        text = self._extract_text(resp)
        finish = "stop"
        if isinstance(resp, dict) and resp.get("candidates"):
            finish = resp["candidates"][0].get("finishReason", "STOP").lower()
            if finish == "stop":
                finish = "stop"

        return {
            "choices": [
                {
                    "message": {"role": "assistant", "content": text},
                    "finish_reason": finish,
                    "index": 0,
                }
            ],
            "model": self.model,
            "_raw_gemini": resp,  # preserve for callers that want it
        }
