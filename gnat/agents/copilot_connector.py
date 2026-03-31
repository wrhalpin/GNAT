"""Agent helper for using the Copilot connector inside GNAT AI workflows.

This is intentionally lightweight: it wraps CopilotClient and exposes a
simple "analyze" method that takes free text and returns a STIX report
via the connector's to_stix() translation.
"""

from __future__ import annotations

from typing import Any

from gnat.connectors.copilot.client import CopilotClient


class CopilotConnectorAgent:
    """Thin wrapper around CopilotClient for AI-assisted analysis flows."""

    def __init__(
        self,
        host: str,
        auth_type: str = "api_key",
        api_key: str = "",
        azure_token: str = "",
        model: str = "copilot-latest",
    ) -> None:
        self.client = CopilotClient(
            host=host,
            auth_type=auth_type,
            api_key=api_key,
            azure_token=azure_token,
        )
        self.model = model

    def analyze_text(
        self,
        text: str,
        system_prompt: str = "You are a helpful threat intelligence analyst.",
        temperature: float = 0.3,
        max_tokens: int | None = 512,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Run a single-shot analysis and return a STIX report dict."""
        messages: list[dict[str, str]] = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": text},
        ]
        native = self.client.chat_completion(
            messages=messages,
            model=self.model,
            temperature=temperature,
            max_tokens=max_tokens,
            **kwargs,
        )
        return self.client.to_stix(native)
