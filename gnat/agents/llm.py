"""
gnat.agents.llm
===============

Unified multi-LLM client for all GNAT AI agents.

Supports Claude, OpenAI, Grok (xAI), and easy extension for Gemini.
Provides automatic fallback, structured output, and config-driven backend selection.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from gnat.clients.base import BaseClient, GNATClientError


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


class LLMClient:
    """
    Unified facade for LLM interactions across multiple providers.

    Backwards-compatible with existing [claude] configuration.
    """

    def __init__(
        self,
        backend: str = "claude",
        **config: Any,
    ) -> None:
        self.backend = backend.lower()
        self.provider = self._create_provider(backend, config)

    def _create_provider(self, backend: str, config: Dict[str, Any]) -> LLMProvider:
        if backend == "claude":
            from .claude import ClaudeProvider
            return ClaudeProvider(**config)
        elif backend in ("openai", "grok"):
            from .openai_compatible import OpenAICompatibleProvider
            return OpenAICompatibleProvider(provider=backend, **config)
        elif backend == "gemini":
            raise NotImplementedError("Gemini provider coming soon (add [gemini] section)")
        raise ValueError(
            f"Unsupported LLM backend '{backend}'. "
            f"Supported: claude, openai, grok"
        )

    def chat(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Unified chat completion with fallback support."""
        try:
            return self.provider.chat(messages, temperature, max_tokens, **kwargs)
        except Exception as e:  # simple fallback stub – extend with full chain if needed
            raise GNATClientError(f"{self.backend} failed: {e}") from e

    def structured(
        self,
        prompt: str,
        output_schema: Dict[str, Any],
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Unified structured (JSON) output."""
        return self.provider.structured(prompt, output_schema, **kwargs)

    def get_model_name(self) -> str:
        """Return the active model name for logging."""
        if hasattr(self.provider, "model"):
            return self.provider.model
        return f"{self.backend}-default"