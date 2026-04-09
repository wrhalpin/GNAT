# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.agents.llm
===============

Unified multi-LLM client for all GNAT AI agents.

Supports Claude, OpenAI, Grok (xAI), and Gemini with:
- Automatic multi-backend fallback chain
- Streaming (server-sent events)
- Tool / function calling
- Embeddings (OpenAI and Gemini backends)
- Structured JSON output
- Config-driven backend selection

Example::

    # Simple usage — Claude primary
    llm = LLMClient(backend="claude", api_key="sk-ant-...")

    # With fallback chain
    llm = LLMClient(
        backend="claude", api_key="sk-ant-...",
        fallback_backends=["openai"],
        fallback_configs={"openai": {"api_key": "sk-..."}},
    )

    # Streaming
    for chunk in llm.stream("Summarise APT29"):
        print(chunk, end="", flush=True)

    # Tool calling
    result = llm.tool_call("What is the weather in NYC?", tools=[...])

    # Embeddings (requires openai or gemini backend)
    vectors = llm.embed(["APT29 indicator", "CVE-2024-1234"])
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from typing import Any

from gnat.agents.base import LLMProvider
from gnat.clients.base import GNATClientError

logger = logging.getLogger(__name__)


class LLMClient:
    """
    Unified facade for LLM interactions across multiple providers.

    Backwards-compatible with existing ``[claude]`` configuration.

    Parameters
    ----------
    backend : str
        Primary backend name: ``"claude"``, ``"openai"``, ``"grok"``, ``"gemini"``.
    fallback_backends : list[str], optional
        Ordered list of backend names to try if the primary fails.
        E.g. ``["openai", "grok"]``.
    fallback_configs : dict[str, dict], optional
        Per-backend configuration dicts for fallback providers.
        Keys match entries in *fallback_backends*.
    **config
        Keyword arguments forwarded to the primary provider constructor
        (``api_key``, ``model``, etc.).
    """

    def __init__(
        self,
        backend: str = "claude",
        fallback_backends: list[str] | None = None,
        fallback_configs: dict[str, dict[str, Any]] | None = None,
        **config: Any,
    ) -> None:
        """Initialize LLMClient."""
        self.backend = backend.lower()
        self._primary_config = config
        self._fallback_backends: list[str] = [b.lower() for b in (fallback_backends or [])]
        self._fallback_configs: dict[str, dict[str, Any]] = fallback_configs or {}
        self.provider = self._create_provider(self.backend, config)

    def _create_provider(self, backend: str, config: dict[str, Any]) -> LLMProvider:
        """Instantiate the provider for *backend* with *config*."""
        if backend == "claude":
            from .claude import ClaudeProvider
            return ClaudeProvider(**config)
        if backend in ("openai", "grok"):
            from .openai_compatible import OpenAICompatibleProvider
            return OpenAICompatibleProvider(provider=backend, **config)
        if backend == "gemini":
            from .gemini import GeminiProvider
            return GeminiProvider(**config)
        raise ValueError(
            f"Unsupported LLM backend '{backend}'. Supported: claude, openai, grok, gemini"
        )

    def _fallback_chain(self) -> Iterator[LLMProvider]:
        """Yield each fallback provider in order (lazy instantiation)."""
        for name in self._fallback_backends:
            cfg = self._fallback_configs.get(name, {})
            try:
                yield self._create_provider(name, cfg)
            except Exception as exc:
                logger.warning("LLMClient: failed to create fallback provider %r: %s", name, exc)

    def chat(
        self,
        messages: list[dict[str, str]],
        temperature: float = 0.7,
        max_tokens: int | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """
        Unified chat completion with automatic fallback.

        Tries the primary backend first.  On failure, attempts each
        fallback backend in order before raising.
        """
        last_exc: Exception | None = None
        for provider in [self.provider, *self._fallback_chain()]:
            try:
                return provider.chat(messages, temperature, max_tokens, **kwargs)
            except Exception as exc:
                logger.warning(
                    "LLMClient.chat: provider %s failed — %s", type(provider).__name__, exc
                )
                last_exc = exc
        raise GNATClientError(
            f"All LLM backends failed. Last error: {last_exc}"
        ) from last_exc

    def structured(
        self,
        prompt: str,
        output_schema: dict[str, Any],
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Unified structured (JSON) output with fallback."""
        last_exc: Exception | None = None
        for provider in [self.provider, *self._fallback_chain()]:
            try:
                return provider.structured(prompt, output_schema, **kwargs)
            except Exception as exc:
                logger.warning(
                    "LLMClient.structured: provider %s failed — %s", type(provider).__name__, exc
                )
                last_exc = exc
        raise GNATClientError(
            f"All LLM backends failed (structured). Last error: {last_exc}"
        ) from last_exc

    def stream(self, prompt: str, **kwargs: Any) -> Iterator[str]:
        """
        Yield incremental text chunks from a streaming completion.

        Tries the primary backend.  Falls back to each fallback backend
        in order if the primary does not support streaming or fails.

        Parameters
        ----------
        prompt : str
            User message text.
        **kwargs
            ``system``, ``temperature``, ``max_tokens`` passed to the provider.

        Yields
        ------
        str
            Text chunks as they arrive.
        """
        last_exc: Exception | None = None
        for provider in [self.provider, *self._fallback_chain()]:
            try:
                yield from provider.stream(prompt, **kwargs)
                return
            except NotImplementedError:
                # Provider doesn't support streaming — try next
                continue
            except Exception as exc:
                logger.warning(
                    "LLMClient.stream: provider %s failed — %s", type(provider).__name__, exc
                )
                last_exc = exc
        raise GNATClientError(
            f"All LLM backends failed (stream). Last error: {last_exc}"
        ) from last_exc

    def tool_call(
        self,
        prompt: str,
        tools: list[dict[str, Any]],
        **kwargs: Any,
    ) -> dict[str, Any]:
        """
        Invoke tool / function calling and return the first tool result.

        Falls back through the fallback chain if the primary does not
        support tool calling or fails.

        Parameters
        ----------
        prompt : str
            User message.
        tools : list[dict]
            Tool definitions (Anthropic or OpenAI format — the provider
            normalises internally).

        Returns
        -------
        dict
            ``{"name": str, "input": dict}``
        """
        last_exc: Exception | None = None
        for provider in [self.provider, *self._fallback_chain()]:
            try:
                return provider.tool_call(prompt, tools, **kwargs)
            except NotImplementedError:
                continue
            except Exception as exc:
                logger.warning(
                    "LLMClient.tool_call: provider %s failed — %s", type(provider).__name__, exc
                )
                last_exc = exc
        raise GNATClientError(
            f"All LLM backends failed (tool_call). Last error: {last_exc}"
        ) from last_exc

    def embed(self, texts: list[str], **kwargs: Any) -> list[list[float]]:
        """
        Return dense embedding vectors for each input text.

        Claude does not support embeddings; the method automatically
        looks for an OpenAI or Gemini provider in the fallback chain if
        the primary backend raises ``NotImplementedError``.

        Parameters
        ----------
        texts : list[str]
            Strings to embed.
        **kwargs
            ``model`` override forwarded to the provider.

        Returns
        -------
        list[list[float]]
            One vector per input text.
        """
        last_exc: Exception | None = None
        for provider in [self.provider, *self._fallback_chain()]:
            try:
                return provider.embed(texts, **kwargs)
            except NotImplementedError:
                continue
            except Exception as exc:
                logger.warning(
                    "LLMClient.embed: provider %s failed — %s", type(provider).__name__, exc
                )
                last_exc = exc
        raise GNATClientError(
            "No LLM backend supports embeddings. "
            "Add openai or gemini to fallback_backends, or use backend='openai'."
        ) from last_exc

    def get_model_name(self) -> str:
        """Return the active model name for logging."""
        if hasattr(self.provider, "model"):
            return self.provider.model
        return f"{self.backend}-default"
