# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.nlp.parser
=================
:class:`NLPQueryEngine` — top-level facade that loads the configured backend
and dispatches natural-language queries to all matching connectors.

Usage::

    from gnat.nlp import NLPQueryEngine
    from gnat.config import GNATConfig

    cfg  = GNATConfig()
    engine = NLPQueryEngine.from_config(cfg)
    results = engine.query("Get all IPs for APT28 from the last 30 days")
    # → list of STIX dicts

Config::

    [nlp]
    backend = builtin      # builtin | claude  (default: builtin)
    model   = claude-sonnet-4-6
"""

from __future__ import annotations

import logging
from typing import Any

from gnat.nlp.query_spec import QuerySpec

logger = logging.getLogger(__name__)


class NLPQueryEngine:
    """
    Natural-language query engine for GNAT.

    Combines a parser backend (builtin or Claude) with multi-connector
    dispatch to translate a free-text analyst query into STIX results.

    Parameters
    ----------
    backend : str
        ``"builtin"`` or ``"claude"``.  Default ``"builtin"``.
    claude_config : AgentConfig, optional
        Required when *backend* is ``"claude"``.
    default_limit : int
        Default per-connector result limit.  Default ``100``.

    Examples
    --------
    >>> engine = NLPQueryEngine()
    >>> spec = engine.parse("APT28 domains last 14 days")
    >>> spec.entities
    ['APT28']
    >>> spec.ioc_types
    ['domain']
    """

    def __init__(
        self,
        backend: str = "builtin",
        claude_config: Any | None = None,
        default_limit: int = 100,
    ) -> None:
        """Initialize NLPQueryEngine."""
        self._backend_name = backend
        self._default_limit = default_limit
        self._parser = self._build_parser(backend, claude_config)

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def from_config(cls, config: Any) -> NLPQueryEngine:
        """
        Instantiate from a :class:`~gnat.config.GNATConfig` object.

        Reads the ``[nlp]`` section (``backend``, ``model``) and the
        ``[claude]`` section when ``backend = claude``.

        Parameters
        ----------
        config : GNATConfig
            Loaded configuration object.

        Returns
        -------
        NLPQueryEngine
        """
        try:
            nlp_cfg = config.get("nlp")
        except KeyError:
            nlp_cfg = {}

        backend = nlp_cfg.get("backend", "builtin").lower()
        claude_config = None

        if backend == "claude":
            try:
                from gnat.agents.base import AgentConfig

                claude_config = AgentConfig.from_config(config._parser)
            except Exception as exc:
                logger.warning(
                    "NLPQueryEngine: could not load Claude config (%s); "
                    "falling back to builtin backend",
                    exc,
                )
                backend = "builtin"

        return cls(backend=backend, claude_config=claude_config)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def parse(self, query: str) -> QuerySpec:
        """
        Parse *query* into a structured :class:`QuerySpec`.

        Parameters
        ----------
        query : str
            Free-text threat-intel query.

        Returns
        -------
        QuerySpec
        """
        return self._parser.parse(query, default_limit=self._default_limit)

    def query(
        self,
        query: str,
        connectors: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """
        Parse *query* and dispatch to all matching connectors.

        Parameters
        ----------
        query : str
            Free-text threat-intel query.
        connectors : dict, optional
            Mapping of ``{connector_key: connector_instance}`` to query.
            When omitted or empty the method returns only the parsed
            :class:`QuerySpec` as a single-element list (useful for testing
            without live connectors).

        Returns
        -------
        list of dict
            Aggregated results from all queried connectors.  Each result
            dict has a ``"_source"`` key indicating which connector produced
            it.
        """
        spec = self.parse(query)
        results: list[dict[str, Any]] = []

        if not connectors:
            # Return the spec serialised so callers can inspect it
            return [{"_type": "query_spec", **spec.to_dict()}]

        targets = (
            {k: v for k, v in connectors.items() if k in spec.platforms}
            if spec.platforms
            else connectors
        )

        for key, connector in targets.items():
            try:
                raw_list = connector.list_objects(
                    spec.ioc_types[0] if spec.ioc_types else "indicator",
                    page_size=spec.limit,
                )
                for item in raw_list:
                    item["_source"] = key
                    results.append(item)
            except Exception as exc:
                logger.warning("NLPQueryEngine: connector %r failed: %s", key, exc)

        return results

    @property
    def backend(self) -> str:
        """Name of the active backend (``"builtin"`` or ``"claude"``)."""
        return self._backend_name

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_parser(backend: str, claude_config: Any | None) -> Any:
        """Internal helper for build parser."""
        if backend == "claude":
            if claude_config is None:
                raise ValueError("NLPQueryEngine: backend='claude' requires claude_config")
            from gnat.nlp.claude_backend import ClaudeParser

            return ClaudeParser(claude_config)

        from gnat.nlp.builtin import BuiltinParser

        return BuiltinParser()
