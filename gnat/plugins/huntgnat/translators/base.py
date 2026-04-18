# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.plugins.huntgnat.translators.base
==========================================

Abstract base class for all HuntGNAT rule translators.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from gnat.plugins.huntgnat.models import RuleLanguage, TranslationResult
from gnat.plugins.huntgnat.parser.stix_pattern import PatternAST


class RuleTranslator(ABC):
    """
    Abstract base for STIX pattern → detection rule translators.

    Subclasses must implement :meth:`translate` and declare
    :attr:`language` and :attr:`version`.
    """

    language: RuleLanguage
    version: str = "1.0.0"

    @abstractmethod
    def translate(
        self,
        ast: PatternAST,
        *,
        pattern: str,
        indicator_id: str | None = None,
        indicator_name: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> TranslationResult:
        """
        Translate a parsed STIX pattern into a detection rule.

        Parameters
        ----------
        ast : PatternAST
            The parsed pattern tree from :func:`parse_pattern`.
        pattern : str
            The original raw pattern string (for error messages and
            metadata).
        indicator_id : str, optional
            STIX Indicator SDO id, if available.
        indicator_name : str
            Human-readable name for the indicator.
        metadata : dict, optional
            Additional key-value pairs to attach to the rule.

        Returns
        -------
        TranslationResult
            The translated rule body and metadata.

        Raises
        ------
        UntranslatableError
            If the pattern contains constructs that cannot be faithfully
            expressed in the target language.
        """

    def translator_version_tag(self) -> str:
        return f"{self.language.value}/{self.version}"
