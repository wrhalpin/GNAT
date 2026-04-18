# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.plugins.huntgnat.translate
===================================

Top-level translation API — the single entry point for converting a
STIX Indicator pattern into detection rules in one or more languages.
"""

from __future__ import annotations

from typing import Any

from gnat.plugins.huntgnat.errors import UntranslatableError
from gnat.plugins.huntgnat.models import RuleLanguage, TranslationResult
from gnat.plugins.huntgnat.parser import parse_pattern
from gnat.plugins.huntgnat.translators.base import RuleTranslator
from gnat.plugins.huntgnat.translators.sigma import SigmaTranslator
from gnat.plugins.huntgnat.translators.snort import SnortTranslator
from gnat.plugins.huntgnat.translators.suricata import SuricataTranslator
from gnat.plugins.huntgnat.translators.yara_hash import YaraHashTranslator

_TRANSLATORS: dict[RuleLanguage, type[RuleTranslator]] = {
    RuleLanguage.SIGMA: SigmaTranslator,
    RuleLanguage.YARA: YaraHashTranslator,
    RuleLanguage.SURICATA: SuricataTranslator,
    RuleLanguage.SNORT: SnortTranslator,
}


def translate(
    pattern: str,
    language: str | RuleLanguage,
    *,
    indicator_id: str | None = None,
    indicator_name: str = "",
    metadata: dict[str, Any] | None = None,
    author: str = "HuntGNAT",
) -> TranslationResult:
    """
    Translate a STIX Indicator pattern into a detection rule.

    Parameters
    ----------
    pattern : str
        A raw STIX 2.1 pattern expression.
    language : str or RuleLanguage
        Target language (``"sigma"``, ``"yara"``, ``"suricata"``,
        ``"snort"``, ``"spl"``, ``"kql"``, ``"eql"``).
    indicator_id : str, optional
        STIX Indicator SDO id for traceability.
    indicator_name : str
        Human-readable indicator name for rule titles.
    metadata : dict, optional
        Extra key-value pairs attached to the result.
    author : str
        Author name stamped into the rule.

    Returns
    -------
    TranslationResult

    Raises
    ------
    UntranslatableError
        If the pattern cannot be expressed in the target language.
    STIXPatternParseError
        If the pattern is syntactically invalid.
    ValueError
        If the target language is unknown.
    """
    if isinstance(language, str):
        try:
            lang = RuleLanguage(language.lower())
        except ValueError:
            raise ValueError(
                f"unknown target language {language!r}; "
                f"supported: {[rl.value for rl in RuleLanguage]}"
            ) from None
    else:
        lang = language

    if lang in (RuleLanguage.SPL, RuleLanguage.KQL, RuleLanguage.EQL):
        raise UntranslatableError(
            reason=f"{lang.value} requires pySigma transpilation from Sigma "
            f"— use translate(pattern, 'sigma') first, then transpile "
            f"the Sigma output via pySigma backends",
            pattern=pattern,
            target_language=lang.value,
        )

    translator_cls = _TRANSLATORS.get(lang)
    if translator_cls is None:
        raise ValueError(f"no translator registered for {lang.value!r}")

    ast = parse_pattern(pattern)

    if translator_cls == SigmaTranslator:
        translator = SigmaTranslator(author=author)
    else:
        translator = translator_cls()

    return translator.translate(
        ast,
        pattern=pattern,
        indicator_id=indicator_id,
        indicator_name=indicator_name,
        metadata=metadata,
    )


def translate_all(
    pattern: str,
    *,
    indicator_id: str | None = None,
    indicator_name: str = "",
    metadata: dict[str, Any] | None = None,
    author: str = "HuntGNAT",
) -> dict[str, TranslationResult | UntranslatableError]:
    """
    Translate a STIX pattern into every supported language.

    Returns a dict mapping language names to either
    :class:`TranslationResult` or :class:`UntranslatableError` (for
    languages that can't express the pattern).
    """
    results: dict[str, TranslationResult | UntranslatableError] = {}
    for lang in (RuleLanguage.SIGMA, RuleLanguage.YARA, RuleLanguage.SURICATA, RuleLanguage.SNORT):
        try:
            results[lang.value] = translate(
                pattern,
                lang,
                indicator_id=indicator_id,
                indicator_name=indicator_name,
                metadata=metadata,
                author=author,
            )
        except UntranslatableError as exc:
            results[lang.value] = exc
    return results
