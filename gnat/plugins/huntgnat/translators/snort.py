# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.plugins.huntgnat.translators.snort
==========================================

Translate STIX network-observable patterns into Snort 3 rules.

Structurally similar to the Suricata translator but uses Snort 3
syntax (``alert`` action, Snort-style options, ``gid``/``sid``).
"""

from __future__ import annotations

from typing import Any

from gnat.plugins.huntgnat.errors import UntranslatableError
from gnat.plugins.huntgnat.models import RuleLanguage, TranslationResult
from gnat.plugins.huntgnat.parser.stix_pattern import (
    Comparison,
    CompoundObservation,
)
from gnat.plugins.huntgnat.translators.base import RuleTranslator

_HOST_ONLY_TYPES = frozenset({
    "file",
    "process",
    "windows-registry-key",
    "directory",
    "software",
    "user-account",
})

_SID_BASE = 8_000_000


class SnortTranslator(RuleTranslator):
    """Translate STIX network patterns into Snort 3 alert rules."""

    language = RuleLanguage.SNORT
    version = "1.0.0"

    def __init__(self, sid_start: int = _SID_BASE) -> None:
        self._next_sid = sid_start

    def translate(
        self,
        ast: CompoundObservation,
        *,
        pattern: str,
        indicator_id: str | None = None,
        indicator_name: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> TranslationResult:
        comparisons = []
        for obs in ast.observations:
            comparisons.extend(obs.expression.iter_comparisons())

        if not comparisons:
            raise UntranslatableError(
                reason="no comparisons in pattern",
                pattern=pattern,
                target_language="snort",
            )

        for cmp in comparisons:
            if cmp.object_path.object_type in _HOST_ONLY_TYPES:
                raise UntranslatableError(
                    reason=f"host-only observable type "
                    f"{cmp.object_path.object_type!r} not supported "
                    f"by network detection language",
                    pattern=pattern,
                    target_language="snort",
                )

        rules: list[str] = []
        for cmp in comparisons:
            rule = self._translate_comparison(cmp, pattern, indicator_id, indicator_name)
            if rule:
                rules.append(rule)

        if not rules:
            raise UntranslatableError(
                reason="no translatable network observables found",
                pattern=pattern,
                target_language="snort",
            )

        rule_body = "\n".join(rules) + "\n"

        return TranslationResult(
            indicator_id=indicator_id,
            language=RuleLanguage.SNORT,
            rule_body=rule_body,
            translator_version=self.translator_version_tag(),
            metadata=metadata or {},
        )

    def _translate_comparison(
        self,
        cmp: Comparison,
        pattern: str,
        indicator_id: str | None,
        name: str,
    ) -> str | None:
        otype = cmp.object_path.object_type
        value = str(cmp.value)
        sid = self._next_sid
        self._next_sid += 1
        msg = name or indicator_id or "HuntGNAT indicator"

        if otype == "domain-name":
            return (
                f'alert dns $HOME_NET any -> any any '
                f'(msg:"HuntGNAT: {msg}"; '
                f'content:"{value}"; nocase; '
                f'gid:1; sid:{sid}; rev:1;)'
            )
        if otype in ("ipv4-addr", "ipv6-addr"):
            prop = ".".join(cmp.object_path.property_path)
            if "dst" in prop or prop == "value":
                return (
                    f'alert ip $HOME_NET any -> {value} any '
                    f'(msg:"HuntGNAT: {msg}"; '
                    f'gid:1; sid:{sid}; rev:1;)'
                )
            return (
                f'alert ip {value} any -> $HOME_NET any '
                f'(msg:"HuntGNAT: {msg}"; '
                f'gid:1; sid:{sid}; rev:1;)'
            )
        if otype == "url":
            return (
                f'alert http $HOME_NET any -> $EXTERNAL_NET any '
                f'(msg:"HuntGNAT: {msg}"; '
                f'http_uri; content:"{value}"; nocase; '
                f'gid:1; sid:{sid}; rev:1;)'
            )
        if otype == "network-traffic":
            prop = ".".join(cmp.object_path.property_path)
            if "dst" in prop:
                return (
                    f'alert ip $HOME_NET any -> {value} any '
                    f'(msg:"HuntGNAT: {msg}"; '
                    f'gid:1; sid:{sid}; rev:1;)'
                )
            if "src" in prop:
                return (
                    f'alert ip {value} any -> $HOME_NET any '
                    f'(msg:"HuntGNAT: {msg}"; '
                    f'gid:1; sid:{sid}; rev:1;)'
                )
        return None
