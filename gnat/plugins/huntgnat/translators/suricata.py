# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.plugins.huntgnat.translators.suricata
=============================================

Translate STIX network-observable patterns into Suricata rules.

Supports ``domain-name:value``, ``ipv4-addr:value``, ``ipv6-addr:value``,
``url:value``, and ``network-traffic:dst_ref.value`` / ``src_ref.value``
patterns. Host-only observables (file, process, registry) raise
:class:`UntranslatableError`.
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

_NETWORK_TYPES = frozenset({
    "domain-name",
    "ipv4-addr",
    "ipv6-addr",
    "url",
    "network-traffic",
})

_HOST_ONLY_TYPES = frozenset({
    "file",
    "process",
    "windows-registry-key",
    "directory",
    "software",
    "user-account",
})

_SID_BASE = 9_000_000


class SuricataTranslator(RuleTranslator):
    """Translate STIX network patterns into Suricata alert rules."""

    language = RuleLanguage.SURICATA
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
                target_language="suricata",
            )

        # Validate: reject host-only observables
        for cmp in comparisons:
            if cmp.object_path.object_type in _HOST_ONLY_TYPES:
                raise UntranslatableError(
                    reason=f"host-only observable type "
                    f"{cmp.object_path.object_type!r} not supported "
                    f"by network detection language",
                    pattern=pattern,
                    target_language="suricata",
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
                target_language="suricata",
            )

        rule_body = "\n".join(rules) + "\n"

        return TranslationResult(
            indicator_id=indicator_id,
            language=RuleLanguage.SURICATA,
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
        """Translate a single comparison into a Suricata rule line."""
        otype = cmp.object_path.object_type
        value = str(cmp.value)
        sid = self._next_sid
        self._next_sid += 1
        msg = name or indicator_id or "HuntGNAT indicator"

        if otype == "domain-name":
            return (
                f'alert dns $HOME_NET any -> any any '
                f'(msg:"HuntGNAT: {msg}"; '
                f'dns.query; content:"{value}"; nocase; '
                f'sid:{sid}; rev:1;)'
            )
        if otype in ("ipv4-addr", "ipv6-addr"):
            prop = ".".join(cmp.object_path.property_path)
            if "dst" in prop or prop == "value":
                return (
                    f'alert ip $HOME_NET any -> {value} any '
                    f'(msg:"HuntGNAT: {msg}"; '
                    f'sid:{sid}; rev:1;)'
                )
            return (
                f'alert ip {value} any -> $HOME_NET any '
                f'(msg:"HuntGNAT: {msg}"; '
                f'sid:{sid}; rev:1;)'
            )
        if otype == "url":
            return (
                f'alert http $HOME_NET any -> $EXTERNAL_NET any '
                f'(msg:"HuntGNAT: {msg}"; '
                f'http.uri; content:"{value}"; nocase; '
                f'sid:{sid}; rev:1;)'
            )
        if otype == "network-traffic":
            prop = ".".join(cmp.object_path.property_path)
            if "dst" in prop:
                return (
                    f'alert ip $HOME_NET any -> {value} any '
                    f'(msg:"HuntGNAT: {msg}"; '
                    f'sid:{sid}; rev:1;)'
                )
            if "src" in prop:
                return (
                    f'alert ip {value} any -> $HOME_NET any '
                    f'(msg:"HuntGNAT: {msg}"; '
                    f'sid:{sid}; rev:1;)'
                )
        return None
