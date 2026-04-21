# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.plugins.huntgnat.translators.sigma
===========================================

Translate STIX 2.1 Indicator patterns into Sigma rules (YAML).

Sigma is HuntGNAT's primary intermediate representation. SPL, KQL, and
EQL are produced by transpiling the Sigma output via pySigma backends
(see :class:`SigmaTranspileTranslator` — Phase 1 stretch / Phase 2).

Mapping strategy
----------------
Each STIX observable type maps to a Sigma ``logsource`` category and
a set of field name mappings:

* ``file:hashes.*``        → ``logsource: {category: file_event}``
* ``process:*``            → ``logsource: {category: process_creation}``
* ``domain-name:value``    → ``logsource: {category: dns}``
* ``ipv4-addr:value``      → ``logsource: {category: firewall}``
* ``url:value``            → ``logsource: {category: proxy}``
* ``windows-registry-key`` → ``logsource: {category: registry_event}``
* ``network-traffic``      → ``logsource: {category: firewall}``
"""

from __future__ import annotations

import uuid
from typing import Any

from gnat.plugins.huntgnat.errors import UntranslatableError
from gnat.plugins.huntgnat.models import RuleLanguage, TranslationResult
from gnat.plugins.huntgnat.parser.stix_pattern import (
    Comparison,
    ComparisonExpr,
    CompoundObservation,
)
from gnat.plugins.huntgnat.translators.base import RuleTranslator

# STIX observable type → Sigma logsource mapping
_LOGSOURCE_MAP: dict[str, dict[str, str]] = {
    "file": {"category": "file_event", "product": "windows"},
    "process": {"category": "process_creation", "product": "windows"},
    "domain-name": {"category": "dns"},
    "ipv4-addr": {"category": "firewall"},
    "ipv6-addr": {"category": "firewall"},
    "url": {"category": "proxy"},
    "network-traffic": {"category": "firewall"},
    "windows-registry-key": {"category": "registry_event", "product": "windows"},
    "email-addr": {"category": "email"},
    "email-message": {"category": "email"},
}

# STIX property path → Sigma field name
_FIELD_MAP: dict[str, str] = {
    "hashes.SHA-256": "Hashes",
    "hashes.SHA-1": "Hashes",
    "hashes.MD5": "Hashes",
    "value": "DestinationHostname",
    "name": "TargetFilename",
    "path": "TargetFilename",
    "command_line": "CommandLine",
    "pid": "ProcessId",
    "key": "TargetObject",
    "values[*].data": "Details",
    "dst_ref.value": "DestinationIp",
    "src_ref.value": "SourceIp",
    "dst_port": "DestinationPort",
    "src_port": "SourcePort",
}

# Override field names for specific observable types
_TYPE_FIELD_OVERRIDES: dict[str, dict[str, str]] = {
    "domain-name": {"value": "DestinationHostname"},
    "ipv4-addr": {"value": "DestinationIp"},
    "ipv6-addr": {"value": "DestinationIp"},
    "url": {"value": "RequestUrl"},
    "process": {"name": "Image"},
    "email-addr": {"value": "SenderAddress"},
}


class SigmaTranslator(RuleTranslator):
    """Translate STIX patterns into Sigma YAML rules."""

    language = RuleLanguage.SIGMA
    version = "1.0.0"

    def __init__(self, author: str = "HuntGNAT") -> None:
        self.author = author

    def translate(
        self,
        ast: CompoundObservation,
        *,
        pattern: str,
        indicator_id: str | None = None,
        indicator_name: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> TranslationResult:
        if not ast.observations:
            raise UntranslatableError(
                reason="empty pattern — no observations",
                pattern=pattern,
                target_language="sigma",
            )

        # Collect all comparisons to determine the primary observable type
        all_comparisons: list[Comparison] = []
        for obs in ast.observations:
            all_comparisons.extend(obs.expression.iter_comparisons())

        if not all_comparisons:
            raise UntranslatableError(
                reason="no comparisons in pattern",
                pattern=pattern,
                target_language="sigma",
            )

        primary_type = all_comparisons[0].object_path.object_type
        logsource = dict(_LOGSOURCE_MAP.get(primary_type, {"category": "generic"}))

        # Build detection block
        detection = self._build_detection(ast, primary_type)

        # Compose YAML
        rule_id = str(uuid.uuid4())
        title = indicator_name or f"STIX Indicator {indicator_id or 'unknown'}"
        lines = [
            f"title: {title}",
            f"id: {rule_id}",
            "status: experimental",
            "description: Auto-translated from STIX pattern by HuntGNAT",
            f"author: {self.author}",
            f"date: {_today()}",
            "logsource:",
        ]
        for k, v in logsource.items():
            lines.append(f"    {k}: {v}")
        lines.append("detection:")
        lines.extend(detection)
        lines.append("level: medium")
        lines.append("falsepositives:")
        lines.append("    - Unknown")

        if indicator_id:
            lines.append("tags:")
            lines.append(f"    - stix.indicator.{indicator_id}")

        rule_body = "\n".join(lines) + "\n"

        return TranslationResult(
            rule_id=rule_id,
            indicator_id=indicator_id,
            language=RuleLanguage.SIGMA,
            rule_body=rule_body,
            translator_version=self.translator_version_tag(),
            metadata=metadata or {},
        )

    def _build_detection(self, ast: CompoundObservation, primary_type: str) -> list[str]:
        """Build the Sigma ``detection:`` block from the AST."""
        lines: list[str] = []

        if len(ast.observations) == 1:
            sel_lines = self._selection_from_expr(ast.observations[0].expression, primary_type)
            lines.append("    selection:")
            lines.extend(f"        {ln}" for ln in sel_lines)
            lines.append("    condition: selection")
        else:
            # Multiple observations → named selections + condition
            sel_names = []
            for i, obs in enumerate(ast.observations):
                name = f"selection_{i + 1}"
                sel_names.append(name)
                sel_lines = self._selection_from_expr(obs.expression, primary_type)
                lines.append(f"    {name}:")
                lines.extend(f"        {ln}" for ln in sel_lines)

            joiner = " or " if ast.operator == "OR" else " and "
            condition = joiner.join(sel_names)
            lines.append(f"    condition: {condition}")

        return lines

    def _selection_from_expr(self, expr: ComparisonExpr, primary_type: str) -> list[str]:
        """Turn a ComparisonExpr into Sigma selection key-value lines."""
        comparisons = expr.iter_comparisons()
        lines: list[str] = []
        for cmp in comparisons:
            field_name = self._resolve_field(cmp, primary_type)
            value = self._format_value(cmp)
            if cmp.operator == "LIKE":
                # Sigma uses * for wildcards; STIX uses %
                value = str(value).replace("%", "*")
                lines.append(f"{field_name}|contains: '{value.strip('*')}'")
            elif cmp.operator == "IN":
                if isinstance(cmp.value, list):
                    lines.append(f"{field_name}:")
                    for v in cmp.value:
                        lines.append(f"    - '{v}'")
                else:
                    lines.append(f"{field_name}: '{value}'")
            elif cmp.operator == "MATCHES":
                lines.append(f"{field_name}|re: '{value}'")
            elif cmp.operator in ("=", "=="):
                lines.append(f"{field_name}: '{value}'")
            elif cmp.operator == "!=":
                lines.append(f"{field_name}|not: '{value}'")
            else:
                lines.append(f"{field_name}: '{value}'")
        return lines

    def _resolve_field(self, cmp: Comparison, primary_type: str) -> str:
        """Map a STIX property path to a Sigma field name."""
        path_str = ".".join(cmp.object_path.property_path)

        # Check type-specific overrides first
        overrides = _TYPE_FIELD_OVERRIDES.get(primary_type, {})
        for path_key, sigma_field in overrides.items():
            if path_str == path_key or path_str.endswith(path_key):
                return sigma_field

        # Then general map
        for path_key, sigma_field in _FIELD_MAP.items():
            if path_str == path_key or path_str.endswith(path_key):
                return sigma_field

        # Fallback: use the last path component as-is
        return cmp.object_path.property_path[-1]

    @staticmethod
    def _format_value(cmp: Comparison) -> Any:
        """Format a comparison value for Sigma output."""
        if isinstance(cmp.value, list):
            return cmp.value
        return cmp.value


def _today() -> str:
    from datetime import date

    return date.today().isoformat()
