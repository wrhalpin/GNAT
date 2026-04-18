# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.plugins.huntgnat.translators.yara_hash
===============================================

Phase 1 YARA translator — hash-only rules from STIX ``file:hashes.*``
patterns. Full byte-pattern YARA from SandGNAT trigrams is Phase 2.

Produces a YARA rule with a ``condition`` block that checks file hash
via the ``hash`` module (``hash.sha256(0, filesize)``).
"""

from __future__ import annotations

import re
from typing import Any

from gnat.plugins.huntgnat.errors import UntranslatableError
from gnat.plugins.huntgnat.models import RuleLanguage, TranslationResult
from gnat.plugins.huntgnat.parser.stix_pattern import (
    Comparison,
    CompoundObservation,
)
from gnat.plugins.huntgnat.translators.base import RuleTranslator

_HASH_ALGO_MAP: dict[str, tuple[str, int]] = {
    "MD5": ("hash.md5", 32),
    "SHA-1": ("hash.sha1", 40),
    "SHA-256": ("hash.sha256", 64),
    "SHA-512": ("hash.sha512", 128),
    "SHA1": ("hash.sha1", 40),
    "SHA256": ("hash.sha256", 64),
    "SHA512": ("hash.sha512", 128),
}

_SAFE_IDENT = re.compile(r"[^a-zA-Z0-9_]")


class YaraHashTranslator(RuleTranslator):
    """Translate STIX file-hash indicators into YARA hash rules."""

    language = RuleLanguage.YARA
    version = "1.0.0"

    def translate(
        self,
        ast: CompoundObservation,
        *,
        pattern: str,
        indicator_id: str | None = None,
        indicator_name: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> TranslationResult:
        # Collect all hash comparisons
        hashes: list[tuple[str, str]] = []
        for obs in ast.observations:
            for cmp in obs.expression.iter_comparisons():
                algo, value = self._extract_hash(cmp, pattern)
                if algo and value:
                    hashes.append((algo, value.lower()))

        if not hashes:
            raise UntranslatableError(
                reason="no file:hashes comparisons found — YARA hash "
                "translator requires at least one hash observable",
                pattern=pattern,
                target_language="yara",
            )

        rule_name = _safe_rule_name(indicator_name or indicator_id or "huntgnat_hash")
        lines = [
            'import "hash"',
            "",
            f"rule {rule_name}",
            "{",
            "    meta:",
            f'        description = "{indicator_name or "STIX hash indicator"}"',
            '        author = "HuntGNAT"',
        ]
        if indicator_id:
            lines.append(f'        stix_indicator = "{indicator_id}"')
        lines.append(f'        date = "{_today()}"')
        lines.append("")
        lines.append("    condition:")

        conditions = []
        for algo, value in hashes:
            yara_fn, expected_len = _HASH_ALGO_MAP.get(
                algo, ("hash.sha256", 64)
            )
            if len(value) != expected_len:
                raise UntranslatableError(
                    reason=f"{algo} hash must be {expected_len} hex chars, "
                    f"got {len(value)}",
                    pattern=pattern,
                    target_language="yara",
                )
            conditions.append(
                f'{yara_fn}(0, filesize) == "{value}"'
            )

        joiner = " or\n        "
        lines.append(f"        {joiner.join(conditions)}")
        lines.append("}")

        rule_body = "\n".join(lines) + "\n"

        return TranslationResult(
            indicator_id=indicator_id,
            language=RuleLanguage.YARA,
            rule_body=rule_body,
            translator_version=self.translator_version_tag(),
            metadata=metadata or {},
        )

    @staticmethod
    def _extract_hash(
        cmp: Comparison, pattern: str
    ) -> tuple[str | None, str | None]:
        """Extract (algorithm, hash_value) from a hash comparison."""
        path = cmp.object_path.property_path
        if cmp.object_path.object_type != "file":
            return None, None
        if len(path) < 2 or path[0] != "hashes":
            return None, None
        algo = path[1].upper().replace("'", "")
        if algo not in _HASH_ALGO_MAP:
            raise UntranslatableError(
                reason=f"unsupported hash algorithm {algo!r}",
                pattern=pattern,
                target_language="yara",
            )
        if not isinstance(cmp.value, str):
            return None, None
        return algo, cmp.value


def _safe_rule_name(name: str) -> str:
    """Sanitize a string into a valid YARA rule identifier."""
    safe = _SAFE_IDENT.sub("_", name)
    if safe and safe[0].isdigit():
        safe = "r_" + safe
    return safe or "huntgnat_rule"


def _today() -> str:
    from datetime import date

    return date.today().isoformat()
