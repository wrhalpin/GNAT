# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.plugins.huntgnat.models
================================

Data models for HuntGNAT detection rules.

In Phase 1, rules are in-memory dataclasses. Phase 3 adds Postgres
persistence via the ``huntgnat_rule`` table; these dataclasses will
become the ORM's serialization targets.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class RuleLanguage(str, Enum):
    """Target detection languages supported by HuntGNAT."""

    SIGMA = "sigma"
    YARA = "yara"
    SPL = "spl"
    KQL = "kql"
    EQL = "eql"
    SURICATA = "suricata"
    SNORT = "snort"


class RuleStatus(str, Enum):
    """Lifecycle status of a detection rule."""

    DRAFT = "draft"
    REVIEWED = "reviewed"
    APPROVED = "approved"
    DEPRECATED = "deprecated"


@dataclass
class TranslationResult:
    """
    Output of a single rule translation.

    Carries the rule body, metadata about the translation, and enough
    context for the caller to persist, display, or pipeline the rule.
    """

    rule_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    indicator_id: str | None = None
    language: RuleLanguage = RuleLanguage.SIGMA
    rule_body: str = ""
    translator_version: str = ""
    status: RuleStatus = RuleStatus.DRAFT
    confidence: int = 60
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    created_by: str = "huntgnat"
    rule_hash: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.rule_hash and self.rule_body:
            self.rule_hash = hashlib.sha256(self.rule_body.encode("utf-8")).hexdigest()

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "indicator_id": self.indicator_id,
            "language": self.language.value,
            "rule_body": self.rule_body,
            "translator_version": self.translator_version,
            "status": self.status.value,
            "confidence": self.confidence,
            "created_at": self.created_at,
            "created_by": self.created_by,
            "hash": self.rule_hash,
            "metadata": self.metadata,
        }
