# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Shared fixtures for rule engine tests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

from gnat.analysis.confidence import (
    ConfidenceScore,
    InformationCredibility,
    SourceReliability,
)
from gnat.analysis.investigations.models import Hypothesis, HypothesisStatus
from gnat.analysis.rules.context import RuleContext
from gnat.analysis.rules.policy import RuleEnginePolicy
from gnat.analysis.rules.resolver import EvidenceResolver


def _now():
    return datetime.now(tz=timezone.utc)


def make_hypothesis(
    status=HypothesisStatus.OPEN,
    supporting=None,
    refuting=None,
    confidence=None,
    created_days_ago=0,
    updated_days_ago=0,
):
    now = _now()
    return Hypothesis(
        statement="Test hypothesis",
        status=status,
        supporting_evidence=supporting or [],
        refuting_evidence=refuting or [],
        confidence=confidence,
        created_at=now - timedelta(days=created_days_ago),
        updated_at=now - timedelta(days=updated_days_ago),
    )


def make_confidence(reliability="B", credibility=2, stix=75):
    return ConfidenceScore(
        source_reliability=SourceReliability(reliability),
        information_credibility=InformationCredibility(credibility),
        stix_confidence=stix,
    )


def make_context(
    platform_map=None,
    policy=None,
):
    store = MagicMock()
    store.get_source_platform = MagicMock(side_effect=lambda ws, sid: (platform_map or {}).get(sid))
    store.get_source_platforms_bulk = MagicMock(
        side_effect=lambda ws, sids: {s: (platform_map or {}).get(s) for s in sids}
    )
    resolver = EvidenceResolver(workspace_id=1, store=store)
    return RuleContext(
        resolver=resolver,
        policy=policy or RuleEnginePolicy(),
        now=_now(),
        workspace_id=1,
    )
