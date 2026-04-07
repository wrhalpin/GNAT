# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.analysis
=============

Analyst-facing layer transforming ingested CTI data into intelligence products.

Modules
-------
confidence
    :class:`~.confidence.ConfidenceScore` combining the NATO Admiralty Scale
    (source reliability A–F, information credibility 1–6) with a STIX 2.1
    numeric confidence value (0–100).
tlp
    :class:`~.tlp.TLPLevel` — TLP 2.0 classification levels shared across the
    analysis, reporting, and dissemination layers.
investigations
    First-class :class:`~.investigations.Investigation` objects with lifecycle
    management, hypothesis tracking, analyst notes, task management, and
    artifact linking.

Architecture
------------
The analysis layer sits above the existing storage layer (Postgres + Solr) and
does not replace or bypass the ingestion pipeline.  See ADR-0031 for the full
rationale.

Quick start::

    from gnat.analysis.confidence import ConfidenceScore, SourceReliability, InformationCredibility
    from gnat.analysis.tlp import TLPLevel
    from gnat.analysis.investigations import Investigation, InvestigationService, InvestigationStore

    score = ConfidenceScore.high(rationale="Cross-corroborated by two independent sources.")
    print(score.label)  # "B2 (HIGH)"

    store   = InvestigationStore("sqlite:///~/.gnat/gnat.db")
    store.create_all()
    service = InvestigationService(store)

    inv = service.create(title="APT28 Campaign Apr 2026", created_by="analyst@example.com")
"""

from gnat.analysis.confidence import (
    ConfidenceLevel,
    ConfidenceScore,
    InformationCredibility,
    SourceReliability,
)
from gnat.analysis.tlp import TLPLevel

__all__ = [
    # Confidence
    "ConfidenceScore",
    "ConfidenceLevel",
    "SourceReliability",
    "InformationCredibility",
    # TLP
    "TLPLevel",
]
