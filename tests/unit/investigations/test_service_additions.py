# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
Unit tests for InvestigationService cross-tool additions.

Covers ``attach_evidence_bundle`` and ``find_by_subject`` — the two new
methods added to :class:`~gnat.analysis.investigations.service.InvestigationService`
for the cross-tool investigation context feature.
"""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock

import pytest

from gnat.analysis.investigations.models import (
    Investigation,
    InvestigationStatus,
)
from gnat.analysis.investigations.service import (
    AttachResult,
    InvestigationError,
    InvestigationService,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _investigation_id() -> str:
    return f"investigation--{uuid.uuid4()}"


def _stix_indicator(investigation_id: str, origin: str = "gnat") -> dict:
    """Build a minimal STIX indicator stamped with investigation properties."""
    return {
        "type": "indicator",
        "id": f"indicator--{uuid.uuid4()}",
        "created": "2026-04-20T00:00:00Z",
        "modified": "2026-04-20T00:00:00Z",
        "name": "Malicious IP",
        "pattern": "[ipv4-addr:value = '10.0.0.1']",
        "pattern_type": "stix",
        "valid_from": "2026-04-20T00:00:00Z",
        "x_gnat_investigation_id": investigation_id,
        "x_gnat_investigation_origin": origin,
        "x_gnat_investigation_link_type": "confirmed",
    }


def _stix_bundle(investigation_id: str, origin: str = "gnat", count: int = 3) -> dict:
    """Build a STIX 2.1 bundle with stamped objects."""
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": [
            _stix_indicator(investigation_id, origin=origin) for _ in range(count)
        ],
    }


def _mismatched_bundle(
    endpoint_id: str, stamped_id: str, count: int = 2
) -> dict:
    """Build a bundle where objects are stamped with a different investigation_id."""
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": [
            _stix_indicator(stamped_id, origin="gnat") for _ in range(count)
        ],
    }


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_store():
    """Return a mock InvestigationStore with sensible defaults."""
    store = MagicMock()
    store.create_all = MagicMock()
    return store


@pytest.fixture
def open_investigation(mock_store) -> Investigation:
    """Create a real Investigation object in OPEN → IN_PROGRESS state."""
    inv = Investigation(
        title="Cross-tool test",
        created_by="analyst@example.com",
    )
    inv.status = InvestigationStatus.IN_PROGRESS
    mock_store.get.return_value = inv
    mock_store.save.return_value = inv
    return inv


@pytest.fixture
def closed_investigation(mock_store) -> Investigation:
    """Create a real Investigation object in CLOSED state."""
    inv = Investigation(
        title="Closed investigation",
        created_by="analyst@example.com",
    )
    inv.status = InvestigationStatus.CLOSED
    mock_store.get.return_value = inv
    mock_store.save.return_value = inv
    return inv


@pytest.fixture
def service(mock_store) -> InvestigationService:
    """Return an InvestigationService backed by the mock store."""
    return InvestigationService(mock_store)


# ---------------------------------------------------------------------------
# Tests: attach_evidence_bundle
# ---------------------------------------------------------------------------


class TestAttachEvidenceBundle:
    """Tests for InvestigationService.attach_evidence_bundle."""

    def test_valid_bundle_returns_accepted(
        self, service, mock_store, open_investigation
    ):
        """A valid bundle with matching investigation_id returns
        an AttachResult with accepted_count > 0."""
        inv_id = open_investigation.id
        bundle = _stix_bundle(inv_id, origin="sandgnat", count=3)

        result = service.attach_evidence_bundle(
            investigation_id=inv_id,
            bundle=bundle,
            origin="sandgnat",
            tenant_id="tenant-1",
        )

        assert result is not None
        assert result.accepted_count > 0
        assert result.rejected_count == 0
        assert result.rejection_reasons == []

    def test_mismatched_investigation_id_rejected(
        self, service, mock_store, open_investigation
    ):
        """Objects stamped with a different investigation_id are rejected."""
        inv_id = open_investigation.id
        other_id = _investigation_id()
        bundle = _mismatched_bundle(inv_id, other_id, count=2)

        result = service.attach_evidence_bundle(
            investigation_id=inv_id,
            bundle=bundle,
            origin="gnat",
            tenant_id="tenant-1",
        )

        assert result is not None
        assert result.rejected_count > 0
        assert len(result.rejection_reasons) > 0

    def test_closed_investigation_raises(
        self, service, mock_store, closed_investigation
    ):
        """Attaching evidence to a CLOSED investigation raises InvestigationError."""
        inv_id = closed_investigation.id
        bundle = _stix_bundle(inv_id)

        with pytest.raises(InvestigationError):
            service.attach_evidence_bundle(
                investigation_id=inv_id,
                bundle=bundle,
                origin="gnat",
                tenant_id="tenant-1",
            )

    def test_attach_records_origin_in_source_connectors(
        self, service, mock_store, open_investigation
    ):
        """The origin is appended to the investigation's source_connectors."""
        inv_id = open_investigation.id
        bundle = _stix_bundle(inv_id, origin="redgnat", count=1)

        result = service.attach_evidence_bundle(
            investigation_id=inv_id,
            bundle=bundle,
            origin="redgnat",
            tenant_id="tenant-1",
        )

        assert result is not None
        assert result.accepted_count > 0
        assert "redgnat" in open_investigation.source_connectors

    def test_attach_result_dataclass_shape(self):
        """AttachResult has the expected fields."""
        r = AttachResult()
        assert r.accepted_count == 0
        assert r.rejected_count == 0
        assert r.rejection_reasons == []

        r2 = AttachResult(accepted_count=5, rejected_count=2, rejection_reasons=["a", "b"])
        assert r2.accepted_count == 5
        assert r2.rejected_count == 2
        assert len(r2.rejection_reasons) == 2


# ---------------------------------------------------------------------------
# Tests: find_by_subject
# ---------------------------------------------------------------------------


class TestFindBySubject:
    """Tests for InvestigationService.find_by_subject."""

    def test_returns_matching_investigations(self, service, mock_store):
        """find_by_subject returns investigations containing the subject_ref."""
        inv_match = Investigation(
            title="Subject match test",
            created_by="analyst@example.com",
        )
        inv_match.indicators = ["indicator--abc-123"]

        inv_no_match = Investigation(
            title="Unrelated investigation",
            created_by="analyst@example.com",
        )
        inv_no_match.indicators = ["indicator--xyz-999"]

        # find_by_subject calls self._store.list(limit=10000)
        mock_store.list.return_value = [inv_match, inv_no_match]

        results = service.find_by_subject(
            subject_ref="indicator--abc-123",
            tenant_id=None,
        )

        assert isinstance(results, list)
        assert len(results) == 1
        assert results[0].id == inv_match.id

    def test_returns_empty_list_when_no_match(self, service, mock_store):
        """find_by_subject returns an empty list when no investigation matches."""
        inv = Investigation(
            title="No match",
            created_by="analyst@example.com",
        )
        inv.indicators = ["indicator--other"]
        mock_store.list.return_value = [inv]

        results = service.find_by_subject(
            subject_ref="indicator--nonexistent",
            tenant_id=None,
        )

        assert isinstance(results, list)
        assert len(results) == 0
