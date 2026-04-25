# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
Unit tests for the cross-tool investigation evidence API endpoint.

Tests the FastAPI router built by ``build_investigation_router`` — verifying
that the POST endpoint for evidence bundles correctly validates stamped
investigation IDs, tenant isolation, and investigation lifecycle state.
"""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock

import pytest

try:
    import fastapi  # noqa: F401

    _HAS_FASTAPI = True
except ImportError:
    _HAS_FASTAPI = False

pytestmark = pytest.mark.skipif(not _HAS_FASTAPI, reason="FastAPI not installed")

from gnat.analysis.investigations.models import InvestigationStatus  # noqa: E402
from gnat.analysis.investigations.service import AttachResult, InvestigationError  # noqa: E402

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

VALID_ORIGINS = ("gnat", "sandgnat", "sensegnat", "redgnat", "external")
VALID_LINK_TYPES = ("confirmed", "inferred", "suggested")


def _investigation_id() -> str:
    return f"investigation--{uuid.uuid4()}"


def _stix_indicator(
    investigation_id: str,
    origin: str = "gnat",
    link_type: str = "confirmed",
) -> dict:
    """Build a minimal STIX indicator stamped with investigation custom properties."""
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
        "x_gnat_investigation_link_type": link_type,
    }


def _stix_bundle(investigation_id: str, origin: str = "gnat", count: int = 2) -> dict:
    """Build a STIX 2.1 bundle with stamped objects."""
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": [_stix_indicator(investigation_id, origin=origin) for _ in range(count)],
    }


# ---------------------------------------------------------------------------
# Mock factories
# ---------------------------------------------------------------------------


def _mock_investigation_service(
    investigation_id: str,
    *,
    status: str = "in_progress",
    tenant_id: str = "tenant-1",
    accept: bool = True,
) -> MagicMock:
    """Return a mock InvestigationService with sensible defaults."""
    svc = MagicMock()

    # .get() returns a mock Investigation with real InvestigationStatus
    inv = MagicMock()
    inv.id = investigation_id
    inv.status = InvestigationStatus(status)
    inv.tenant_id = tenant_id
    inv.hypothesis = []
    inv.indicators = []
    inv.observables = []
    inv.tags = []
    inv.source_connectors = []
    svc.get.return_value = inv

    # .attach_evidence_bundle() returns a real AttachResult
    if accept:
        svc.attach_evidence_bundle.return_value = AttachResult(accepted_count=2, rejected_count=0)
    else:
        svc.attach_evidence_bundle.return_value = AttachResult(
            accepted_count=0, rejected_count=2, rejection_reasons=["mismatched id"]
        )

    # .list() and .find_by_subject()
    svc.list.return_value = [inv]
    svc.find_by_subject.return_value = [inv]

    # .transition() for reopen — must update status on the mock
    def _mock_transition(inv_id, new_status, **kwargs):
        inv.status = new_status
        return inv

    svc.transition.side_effect = _mock_transition

    return svc


def _mock_key_store(token: str = "test-token", tenant_id: str = "tenant-1") -> MagicMock:
    """Return a mock APIKeyStore that validates a single token."""
    from gnat.analysis.tlp import TLPLevel
    from gnat.dissemination.api.auth import APIKey

    key = APIKey(
        token=token,
        tlp_level=TLPLevel.AMBER,
        label="test",
        role="analyst",
        metadata={"tenant_id": tenant_id},
    )
    store = MagicMock()
    store.get_key.side_effect = lambda t: key if t == token else None
    return store


# ---------------------------------------------------------------------------
# Fixture: TestClient
# ---------------------------------------------------------------------------


@pytest.fixture
def client_factory():
    """Return a factory that creates a TestClient for the investigation router."""

    def _make(
        investigation_id: str | None = None,
        status: str = "in_progress",
        tenant_id: str = "tenant-1",
        accept: bool = True,
    ):
        inv_id = investigation_id or _investigation_id()
        svc = _mock_investigation_service(inv_id, status=status, tenant_id=tenant_id, accept=accept)
        key_store = _mock_key_store(tenant_id=tenant_id)

        from gnat.dissemination.api.investigations import build_investigation_router

        router = build_investigation_router(svc, key_store)

        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        app = FastAPI()
        app.include_router(router, prefix="/api/v1")
        return TestClient(app), svc, inv_id

    return _make


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestPostEvidenceBundle:
    """Tests for POST /api/v1/investigations/{id}/evidence."""

    def test_accepts_valid_stamped_bundle(self, client_factory):
        """A bundle whose objects all carry the correct investigation_id is accepted."""
        tc, svc, inv_id = client_factory()
        bundle = _stix_bundle(inv_id, origin="sandgnat")

        resp = tc.post(
            f"/api/v1/investigations/{inv_id}/evidence",
            json=bundle,
            headers={"Authorization": "Bearer test-token"},
        )

        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["accepted_count"] >= 1
        assert body["rejected_count"] == 0
        svc.attach_evidence_bundle.assert_called_once()

    def test_rejects_mismatched_investigation_id(self, client_factory):
        """Bundle stamped with ID-A posted to endpoint for ID-B is rejected."""
        tc, svc, inv_id = client_factory(accept=False)
        other_id = _investigation_id()
        bundle = _stix_bundle(other_id, origin="gnat")

        # The router should detect the mismatch before calling the service,
        # or the service returns a rejection.  Either way we expect 4xx.
        svc.attach_evidence_bundle.return_value = AttachResult(
            accepted_count=0,
            rejected_count=2,
            rejection_reasons=[f"Object stamped with {other_id} does not match endpoint {inv_id}"],
        )

        resp = tc.post(
            f"/api/v1/investigations/{inv_id}/evidence",
            json=bundle,
            headers={"Authorization": "Bearer test-token"},
        )

        # Accept either 400 (pre-check) or 200 with rejected_count > 0 (service-level)
        if resp.status_code == 200:
            body = resp.json()
            assert body["rejected_count"] > 0
        else:
            assert resp.status_code in (400, 409, 422)

    def test_rejects_cross_tenant_reference(self, client_factory):
        """Evidence posted by tenant-1 key cannot target a tenant-2 investigation."""
        inv_id = _investigation_id()

        # Build a service where the investigation belongs to tenant-2
        # and the API key belongs to tenant-1 — the service.attach_evidence_bundle()
        # returns a rejection because the tenant_id mismatch is checked there.
        svc_cross = _mock_investigation_service(inv_id, tenant_id="tenant-2")
        svc_cross.attach_evidence_bundle.return_value = AttachResult(
            accepted_count=0,
            rejected_count=1,
            rejection_reasons=[
                "Cross-tenant reference denied: investigation belongs to "
                "'tenant-2', request authenticated as 'tenant-1'"
            ],
        )
        other_key_store = _mock_key_store(tenant_id="tenant-1")

        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from gnat.dissemination.api.investigations import build_investigation_router

        router = build_investigation_router(svc_cross, other_key_store)
        app = FastAPI()
        app.include_router(router, prefix="/api/v1")
        tc_cross = TestClient(app)

        bundle = _stix_bundle(inv_id)
        resp = tc_cross.post(
            f"/api/v1/investigations/{inv_id}/evidence",
            json=bundle,
            headers={"Authorization": "Bearer test-token"},
        )

        # The service returns rejected_count > 0 and accepted_count == 0,
        # so the router should return 400.
        assert resp.status_code in (400, 403, 409, 422), (
            f"Expected rejection for cross-tenant, got {resp.status_code}: {resp.text}"
        )

    def test_rejects_closed_investigation_without_reopen_header(self, client_factory):
        """POSTing evidence to a CLOSED investigation without X-Reopen-Investigation fails."""
        tc, svc, inv_id = client_factory(status="closed")

        # The service raises InvestigationError for closed investigations
        svc.attach_evidence_bundle.side_effect = InvestigationError(
            f"Investigation {inv_id} is CLOSED. Set X-Reopen-Investigation header to reopen."
        )

        bundle = _stix_bundle(inv_id)
        resp = tc.post(
            f"/api/v1/investigations/{inv_id}/evidence",
            json=bundle,
            headers={"Authorization": "Bearer test-token"},
        )

        assert resp.status_code == 409, (
            f"Expected 409 for closed investigation, got {resp.status_code}: {resp.text}"
        )

    def test_accepts_with_reopen_header(self, client_factory):
        """X-Reopen-Investigation: true allows evidence on a closed investigation."""
        tc, svc, inv_id = client_factory(status="closed")

        # When X-Reopen-Investigation is sent, the router calls transition()
        # first (changing status to IN_PROGRESS), then attach_evidence_bundle().
        # The transition side_effect updates inv.status, so attach won't see CLOSED.
        svc.attach_evidence_bundle.return_value = AttachResult(accepted_count=2, rejected_count=0)

        bundle = _stix_bundle(inv_id)
        resp = tc.post(
            f"/api/v1/investigations/{inv_id}/evidence",
            json=bundle,
            headers={
                "Authorization": "Bearer test-token",
                "X-Reopen-Investigation": "true",
            },
        )

        assert resp.status_code == 200, (
            f"Expected 200 with reopen header, got {resp.status_code}: {resp.text}"
        )
        body = resp.json()
        assert body["accepted_count"] >= 1
        # Verify transition was called to reopen
        svc.transition.assert_called_once()
