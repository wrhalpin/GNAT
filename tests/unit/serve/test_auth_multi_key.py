# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
tests/unit/serve/test_auth_multi_key.py
=======================================

Unit tests for the updated :class:`~gnat.serve.auth.APIKeyAuth` that
accepts an :class:`~gnat.dissemination.api.auth.APIKeyStore` and supports
both ``Authorization: Bearer`` and ``X-Api-Key`` headers.

Requires FastAPI (skip the module if not installed).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

# Skip the whole module when FastAPI is not available.
pytest.importorskip("fastapi")

from fastapi import Depends, FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from gnat.analysis.tlp import TLPLevel  # noqa: E402
from gnat.dissemination.api.auth import APIKey, APIKeyStore  # noqa: E402
from gnat.serve.auth import APIKeyAuth  # noqa: E402

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_VALID_TOKEN = "test-valid-token-abc123"
_SECOND_TOKEN = "test-second-token-xyz789"
_INVALID_TOKEN = "wrong-token"


def _build_app(store: APIKeyStore) -> FastAPI:
    """Build a minimal FastAPI app with the multi-key auth dependency."""
    auth = APIKeyAuth(key_store=store)

    app = FastAPI()

    @app.get("/protected")
    def protected(key: APIKey = Depends(auth)):
        return {"label": key.label, "role": key.role}

    return app


def _make_store() -> APIKeyStore:
    """Create a store pre-loaded with two keys."""
    store = APIKeyStore()
    store.add_key(
        _VALID_TOKEN,
        TLPLevel.AMBER,
        label="primary-integration",
        role="analyst",
    )
    store.add_key(
        _SECOND_TOKEN,
        TLPLevel.GREEN,
        label="secondary-partner",
        role="viewer",
    )
    return store


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestMultiKeyAuthValid:
    """Valid keys should be accepted and return identity."""

    def test_valid_key_returns_200(self):
        client = TestClient(_build_app(_make_store()))
        resp = client.get(
            "/protected",
            headers={"Authorization": f"Bearer {_VALID_TOKEN}"},
        )
        assert resp.status_code == 200
        assert resp.json()["label"] == "primary-integration"

    def test_per_key_identity(self):
        """Different keys yield different labels in the response."""
        store = _make_store()
        client = TestClient(_build_app(store))

        resp1 = client.get(
            "/protected",
            headers={"Authorization": f"Bearer {_VALID_TOKEN}"},
        )
        resp2 = client.get(
            "/protected",
            headers={"Authorization": f"Bearer {_SECOND_TOKEN}"},
        )
        assert resp1.status_code == 200
        assert resp2.status_code == 200
        assert resp1.json()["label"] == "primary-integration"
        assert resp2.json()["label"] == "secondary-partner"
        assert resp1.json()["role"] == "analyst"
        assert resp2.json()["role"] == "viewer"


class TestMultiKeyAuthInvalid:
    """Invalid, expired, and revoked keys should be rejected."""

    def test_invalid_key_returns_401(self):
        client = TestClient(_build_app(_make_store()))
        resp = client.get(
            "/protected",
            headers={"Authorization": f"Bearer {_INVALID_TOKEN}"},
        )
        assert resp.status_code == 401

    def test_missing_header_returns_401(self):
        client = TestClient(_build_app(_make_store()))
        resp = client.get("/protected")
        assert resp.status_code == 401

    def test_expired_key_returns_401(self):
        store = APIKeyStore()
        store.add_key(
            "expired-tok",
            TLPLevel.GREEN,
            label="expired",
            expires_at=datetime.now(tz=timezone.utc) - timedelta(hours=1),
        )
        client = TestClient(_build_app(store))
        resp = client.get(
            "/protected",
            headers={"Authorization": "Bearer expired-tok"},
        )
        assert resp.status_code == 401

    def test_revoked_key_returns_401(self):
        store = _make_store()
        store.revoke_key(_VALID_TOKEN)
        client = TestClient(_build_app(store))
        resp = client.get(
            "/protected",
            headers={"Authorization": f"Bearer {_VALID_TOKEN}"},
        )
        assert resp.status_code == 401


class TestBackwardCompatHeaders:
    """Both ``Authorization: Bearer`` and ``X-Api-Key`` headers are accepted."""

    def test_bearer_header_works(self):
        client = TestClient(_build_app(_make_store()))
        resp = client.get(
            "/protected",
            headers={"Authorization": f"Bearer {_VALID_TOKEN}"},
        )
        assert resp.status_code == 200

    def test_x_api_key_header_works(self):
        client = TestClient(_build_app(_make_store()))
        resp = client.get(
            "/protected",
            headers={"X-Api-Key": _VALID_TOKEN},
        )
        assert resp.status_code == 200

    def test_authorization_takes_precedence_over_x_api_key(self):
        """When both headers are present, Authorization wins."""
        store = _make_store()
        client = TestClient(_build_app(store))
        resp = client.get(
            "/protected",
            headers={
                "Authorization": f"Bearer {_VALID_TOKEN}",
                "X-Api-Key": _SECOND_TOKEN,
            },
        )
        assert resp.status_code == 200
        # Should resolve to the Authorization header's key
        assert resp.json()["label"] == "primary-integration"
