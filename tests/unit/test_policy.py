"""Unit tests for gnat.policy (RBAC engine)."""

from __future__ import annotations

import pytest


# ── Models ────────────────────────────────────────────────────────────────────

def test_role_values():
    from gnat.policy.models import Role
    assert Role.VIEWER         == "viewer"
    assert Role.ANALYST        == "analyst"
    assert Role.SENIOR_ANALYST == "senior_analyst"
    assert Role.REVIEWER       == "reviewer"
    assert Role.ADMIN          == "admin"


def test_permission_values():
    from gnat.policy.models import Permission
    assert Permission.READ_INVESTIGATIONS  == "read_investigations"
    assert Permission.WRITE_INVESTIGATIONS == "write_investigations"
    assert Permission.MANAGE_KEYS          == "manage_keys"
    assert Permission.WRITE_TAXII          == "write_taxii"


def test_role_permissions_matrix():
    from gnat.policy.models import Role, Permission, ROLE_PERMISSIONS

    viewer_perms = ROLE_PERMISSIONS[Role.VIEWER]
    assert Permission.READ_INVESTIGATIONS in viewer_perms
    assert Permission.WRITE_INVESTIGATIONS not in viewer_perms

    analyst_perms = ROLE_PERMISSIONS[Role.ANALYST]
    assert Permission.WRITE_INVESTIGATIONS in analyst_perms
    assert Permission.SUBMIT_REPORTS not in analyst_perms

    senior_perms = ROLE_PERMISSIONS[Role.SENIOR_ANALYST]
    assert Permission.SUBMIT_REPORTS in senior_perms
    assert Permission.WRITE_TAXII in senior_perms

    reviewer_perms = ROLE_PERMISSIONS[Role.REVIEWER]
    assert Permission.APPROVE_REPORTS in reviewer_perms

    admin_perms = ROLE_PERMISSIONS[Role.ADMIN]
    for p in Permission:
        assert p in admin_perms, f"ADMIN should have {p}"


def test_permissions_for():
    from gnat.policy.models import Role, Permission, permissions_for
    assert permissions_for(Role.VIEWER) == {Permission.READ_INVESTIGATIONS, Permission.READ_REPORTS}


def test_roles_with():
    from gnat.policy.models import Permission, roles_with
    roles = roles_with(Permission.MANAGE_KEYS)
    from gnat.policy.models import Role
    assert Role.ADMIN in roles
    assert Role.VIEWER not in roles


# ── PolicyEngine ──────────────────────────────────────────────────────────────

def test_engine_evaluate_by_role():
    from gnat.policy.engine import PolicyEngine
    from gnat.policy.models import Role, Permission

    engine = PolicyEngine(default_role=Role.VIEWER)
    assert engine.evaluate_role(Role.ANALYST, Permission.WRITE_INVESTIGATIONS) is True
    assert engine.evaluate_role(Role.VIEWER,  Permission.WRITE_INVESTIGATIONS) is False
    assert engine.evaluate_role(Role.ADMIN,   Permission.MANAGE_KEYS) is True


def test_engine_evaluate_subject_with_role_string():
    from gnat.policy.engine import PolicyEngine
    from gnat.policy.models import Permission

    class FakeKey:
        role = "analyst"

    engine = PolicyEngine()
    assert engine.evaluate(FakeKey(), Permission.WRITE_INVESTIGATIONS) is True
    assert engine.evaluate(FakeKey(), Permission.MANAGE_KEYS) is False


def test_engine_evaluate_subject_unknown_role_uses_default():
    from gnat.policy.engine import PolicyEngine
    from gnat.policy.models import Permission, Role

    class FakeKey:
        role = "nonexistent_role"

    engine = PolicyEngine(default_role=Role.VIEWER)
    # Falls back to VIEWER — can read but not write
    assert engine.evaluate(FakeKey(), Permission.READ_INVESTIGATIONS) is True
    assert engine.evaluate(FakeKey(), Permission.WRITE_INVESTIGATIONS) is False


def test_engine_evaluate_subject_none_uses_default():
    from gnat.policy.engine import PolicyEngine
    from gnat.policy.models import Permission, Role

    engine = PolicyEngine(default_role=Role.ANALYST)
    assert engine.evaluate(None, Permission.WRITE_INVESTIGATIONS) is True


def test_engine_audit_emits_hook_event():
    from gnat.policy.engine import PolicyEngine
    from gnat.policy.models import Permission
    from gnat.plugins.hooks import HookBus

    # audit() uses the HookBus singleton — register on it
    bus    = HookBus.instance()
    events = []
    handler = lambda **kw: events.append(kw)
    bus.register("policy_decision", handler)
    try:
        engine = PolicyEngine()
        engine.audit("alice", Permission.READ_INVESTIGATIONS, resource="inv-1", granted=True)

        assert len(events) == 1
        assert events[0]["actor"]   == "alice"
        assert events[0]["granted"] is True
    finally:
        bus.unregister("policy_decision", handler)


def test_engine_require_without_fastapi_returns_callable():
    from gnat.policy.engine import PolicyEngine
    from gnat.policy.models import Permission

    engine = PolicyEngine()
    dep    = engine.require(Permission.READ_INVESTIGATIONS)
    assert callable(dep)


# ── APIKey role field ──────────────────────────────────────────────────────────

def test_apikey_default_role():
    from gnat.dissemination.api.auth import APIKey
    from gnat.analysis.tlp import TLPLevel

    key = APIKey(token="t", tlp_level=TLPLevel.GREEN)
    assert key.role == "viewer"


def test_apikey_store_add_key_with_role():
    from gnat.dissemination.api.auth import APIKeyStore
    from gnat.analysis.tlp import TLPLevel

    store = APIKeyStore()
    key   = store.add_key("token", TLPLevel.AMBER, label="test", role="analyst")
    assert key.role == "analyst"
    assert key.to_dict()["role"] == "analyst"


def test_apikey_store_generate_key_with_role():
    from gnat.dissemination.api.auth import APIKeyStore
    from gnat.analysis.tlp import TLPLevel

    store = APIKeyStore()
    key   = store.generate_key(TLPLevel.RED, label="admin key", role="admin")
    assert key.role == "admin"


# ── policy/__init__ exports ───────────────────────────────────────────────────

def test_policy_init_exports():
    import gnat.policy as p
    assert hasattr(p, "PolicyEngine")
    assert hasattr(p, "Role")
    assert hasattr(p, "Permission")
    assert hasattr(p, "ROLE_PERMISSIONS")
    assert hasattr(p, "build_audit_middleware")
