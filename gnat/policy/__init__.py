"""
gnat.policy
===========

Role-based access control (RBAC) for the GNAT API layer.

Provides a permission matrix, a :class:`PolicyEngine` for evaluating
access decisions, and optional FastAPI middleware for audit logging.

Quick start::

    from gnat.policy import PolicyEngine, Permission, Role

    engine = PolicyEngine()

    # Standalone evaluation
    from gnat.dissemination.api.auth import APIKey, APIKeyStore
    from gnat.analysis.tlp import TLPLevel

    store = APIKeyStore()
    key   = store.add_key("token", TLPLevel.AMBER, role=Role.ANALYST)
    print(engine.evaluate(key, Permission.WRITE_INVESTIGATIONS))  # True

    # FastAPI Depends integration
    from fastapi import APIRouter, Depends

    router = APIRouter()

    @router.post("/investigations")
    def create(key=Depends(engine.require(Permission.WRITE_INVESTIGATIONS,
                                          key_store=store))):
        ...

    # Audit middleware
    from gnat.policy import build_audit_middleware
    from fastapi import FastAPI

    app = FastAPI()
    app.add_middleware(build_audit_middleware(store))
"""

from gnat.policy.engine import PolicyEngine
from gnat.policy.middleware import build_audit_middleware
from gnat.policy.models import (
    AgentActionType,
    Permission,
    Role,
    ROLE_PERMISSIONS,
    agent_can_act,
    permissions_for,
    roles_with,
)

__all__ = [
    "PolicyEngine",
    "build_audit_middleware",
    "AgentActionType",
    "Permission",
    "Role",
    "ROLE_PERMISSIONS",
    "agent_can_act",
    "permissions_for",
    "roles_with",
]
