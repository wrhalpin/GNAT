"""
gnat.policy.models
===================

Role and permission models for the GNAT policy engine.

Design
------
A simple role-based access control (RBAC) model with a static permission
matrix.  Roles map to sets of permissions; an API key holds one role.

Roles (lowest → highest privilege)
-----------------------------------
- **VIEWER** — read-only access to published reports and investigations
- **ANALYST** — create/update investigations and hypotheses
- **SENIOR_ANALYST** — all analyst rights + submit reports for review
- **REVIEWER** — approve reports for publication
- **ADMIN** — full access including key management and plugin administration

Permissions
-----------
- ``READ_INVESTIGATIONS`` — list and view investigations
- ``WRITE_INVESTIGATIONS`` — create, edit, and transition investigations
- ``READ_REPORTS`` — view reports (including unpublished)
- ``SUBMIT_REPORTS`` — move reports to REVIEW status
- ``APPROVE_REPORTS`` — approve reports (REVIEW → APPROVED)
- ``PUBLISH_REPORTS`` — publish approved reports
- ``EXPORT_RED`` — export TLP:RED content
- ``MANAGE_KEYS`` — create/revoke API keys
- ``MANAGE_PLUGINS`` — load/unload plugins
- ``WRITE_TAXII`` — push STIX objects via TAXII write endpoint
"""

from __future__ import annotations

from enum import Enum


class Role(str, Enum):
    """Analyst role granting a bundle of permissions."""

    VIEWER          = "viewer"
    ANALYST         = "analyst"
    SENIOR_ANALYST  = "senior_analyst"
    REVIEWER        = "reviewer"
    ADMIN           = "admin"


class Permission(str, Enum):
    """Granular permission checked by the policy engine."""

    READ_INVESTIGATIONS   = "read_investigations"
    WRITE_INVESTIGATIONS  = "write_investigations"
    READ_REPORTS          = "read_reports"
    SUBMIT_REPORTS        = "submit_reports"
    APPROVE_REPORTS       = "approve_reports"
    PUBLISH_REPORTS       = "publish_reports"
    EXPORT_RED            = "export_red"
    MANAGE_KEYS           = "manage_keys"
    MANAGE_PLUGINS        = "manage_plugins"
    WRITE_TAXII           = "write_taxii"


# ---------------------------------------------------------------------------
# Static permission matrix
# ---------------------------------------------------------------------------

ROLE_PERMISSIONS: dict[Role, set[Permission]] = {
    Role.VIEWER: {
        Permission.READ_INVESTIGATIONS,
        Permission.READ_REPORTS,
    },
    Role.ANALYST: {
        Permission.READ_INVESTIGATIONS,
        Permission.WRITE_INVESTIGATIONS,
        Permission.READ_REPORTS,
    },
    Role.SENIOR_ANALYST: {
        Permission.READ_INVESTIGATIONS,
        Permission.WRITE_INVESTIGATIONS,
        Permission.READ_REPORTS,
        Permission.SUBMIT_REPORTS,
        Permission.WRITE_TAXII,
    },
    Role.REVIEWER: {
        Permission.READ_INVESTIGATIONS,
        Permission.WRITE_INVESTIGATIONS,
        Permission.READ_REPORTS,
        Permission.SUBMIT_REPORTS,
        Permission.APPROVE_REPORTS,
        Permission.WRITE_TAXII,
    },
    Role.ADMIN: set(Permission),   # full access
}


def permissions_for(role: Role) -> set[Permission]:
    """Return the permission set for *role*."""
    return ROLE_PERMISSIONS.get(role, set())


def roles_with(permission: Permission) -> list[Role]:
    """Return all roles that have *permission*."""
    return [r for r, perms in ROLE_PERMISSIONS.items() if permission in perms]
