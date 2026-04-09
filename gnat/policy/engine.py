"""
gnat.policy.engine
===================

The :class:`PolicyEngine` evaluates whether an API key (subject) holds a
permission, and provides a FastAPI ``Depends``-compatible factory.

Usage (standalone)::

    from gnat.policy import PolicyEngine, Permission

    engine = PolicyEngine()
    key    = api_key_store.get_key("bearer-token")
    if not engine.evaluate(key, Permission.WRITE_INVESTIGATIONS):
        raise PermissionError("Insufficient role")

Usage (FastAPI ``Depends``)::

    from fastapi import APIRouter, Depends
    from gnat.policy import PolicyEngine, Permission
    from gnat.dissemination.api.auth import APIKeyStore

    engine    = PolicyEngine()
    key_store = APIKeyStore()
    router    = APIRouter()

    @router.post("/investigations")
    def create_investigation(
        key: APIKey = Depends(engine.require(Permission.WRITE_INVESTIGATIONS,
                                             key_store=key_store)),
    ):
        ...
"""

from __future__ import annotations

import logging
from typing import Any

from gnat.policy.models import Permission, Role, permissions_for

logger = logging.getLogger(__name__)


class PolicyEngine:
    """
    Evaluates role-based permissions for GNAT API keys.

    Parameters
    ----------
    default_role : Role, optional
        Role assigned to keys that have no ``role`` attribute.
        Defaults to :attr:`~gnat.policy.models.Role.VIEWER`.
    """

    def __init__(self, default_role: Role = Role.VIEWER) -> None:
        self.default_role = default_role

    # ── Core evaluation ───────────────────────────────────────────────────

    def evaluate(self, subject: Any, permission: Permission) -> bool:
        """
        Return True if *subject* (an :class:`~gnat.dissemination.api.auth.APIKey`)
        holds *permission*.

        If *subject* is ``None`` or has no role, the ``default_role`` is used.
        """
        if subject is None:
            role = self.default_role
        else:
            role = getattr(subject, "role", self.default_role)
            if isinstance(role, str):
                try:
                    role = Role(role)
                except ValueError:
                    role = self.default_role

        has = permission in permissions_for(role)
        logger.debug(
            "PolicyEngine: subject role=%r, permission=%r → %s",
            role, permission, "ALLOW" if has else "DENY",
        )
        return has

    def evaluate_role(self, role: Role, permission: Permission) -> bool:
        """Convenience: check whether *role* has *permission* (no subject needed)."""
        return permission in permissions_for(role)

    # ── FastAPI dependency factory ────────────────────────────────────────

    def require(
        self,
        permission:  Permission,
        key_store:   Any | None = None,
        allow_none:  bool = False,
    ) -> Any:
        """
        Return a FastAPI ``Depends``-compatible callable that enforces *permission*.

        The returned callable reads the ``Authorization: Bearer <token>`` header,
        resolves the :class:`~gnat.dissemination.api.auth.APIKey`, checks the
        permission, and raises HTTP 401/403 on failure.

        Parameters
        ----------
        permission : Permission
            The permission to enforce.
        key_store : APIKeyStore, optional
            The key store to resolve tokens from.  If ``None``, an
            unauthenticated :class:`~gnat.dissemination.api.auth.APIKey` with
            the ``default_role`` is assumed.
        allow_none : bool
            If True, missing/invalid tokens are allowed with the default role
            (useful for public read endpoints).

        Returns
        -------
        Callable
            A FastAPI ``Depends`` callable.
        """
        engine = self
        _key_store = key_store

        try:
            from fastapi import Header, HTTPException

            def _dependency(authorization: str = Header(default="")) -> Any:
                key: Any = None
                if _key_store is not None and authorization.startswith("Bearer "):
                    token = authorization.removeprefix("Bearer ").strip()
                    key   = _key_store.get_key(token)
                    if key is None and not allow_none:
                        raise HTTPException(
                            status_code=401, detail="Invalid or missing API key."
                        )

                if not engine.evaluate(key, permission):
                    raise HTTPException(
                        status_code=403,
                        detail=f"Permission denied: {permission.value!r} required.",
                    )
                return key

            return _dependency

        except ImportError:
            # FastAPI not installed — return a plain callable
            def _plain_dependency(**_kwargs: Any) -> None:
                return None

            return _plain_dependency

    # ── Audit helper ──────────────────────────────────────────────────────

    def audit(
        self,
        subject:    Any,
        permission: Permission,
        resource:   str = "",
        granted:    bool | None = None,
    ) -> None:
        """
        Emit an audit log entry for an access decision.

        Integrates with the :class:`~gnat.plugins.hooks.HookBus` when available.
        """
        if granted is None:
            granted = self.evaluate(subject, permission)

        role = getattr(subject, "role", self.default_role)
        actor = getattr(subject, "label", str(subject))

        logger.info(
            "AUDIT: actor=%r role=%r permission=%r resource=%r decision=%s",
            actor, role, permission.value, resource, "ALLOW" if granted else "DENY",
        )

        try:
            from gnat.plugins.hooks import HookBus
            HookBus.instance().emit(
                "policy_decision",
                actor      = actor,
                role       = role,
                permission = permission.value,
                resource   = resource,
                granted    = granted,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Policy audit log emit failed: %s", exc)
