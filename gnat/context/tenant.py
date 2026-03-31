"""
gnat.context.tenant
====================
Multi-tenant workspace isolation for MSP (Managed Security Provider) deployments.

Design
------
Each analyst workspace is transparently prefixed with a tenant identifier,
producing fully-isolated namespace segments within a single shared store::

    acme::apt28-investigation   ← tenant "acme"
    beta::apt28-investigation   ← tenant "beta", same local name — no collision
    default::legacy-workspace   ← the "default" tenant (existing workspaces)

This approach requires **no schema migration**: it works with both the SQLAlchemy
``WorkspaceStore`` and the flat-file ``FlatFileStore``.  Existing workspaces that
were created before multi-tenancy was enabled are implicitly treated as belonging
to the ``"default"`` tenant.

Components
----------
:class:`Tenant`
    Immutable dataclass describing a registered tenant.

:class:`TenantRegistry`
    JSON-backed registry of tenants at ``~/.gnat/tenants.json``.  Provides
    ``register``, ``get``, ``list``, ``update``, and ``delete`` operations.

:class:`TenantWorkspaceManager`
    Drop-in :class:`~gnat.context.workspace.WorkspaceManager` replacement,
    scoped to one tenant.  All workspace ``create``/``open``/``list``/``delete``
    calls are automatically prefixed with ``{tenant_id}::``.  The tenant prefix
    is **transparent** to callers — returned workspace names are stripped of the
    prefix, so existing code that processes workspace names needs no changes.

Usage
-----
::

    from gnat.context import WorkspaceManager
    from gnat.context.tenant import TenantRegistry, TenantWorkspaceManager

    # Register tenants (one-time setup)
    registry = TenantRegistry()
    registry.register("acme", display_name="Acme Corp", config_path="/etc/gnat/acme.ini")
    registry.register("beta", display_name="Beta Ltd")

    # Scope a WorkspaceManager to a tenant
    manager = WorkspaceManager.default()
    acme = manager.for_tenant("acme")

    ws = acme.create("apt28-investigation")
    # Stored internally as "acme::apt28-investigation"

    acme2 = manager.for_tenant("acme")
    print([w["name"] for w in acme2.list()])   # ["apt28-investigation"]

    # Different tenant — completely isolated view
    beta = manager.for_tenant("beta")
    print(beta.list())   # []  ← no cross-tenant leakage

    # Shortcut: named constructor
    acme3 = TenantWorkspaceManager.default("acme")
"""

from __future__ import annotations

import builtins
import json
import logging
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from gnat.context.workspace import Workspace, WorkspaceManager

logger = logging.getLogger(__name__)

# Tenant ID validation: lowercase alphanumeric, hyphens, underscores; 1–63 chars
_TENANT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")

# Separator used between tenant_id and workspace name
TENANT_SEPARATOR = "::"


# ---------------------------------------------------------------------------
# Tenant dataclass
# ---------------------------------------------------------------------------

@dataclass
class Tenant:
    """
    Metadata record for a registered tenant.

    Attributes
    ----------
    tenant_id : str
        Unique, URL-safe identifier.  Must match ``[a-z0-9][a-z0-9_-]{0,62}``.
    display_name : str
        Human-readable name (e.g. ``"Acme Corp"``).
    description : str
        Optional longer description.
    config_path : str, optional
        Path to a tenant-specific ``gnat.ini`` file.  When set,
        :meth:`TenantWorkspaceManager.default` uses this config rather than
        the global ``~/.gnat/config.ini``.
    created_at : str
        ISO-8601 creation timestamp (set automatically on registration).
    """

    tenant_id: str
    display_name: str = ""
    description: str = ""
    config_path: str | None = None
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )

    def __post_init__(self) -> None:
        if not _TENANT_ID_RE.match(self.tenant_id):
            raise ValueError(
                f"Invalid tenant_id {self.tenant_id!r}. "
                "Must be lowercase alphanumeric with optional hyphens/underscores, "
                "1–63 characters, and start with a letter or digit "
                "(e.g., 'acme', 'customer-a', 'tenant_42')."
            )
        if not self.display_name:
            self.display_name = self.tenant_id


# ---------------------------------------------------------------------------
# TenantRegistry
# ---------------------------------------------------------------------------

class TenantRegistry:
    """
    JSON-backed registry of registered tenants.

    Persists to ``~/.gnat/tenants.json`` by default.  The file is created
    automatically on first ``register()`` call.

    Parameters
    ----------
    registry_path : str, optional
        Path to the JSON registry file.  Defaults to ``~/.gnat/tenants.json``.

    Examples
    --------
    ::

        registry = TenantRegistry()
        registry.register("acme", display_name="Acme Corp",
                          config_path="/etc/gnat/acme.ini")
        registry.register("beta", display_name="Beta Ltd")

        for tenant in registry.list():
            print(tenant.tenant_id, tenant.display_name)

        registry.delete("beta")
    """

    DEFAULT_PATH = "~/.gnat/tenants.json"

    def __init__(self, registry_path: str | None = None) -> None:
        self._path = Path(registry_path or self.DEFAULT_PATH).expanduser()
        self._tenants: dict[str, Tenant] = {}
        self._load()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _load(self) -> None:
        """Load tenants from the JSON registry file."""
        if not self._path.exists():
            return
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            for tid, td in raw.items():
                try:
                    self._tenants[tid] = Tenant(**td)
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Skipping malformed tenant entry %r: %s", tid, exc)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to load tenant registry from %s: %s", self._path, exc)

    def _save(self) -> None:
        """Persist tenants to the JSON registry file."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(
            json.dumps(
                {tid: asdict(t) for tid, t in self._tenants.items()},
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def register(
        self,
        tenant_id: str,
        display_name: str = "",
        description: str = "",
        config_path: str | None = None,
    ) -> Tenant:
        """
        Register a new tenant.

        Parameters
        ----------
        tenant_id : str
            Unique identifier.  Must match ``[a-z0-9][a-z0-9_-]{0,62}``.
        display_name : str
            Human-readable name.
        description : str
            Optional longer description.
        config_path : str, optional
            Path to a tenant-specific ``gnat.ini``.

        Returns
        -------
        Tenant

        Raises
        ------
        ValueError
            If *tenant_id* is invalid or already registered.
        """
        if tenant_id in self._tenants:
            raise ValueError(
                f"Tenant {tenant_id!r} is already registered. "
                "Use update() to modify it."
            )
        tenant = Tenant(
            tenant_id=tenant_id,
            display_name=display_name,
            description=description,
            config_path=config_path,
        )
        self._tenants[tenant_id] = tenant
        self._save()
        logger.info("Registered tenant %r", tenant_id)
        return tenant

    def get(self, tenant_id: str) -> Tenant | None:
        """Return the :class:`Tenant` for *tenant_id*, or ``None``."""
        return self._tenants.get(tenant_id)

    def list(self) -> builtins.list[Tenant]:
        """Return all registered tenants sorted by tenant_id."""
        return sorted(self._tenants.values(), key=lambda t: t.tenant_id)

    def update(
        self,
        tenant_id: str,
        display_name: str | None = None,
        description: str | None = None,
        config_path: str | None = None,
    ) -> Tenant:
        """
        Update mutable fields of an existing tenant.

        Raises
        ------
        KeyError
            If *tenant_id* is not registered.
        """
        tenant = self._tenants.get(tenant_id)
        if tenant is None:
            raise KeyError(f"Tenant {tenant_id!r} not found.")
        if display_name is not None:
            tenant.display_name = display_name
        if description is not None:
            tenant.description = description
        if config_path is not None:
            tenant.config_path = config_path
        self._save()
        return tenant

    def delete(self, tenant_id: str) -> bool:
        """
        Delete a tenant from the registry.

        Returns ``True`` if found and deleted, ``False`` otherwise.

        .. warning::
            This only removes the tenant metadata record.  Workspace data
            in the backing store is **not** deleted automatically.  Use
            :meth:`TenantWorkspaceManager.purge` to remove all workspaces
            before deleting the tenant.
        """
        if tenant_id not in self._tenants:
            return False
        del self._tenants[tenant_id]
        self._save()
        logger.info("Deleted tenant %r from registry", tenant_id)
        return True

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def default(cls) -> TenantRegistry:
        """Return a TenantRegistry using the default path ``~/.gnat/tenants.json``."""
        return cls()

    def __len__(self) -> int:
        return len(self._tenants)

    def __repr__(self) -> str:
        return f"TenantRegistry(path={str(self._path)!r}, tenants={len(self._tenants)})"


# ---------------------------------------------------------------------------
# TenantWorkspaceManager
# ---------------------------------------------------------------------------

class TenantWorkspaceManager:
    """
    A :class:`~gnat.context.workspace.WorkspaceManager` scoped to one tenant.

    All workspace names passed to :meth:`create`, :meth:`open`,
    :meth:`get_or_create`, and :meth:`delete` are automatically prefixed
    with ``{tenant_id}::``.  The prefix is stripped from names returned by
    :meth:`list`, so callers see plain workspace names regardless of the
    underlying storage key.

    Parameters
    ----------
    tenant_id : str
        Tenant identifier used as the namespace prefix.
    manager : WorkspaceManager
        Underlying manager to delegate to.

    Examples
    --------
    ::

        manager = WorkspaceManager.default()

        acme = TenantWorkspaceManager("acme", manager)
        ws = acme.create("apt28")
        # Stored as "acme::apt28" in the backing store

        beta = TenantWorkspaceManager("beta", manager)
        ws2 = beta.create("apt28")    # "beta::apt28" — no collision

        print([w["name"] for w in acme.list()])  # ["apt28"]
        print([w["name"] for w in beta.list()])  # ["apt28"]
    """

    SEPARATOR: str = TENANT_SEPARATOR

    def __init__(self, tenant_id: str, manager: WorkspaceManager) -> None:
        # Validate tenant_id
        if not _TENANT_ID_RE.match(tenant_id):
            raise ValueError(
                f"Invalid tenant_id {tenant_id!r}. "
                "Must be lowercase alphanumeric with optional hyphens/underscores, "
                "1–63 characters."
            )
        self.tenant_id: str = tenant_id
        self._manager: WorkspaceManager = manager
        self._prefix: str = f"{tenant_id}{self.SEPARATOR}"

    # ------------------------------------------------------------------
    # Name scoping helpers
    # ------------------------------------------------------------------

    def _scoped(self, name: str) -> str:
        """Return ``{tenant_id}::{name}``."""
        return f"{self._prefix}{name}"

    def _unscoped(self, full_name: str) -> str:
        """Strip the tenant prefix from a stored workspace name."""
        return full_name[len(self._prefix):]

    def _strip_meta(self, ws_meta: dict) -> dict:
        """Return a copy of a workspace metadata dict with name unscoped."""
        m = dict(ws_meta)
        m["name"] = self._unscoped(m["name"])
        m["tenant_id"] = self.tenant_id
        return m

    # ------------------------------------------------------------------
    # WorkspaceManager interface (mirrored API)
    # ------------------------------------------------------------------

    def create(self, name: str, description: str = "") -> Workspace:
        """
        Create a new workspace for this tenant.

        Parameters
        ----------
        name : str
            Workspace name (**without** tenant prefix).
        description : str, optional
            Human-readable description.

        Returns
        -------
        Workspace

        Raises
        ------
        ValueError
            If the workspace already exists for this tenant.
        """
        return self._manager.create(self._scoped(name), description=description)

    def open(self, name: str) -> Workspace:
        """
        Open an existing workspace for this tenant.

        Raises
        ------
        KeyError
            If no workspace with this name exists for this tenant.
        """
        return self._manager.open(self._scoped(name))

    def get_or_create(self, name: str, **kwargs: Any) -> Workspace:
        """Open an existing workspace or create it if it doesn't exist."""
        return self._manager.get_or_create(self._scoped(name), **kwargs)

    def list(self) -> builtins.list[dict]:
        """
        Return metadata dicts for all workspaces belonging to this tenant.

        Names in the returned dicts are unscoped (tenant prefix stripped).
        An extra ``"tenant_id"`` key is added to each dict.
        """
        result: list[dict] = []
        for ws in self._manager.list():
            if ws.get("name", "").startswith(self._prefix):
                result.append(self._strip_meta(ws))
        return result

    def delete(self, name: str) -> bool:
        """
        Permanently delete a workspace for this tenant.

        Returns ``True`` if found and deleted.
        """
        return self._manager.delete(self._scoped(name))

    def purge(self) -> int:
        """
        Delete **all** workspaces for this tenant.

        Returns the number of workspaces deleted.  Use with caution — this
        operation is irreversible.

        Returns
        -------
        int
            Number of workspaces deleted.
        """
        names = [ws["name"] for ws in self.list()]
        for name in names:
            self._manager.delete(self._scoped(name))
        logger.info("Purged %d workspace(s) for tenant %r", len(names), self.tenant_id)
        return len(names)

    def workspace_names(self) -> builtins.list[str]:
        """Return the unscoped names of all workspaces for this tenant."""
        return [ws["name"] for ws in self.list()]

    # ------------------------------------------------------------------
    # Factories
    # ------------------------------------------------------------------

    @classmethod
    def default(
        cls,
        tenant_id: str,
        config_path: str | None = None,
        db_url: str | None = None,
    ) -> TenantWorkspaceManager:
        """
        Create a :class:`TenantWorkspaceManager` using the default store.

        Parameters
        ----------
        tenant_id : str
            Tenant identifier.
        config_path : str, optional
            Path to INI config (used for the underlying ``WorkspaceManager``).
        db_url : str, optional
            SQLAlchemy URL for the workspace DB.

        Returns
        -------
        TenantWorkspaceManager
        """
        from gnat.context.workspace import WorkspaceManager
        manager = WorkspaceManager.default(config_path=config_path, db_url=db_url)
        return cls(tenant_id, manager)

    def __repr__(self) -> str:
        return f"TenantWorkspaceManager(tenant_id={self.tenant_id!r})"
