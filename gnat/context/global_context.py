"""
gnat.context.global_context
================================

:class:`GlobalContext` represents a persistent connection to a security
platform that acts as an authoritative data source — the system of record
that analyst workspaces load from and commit back to.

Multiple global contexts can be registered simultaneously (e.g. ThreatQ as
primary, XSOAR as secondary, Recorded Future as read-only enrichment source).
One is designated the default write target.

The :class:`GlobalContextRegistry` manages the collection and is configured
from the ``[global]`` and ``[global.<name>]`` INI sections::

    [global]
    default = threatq_prod

    [global.threatq_prod]
    target   = threatq
    host     = https://threatq.example.com
    client_id     = ...
    client_secret = ...

    [global.crowdstrike_falcon]
    target   = crowdstrike
    host     = https://api.crowdstrike.com
    client_id     = ...
    client_secret = ...
    read_only = true

    [global.recorded_future]
    target    = recordedfuture
    host      = https://api.recordedfuture.com
    api_token = ...
    read_only = true
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Iterator, List, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from gnat.client import SAKClient
    from gnat.orm.base import STIXBase

logger = logging.getLogger(__name__)


class GlobalContext:
    """
    A named, connected security platform context.

    A global context wraps a :class:`~gnat.client.SAKClient` and adds
    metadata (name, read-only flag, priority) used by workspaces to decide
    which platform to load from and write to.

    Parameters
    ----------
    name : str
        Unique human-readable identifier (e.g. ``"threatq_prod"``).
    client : SAKClient
        A connected platform client.
    read_only : bool
        If ``True``, this context is never used as a write target.
        Default ``False``.
    priority : int
        Load priority when multiple globals are queried.  Lower = higher
        priority.  Default ``10``.
    description : str, optional
        Free-text description shown in listings.

    Examples
    --------
    >>> from gnat import SAKClient
    >>> cli = SAKClient().connect("threatq")
    >>> gc = GlobalContext("threatq_prod", cli, priority=1)
    """

    def __init__(
        self,
        name: str,
        client: "SAKClient",
        read_only: bool = False,
        priority: int = 10,
        description: str = "",
    ):
        self.name        = name
        self.client      = client
        self.read_only   = read_only
        self.priority    = priority
        self.description = description

    @property
    def target(self) -> Optional[str]:
        """Platform target name (e.g. ``"threatq"``)."""
        return self.client.target

    def ping(self) -> bool:
        """Return ``True`` if the underlying platform is reachable."""
        return self.client.ping()

    # ── Read operations (delegated to connector) ───────────────────────────

    def get_object(self, stix_type: str, object_id: str) -> dict:
        """Fetch a single STIX object dict from this platform."""
        raw = self.client.client.get_object(stix_type, object_id)
        return self.client.client.to_stix(raw)

    def list_objects(
        self,
        stix_type: str,
        filters: Optional[Dict[str, Any]] = None,
        page: int = 1,
        page_size: int = 100,
    ) -> List[dict]:
        """List STIX object dicts from this platform."""
        raw_list = self.client.client.list_objects(
            stix_type, filters=filters, page=page, page_size=page_size
        )
        return [self.client.client.to_stix(r) for r in raw_list]

    # ── Write operations ────────────────────────────────────────────────────

    def write_object(self, stix_dict: dict) -> dict:
        """
        Write a STIX object to this platform.

        Raises
        ------
        PermissionError
            If this global context is marked ``read_only``.
        """
        if self.read_only:
            raise PermissionError(
                f"GlobalContext {self.name!r} is read-only — write rejected."
            )
        payload = self.client.client.from_stix(stix_dict)
        result  = self.client.client.upsert_object(stix_dict["type"], payload)
        return self.client.client.to_stix(result)

    def delete_object(self, stix_type: str, stix_id: str) -> None:
        """Delete a STIX object from this platform."""
        if self.read_only:
            raise PermissionError(
                f"GlobalContext {self.name!r} is read-only — delete rejected."
            )
        self.client.client.delete_object(stix_type, stix_id)

    def __repr__(self) -> str:  # pragma: no cover
        rw = "read-only" if self.read_only else "read-write"
        return (
            f"GlobalContext(name={self.name!r}, target={self.target!r}, "
            f"{rw}, priority={self.priority})"
        )


# ---------------------------------------------------------------------------
# GlobalContextRegistry
# ---------------------------------------------------------------------------

class GlobalContextRegistry:
    """
    Registry of all configured global contexts.

    Acts as the single point of truth for which platforms are available,
    which is the default write target, and how they are prioritised.

    Typically constructed once via :meth:`from_config` and stored on the
    :class:`~gnat.context.workspace.WorkspaceManager`.

    Parameters
    ----------
    default_name : str, optional
        Name of the default write context.  Can be set later via
        :meth:`set_default`.

    Examples
    --------
    >>> registry = GlobalContextRegistry.from_config()
    >>> registry.default.name
    'threatq_prod'
    >>> registry.get("crowdstrike_falcon").list_objects("indicator", page_size=5)
    """

    def __init__(self, default_name: Optional[str] = None):
        self._contexts: Dict[str, GlobalContext] = {}
        self._default_name: Optional[str] = default_name

    # ── Factory ────────────────────────────────────────────────────────────

    @classmethod
    def from_config(
        cls,
        config_path: Optional[str] = None,
    ) -> "GlobalContextRegistry":
        """
        Build a registry from INI configuration.

        Reads ``[global]`` for the default name, then finds all
        ``[global.<name>]`` sections and connects each one.

        Parameters
        ----------
        config_path : str, optional
            Explicit path to config.ini.  If omitted the default search
            order is used (see :class:`~gnat.config.SAKConfig`).

        Returns
        -------
        GlobalContextRegistry
            Populated registry, with all clients connected.
        """
        from gnat.config import SAKConfig
        from gnat.client import SAKClient

        cfg = SAKConfig(config_path)
        registry = cls()

        # Read [global] section for defaults
        global_meta: dict = {}
        try:
            global_meta = cfg.get("global")
        except KeyError:
            pass

        default_name = global_meta.get("default", "")

        # Find all [global.<name>] sections
        for section in cfg.sections:
            if not section.startswith("global."):
                continue
            name = section[len("global."):]
            section_cfg = cfg.get(section)
            target = section_cfg.pop("target", "")
            read_only = section_cfg.pop("read_only", "false").lower() == "true"
            priority  = int(section_cfg.pop("priority", "10"))
            description = section_cfg.pop("description", "")

            if not target:
                logger.warning("GlobalContextRegistry: [%s] has no 'target' — skipped", section)
                continue

            try:
                cli = SAKClient(config_path=config_path)
                cli.connect(target=target, **section_cfg)
                gc = GlobalContext(
                    name=name, client=cli,
                    read_only=read_only, priority=priority,
                    description=description,
                )
                registry.register(gc)
                logger.info("GlobalContextRegistry: registered %r → %s", name, target)
            except Exception as exc:  # noqa: BLE001
                logger.error("GlobalContextRegistry: failed to connect %r — %s", name, exc)

        if default_name:
            registry.set_default(default_name)
        elif registry._contexts:
            # Auto-select the highest-priority (lowest number) read-write context
            candidates = [g for g in registry.all() if not g.read_only]
            if candidates:
                registry.set_default(candidates[0].name)

        return registry

    @classmethod
    def from_clients(
        cls,
        clients: Dict[str, "SAKClient"],
        default: Optional[str] = None,
        read_only: Optional[List[str]] = None,
    ) -> "GlobalContextRegistry":
        """
        Build a registry directly from a dict of connected SAKClients.

        Convenient for programmatic setup without an INI file.

        Parameters
        ----------
        clients : dict
            ``{name: SAKClient}`` mapping.
        default : str, optional
            Name of the default write context.
        read_only : list of str, optional
            Names that should be marked read-only.

        Examples
        --------
        >>> registry = GlobalContextRegistry.from_clients(
        ...     {"tq": tq_cli, "rf": rf_cli, "cs": cs_cli},
        ...     default="tq",
        ...     read_only=["rf"],
        ... )
        """
        registry = cls()
        ro_set = set(read_only or [])
        for i, (name, client) in enumerate(clients.items()):
            gc = GlobalContext(
                name=name, client=client,
                read_only=name in ro_set,
                priority=i,
            )
            registry.register(gc)
        if default:
            registry.set_default(default)
        return registry

    # ── Registry management ────────────────────────────────────────────────

    def register(self, context: GlobalContext) -> None:
        """Add a global context to the registry."""
        self._contexts[context.name] = context

    def unregister(self, name: str) -> bool:
        """Remove a global context. Returns ``True`` if it existed."""
        if name in self._contexts:
            del self._contexts[name]
            if self._default_name == name:
                self._default_name = None
            return True
        return False

    def set_default(self, name: str) -> None:
        """Set the default write target by name."""
        if name not in self._contexts:
            raise KeyError(
                f"No registered global context named {name!r}. "
                f"Available: {sorted(self._contexts.keys())}"
            )
        self._default_name = name

    # ── Access ─────────────────────────────────────────────────────────────

    def get(self, name: str) -> GlobalContext:
        """Return a global context by name."""
        if name not in self._contexts:
            raise KeyError(
                f"No global context named {name!r}. "
                f"Available: {sorted(self._contexts.keys())}"
            )
        return self._contexts[name]

    @property
    def default(self) -> GlobalContext:
        """
        Return the default write context.

        Raises
        ------
        RuntimeError
            If no default has been set and the registry is empty.
        """
        if self._default_name and self._default_name in self._contexts:
            return self._contexts[self._default_name]
        # Fall back to highest-priority read-write context
        candidates = sorted(
            [g for g in self._contexts.values() if not g.read_only],
            key=lambda g: g.priority,
        )
        if not candidates:
            raise RuntimeError(
                "No writable global context registered. "
                "Add at least one non-read-only GlobalContext."
            )
        return candidates[0]

    def all(self) -> List[GlobalContext]:
        """All registered contexts sorted by priority."""
        return sorted(self._contexts.values(), key=lambda g: g.priority)

    def writable(self) -> List[GlobalContext]:
        """All read-write contexts sorted by priority."""
        return [g for g in self.all() if not g.read_only]

    def read_only_contexts(self) -> List[GlobalContext]:
        """All read-only contexts (enrichment sources)."""
        return [g for g in self.all() if g.read_only]

    def __iter__(self) -> Iterator[GlobalContext]:
        return iter(self.all())

    def __len__(self) -> int:
        return len(self._contexts)

    def __contains__(self, name: str) -> bool:
        return name in self._contexts

    def __repr__(self) -> str:  # pragma: no cover
        default = self._default_name or "(none)"
        return (
            f"GlobalContextRegistry("
            f"contexts={sorted(self._contexts.keys())}, "
            f"default={default!r})"
        )
