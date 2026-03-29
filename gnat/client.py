"""
gnat.client
==============

Top-level :class:`GNATClient` facade.  This is the primary entry point for
library users — it resolves configuration, selects the correct connector
client, and exposes a unified interface to the rest of the library.

Usage::

    import gnat

    # Auto-load config from ~/.gnat/config.ini
    cli = gnat.GNATClient()
    cli.connect(target="threatq")

    # Explicit config path
    cli = gnat.GNATClient(config_path="/path/to/my.ini")
    cli.connect(target="crowdstrike")

    # Pass config dict directly (no INI file needed)
    cli = gnat.GNATClient()
    cli.connect(
        target="netskope",
        host="https://tenant.goskope.com",
        api_token="...",
        auth_type="token",
    )
"""

from typing import Any, Dict, List, Optional

from gnat.config import GNATConfig
from gnat.clients.base import BaseClient, GNATClientError


class GNATClient:
    """
    Universal security platform client.

    :class:`GNATClient` is the primary object users interact with.  Call
    :meth:`connect` to establish a connection to a named target system;
    after that, :attr:`client` exposes the raw connector client and ORM
    objects can be instantiated with ``client=`` this instance.

    Parameters
    ----------
    config_path : str, optional
        Path to an INI configuration file.  If omitted the library searches
        the default locations (see :class:`~gnat.config.GNATConfig`).

    Attributes
    ----------
    client : BaseClient or None
        The active connector client after :meth:`connect` succeeds.
    target : str or None
        Name of the currently connected target (e.g. ``"threatq"``).
    """

    def __init__(self, config_path: Optional[str] = None):
        self._config_path = config_path
        self._config: Optional[GNATConfig] = None
        self.client: Optional[BaseClient] = None
        self.target: Optional[str] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def connect(self, target: str, **override_kwargs: Any) -> "GNATClient":
        """
        Connect to a security platform by name.

        Configuration is loaded from the INI file (or ``override_kwargs``
        if provided).  The connector's ``authenticate()`` method is called
        automatically on the first subsequent HTTP request.

        Parameters
        ----------
        target : str
            Target system identifier.  Must match a section in the config
            file or a key in ``CLIENT_REGISTRY``.  Case-insensitive.
        **override_kwargs
            Any key/value pairs that should override the INI config values
            (e.g. ``host=``, ``api_token=``, ``auth_type=``).

        Returns
        -------
        GNATClient
            Returns ``self`` for optional method chaining.

        Raises
        ------
        KeyError
            If *target* is not a recognised connector name.
        GNATClientError
            If the connector cannot be instantiated.

        Examples
        --------
        >>> cli = GNATClient().connect("threatq")
        >>> cli = GNATClient().connect("netskope", api_token="tok123")
        """
        # Import here to avoid circular imports at module load time
        from gnat.clients import CLIENT_REGISTRY

        target = target.lower()
        if target not in CLIENT_REGISTRY:
            raise KeyError(
                f"Unknown target {target!r}. "
                f"Available: {sorted(CLIENT_REGISTRY.keys())}"
            )

        cfg = self._load_config(target, override_kwargs)
        connector_cls = CLIENT_REGISTRY[target]
        self.client = connector_cls(**cfg)
        self.target = target
        return self

    def disconnect(self) -> None:
        """
        Release resources associated with the active connection.

        After calling this method :attr:`client` is set to ``None``.
        """
        self.client = None
        self.target = None

    def ping(self) -> bool:
        """
        Return ``True`` if the current connection is reachable.

        Each connector implements ``health_check()``; this method wraps it
        with a boolean return so callers don't need to handle exceptions.
        """
        if self.client is None:
            return False
        try:
            self.client.health_check()
            return True
        except Exception:  # noqa: BLE001
            return False

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_config(self, target: str, overrides: dict) -> dict:
        """
        Merge INI-file config with caller-supplied keyword overrides.

        *overrides* always win over INI values.
        """
        cfg: dict = {}

        # Try to load from INI — not required if all params are in overrides
        if self._config is None:
            try:
                self._config = GNATConfig(self._config_path)
            except FileNotFoundError:
                pass

        if self._config is not None:
            try:
                cfg.update(self._config.get(target))
            except KeyError:
                pass  # Caller must supply all params via overrides

        cfg.update({k: v for k, v in overrides.items() if v is not None})

        if not cfg.get("host"):
            raise GNATClientError(
                f"No 'host' found for target {target!r}. "
                "Set it in config.ini or pass host= to connect()."
            )
        return cfg

    def natural_language_query(
        self,
        query: str,
        extra_connectors: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Translate a free-text query into STIX results using the NLP engine.

        Reads the ``[nlp]`` section from the loaded config to choose the
        backend (``builtin`` or ``claude``).  When a connector is already
        connected via :meth:`connect`, it is automatically included in the
        dispatch set.

        Parameters
        ----------
        query : str
            Free-text analyst query, e.g.
            ``"Get all IPs for APT28 from the last 30 days"``.
        extra_connectors : dict, optional
            Additional ``{name: connector_instance}`` pairs to query beyond
            the currently-connected client.

        Returns
        -------
        list of dict
            Aggregated raw objects from all queried connectors, each tagged
            with a ``"_source"`` key.  If no live connectors are provided
            the parsed :class:`~gnat.nlp.QuerySpec` is returned serialised
            as a single-element list.

        Examples
        --------
        >>> cli = GNATClient().connect("threatq")
        >>> results = cli.natural_language_query(
        ...     "Show me all domains for Lazarus Group since January"
        ... )
        """
        from gnat.nlp.parser import NLPQueryEngine

        if self._config is None:
            try:
                self._config = GNATConfig(self._config_path)
            except FileNotFoundError:
                pass

        if self._config is not None:
            engine = NLPQueryEngine.from_config(self._config)
        else:
            engine = NLPQueryEngine()

        connectors: Dict[str, Any] = {}
        if self.client is not None and self.target is not None:
            connectors[self.target] = self.client
        if extra_connectors:
            connectors.update(extra_connectors)

        return engine.query(query, connectors=connectors if connectors else None)

    def __repr__(self) -> str:  # pragma: no cover
        return f"GNATClient(target={self.target!r}, connected={self.client is not None})"
