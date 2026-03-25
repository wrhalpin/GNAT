"""
ctm_sak.client
==============

Top-level :class:`SAKClient` facade.  This is the primary entry point for
library users — it resolves configuration, selects the correct connector
client, and exposes a unified interface to the rest of the library.

Usage::

    import ctm_sak

    # Auto-load config from ~/.ctm_sak/config.ini
    cli = ctm_sak.SAKClient()
    cli.connect(target="threatq")

    # Explicit config path
    cli = ctm_sak.SAKClient(config_path="/path/to/my.ini")
    cli.connect(target="crowdstrike")

    # Pass config dict directly (no INI file needed)
    cli = ctm_sak.SAKClient()
    cli.connect(
        target="netskope",
        host="https://tenant.goskope.com",
        api_token="...",
        auth_type="token",
    )
"""

from typing import Any, Optional

from ctm_sak.config import SAKConfig
from ctm_sak.clients.base import BaseClient, SAKClientError


class SAKClient:
    """
    Universal security platform client.

    :class:`SAKClient` is the primary object users interact with.  Call
    :meth:`connect` to establish a connection to a named target system;
    after that, :attr:`client` exposes the raw connector client and ORM
    objects can be instantiated with ``client=`` this instance.

    Parameters
    ----------
    config_path : str, optional
        Path to an INI configuration file.  If omitted the library searches
        the default locations (see :class:`~ctm_sak.config.SAKConfig`).

    Attributes
    ----------
    client : BaseClient or None
        The active connector client after :meth:`connect` succeeds.
    target : str or None
        Name of the currently connected target (e.g. ``"threatq"``).
    """

    def __init__(self, config_path: Optional[str] = None):
        self._config_path = config_path
        self._config: Optional[SAKConfig] = None
        self.client: Optional[BaseClient] = None
        self.target: Optional[str] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def connect(self, target: str, **override_kwargs: Any) -> "SAKClient":
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
        SAKClient
            Returns ``self`` for optional method chaining.

        Raises
        ------
        KeyError
            If *target* is not a recognised connector name.
        SAKClientError
            If the connector cannot be instantiated.

        Examples
        --------
        >>> cli = SAKClient().connect("threatq")
        >>> cli = SAKClient().connect("netskope", api_token="tok123")
        """
        # Import here to avoid circular imports at module load time
        from ctm_sak.clients import CLIENT_REGISTRY

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
                self._config = SAKConfig(self._config_path)
            except FileNotFoundError:
                pass

        if self._config is not None:
            try:
                cfg.update(self._config.get(target))
            except KeyError:
                pass  # Caller must supply all params via overrides

        cfg.update({k: v for k, v in overrides.items() if v is not None})

        if not cfg.get("host"):
            raise SAKClientError(
                f"No 'host' found for target {target!r}. "
                "Set it in config.ini or pass host= to connect()."
            )
        return cfg

    def __repr__(self) -> str:  # pragma: no cover
        return f"SAKClient(target={self.target!r}, connected={self.client is not None})"
