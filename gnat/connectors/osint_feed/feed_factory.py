"""
gnat.connectors.osint_feed.feed_factory
=========================================

Utility for creating and registering :class:`~gnat.connectors.osint_feed.connector.OsintFeedConnector`
instances from INI-file configuration sections — no custom Python code required.

How it works
------------
Call :func:`register_feeds_from_config` (or :meth:`FeedConnectorFactory.from_config`) to
scan a :class:`~gnat.config.GNATConfig` for **any section that contains a
``feed_type`` key**.  For each such section a new subclass of
:class:`~gnat.connectors.osint_feed.connector.OsintFeedConnector` is created
with the section name as the class name, and that class is registered in the
supplied *registry* dict (which is typically
:data:`~gnat.clients.CLIENT_REGISTRY`).

After registration users can connect to the feed just like any built-in connector::

    cli = GNATClient().connect("osint_feed_limo")

Configuration
-------------
Minimal example::

    [osint_feed_limo]
    host            = https://limo.anomali.com
    feed_type       = taxii
    taxii_path      = /api/v1/taxii2/
    auth_type       = basic
    username        = guest
    password        = guest
    collection_title = Phish Tank
    stix_types      = indicator

    [osint_feed_circl]
    host       = https://www.circl.lu
    feed_type  = stix_json
    feed_path  = /doc/misp/feed-osint/manifest.json
    auth_type  = none

Any ``feed_type``-bearing section is auto-detected; the section name becomes
the registry key (lowercased).

Advanced: dynamic class names
------------------------------
Each registered entry is a *named subclass* of ``OsintFeedConnector`` so that
``type(client).__name__`` returns a meaningful label (e.g. ``"OsintFeedLimo"``).
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from gnat.connectors.osint_feed.connector import OsintFeedConnector

if TYPE_CHECKING:
    from gnat.config import GNATConfig

logger = logging.getLogger(__name__)

# Keys consumed by OsintFeedConnector.__init__ (passed as-is from config section)
_FEED_INIT_KEYS = frozenset(
    {
        "host",
        "feed_type",
        "taxii_path",
        "collection_id",
        "collection_title",
        "feed_path",
        "auth_type",
        "username",
        "password",
        "api_key",
        "api_key_header",
        "bearer_token",
        "client_id",
        "client_secret",
        "token_url",
        "stix_types",
        "added_after",
        "feed_name",
        "timeout",
        "verify_ssl",
        "max_retries",
    }
)


class FeedConnectorFactory:
    """
    Factory that creates :class:`~gnat.connectors.osint_feed.connector.OsintFeedConnector`
    subclasses from :class:`~gnat.config.GNATConfig` sections.

    Examples
    --------
    >>> from gnat.config import GNATConfig
    >>> from gnat.clients import CLIENT_REGISTRY
    >>> config = GNATConfig("my-feeds.ini")
    >>> FeedConnectorFactory.from_config(config, registry=CLIENT_REGISTRY)
    >>> # Now connect as usual:
    >>> cli = GNATClient().connect("osint_feed_limo")
    """

    @staticmethod
    def from_config(
        config: GNATConfig,
        registry: dict[str, Any] | None = None,
    ) -> dict[str, type[OsintFeedConnector]]:
        """
        Scan *config* for feed sections and return a mapping of
        ``{section_name: connector_class}``.

        A section is treated as a feed definition when it contains a
        ``feed_type`` key.

        Parameters
        ----------
        config : GNATConfig
            Loaded configuration object.
        registry : dict, optional
            If provided the newly created classes are added to this dict
            (typically :data:`~gnat.clients.CLIENT_REGISTRY`).

        Returns
        -------
        dict
            ``{section_name: OsintFeedConnector subclass}`` for every
            detected feed section.
        """
        feeds: dict[str, type[OsintFeedConnector]] = {}

        for section in config.sections:
            try:
                section_cfg = config.get(section)
            except KeyError:
                continue

            if "feed_type" not in section_cfg:
                continue

            cls = FeedConnectorFactory._make_class(section, section_cfg)
            feeds[section] = cls
            if registry is not None:
                registry[section] = cls
            logger.debug("Registered OSINT feed connector: %r", section)

        return feeds

    @staticmethod
    def _make_class(
        section_name: str,
        section_cfg: dict[str, Any],
    ) -> type[OsintFeedConnector]:
        """
        Create a named :class:`OsintFeedConnector` subclass whose
        ``__init__`` hard-wires the configuration values as defaults.

        The generated class name is derived from the section name in
        CamelCase (e.g. ``"osint_feed_limo"`` → ``"OsintFeedLimo"``).
        """
        class_name = "".join(part.capitalize() for part in section_name.split("_"))

        # Extract only the keys that OsintFeedConnector understands
        feed_defaults = {k: v for k, v in section_cfg.items() if k in _FEED_INIT_KEYS}
        feed_defaults.setdefault("feed_name", section_name)

        # Build a subclass that pre-fills config defaults
        def __init__(self: OsintFeedConnector, **kwargs: Any) -> None:  # type: ignore[misc]
            merged = {**feed_defaults, **kwargs}
            # host is required by BaseClient; pull from merged
            host = merged.pop("host", "")
            OsintFeedConnector.__init__(self, host=host, **merged)

        cls = type(class_name, (OsintFeedConnector,), {"__init__": __init__})
        return cls  # type: ignore[return-value]


def register_feeds_from_config(
    config: GNATConfig,
    registry: dict[str, Any] | None = None,
) -> dict[str, type[OsintFeedConnector]]:
    """
    Module-level shortcut for :meth:`FeedConnectorFactory.from_config`.

    Parameters
    ----------
    config : GNATConfig
        Loaded configuration object.
    registry : dict, optional
        Destination registry; if ``None`` the result is returned but not
        stored anywhere.

    Returns
    -------
    dict
        ``{section_name: connector_class}`` for every detected feed section.

    Examples
    --------
    >>> from gnat.config import GNATConfig
    >>> from gnat.clients import CLIENT_REGISTRY
    >>> from gnat.connectors.osint_feed import register_feeds_from_config
    >>> register_feeds_from_config(GNATConfig(), registry=CLIENT_REGISTRY)
    """
    return FeedConnectorFactory.from_config(config, registry=registry)
