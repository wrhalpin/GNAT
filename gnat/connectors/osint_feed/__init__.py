# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.osint_feed
===========================

Generic OSINT feed connector for TAXII 2.x servers and direct STIX-JSON endpoints.

Classes
-------
OsintFeedConnector
    Configurable read-only connector; no custom Python needed for new feeds.

FeedConnectorFactory
    Creates and optionally registers named connector classes from INI config.

Functions
---------
register_feeds_from_config
    Convenience wrapper for :meth:`FeedConnectorFactory.from_config`.
"""

from gnat.connectors.osint_feed.connector import OsintFeedConnector
from gnat.connectors.osint_feed.feed_factory import (
    FeedConnectorFactory,
    register_feeds_from_config,
)

__all__ = [
    "OsintFeedConnector",
    "FeedConnectorFactory",
    "register_feeds_from_config",
]
