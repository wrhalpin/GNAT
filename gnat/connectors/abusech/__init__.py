# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.abusech
==========================

Unified connector for the abuse.ch free-feed family:

* **URLhaus** — malicious URLs
* **MalwareBazaar** — malware sample metadata and hashes
* **ThreatFox** — actor-attributed IOCs
* **Feodo Tracker** — Emotet / Dridex / TrickBot C2 infrastructure
* **SSL Blacklist (SSLBL)** — malicious TLS certificates and JA3 hashes

A single :class:`AbuseChClient` dispatches to the right sub-feed based on
``filters["feed"]`` in :meth:`~AbuseChClient.list_objects` or via the
``query_*`` domain helpers.  All five feeds accept an optional ``Auth-Key``
header for higher rate limits.
"""

from .client import AbuseChClient

__all__ = ["AbuseChClient"]
