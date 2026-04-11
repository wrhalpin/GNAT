# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.mitre_attack
================================

MITRE ATT&CK connector.

Wraps the public MITRE ATT&CK TAXII 2.1 server
(``https://attack-taxii.mitre.org/api/v21/``) so that ATT&CK data
(attack-patterns, intrusion-sets, malware, tools, tactics, matrices) is
available via the standard GNAT connector interface.

The heavy lifting — TAXII polling and rate limiting — lives in
:class:`~gnat.ingest.sources.mitre_taxii_reader.MitreAttackTAXIIReader`;
this connector is a thin facade so ATT&CK appears in
:data:`gnat.clients.CLIENT_REGISTRY`, ``gnat ping``, and
``client.capabilities()``.
"""

from .client import MitreAttackClient

__all__ = ["MitreAttackClient"]
