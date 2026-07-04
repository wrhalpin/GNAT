# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.sandgnat
===========================

SandGNAT connector — the GNAT-o-sphere malware detonation sandbox.
Submits samples for detonation in isolated Windows VMs, pulls completed
STIX 2.1 bundles, static-analysis findings, and LSH similarity
neighbours over SandGNAT's read-only export API.
"""

from .client import SandGNATClient

__all__ = ["SandGNATClient"]
