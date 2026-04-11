# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.vulncheck
=============================

Connector for the VulnCheck vulnerability and exploit intelligence API.

VulnCheck maintains a broader KEV catalog than CISA, plus dedicated indices
for initial-access exploits, publicly-known exploits, and exploitation
telemetry from their global canary network.
"""

from .client import VulnCheckClient

__all__ = ["VulnCheckClient"]
