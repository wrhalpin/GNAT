# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.cisco_umbrella
================================

Cisco Umbrella connector for DNS-layer threat intelligence, enforcement,
and allow-list management.

Classes
-------
CiscoUmbrellaClient
    Combines the Investigate (threat intel), Enforcement (block-list), and
    Management (allow-list) APIs.
"""

from gnat.connectors.cisco_umbrella.client import CiscoUmbrellaClient

__all__ = ["CiscoUmbrellaClient"]
