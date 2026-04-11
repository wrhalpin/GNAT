# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.project_honey_pot
=====================================

Project Honey Pot — community spam-trap and harvester intelligence.
Wraps the http:BL DNS-based query API at ``dnsbl.httpbl.org``.
"""

from .client import ProjectHoneyPotClient

__all__ = ["ProjectHoneyPotClient"]
