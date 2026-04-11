# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.bitdefender_iz
==================================

Bitdefender IntelliZone connector. Wraps the REST API at
``https://intellizone.bitdefender.com/api/v1/``.
"""

from .client import BitdefenderIntelliZoneClient

__all__ = ["BitdefenderIntelliZoneClient"]
