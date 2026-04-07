# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.claroty
=======================

Claroty (xDome / CTD) connector for OT/ICS asset inventory, alerts, and vulnerability management.
"""

from .client import ClarotyClient

__all__ = ["ClarotyClient"]
