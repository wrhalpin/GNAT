# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.ironscales
==============================

IRONSCALES AI-driven email security connector. Wraps the v1 REST API
at ``https://appapi.ironscales.com/appapi/``.
"""

from .client import IRONSCALESClient

__all__ = ["IRONSCALESClient"]
