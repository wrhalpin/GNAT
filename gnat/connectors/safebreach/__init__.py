# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.safebreach
==============================

SafeBreach Breach-and-Attack-Simulation connector. Wraps the v1 API at
``https://api.safebreach.com/api/``.
"""

from .client import SafeBreachClient

__all__ = ["SafeBreachClient"]
