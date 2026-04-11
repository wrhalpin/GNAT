# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.huntress
============================

Huntress Managed EDR / ITDR connector. Wraps the v1 public API at
``https://api.huntress.io/v1/``.
"""

from .client import HuntressClient

__all__ = ["HuntressClient"]
