# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.samdesk
===========================

Samdesk global crisis-detection connector. Wraps the v1 REST API at
``https://api.samdesk.io/``.
"""

from .client import SamdeskClient

__all__ = ["SamdeskClient"]
