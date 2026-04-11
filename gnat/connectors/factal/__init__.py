# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.factal
==========================

Factal verified breaking-news / risk intelligence connector. Wraps the
v2 REST API at ``https://api.factal.com/``.
"""

from .client import FactalClient

__all__ = ["FactalClient"]
