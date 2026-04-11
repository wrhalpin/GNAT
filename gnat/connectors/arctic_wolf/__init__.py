# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.arctic_wolf
===============================

Arctic Wolf Managed Detection and Response (MDR) connector. Wraps the
v1 API at ``https://api.arcticwolf.com/``.
"""

from .client import ArcticWolfClient

__all__ = ["ArcticWolfClient"]
