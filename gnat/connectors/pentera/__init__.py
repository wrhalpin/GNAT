# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.pentera
===========================

Pentera automated security validation connector. Wraps the v1 API at
``https://<tenant>.pentera.io/api/v1/``.
"""

from .client import PenteraClient

__all__ = ["PenteraClient"]
