# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.code42
==========================

Code42 Incydr insider-risk connector. Wraps the v1/v2 REST API at
``https://api.us.code42.com/``.
"""

from .client import Code42Client

__all__ = ["Code42Client"]
