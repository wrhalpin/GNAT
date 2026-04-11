# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.red_canary
==============================

Red Canary MDR connector. Wraps the public API at
``https://my.redcanary.co/openapi/v3/``.
"""

from .client import RedCanaryClient

__all__ = ["RedCanaryClient"]
