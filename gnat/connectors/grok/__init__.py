# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.grok
====================

Grok (xAI) connector for the GNAT threat intelligence toolkit.
"""

from .client import GrokClient

__all__ = ["GrokClient"]
