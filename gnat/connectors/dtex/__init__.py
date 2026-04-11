# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.dtex
========================

DTEX InTERCEPT behavioral insider-threat connector. Wraps
``https://api.dtexsystems.com/v1/``.
"""

from .client import DTEXClient

__all__ = ["DTEXClient"]
