# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.exabeam
===========================

Exabeam UEBA / Security Operations Platform connector. Wraps
``https://api.exabeam.com/``.
"""

from .client import ExabeamClient

__all__ = ["ExabeamClient"]
