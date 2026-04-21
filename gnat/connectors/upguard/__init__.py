# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.upguard
===========================

Public API surface for the ``gnat.connectors.upguard`` package.

Exports: ``UpGuardClient``.
"""

from .client import UpGuardClient

__all__ = ["UpGuardClient"]
