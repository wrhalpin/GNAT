# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.greenbone
=============================

Public API surface for the ``gnat.connectors.greenbone`` package.

Exports: ``GreenboneClient``.
"""

from .client import GreenboneClient

__all__ = ["GreenboneClient"]
