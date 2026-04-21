# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.armis
=========================

Public API surface for the ``gnat.connectors.armis`` package.

Exports: ``ArmisClient``.
"""

from .client import ArmisClient

__all__ = ["ArmisClient"]
