# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.flashpoint
==============================

Public API surface for the ``gnat.connectors.flashpoint`` package.

Exports: ``FlashpointClient``.
"""
from .client import FlashpointClient

__all__ = ["FlashpointClient"]
