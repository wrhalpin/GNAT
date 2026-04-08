# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.orca
========================

Public API surface for the ``gnat.connectors.orca`` package.

Exports: ``OrcaClient``.
"""
from .client import OrcaClient

__all__ = ["OrcaClient"]
