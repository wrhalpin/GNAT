# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.qualys
==========================

Public API surface for the ``gnat.gnat.connectors.qualys`` package.

Exports: ``QualysVMDRClient``.
"""
from .client import QualysVMDRClient

__all__ = ["QualysVMDRClient"]
