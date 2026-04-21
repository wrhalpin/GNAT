# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.defectdojo
==============================

Public API surface for the ``gnat.connectors.defectdojo`` package.

Exports: ``DefectDojoClient``.
"""

from .client import DefectDojoClient

__all__ = ["DefectDojoClient"]
