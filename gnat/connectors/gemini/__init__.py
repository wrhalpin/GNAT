# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.gemini
==========================

Public API surface for the ``gnat.connectors.gemini`` package.

Exports: ``GeminiClient``.
"""
from .client import GeminiClient

__all__ = ["GeminiClient"]
