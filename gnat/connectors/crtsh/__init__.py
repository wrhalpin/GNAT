# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.crtsh
=========================

crt.sh — free public Certificate Transparency log search.
Wraps the JSON endpoints at ``https://crt.sh/``.
"""

from .client import CrtShClient

__all__ = ["CrtShClient"]
