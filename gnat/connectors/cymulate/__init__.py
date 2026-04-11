# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.cymulate
============================

Cymulate Breach-and-Attack-Simulation platform connector.  Wraps the v1
API at ``https://api.app.cymulate.com/v1/``.
"""

from .client import CymulateClient

__all__ = ["CymulateClient"]
