# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.dataminr
============================

Dataminr Pulse real-time event / threat / risk intelligence connector.
Wraps the Pulse API at ``https://gateway.dataminr.com/``.
"""

from .client import DataminrClient

__all__ = ["DataminrClient"]
