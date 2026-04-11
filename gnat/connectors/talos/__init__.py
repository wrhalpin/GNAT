# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.talos
=========================

Cisco Talos Intelligence connector.  Wraps the public
reputation / lookup endpoints at ``https://talosintelligence.com/``.
"""

from .client import TalosClient

__all__ = ["TalosClient"]
