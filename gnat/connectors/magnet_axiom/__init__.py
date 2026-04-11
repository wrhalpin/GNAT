# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.magnet_axiom
================================

Magnet AXIOM Cyber — remote forensic acquisition and DFIR.
Wraps the AXIOM Cyber REST API at ``/api/v1/``.
"""

from .client import MagnetAxiomClient

__all__ = ["MagnetAxiomClient"]
