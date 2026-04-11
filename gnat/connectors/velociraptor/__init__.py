# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.velociraptor
================================

Velociraptor — open-source endpoint visibility and digital-forensics
collection. Wraps the gRPC-Web bridge / REST API exposed by a
Velociraptor server.
"""

from .client import VelociraptorClient

__all__ = ["VelociraptorClient"]
