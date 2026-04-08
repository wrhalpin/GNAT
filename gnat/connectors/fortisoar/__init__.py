# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.fortisoar
=========================

FortiSOAR (Fortinet Security Orchestration, Automation and Response) connector.
"""

from .client import FortiSOARClient

__all__ = ["FortiSOARClient"]
