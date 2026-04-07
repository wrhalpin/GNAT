# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.fortiedr
========================

FortiEDR (Fortinet Endpoint Detection and Response) connector.
"""

from .client import FortiEDRClient

__all__ = ["FortiEDRClient"]
