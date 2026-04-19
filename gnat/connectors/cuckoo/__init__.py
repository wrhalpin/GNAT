# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.cuckoo
=========================

Cuckoo Sandbox / CAPEv2 connector — automated malware analysis with
behavioral reports, IOC extraction, and STIX indicator generation.
Supports both Cuckoo 2.x and CAPEv2/3.x APIs with auto-detection.
"""

from .client import CuckooClient

__all__ = ["CuckooClient"]
