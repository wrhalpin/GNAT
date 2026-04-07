# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.google_chronicle
================================

Google Security Operations (formerly Chronicle) connector for SIEM search, detections, and investigation.
"""

from .client import GoogleChronicleClient

__all__ = ["GoogleChronicleClient"]
