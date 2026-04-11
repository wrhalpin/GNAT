# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.cofense_intel
=================================

Cofense Intelligence connector — human-verified phishing intel from
Cofense's Triage + PhishMe reporting network. Wraps
``https://www.threathq.com/apiv1/``.
"""

from .client import CofenseIntelClient

__all__ = ["CofenseIntelClient"]
