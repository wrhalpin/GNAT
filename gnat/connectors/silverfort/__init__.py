# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.silverfort
==============================

Silverfort ITDR connector — runtime identity telemetry (auth events,
risk scores, MFA decisions) from the customer's Silverfort deployment.
"""

from .client import SilverfortClient

__all__ = ["SilverfortClient"]
