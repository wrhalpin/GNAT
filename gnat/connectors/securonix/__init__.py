# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.securonix
=============================

Securonix cloud-native SIEM / UEBA connector. Wraps the SCC
resource API at ``https://<tenant>.securonix.com/Snypr/ws/sccresource/``.
"""

from .client import SecuronixClient

__all__ = ["SecuronixClient"]
