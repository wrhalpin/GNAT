# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.kaspersky_opentip
=====================================

Kaspersky OpenTIP connector.  Wraps ``https://opentip.kaspersky.com/api/v1/``.
"""

from .client import KasperskyOpenTIPClient

__all__ = ["KasperskyOpenTIPClient"]
