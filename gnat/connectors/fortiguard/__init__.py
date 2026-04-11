# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.fortiguard
==============================

Fortinet FortiGuard Labs connector.  Wraps the public IOC and
outbreak-alert feeds at ``https://fortiguard.com/``.
"""

from .client import FortiGuardClient

__all__ = ["FortiGuardClient"]
