# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.entra_id
============================

Microsoft Entra ID (formerly Azure Active Directory) connector. Wraps
the Microsoft Graph v1.0 API at ``https://graph.microsoft.com/v1.0/``.
"""

from .client import EntraIDClient

__all__ = ["EntraIDClient"]
