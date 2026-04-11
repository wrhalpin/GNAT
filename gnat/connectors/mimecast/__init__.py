# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.mimecast
============================

Mimecast email security connector.  Wraps the Mimecast API 2.0 Cloud
Integrated Email Security platform at ``https://api.services.mimecast.com``.
"""

from .client import MimecastClient

__all__ = ["MimecastClient"]
