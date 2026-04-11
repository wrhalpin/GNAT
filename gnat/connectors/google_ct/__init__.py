# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.google_ct
=============================

Google Certificate Transparency log API connector. Wraps the public
RFC 6962 endpoints exposed at log servers operated by Google
(``ct.googleapis.com/logs/eu1/``, ``/argon2026/``, etc.).
"""

from .client import GoogleCTClient

__all__ = ["GoogleCTClient"]
