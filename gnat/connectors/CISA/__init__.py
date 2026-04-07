# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.cisa
====================

CISA (Cybersecurity and Infrastructure Security Agency) connector, primarily for the Known Exploited Vulnerabilities (KEV) Catalog.
"""

from .client import CISAClient

__all__ = ["CISAClient"]
