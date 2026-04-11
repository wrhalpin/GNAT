# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.eset_ti
===========================

ESET Threat Intelligence connector. Wraps the REST API at
``https://eti.eset.com/api/v1/``.
"""

from .client import ESETThreatIntelClient

__all__ = ["ESETThreatIntelClient"]
