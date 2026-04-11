# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.abuseipdb
=============================

AbuseIPDB community-sourced IP reputation connector. Wraps the v2 REST
API at ``https://api.abuseipdb.com/api/v2/``.
"""

from .client import AbuseIPDBClient

__all__ = ["AbuseIPDBClient"]
