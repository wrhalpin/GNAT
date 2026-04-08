# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.shodan
======================

Shodan (Internet search engine for connected devices) connector.
"""

from .client import ShodanClient

__all__ = ["ShodanClient"]
