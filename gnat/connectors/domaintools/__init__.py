# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.domaintools
===============================

DomainTools Iris connector — industry-standard passive DNS / WHOIS
intelligence and domain pivoting. Wraps ``https://api.domaintools.com/``.
"""

from .client import DomainToolsClient

__all__ = ["DomainToolsClient"]
