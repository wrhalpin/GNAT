# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.hackerone
=============================

HackerOne — bug bounty / VDP / pentest-as-a-service platform.
Wraps the v1 REST API at ``https://api.hackerone.com/v1/``.
"""

from .client import HackerOneClient

__all__ = ["HackerOneClient"]
