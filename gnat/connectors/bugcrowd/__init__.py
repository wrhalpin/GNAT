# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.bugcrowd
============================

Bugcrowd — managed bug bounty / VDP / penetration-testing platform.
Wraps the v4 REST API at ``https://api.bugcrowd.com/``.
"""

from .client import BugcrowdClient

__all__ = ["BugcrowdClient"]
