# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.attackiq
============================

AttackIQ Security Optimization / Flex platform connector. Wraps the v1
API at ``https://gts.attackiq.com/api/v1/`` (or tenant URL).
"""

from .client import AttackIQClient

__all__ = ["AttackIQClient"]
