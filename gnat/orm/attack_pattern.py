# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.orm.attack_pattern
==========================
STIX 2.1 Attack Pattern SDO.
"""

from gnat.orm.base import STIXBase


class AttackPattern(STIXBase):
    """STIX 2.1 Attack Pattern domain object."""

    stix_type = "attack-pattern"
