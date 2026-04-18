# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.orm.campaign
====================
STIX 2.1 Campaign SDO.
"""

from gnat.orm.base import STIXBase


class Campaign(STIXBase):
    """STIX 2.1 Campaign domain object."""

    stix_type = "campaign"

    def __init__(self, client=None, **kwargs):
        """Initialize Campaign."""
        kwargs.setdefault("aliases", [])
        kwargs.setdefault("first_seen", None)
        kwargs.setdefault("last_seen", None)
        kwargs.setdefault("objective", "")
        super().__init__(client=client, **kwargs)
