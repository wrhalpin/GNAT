# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.orm.threat_actor
========================
STIX 2.1 Threat Actor SDO.
"""

from gnat.orm.base import STIXBase


class ThreatActor(STIXBase):
    """STIX 2.1 Threat Actor domain object."""

    stix_type = "threat-actor"

    def __init__(self, client=None, **kwargs):
        kwargs.setdefault("threat_actor_types", [])
        super().__init__(client=client, **kwargs)
