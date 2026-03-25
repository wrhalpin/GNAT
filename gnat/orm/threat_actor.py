"""
ctm_sak.orm.threat_actor
========================
STIX 2.1 Threat Actor SDO.
"""
from ctm_sak.orm.base import STIXBase

class ThreatActor(STIXBase):
    """STIX 2.1 Threat Actor domain object."""
    stix_type = "threat-actor"
    def __init__(self, client=None, **kwargs):
        kwargs.setdefault("threat_actor_types", [])
        super().__init__(client=client, **kwargs)
