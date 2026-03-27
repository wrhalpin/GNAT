"""
gnat.orm.relationship
========================
STIX 2.1 Relationship SRO.
"""
from gnat.orm.base import STIXBase

class Relationship(STIXBase):
    """
    STIX 2.1 Relationship object.

    Parameters
    ----------
    relationship_type : str
        Relationship verb, e.g. ``"indicates"``, ``"uses"``.
    source_ref : str
        STIX id of the source object.
    target_ref : str
        STIX id of the target object.
    """
    stix_type = "relationship"
