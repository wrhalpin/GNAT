"""
gnat.dissemination.taxii.collections
======================================

TLP-based TAXII 2.1 collection management.

Each TLP level maps to a named collection.  A consumer with access level
``amber`` can read the ``tlp-white``, ``tlp-green``, and ``tlp-amber``
collections.

Collection IDs are deterministic UUIDs derived from the collection name so
they are stable across restarts.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

from gnat.analysis.tlp import TLPLevel


def _cid(name: str) -> str:
    """Deterministic UUID for a collection name."""
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"gnat-taxii-collection:{name}"))


@dataclass
class TAXIICollection:
    """
    A TAXII 2.1 collection backed by the GNAT report store.

    Parameters
    ----------
    id : str
        TAXII collection UUID.
    title : str
        Human-readable collection title.
    description : str
        Collection description.
    tlp_level : TLPLevel
        TLP level of content in this collection.
    min_access_level : TLPLevel
        Minimum TLP level required for read access.
    can_read : bool
        Whether external consumers can read (default True).
    can_write : bool
        Whether external consumers can write (default False — internal only).
    """

    id: str
    title: str
    description: str
    tlp_level: TLPLevel
    min_access_level: TLPLevel
    can_read: bool = True
    can_write: bool = False
    media_types: list[str] = field(default_factory=lambda: ["application/stix+json;version=2.1"])

    def to_taxii_dict(self) -> dict[str, Any]:
        """Serialise to TAXII 2.1 Collection resource."""
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "can_read": self.can_read,
            "can_write": self.can_write,
            "media_types": self.media_types,
        }

    def is_accessible(self, api_key_tlp: TLPLevel) -> bool:
        """True if *api_key_tlp* has sufficient access for this collection."""
        return api_key_tlp.rank >= self.min_access_level.rank


# ── Built-in collections (one per TLP level) ─────────────────────────────────

COLLECTIONS: dict[str, TAXIICollection] = {
    "tlp-white": TAXIICollection(
        id=_cid("tlp-white"),
        title="TLP:WHITE Intelligence",
        description="Publicly shareable finished intelligence reports (TLP:WHITE).",
        tlp_level=TLPLevel.WHITE,
        min_access_level=TLPLevel.WHITE,
    ),
    "tlp-green": TAXIICollection(
        id=_cid("tlp-green"),
        title="TLP:GREEN Intelligence",
        description="Community-shareable intelligence reports (TLP:GREEN and below).",
        tlp_level=TLPLevel.GREEN,
        min_access_level=TLPLevel.GREEN,
    ),
    "tlp-amber": TAXIICollection(
        id=_cid("tlp-amber"),
        title="TLP:AMBER Intelligence",
        description="Limited-distribution intelligence reports (TLP:AMBER and below).",
        tlp_level=TLPLevel.AMBER,
        min_access_level=TLPLevel.AMBER,
        can_write=True,
    ),
    "tlp-red": TAXIICollection(
        id=_cid("tlp-red"),
        title="TLP:RED Intelligence",
        description="Restricted intelligence reports (TLP:RED — explicit grant required).",
        tlp_level=TLPLevel.RED,
        min_access_level=TLPLevel.RED,
        can_write=True,
    ),
}

# Map collection UUID → TAXIICollection
COLLECTION_BY_ID: dict[str, TAXIICollection] = {c.id: c for c in COLLECTIONS.values()}


def collections_for_key(key_tlp: TLPLevel) -> list[TAXIICollection]:
    """Return collections accessible to a key with *key_tlp* access level."""
    return [c for c in COLLECTIONS.values() if c.is_accessible(key_tlp)]


def tlp_filter_for_collection(collection_id: str) -> list[str]:
    """
    Return TLP level values that should be included in *collection_id*.

    A TLP:AMBER collection includes AMBER, GREEN, and WHITE reports.
    """
    col = COLLECTION_BY_ID.get(collection_id)
    if col is None:
        return []
    include = [tlp.value for tlp in TLPLevel if tlp.rank <= col.tlp_level.rank]
    return include
