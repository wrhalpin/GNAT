# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.analysis.tlp
=================

TLP (Traffic Light Protocol) classification levels shared across the
analysis, reporting, and dissemination layers.

TLP levels follow the FIRST TLP 2.0 standard:
https://www.first.org/tlp/

Usage::

    from gnat.analysis.tlp import TLPLevel

    level = TLPLevel.AMBER
    print(level.label)   # "TLP:AMBER"
    print(level.colour)  # "#FFA500"
"""

from __future__ import annotations

from enum import Enum


class TLPLevel(str, Enum):
    """
    Traffic Light Protocol 2.0 classification levels.

    Each member is also a string equal to its STIX ``object_marking_refs``
    identifier fragment so it serializes naturally in STIX bundles.

    Attributes
    ----------
    WHITE : str
        Unlimited distribution. (TLP 2.0: renamed to CLEAR)
    CLEAR : str
        Unlimited distribution. (TLP 2.0 name for WHITE)
    GREEN : str
        Community-wide distribution; no external publication.
    AMBER : str
        Limited distribution to members' organization.
    AMBER_STRICT : str
        Limited distribution within the recipient's own organization only.
    RED : str
        Restricted to specific individuals; not for distribution.
    """

    WHITE = "white"
    CLEAR = "clear"
    GREEN = "green"
    AMBER = "amber"
    AMBER_STRICT = "amber+strict"
    RED = "red"

    @property
    def label(self) -> str:
        """Human-readable TLP label, e.g. ``'TLP:AMBER'``."""
        return f"TLP:{self.value.upper()}"

    @property
    def colour(self) -> str:
        """Hex colour associated with the TLP level."""
        return _COLOURS[self]

    @property
    def stix_marking_id(self) -> str:
        """
        Standard STIX 2.1 marking definition ID for this TLP level.

        These are the well-known IDs registered by FIRST at
        ``https://www.first.org/tlp/``.
        """
        return _STIX_MARKING_IDS.get(self, f"marking-definition--{self.value}")

    @property
    def rank(self) -> int:
        """
        Numeric rank for severity comparison (higher = more restricted).

        Useful for ``max(tlp_a, tlp_b, key=lambda t: t.rank)``.
        """
        return _RANKS[self]


_COLOURS: dict[TLPLevel, str] = {
    TLPLevel.WHITE: "#FFFFFF",
    TLPLevel.CLEAR: "#FFFFFF",
    TLPLevel.GREEN: "#33FF00",
    TLPLevel.AMBER: "#FFA500",
    TLPLevel.AMBER_STRICT: "#FFA500",
    TLPLevel.RED: "#FF0000",
}

_RANKS: dict[TLPLevel, int] = {
    TLPLevel.WHITE: 0,
    TLPLevel.CLEAR: 0,
    TLPLevel.GREEN: 1,
    TLPLevel.AMBER: 2,
    TLPLevel.AMBER_STRICT: 3,
    TLPLevel.RED: 4,
}

# Well-known STIX 2.1 marking definition IDs (FIRST registered)
_STIX_MARKING_IDS: dict[TLPLevel, str] = {
    TLPLevel.WHITE: "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    TLPLevel.CLEAR: "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    TLPLevel.GREEN: "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    TLPLevel.AMBER: "marking-definition--f88d31f6-1088-400b-8ce4-c732f945ee31",
    TLPLevel.RED: "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
}
