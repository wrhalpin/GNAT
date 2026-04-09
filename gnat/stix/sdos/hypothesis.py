# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.stix.sdos.hypothesis
==========================

Custom STIX 2.1 SDO representing a reasoning hypothesis.

A :class:`STIXHypothesis` is an assertion about a threat, actor, campaign,
or relationship that can be confirmed or refuted through evidence.  It is
stored via the existing STIX ORM path (``workspace._add_object()``) so no
new storage infrastructure is needed.

STIX type: ``x-gnat-hypothesis``

Usage
-----
::

    from gnat.stix.sdos.hypothesis import STIXHypothesis

    h = STIXHypothesis(
        statement="APT29 is responsible for the Q1 2026 phishing campaign.",
        confidence=0.4,
    )
    h.add_supporting_evidence("relationship--abc123")
    print(h.to_dict())
"""

from __future__ import annotations

from typing import Any, Optional

from gnat.orm.base import STIXBase, _utcnow


class STIXHypothesis(STIXBase):
    """
    Custom STIX 2.1 SDO — ``x-gnat-hypothesis``.

    Represents an analyst or engine hypothesis about threat attribution,
    campaign linkage, or actor identity.  Evidence is tracked through
    STIX relationship IDs pointing to supporting or refuting objects.

    Parameters
    ----------
    statement : str
        Human-readable assertion being tested.
    confidence : float
        Initial confidence score in the range ``[0.0, 1.0]``.
    status : str
        Lifecycle status: ``"pending"``, ``"confirmed"``, ``"refuted"``,
        or ``"inconclusive"``.

    Examples
    --------
    ::

        h = STIXHypothesis(
            statement="192.0.2.1 is a C2 server for Lazarus Group.",
            confidence=0.3,
        )
        h.add_supporting_evidence("relationship--uuid1")
        h.add_refuting_evidence("relationship--uuid2")
        h.update_confidence(0.7)
        h.close("confirmed")
    """

    stix_type = "x-gnat-hypothesis"
    schema_version = 1

    # Valid lifecycle statuses
    STATUSES = frozenset({"pending", "confirmed", "refuted", "inconclusive"})

    def __init__(
        self,
        statement: str = "",
        confidence: float = 0.0,
        status: str = "pending",
        supporting_evidence: list[str] | None = None,
        refuting_evidence: list[str] | None = None,
        client: Optional[Any] = None,
        **kwargs: Any,
    ) -> None:
        """Initialize STIXHypothesis."""
        super().__init__(client=client, **kwargs)
        if status not in self.STATUSES:
            raise ValueError(
                f"Invalid hypothesis status {status!r}. "
                f"Must be one of: {sorted(self.STATUSES)}"
            )
        if not (0.0 <= confidence <= 1.0):
            raise ValueError(
                f"confidence must be in [0.0, 1.0], got {confidence!r}"
            )
        self._properties["statement"] = statement
        self._properties["confidence"] = float(confidence)
        self._properties["status"] = status
        self._properties["supporting_evidence"] = list(supporting_evidence or [])
        self._properties["refuting_evidence"] = list(refuting_evidence or [])

    # ── Evidence management ────────────────────────────────────────────────────

    def add_supporting_evidence(self, relationship_id: str) -> None:
        """
        Link a supporting STIX relationship to this hypothesis.

        Parameters
        ----------
        relationship_id : str
            STIX ID of a ``relationship`` object linking evidence to this hypothesis.
        """
        if relationship_id not in self._properties["supporting_evidence"]:
            self._properties["supporting_evidence"].append(relationship_id)
        self.modified = _utcnow()

    def add_refuting_evidence(self, relationship_id: str) -> None:
        """
        Link a refuting STIX relationship to this hypothesis.

        Parameters
        ----------
        relationship_id : str
            STIX ID of a ``relationship`` object linking contradicting evidence.
        """
        if relationship_id not in self._properties["refuting_evidence"]:
            self._properties["refuting_evidence"].append(relationship_id)
        self.modified = _utcnow()

    # ── Lifecycle ──────────────────────────────────────────────────────────────

    def update_confidence(self, confidence: float) -> None:
        """
        Update the confidence score.

        Parameters
        ----------
        confidence : float
            New score in ``[0.0, 1.0]``.
        """
        if not (0.0 <= confidence <= 1.0):
            raise ValueError(f"confidence must be in [0.0, 1.0], got {confidence!r}")
        self._properties["confidence"] = float(confidence)
        self.modified = _utcnow()

    def close(self, verdict: str) -> None:
        """
        Finalise this hypothesis with a verdict.

        Parameters
        ----------
        verdict : str
            One of ``"confirmed"``, ``"refuted"``, or ``"inconclusive"``.
        """
        valid = {"confirmed", "refuted", "inconclusive"}
        if verdict not in valid:
            raise ValueError(f"verdict must be one of {sorted(valid)}, got {verdict!r}")
        self._properties["status"] = verdict
        self.modified = _utcnow()

    # ── Serialization ──────────────────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a STIX-compatible dict."""
        return {
            "type": self.stix_type,
            "id": self.id,
            "spec_version": self.spec_version,
            "created": self.created,
            "modified": self.modified,
            "statement": self._properties.get("statement", ""),
            "confidence": self._properties.get("confidence", 0.0),
            "status": self._properties.get("status", "pending"),
            "supporting_evidence": self._properties.get("supporting_evidence", []),
            "refuting_evidence": self._properties.get("refuting_evidence", []),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any], client: Optional[Any] = None) -> STIXHypothesis:
        """Deserialise from a STIX dict."""
        obj = cls(
            statement=data.get("statement", ""),
            confidence=float(data.get("confidence", 0.0)),
            status=data.get("status", "pending"),
            supporting_evidence=data.get("supporting_evidence", []),
            refuting_evidence=data.get("refuting_evidence", []),
            client=client,
            id=data.get("id"),
            created=data.get("created"),
            modified=data.get("modified"),
            spec_version=data.get("spec_version", "2.1"),
        )
        return obj

    def __repr__(self) -> str:  # pragma: no cover
        stmt = self._properties.get("statement", "")[:50]
        return (
            f"STIXHypothesis(status={self._properties.get('status')!r}, "
            f"confidence={self._properties.get('confidence'):.2f}, "
            f"statement={stmt!r})"
        )
