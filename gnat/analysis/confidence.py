"""
gnat.analysis.confidence
========================

Confidence scoring model combining the NATO Admiralty Scale with the STIX 2.1
numeric confidence field (0–100).

The Admiralty Scale is the most widely used framework in professional CTI:
it separates *source reliability* (how trustworthy is the originating source?)
from *information credibility* (how believable is this specific report?),
preventing the common mistake of conflating source and content quality.

References:
- NATO STANAG 2511 (Admiralty Scale)
- STIX 2.1 §7.2 — confidence property

Usage::

    from gnat.analysis.confidence import (
        ConfidenceScore,
        ConfidenceLevel,
        SourceReliability,
        InformationCredibility,
    )

    score = ConfidenceScore(
        source_reliability      = SourceReliability.B_USUALLY_RELIABLE,
        information_credibility = InformationCredibility.PROBABLY_TRUE,
        stix_confidence         = 75,
        rationale               = "Cross-corroborated by two independent sources.",
    )

    print(score.band)   # "HIGH"
    print(score.label)  # "B2 (HIGH)"
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class SourceReliability(str, Enum):
    """
    Admiralty Scale — Source Reliability (A through F).

    Assesses the originating source as a whole, not the specific report.

    Attributes
    ----------
    A_COMPLETELY_RELIABLE : str
        No doubt about authenticity, trustworthiness, or competency. History
        of complete reliability.
    B_USUALLY_RELIABLE : str
        Minor doubts. History of mostly valid information.
    C_FAIRLY_RELIABLE : str
        Doubts about past reliability. Has provided valid information in the
        past.
    D_NOT_USUALLY_RELIABLE : str
        Significant doubts. Provided invalid information in the past.
    E_UNRELIABLE : str
        Lack of authenticity, trustworthiness, or competency. History of
        invalid information.
    F_CANNOT_BE_JUDGED : str
        Insufficient basis to evaluate reliability.
    """

    A_COMPLETELY_RELIABLE = "A"
    B_USUALLY_RELIABLE    = "B"
    C_FAIRLY_RELIABLE     = "C"
    D_NOT_USUALLY_RELIABLE = "D"
    E_UNRELIABLE          = "E"
    F_CANNOT_BE_JUDGED    = "F"

    @property
    def description(self) -> str:
        """Full description of the reliability grade."""
        return _SOURCE_DESCRIPTIONS[self]


class InformationCredibility(int, Enum):
    """
    Admiralty Scale — Information Credibility (1 through 6).

    Assesses the specific piece of information, independent of the source.

    Attributes
    ----------
    CONFIRMED : int
        Confirmed by other independent sources. Logical. Consistent with
        other information on the subject.
    PROBABLY_TRUE : int
        Not confirmed. Logical. Consistent with other information on the
        subject.
    POSSIBLY_TRUE : int
        Not confirmed. Reasonably logical. Agrees with some other information
        on the subject.
    DOUBTFUL : int
        Not confirmed. Possible but illogical. No other information on the
        subject.
    IMPROBABLE : int
        Not confirmed. Not logical. Contradicted by other information on the
        subject.
    CANNOT_BE_JUDGED : int
        No basis exists for evaluating the validity of the information.
    """

    CONFIRMED         = 1
    PROBABLY_TRUE     = 2
    POSSIBLY_TRUE     = 3
    DOUBTFUL          = 4
    IMPROBABLE        = 5
    CANNOT_BE_JUDGED  = 6

    @property
    def description(self) -> str:
        """Full description of the credibility grade."""
        return _CREDIBILITY_DESCRIPTIONS[self]


class ConfidenceLevel(str, Enum):
    """
    Convenience confidence band for display and filtering.

    Maps to STIX numeric ranges: HIGH ≥ 70, MEDIUM 40–69, LOW < 40.
    """

    HIGH   = "HIGH"
    MEDIUM = "MEDIUM"
    LOW    = "LOW"

    @classmethod
    def from_stix(cls, stix_confidence: int) -> "ConfidenceLevel":
        """
        Derive a ConfidenceLevel band from a STIX 0–100 confidence value.

        Parameters
        ----------
        stix_confidence : int
            STIX numeric confidence in range 0–100.

        Returns
        -------
        ConfidenceLevel
        """
        if stix_confidence >= 70:
            return cls.HIGH
        if stix_confidence >= 40:
            return cls.MEDIUM
        return cls.LOW


@dataclass
class ConfidenceScore:
    """
    Composite confidence combining the Admiralty Scale with STIX numeric confidence.

    Parameters
    ----------
    source_reliability : SourceReliability
        Admiralty Scale reliability grade for the originating source (A–F).
    information_credibility : InformationCredibility
        Admiralty Scale credibility grade for this specific information (1–6).
    stix_confidence : int
        STIX 2.1 numeric confidence in range 0–100. Required for STIX
        serialization and used to derive the convenience ``band``.
    rationale : str, optional
        Human-readable explanation for the assigned confidence level.

    Examples
    --------
    >>> score = ConfidenceScore(
    ...     source_reliability      = SourceReliability.B_USUALLY_RELIABLE,
    ...     information_credibility = InformationCredibility.PROBABLY_TRUE,
    ...     stix_confidence         = 75,
    ...     rationale               = "Two independent sources.",
    ... )
    >>> score.band
    <ConfidenceLevel.HIGH: 'HIGH'>
    >>> score.label
    'B2 (HIGH)'
    """

    source_reliability:      SourceReliability
    information_credibility: InformationCredibility
    stix_confidence:         int
    rationale:               str | None = field(default=None)

    def __post_init__(self) -> None:
        if not 0 <= self.stix_confidence <= 100:
            raise ValueError(
                f"stix_confidence must be 0–100, got {self.stix_confidence}"
            )

    @property
    def band(self) -> ConfidenceLevel:
        """Convenience confidence band (HIGH / MEDIUM / LOW)."""
        return ConfidenceLevel.from_stix(self.stix_confidence)

    @property
    def label(self) -> str:
        """Short label combining Admiralty codes and band, e.g. ``'B2 (HIGH)'``."""
        return (
            f"{self.source_reliability.value}"
            f"{self.information_credibility.value}"
            f" ({self.band.value})"
        )

    def to_dict(self) -> dict:
        """Serialise to a plain dict suitable for JSON storage."""
        return {
            "source_reliability":      self.source_reliability.value,
            "information_credibility": self.information_credibility.value,
            "stix_confidence":         self.stix_confidence,
            "band":                    self.band.value,
            "label":                   self.label,
            "rationale":               self.rationale,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ConfidenceScore":
        """Deserialise from a plain dict produced by :meth:`to_dict`."""
        return cls(
            source_reliability      = SourceReliability(data["source_reliability"]),
            information_credibility = InformationCredibility(data["information_credibility"]),
            stix_confidence         = int(data["stix_confidence"]),
            rationale               = data.get("rationale"),
        )

    @classmethod
    def high(cls, rationale: str | None = None) -> "ConfidenceScore":
        """Convenience factory: B2 HIGH (75)."""
        return cls(
            source_reliability      = SourceReliability.B_USUALLY_RELIABLE,
            information_credibility = InformationCredibility.PROBABLY_TRUE,
            stix_confidence         = 75,
            rationale               = rationale,
        )

    @classmethod
    def medium(cls, rationale: str | None = None) -> "ConfidenceScore":
        """Convenience factory: C3 MEDIUM (50)."""
        return cls(
            source_reliability      = SourceReliability.C_FAIRLY_RELIABLE,
            information_credibility = InformationCredibility.POSSIBLY_TRUE,
            stix_confidence         = 50,
            rationale               = rationale,
        )

    @classmethod
    def low(cls, rationale: str | None = None) -> "ConfidenceScore":
        """Convenience factory: D4 LOW (25)."""
        return cls(
            source_reliability      = SourceReliability.D_NOT_USUALLY_RELIABLE,
            information_credibility = InformationCredibility.DOUBTFUL,
            stix_confidence         = 25,
            rationale               = rationale,
        )


# ── Description tables ────────────────────────────────────────────────────────

_SOURCE_DESCRIPTIONS: dict[SourceReliability, str] = {
    SourceReliability.A_COMPLETELY_RELIABLE:    "No doubt about authenticity, trustworthiness, or competency.",
    SourceReliability.B_USUALLY_RELIABLE:       "Minor doubts; history of mostly valid information.",
    SourceReliability.C_FAIRLY_RELIABLE:        "Doubts about past reliability; has provided valid information in the past.",
    SourceReliability.D_NOT_USUALLY_RELIABLE:   "Significant doubts; has provided invalid information in the past.",
    SourceReliability.E_UNRELIABLE:             "Lack of authenticity, trustworthiness, or competency.",
    SourceReliability.F_CANNOT_BE_JUDGED:       "Insufficient basis to evaluate reliability.",
}

_CREDIBILITY_DESCRIPTIONS: dict[InformationCredibility, str] = {
    InformationCredibility.CONFIRMED:        "Confirmed by independent sources; logical and consistent.",
    InformationCredibility.PROBABLY_TRUE:    "Not confirmed; logical and consistent with other information.",
    InformationCredibility.POSSIBLY_TRUE:    "Not confirmed; reasonably logical; agrees with some information.",
    InformationCredibility.DOUBTFUL:         "Not confirmed; possible but illogical; no corroboration.",
    InformationCredibility.IMPROBABLE:       "Not confirmed; not logical; contradicted by other information.",
    InformationCredibility.CANNOT_BE_JUDGED: "No basis exists for evaluating validity.",
}
