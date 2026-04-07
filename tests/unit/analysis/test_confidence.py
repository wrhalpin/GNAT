"""Unit tests for gnat.analysis.confidence and gnat.analysis.tlp."""

import pytest

from gnat.analysis.confidence import (
    ConfidenceLevel,
    ConfidenceScore,
    InformationCredibility,
    SourceReliability,
)
from gnat.analysis.tlp import TLPLevel


# ── TLPLevel ──────────────────────────────────────────────────────────────────

class TestTLPLevel:
    def test_label(self):
        assert TLPLevel.AMBER.label == "TLP:AMBER"
        assert TLPLevel.RED.label   == "TLP:RED"
        assert TLPLevel.GREEN.label == "TLP:GREEN"
        assert TLPLevel.WHITE.label == "TLP:WHITE"

    def test_rank_ordering(self):
        assert TLPLevel.WHITE.rank < TLPLevel.GREEN.rank
        assert TLPLevel.GREEN.rank < TLPLevel.AMBER.rank
        assert TLPLevel.AMBER.rank < TLPLevel.AMBER_STRICT.rank
        assert TLPLevel.AMBER_STRICT.rank < TLPLevel.RED.rank

    def test_max_by_rank(self):
        levels = [TLPLevel.GREEN, TLPLevel.RED, TLPLevel.AMBER]
        most_restrictive = max(levels, key=lambda t: t.rank)
        assert most_restrictive == TLPLevel.RED

    def test_stix_marking_id_format(self):
        for level in (TLPLevel.WHITE, TLPLevel.GREEN, TLPLevel.AMBER, TLPLevel.RED):
            assert level.stix_marking_id.startswith("marking-definition--")

    def test_colour_is_hex(self):
        for level in TLPLevel:
            assert TLPLevel(level).colour.startswith("#")

    def test_string_value(self):
        assert TLPLevel.AMBER == "amber"
        assert TLPLevel.AMBER_STRICT == "amber+strict"

    def test_clear_white_same_rank(self):
        assert TLPLevel.CLEAR.rank == TLPLevel.WHITE.rank


# ── ConfidenceScore ───────────────────────────────────────────────────────────

class TestConfidenceScore:
    def test_high_band(self):
        score = ConfidenceScore(
            source_reliability      = SourceReliability.A_COMPLETELY_RELIABLE,
            information_credibility = InformationCredibility.CONFIRMED,
            stix_confidence         = 95,
        )
        assert score.band == ConfidenceLevel.HIGH

    def test_medium_band(self):
        score = ConfidenceScore.medium()
        assert score.band == ConfidenceLevel.MEDIUM
        assert score.stix_confidence == 50

    def test_low_band(self):
        score = ConfidenceScore.low()
        assert score.band == ConfidenceLevel.LOW
        assert score.stix_confidence == 25

    def test_label_format(self):
        score = ConfidenceScore(
            source_reliability      = SourceReliability.B_USUALLY_RELIABLE,
            information_credibility = InformationCredibility.PROBABLY_TRUE,
            stix_confidence         = 75,
        )
        assert score.label == "B2 (HIGH)"

    def test_rationale_optional(self):
        score = ConfidenceScore.high()
        assert score.rationale is None

        score_with = ConfidenceScore.high(rationale="From two independent sources.")
        assert score_with.rationale == "From two independent sources."

    def test_stix_confidence_bounds(self):
        with pytest.raises(ValueError):
            ConfidenceScore(
                source_reliability      = SourceReliability.A_COMPLETELY_RELIABLE,
                information_credibility = InformationCredibility.CONFIRMED,
                stix_confidence         = 101,
            )
        with pytest.raises(ValueError):
            ConfidenceScore(
                source_reliability      = SourceReliability.A_COMPLETELY_RELIABLE,
                information_credibility = InformationCredibility.CONFIRMED,
                stix_confidence         = -1,
            )

    def test_roundtrip_serialization(self):
        original = ConfidenceScore(
            source_reliability      = SourceReliability.C_FAIRLY_RELIABLE,
            information_credibility = InformationCredibility.POSSIBLY_TRUE,
            stix_confidence         = 45,
            rationale               = "Partially corroborated.",
        )
        data     = original.to_dict()
        restored = ConfidenceScore.from_dict(data)

        assert restored.source_reliability      == original.source_reliability
        assert restored.information_credibility == original.information_credibility
        assert restored.stix_confidence         == original.stix_confidence
        assert restored.rationale               == original.rationale
        assert restored.band                    == original.band

    def test_to_dict_contains_band_and_label(self):
        score = ConfidenceScore.high()
        d = score.to_dict()
        assert "band"  in d
        assert "label" in d
        assert d["band"] == "HIGH"

    def test_confidence_level_from_stix(self):
        assert ConfidenceLevel.from_stix(0)   == ConfidenceLevel.LOW
        assert ConfidenceLevel.from_stix(39)  == ConfidenceLevel.LOW
        assert ConfidenceLevel.from_stix(40)  == ConfidenceLevel.MEDIUM
        assert ConfidenceLevel.from_stix(69)  == ConfidenceLevel.MEDIUM
        assert ConfidenceLevel.from_stix(70)  == ConfidenceLevel.HIGH
        assert ConfidenceLevel.from_stix(100) == ConfidenceLevel.HIGH

    def test_convenience_factories(self):
        high   = ConfidenceScore.high()
        medium = ConfidenceScore.medium()
        low    = ConfidenceScore.low()

        assert high.band   == ConfidenceLevel.HIGH
        assert medium.band == ConfidenceLevel.MEDIUM
        assert low.band    == ConfidenceLevel.LOW

    def test_source_reliability_enum_values(self):
        assert SourceReliability.A_COMPLETELY_RELIABLE.value == "A"
        assert SourceReliability.F_CANNOT_BE_JUDGED.value    == "F"

    def test_information_credibility_enum_values(self):
        assert InformationCredibility.CONFIRMED.value         == 1
        assert InformationCredibility.CANNOT_BE_JUDGED.value  == 6
