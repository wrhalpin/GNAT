# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
Unit tests for gnat.streaming event types and streaming-aware methods.

Covers:
- StreamEvent, ProgressEvent, TokenEvent, ResultEvent, ErrorEvent creation
- InvestigationBuilder.build_with_progress callback invocations
- GapDetector.detect_with_progress callback invocations
- ReportDraftingAssistant.draft_with_progress callback invocations
- LLMClient.stream_events yield sequence
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from gnat.streaming import (
    ErrorEvent,
    ProgressEvent,
    ResultEvent,
    StreamEvent,
    TokenEvent,
)

# ── StreamEvent dataclass tests ──────────────────────────────────────────────


class TestStreamEventTypes:
    def test_stream_event_base(self):
        ev = StreamEvent()
        assert isinstance(ev, StreamEvent)

    def test_progress_event_defaults(self):
        ev = ProgressEvent(progress=0.5)
        assert ev.progress == 0.5
        assert ev.message == ""

    def test_progress_event_with_message(self):
        ev = ProgressEvent(progress=0.75, message="Almost done")
        assert ev.progress == 0.75
        assert ev.message == "Almost done"

    def test_token_event(self):
        ev = TokenEvent(text="Hello")
        assert ev.text == "Hello"
        assert isinstance(ev, StreamEvent)

    def test_result_event(self):
        ev = ResultEvent(result={"text": "full output"})
        assert ev.result == {"text": "full output"}
        assert isinstance(ev, StreamEvent)

    def test_error_event(self):
        ev = ErrorEvent(error="something went wrong")
        assert ev.error == "something went wrong"
        assert isinstance(ev, StreamEvent)

    def test_progress_event_boundary_values(self):
        ev_zero = ProgressEvent(progress=0.0, message="Start")
        ev_one = ProgressEvent(progress=1.0, message="Done")
        assert ev_zero.progress == 0.0
        assert ev_one.progress == 1.0


# ── InvestigationBuilder.build_with_progress ─────────────────────────────────


class TestInvestigationBuilderBuildWithProgress:
    def test_callback_invoked_at_expected_points(self):
        from gnat.investigations.model import Seed, SeedType

        calls: list[tuple[float, str]] = []

        def cb(progress: float, message: str) -> None:
            calls.append((progress, message))

        with (
            patch(
                "gnat.investigations.builder.InvestigationBuilder._expand_seed"
            ) as mock_expand_seed,
            patch("gnat.investigations.builder.correlate"),
        ):
            from gnat.investigations.builder import InvestigationBuilder

            builder = InvestigationBuilder(connectors={})
            seeds = [
                Seed("1.2.3.4", SeedType.IP),
                Seed("evil.com", SeedType.DOMAIN),
            ]
            graph = builder.build_with_progress(
                seeds=seeds,
                title="Test",
                progress_callback=cb,
            )

        # Verify callback was invoked
        assert len(calls) >= 5
        # First call: "Validating seeds"
        assert calls[0] == (0.0, "Validating seeds")
        # Seed expansions
        assert "Expanding seed 1/2" in calls[1][1]
        assert "Expanding seed 2/2" in calls[2][1]
        # Incidents phase
        assert "Expanding incidents" in calls[3][1]
        # Correlating
        correlating = [c for c in calls if "Correlating" in c[1]]
        assert len(correlating) == 1
        assert correlating[0][0] == 0.8
        # Complete
        assert calls[-1] == (1.0, "Complete")

    def test_callback_none_does_not_raise(self):
        from gnat.investigations.model import Seed, SeedType

        with (
            patch("gnat.investigations.builder.InvestigationBuilder._expand_seed"),
            patch("gnat.investigations.builder.correlate"),
        ):
            from gnat.investigations.builder import InvestigationBuilder

            builder = InvestigationBuilder(connectors={})
            seeds = [Seed("1.2.3.4", SeedType.IP)]
            # Should not raise even without a callback
            graph = builder.build_with_progress(seeds=seeds, title="T")
            assert graph is not None

    def test_returns_evidence_graph(self):
        from gnat.investigations.builder import InvestigationBuilder
        from gnat.investigations.model import EvidenceGraph, Seed, SeedType

        with (
            patch("gnat.investigations.builder.InvestigationBuilder._expand_seed"),
            patch("gnat.investigations.builder.correlate"),
        ):
            builder = InvestigationBuilder(connectors={})
            result = builder.build_with_progress(
                seeds=[Seed("x", SeedType.IP)],
                title="Graph Test",
            )
            assert isinstance(result, EvidenceGraph)
            assert result.title == "Graph Test"


# ── GapDetector.detect_with_progress ─────────────────────────────────────────


def _make_hypothesis(text: str) -> MagicMock:
    h = MagicMock()
    h.id = f"hyp-{text[:10].replace(' ', '-')}"
    h.statement = text
    h.status = "active"
    h.supporting_evidence = []
    h.refuting_evidence = []
    return h


def _make_investigation(
    hypotheses: list | None = None,
    indicators: list | None = None,
    observables: list | None = None,
) -> MagicMock:
    inv = MagicMock()
    inv.hypothesis = hypotheses or []
    inv.indicators = indicators or []
    inv.observables = observables or []
    inv.threat_actors = []
    inv.campaigns = []
    inv.tags = []
    return inv


class TestGapDetectorDetectWithProgress:
    def test_callback_invoked_per_rule(self):
        from gnat.analysis.copilot.gap_detector import _RULES, GapDetector

        calls: list[tuple[float, str]] = []

        def cb(progress: float, message: str) -> None:
            calls.append((progress, message))

        detector = GapDetector()
        hyp = _make_hypothesis("Lateral movement via SMB")
        inv = _make_investigation(hypotheses=[hyp])
        gaps = detector.detect_with_progress(hyp, inv, progress_callback=cb)

        # One call per rule + final "complete" call
        n_rules = len(_RULES)
        assert len(calls) == n_rules + 1
        # First rule starts at progress 0.0
        assert calls[0][0] == pytest.approx(0.0)
        assert "Checking rule:" in calls[0][1]
        # Last call is the completion signal
        assert calls[-1] == (1.0, "Gap detection complete")

    def test_results_match_detect(self):
        from gnat.analysis.copilot.gap_detector import GapDetector

        detector = GapDetector()
        hyp = _make_hypothesis("Ransomware was deployed on target hosts")
        inv = _make_investigation(hypotheses=[hyp])
        gaps_plain = detector.detect(hyp, inv)
        gaps_progress = detector.detect_with_progress(hyp, inv)
        # Same results regardless of callback
        assert [g.rule_id for g in gaps_plain] == [g.rule_id for g in gaps_progress]

    def test_callback_none_does_not_raise(self):
        from gnat.analysis.copilot.gap_detector import GapDetector

        detector = GapDetector()
        hyp = _make_hypothesis("Some hypothesis")
        inv = _make_investigation(hypotheses=[hyp])
        gaps = detector.detect_with_progress(hyp, inv, progress_callback=None)
        assert isinstance(gaps, list)


# ── ReportDraftingAssistant.draft_with_progress ──────────────────────────────


def _make_finding(
    statement: str, techniques: list | None = None, confidence_label: str = "medium"
) -> MagicMock:
    f = MagicMock()
    f.statement = statement
    f.mitre_techniques = techniques or []
    f.confidence = MagicMock(label=confidence_label)
    return f


def _make_evidence(
    statement: str,
    link_type: str = "supports",
    artifact_source: str = "xsoar",
    artifact_type: str = "indicator",
    artifact_id: str = "1",
) -> MagicMock:
    e = MagicMock()
    e.statement = statement
    e.link_type = MagicMock(value=link_type)
    e.artifact_source = artifact_source
    e.artifact_type = artifact_type
    e.artifact_id = artifact_id
    return e


def _make_report(
    title: str = "Test Report",
    report_type: str = "incident",
    classification: str = "amber",
    authors: list | None = None,
    key_findings: list | None = None,
    evidence_links: list | None = None,
) -> MagicMock:
    r = MagicMock()
    r.title = title
    r.report_type = MagicMock(value=report_type)
    r.classification = MagicMock(label=classification)
    r.authors = authors or ["alice"]
    r.key_findings = key_findings or []
    r.evidence_links = evidence_links or []
    return r


class TestReportDraftingAssistantDraftWithProgress:
    def test_callback_invoked_at_all_steps(self):
        from gnat.analysis.copilot.drafting import DraftResult, ReportDraftingAssistant

        calls: list[tuple[float, str]] = []

        def cb(progress: float, message: str) -> None:
            calls.append((progress, message))

        fake_llm = MagicMock()
        fake_llm.complete.return_value = {
            "content": "Draft text.",
            "model": "test-model",
        }

        assistant = ReportDraftingAssistant(llm_client=fake_llm)
        report = _make_report(key_findings=[_make_finding("IOC found")])
        result = assistant.draft_with_progress(report, progress_callback=cb)

        assert isinstance(result, DraftResult)
        # Should have exactly 5 callbacks
        assert len(calls) == 5

        progress_values = [c[0] for c in calls]
        messages = [c[1] for c in calls]

        assert progress_values == [0.1, 0.3, 0.5, 0.8, 1.0]
        assert messages[0] == "Formatting findings"
        assert messages[1] == "Formatting evidence"
        assert messages[2] == "Querying LLM for executive summary"
        assert messages[3] == "Querying LLM for key findings narrative"
        assert messages[4] == "Draft complete"

    def test_two_llm_calls_made(self):
        from gnat.analysis.copilot.drafting import ReportDraftingAssistant

        fake_llm = MagicMock()
        fake_llm.complete.return_value = {"content": "text", "model": "m"}

        assistant = ReportDraftingAssistant(llm_client=fake_llm)
        report = _make_report(key_findings=[_make_finding("Finding A")])
        assistant.draft_with_progress(report)
        assert fake_llm.complete.call_count == 2

    def test_no_llm_returns_placeholder(self):
        from gnat.analysis.copilot.drafting import DraftResult, ReportDraftingAssistant

        assistant = ReportDraftingAssistant(llm_client=None)
        report = _make_report(key_findings=[_make_finding("Finding B")])
        result = assistant.draft_with_progress(report)
        assert isinstance(result, DraftResult)
        assert len(result.warnings) > 0

    def test_callback_none_does_not_raise(self):
        from gnat.analysis.copilot.drafting import ReportDraftingAssistant

        assistant = ReportDraftingAssistant(llm_client=None)
        report = _make_report()
        result = assistant.draft_with_progress(report, progress_callback=None)
        assert result is not None


# ── LLMClient.stream_events ─────────────────────────────────────────────────


class TestLLMClientStreamEvents:
    def test_yields_token_events_then_result(self):
        from gnat.agents.llm import LLMClient

        chunks = ["Hello", " ", "world"]

        with patch.object(LLMClient, "stream", return_value=iter(chunks)):
            client = LLMClient.__new__(LLMClient)
            events = list(client.stream_events("test prompt"))

        # First N events are TokenEvents
        assert len(events) == 4  # 3 tokens + 1 result
        for i in range(3):
            assert isinstance(events[i], TokenEvent)
            assert events[i].text == chunks[i]

        # Last event is ResultEvent with concatenated text
        assert isinstance(events[3], ResultEvent)
        assert events[3].result == {"text": "Hello world"}

    def test_empty_stream(self):
        from gnat.agents.llm import LLMClient

        with patch.object(LLMClient, "stream", return_value=iter([])):
            client = LLMClient.__new__(LLMClient)
            events = list(client.stream_events("empty"))

        # Should still yield a ResultEvent
        assert len(events) == 1
        assert isinstance(events[0], ResultEvent)
        assert events[0].result == {"text": ""}

    def test_single_chunk(self):
        from gnat.agents.llm import LLMClient

        with patch.object(LLMClient, "stream", return_value=iter(["only"])):
            client = LLMClient.__new__(LLMClient)
            events = list(client.stream_events("one"))

        assert len(events) == 2
        assert isinstance(events[0], TokenEvent)
        assert events[0].text == "only"
        assert isinstance(events[1], ResultEvent)
        assert events[1].result == {"text": "only"}

    def test_kwargs_forwarded_to_stream(self):
        from gnat.agents.llm import LLMClient

        with patch.object(LLMClient, "stream", return_value=iter(["ok"])) as mock_stream:
            client = LLMClient.__new__(LLMClient)
            list(client.stream_events("p", temperature=0.5, max_tokens=100))

        mock_stream.assert_called_once_with("p", temperature=0.5, max_tokens=100)
