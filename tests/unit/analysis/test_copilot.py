"""
Unit tests for gnat.analysis.copilot (GapDetector + ReportDraftingAssistant)
"""

from __future__ import annotations

from unittest.mock import MagicMock

from gnat.analysis.copilot import (
    DraftResult,
    GapDetector,
    GapRecommendation,
    GapSeverity,
    ReportDraftingAssistant,
)

# ── Helpers ───────────────────────────────────────────────────────────────────


def _make_hypothesis(text: str) -> MagicMock:
    h = MagicMock()
    h.id = f"hyp-{text[:10].replace(' ', '-')}"
    h.statement = text
    h.status = "active"
    h.supporting_evidence = []
    h.refuting_evidence = []
    return h


def _make_investigation(
    hypotheses: list | None = None, indicators: list | None = None, observables: list | None = None
) -> MagicMock:
    inv = MagicMock()
    inv.hypothesis = hypotheses or []  # singular — matches detect_all()
    inv.indicators = indicators or []
    inv.observables = observables or []
    inv.threat_actors = []
    inv.campaigns = []
    inv.tags = []
    return inv


def _make_report(
    title: str = "Test Report",
    report_type: str = "incident",
    classification: str = "amber",
    authors: list | None = None,
    key_findings: list | None = None,
    evidence_links: list | None = None,
    executive_summary: str = "",
) -> MagicMock:
    r = MagicMock()
    r.title = title
    r.report_type = MagicMock(value=report_type)
    r.classification = MagicMock(label=classification)
    r.authors = authors or ["alice"]
    r.key_findings = key_findings or []
    r.evidence_links = evidence_links or []
    r.executive_summary = executive_summary
    return r


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


# ── GapDetector ───────────────────────────────────────────────────────────────


class TestGapDetector:
    def test_no_evidence_always_triggered_when_no_indicators(self):
        detector = GapDetector()
        hyp = _make_hypothesis("Attacker performed lateral movement")
        inv = _make_investigation(hypotheses=[hyp])
        gaps = detector.detect(hyp, inv)
        severities = {g.rule_id for g in gaps}
        assert "no-evidence" in severities

    def test_lateral_movement_no_host_triggered(self):
        detector = GapDetector()
        hyp = _make_hypothesis("The adversary performed lateral movement via SMB")
        inv = _make_investigation(hypotheses=[hyp])
        gaps = detector.detect(hyp, inv)
        rule_ids = {g.rule_id for g in gaps}
        assert "lateral-movement-no-host" in rule_ids

    def test_exfiltration_triggers_network_gap(self):
        detector = GapDetector()
        hyp = _make_hypothesis("Data was exfiltrated via HTTPS to external server")
        inv = _make_investigation(hypotheses=[hyp])
        gaps = detector.detect(hyp, inv)
        rule_ids = {g.rule_id for g in gaps}
        assert "exfiltration-no-network" in rule_ids

    def test_attribution_triggers_ttp_gap(self):
        detector = GapDetector()
        # "actor" is in the keywords list for attribution-no-ttp
        hyp = _make_hypothesis("Threat actor responsible for lateral movement")
        inv = _make_investigation(hypotheses=[hyp])
        gaps = detector.detect(hyp, inv)
        rule_ids = {g.rule_id for g in gaps}
        assert "attribution-no-ttp" in rule_ids

    def test_ransomware_triggers_hash_gap(self):
        detector = GapDetector()
        hyp = _make_hypothesis("Ransomware was deployed on target hosts")
        inv = _make_investigation(hypotheses=[hyp])
        gaps = detector.detect(hyp, inv)
        rule_ids = {g.rule_id for g in gaps}
        assert "ransomware-no-hash" in rule_ids

    def test_phishing_triggers_email_domain_gap(self):
        detector = GapDetector()
        hyp = _make_hypothesis("Phishing emails delivered the initial payload")
        inv = _make_investigation(hypotheses=[hyp])
        gaps = detector.detect(hyp, inv)
        rule_ids = {g.rule_id for g in gaps}
        assert "phishing-no-email-or-domain" in rule_ids

    def test_c2_triggers_network_gap(self):
        detector = GapDetector()
        hyp = _make_hypothesis("C2 communication was observed with external IP")
        inv = _make_investigation(hypotheses=[hyp])
        gaps = detector.detect(hyp, inv)
        rule_ids = {g.rule_id for g in gaps}
        assert "c2-no-network-ioc" in rule_ids

    def test_detect_all_returns_dict(self):
        detector = GapDetector()
        h1 = _make_hypothesis("Lateral movement via RDP")
        h2 = _make_hypothesis("Attributed to threat actor group")
        inv = _make_investigation(hypotheses=[h1, h2])
        result = detector.detect_all(inv)
        assert isinstance(result, dict)
        assert len(result) == 2

    def test_summary_counts_by_severity(self):
        detector = GapDetector()
        hyp = _make_hypothesis("Ransomware attack with exfiltration and attribution")
        inv = _make_investigation(hypotheses=[hyp])
        gaps = detector.detect(hyp, inv)
        summary = detector.summary(gaps)
        assert "total" in summary
        assert summary["total"] == len(gaps)

    def test_gap_recommendation_has_required_fields(self):
        detector = GapDetector()
        hyp = _make_hypothesis("Lateral movement via SMB")
        inv = _make_investigation(hypotheses=[hyp])
        gaps = detector.detect(hyp, inv)
        for gap in gaps:
            assert isinstance(gap, GapRecommendation)
            assert gap.rule_id
            assert isinstance(gap.severity, GapSeverity)
            assert gap.description
            assert gap.suggested_action

    def test_no_evidence_is_critical(self):
        detector = GapDetector()
        hyp = _make_hypothesis("Some hypothesis")
        inv = _make_investigation(hypotheses=[hyp])
        gaps = detector.detect(hyp, inv)
        no_evidence_gaps = [g for g in gaps if g.rule_id == "no-evidence"]
        assert all(g.severity == GapSeverity.CRITICAL for g in no_evidence_gaps)


# ── ReportDraftingAssistant ───────────────────────────────────────────────────


class TestReportDraftingAssistant:
    def test_no_llm_returns_placeholder(self):
        assistant = ReportDraftingAssistant(llm_client=None)
        report = _make_report(key_findings=[_make_finding("APT used PowerShell")])
        result = assistant.draft_executive_summary(report)
        assert isinstance(result, DraftResult)
        assert result.executive_summary != ""
        assert len(result.warnings) > 0

    def test_no_llm_warning_message(self):
        assistant = ReportDraftingAssistant(llm_client=None)
        result = assistant.draft_executive_summary(_make_report())
        assert any("No LLM" in w or "no LLM" in w.lower() for w in result.warnings)

    def test_llm_client_called(self):
        fake_llm = MagicMock()
        fake_llm.complete.return_value = {
            "content": "APT29 used spear-phishing to gain access.",
            "model": "claude-sonnet-4-5",
        }
        assistant = ReportDraftingAssistant(llm_client=fake_llm)
        report = _make_report(key_findings=[_make_finding("PowerShell execution")])
        result = assistant.draft_executive_summary(report)
        assert fake_llm.complete.called
        assert "APT29" in result.executive_summary

    def test_llm_failure_returns_draft_failed(self):
        fake_llm = MagicMock()
        fake_llm.complete.side_effect = RuntimeError("timeout")
        assistant = ReportDraftingAssistant(llm_client=fake_llm)
        result = assistant.draft_executive_summary(_make_report())
        assert "[DRAFT FAILED]" in result.executive_summary
        assert len(result.warnings) > 0

    def test_draft_key_findings_no_findings_returns_warning(self):
        assistant = ReportDraftingAssistant(llm_client=None)
        report = _make_report(key_findings=[])
        result = assistant.draft_key_findings_narrative(report)
        assert len(result.warnings) > 0

    def test_draft_full_merges_results(self):
        assistant = ReportDraftingAssistant(llm_client=None)
        report = _make_report(key_findings=[_make_finding("Indicator of compromise detected")])
        result = assistant.draft_full(report)
        assert isinstance(result, DraftResult)
        assert result.executive_summary != ""

    def test_draft_full_sums_token_counts(self):
        fake_llm = MagicMock()
        fake_llm.complete.return_value = {"content": "text", "model": "m"}
        assistant = ReportDraftingAssistant(llm_client=fake_llm)
        report = _make_report(key_findings=[_make_finding("Lateral movement via PsExec")])
        result = assistant.draft_full(report)
        # draft_full makes two LLM calls
        assert fake_llm.complete.call_count == 2

    def test_custom_prompt_template_used(self):
        custom_tmpl = (
            "TITLE: {title}\nTYPE: {report_type}\nTLP: {classification}\n"
            "AUTHORS: {authors}\nFINDINGS: {n_findings}\n"
            "{findings_block}\n{evidence_block}"
        )
        fake_llm = MagicMock()
        fake_llm.complete.return_value = {"content": "draft", "model": "m"}
        assistant = ReportDraftingAssistant(
            llm_client=fake_llm,
            summary_prompt_template=custom_tmpl,
        )
        report = _make_report()
        assistant.draft_executive_summary(report)
        call_args = fake_llm.complete.call_args[0][0]
        assert "TITLE:" in call_args

    def test_evidence_truncated_at_20(self):
        many_evidence = [_make_evidence(f"ev-{i}") for i in range(25)]
        fake_llm = MagicMock()
        fake_llm.complete.return_value = {"content": "ok", "model": "m"}
        assistant = ReportDraftingAssistant(llm_client=fake_llm)
        report = _make_report(evidence_links=many_evidence)
        assistant.draft_executive_summary(report)
        prompt = fake_llm.complete.call_args[0][0]
        # The truncation notice should appear
        assert "more" in prompt

    def test_draft_result_to_dict(self):
        result = DraftResult(
            executive_summary="Summary here.",
            key_findings_narrative="Findings narrative.",
            model="claude-3-5",
            prompt_tokens=200,
            completion_tokens=100,
            warnings=[],
        )
        d = result.to_dict()
        assert d["executive_summary"] == "Summary here."
        assert d["model"] == "claude-3-5"
        assert d["prompt_tokens"] == 200
