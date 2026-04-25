"""
gnat.analysis.copilot.drafting
================================

LLM-backed report section drafting.

:class:`ReportDraftingAssistant` takes a structured set of
:class:`~gnat.reporting.models.Finding` and
:class:`~gnat.reporting.models.EvidenceLink` objects and generates a draft
executive summary and key-findings narrative via the GNAT
:class:`~gnat.agents.llm.LLMClient`.

The LLM is invoked only for *drafting* — it never modifies stored data
directly.  All output is returned as a :class:`DraftResult` for analyst
review before being applied to a :class:`~gnat.reporting.models.Report`.

Usage::

    from gnat.analysis.copilot.drafting import ReportDraftingAssistant

    assistant = ReportDraftingAssistant(llm_client=llm)
    result    = assistant.draft_executive_summary(report)

    print(result.executive_summary)
    # Apply after analyst review:
    service.update_summary(report.id, result.executive_summary)
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

_DEFAULT_SUMMARY_PROMPT = """\
You are a senior threat intelligence analyst writing an executive summary for a \
cybersecurity intelligence report. Use only the findings and evidence provided — \
do not invent details.

Report title: {title}
Report type:  {report_type}
TLP level:    {classification}
Authors:      {authors}

Key findings ({n_findings}):
{findings_block}

Supporting evidence:
{evidence_block}

Write a concise executive summary (3–5 sentences) suitable for senior leadership. \
Use plain language. Do not use bullet points. Focus on: what happened, who is \
affected, what the impact is, and what action is recommended.
"""

_DEFAULT_FINDINGS_PROMPT = """\
You are a senior threat intelligence analyst. Based on the following structured \
findings and evidence links, write a narrative key-findings section (1–2 \
sentences per finding) that an analyst can refine.

Report title: {title}
TLP level:    {classification}

Findings:
{findings_block}

Evidence links:
{evidence_block}

For each finding write a short narrative paragraph (1–3 sentences) that \
incorporates the supporting evidence. Prefix each paragraph with the finding \
statement in bold.
"""


@dataclass
class DraftResult:
    """
    The output of a drafting assistant call.

    Parameters
    ----------
    executive_summary : str
        Drafted executive summary text (markdown).
    key_findings_narrative : str
        Drafted key-findings narrative (markdown).
    model : str
        LLM model identifier used.
    prompt_tokens : int
        Approximate prompt token count.
    completion_tokens : int
        Approximate completion token count.
    warnings : list of str
        Any warnings generated during drafting.
    """

    executive_summary: str
    key_findings_narrative: str
    model: str = ""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "executive_summary": self.executive_summary,
            "key_findings_narrative": self.key_findings_narrative,
            "model": self.model,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "warnings": self.warnings,
        }


class ReportDraftingAssistant:
    """
    LLM-backed drafting assistant for report section generation.

    Parameters
    ----------
    llm_client : LLMClient, optional
        :class:`~gnat.agents.llm.LLMClient` instance.  If ``None``, a
        ``DraftResult`` with placeholder text and a warning is returned
        (no LLM available fallback).
    summary_prompt_template : str, optional
        Jinja2-style format string for the executive summary prompt.
    findings_prompt_template : str, optional
        Format string for the key-findings narrative prompt.
    max_tokens : int
        Maximum tokens to request from the LLM (default 1024).
    """

    def __init__(
        self,
        llm_client: Any | None = None,
        summary_prompt_template: str | None = None,
        findings_prompt_template: str | None = None,
        max_tokens: int = 1024,
    ) -> None:
        self._llm = llm_client
        self._summary_tmpl = summary_prompt_template or _DEFAULT_SUMMARY_PROMPT
        self._findings_tmpl = findings_prompt_template or _DEFAULT_FINDINGS_PROMPT
        self._max_tokens = max_tokens

    def draft_executive_summary(self, report: Any) -> DraftResult:
        """
        Draft an executive summary for *report*.

        Parameters
        ----------
        report : Report
            The report whose findings and evidence will be used as context.

        Returns
        -------
        DraftResult
        """
        findings_block = self._format_findings(report)
        evidence_block = self._format_evidence(report)

        prompt = self._summary_tmpl.format(
            title=report.title,
            report_type=report.report_type.value,
            classification=report.classification.label,
            authors=", ".join(report.authors) or "Unknown",
            n_findings=len(report.key_findings),
            findings_block=findings_block,
            evidence_block=evidence_block,
        )

        return self._call_llm(prompt, report)

    def draft_key_findings_narrative(self, report: Any) -> DraftResult:
        """
        Draft a narrative key-findings section for *report*.

        Returns
        -------
        DraftResult
        """
        if not report.key_findings:
            return DraftResult(
                executive_summary="",
                key_findings_narrative="",
                warnings=["No key findings to draft narrative for."],
            )

        findings_block = self._format_findings(report)
        evidence_block = self._format_evidence(report)

        prompt = self._findings_tmpl.format(
            title=report.title,
            classification=report.classification.label,
            findings_block=findings_block,
            evidence_block=evidence_block,
        )

        return self._call_llm(prompt, report)

    def draft_full(self, report: Any) -> DraftResult:
        """
        Draft both executive summary and key-findings narrative in one call.

        Makes two LLM calls (one per section) and merges results.

        Returns
        -------
        DraftResult
        """
        summary_result = self.draft_executive_summary(report)
        findings_result = self.draft_key_findings_narrative(report)

        return DraftResult(
            executive_summary=summary_result.executive_summary,
            key_findings_narrative=findings_result.key_findings_narrative,
            model=summary_result.model or findings_result.model,
            prompt_tokens=summary_result.prompt_tokens + findings_result.prompt_tokens,
            completion_tokens=summary_result.completion_tokens + findings_result.completion_tokens,
            warnings=summary_result.warnings + findings_result.warnings,
        )

    def draft_with_progress(
        self,
        report: Any,
        progress_callback: Callable[[float, str], None] | None = None,
    ) -> DraftResult:
        """
        Draft both sections with progress reporting at each stage.

        Identical to :meth:`draft_full` but invokes *progress_callback* at
        each major step so callers (UIs, job framework) can display live
        status.

        Parameters
        ----------
        report : Report
            The report whose findings and evidence will be used as context.
        progress_callback : callable, optional
            ``callback(progress: float, message: str)`` invoked at each step.
            *progress* is a fraction in ``[0.0, 1.0]``.

        Returns
        -------
        DraftResult
        """
        cb = progress_callback or (lambda p, m: None)

        cb(0.1, "Formatting findings")
        findings_block = self._format_findings(report)

        cb(0.3, "Formatting evidence")
        evidence_block = self._format_evidence(report)

        cb(0.5, "Querying LLM for executive summary")
        summary_prompt = self._summary_tmpl.format(
            title=report.title,
            report_type=report.report_type.value,
            classification=report.classification.label,
            authors=", ".join(report.authors) or "Unknown",
            n_findings=len(report.key_findings),
            findings_block=findings_block,
            evidence_block=evidence_block,
        )
        summary_result = self._call_llm(summary_prompt, report)

        cb(0.8, "Querying LLM for key findings narrative")
        findings_prompt = self._findings_tmpl.format(
            title=report.title,
            classification=report.classification.label,
            findings_block=findings_block,
            evidence_block=evidence_block,
        )
        findings_result = self._call_llm(findings_prompt, report)

        cb(1.0, "Draft complete")

        return DraftResult(
            executive_summary=summary_result.executive_summary,
            key_findings_narrative=findings_result.key_findings_narrative,
            model=summary_result.model or findings_result.model,
            prompt_tokens=summary_result.prompt_tokens + findings_result.prompt_tokens,
            completion_tokens=(
                summary_result.completion_tokens + findings_result.completion_tokens
            ),
            warnings=summary_result.warnings + findings_result.warnings,
        )

    # ── Internal ──────────────────────────────────────────────────────────────

    def _call_llm(self, prompt: str, report: Any) -> DraftResult:
        warnings: list[str] = []

        if self._llm is None:
            warnings.append("No LLM client configured — returning placeholder text.")
            return DraftResult(
                executive_summary=f"[DRAFT REQUIRED] {report.title}",
                key_findings_narrative="\n\n".join(
                    f"**{f.statement}**\n\n[Evidence review pending.]" for f in report.key_findings
                ),
                warnings=warnings,
            )

        try:
            response = self._llm.complete(prompt, max_tokens=self._max_tokens)
            text = response.get("content", "") if isinstance(response, dict) else str(response)
            model = response.get("model", "") if isinstance(response, dict) else ""
            return DraftResult(
                executive_summary=text.strip(),
                key_findings_narrative=text.strip(),
                model=model,
                warnings=warnings,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("ReportDraftingAssistant: LLM call failed: %s", exc)
            warnings.append(f"LLM call failed: {exc}")
            return DraftResult(
                executive_summary=f"[DRAFT FAILED] {report.title}",
                key_findings_narrative="",
                warnings=warnings,
            )

    @staticmethod
    def _format_findings(report: Any) -> str:
        if not report.key_findings:
            return "  (no findings yet)"
        lines = []
        for i, f in enumerate(report.key_findings, 1):
            conf = f.confidence.label if f.confidence else "unscored"
            ttps = ", ".join(f.mitre_techniques) if f.mitre_techniques else "none"
            lines.append(f"  {i}. [{conf}] {f.statement} (ATT&CK: {ttps})")
        return "\n".join(lines)

    @staticmethod
    def _format_evidence(report: Any) -> str:
        if not report.evidence_links:
            return "  (no evidence links yet)"
        lines = []
        for e in report.evidence_links[:20]:  # cap to avoid token explosion
            lines.append(
                f"  - [{e.link_type.value.upper()}] {e.statement} "
                f"(source: {e.artifact_source}, artifact: {e.artifact_type}:{e.artifact_id})"
            )
        if len(report.evidence_links) > 20:
            lines.append(f"  ... and {len(report.evidence_links) - 20} more")
        return "\n".join(lines)
