# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.agents.copilot_prompts
=============================

Prompt templates for Investigation Copilot, organized by investigation phase.
Supports prompt caching via claude:cache_control for context reuse.
"""

from enum import Enum
from typing import Dict, List, Any


class QuestionCategory(str, Enum):
    """Types of clarifying questions."""
    SCOPE = "scope"
    TIMELINE = "timeline"
    IMPACT = "impact"
    ATTRIBUTION = "attribution"
    CONFIDENCE = "confidence"


GATHERING_QUESTIONS = {
    QuestionCategory.SCOPE: [
        "How many unique IOCs do we have in this investigation? (give a rough count)",
        "Are these IOCs from a single source or multiple sources?",
        "Do the IOCs cluster around a specific geography or sector?",
    ],
    QuestionCategory.IMPACT: [
        "What's the suspected impact of this activity? (lateral movement / data theft / infrastructure compromise / supply chain / unknown)",
        "Are we looking at a targeted attack or broad-based scanning?",
        "Do we have evidence of successful compromise, or just indicators of attempted access?",
    ],
    QuestionCategory.TIMELINE: [
        "When did this activity first appear in our logs? (date or 'unknown')",
        "Is this activity ongoing or historical?",
        "How long has this been happening? (days / weeks / months / years)",
    ],
}

HYPOTHESIZING_QUESTIONS = {
    QuestionCategory.ATTRIBUTION: [
        "Do you suspect a known threat actor is behind this? (If yes, name them; if no, say 'unknown')",
        "What's your confidence level in that attribution? (high / medium / low / none)",
        "Are there any historical campaigns this resembles?",
    ],
    QuestionCategory.CONFIDENCE: [
        "How confident are you in the IOC enrichment so far? (high / medium / low)",
        "Do we have any direct evidence (e.g., captured malware, emails) or just indicators?",
        "What's your confidence that these IOCs are actually malicious? (high / medium / low)",
    ],
}

TESTING_QUESTIONS = {
    QuestionCategory.SCOPE: [
        "Should we narrow the investigation scope based on what we've learned, or expand it?",
        "Are there any IOCs or hypotheses we should deprioritize?",
    ],
    QuestionCategory.IMPACT: [
        "Based on the enrichment, what's our updated assessment of impact?",
        "Do we need to involve response teams, or is this analysis-only?",
    ],
}

CLOSING_QUESTIONS = {
    QuestionCategory.CONFIDENCE: [
        "What's your final confidence in the hypothesis? (high / medium / low)",
        "Are there any outstanding gaps that should be documented?",
        "Should we escalate this to incident response, or close as analysis complete?",
    ],
}


def get_next_question(
    phase: str,
    investigation_state: Dict[str, Any],
    conversation_history: List[str],
) -> str:
    """
    Select next clarifying question based on phase and investigation state.

    Args:
        phase: Current copilot phase (GATHERING, HYPOTHESIZING, TESTING, CLOSING)
        investigation_state: Investigation data (IOC count, confidence, etc.)
        conversation_history: Previous questions asked

    Returns:
        Prompt for Claude to generate contextual question
    """
    if phase == "GATHERING":
        question_pool = GATHERING_QUESTIONS
    elif phase == "HYPOTHESIZING":
        question_pool = HYPOTHESIZING_QUESTIONS
    elif phase == "TESTING":
        question_pool = TESTING_QUESTIONS
    elif phase == "CLOSING":
        question_pool = CLOSING_QUESTIONS
    else:
        question_pool = GATHERING_QUESTIONS

    # Flatten questions from categories
    all_questions = []
    for category, questions in question_pool.items():
        all_questions.extend(questions)

    # Filter out already asked
    asked_set = set(conversation_history)
    unanswered = [q for q in all_questions if q not in asked_set]

    # If all questions asked, allow repeats (Claude will vary phrasing)
    candidates = unanswered if unanswered else all_questions

    return _build_question_selection_prompt(
        phase=phase,
        investigation_state=investigation_state,
        candidate_questions=candidates[:5],  # Top 5 candidates
    )


def _build_question_selection_prompt(
    phase: str,
    investigation_state: Dict[str, Any],
    candidate_questions: List[str],
) -> str:
    """Build Claude prompt to select contextual question."""
    ioc_count = investigation_state.get("ioc_count", 0)
    confidence = investigation_state.get("avg_confidence", 0.0)
    has_actor = investigation_state.get("suspected_actor")
    has_campaign = investigation_state.get("suspected_campaign")

    return f"""
You are an expert threat intelligence analyst guiding a colleague through an investigation.

Investigation phase: {phase}
IOC count: {ioc_count}
Average confidence: {confidence:.0%}
Suspected actor: {has_actor or 'unknown'}
Suspected campaign: {has_campaign or 'unknown'}

Pick ONE question from the list below that is most relevant and useful RIGHT NOW.
The question should advance the investigation — not repeat previous questions.
Keep your response to just the question, no preamble.

Candidate questions:
{_format_question_list(candidate_questions)}

What is your next clarifying question?
"""


def get_refinement_prompt(
    hypotheses: List[Dict[str, Any]],
    analyst_feedback: str,
) -> str:
    """
    Build prompt for hypothesis refinement based on analyst feedback.

    Args:
        hypotheses: Current hypotheses with confidence scores
        analyst_feedback: Analyst's response ("I'm confident", "This seems unlikely", etc.)

    Returns:
        Prompt for Claude to re-score hypotheses
    """
    return f"""
You are a threat intelligence analyst. The lead analyst has provided feedback on current hypotheses.

Current hypotheses:
{_format_hypothesis_list(hypotheses)}

Analyst feedback: "{analyst_feedback}"

Based on this feedback, re-score each hypothesis:
1. Increase confidence if feedback supports it
2. Decrease confidence if feedback contradicts it
3. Mark hypotheses as "likely" or "unlikely" based on the feedback

Return JSON:
{{
  "updated_hypotheses": [
    {{"text": "...", "confidence": 0.X, "status": "likely"}},
    ...
  ],
  "reasoning": "Brief explanation of score changes"
}}
"""


def get_next_step_prompt(
    investigation_state: Dict[str, Any],
    conversation_turns: int,
    hypotheses: List[Dict[str, Any]],
) -> str:
    """
    Build prompt to suggest next investigation step.

    Args:
        investigation_state: Current investigation data
        conversation_turns: Number of turns in conversation
        hypotheses: Current hypotheses

    Returns:
        Prompt for Claude to suggest action
    """
    return f"""
You are a threat intelligence analyst. You've been guiding an investigation.
Based on current progress, recommend the next step.

Investigation summary:
- IOC count: {investigation_state.get('ioc_count', 0)}
- Avg confidence: {investigation_state.get('avg_confidence', 0.0):.0%}
- Known actors: {', '.join(investigation_state.get('actors', []) or ['none'])}
- Known campaigns: {', '.join(investigation_state.get('campaigns', []) or ['none'])}
- Conversation turns so far: {conversation_turns}

Current hypotheses:
{_format_hypothesis_list(hypotheses)}

Recommend the next investigation step from this list:
1. Run automated enrichment on IOCs (ThreatQ, Recorded Future, VirusTotal)
2. Query for campaign overlap with historical data
3. Check for infrastructure reuse patterns
4. Correlate with threat actor profiles
5. Validate IOCs against known FP lists
6. Narrow investigation scope (exclude some IOCs or hypotheses)
7. Escalate to incident response
8. Close investigation (analysis complete)

Return JSON:
{{
  "recommended_step": "Step name from list above",
  "reason": "Brief explanation",
  "estimated_duration_seconds": 120,
  "metadata": {{"requires_manual_review": false}}
}}
"""


# ─── Utility helpers ───


def _format_question_list(questions: List[str]) -> str:
    """Format questions for display in prompt."""
    return "\n".join([f"{i+1}. {q}" for i, q in enumerate(questions)])


def _format_hypothesis_list(hypotheses: List[Dict[str, Any]]) -> str:
    """Format hypotheses for display in prompt."""
    if not hypotheses:
        return "- No hypotheses yet"

    lines = []
    for h in hypotheses:
        text = h.get("text", "Unknown")
        conf = h.get("confidence", 0.0)
        lines.append(f"- {text} (confidence: {conf:.0%})")

    return "\n".join(lines)


# ─── System prompts ───

COPILOT_SYSTEM_PROMPT = """
You are an expert threat intelligence analyst guiding junior analysts through complex investigations.

Your role:
1. Ask clarifying questions to narrow investigation scope
2. Validate hypotheses based on analyst feedback
3. Recommend next actions (enrichment, correlation, escalation)
4. Provide context and background on threat actors/campaigns when relevant
5. Explain investigation logic in plain language

Tone: Professional, concise, actionable. Avoid jargon unless the analyst uses it first.

Confidence scoring: When evaluating hypotheses, consider:
- Quality of IOC enrichment (trusted connectors score higher)
- Overlap with known campaigns
- Timing consistency
- Attribution confidence (is this actor definitively linked?)
- False positive risk (how often are these IOCs misidentified?)

When suggesting next steps:
- Prioritize high-confidence actions first
- Estimate execution time
- Flag if analyst approval is needed (e.g., "Escalate to IR?")
- Suggest stopping conditions (when is investigation "done"?)
"""

ASSISTANT_SYSTEM_PROMPT = """
You are a threat intelligence research assistant providing on-demand support.

Your role:
1. Suggest relevant connectors for enrichment (explain why each is useful)
2. Draft report sections (provide multiple tones: executive, technical, narrative)
3. Explain findings in plain language (connect to campaigns, actors, TTPs)
4. Help analysts search across connectors (provide query syntax and examples)
5. Summarize investigation progress and suggest improvements

Tone: Helpful, concise, educational. Explain "why" decisions matter.

When suggesting enrichment:
- Recommend 3-5 connectors ranked by relevance
- Estimate query time and cost impact
- Link to threat intel (e.g., "Recorded Future specializes in this actor")

When drafting sections:
- Offer multiple options (formal for executives, technical for SOC, narrative for reports)
- Provide 2-3 paragraphs max
- Include data (counts, dates, confidence) but keep prose readable

When explaining findings:
- Connect to known campaigns/actors (reference credible sources)
- Explain confidence/risk
- Suggest follow-up investigation paths
"""
