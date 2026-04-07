"""
gnat.analysis.copilot.gap_detector
====================================

Rule-based hypothesis gap detection — no LLM required.

Given a :class:`~gnat.analysis.investigations.Hypothesis` and its linked
evidence, the :class:`GapDetector` surfaces what is logically missing to
adequately support or refute the hypothesis.

Rules are keyed on keyword patterns found in the hypothesis ``statement``.
Each rule defines:

- A **description** of the gap ("No host-based indicator linked")
- The **severity** of the gap (CRITICAL / HIGH / MEDIUM / LOW)
- A **suggested action** the analyst should take

Gap rules
---------

+----------------------------+--------------------------------------------+
| Hypothesis keyword(s)      | Required evidence type(s)                  |
+============================+============================================+
| lateral movement / pivot   | ≥1 host-based observable (IP/hostname)     |
+----------------------------+--------------------------------------------+
| exfiltration / data theft  | ≥1 network traffic indicator               |
+----------------------------+--------------------------------------------+
| attribution / responsible  | ≥1 TTP/malware indicator + ≥1 infra IOC   |
+----------------------------+--------------------------------------------+
| ransomware / encrypted     | ≥1 file hash or YARA indicator             |
+----------------------------+--------------------------------------------+
| phishing / spear-phishing  | ≥1 email address or domain indicator       |
+----------------------------+--------------------------------------------+
| C2 / command and control   | ≥1 IP or domain indicator                  |
+----------------------------+--------------------------------------------+
| (any hypothesis)           | ≥1 supporting evidence artifact linked     |
+----------------------------+--------------------------------------------+

Usage::

    from gnat.analysis.copilot.gap_detector import GapDetector

    detector   = GapDetector()
    hypothesis = investigation.hypothesis[0]
    gaps       = detector.detect(hypothesis, investigation)
    for gap in gaps:
        print(f"[{gap.severity}] {gap.description}")
        print(f"  → {gap.suggested_action}")
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any


class GapSeverity(str, Enum):
    """Severity of a detected gap."""
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"


@dataclass
class GapRecommendation:
    """
    A single detected evidence gap with remediation guidance.

    Parameters
    ----------
    description : str
        What is missing.
    severity : GapSeverity
        How important this gap is to address.
    suggested_action : str
        Concrete analyst action to close the gap.
    rule_id : str
        Identifier of the rule that triggered this gap.
    """

    description:      str
    severity:         GapSeverity
    suggested_action: str
    rule_id:          str

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id":          self.rule_id,
            "description":      self.description,
            "severity":         self.severity.value,
            "suggested_action": self.suggested_action,
        }


# ── Rule definitions ──────────────────────────────────────────────────────────

@dataclass
class _GapRule:
    id:               str
    keywords:         list[str]           # any match triggers check
    check_fn:         Any                 # callable(hypothesis, investigation) -> bool (True = gap)
    description:      str
    severity:         GapSeverity
    suggested_action: str


def _has_ioc_type(investigation: Any, *ioc_types: str) -> bool:
    """True if any indicator or observable with a matching type is linked."""
    all_iocs: list[str] = list(investigation.indicators) + list(investigation.observables)
    # Simple heuristic: check if any IOC ID or raw value hints at the type
    type_patterns = {
        "host":    re.compile(r"hostname|workstation|server|\d{1,3}\.\d{1,3}", re.I),
        "network": re.compile(r"ipv4|ip-addr|domain|url|cidr|\d{1,3}\.\d{1,3}", re.I),
        "file":    re.compile(r"hash|md5|sha256|sha1|yara|file", re.I),
        "email":   re.compile(r"email|phish|@", re.I),
        "domain":  re.compile(r"domain|fqdn|\.", re.I),
        "ip":      re.compile(r"ip|addr|\d{1,3}\.\d{1,3}", re.I),
    }
    for ioc_type in ioc_types:
        pattern = type_patterns.get(ioc_type)
        if pattern and any(pattern.search(ioc_id) for ioc_id in all_iocs):
            return True
    return False


def _has_no_evidence(hypothesis: Any, _investigation: Any) -> bool:
    return (
        not hypothesis.supporting_evidence
        and not hypothesis.refuting_evidence
    )


_RULES: list[_GapRule] = [
    _GapRule(
        id               = "no-evidence",
        keywords         = [],  # always checked
        check_fn         = _has_no_evidence,
        description      = "No evidence artifacts linked to this hypothesis.",
        severity         = GapSeverity.CRITICAL,
        suggested_action = (
            "Link at least one supporting indicator, observable, or analyst note "
            "to this hypothesis before submitting for review."
        ),
    ),
    _GapRule(
        id               = "lateral-movement-no-host",
        keywords         = ["lateral movement", "lateral-movement", "pivot", "pivoting"],
        check_fn         = lambda hyp, inv: not _has_ioc_type(inv, "host", "network"),
        description      = "Lateral movement hypothesis lacks host-based or network observable.",
        severity         = GapSeverity.HIGH,
        suggested_action = (
            "Link a hostname, internal IP address, or network traffic indicator "
            "that demonstrates the movement path."
        ),
    ),
    _GapRule(
        id               = "exfiltration-no-network",
        keywords         = ["exfiltration", "data theft", "exfil", "stolen", "leaked"],
        check_fn         = lambda hyp, inv: not _has_ioc_type(inv, "network", "ip"),
        description      = "Exfiltration hypothesis lacks network traffic evidence.",
        severity         = GapSeverity.HIGH,
        suggested_action = (
            "Link a destination IP, domain, or URL observed during the suspected "
            "exfiltration window."
        ),
    ),
    _GapRule(
        id               = "attribution-no-ttp",
        keywords         = ["attributed", "attribution", "responsible", "actor", "group"],
        check_fn         = lambda hyp, inv: not inv.threat_actors and not _has_ioc_type(inv, "file", "network"),
        description      = "Attribution hypothesis lacks TTP evidence or linked threat-actor.",
        severity         = GapSeverity.HIGH,
        suggested_action = (
            "Link a STIX ThreatActor SDO or add indicators (malware hash, C2 domain) "
            "that corroborate the attribution claim."
        ),
    ),
    _GapRule(
        id               = "ransomware-no-hash",
        keywords         = ["ransomware", "encrypted", "ransom note", "locker"],
        check_fn         = lambda hyp, inv: not _has_ioc_type(inv, "file"),
        description      = "Ransomware hypothesis lacks file-hash or YARA indicator.",
        severity         = GapSeverity.MEDIUM,
        suggested_action = (
            "Collect a file hash (SHA-256 preferred) from the encrypted binary or "
            "ransom dropper and link it as an indicator."
        ),
    ),
    _GapRule(
        id               = "phishing-no-email-or-domain",
        keywords         = ["phishing", "spear-phishing", "spear phishing", "lure", "pretexting"],
        check_fn         = lambda hyp, inv: not _has_ioc_type(inv, "email", "domain"),
        description      = "Phishing hypothesis lacks email address or sender domain indicator.",
        severity         = GapSeverity.MEDIUM,
        suggested_action = (
            "Link the sender email address, lure domain, or URL from the phishing "
            "message headers."
        ),
    ),
    _GapRule(
        id               = "c2-no-network-ioc",
        keywords         = ["c2", "c&c", "command and control", "command-and-control", "beaconing"],
        check_fn         = lambda hyp, inv: not _has_ioc_type(inv, "ip", "domain"),
        description      = "C2 hypothesis lacks an IP address or domain indicator.",
        severity         = GapSeverity.HIGH,
        suggested_action = (
            "Extract the C2 IP or domain from network captures or EDR telemetry "
            "and link it as an indicator."
        ),
    ),
    _GapRule(
        id               = "no-campaign-linkage",
        keywords         = ["campaign", "operation", "wave", "cluster"],
        check_fn         = lambda hyp, inv: not inv.campaigns and len(inv.indicators) < 2,
        description      = "Campaign hypothesis has no linked STIX Campaign and fewer than 2 indicators.",
        severity         = GapSeverity.LOW,
        suggested_action = (
            "Link a STIX Campaign SDO and ensure at least two indicators are "
            "attributed to the same campaign activity."
        ),
    ),
]


# ── Detector ──────────────────────────────────────────────────────────────────

class GapDetector:
    """
    Detect evidence gaps in analytical hypotheses.

    Gap detection is entirely rule-based and requires no LLM or external
    service.

    Examples
    --------
    >>> detector = GapDetector()
    >>> gaps = detector.detect(hypothesis, investigation)
    >>> [g.rule_id for g in gaps]
    ['no-evidence']
    """

    def detect(
        self,
        hypothesis:    Any,
        investigation: Any,
    ) -> list[GapRecommendation]:
        """
        Detect evidence gaps for *hypothesis* within *investigation* context.

        Parameters
        ----------
        hypothesis : Hypothesis
            The hypothesis to evaluate.
        investigation : Investigation
            The investigation providing the evidence context.

        Returns
        -------
        list of GapRecommendation
            Detected gaps sorted by severity (CRITICAL first).
        """
        stmt = hypothesis.statement.lower()
        gaps: list[GapRecommendation] = []

        for rule in _RULES:
            # Always-checked rules have empty keywords list
            if rule.keywords and not any(kw in stmt for kw in rule.keywords):
                continue
            try:
                if rule.check_fn(hypothesis, investigation):
                    gaps.append(GapRecommendation(
                        rule_id          = rule.id,
                        description      = rule.description,
                        severity         = rule.severity,
                        suggested_action = rule.suggested_action,
                    ))
            except Exception:  # noqa: BLE001
                pass  # rule evaluation failure never blocks gap detection

        _ORDER = {GapSeverity.CRITICAL: 0, GapSeverity.HIGH: 1,
                  GapSeverity.MEDIUM: 2, GapSeverity.LOW: 3}
        gaps.sort(key=lambda g: _ORDER[g.severity])
        return gaps

    def detect_all(
        self,
        investigation: Any,
    ) -> dict[str, list[GapRecommendation]]:
        """
        Run gap detection for every hypothesis in *investigation*.

        Returns
        -------
        dict
            ``{hypothesis_id: [GapRecommendation, ...]}``.
        """
        return {
            h.id: self.detect(h, investigation)
            for h in investigation.hypothesis
        }

    def summary(self, gaps: list[GapRecommendation]) -> dict[str, Any]:
        """Return a count summary of gaps by severity."""
        from collections import Counter
        counts = Counter(g.severity.value for g in gaps)
        return {
            "total":    len(gaps),
            "critical": counts.get("critical", 0),
            "high":     counts.get("high", 0),
            "medium":   counts.get("medium", 0),
            "low":      counts.get("low", 0),
        }
