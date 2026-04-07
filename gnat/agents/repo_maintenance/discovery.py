# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Discovery and planning engine for connector compatibility maintenance."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import urllib3

from gnat.agents.repo_maintenance.models import (
    ChangeImpact,
    ConnectorDiscoveryResult,
    DriftSignal,
    ProbeResult,
    PullRequestPlan,
    RepoMaintenancePlan,
)
from gnat.agents.repo_maintenance.registry import ConnectorRegistry, ConnectorSpec, ProbeSpec


class DiscoveryEngine:
    """Probe upstream metadata and build a conservative repair plan."""

    def __init__(
        self,
        registry: ConnectorRegistry,
        baseline_dir: str | Path,
        repo_root: str | Path = ".",
        timeout: float = 10.0,
    ):
        self.registry = registry
        self.baseline_dir = Path(baseline_dir)
        self.repo_root = Path(repo_root)
        self.http = urllib3.PoolManager(
            timeout=urllib3.Timeout(connect=timeout, read=timeout),
        )

    def discover(self, connector: str) -> RepoMaintenancePlan:
        spec = self.registry.get(connector)
        probes = [self._run_probe(p) for p in spec.probes]
        signals = self._signals_from_probes(spec, probes)
        impact = self._classify(spec, signals)
        actions = self._recommended_actions(spec, impact, signals)
        discovery = ConnectorDiscoveryResult(
            connector=connector,
            impact=impact,
            probes=probes,
            signals=signals,
            recommended_actions=actions,
        )
        pr_plan = self._build_pr_plan(spec, discovery)
        return RepoMaintenancePlan(
            connector=connector,
            impact=impact,
            discovery=discovery,
            pull_request=pr_plan,
            files_to_touch=spec.files,
            confidence=_confidence_for(impact, probes, signals),
        )

    def persist_baseline(self, connector: str, plan: RepoMaintenancePlan) -> Path:
        self.baseline_dir.mkdir(parents=True, exist_ok=True)
        path = self.baseline_dir / f"{connector}.json"
        payload = {
            "connector": connector,
            "recorded_at": _utcnow_iso(),
            "impact": plan.impact.value,
            "probes": [probe.__dict__ for probe in plan.discovery.probes],
        }
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return path

    def _run_probe(self, probe: ProbeSpec) -> ProbeResult:
        if probe.target.startswith("file://"):
            target_path = self.repo_root / probe.target.removeprefix("file://")
            return self._file_probe(probe, target_path)
        try:
            response = self.http.request(probe.method, probe.target, headers=probe.headers)
            body = response.data.decode("utf-8", errors="replace")
            fingerprint = _fingerprint_text(_extract_pointer(body, probe.json_pointer))
            return ProbeResult(
                probe_type=probe.probe_type,
                target=probe.target,
                success=200 <= response.status < 300,
                status_code=response.status,
                latency_ms=None,
                fingerprint=fingerprint,
                payload_excerpt=body[:300],
            )
        except Exception as exc:  # pragma: no cover
            return ProbeResult(
                probe_type=probe.probe_type,
                target=probe.target,
                success=False,
                error=str(exc),
            )

    def _file_probe(self, probe: ProbeSpec, target_path: Path) -> ProbeResult:
        body = target_path.read_text(encoding="utf-8")
        fingerprint = _fingerprint_text(_extract_pointer(body, probe.json_pointer))
        return ProbeResult(
            probe_type=probe.probe_type,
            target=str(target_path),
            success=True,
            status_code=200,
            fingerprint=fingerprint,
            payload_excerpt=body[:300],
        )

    def _signals_from_probes(
        self,
        spec: ConnectorSpec,
        probes: list[ProbeResult],
    ) -> list[DriftSignal]:
        baseline = _load_previous_probe_fingerprints(self.baseline_dir / f"{spec.name}.json")
        signals: list[DriftSignal] = []
        for probe in probes:
            if not probe.success:
                signals.append(
                    DriftSignal(
                        kind="probe_failure",
                        severity="high",
                        summary=f"{probe.probe_type} probe failed for {spec.name}",
                        details={"target": probe.target, "error": probe.error or "unknown"},
                    )
                )
                continue
            previous = baseline.get(probe.target)
            if previous and previous != probe.fingerprint:
                signals.append(
                    DriftSignal(
                        kind="fingerprint_changed",
                        severity="medium",
                        summary=f"{probe.probe_type} fingerprint changed for {spec.name}",
                        details={
                            "target": probe.target,
                            "previous": previous,
                            "current": probe.fingerprint,
                        },
                    )
                )
        return signals

    def _classify(self, spec: ConnectorSpec, signals: list[DriftSignal]) -> ChangeImpact:
        if not signals:
            return ChangeImpact.NO_CHANGE
        if any(signal.kind == "probe_failure" for signal in signals):
            return ChangeImpact.SECURITY_REVIEW
        if spec.compatibility_strategy == "translation":
            return ChangeImpact.TRANSLATION_UPDATE
        if spec.compatibility_strategy == "versioned_adapter":
            return ChangeImpact.ADAPTER_UPDATE
        if spec.compatibility_strategy == "manual":
            return ChangeImpact.BREAKING_CHANGE
        return ChangeImpact.BACKWARD_COMPATIBLE

    def _recommended_actions(
        self,
        spec: ConnectorSpec,
        impact: ChangeImpact,
        signals: list[DriftSignal],
    ) -> list[str]:
        if impact == ChangeImpact.NO_CHANGE:
            return ["No action required; refresh baseline only."]
        actions = [
            f"Review connector package at {spec.package_path}.",
            "Update or add fixture coverage for changed upstream behavior.",
        ]
        if impact in {ChangeImpact.ADAPTER_UPDATE, ChangeImpact.BACKWARD_COMPATIBLE}:
            actions.append(
                "Patch client request/response handling while preserving existing method signatures."
            )
        if impact == ChangeImpact.TRANSLATION_UPDATE:
            actions.append("Update STIX translation logic and add golden bundle comparison tests.")
        if impact in {ChangeImpact.BREAKING_CHANGE, ChangeImpact.SECURITY_REVIEW}:
            actions.append("Open draft PR only and require maintainer review before merge.")
        if signals:
            actions.append(f"Document {len(signals)} discovery signal(s) in the PR body.")
        return actions

    def _build_pr_plan(
        self, spec: ConnectorSpec, discovery: ConnectorDiscoveryResult
    ) -> PullRequestPlan:
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        branch = f"bot/connector/{spec.name}/compat-{today}"
        labels = ["connector-maintenance", f"impact:{discovery.impact.value}"]
        draft = discovery.impact in {
            ChangeImpact.BREAKING_CHANGE,
            ChangeImpact.SECURITY_REVIEW,
            ChangeImpact.TRANSLATION_UPDATE,
        }
        title = f"Maintain {spec.name} connector compatibility"
        body_lines = [
            f"## Summary\nAutomated maintenance plan for `{spec.name}`.",
            f"\nImpact: `{discovery.impact.value}`",
            "\n### Recommended actions",
        ]
        body_lines.extend([f"- {item}" for item in discovery.recommended_actions])
        if discovery.signals:
            body_lines.append("\n### Discovery signals")
            body_lines.extend([f"- {signal.summary}" for signal in discovery.signals])
        return PullRequestPlan(
            branch_name=branch,
            title=title,
            body="\n".join(body_lines),
            labels=labels,
            draft=draft,
        )


def _extract_pointer(body: str, pointer: str | None) -> str:
    if not pointer:
        return body
    try:
        current: Any = json.loads(body)
    except json.JSONDecodeError:
        return body
    for part in pointer.strip("/").split("/"):
        if not part:
            continue
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list) and part.isdigit():
            index = int(part)
            current = current[index] if index < len(current) else None
        else:
            return body
    return json.dumps(current, sort_keys=True, default=str)


def _fingerprint_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _load_previous_probe_fingerprints(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    return {
        probe["target"]: probe.get("fingerprint", "")
        for probe in payload.get("probes", [])
        if probe.get("target")
    }


def _confidence_for(
    impact: ChangeImpact,
    probes: list[ProbeResult],
    signals: list[DriftSignal],
) -> float:
    if impact == ChangeImpact.NO_CHANGE:
        return 0.98
    success_ratio = sum(1 for probe in probes if probe.success) / max(len(probes), 1)
    penalty = 0.1 * len([signal for signal in signals if signal.severity == "high"])
    base = {
        ChangeImpact.BACKWARD_COMPATIBLE: 0.8,
        ChangeImpact.ADAPTER_UPDATE: 0.72,
        ChangeImpact.TRANSLATION_UPDATE: 0.62,
        ChangeImpact.BREAKING_CHANGE: 0.45,
        ChangeImpact.SECURITY_REVIEW: 0.35,
    }.get(impact, 0.5)
    return round(max(0.05, min(0.99, base * success_ratio - penalty)), 2)


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
