# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.plugins.huntgnat.coverage
=================================

ATT&CK coverage matrix — tracks which techniques have detection rules
and which are uncovered gaps.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from gnat.plugins.huntgnat.hunt_package import HuntPackage


@dataclass
class TechniqueCoverage:
    """Coverage status for a single ATT&CK technique."""

    technique_id: str = ""
    technique_name: str = ""
    rule_count: int = 0
    languages: list[str] = field(default_factory=list)
    packages: list[str] = field(default_factory=list)
    covered: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "rule_count": self.rule_count,
            "languages": list(self.languages),
            "packages": list(self.packages),
            "covered": self.covered,
        }


@dataclass
class CoverageMatrix:
    """
    ATT&CK technique × detection rule coverage matrix.

    Built from a collection of :class:`HuntPackage` objects.
    """

    techniques: dict[str, TechniqueCoverage] = field(default_factory=dict)
    total_techniques: int = 0
    covered_count: int = 0

    @property
    def coverage_pct(self) -> float:
        if self.total_techniques == 0:
            return 0.0
        return self.covered_count / self.total_techniques * 100

    @property
    def gaps(self) -> list[str]:
        return sorted(tid for tid, tc in self.techniques.items() if not tc.covered)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_techniques": self.total_techniques,
            "covered_count": self.covered_count,
            "coverage_pct": round(self.coverage_pct, 1),
            "gaps": self.gaps,
            "techniques": {tid: tc.to_dict() for tid, tc in self.techniques.items()},
        }


class CoverageAnalyzer:
    """Builds coverage matrices from hunt packages."""

    @staticmethod
    def build_matrix(
        packages: list[HuntPackage],
        all_techniques: list[str] | None = None,
    ) -> CoverageMatrix:
        """
        Build a coverage matrix from a list of hunt packages.

        Parameters
        ----------
        packages : list[HuntPackage]
        all_techniques : list[str], optional
            Complete list of ATT&CK technique IDs to track. If omitted,
            only techniques referenced by packages are included.
        """
        tech_map: dict[str, TechniqueCoverage] = {}

        if all_techniques:
            for tid in all_techniques:
                tech_map[tid] = TechniqueCoverage(technique_id=tid)

        for pkg in packages:
            for tid in pkg.techniques_covered:
                if tid not in tech_map:
                    tech_map[tid] = TechniqueCoverage(technique_id=tid)
                tc = tech_map[tid]
                tc.covered = True
                tc.rule_count += pkg.rule_count
                tc.packages.append(pkg.id)
                for rule in pkg.rules:
                    lang = rule.language.value
                    if lang not in tc.languages:
                        tc.languages.append(lang)

        covered = sum(1 for tc in tech_map.values() if tc.covered)
        return CoverageMatrix(
            techniques=tech_map,
            total_techniques=len(tech_map),
            covered_count=covered,
        )

    @staticmethod
    def find_gaps(
        matrix: CoverageMatrix,
        platform: str | None = None,
    ) -> list[str]:
        """Return technique IDs with no active rules."""
        if platform:
            return sorted(
                tid
                for tid, tc in matrix.techniques.items()
                if not tc.covered or platform not in tc.languages
            )
        return matrix.gaps
