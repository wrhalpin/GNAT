# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.reports.custom_section
============================

Analyst-defined report sections.

A :class:`CustomSection` lets analysts define additional report content
by:

1. Specifying a filter query (STIX type + field filters)
2. Optionally calling specific :class:`~gnat.reports.aggregator.DataAggregator`
   methods to slice the aggregates
3. Passing the result through the synthesizer for AI-assisted narrative

Usage::

    from gnat.reports.custom_section import CustomSection

    # Add a custom "APT29 Focus" section for a specific campaign
    section = CustomSection(
        id       = "apt29_focus",
        title    = "APT29 — Cozy Bear Campaign Activity",
        stix_type = "threat-actor",
        filters  = {"aliases": "APT29"},
        prompt_hint = "Summarise APT29 activity focusing on credential theft TTPs.",
    )
    extra_content = section.render(aggregates, synthesizer=synthesizer)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable

from gnat.reports.templates import SectionSpec

logger = logging.getLogger(__name__)


@dataclass
class CustomSection(SectionSpec):
    """
    An analyst-defined :class:`~gnat.reports.templates.SectionSpec` with
    additional filter and prompt hints.

    Parameters
    ----------
    stix_type : str
        STIX type to query (e.g. ``"indicator"``, ``"threat-actor"``).
    filters : dict
        Field → value filters applied to objects of *stix_type*.
    aggregator_method : str
        Optional method name on :class:`~gnat.reports.aggregator.DataAggregator`
        to call for custom aggregation.
    prompt_hint : str
        Appended to the AI synthesis prompt for this section.
    custom_renderer : Callable | None
        Optional custom rendering function ``(data, aggregates) -> str``.
        When set, overrides default rendering.
    """

    stix_type:         str                         = ""
    filters:           dict[str, Any]              = field(default_factory=dict)
    aggregator_method: str                         = ""
    prompt_hint:       str                         = ""
    custom_renderer:   Callable | None             = None

    def render(
        self,
        aggregates: Any,
        synthesizer: Any = None,
        workspace_objects: list[Any] | None = None,
    ) -> str:
        """
        Render this custom section to a markdown string.

        Parameters
        ----------
        aggregates : ReportAggregates
        synthesizer : ReportSynthesizer, optional
            When provided, AI narrative is generated for this section.
        workspace_objects : list[STIXBase], optional
            Raw STIX objects to filter for this section.

        Returns
        -------
        str
            Rendered section content (markdown).
        """
        # Apply filters to workspace objects if provided
        filtered_objects = self._filter_objects(workspace_objects or [])

        # Build section data
        data: dict[str, Any] = {
            "section_id":   self.id,
            "section_title": self.title,
            "stix_type":    self.stix_type,
            "filters":      self.filters,
            "object_count": len(filtered_objects),
            "objects":      [
                self._summarise_object(obj)
                for obj in filtered_objects[:50]  # cap for prompt safety
            ],
        }

        # Optionally call aggregator method
        if self.aggregator_method and hasattr(aggregates, self.aggregator_method):
            try:
                method = getattr(aggregates, self.aggregator_method)
                data["aggregated"] = method() if callable(method) else method
            except Exception as exc:
                logger.warning("CustomSection %r: aggregator_method %r failed: %s",
                               self.id, self.aggregator_method, exc)

        # Custom renderer takes precedence
        if self.custom_renderer is not None:
            try:
                return str(self.custom_renderer(data, aggregates))
            except Exception as exc:
                logger.warning("CustomSection %r: custom_renderer failed: %s", self.id, exc)

        # AI-assisted synthesis
        if synthesizer is not None:
            return self._ai_render(data, synthesizer)

        # Plain fallback
        return self._plain_render(data)

    # ── Private helpers ─────────────────────────────────────────────────────────

    def _filter_objects(self, objects: list[Any]) -> list[Any]:
        """Apply stix_type and field filters to the object list."""
        result = objects
        if self.stix_type:
            result = [o for o in result if getattr(o, "type", "") == self.stix_type]
        for field_name, value in self.filters.items():
            filtered = []
            for obj in result:
                obj_val = getattr(obj, field_name, None)
                if obj_val is None:
                    # Check _properties dict
                    obj_val = (getattr(obj, "_properties", {}) or {}).get(field_name)
                if obj_val is None:
                    continue
                # Match: exact, list contains, or str contains
                if isinstance(obj_val, list):
                    if any(str(value).lower() in str(v).lower() for v in obj_val):
                        filtered.append(obj)
                elif str(value).lower() in str(obj_val).lower():
                    filtered.append(obj)
            result = filtered
        return result

    def _summarise_object(self, obj: Any) -> dict[str, Any]:
        """Extract a compact summary dict from a STIX object."""
        summary: dict[str, Any] = {}
        for attr in ("id", "type", "name", "description", "confidence", "created", "modified"):
            val = getattr(obj, attr, None)
            if val is not None:
                summary[attr] = str(val)
        return summary

    def _ai_render(self, data: dict[str, Any], synthesizer: Any) -> str:
        """Use the synthesizer to generate AI-assisted narrative."""
        objects_text = "\n".join(
            f"- {o.get('name', o.get('id', ''))} ({o.get('type', '')})"
            for o in data.get("objects", [])[:20]
        )
        prompt = (
            f"Generate a concise intelligence section titled '{self.title}'.\n"
            f"Object type: {self.stix_type or 'mixed'}\n"
            f"Count: {data['object_count']}\n"
            f"Sample objects:\n{objects_text}\n"
        )
        if self.prompt_hint:
            prompt += f"\nAdditional context: {self.prompt_hint}\n"
        try:
            if hasattr(synthesizer, "synthesize_section"):
                return synthesizer.synthesize_section(self.title, prompt)
            return f"## {self.title}\n\n{prompt}"
        except Exception as exc:
            logger.warning("CustomSection %r: AI synthesis failed: %s", self.id, exc)
            return self._plain_render(data)

    def _plain_render(self, data: dict[str, Any]) -> str:
        """Render a simple markdown table without AI assistance."""
        lines = [f"## {self.title}", ""]
        count = data.get("object_count", 0)
        if count == 0:
            lines.append("*No matching objects found.*")
            return "\n".join(lines)

        lines.append(f"**{count} object(s) matched.**\n")
        objects = data.get("objects", [])
        if objects:
            lines.append("| Name | Type | Confidence |")
            lines.append("|------|------|-----------|")
            for obj in objects[:25]:
                name  = obj.get("name", obj.get("id", "—"))
                typ   = obj.get("type", "—")
                conf  = obj.get("confidence", "—")
                lines.append(f"| {name} | {typ} | {conf} |")
        return "\n".join(lines)
