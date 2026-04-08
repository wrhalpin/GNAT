# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.search.mixin
====================

:class:`STIXSearchMixin` — optional mixin for :class:`~gnat.orm.base.STIXBase`
subclasses that adds a ``to_search_doc()`` method.

The mixin is deliberately separate from ``STIXBase`` so that:

* The ORM has zero dependency on the search layer.
* Individual SDO/SCO classes can override ``_search_text_fields`` to
  control exactly which fields get flattened into ``text_content``.
* The sidecar can be completely absent and nothing breaks.

Design
------
Solr receives a flat document containing:

``id``
    The STIX object ID — the primary key linking Solr back to the
    source of truth.  Solr never owns this data.

``stix_type``
    Allows Solr-side type filtering without a round-trip to Postgres.

``source_platform``
    Which connector produced the object (populated by the pipeline).

``created`` / ``modified``
    ISO-8601 strings; Solr ``pdate`` fields for range queries.

``text_content``
    All human-readable text fields concatenated and deduplicated.
    This is the *only* field used for full-text queries.
    It is marked ``stored="false"`` in the Solr schema — it exists
    purely for inverted-index construction and is never returned.

``display_name``
    A single best-effort label for display in search results
    (``name``, ``value``, ``pattern``, first alias — whichever
    is non-empty first).  Stored but not tokenised; used for
    highlighting only.

Subclass customisation
----------------------
Override ``_search_text_fields`` to declare which ``_properties``
keys to include::

    class ThreatActor(STIXSearchMixin, STIXBase):
        stix_type = "threat-actor"
        _search_text_fields = [
            "name", "description", "aliases",
            "goals", "resource_level", "sophistication",
        ]

If a subclass does *not* define ``_search_text_fields``, the mixin
falls back to indexing every string-valued ``_properties`` key that
is not in :data:`_STRUCTURED_FIELDS`.  This is safe for v1 since you
control the schema; revisit if you ingest third-party STIX that carries
very large blob fields.

Fields explicitly excluded from FT indexing
--------------------------------------------
:data:`_STRUCTURED_FIELDS` lists keys that are always pure structured
data and should never end up in ``text_content``:

* ``pattern_type``, ``spec_version`` — vocabulary strings, not prose
* ``confidence``, ``score``, ``priority`` — numerics stored as strings
* ``tlp``, ``traffic_light_protocol`` — short vocab tokens
* ``external_references`` — nested JSON; not useful as raw text

These fields belong in your Postgres layer, queried as predicates.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    pass  # avoid circular imports


# Fields that are purely structural — never go into text_content.
_STRUCTURED_FIELDS: frozenset = frozenset(
    {
        "type",
        "spec_version",
        "pattern_type",
        "confidence",
        "score",
        "priority",
        "severity",
        "tlp",
        "traffic_light_protocol",
        "external_references",
        "object_marking_refs",
        "granular_markings",
        "revoked",
        "labels",  # short vocab tokens; index separately if needed
        "created_by_ref",
        "relationship_type",
        "source_ref",
        "target_ref",
    }
)


class STIXSearchMixin:
    """
    Mixin that adds full-text search document generation to any
    :class:`~gnat.orm.base.STIXBase` subclass.

    Apply **before** ``STIXBase`` in the MRO::

        class ThreatActor(STIXSearchMixin, STIXBase):
            ...

    Class Attributes
    ----------------
    _search_text_fields : list of str
        Override in subclasses to restrict which ``_properties`` keys
        contribute to ``text_content``.  If empty or absent the mixin
        uses all string-valued properties not in :data:`_STRUCTURED_FIELDS`.

    _search_display_priority : list of str
        Ordered list of field names tried when constructing
        ``display_name``.  First non-empty value wins.
    """

    _search_text_fields: list[str] = []
    _search_display_priority: list[str] = [
        "name",
        "value",
        "pattern",
        "subject",
        "display_name",
        "title",
        "description",
    ]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def to_search_doc(
        self,
        source_platform: str = "",
        extra_fields: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Produce a flat Solr document dict for this STIX object.

        Parameters
        ----------
        source_platform : str, optional
            Name of the platform connector that produced this object
            (e.g. ``"threatq"``, ``"recordedfuture"``).  Stored in Solr
            for faceting but not used in FT queries.
        extra_fields : dict, optional
            Any additional key/value pairs to merge into the document.
            Useful for pipeline-level metadata (feed name, batch ID, etc.)
            without polluting the ORM.

        Returns
        -------
        dict
            Flat document ready to POST to ``/solr/<collection>/update``.
        """
        doc: dict[str, Any] = {
            "id": self.id,  # type: ignore[attr-defined]
            "stix_type": self.stix_type,  # type: ignore[attr-defined]
            "created": self.created,  # type: ignore[attr-defined]
            "modified": self.modified,  # type: ignore[attr-defined]
            "source_platform": source_platform,
            "display_name": self._build_display_name(),
            "text_content": self._build_text_content(),
        }
        if extra_fields:
            doc.update(extra_fields)
        return doc

    # ------------------------------------------------------------------
    # Helpers (override freely in subclasses)
    # ------------------------------------------------------------------

    def _build_display_name(self) -> str:
        """Return the first non-empty value from ``_search_display_priority``."""
        props = self._properties  # type: ignore[attr-defined]
        for field in self._search_display_priority:
            val = props.get(field)
            if val and isinstance(val, str):
                return val.strip()
            # Aliases list — use first entry
            if field == "aliases" and isinstance(val, list) and val:
                return str(val[0]).strip()
        return self.id  # type: ignore[attr-defined]

    def _build_text_content(self) -> str:
        """
        Flatten the relevant ``_properties`` into a single text blob.

        Deduplicates tokens so repeated field values don't inflate TF scores.
        List values (e.g. ``aliases``) are joined with spaces.
        Nested dicts/lists beyond one level are JSON-serialised as a last
        resort — you get searchability, not beauty.
        """
        props = self._properties  # type: ignore[attr-defined]

        if self._search_text_fields:
            keys = self._search_text_fields
        else:
            keys = [k for k in props if k not in _STRUCTURED_FIELDS]

        parts: list[str] = []
        seen: set = set()

        def _add(token: str) -> None:
            """Internal helper for add."""
            t = token.strip()
            if t and t not in seen:
                seen.add(t)
                parts.append(t)

        for key in keys:
            val = props.get(key)
            if val is None:
                continue
            if isinstance(val, str):
                _add(val)
            elif isinstance(val, list):
                for item in val:
                    if isinstance(item, str):
                        _add(item)
                    elif isinstance(item, dict):
                        # e.g. external_references — shouldn't be here
                        # after _STRUCTURED_FIELDS filter, but be safe
                        import json as _json

                        _add(_json.dumps(item, separators=(",", ":")))
            elif isinstance(val, dict):
                import json as _json

                _add(_json.dumps(val, separators=(",", ":")))
            elif isinstance(val, (int, float)):
                # Numbers surface in keyword searches ("score:85" etc.)
                _add(str(val))

        return " ".join(parts)
