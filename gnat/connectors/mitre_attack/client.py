# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.mitre_attack.client
=======================================

MITRE ATT&CK TAXII 2.1 connector.

Authentication
--------------
None — MITRE's public TAXII server is anonymous. The server is rate-limited
to 10 requests per 10 minutes per source IP; this connector delegates rate
limiting to
:class:`~gnat.ingest.sources.mitre_taxii_reader.MitreAttackTAXIIReader`.

Configuration::

    [mitre_attack]
    host   = https://attack-taxii.mitre.org
    matrix = enterprise-attack   ; or mobile-attack, ics-attack

STIX Type Mapping
-----------------
ATT&CK data is already STIX 2.1, so ``to_stix`` is a near-identity
passthrough that adds an ``x_source_platform`` marker. The connector
exposes the following STIX types:

* ``attack-pattern`` — techniques / sub-techniques
* ``intrusion-set`` — groups (G####)
* ``malware`` — software (S####)
* ``tool`` — software (S####)
* ``campaign`` — campaigns (C####)
* ``course-of-action`` — mitigations (M####)
* ``x-mitre-tactic`` — tactics (TA####)
* ``x-mitre-matrix`` — matrix object
* ``relationship`` — ATT&CK relationships
* ``identity`` — MITRE Corporation identity
* ``marking-definition`` — TLP markings

Notes
-----
* Read-only. Write operations raise :class:`GNATClientError`.
* The connector lazily instantiates the underlying reader so importing
  this module does not require ``taxii2-client`` to be installed.
* Rate limiting is enforced inside the reader; callers do not need to
  throttle their own code.
"""

from __future__ import annotations

from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.utils.stix_helpers import utcnow

# STIX types that ATT&CK emits. Used for both filtering and validation.
_ATTACK_STIX_TYPES: frozenset[str] = frozenset(
    {
        "attack-pattern",
        "intrusion-set",
        "malware",
        "tool",
        "campaign",
        "course-of-action",
        "x-mitre-tactic",
        "x-mitre-matrix",
        "x-mitre-data-source",
        "x-mitre-data-component",
        "relationship",
        "identity",
        "marking-definition",
    }
)

_VALID_MATRICES = ("enterprise-attack", "mobile-attack", "ics-attack")


class MitreAttackClient(BaseClient, ConnectorMixin):
    """
    HTTP client for the MITRE ATT&CK TAXII 2.1 server.

    Parameters
    ----------
    host : str
        Base URL of the TAXII server. Defaults to
        ``"https://attack-taxii.mitre.org"``.
    matrix : str
        ATT&CK matrix name. One of ``"enterprise-attack"`` (default),
        ``"mobile-attack"``, ``"ics-attack"``.
    """

    TRUST_LEVEL: str = "untrusted_external"
    API_VERSION: str = "v21"
    API_PREFIX: str = "/api/v21"
    COST_UNIT: int = 10  # Bulk poll; MITRE rate-limits aggressively

    stix_type_map: dict[str, str] = {
        "attack-pattern": "enterprise-attack",
        "intrusion-set": "enterprise-attack",
        "malware": "enterprise-attack",
        "tool": "enterprise-attack",
        "campaign": "enterprise-attack",
        "course-of-action": "enterprise-attack",
        "x-mitre-tactic": "enterprise-attack",
        "x-mitre-matrix": "enterprise-attack",
    }

    def __init__(
        self,
        host: str = "https://attack-taxii.mitre.org",
        matrix: str = "enterprise-attack",
        **kwargs: Any,
    ) -> None:
        """Initialize MitreAttackClient."""
        if matrix not in _VALID_MATRICES:
            raise GNATClientError(
                f"Invalid MITRE ATT&CK matrix {matrix!r}. Valid values: {_VALID_MATRICES}"
            )
        super().__init__(host=host, **kwargs)
        self.matrix = matrix
        self._reader: Any = None  # lazy MitreAttackTAXIIReader
        self._cache: list[dict[str, Any]] | None = None

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """No authentication required for MITRE's public TAXII server."""
        self._auth_headers["Accept"] = "application/taxii+json;version=2.1"

    # ── Reader plumbing ────────────────────────────────────────────────────

    def _ensure_reader(self) -> Any:
        """Lazily create the underlying TAXII reader on first use."""
        if self._reader is None:
            from gnat.ingest.sources.mitre_taxii_reader import (
                MitreAttackTAXIIReader,
            )

            self._reader = MitreAttackTAXIIReader(matrix=self.matrix)
        return self._reader

    def _fetch_all(self) -> list[dict[str, Any]]:
        """Return all STIX objects for the configured matrix (cached)."""
        if self._cache is None:
            reader = self._ensure_reader()
            self._cache = list(reader)
        return self._cache

    # ── ConnectorMixin — CRUD ──────────────────────────────────────────────

    def health_check(self) -> bool:
        """
        Verify connectivity by instantiating the TAXII collection.

        Does not fetch any objects — this keeps rate-limit budget for real
        queries while still validating that the endpoint is reachable.
        """
        try:
            self._ensure_reader()
            return True
        except ImportError:
            # taxii2-client not installed; report unhealthy rather than crash
            return False
        except Exception:  # noqa: BLE001
            return False

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """
        Fetch a single ATT&CK object by STIX id or ATT&CK external id.

        ``object_id`` may be either a full STIX id (``attack-pattern--...``)
        or an ATT&CK identifier (``T1055``, ``G0007``, ``S0002``, etc.).
        """
        if stix_type not in _ATTACK_STIX_TYPES:
            raise GNATClientError(f"Unknown ATT&CK STIX type {stix_type!r}")
        target = object_id.strip()
        for obj in self._fetch_all():
            if obj.get("type") != stix_type:
                continue
            if obj.get("id") == target:
                return obj
            for ref in obj.get("external_references", []) or []:
                if ref.get("source_name") == "mitre-attack" and ref.get("external_id") == target:
                    return obj
        raise GNATClientError(
            f"{stix_type} {object_id!r} not found in MITRE ATT&CK matrix {self.matrix}"
        )

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        List ATT&CK objects of a given STIX type.

        ``filters`` currently supports a ``"name_contains"`` key that does
        a case-insensitive substring match against the object ``name``.
        """
        if stix_type not in _ATTACK_STIX_TYPES:
            raise GNATClientError(f"Unknown ATT&CK STIX type {stix_type!r}")
        objects = [o for o in self._fetch_all() if o.get("type") == stix_type]

        filters = dict(filters or {})
        name_contains = filters.get("name_contains", "")
        if name_contains:
            needle = str(name_contains).lower()
            objects = [o for o in objects if needle in str(o.get("name", "")).lower()]

        start = max(0, (int(page) - 1) * int(page_size))
        end = start + int(page_size)
        return objects[start:end]

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """MITRE ATT&CK is read-only — no write operations supported."""
        raise GNATClientError(
            "MITRE ATT&CK connector is read-only — no write operations supported."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """MITRE ATT&CK is read-only — no delete operations supported."""
        raise GNATClientError(
            "MITRE ATT&CK connector is read-only — no delete operations supported."
        )

    # ── Domain-specific helpers ────────────────────────────────────────────

    def get_technique(self, attack_id: str) -> dict[str, Any]:
        """Fetch an ATT&CK technique by ID (e.g. ``T1055``)."""
        return self.get_object("attack-pattern", attack_id)

    def get_group(self, attack_id: str) -> dict[str, Any]:
        """Fetch an ATT&CK group (intrusion-set) by ID (e.g. ``G0007``)."""
        return self.get_object("intrusion-set", attack_id)

    def get_software(self, attack_id: str) -> dict[str, Any]:
        """
        Fetch an ATT&CK software object by ID (e.g. ``S0002``).

        Tries ``malware`` first and falls back to ``tool``.
        """
        try:
            return self.get_object("malware", attack_id)
        except GNATClientError:
            return self.get_object("tool", attack_id)

    def list_tactics(self) -> list[dict[str, Any]]:
        """Return all tactics (``x-mitre-tactic``) for the configured matrix."""
        return self.list_objects("x-mitre-tactic", page_size=1000)

    def list_techniques(self) -> list[dict[str, Any]]:
        """Return all techniques (``attack-pattern``) for the configured matrix."""
        return self.list_objects("attack-pattern", page_size=10000)

    def list_groups(self) -> list[dict[str, Any]]:
        """Return all threat groups (``intrusion-set``)."""
        return self.list_objects("intrusion-set", page_size=1000)

    # ── ConnectorMixin — STIX translation ──────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """
        Convert a raw ATT&CK object to STIX 2.1.

        ATT&CK data is already STIX 2.1, so this is a near-identity
        passthrough that:

        * injects ``spec_version = "2.1"`` if missing,
        * stamps ``x_source_platform = "mitre_attack"``,
        * stamps the matrix name via ``x_attack_matrix``.
        """
        if not isinstance(native, dict):
            raise GNATClientError("MITRE ATT&CK to_stix expects a dict input")
        obj = dict(native)
        obj.setdefault("spec_version", "2.1")
        obj.setdefault("modified", utcnow())
        obj["x_source_platform"] = "mitre_attack"
        obj["x_attack_matrix"] = self.matrix
        return obj

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """MITRE ATT&CK is read-only. Returns an informational dict."""
        return {
            "note": (
                "MITRE ATT&CK connector is read-only. Use list_objects / "
                "get_technique / get_group / get_software for enrichment."
            ),
            "stix_id": stix_dict.get("id", ""),
        }
