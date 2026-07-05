# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.sandgnat.client
==================================

SandGNAT connector — automated malware runtime analysis (GNAT-o-sphere).

SandGNAT detonates suspicious binaries in isolated Windows VMs, captures
behavioural artifacts (registry deltas, file I/O, network traffic,
process trees), runs a Linux static-analysis pre-stage (PE/ELF parsing,
CAPA, deep YARA, fuzzy hashing), and emits STIX 2.1 bundles. This
connector consumes its intake + export HTTP API; integration is
pull-based — SandGNAT never pushes to GNAT.

Authentication
--------------
Shared API key sent as ``X-API-Key`` (SandGNAT's ``INTAKE_API_KEY``)::

    [sandgnat]
    host    = https://sandgnat.lab.internal:8000
    api_key = <INTAKE_API_KEY value>

Key endpoints
-------------
* ``GET  /healthz``                        liveness probe
* ``POST /submit``                         multipart sample submission
* ``GET  /analyses``                       list + filters + pagination
* ``GET  /analyses/<uuid>``                one analysis job row
* ``GET  /analyses/<uuid>/bundle``         full STIX 2.1 bundle (409 until completed)
* ``GET  /analyses/<uuid>/static``         static-analysis findings
* ``GET  /analyses/<uuid>/similar``        LSH + lineage neighbours
* ``POST /analyses/<uuid>/investigation``  retroactive investigation tag

STIX Type Mapping
-----------------
``malware-analysis`` carries the job verdict/timing; ``file`` is the
submitted sample with its hash set; ``indicator`` is a SHA-256 file
pattern. Completed detonations also expose a full server-built STIX
bundle via :meth:`get_bundle` — prefer that for ingest, since it
includes process, network-traffic, and dropped-file objects this
connector does not re-derive.
"""

from __future__ import annotations

import os
import uuid
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.stix.version import CURRENT_SPEC_VERSION
from gnat.utils.stix_helpers import make_indicator_pattern, utcnow

_NAMESPACE_SANDGNAT = uuid.UUID("5a4d6a47-0001-45a4-9a47-5a4d6a475a4d")

_SUPPORTED_TYPES = ("malware-analysis", "file", "indicator")

# SandGNAT job lifecycle states (orchestrator.models.JobStatus).
_JOB_STATUSES = ("queued", "running", "completed", "failed", "quarantined")

# Investigation link types accepted by SandGNAT's intake validator.
_LINK_TYPES = ("confirmed", "inferred", "suggested")

# VT verdict → STIX malware-analysis result vocabulary.
_VERDICT_TO_RESULT = {
    "malicious": "malicious",
    "suspicious": "suspicious",
    "clean": "benign",
    "benign": "benign",
    "unknown": "unknown",
}


class SandGNATClient(BaseClient, ConnectorMixin):
    """
    HTTP client for the SandGNAT malware detonation sandbox.

    Parameters
    ----------
    host : str
        Base URL of the SandGNAT intake/export service.
    api_key : str
        Shared secret sent as ``X-API-Key`` (SandGNAT ``INTAKE_API_KEY``).
    """

    TRUST_LEVEL: str = "trusted_internal"
    COST_UNIT: int = 5

    stix_type_map: dict[str, str] = {
        "malware-analysis": "analyses",
        "file": "analyses",
        "indicator": "analyses",
    }

    def __init__(self, host: str = "", api_key: str = "", **kwargs: Any) -> None:
        super().__init__(host=host, **kwargs)
        self.api_key = api_key

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        if not self.api_key:
            raise GNATClientError("SandGNAT connector requires api_key in config.")
        self._auth_headers["X-API-Key"] = self.api_key

    # ── ConnectorMixin — CRUD ──────────────────────────────────────────────

    def health_check(self) -> bool:
        try:
            resp = self.get("/healthz")
            return isinstance(resp, dict) and resp.get("status") == "ok"
        except Exception:  # noqa: BLE001
            return False

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        if not object_id:
            raise GNATClientError("SandGNAT get_object requires a non-empty id")
        if stix_type not in _SUPPORTED_TYPES:
            raise GNATClientError(f"SandGNAT get_object does not support stix_type={stix_type!r}")
        resp = self.get(f"/analyses/{object_id}")
        if not isinstance(resp, dict):
            raise GNATClientError(
                f"SandGNAT returned unexpected payload for analysis {object_id!r}"
            )
        return dict(resp, _sandgnat_kind=stix_type)

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        List analysis jobs.

        Supported filters (all optional): ``sha256``, ``status``
        (queued/running/completed/failed/quarantined), ``since``
        (ISO-8601), ``investigation_id``, ``has_investigation`` (bool).
        """
        if stix_type not in _SUPPORTED_TYPES:
            raise GNATClientError(f"SandGNAT list_objects does not support stix_type={stix_type!r}")
        # Export API caps limit at 200 per request.
        limit = min(max(1, int(page_size)), 200)
        offset = max(0, (int(page) - 1) * limit)
        params: dict[str, Any] = {"limit": limit, "offset": offset}

        for key in ("sha256", "status", "since", "investigation_id"):
            value = (filters or {}).get(key)
            if value is not None:
                params[key] = value
        has_inv = (filters or {}).get("has_investigation")
        if has_inv is not None:
            params["has_investigation"] = "true" if has_inv else "false"

        resp = self.get("/analyses", params=params)
        items = resp.get("items", []) if isinstance(resp, dict) else []
        return [dict(r, _sandgnat_kind=stix_type) for r in items if isinstance(r, dict)]

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        raise GNATClientError(
            "SandGNAT analyses are created by detonation, not upsert — use "
            "submit_sample / submit_file to queue a sample, or "
            "set_investigation to tag a completed analysis."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        raise GNATClientError(
            "SandGNAT export API is read-only; analyses cannot be deleted remotely."
        )

    # ── Domain-specific helpers ────────────────────────────────────────────

    def submit_sample(
        self,
        data: bytes,
        name: str | None = None,
        priority: int = 5,
        force: bool = False,
        submitter: str | None = None,
        investigation_id: str | None = None,
        investigation_tenant_id: str | None = None,
        investigation_link_type: str | None = None,
    ) -> dict[str, Any]:
        """
        Submit sample bytes for detonation.

        Returns SandGNAT's IntakeReport: ``decision`` (queued / prioritized /
        duplicate / rejected), ``analysis_id``, hash set, VT verdict, and
        YARA pre-classification matches.
        """
        if not data:
            raise GNATClientError("submit_sample requires non-empty sample bytes")

        form: dict[str, Any] = {"priority": str(priority)}
        if force:
            form["force"] = "true"
        if submitter:
            form["submitter"] = submitter
        if investigation_id:
            form["investigation_id"] = investigation_id
        if investigation_tenant_id:
            form["investigation_tenant_id"] = investigation_tenant_id
        if investigation_link_type:
            form["investigation_link_type"] = investigation_link_type

        return self.post(
            "/submit",
            data=form,
            files={"file": (name or "sample.bin", data)},
        )

    def submit_file(self, filepath: str, **opts: Any) -> dict[str, Any]:
        """Submit a file from disk; see :meth:`submit_sample` for options."""
        if not os.path.isfile(filepath):
            raise GNATClientError(f"submit_file: {filepath!r} does not exist")
        with open(filepath, "rb") as fh:
            data = fh.read()
        return self.submit_sample(data, name=os.path.basename(filepath), **opts)

    def get_analysis(self, analysis_id: str) -> dict[str, Any]:
        """Fetch one analysis job row (any status)."""
        return self.get_object("malware-analysis", analysis_id)

    def get_bundle(self, analysis_id: str) -> dict[str, Any]:
        """
        Fetch the full server-built STIX 2.1 bundle for a completed analysis.

        SandGNAT returns 409 until the job reaches ``completed``; that
        surfaces here as a :class:`GNATClientError` with status 409.
        """
        resp = self.get(f"/analyses/{analysis_id}/bundle")
        if not isinstance(resp, dict) or resp.get("type") != "bundle":
            raise GNATClientError(
                f"SandGNAT returned a non-bundle payload for analysis {analysis_id!r}"
            )
        return resp

    def get_bundle_objects(self, analysis_id: str) -> list[dict[str, Any]]:
        """The bundle's object list, ready for workspace ingest."""
        return list(self.get_bundle(analysis_id).get("objects", []))

    def get_static_analysis(self, analysis_id: str) -> dict[str, Any]:
        """
        Static-analysis findings for a job: file format, sections,
        imports/exports, CAPA capabilities, deep YARA matches, plus the
        imphash/ssdeep/tlsh fingerprints. 404s if the static stage
        didn't run.
        """
        resp = self.get(f"/analyses/{analysis_id}/static")
        if not isinstance(resp, dict):
            raise GNATClientError(
                f"SandGNAT returned unexpected static payload for {analysis_id!r}"
            )
        return resp

    def get_similar(
        self,
        analysis_id: str,
        threshold: float = 0.5,
        limit: int = 25,
        flavour: str = "either",
    ) -> list[dict[str, Any]]:
        """
        LSH-banded similarity neighbours (byte / opcode trigram MinHash)
        plus near-duplicate lineage relations for an analysis.

        ``flavour`` is ``byte``, ``opcode``, or ``either``.
        """
        if flavour not in ("byte", "opcode", "either"):
            raise GNATClientError(f"invalid similarity flavour: {flavour!r}")
        resp = self.get(
            f"/analyses/{analysis_id}/similar",
            params={"threshold": threshold, "limit": limit, "flavour": flavour},
        )
        return resp.get("items", []) if isinstance(resp, dict) else []

    def set_investigation(
        self,
        analysis_id: str,
        investigation_id: str,
        link_type: str = "inferred",
        tenant_id: str | None = None,
        force: bool = False,
    ) -> dict[str, Any]:
        """
        Retroactively tag a completed analysis with a GNAT investigation.

        ``link_type`` must be ``confirmed``, ``inferred``, or ``suggested``
        (SandGNAT's intake validator vocabulary). SandGNAT 409s if a tag is
        already set unless ``force=True``. This is the connector's only
        write besides sample submission.
        """
        if not investigation_id:
            raise GNATClientError("set_investigation requires investigation_id")
        if link_type not in _LINK_TYPES:
            raise GNATClientError(f"invalid link_type {link_type!r}; must be one of {_LINK_TYPES}")
        body: dict[str, Any] = {
            "investigation_id": investigation_id,
            "link_type": link_type,
        }
        if tenant_id:
            body["tenant_id"] = tenant_id
        params = {"force": "true"} if force else None
        return self.post(f"/analyses/{analysis_id}/investigation", json=body, params=params)

    def list_for_investigation(self, investigation_id: str) -> list[dict[str, Any]]:
        """All analyses tagged with a GNAT investigation id."""
        return self.list_objects("malware-analysis", filters={"investigation_id": investigation_id})

    # ── ConnectorMixin — STIX translation ──────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """
        Convert an analysis job row to a STIX object.

        The ``_sandgnat_kind`` tag stamped by get_object/list_objects picks
        the view; bare rows default to ``malware-analysis``. For completed
        jobs, prefer :meth:`get_bundle_objects` — the server bundle carries
        the full behavioural graph.
        """
        if not isinstance(native, dict):
            raise GNATClientError("SandGNAT to_stix expects a dict input")

        kind = native.get("_sandgnat_kind") or "malware-analysis"
        if kind == "file":
            return self._to_stix_file(native)
        if kind == "indicator":
            return self._to_stix_indicator(native)
        return self._to_stix_malware_analysis(native)

    def _hashes(self, native: dict[str, Any]) -> dict[str, str]:
        hashes: dict[str, str] = {}
        if native.get("sample_hash_sha256"):
            hashes["SHA-256"] = native["sample_hash_sha256"]
        if native.get("sample_hash_sha1"):
            hashes["SHA-1"] = native["sample_hash_sha1"]
        if native.get("sample_hash_md5"):
            hashes["MD5"] = native["sample_hash_md5"]
        return hashes

    def _to_stix_malware_analysis(self, native: dict[str, Any]) -> dict[str, Any]:
        analysis_id = str(native.get("id", ""))
        sha256 = native.get("sample_hash_sha256") or ""
        verdict = (native.get("vt_verdict") or "unknown").lower()
        result = _VERDICT_TO_RESULT.get(verdict, "unknown")

        stix_uuid = uuid.uuid5(_NAMESPACE_SANDGNAT, f"malware-analysis|{analysis_id}")
        obj: dict[str, Any] = {
            "type": "malware-analysis",
            "id": f"malware-analysis--{stix_uuid}",
            "spec_version": CURRENT_SPEC_VERSION,
            "created": utcnow(),
            "modified": utcnow(),
            "product": "sandgnat",
            "result": result,
            "x_sandgnat": {
                "analysis_id": analysis_id,
                "status": native.get("status"),
                "sample_name": native.get("sample_name"),
                "sha256": sha256,
                "evasion_observed": bool(native.get("evasion_observed")),
                "yara_matches": list(native.get("yara_matches") or []),
                "vt_detection_count": native.get("vt_detection_count"),
                "vt_total_engines": native.get("vt_total_engines"),
                "investigation_id": native.get("investigation_id"),
                "imphash": native.get("imphash"),
                "ssdeep": native.get("ssdeep"),
                "tlsh": native.get("tlsh"),
            },
        }
        if native.get("started_at"):
            obj["analysis_started"] = native["started_at"]
        if native.get("completed_at"):
            obj["analysis_ended"] = native["completed_at"]
        return obj

    def _to_stix_file(self, native: dict[str, Any]) -> dict[str, Any]:
        sha256 = native.get("sample_hash_sha256") or ""
        stix_uuid = uuid.uuid5(_NAMESPACE_SANDGNAT, f"file|{sha256}")
        obj: dict[str, Any] = {
            "type": "file",
            "id": f"file--{stix_uuid}",
            "spec_version": CURRENT_SPEC_VERSION,
            "hashes": self._hashes(native),
            "x_sandgnat": {"analysis_id": str(native.get("id", ""))},
        }
        if native.get("sample_name"):
            obj["name"] = native["sample_name"]
        if native.get("sample_size_bytes") is not None:
            obj["size"] = native["sample_size_bytes"]
        if native.get("sample_mime_type"):
            obj["mime_type"] = native["sample_mime_type"]
        return obj

    def _to_stix_indicator(self, native: dict[str, Any]) -> dict[str, Any]:
        sha256 = native.get("sample_hash_sha256") or ""
        if not sha256:
            raise GNATClientError("SandGNAT indicator conversion requires sample_hash_sha256")
        verdict = (native.get("vt_verdict") or "unknown").lower()
        stix_uuid = uuid.uuid5(_NAMESPACE_SANDGNAT, f"indicator|{sha256}")
        return {
            "type": "indicator",
            "id": f"indicator--{stix_uuid}",
            "spec_version": CURRENT_SPEC_VERSION,
            "created": utcnow(),
            "modified": utcnow(),
            "pattern": make_indicator_pattern("file:sha256", sha256),
            "pattern_type": "stix",
            "valid_from": utcnow(),
            "name": f"SandGNAT: {native.get('sample_name') or sha256}",
            "description": f"SandGNAT detonation verdict: {verdict}",
            "labels": ["malicious-activity"],
            "x_sandgnat": {
                "analysis_id": str(native.get("id", "")),
                "verdict": verdict,
            },
        }

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """
        Extract a SandGNAT lookup descriptor from a STIX object.

        Pulls a SHA-256 from a ``file`` SCO's hashes or an ``indicator``'s
        file pattern, suitable for ``list_objects(filters={"sha256": ...})``.
        Sample *submission* needs raw bytes — use :meth:`submit_sample`.
        """
        if not isinstance(stix_dict, dict):
            raise GNATClientError("SandGNAT from_stix expects a dict input")

        sha256 = ""
        if stix_dict.get("type") == "file":
            hashes = stix_dict.get("hashes") or {}
            sha256 = hashes.get("SHA-256") or hashes.get("sha256") or ""
        elif stix_dict.get("type") == "indicator":
            pattern = stix_dict.get("pattern") or ""
            marker = "file:hashes.'SHA-256' = '"
            start = pattern.find(marker)
            if start != -1:
                start += len(marker)
                end = pattern.find("'", start)
                if end != -1:
                    sha256 = pattern[start:end]

        return {
            "sha256": sha256.lower(),
            "stix_id": stix_dict.get("id", ""),
        }
