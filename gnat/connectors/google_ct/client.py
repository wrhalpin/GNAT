# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.google_ct.client
====================================

Google Certificate Transparency log API connector.

Google operates a number of public RFC 6962 logs (Argon, Xenon, etc.)
exposed at ``ct.googleapis.com/logs/<log>/``. This connector wraps the
read-side endpoints::

    GET /ct/v1/get-sth                           # signed tree head
    GET /ct/v1/get-entries?start=N&end=M         # leaf entries
    GET /ct/v1/get-roots                         # accepted root CAs
    GET /ct/v1/get-proof-by-hash?hash=...        # inclusion proof

Configuration::

    [google_ct]
    host = https://ct.googleapis.com
    log  = logs/eu1/xenon2026

The ``log`` setting is the path prefix for a specific log; switch logs
by changing the config or passing ``log=`` to the helper methods.
"""

from __future__ import annotations

import uuid
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.utils.stix_helpers import utcnow

_NAMESPACE_GCT = uuid.UUID("60061ec7-0001-4a1e-9b1e-60061ec7c0fe")


class GoogleCTClient(BaseClient, ConnectorMixin):
    """HTTP client for Google's Certificate Transparency logs."""

    TRUST_LEVEL: str = "untrusted_external"
    API_VERSION: str = "v1"
    API_PREFIX: str = "/ct/v1"
    COST_UNIT: int = 1

    stix_type_map: dict[str, str] = {"x509-certificate": "get-entries"}

    def __init__(
        self,
        host: str = "https://ct.googleapis.com",
        log: str = "logs/eu1/xenon2026",
        **kwargs: Any,
    ) -> None:
        """Initialize GoogleCTClient."""
        super().__init__(host=host, **kwargs)
        self.log = (log or "").strip("/")

    def authenticate(self) -> None:
        """Google CT logs require no authentication."""
        self._auth_headers["Accept"] = "application/json"

    def health_check(self) -> bool:
        """Fetch the signed tree head as a liveness probe."""
        try:
            self.get_sth()
            return True
        except Exception:  # noqa: BLE001
            return False

    def _path(self, suffix: str, log: str | None = None) -> str:
        """Compose a full path under the configured log prefix."""
        log_prefix = (log or self.log).strip("/")
        if not log_prefix:
            raise GNATClientError(
                "GoogleCT requires a log path (e.g. logs/eu1/xenon2026)"
            )
        return f"/{log_prefix}/ct/v1/{suffix}"

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch a single CT entry by leaf index (passed as ``object_id``)."""
        if not object_id:
            raise GNATClientError("GoogleCT get_object requires a non-empty index")
        if stix_type != "x509-certificate":
            raise GNATClientError(
                f"GoogleCT get_object does not support stix_type={stix_type!r}"
            )
        try:
            idx = int(object_id)
        except (TypeError, ValueError) as exc:
            raise GNATClientError(
                f"GoogleCT get_object expects a numeric leaf index, got {object_id!r}"
            ) from exc
        resp = self.get(
            self._path("get-entries"),
            params={"start": idx, "end": idx},
        )
        entries = resp.get("entries", []) if isinstance(resp, dict) else []
        if not entries:
            raise GNATClientError(
                f"GoogleCT returned no entry for leaf_index={idx}"
            )
        return dict(entries[0], _gct_kind="entry", _gct_index=idx)

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """List CT entries by ``[start, end]`` range or roots."""
        filters = dict(filters or {})
        if stix_type != "x509-certificate":
            raise GNATClientError(
                f"GoogleCT list_objects does not support stix_type={stix_type!r}"
            )
        kind = (filters.get("kind") or "entries").lower()
        if kind == "roots":
            resp = self.get(self._path("get-roots"))
            roots = resp.get("certificates", []) if isinstance(resp, dict) else []
            return [
                {"_gct_kind": "root", "der_b64": d}
                for d in roots
                if isinstance(d, str)
            ]
        start = int(filters.get("start") or 0)
        end = int(filters.get("end") or (start + max(1, int(page_size)) - 1))
        resp = self.get(
            self._path("get-entries"),
            params={"start": start, "end": end},
        )
        entries = resp.get("entries", []) if isinstance(resp, dict) else []
        out: list[dict[str, Any]] = []
        for offset, entry in enumerate(entries):
            if isinstance(entry, dict):
                out.append(
                    dict(entry, _gct_kind="entry", _gct_index=start + offset)
                )
        return out

    def upsert_object(
        self, stix_type: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """GoogleCT connector is read-only."""
        raise GNATClientError(
            "GoogleCT connector is read-only — RFC 6962 logs accept "
            "submissions only via add-chain/add-pre-chain which are not "
            "exposed by this connector."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """GoogleCT connector is read-only."""
        raise GNATClientError(
            "GoogleCT connector is read-only — CT logs are append-only."
        )

    # ── Domain-specific helpers ────────────────────────────────────────────

    def get_sth(self, log: str | None = None) -> dict[str, Any]:
        """Return the current signed tree head for a log."""
        resp = self.get(self._path("get-sth", log=log))
        if not isinstance(resp, dict):
            raise GNATClientError("GoogleCT get_sth returned a non-dict payload")
        return dict(resp, _gct_kind="sth")

    def get_entries(
        self, start: int, end: int, log: str | None = None
    ) -> list[dict[str, Any]]:
        """Return entries in the half-open range ``[start, end]``."""
        resp = self.get(
            self._path("get-entries", log=log),
            params={"start": int(start), "end": int(end)},
        )
        entries = resp.get("entries", []) if isinstance(resp, dict) else []
        return [
            dict(e, _gct_kind="entry", _gct_index=int(start) + i)
            for i, e in enumerate(entries)
            if isinstance(e, dict)
        ]

    def get_roots(self, log: str | None = None) -> list[str]:
        """Return base64-DER root certificates accepted by a log."""
        resp = self.get(self._path("get-roots", log=log))
        roots = resp.get("certificates", []) if isinstance(resp, dict) else []
        return [d for d in roots if isinstance(d, str)]

    def get_proof_by_hash(
        self,
        leaf_hash: str,
        tree_size: int,
        log: str | None = None,
    ) -> dict[str, Any]:
        """Return an inclusion proof for a leaf hash."""
        resp = self.get(
            self._path("get-proof-by-hash", log=log),
            params={"hash": leaf_hash, "tree_size": int(tree_size)},
        )
        if not isinstance(resp, dict):
            raise GNATClientError(
                "GoogleCT get_proof_by_hash returned a non-dict payload"
            )
        return dict(resp, _gct_kind="proof")

    # ── ConnectorMixin — STIX translation ──────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert a Google CT record to a STIX 2.1 x509-certificate stub."""
        if not isinstance(native, dict):
            raise GNATClientError("GoogleCT to_stix expects a dict input")

        kind = native.get("_gct_kind") or "entry"

        if kind == "sth":
            tree_size = native.get("tree_size") or 0
            timestamp = native.get("timestamp") or 0
            stix_uuid = uuid.uuid5(
                _NAMESPACE_GCT, f"x-google-ct-sth|{self.log}|{tree_size}|{timestamp}"
            )
            return {
                "type": "x-google-ct-sth",
                "id": f"x-google-ct-sth--{stix_uuid}",
                "spec_version": "2.1",
                "log": self.log,
                "tree_size": tree_size,
                "timestamp": timestamp,
                "sha256_root_hash": native.get("sha256_root_hash"),
                "tree_head_signature": native.get("tree_head_signature"),
                "x_google_ct": {"raw": native},
            }

        if kind == "root":
            der = native.get("der_b64", "")
            stix_uuid = uuid.uuid5(_NAMESPACE_GCT, f"x509-certificate|root|{der[:32]}")
            return {
                "type": "x509-certificate",
                "id": f"x509-certificate--{stix_uuid}",
                "spec_version": "2.1",
                "is_self_signed": True,
                "x_google_ct": {"role": "root", "der_b64": der, "raw": native},
            }

        # Default → x509-certificate stub for an entry
        index = native.get("_gct_index") or 0
        leaf_input = native.get("leaf_input") or ""
        stix_uuid = uuid.uuid5(
            _NAMESPACE_GCT, f"x509-certificate|{self.log}|{index}"
        )
        return {
            "type": "x509-certificate",
            "id": f"x509-certificate--{stix_uuid}",
            "spec_version": "2.1",
            "x_google_ct": {
                "log": self.log,
                "leaf_index": index,
                "leaf_input": leaf_input,
                "extra_data": native.get("extra_data"),
                "observed": utcnow(),
                "raw": native,
            },
        }

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """GoogleCT connector is read-only."""
        return {
            "note": (
                "GoogleCT connector is read-only. Use get_sth, get_entries, "
                "get_roots, or get_proof_by_hash to query a CT log."
            ),
            "stix_id": stix_dict.get("id", ""),
        }
