# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.safebreach.client
=====================================

SafeBreach BAS connector.

Authentication
--------------
Two custom headers — ``x-apitoken`` and ``x-accountid``::

    [safebreach]
    host        = https://api.safebreach.com
    api_token   = sb_...
    account_id  = 12345

Key endpoints
-------------
* ``GET /api/config/v1/accounts/{account_id}/simulators``
* ``GET /api/data/v1/accounts/{account_id}/tests``
* ``GET /api/data/v1/accounts/{account_id}/tests/{test_id}/simulations``
* ``GET /api/data/v1/accounts/{account_id}/findings``
* ``GET /api/config/v1/accounts/{account_id}/scenarios``
* ``GET /api/config/v1/accounts/{account_id}/attackers``

STIX Type Mapping
-----------------
* ``observed-data`` → simulations + findings (via
  :func:`bas_simulation_envelope`)
* ``attack-pattern`` → SafeBreach "attacker" records (MITRE ATT&CK
  techniques)
"""

from __future__ import annotations

import uuid
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.stix.version import CURRENT_SPEC_VERSION
from gnat.utils.stix_helpers import bas_simulation_envelope, utcnow

_NAMESPACE_SAFEBREACH = uuid.UUID("5afeb1ea-c000-4a1e-9b1e-5afeb1eac0fe")


class SafeBreachClient(BaseClient, ConnectorMixin):
    """HTTP client for the SafeBreach BAS platform."""

    TRUST_LEVEL: str = "trusted_internal"
    API_VERSION: str = "v1"
    API_PREFIX: str = "/api"
    COST_UNIT: int = 1

    stix_type_map: dict[str, str] = {
        "observed-data": "data/v1/tests",
        "attack-pattern": "config/v1/attackers",
    }

    def __init__(
        self,
        host: str = "https://api.safebreach.com",
        api_token: str = "",
        account_id: str = "",
        **kwargs: Any,
    ) -> None:
        """Initialize SafeBreachClient."""
        super().__init__(host=host, **kwargs)
        self.api_token = api_token
        self.account_id = account_id

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Set custom x-apitoken + x-accountid headers."""
        if not self.api_token or not self.account_id:
            raise GNATClientError(
                "SafeBreach connector requires api_token and account_id."
            )
        self._auth_headers["x-apitoken"] = self.api_token
        self._auth_headers["x-accountid"] = str(self.account_id)
        self._auth_headers["Accept"] = "application/json"

    # ── Internal ──────────────────────────────────────────────────────────

    def _acct_path(self, suffix: str, tree: str = "data") -> str:
        """Return an account-scoped SafeBreach API path."""
        return f"/api/{tree}/v1/accounts/{self.account_id}/{suffix.lstrip('/')}"

    # ── ConnectorMixin — CRUD ──────────────────────────────────────────────

    def health_check(self) -> bool:
        """Call the simulators config endpoint as an authenticated probe."""
        try:
            self.get(self._acct_path("simulators", tree="config"))
            return True
        except Exception:  # noqa: BLE001
            return False

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch a single SafeBreach record by id."""
        if not object_id:
            raise GNATClientError("SafeBreach get_object requires a non-empty id")
        if stix_type == "observed-data":
            resp = self.get(self._acct_path(f"tests/{object_id}"))
            kind = "test"
        elif stix_type == "attack-pattern":
            resp = self.get(self._acct_path(f"attackers/{object_id}", tree="config"))
            kind = "attacker"
        else:
            raise GNATClientError(
                f"SafeBreach get_object does not support stix_type={stix_type!r}"
            )
        if not isinstance(resp, dict):
            raise GNATClientError(
                f"SafeBreach returned unexpected payload for {object_id!r}"
            )
        return dict(resp, _sb_kind=kind)

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        List SafeBreach records.

        ``filters`` keys:

        * ``kind`` — ``"tests"`` (default), ``"findings"``, ``"scenarios"``,
          ``"simulations"``, ``"attackers"``
        * ``test_id`` — required when ``kind == "simulations"``
        """
        filters = dict(filters or {})
        params: dict[str, Any] = {"pageSize": int(page_size), "page": int(page)}
        kind = (filters.get("kind") or "tests").lower()

        if stix_type == "observed-data":
            if kind == "findings":
                resp = self.get(self._acct_path("findings"), params=params)
                tag = "finding"
            elif kind == "scenarios":
                resp = self.get(
                    self._acct_path("scenarios", tree="config"), params=params
                )
                tag = "scenario"
            elif kind == "simulations":
                test_id = filters.get("test_id")
                if not test_id:
                    raise GNATClientError(
                        "SafeBreach list_objects(simulations) requires 'test_id' filter"
                    )
                resp = self.get(
                    self._acct_path(f"tests/{test_id}/simulations"), params=params
                )
                tag = "simulation"
            else:
                resp = self.get(self._acct_path("tests"), params=params)
                tag = "test"
        elif stix_type == "attack-pattern":
            resp = self.get(
                self._acct_path("attackers", tree="config"), params=params
            )
            tag = "attacker"
        else:
            raise GNATClientError(
                f"SafeBreach list_objects does not support stix_type={stix_type!r}"
            )

        return [dict(r, _sb_kind=tag) for r in _extract_sb_list(resp)]

    def upsert_object(
        self, stix_type: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """SafeBreach connector is read-only."""
        raise GNATClientError(
            "SafeBreach connector is read-only — no write operations supported."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """SafeBreach connector is read-only."""
        raise GNATClientError(
            "SafeBreach connector is read-only — no delete operations supported."
        )

    # ── Domain-specific helpers ────────────────────────────────────────────

    def list_tests(self) -> list[dict[str, Any]]:
        """Return SafeBreach test runs."""
        return self.list_objects(
            "observed-data", filters={"kind": "tests"}, page_size=1000
        )

    def list_simulations(self, test_id: str) -> list[dict[str, Any]]:
        """Return simulations for a specific test run."""
        return self.list_objects(
            "observed-data",
            filters={"kind": "simulations", "test_id": test_id},
            page_size=1000,
        )

    def list_findings(self) -> list[dict[str, Any]]:
        """Return SafeBreach findings."""
        return self.list_objects(
            "observed-data", filters={"kind": "findings"}, page_size=1000
        )

    def list_attackers(self) -> list[dict[str, Any]]:
        """Return SafeBreach attackers (MITRE technique catalog)."""
        return self.list_objects("attack-pattern", page_size=1000)

    def get_test(self, test_id: str) -> dict[str, Any]:
        """Fetch a single test run."""
        return self.get_object("observed-data", test_id)

    # ── ConnectorMixin — STIX translation ──────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert a SafeBreach record to STIX 2.1."""
        if not isinstance(native, dict):
            raise GNATClientError("SafeBreach to_stix expects a dict input")

        kind = native.get("_sb_kind") or "test"

        if kind == "attacker":
            attacker_id = native.get("id") or native.get("name", "unknown")
            mitre = native.get("mitreTechnique") or native.get("mitre_id", "")
            stix_uuid = uuid.uuid5(
                _NAMESPACE_SAFEBREACH, f"attack-pattern|{attacker_id}"
            )
            external_refs = []
            if mitre:
                external_refs.append(
                    {"source_name": "mitre-attack", "external_id": mitre}
                )
            return {
                "type": "attack-pattern",
                "id": f"attack-pattern--{stix_uuid}",
                "spec_version": CURRENT_SPEC_VERSION,
                "created": utcnow(),
                "modified": utcnow(),
                "name": native.get("name") or str(attacker_id),
                "description": native.get("description") or "",
                "external_references": external_refs,
                "x_safebreach": {"raw": native},
            }

        # test / simulation / finding / scenario → observed-data
        simulation_id = str(
            native.get("id") or native.get("simulationId") or native.get("testId", "")
        )
        targets = _values(
            native.get("targets")
            or native.get("targetNodes")
            or native.get("nodes")
        )
        techniques = _values(
            native.get("mitreTechniques")
            or native.get("techniques")
            or native.get("attackerId")
        )
        return bas_simulation_envelope(
            source_name="safebreach",
            simulation_id=simulation_id,
            target_assets=targets,
            attack_techniques=techniques,
            result=native.get("status") or native.get("result", ""),
            score=_as_float(native.get("score") or native.get("severity")),
            first_observed=native.get("startTime") or native.get("createdAt", ""),
            last_observed=native.get("endTime") or native.get("updatedAt", ""),
            raw_report=native,
        )

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """SafeBreach connector is read-only."""
        return {
            "note": (
                "SafeBreach connector is read-only. Use list_tests, "
                "list_simulations, list_findings, list_attackers, or "
                "get_test to query the API."
            ),
            "stix_id": stix_dict.get("id", ""),
        }


def _extract_sb_list(resp: Any) -> list[dict[str, Any]]:
    """Pull records out of a SafeBreach list response envelope."""
    if isinstance(resp, list):
        return [r for r in resp if isinstance(r, dict)]
    if not isinstance(resp, dict):
        return []
    for key in ("data", "result", "results", "items", "tests", "findings", "scenarios", "simulations"):
        val = resp.get(key)
        if isinstance(val, list):
            return [r for r in val if isinstance(r, dict)]
    return []


def _values(container: Any) -> list[str]:
    """Normalize scalar / list / None into a list of strings."""
    if container is None:
        return []
    if isinstance(container, list):
        out: list[str] = []
        for item in container:
            if isinstance(item, str):
                out.append(item)
            elif isinstance(item, dict):
                val = item.get("name") or item.get("id") or item.get("host")
                if isinstance(val, str):
                    out.append(val)
        return out
    if isinstance(container, str):
        return [container]
    return []


def _as_float(value: Any) -> float | None:
    """Safely cast *value* to float, returning None on failure."""
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
