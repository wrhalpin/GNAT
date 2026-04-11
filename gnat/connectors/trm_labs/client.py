# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.trm_labs.client
===================================

TRM Labs connector — blockchain / cryptocurrency threat intelligence and
wallet-risk screening.

Authentication
--------------
HTTP Basic auth with the API key as username (empty password)::

    [trm_labs]
    host    = https://api.trmlabs.com
    api_key = trm_...

Key endpoints
-------------
* ``POST /public/v2/screening/addresses`` — batch address risk screening
* ``GET  /public/v2/entities/{entity_id}`` — entity attribution record
* ``GET  /public/v2/addresses/{chain}/{address}`` — full wallet profile

STIX Type Mapping
-----------------
* ``indicator``    → high-risk wallet addresses (custom pattern)
* ``threat-actor`` → attributed entities (exchanges, sanctioned OFAC
  entries, ransomware groups, etc.)
* ``observed-data`` → transaction history snapshots
"""

from __future__ import annotations

import uuid
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.utils.stix_helpers import make_observed_data_envelope, utcnow

_NAMESPACE_TRM = uuid.UUID("7a14b500-0001-4d0c-9ab1-7a14b500abcd")


class TRMLabsClient(BaseClient, ConnectorMixin):
    """
    HTTP client for TRM Labs.

    Parameters
    ----------
    host : str
        Base URL.  Defaults to ``"https://api.trmlabs.com"``.
    api_key : str
        TRM Labs API key (used as Basic auth username; password empty).
    """

    TRUST_LEVEL: str = "semi_trusted"
    API_VERSION: str = "v2"
    API_PREFIX: str = "/public/v2"
    COST_UNIT: int = 1

    stix_type_map: dict[str, str] = {
        "indicator": "addresses/screening",
        "threat-actor": "entities",
        "observed-data": "addresses",
    }

    def __init__(
        self,
        host: str = "https://api.trmlabs.com",
        api_key: str = "",
        **kwargs: Any,
    ) -> None:
        """Initialize TRMLabsClient."""
        super().__init__(host=host, **kwargs)
        self.api_key = api_key

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Set HTTP Basic Authorization header (api_key as username)."""
        if not self.api_key:
            raise GNATClientError(
                "TRM Labs connector requires api_key in config."
            )
        self._auth_headers["Authorization"] = self._basic_auth(self.api_key, "")
        self._auth_headers["Accept"] = "application/json"

    # ── ConnectorMixin — CRUD ──────────────────────────────────────────────

    def health_check(self) -> bool:
        """Screen a well-known sanctioned address as a liveness probe."""
        try:
            self.post(
                "/public/v2/screening/addresses",
                json=[{"address": "0x0000000000000000000000000000000000000000", "chain": "ethereum"}],
            )
            return True
        except Exception:  # noqa: BLE001
            return False

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """
        Fetch a single TRM Labs record.

        ``stix_type`` values:

        * ``"threat-actor"`` — entity attribution via ``/entities/{id}``
        * ``"observed-data"`` — full wallet profile via
          ``/addresses/{chain}/{address}`` (``object_id`` must be in the
          form ``"{chain}:{address}"``)
        """
        if not object_id:
            raise GNATClientError("TRM Labs get_object requires a non-empty id")

        if stix_type == "threat-actor":
            resp = self.get(f"/public/v2/entities/{object_id}")
            if not isinstance(resp, dict):
                raise GNATClientError(
                    f"TRM Labs returned unexpected payload for entity {object_id!r}"
                )
            return dict(resp, _trm_kind="entity")
        if stix_type == "observed-data":
            if ":" not in object_id:
                raise GNATClientError(
                    "TRM Labs observed-data ids must be 'chain:address' (e.g. 'ethereum:0xabc...')"
                )
            chain, address = object_id.split(":", 1)
            resp = self.get(f"/public/v2/addresses/{chain}/{address}")
            if not isinstance(resp, dict):
                raise GNATClientError(
                    f"TRM Labs returned unexpected payload for {object_id!r}"
                )
            return dict(resp, _trm_kind="address", _trm_chain=chain, _trm_address=address)

        raise GNATClientError(
            f"TRM Labs get_object does not support stix_type={stix_type!r}"
        )

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        List / screen records.

        ``filters`` keys:

        * ``addresses`` — list of ``{"chain": ..., "address": ...}`` dicts
          for batch screening
        """
        filters = dict(filters or {})
        if stix_type == "indicator":
            addresses = filters.get("addresses") or []
            if not addresses:
                raise GNATClientError(
                    "TRM Labs list_objects(indicator) requires an 'addresses' filter"
                )
            resp = self.post(
                "/public/v2/screening/addresses", json=addresses
            )
            records = _extract_records(resp)
            return [dict(r, _trm_kind="screening") for r in records]
        raise GNATClientError(
            f"TRM Labs list_objects does not support stix_type={stix_type!r}"
        )

    def upsert_object(
        self, stix_type: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        """TRM Labs connector is read-only."""
        raise GNATClientError(
            "TRM Labs connector is read-only — no write operations supported."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """TRM Labs connector is read-only."""
        raise GNATClientError(
            "TRM Labs connector is read-only — no delete operations supported."
        )

    # ── Domain-specific helpers ────────────────────────────────────────────

    def screen_address(self, chain: str, address: str) -> dict[str, Any]:
        """Screen a single wallet address and return its risk record."""
        records = self.list_objects(
            "indicator",
            filters={"addresses": [{"chain": chain, "address": address}]},
        )
        if records:
            return records[0]
        return {}

    def screen_addresses_batch(
        self, addresses: list[dict[str, str]]
    ) -> list[dict[str, Any]]:
        """Batch-screen many addresses in a single API call."""
        return self.list_objects("indicator", filters={"addresses": addresses})

    def get_entity(self, entity_id: str) -> dict[str, Any]:
        """Fetch a TRM Labs entity attribution record."""
        return self.get_object("threat-actor", entity_id)

    def get_address_profile(self, chain: str, address: str) -> dict[str, Any]:
        """Fetch the full profile for a wallet address."""
        return self.get_object("observed-data", f"{chain}:{address}")

    # ── ConnectorMixin — STIX translation ──────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert a TRM Labs record to STIX 2.1."""
        if not isinstance(native, dict):
            raise GNATClientError("TRM Labs to_stix expects a dict input")

        kind = native.get("_trm_kind") or "screening"
        now = utcnow()

        if kind == "screening":
            address = (
                native.get("address") or native.get("walletAddress") or ""
            )
            chain = (
                native.get("chain")
                or native.get("network")
                or native.get("blockchain")
                or ""
            )
            risk_score = (
                native.get("addressRiskIndicatorRiskScore")
                or native.get("riskScore")
                or 0
            )
            try:
                risk_score_num = float(risk_score)
            except (TypeError, ValueError):
                risk_score_num = 0.0
            pattern = f"[x-cryptocurrency-wallet:value = '{address}' AND x-cryptocurrency-wallet:chain = '{chain}']"
            stix_uuid = uuid.uuid5(
                _NAMESPACE_TRM, f"indicator|{chain}|{address}"
            )
            return {
                "type": "indicator",
                "id": f"indicator--{stix_uuid}",
                "spec_version": "2.1",
                "created": now,
                "modified": now,
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": now,
                "name": f"TRM Labs: {chain}:{address[:16]}",
                "description": native.get("entities", [{}])[0].get("entity", "")
                if isinstance(native.get("entities"), list) and native.get("entities")
                else "TRM Labs wallet screening",
                "labels": ["malicious-activity"] if risk_score_num >= 10 else ["benign"],
                "x_trm_labs": {
                    "chain": chain,
                    "address": address,
                    "risk_score": risk_score_num,
                    "entities": native.get("entities", []),
                    "trm_app_url": native.get("trmAppUrl"),
                    "sanctioned": native.get("sanctioned", False),
                    "raw": native,
                },
            }

        if kind == "entity":
            entity_id = native.get("id") or native.get("entity", "")
            stix_uuid = uuid.uuid5(_NAMESPACE_TRM, f"threat-actor|{entity_id}")
            return {
                "type": "threat-actor",
                "id": f"threat-actor--{stix_uuid}",
                "spec_version": "2.1",
                "created": now,
                "modified": now,
                "name": native.get("name") or native.get("entity") or str(entity_id),
                "description": native.get("description") or "",
                "threat_actor_types": native.get("threat_types") or ["criminal"],
                "x_trm_labs": {
                    "entity_id": entity_id,
                    "category": native.get("category"),
                    "subcategory": native.get("subcategory"),
                    "sanctioned": native.get("sanctioned", False),
                    "sanction_lists": native.get("sanction_lists", []),
                    "raw": native,
                },
            }

        # Full wallet profile → observed-data envelope
        chain = native.get("_trm_chain", "")
        address = native.get("_trm_address", "")
        refs: list[str] = []
        if chain and address:
            w_uuid = uuid.uuid5(
                _NAMESPACE_TRM, f"wallet|{chain}|{address}"
            )
            refs.append(f"x-cryptocurrency-wallet--{w_uuid}")

        first = native.get("firstTransactionAt") or now
        last = native.get("lastTransactionAt") or first

        return make_observed_data_envelope(
            first_observed=first,
            last_observed=last,
            number_observed=int(native.get("transactionCount") or 1),
            object_refs=refs,
            source_name="trm_labs",
            x_extensions={
                "trm_labs": {
                    "chain": chain,
                    "address": address,
                    "risk_score": native.get("riskScore"),
                    "entities": native.get("entities", []),
                    "total_value_usd": native.get("totalValueUsd"),
                    "incoming_value_usd": native.get("incomingValueUsd"),
                    "outgoing_value_usd": native.get("outgoingValueUsd"),
                    "raw": native,
                }
            },
        )

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """TRM Labs connector is read-only."""
        return {
            "note": (
                "TRM Labs connector is read-only. Use screen_address, "
                "screen_addresses_batch, get_entity, or get_address_profile "
                "to query the API."
            ),
            "stix_id": stix_dict.get("id", ""),
        }


def _extract_records(resp: Any) -> list[dict[str, Any]]:
    """Pull records out of a TRM Labs response envelope."""
    if isinstance(resp, list):
        return [r for r in resp if isinstance(r, dict)]
    if not isinstance(resp, dict):
        return []
    for key in ("results", "data", "items"):
        val = resp.get(key)
        if isinstance(val, list):
            return [r for r in val if isinstance(r, dict)]
    return []
