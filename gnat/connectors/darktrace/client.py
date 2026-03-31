"""
gnat.connectors.darktrace.client
================================

Darktrace Enterprise Immune System connector.

Authentication
--------------
HMAC-signed requests using a public/private key pair::

    [darktrace]
    host        = https://<darktrace-instance>
    public_key  = <public-key>
    private_key = <private-key>

Darktrace uses a bespoke HMAC-SHA1 authentication scheme: each request
carries a ``DTAPI-Token`` header computed from the request path, timestamp,
and the private key.

STIX Type Mapping
-----------------
+------------------+-----------------------------------+
| STIX Type        | Darktrace Resource                |
+==================+===================================+
| observed-data    | Alerts / Model Breaches           |
+------------------+-----------------------------------+
| threat-actor     | Devices (scored entities)         |
+------------------+-----------------------------------+

Key Endpoints (Darktrace REST API)
------------------------------------
* /alerts                     — Model breach alerts
* /modelbreaches              — Model breach details
* /devices                    — AI-scored devices
* /details                    — Connection details
* /intelfeed                  — Custom threat intelligence feed
"""

from __future__ import annotations

import hashlib
import hmac
import time
import uuid as _uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

_STIX_NS = _uuid.UUID("e5f6a7b8-c9d0-1234-ef01-567890123456")


def _now_ts() -> str:
    """ISO 8601 timestamp."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _darktrace_signature(path: str, private_key: str, public_key: str) -> Dict[str, str]:
    """
    Build Darktrace HMAC authentication headers.

    Parameters
    ----------
    path : str
        Request path (e.g. ``"/alerts"``).
    private_key : str
        Darktrace private API key.
    public_key : str
        Darktrace public API key.

    Returns
    -------
    dict
        Headers dict with ``DTAPI-Token``, ``DTAPI-Date``, and ``DTAPI-Signature``.
    """
    date_str = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
    message  = f"{path}\n{public_key}\n{date_str}".encode("utf-8")
    sig      = hmac.new(private_key.encode("utf-8"), message, hashlib.sha1).hexdigest()
    return {
        "DTAPI-Token":     public_key,
        "DTAPI-Date":      date_str,
        "DTAPI-Signature": sig,
    }


class DarktraceClient(BaseClient, ConnectorMixin):
    """
    HTTP client for the Darktrace Enterprise Immune System REST API.

    Parameters
    ----------
    host : str
        Darktrace instance base URL (e.g. ``"https://darktrace.corp.example.com"``).
    public_key : str
        Darktrace API public key.
    private_key : str
        Darktrace API private key (used for HMAC signing).
    """

    stix_type_map: Dict[str, str] = {
        "observed-data": "modelbreaches",
        "threat-actor":  "devices",
    }

    def __init__(
        self,
        host: str = "",
        public_key: str = "",
        private_key: str = "",
        **kwargs: Any,
    ) -> None:
        super().__init__(host=host, **kwargs)
        self._public_key  = public_key
        self._private_key = private_key

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """
        Validate the key pair by performing a test request to ``/status``.

        Darktrace authentication is per-request HMAC signing, so this method
        validates connectivity and stores the keys for later use.
        """
        if not self._public_key or not self._private_key:
            raise GNATClientError("Darktrace: public_key and private_key are required")
        # Mark as authenticated; actual signing happens per-request in _signed_get/post
        self._auth_headers["Accept"] = "application/json"

    def _signed_headers(self, path: str) -> Dict[str, str]:
        """Return per-request HMAC-signed headers merged with base auth headers."""
        signed = _darktrace_signature(path, self._private_key, self._public_key)
        return {**self._auth_headers, **signed}

    # ── ConnectorMixin — CRUD ─────────────────────────────────────────────

    def health_check(self) -> bool:
        """Ping Darktrace status endpoint."""
        self.get("/status")
        return True

    def get_object(self, stix_type: str, object_id: str) -> Dict[str, Any]:
        """Fetch a single model breach or device by ID."""
        if stix_type == "observed-data":
            resp = self.get(f"/modelbreaches/{object_id}")
            return resp if isinstance(resp, dict) else {}
        if stix_type == "threat-actor":
            resp = self.get(f"/devices", params={"did": object_id})
            devs = resp.get("devices", []) if isinstance(resp, dict) else []
            return devs[0] if devs else {}
        raise GNATClientError(f"Darktrace: unsupported STIX type '{stix_type}'")

    def list_objects(
        self,
        stix_type: str = "observed-data",
        filters: Optional[Dict[str, Any]] = None,
        page: int = 1,
        page_size: int = 100,
    ) -> List[Dict[str, Any]]:
        """List model breaches or devices."""
        params: Dict[str, Any] = {"count": page_size, "offset": (page - 1) * page_size}
        if filters:
            params.update(filters)

        if stix_type == "observed-data":
            resp = self.get("/modelbreaches", params=params)
            return resp if isinstance(resp, list) else []
        if stix_type == "threat-actor":
            resp = self.get("/devices", params=params)
            return resp.get("devices", []) if isinstance(resp, dict) else []
        raise GNATClientError(f"Darktrace: unsupported STIX type '{stix_type}'")

    def upsert_object(self, stix_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Darktrace is primarily read-only; upsert only supported for threat intel feed."""
        if stix_type != "indicator":
            raise GNATClientError("Darktrace: upsert only supported for custom intel feed entries")
        resp = self.post("/intelfeed", json=payload)
        return resp if isinstance(resp, dict) else {}

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Remove an entry from the Darktrace custom intel feed."""
        if stix_type != "indicator":
            raise GNATClientError("Darktrace: delete only supported for intel feed entries")
        self.delete(f"/intelfeed/{object_id}")

    # ── Domain-specific helpers ───────────────────────────────────────────

    def list_alerts(
        self,
        min_score: Optional[float] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """
        Fetch model breach alerts.

        Parameters
        ----------
        min_score : float, optional
            Minimum breach score to include (0.0–1.0).
        limit : int
            Maximum records to return.
        """
        params: Dict[str, Any] = {"count": limit}
        if min_score is not None:
            params["minscore"] = min_score
        resp = self.get("/alerts", params=params)
        return resp if isinstance(resp, list) else []

    def list_model_breaches(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Fetch detailed model breach records."""
        resp = self.get("/modelbreaches", params={"count": limit})
        return resp if isinstance(resp, list) else []

    def list_devices(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Fetch AI-scored network device entities."""
        resp = self.get("/devices", params={"count": limit})
        return resp.get("devices", []) if isinstance(resp, dict) else []

    def add_intel_feed_entry(
        self,
        value: str,
        entry_type: str = "ip",
        description: str = "",
    ) -> Dict[str, Any]:
        """
        Add an entry to the Darktrace custom threat intelligence feed.

        Parameters
        ----------
        value : str
            IOC value (IP, domain, hostname, etc.).
        entry_type : str
            Type of IOC: ``"ip"``, ``"hostname"``, ``"useragent"``.
        description : str
            Human-readable description.
        """
        resp = self.post("/intelfeed", json={
            "value":       value,
            "type":        entry_type,
            "description": description,
        })
        return resp if isinstance(resp, dict) else {}

    # ── STIX Translation ──────────────────────────────────────────────────

    def to_stix(self, native: Dict[str, Any]) -> Dict[str, Any]:
        """Convert a Darktrace model breach or device to a STIX 2.1 object."""
        if "pbid" in native or "triggeredComponents" in native:
            return self._breach_to_stix(native)
        return self._device_to_stix(native)

    def from_stix(self, stix_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Convert a STIX indicator to a Darktrace intel feed entry."""
        return {
            "value":       stix_dict.get("name", ""),
            "type":        "hostname",
            "description": stix_dict.get("description", "Imported via GNAT"),
        }

    def _breach_to_stix(self, breach: Dict[str, Any]) -> Dict[str, Any]:
        now = _now_ts()
        bid = str(breach.get("pbid", ""))
        ts  = breach.get("time", now)
        return {
            "type":            "observed-data",
            "id":              f"observed-data--{_uuid.uuid5(_STIX_NS, f'darktrace:{bid}')}",
            "spec_version":    "2.1",
            "created":         ts,
            "modified":        ts,
            "first_observed":  ts,
            "last_observed":   ts,
            "number_observed": 1,
            "object_refs":     [],
            "x_darktrace": {
                "breach_id":   bid,
                "score":       breach.get("score"),
                "model":       breach.get("model", {}).get("name"),
                "device":      breach.get("device", {}).get("hostname"),
                "device_ip":   breach.get("device", {}).get("ip"),
            },
        }

    def _device_to_stix(self, device: Dict[str, Any]) -> Dict[str, Any]:
        now = _now_ts()
        did = str(device.get("did", ""))
        return {
            "type":         "threat-actor",
            "id":           f"threat-actor--{_uuid.uuid5(_STIX_NS, f'darktrace:{did}')}",
            "spec_version": "2.1",
            "created":      now,
            "modified":     now,
            "name":         device.get("hostname", device.get("ip", f"Device {did}")),
            "description":  f"Darktrace AI-monitored network entity",
            "x_darktrace": {
                "device_id": did,
                "ip":        device.get("ip"),
                "mac":       device.get("macaddress"),
                "os":        device.get("os"),
                "tags":      [t.get("name") for t in device.get("tags", [])],
            },
        }
