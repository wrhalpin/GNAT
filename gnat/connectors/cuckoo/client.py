# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.cuckoo.client
=================================

Cuckoo Sandbox / CAPEv2 connector — automated malware analysis.

Supports both the legacy Cuckoo 2.x API (``/api/``) and the
CAPEv2/Cuckoo 3.x API (``/apiv2/``).  API version is auto-detected
at :meth:`authenticate` time unless explicitly overridden.

Authentication
--------------
Bearer token::

    [cuckoo]
    host        = https://cuckoo.lab.internal
    api_key     = <your-api-key>
    # api_version = 3     ; optional — auto-detected if omitted

Key endpoints (v2 → v3)
-----------------------
* ``GET  /cuckoo/status`` → ``GET  /apiv2/cuckoo/status/``
* ``POST /tasks/create/file`` → ``POST /apiv2/tasks/create/file/``
* ``POST /tasks/create/url`` → ``POST /apiv2/tasks/create/url/``
* ``GET  /tasks/list`` → ``GET  /apiv2/tasks/list/``
* ``GET  /tasks/view/<id>`` → ``GET  /apiv2/tasks/view/<id>/``
* ``GET  /tasks/report/<id>`` → ``GET  /apiv2/tasks/report/<id>/``

STIX Type Mapping
-----------------
``observed-data`` wraps the full behavioral report via
:func:`sandbox_report_envelope`; ``malware`` carries verdict/family;
``indicator`` is emitted per extracted IOC.
"""

from __future__ import annotations

import uuid
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin
from gnat.stix.version import CURRENT_SPEC_VERSION
from gnat.utils.stix_helpers import (
    make_indicator_pattern,
    sandbox_report_envelope,
    utcnow,
)

_NAMESPACE_CUCKOO = uuid.UUID("c0cc00c0-0001-4c0c-b0c0-c0cc00c0c0fe")


def _score_to_verdict(score: Any) -> str:
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "unknown"
    if s <= 3:
        return "clean"
    if s <= 6:
        return "suspicious"
    return "malicious"


def _cuckoo_malware_types(native: dict[str, Any]) -> list[str]:
    sigs = native.get("signatures") or []
    tags: list[str] = []
    for sig in sigs:
        name = (sig.get("name") or "").lower() if isinstance(sig, dict) else ""
        tags.append(name)
    out: list[str] = []
    combined = " ".join(tags)
    if "trojan" in combined:
        out.append("trojan")
    if "ransom" in combined:
        out.append("ransomware")
    if "backdoor" in combined:
        out.append("backdoor")
    if "worm" in combined:
        out.append("worm")
    if "rootkit" in combined:
        out.append("rootkit")
    if "rat" in combined:
        out.append("remote-access-trojan")
    return out or ["unknown"]


def _extract_cuckoo_list(resp: Any) -> list[dict[str, Any]]:
    if isinstance(resp, list):
        return [r for r in resp if isinstance(r, dict)]
    if not isinstance(resp, dict):
        return []
    for key in ("data", "tasks", "results"):
        val = resp.get(key)
        if isinstance(val, list):
            return [r for r in val if isinstance(r, dict)]
    return []


class CuckooClient(BaseClient, ConnectorMixin):
    """
    HTTP client for Cuckoo Sandbox (2.x) and CAPEv2 (3.x).

    Parameters
    ----------
    host : str
        Base URL of the Cuckoo/CAPEv2 instance.
    api_key : str
        API key for Bearer authentication.
    api_version : str, optional
        ``"2"`` for Cuckoo 2.x, ``"3"`` for CAPEv2/3.x.
        Auto-detected if omitted.
    """

    TRUST_LEVEL: str = "semi_trusted"
    COST_UNIT: int = 5

    stix_type_map: dict[str, str] = {
        "observed-data": "tasks",
        "malware": "tasks",
        "indicator": "tasks",
    }

    def __init__(
        self,
        host: str = "",
        api_key: str = "",
        api_version: str | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(host=host, **kwargs)
        self.api_key = api_key
        self._api_version = api_version
        self._prefix = "/apiv2" if api_version == "3" else "/api"

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        if not self.api_key:
            raise GNATClientError(
                "Cuckoo connector requires api_key in config."
            )
        self._auth_headers["Authorization"] = f"Bearer {self.api_key}"

        if self._api_version is None:
            self._detect_version()
        else:
            self._prefix = "/apiv2" if self._api_version == "3" else "/api"

    def _detect_version(self) -> None:
        try:
            self.get("/apiv2/cuckoo/status/")
            self._api_version = "3"
            self._prefix = "/apiv2"
        except Exception:  # noqa: BLE001
            self._api_version = "2"
            self._prefix = "/api"

    # ── ConnectorMixin — CRUD ──────────────────────────────────────────────

    def health_check(self) -> bool:
        try:
            self.get(f"{self._prefix}/cuckoo/status{'/' if self._api_version == '3' else ''}")
            return True
        except Exception:  # noqa: BLE001
            return False

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        if not object_id:
            raise GNATClientError("Cuckoo get_object requires a non-empty id")
        if stix_type not in ("observed-data", "malware", "indicator"):
            raise GNATClientError(
                f"Cuckoo get_object does not support stix_type={stix_type!r}"
            )
        trail = "/" if self._api_version == "3" else ""
        resp = self.get(f"{self._prefix}/tasks/report/{object_id}{trail}")
        if not isinstance(resp, dict):
            raise GNATClientError(
                f"Cuckoo returned unexpected payload for task {object_id!r}"
            )
        return dict(resp, _cuckoo_kind=stix_type, _cuckoo_task_id=str(object_id))

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        if stix_type not in ("observed-data", "malware", "indicator"):
            raise GNATClientError(
                f"Cuckoo list_objects does not support stix_type={stix_type!r}"
            )
        trail = "/" if self._api_version == "3" else ""
        limit = int(page_size)
        offset = max(0, (int(page) - 1) * limit)
        resp = self.get(
            f"{self._prefix}/tasks/list/{limit}/{offset}{trail}"
        )
        items = _extract_cuckoo_list(resp)
        return [dict(r, _cuckoo_kind=stix_type) for r in items]

    def upsert_object(
        self, stix_type: str, payload: dict[str, Any]
    ) -> dict[str, Any]:
        raise GNATClientError(
            "Cuckoo connector is read-only via CRUD — use submit_file / "
            "submit_url domain helpers to trigger analyses."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        if self._api_version == "3":
            self.get(f"{self._prefix}/tasks/delete/{object_id}/")
        else:
            raise GNATClientError(
                "Cuckoo 2.x API does not support task deletion."
            )

    # ── Domain-specific helpers ────────────────────────────────────────────

    def submit_file(
        self, filepath: str, **opts: Any
    ) -> dict[str, Any]:
        import os

        if not os.path.isfile(filepath):
            raise GNATClientError(f"submit_file: {filepath!r} does not exist")
        with open(filepath, "rb") as fh:
            files = {"file": (os.path.basename(filepath), fh.read())}
        trail = "/" if self._api_version == "3" else ""
        data: dict[str, Any] = {}
        if opts.get("machine"):
            data["machine"] = opts["machine"]
        if opts.get("package"):
            data["package"] = opts["package"]
        if opts.get("timeout"):
            data["timeout"] = str(opts["timeout"])
        return self.post(
            f"{self._prefix}/tasks/create/file{trail}",
            data=data or None,
            files=files,
        )

    def submit_url(self, url: str, **opts: Any) -> dict[str, Any]:
        trail = "/" if self._api_version == "3" else ""
        data: dict[str, Any] = {"url": url}
        if opts.get("machine"):
            data["machine"] = opts["machine"]
        if opts.get("package"):
            data["package"] = opts["package"]
        return self.post(
            f"{self._prefix}/tasks/create/url{trail}", data=data
        )

    def get_report(self, task_id: str) -> dict[str, Any]:
        return self.get_object("observed-data", task_id)

    def get_task_view(self, task_id: str) -> dict[str, Any]:
        trail = "/" if self._api_version == "3" else ""
        return self.get(f"{self._prefix}/tasks/view/{task_id}{trail}")

    def list_machines(self) -> list[dict[str, Any]]:
        trail = "/" if self._api_version == "3" else ""
        resp = self.get(f"{self._prefix}/machines/list{trail}")
        return _extract_cuckoo_list(resp)

    def get_pcap(self, task_id: str) -> Any:
        if self._api_version == "3":
            return self.get(f"{self._prefix}/tasks/pcap/{task_id}/")
        return self.get(f"{self._prefix}/pcap/get/{task_id}")

    def get_iocs(self, task_id: str) -> list[dict[str, Any]]:
        report = self.get_object("observed-data", task_id)
        return _extract_iocs(report)

    def iocs_to_indicators(self, task_id: str) -> list[dict[str, Any]]:
        iocs = self.get_iocs(task_id)
        return [
            dict(ioc, _cuckoo_kind="indicator", _cuckoo_task_id=task_id)
            for ioc in iocs
        ]

    # ── ConnectorMixin — STIX translation ──────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(native, dict):
            raise GNATClientError("Cuckoo to_stix expects a dict input")

        kind = native.get("_cuckoo_kind") or "observed-data"
        task_id = str(native.get("_cuckoo_task_id") or native.get("id", ""))

        if kind == "indicator":
            return self._to_stix_indicator(native)

        if kind == "malware":
            return self._to_stix_malware(native, task_id)

        return self._to_stix_observed_data(native, task_id)

    def _to_stix_indicator(self, native: dict[str, Any]) -> dict[str, Any]:
        ioc_type = (native.get("type") or "").lower()
        value = native.get("value") or ""

        if ioc_type in ("ip", "ipv4", "ipv4-addr"):
            pattern = make_indicator_pattern("ipv4-addr", value)
        elif ioc_type in ("domain", "domain-name"):
            pattern = make_indicator_pattern("domain-name", value)
        elif ioc_type == "url":
            pattern = make_indicator_pattern("url", value)
        elif ioc_type in ("sha256", "sha1", "md5"):
            pattern = make_indicator_pattern(f"file:{ioc_type}", value)
        else:
            escaped = value.replace("'", "\\'")
            pattern = f"[x-cuckoo:value = '{escaped}']"

        stix_uuid = uuid.uuid5(_NAMESPACE_CUCKOO, f"indicator|{value}")
        return {
            "type": "indicator",
            "id": f"indicator--{stix_uuid}",
            "spec_version": CURRENT_SPEC_VERSION,
            "created": utcnow(),
            "modified": utcnow(),
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": utcnow(),
            "name": f"Cuckoo: {value}",
            "description": "Cuckoo Sandbox extracted IOC",
            "labels": ["malicious-activity"],
            "x_cuckoo": {
                "task_id": native.get("_cuckoo_task_id"),
                "ioc_type": ioc_type,
            },
        }

    def _to_stix_malware(
        self, native: dict[str, Any], task_id: str
    ) -> dict[str, Any]:
        info = native.get("info") or {}
        target = native.get("target") or {}
        target_file = target.get("file") or {}

        score = info.get("score") or native.get("score")
        verdict = _score_to_verdict(score)
        family = (
            native.get("malfamily")
            or native.get("detections")
            or target_file.get("name")
            or "unknown"
        )
        if isinstance(family, list):
            family = family[0] if family else "unknown"

        stix_uuid = uuid.uuid5(_NAMESPACE_CUCKOO, f"malware|{task_id}|{family}")
        return {
            "type": "malware",
            "id": f"malware--{stix_uuid}",
            "spec_version": CURRENT_SPEC_VERSION,
            "created": utcnow(),
            "modified": utcnow(),
            "name": str(family),
            "is_family": True,
            "description": f"Cuckoo Sandbox: {verdict} ({family})",
            "malware_types": _cuckoo_malware_types(native),
            "x_cuckoo": {
                "task_id": task_id,
                "score": score,
                "verdict": verdict,
            },
        }

    def _to_stix_observed_data(
        self, native: dict[str, Any], task_id: str
    ) -> dict[str, Any]:
        info = native.get("info") or {}
        target = native.get("target") or {}
        target_file = target.get("file") or {}
        network = native.get("network") or {}
        behavior = native.get("behavior") or {}

        hosts = [
            h if isinstance(h, str) else h.get("ip", "")
            for h in (network.get("hosts") or [])
        ]
        domains = [
            d.get("domain") if isinstance(d, dict) else str(d)
            for d in (network.get("domains") or [])
        ]
        urls = [
            h.get("uri") if isinstance(h, dict) else str(h)
            for h in (network.get("http") or [])
        ]
        processes = [
            p.get("process_name") if isinstance(p, dict) else str(p)
            for p in (behavior.get("processes") or [])
        ]
        return sandbox_report_envelope(
            source_name="cuckoo",
            analysis_id=task_id,
            submitted_sha256=target_file.get("sha256", ""),
            submitted_filename=target_file.get("name", ""),
            processes=[p for p in processes if p],
            contacted_ips=[ip for ip in hosts if ip],
            contacted_domains=[d for d in domains if d],
            contacted_urls=[u for u in urls if u],
            first_observed=info.get("started") or "",
            last_observed=info.get("ended") or "",
            verdict=_score_to_verdict(info.get("score")),
            score=info.get("score"),
            raw_report=native,
        )

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        return {
            "note": (
                "Cuckoo connector is read-only via CRUD. Use submit_file, "
                "submit_url, get_report, get_iocs, or iocs_to_indicators "
                "to interact with the platform."
            ),
            "stix_id": stix_dict.get("id", ""),
        }


def _extract_iocs(report: dict[str, Any]) -> list[dict[str, Any]]:
    iocs: list[dict[str, Any]] = []
    network = report.get("network") or {}

    for host in network.get("hosts") or []:
        ip = host if isinstance(host, str) else (host.get("ip") or "")
        if ip:
            iocs.append({"type": "ipv4", "value": ip})

    for entry in network.get("domains") or []:
        domain = entry.get("domain") if isinstance(entry, dict) else str(entry)
        if domain:
            iocs.append({"type": "domain", "value": domain})

    for entry in network.get("http") or []:
        uri = entry.get("uri") if isinstance(entry, dict) else str(entry)
        if uri:
            iocs.append({"type": "url", "value": uri})

    for entry in report.get("dropped") or []:
        if isinstance(entry, dict) and entry.get("sha256"):
            iocs.append({"type": "sha256", "value": entry["sha256"]})

    for entry in network.get("dns") or []:
        if isinstance(entry, dict):
            for answer in entry.get("answers") or []:
                data = answer.get("data") if isinstance(answer, dict) else ""
                if data:
                    iocs.append({"type": "ipv4", "value": data})

    for sig in report.get("signatures") or []:
        if isinstance(sig, dict):
            for mark in sig.get("marks") or []:
                if isinstance(mark, dict) and mark.get("ioc"):
                    iocs.append({"type": "unknown", "value": mark["ioc"]})

    seen: set[str] = set()
    deduped: list[dict[str, Any]] = []
    for ioc in iocs:
        key = f"{ioc['type']}|{ioc['value']}"
        if key not in seen:
            seen.add(key)
            deduped.append(ioc)
    return deduped
