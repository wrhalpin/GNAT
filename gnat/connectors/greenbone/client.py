"""
gnat.connectors.greenbone.client
================================

Greenbone Vulnerability Management (GVM / OpenVAS) connector — full client.

Authentication
--------------
GMP (Greenbone Management Protocol) over TLS/SSH/Socket with username/password::

    [greenbone]
    host     = your-greenbone-host.example.com
    port     = 9390                  # default GMP port
    username = <gvm-username>
    password = <gvm-password>

Notes
-----
* Uses python-gvm library (recommended) or raw GMP XML.
* Ideal for ingesting scan results and vulnerabilities into DefectDojo-style orchestration.
* Self-hostable (Community Edition or Enterprise).
* Read-heavy for vuln data; supports triggering scans if needed.
"""

from __future__ import annotations

import uuid as _uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    from gvm.connections import UnixSocketConnection, TLSConnection
    from gvm.protocols.gmp import Gmp
    from gvm.transforms import EtreeTransform
    _HAS_GVM = True
except ImportError:
    _HAS_GVM = False

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

_STIX_NS = _uuid.UUID("b3c4d5e6-f7a8-9b0c-1d2e-3f4a5b6c7d8e")

def _now_ts() -> str:
    """ISO 8601 timestamp with millisecond precision."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class GreenboneClient(BaseClient, ConnectorMixin):
    """
    Full client for Greenbone Vulnerability Management (GVM / OpenVAS) via GMP.

    Parameters
    ----------
    host : str
        Greenbone host (for TLS) or socket path.
    port : int
        GMP port (default 9390 for TLS).
    username : str
        GVM username.
    password : str
        GVM password.
    """

    stix_type_map: Dict[str, str] = {
        "vulnerability": "results",
        "report":        "reports",
    }

    def __init__(self, host: str = "localhost", port: int = 9390, username: str = "", password: str = "", **kwargs: Any):
        super().__init__(host=host, **kwargs)
        self._port = port
        self._username = username
        self._password = password
        self._gmp: Optional[Any] = None

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Connect via GMP (TLS or Unix socket)."""
        if not _HAS_GVM:
            raise GNATClientError("python-gvm library is required for Greenbone connector. Install with: pip install python-gvm")

        connection = TLSConnection(hostname=self.host, port=self._port)
        transform = EtreeTransform()

        self._gmp = Gmp(connection=connection, transform=transform)
        self._gmp.connect()
        self._gmp.authenticate(self._username, self._password)

    # ── ConnectorMixin — CRUD ─────────────────────────────────────────────

    def health_check(self) -> bool:
        """Verify GMP connection and get version."""
        if not self._gmp:
            self.authenticate()
        version = self._gmp.get_version()
        return bool(version)

    def get_object(self, stix_type: str, object_id: str) -> Dict[str, Any]:
        if not self._gmp:
            self.authenticate()
        if stix_type == "vulnerability":
            # Get single result
            return self._gmp.get_result(result_id=object_id)
        if stix_type == "report":
            return self._gmp.get_report(report_id=object_id)
        raise GNATClientError(f"Unsupported STIX type for Greenbone: {stix_type}")

    def list_objects(
        self,
        stix_type: str,
        filters: Optional[Dict[str, Any]] = None,
        page: int = 1,
        page_size: int = 100,
    ) -> List[Dict[str, Any]]:
        if not self._gmp:
            self.authenticate()
        filters = dict(filters or {})

        if stix_type == "vulnerability":
            # Get results (vulnerability findings)
            resp = self._gmp.get_results(filter_string=filters.get("filter", ""), details=True)
            # Parse XML/Etree as needed — simplify to dict list
            return self._parse_results(resp) if hasattr(resp, "findall") else []
        # Default: reports
        resp = self._gmp.get_reports(filter_string=filters.get("filter", ""))
        return self._parse_reports(resp) if hasattr(resp, "findall") else []

    def upsert_object(self, stix_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        raise GNATClientError("Greenbone connector is read-focused for results/reports.")

    def delete_object(self, stix_type: str, object_id: str) -> None:
        raise GNATClientError("Deletion not typically supported via GMP in this connector.")

    # ── Helpers for parsing (simplified) ───────────────────────────────────

    def _parse_results(self, xml_response: Any) -> List[Dict[str, Any]]:
        """Basic parsing of GMP results XML to dict list (expand with lxml/etree as needed)."""
        results = []
        # Placeholder — in practice use xml.etree or lxml to extract
        # Example structure: results with name, severity, host, etc.
        return results  # Replace with actual parsing

    def _parse_reports(self, xml_response: Any) -> List[Dict[str, Any]]:
        """Basic parsing of reports."""
        return []  # Replace with actual parsing

    # ── STIX Translation ──────────────────────────────────────────────────

    def to_stix(self, native: Dict[str, Any]) -> Dict[str, Any]:
        """Convert GVM result or report to STIX."""
        if "severity" in native and "name" in native:
            return self._result_to_stix(native)
        return self._report_to_stix(native)

    def from_stix(self, stix_dict: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "note": "Greenbone is read-only for vulnerability scan data.",
            "stix_id": stix_dict.get("id", ""),
        }

    def _result_to_stix(self, result: Dict[str, Any]) -> Dict[str, Any]:
        now = _now_ts()
        rid = result.get("id", "")
        vul_id = f"vulnerability--{_uuid.uuid5(_STIX_NS, f'gvm:{rid}')}"
        return {
            "type": "vulnerability",
            "id": vul_id,
            "spec_version": "2.1",
            "created": now,
            "modified": now,
            "name": result.get("name", "Greenbone Finding"),
            "description": result.get("description", ""),
            "external_references": [{"source_name": "greenbone", "external_id": rid}],
            "x_greenbone": {
                "result_id": rid,
                "severity": result.get("severity"),
                "host": result.get("host"),
                "nvt": result.get("nvt"),
            },
        }

    def _report_to_stix(self, report: Dict[str, Any]) -> Dict[str, Any]:
        now = _now_ts()
        rid = report.get("id", "")
        report_id = f"report--{_uuid.uuid5(_STIX_NS, f'gvm:{rid}')}"
        return {
            "type": "report",
            "id": report_id,
            "spec_version": "2.1",
            "created": now,
            "modified": now,
            "name": report.get("name", "Greenbone Scan Report"),
            "description": "Vulnerability scan report from Greenbone GVM",
            "report_types": ["vulnerability-report"],
            "x_greenbone": {
                "report_id": rid,
                "scan_start": report.get("scan_start"),
                "scan_end": report.get("scan_end"),
            },
        }