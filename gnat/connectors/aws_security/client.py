"""
gnat.connectors.aws_security.client
=====================================

AWS Security Hub + GuardDuty connector.

Provides unified access to AWS Security Hub aggregated findings and
AWS GuardDuty threat intelligence findings via the AWS REST APIs.

Authentication
--------------
AWS Signature Version 4 (SigV4) via access key + secret::

    [aws_security]
    host             = https://securityhub.us-east-1.amazonaws.com
    aws_access_key   = AKIAIOSFODNN7EXAMPLE
    aws_secret_key   = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
    aws_region       = us-east-1
    aws_session_token =                  ; optional (for STS/AssumeRole)

The connector uses the Authorization header with AWS4-HMAC-SHA256
signature scheme for all requests.

STIX Type Mapping
-----------------
+----------------+----------------------------------------------+
| STIX Type      | AWS Resource                                 |
+================+==============================================+
| indicator      | GuardDuty Findings (threat indicators)       |
+----------------+----------------------------------------------+
| vulnerability  | Security Hub Findings (CVE/compliance)       |
+----------------+----------------------------------------------+
| report         | Security Hub Insights / aggregated findings  |
+----------------+----------------------------------------------+

Key Endpoints (Security Hub)
-----------------------------
* POST /findings/get          — Fetch findings with filters
* POST /insights/results/{arn} — Insight results
* POST /findings              — Import custom findings (ASFF)

Key Endpoints (GuardDuty)
--------------------------
* GET  /detector              — List detectors
* POST /detector/{id}/findings/get — Get findings by IDs
* POST /detector/{id}/findings     — List finding IDs

Notes
-----
* GuardDuty findings are accessed via regional REST endpoints.
* Security Hub uses the same regional endpoint pattern.
* ASFF (Amazon Security Finding Format) is used for both.

References
----------
https://docs.aws.amazon.com/securityhub/latest/APIReference/
https://docs.aws.amazon.com/guardduty/latest/APIReference/
"""

from __future__ import annotations

import hashlib
import hmac
import uuid as _uuid
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin

_STIX_NS = _uuid.UUID("d4e5f6a7-b8c9-0123-def0-234567890123")


def _now_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _get_signature_key(
    secret_key: str, date_stamp: str, region: str, service: str
) -> bytes:
    k_date = _sign(("AWS4" + secret_key).encode("utf-8"), date_stamp)
    k_region = _sign(k_date, region)
    k_service = _sign(k_region, service)
    k_signing = _sign(k_service, "aws4_request")
    return k_signing


class AWSSecurityClient(BaseClient, ConnectorMixin):
    """
    HTTP client for AWS Security Hub and GuardDuty APIs.

    Signs requests using AWS Signature Version 4.

    Parameters
    ----------
    host : str
        Security Hub base URL (e.g.
        ``https://securityhub.us-east-1.amazonaws.com``).
    aws_access_key : str
        AWS IAM access key ID.
    aws_secret_key : str
        AWS IAM secret access key.
    aws_region : str
        AWS region (e.g. ``us-east-1``).
    aws_session_token : str
        Optional STS session token.
    guardduty_host : str
        Override for GuardDuty base URL. Defaults to same region.
    """

    stix_type_map: dict[str, str] = {
        "indicator":     "guardduty/findings",
        "vulnerability": "securityhub/findings",
        "report":        "securityhub/insights",
    }

    def __init__(
        self,
        host: str = "https://securityhub.us-east-1.amazonaws.com",
        aws_access_key: str = "",
        aws_secret_key: str = "",
        aws_region: str = "us-east-1",
        aws_session_token: str = "",
        guardduty_host: str = "",
        **kwargs: Any,
    ) -> None:
        super().__init__(host=host, **kwargs)
        self._access_key = aws_access_key
        self._secret_key = aws_secret_key
        self._region = aws_region
        self._session_token = aws_session_token
        self._guardduty_host = (
            guardduty_host
            or f"https://guardduty.{aws_region}.amazonaws.com"
        )

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Store credentials; SigV4 signing is applied per-request."""
        if not self._access_key or not self._secret_key:
            raise GNATClientError("AWS: aws_access_key and aws_secret_key are required")
        # Validation ping deferred to health_check; store service name
        self._auth_headers["X-Gnat-AWS-Service"] = "securityhub"

    def _aws_auth_headers(
        self, service: str, method: str, path: str, body: str = ""
    ) -> dict[str, str]:
        """Compute AWS SigV4 Authorization header for a request."""
        now = _utc_now()
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        date_stamp = now.strftime("%Y%m%d")

        # Determine host from current base URL
        parsed = urlparse(self._host)
        host_hdr = parsed.netloc

        payload_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()

        headers_to_sign = {
            "host": host_hdr,
            "x-amz-date": amz_date,
            "x-amz-content-sha256": payload_hash,
        }
        if self._session_token:
            headers_to_sign["x-amz-security-token"] = self._session_token

        canonical_headers = "".join(
            f"{k}:{v}\n" for k, v in sorted(headers_to_sign.items())
        )
        signed_headers = ";".join(sorted(headers_to_sign.keys()))

        canonical_request = "\n".join([
            method,
            path,
            "",   # query string (empty for POST bodies)
            canonical_headers,
            signed_headers,
            payload_hash,
        ])

        credential_scope = f"{date_stamp}/{self._region}/{service}/aws4_request"
        string_to_sign = "\n".join([
            "AWS4-HMAC-SHA256",
            amz_date,
            credential_scope,
            hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
        ])

        signing_key = _get_signature_key(
            self._secret_key, date_stamp, self._region, service
        )
        signature = hmac.new(
            signing_key, string_to_sign.encode("utf-8"), hashlib.sha256
        ).hexdigest()

        authorization = (
            f"AWS4-HMAC-SHA256 Credential={self._access_key}/{credential_scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        )
        result: dict[str, str] = {
            "Authorization": authorization,
            "X-Amz-Date": amz_date,
            "X-Amz-Content-Sha256": payload_hash,
            "Content-Type": "application/json",
        }
        if self._session_token:
            result["X-Amz-Security-Token"] = self._session_token
        return result

    # ── ConnectorMixin — CRUD ──────────────────────────────────────────────

    def health_check(self) -> bool:
        """Verify Security Hub connectivity by listing enabled standards."""
        self.get("/standards/subscriptions", params={"MaxResults": 1})
        return True

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """Fetch a single AWS finding by type and ID."""
        if stix_type in ("indicator", "vulnerability"):
            resp = self.post("/findings/get", json={"FindingIds": [object_id]})
            findings = resp.get("Findings", []) if isinstance(resp, dict) else []
            return findings[0] if findings else {}
        if stix_type == "report":
            return self.get(f"/insights/{object_id}")
        raise GNATClientError(f"Unsupported STIX type for AWS Security: {stix_type}")

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """List Security Hub or GuardDuty findings by STIX type."""
        f = filters or {}
        params: dict[str, Any] = {"MaxResults": page_size}
        if "next_token" in f:
            params["NextToken"] = f["next_token"]

        if stix_type == "vulnerability":
            body: dict[str, Any] = {"MaxResults": page_size}
            # Apply ASFF filters
            asff_filters: dict[str, Any] = {}
            if "severity" in f:
                asff_filters["SeverityLabel"] = [
                    {"Value": f["severity"].upper(), "Comparison": "EQUALS"}
                ]
            if asff_filters:
                body["Filters"] = asff_filters
            resp = self.post("/findings", json=body)
            return resp.get("Findings", []) if isinstance(resp, dict) else []

        if stix_type == "indicator":
            # GuardDuty findings
            detector_id = self._get_detector_id()
            if not detector_id:
                return []
            body_gd: dict[str, Any] = {
                "MaxResults": page_size,
                "FindingCriteria": f.get("finding_criteria", {}),
            }
            resp = self.post(
                f"/detector/{detector_id}/findings",
                json=body_gd,
            )
            ids = resp.get("FindingIds", []) if isinstance(resp, dict) else []
            if not ids:
                return []
            resp2 = self.post(
                f"/detector/{detector_id}/findings/get",
                json={"FindingIds": ids[:page_size]},
            )
            return resp2.get("Findings", []) if isinstance(resp2, dict) else []

        if stix_type == "report":
            resp = self.get("/insights", params=params)
            return resp.get("Insights", []) if isinstance(resp, dict) else []

        raise GNATClientError(f"Unsupported STIX type for AWS Security: {stix_type}")

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """Import custom findings in ASFF format."""
        if stix_type == "vulnerability":
            resp = self.post("/findings/import", json={"Findings": [payload]})
            return resp if isinstance(resp, dict) else {}
        raise GNATClientError(
            f"AWS Security: upsert not supported for STIX type '{stix_type}'"
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Archive a Security Hub finding (soft-delete via ARCHIVED status)."""
        self.patch("/findings", json={
            "FindingIdentifiers": [{"Id": object_id, "ProductArn": ""}],
            "Note": {"Text": "Archived by GNAT", "UpdatedBy": "gnat"},
            "RecordState": "ARCHIVED",
        })

    # ── Platform-specific helpers ──────────────────────────────────────────

    def _get_detector_id(self) -> str:
        """Fetch the first GuardDuty detector ID."""
        resp = self.get("/detector")
        ids = resp.get("DetectorIds", []) if isinstance(resp, dict) else []
        return ids[0] if ids else ""

    def get_security_hub_findings(
        self,
        severity: str | None = None,
        workflow_status: str | None = None,
        max_results: int = 100,
    ) -> list[dict[str, Any]]:
        """Fetch Security Hub findings with optional severity/workflow filters."""
        body: dict[str, Any] = {"MaxResults": max_results}
        asff: dict[str, Any] = {}
        if severity:
            asff["SeverityLabel"] = [{"Value": severity.upper(), "Comparison": "EQUALS"}]
        if workflow_status:
            asff["WorkflowStatus"] = [{"Value": workflow_status.upper(), "Comparison": "EQUALS"}]
        if asff:
            body["Filters"] = asff
        resp = self.post("/findings", json=body)
        return resp.get("Findings", []) if isinstance(resp, dict) else []

    def get_guardduty_findings(
        self,
        severity_min: float = 0.0,
        max_results: int = 50,
    ) -> list[dict[str, Any]]:
        """Fetch GuardDuty findings with optional minimum severity."""
        detector_id = self._get_detector_id()
        if not detector_id:
            return []
        criteria: dict[str, Any] = {}
        if severity_min > 0:
            criteria = {
                "severity": {
                    "Gte": severity_min,
                }
            }
        body: dict[str, Any] = {
            "MaxResults": max_results,
            "FindingCriteria": {"Criterion": criteria} if criteria else {},
        }
        resp = self.post(
            f"/detector/{detector_id}/findings",
            json=body,
        )
        ids = resp.get("FindingIds", []) if isinstance(resp, dict) else []
        if not ids:
            return []
        resp2 = self.post(
            f"/detector/{detector_id}/findings/get",
            json={"FindingIds": ids[:max_results]},
        )
        return resp2.get("Findings", []) if isinstance(resp2, dict) else []

    def enable_security_hub(self) -> dict[str, Any]:
        """Enable Security Hub for the current account."""
        resp = self.post("/accounts", json={})
        return resp if isinstance(resp, dict) else {}

    # ── STIX translation ───────────────────────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """Convert an AWS ASFF finding to STIX."""
        # GuardDuty findings have a Service block
        if "Service" in native and "Action" in native.get("Service", {}):
            return self._guardduty_to_stix(native)
        # Security Hub findings
        return self._securityhub_to_stix(native)

    def _securityhub_to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        finding_id = native.get("Id", "")
        uid = str(_uuid.uuid5(_STIX_NS, f"aws-sh-{finding_id}"))
        sev = native.get("Severity", {})
        sev_label = (
            sev.get("Label", "INFORMATIONAL").upper()
            if isinstance(sev, dict)
            else "INFORMATIONAL"
        )
        sev_map = {"CRITICAL": 90, "HIGH": 75, "MEDIUM": 50, "LOW": 25, "INFORMATIONAL": 10}
        confidence = sev_map.get(sev_label, 10)
        vuln_ids = [v.get("Id", "") for v in native.get("Vulnerabilities", [])]
        return {
            "type": "vulnerability",
            "id": f"vulnerability--{uid}",
            "name": native.get("Title", finding_id),
            "description": native.get("Description", "")[:1000],
            "created": native.get("CreatedAt", _now_ts()),
            "modified": native.get("UpdatedAt", _now_ts()),
            "x_source_platform": "aws_security",
            "x_aws": {
                "finding_id": finding_id,
                "product_arn": native.get("ProductArn", ""),
                "generator_id": native.get("GeneratorId", ""),
                "severity_label": sev_label,
                "severity_score": confidence,
                "workflow_status": native.get("Workflow", {}).get("Status", ""),
                "cve_ids": vuln_ids,
                "region": native.get("Region", ""),
                "account_id": native.get("AwsAccountId", ""),
                "source": "securityhub",
            },
        }

    def _guardduty_to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        finding_id = native.get("Id", "")
        uid = str(_uuid.uuid5(_STIX_NS, f"aws-gd-{finding_id}"))
        severity = native.get("Severity", 0.0)
        confidence = min(100, int(severity * 10))

        svc = native.get("Service", {})
        action = svc.get("Action", {})
        action_type = action.get("ActionType", "")
        network = action.get("NetworkConnectionAction", action.get("PortProbeAction", {}))
        remote_ip = (
            network.get("RemoteIpDetails", {}).get("IpAddressV4", "")
            if isinstance(network, dict) else ""
        )
        if remote_ip:
            pattern = f"[ipv4-addr:value = '{remote_ip}']"
        else:
            # Non-network finding: represent as a named file artifact using the finding ID
            pattern = f"[file:name = 'aws-guardduty-finding-{finding_id[:36]}']"
        return {
            "type": "indicator",
            "id": f"indicator--{uid}",
            "name": native.get("Title", finding_id),
            "pattern": pattern,
            "pattern_type": "stix",
            "created": native.get("CreatedAt", _now_ts()),
            "modified": native.get("UpdatedAt", _now_ts()),
            "indicator_types": ["malicious-activity"],
            "confidence": confidence,
            "x_source_platform": "aws_security",
            "x_aws": {
                "finding_id": finding_id,
                "type": native.get("Type", ""),
                "severity": severity,
                "action_type": action_type,
                "remote_ip": remote_ip,
                "region": native.get("Region", ""),
                "account_id": native.get("AccountId", ""),
                "source": "guardduty",
            },
        }

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """Convert a STIX dict to an ASFF finding payload."""
        return {
            "Title": stix_dict.get("name", ""),
            "Description": stix_dict.get("description", ""),
            "Severity": {"Label": "MEDIUM"},
            "Types": ["Software and Configuration Checks"],
            "stix_id": stix_dict.get("id", ""),
        }
