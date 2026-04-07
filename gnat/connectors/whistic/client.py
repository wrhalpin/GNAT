# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.whistic.client
===================================

Whistic Vendor Security Network connector.

**Scope:** Vendor list and questionnaire workflows only (per original spec).
Whistic is a vendor risk management platform — it does not produce traditional
threat indicators.  This connector maps Whistic vendor assessments and
questionnaire responses to STIX ``threat-actor`` (vendor identity) and
``x-whistic-assessment`` custom objects.

Authentication
--------------
API key via ``X-Whistic-Token`` header::

    [whistic]
    host    = https://api.whistic.com
    api_key = <api-key>
    auth_type = api_key

STIX Type Mapping
-----------------
+--------------------+----------------------------------+
| STIX Type          | Whistic Resource                 |
+====================+==================================+
| threat-actor       | vendor                           |
+--------------------+----------------------------------+
| x-assessment       | assessment / questionnaire       |
+--------------------+----------------------------------+

Workflow
--------
1. ``list_vendors()`` — list all vendors in your Whistic network
2. ``get_vendor(vendor_id)`` — full vendor profile + trust score
3. ``list_assessments(vendor_id)`` — questionnaire submissions for a vendor
4. ``get_assessment(assessment_id)`` — detailed assessment with responses
5. ``request_assessment(vendor_id, profile_id)`` — send a new questionnaire

The ``to_stix()`` method produces a ``threat-actor`` node (representing the
vendor as a third-party entity) plus an ``x_whistic_trust_score`` extension
field.  Relationship objects connect vendors to their assessments.
"""

from __future__ import annotations

from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin


class WhisticClient(BaseClient, ConnectorMixin):
    """
    HTTP client for the Whistic REST API.

    Parameters
    ----------
    host : str
        Base URL, e.g. ``"https://api.whistic.com"``.
    api_key : str
        Whistic API key.
    """

    stix_type_map: dict[str, str] = {
        "threat-actor": "vendors",
        "x-assessment": "assessments",
    }

    def __init__(self, host: str, api_key: str = "", **kwargs: Any):
        super().__init__(host=host, **kwargs)
        self._api_key = api_key

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Inject the Whistic API key header."""
        self._auth_headers["X-Whistic-Token"] = self._api_key

    # ── ConnectorMixin — CRUD ─────────────────────────────────────────────

    def health_check(self) -> bool:
        """Verify connectivity via the Whistic API."""
        self.get("/v1/vendors", params={"limit": 1})
        return True

    def get_object(self, stix_type: str, object_id: str) -> dict[str, Any]:
        """
        Fetch a Whistic vendor or assessment by id.

        Parameters
        ----------
        stix_type : str
            ``"threat-actor"`` → vendor, ``"x-assessment"`` → assessment.
        object_id : str
            Whistic entity UUID.
        """
        if stix_type == "threat-actor":
            return self.get_vendor(object_id)
        if stix_type == "x-assessment":
            return self.get_assessment(object_id)
        raise GNATClientError(f"Whistic: unsupported STIX type '{stix_type}'")

    def list_objects(
        self,
        stix_type: str,
        filters: dict[str, Any] | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """List Whistic vendors or assessments."""
        if stix_type == "threat-actor":
            return self.list_vendors(page=page, page_size=page_size, filters=filters)
        if stix_type == "x-assessment":
            vendor_id = (filters or {}).get("vendor_id")
            return self.list_assessments(vendor_id=vendor_id, page=page, page_size=page_size)
        raise GNATClientError(f"Whistic: unsupported STIX type '{stix_type}'")

    def upsert_object(self, stix_type: str, payload: dict[str, Any]) -> dict[str, Any]:
        """
        Create or update a Whistic resource.

        For vendors: updates the vendor profile.
        For assessments: sends a new questionnaire request.
        """
        if stix_type == "x-assessment":
            vendor_id = payload.get("vendor_id", "")
            profile_id = payload.get("profile_id", "")
            return self.request_assessment(vendor_id, profile_id)
        raise GNATClientError(
            "Whistic: direct vendor creation is not supported. "
            "Vendors are added via the Whistic network invitation flow."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Remove a vendor from your network."""
        if stix_type == "threat-actor":
            self.delete(f"/v1/vendors/{object_id}")
            return
        raise GNATClientError(f"Whistic: delete not supported for '{stix_type}'")

    # ── Domain-specific operations ────────────────────────────────────────

    def list_vendors(
        self,
        page: int = 1,
        page_size: int = 100,
        filters: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """
        List all vendors in your Whistic network.

        Parameters
        ----------
        filters : dict, optional
            Optional filters: ``status``, ``trust_score_min``,
            ``trust_score_max``, ``category``.

        Returns
        -------
        list of dict
            Raw Whistic vendor objects.
        """
        params: dict[str, Any] = {
            "limit": page_size,
            "offset": (page - 1) * page_size,
        }
        if filters:
            params.update(filters)
        resp = self.get("/v1/vendors", params=params)
        return resp.get("vendors", []) if isinstance(resp, dict) else []

    def get_vendor(self, vendor_id: str) -> dict[str, Any]:
        """
        Fetch full vendor profile including trust score and assessment status.

        Parameters
        ----------
        vendor_id : str
            Whistic vendor UUID.

        Returns
        -------
        dict
            Vendor profile with ``name``, ``trust_score``,
            ``assessment_status``, ``categories``.
        """
        return self.get(f"/v1/vendors/{vendor_id}")

    def list_assessments(
        self,
        vendor_id: str | None = None,
        page: int = 1,
        page_size: int = 100,
    ) -> list[dict[str, Any]]:
        """
        List questionnaire assessments, optionally filtered by vendor.

        Parameters
        ----------
        vendor_id : str, optional
            If provided, only return assessments for this vendor.
        """
        params: dict[str, Any] = {
            "limit": page_size,
            "offset": (page - 1) * page_size,
        }
        if vendor_id:
            params["vendor_id"] = vendor_id
        resp = self.get("/v1/assessments", params=params)
        return resp.get("assessments", []) if isinstance(resp, dict) else []

    def get_assessment(self, assessment_id: str) -> dict[str, Any]:
        """
        Fetch a completed questionnaire assessment with all question responses.

        Parameters
        ----------
        assessment_id : str
            Whistic assessment UUID.

        Returns
        -------
        dict
            Assessment with ``profile_name``, ``completed_at``,
            ``overall_score``, ``sections`` containing Q&A responses.
        """
        return self.get(f"/v1/assessments/{assessment_id}")

    def request_assessment(
        self,
        vendor_id: str,
        profile_id: str,
        message: str = "",
    ) -> dict[str, Any]:
        """
        Send a questionnaire request to a vendor.

        Parameters
        ----------
        vendor_id : str
            Target vendor UUID.
        profile_id : str
            Whistic security profile UUID to use as the questionnaire template.
        message : str, optional
            Optional personal message included in the request email.

        Returns
        -------
        dict
            The newly-created assessment object.
        """
        return self.post(
            "/v1/assessments",
            json={
                "vendor_id": vendor_id,
                "profile_id": profile_id,
                "message": message,
            },
        )

    def get_trust_score(self, vendor_id: str) -> float | None:
        """
        Return just the trust score for a vendor (0.0–100.0).

        Parameters
        ----------
        vendor_id : str
            Whistic vendor UUID.

        Returns
        -------
        float or None
            Trust score, or ``None`` if not yet assessed.
        """
        vendor = self.get_vendor(vendor_id)
        return vendor.get("trust_score")

    # ── ConnectorMixin — STIX translation ─────────────────────────────────

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """
        Translate a Whistic vendor record to a STIX threat-actor object.

        The ``threat-actor`` type is used to represent a third-party vendor
        as an entity in the security posture graph.  The trust score is
        carried as ``x_whistic_trust_score``.
        """
        data = native.get("data", native)
        categories = data.get("categories", [])
        stix: dict[str, Any] = {
            "type": "threat-actor",
            "id": f"threat-actor--{data.get('id', '')}",
            "name": data.get("name", ""),
            "description": data.get("description", ""),
            "created": data.get("created_at", ""),
            "modified": data.get("updated_at", ""),
            "threat_actor_types": ["vendor"],
            "x_whistic_trust_score": data.get("trust_score"),
            "x_whistic_status": data.get("assessment_status", ""),
            "x_whistic_categories": categories,
            "x_whistic_vendor_id": data.get("id", ""),
            "x_whistic_profile_complete": data.get("profile_complete", False),
        }
        if categories:
            stix["x_target_sectors"] = categories
        return stix

    def from_stix(self, stix_dict: dict[str, Any]) -> dict[str, Any]:
        """
        Translate a STIX threat-actor dict to a Whistic vendor update payload.
        """
        return {
            "name": stix_dict.get("name", ""),
            "description": stix_dict.get("description", ""),
        }

    def assessment_to_stix(self, assessment: dict[str, Any]) -> dict[str, Any]:
        """
        Translate a Whistic assessment to a custom STIX-like assessment object.

        Returns a dict with ``type: x-whistic-assessment`` carrying the
        overall score and completion metadata.  Link this to a vendor
        ``threat-actor`` via a Relationship with ``relationship_type:
        "assessed-by"``.
        """
        data = assessment.get("data", assessment)
        return {
            "type": "x-whistic-assessment",
            "id": f"x-whistic-assessment--{data.get('id', '')}",
            "name": data.get("profile_name", ""),
            "created": data.get("created_at", ""),
            "modified": data.get("completed_at", ""),
            "x_whistic_assessment_id": data.get("id", ""),
            "x_whistic_overall_score": data.get("overall_score"),
            "x_whistic_completed_at": data.get("completed_at", ""),
            "x_whistic_vendor_id": data.get("vendor_id", ""),
            "x_whistic_profile_id": data.get("profile_id", ""),
            "x_whistic_section_scores": {
                s.get("name", ""): s.get("score") for s in data.get("sections", [])
            },
        }

    # ── Profiles (questionnaire templates) ───────────────────────────────────

    def list_profiles(self) -> list[dict[str, Any]]:
        """List available Whistic security profile templates."""
        resp = self.get("/v1/profiles")
        return resp.get("profiles", []) if isinstance(resp, dict) else []

    def get_profile(self, profile_id: str) -> dict[str, Any]:
        """Retrieve a specific security profile template by ID."""
        return self.get(f"/v1/profiles/{profile_id}")

    # ── Vendor management ─────────────────────────────────────────────────────

    def search_vendors(self, query: str, limit: int = 50) -> list[dict[str, Any]]:
        """Search the Whistic vendor network by name or domain."""
        resp = self.get("/v1/vendors/search", params={"q": query, "limit": limit})
        return resp.get("vendors", []) if isinstance(resp, dict) else []

    def update_vendor(self, vendor_id: str, updates: dict[str, Any]) -> dict[str, Any]:
        """Update vendor metadata (tier, tags, notes, etc.)."""
        resp = self.patch(f"/v1/vendors/{vendor_id}", json=updates)
        return resp if isinstance(resp, dict) else {}

    def invite_vendor(
        self,
        email: str,
        name: str = "",
        message: str = "",
        profile_id: str = "",
    ) -> dict[str, Any]:
        """
        Invite a vendor to join your Whistic network.

        An email invitation is sent to the vendor's security contact.
        """
        payload: dict[str, Any] = {"email": email}
        if name:
            payload["name"] = name
        if message:
            payload["message"] = message
        if profile_id:
            payload["profile_id"] = profile_id
        return self.post("/v1/vendors/invite", json=payload)

    def get_vendor_risk_summary(self, vendor_id: str) -> dict[str, Any]:
        """
        Retrieve a consolidated risk summary for a vendor.

        Returns trust score, assessment completion, and section-level
        risk breakdowns.
        """
        resp = self.get(f"/v1/vendors/{vendor_id}/risk-summary")
        return resp if isinstance(resp, dict) else {}

    def list_vendor_documents(self, vendor_id: str) -> list[dict[str, Any]]:
        """List compliance documents (SOC 2, ISO 27001, etc.) shared by a vendor."""
        resp = self.get(f"/v1/vendors/{vendor_id}/documents")
        return resp.get("documents", []) if isinstance(resp, dict) else []

    def get_vendor_document(self, vendor_id: str, document_id: str) -> dict[str, Any]:
        """Retrieve metadata and download URL for a specific compliance document."""
        return self.get(f"/v1/vendors/{vendor_id}/documents/{document_id}")

    def list_contacts(self, vendor_id: str) -> list[dict[str, Any]]:
        """List security contacts associated with a vendor."""
        resp = self.get(f"/v1/vendors/{vendor_id}/contacts")
        return resp.get("contacts", []) if isinstance(resp, dict) else []

    def add_contact(
        self,
        vendor_id: str,
        name: str,
        email: str,
        role: str = "",
    ) -> dict[str, Any]:
        """Add a security contact to a vendor record."""
        payload: dict[str, Any] = {"name": name, "email": email}
        if role:
            payload["role"] = role
        return self.post(f"/v1/vendors/{vendor_id}/contacts", json=payload)

    # ── Assessment lifecycle ──────────────────────────────────────────────────

    def bulk_request_assessments(
        self,
        vendor_ids: list[str],
        profile_id: str,
        message: str = "",
    ) -> list[dict[str, Any]]:
        """
        Send a questionnaire request to multiple vendors at once.

        Returns a list of newly created assessment objects.
        """
        results = []
        for vid in vendor_ids:
            try:
                result = self.request_assessment(vid, profile_id, message)
                results.append(result)
            except Exception:
                results.append({"vendor_id": vid, "error": "request_failed"})
        return results

    def resend_assessment_request(self, assessment_id: str) -> dict[str, Any]:
        """Resend a reminder to a vendor for a pending assessment."""
        return self.post(f"/v1/assessments/{assessment_id}/resend")

    def archive_assessment(self, assessment_id: str) -> dict[str, Any]:
        """Archive a completed or superseded assessment."""
        return self.post(f"/v1/assessments/{assessment_id}/archive")

    def get_assessment_sections(self, assessment_id: str) -> list[dict[str, Any]]:
        """
        Retrieve section-level scores and responses for an assessment.

        Returns a list of section dicts each containing ``name``,
        ``score``, ``max_score``, and ``questions``.
        """
        resp = self.get(f"/v1/assessments/{assessment_id}/sections")
        return resp.get("sections", []) if isinstance(resp, dict) else []

    # ── Risk exceptions ───────────────────────────────────────────────────────

    def list_exceptions(self, vendor_id: str) -> list[dict[str, Any]]:
        """List accepted risk exceptions for a vendor."""
        resp = self.get(f"/v1/vendors/{vendor_id}/exceptions")
        return resp.get("exceptions", []) if isinstance(resp, dict) else []

    def create_exception(
        self,
        vendor_id: str,
        criterion: str,
        reason: str,
        expires_at: str = "",
    ) -> dict[str, Any]:
        """
        Accept a risk exception for a specific criterion on a vendor.

        ``criterion`` — name or ID of the failing control.
        ``expires_at`` — ISO 8601 date for exception expiry (optional).
        """
        payload: dict[str, Any] = {"criterion": criterion, "reason": reason}
        if expires_at:
            payload["expires_at"] = expires_at
        return self.post(f"/v1/vendors/{vendor_id}/exceptions", json=payload)

    # ── Portfolio & reporting ─────────────────────────────────────────────────

    def get_network_stats(self) -> dict[str, Any]:
        """
        Retrieve aggregate portfolio statistics.

        Returns vendor counts by trust score tier, assessment completion
        rates, and risk distribution across the monitored vendor network.
        """
        resp = self.get("/v1/network/stats")
        return resp if isinstance(resp, dict) else {}

    def list_categories(self) -> list[dict[str, Any]]:
        """List all available vendor risk categories."""
        resp = self.get("/v1/categories")
        return resp.get("categories", []) if isinstance(resp, dict) else []

    def list_integrations(self) -> list[dict[str, Any]]:
        """List configured third-party integrations (Jira, Slack, SSO, etc.)."""
        resp = self.get("/v1/integrations")
        return resp.get("integrations", []) if isinstance(resp, dict) else []
