"""
gnat.connectors.grok.client
===========================

Grok (xAI) connector.

Authentication
--------------
API key via ``Authorization: Bearer`` header::

    [grok]
    host      = https://api.x.ai
    api_key   = <your-xai-api-key>

Get your free/paid API key at https://console.x.ai (or https://x.ai/api).

STIX Type Mapping
-----------------
+----------------+----------------------------------+
| STIX Type      | Grok Resource                    |
+================+==================================+
| report         | chat completion / conversation   |
+----------------+----------------------------------+

Key Endpoints
-------------
* ``/v1/chat/completions`` — main inference endpoint (OpenAI-compatible)
* ``/v1/models``           — list available models (health / discovery)

Notes
-----
* Grok is **read-only inference** — no persistent object storage or mutation.
* Designed for AI-assisted threat intel workflows (e.g., analysis, summarization, research).
* Supports standard chat parameters (model, temperature, max_tokens, etc.).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin


def _now_ts() -> str:
    """ISO 8601 timestamp with millisecond precision."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class GrokClient(BaseClient, ConnectorMixin):
    """
    HTTP client for the xAI Grok API (OpenAI-compatible).

    Parameters
    ----------
    host : str
        Base URL, e.g. ``"https://api.x.ai"``.
    api_key : str
        xAI API key.
    """

    stix_type_map: Dict[str, str] = {
        "report": "chat",  # chat completions mapped to STIX reports
    }

    def __init__(self, host: str = "https://api.x.ai", api_key: str = "", **kwargs: Any):
        super().__init__(host=host, **kwargs)
        self._api_key = api_key

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Inject the xAI Bearer token and JSON headers."""
        self._auth_headers["Authorization"] = f"Bearer {self._api_key}"
        self._auth_headers["Accept"] = "application/json"
        self._auth_headers["Content-Type"] = "application/json"

    # ── ConnectorMixin — CRUD ─────────────────────────────────────────────

    def health_check(self) -> bool:
        """Verify connectivity via the models list endpoint."""
        self.get("/v1/models")
        return True

    def get_object(self, stix_type: str, object_id: str) -> Dict[str, Any]:
        """
        Not directly supported (no persistent objects). Returns a placeholder.

        For chat history simulation, use ``chat_completion`` instead.
        """
        if stix_type == "report":
            # Could extend to retrieve previous responses if xAI adds IDs later
            raise GNATClientError(
                f"Grok does not support retrieving persistent objects by ID. "
                f"Use chat_completion for new inferences."
            )
        raise GNATClientError(f"Unsupported STIX type for Grok: {stix_type}")

    def list_objects(
        self,
        stix_type: str,
        filters: Optional[Dict[str, Any]] = None,
        page: int = 1,
        page_size: int = 10,
    ) -> List[Dict[str, Any]]:
        """
        List available models (for "report" or discovery) or raise for other types.

        Filters are ignored for now (Grok has no native list of past chats).
        """
        if stix_type == "report":
            # Return list of available models as lightweight "reports"
            resp = self.get("/v1/models")
            models = resp.get("data", []) if isinstance(resp, dict) else []
            return [{"id": m.get("id"), "type": "model"} for m in models]
        raise GNATClientError(f"list_objects not meaningfully supported for STIX type: {stix_type}")

    def upsert_object(self, stix_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Grok is inference-only — no object creation/updates."""
        raise GNATClientError("Grok (xAI) is read-only inference. Use chat_completion helper instead.")

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Grok has no persistent object deletion."""
        raise GNATClientError("Grok (xAI) does not support object deletion.")

    # ── Domain-specific operations (platform-specific) ─────────────────────

    def chat_completion(
        self,
        messages: List[Dict[str, str]],
        model: str = "grok-4-0709",  # or latest flagship from docs
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Perform a chat completion against the Grok API.

        Parameters
        ----------
        messages : list of dict
            List of {"role": "system|user|assistant", "content": str}.
        model : str
            Grok model ID (e.g., "grok-4-0709", "grok-4-1-fast-reasoning", etc.).
        temperature : float
            Sampling temperature (0.0–2.0).
        max_tokens : int, optional
            Maximum output tokens.

        Returns
        -------
        dict
            Full API response (choices, usage, etc.).
        """
        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            **({"max_tokens": max_tokens} if max_tokens is not None else {}),
            **kwargs,
        }
        return self.post("/v1/chat/completions", json=payload)

    # ── ConnectorMixin — STIX translation ─────────────────────────────────

    def to_stix(self, native: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert a Grok chat completion response (or model list) to STIX 2.1 report.

        Parameters
        ----------
        native : dict
            Raw response from chat_completion or /v1/models.

        Returns
        -------
        dict
            STIX Report SDO with x_grok metadata.
        """
        now = _now_ts()

        if "choices" in native:  # chat completion response
            content = native.get("choices", [{}])[0].get("message", {}).get("content", "")
            model_used = native.get("model", "unknown")
            report_id = f"report--grok-{hash(content) % 10**12}"  # simplistic deterministic ID

            return {
                "type": "report",
                "id": report_id,
                "spec_version": "2.1",
                "created": now,
                "modified": now,
                "name": f"Grok Analysis ({model_used})",
                "description": content[:500] + ("..." if len(content) > 500 else ""),
                "report_types": ["threat-report", "analysis"],
                "labels": ["grok", "xai"],
                "x_grok": {
                    "model": model_used,
                    "completion_id": native.get("id"),
                    "usage": native.get("usage", {}),
                    "raw_response": native,  # full payload for debugging
                },
            }

        # Fallback for model list or other native objects
        return {
            "type": "report",
            "id": f"report--grok-models-{now.replace(':', '')}",
            "spec_version": "2.1",
            "created": now,
            "modified": now,
            "name": "Grok Available Models",
            "description": "List of supported Grok models from xAI API.",
            "x_grok": {"models": native.get("data", [])},
        }

    def from_stix(self, stix_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Grok is read-only inference. Returns a prompt template for chat."""
        return {
            "note": "Grok connector is inference-only. Use chat_completion with messages derived from this STIX object.",
            "suggested_messages": [
                {"role": "system", "content": "You are a helpful threat intelligence analyst."},
                {"role": "user", "content": stix_dict.get("description", "Analyze this threat intel.")},
            ],
            "stix_id": stix_dict.get("id", ""),
        }