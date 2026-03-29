"""
gnat.connectors.copilot.client
==============================

Copilot (LLM) connector.

Authentication
--------------
Supports multiple auth modes via config::

    [copilot]
    host        = https://your-copilot-endpoint
    auth_type   = api_key  # or azure, none
    api_key     = <your-api-key>
    azure_token = <your-azure-ad-token>

STIX Type Mapping
-----------------
+----------------+----------------------------------+
| STIX Type      | Copilot Resource                 |
+================+==================================+
| report         | chat completion / conversation   |
+----------------+----------------------------------+

Key Endpoints
-------------
* ``/v1/chat/completions`` — main inference endpoint (OpenAI-compatible)
* ``/v1/models``           — list available models (health / discovery)

Notes
-----
* Copilot is **read-only inference** — no persistent object storage or mutation.
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


class CopilotClient(BaseClient, ConnectorMixin):
    """Generic Copilot-style LLM connector.

    Supports:
    - Microsoft Copilot (Azure AD auth)
    - Internal Copilot-like LLMs (API key or no auth)

    Parameters
    ----------
    host : str
        Base URL for the LLM endpoint.
    auth_type : str
        "azure", "api_key", or "none".
    api_key : str
        API key for internal deployments.
    azure_token : str
        Azure AD token for Microsoft Copilot.
    """

    stix_type_map: Dict[str, str] = {"report": "chat"}

    def __init__(
        self,
        host: str = "https://your-copilot-endpoint",
        auth_type: str = "api_key",
        api_key: str = "",
        azure_token: str = "",
        **kwargs: Any,
    ) -> None:
        super().__init__(host=host, **kwargs)
        self.auth_type = auth_type
        self.api_key = api_key
        self.azure_token = azure_token

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def authenticate(self) -> None:
        """Inject auth headers based on configured auth_type."""
        if self.auth_type == "api_key":
            self._auth_headers["Authorization"] = f"Bearer {self.api_key}"
        elif self.auth_type == "azure":
            self._auth_headers["Authorization"] = f"Bearer {self.azure_token}"
        elif self.auth_type == "none":
            # No auth header
            pass
        else:
            raise GNATClientError(f"Unknown auth_type: {self.auth_type}")

        self._auth_headers["Accept"] = "application/json"
        self._auth_headers["Content-Type"] = "application/json"

    # ------------------------------------------------------------------
    # CRUD (read-only)
    # ------------------------------------------------------------------

    def health_check(self) -> bool:
        """Verify connectivity via the models list endpoint."""
        self.get("/v1/models")
        return True

    def get_object(self, stix_type: str, object_id: str) -> Dict[str, Any]:
        """Copilot does not support persistent objects."""
        raise GNATClientError("Copilot does not support retrieving persistent objects by ID.")

    def list_objects(
        self,
        stix_type: str,
        filters: Optional[Dict[str, Any]] = None,
        page: int = 1,
        page_size: int = 10,
    ) -> List[Dict[str, Any]]:
        """List available models as lightweight "objects" for STIX report discovery."""
        if stix_type != "report":
            raise GNATClientError(f"list_objects not meaningfully supported for STIX type: {stix_type}")

        resp = self.get("/v1/models")
        models = resp.get("data", []) if isinstance(resp, dict) else []
        return [{"id": m.get("id"), "type": "model"} for m in models]

    def upsert_object(self, stix_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Copilot is inference-only — no object creation/updates."""
        raise GNATClientError("Copilot is inference-only. Use chat_completion helper instead.")

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """Copilot has no persistent object deletion."""
        raise GNATClientError("Copilot does not support object deletion.")

    # ------------------------------------------------------------------
    # Domain-specific operations (platform-specific)
    # ------------------------------------------------------------------

    def chat_completion(
        self,
        messages: List[Dict[str, str]],
        model: str = "copilot-latest",
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Perform a chat completion against the Copilot-compatible API."""
        payload: Dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            **({"max_tokens": max_tokens} if max_tokens is not None else {}),
            **kwargs,
        }
        return self.post("/v1/chat/completions", json=payload)

    # ------------------------------------------------------------------
    # STIX translation
    # ------------------------------------------------------------------

    def to_stix(self, native: Dict[str, Any]) -> Dict[str, Any]:
        """Convert a Copilot chat completion or model list to a STIX 2.1 report."""
        now = _now_ts()

        if "choices" in native:
            content = native.get("choices", [{}])[0].get("message", {}).get("content", "")
            model_used = native.get("model", "unknown")
            report_id = f"report--copilot-{hash(content) % 10**12}"

            return {
                "type": "report",
                "id": report_id,
                "spec_version": "2.1",
                "created": now,
                "modified": now,
                "name": f"Copilot Analysis ({model_used})",
                "description": content[:500] + ("..." if len(content) > 500 else ""),
                "report_types": ["threat-report", "analysis"],
                "labels": ["copilot", "ai"],
                "x_copilot": {
                    "model": model_used,
                    "completion_id": native.get("id"),
                    "usage": native.get("usage", {}),
                    "raw_response": native,
                },
            }

        return {
            "type": "report",
            "id": f"report--copilot-models-{now.replace(':', '')}",
            "spec_version": "2.1",
            "created": now,
            "modified": now,
            "name": "Copilot Available Models",
            "description": "List of supported Copilot models from the API.",
            "x_copilot": {"models": native.get("data", [])},
        }

    def from_stix(self, stix_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Return a suggested prompt template for use with chat_completion."""
        return {
            "note": "Copilot connector is inference-only. Use chat_completion with messages derived from this STIX object.",
            "suggested_messages": [
                {"role": "system", "content": "You are a helpful threat intelligence analyst."},
                {"role": "user", "content": stix_dict.get("description", "Analyze this threat intel.")},
            ],
            "stix_id": stix_dict.get("id", ""),
        }
