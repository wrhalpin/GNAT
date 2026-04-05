from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin


class GeminiClient(BaseClient, ConnectorMixin):
    """
    GNAT Connector for Google Gemini with search-to-STIX capabilities.
    """

    stix_type_map = {
        "report": "generate_content",
    }

    def __init__(
        self,
        host: str = "https://generativelanguage.googleapis.com",
        api_key: str = "",
        **kwargs: Any,
    ):
        super().__init__(host=host, **kwargs)
        self._api_key = api_key

    def authenticate(self) -> None:
        """Gemini often uses a query parameter or custom header for API keys."""
        self._auth_headers["x-goog-api-key"] = self._api_key
        self._auth_headers["Content-Type"] = "application/json"

    def health_check(self) -> bool:
        """Ping the models list to verify the API key."""
        self.get("/v1beta/models")
        return True

    def to_stix(self, native: dict[str, Any]) -> dict[str, Any]:
        """
        Parses Gemini's response. Ideally, we prompt Gemini to return
        valid STIX 2.1 JSON directly in the 'text' field.
        """
        content = (
            native.get("candidates", [{}])[0]
            .get("content", {})
            .get("parts", [{}])[0]
            .get("text", "")
        )
        try:
            # Attempt to parse Gemini's output as STIX JSON
            return json.loads(content)
        except json.JSONDecodeError:
            # Fallback to a basic report if parsing fails
            now = datetime.now(timezone.utc).isoformat()
            return {
                "type": "report",
                "id": f"report--gemini-{datetime.now().timestamp()}",
                "spec_version": "2.1",
                "created": now,
                "modified": now,
                "name": "Gemini Research Result",
                "description": content[:500],
            }

    def research_to_stix(self, concept: str) -> dict[str, Any]:
        """
        Custom method: Sends a research concept to Gemini with instructions
        to use search and return a STIX 2.1 Report.
        """
        payload = {
            "contents": [
                {
                    "parts": [
                        {
                            "text": (
                                f"Research the following concept: {concept}. "
                                "Search for recent threat intelligence, actors, and indicators. "
                                "Return the results strictly as a valid STIX 2.1 JSON Report object."
                            )
                        }
                    ]
                }
            ],
            "tools": [{"google_search": {}}],  # Enables search grounding
        }

        # Call Gemini's generation endpoint
        resp = self.post("/v1beta/models/gemini-2.0-flash:generateContent", json=payload)
        return self.to_stix(resp)

    # Implement other CRUD stubs as GNATClientError (inference-only)
    def upsert_object(self, stix_type, payload):
        raise GNATClientError("Gemini is read-only research/inference.")
