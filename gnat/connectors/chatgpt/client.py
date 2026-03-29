"""
gnat.connectors.chatgpt.client
==============================

ChatGPT connector.

Authentication
--------------
API key via ``Authorization: Bearer`` header::

    [chatgpt]
    host    = https://api.openai.com
    api_key = <your-openai-api-key>

STIX Type Mapping
-----------------
+----------------+----------------------------------+
| STIX Type      | ChatGPT Resource                 |
+================+==================================+
| report         | chat completion / response       |
+----------------+----------------------------------+

Key Endpoints
-------------
* ``/v1/chat/completions`` — chat inference endpoint
* ``/v1/models``           — model discovery / health check

Notes
-----
* ChatGPT is **read-only inference** — no persistent object storage.
* Designed for AI-assisted threat intel workflows.
* Prompt results are converted to STIX 2.1 reports.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.base_connector import ConnectorMixin


def _now_ts() -> str:
    """ISO 8601 timestamp with millisecond precision."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _stable_report_id(text: str, model: str) -> str:
    """Create a deterministic STIX-ish report id suffix from content."""
    material = f"{model}:{text}".encode("utf-8")
    digest = hashlib.sha256(material).hexdigest()[:24]
    return f"report--chatgpt-{digest}"


class ChatGPTClient(BaseClient, ConnectorMixin):
    """
    HTTP client for the OpenAI Chat Completions API.

    Parameters
    ----------
    host : str
        Base URL, e.g. ``"https://api.openai.com"``.
    api_key : str
        OpenAI API key.
    """

    stix_type_map: Dict[str, str] = {
        "report": "chat",
    }

    def __init__(self, host: str = "https://api.openai.com", api_key: str = "", **kwargs: Any):
        super().__init__(host=host.rstrip("/"), **kwargs)
        self._api_key = api_key

    # ── Authentication ─────────────────────────────────────────────────────

    def authenticate(self) -> None:
        """Inject the OpenAI Bearer token and JSON headers."""
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
        Not supported because chat completions are not treated as persistent objects.
        """
        if stix_type == "report":
            raise GNATClientError(
                "ChatGPT does not support retrieving persistent objects by ID. "
                "Use chat_completion() for new inference."
            )
        raise GNATClientError(f"Unsupported STIX type for ChatGPT: {stix_type}")

    def list_objects(
        self,
        stix_type: str,
        filters: Optional[Dict[str, Any]] = None,
        page: int = 1,
        page_size: int = 10,
    ) -> List[Dict[str, Any]]:
        """
        Return model inventory as lightweight discovery objects.

        ChatGPT has no native list of prior conversations here, so this mirrors
        the Grok connector pattern.
        """
        if stix_type == "report":
            resp = self.get("/v1/models")
            models = resp.get("data", []) if isinstance(resp, dict) else []
            return [{"id": m.get("id"), "type": "model"} for m in models]
        raise GNATClientError(
            f"list_objects not meaningfully supported for STIX type: {stix_type}"
        )

    def upsert_object(self, stix_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """ChatGPT is inference-only — no object creation/updates."""
        raise GNATClientError(
            "ChatGPT connector is read-only inference. Use chat_completion() helper instead."
        )

    def delete_object(self, stix_type: str, object_id: str) -> None:
        """ChatGPT has no persistent object deletion."""
        raise GNATClientError("ChatGPT does not support object deletion.")

    # ── Domain-specific operations ─────────────────────────────────────────

    def chat_completion(
        self,
        messages: List[Dict[str, str]],
        model: str = "gpt-4.1",
        temperature: float = 0.2,
        max_tokens: Optional[int] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Perform a chat completion against the OpenAI API.

        Parameters
        ----------
        messages : list of dict
            List of {"role": "system|user|assistant", "content": str}.
        model : str
            OpenAI model ID.
        temperature : float
            Sampling temperature.
        max_tokens : int, optional
            Maximum output tokens.

        Returns
        -------
        dict
            Full API response.
        """
        payload = {
            "model": model,
            "messages": messages,
            "temperature": temperature,
            **({"max_tokens": max_tokens} if max_tokens is not None else {}),
            **kwargs,
        }
        return self.post("/v1/chat/completions", json=payload)

    def prompt_to_stix(
        self,
        prompt: str,
        model: str = "gpt-4.1",
        system_prompt: str = "You are a threat intelligence analyst.",
        temperature: float = 0.2,
        max_tokens: Optional[int] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """
        Convenience helper: send a prompt and return a STIX report directly.
        """
        native = self.chat_completion(
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt},
            ],
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            **kwargs,
        )
        return self.to_stix(native)

    # ── ConnectorMixin — STIX translation ─────────────────────────────────

    def to_stix(self, native: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert a chat completion response (or model list) to STIX 2.1 report.
        """
        now = _now_ts()

        if "choices" in native:
            message = native.get("choices", [{}])[0].get("message", {})
            content = message.get("content", "")
            model_used = native.get("model", "unknown")
            report_id = _stable_report_id(content, model_used)

            return {
                "type": "report",
                "id": report_id,
                "spec_version": "2.1",
                "created": now,
                "modified": now,
                "name": f"ChatGPT Analysis ({model_used})",
                "description": content[:500] + ("..." if len(content) > 500 else ""),
                "report_types": ["threat-report", "analysis"],
                "labels": ["chatgpt", "openai", "ai-generated"],
                "x_chatgpt": {
                    "model": model_used,
                    "completion_id": native.get("id"),
                    "usage": native.get("usage", {}),
                    "finish_reason": native.get("choices", [{}])[0].get("finish_reason"),
                    "raw_response": native,
                    "full_text": content,
                },
            }

        return {
            "type": "report",
            "id": f"report--chatgpt-models-{now.replace(':', '')}",
            "spec_version": "2.1",
            "created": now,
            "modified": now,
            "name": "ChatGPT Available Models",
            "description": "List of supported OpenAI models.",
            "x_chatgpt": {
                "models": native.get("data", []),
            },
        }

    def from_stix(self, stix_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        ChatGPT is inference-only. Return a suggested prompt structure.
        """
        return {
            "note": (
                "ChatGPT connector is inference-only. "
                "Use chat_completion() with messages derived from this STIX object."
            ),
            "suggested_messages": [
                {
                    "role": "system",
                    "content": "You are a helpful threat intelligence analyst.",
                },
                {
                    "role": "user",
                    "content": stix_dict.get("description", "Analyze this threat intelligence."),
                },
            ],
            "stix_id": stix_dict.get("id", ""),
        }