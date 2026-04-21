# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.codegen.openapi_generator
===================================

Automated connector code generation from OpenAPI 3.x / Swagger 2.x specs.

Given an OpenAPI specification file (JSON or YAML) this script generates:

* A fully structured connector client module (``client.py``)
* A skeleton ``__init__.py``
* A pytest test scaffold (``tests/unit/connectors/test_<name>.py``)

Usage (CLI)::

    # Scaffold (no AI)
    gnat codegen openapi --spec ./specs/myplatform.json --name myplatform --auth oauth2

    # Complete implementation (requires [claude] in config.ini)
    gnat codegen openapi --spec ./specs/myplatform.json --name myplatform --auth oauth2 --ai

Usage (Python API)::

    from gnat.codegen.openapi_generator import generate_connector
    generate_connector(
        spec_path="./myplatform.yaml",
        connector_name="myplatform",
        auth_type="api_key",
        out_dir="./gnat/connectors",
        use_ai=True,
    )

The generator inspects the spec's ``paths`` and ``components/schemas`` to:

1. Detect CRUD-like endpoints (``GET /resource/{id}``, ``POST /resource``, etc.)
2. Build ``stix_type_map`` from schema names heuristically.
3. Scaffold ``to_stix`` / ``from_stix`` with all schema fields as comments.

When *use_ai* is ``True`` and Claude is configured, the AI layer generates
complete method implementations (``to_stix``, ``from_stix``, CRUD bodies,
realistic test fixtures) by analysing the full spec in context.
"""

import argparse
import json
import logging
import sys
import textwrap
from pathlib import Path
from typing import Any

try:
    import yaml  # PyYAML is optional; json specs work without it

    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate_connector(
    spec_path: str,
    connector_name: str,
    auth_type: str = "oauth2",
    out_dir: str = "./gnat/connectors",
    test_dir: str = "./tests/unit/connectors",
    overwrite: bool = False,
    use_ai: bool = False,
    config_path: str | None = None,
) -> None:
    """
    Generate a GNAT connector package from an OpenAPI specification.

    Parameters
    ----------
    spec_path : str
        Path to the OpenAPI spec (JSON or YAML).
    connector_name : str
        Snake-case name for the connector (e.g. ``"myplatform"``).
    auth_type : str
        Authentication type: ``"oauth2"``, ``"api_key"``, or ``"basic"``.
    out_dir : str
        Directory under which the connector sub-package is created.
    test_dir : str
        Directory under which the test scaffold is written.
    overwrite : bool
        If ``False`` (default) raises ``FileExistsError`` when the connector
        directory already exists.
    use_ai : bool
        When ``True``, use Claude to generate complete method implementations
        instead of scaffold stubs.  Falls back to scaffold silently when
        Claude is not configured or the AI call fails.
    config_path : str or None
        Explicit path to ``config.ini`` for AI configuration lookup.
        Defaults to the normal GNAT config search order.

    Raises
    ------
    FileExistsError
        If the target connector directory already exists and *overwrite* is
        ``False``.
    ValueError
        If the spec cannot be parsed.
    """
    spec = _load_spec(spec_path)
    name = connector_name.lower().replace("-", "_")
    class_name = "".join(w.capitalize() for w in name.split("_")) + "Client"

    connector_dir = Path(out_dir) / name
    test_path = Path(test_dir) / f"test_{name}.py"

    if connector_dir.exists() and not overwrite:
        raise FileExistsError(
            f"Connector directory already exists: {connector_dir}. "
            "Pass overwrite=True to replace it."
        )

    connector_dir.mkdir(parents=True, exist_ok=True)

    endpoints = _extract_endpoints(spec)
    schemas = _extract_schemas(spec)
    host = _extract_server(spec)
    type_map = _build_type_map(schemas)

    # --- Optional AI enhancement ---
    ai_impls: dict[str, str] = {}
    ai_fixtures: dict[str, str] = {}
    if use_ai:
        llm = _try_load_llm(config_path)
        if llm is None:
            logger.warning(
                "AI mode requested but Claude is not configured; falling back to scaffold."
            )
        else:
            try:
                ai_impls = _ai_enhance(
                    llm=llm,
                    spec=spec,
                    connector_name=name,
                    class_name=class_name,
                    endpoints=endpoints,
                    schemas=schemas,
                    type_map=type_map,
                    auth_type=auth_type,
                )
                ai_fixtures = _ai_test_fixtures(
                    llm=llm,
                    connector_name=name,
                    schemas=schemas,
                    type_map=type_map,
                )
            except Exception as exc:
                logger.warning("AI enhancement failed, falling back to scaffold: %s", exc)

    client_code = _render_client(
        name=name,
        class_name=class_name,
        host=host,
        auth_type=auth_type,
        endpoints=endpoints,
        schemas=schemas,
        type_map=type_map,
        spec_path=spec_path,
        ai_impls=ai_impls,
    )

    init_code = _render_init(name, class_name)
    test_code = _render_tests(name, class_name, ai_fixtures=ai_fixtures)

    (connector_dir / "client.py").write_text(client_code)
    (connector_dir / "__init__.py").write_text(init_code)
    test_path.parent.mkdir(parents=True, exist_ok=True)
    test_path.write_text(test_code)

    ai_tag = " (AI-generated)" if ai_impls else ""
    print(f"✅  Connector '{name}' generated{ai_tag}:")
    print(f"    {connector_dir / 'client.py'}")
    print(f"    {connector_dir / '__init__.py'}")
    print(f"    {test_path}")
    print()
    print("Next steps:")
    print(f"  1. Register '{name}' in gnat/clients/__init__.py CLIENT_REGISTRY")
    print(f"  2. Add [{name}] section to your config.ini")
    if not ai_impls:
        print(f"  3. Implement to_stix() and from_stix() in {connector_dir / 'client.py'}")


# ---------------------------------------------------------------------------
# Spec loading
# ---------------------------------------------------------------------------


def _load_spec(path: str) -> dict[str, Any]:
    """Internal helper for load spec."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"OpenAPI spec not found: {path}")
    text = p.read_text(encoding="utf-8")
    if p.suffix in (".yaml", ".yml"):
        if not _HAS_YAML:
            raise ImportError("PyYAML required for YAML specs: pip install pyyaml")
        return yaml.safe_load(text)
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Cannot parse spec as JSON: {exc}") from exc


# ---------------------------------------------------------------------------
# Spec analysis helpers
# ---------------------------------------------------------------------------


def _extract_server(spec: dict[str, Any]) -> str:
    """Internal helper for extract server."""
    servers = spec.get("servers", [])
    if servers:
        return servers[0].get("url", "https://api.example.com")
    # Swagger 2.x
    host = spec.get("host", "api.example.com")
    scheme = (spec.get("schemes") or ["https"])[0]
    base = spec.get("basePath", "")
    return f"{scheme}://{host}{base}"


def _extract_endpoints(spec: dict[str, Any]) -> list[dict[str, Any]]:
    """Return a simplified list of endpoint descriptors."""
    endpoints = []
    for path, methods in spec.get("paths", {}).items():
        for method, detail in methods.items():
            if method.lower() not in ("get", "post", "put", "patch", "delete"):
                continue
            endpoints.append(
                {
                    "path": path,
                    "method": method.upper(),
                    "operation_id": detail.get("operationId", ""),
                    "summary": detail.get("summary", ""),
                    "tags": detail.get("tags", []),
                    "params": [
                        p.get("name", "")
                        for p in detail.get("parameters", [])
                        if p.get("in") == "path"
                    ],
                }
            )
    return endpoints


def _extract_schemas(spec: dict[str, Any]) -> dict[str, Any]:
    """Internal helper for extract schemas."""
    return (
        spec.get("components", {}).get("schemas", {})  # OAS 3
        or spec.get("definitions", {})  # Swagger 2
    )


def _build_type_map(schemas: dict[str, Any]) -> dict[str, str]:
    """Heuristically map schema names to STIX types."""
    stix_keywords = {
        "indicator": "indicator",
        "malware": "malware",
        "threat": "threat-actor",
        "actor": "threat-actor",
        "vuln": "vulnerability",
        "cve": "vulnerability",
        "attack": "attack-pattern",
        "ttps": "attack-pattern",
    }
    result: dict[str, str] = {}
    for schema_name in schemas:
        lower = schema_name.lower()
        for kw, stix_type in stix_keywords.items():
            if kw in lower:
                result[stix_type] = schema_name
                break
    return result


def _build_endpoint_table(endpoints: list[dict[str, Any]]) -> str:
    """Format endpoints as a compact table for AI prompts."""
    lines = []
    for e in endpoints[:40]:
        params = ", ".join(e["params"]) if e["params"] else ""
        summary = e["summary"][:60] if e["summary"] else e["operation_id"]
        lines.append(f"  {e['method']:6} {e['path']:<40} {params:<20} {summary}")
    return "\n".join(lines)


def _build_schema_summary(schemas: dict[str, Any]) -> str:
    """Format schemas as a compact summary for AI prompts."""
    lines = []
    for schema_name, schema in list(schemas.items())[:15]:
        props = schema.get("properties", {})
        fields = []
        for fname, fschema in list(props.items())[:12]:
            ftype = fschema.get("type", fschema.get("$ref", "any"))
            if "$ref" in fschema:
                ftype = fschema["$ref"].split("/")[-1]
            fields.append(f"{fname}:{ftype}")
        lines.append(f"  {schema_name}: {', '.join(fields)}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# AI enhancement
# ---------------------------------------------------------------------------


def _try_load_llm(config_path: str | None) -> Any:
    """
    Attempt to load LLMClient from GNAT config.

    Returns ``None`` if Claude is not configured or dependencies are missing.
    """
    try:
        from gnat.agents.llm import LLMClient
        from gnat.config import GNATConfig

        cfg = GNATConfig(config_path=config_path)
        claude_cfg = cfg.get("claude")
        return LLMClient(backend="claude", **claude_cfg)
    except Exception:
        return None


def _ai_enhance(
    llm: Any,
    spec: dict[str, Any],
    connector_name: str,
    class_name: str,
    endpoints: list[dict[str, Any]],
    schemas: dict[str, Any],
    type_map: dict[str, str],
    auth_type: str,
) -> dict[str, str]:
    """
    Use Claude to generate complete method implementations from the OpenAPI spec.

    Returns a dict mapping method name → Python body string (8-space indented,
    no ``def`` line).  Keys: ``to_stix``, ``from_stix``, ``get_object``,
    ``list_objects``, ``upsert_object``, ``delete_object``, ``health_check``,
    and optionally ``helpers`` (additional platform-specific methods).
    """
    endpoint_table = _build_endpoint_table(endpoints)
    schema_summary = _build_schema_summary(schemas)
    type_map_str = json.dumps(type_map, indent=2)

    system_prompt = textwrap.dedent("""\
        You are an expert Python developer writing GNAT security platform connector
        implementations. GNAT connectors inherit from BaseClient which provides:
          self.get(path, params=None, headers=None) -> dict | list
          self.post(path, json=None, data=None, params=None, headers=None) -> dict | list
          self.put(path, json=None, params=None, headers=None) -> dict | list
          self.patch(path, json=None, params=None, headers=None) -> dict | list
          self.delete(path, params=None, headers=None) -> dict | list
        All methods return parsed JSON. Raise GNATClientError on failure.
        NEVER use requests or urllib3 directly. NEVER call authenticate() manually.
        Use self.stix_type_map.get(stix_type, stix_type) to resolve resource names.
        Write idiomatic, production-quality Python 3.9+ code without TODO comments.
    """)

    user_prompt = textwrap.dedent(f"""\
        Generate complete Python method body implementations for a GNAT connector.

        Connector name: {connector_name}
        Class name: {class_name}
        Auth type: {auth_type}

        API Endpoints:
        {endpoint_table}

        Schema definitions (field: type):
        {schema_summary}

        STIX type map (stix_type -> schema_name):
        {type_map_str}

        Return a JSON object with exactly these keys. Each value is the Python
        function BODY ONLY (indented 8 spaces, no def line, no decorators):

        {{
          "health_check": "...",
          "get_object": "...",
          "list_objects": "...",
          "upsert_object": "...",
          "delete_object": "...",
          "to_stix": "...",
          "from_stix": "...",
          "helpers": "..."
        }}

        For "helpers": include 1-3 platform-specific convenience methods as a
        string containing the full def blocks (indented 4 spaces), or "" if none
        are needed.

        For to_stix: map all detected schema fields to appropriate STIX 2.1
        properties. Include stix_type, id (use uuid5 of the native id), name,
        created, modified, and any domain-specific fields.

        For list_objects: detect the correct pagination scheme (offset/page/cursor)
        from the endpoint parameters. Handle both array and object responses.

        For health_check: use the most appropriate endpoint (status, health, ping,
        or a lightweight list endpoint). Return True on success.
    """)

    output_schema = {
        "type": "object",
        "properties": {
            "health_check": {"type": "string"},
            "get_object": {"type": "string"},
            "list_objects": {"type": "string"},
            "upsert_object": {"type": "string"},
            "delete_object": {"type": "string"},
            "to_stix": {"type": "string"},
            "from_stix": {"type": "string"},
            "helpers": {"type": "string"},
        },
        "required": [
            "health_check",
            "get_object",
            "list_objects",
            "upsert_object",
            "delete_object",
            "to_stix",
            "from_stix",
            "helpers",
        ],
    }

    result = llm.structured(
        prompt=user_prompt,
        output_schema=output_schema,
        system=system_prompt,
        temperature=0.2,
        max_tokens=4096,
    )

    # Strip empty helpers
    if not result.get("helpers", "").strip():
        result.pop("helpers", None)

    return result


def _ai_test_fixtures(
    llm: Any,
    connector_name: str,
    schemas: dict[str, Any],
    type_map: dict[str, str],
) -> dict[str, str]:
    """
    Use Claude to generate realistic test fixture dicts for to_stix / from_stix tests.

    Returns dict with keys ``native_fixture`` and ``stix_fixture`` as Python
    dict-literal strings.
    """
    schema_summary = _build_schema_summary(schemas)
    primary_schema = next(iter(schemas), "unknown")

    user_prompt = textwrap.dedent(f"""\
        Generate realistic test fixture dicts for a GNAT connector named '{connector_name}'.

        Primary schema: {primary_schema}
        Schema fields:
        {schema_summary}

        STIX type map: {json.dumps(type_map)}

        Return JSON with two keys:
        - "native_fixture": a Python dict literal string representing a realistic
          native API response object for {primary_schema} (use plausible values,
          not "test" or "1")
        - "stix_fixture": a Python dict literal string representing the expected
          STIX 2.1 output after to_stix() conversion

        Example format for native_fixture:
        '{{"id": "ioc-7f3a2b", "value": "malicious.example.com", "type": "domain", ...}}'
    """)

    output_schema = {
        "type": "object",
        "properties": {
            "native_fixture": {"type": "string"},
            "stix_fixture": {"type": "string"},
        },
        "required": ["native_fixture", "stix_fixture"],
    }

    try:
        return llm.structured(
            prompt=user_prompt,
            output_schema=output_schema,
            temperature=0.2,
            max_tokens=1024,
        )
    except Exception as exc:
        logger.debug("AI fixture generation failed: %s", exc)
        return {}


# ---------------------------------------------------------------------------
# Code rendering
# ---------------------------------------------------------------------------


def _render_client(
    name: str,
    class_name: str,
    host: str,
    auth_type: str,
    endpoints: list[dict[str, Any]],
    schemas: dict[str, Any],
    type_map: dict[str, str],
    spec_path: str,
    ai_impls: dict[str, str] | None = None,
) -> str:
    """Render the client.py module source code."""
    ai_impls = ai_impls or {}
    auth_snippet = _auth_snippet(auth_type)
    type_map_repr = repr(type_map)
    endpoint_summary = "\n".join(
        f"    # {e['method']:6s} {e['path']}  — {e['summary']}" for e in endpoints[:30]
    )
    schema_fields = _schema_field_comments(schemas)
    ai_tag = "AI-generated" if ai_impls else "scaffold"

    # Method bodies — use AI impl when available, else scaffold
    def _body(key: str, scaffold: str) -> str:
        if key in ai_impls:
            return ai_impls[key]
        return scaffold

    health_check_body = _body(
        "health_check",
        '        """Check platform connectivity."""\n'
        '        self.get("/health")\n'
        "        return True",
    )
    get_object_body = _body(
        "get_object",
        f'        """TODO: Implement get_object for {name}."""\n'
        "        resource = self.stix_type_map.get(stix_type, stix_type)\n"
        '        return self.get(f"/{resource}/{object_id}")',
    )
    list_objects_body = _body(
        "list_objects",
        f'        """TODO: Implement list_objects for {name}."""\n'
        "        resource = self.stix_type_map.get(stix_type, stix_type)\n"
        '        params: Dict[str, Any] = {"limit": page_size, "page": page}\n'
        "        if filters:\n"
        "            params.update(filters)\n"
        '        resp = self.get(f"/{resource}", params=params)\n'
        '        return resp.get("data", []) if isinstance(resp, dict) else []',
    )
    upsert_object_body = _body(
        "upsert_object",
        f'        """TODO: Implement upsert_object for {name}."""\n'
        "        resource = self.stix_type_map.get(stix_type, stix_type)\n"
        '        obj_id = payload.pop("id", None)\n'
        "        if obj_id:\n"
        '            return self.put(f"/{resource}/{obj_id}", json=payload)\n'
        '        return self.post(f"/{resource}", json=payload)',
    )
    delete_object_body = _body(
        "delete_object",
        f'        """TODO: Implement delete_object for {name}."""\n'
        "        resource = self.stix_type_map.get(stix_type, stix_type)\n"
        '        self.delete(f"/{resource}/{object_id}")',
    )
    to_stix_body = _body(
        "to_stix",
        f'        """\n'
        f"        TODO: Map native {name} fields to STIX 2.1.\n\n"
        f"        Detected schema fields:\n"
        f"{schema_fields}\n"
        f'        """\n'
        "        return {\n"
        '            "type": "indicator",\n'
        "            \"id\": f\"indicator--{native.get('id', '')}\",\n"
        '            "name": native.get("name", native.get("value", "")),\n'
        '            "pattern_type": "stix",\n'
        '            "created": native.get("created_at", native.get("created", "")),\n'
        '            "modified": native.get("updated_at", native.get("modified", "")),\n'
        "        }",
    )
    from_stix_body = _body(
        "from_stix",
        '        """Map STIX 2.1 fields to native format."""\n'
        "        return {\n"
        '            "name": stix_dict.get("name", ""),\n'
        '            "description": stix_dict.get("description", ""),\n'
        '            "confidence": stix_dict.get("confidence"),\n'
        '            "labels": stix_dict.get("labels", []),\n'
        '            "created": stix_dict.get("created", ""),\n'
        '            "modified": stix_dict.get("modified", ""),\n'
        '            "valid_from": stix_dict.get("valid_from"),\n'
        '            "valid_until": stix_dict.get("valid_until"),\n'
        '            "pattern": stix_dict.get("pattern"),\n'
        '            "pattern_type": stix_dict.get("pattern_type"),\n'
        '            "external_references": stix_dict.get("external_references", []),\n'
        '            "object_marking_refs": stix_dict.get("object_marking_refs", []),\n'
        '            "stix_id": stix_dict.get("id", ""),\n'
        '            "stix_type": stix_dict.get("type", ""),\n'
        "        }",
    )

    # Optional AI-generated helpers
    helpers_block = ""
    if "helpers" in ai_impls and ai_impls["helpers"].strip():
        helpers_block = (
            f"\n    # --- Platform-specific helpers (AI-generated) ---\n\n{ai_impls['helpers']}\n"
        )

    return textwrap.dedent(f'''\
        """
        gnat.connectors.{name}.client
        {"=" * (len(name) + 30)}

        Auto-generated ({ai_tag}) from: {spec_path}
        Default host:        {host}
        Auth type:           {auth_type}

        Detected endpoints (first 30):
        {endpoint_summary}
        """

        from typing import Any, Dict, List, Optional
        from gnat.clients.base import BaseClient, GNATClientError
        from gnat.connectors.base_connector import ConnectorMixin


        class {class_name}(BaseClient, ConnectorMixin):
            """Auto-generated HTTP client for {name}."""

            stix_type_map: Dict[str, str] = {type_map_repr}

        {auth_snippet}

            def health_check(self) -> bool:
        {health_check_body}

            def get_object(self, stix_type: str, object_id: str) -> Dict[str, Any]:
        {get_object_body}

            def list_objects(
                self, stix_type: str,
                filters: Optional[Dict[str, Any]] = None,
                page: int = 1, page_size: int = 100,
            ) -> List[Dict[str, Any]]:
        {list_objects_body}

            def upsert_object(self, stix_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        {upsert_object_body}

            def delete_object(self, stix_type: str, object_id: str) -> None:
        {delete_object_body}

            def to_stix(self, native: Dict[str, Any]) -> Dict[str, Any]:
        {to_stix_body}

            def from_stix(self, stix_dict: Dict[str, Any]) -> Dict[str, Any]:
        {from_stix_body}
        {helpers_block}''')


def _auth_snippet(auth_type: str) -> str:
    """Internal helper for auth snippet."""
    if auth_type == "oauth2":
        return textwrap.indent(
            textwrap.dedent('''\
            def __init__(self, host: str, client_id: str = "",
                         client_secret: str = "", **kwargs: Any):
                super().__init__(host=host, **kwargs)
                self._client_id = client_id
                self._client_secret = client_secret

            def authenticate(self) -> None:
                """Obtain OAuth2 Bearer token."""
                resp = self.post("/oauth2/token", data={
                    "grant_type": "client_credentials",
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                })
                token = resp.get("access_token") if isinstance(resp, dict) else None
                if not token:
                    raise GNATClientError("Failed to obtain access token")
                self._auth_headers["Authorization"] = f"Bearer {token}"
            '''),
            "    ",
        )
    if auth_type == "api_key":
        return textwrap.indent(
            textwrap.dedent('''\
            def __init__(self, host: str, api_key: str = "", **kwargs: Any):
                super().__init__(host=host, **kwargs)
                self._api_key = api_key

            def authenticate(self) -> None:
                """Inject API key header."""
                self._auth_headers["X-Api-Key"] = self._api_key
            '''),
            "    ",
        )
    # basic
    return textwrap.indent(
        textwrap.dedent('''\
        def __init__(self, host: str, username: str = "",
                     password: str = "", **kwargs: Any):
            import base64
            super().__init__(host=host, **kwargs)
            raw = f"{username}:{password}".encode()
            self._basic = base64.b64encode(raw).decode()

        def authenticate(self) -> None:
            """Inject HTTP Basic credentials."""
            self._auth_headers["Authorization"] = f"Basic {self._basic}"
        '''),
        "    ",
    )


def _schema_field_comments(schemas: dict[str, Any]) -> str:
    """Internal helper for schema field comments."""
    lines = []
    for schema_name, schema in list(schemas.items())[:5]:
        props = schema.get("properties", {})
        field_list = ", ".join(list(props.keys())[:8])
        lines.append(f"                    {schema_name}: {field_list}")
    return "\n".join(lines) if lines else "                    (no schemas detected)"


def _render_init(name: str, class_name: str) -> str:
    """Internal helper for render init."""
    return textwrap.dedent(f'''\
        """gnat.connectors.{name} — auto-generated connector."""
        from gnat.connectors.{name}.client import {class_name}
        __all__ = ["{class_name}"]
        ''')


def _render_tests(
    name: str,
    class_name: str,
    ai_fixtures: dict[str, str] | None = None,
) -> str:
    """
    Render the pytest test scaffold.

    Parameters
    ----------
    name : str
        Connector snake_case name.
    class_name : str
        Connector class name.
    ai_fixtures : dict, optional
        ``{"native_fixture": "...", "stix_fixture": "..."}`` from AI generation.
        When present, replaces the generic placeholder dicts in STIX tests.
    """
    ai_fixtures = ai_fixtures or {}
    native_fixture = ai_fixtures.get(
        "native_fixture",
        '{"id": "1", "name": "test", "created_at": "", "updated_at": ""}',
    )
    stix_fixture = ai_fixtures.get(
        "stix_fixture",
        '{"type": "indicator", "id": "indicator--1", "name": "test"}',
    )

    return textwrap.dedent(f'''\
        """
        Unit tests for gnat.connectors.{name}
        Auto-generated by gnat.codegen.openapi_generator
        """

        import pytest
        from unittest.mock import MagicMock, patch

        from gnat.connectors.{name}.client import {class_name}


        @pytest.fixture
        def client(mock_auth):
            """Return an authenticated {class_name} with mocked HTTP."""
            c = {class_name}(host="https://fake.example.com", api_key="test-key")
            c._authenticated = True
            return c


        @pytest.fixture
        def mock_auth(monkeypatch):
            """Patch authenticate() so tests don't hit the network."""
            monkeypatch.setattr({class_name}, "authenticate", lambda self: None)


        # ---------------------------------------------------------------------------
        # Authentication
        # ---------------------------------------------------------------------------

        class TestAuthentication:
            def test_sets_auth_header(self, monkeypatch):
                mock_post = MagicMock(return_value={{"access_token": "tok123"}})
                c = {class_name}(host="https://fake.example.com")
                monkeypatch.setattr(c, "_request", mock_post)
                c.authenticate()
                assert "Authorization" in c._auth_headers, (
                    "authenticate() must populate c._auth_headers['Authorization']"
                )


        # ---------------------------------------------------------------------------
        # CRUD
        # ---------------------------------------------------------------------------

        class TestGetObject:
            def test_returns_dict(self, client, monkeypatch):
                monkeypatch.setattr(client, "get", MagicMock(return_value={{"id": "1", "name": "test"}}))
                result = client.get_object("indicator", "1")
                assert isinstance(result, dict)

            def test_raises_on_http_error(self, client, monkeypatch):
                from gnat.clients.base import GNATClientError
                monkeypatch.setattr(client, "get", MagicMock(side_effect=GNATClientError("404", 404)))
                with pytest.raises(GNATClientError):
                    client.get_object("indicator", "bad-id")


        class TestListObjects:
            def test_returns_list(self, client, monkeypatch):
                monkeypatch.setattr(client, "get", MagicMock(return_value={{"data": [{{"id": "1"}}]}}))
                result = client.list_objects("indicator")
                assert isinstance(result, list)


        class TestUpsertObject:
            def test_create(self, client, monkeypatch):
                monkeypatch.setattr(client, "post", MagicMock(return_value={{"id": "new-1"}}))
                result = client.upsert_object("indicator", {{"name": "evil.com"}})
                assert isinstance(result, dict)


        # ---------------------------------------------------------------------------
        # STIX translation
        # ---------------------------------------------------------------------------

        class TestToStix:
            def test_returns_valid_stix_keys(self, client):
                native = {native_fixture}
                stix = client.to_stix(native)
                assert "type" in stix
                assert "id" in stix
                assert "name" in stix

            def test_id_has_stix_prefix(self, client):
                native = {native_fixture}
                stix = client.to_stix(native)
                assert "--" in stix["id"], "STIX ID must be in format type--uuid"


        class TestFromStix:
            def test_returns_dict(self, client):
                stix = {stix_fixture}
                result = client.from_stix(stix)
                assert isinstance(result, dict)

            def test_round_trip_name(self, client):
                stix = {stix_fixture}
                result = client.from_stix(stix)
                assert "name" in result
        ''')


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def _main() -> None:
    """Internal helper for main."""
    parser = argparse.ArgumentParser(description="Generate a GNAT connector from an OpenAPI spec.")
    parser.add_argument("--spec", required=True, help="Path to OpenAPI spec (JSON/YAML)")
    parser.add_argument("--name", required=True, help="Connector name (snake_case)")
    parser.add_argument(
        "--auth",
        default="oauth2",
        choices=["oauth2", "api_key", "basic"],
        help="Authentication type (default: oauth2)",
    )
    parser.add_argument("--out-dir", default="./gnat/connectors", help="Connector output directory")
    parser.add_argument(
        "--test-dir", default="./tests/unit/connectors", help="Test output directory"
    )
    parser.add_argument("--overwrite", action="store_true", help="Overwrite existing connector")
    parser.add_argument(
        "--ai",
        action="store_true",
        help="Use Claude to generate complete implementations (requires [claude] in config.ini)",
    )
    parser.add_argument(
        "--config",
        dest="config_path",
        default=None,
        help="Path to config.ini for AI configuration",
    )
    args = parser.parse_args()

    try:
        generate_connector(
            spec_path=args.spec,
            connector_name=args.name,
            auth_type=args.auth,
            out_dir=args.out_dir,
            test_dir=args.test_dir,
            overwrite=args.overwrite,
            use_ai=args.ai,
            config_path=args.config_path,
        )
    except (FileNotFoundError, FileExistsError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    _main()
