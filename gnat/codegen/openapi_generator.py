"""
gnat.codegen.openapi_generator
===================================

Automated connector code generation from OpenAPI 3.x / Swagger 2.x specs.

Given an OpenAPI specification file (JSON or YAML) this script generates:

* A fully structured connector client module (``client.py``)
* A skeleton ``__init__.py``
* A pytest test scaffold (``tests/unit/connectors/test_<name>.py``)

Usage (CLI)::

    python -m gnat.codegen.openapi_generator \\
        --spec    ./specs/myplatform-openapi.json \\
        --name    myplatform \\
        --auth    oauth2 \\
        --out-dir ./gnat/connectors

Usage (Python API)::

    from gnat.codegen.openapi_generator import generate_connector
    generate_connector(
        spec_path="./myplatform.yaml",
        connector_name="myplatform",
        auth_type="api_key",
        out_dir="./gnat/connectors",
    )

The generator inspects the spec's ``paths`` and ``components/schemas`` to:

1. Detect CRUD-like endpoints (``GET /resource/{id}``, ``POST /resource``, etc.)
2. Build ``stix_type_map`` from schema names heuristically.
3. Scaffold ``to_stix`` / ``from_stix`` with all schema fields as comments.
"""

import argparse
import json
import sys
import textwrap
from pathlib import Path
from typing import Any

try:
    import yaml  # PyYAML is optional; json specs work without it
    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False


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
    schemas   = _extract_schemas(spec)
    host      = _extract_server(spec)
    type_map  = _build_type_map(schemas)

    client_code = _render_client(
        name=name,
        class_name=class_name,
        host=host,
        auth_type=auth_type,
        endpoints=endpoints,
        schemas=schemas,
        type_map=type_map,
        spec_path=spec_path,
    )

    init_code = _render_init(name, class_name)
    test_code = _render_tests(name, class_name)

    (connector_dir / "client.py").write_text(client_code)
    (connector_dir / "__init__.py").write_text(init_code)
    test_path.parent.mkdir(parents=True, exist_ok=True)
    test_path.write_text(test_code)

    print(f"✅  Connector '{name}' generated:")
    print(f"    {connector_dir / 'client.py'}")
    print(f"    {connector_dir / '__init__.py'}")
    print(f"    {test_path}")
    print()
    print("Next steps:")
    print(f"  1. Register '{name}' in gnat/clients/__init__.py CLIENT_REGISTRY")
    print(f"  2. Add [{name}] section to your config.ini")
    print(f"  3. Implement to_stix() and from_stix() in {connector_dir / 'client.py'}")


# ---------------------------------------------------------------------------
# Spec loading
# ---------------------------------------------------------------------------


def _load_spec(path: str) -> dict[str, Any]:
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
    servers = spec.get("servers", [])
    if servers:
        return servers[0].get("url", "https://api.example.com")
    # Swagger 2.x
    host   = spec.get("host", "api.example.com")
    scheme = (spec.get("schemes") or ["https"])[0]
    base   = spec.get("basePath", "")
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
                        p.get("name", "") for p in detail.get("parameters", [])
                        if p.get("in") == "path"
                    ],
                }
            )
    return endpoints


def _extract_schemas(spec: dict[str, Any]) -> dict[str, Any]:
    return (
        spec.get("components", {}).get("schemas", {})      # OAS 3
        or spec.get("definitions", {})                      # Swagger 2
    )


def _build_type_map(schemas: dict[str, Any]) -> dict[str, str]:
    """Heuristically map schema names to STIX types."""
    stix_keywords = {
        "indicator": "indicator",
        "malware":   "malware",
        "threat":    "threat-actor",
        "actor":     "threat-actor",
        "vuln":      "vulnerability",
        "cve":       "vulnerability",
        "attack":    "attack-pattern",
        "ttps":      "attack-pattern",
    }
    result: dict[str, str] = {}
    for schema_name in schemas:
        lower = schema_name.lower()
        for kw, stix_type in stix_keywords.items():
            if kw in lower:
                result[stix_type] = schema_name
                break
    return result


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
) -> str:
    """Render the client.py module source code."""
    auth_snippet = _auth_snippet(auth_type)
    type_map_repr = repr(type_map)
    endpoint_summary = "\n".join(
        f"    # {e['method']:6s} {e['path']}  — {e['summary']}"
        for e in endpoints[:30]
    )
    schema_fields = _schema_field_comments(schemas)

    return textwrap.dedent(f'''\
        """
        gnat.connectors.{name}.client
        {"=" * (len(name) + 30)}

        Auto-generated from: {spec_path}
        Default host:        {host}
        Auth type:           {auth_type}

        Detected endpoints (first 30):
        {endpoint_summary}

        TODO: Implement to_stix() and from_stix() field mappings.
        """

        from typing import Any, Dict, List, Optional
        from gnat.clients.base import BaseClient, GNATClientError
        from gnat.connectors.base_connector import ConnectorMixin


        class {class_name}(BaseClient, ConnectorMixin):
            """Auto-generated HTTP client for {name}."""

            stix_type_map: Dict[str, str] = {type_map_repr}

        {auth_snippet}

            def health_check(self) -> bool:
                """TODO: Replace with a real ping/status endpoint."""
                self.get("/health")
                return True

            def get_object(self, stix_type: str, object_id: str) -> Dict[str, Any]:
                """TODO: Implement get_object for {name}."""
                resource = self.stix_type_map.get(stix_type, stix_type)
                return self.get(f"/{{resource}}/{{object_id}}")

            def list_objects(
                self, stix_type: str,
                filters: Optional[Dict[str, Any]] = None,
                page: int = 1, page_size: int = 100,
            ) -> List[Dict[str, Any]]:
                """TODO: Implement list_objects for {name}."""
                resource = self.stix_type_map.get(stix_type, stix_type)
                params: Dict[str, Any] = {{"limit": page_size, "page": page}}
                if filters:
                    params.update(filters)
                resp = self.get(f"/{{resource}}", params=params)
                return resp.get("data", []) if isinstance(resp, dict) else []

            def upsert_object(self, stix_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
                """TODO: Implement upsert_object for {name}."""
                resource = self.stix_type_map.get(stix_type, stix_type)
                obj_id = payload.pop("id", None)
                if obj_id:
                    return self.put(f"/{{resource}}/{{obj_id}}", json=payload)
                return self.post(f"/{{resource}}", json=payload)

            def delete_object(self, stix_type: str, object_id: str) -> None:
                """TODO: Implement delete_object for {name}."""
                resource = self.stix_type_map.get(stix_type, stix_type)
                self.delete(f"/{{resource}}/{{object_id}}")

            def to_stix(self, native: Dict[str, Any]) -> Dict[str, Any]:
                """
                TODO: Map native {name} fields to STIX 2.1.

                Detected schema fields:
        {schema_fields}
                """
                return {{
                    "type": "indicator",
                    "id": f"indicator--{{native.get('id', '')}}",
                    "name": native.get("name", native.get("value", "")),
                    "pattern_type": "stix",
                    "created": native.get("created_at", native.get("created", "")),
                    "modified": native.get("updated_at", native.get("modified", "")),
                }}

            def from_stix(self, stix_dict: Dict[str, Any]) -> Dict[str, Any]:
                """TODO: Map STIX 2.1 fields to {name} native format."""
                return {{
                    "name": stix_dict.get("name", ""),
                    # TODO: Map remaining fields
                }}
        ''')


def _auth_snippet(auth_type: str) -> str:
    if auth_type == "oauth2":
        return textwrap.indent(textwrap.dedent('''\
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
            '''), "    ")
    if auth_type == "api_key":
        return textwrap.indent(textwrap.dedent('''\
            def __init__(self, host: str, api_key: str = "", **kwargs: Any):
                super().__init__(host=host, **kwargs)
                self._api_key = api_key

            def authenticate(self) -> None:
                """Inject API key header."""
                self._auth_headers["X-Api-Key"] = self._api_key
            '''), "    ")
    # basic
    return textwrap.indent(textwrap.dedent('''\
        def __init__(self, host: str, username: str = "",
                     password: str = "", **kwargs: Any):
            import base64
            super().__init__(host=host, **kwargs)
            raw = f"{username}:{password}".encode()
            self._basic = base64.b64encode(raw).decode()

        def authenticate(self) -> None:
            """Inject HTTP Basic credentials."""
            self._auth_headers["Authorization"] = f"Basic {self._basic}"
        '''), "    ")


def _schema_field_comments(schemas: dict[str, Any]) -> str:
    lines = []
    for schema_name, schema in list(schemas.items())[:5]:
        props = schema.get("properties", {})
        field_list = ", ".join(list(props.keys())[:8])
        lines.append(f"                    {schema_name}: {field_list}")
    return "\n".join(lines) if lines else "                    (no schemas detected)"


def _render_init(name: str, class_name: str) -> str:
    return textwrap.dedent(f'''\
        """gnat.connectors.{name} — auto-generated connector."""
        from gnat.connectors.{name}.client import {class_name}
        __all__ = ["{class_name}"]
        ''')


def _render_tests(name: str, class_name: str) -> str:
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
                # TODO: assert the correct auth header is set


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
                native = {{"id": "1", "name": "test", "created_at": "", "updated_at": ""}}
                stix = client.to_stix(native)
                assert stix.get("type") == "indicator"
                assert "id" in stix
                assert "name" in stix

            def test_id_prefix(self, client):
                stix = client.to_stix({{"id": "42"}})
                assert stix["id"].startswith("indicator--")


        class TestFromStix:
            def test_returns_dict(self, client):
                stix = {{"type": "indicator", "id": "indicator--1", "name": "evil.com"}}
                result = client.from_stix(stix)
                assert isinstance(result, dict)
        ''')


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate a GNAT connector from an OpenAPI spec."
    )
    parser.add_argument("--spec",      required=True, help="Path to OpenAPI spec (JSON/YAML)")
    parser.add_argument("--name",      required=True, help="Connector name (snake_case)")
    parser.add_argument("--auth",      default="oauth2",
                        choices=["oauth2", "api_key", "basic"],
                        help="Authentication type (default: oauth2)")
    parser.add_argument("--out-dir",   default="./gnat/connectors",
                        help="Connector output directory")
    parser.add_argument("--test-dir",  default="./tests/unit/connectors",
                        help="Test output directory")
    parser.add_argument("--overwrite", action="store_true",
                        help="Overwrite existing connector")
    args = parser.parse_args()

    try:
        generate_connector(
            spec_path=args.spec,
            connector_name=args.name,
            auth_type=args.auth,
            out_dir=args.out_dir,
            test_dir=args.test_dir,
            overwrite=args.overwrite,
        )
    except (FileNotFoundError, FileExistsError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    _main()
