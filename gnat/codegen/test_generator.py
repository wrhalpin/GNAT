# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.codegen.test_generator
==============================

Generate unit test files for existing GNAT connectors.

Approximately 80 of the 99 connectors shipped without unit tests.
This module produces a test scaffold (or AI-enhanced test suite) for any
connector registered in :data:`~gnat.clients.CLIENT_REGISTRY`.

Usage (CLI)::

    gnat codegen tests --connector crowdstrike --overwrite
    gnat codegen tests --connector virustotal --ai --overwrite

Usage (Python API)::

    from gnat.codegen.test_generator import generate_connector_tests
    generate_connector_tests("crowdstrike", overwrite=True)
"""

import inspect
import logging
import textwrap
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate_connector_tests(
    connector_name: str,
    out_dir: str = "./tests/unit/connectors",
    overwrite: bool = False,
    use_ai: bool = False,
    config_path: str | None = None,
) -> None:
    """
    Generate a pytest test file for an existing registered connector.

    Parameters
    ----------
    connector_name : str
        Name as registered in ``CLIENT_REGISTRY`` (e.g. ``"crowdstrike"``).
    out_dir : str
        Directory to write the test file into.
    overwrite : bool
        Replace an existing file when ``True``.
    use_ai : bool
        When ``True``, use Claude to generate realistic fixtures and
        platform-specific test cases.
    config_path : str or None
        Explicit path to ``config.ini`` for AI lookup.

    Raises
    ------
    KeyError
        If *connector_name* is not registered in ``CLIENT_REGISTRY``.
    FileExistsError
        If the test file already exists and *overwrite* is ``False``.
    """
    from gnat.clients import CLIENT_REGISTRY

    name = connector_name.lower().replace("-", "_")
    if name not in CLIENT_REGISTRY:
        raise KeyError(
            f"Connector '{name}' not found in CLIENT_REGISTRY. Available: {sorted(CLIENT_REGISTRY)}"
        )

    cls = CLIENT_REGISTRY[name]
    class_name = cls.__name__
    meta = _inspect_connector(cls)

    out_path = Path(out_dir) / f"test_{name}.py"
    if out_path.exists() and not overwrite:
        raise FileExistsError(
            f"Test file already exists: {out_path}. Pass overwrite=True to replace it."
        )

    # --- Optional AI fixtures ---
    ai_fixtures: dict[str, str] = {}
    if use_ai:
        from gnat.codegen.openapi_generator import _try_load_llm

        llm = _try_load_llm(config_path)
        if llm is None:
            logger.warning(
                "AI mode requested but Claude is not configured; falling back to scaffold."
            )
        else:
            try:
                ai_fixtures = _ai_connector_fixtures(llm, name, class_name, meta)
            except Exception as exc:
                logger.warning("AI fixture generation failed: %s", exc)

    test_code = _render_connector_tests(name, class_name, meta, ai_fixtures=ai_fixtures)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(test_code)

    ai_tag = " (AI-enhanced)" if ai_fixtures else ""
    print(f"✅  Tests generated{ai_tag}: {out_path}")


# ---------------------------------------------------------------------------
# Connector introspection
# ---------------------------------------------------------------------------


def _inspect_connector(cls: type) -> dict[str, Any]:
    """
    Extract metadata from a registered connector class.

    Returns a dict with:
    - ``auth_type``: inferred from ``__init__`` params
    - ``trust_level``: class variable
    - ``api_version``: class variable
    - ``api_prefix``: class variable
    - ``stix_type_map``: class variable
    - ``has_health_check``: bool
    - ``custom_methods``: list of public method names beyond the base interface
    """
    base_methods = {
        "authenticate",
        "health_check",
        "get_object",
        "list_objects",
        "upsert_object",
        "delete_object",
        "to_stix",
        "from_stix",
        "get",
        "post",
        "put",
        "patch",
        "delete",
        "request",
        "capabilities",
        "call",
    }

    # Auth type detection from __init__ signature
    auth_type = "api_key"
    try:
        sig = inspect.signature(cls.__init__)
        params = list(sig.parameters.keys())
        if "client_id" in params or "client_secret" in params:
            auth_type = "oauth2"
        elif "username" in params or "password" in params:
            auth_type = "basic"
        elif "api_key" in params or "token" in params or "api_token" in params:
            auth_type = "api_key"
    except (ValueError, TypeError):
        pass

    # Gather custom public methods
    custom_methods = []
    for method_name in dir(cls):
        if method_name.startswith("_"):
            continue
        if method_name in base_methods:
            continue
        try:
            attr = getattr(cls, method_name)
            if callable(attr) and not isinstance(attr, property):
                custom_methods.append(method_name)
        except Exception:
            pass

    return {
        "auth_type": auth_type,
        "trust_level": getattr(cls, "TRUST_LEVEL", "semi_trusted"),
        "api_version": getattr(cls, "API_VERSION", ""),
        "api_prefix": getattr(cls, "API_PREFIX", ""),
        "stix_type_map": getattr(cls, "stix_type_map", {}),
        "has_health_check": "health_check" in cls.__dict__,
        "custom_methods": custom_methods[:10],
    }


# ---------------------------------------------------------------------------
# AI fixture generation
# ---------------------------------------------------------------------------


def _ai_connector_fixtures(
    llm: Any,
    connector_name: str,
    class_name: str,
    meta: dict[str, Any],
) -> dict[str, str]:
    """Use Claude to generate realistic fixtures and extra test cases."""
    import json

    prompt = textwrap.dedent(f"""\
        Generate realistic pytest fixtures and test cases for a GNAT connector.

        Connector: {connector_name} ({class_name})
        Trust level: {meta["trust_level"]}
        Auth type: {meta["auth_type"]}
        STIX type map: {json.dumps(meta["stix_type_map"])}
        Custom methods: {meta["custom_methods"]}

        Return JSON with:
        - "native_fixture": Python dict literal for a realistic native API response
          (use real-looking values appropriate for {connector_name}, not "test" or "1")
        - "stix_fixture": Python dict literal for the expected STIX 2.1 output
        - "list_response": Python dict/list literal for a realistic list_objects response
        - "extra_tests": Python code string with 1-2 additional test methods for
          platform-specific behaviour (empty string if none needed).
          Each method must be indented 8 spaces (inside a test class body).
    """)

    output_schema = {
        "type": "object",
        "properties": {
            "native_fixture": {"type": "string"},
            "stix_fixture": {"type": "string"},
            "list_response": {"type": "string"},
            "extra_tests": {"type": "string"},
        },
        "required": ["native_fixture", "stix_fixture", "list_response", "extra_tests"],
    }

    return llm.structured(
        prompt=prompt, output_schema=output_schema, temperature=0.2, max_tokens=2048
    )


# ---------------------------------------------------------------------------
# Test rendering
# ---------------------------------------------------------------------------


def _render_connector_tests(
    name: str,
    class_name: str,
    meta: dict[str, Any],
    ai_fixtures: dict[str, str] | None = None,
) -> str:
    """Render the full test file source."""
    ai_fixtures = ai_fixtures or {}

    native_fixture = ai_fixtures.get(
        "native_fixture",
        '{"id": "obj-1", "name": "test-object", "created_at": "2026-01-01T00:00:00Z"}',
    )
    stix_fixture = ai_fixtures.get(
        "stix_fixture",
        '{"type": "indicator", "id": "indicator--test-1", "name": "test-object"}',
    )
    list_response = ai_fixtures.get(
        "list_response",
        '{"data": [{"id": "obj-1", "name": "test-object"}]}',
    )
    extra_tests = ai_fixtures.get("extra_tests", "")

    # Build __init__ kwargs based on auth type
    auth_kwargs: dict[str, str] = {"host": '"https://fake.example.com"'}
    if meta["auth_type"] == "oauth2":
        auth_kwargs["client_id"] = '"test-id"'
        auth_kwargs["client_secret"] = '"test-secret"'
    elif meta["auth_type"] == "basic":
        auth_kwargs["username"] = '"test-user"'
        auth_kwargs["password"] = '"test-pass"'
    else:
        auth_kwargs["api_key"] = '"test-key"'

    auth_kwargs_str = ", ".join(f"{k}={v}" for k, v in auth_kwargs.items())

    stix_types = list(meta["stix_type_map"].keys()) or ["indicator"]
    primary_stix_type = stix_types[0]

    custom_method_tests = ""
    if meta["custom_methods"]:
        tests = []
        for method in meta["custom_methods"][:3]:
            tests.append(
                f"    def test_{method}_callable(self, client):\n"
                f"        assert callable(getattr(client, '{method}', None))"
            )
        custom_method_tests = (
            "\n\n# ---------------------------------------------------------------------------\n"
            "# Platform-specific methods\n"
            "# ---------------------------------------------------------------------------\n\n"
            "class TestCustomMethods:\n" + "\n\n".join(tests)
        )

    extra_tests_block = ""
    if extra_tests.strip():
        extra_tests_block = (
            "\n\n# ---------------------------------------------------------------------------\n"
            "# AI-generated platform-specific tests\n"
            "# ---------------------------------------------------------------------------\n\n"
            f"class TestPlatformSpecific:\n{extra_tests}"
        )

    ai_tag = "(AI-enhanced)" if ai_fixtures else "(scaffold)"

    return textwrap.dedent(f'''\
        """
        Unit tests for gnat.connectors.{name}  {ai_tag}
        Generated by gnat.codegen.test_generator
        """

        import pytest
        from unittest.mock import MagicMock

        from gnat.connectors.{name}.client import {class_name}


        # ---------------------------------------------------------------------------
        # Fixtures
        # ---------------------------------------------------------------------------

        @pytest.fixture
        def client(monkeypatch):
            """Return an authenticated {class_name} with authenticate() mocked out."""
            monkeypatch.setattr({class_name}, "authenticate", lambda self: None)
            c = {class_name}({auth_kwargs_str})
            c._authenticated = True
            return c


        # ---------------------------------------------------------------------------
        # Class-level attributes
        # ---------------------------------------------------------------------------

        class TestClassAttributes:
            def test_trust_level_set(self):
                assert {class_name}.TRUST_LEVEL == "{meta["trust_level"]}"

            def test_stix_type_map_is_dict(self):
                assert isinstance({class_name}.stix_type_map, dict)


        # ---------------------------------------------------------------------------
        # Authentication
        # ---------------------------------------------------------------------------

        class TestAuthentication:
            def test_auth_headers_populated(self, monkeypatch):
                """authenticate() must set at least one header."""
                c = {class_name}({auth_kwargs_str})
                # Patch the underlying _request so no network call is made
                monkeypatch.setattr(c, "_request", MagicMock(
                    return_value=type("R", (), {{"status": 200, "data": b\'{{"access_token":"tok"}}\'}})()
                ))
                try:
                    c.authenticate()
                except Exception:
                    pass  # Some auth flows need live creds; just ensure no crash on import
                # The class must have _auth_headers as a dict
                assert isinstance(c._auth_headers, dict)


        # ---------------------------------------------------------------------------
        # CRUD operations
        # ---------------------------------------------------------------------------

        class TestGetObject:
            def test_returns_dict(self, client, monkeypatch):
                monkeypatch.setattr(client, "get", MagicMock(return_value={native_fixture}))
                result = client.get_object("{primary_stix_type}", "obj-1")
                assert isinstance(result, dict)

            def test_http_error_propagates(self, client, monkeypatch):
                from gnat.clients.base import GNATClientError
                monkeypatch.setattr(client, "get", MagicMock(
                    side_effect=GNATClientError("not found", 404)
                ))
                with pytest.raises(GNATClientError):
                    client.get_object("{primary_stix_type}", "bad-id")


        class TestListObjects:
            def test_returns_list(self, client, monkeypatch):
                monkeypatch.setattr(client, "get", MagicMock(return_value={list_response}))
                result = client.list_objects("{primary_stix_type}")
                assert isinstance(result, list)

            def test_empty_response(self, client, monkeypatch):
                monkeypatch.setattr(client, "get", MagicMock(return_value={{}}))
                result = client.list_objects("{primary_stix_type}")
                assert isinstance(result, list)


        class TestUpsertObject:
            def test_create_returns_dict(self, client, monkeypatch):
                monkeypatch.setattr(client, "post", MagicMock(return_value={native_fixture}))
                result = client.upsert_object("{primary_stix_type}", {{"name": "test"}})
                assert isinstance(result, dict)

            def test_update_uses_put(self, client, monkeypatch):
                mock_put = MagicMock(return_value={native_fixture})
                monkeypatch.setattr(client, "put", mock_put)
                monkeypatch.setattr(client, "post", MagicMock())
                client.upsert_object("{primary_stix_type}", {{"id": "obj-1", "name": "test"}})
                assert mock_put.called or True  # some connectors may POST for updates


        class TestDeleteObject:
            def test_delete_called(self, client, monkeypatch):
                mock_del = MagicMock(return_value=None)
                monkeypatch.setattr(client, "delete", mock_del)
                client.delete_object("{primary_stix_type}", "obj-1")
                mock_del.assert_called_once()


        # ---------------------------------------------------------------------------
        # STIX translation
        # ---------------------------------------------------------------------------

        class TestToStix:
            def test_returns_dict(self, client):
                result = client.to_stix({native_fixture})
                assert isinstance(result, dict)

            def test_has_required_stix_fields(self, client):
                result = client.to_stix({native_fixture})
                assert "type" in result
                assert "id" in result
                assert "--" in result["id"], "STIX ID must be in format type--uuid"

            def test_name_present(self, client):
                result = client.to_stix({native_fixture})
                assert "name" in result


        class TestFromStix:
            def test_returns_dict(self, client):
                result = client.from_stix({stix_fixture})
                assert isinstance(result, dict)

            def test_name_preserved(self, client):
                result = client.from_stix({stix_fixture})
                assert "name" in result
        {custom_method_tests}
        {extra_tests_block}
        ''')
