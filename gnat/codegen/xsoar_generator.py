"""
gnat.codegen.xsoar_generator
================================
Generate a valid XSOAR 6 content pack zip from an existing GNAT connector.

Usage (CLI)::

    gnat codegen xsoar --connector threatq --output ./packs/

Usage (Python)::

    from gnat.codegen.xsoar_generator import generate_xsoar_pack
    generate_xsoar_pack("threatq", output_dir="./packs/")

Content pack layout produced
-----------------------------
::

    <ConnectorName>/
    ├── pack_metadata.json
    ├── Integrations/
    │   └── <ConnectorName>/
    │       ├── <ConnectorName>.yml   # integration manifest + command defs
    │       └── <ConnectorName>.py    # Python script delegating to GNAT
    └── ReleaseNotes/
        └── 1_0_0.md

The generator introspects the connector via ``ConnectorMixin.capabilities()``
so that platform-specific helper methods are also surfaced as XSOAR commands.

Write-classified methods (``upsert_object``, ``delete_object``) are included
but flagged ``dangerous: true`` in the YAML manifest.

Auth methods are omitted from the command list (handled at integration level).
"""

from __future__ import annotations

import json
import os
import re
import textwrap
import zipfile
from datetime import datetime, timezone
from typing import Any

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _to_pascal(name: str) -> str:
    """Convert snake_case or kebab-case to PascalCase."""
    return "".join(part.capitalize() for part in re.split(r"[_\-]+", name))


def _to_kebab(name: str) -> str:
    """Convert snake_case to kebab-case."""
    return name.replace("_", "-")


def _method_to_xsoar_command(
    method_name: str,
    meta: dict[str, Any],
    connector_prefix: str,
) -> dict[str, Any]:
    """
    Convert a capabilities() entry to an XSOAR command definition dict.

    Parameters
    ----------
    method_name : str
        Python method name (e.g. ``"list_objects"``).
    meta : dict
        Capabilities metadata entry.
    connector_prefix : str
        Kebab-cased connector name used to namespace XSOAR commands
        (e.g. ``"threatq"`` → command name ``"threatq-list-objects"``).

    Returns
    -------
    dict
        XSOAR command definition for embedding in the integration YAML.
    """
    xsoar_name = f"{connector_prefix}-{_to_kebab(method_name)}"
    sig = meta.get("signature", "()")
    doc = meta.get("description", meta.get("doc", "")) or ""
    is_write = meta["type"] == "write"

    # Parse parameter names from signature string "(param1, param2, ...)"
    inner = sig.strip("()")
    raw_params = [p.strip() for p in inner.split(",") if p.strip()] if inner else []

    # Build XSOAR argument list — skip *args/**kwargs indicators
    arguments: list[dict[str, Any]] = []
    for param in raw_params:
        # Strip type annotations and defaults for display
        param_clean = re.split(r"[=:]", param)[0].strip()
        if not param_clean or param_clean.startswith("*"):
            continue
        arguments.append(
            {
                "name": param_clean,
                "required": param_clean in ("stix_type", "object_id", "payload"),
                "description": f"Argument '{param_clean}' for {method_name}()",
                "type": "String",
            }
        )

    cmd: dict[str, Any] = {
        "name": xsoar_name,
        "description": doc or f"Call {method_name}() on the GNAT {connector_prefix} connector.",
        "arguments": arguments,
        "outputs": [
            {
                "contextPath": f"GNAT.{_to_pascal(connector_prefix)}.{method_name}",
                "description": f"Result of {method_name}()",
                "type": "Unknown",
            }
        ],
    }
    if is_write:
        cmd["dangerous"] = True
    return cmd


# ---------------------------------------------------------------------------
# Template renderers
# ---------------------------------------------------------------------------


def _render_integration_yml(
    connector_name: str,
    pascal_name: str,
    commands: list[dict[str, Any]],
    auth_type: str,
) -> str:
    """
    Render the XSOAR integration YAML manifest.

    Parameters
    ----------
    connector_name : str
        Kebab-cased name used in command prefixes (e.g. ``"threat-q"``).
    pascal_name : str
        PascalCase integration name (e.g. ``"ThreatQ"``).
    commands : list of dict
        XSOAR command definitions from :func:`_method_to_xsoar_command`.
    auth_type : str
        ``"api_key"`` | ``"basic"`` | ``"oauth2"``.

    Returns
    -------
    str
        YAML string (uses plain string building to avoid pyyaml dependency).
    """
    auth_section = {
        "api_key": textwrap.dedent("""\
            configuration:
            - display: API Key
              name: api_key
              required: true
              type: 4
              additionalinfo: Platform API key
        """),
        "basic": textwrap.dedent("""\
            configuration:
            - display: Username
              name: username
              required: true
              type: 0
            - display: Password
              name: password
              required: true
              type: 4
              additionalinfo: Platform password
        """),
        "oauth2": textwrap.dedent("""\
            configuration:
            - display: Client ID
              name: client_id
              required: true
              type: 0
            - display: Client Secret
              name: client_secret
              required: true
              type: 4
              additionalinfo: OAuth2 client secret
        """),
    }.get(auth_type, "")

    # Render commands block (hand-crafted YAML to avoid pyyaml dependency)
    cmd_lines: list[str] = ["script:"]
    cmd_lines.append("  commands:")
    for cmd in commands:
        cmd_lines.append(f"  - name: {cmd['name']}")
        desc = cmd.get("description", "").replace('"', "'")
        cmd_lines.append(f'    description: "{desc}"')
        if cmd.get("dangerous"):
            cmd_lines.append("    dangerous: true")
        if cmd.get("arguments"):
            cmd_lines.append("    arguments:")
            for arg in cmd["arguments"]:
                cmd_lines.append(f"    - name: {arg['name']}")
                cmd_lines.append(f"      required: {str(arg['required']).lower()}")
                arg_desc = arg.get("description", "").replace('"', "'")
                cmd_lines.append(f'      description: "{arg_desc}"')
        if cmd.get("outputs"):
            cmd_lines.append("    outputs:")
            for out in cmd["outputs"]:
                cmd_lines.append(f"    - contextPath: {out['contextPath']}")
                out_desc = out.get("description", "").replace('"', "'")
                cmd_lines.append(f'      description: "{out_desc}"')
                cmd_lines.append(f"      type: {out['type']}")

    commands_yaml = "\n".join(cmd_lines)

    return textwrap.dedent(f"""\
        commonfields:
          id: GNAT-{pascal_name}
          version: -1
        name: GNAT-{pascal_name}
        display: GNAT {pascal_name}
        category: Data Enrichment & Threat Intelligence
        description: >
          GNAT connector integration for {pascal_name}. Generated by
          gnat codegen xsoar. Delegates all operations to the GNAT
          {connector_name} connector via the Python client library.
        {auth_section}
        {commands_yaml}
          runonce: false
          script: '-'
          subtype: python3
          type: python
        fromversion: "6.0.0"
    """)


def _render_integration_py(
    pascal_name: str,
    connector_key: str,
    commands: list[dict[str, Any]],
    auth_type: str,
) -> str:
    """
    Render the XSOAR integration Python script.

    The script imports GNAT at runtime, builds a connector from XSOAR
    params, and dispatches each command to the appropriate method via
    ``ConnectorMixin.call()``.

    Parameters
    ----------
    pascal_name : str
        PascalCase connector name for display/logging.
    connector_key : str
        GNAT ``CLIENT_REGISTRY`` key (e.g. ``"threatq"``).
    commands : list of dict
        XSOAR command definitions.
    auth_type : str
        Auth strategy string.

    Returns
    -------
    str
        Python source code string.
    """
    auth_setup = {
        "api_key": textwrap.dedent("""\
            init_kwargs = {
                "host": demisto.params().get("url", "").rstrip("/"),
                "api_key": demisto.params().get("api_key", ""),
            }
        """),
        "basic": textwrap.dedent("""\
            init_kwargs = {
                "host":     demisto.params().get("url", "").rstrip("/"),
                "username": demisto.params().get("username", ""),
                "password": demisto.params().get("password", ""),
            }
        """),
        "oauth2": textwrap.dedent("""\
            init_kwargs = {
                "host":          demisto.params().get("url", "").rstrip("/"),
                "client_id":     demisto.params().get("client_id", ""),
                "client_secret": demisto.params().get("client_secret", ""),
            }
        """),
    }.get(auth_type, 'init_kwargs = {"host": demisto.params().get("url", "")}\n')

    # Build dispatch table
    dispatch_lines: list[str] = []
    for cmd in commands:
        method = cmd["name"].split("-", 1)[-1].replace("-", "_")
        arg_names = [a["name"] for a in cmd.get("arguments", [])]
        is_write = cmd.get("dangerous", False)
        kwargs_expr = ", ".join(f'{a}=args.get("{a}")' for a in arg_names) if arg_names else ""
        aw_kwarg = ", allow_write=True" if is_write else ""
        call_expr = (
            f'connector.call("{method}"{aw_kwarg}{", " + kwargs_expr if kwargs_expr else ""})'
        )
        dispatch_lines.append(
            f'    elif command == "{cmd["name"]}":\n'
            f"        result = {call_expr}\n"
            f'        return_results(CommandResults(outputs_prefix="GNAT.{pascal_name}.{method}",\n'
            f"                                      outputs=result))"
        )

    dispatch_block = "\n".join(dispatch_lines)

    return textwrap.dedent(f"""\
        # GNAT {pascal_name} Integration
        # Generated by: gnat codegen xsoar
        # Do not edit manually — re-run generator to update.

        import demistomock as demisto
        from CommonServerPython import *  # noqa: F401,F403

        # GNAT imports — requires gnat package installed in XSOAR Python env
        from gnat.clients import CLIENT_REGISTRY

        CONNECTOR_KEY = "{connector_key}"


        def build_connector():
            \"\"\"Instantiate and authenticate the GNAT connector from XSOAR params.\"\"\"
            {auth_setup.strip()}
            cls = CLIENT_REGISTRY[CONNECTOR_KEY]
            connector = cls(**init_kwargs)
            connector.authenticate()
            return connector


        def main():
            command = demisto.command()
            args = demisto.args()
            connector = build_connector()

            try:
                if command == "test-module":
                    ok = connector.call("health_check")
                    return_results("ok" if ok else "FAILED")

        {dispatch_block}

                else:
                    return_error(f"Unknown command: {{command}}")

            except Exception as exc:
                return_error(f"GNAT {pascal_name} integration error: {{exc}}", error=exc)


        if __name__ in ("__main__", "__builtin__", "builtins"):
            main()
    """)


def _render_pack_metadata(
    pascal_name: str,
    connector_key: str,
    version: str = "1.0.0",
) -> str:
    """Render ``pack_metadata.json`` as a JSON string."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    meta = {
        "name": f"GNAT {pascal_name}",
        "description": (
            f"GNAT connector integration for {pascal_name}. "
            "Provides threat-intelligence CRUD operations via the GNAT unified client."
        ),
        "support": "community",
        "currentVersion": version,
        "author": "GNAT",
        "url": "https://github.com/wrhalpin/GNAT",
        "email": "",
        "categories": ["Data Enrichment & Threat Intelligence"],
        "tags": ["GNAT", connector_key, "threat-intelligence"],
        "useCases": ["Threat Intelligence"],
        "keywords": [connector_key, "GNAT", "STIX"],
        "created": now,
        "updated": now,
        "hidden": False,
    }
    return json.dumps(meta, indent=2)


def _render_release_notes(version: str = "1.0.0") -> str:
    """Render initial release notes markdown."""
    return textwrap.dedent(f"""\
        ## [{version}]

        - Initial release — generated by `gnat codegen xsoar`.
        - Exposes all GNAT connector capabilities as XSOAR commands.
        - Write operations (upsert/delete) are flagged `dangerous: true`.
    """)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate_xsoar_pack(
    connector_name: str,
    output_dir: str = ".",
    version: str = "1.0.0",
    auth_type: str | None = None,
    overwrite: bool = False,
) -> str:
    """
    Generate a XSOAR 6 content pack zip for an existing GNAT connector.

    Uses :meth:`ConnectorMixin.capabilities` to discover all available
    operations and maps them to XSOAR command definitions.

    Parameters
    ----------
    connector_name : str
        GNAT ``CLIENT_REGISTRY`` key (e.g. ``"threatq"``).
    output_dir : str
        Directory in which the ``.zip`` file is written.  Created if absent.
    version : str
        Pack semantic version.  Default ``"1.0.0"``.
    auth_type : str, optional
        Override auth type (``"api_key"``, ``"basic"``, ``"oauth2"``).
        When ``None`` the generator infers from the connector's class
        attributes or defaults to ``"api_key"``.
    overwrite : bool
        Overwrite an existing zip file.  Default ``False``.

    Returns
    -------
    str
        Absolute path of the generated zip file.

    Raises
    ------
    KeyError
        If *connector_name* is not in ``CLIENT_REGISTRY``.
    FileExistsError
        If the output zip already exists and *overwrite* is ``False``.
    """
    from gnat.clients import CLIENT_REGISTRY

    if connector_name not in CLIENT_REGISTRY:
        raise KeyError(
            f"'{connector_name}' not found in CLIENT_REGISTRY. "
            f"Available: {sorted(CLIENT_REGISTRY.keys())}"
        )

    cls = CLIENT_REGISTRY[connector_name]
    pascal_name = _to_pascal(connector_name)
    kebab_prefix = _to_kebab(connector_name)

    # --- Infer auth type ----------------------------------------------------
    if auth_type is None:
        # Look for hints in class-level attributes or constructor signature
        import inspect

        try:
            params = inspect.signature(cls.__init__).parameters
        except (ValueError, TypeError):
            params = {}
        if "client_secret" in params or "client_id" in params:
            auth_type = "oauth2"
        elif "username" in params and "password" in params:
            auth_type = "basic"
        else:
            auth_type = "api_key"

    # --- Build a stub instance to call capabilities() ----------------------
    # We construct with dummy args; we never call authenticate() or HTTP methods.
    try:
        import inspect

        params = inspect.signature(cls.__init__).parameters
        dummy_kwargs: dict[str, Any] = {}
        for pname, param in params.items():
            if pname in ("self", "args", "kwargs"):
                continue
            if param.default is inspect.Parameter.empty:
                # Required param — supply a placeholder string
                dummy_kwargs[pname] = f"__dummy_{pname}__"
        instance = cls(**dummy_kwargs)
    except Exception as exc:
        raise RuntimeError(
            f"Could not instantiate '{connector_name}' connector for introspection: {exc}"
        ) from exc

    caps = instance.capabilities()

    # Filter to non-auth callable methods (auth is handled at integration level)
    commands: list[dict[str, Any]] = []
    for method_name, meta in sorted(caps.items()):
        if meta["type"] == "auth":
            continue  # handled at integration level
        commands.append(_method_to_xsoar_command(method_name, meta, kebab_prefix))

    # --- Render file contents -----------------------------------------------
    yml_content = _render_integration_yml(kebab_prefix, pascal_name, commands, auth_type)
    py_content = _render_integration_py(pascal_name, connector_name, commands, auth_type)
    meta_content = _render_pack_metadata(pascal_name, connector_name, version)
    rn_content = _render_release_notes(version)

    # --- Write zip ----------------------------------------------------------
    os.makedirs(output_dir, exist_ok=True)
    zip_name = f"GNAT-{pascal_name}-{version}.zip"
    zip_path = os.path.join(output_dir, zip_name)

    if os.path.exists(zip_path) and not overwrite:
        raise FileExistsError(
            f"Output file already exists: {zip_path}. Pass overwrite=True to replace."
        )

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(f"{pascal_name}/pack_metadata.json", meta_content)
        zf.writestr(
            f"{pascal_name}/Integrations/{pascal_name}/{pascal_name}.yml",
            yml_content,
        )
        zf.writestr(
            f"{pascal_name}/Integrations/{pascal_name}/{pascal_name}.py",
            py_content,
        )
        ver_slug = version.replace(".", "_")
        zf.writestr(
            f"{pascal_name}/ReleaseNotes/{ver_slug}.md",
            rn_content,
        )

    return os.path.abspath(zip_path)
