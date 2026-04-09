# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.codegen.config_docs_generator
=====================================

Regenerate the platform connector table in ``docs/reference/configuration.md``
from ``config/config.ini.example`` as the single source of truth.

Sections are injected between sentinel HTML comments:

    <!-- codegen:begin:platform-connectors -->
    ...auto-generated content...
    <!-- codegen:end:platform-connectors -->

Usage (CLI)::

    # Preview what would change
    gnat codegen config-docs --dry-run

    # Write changes
    gnat codegen config-docs

    # Use AI to generate richer descriptions
    gnat codegen config-docs --ai

Usage (Python API)::

    from gnat.codegen.config_docs_generator import generate_config_docs

    generate_config_docs(dry_run=True)
    generate_config_docs()
"""

import configparser
import logging
import re
import textwrap
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_DEFAULT_INI  = "config/config.ini.example"
_DEFAULT_OUT  = "docs/reference/configuration.md"
_SENTINEL_KEY = "platform-connectors"

# Sections that are *not* per-platform connector configs.
_CORE_SECTIONS = frozenset({
    "DEFAULT",
    "claude",
    "openai",
    "grok",
    "gemini",
    "search",
    "analysis",
    "reporting",
    "agent_policy",
    "connector_limits",
    "workspace_defaults",
    "execution_context",
    "sector_aliases",
    "report",
    "report_executive",
    "report_trends",
    "report_annual",
    "schedule",
    "ingest",
    "export",
})

# Known auth types — used for generating the Auth column.
_AUTH_LABELS: dict[str, str] = {
    "oauth2":  "OAuth2",
    "api_key": "API key",
    "token":   "Token",
    "basic":   "Basic",
    "bearer":  "Bearer",
    "hmac":    "HMAC",
    "none":    "None (public)",
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate_config_docs(
    ini_path: str = _DEFAULT_INI,
    out_path: str = _DEFAULT_OUT,
    repo_root: str = ".",
    dry_run: bool = False,
    use_ai: bool = False,
    config_path: str | None = None,
) -> None:
    """
    Regenerate the platform connector configuration table in the docs.

    Reads ``ini_path``, extracts every non-core section, and produces a
    Markdown table of ``Key | Example | Description`` for each platform.
    The table is spliced into ``out_path`` between the sentinel comments.

    Parameters
    ----------
    ini_path : str
        Path to the INI example file (relative to ``repo_root``).
    out_path : str
        Path to the Markdown documentation file.
    repo_root : str
        Root of the GNAT repository.
    dry_run : bool
        Print what would change without writing the file.
    use_ai : bool
        Use Claude to generate richer field descriptions.
    config_path : str or None
        Path to GNAT config.ini for AI model lookup.
    """
    root = Path(repo_root)
    ini_full  = root / ini_path
    out_full  = root / out_path

    if not ini_full.exists():
        raise FileNotFoundError(f"INI file not found: {ini_full}")
    if not out_full.exists():
        raise FileNotFoundError(f"Documentation file not found: {out_full}")

    sections = _parse_ini(ini_full)

    # Optional AI enhancement for descriptions
    llm = None
    if use_ai:
        from gnat.codegen.openapi_generator import _try_load_llm  # type: ignore[attr-defined]
        llm = _try_load_llm(config_path)
        if llm is None:
            logger.warning(
                "AI mode requested but Claude is not configured; falling back to INI comments."
            )

    generated = _render_platform_table(sections, llm=llm)

    current = out_full.read_text(encoding="utf-8")
    new_source = _splice(current, _SENTINEL_KEY, generated)

    if new_source == current:
        print("ℹ️  Documentation is already up to date — nothing to do.")
        return

    if dry_run:
        import difflib
        diff = difflib.unified_diff(
            current.splitlines(keepends=True),
            new_source.splitlines(keepends=True),
            fromfile=str(out_path),
            tofile=str(out_path) + " (updated)",
            n=3,
        )
        print(f"[dry-run] Changes to {out_path}:")
        print("".join(list(diff)[:80]) or "  (no diff lines)")
        return

    out_full.write_text(new_source, encoding="utf-8")
    print(f"✅  Updated {out_path} ({len(sections)} platform sections)")


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------


def _parse_ini(ini_path: Path) -> list[dict[str, Any]]:
    """
    Parse the INI example file, returning one dict per connector section.

    Each dict has:
    - ``name``: section name
    - ``keys``: list of (key, example_value, inline_comment) tuples
    - ``section_comment``: the block comment above the section (if any)
    """
    raw = ini_path.read_text(encoding="utf-8")
    lines = raw.splitlines()

    # Extract block comments preceding each [section] header
    section_comments: dict[str, str] = {}
    for i, line in enumerate(lines):
        m = re.match(r"^\[([^\]]+)\]", line)
        if not m:
            continue
        section_name = m.group(1)
        comment_lines: list[str] = []
        j = i - 1
        while j >= 0 and (lines[j].startswith("#") or lines[j].strip() == ""):
            if lines[j].startswith("#"):
                comment_lines.insert(0, lines[j].lstrip("# ").strip())
            j -= 1
        section_comments[section_name] = " ".join(comment_lines).strip()

    # Parse key=value and inline comments using configparser
    cfg = configparser.RawConfigParser(allow_no_value=True)
    cfg.read_string(raw)

    # Build per-key inline comments from the raw text
    key_comments: dict[str, dict[str, str]] = {}
    current_section = None
    for line in lines:
        sec_m = re.match(r"^\[([^\]]+)\]", line)
        if sec_m:
            current_section = sec_m.group(1)
            key_comments.setdefault(current_section, {})
            continue
        if current_section is None:
            continue
        kv_m = re.match(r"^\s*([^#;=\s][^=]*?)\s*=\s*(.*?)\s*(?:;\s*(.+))?$", line)
        if kv_m:
            key   = kv_m.group(1).strip()
            value = kv_m.group(2).strip()
            comment = kv_m.group(3) or ""
            # Inline comment after # character
            if "#" in value:
                value, _, inline = value.partition("#")
                value = value.strip()
                comment = comment or inline.strip()
            key_comments[current_section][key] = comment

    sections: list[dict[str, Any]] = []
    for section in cfg.sections():
        if section in _CORE_SECTIONS:
            continue
        keys: list[tuple[str, str, str]] = []
        for key, value in cfg.items(section, raw=True):
            # Skip keys inherited from DEFAULT
            if key in cfg.defaults() and section != "DEFAULT":
                continue
            comment = key_comments.get(section, {}).get(key, "")
            keys.append((key, value or "", comment))

        if not keys:
            continue

        sections.append({
            "name": section,
            "keys": keys,
            "section_comment": section_comments.get(section, ""),
        })

    return sections


# ---------------------------------------------------------------------------
# Rendering helpers
# ---------------------------------------------------------------------------


def _render_platform_table(
    sections: list[dict[str, Any]],
    llm: Any = None,
) -> str:
    """Render the full Markdown content for the platform connector block."""
    parts: list[str] = []

    for sec in sections:
        name    = sec["name"]
        keys    = sec["keys"]
        comment = sec["section_comment"]

        # Detect auth type from 'auth_type' key or key names
        auth_type = _infer_auth_type(keys)
        auth_label = _AUTH_LABELS.get(auth_type, auth_type)

        # Optional AI descriptions
        ai_descriptions: dict[str, str] = {}
        if llm is not None:
            try:
                ai_descriptions = _ai_field_descriptions(llm, name, keys)
            except Exception as exc:
                logger.warning("AI description failed for [%s]: %s", name, exc)

        heading_comment = f" — {comment}" if comment else ""

        header = f"#### `[{name}]`{heading_comment}\n\n"
        header += f"Auth: **{auth_label}**\n\n"
        header += "| Key | Example | Description |\n"
        header += "|-----|---------|-------------|\n"

        rows: list[str] = []
        for key, value, inline_comment in keys:
            if key == "auth_type":
                continue
            desc = ai_descriptions.get(key) or inline_comment or _default_description(key)
            # Escape pipe characters in values for Markdown tables
            safe_value = value.replace("|", "\\|")
            safe_desc  = desc.replace("|", "\\|")
            rows.append(f"| `{key}` | `{safe_value}` | {safe_desc} |")

        parts.append(header + "\n".join(rows) + "\n")

    return "\n".join(parts)


def _infer_auth_type(keys: list[tuple[str, str, str]]) -> str:
    """Infer auth type from keys list."""
    for key, value, _ in keys:
        if key == "auth_type":
            return value.lower()
    # Heuristic from key names
    key_names = {k for k, _, _ in keys}
    if "client_id" in key_names or "client_secret" in key_names:
        return "oauth2"
    if "api_key" in key_names:
        return "api_key"
    if "api_token" in key_names or "token" in key_names:
        return "token"
    if "username" in key_names or "password" in key_names:
        return "basic"
    return "api_key"


def _default_description(key: str) -> str:
    """Return a sensible default description for common key names."""
    _defaults: dict[str, str] = {
        "host":           "Base URL for the platform API",
        "api_key":        "API key for authentication",
        "api_token":      "API token for authentication",
        "token":          "Authentication token",
        "client_id":      "OAuth2 client ID",
        "client_secret":  "OAuth2 client secret",
        "username":       "Username for basic authentication",
        "password":       "Password for basic authentication",
        "timeout":        "Request timeout in seconds",
        "verify_ssl":     "Verify SSL certificates",
        "max_retries":    "Maximum number of request retries",
        "auth_type":      "Authentication mechanism",
    }
    return _defaults.get(key, "")


# ---------------------------------------------------------------------------
# AI field descriptions
# ---------------------------------------------------------------------------


def _ai_field_descriptions(
    llm: Any,
    section_name: str,
    keys: list[tuple[str, str, str]],
) -> dict[str, str]:
    """Use Claude to produce concise field descriptions for an INI section."""
    import json

    key_list = [
        {"key": k, "example": v, "inline_comment": c}
        for k, v, c in keys
        if k != "auth_type"
    ]
    if not key_list:
        return {}

    prompt = textwrap.dedent(f"""\
        Write a concise one-sentence description (≤ 12 words) for each
        configuration key in the [{section_name}] INI section below.

        Keys:
        {json.dumps(key_list, indent=2)}

        Return JSON where each key name maps to its description string.
        Focus on what the value is used for, not how to obtain it.
    """)

    output_schema = {
        "type": "object",
        "additionalProperties": {"type": "string"},
    }

    return llm.structured(prompt=prompt, output_schema=output_schema, temperature=0.1, max_tokens=1024)


# ---------------------------------------------------------------------------
# Sentinel splice
# ---------------------------------------------------------------------------


def _splice(source: str, key: str, content: str) -> str:
    """
    Replace the text between sentinel comments in *source* with *content*.

    If no sentinels are found, appends a new block at the end (before the
    final ``---`` separator if present).
    """
    begin_tag = f"<!-- codegen:begin:{key} -->"
    end_tag   = f"<!-- codegen:end:{key} -->"

    if begin_tag in source and end_tag in source:
        pattern = re.compile(
            re.escape(begin_tag) + r".*?" + re.escape(end_tag),
            re.DOTALL,
        )
        replacement = f"{begin_tag}\n{content}\n{end_tag}"
        return pattern.sub(replacement, source)

    # No sentinel found — inject before the last "---\n" or at end
    block = f"\n{begin_tag}\n{content}\n{end_tag}\n"
    last_sep = source.rfind("\n---\n")
    if last_sep != -1:
        return source[:last_sep] + block + source[last_sep:]
    return source + block
