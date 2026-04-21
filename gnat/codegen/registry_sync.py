# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.codegen.registry_sync
==============================

Scan ``gnat/connectors/`` for packages that are missing from
``CLIENT_REGISTRY`` in ``gnat/clients/__init__.py`` and patch them in.

Usage (CLI)::

    # Add a single connector
    gnat codegen register --connector myplatform

    # Find all unregistered connectors
    gnat codegen register --scan --dry-run

    # Find and register all gaps automatically
    gnat codegen register --scan

Usage (Python API)::

    from gnat.codegen.registry_sync import sync_registry, scan_unregistered

    # Report gaps
    gaps = scan_unregistered(repo_root=".")
    for gap in gaps:
        print(gap)

    # Register one connector
    sync_registry("myplatform", repo_root=".")
"""

import logging
import re
from pathlib import Path
from typing import NamedTuple

logger = logging.getLogger(__name__)

_REGISTRY_FILE = "gnat/clients/__init__.py"
_CONNECTORS_DIR = "gnat/connectors"

# Regex to detect the class definition in client.py
_CLASS_RE = re.compile(r"^class\s+(\w+Client)\s*\(", re.MULTILINE)

# Regex to find the CLIENT_REGISTRY dict block
_REGISTRY_START_RE = re.compile(r"^CLIENT_REGISTRY\s*(?::\s*dict\S*\s*)?\s*=\s*\{", re.MULTILINE)


# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------


class RegistryGap(NamedTuple):
    """A connector that exists on disk but is missing from CLIENT_REGISTRY."""

    name: str  # snake_case connector name (matches directory name)
    class_name: str  # detected class name from client.py
    client_path: str  # relative path to client.py


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def scan_unregistered(repo_root: str = ".") -> list[RegistryGap]:
    """
    Return all connectors that have a ``client.py`` but are not in
    ``CLIENT_REGISTRY``.

    Parameters
    ----------
    repo_root : str
        Root of the GNAT repository.

    Returns
    -------
    list of RegistryGap
    """
    root = Path(repo_root)
    registered = _read_registered_names(root)
    gaps: list[RegistryGap] = []

    connectors_dir = root / _CONNECTORS_DIR
    for connector_dir in sorted(connectors_dir.iterdir()):
        if not connector_dir.is_dir():
            continue
        name = connector_dir.name
        if name.startswith("_"):
            continue

        client_file = connector_dir / "client.py"
        if not client_file.exists():
            continue

        if name.lower() in registered or name in registered:
            continue

        # Detect class name from file
        class_name = _detect_class_name(client_file)
        if class_name is None:
            logger.debug("Could not detect class in %s; skipping", client_file)
            continue

        gaps.append(
            RegistryGap(
                name=name,
                class_name=class_name,
                client_path=str(client_file.relative_to(root)),
            )
        )

    return gaps


def sync_registry(
    connector_name: str,
    repo_root: str = ".",
    dry_run: bool = False,
) -> None:
    """
    Add a connector to ``CLIENT_REGISTRY`` if it is not already present.

    Patches ``gnat/clients/__init__.py`` in-place: adds the import line
    (in alphabetical order with existing imports) and the registry entry.

    Parameters
    ----------
    connector_name : str
        Snake-case connector name (matches directory name under
        ``gnat/connectors/``).
    repo_root : str
        Root of the GNAT repository.
    dry_run : bool
        Print what would change without writing the file.

    Raises
    ------
    FileNotFoundError
        If the connector directory or ``client.py`` does not exist.
    ValueError
        If no ``BaseClient`` subclass is found in ``client.py``.
    """
    root = Path(repo_root)
    name = connector_name.lower().replace("-", "_")

    client_file = root / _CONNECTORS_DIR / name / "client.py"
    if not client_file.exists():
        raise FileNotFoundError(f"Connector client not found: {client_file}")

    class_name = _detect_class_name(client_file)
    if class_name is None:
        raise ValueError(f"Could not detect a BaseClient subclass in {client_file}")

    registered = _read_registered_names(root)
    if name in registered:
        print(f"ℹ️  '{name}' is already in CLIENT_REGISTRY — nothing to do.")
        return

    registry_path = root / _REGISTRY_FILE
    source = registry_path.read_text(encoding="utf-8")

    # Build the import line
    # Use the same casing as the directory name for the module path
    module_path = f"gnat.connectors.{name}.client"
    import_line = f"from {module_path} import {class_name}"

    # Build the registry entry
    registry_entry = f'    "{name}": {class_name},'

    new_source = _insert_import(source, import_line)
    new_source = _insert_registry_entry(new_source, registry_entry)

    if dry_run:
        print(f"[dry-run] Would add to {_REGISTRY_FILE}:")
        print(f"  Import:  {import_line}")
        print(f"  Entry:   {registry_entry}")
        return

    registry_path.write_text(new_source, encoding="utf-8")
    print(f"✅  Registered '{name}' ({class_name}) in {_REGISTRY_FILE}")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _read_registered_names(root: Path) -> set[str]:
    """Parse CLIENT_REGISTRY from __init__.py; return the set of registered keys."""
    registry_path = root / _REGISTRY_FILE
    if not registry_path.exists():
        return set()

    source = registry_path.read_text(encoding="utf-8")
    # Find string keys inside the CLIENT_REGISTRY dict
    # Matches: "name": SomeClass,  or  'name': SomeClass,
    key_re = re.compile(r'["\']([a-z0-9_]+)["\']:\s*\w+')
    # Locate the registry dict body
    m = _REGISTRY_START_RE.search(source)
    if not m:
        return set()

    # Scan from the opening brace to the matching closing brace
    start = m.end()
    depth = 1
    pos = start
    while pos < len(source) and depth > 0:
        if source[pos] == "{":
            depth += 1
        elif source[pos] == "}":
            depth -= 1
        pos += 1

    registry_body = source[start:pos]
    return {m2.group(1) for m2 in key_re.finditer(registry_body)}


def _detect_class_name(client_file: Path) -> str | None:
    """Return the first BaseClient subclass name found in a client.py file."""
    text = client_file.read_text(encoding="utf-8")
    m = _CLASS_RE.search(text)
    return m.group(1) if m else None


def _insert_import(source: str, import_line: str) -> str:
    """Insert an import line into the sorted block of connector imports."""
    lines = source.splitlines(keepends=True)

    # Find all existing 'from gnat.connectors.' import lines
    connector_import_re = re.compile(r"^from gnat\.connectors\.")
    indices = [i for i, ln in enumerate(lines) if connector_import_re.match(ln)]

    if not indices:
        # Fallback: insert after the last 'from gnat.' import
        from_gnat_re = re.compile(r"^from gnat\.")
        indices = [i for i, ln in enumerate(lines) if from_gnat_re.match(ln)]
        if not indices:
            return source

    # Insert in alphabetical order within the connector import block
    insert_line = import_line + "\n"

    # Find the right position (keep sorted)
    for idx in indices:
        if lines[idx].strip() >= import_line:
            lines.insert(idx, insert_line)
            return "".join(lines)

    # Append after the last connector import
    last_idx = indices[-1]
    lines.insert(last_idx + 1, insert_line)
    return "".join(lines)


def _insert_registry_entry(source: str, entry_line: str) -> str:
    """Insert a registry entry into the CLIENT_REGISTRY dict body."""
    m = _REGISTRY_START_RE.search(source)
    if not m:
        logger.warning("Could not locate CLIENT_REGISTRY in %s", _REGISTRY_FILE)
        return source

    start = m.end()
    # Find existing entries and insert in alphabetical order
    entry_key_re = re.compile(r'^\s+["\']([a-z0-9_]+)["\']:')
    lines = source[start:].splitlines(keepends=True)

    new_entry_key = re.search(r'["\']([a-z0-9_]+)["\']', entry_line)
    if not new_entry_key:
        return source
    new_key = new_entry_key.group(1)

    insert_idx = None
    for i, line in enumerate(lines):
        m2 = entry_key_re.match(line)
        if m2 and m2.group(1) >= new_key:
            insert_idx = i
            break

    if insert_idx is None:
        # Find the closing brace and insert before it
        for i, line in enumerate(lines):
            if line.strip() == "}":
                insert_idx = i
                break

    if insert_idx is None:
        return source

    lines.insert(insert_idx, entry_line + "\n")
    return source[:start] + "".join(lines)
