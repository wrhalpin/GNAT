# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.ingest._ioc_classifier
================================

IOC classification and defanging utilities.

Tries to use the native Rust extension ``gnat._core`` for maximum throughput.
Falls back transparently to the pure-Python implementation if the extension
is not installed.

Usage
-----
::

    from gnat.ingest._ioc_classifier import classify_ioc, defang, classify_ioc_batch

    ioc_type = classify_ioc("1.2.3.4")          # → "ip"
    clean    = defang("hxxp://evil[.]com/path")  # → "http://evil.com/path"
    types    = classify_ioc_batch(["1.2.3.4", "evil.com"])  # → ["ip", "domain"]
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Attempt to import the Rust native extension
# ---------------------------------------------------------------------------

try:
    # gnat-core installs as the '_core' package (built via maturin).
    # The wheel places functions at _core.classify_ioc etc.
    from _core import (  # type: ignore[import]
        classify_ioc as _rust_classify,
    )
    from _core import (
        classify_ioc_batch as _rust_classify_batch,
    )
    from _core import (
        defang as _rust_defang,
    )
    from _core import (
        extract_pattern_value as _rust_extract_pattern_value,
    )
    from _core import (
        refang as _rust_refang,
    )

    RUST_AVAILABLE: bool = True
except ImportError:
    RUST_AVAILABLE = False

# ---------------------------------------------------------------------------
# Pure-Python fallbacks (identical logic to PlainTextReader._classify() and
# the helpers in gnat/export/transforms/edl.py)
# ---------------------------------------------------------------------------

_PATTERNS = {
    "sha256": re.compile(r"^[0-9a-fA-F]{64}$"),
    "sha1": re.compile(r"^[0-9a-fA-F]{40}$"),
    "md5": re.compile(r"^[0-9a-fA-F]{32}$"),
    "ip": re.compile(
        r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
        r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:/\d{1,2})?$"
    ),
    "ipv6": re.compile(r"^[0-9a-fA-F:]{2,39}(?:/\d{1,3})?$"),
    "url": re.compile(r"^https?://", re.IGNORECASE),
    "email": re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$"),
    "domain": re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,}$"
    ),
}

_DEFANG_RE = [
    (re.compile(r"\[\.?\]"), "."),
    (re.compile(r"(?i)hxxps://"), "https://"),
    (re.compile(r"(?i)hxxp://"), "http://"),
]

_VALUE_RE = re.compile(r"=\s*'([^']+)'")


def _py_classify_ioc(value: str) -> str:
    for ioc_type, pattern in _PATTERNS.items():
        if pattern.match(value):
            return ioc_type
    return "unknown"


def _py_defang(value: str) -> str:
    for pattern, repl in _DEFANG_RE:
        value = pattern.sub(repl, value)
    return value.strip()


def _py_refang(value: str) -> str:
    value = value.replace("https://", "hxxps://").replace("http://", "hxxp://")
    return value.replace(".", "[.]")


def _py_extract_pattern_value(pattern: str) -> str | None:
    m = _VALUE_RE.search(pattern)
    return m.group(1) if m else None


def _py_classify_ioc_batch(values: list[str]) -> list[str]:
    return [_py_classify_ioc(v) for v in values]


# ---------------------------------------------------------------------------
# Public interface — dispatches to Rust or pure Python
# ---------------------------------------------------------------------------


def classify_ioc(value: str) -> str:
    """
    Classify an IOC string into one of:
    ``"sha256"``, ``"sha1"``, ``"md5"``, ``"ip"``, ``"ipv6"``,
    ``"url"``, ``"email"``, ``"domain"``, ``"unknown"``.

    Uses the Rust native extension when available (``gnat[fast]`` install),
    otherwise falls back to pure Python.
    """
    if RUST_AVAILABLE:
        return _rust_classify(value)
    return _py_classify_ioc(value)


def defang(value: str) -> str:
    """
    Remove defanging substitutions to restore canonical IOC values.

    ``[.]`` → ``.``, ``hxxp://`` → ``http://``, ``hxxps://`` → ``https://``.
    """
    if RUST_AVAILABLE:
        return _rust_defang(value)
    return _py_defang(value)


def refang(value: str) -> str:
    """
    Apply defanging substitutions for safe display.

    ``http://`` → ``hxxp://``, ``.`` → ``[.]``, etc.
    """
    if RUST_AVAILABLE:
        return _rust_refang(value)
    return _py_refang(value)


def extract_pattern_value(pattern: str) -> str | None:
    """
    Extract the quoted value from a STIX pattern string.

    ``"[ipv4-addr:value = '1.2.3.4']"`` → ``"1.2.3.4"``
    """
    if RUST_AVAILABLE:
        return _rust_extract_pattern_value(pattern)
    return _py_extract_pattern_value(pattern)


def classify_ioc_batch(values: list[str]) -> list[str]:
    """
    Classify a list of IOC strings in bulk.

    When the Rust extension is available, this is significantly faster than
    calling ``classify_ioc()`` in a Python loop because the hot loop stays
    in native code.
    """
    if RUST_AVAILABLE:
        return _rust_classify_batch(values)
    return _py_classify_ioc_batch(values)
