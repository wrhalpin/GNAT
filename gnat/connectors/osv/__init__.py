# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.osv
======================

Connector for the Open Source Vulnerabilities database at https://osv.dev.

OSV aggregates vulnerabilities for open-source ecosystems (PyPI, npm,
Maven, Go, Rust, RubyGems, crates.io, Packagist, Debian, Alpine, and
others) under a common JSON schema.  The API is free and requires no
authentication.
"""

from .client import OSVClient

__all__ = ["OSVClient"]
