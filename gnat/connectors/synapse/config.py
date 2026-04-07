# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Configuration dataclass for the Synapse connector."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class SynapseConfig:
    """
    Configuration for the Vertex Project Synapse connector.

    Parameters
    ----------
    host : str
        Base URL of the Synapse Cortex HTTP API,
        e.g. ``"https://synapse.example.com"``.
    username : str
        Username for login-based authentication.
    password : str
        Password for login-based authentication.
    api_key : str
        API key (Bearer token) — alternative to username/password.
    verify_ssl : bool
        Verify TLS certificates.  Defaults to ``True``.
    timeout : int
        Request timeout in seconds.  Defaults to ``30``.
    view : str
        Default view iden for Storm queries.  Empty string uses the
        Cortex default view.
    """

    host: str
    username: str = ""
    password: str = ""
    api_key: str = ""
    verify_ssl: bool = True
    timeout: int = 30
    view: str = ""
