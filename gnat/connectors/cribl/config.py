"""Configuration dataclass for the Cribl connector."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class CriblConfig:
    """
    Configuration for the Cribl Stream / Edge connector.

    Parameters
    ----------
    host : str
        Base URL of the Cribl leader node,
        e.g. ``"https://cribl-leader.example.com"``.
    username : str
        Username for username/password authentication.
    password : str
        Password for username/password authentication.
    token : str
        Direct API token (alternative to username/password).
    worker_group : str
        Default worker-group to target.  Defaults to ``"default"``.
    verify_ssl : bool
        Verify TLS certificates.  Defaults to ``True``.
    timeout : int
        Request timeout in seconds.  Defaults to ``30``.
    """

    host: str
    username: str = ""
    password: str = ""
    token: str = ""
    worker_group: str = "default"
    verify_ssl: bool = True
    timeout: int = 30
