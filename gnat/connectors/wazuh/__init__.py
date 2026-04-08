# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
GNAT Wazuh Connector

Connector for Wazuh Open Source XDR / SIEM platform.

Covers two API surfaces:

- Wazuh Manager API  (port 55000) -- agents, alerts, rules, FIM, SCA,
  vulnerabilities, active response
- Wazuh Indexer API  (port 9200)  -- OpenSearch-based log/alert search
  (optional; requires indexer access)

Auth: JWT Bearer token via POST /security/user/authenticate.
Tokens expire after ~900 seconds (configurable on the server).
WazuhAuthManager handles automatic renewal transparently.

STIX: No native STIX support in Wazuh. The WazuhSTIXMapper converts:

- Alert events       -> STIX observed-data + SCOs (ipv4-addr, domain-name,
  file, user-account, process)
- FIM events         -> STIX observed-data + file SCOs
- Vulnerability data -> STIX vulnerability SDOs
- Agent metadata     -> STIX identity SDOs (x-wazuh-agent extension)

Dev access: Completely free and open source. Self-hosted.
Docker: https://documentation.wazuh.com/current/deployment-options/
docker/docker-installation.html
OVA:    https://documentation.wazuh.com/current/deployment-options/
virtual-machine/virtual-machine.html

Configuration section (gnat.ini):
[wazuh]
host              = localhost
port              = 55000
username          = wazuh
password          =
verify_ssl        = false       ; Wazuh default uses self-signed certs
scheme            = https
timeout           = 30
max_results       = 500
indexer_enabled   = false
indexer_host      = localhost
indexer_port      = 9200
indexer_username  = admin
indexer_password  =
token_expiry_secs = 900         ; mirror your Wazuh server setting
"""

from .active_response import WazuhActiveResponseCommands
from .agents import WazuhAgentCommands
from .alerts import WazuhAlertCommands
from .auth import WazuhAuthManager
from .client import WazuhClient
from .config import WazuhConfig, load_wazuh_config
from .exceptions import (
    WazuhAPIError,
    WazuhAuthError,
    WazuhConfigError,
    WazuhIndexerError,
    WazuhNotFoundError,
    WazuhPermissionError,
    WazuhSTIXError,
)
from .indexer import WazuhIndexerCommands
from .rules import WazuhRulesCommands
from .stix_mapper import WazuhSTIXMapper
from .syscheck import WazuhSyscheckCommands
from .vulnerabilities import WazuhVulnerabilityCommands

__all__ = [
    "WazuhClient",
    "WazuhAuthManager",
    "WazuhAgentCommands",
    "WazuhAlertCommands",
    "WazuhSyscheckCommands",
    "WazuhVulnerabilityCommands",
    "WazuhRulesCommands",
    "WazuhActiveResponseCommands",
    "WazuhIndexerCommands",
    "WazuhSTIXMapper",
    "WazuhConfig",
    "load_wazuh_config",
    "WazuhAuthError",
    "WazuhAPIError",
    "WazuhNotFoundError",
    "WazuhPermissionError",
    "WazuhConfigError",
    "WazuhSTIXError",
    "WazuhIndexerError",
]

__version__ = "0.1.0"
__platform__ = "Wazuh Open Source XDR / SIEM"
__api_versions__ = ["4.7.x", "4.8.x", "4.9.x", "4.10.x", "4.11.x", "4.12.x"]
__stix_support__ = "mapped"  # No native STIX; full mapping via WazuhSTIXMapper
