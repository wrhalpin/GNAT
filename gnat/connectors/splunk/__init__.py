"""
GNAT Splunk Connector

Connector for Splunk Enterprise / Splunk Cloud Platform.

Covers two API surfaces:

- Splunk REST API (splunkd, port 8089) -- search, alerts, KV store, saved searches
- Enterprise Security Threat Intel API -- IOC/STIX 2.x upload and TI management

Auth: Bearer token (session-key or pre-generated token)
STIX: Inbound observable ingestion (STIX 2.0/2.1 observed-data objects).
Indicator pattern syntax is NOT supported by Splunk ES -- mapping is
handled at the GNAT ORM layer before submission.

Dev access: 60-day trial download OR 6-month renewable developer license
(10 GB/day indexing). No credit card required.
https://dev.splunk.com/enterprise/dev_license/

Configuration section (gnat.ini)::

    [splunk]
    host            = localhost
    port            = 8089
    username        = admin
    password        =
    token           =                ; pre-generated token (preferred over password)
    verify_ssl      = true
    scheme          = https
    es_enabled      = false           ; set true if Splunk ES app is installed
    app_context     = search          ; Splunk app namespace for REST calls
    default_index   = main
    timeout         = 30
    max_results     = 10000
"""

from .alerts import SplunkAlertCommands
from .auth import SplunkAuthManager
from .client import SplunkClient
from .config import SplunkConfig
from .exceptions import (
    SplunkAPIError,
    SplunkAuthError,
    SplunkConfigError,
    SplunkSearchError,
    SplunkThreatIntelError,
)
from .kvstore import SplunkKVStoreCommands
from .search import SplunkSearchCommands
from .stix_mapper import SplunkSTIXMapper
from .threat_intel import SplunkThreatIntelCommands

__all__ = [
    "SplunkClient",
    "SplunkAuthManager",
    "SplunkSearchCommands",
    "SplunkAlertCommands",
    "SplunkThreatIntelCommands",
    "SplunkKVStoreCommands",
    "SplunkSTIXMapper",
    "SplunkConfig",
    "SplunkAuthError",
    "SplunkAPIError",
    "SplunkSearchError",
    "SplunkThreatIntelError",
    "SplunkConfigError",
]

__version__ = "0.1.0"
__platform__ = "Splunk Enterprise / Splunk Cloud Platform"
__api_versions__ = ["8.x", "9.x", "10.x"]
__stix_support__ = "partial"  # observed-data objects; indicator patterns unsupported
