# """
CTM-SAK Splunk Connector

Connector for Splunk Enterprise / Splunk Cloud Platform.

Covers two API surfaces:

- Splunk REST API (splunkd, port 8089) -- search, alerts, KV store, saved searches
- Enterprise Security Threat Intel API  -- IOC/STIX 2.x upload and TI management

Auth: Bearer token (session-key or pre-generated token)
STIX: Inbound observable ingestion (STIX 2.0/2.1 observed-data objects).
Indicator pattern syntax is NOT supported by Splunk ES -- mapping is
handled at the CTM-SAK ORM layer before submission.

Dev access: 60-day trial download OR 6-month renewable developer license
(10 GB/day indexing). No credit card required.
https://dev.splunk.com/enterprise/dev_license/

Configuration section (ctm_sak.ini):
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

from .client import SplunkClient
from .auth import SplunkAuthManager
from .search import SplunkSearchCommands
from .alerts import SplunkAlertCommands
from .threat_intel import SplunkThreatIntelCommands
from .kvstore import SplunkKVStoreCommands
from .stix_mapper import SplunkSTIXMapper
from .config import SplunkConfig
from .exceptions import (
SplunkAuthError,
SplunkAPIError,
SplunkSearchError,
SplunkThreatIntelError,
SplunkConfigError,
)

**all** = [
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

**version** = "0.1.0"
**platform** = "Splunk Enterprise / Splunk Cloud Platform"
**api_versions** = ["8.x", "9.x", "10.x"]
**stix_support** = "partial"  # observed-data objects; indicator patterns unsupported