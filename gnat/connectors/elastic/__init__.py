# “””
GNAT Elastic Security Connector

Connector for Elastic Security (Elasticsearch + Kibana Security).

Covers two API surfaces:

Surface A — Elasticsearch REST API  (port 9200)
─────────────────────────────────────────────────

- Index search, document CRUD, index management
- Threat intelligence indicator indices (logs-ti_*)
- Alert/signal indices (.alerts-security.*)
- Direct Query DSL for advanced analytics

Surface B — Kibana Security API     (port 5601)
─────────────────────────────────────────────────

- Detection rules (create/read/update/delete/enable/disable/import/export)
- Alert management (status updates, bulk actions)
- Cases (incident management)
- SIEM exception lists
- Timeline management
- TAXII 2.1 server integration

## Auth

Both surfaces share a single Elastic API key:
Authorization: ApiKey <base64(id:api_key)>

The API key is created in Kibana:
Stack Management → API Keys → Create API key

Or via the Elasticsearch API:
POST /_security/api_key

Kibana API additionally requires:
kbn-xsrf: true         (all non-GET requests)
Content-Type: application/json

## STIX 2.1 Support

Elastic Security has native STIX 2.1 / TAXII 2.1 support via the
Custom Threat Intelligence integration (ti_custom). The connector:

- Reads TI indicators from logs-ti_* indices (ES surface)
- Uploads STIX 2.1 bundles via the TI upload endpoint (Kibana surface)
- Maps Elastic alert fields ↔ STIX 2.1 observed-data via ElasticSTIXMapper
- Maps Detection Rule fields ↔ STIX 2.1 indicator SDOs

ECS (Elastic Common Schema) is the normalisation layer between
raw event data and STIX. GNAT maps ECS fields directly.

## Dev access

Free self-hosted Basic tier with full API access:
Docker: https://www.elastic.co/guide/en/elasticsearch/reference/current/docker.html
14-day cloud trial (no credit card): https://cloud.elastic.co/registration

Configuration section (gnat.ini):
[elastic]
es_host           = localhost
es_port           = 9200
kibana_host       = localhost
kibana_port       = 5601
scheme            = https
api_key_id        =
api_key_secret    =
verify_ssl        = true
timeout           = 30
max_results       = 1000
es_index_alerts   = .alerts-security.*
es_index_ti       = logs-ti_*
kibana_space      = default
cloud_id          =            ; Elastic Cloud ID (overrides host/port)
“””

from .client import ElasticClient
from .auth import ElasticAuthManager
from .es_search import ElasticSearchCommands
from .kibana_rules import KibanaRulesCommands
from .kibana_alerts import KibanaAlertsCommands
from .kibana_cases import KibanaCasesCommands
from .threat_intel import ElasticThreatIntelCommands
from .stix_mapper import ElasticSTIXMapper
from .config import ElasticConfig, load_elastic_config
from .exceptions import (
ElasticAuthError,
ElasticAPIError,
ElasticNotFoundError,
ElasticConfigError,
ElasticRateLimitError,
ElasticSTIXError,
ElasticKibanaError,
)

**all** = [
“ElasticClient”,
“ElasticAuthManager”,
“ElasticSearchCommands”,
“KibanaRulesCommands”,
“KibanaAlertsCommands”,
“KibanaCasesCommands”,
“ElasticThreatIntelCommands”,
“ElasticSTIXMapper”,
“ElasticConfig”,
“load_elastic_config”,
“ElasticAuthError”,
“ElasticAPIError”,
“ElasticNotFoundError”,
“ElasticConfigError”,
“ElasticRateLimitError”,
“ElasticSTIXError”,
“ElasticKibanaError”,
]

**version** = “0.1.0”
**platform** = “Elastic Security (Elasticsearch + Kibana)”
**api_versions** = [“8.x”, “8.10+”]
**stix_support** = “native”   # STIX 2.1 + TAXII 2.1 via Custom TI integration