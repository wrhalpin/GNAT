# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
GNAT IBM QRadar Connector
==============================
Connector for IBM QRadar SIEM (on-premises and QRadar on Cloud).

API surface
-----------
QRadar exposes a single versioned REST API:
  https://<host>/api/<endpoint>

Key conventions that differ from other connectors:
  - Auth via ``SEC: <token>`` header (not Bearer, not Basic, not ApiKey)
  - API version declared via ``Version: <ver>`` header (not URL path)
  - Pagination via ``Range: items=<start>-<end>`` request header
    and ``Content-Range: items <start>-<end>/<total>`` response header
  - Async search jobs (Ariel): POST → poll → fetch (same pattern as Splunk)

Key domains
-----------
  Offenses        — QRadar's primary incident/alert concept. Offenses
                    aggregate correlated events and flows into security
                    incidents. Each offense has a status, magnitude,
                    assigned owner, and linked events.

  Ariel Search    — QRadar's proprietary query language (AQL) for
                    searching event and flow data. Jobs are async:
                    create → poll → retrieve results.

  Reference Data  — QRadar's KV store equivalent. Supports:
                    reference sets (single-value lists)
                    reference maps (key→value)
                    reference map of sets (key→set)
                    reference tables (key→row)
                    Used by GNAT to push IOC data into QRadar.

  Rules           — Correlation rules that generate offenses.
  Assets          — Asset / host inventory.
  Log Sources     — Configured log source inventory.

Auth
----
  ``SEC: <token>``
  ``Version: 20.0``
  ``Accept: application/json``

  The token is created in:
  QRadar Admin → User Management → Authorized Services → Add Authorized Service

  Tokens are scoped by user capability set. GNAT needs at minimum:
    OFFENSE MANAGER   — read/update offenses
    NETWORK ACTIVITY  — search events/flows via Ariel
    REFERENCE DATA MANAGER — manage reference sets

STIX 2.1 support
----------------
No native STIX. QRadarSTIXMapper converts:
  Offense records  → STIX observed-data SDOs + SCOs
  Ariel event rows → STIX observed-data bundles
  STIX indicators  → QRadar reference set entries (IOC push)

Dev access
----------
QRadar Community Edition:
  https://www.ibm.com/community/101/qradar/ce/
  100 EPS / 5,000 FPM, 3-month renewable license, full API access.

Configuration section (gnat.ini):
  [qradar]
  host              = qradar.corp.example.com
  token             =
  verify_ssl        = true
  api_version       = 20.0
  scheme            = https
  timeout           = 30
  max_results       = 50      ; max items per Range header request
  offense_status    = OPEN    ; default offense status filter
"""

from .ariel import QRadarArielCommands
from .assets import QRadarAssetCommands
from .auth import QRadarAuthManager
from .client import QRadarClient
from .config import QRadarConfig, load_qradar_config
from .exceptions import (
    QRadarAPIError,
    QRadarArielError,
    QRadarAuthError,
    QRadarConfigError,
    QRadarNotFoundError,
    QRadarRateLimitError,
    QRadarSTIXError,
)
from .log_sources import QRadarLogSourceCommands
from .offenses import QRadarOffenseCommands
from .reference_data import QRadarReferenceDataCommands
from .rules import QRadarRulesCommands
from .stix_mapper import QRadarSTIXMapper

__all__ = [
    "QRadarClient",
    "QRadarAuthManager",
    "QRadarOffenseCommands",
    "QRadarArielCommands",
    "QRadarReferenceDataCommands",
    "QRadarRulesCommands",
    "QRadarAssetCommands",
    "QRadarLogSourceCommands",
    "QRadarSTIXMapper",
    "QRadarConfig",
    "load_qradar_config",
    "QRadarAuthError",
    "QRadarAPIError",
    "QRadarNotFoundError",
    "QRadarConfigError",
    "QRadarArielError",
    "QRadarRateLimitError",
    "QRadarSTIXError",
]

__version__ = "0.1.0"
__platform__ = "IBM QRadar SIEM"
__api_versions__ = ["17.0", "18.0", "19.0", "20.0"]
__stix_support__ = "mapped"  # No native STIX; full mapping via QRadarSTIXMapper
