# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
GNAT Dynatrace Connector
============================
Connector for Dynatrace (Observability, APM, AppSec, and Grail analytics).

API surface
-----------
Dynatrace is accessed through two separate API stacks:

Environment API v2 (static Api-Token auth)
  - Entities (monitored hosts, services, applications, etc.)
  - Problems (availability and performance incidents)
  - Security Problems (CVEs and runtime vulnerabilities)
  - Attacks (runtime injection attacks via Application Security)
  - Events (custom and built-in event ingestion)
  - Metrics (time-series data query)
  - Settings (configuration objects)

Grail / Platform Storage API (OAuth2 Bearer auth)
  - DQL query execution (fetch logs, events, bizevents, spans)
  - Log export
  - Security event search
  - Business event ingestion and export

Auth
----
Environment API v2:
  Static Api-Token header:
    Authorization: Api-Token dt0c01.YOUR_API_TOKEN

Grail Platform Storage API:
  OAuth2 client credentials:
    POST https://sso.dynatrace.com/sso/oauth2/token
    grant_type=client_credentials
    &client_id=dt0s01.CLIENT_ID
    &client_secret=...
    &scope=storage:logs:read storage:events:read ...

  Returns: {"access_token": "...", "expires_in": 3600}
  Tokens expire in 3600s. DynatraceOAuthManager renews proactively at 80%.

Required Api-Token scopes:
  entities.read, problems.read, securityProblems.read, attacks.read,
  events.read, events.ingest, metrics.read, logs.read,
  settings.read, settings.write

Required OAuth2 scopes (Grail):
  storage:logs:read, storage:events:read, storage:query:execute,
  storage:bizevents:read, storage:bizevents:write

STIX 2.1 support
----------------
  Entity            → infrastructure SDO
  Security Problem  → vulnerability SDO
  Attack            → indicator SDO
  Problem           → observed-data SDO
  Event             → observed-data SDO
  STIX dict         → event ingest payload (from_stix)

Configuration section (gnat.ini):
  [dynatrace]
  host      = https://YOUR_ENV_ID.live.dynatrace.com
  api_token = dt0c01.YOUR_API_TOKEN
  ; --- Grail (optional)
  ; oauth_client_id     = dt0s01.YOUR_OAUTH2_CLIENT_ID
  ; oauth_client_secret = dt0s01.YOUR_OAUTH2_CLIENT_SECRET
  ; oauth_token_url     = https://sso.dynatrace.com/sso/oauth2/token
  verify_ssl = true
  timeout    = 30
"""

from .auth import DynatraceOAuthManager
from .client import DynatraceClient
from .config import DynatraceConfig, load_dynatrace_config
from .exceptions import (
    DynatraceAPIError,
    DynatraceAuthError,
    DynatraceConfigError,
    DynatraceConflictError,
    DynatraceError,
    DynatraceNotFoundError,
    DynatraceQueryTimeoutError,
    DynatraceRateLimitError,
    DynatraceSTIXError,
)
from .stix_mapper import DynatraceSTIXMapper

__all__ = [
    "DynatraceClient",
    "DynatraceOAuthManager",
    "DynatraceSTIXMapper",
    "DynatraceConfig",
    "load_dynatrace_config",
    "DynatraceError",
    "DynatraceConfigError",
    "DynatraceAuthError",
    "DynatraceAPIError",
    "DynatraceNotFoundError",
    "DynatraceRateLimitError",
    "DynatraceConflictError",
    "DynatraceSTIXError",
    "DynatraceQueryTimeoutError",
]

__version__ = "0.1.0"
__platform__ = "Dynatrace"
__api_versions__ = ["v2", "platform-storage-v1"]
__stix_support__ = "bidirectional"
