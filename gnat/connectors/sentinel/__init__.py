"""
GNAT Microsoft Sentinel Connector
=======================================
Connector for Microsoft Sentinel (Azure cloud-native SIEM/SOAR).

API surface
-----------
Microsoft Sentinel is accessed through the Azure REST API and the
Microsoft Sentinel REST API, both hosted under management.azure.com.

All Sentinel resources are scoped to an Azure workspace:
  /subscriptions/<sub_id>/resourceGroups/<rg>/providers/
    Microsoft.OperationalInsights/workspaces/<workspace>/providers/
      Microsoft.SecurityInsights/<resource>

Key domains covered:
  Incidents      — Sentinel's primary alert/case concept (maps to offenses
                   in QRadar; alerts/cases in Elastic). Incidents aggregate
                   alerts and have their own lifecycle.
  Alerts         — Individual alert entities linked to incidents.
  Watchlists     — CSV-backed lookup tables used in detection rules.
  Analytic Rules — Scheduled KQL queries and Fusion/ML detection rules.
  Threat Intel   — STIX-adjacent indicator management (TI Indicators API).
  Hunting Queries — Saved KQL hunting queries.
  Bookmarks      — Investigation bookmarks linking entities to incidents.

Auth
----
Azure OAuth2 client credentials flow:
  POST https://login.microsoftonline.com/<tenant_id>/oauth2/v2.0/token
  Body: grant_type=client_credentials
        client_id=<app_id>
        client_secret=<secret>
        scope=https://management.azure.com/.default

  Returns: {"access_token": "...", "expires_in": 3600, "token_type": "Bearer"}

  Tokens expire in 3600s. SentinelAuthManager renews proactively at 80%.

Required Azure RBAC roles for the service principal:
  Microsoft Sentinel Reader       — read incidents, alerts, rules
  Microsoft Sentinel Responder    — update incidents, close alerts
  Microsoft Sentinel Contributor  — create/update rules, watchlists, TI

STIX 2.1 support
----------------
Sentinel's Threat Intelligence Indicators API maps directly to STIX 2.1
indicator SDOs. The connector supports:
  - Reading TI indicators (GET /threatIntelligence/main/indicators)
  - Creating indicators (POST /threatIntelligence/main/createIndicator)
  - STIX bundle ingestion via bulk create

Dev access
----------
Microsoft Sentinel requires an Azure subscription.
  31-day free trial: https://azure.microsoft.com/en-us/free/
  Microsoft Sentinel free trial: 31 days, 10 GB/day ingestion.
  Azure student subscription available with .edu email.

Configuration section (gnat.ini):
  [sentinel]
  tenant_id         =
  client_id         =
  client_secret     =
  subscription_id   =
  resource_group    =
  workspace_name    =
  workspace_id      =     ; optional, used for some Log Analytics queries
  verify_ssl        = true
  timeout           = 30
  max_results       = 100
  api_version       = 2023-11-01
"""

from .alerts import SentinelAlertCommands
from .analytic_rules import SentinelAnalyticRuleCommands
from .auth import SentinelAuthManager
from .client import SentinelClient
from .config import SentinelConfig, load_sentinel_config
from .exceptions import (
    SentinelAPIError,
    SentinelAuthError,
    SentinelConfigError,
    SentinelNotFoundError,
    SentinelRateLimitError,
    SentinelSTIXError,
)
from .hunting import SentinelHuntingCommands
from .incidents import SentinelIncidentCommands
from .stix_mapper import SentinelSTIXMapper
from .threat_intel import SentinelThreatIntelCommands
from .watchlists import SentinelWatchlistCommands

__all__ = [
    "SentinelClient",
    "SentinelAuthManager",
    "SentinelIncidentCommands",
    "SentinelAlertCommands",
    "SentinelWatchlistCommands",
    "SentinelAnalyticRuleCommands",
    "SentinelThreatIntelCommands",
    "SentinelHuntingCommands",
    "SentinelSTIXMapper",
    "SentinelConfig",
    "load_sentinel_config",
    "SentinelAuthError",
    "SentinelAPIError",
    "SentinelNotFoundError",
    "SentinelConfigError",
    "SentinelRateLimitError",
    "SentinelSTIXError",
]

__version__ = "0.1.0"
__platform__ = "Microsoft Sentinel"
__api_versions__ = ["2023-11-01", "2024-01-01-preview"]
__stix_support__ = "native"  # TI Indicators API maps directly to STIX indicator SDOs
