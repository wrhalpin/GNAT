"""
GNAT MISP Connector
========================
Connector for MISP (Malware Information Sharing Platform).

MISP is the de-facto open standard CTI sharing platform, used as the
backbone of most national and sector-level threat intelligence sharing
communities (ISACs, CERTs, government agencies).

API surface
-----------
MISP exposes a REST API at https://<host>/<resource>.json or via
the /events/restSearch endpoint for complex queries.

Key domains:
  Events      — MISP's primary container. Each event aggregates related
                IOCs (attributes) and metadata. Maps roughly to a STIX
                report SDO.
  Attributes  — Individual IOC values within events (ip-src, domain,
                md5, sha256, url, etc.). Map to STIX SCOs/indicator SDOs.
  Tags        — Free-form labels on events/attributes; includes Galaxies
                (MITRE ATT&CK, threat actors, malware families, etc.)
  Galaxies    — Structured knowledge bases: ATT&CK techniques, actors,
                tools, vulnerabilities.
  Feeds       — Configured MISP feeds (free/paid IOC subscription feeds).
  Sightings   — "I have seen this IOC" reports from sharing community.
  Taxonomies  — Structured tag namespaces (TLP, PAP, CIRCL, etc.)
  Sharing Groups — Fine-grained sharing control beyond community-wide.

Auth
----
Static API key sent as ``Authorization: <api_key>`` header.
Also requires ``Accept: application/json`` on all requests.
The key is found in MISP under Administration → List Users → My Profile.

STIX 2.1 support
----------------
Native. MISP supports:
  - STIX 2.1 export via /events/restSearch with returnFormat=stix2
  - STIX 2.1 import via /events/upload_stix
  - TAXII 2.1 server (MISP-TAXII bridge)
  - The connector also provides a Python-level STIX mapper for
    programmatic event↔STIX conversion without the round-trip.

Dev access
----------
Completely free and open source.
  Docker: https://www.misp-project.org/download/#docker
  OVA:    https://www.misp-project.org/download/
  MISP community training instance (request access):
    https://www.misp-project.org/misp-training/

Configuration section (gnat.ini):
  [misp]
  url               = https://misp.corp.example.com
  api_key           =
  verify_ssl        = true
  timeout           = 30
  max_results       = 100
  default_distribution  = 0    ; 0=org, 1=community, 2=connected, 3=all
  default_threat_level  = 2    ; 1=high, 2=medium, 3=low, 4=undefined
  default_analysis      = 0    ; 0=initial, 1=ongoing, 2=complete
"""

from .client import MISPClient
from .auth import MISPAuthManager
from .events import MISPEventCommands
from .attributes import MISPAttributeCommands
from .tags import MISPTagCommands
from .galaxies import MISPGalaxyCommands
from .feeds import MISPFeedCommands
from .sightings import MISPSightingCommands
from .stix_mapper import MISPSTIXMapper
from .config import MISPConfig, load_misp_config
from .exceptions import (
    MISPAuthError,
    MISPAPIError,
    MISPNotFoundError,
    MISPConfigError,
    MISPValidationError,
    MISPSTIXError,
)

__all__ = [
    "MISPClient",
    "MISPAuthManager",
    "MISPEventCommands",
    "MISPAttributeCommands",
    "MISPTagCommands",
    "MISPGalaxyCommands",
    "MISPFeedCommands",
    "MISPSightingCommands",
    "MISPSTIXMapper",
    "MISPConfig",
    "load_misp_config",
    "MISPAuthError",
    "MISPAPIError",
    "MISPNotFoundError",
    "MISPConfigError",
    "MISPValidationError",
    "MISPSTIXError",
]

__version__ = "0.1.0"
__platform__ = "MISP Malware Information Sharing Platform"
__api_versions__ = ["2.4.x"]
__stix_support__ = "native"  # STIX 2.1 export + import; TAXII 2.1
