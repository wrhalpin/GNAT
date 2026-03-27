"""
gnat.clients
===============

HTTP client implementations for each supported security platform.

All clients inherit from :class:`~gnat.clients.base.BaseClient` and are
registered in the :data:`CLIENT_REGISTRY` dict so that
:class:`~gnat.client.SAKClient` can resolve them by name.
"""

from gnat.clients.base import BaseClient, SAKClientError
from gnat.connectors.threatq.client import ThreatQClient
from gnat.connectors.proofpoint.client import ProofpointClient
from gnat.connectors.netskope.client import NetskopeClient
from gnat.connectors.crowdstrike.client import CrowdStrikeClient
from gnat.connectors.xsoar.client import XSOARClient
from gnat.connectors.recordedfuture.client import RecordedFutureClient
from gnat.connectors.greymatter.client import GreyMatterClient
from gnat.connectors.whistic.client import WhisticClient
from gnat.connectors.riskrecon.client import RiskReconClient
from gnat.connectors.feedly.client import FeedlyClient
from gnat.connectors.splunk.client import SplunkClient
from gnat.connectors.virustotal.client import VirusTotalClient
from gnat.connectors.shadowserver.client import ShadowServerClient
from gnat.connectors.rapid7.client import Rapid7Client
from gnat.connectors.nucleus.client import NucleusClient

CLIENT_REGISTRY: dict = {
    "threatq": ThreatQClient,
    "proofpoint": ProofpointClient,
    "netskope": NetskopeClient,
    "crowdstrike": CrowdStrikeClient,
    "xsoar": XSOARClient,
    "recordedfuture": RecordedFutureClient,
    "greymatter":     GreyMatterClient,
    "whistic":        WhisticClient,
    "riskrecon":      RiskReconClient,
    "feedly":         FeedlyClient,
    "splunk":         SplunkClient,
    "virustotal":     VirusTotalClient,
    "shadowserver":   ShadowServerClient,
    "rapid7":         Rapid7Client,
    "nucleus":        NucleusClient,
}

__all__ = [
    "BaseClient",
    "SAKClientError",
    "CLIENT_REGISTRY",
]
