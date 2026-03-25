"""
ctm_sak.clients
===============

HTTP client implementations for each supported security platform.

All clients inherit from :class:`~ctm_sak.clients.base.BaseClient` and are
registered in the :data:`CLIENT_REGISTRY` dict so that
:class:`~ctm_sak.client.SAKClient` can resolve them by name.
"""

from ctm_sak.clients.base import BaseClient, SAKClientError
from ctm_sak.connectors.threatq.client import ThreatQClient
from ctm_sak.connectors.proofpoint.client import ProofpointClient
from ctm_sak.connectors.netskope.client import NetskopeClient
from ctm_sak.connectors.crowdstrike.client import CrowdStrikeClient
from ctm_sak.connectors.xsoar.client import XSOARClient
from ctm_sak.connectors.recordedfuture.client import RecordedFutureClient
from ctm_sak.connectors.greymatter.client import GreyMatterClient
from ctm_sak.connectors.whistic.client import WhisticClient
from ctm_sak.connectors.riskrecon.client import RiskReconClient
from ctm_sak.connectors.feedly.client import FeedlyClient
from ctm_sak.connectors.splunk.client import SplunkClient
from ctm_sak.connectors.virustotal.client import VirusTotalClient
from ctm_sak.connectors.shadowserver.client import ShadowServerClient
from ctm_sak.connectors.rapid7.client import Rapid7Client
from ctm_sak.connectors.nucleus.client import NucleusClient

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
