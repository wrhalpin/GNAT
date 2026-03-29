"""
gnat.clients
===============

HTTP client implementations for each supported security platform.

All clients inherit from :class:`~gnat.clients.base.BaseClient` and are
registered in the :data:`CLIENT_REGISTRY` dict so that
:class:`~gnat.client.GNATClient` can resolve them by name.
"""

from gnat.clients.base import BaseClient, GNATClientError
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
from gnat.connectors.controlup.client import ControlUpClient
from gnat.connectors.alienvault.client import AlienVaultClient
from gnat.connectors.graylog.client import GraylogClient
from gnat.connectors.ossim.client import OSSIMClient
from gnat.connectors.security_onion.client import SecurityOnionClient
from gnat.connectors.snort.client import SnortClient
from gnat.connectors.suricata.client import SuricataClient
from gnat.connectors.zeek.client import ZeekClient
from gnat.connectors.elastic.connector import ElasticConnector
from gnat.connectors.misp.connector import MISPConnector
from gnat.connectors.opencti.client import OpenCTIClient
from gnat.connectors.qradar.connector import QRadarConnector
from gnat.connectors.sentinel.connector import SentinelConnector
from gnat.connectors.wazuh.connector import WazuhConnector
from gnat.connectors.servicenow.client import ServiceNowClient
from gnat.connectors.jira.client import JiraClient
from gnat.connectors.threatconnect.client import ThreatConnectClient
from gnat.connectors.mandiant.client import MandiantClient
from gnat.connectors.defenderti.client import DefenderTIClient
from gnat.connectors.thehive.client import TheHiveClient
from gnat.connectors.threatstream.client import ThreatStreamClient
from gnat.connectors.socradar.client import SOCRadarClient
from gnat.connectors.pulsedive.client import PulseDiveClient
from gnat.connectors.flare.client import FlareClient
from gnat.connectors.stellarcyber.client import StellarCyberClient
from gnat.connectors.yeti.client import YetiClient
from gnat.connectors.cloudsek.client import CloudSEKClient
from gnat.connectors.grok.uclient import GrokClient
from gnat.connectors.gemini.client import GeminiClient
from gnat.connectors.copilot.client import CopilotClient
from gnat.connectors.chatgpt import ChatGPTClient
from gnat.connectors.cyble_vision.client import CybleVisionClient

CLIENT_REGISTRY["cyble_vision"] = CybleVisionClient
    CLIENT_REGISTRY = {
        # existing entries...
        "copilot": CopilotClient,
    }

CLIENT_REGISTRY: dict = {
    "threatq":        ThreatQClient,
    "proofpoint":     ProofpointClient,
    "netskope":       NetskopeClient,
    "crowdstrike":    CrowdStrikeClient,
    "xsoar":          XSOARClient,
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
    "controlup":      ControlUpClient,
    "alienvault":     AlienVaultClient,
    "alienvault_otx": AlienVaultClient,
    "graylog":        GraylogClient,
    "ossim":          OSSIMClient,
    "security_onion": SecurityOnionClient,
    "snort":          SnortClient,
    "suricata":       SuricataClient,
    "zeek":           ZeekClient,
    "elastic":        ElasticConnector,
    "misp":           MISPConnector,
    "opencti":        OpenCTIClient,
    "qradar":         QRadarConnector,
    "sentinel":       SentinelConnector,
    "wazuh":          WazuhConnector,
    "servicenow":     ServiceNowClient,
    "jira":           JiraClient,
    "threatconnect":  ThreatConnectClient,
    "mandiant":       MandiantClient,
    "defenderti":     DefenderTIClient,
    "thehive":        TheHiveClient,
    "threatstream":   ThreatStreamClient,
    "socradar":       SOCRadarClient,
    "pulsedive":      PulseDiveClient,
    "flare":          FlareClient,
    "stellarcyber":   StellarCyberClient,
    "yeti":           YetiClient,
    "cloudsek":       CloudSEKClient,
    "grok":           GrokClient,
    "gemini":         GeminiClient,
    "copilot":        CopilotClient, 
    "chatgpt"         ChatGPTClient,
    "cyble_vision":   CybleVisionClient,
}

__all__ = [
    "BaseClient",
    "GNATClientError",
    "CLIENT_REGISTRY",
]
