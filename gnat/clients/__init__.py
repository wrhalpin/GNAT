"""
gnat.clients
===============

HTTP client implementations for each supported security platform.

All clients inherit from :class:`~gnat.clients.base.BaseClient` and are
registered in the :data:`CLIENT_REGISTRY` dict so that
:class:`~gnat.client.GNATClient` can resolve them by name.
"""

from gnat.clients.base import BaseClient, GNATClientError
from gnat.connectors.alienvault.client import AlienVaultClient
from gnat.connectors.armis.client import ArmisClient
from gnat.connectors.axonius.client import AxoniusClient
from gnat.connectors.chatgpt import ChatGPTClient
from gnat.connectors.cloudsek.client import CloudSEKClient
from gnat.connectors.controlup.client import ControlUpClient
from gnat.connectors.copilot.client import CopilotClient
from gnat.connectors.cortex_xpanse.client import CortexXpanseClient
from gnat.connectors.cribl.client import CriblClient
from gnat.connectors.crowdstrike.client import CrowdStrikeClient
from gnat.connectors.cyble_vision.client import CybleVisionClient
from gnat.connectors.cycognito.client import CyCognitoClient
from gnat.connectors.defectdojo.client import DefectDojoClient
from gnat.connectors.defenderti.client import DefenderTIClient
from gnat.connectors.elastic.connector import ElasticConnector
from gnat.connectors.feedly.client import FeedlyClient
from gnat.connectors.flare.client import FlareClient
from gnat.connectors.gemini.client import GeminiClient
from gnat.connectors.graylog.client import GraylogClient
from gnat.connectors.greenbone.client import GreenboneClient
from gnat.connectors.greymatter.client import GreyMatterClient
from gnat.connectors.grok.client import GrokClient
from gnat.connectors.group_ib.client import GroupIBClient
from gnat.connectors.jira.client import JiraClient
from gnat.connectors.mandiant.client import MandiantClient
from gnat.connectors.misp.connector import MISPConnector
from gnat.connectors.netskope.client import NetskopeClient
from gnat.connectors.nucleus.client import NucleusClient
from gnat.connectors.opencti.client import OpenCTIClient
from gnat.connectors.orca.client import OrcaClient
from gnat.connectors.ossim.client import OSSIMClient
from gnat.connectors.proofpoint.client import ProofpointClient
from gnat.connectors.pulsedive.client import PulseDiveClient
from gnat.connectors.qradar.connector import QRadarConnector
from gnat.connectors.qualys.client import QualysVMDRClient
from gnat.connectors.rapid7.client import Rapid7Client
from gnat.connectors.recordedfuture.client import RecordedFutureClient
from gnat.connectors.riskrecon.client import RiskReconClient
from gnat.connectors.security_onion.client import SecurityOnionClient
from gnat.connectors.sentinel.connector import SentinelConnector
from gnat.connectors.sentinelone.client import SentinelOneClient
from gnat.connectors.servicenow.client import ServiceNowClient
from gnat.connectors.shadowserver.client import ShadowServerClient
from gnat.connectors.snort.client import SnortClient
from gnat.connectors.socradar.client import SOCRadarClient
from gnat.connectors.splunk.client import SplunkClient
from gnat.connectors.stellarcyber.client import StellarCyberClient
from gnat.connectors.suricata.client import SuricataClient
from gnat.connectors.synapse.client import SynapseClient
from gnat.connectors.tenable_one.client import TenableOneClient
from gnat.connectors.thehive.client import TheHiveClient
from gnat.connectors.threatconnect.client import ThreatConnectClient
from gnat.connectors.threatq.client import ThreatQClient
from gnat.connectors.threatstream.client import ThreatStreamClient
from gnat.connectors.virustotal.client import VirusTotalClient
from gnat.connectors.wazuh.connector import WazuhConnector
from gnat.connectors.whistic.client import WhisticClient
from gnat.connectors.wiz.client import WizClient
from gnat.connectors.xsoar.client import XSOARClient
from gnat.connectors.yeti.client import YetiClient
from gnat.connectors.zeek.client import ZeekClient
from gnat.connectors.censys.client import CensysClient
from gnat.connectors.darktrace.client import DarktraceClient
from gnat.connectors.extrahop.client import ExtraHopClient
from gnat.connectors.lansweeper.client import LansweeperClient
from gnat.connectors.servicenow_secops.client import ServiceNowSecOpsClient
from gnat.connectors.sophos.client import SophosClient
from gnat.connectors.trellix.client import TrellixClient
from gnat.connectors.vectra.client import VectraClient
from gnat.connectors.zerofox.client import ZeroFoxClient
from gnat.connectors.bitsight.client import BitSightClient
from gnat.connectors.flashpoint.client import FlashpointClient
from gnat.connectors.hudsonrock.client import HudsonRockClient
from gnat.connectors.intel471.client import Intel471Client
from gnat.connectors.upguard.client import UpGuardClient
from gnat.connectors.trendmicro_visionone.client import TrendMicroVisionOneClient
from gnat.connectors.hibp.client import HIBPClient
from gnat.connectors.tanium.client import TaniumClient
from gnat.connectors.aws_security.client import AWSSecurityClient
from gnat.connectors.securityscorecard.client import SecurityScorecardClient
from gnat.connectors.dragos.client import DragosClient
from gnat.connectors.datadog.client import DatadogClient

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
    "cribl":          CriblClient,
    "alienvault":     AlienVaultClient,
    "alienvault_otx": AlienVaultClient,
    "graylog":        GraylogClient,
    "ossim":          OSSIMClient,
    "security_onion": SecurityOnionClient,
    "snort":          SnortClient,
    "suricata":       SuricataClient,
    "synapse":        SynapseClient,
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
    "chatgpt":        ChatGPTClient,
    "cyble_vision":   CybleVisionClient,
    "armis":          ArmisClient,
    "axonius":        AxoniusClient,
    "cortex_xpanse":  CortexXpanseClient,
    "cycognito":      CyCognitoClient,
    "defectdojo":     DefectDojoClient,
    "greenbone":      GreenboneClient,
    "group_ib":       GroupIBClient,
    "orca":           OrcaClient,
    "qualys":         QualysVMDRClient,
    "sentinelone":    SentinelOneClient,
    "tenable_one":    TenableOneClient,
    "wiz":            WizClient,
    "zerofox":        ZeroFoxClient,
    "trellix":        TrellixClient,
    "sophos":         SophosClient,
    "vectra":         VectraClient,
    "extrahop":       ExtraHopClient,
    "darktrace":      DarktraceClient,
    "lansweeper":     LansweeperClient,
    "censys":         CensysClient,
    "servicenow_secops": ServiceNowSecOpsClient,
    "bitsight":       BitSightClient,
    "flashpoint":     FlashpointClient,
    "hudsonrock":     HudsonRockClient,
    "intel471":       Intel471Client,
    "upguard":        UpGuardClient,
    "trendmicro_visionone": TrendMicroVisionOneClient,
    "hibp":           HIBPClient,
    "tanium":         TaniumClient,
    "aws_security":   AWSSecurityClient,
    "securityscorecard": SecurityScorecardClient,
    "dragos":         DragosClient,
    "datadog":        DatadogClient,
}

__all__ = [
    "BaseClient",
    "GNATClientError",
    "CLIENT_REGISTRY",
    "ArmisClient",
    "AxoniusClient",
    "CortexXpanseClient",
    "CyCognitoClient",
    "DefectDojoClient",
    "GreenboneClient",
    "GroupIBClient",
    "OrcaClient",
    "QualysVMDRClient",
    "SentinelOneClient",
    "TenableOneClient",
    "WizClient",
    "ZeroFoxClient",
    "CriblClient",
    "SynapseClient",
    "TrellixClient",
    "SophosClient",
    "VectraClient",
    "ExtraHopClient",
    "DarktraceClient",
    "LansweeperClient",
    "CensysClient",
    "ServiceNowSecOpsClient",
    "BitSightClient",
    "FlashpointClient",
    "HudsonRockClient",
    "Intel471Client",
    "UpGuardClient",
    "TrendMicroVisionOneClient",
    "HIBPClient",
    "TaniumClient",
    "AWSSecurityClient",
    "SecurityScorecardClient",
    "DragosClient",
    "DatadogClient",
]
