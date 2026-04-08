# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Generate GNAT connector architecture diagram.

Run from the repo root:
    python docs/_diagrams/generate_connector_arch.py

Output: docs/explanation/architecture/img/connector_architecture.png
"""

import os

from diagrams import Cluster, Diagram, Edge
from diagrams.generic.compute import Rack
from diagrams.generic.network import Router, Switch
from diagrams.onprem.client import User
from diagrams.onprem.compute import Server
from diagrams.onprem.network import Nginx
from diagrams.onprem.security import Vault

OUTPUT = os.path.join(
    os.path.dirname(__file__),
    "..",
    "explanation",
    "architecture",
    "img",
    "connector_architecture",
)

graph_attr = {
    "fontsize": "13",
    "bgcolor": "white",
    "pad": "0.5",
    "splines": "ortho",
    "rankdir": "LR",
}

with Diagram(
    "GNAT Connector Architecture",
    filename=OUTPUT,
    show=False,
    direction="LR",
    graph_attr=graph_attr,
    outformat="png",
):
    client = Rack("GNATClient\ngnat/client.py")

    with Cluster("CLIENT_REGISTRY\ngnat/clients/__init__.py"):
        registry = Switch("Registry")

    with Cluster("Base Classes"):
        base_client = Server("BaseClient\ngnat/clients/base.py")
        connector_mixin = Server("ConnectorMixin\ngnat/connectors/base_connector.py")

    with Cluster("HTTP Transport"):
        urllib3 = Nginx("urllib3\n(sync)")
        httpx = Nginx("httpx\n(async)")

    with Cluster("STIX ORM"):
        orm = Vault("STIXBase\ngnat/orm/")

    with Cluster("Example Connectors"):
        threatq = User("ThreatQ")
        crowdstrike = User("CrowdStrike")
        splunk = User("Splunk")
        sentinel = User("Sentinel")
        more = User("…96 more")

    with Cluster("External Platforms"):
        platform_a = Router("ThreatQ API")
        platform_b = Router("CrowdStrike API")
        platform_c = Router("Splunk API")
        platform_d = Router("Sentinel API")

    # Flow
    client >> registry
    registry >> connector_mixin
    connector_mixin >> base_client
    base_client >> urllib3
    base_client >> httpx

    # Connectors implement ConnectorMixin
    connector_mixin - Edge(style="dashed", label="implements") - threatq
    connector_mixin - Edge(style="dashed", label="implements") - crowdstrike
    connector_mixin - Edge(style="dashed", label="implements") - splunk
    connector_mixin - Edge(style="dashed", label="implements") - sentinel
    connector_mixin - Edge(style="dashed", label="implements") - more

    # Connectors ↔ STIX ORM
    threatq >> orm
    crowdstrike >> orm

    # HTTP ↔ external
    urllib3 >> platform_a
    urllib3 >> platform_b
    urllib3 >> platform_c
    urllib3 >> platform_d

print(f"Written → {OUTPUT}.png")
