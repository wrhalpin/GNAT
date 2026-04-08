# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Generate GNAT ingest pipeline diagram.

Run from the repo root:
    python docs/_diagrams/generate_ingest_pipeline.py

Output: docs/explanation/architecture/img/ingest_pipeline.png
"""

import os

from diagrams import Cluster, Diagram, Edge
from diagrams.generic.storage import Storage
from diagrams.onprem.analytics import Spark
from diagrams.onprem.compute import Server
from diagrams.onprem.database import PostgreSQL
from diagrams.onprem.network import Nginx
from diagrams.onprem.security import Vault

OUTPUT = os.path.join(
    os.path.dirname(__file__),
    "..",
    "explanation",
    "architecture",
    "img",
    "ingest_pipeline",
)

graph_attr = {
    "fontsize": "13",
    "bgcolor": "white",
    "pad": "0.5",
    "splines": "ortho",
    "rankdir": "LR",
}

with Diagram(
    "GNAT Ingestion Pipeline",
    filename=OUTPUT,
    show=False,
    direction="LR",
    graph_attr=graph_attr,
    outformat="png",
):
    with Cluster("Source Data"):
        csv = Storage("CSV / JSONL\nPlainText / OpenIOC")
        taxii = Nginx("TAXII 2.1\nCollection")
        stix_bundle = Storage("STIX Bundle")
        rss = Nginx("RSS / Email")
        misp = Server("MISP / SQL\nSplunk / Elastic")

    with Cluster("Source Readers  (14)\ngnat/ingest/sources/"):
        readers = Spark("SourceReader\nsubclasses")

    with Cluster("Record Mappers  (12)\ngnat/ingest/mappers/"):
        mappers = Spark("RecordMapper\nsubclasses")

    with Cluster("IOC Classifier\ngnat/ingest/_ioc_classifier.py"):
        classifier = Server("IOC Classifier\n(Python / Rust)")

    with Cluster("Normalisation"):
        normaliser = Server("Record\nNormaliser")

    with Cluster("STIX ORM\ngnat/orm/"):
        stix_obj = PostgreSQL("STIXBase\nObjects")

    with Cluster("Platform Connectors"):
        connectors = Vault("Connector\nUpsert")

    with Cluster("Search Sidecar"):
        solr = Server("Solr Index\ngnat/search/")

    # Sources → readers
    csv >> readers
    taxii >> readers
    stix_bundle >> readers
    rss >> readers
    misp >> readers

    # Readers → mappers
    readers >> mappers

    # Mappers → classifier → normaliser
    mappers >> classifier >> normaliser

    # Normaliser → ORM
    normaliser >> stix_obj

    # ORM → connectors & search
    stix_obj >> connectors
    stix_obj >> solr

print(f"Written → {OUTPUT}.png")
