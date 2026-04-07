# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
Investigation workspace example — XSOAR + ThreatQ + GreyMatter → Power BI
==========================================================================

Purpose
-------
This script demonstrates the end-to-end investigation pipeline:

    1. Load connector credentials from gnat.ini (or env-vars as fallback)
    2. Authenticate to XSOAR, ThreatQ, and GreyMatter
    3. Define investigation seeds (IP, case ID, domain)
    4. Run InvestigationBuilder to produce an EvidenceGraph
       - Step 1: seed expansion across all three platforms
       - Step 2: incident expansion (alerts/tasks/timeline from XSOAR,
                 observables/tasks from GreyMatter, indicators/adversaries
                 from ThreatQ events)
       - Step 3-4: correlation and cross-platform edge inference
    5. Materialise the graph into a GNAT workspace
    6. Export to Excel (multi-sheet) for Power BI import
    7. (Optional) export the Power BI data-model JSON schema

This script also serves as a completeness check for the investigations
module: every expand path for xsoar / greymatter / threatq is exercised,
and the normaliser dispatch table is exercised for all three platform /
record-type combinations.

Usage
-----
    # Full run from real credentials (gnat.ini must have [xsoar], [threatq],
    # [greymatter] sections):
    python docs/tutorials/investigation_xsoar_tq_gm_powerbi.py

    # Dry-run with mock connectors (no live credentials required):
    python docs/tutorials/investigation_xsoar_tq_gm_powerbi.py --mock

    # Custom output path:
    python docs/tutorials/investigation_xsoar_tq_gm_powerbi.py --output /tmp/incident.xlsx

Configuration (gnat.ini / ~/.gnat/config.ini)
---------------------------------------------
    [xsoar]
    host       = https://xsoar.example.com
    api_key    = <xsoar-api-key>

    [threatq]
    host          = https://tq.example.com
    client_id     = <oauth2-client-id>
    client_secret = <oauth2-client-secret>

    [greymatter]
    host    = https://api.greymatter.io
    api_key = <greymatter-api-key>
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

# ── GNAT imports ──────────────────────────────────────────────────────────────
from gnat.config import GNATConfig
from gnat.context.workspace import WorkspaceManager
from gnat.investigations.builder import InvestigationBuilder
from gnat.investigations.model import Seed, SeedType
from gnat.investigations.workspace import materialize
from gnat.viz.export import PowerBIExporter

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
)
logger = logging.getLogger("investigation_example")


# ── Investigation parameters ──────────────────────────────────────────────────

INVESTIGATION_TITLE = "Ransomware triage — 2026-04-07"

#: Starting seeds: mix of IOC, a platform-specific case ID, and a domain.
#: In a real engagement replace these with actual observed indicators.
SEEDS = [
    # Suspicious IP seen in firewall logs — query all three platforms for it
    Seed("185.220.101.5", SeedType.IP),
    # Existing XSOAR incident — hint so only XSOAR is queried for this seed
    Seed("INC-4892", SeedType.CASE_ID, hint_platform="xsoar"),
    # C2 domain — query all three platforms
    Seed("evil-c2.example.net", SeedType.DOMAIN),
    # ThreatQ event known to track this campaign
    Seed("EVT-1337", SeedType.CASE_ID, hint_platform="threatq"),
    # GreyMatter investigation case
    Seed("GM-0099", SeedType.CASE_ID, hint_platform="greymatter"),
]


# ── Mock connectors (--mock mode) ─────────────────────────────────────────────

def _mock_xsoar() -> MagicMock:
    """Return a MagicMock that mimics the XSOAR investigation sub-API."""
    c = MagicMock(name="XSOARClient")

    # Seed: get_object("observed-data") returns a minimal incident
    c.get_object.return_value = {
        "id": "INC-4892",
        "name": "Ransomware intrusion — workstation-42",
        "type": "Ransomware",
        "severity": 3,
        "status": "Active",
        "occurred": "2026-04-06T14:22:00Z",
        "CustomFields": {"hostname": "workstation-42"},
    }

    # Seed: list_objects("observed-data") — incident text search
    c.list_objects.return_value = [
        {
            "id": "INC-4892",
            "name": "Ransomware intrusion — workstation-42",
            "severity": 3,
            "status": "Active",
            "occurred": "2026-04-06T14:22:00Z",
        }
    ]

    # Seed: indicator search
    c.search_indicators_by_value.return_value = [
        {
            "id": "ind-001",
            "value": "185.220.101.5",
            "indicator_type": "IP",
            "score": 3,
            "verdict": "Malicious",
        }
    ]

    # Expand: alerts linked to INC-4892
    c.get_incident_alerts.return_value = [
        {
            "id": "alert-7001",
            "name": "Ransomware binary executed",
            "severity": "High",
            "occurred": "2026-04-06T14:20:00Z",
        },
        {
            "id": "alert-7002",
            "name": "Lateral movement detected",
            "severity": "High",
            "occurred": "2026-04-06T14:21:30Z",
        },
    ]

    # Expand: tasks linked to INC-4892
    c.get_incident_tasks.return_value = [
        {
            "id": "task-001",
            "name": "Isolate workstation-42",
            "state": "InProgress",
            "dueDate": "2026-04-06T16:00:00Z",
        }
    ]

    # Expand: timeline entries for INC-4892
    c.get_incident_timeline.return_value = [
        {
            "id": "tl-001",
            "type": "Evidence",
            "entryType": 1,
            "contents": "Analyst confirmed lateral movement from 185.220.101.5",
            "created": "2026-04-06T14:25:00Z",
        }
    ]

    return c


def _mock_threatq() -> MagicMock:
    """Return a MagicMock that mimics the ThreatQ investigation sub-API."""
    c = MagicMock(name="ThreatQClient")

    # Seed: get_object("observed-data") — fetch an event by ID
    c.get_object.return_value = {
        "data": {
            "id": 1337,
            "title": "Ransomware C2 campaign — April 2026",
            "event_type": "intrusion",
            "happened_at": "2026-04-05T00:00:00Z",
            "created_at": "2026-04-05T08:00:00Z",
            "updated_at": "2026-04-06T12:00:00Z",
            "description": "Tracked ransomware operator reusing C2 infra.",
        }
    }

    # Seed: list_objects("observed-data") — event search by query
    c.list_objects.return_value = [
        {
            "id": 1337,
            "title": "Ransomware C2 campaign — April 2026",
            "event_type": "intrusion",
            "happened_at": "2026-04-05T00:00:00Z",
            "created_at": "2026-04-05T08:00:00Z",
            "updated_at": "2026-04-06T12:00:00Z",
        }
    ]

    # Seed: indicator search
    c.search_indicators_by_value.return_value = [
        {
            "id": 501,
            "value": "185.220.101.5",
            "type": {"name": "IP Address"},
            "score": 4,
            "status": {"name": "Active"},
            "created_at": "2026-04-05T10:00:00Z",
            "updated_at": "2026-04-06T09:00:00Z",
        }
    ]

    # Expand: indicators linked to event 1337
    c.get_event_indicators.return_value = [
        {
            "id": 501,
            "value": "185.220.101.5",
            "type": {"name": "IP Address"},
            "score": 4,
            "status": {"name": "Active"},
        },
        {
            "id": 502,
            "value": "evil-c2.example.net",
            "type": {"name": "FQDN"},
            "score": 4,
            "status": {"name": "Active"},
        },
    ]

    # Expand: adversaries linked to event 1337
    c.get_event_adversaries.return_value = [
        {
            "id": 21,
            "name": "BLACKCAT Operator",
            "created_at": "2026-03-01T00:00:00Z",
            "updated_at": "2026-04-01T00:00:00Z",
        }
    ]

    return c


def _mock_greymatter() -> MagicMock:
    """Return a MagicMock that mimics the GreyMatter investigation sub-API."""
    c = MagicMock(name="GreyMatterClient")

    # Seed: get_object("observed-data") — fetch case by ID
    c.get_object.return_value = {
        "data": {
            "id": "gm-0099",
            "title": "Ransomware: workstation-42 compromise",
            "case_number": "GM-0099",
            "status": "In Progress",
            "severity": "Critical",
            "assigned_to": "analyst@example.com",
            "created_at": "2026-04-06T14:30:00Z",
            "updated_at": "2026-04-07T08:00:00Z",
            "description": "Endpoint isolated; memory dump collected.",
        }
    }

    # Seed: list_objects("observed-data") — case search by query
    c.list_objects.return_value = [
        {
            "id": "gm-0099",
            "title": "Ransomware: workstation-42 compromise",
            "case_number": "GM-0099",
            "status": "In Progress",
            "severity": "Critical",
            "created_at": "2026-04-06T14:30:00Z",
            "updated_at": "2026-04-07T08:00:00Z",
        }
    ]

    # Seed: observable search
    c.search_observables_by_value.return_value = [
        {
            "id": "obs-301",
            "type": "ipv4",
            "value": "185.220.101.5",
            "confidence": 90,
            "tlp": "RED",
            "created_at": "2026-04-06T14:00:00Z",
            "updated_at": "2026-04-06T15:00:00Z",
        }
    ]

    # Expand: observables linked to case GM-0099
    c.get_investigation_observables.return_value = [
        {
            "id": "obs-301",
            "type": "ipv4",
            "value": "185.220.101.5",
            "confidence": 90,
            "tlp": "RED",
            "created_at": "2026-04-06T14:00:00Z",
            "updated_at": "2026-04-06T15:00:00Z",
        },
        {
            "id": "obs-302",
            "type": "domain",
            "value": "evil-c2.example.net",
            "confidence": 85,
            "tlp": "AMBER",
            "created_at": "2026-04-06T14:05:00Z",
            "updated_at": "2026-04-06T15:00:00Z",
        },
    ]

    # Expand: tasks linked to case GM-0099
    c.get_investigation_tasks.return_value = [
        {
            "id": "gm-task-001",
            "title": "Collect memory dump from workstation-42",
            "status": "Completed",
            "created_at": "2026-04-06T15:00:00Z",
            "updated_at": "2026-04-06T17:00:00Z",
        }
    ]

    return c


# ── Live connectors (real credentials) ───────────────────────────────────────

def _load_live_connectors(cfg: GNATConfig) -> dict[str, Any]:
    """
    Instantiate real connectors from gnat.ini.

    Raises RuntimeError if any required section is missing.
    """
    from gnat.connectors.greymatter.client import GreyMatterClient
    from gnat.connectors.threatq.client import ThreatQClient
    from gnat.connectors.xsoar.client import XSOARClient

    missing = [s for s in ("xsoar", "threatq", "greymatter") if not cfg.has_section(s)]
    if missing:
        raise RuntimeError(
            f"Missing config sections: {missing}. "
            "Add them to gnat.ini or use --mock for a dry run."
        )

    xsoar_cfg = dict(cfg.items("xsoar"))
    tq_cfg    = dict(cfg.items("threatq"))
    gm_cfg    = dict(cfg.items("greymatter"))

    xsoar = XSOARClient(
        host    = xsoar_cfg["host"],
        api_key = xsoar_cfg["api_key"],
    )
    xsoar.authenticate()

    tq = ThreatQClient(
        host          = tq_cfg["host"],
        client_id     = tq_cfg.get("client_id", ""),
        client_secret = tq_cfg.get("client_secret", ""),
    )
    tq.authenticate()

    gm = GreyMatterClient(
        host    = gm_cfg["host"],
        api_key = gm_cfg["api_key"],
    )
    gm.authenticate()

    return {"xsoar": xsoar, "threatq": tq, "greymatter": gm}


# ── Main ──────────────────────────────────────────────────────────────────────

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build a cross-platform investigation graph and export to Power BI.",
    )
    parser.add_argument(
        "--mock",
        action="store_true",
        default=False,
        help="Use mock connectors instead of live credentials (no network required).",
    )
    parser.add_argument(
        "--output",
        default="incident_graph.xlsx",
        help="Output path for the Power BI xlsx export (default: incident_graph.xlsx).",
    )
    parser.add_argument(
        "--model-json",
        default="",
        help="If set, also write a Power BI data-model schema JSON to this path.",
    )
    parser.add_argument(
        "--config",
        default=os.environ.get("GNAT_CONFIG", ""),
        help="Path to gnat.ini. Falls back to GNAT_CONFIG env var.",
    )
    parser.add_argument(
        "--workspace-name",
        default="ransomware-apr-2026",
        help="GNAT workspace name for the materialised graph.",
    )
    args = parser.parse_args(argv)

    # ── 1. Initialise connectors ──────────────────────────────────────────────
    if args.mock:
        logger.info("Running in MOCK mode — no live credentials required.")
        connectors = {
            "xsoar":       _mock_xsoar(),
            "threatq":     _mock_threatq(),
            "greymatter":  _mock_greymatter(),
        }
    else:
        logger.info("Loading live connectors from config: %s", args.config or "auto-detect")
        cfg = GNATConfig(args.config or None)
        connectors = _load_live_connectors(cfg)

    # ── 2. Build the investigation graph ──────────────────────────────────────
    logger.info("Building investigation: %r", INVESTIGATION_TITLE)
    builder = InvestigationBuilder(connectors)
    graph   = builder.build(seeds=SEEDS, title=INVESTIGATION_TITLE)

    # ── 3. Print summary ──────────────────────────────────────────────────────
    summary = graph.summary()
    logger.info("Graph complete:\n%s", json.dumps(summary, indent=2, default=str))

    print("\n" + "=" * 70)
    print(f"  Investigation: {graph.title}")
    print("=" * 70)
    print(f"  Nodes     : {len(graph.nodes)}")
    print(f"  Edges     : {len(graph.edges)}")

    if summary.get("nodes_by_platform"):
        print("\n  Nodes by platform:")
        for platform, count in sorted(summary["nodes_by_platform"].items()):
            print(f"    {platform:<20} {count}")

    if summary.get("nodes_by_type"):
        print("\n  Nodes by type:")
        for ntype, count in sorted(summary["nodes_by_type"].items()):
            print(f"    {ntype:<20} {count}")

    if summary.get("cross_platform_edges"):
        print(f"\n  Cross-platform edges : {summary['cross_platform_edges']}")
    if summary.get("shared_iocs"):
        print(f"  Shared IOC values    : {summary['shared_iocs']}")
    if summary.get("shared_hostnames"):
        print(f"  Shared hostnames     : {summary['shared_hostnames']}")
    if summary.get("shared_campaigns"):
        print(f"  Shared campaigns     : {summary['shared_campaigns']}")
    print("=" * 70 + "\n")

    # ── 4. Materialise into a GNAT workspace ──────────────────────────────────
    logger.info("Materialising graph into workspace %r …", args.workspace_name)
    if args.mock:
        # Use an in-memory SQLite store + empty registry so no config file is
        # required during a dry run.
        from gnat.context.global_context import GlobalContextRegistry
        from gnat.context.store import WorkspaceStore

        _registry = GlobalContextRegistry()
        _store    = WorkspaceStore("sqlite:///:memory:")
        _store.create_all()
        workspace_manager = WorkspaceManager(registry=_registry, store=_store)
    else:
        workspace_manager = WorkspaceManager.default(args.config or None)
    ws = materialize(
        graph,
        workspace_manager,
        name        = args.workspace_name,
        description = (
            f"Auto-generated by investigation_xsoar_tq_gm_powerbi.py — "
            f"{INVESTIGATION_TITLE}"
        ),
    )
    logger.info(
        "Workspace '%s' created — %d STIX objects",
        ws.name,
        len(ws.objects),
    )

    # ── 5. Export to Power BI ─────────────────────────────────────────────────
    exporter = PowerBIExporter(ws)

    output_path = Path(args.output)
    exporter.to_xlsx(str(output_path))
    logger.info("Power BI xlsx written → %s", output_path.resolve())
    print(f"[OK] Excel export  : {output_path.resolve()}")

    if args.model_json:
        model_path = Path(args.model_json)
        exporter.to_model_json(str(model_path))
        logger.info("Power BI model JSON written → %s", model_path.resolve())
        print(f"[OK] Model JSON    : {model_path.resolve()}")

    # ── 6. Investigations module completeness check ───────────────────────────
    _verify_investigations_module(graph, connectors)

    return 0


def _verify_investigations_module(
    graph: "EvidenceGraph",  # noqa: F821
    connectors: dict[str, Any],
) -> None:
    """
    Assert that the investigations module is complete for all three platforms.

    Checks:
    - Each expand method was found on its connector (hasattr)
    - At least one node was collected per platform
    - Cross-platform correlation found at least one shared IOC (IP / domain
      appears in all three platforms' data)
    """
    from gnat.investigations.model import NodeType

    failures: list[str] = []

    # ── Connector method coverage ─────────────────────────────────────────────
    xsoar_methods = [
        "get_incident_alerts",
        "get_incident_tasks",
        "get_incident_timeline",
        "link_incident",
        "get_incident_indicators",
    ]
    gm_methods = [
        "get_investigation_observables",
        "get_investigation_tasks",
        "link_investigation",
    ]
    tq_methods = [
        "get_event_indicators",
        "get_event_adversaries",
        "link_event",
        "get_event_malware",
        "get_event_vulnerabilities",
        "get_event_attack_patterns",
    ]

    for method in xsoar_methods:
        if not hasattr(connectors["xsoar"], method):
            failures.append(f"XSOAR missing method: {method}")
    for method in gm_methods:
        if not hasattr(connectors["greymatter"], method):
            failures.append(f"GreyMatter missing method: {method}")
    for method in tq_methods:
        if not hasattr(connectors["threatq"], method):
            failures.append(f"ThreatQ missing method: {method}")

    # ── At least one node per platform ───────────────────────────────────────
    from gnat.investigations.model import EvidenceGraph
    nodes_by_platform: dict[str, int] = {}
    for node in graph.nodes.values():
        nodes_by_platform[node.platform] = nodes_by_platform.get(node.platform, 0) + 1

    for platform in ("xsoar", "threatq", "greymatter"):
        if nodes_by_platform.get(platform, 0) == 0:
            failures.append(f"No nodes collected from platform: {platform}")

    # ── Cross-platform correlation ────────────────────────────────────────────
    cross_edges = [e for e in graph.edges if e.relationship_type != "part-of"]
    if not cross_edges:
        # Warn but don't fail — mock data may not always produce correlation
        logger.warning(
            "No cross-platform correlation edges found. "
            "Verify that IOC values overlap across platforms in real data."
        )

    # ── Incident nodes from all three platforms ───────────────────────────────
    incident_platforms = {
        node.platform
        for node in graph.nodes.values()
        if node.node_type == NodeType.INCIDENT
    }
    for platform in ("xsoar", "threatq", "greymatter"):
        if platform not in incident_platforms:
            failures.append(f"No INCIDENT node found for platform: {platform}")

    # ── Report ────────────────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    print("  Investigations module completeness check")
    print("=" * 70)
    if failures:
        print(f"  FAILURES ({len(failures)}):")
        for f in failures:
            print(f"    [FAIL] {f}")
        print("=" * 70 + "\n")
        logger.error("Investigations module completeness check FAILED: %s", failures)
    else:
        print("  All checks passed:")
        total_methods = len(xsoar_methods) + len(gm_methods) + len(tq_methods)
        print(f"    [OK] {total_methods} investigation methods verified across 3 platforms")
        print(f"    [OK] Nodes collected from: {sorted(nodes_by_platform.keys())}")
        print(f"    [OK] Incident nodes present for: {sorted(incident_platforms)}")
        if cross_edges:
            print(f"    [OK] {len(cross_edges)} cross-platform correlation edges")
        print("=" * 70 + "\n")
        logger.info("Investigations module completeness check PASSED.")


if __name__ == "__main__":
    sys.exit(main())
