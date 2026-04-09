#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
ControlUp IP-to-Device Geolocation Investigation
=================================================

Given a set of incident IP addresses, this example:

1. Queries ControlUp DEX for all managed devices.
2. Correlates each device to incident IPs via its ``ipAddresses`` field.
3. Geolocates every matched IP using the ip-api.com batch endpoint
   (free, no API key, max 100 IPs per request via urllib3 — consistent
   with GNAT's no-requests policy).
4. Writes a structured text report to ``controlup_geo_report.txt``.

The entire flow is wrapped as a GNAT :class:`~gnat.agents.workflow.Workflow`
so it can be triggered on a schedule, via a webhook, or called programmatically.

Running modes
-------------
- **Simulation (default)** — No credentials needed.  Canned fixture data is
  used for ControlUp devices; ip-api.com geolocation still runs against the
  fixture IPs (real network call) *unless* ``GEO_SIMULATE=true`` is set, in
  which case canned geo data is substituted too.

- **Live** — Set credentials via environment variables or ``gnat.ini`` and
  call with ``simulate=False``.

Usage
-----
::

    # Simulated (no credentials needed):
    python examples/controlup_ip_geo_investigation.py

    # Live (requires ControlUp credentials):
    CONTROLUP_API_KEY=<key> CONTROLUP_ORG_ID=<orgId> \\
    python examples/controlup_ip_geo_investigation.py --live

    # Live, custom incident IPs:
    CONTROLUP_API_KEY=<key> CONTROLUP_ORG_ID=<orgId> \\
    python examples/controlup_ip_geo_investigation.py --live \\
        --ips 192.168.1.50 10.0.0.5 203.0.113.99

Environment variables
---------------------
``CONTROLUP_API_KEY``
    Bearer token from app.controlup.com.
``CONTROLUP_ORG_ID``
    ControlUp organisation UUID.
``CONTROLUP_HOST``
    API base URL (default: ``https://api.controlup.io``).
``GEO_SIMULATE``
    Set to ``true`` to skip ip-api.com calls and use canned geo data.

Dependencies
------------
- Core GNAT install (``pip install gnat``) — no extras required for this
  example beyond the base package.
- ``urllib3`` (bundled with GNAT's requirements).
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any

import urllib3

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default incident IPs for simulation / demo
# ---------------------------------------------------------------------------
_DEFAULT_INCIDENT_IPS: list[str] = [
    "203.0.113.10",   # RFC 5737 documentation range — safe for demo
    "198.51.100.42",
    "192.0.2.7",
    "10.0.0.50",      # RFC 1918 — ip-api returns a "reserved" result for these
]

# ---------------------------------------------------------------------------
# Simulation fixtures
# ---------------------------------------------------------------------------
_SIMULATED_DEVICES: list[dict[str, Any]] = [
    {
        "deviceId": "dev-001",
        "hostname": "WORKSTATION-ALICE",
        "osName": "Windows 11",
        "osFamily": "windows",
        "status": "active",
        "healthScore": 82,
        "lastSeen": "2026-04-09T08:14:00Z",
        "ipAddresses": ["203.0.113.10", "10.10.1.5"],
        "tags": ["finance", "critical"],
    },
    {
        "deviceId": "dev-002",
        "hostname": "WORKSTATION-BOB",
        "osName": "Windows 10",
        "osFamily": "windows",
        "status": "active",
        "healthScore": 91,
        "lastSeen": "2026-04-09T07:55:00Z",
        "ipAddresses": ["198.51.100.42"],
        "tags": ["engineering"],
    },
    {
        "deviceId": "dev-003",
        "hostname": "SERVER-PROD-01",
        "osName": "Ubuntu 22.04",
        "osFamily": "linux",
        "status": "active",
        "healthScore": 95,
        "lastSeen": "2026-04-09T08:20:00Z",
        "ipAddresses": ["10.0.0.50", "172.16.0.1"],
        "tags": ["server", "production"],
    },
    {
        "deviceId": "dev-004",
        "hostname": "LAPTOP-CAROL",
        "osName": "macOS 14",
        "osFamily": "macos",
        "status": "offline",
        "healthScore": 60,
        "lastSeen": "2026-04-08T23:10:00Z",
        "ipAddresses": ["172.16.50.22"],
        "tags": ["executive"],
    },
]

_SIMULATED_GEO: dict[str, dict[str, Any]] = {
    "203.0.113.10": {
        "status": "success",
        "country": "United States",
        "countryCode": "US",
        "regionName": "California",
        "city": "San Jose",
        "lat": 37.3382,
        "lon": -121.8863,
        "isp": "Simulated ISP",
        "org": "Documentation Network",
        "query": "203.0.113.10",
    },
    "198.51.100.42": {
        "status": "success",
        "country": "Germany",
        "countryCode": "DE",
        "regionName": "Bavaria",
        "city": "Munich",
        "lat": 48.1375,
        "lon": 11.5755,
        "isp": "Simulated ISP DE",
        "org": "Documentation Network",
        "query": "198.51.100.42",
    },
    "192.0.2.7": {
        "status": "fail",
        "message": "reserved range",
        "query": "192.0.2.7",
    },
    "10.0.0.50": {
        "status": "fail",
        "message": "reserved range",
        "query": "10.0.0.50",
    },
}

# ---------------------------------------------------------------------------
# ip-api.com geolocation
# ---------------------------------------------------------------------------
_GEO_BATCH_URL = "http://ip-api.com/batch"
_GEO_RATE_LIMIT = 15   # free tier: 15 requests/min
_GEO_BATCH_SIZE = 100  # max IPs per batch request


def geolocate_ips(
    ips: list[str],
    *,
    simulate: bool = False,
    http: urllib3.PoolManager | None = None,
) -> dict[str, dict[str, Any]]:
    """
    Geolocate a list of IP addresses using ip-api.com batch API.

    Parameters
    ----------
    ips:
        IP addresses to look up.
    simulate:
        If ``True``, return canned results without making HTTP calls.
    http:
        ``urllib3.PoolManager`` to use.  A new one is created if not provided.

    Returns
    -------
    dict
        Mapping ``ip → geo_result`` where each result contains keys:
        ``status``, ``country``, ``city``, ``lat``, ``lon``, etc.
        Failed lookups (private/reserved IPs) will have ``status="fail"``.
    """
    if not ips:
        return {}

    if simulate:
        log.info("GEO: simulation mode — using canned geo data for %d IPs", len(ips))
        return {ip: _SIMULATED_GEO.get(ip, {"status": "fail", "message": "not in simulation fixture", "query": ip}) for ip in ips}

    http = http or urllib3.PoolManager()
    results: dict[str, dict[str, Any]] = {}
    dedup = list(dict.fromkeys(ips))  # deduplicate while preserving order

    for batch_start in range(0, len(dedup), _GEO_BATCH_SIZE):
        batch = dedup[batch_start : batch_start + _GEO_BATCH_SIZE]
        payload = json.dumps([{"query": ip} for ip in batch]).encode()
        log.info("GEO: looking up %d IPs via ip-api.com (batch %d–%d)",
                 len(batch), batch_start + 1, batch_start + len(batch))
        try:
            resp = http.request(
                "POST",
                _GEO_BATCH_URL,
                body=payload,
                headers={"Content-Type": "application/json"},
                timeout=urllib3.Timeout(connect=5.0, read=15.0),
            )
            if resp.status == 200:
                geo_list: list[dict[str, Any]] = json.loads(resp.data.decode())
                for entry in geo_list:
                    results[entry.get("query", "")] = entry
            else:
                log.warning("GEO: ip-api.com returned HTTP %d", resp.status)
                for ip in batch:
                    results[ip] = {"status": "fail", "message": f"HTTP {resp.status}", "query": ip}
        except Exception as exc:
            log.error("GEO: request failed: %s", exc)
            for ip in batch:
                results[ip] = {"status": "fail", "message": str(exc), "query": ip}

        # Respect rate limit between batches
        if batch_start + _GEO_BATCH_SIZE < len(dedup):
            time.sleep(60 / _GEO_RATE_LIMIT)

    return results


# ---------------------------------------------------------------------------
# ControlUp device fetching
# ---------------------------------------------------------------------------

def fetch_all_devices(
    client: Any,
    *,
    simulate: bool = False,
    page_size: int = 500,
) -> list[dict[str, Any]]:
    """
    Fetch all devices from ControlUp, paginating automatically.

    Parameters
    ----------
    client:
        A ``ControlUpClient`` instance.
    simulate:
        If ``True``, return canned fixture devices instead of calling the API.
    page_size:
        Devices per API page (max 1000).

    Returns
    -------
    list[dict]
        All device records.
    """
    if simulate:
        log.info("CONTROLUP: simulation mode — returning %d canned devices", len(_SIMULATED_DEVICES))
        return list(_SIMULATED_DEVICES)

    all_devices: list[dict[str, Any]] = []
    page = 1
    while True:
        log.info("CONTROLUP: fetching devices page %d (page_size=%d)…", page, page_size)
        batch = client.list_devices(page=page, page_size=page_size)
        if not batch:
            break
        all_devices.extend(batch)
        log.info("CONTROLUP: got %d devices (total so far: %d)", len(batch), len(all_devices))
        if len(batch) < page_size:
            break
        page += 1

    return all_devices


# ---------------------------------------------------------------------------
# Correlation logic
# ---------------------------------------------------------------------------

def correlate_devices_to_ips(
    devices: list[dict[str, Any]],
    incident_ips: set[str],
) -> list[dict[str, Any]]:
    """
    Find devices whose ``ipAddresses`` list overlaps with *incident_ips*.

    Parameters
    ----------
    devices:
        Raw ControlUp device dicts (from ``list_devices()``).
    incident_ips:
        Set of IP addresses from the incident.

    Returns
    -------
    list[dict]
        Matched devices, each augmented with a ``matched_ips`` key containing
        the specific IPs that overlapped.
    """
    matched: list[dict[str, Any]] = []
    for dev in devices:
        device_ips = set(dev.get("ipAddresses", []))
        overlap = device_ips & incident_ips
        if overlap:
            augmented = dict(dev)
            augmented["matched_ips"] = sorted(overlap)
            matched.append(augmented)
            log.info(
                "MATCH: device %s (%s) matched IPs: %s",
                dev.get("hostname", "?"),
                dev.get("deviceId", "?"),
                ", ".join(sorted(overlap)),
            )

    log.info("CORRELATE: %d / %d devices matched incident IPs", len(matched), len(devices))
    return matched


# ---------------------------------------------------------------------------
# Report export
# ---------------------------------------------------------------------------

def write_report(
    matched_devices: list[dict[str, Any]],
    geo_data: dict[str, dict[str, Any]],
    incident_ips: list[str],
    output_path: str,
    *,
    simulate: bool = False,
) -> None:
    """
    Write a structured text report mapping devices → geo-located IPs.

    Parameters
    ----------
    matched_devices:
        Devices returned by :func:`correlate_devices_to_ips`.
    geo_data:
        Mapping of ``ip → geo result`` from :func:`geolocate_ips`.
    incident_ips:
        Original incident IP list (for the report header).
    output_path:
        File path for the text report.
    simulate:
        Flag recorded in the report header.
    """
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    lines: list[str] = [
        "=" * 72,
        "GNAT — ControlUp IP-to-Device Geolocation Investigation Report",
        f"Generated : {now}",
        f"Mode      : {'SIMULATION' if simulate else 'LIVE'}",
        f"Incident IPs ({len(incident_ips)}): {', '.join(incident_ips)}",
        "=" * 72,
        "",
        f"Matched devices: {len(matched_devices)}",
        "",
    ]

    if not matched_devices:
        lines.append("  No ControlUp devices matched the incident IP addresses.")
        lines.append("")
    else:
        for idx, dev in enumerate(matched_devices, 1):
            hostname = dev.get("hostname", "unknown")
            device_id = dev.get("deviceId", "unknown")
            os_name = dev.get("osName", "unknown")
            status = dev.get("status", "unknown")
            health = dev.get("healthScore", "N/A")
            tags = ", ".join(dev.get("tags", [])) or "—"
            last_seen = dev.get("lastSeen", "unknown")
            matched = dev.get("matched_ips", [])

            lines += [
                f"[{idx}] {hostname}  ({device_id})",
                f"    OS         : {os_name}",
                f"    Status     : {status}",
                f"    Health     : {health}",
                f"    Last seen  : {last_seen}",
                f"    Tags       : {tags}",
                f"    Matched IPs: {', '.join(matched)}",
                "",
            ]

            for ip in matched:
                geo = geo_data.get(ip, {})
                if geo.get("status") == "success":
                    lines += [
                        f"    Geolocation for {ip}:",
                        f"      Country  : {geo.get('country', '?')} ({geo.get('countryCode', '?')})",
                        f"      Region   : {geo.get('regionName', '?')}",
                        f"      City     : {geo.get('city', '?')}",
                        f"      Lat/Lon  : {geo.get('lat', '?')}, {geo.get('lon', '?')}",
                        f"      ISP      : {geo.get('isp', '?')}",
                        f"      Org      : {geo.get('org', '?')}",
                        "",
                    ]
                else:
                    reason = geo.get("message", "lookup failed or reserved range")
                    lines += [
                        f"    Geolocation for {ip}: N/A ({reason})",
                        "",
                    ]

            lines.append("-" * 72)
            lines.append("")

    # Summary of unmatched incident IPs
    all_device_ips: set[str] = set()
    for dev in matched_devices:
        all_device_ips.update(dev.get("matched_ips", []))
    unmatched = [ip for ip in incident_ips if ip not in all_device_ips]
    if unmatched:
        lines += [
            "Incident IPs with NO matching ControlUp device:",
            *[f"  - {ip}" for ip in unmatched],
            "",
        ]

    lines += [
        "=" * 72,
        "END OF REPORT",
        "=" * 72,
    ]

    report_text = "\n".join(lines)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write(report_text)

    log.info("REPORT: written to %s (%d lines)", output_path, len(lines))
    print(report_text)


# ---------------------------------------------------------------------------
# GNAT Workflow wrapper
# ---------------------------------------------------------------------------

def build_controlup_geo_workflow(
    incident_ips: list[str],
    output_path: str = "controlup_geo_report.txt",
    *,
    simulate: bool = True,
    controlup_host: str = "https://api.controlup.io",
    controlup_api_key: str = "",
    controlup_org_id: str = "",
    geo_simulate: bool = False,
) -> "Workflow":  # type: ignore[name-defined]
    """
    Build a GNAT :class:`~gnat.agents.workflow.Workflow` that encapsulates
    the full IP → device correlation → geolocation → report pipeline.

    The workflow runs five steps:

    1. ``fetch_devices``    — pull all ControlUp endpoints
    2. ``correlate_ips``   — match devices to incident IPs
    3. ``geolocate``       — look up geo data for matched IPs
    4. ``write_report``    — export the structured text report
    5. ``summarise``       — log final statistics to the workflow result

    Parameters
    ----------
    incident_ips:
        IP addresses from the incident alert.
    output_path:
        Destination file path for the text report.
    simulate:
        Use canned ControlUp fixture data (no credentials required).
    controlup_host, controlup_api_key, controlup_org_id:
        ControlUp credentials — ignored when ``simulate=True``.
    geo_simulate:
        Use canned geo data (skips ip-api.com calls entirely).

    Returns
    -------
    Workflow
        Ready-to-run workflow; call ``.run(ctx)`` to execute.
    """
    from gnat.agents.workflow import Workflow, WorkflowContext, WorkflowStep

    incident_ip_set = set(incident_ips)
    http_pool = urllib3.PoolManager()

    # Lazy client construction so imports don't fail when running simulated
    def _make_client() -> Any:
        if simulate:
            return None
        from gnat.connectors.controlup.client import ControlUpClient
        client = ControlUpClient(
            host=controlup_host,
            api_key=controlup_api_key,
            org_id=controlup_org_id,
        )
        client.authenticate()
        return client

    # ── Step 1: fetch devices ──────────────────────────────────────────────
    def _fetch(ctx: WorkflowContext) -> list[dict[str, Any]]:
        client = ctx.shared.get("_cu_client") or _make_client()
        ctx.shared["_cu_client"] = client
        devices = fetch_all_devices(client, simulate=simulate)
        ctx.shared["devices"] = devices
        return devices

    # ── Step 2: correlate ─────────────────────────────────────────────────
    def _correlate(ctx: WorkflowContext) -> list[dict[str, Any]]:
        devices = ctx.shared.get("devices", [])
        matched = correlate_devices_to_ips(devices, incident_ip_set)
        ctx.shared["matched_devices"] = matched
        return matched

    # ── Step 3: geolocate ─────────────────────────────────────────────────
    def _geolocate(ctx: WorkflowContext) -> dict[str, Any]:
        matched = ctx.shared.get("matched_devices", [])
        all_matched_ips: list[str] = []
        for dev in matched:
            all_matched_ips.extend(dev.get("matched_ips", []))
        geo = geolocate_ips(
            list(dict.fromkeys(all_matched_ips)),
            simulate=geo_simulate,
            http=http_pool,
        )
        ctx.shared["geo_data"] = geo
        return geo

    # ── Step 4: write report ──────────────────────────────────────────────
    def _report(ctx: WorkflowContext) -> str:
        matched = ctx.shared.get("matched_devices", [])
        geo = ctx.shared.get("geo_data", {})
        write_report(matched, geo, incident_ips, output_path, simulate=(simulate or geo_simulate))
        return output_path

    # ── Step 5: summarise ─────────────────────────────────────────────────
    def _summarise(ctx: WorkflowContext) -> dict[str, Any]:
        matched = ctx.shared.get("matched_devices", [])
        geo = ctx.shared.get("geo_data", {})
        success_count = sum(1 for g in geo.values() if g.get("status") == "success")
        summary = {
            "incident_ips": len(incident_ips),
            "devices_scanned": len(ctx.shared.get("devices", [])),
            "devices_matched": len(matched),
            "ips_geolocated": success_count,
            "report_path": output_path,
        }
        log.info("SUMMARY: %s", summary)
        ctx.shared["summary"] = summary
        return summary

    wf = (
        Workflow("controlup_ip_geo_investigation")
        .add_step(WorkflowStep(name="fetch_devices",  action=_fetch))
        .add_step(WorkflowStep(name="correlate_ips",  action=_correlate))
        .add_step(WorkflowStep(name="geolocate",      action=_geolocate))
        .add_step(WorkflowStep(name="write_report",   action=_report))
        .add_step(WorkflowStep(name="summarise",      action=_summarise))
    )
    return wf


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Correlate incident IPs to ControlUp devices and export geolocation."
    )
    parser.add_argument(
        "--ips",
        nargs="+",
        default=_DEFAULT_INCIDENT_IPS,
        metavar="IP",
        help="Incident IP addresses to investigate (default: demo IPs).",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Use live ControlUp API instead of simulation fixture data.",
    )
    parser.add_argument(
        "--geo-live",
        action="store_true",
        help="Use live ip-api.com geolocation instead of simulation data.",
    )
    parser.add_argument(
        "--output",
        default="controlup_geo_report.txt",
        metavar="PATH",
        help="Output file path (default: controlup_geo_report.txt).",
    )
    args = parser.parse_args(argv)

    simulate_cu = not args.live
    simulate_geo = not args.geo_live

    if not simulate_cu:
        api_key = os.environ.get("CONTROLUP_API_KEY", "")
        org_id = os.environ.get("CONTROLUP_ORG_ID", "")
        host = os.environ.get("CONTROLUP_HOST", "https://api.controlup.io")
        if not api_key or not org_id:
            log.error(
                "Live mode requires CONTROLUP_API_KEY and CONTROLUP_ORG_ID "
                "environment variables."
            )
            return 1
    else:
        api_key = org_id = ""
        host = "https://api.controlup.io"

    incident_ips: list[str] = args.ips
    log.info("Starting investigation for %d incident IPs: %s", len(incident_ips), incident_ips)
    log.info("ControlUp source: %s", "LIVE" if not simulate_cu else "SIMULATION")
    log.info("Geolocation source: %s", "LIVE (ip-api.com)" if not simulate_geo else "SIMULATION")

    from gnat.agents.workflow import WorkflowContext

    wf = build_controlup_geo_workflow(
        incident_ips=incident_ips,
        output_path=args.output,
        simulate=simulate_cu,
        controlup_host=host,
        controlup_api_key=api_key,
        controlup_org_id=org_id,
        geo_simulate=simulate_geo,
    )

    ctx = WorkflowContext(investigation_id="controlup-geo-demo")
    result = wf.run(ctx)

    if result.success:
        summary = ctx.shared.get("summary", {})
        log.info(
            "Investigation complete — %d device(s) matched, "
            "%d IP(s) geolocated. Report: %s",
            summary.get("devices_matched", 0),
            summary.get("ips_geolocated", 0),
            args.output,
        )
        return 0
    else:
        log.error("Workflow failed at step '%s': %s", result.failed_step, result.error)
        return 2


if __name__ == "__main__":
    sys.exit(main())
