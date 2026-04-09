#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
ControlUp IP-to-Device Geolocation Investigation
=================================================

Given a set of incident IP addresses, this example:

1. Queries ControlUp DEX for all managed devices via the REST API.
2. Correlates each device to incident IPs via its ``ipAddresses`` field.
3. Fetches **native geolocation** for matched devices from the ControlUp
   Data Access Layer (DAL) — ``location.city``, ``location.country``,
   ``location.latitude``, ``location.longitude``.
4. For IPs not covered by native ControlUp geo (e.g. dynamic addresses not
   tracked by the DEX agent), falls back to the ip-api.com batch endpoint
   (free, no API key, urllib3).
5. Writes a structured text report to ``controlup_geo_report.txt``.

The entire flow is wrapped as a GNAT :class:`~gnat.agents.workflow.Workflow`
so it can be triggered on a schedule, via a webhook, or called programmatically.

Native geo vs. external fallback
---------------------------------
ControlUp's DEX agent records device location at enrolment time and updates it
as the device roams.  The DAL ``"devices"`` index exposes::

    location.city, location.country, location.latitude, location.longitude

This is richer and more accurate than IP geolocation because it reflects the
*physical* location of the device, not just its current egress IP.  The
ip-api.com fallback is used for incident IPs that are *not* matched to a
ControlUp-managed device (e.g. external attacker IPs).

Running modes
-------------
- **Simulation (default)** — No credentials needed.  Canned fixture data is
  used for both ControlUp REST devices and DAL geo results.

- **Live** — Set credentials via environment variables and call with ``--live``.

Usage
-----
::

    # Simulation (no credentials needed):
    python examples/controlup_ip_geo_investigation.py

    # Live (requires ControlUp credentials):
    CONTROLUP_API_KEY=<key> CONTROLUP_ORG_ID=<orgId> \\
    CONTROLUP_DAL_HOST=https://your-tenant.controlup.com \\
    python examples/controlup_ip_geo_investigation.py --live

    # Live, custom incident IPs:
    CONTROLUP_API_KEY=<key> CONTROLUP_ORG_ID=<orgId> \\
    CONTROLUP_DAL_HOST=https://your-tenant.controlup.com \\
    python examples/controlup_ip_geo_investigation.py --live \\
        --ips 192.168.1.50 10.0.0.5 203.0.113.99

Environment variables
---------------------
``CONTROLUP_API_KEY``
    Bearer token from app.controlup.com.
``CONTROLUP_ORG_ID``
    ControlUp organisation UUID.
``CONTROLUP_HOST``
    REST API base URL (default: ``https://api.controlup.io``).
``CONTROLUP_DAL_HOST``
    Tenant-specific DAL base URL, e.g. ``https://your-tenant.controlup.com``.
    Defaults to ``CONTROLUP_HOST`` when not set.
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
    "203.0.113.10",   # RFC 5737 documentation range — matched to WORKSTATION-ALICE
    "198.51.100.42",  # RFC 5737 — matched to WORKSTATION-BOB
    "192.0.2.7",      # RFC 5737 — not matched (external attacker IP, geo via ip-api)
    "10.0.0.50",      # RFC 1918 — matched to SERVER-PROD-01 (private, no ip-api geo)
]

# ---------------------------------------------------------------------------
# Simulation fixtures — REST devices
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

# ---------------------------------------------------------------------------
# Simulation fixtures — DAL native geolocation
# Keyed by hostname (deviceName in DAL), matching _SIMULATED_DEVICES above.
# ---------------------------------------------------------------------------
_SIMULATED_DAL_GEO: dict[str, dict[str, Any]] = {
    "WORKSTATION-ALICE": {
        "city":    "San Jose",
        "country": "United States",
        "lat":     37.3382,
        "lon":     -121.8863,
    },
    "WORKSTATION-BOB": {
        "city":    "Munich",
        "country": "Germany",
        "lat":     48.1375,
        "lon":     11.5755,
    },
    "SERVER-PROD-01": {
        "city":    "Frankfurt",
        "country": "Germany",
        "lat":     50.1109,
        "lon":     8.6821,
    },
    # LAPTOP-CAROL: no location data (simulates a device the DEX agent lost track of)
}

# ---------------------------------------------------------------------------
# ip-api.com geolocation (external fallback for unmatched IPs)
# ---------------------------------------------------------------------------
_GEO_BATCH_URL = "http://ip-api.com/batch"
_GEO_RATE_LIMIT = 15   # free tier: 15 requests/min
_GEO_BATCH_SIZE = 100  # max IPs per batch request

# Canned fallback results for the simulation demo IPs
_SIMULATED_IPAPI: dict[str, dict[str, Any]] = {
    "192.0.2.7": {
        "status": "success",
        "country": "Netherlands",
        "countryCode": "NL",
        "regionName": "North Holland",
        "city": "Amsterdam",
        "lat": 52.3740,
        "lon": 4.8897,
        "isp": "Simulated ISP NL",
        "org": "Documentation Network",
        "query": "192.0.2.7",
    },
}


def geolocate_ips_external(
    ips: list[str],
    *,
    simulate: bool = False,
    http: urllib3.PoolManager | None = None,
) -> dict[str, dict[str, Any]]:
    """
    Geolocate IP addresses using the ip-api.com batch API.

    Used only as a fallback for IPs that could *not* be matched to a
    ControlUp-managed device (e.g. external attacker IPs).  RFC 1918 /
    documentation-range IPs will return ``status="fail"``.

    Parameters
    ----------
    ips:
        IP addresses to look up.
    simulate:
        Return canned results without making HTTP calls.
    http:
        urllib3 PoolManager to use.

    Returns
    -------
    dict
        ``{ip: geo_result}`` with keys ``status``, ``country``, ``city``,
        ``lat``, ``lon``.
    """
    if not ips:
        return {}

    if simulate:
        log.info("GEO (external, sim): returning canned data for %d IPs", len(ips))
        return {ip: _SIMULATED_IPAPI.get(ip, {"status": "fail", "message": "not in simulation fixture", "query": ip}) for ip in ips}

    http = http or urllib3.PoolManager()
    results: dict[str, dict[str, Any]] = {}
    dedup = list(dict.fromkeys(ips))

    for batch_start in range(0, len(dedup), _GEO_BATCH_SIZE):
        batch = dedup[batch_start : batch_start + _GEO_BATCH_SIZE]
        payload = json.dumps([{"query": ip} for ip in batch]).encode()
        log.info("GEO (external): looking up %d IPs via ip-api.com", len(batch))
        try:
            resp = http.request(
                "POST",
                _GEO_BATCH_URL,
                body=payload,
                headers={"Content-Type": "application/json"},
                timeout=urllib3.Timeout(connect=5.0, read=15.0),
            )
            if resp.status == 200:
                for entry in json.loads(resp.data.decode()):
                    results[entry.get("query", "")] = entry
            else:
                for ip in batch:
                    results[ip] = {"status": "fail", "message": f"HTTP {resp.status}", "query": ip}
        except Exception as exc:
            log.error("GEO (external): request failed: %s", exc)
            for ip in batch:
                results[ip] = {"status": "fail", "message": str(exc), "query": ip}

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
    """Fetch all ControlUp devices, paginating automatically."""
    if simulate:
        log.info("CONTROLUP REST: simulation — %d canned devices", len(_SIMULATED_DEVICES))
        return list(_SIMULATED_DEVICES)

    all_devices: list[dict[str, Any]] = []
    page = 1
    while True:
        log.info("CONTROLUP REST: page %d (size=%d)…", page, page_size)
        batch = client.list_devices(page=page, page_size=page_size)
        if not batch:
            break
        all_devices.extend(batch)
        if len(batch) < page_size:
            break
        page += 1

    log.info("CONTROLUP REST: %d devices total", len(all_devices))
    return all_devices


def fetch_native_locations(
    client: Any,
    hostnames: list[str],
    *,
    simulate: bool = False,
) -> dict[str, dict[str, Any]]:
    """
    Fetch native device geolocation from the ControlUp DAL.

    Parameters
    ----------
    client:
        A ``ControlUpClient`` instance.
    hostnames:
        Hostnames of the matched devices (used only for logging in live mode).
    simulate:
        Return canned DAL fixture data without making API calls.

    Returns
    -------
    dict
        ``{hostname: {"city": ..., "country": ..., "lat": ..., "lon": ...}}``
    """
    if simulate:
        log.info("CONTROLUP DAL: simulation — returning canned native geo for %d hostnames", len(hostnames))
        return {h: _SIMULATED_DAL_GEO[h] for h in hostnames if h in _SIMULATED_DAL_GEO}

    log.info("CONTROLUP DAL: fetching native geolocation for %d devices…", len(hostnames))
    try:
        return client.get_device_locations(limit=1000)
    except Exception as exc:
        log.warning("CONTROLUP DAL: geo fetch failed (%s) — will fall back to ip-api.com", exc)
        return {}


# ---------------------------------------------------------------------------
# Correlation logic
# ---------------------------------------------------------------------------

def correlate_devices_to_ips(
    devices: list[dict[str, Any]],
    incident_ips: set[str],
) -> list[dict[str, Any]]:
    """Match devices by ipAddresses overlap with incident_ips."""
    matched: list[dict[str, Any]] = []
    for dev in devices:
        overlap = set(dev.get("ipAddresses", [])) & incident_ips
        if overlap:
            augmented = dict(dev)
            augmented["matched_ips"] = sorted(overlap)
            matched.append(augmented)
            log.info(
                "MATCH: %s (%s) ← %s",
                dev.get("hostname", "?"),
                dev.get("deviceId", "?"),
                ", ".join(sorted(overlap)),
            )

    log.info("CORRELATE: %d / %d devices matched", len(matched), len(devices))
    return matched


# ---------------------------------------------------------------------------
# Report export
# ---------------------------------------------------------------------------

def write_report(
    matched_devices: list[dict[str, Any]],
    native_geo: dict[str, dict[str, Any]],
    external_geo: dict[str, dict[str, Any]],
    incident_ips: list[str],
    output_path: str,
    *,
    simulate: bool = False,
) -> None:
    """
    Write a structured text report.

    For each matched device, the report shows:
    - Device metadata (hostname, OS, status, health, tags)
    - Matched IP(s)
    - Native ControlUp geolocation (from DAL) when available
    - External ip-api.com geolocation for unmatched/external IPs
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
        f"Matched ControlUp devices: {len(matched_devices)}",
        "",
    ]

    matched_ip_set: set[str] = set()

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
            matched_ip_set.update(matched)

            lines += [
                f"[{idx}] {hostname}  ({device_id})",
                f"    OS        : {os_name}",
                f"    Status    : {status}",
                f"    Health    : {health}",
                f"    Last seen : {last_seen}",
                f"    Tags      : {tags}",
                f"    Matched   : {', '.join(matched)}",
                "",
            ]

            # Native ControlUp geolocation (DEX agent — physical location)
            native = native_geo.get(hostname)
            if native and (native.get("lat") is not None or native.get("city")):
                lines += [
                    f"    Native ControlUp location (DEX agent):",
                    f"      City    : {native.get('city', '?')}",
                    f"      Country : {native.get('country', '?')}",
                    f"      Lat/Lon : {native.get('lat', '?')}, {native.get('lon', '?')}",
                    f"      Source  : ControlUp DAL  [authoritative — physical device location]",
                    "",
                ]
            else:
                lines += [
                    f"    Native ControlUp location: not available for this device",
                    "",
                ]

            lines.append("-" * 72)
            lines.append("")

    # External IP geolocation for unmatched / external IPs
    unmatched = [ip for ip in incident_ips if ip not in matched_ip_set]
    if unmatched:
        lines += [
            "Incident IPs with NO matching ControlUp device (external geo lookup):",
            "",
        ]
        for ip in unmatched:
            geo = external_geo.get(ip, {})
            if geo.get("status") == "success":
                lines += [
                    f"  {ip}:",
                    f"    Country : {geo.get('country', '?')} ({geo.get('countryCode', '?')})",
                    f"    Region  : {geo.get('regionName', '?')}",
                    f"    City    : {geo.get('city', '?')}",
                    f"    Lat/Lon : {geo.get('lat', '?')}, {geo.get('lon', '?')}",
                    f"    ISP     : {geo.get('isp', '?')}",
                    f"    Source  : ip-api.com  [IP geolocation — egress location only]",
                    "",
                ]
            else:
                reason = geo.get("message", "reserved range / lookup failed")
                lines += [f"  {ip}: N/A ({reason})", ""]

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
    controlup_dal_host: str | None = None,
    controlup_api_key: str = "",
    controlup_org_id: str = "",
) -> "Workflow":  # type: ignore[name-defined]
    """
    Build a GNAT Workflow for the ControlUp IP → device → geo investigation.

    Steps
    -----
    1. ``fetch_devices``    — REST API: list all managed endpoints
    2. ``correlate_ips``   — match devices to incident IPs via ipAddresses
    3. ``native_geo``      — DAL: fetch ControlUp-native device locations
    4. ``external_geo``    — ip-api.com: geolocate unmatched/external IPs
    5. ``write_report``    — export structured text report
    6. ``summarise``       — log final statistics

    Parameters
    ----------
    simulate:
        Use canned fixture data (no credentials required).
    controlup_dal_host:
        Tenant-specific DAL base URL (e.g. ``https://your-tenant.controlup.com``).
        Defaults to ``controlup_host`` when ``None``.
    """
    from gnat.agents.workflow import Workflow, WorkflowContext, WorkflowStep

    incident_ip_set = set(incident_ips)
    http_pool = urllib3.PoolManager()

    def _make_client() -> Any:
        if simulate:
            return None
        from gnat.connectors.controlup.client import ControlUpClient
        client = ControlUpClient(
            host=controlup_host,
            api_key=controlup_api_key,
            org_id=controlup_org_id,
            dal_host=controlup_dal_host,
        )
        client.authenticate()
        return client

    # Step 1 ─ fetch devices
    def _fetch(ctx: WorkflowContext) -> list[dict[str, Any]]:
        client = ctx.shared.get("_cu_client") or _make_client()
        ctx.shared["_cu_client"] = client
        devices = fetch_all_devices(client, simulate=simulate)
        ctx.shared["devices"] = devices
        return devices

    # Step 2 ─ correlate
    def _correlate(ctx: WorkflowContext) -> list[dict[str, Any]]:
        devices = ctx.shared.get("devices", [])
        matched = correlate_devices_to_ips(devices, incident_ip_set)
        ctx.shared["matched_devices"] = matched
        return matched

    # Step 3 ─ native ControlUp geolocation (DAL)
    def _native_geo(ctx: WorkflowContext) -> dict[str, Any]:
        matched = ctx.shared.get("matched_devices", [])
        hostnames = [d.get("hostname", "") for d in matched if d.get("hostname")]
        client = ctx.shared.get("_cu_client")
        geo = fetch_native_locations(client, hostnames, simulate=simulate)
        ctx.shared["native_geo"] = geo
        log.info(
            "DAL geo: %d / %d devices have native location data",
            sum(1 for h in hostnames if h in geo),
            len(hostnames),
        )
        return geo

    # Step 4 ─ external ip-api.com fallback for unmatched IPs
    def _external_geo(ctx: WorkflowContext) -> dict[str, Any]:
        matched = ctx.shared.get("matched_devices", [])
        matched_ips: set[str] = set()
        for dev in matched:
            matched_ips.update(dev.get("matched_ips", []))
        unmatched_ips = [ip for ip in incident_ips if ip not in matched_ips]
        geo = geolocate_ips_external(unmatched_ips, simulate=simulate, http=http_pool)
        ctx.shared["external_geo"] = geo
        return geo

    # Step 5 ─ write report
    def _report(ctx: WorkflowContext) -> str:
        write_report(
            matched_devices=ctx.shared.get("matched_devices", []),
            native_geo=ctx.shared.get("native_geo", {}),
            external_geo=ctx.shared.get("external_geo", {}),
            incident_ips=incident_ips,
            output_path=output_path,
            simulate=simulate,
        )
        return output_path

    # Step 6 ─ summarise
    def _summarise(ctx: WorkflowContext) -> dict[str, Any]:
        matched = ctx.shared.get("matched_devices", [])
        native = ctx.shared.get("native_geo", {})
        ext = ctx.shared.get("external_geo", {})
        summary = {
            "incident_ips":          len(incident_ips),
            "devices_scanned":       len(ctx.shared.get("devices", [])),
            "devices_matched":       len(matched),
            "native_geo_hits":       len(native),
            "external_geo_hits":     sum(1 for g in ext.values() if g.get("status") == "success"),
            "report_path":           output_path,
        }
        log.info("SUMMARY: %s", summary)
        ctx.shared["summary"] = summary
        return summary

    return (
        Workflow("controlup_ip_geo_investigation")
        .add_step(WorkflowStep(name="fetch_devices", action=_fetch))
        .add_step(WorkflowStep(name="correlate_ips", action=_correlate))
        .add_step(WorkflowStep(name="native_geo",    action=_native_geo))
        .add_step(WorkflowStep(name="external_geo",  action=_external_geo))
        .add_step(WorkflowStep(name="write_report",  action=_report))
        .add_step(WorkflowStep(name="summarise",     action=_summarise))
    )


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Correlate incident IPs to ControlUp devices and export geolocation."
    )
    parser.add_argument(
        "--ips", nargs="+", default=_DEFAULT_INCIDENT_IPS, metavar="IP",
        help="Incident IP addresses (default: demo IPs).",
    )
    parser.add_argument(
        "--live", action="store_true",
        help="Use live ControlUp API instead of simulation fixture data.",
    )
    parser.add_argument(
        "--output", default="controlup_geo_report.txt", metavar="PATH",
        help="Output file path (default: controlup_geo_report.txt).",
    )
    args = parser.parse_args(argv)

    simulate = not args.live

    if not simulate:
        api_key = os.environ.get("CONTROLUP_API_KEY", "")
        org_id = os.environ.get("CONTROLUP_ORG_ID", "")
        host = os.environ.get("CONTROLUP_HOST", "https://api.controlup.io")
        dal_host = os.environ.get("CONTROLUP_DAL_HOST") or host
        if not api_key or not org_id:
            log.error(
                "Live mode requires CONTROLUP_API_KEY and CONTROLUP_ORG_ID. "
                "Set CONTROLUP_DAL_HOST for the tenant-specific DAL endpoint."
            )
            return 1
    else:
        api_key = org_id = ""
        host = "https://api.controlup.io"
        dal_host = host

    incident_ips: list[str] = args.ips
    log.info("Starting investigation  IPs=%s  mode=%s", incident_ips, "LIVE" if not simulate else "SIMULATION")

    from gnat.agents.workflow import WorkflowContext

    wf = build_controlup_geo_workflow(
        incident_ips=incident_ips,
        output_path=args.output,
        simulate=simulate,
        controlup_host=host,
        controlup_dal_host=dal_host,
        controlup_api_key=api_key,
        controlup_org_id=org_id,
    )

    ctx = WorkflowContext(investigation_id="controlup-geo-demo")
    result = wf.run(ctx)

    if result.success:
        s = ctx.shared.get("summary", {})
        log.info(
            "Done — %d device(s) matched · %d native geo · %d external geo · report: %s",
            s.get("devices_matched", 0),
            s.get("native_geo_hits", 0),
            s.get("external_geo_hits", 0),
            args.output,
        )
        return 0

    log.error("Workflow failed at '%s': %s", result.failed_step, result.error)
    return 2


if __name__ == "__main__":
    sys.exit(main())
