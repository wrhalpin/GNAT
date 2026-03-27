# “””
ctm_sak.connectors.wazuh.stix_mapper

STIX 2.1 mapping layer for the Wazuh connector.

Wazuh has no native STIX support. This module converts Wazuh-specific
data structures to and from STIX 2.1 objects.

## Supported mappings

Wazuh → STIX (for export / downstream processing):

Alert record         → observed-data SDO wrapping:
• ipv4-addr SCO  (srcip, dstip)
• user-account SCO (srcuser, dstuser)
• process SCO    (process.name)
• domain-name SCO (hostname fields)
• network-traffic SCO (when ports present)
+ x-wazuh-alert extension on observed-data

FIM / syscheck event → observed-data SDO wrapping file SCO
• file SCO with hashes, permissions, owner
+ x-wazuh-fim extension on observed-data

Vulnerability record → vulnerability SDO
• CVE ID, CVSS scores, description

Agent record         → identity SDO
• x-wazuh-agent extension

STIX → Wazuh (for importing IOCs as custom rules or AR triggers):
indicator SDO        → Wazuh custom rule XML snippet (text only)
ipv4-addr SCO        → IP to block via Active Response firewall-drop

Extension naming follows STIX 2.1 custom extension conventions:
x-wazuh-alert   — alert metadata (rule.id, rule.level, agent.id, etc.)
x-wazuh-fim     — FIM event metadata (event_type, permissions, owner)
x-wazuh-agent   — agent identity metadata

## References

- https://stix2.readthedocs.io/en/latest/
- https://documentation.wazuh.com/current/user-manual/capabilities/
  “””

from **future** import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from .exceptions import WazuhSTIXError

# ── STIX namespace for deterministic UUIDs ────────────────────────────────────

_STIX_NAMESPACE = uuid.UUID(“00abedb4-aa42-466c-9c01-fed23315a9b7”)

# ── Wazuh MITRE tactic → STIX kill-chain phase name ──────────────────────────

_MITRE_TACTIC_MAP = {
“initial-access”: “initial-access”,
“execution”: “execution”,
“persistence”: “persistence”,
“privilege-escalation”: “privilege-escalation”,
“defense-evasion”: “defense-evasion”,
“credential-access”: “credential-access”,
“discovery”: “discovery”,
“lateral-movement”: “lateral-movement”,
“collection”: “collection”,
“command-and-control”: “command-and-control”,
“exfiltration”: “exfiltration”,
“impact”: “impact”,
“reconnaissance”: “reconnaissance”,
“resource-development”: “resource-development”,
}

class WazuhSTIXMapper:
“””
Bidirectional mapper between Wazuh data structures and STIX 2.1 objects.

```
Operates on plain Python dicts (from WazuhClient responses or CTM-SAK
ORM .to_dict() output). Does not depend on external STIX libraries.

Usage
-----
mapper = WazuhSTIXMapper()

# Alert → STIX bundle
bundle = mapper.alert_to_stix_bundle(normalised_alert)

# FIM event → STIX bundle
bundle = mapper.fim_event_to_stix_bundle(normalised_fim)

# Vulnerability → STIX vulnerability SDO
vuln_sdo = mapper.vulnerability_to_stix(normalised_vuln)

# Agent → STIX identity SDO
identity = mapper.agent_to_stix_identity(normalised_agent)

# STIX indicator → Wazuh rule snippet
rule_xml = mapper.stix_indicator_to_wazuh_rule(indicator_obj)
"""

# ── Alert → STIX ──────────────────────────────────────────────────────

def alert_to_stix_bundle(self, alert: dict) -> dict:
    """
    Convert a normalised Wazuh alert to a STIX 2.1 bundle.

    Produces:
      - SCOs for all observable entities in the alert
      - One observed-data SDO referencing all SCOs
      - Kill-chain-phase objects from MITRE ATT&CK mapping (if present)

    Parameters
    ----------
    alert : dict
        Normalised alert from WazuhAlertCommands.normalise_alert().

    Returns
    -------
    dict
        STIX 2.1 bundle.
    """
    now = _now_ts()
    ts = alert.get("timestamp") or now
    objects: list[dict] = []
    refs: list[str] = []
    seen: set[str] = set()

    # ── Source IP ──────────────────────────────────────────────────
    if src_ip := alert.get("src_ip"):
        obj = _make_ipv4(src_ip)
        if obj["id"] not in seen:
            seen.add(obj["id"])
            objects.append(obj)
        refs.append(obj["id"])

    # ── Dest IP ────────────────────────────────────────────────────
    if dst_ip := alert.get("dst_ip"):
        obj = _make_ipv4(dst_ip)
        if obj["id"] not in seen:
            seen.add(obj["id"])
            objects.append(obj)
        refs.append(obj["id"])

    # ── Network traffic (if both src and dst IP + ports present) ──
    raw = alert.get("_raw", {})
    src_port = raw.get("data", {}).get("srcport")
    dst_port = raw.get("data", {}).get("dstport")
    if alert.get("src_ip") and alert.get("dst_ip") and (src_port or dst_port):
        net_obj = self._make_network_traffic(
            alert["src_ip"], alert["dst_ip"],
            src_port, dst_port,
            raw.get("data", {}).get("protocol"),
        )
        if net_obj:
            objects.append(net_obj)
            refs.append(net_obj["id"])

    # ── Source user ────────────────────────────────────────────────
    if src_user := alert.get("src_user"):
        obj = _make_user_account(src_user)
        if obj["id"] not in seen:
            seen.add(obj["id"])
            objects.append(obj)
        refs.append(obj["id"])

    # ── Destination user ───────────────────────────────────────────
    if dst_user := alert.get("dst_user"):
        if dst_user != alert.get("src_user"):
            obj = _make_user_account(dst_user)
            if obj["id"] not in seen:
                seen.add(obj["id"])
                objects.append(obj)
            refs.append(obj["id"])

    # ── Process ────────────────────────────────────────────────────
    proc_data = raw.get("data", {})
    if proc_name := proc_data.get("process") or proc_data.get("processname"):
        obj = _make_process(proc_name)
        if obj["id"] not in seen:
            seen.add(obj["id"])
            objects.append(obj)
        refs.append(obj["id"])

    # ── Hostname / domain ──────────────────────────────────────────
    if hostname := raw.get("data", {}).get("hostname") or raw.get("hostname"):
        if "." in hostname and not hostname.replace(".", "").isdigit():
            obj = _make_domain(hostname)
            if obj["id"] not in seen:
                seen.add(obj["id"])
                objects.append(obj)
            refs.append(obj["id"])

    # ── Kill chain phases from MITRE ───────────────────────────────
    kill_chain_phases = self._build_kill_chain_phases(alert.get("rule_mitre", {}))

    # ── Observed-data SDO ──────────────────────────────────────────
    obs_id = f"observed-data--{uuid.uuid4()}"
    observed: dict = {
        "type": "observed-data",
        "id": obs_id,
        "spec_version": "2.1",
        "created": now,
        "modified": now,
        "first_observed": ts,
        "last_observed": ts,
        "number_observed": 1,
        "object_refs": refs,
        # Wazuh alert extension
        "x_wazuh_alert": {
            "rule_id": alert.get("rule_id"),
            "rule_description": alert.get("rule_description"),
            "rule_level": alert.get("rule_level"),
            "rule_groups": alert.get("rule_groups", []),
            "severity": alert.get("severity"),
            "severity_label": alert.get("severity_label"),
            "agent_id": alert.get("agent_id"),
            "agent_name": alert.get("agent_name"),
            "agent_ip": alert.get("agent_ip"),
            "decoder": alert.get("decoder"),
            "location": alert.get("location"),
            "full_log": alert.get("full_log"),
        },
    }
    if kill_chain_phases:
        observed["x_wazuh_mitre"] = kill_chain_phases
    objects.append(observed)

    return _make_bundle(objects)

def alerts_to_stix_bundle(self, alerts: list[dict]) -> dict:
    """
    Convert a list of normalised alerts to a single STIX 2.1 bundle.

    Deduplicates shared SCOs (same IP/user appearing in multiple alerts)
    across the bundle.

    Parameters
    ----------
    alerts : list[dict]
        Normalised alert records.

    Returns
    -------
    dict
        Merged STIX 2.1 bundle.
    """
    all_objects: list[dict] = []
    seen_ids: set[str] = set()

    for alert in alerts:
        sub_bundle = self.alert_to_stix_bundle(alert)
        for obj in sub_bundle.get("objects", []):
            if obj["id"] not in seen_ids:
                seen_ids.add(obj["id"])
                all_objects.append(obj)

    return _make_bundle(all_objects)

# ── FIM event → STIX ──────────────────────────────────────────────────

def fim_event_to_stix_bundle(
    self,
    fim: dict,
    agent_id: str | None = None,
) -> dict:
    """
    Convert a normalised FIM event to a STIX 2.1 bundle.

    Produces a file SCO wrapped in an observed-data SDO with
    x_wazuh_fim extension metadata.

    Parameters
    ----------
    fim : dict
        Normalised FIM event from WazuhSyscheckCommands.normalise_fim_event().
    agent_id : str | None
        Agent ID for attribution.

    Returns
    -------
    dict
        STIX 2.1 bundle.
    """
    now = _now_ts()
    ts = fim.get("date") or now
    objects: list[dict] = []

    # ── File SCO ───────────────────────────────────────────────────
    file_obj = self._make_file_sco(fim)
    objects.append(file_obj)

    # ── Observed-data SDO ──────────────────────────────────────────
    obs_id = f"observed-data--{uuid.uuid4()}"
    observed: dict = {
        "type": "observed-data",
        "id": obs_id,
        "spec_version": "2.1",
        "created": now,
        "modified": now,
        "first_observed": ts,
        "last_observed": ts,
        "number_observed": 1,
        "object_refs": [file_obj["id"]],
        "x_wazuh_fim": {
            "event_type": fim.get("event_type"),
            "permissions": fim.get("permissions"),
            "owner": fim.get("owner"),
            "group_owner": fim.get("group_owner"),
            "uid": fim.get("uid"),
            "gid": fim.get("gid"),
            "inode": fim.get("inode"),
            "agent_id": agent_id,
        },
    }
    objects.append(observed)
    return _make_bundle(objects)

# ── Vulnerability → STIX ──────────────────────────────────────────────

def vulnerability_to_stix(self, vuln: dict) -> dict:
    """
    Convert a normalised vulnerability record to a STIX 2.1
    vulnerability SDO.

    Parameters
    ----------
    vuln : dict
        Normalised vulnerability from WazuhVulnerabilityCommands.normalise_vulnerability().

    Returns
    -------
    dict
        STIX 2.1 vulnerability SDO.
    """
    cve = vuln.get("cve") or ""
    if not cve:
        raise WazuhSTIXError(
            "Cannot create STIX vulnerability SDO: 'cve' field is missing."
        )
    now = _now_ts()
    det_id = f"vulnerability--{_det_uuid('vulnerability', cve)}"
    return {
        "type": "vulnerability",
        "id": det_id,
        "spec_version": "2.1",
        "created": now,
        "modified": now,
        "name": cve,
        "description": vuln.get("title", ""),
        "external_references": [
            {
                "source_name": "cve",
                "external_id": cve,
                "url": f"https://nvd.nist.gov/vuln/detail/{cve}",
            }
        ] + [
            {"source_name": "reference", "url": ref}
            for ref in vuln.get("references", [])
            if isinstance(ref, str)
        ],
        "x_wazuh_vulnerability": {
            "package_name": vuln.get("package_name"),
            "package_version": vuln.get("package_version"),
            "architecture": vuln.get("architecture"),
            "severity_label": vuln.get("severity_label"),
            "cvss2_score": vuln.get("cvss2_score"),
            "cvss3_score": vuln.get("cvss3_score"),
            "detection_time": vuln.get("detection_time"),
            "condition": vuln.get("condition"),
        },
    }

def vulnerabilities_to_stix_bundle(self, vulns: list[dict]) -> dict:
    """
    Convert a list of normalised vulnerability records to a bundle.

    Parameters
    ----------
    vulns : list[dict]
        Normalised vulnerability records.

    Returns
    -------
    dict
        STIX 2.1 bundle of vulnerability SDOs.
    """
    objects = []
    seen: set[str] = set()
    for v in vulns:
        try:
            sdo = self.vulnerability_to_stix(v)
            if sdo["id"] not in seen:
                seen.add(sdo["id"])
                objects.append(sdo)
        except WazuhSTIXError:
            pass  # Skip vulns with missing CVE
    return _make_bundle(objects)

# ── Agent → STIX identity ──────────────────────────────────────────────

def agent_to_stix_identity(self, agent: dict) -> dict:
    """
    Convert a normalised Wazuh agent record to a STIX 2.1 identity SDO.

    Parameters
    ----------
    agent : dict
        Normalised agent from WazuhAgentCommands.normalise_agent().

    Returns
    -------
    dict
        STIX 2.1 identity SDO with x_wazuh_agent extension.
    """
    now = _now_ts()
    agent_id = agent.get("id") or "unknown"
    agent_name = agent.get("name") or f"agent-{agent_id}"
    identity_id = f"identity--{_det_uuid('identity', f'wazuh-agent-{agent_id}')}"
    return {
        "type": "identity",
        "id": identity_id,
        "spec_version": "2.1",
        "created": now,
        "modified": now,
        "name": agent_name,
        "identity_class": "system",
        "x_wazuh_agent": {
            "agent_id": agent_id,
            "ip": agent.get("ip"),
            "status": agent.get("status"),
            "os_platform": agent.get("os_platform"),
            "os_name": agent.get("os_name"),
            "os_version": agent.get("os_version"),
            "agent_version": agent.get("agent_version"),
            "last_keep_alive": agent.get("last_keep_alive"),
            "groups": agent.get("groups", []),
            "manager": agent.get("manager"),
        },
    }

# ── STIX indicator → Wazuh rule ────────────────────────────────────────

def stix_indicator_to_wazuh_rule(
    self,
    indicator: dict,
    rule_id: int = 200000,
    rule_level: int = 10,
    group: str = "ctm_sak_ioc",
) -> str:
    """
    Convert a STIX 2.1 indicator to a Wazuh custom rule XML snippet.

    This is a best-effort text conversion. The output is a Wazuh
    rule XML string that can be placed in a custom rules file.
    Only simple IP and domain patterns are supported.

    Parameters
    ----------
    indicator : dict
        STIX 2.1 indicator dict.
    rule_id : int
        Rule ID to assign (should be in 100000-199999 range for custom rules).
    rule_level : int
        Wazuh rule level (0-15).
    group : str
        Rule group name for tagging.

    Returns
    -------
    str
        Wazuh rule XML string.
    """
    name = indicator.get("name", "CTM-SAK IOC")
    description = indicator.get("description", name)
    pattern = indicator.get("pattern", "")
    indicator_types = indicator.get("indicator_types", [])

    # Extract observable value from simple patterns
    import re
    match = re.search(r"=\s*'([^']+)'", pattern)
    value = match.group(1) if match else ""

    # Determine match field from pattern type
    if "ipv4-addr:value" in pattern or "ipv6-addr:value" in pattern:
        match_field = "srcip"
        rule_comment = f"IOC: Malicious IP {value}"
    elif "domain-name:value" in pattern:
        match_field = "data.hostname"
        rule_comment = f"IOC: Malicious domain {value}"
    elif "url:value" in pattern:
        match_field = "data.url"
        rule_comment = f"IOC: Malicious URL {value}"
    else:
        match_field = "full_log"
        rule_comment = f"IOC: {description}"

    if not value:
        return (
            f"<!-- CTM-SAK: Could not extract observable value from pattern: {pattern} -->"
        )

    return f"""<group name="{group}">
```

  <!-- {rule_comment} -->

  <!-- STIX ID: {indicator.get("id", "unknown")} -->

  <!-- Indicator types: {", ".join(indicator_types)} -->

  <rule id="{rule_id}" level="{rule_level}">
    <field name="{match_field}">{value}</field>
    <description>CTM-SAK IOC Match: {description}</description>
    <group>{group},{",".join(indicator_types)}</group>
    <options>no_full_log</options>
  </rule>
</group>"""

```
# ── Internal helpers ───────────────────────────────────────────────────

@staticmethod
def _make_file_sco(fim: dict) -> dict:
    """Build a STIX 2.1 file SCO from a normalised FIM event."""
    file_path = fim.get("file", "")
    # Use SHA-256 for deterministic ID when available, else path
    key = fim.get("sha256") or file_path
    file_id = f"file--{_det_uuid('file', key)}"
    obj: dict = {
        "type": "file",
        "id": file_id,
        "spec_version": "2.1",
    }
    if file_path:
        import posixpath
        obj["name"] = posixpath.basename(file_path)
        obj["parent_directory_ref"] = None  # Would need dir SCO
    if fim.get("size") is not None:
        try:
            obj["size"] = int(fim["size"])
        except (ValueError, TypeError):
            pass
    hashes: dict = {}
    for h, k in (("md5", "MD5"), ("sha1", "SHA-1"), ("sha256", "SHA-256")):
        if v := fim.get(h):
            hashes[k] = v
    if hashes:
        obj["hashes"] = hashes
    if mtime := fim.get("mtime"):
        obj["modified"] = mtime
    return obj

@staticmethod
def _make_network_traffic(
    src_ip: str,
    dst_ip: str,
    src_port: Any,
    dst_port: Any,
    protocol: str | None,
) -> dict | None:
    """Build a STIX 2.1 network-traffic SCO."""
    try:
        src_ref = f"ipv4-addr--{_det_uuid('ipv4-addr', src_ip)}"
        dst_ref = f"ipv4-addr--{_det_uuid('ipv4-addr', dst_ip)}"
        net_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        net_id = f"network-traffic--{_det_uuid('network-traffic', net_key)}"
        obj: dict = {
            "type": "network-traffic",
            "id": net_id,
            "spec_version": "2.1",
            "src_ref": src_ref,
            "dst_ref": dst_ref,
            "protocols": [protocol.lower()] if protocol else ["tcp"],
        }
        if src_port:
            obj["src_port"] = int(src_port)
        if dst_port:
            obj["dst_port"] = int(dst_port)
        return obj
    except Exception:
        return None

@staticmethod
def _build_kill_chain_phases(mitre: dict) -> list[dict]:
    """Build STIX kill-chain-phase list from Wazuh MITRE ATT&CK data."""
    phases: list[dict] = []
    tactics = mitre.get("tactic", [])
    if isinstance(tactics, str):
        tactics = [tactics]
    for tactic in tactics:
        phase_name = _MITRE_TACTIC_MAP.get(tactic.lower(), tactic.lower())
        phases.append({
            "kill_chain_name": "mitre-attack",
            "phase_name": phase_name,
        })
    return phases
```

# ── Standalone STIX object factory functions ──────────────────────────────────

def _make_ipv4(value: str) -> dict:
return {
“type”: “ipv4-addr”,
“id”: f”ipv4-addr–{_det_uuid(‘ipv4-addr’, value)}”,
“spec_version”: “2.1”,
“value”: value,
}

def _make_user_account(user_id: str) -> dict:
return {
“type”: “user-account”,
“id”: f”user-account–{_det_uuid(‘user-account’, user_id)}”,
“spec_version”: “2.1”,
“user_id”: user_id,
}

def _make_process(name: str) -> dict:
return {
“type”: “process”,
“id”: f”process–{_det_uuid(‘process’, name)}”,
“spec_version”: “2.1”,
“name”: name,
}

def _make_domain(value: str) -> dict:
return {
“type”: “domain-name”,
“id”: f”domain-name–{_det_uuid(‘domain-name’, value)}”,
“spec_version”: “2.1”,
“value”: value,
}

def _make_bundle(objects: list[dict]) -> dict:
return {
“type”: “bundle”,
“id”: f”bundle–{uuid.uuid4()}”,
“spec_version”: “2.1”,
“objects”: objects,
}

def _det_uuid(stix_type: str, value: str) -> str:
“”“Deterministic UUID5 using STIX 2.1 namespace.”””
return str(uuid.uuid5(_STIX_NAMESPACE, f”{stix_type}:{value}”))

def _now_ts() -> str:
“”“Current UTC time in STIX 2.1 format.”””
return datetime.now(timezone.utc).strftime(”%Y-%m-%dT%H:%M:%S.%f”)[:-3] + “Z”