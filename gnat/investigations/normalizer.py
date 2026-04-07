# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.investigations.normalizer
=================================

Translate raw platform API records into :class:`~.model.EvidenceNode` objects
with extracted correlation attributes.

Each platform stores the same underlying concepts (incident, indicator,
observable, task, timeline entry) in different schemas.  The normaliser's job
is to produce a common :class:`EvidenceNode` regardless of source so the
correlator and builder can work in a uniform model.

Normaliser functions are intentionally defensive — they never raise on
missing fields; they produce partial nodes instead.

Usage::

    from gnat.investigations.normalizer import normalize

    node = normalize("xsoar", "incident", raw_incident_dict)
    node = normalize("greymatter", "observable", raw_observable_dict)
    node = normalize("threatq", "event", raw_event_dict)
"""

from __future__ import annotations

import re
from typing import Any

from gnat.investigations.model import EvidenceNode, NodeType

# ── Regex helpers ──────────────────────────────────────────────────────────

_IP_RE     = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_DOMAIN_RE = re.compile(r'\b(?:[a-z0-9\-]+\.)+[a-z]{2,}\b', re.IGNORECASE)
_HASH_RE   = re.compile(r'\b[0-9a-fA-F]{32,64}\b')
_EMAIL_RE  = re.compile(r'\b[^\s@]+@[^\s@]+\.[^\s@]+\b')

# Ticket patterns: JIRA-123, INC-4892, CHG-0001, ticket#12345
_TICKET_RE = re.compile(r'\b(?:[A-Z]+-\d+|(?:INC|CHG|REQ|TICKET)-?\d+)\b', re.IGNORECASE)


def _extract_iocs(text: str) -> list[str]:
    """Pull IP addresses, hashes, emails from a free-text string."""
    found: list[str] = []
    found.extend(_IP_RE.findall(text))
    found.extend(_HASH_RE.findall(text))
    found.extend(_EMAIL_RE.findall(text))
    return list(dict.fromkeys(found))  # dedup, preserve order


def _extract_tickets(text: str) -> list[str]:
    """Internal helper for extract tickets."""
    return list(dict.fromkeys(_TICKET_RE.findall(text)))


def _node_id(platform: str, node_type: NodeType, source_id: str) -> str:
    """Internal helper for node id."""
    return f"{platform}::{node_type}::{source_id}"


# ── XSOAR ──────────────────────────────────────────────────────────────────

def _xsoar_incident(platform: str, raw: dict[str, Any]) -> EvidenceNode:
    """Internal helper for xsoar incident."""
    inc_id     = str(raw.get("id", ""))
    opened_at  = raw.get("occurred", raw.get("created", ""))
    modified   = raw.get("modified", opened_at)
    name       = raw.get("name", "")
    details    = raw.get("details", "")
    custom     = raw.get("CustomFields", {}) if isinstance(raw.get("CustomFields"), dict) else {}

    # Extract correlation attributes
    blob = f"{name} {details} {' '.join(str(v) for v in custom.values())}"
    ioc_values  = _extract_iocs(blob)
    ticket_refs = _extract_tickets(blob)
    # Hostnames from CustomFields
    hostnames = [
        str(custom[k]) for k in ("src_hostname", "dest_hostname", "hostname")
        if k in custom and custom[k]
    ]
    usernames = [
        str(custom[k]) for k in ("src_user", "dest_user", "username", "account_id")
        if k in custom and custom[k]
    ]
    # Campaign / actor from labels
    campaign_labels = [
        lbl.get("value", "") for lbl in raw.get("labels", [])
        if isinstance(lbl, dict) and lbl.get("type", "").lower() in ("campaign", "actor", "malware")
        and lbl.get("value")
    ]

    stix: dict[str, Any] = {
        "type":                "observed-data",
        "id":                  f"observed-data--{inc_id}",
        "created":             opened_at,
        "modified":            modified,
        "first_observed":      opened_at,
        "last_observed":       modified,
        "number_observed":     1,
        "object_refs":         [],
        "name":                name,
        "description":         details,
        "x_xsoar_incident_id": inc_id,
        "x_xsoar_severity":    raw.get("severity", 0),
        "x_xsoar_status":      raw.get("status", 0),
        "x_xsoar_owner":       raw.get("owner", ""),
        "x_xsoar_type":        raw.get("type", ""),
        "x_source_platform":   platform,
    }
    return EvidenceNode(
        node_id         = _node_id(platform, NodeType.INCIDENT, inc_id),
        node_type       = NodeType.INCIDENT,
        platform        = platform,
        source_id       = inc_id,
        stix            = stix,
        raw             = raw,
        ioc_values      = ioc_values,
        hostnames       = hostnames,
        usernames       = usernames,
        campaign_labels = campaign_labels,
        ticket_refs     = ticket_refs,
        time_window     = (opened_at, modified) if opened_at else None,
    )


def _xsoar_indicator(platform: str, raw: dict[str, Any]) -> EvidenceNode:
    """Internal helper for xsoar indicator."""
    src_id  = str(raw.get("id", ""))
    value   = raw.get("value", "")
    i_type  = str(raw.get("indicator_type", "")).lower()
    created = raw.get("timestamp", "")
    modified = raw.get("modified", created)

    stix: dict[str, Any] = {
        "type":            "indicator",
        "id":              f"indicator--{src_id}",
        "name":            value,
        "pattern":         f"[{i_type}:value = '{value}']",
        "pattern_type":    "stix",
        "created":         created,
        "modified":        modified,
        "indicator_types": [raw.get("indicator_type", "unknown")],
        "x_source_platform": platform,
    }
    return EvidenceNode(
        node_id     = _node_id(platform, NodeType.OBSERVABLE, src_id),
        node_type   = NodeType.OBSERVABLE,
        platform    = platform,
        source_id   = src_id,
        stix        = stix,
        raw         = raw,
        ioc_values  = [value] if value else [],
        time_window = (created, modified) if created else None,
    )


def _xsoar_alert(platform: str, raw: dict[str, Any]) -> EvidenceNode:
    """Internal helper for xsoar alert."""
    src_id  = str(raw.get("id", raw.get("alertId", "")))
    name    = raw.get("name", raw.get("message", ""))
    created = raw.get("startDate", raw.get("occurred", ""))
    stix: dict[str, Any] = {
        "type":              "observed-data",
        "id":                f"observed-data--alert-{src_id}",
        "created":           created,
        "modified":          raw.get("closeDate", created),
        "first_observed":    created,
        "last_observed":     created,
        "number_observed":   1,
        "object_refs":       [],
        "name":              name,
        "x_xsoar_alert_id":  src_id,
        "x_source_platform": platform,
    }
    return EvidenceNode(
        node_id     = _node_id(platform, NodeType.FINDING, f"alert-{src_id}"),
        node_type   = NodeType.FINDING,
        platform    = platform,
        source_id   = f"alert-{src_id}",
        stix        = stix,
        raw         = raw,
        ioc_values  = _extract_iocs(name),
        time_window = (created, created) if created else None,
    )


def _xsoar_task(platform: str, raw: dict[str, Any]) -> EvidenceNode:
    """Internal helper for xsoar task."""
    src_id  = str(raw.get("id", ""))
    name    = raw.get("name", raw.get("title", ""))
    created = raw.get("startDate", "")
    stix: dict[str, Any] = {
        "type":              "note",
        "id":                f"note--task-{src_id}",
        "created":           created,
        "modified":          raw.get("dueDate", created),
        "abstract":          name,
        "content":           raw.get("description", ""),
        "x_xsoar_task_id":   src_id,
        "x_xsoar_status":    raw.get("state", ""),
        "x_source_platform": platform,
    }
    return EvidenceNode(
        node_id    = _node_id(platform, NodeType.TASK, src_id),
        node_type  = NodeType.TASK,
        platform   = platform,
        source_id  = src_id,
        stix       = stix,
        raw        = raw,
        time_window = (created, created) if created else None,
    )


def _xsoar_timeline(platform: str, raw: dict[str, Any]) -> EvidenceNode:
    """Internal helper for xsoar timeline."""
    src_id  = str(raw.get("id", ""))
    content = raw.get("contents", raw.get("message", ""))
    created = raw.get("created", "")
    stix: dict[str, Any] = {
        "type":              "note",
        "id":                f"note--timeline-{src_id}",
        "created":           created,
        "modified":          created,
        "abstract":          f"Timeline: {raw.get('type', 'entry')}",
        "content":           content,
        "x_source_platform": platform,
    }
    return EvidenceNode(
        node_id    = _node_id(platform, NodeType.TIMELINE_EVENT, src_id),
        node_type  = NodeType.TIMELINE_EVENT,
        platform   = platform,
        source_id  = src_id,
        stix       = stix,
        raw        = raw,
        ioc_values = _extract_iocs(content),
        time_window = (created, created) if created else None,
    )


# ── GreyMatter ─────────────────────────────────────────────────────────────

def _gm_incident(platform: str, raw: dict[str, Any]) -> EvidenceNode:
    """Internal helper for gm incident."""
    data    = raw.get("data", raw)
    src_id  = str(data.get("id", ""))
    created = data.get("created_at", "")
    modified = data.get("updated_at", created)
    title   = data.get("title", data.get("name", ""))
    desc    = data.get("description", "")
    blob    = f"{title} {desc}"
    ticket_refs = _extract_tickets(blob)
    campaign_labels = [
        t for t in data.get("tags", [])
        if isinstance(t, str) and len(t) > 2
    ]

    stix: dict[str, Any] = {
        "type":               "observed-data",
        "id":                 f"observed-data--{src_id}",
        "created":            created,
        "modified":           modified,
        "first_observed":     created,
        "last_observed":      modified,
        "number_observed":    1,
        "object_refs":        [],
        "name":               title,
        "description":        desc,
        "x_gm_case_number":   data.get("case_number", ""),
        "x_gm_status":        data.get("status", ""),
        "x_gm_severity":      data.get("severity", ""),
        "x_gm_assigned_to":   data.get("assigned_to", ""),
        "x_source_platform":  platform,
    }
    return EvidenceNode(
        node_id         = _node_id(platform, NodeType.INCIDENT, src_id),
        node_type       = NodeType.INCIDENT,
        platform        = platform,
        source_id       = src_id,
        stix            = stix,
        raw             = raw,
        ioc_values      = _extract_iocs(blob),
        ticket_refs     = ticket_refs,
        campaign_labels = campaign_labels,
        time_window     = (created, modified) if created else None,
    )


def _gm_observable(platform: str, raw: dict[str, Any]) -> EvidenceNode:
    """Internal helper for gm observable."""
    data    = raw.get("data", raw)
    src_id  = str(data.get("id", ""))
    value   = data.get("value", data.get("name", ""))
    gm_type = data.get("type", "unknown")
    created = data.get("created_at", "")
    modified = data.get("updated_at", created)

    # Build STIX pattern
    _pattern_map = {
        "ipv4":   f"[ipv4-addr:value = '{value}']",
        "ipv6":   f"[ipv6-addr:value = '{value}']",
        "domain": f"[domain-name:value = '{value}']",
        "url":    f"[url:value = '{value}']",
        "md5":    f"[file:hashes.MD5 = '{value}']",
        "sha1":   f"[file:hashes.SHA-1 = '{value}']",
        "sha256": f"[file:hashes.SHA-256 = '{value}']",
        "email":  f"[email-addr:value = '{value}']",
    }
    pattern = _pattern_map.get(gm_type, f"[unknown:value = '{value}']")

    stix: dict[str, Any] = {
        "type":              "indicator",
        "id":                f"indicator--{src_id}",
        "name":              value,
        "pattern":           pattern,
        "pattern_type":      "stix",
        "created":           created,
        "modified":          modified,
        "indicator_types":   [data.get("classification", "unknown")],
        "confidence":        data.get("confidence", 50),
        "x_gm_type":         gm_type,
        "x_source_platform": platform,
    }
    return EvidenceNode(
        node_id     = _node_id(platform, NodeType.OBSERVABLE, src_id),
        node_type   = NodeType.OBSERVABLE,
        platform    = platform,
        source_id   = src_id,
        stix        = stix,
        raw         = raw,
        ioc_values  = [value] if value else [],
        time_window = (created, modified) if created else None,
    )


def _gm_task(platform: str, raw: dict[str, Any]) -> EvidenceNode:
    """Internal helper for gm task."""
    data    = raw.get("data", raw)
    src_id  = str(data.get("id", ""))
    title   = data.get("title", data.get("name", ""))
    created = data.get("created_at", "")
    stix: dict[str, Any] = {
        "type":              "note",
        "id":                f"note--gm-task-{src_id}",
        "created":           created,
        "modified":          data.get("updated_at", created),
        "abstract":          title,
        "content":           data.get("description", ""),
        "x_gm_task_status":  data.get("status", ""),
        "x_source_platform": platform,
    }
    return EvidenceNode(
        node_id    = _node_id(platform, NodeType.TASK, src_id),
        node_type  = NodeType.TASK,
        platform   = platform,
        source_id  = src_id,
        stix       = stix,
        raw        = raw,
        time_window = (created, created) if created else None,
    )


# ── ThreatQ ────────────────────────────────────────────────────────────────

def _tq_event(platform: str, raw: dict[str, Any]) -> EvidenceNode:
    """Internal helper for tq event."""
    data    = raw.get("data", raw)
    src_id  = str(data.get("id", ""))
    title   = data.get("title", "")
    desc    = data.get("description", "")
    created = data.get("created_at", "")
    happened = data.get("happened_at", created)
    modified = data.get("updated_at", created)
    blob    = f"{title} {desc}"
    ticket_refs = _extract_tickets(blob)

    stix: dict[str, Any] = {
        "type":              "observed-data",
        "id":                f"observed-data--{src_id}",
        "created":           created,
        "modified":          modified,
        "first_observed":    happened,
        "last_observed":     happened,
        "number_observed":   1,
        "object_refs":       [],
        "name":              title,
        "description":       desc,
        "x_tq_event_type":   data.get("event_type", ""),
        "x_tq_event_id":     src_id,
        "x_source_platform": platform,
    }
    return EvidenceNode(
        node_id     = _node_id(platform, NodeType.INCIDENT, src_id),
        node_type   = NodeType.INCIDENT,
        platform    = platform,
        source_id   = src_id,
        stix        = stix,
        raw         = raw,
        ioc_values  = _extract_iocs(blob),
        ticket_refs = ticket_refs,
        time_window = (happened, happened) if happened else None,
    )


def _tq_indicator(platform: str, raw: dict[str, Any]) -> EvidenceNode:
    """Internal helper for tq indicator."""
    data    = raw.get("data", raw)
    src_id  = str(data.get("id", ""))
    value   = data.get("value", "")
    tq_type = data.get("type", "unknown")
    created = data.get("created_at", "")
    modified = data.get("updated_at", created)

    stix: dict[str, Any] = {
        "type":              "indicator",
        "id":                f"indicator--{src_id}",
        "name":              value,
        "pattern":           f"[{tq_type}:value = '{value}']",
        "pattern_type":      "stix",
        "created":           created,
        "modified":          modified,
        "indicator_types":   [data.get("class", "unknown")],
        "x_source_platform": platform,
    }
    return EvidenceNode(
        node_id     = _node_id(platform, NodeType.OBSERVABLE, src_id),
        node_type   = NodeType.OBSERVABLE,
        platform    = platform,
        source_id   = src_id,
        stix        = stix,
        raw         = raw,
        ioc_values  = [value] if value else [],
        time_window = (created, modified) if created else None,
    )


def _tq_adversary(platform: str, raw: dict[str, Any]) -> EvidenceNode:
    """Internal helper for tq adversary."""
    data    = raw.get("data", raw)
    src_id  = str(data.get("id", ""))
    name    = data.get("name", data.get("value", ""))
    created = data.get("created_at", "")
    stix: dict[str, Any] = {
        "type":              "threat-actor",
        "id":                f"threat-actor--{src_id}",
        "name":              name,
        "created":           created,
        "modified":          data.get("updated_at", created),
        "x_source_platform": platform,
    }
    return EvidenceNode(
        node_id         = _node_id(platform, NodeType.IDENTITY, src_id),
        node_type       = NodeType.IDENTITY,
        platform        = platform,
        source_id       = src_id,
        stix            = stix,
        raw             = raw,
        campaign_labels = [name] if name else [],
        time_window     = (created, created) if created else None,
    )


# ── TheHive ────────────────────────────────────────────────────────────────

def _hive_case(platform: str, raw: dict[str, Any]) -> EvidenceNode:
    """Internal helper for hive case."""
    src_id   = str(raw.get("_id", raw.get("id", "")))
    title    = raw.get("title", "")
    desc     = raw.get("description", "")
    created  = raw.get("_createdAt", raw.get("startDate", ""))
    modified = raw.get("_updatedAt", raw.get("endDate", created))
    blob     = f"{title} {desc}"
    campaign_labels = [t for t in raw.get("tags", []) if isinstance(t, str)]
    ticket_refs = _extract_tickets(blob)

    stix: dict[str, Any] = {
        "type":                "observed-data",
        "id":                  f"observed-data--hive-{src_id}",
        "created":             created,
        "modified":            modified,
        "first_observed":      created,
        "last_observed":       modified,
        "number_observed":     1,
        "object_refs":         [],
        "name":                title,
        "description":         desc,
        "x_hive_case_id":      src_id,
        "x_hive_status":       raw.get("status", ""),
        "x_hive_severity":     raw.get("severity", 2),
        "x_hive_assigned_to":  raw.get("assignee", ""),
        "x_source_platform":   platform,
    }
    return EvidenceNode(
        node_id         = _node_id(platform, NodeType.INCIDENT, src_id),
        node_type       = NodeType.INCIDENT,
        platform        = platform,
        source_id       = src_id,
        stix            = stix,
        raw             = raw,
        ioc_values      = _extract_iocs(blob),
        campaign_labels = campaign_labels,
        ticket_refs     = ticket_refs,
        time_window     = (created, modified) if created else None,
    )


def _hive_observable(platform: str, raw: dict[str, Any]) -> EvidenceNode:
    """Internal helper for hive observable."""
    src_id    = str(raw.get("_id", raw.get("id", "")))
    value     = raw.get("data", "")
    data_type = raw.get("dataType", "unknown")
    created   = raw.get("_createdAt", "")
    modified  = raw.get("_updatedAt", created)

    _pattern_map = {
        "ip":       f"[ipv4-addr:value = '{value}']",
        "domain":   f"[domain-name:value = '{value}']",
        "url":      f"[url:value = '{value}']",
        "hash":     f"[file:hashes.MD5 = '{value}']",
        "mail":     f"[email-addr:value = '{value}']",
        "hostname": f"[domain-name:value = '{value}']",
        "filename": f"[file:name = '{value}']",
    }
    pattern = _pattern_map.get(data_type, f"[unknown:value = '{value}']")

    stix: dict[str, Any] = {
        "type":              "indicator",
        "id":                f"indicator--hive-obs-{src_id}",
        "name":              value,
        "pattern":           pattern,
        "pattern_type":      "stix",
        "created":           created,
        "modified":          modified,
        "indicator_types":   [data_type],
        "x_hive_ioc":        raw.get("ioc", False),
        "x_hive_tlp":        raw.get("tlp", 1),
        "x_source_platform": platform,
    }
    return EvidenceNode(
        node_id     = _node_id(platform, NodeType.OBSERVABLE, src_id),
        node_type   = NodeType.OBSERVABLE,
        platform    = platform,
        source_id   = src_id,
        stix        = stix,
        raw         = raw,
        ioc_values  = [value] if value else [],
        time_window = (created, modified) if created else None,
    )


def _hive_task(platform: str, raw: dict[str, Any]) -> EvidenceNode:
    """Internal helper for hive task."""
    src_id   = str(raw.get("_id", raw.get("id", "")))
    title    = raw.get("title", raw.get("name", ""))
    created  = raw.get("_createdAt", "")
    modified = raw.get("_updatedAt", created)

    stix: dict[str, Any] = {
        "type":               "note",
        "id":                 f"note--hive-task-{src_id}",
        "created":            created,
        "modified":           modified,
        "abstract":           title,
        "content":            raw.get("description", ""),
        "x_hive_task_status": raw.get("status", ""),
        "x_hive_assignee":    raw.get("assignee", ""),
        "x_source_platform":  platform,
    }
    return EvidenceNode(
        node_id    = _node_id(platform, NodeType.TASK, src_id),
        node_type  = NodeType.TASK,
        platform   = platform,
        source_id  = src_id,
        stix       = stix,
        raw        = raw,
        time_window = (created, modified) if created else None,
    )


# ── ServiceNow SecOps ─────────────────────────────────────────────────────

def _sn_secops_incident(platform: str, raw: dict[str, Any]) -> EvidenceNode:
    """Internal helper for sn secops incident."""
    src_id   = str(raw.get("sys_id", ""))
    title    = raw.get("short_description", "")
    desc     = raw.get("description", "")
    created  = raw.get("sys_created_on", "")
    modified = raw.get("sys_updated_on", created)
    blob     = f"{title} {desc} {raw.get('work_notes', '')}"
    campaign_labels = [
        raw.get("category", ""),
        raw.get("subcategory", ""),
    ]
    campaign_labels = [c for c in campaign_labels if c]
    ticket_refs = _extract_tickets(blob)
    # Extract linked Jira/ticket from correlation_id or correlation_display
    corr = raw.get("correlation_id", "") or raw.get("correlation_display", "")
    if corr:
        ticket_refs = list(dict.fromkeys(ticket_refs + [corr]))

    stix: dict[str, Any] = {
        "type":                   "observed-data",
        "id":                     f"observed-data--sn-{src_id}",
        "created":                created,
        "modified":               modified,
        "first_observed":         created,
        "last_observed":          modified,
        "number_observed":        1,
        "object_refs":            [],
        "name":                   title,
        "description":            desc,
        "x_sn_sys_id":            src_id,
        "x_sn_number":            raw.get("number", ""),
        "x_sn_state":             raw.get("state", {}).get("value", raw.get("state", "")),
        "x_sn_priority":          raw.get("priority", {}).get("value", raw.get("priority", "")),
        "x_sn_assigned_to":       raw.get("assigned_to", {}).get("display_value", ""),
        "x_sn_category":          raw.get("category", ""),
        "x_source_platform":      platform,
    }
    return EvidenceNode(
        node_id         = _node_id(platform, NodeType.INCIDENT, src_id),
        node_type       = NodeType.INCIDENT,
        platform        = platform,
        source_id       = src_id,
        stix            = stix,
        raw             = raw,
        ioc_values      = _extract_iocs(blob),
        campaign_labels = campaign_labels,
        ticket_refs     = ticket_refs,
        time_window     = (created, modified) if created else None,
    )


def _sn_secops_task(platform: str, raw: dict[str, Any]) -> EvidenceNode:
    """Internal helper for sn secops task."""
    src_id   = str(raw.get("sys_id", ""))
    title    = raw.get("short_description", raw.get("name", ""))
    created  = raw.get("sys_created_on", "")
    modified = raw.get("sys_updated_on", created)

    stix: dict[str, Any] = {
        "type":              "note",
        "id":                f"note--sn-task-{src_id}",
        "created":           created,
        "modified":          modified,
        "abstract":          title,
        "content":           raw.get("description", raw.get("work_notes", "")),
        "x_sn_task_state":   raw.get("state", {}).get("value", raw.get("state", "")),
        "x_source_platform": platform,
    }
    return EvidenceNode(
        node_id    = _node_id(platform, NodeType.TASK, src_id),
        node_type  = NodeType.TASK,
        platform   = platform,
        source_id  = src_id,
        stix       = stix,
        raw        = raw,
        time_window = (created, modified) if created else None,
    )


def _sn_secops_observable(platform: str, raw: dict[str, Any]) -> EvidenceNode:
    """Internal helper for sn secops observable."""
    src_id    = str(raw.get("sys_id", ""))
    value     = raw.get("value", "")
    obs_type  = raw.get("type", {}).get("display_value", raw.get("type", "unknown"))
    created   = raw.get("sys_created_on", "")
    modified  = raw.get("sys_updated_on", created)

    _pattern_map: dict[str, str] = {
        "IP Address":  f"[ipv4-addr:value = '{value}']",
        "Domain":      f"[domain-name:value = '{value}']",
        "URL":         f"[url:value = '{value}']",
        "File Hash":   f"[file:hashes.MD5 = '{value}']",
        "Email":       f"[email-addr:value = '{value}']",
    }
    pattern = _pattern_map.get(obs_type, f"[unknown:value = '{value}']")

    stix: dict[str, Any] = {
        "type":              "indicator",
        "id":                f"indicator--sn-obs-{src_id}",
        "name":              value,
        "pattern":           pattern,
        "pattern_type":      "stix",
        "created":           created,
        "modified":          modified,
        "indicator_types":   [obs_type],
        "x_sn_obs_type":     obs_type,
        "x_source_platform": platform,
    }
    return EvidenceNode(
        node_id     = _node_id(platform, NodeType.OBSERVABLE, src_id),
        node_type   = NodeType.OBSERVABLE,
        platform    = platform,
        source_id   = src_id,
        stix        = stix,
        raw         = raw,
        ioc_values  = [value] if value else [],
        time_window = (created, modified) if created else None,
    )


# ── Cortex XDR ────────────────────────────────────────────────────────────

def _xdr_incident(platform: str, raw: dict[str, Any]) -> EvidenceNode:
    """Internal helper for xdr incident."""
    inc_id   = str(raw.get("incident_id", ""))
    name     = raw.get("incident_name", f"XDR Incident {inc_id}")
    desc     = raw.get("description", "")
    ts       = raw.get("creation_time", "")
    mod_ts   = raw.get("modification_time", ts)
    hosts    = raw.get("hosts", [])
    users    = raw.get("users", [])
    blob     = f"{name} {desc}"

    stix: dict[str, Any] = {
        "type":              "observed-data",
        "id":                f"observed-data--xdr-{inc_id}",
        "created":           str(ts),
        "modified":          str(mod_ts),
        "first_observed":    str(ts),
        "last_observed":     str(mod_ts),
        "number_observed":   1,
        "object_refs":       [],
        "name":              name,
        "description":       desc,
        "x_xdr_incident_id": inc_id,
        "x_xdr_severity":    raw.get("severity", ""),
        "x_xdr_status":      raw.get("status", ""),
        "x_xdr_alert_count": raw.get("alert_count", 0),
        "x_source_platform": platform,
    }
    return EvidenceNode(
        node_id     = _node_id(platform, NodeType.INCIDENT, inc_id),
        node_type   = NodeType.INCIDENT,
        platform    = platform,
        source_id   = inc_id,
        stix        = stix,
        raw         = raw,
        ioc_values  = _extract_iocs(blob),
        hostnames   = [str(h) for h in hosts if h],
        usernames   = [str(u) for u in users if u],
        time_window = (str(ts), str(mod_ts)) if ts else None,
    )


def _xdr_alert(platform: str, raw: dict[str, Any]) -> EvidenceNode:
    """Internal helper for xdr alert."""
    alert_id = str(raw.get("alert_id", ""))
    name     = raw.get("name", raw.get("alert_name", f"XDR Alert {alert_id}"))
    ts       = raw.get("detection_timestamp", "")
    host     = raw.get("host_name", "")
    remote_ip = raw.get("remote_ip", "")

    stix: dict[str, Any] = {
        "type":              "observed-data",
        "id":                f"observed-data--xdr-alert-{alert_id}",
        "created":           str(ts),
        "modified":          str(ts),
        "first_observed":    str(ts),
        "last_observed":     str(ts),
        "number_observed":   1,
        "object_refs":       [],
        "name":              name,
        "x_xdr_alert_id":    alert_id,
        "x_xdr_severity":    raw.get("severity", ""),
        "x_xdr_category":    raw.get("category", ""),
        "x_source_platform": platform,
    }
    return EvidenceNode(
        node_id     = _node_id(platform, NodeType.FINDING, f"alert-{alert_id}"),
        node_type   = NodeType.FINDING,
        platform    = platform,
        source_id   = f"alert-{alert_id}",
        stix        = stix,
        raw         = raw,
        ioc_values  = [remote_ip] if remote_ip else [],
        hostnames   = [host] if host else [],
        time_window = (str(ts), str(ts)) if ts else None,
    )


def _xdr_artifact(platform: str, raw: dict[str, Any]) -> EvidenceNode:
    """Internal helper for xdr artifact."""
    src_id = str(raw.get("alert_id", raw.get("file_sha256", raw.get("network_remote_ip", ""))))
    artifact_type = "network" if "network_remote_ip" in raw else "file"
    value = raw.get("network_remote_ip", "") or raw.get("file_sha256", "")
    name = raw.get("file_name", "") or raw.get("network_remote_domain", value)

    stix: dict[str, Any] = {
        "type":              "indicator",
        "id":                f"indicator--xdr-artifact-{src_id[:40]}",
        "name":              name or value,
        "pattern":           (
            f"[ipv4-addr:value = '{value}']" if artifact_type == "network"
            else f"[file:hashes.'SHA-256' = '{value}']"
        ),
        "pattern_type":      "stix",
        "created":           "",
        "modified":          "",
        "indicator_types":   ["malicious-activity"],
        "x_source_platform": platform,
    }
    return EvidenceNode(
        node_id    = _node_id(platform, NodeType.ARTIFACT, f"artifact-{src_id[:40]}"),
        node_type  = NodeType.ARTIFACT,
        platform   = platform,
        source_id  = f"artifact-{src_id[:40]}",
        stix       = stix,
        raw        = raw,
        ioc_values = [value] if value else [],
    )


# ── Public dispatcher ──────────────────────────────────────────────────────

_DISPATCH: dict[tuple[str, str], Any] = {
    # XSOAR
    ("xsoar",             "incident"):       _xsoar_incident,
    ("xsoar",             "indicator"):      _xsoar_indicator,
    ("xsoar",             "alert"):          _xsoar_alert,
    ("xsoar",             "task"):           _xsoar_task,
    ("xsoar",             "timeline"):       _xsoar_timeline,
    # GreyMatter
    ("greymatter",        "incident"):       _gm_incident,
    ("greymatter",        "observable"):     _gm_observable,
    ("greymatter",        "task"):           _gm_task,
    # ThreatQ
    ("threatq",           "event"):          _tq_event,
    ("threatq",           "incident"):       _tq_event,      # alias: ThreatQ Events are the investigation container
    ("threatq",           "indicator"):      _tq_indicator,
    ("threatq",           "adversary"):      _tq_adversary,
    # TheHive
    ("thehive",           "case"):           _hive_case,
    ("thehive",           "incident"):       _hive_case,
    ("thehive",           "observable"):     _hive_observable,
    ("thehive",           "task"):           _hive_task,
    # ServiceNow SecOps
    ("servicenow_secops", "incident"):       _sn_secops_incident,
    ("servicenow_secops", "task"):           _sn_secops_task,
    ("servicenow_secops", "observable"):     _sn_secops_observable,
    # Cortex XDR
    ("cortex_xdr",        "incident"):       _xdr_incident,
    ("cortex_xdr",        "alert"):          _xdr_alert,
    ("cortex_xdr",        "artifact"):       _xdr_artifact,
    # Aliases — "observed-data" → incident normaliser for each platform
    ("xsoar",             "observed-data"):  _xsoar_incident,
    ("greymatter",        "observed-data"):  _gm_incident,
    ("threatq",           "observed-data"):  _tq_event,
    ("thehive",           "observed-data"):  _hive_case,
    ("servicenow_secops", "observed-data"):  _sn_secops_incident,
    ("cortex_xdr",        "observed-data"):  _xdr_incident,
    # indicator alias for platforms that call it differently
    ("thehive",           "indicator"):      _hive_observable,
    ("servicenow_secops", "indicator"):      _sn_secops_observable,
    ("cortex_xdr",        "indicator"):      _xdr_alert,
}


def normalize(
    platform: str,
    record_type: str,
    raw: dict[str, Any],
) -> EvidenceNode | None:
    """
    Translate a raw platform record into an :class:`EvidenceNode`.

    Returns ``None`` if the platform/record_type combination is unknown
    or if *raw* is empty.

    Parameters
    ----------
    platform : str
        Connector name (``"xsoar"``, ``"greymatter"``, ``"threatq"``,
        ``"thehive"``, ``"servicenow_secops"``, ``"cortex_xdr"``).
    record_type : str
        Platform record category (``"incident"``, ``"indicator"``,
        ``"observable"``, ``"alert"``, ``"task"``, ``"event"``, …).
    raw : dict
        Raw API response from the connector.

    Returns
    -------
    EvidenceNode or None
    """
    if not raw:
        return None
    key = (platform.lower(), record_type.lower())
    fn = _DISPATCH.get(key)
    if fn is None and record_type in ("observable", "indicator"):
        fn = _DISPATCH.get((platform.lower(), "observable")) \
          or _DISPATCH.get((platform.lower(), "indicator"))
    if fn is None:
        return None
    return fn(platform, raw)
