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
    return list(dict.fromkeys(_TICKET_RE.findall(text)))


def _node_id(platform: str, node_type: NodeType, source_id: str) -> str:
    return f"{platform}::{node_type}::{source_id}"


# ── XSOAR ──────────────────────────────────────────────────────────────────

def _xsoar_incident(platform: str, raw: dict[str, Any]) -> EvidenceNode:
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


# ── Public dispatcher ──────────────────────────────────────────────────────

_DISPATCH: dict[tuple[str, str], Any] = {
    ("xsoar",       "incident"):       _xsoar_incident,
    ("xsoar",       "indicator"):      _xsoar_indicator,
    ("xsoar",       "alert"):          _xsoar_alert,
    ("xsoar",       "task"):           _xsoar_task,
    ("xsoar",       "timeline"):       _xsoar_timeline,
    ("greymatter",  "incident"):       _gm_incident,
    ("greymatter",  "observable"):     _gm_observable,
    ("greymatter",  "task"):           _gm_task,
    ("threatq",     "event"):          _tq_event,
    ("threatq",     "indicator"):      _tq_indicator,
    ("threatq",     "adversary"):      _tq_adversary,
    # Aliases
    ("xsoar",       "observed-data"):  _xsoar_incident,
    ("greymatter",  "observed-data"):  _gm_incident,
    ("threatq",     "observed-data"):  _tq_event,
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
        Connector name (``"xsoar"``, ``"greymatter"``, ``"threatq"``).
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
