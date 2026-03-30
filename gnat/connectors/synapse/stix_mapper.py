"""STIX ↔ Synapse node translation helpers."""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class SynapseSTIXMapper:
    """
    Converts between Synapse node dicts and STIX 2.1 representations.

    Synapse node format::

        {
            "ndef": ["form", "value"],
            "props": {...},
            "tags":  {"tag.name": [ts1, ts2], ...},
            "iden":  "hexstring",
        }

    Uses a stable UUID5 namespace so identical inputs always produce
    the same STIX identifier.
    """

    _NAMESPACE = uuid.UUID("9c4b7e2d-1a3f-4d8e-b5c6-7f8a9b0c1d2e")

    _FORM_TO_STIX: Dict[str, str] = {
        # Network SCOs
        "inet:ipv4":   "ipv4-addr",
        "inet:ipv6":   "ipv6-addr",
        "inet:fqdn":   "domain-name",
        "inet:url":    "url",
        "inet:email":  "email-addr",
        "inet:asn":    "autonomous-system",
        "inet:flow":   "network-traffic",
        # File / hash forms
        "file:bytes":  "file",
        "hash:md5":    "file",
        "hash:sha1":   "file",
        "hash:sha256": "file",
        # Risk / threat intel SDOs
        "risk:vuln":       "vulnerability",
        "risk:attack":     "attack-pattern",
        "risk:threat":     "threat-actor",
        "risk:mitigation": "course-of-action",
        # MITRE ATT&CK forms
        "it:mitre:attack:technique": "attack-pattern",
        "it:mitre:attack:software":  "malware",
        "it:mitre:attack:group":     "threat-actor",
        # Identity / people / org
        "ou:org":    "identity",
        "ps:person": "identity",
        # Reports and events
        "media:news":  "report",
        "meta:event":  "observed-data",
    }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _make_id(self, stix_type: str, value: str) -> str:
        """
        Generate a deterministic STIX 2.1 identifier.

        Parameters
        ----------
        stix_type : str
            STIX object type.
        value : str
            Unique seed value.

        Returns
        -------
        str
            STIX id in ``<type>--<uuid5>`` format.
        """
        return f"{stix_type}--{uuid.uuid5(self._NAMESPACE, str(value))}"

    def _tags_to_stix_labels(self, tags: Dict[str, Any]) -> List[str]:
        """
        Convert Synapse tag names to a list of STIX label strings.

        Uses the last dotted component of each tag name as the label.

        Parameters
        ----------
        tags : dict
            Synapse tags dict mapping tag name → ``[ts1, ts2]``.

        Returns
        -------
        list of str
        """
        labels: List[str] = []
        for tag_name in tags:
            part = tag_name.split(".")[-1]
            if part and part not in labels:
                labels.append(part)
        return labels

    # ------------------------------------------------------------------
    # Top-level dispatch
    # ------------------------------------------------------------------

    def node_to_stix(self, node: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert a Synapse node dict to a STIX 2.1 object.

        Parameters
        ----------
        node : dict
            Synapse node with ``ndef``, ``props``, ``tags``, and ``iden``
            keys.

        Returns
        -------
        dict
            STIX 2.1 object corresponding to the node's form.
        """
        form = node.get("ndef", ["", ""])[0]

        dispatch = {
            "inet:ipv4":   self._ipv4_to_stix,
            "inet:ipv6":   self._ipv6_to_stix,
            "inet:fqdn":   self._fqdn_to_stix,
            "inet:url":    self._url_to_stix,
            "inet:email":  self._email_to_stix,
            "inet:asn":    self._asn_to_stix,
            "inet:flow":   self._flow_to_stix,
            "file:bytes":  self._file_to_stix,
            "hash:md5":    self._file_to_stix,
            "hash:sha1":   self._file_to_stix,
            "hash:sha256": self._file_to_stix,
            "risk:vuln":       self._vuln_to_stix,
            "risk:attack":     self._attack_to_stix,
            "risk:threat":     self._threat_actor_to_stix,
            "risk:mitigation": self._mitigation_to_stix,
            "it:mitre:attack:technique": self._attack_to_stix,
            "it:mitre:attack:software":  self._malware_to_stix,
            "it:mitre:attack:group":     self._threat_actor_to_stix,
            "ou:org":      self._identity_to_stix,
            "ps:person":   self._identity_to_stix,
            "media:news":  self._report_to_stix,
            "meta:event":  self._observed_data_to_stix,
        }

        handler = dispatch.get(form)
        if handler:
            return handler(node)

        # Generic fallback
        value = node.get("ndef", ["", ""])[1]
        ts = _now_iso()
        return {
            "type": "x-synapse-node",
            "id": self._make_id("x-synapse-node", f"{form}:{value}"),
            "created": ts,
            "modified": ts,
            "x_synapse_form": form,
            "x_synapse_value": value,
            "x_synapse_tags": list(node.get("tags", {}).keys()),
            "x_synapse_iden": node.get("iden", ""),
        }

    # ------------------------------------------------------------------
    # Per-form helpers
    # ------------------------------------------------------------------

    def _base_fields(
        self, stix_type: str, value: str, node: Dict[str, Any]
    ) -> Dict[str, Any]:
        ts = _now_iso()
        tags = node.get("tags", {})
        labels = self._tags_to_stix_labels(tags)
        obj: Dict[str, Any] = {
            "type": stix_type,
            "id": self._make_id(stix_type, value),
            "created": ts,
            "modified": ts,
            "x_synapse_iden": node.get("iden", ""),
            "x_synapse_tags": list(tags.keys()),
        }
        if labels:
            obj["labels"] = labels
        return obj

    def _ipv4_to_stix(self, node: Dict[str, Any]) -> Dict[str, Any]:
        """Convert an ``inet:ipv4`` node to a STIX ``ipv4-addr`` SCO."""
        value = node["ndef"][1]
        obj = self._base_fields("ipv4-addr", str(value), node)
        obj["value"] = str(value)
        return obj

    def _ipv6_to_stix(self, node: Dict[str, Any]) -> Dict[str, Any]:
        """Convert an ``inet:ipv6`` node to a STIX ``ipv6-addr`` SCO."""
        value = node["ndef"][1]
        obj = self._base_fields("ipv6-addr", str(value), node)
        obj["value"] = str(value)
        return obj

    def _fqdn_to_stix(self, node: Dict[str, Any]) -> Dict[str, Any]:
        """Convert an ``inet:fqdn`` node to a STIX ``domain-name`` SCO."""
        value = node["ndef"][1]
        obj = self._base_fields("domain-name", str(value), node)
        obj["value"] = str(value)
        return obj

    def _url_to_stix(self, node: Dict[str, Any]) -> Dict[str, Any]:
        """Convert an ``inet:url`` node to a STIX ``url`` SCO."""
        value = node["ndef"][1]
        obj = self._base_fields("url", str(value), node)
        obj["value"] = str(value)
        return obj

    def _email_to_stix(self, node: Dict[str, Any]) -> Dict[str, Any]:
        """Convert an ``inet:email`` node to a STIX ``email-addr`` SCO."""
        value = node["ndef"][1]
        obj = self._base_fields("email-addr", str(value), node)
        obj["value"] = str(value)
        return obj

    def _file_to_stix(self, node: Dict[str, Any]) -> Dict[str, Any]:
        """Convert a file/hash node to a STIX ``file`` SCO."""
        form = node["ndef"][0]
        value = node["ndef"][1]
        props = node.get("props", {})

        hashes: Dict[str, str] = {}
        if form == "file:bytes":
            if props.get("sha256"):
                hashes["SHA-256"] = str(props["sha256"])
            if props.get("md5"):
                hashes["MD5"] = str(props["md5"])
            if props.get("sha512"):
                hashes["SHA-512"] = str(props["sha512"])
        elif form == "hash:md5":
            hashes["MD5"] = str(value)
        elif form == "hash:sha1":
            hashes["SHA-1"] = str(value)
        elif form == "hash:sha256":
            hashes["SHA-256"] = str(value)

        seed = next(iter(hashes.values())) if hashes else str(value)
        obj = self._base_fields("file", seed, node)
        if hashes:
            obj["hashes"] = hashes
        name = props.get("name", "")
        if name:
            obj["name"] = str(name)
        return obj

    def _vuln_to_stix(self, node: Dict[str, Any]) -> Dict[str, Any]:
        """Convert a ``risk:vuln`` node to a STIX ``vulnerability`` SDO."""
        value = node["ndef"][1]
        props = node.get("props", {})
        obj = self._base_fields("vulnerability", str(value), node)
        obj["name"] = str(props.get("name", value))
        desc = props.get("desc", "")
        if desc:
            obj["description"] = str(desc)
        # Expose CVE identifier when present (risk:vuln stores it as :cve)
        cve = props.get("cve", "")
        if cve:
            obj["external_references"] = [
                {"source_name": "cve", "external_id": str(cve)}
            ]
        return obj

    def _attack_to_stix(self, node: Dict[str, Any]) -> Dict[str, Any]:
        """Convert a ``risk:attack`` / ``it:mitre:attack:technique`` node to ``attack-pattern``."""
        form = node["ndef"][0]
        value = node["ndef"][1]
        props = node.get("props", {})
        obj = self._base_fields("attack-pattern", str(value), node)
        obj["name"] = str(props.get("name", value))
        desc = props.get("desc", "") or props.get("summary", "")
        if desc:
            obj["description"] = str(desc)
        # Expose MITRE ATT&CK ID for the technique form
        if form == "it:mitre:attack:technique":
            technique_id = props.get("technique_id", "") or str(value)
            obj["external_references"] = [
                {
                    "source_name": "mitre-attack",
                    "external_id": technique_id,
                    "url": f"https://attack.mitre.org/techniques/{technique_id}/",
                }
            ]
        return obj

    def _malware_to_stix(self, node: Dict[str, Any]) -> Dict[str, Any]:
        """Convert an ``it:mitre:attack:software`` node to a STIX ``malware`` SDO."""
        value = node["ndef"][1]
        props = node.get("props", {})
        obj = self._base_fields("malware", str(value), node)
        obj["name"] = str(props.get("name", value))
        obj["is_family"] = False
        software_id = props.get("software_id", "")
        if software_id:
            obj["external_references"] = [
                {
                    "source_name": "mitre-attack",
                    "external_id": str(software_id),
                    "url": f"https://attack.mitre.org/software/{software_id}/",
                }
            ]
        return obj

    def _threat_actor_to_stix(self, node: Dict[str, Any]) -> Dict[str, Any]:
        """Convert a ``risk:threat`` / ``it:mitre:attack:group`` node to ``threat-actor``."""
        form = node["ndef"][0]
        value = node["ndef"][1]
        props = node.get("props", {})
        obj = self._base_fields("threat-actor", str(value), node)
        obj["name"] = str(props.get("name", value))
        if form == "it:mitre:attack:group":
            group_id = props.get("group_id", "")
            if group_id:
                obj["external_references"] = [
                    {
                        "source_name": "mitre-attack",
                        "external_id": str(group_id),
                        "url": f"https://attack.mitre.org/groups/{group_id}/",
                    }
                ]
        return obj

    def _mitigation_to_stix(self, node: Dict[str, Any]) -> Dict[str, Any]:
        """Convert a ``risk:mitigation`` node to a STIX ``course-of-action`` SDO."""
        value = node["ndef"][1]
        props = node.get("props", {})
        obj = self._base_fields("course-of-action", str(value), node)
        obj["name"] = str(props.get("name", value))
        desc = props.get("desc", "")
        if desc:
            obj["description"] = str(desc)
        return obj

    def _asn_to_stix(self, node: Dict[str, Any]) -> Dict[str, Any]:
        """Convert an ``inet:asn`` node to a STIX ``autonomous-system`` SCO."""
        value = node["ndef"][1]
        props = node.get("props", {})
        obj = self._base_fields("autonomous-system", str(value), node)
        try:
            obj["number"] = int(value)
        except (TypeError, ValueError):
            obj["number"] = 0
        name = props.get("name", "")
        if name:
            obj["name"] = str(name)
        return obj

    def _flow_to_stix(self, node: Dict[str, Any]) -> Dict[str, Any]:
        """Convert an ``inet:flow`` node to a STIX ``network-traffic`` SCO."""
        value = node["ndef"][1]
        props = node.get("props", {})
        obj = self._base_fields("network-traffic", str(value), node)
        obj["src_ref"] = props.get("src:ipv4", props.get("src:ipv6", ""))
        obj["dst_ref"] = props.get("dst:ipv4", props.get("dst:ipv6", ""))
        src_port = props.get("src:port")
        dst_port = props.get("dst:port")
        if src_port:
            obj["src_port"] = int(src_port)
        if dst_port:
            obj["dst_port"] = int(dst_port)
        proto = props.get("proto", "")
        if proto:
            obj["protocols"] = [str(proto).lower()]
        return obj

    def _identity_to_stix(self, node: Dict[str, Any]) -> Dict[str, Any]:
        """Convert an ``ou:org`` or ``ps:person`` node to a STIX ``identity`` SDO."""
        form = node["ndef"][0]
        value = node["ndef"][1]
        props = node.get("props", {})
        obj = self._base_fields("identity", str(value), node)
        obj["name"] = str(props.get("name", value))
        obj["identity_class"] = "organization" if form == "ou:org" else "individual"
        return obj

    def _report_to_stix(self, node: Dict[str, Any]) -> Dict[str, Any]:
        """Convert a ``media:news`` node to a STIX ``report`` SDO."""
        value = node["ndef"][1]
        props = node.get("props", {})
        obj = self._base_fields("report", str(value), node)
        obj["name"] = str(props.get("title", value))
        obj["object_refs"] = []
        published = props.get("published", _now_iso())
        obj["published"] = str(published)
        url = props.get("url", "")
        if url:
            obj["external_references"] = [{"source_name": "media:news", "url": str(url)}]
        return obj

    def _observed_data_to_stix(self, node: Dict[str, Any]) -> Dict[str, Any]:
        """Convert a ``meta:event`` node to a STIX ``observed-data`` SDO."""
        value = node["ndef"][1]
        props = node.get("props", {})
        ts = _now_iso()
        obj = self._base_fields("observed-data", str(value), node)
        obj["first_observed"] = str(props.get("time", ts))
        obj["last_observed"] = str(props.get("time", ts))
        obj["number_observed"] = 1
        obj["object_refs"] = []
        return obj

    # ------------------------------------------------------------------
    # Bundle
    # ------------------------------------------------------------------

    def nodes_to_stix_bundle(self, nodes: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Convert a list of Synapse nodes to a STIX 2.1 bundle.

        Parameters
        ----------
        nodes : list of dict
            Synapse node dicts.

        Returns
        -------
        dict
            STIX 2.1 bundle object.
        """
        objects = [self.node_to_stix(n) for n in nodes]
        return {
            "type": "bundle",
            "id": f"bundle--{uuid.uuid5(self._NAMESPACE, str([o['id'] for o in objects]))}",
            "objects": objects,
        }

    # ------------------------------------------------------------------
    # STIX → Synapse
    # ------------------------------------------------------------------

    def stix_indicator_to_node(self, stix_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert a STIX ``indicator`` SDO to a Synapse node descriptor.

        Parses simple single-observable STIX patterns into Synapse form /
        value pairs.

        Parameters
        ----------
        stix_dict : dict
            STIX 2.1 ``indicator`` object.

        Returns
        -------
        dict
            Dict with ``form``, ``value``, ``props``, and ``tags`` keys.
        """
        pattern = stix_dict.get("pattern", "")
        labels = stix_dict.get("labels", [])
        tags = {lbl: [None, None] for lbl in labels}

        form, value = _parse_stix_pattern(pattern)

        return {
            "form": form,
            "value": value,
            "props": {},
            "tags": tags,
        }

    def stix_to_storm_add(self, stix_dict: Dict[str, Any]) -> str:
        """
        Convert a STIX indicator to a Storm ``[ form=value ]`` add query.

        Parameters
        ----------
        stix_dict : dict
            STIX 2.1 ``indicator`` object.

        Returns
        -------
        str
            Storm query string suitable for ``storm()`` execution.
        """
        node = self.stix_indicator_to_node(stix_dict)
        form = node["form"]
        value = node["value"]
        tags = node.get("tags", {})

        query = f"[{form}='{value}'"
        valid_from = stix_dict.get("valid_from")
        if valid_from:
            query += f" :seen='{valid_from}'"
        query += "]"

        for tag in tags:
            query += f" [+#{tag}]"

        return query


# ------------------------------------------------------------------
# Module-level pattern parser
# ------------------------------------------------------------------

_PATTERN_MAP: List[tuple] = [
    (r"ipv4-addr:value\s*=\s*['\"]([^'\"]+)['\"]",           "inet:ipv4"),
    (r"ipv6-addr:value\s*=\s*['\"]([^'\"]+)['\"]",           "inet:ipv6"),
    (r"domain-name:value\s*=\s*['\"]([^'\"]+)['\"]",         "inet:fqdn"),
    (r"url:value\s*=\s*['\"]([^'\"]+)['\"]",                 "inet:url"),
    (r"email-addr:value\s*=\s*['\"]([^'\"]+)['\"]",          "inet:email"),
    # File hashes — unquoted dot notation  (file:hashes.SHA-256 = '…')
    (r"file:hashes\.MD5\s*=\s*['\"]([^'\"]+)['\"]",          "hash:md5"),
    (r"file:hashes\.SHA-1\s*=\s*['\"]([^'\"]+)['\"]",        "hash:sha1"),
    (r"file:hashes\.SHA-256\s*=\s*['\"]([^'\"]+)['\"]",      "hash:sha256"),
    (r"file:hashes\.SHA-512\s*=\s*['\"]([^'\"]+)['\"]",      "hash:sha256"),
    # File hashes — bracket notation  (file:hashes['SHA-256'] = '…')
    (r"file:hashes\[.MD5.\]\s*=\s*['\"]([^'\"]+)['\"]",      "hash:md5"),
    (r"file:hashes\[.SHA-1.\]\s*=\s*['\"]([^'\"]+)['\"]",    "hash:sha1"),
    (r"file:hashes\[.SHA-256.\]\s*=\s*['\"]([^'\"]+)['\"]",  "hash:sha256"),
    # File hashes — single-quoted key notation (file:hashes.'SHA-256' = '…')
    (r"file:hashes\.'MD5'\s*=\s*['\"]([^'\"]+)['\"]",        "hash:md5"),
    (r"file:hashes\.'SHA-1'\s*=\s*['\"]([^'\"]+)['\"]",      "hash:sha1"),
    (r"file:hashes\.'SHA-256'\s*=\s*['\"]([^'\"]+)['\"]",    "hash:sha256"),
    # Autonomous system
    (r"autonomous-system:number\s*=\s*(\d+)",                 "inet:asn"),
]


def _parse_stix_pattern(pattern: str) -> tuple:
    """
    Extract form and value from a simple STIX pattern string.

    Parameters
    ----------
    pattern : str
        STIX 2.1 pattern expression.

    Returns
    -------
    tuple of (str, str)
        ``(synapse_form, value)`` pair.  Falls back to
        ``("x-unknown", pattern)`` for unrecognised patterns.
    """
    for regex, form in _PATTERN_MAP:
        m = re.search(regex, pattern)
        if m:
            return form, m.group(1)
    return "x-unknown", pattern
