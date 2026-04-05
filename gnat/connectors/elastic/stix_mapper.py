"""
gnat.connectors.elastic.stix_mapper

STIX 2.1 ↔ Elastic Common Schema (ECS) bidirectional mapping.

Elastic Security uses ECS as its normalisation layer. This mapper
bridges GNAT's STIX 2.1 ORM objects and Elastic's ECS schema.

## Direction A -- STIX -> ECS (for threat intel upload to Elastic)

STIX SCO / indicator objects -> ECS `threat.indicator.*` documents
suitable for indexing into `logs-ti_*` data streams.

Supported STIX types -> ECS:
ipv4-addr     -> threat.indicator.type: 'ipv4-addr'
threat.indicator.ip: <value>
ipv6-addr     -> threat.indicator.type: 'ipv6-addr'
threat.indicator.ip: <value>
domain-name   -> threat.indicator.type: 'domain-name'
threat.indicator.domain: <value>
url           -> threat.indicator.type: 'url'
threat.indicator.url.full: <value>
file          -> threat.indicator.type: 'file'
threat.indicator.file.hash.{md5,sha1,sha256}: <values>
threat.indicator.file.name: <name>
email-addr    -> threat.indicator.type: 'email-addr'
threat.indicator.email.address: <value>
indicator SDO -> type determined by pattern content
+ threat.indicator.description, confidence, first_seen

## Direction B -- ECS -> STIX (for export from Elastic to GNAT ORM)

ECS `threat.indicator.*` documents -> STIX 2.1 indicator SDOs
or SCOs depending on the indicator type.

## Direction C -- ECS alert event -> STIX observed-data bundle

Kibana security alert fields -> STIX observed-data wrapping:
host.ip / source.ip / destination.ip -> ipv4-addr SCOs
user.name -> user-account SCO
process.name -> process SCO
url.full / url.domain -> url / domain-name SCOs
file.hash.* -> file SCO

## References

- https://www.elastic.co/guide/en/ecs/current/ecs-threat.html
- https://stix2.readthedocs.io/en/latest/
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from .exceptions import ElasticSTIXError

_STIX_NS = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")

# STIX confidence integer (0-100) -> ECS label

_CONFIDENCE_LABEL = {
    range(75, 101): "High",
    range(50, 75): "Medium",
    range(25, 50): "Low",
}

# ECS indicator type -> STIX SCO type

_ECS_TO_STIX_TYPE = {
    "ipv4-addr": "ipv4-addr",
    "ipv6-addr": "ipv6-addr",
    "domain-name": "domain-name",
    "url": "url",
    "file": "file",
    "email-addr": "email-addr",
    "windows-registry-key": "windows-registry-key",
    "x509-certificate": "x509-certificate",
    "autonomous-system": "autonomous-system",
    "user-account": "user-account",
    "process": "process",
}


class ElasticSTIXMapper:
    """
    Bidirectional mapper between STIX 2.1 and Elastic ECS.

    Operates on plain Python dicts (from GNAT ORM .to_dict()
    or ElasticClient search results).

    Usage
    -----
    mapper = ElasticSTIXMapper()

    # STIX bundle -> ECS indicator docs
    ecs_docs = mapper.stix_bundle_to_ecs_indicators(bundle, provider="GNAT")

    # ECS indicator doc -> STIX indicator SDO
    stix_obj = mapper.ecs_indicator_to_stix(ecs_doc)

    # Kibana alert -> STIX observed-data bundle
    bundle = mapper.alert_to_stix_bundle(normalised_alert)
    """

    # ── STIX -> ECS ────────────────────────────────────────────────────────

    def stix_bundle_to_ecs_indicators(
        self,
        bundle: dict,
        provider: str = "gnat",
        feed_name: str = "GNAT",
    ) -> list[dict]:
        """
        Convert a STIX 2.1 bundle to a list of ECS indicator documents.

        Parameters
        ----------
        bundle : dict
            STIX 2.1 bundle with ``type: "bundle"`` and ``objects``.
        provider : str
            Value for threat.indicator.provider.
        feed_name : str
            Value for threat.feed.name.

        Returns
        -------
        list[dict]
            ECS-formatted documents ready for Elasticsearch indexing.

        Raises
        ------
        ElasticSTIXError
            If the bundle is malformed.
        """
        if bundle.get("type") != "bundle":
            raise ElasticSTIXError(f"Expected STIX bundle, got type='{bundle.get('type')}'.")
        docs: list[dict] = []
        for obj in bundle.get("objects", []):
            obj_type = obj.get("type", "")
            try:
                if obj_type in (
                    "ipv4-addr",
                    "ipv6-addr",
                    "domain-name",
                    "url",
                    "file",
                    "email-addr",
                ):
                    doc = self._sco_to_ecs(obj, provider, feed_name)
                    if doc:
                        docs.append(doc)
                elif obj_type == "indicator":
                    doc = self._indicator_sdo_to_ecs(obj, provider, feed_name)
                    if doc:
                        docs.append(doc)
                # Skip SROs, identity, bundle-level objects silently
            except ElasticSTIXError:
                raise
            except Exception as exc:
                raise ElasticSTIXError(f"Failed to map STIX object {obj.get('id')}: {exc}") from exc
        return docs

    def stix_object_to_ecs_indicator(
        self,
        obj: dict,
        provider: str = "gnat",
        feed_name: str = "GNAT",
    ) -> dict | None:
        """
        Convert a single STIX object to an ECS indicator doc.

        Parameters
        ----------
        obj : dict
            STIX object dict.
        provider : str
            Threat indicator provider name.
        feed_name : str
            Threat feed name.

        Returns
        -------
        dict | None
            ECS doc, or None if the type is not mappable.
        """
        obj_type = obj.get("type", "")
        if obj_type in ("ipv4-addr", "ipv6-addr", "domain-name", "url", "file", "email-addr"):
            return self._sco_to_ecs(obj, provider, feed_name)
        if obj_type == "indicator":
            return self._indicator_sdo_to_ecs(obj, provider, feed_name)
        return None

    # ── ECS -> STIX ────────────────────────────────────────────────────────

    def ecs_indicator_to_stix(self, doc: dict) -> dict | None:
        """
        Convert an ECS threat indicator document to a STIX 2.1 object.

        Parameters
        ----------
        doc : dict
            ECS indicator source document with ``threat.indicator.*`` fields.

        Returns
        -------
        dict | None
            STIX 2.1 indicator SDO, or None if type cannot be determined.
        """
        ti = doc.get("threat", {}).get("indicator", {})
        now = _now_ts()
        indicator_type = ti.get("type", "")
        if not indicator_type:
            return None

        # Build a simple STIX pattern from the ECS value
        pattern, value = self._build_pattern(indicator_type, ti)
        if not pattern:
            return None

        stix_id = f"indicator--{_det_uuid('indicator', f'{indicator_type}:{value}')}"
        obj: dict = {
            "type": "indicator",
            "id": stix_id,
            "spec_version": "2.1",
            "created": ti.get("first_seen") or now,
            "modified": ti.get("last_seen") or now,
            "name": ti.get("description") or f"{indicator_type}: {value}",
            "description": ti.get("description", ""),
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": ti.get("first_seen") or now,
            "indicator_types": ["malicious-activity"],
        }
        if ti.get("valid_until") or ti.get("last_seen"):
            obj["valid_until"] = ti.get("last_seen")
        if ref := ti.get("reference"):
            obj["external_references"] = [
                {"source_name": ti.get("provider", "unknown"), "url": ref}
            ]
        return obj

    def ecs_indicators_to_stix_bundle(self, docs: list[dict]) -> dict:
        """
        Convert a list of ECS indicator documents to a STIX 2.1 bundle.

        Parameters
        ----------
        docs : list[dict]
            ECS indicator source documents.

        Returns
        -------
        dict
            STIX 2.1 bundle.
        """
        objects: list[dict] = []
        seen: set[str] = set()
        for doc in docs:
            obj = self.ecs_indicator_to_stix(doc)
            if obj and obj["id"] not in seen:
                seen.add(obj["id"])
                objects.append(obj)
        return _make_bundle(objects)

    # ── Alert -> STIX ──────────────────────────────────────────────────────

    def alert_to_stix_bundle(self, alert: dict) -> dict:
        """
        Convert a normalised Kibana security alert to a STIX 2.1 bundle.

        Produces observed-data SDO wrapping SCOs built from ECS fields.

        Parameters
        ----------
        alert : dict
            Normalised alert from KibanaAlertsCommands.normalise_alert().

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

        # Source IP
        if src := alert.get("src_ip"):
            obj = _ipv4(src)
            if obj["id"] not in seen:
                seen.add(obj["id"])
                objects.append(obj)
            refs.append(obj["id"])

        # Dest IP
        if dst := alert.get("dest_ip"):
            obj = _ipv4(dst)
            if obj["id"] not in seen:
                seen.add(obj["id"])
                objects.append(obj)
            refs.append(obj["id"])

        # Host IPs
        raw = alert.get("_raw", {})
        for hip in _listify(raw.get("host", {}).get("ip")):
            obj = _ipv4(hip)
            if obj["id"] not in seen:
                seen.add(obj["id"])
                objects.append(obj)
            refs.append(obj["id"])

        # User
        if user := alert.get("user_name"):
            obj = _user_account(user)
            if obj["id"] not in seen:
                seen.add(obj["id"])
                objects.append(obj)
            refs.append(obj["id"])

        # Process
        if proc := alert.get("process_name"):
            obj = _process(proc)
            if obj["id"] not in seen:
                seen.add(obj["id"])
                objects.append(obj)
            refs.append(obj["id"])

        # URL / domain
        url_full = raw.get("url", {}).get("full")
        url_domain = raw.get("url", {}).get("domain")
        if url_full:
            obj = _url(url_full)
            if obj["id"] not in seen:
                seen.add(obj["id"])
                objects.append(obj)
            refs.append(obj["id"])
        elif url_domain:
            obj = _domain(url_domain)
            if obj["id"] not in seen:
                seen.add(obj["id"])
                objects.append(obj)
            refs.append(obj["id"])

        # File
        file_info = raw.get("file", {})
        hashes: dict = {}
        if md5 := file_info.get("hash", {}).get("md5"):
            hashes["MD5"] = md5
        if sha256 := file_info.get("hash", {}).get("sha256"):
            hashes["SHA-256"] = sha256
        if hashes:
            key = next(iter(hashes.values()))
            fid = f"file--{_det_uuid('file', key)}"
            file_obj: dict = {"type": "file", "id": fid, "spec_version": "2.1"}
            if hashes:
                file_obj["hashes"] = hashes
            if fname := file_info.get("name"):
                file_obj["name"] = fname
            if fid not in seen:
                seen.add(fid)
                objects.append(file_obj)
            refs.append(fid)

        # Observed-data SDO
        obs_id = f"observed-data--{uuid.uuid4()}"
        rule_name = alert.get("rule_name") or ""
        objects.append(
            {
                "type": "observed-data",
                "id": obs_id,
                "spec_version": "2.1",
                "created": now,
                "modified": now,
                "first_observed": ts,
                "last_observed": ts,
                "number_observed": 1,
                "object_refs": refs,
                "x_elastic_alert": {
                    "rule_name": rule_name,
                    "rule_id": alert.get("rule_id"),
                    "severity": alert.get("severity"),
                    "severity_label": alert.get("severity_label"),
                    "severity_score": alert.get("severity_score"),
                    "status": alert.get("status"),
                    "reason": alert.get("reason"),
                    "host_name": alert.get("host_name"),
                },
            }
        )
        return _make_bundle(objects)

    def alerts_to_stix_bundle(self, alerts: list[dict]) -> dict:
        """
        Convert multiple normalised alerts to a single deduplicated bundle.

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
        seen: set[str] = set()
        for alert in alerts:
            for obj in self.alert_to_stix_bundle(alert).get("objects", []):
                if obj["id"] not in seen:
                    seen.add(obj["id"])
                    all_objects.append(obj)
        return _make_bundle(all_objects)

    # ── Internal helpers ───────────────────────────────────────────────────

    def _sco_to_ecs(
        self,
        obj: dict,
        provider: str,
        feed_name: str,
    ) -> dict | None:
        """Convert a STIX SCO to an ECS threat indicator document."""
        obj_type = obj.get("type", "")
        now = _now_ts()
        base: dict = {
            "@timestamp": now,
            "event": {"category": "threat", "kind": "enrichment", "type": ["indicator"]},
            "threat": {
                "indicator": {
                    "type": obj_type,
                    "provider": provider,
                    "first_seen": now,
                    "last_seen": now,
                    "confidence": "Not Specified",
                },
                "feed": {"name": feed_name},
            },
        }
        ti = base["threat"]["indicator"]

        if obj_type in ("ipv4-addr", "ipv6-addr"):
            value = obj.get("value")
            if not value:
                return None
            ti["ip"] = value

        elif obj_type == "domain-name":
            value = obj.get("value")
            if not value:
                return None
            ti["domain"] = value

        elif obj_type == "url":
            value = obj.get("value")
            if not value:
                return None
            ti["url"] = {"full": value}
            # Try to extract domain from URL
            try:
                from urllib.parse import urlparse

                parsed = urlparse(value)
                if parsed.netloc:
                    ti["url"]["domain"] = parsed.netloc
            except Exception:
                pass

        elif obj_type == "file":
            hashes = obj.get("hashes", {})
            file_dict: dict = {}
            if md5 := hashes.get("MD5"):
                file_dict.setdefault("hash", {})["md5"] = md5
            if sha1 := hashes.get("SHA-1"):
                file_dict.setdefault("hash", {})["sha1"] = sha1
            if sha256 := hashes.get("SHA-256"):
                file_dict.setdefault("hash", {})["sha256"] = sha256
            if name := obj.get("name"):
                file_dict["name"] = name
            if not file_dict:
                return None
            ti["file"] = file_dict

        elif obj_type == "email-addr":
            value = obj.get("value")
            if not value:
                return None
            ti["email"] = {"address": value}

        else:
            return None

        # Common STIX metadata
        if stix_id := obj.get("id"):
            base.setdefault("labels", {})["stix_id"] = stix_id

        return base

    def _indicator_sdo_to_ecs(
        self,
        obj: dict,
        provider: str,
        feed_name: str,
    ) -> dict | None:
        """Convert a STIX indicator SDO to an ECS threat indicator document."""
        pattern = obj.get("pattern", "")
        now = _now_ts()

        # Determine indicator type from pattern
        type_hints = {
            "ipv4-addr:value": "ipv4-addr",
            "ipv6-addr:value": "ipv6-addr",
            "domain-name:value": "domain-name",
            "url:value": "url",
            "file:hashes": "file",
            "email-addr:value": "email-addr",
        }
        indicator_type = "unknown"
        for hint, itype in type_hints.items():
            if hint in pattern:
                indicator_type = itype
                break

        # Extract value from simple pattern
        import re

        value_match = re.search(r"=\s*'([^']+)'", pattern)
        value = value_match.group(1) if value_match else ""

        # Build confidence label
        conf_int = obj.get("confidence")
        confidence_label = "Not Specified"
        if conf_int is not None:
            for r, label in _CONFIDENCE_LABEL.items():
                if conf_int in r:
                    confidence_label = label
                    break

        base: dict = {
            "@timestamp": obj.get("created") or now,
            "event": {"category": "threat", "kind": "enrichment", "type": ["indicator"]},
            "threat": {
                "indicator": {
                    "type": indicator_type,
                    "provider": provider,
                    "description": obj.get("description") or obj.get("name", ""),
                    "first_seen": obj.get("valid_from") or now,
                    "last_seen": obj.get("valid_until") or now,
                    "confidence": confidence_label,
                },
                "feed": {"name": feed_name},
            },
            "labels": {
                "stix_id": obj.get("id", ""),
                "stix_pattern": pattern,
            },
        }
        ti = base["threat"]["indicator"]

        if value:
            if indicator_type in ("ipv4-addr", "ipv6-addr"):
                ti["ip"] = value
            elif indicator_type == "domain-name":
                ti["domain"] = value
            elif indicator_type == "url":
                ti["url"] = {"full": value}
            elif indicator_type == "email-addr":
                ti["email"] = {"address": value}

        return base

    @staticmethod
    def _build_pattern(indicator_type: str, ti: dict) -> tuple[str, str]:
        """Build a STIX pattern string from an ECS threat indicator."""
        if indicator_type in ("ipv4-addr", "ipv6-addr"):
            value = ti.get("ip", "")
            return f"[{indicator_type}:value = '{value}']", value
        if indicator_type == "domain-name":
            value = ti.get("domain", "")
            return f"[domain-name:value = '{value}']", value
        if indicator_type == "url":
            value = ti.get("url", {}).get("full", "")
            return f"[url:value = '{value}']", value
        if indicator_type == "email-addr":
            value = ti.get("email", {}).get("address", "")
            return f"[email-addr:value = '{value}']", value
        if indicator_type == "file":
            sha256 = ti.get("file", {}).get("hash", {}).get("sha256", "")
            if sha256:
                return (
                    f"[file:hashes.'SHA-256' = '{sha256}']",
                    sha256,
                )
        return "", ""

    # ── STIX object factory helpers ───────────────────────────────────────────────


def _ipv4(value: str) -> dict:
    return {
        "type": "ipv4-addr",
        "id": f"ipv4-addr-{_det_uuid('ipv4-addr', value)}",
        "spec_version": "2.1",
        "value": value,
    }


def _domain(value: str) -> dict:
    return {
        "type": "domain-name",
        "id": f"domain-name-{_det_uuid('domain-name', value)}",
        "spec_version": "2.1",
        "value": value,
    }


def _url(value: str) -> dict:
    return {
        "type": "url",
        "id": f"url-{_det_uuid('url', value)}",
        "spec_version": "2.1",
        "value": value,
    }


def _user_account(user_id: str) -> dict:
    return {
        "type": "user-account",
        "id": f"user-account-{_det_uuid('user-account', user_id)}",
        "spec_version": "2.1",
        "user_id": user_id,
    }


def _process(name: str) -> dict:
    return {
        "type": "process",
        "id": f"process-{_det_uuid('process', name)}",
        "spec_version": "2.1",
        "name": name,
    }


def _make_bundle(objects: list[dict]) -> dict:
    return {
        "type": "bundle",
        "id": f"bundle-{uuid.uuid4()}",
        "spec_version": "2.1",
        "objects": objects,
    }


def _det_uuid(stix_type: str, value: str) -> str:
    return str(uuid.uuid5(_STIX_NS, f"{stix_type}:{value}"))


def _now_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _listify(val: Any) -> list:
    """Normalise a value that might be str, list, or None to a list."""
    if val is None:
        return []
    if isinstance(val, list):
        return val
    return [val]
