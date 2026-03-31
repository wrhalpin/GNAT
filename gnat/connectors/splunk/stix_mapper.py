"""
gnat.connectors.splunk.stix_mapper

STIX 2.1 ↔ Splunk field mapping layer.

This module bridges GNAT's STIX 2.1 ORM objects and Splunk's flat
KV store / threat intel field schemas.

## Direction A -- STIX -> Splunk (for threat intel ingestion)

GNAT STIX ORM objects are converted to Splunk KV store records
suitable for direct upsert into Splunk ES threat intel collections.

Supported STIX SDO/SCO types -> Splunk collection:
indicator          -> ip_intel / domain_intel / url_intel (by pattern type)
observed-data      -> ip_intel / domain_intel / url_intel / file_intel
ipv4-addr (SCO)    -> ip_intel
ipv6-addr (SCO)    -> ip_intel
domain-name (SCO)  -> domain_intel
url (SCO)          -> url_intel
file (SCO)         -> file_intel
email-addr (SCO)   -> email_intel
process (SCO)      -> process_intel
windows-registry-key (SCO) -> registry_intel
x509-certificate (SCO)     -> certificate_intel
user-account (SCO) -> user_intel

NOT supported (Splunk limitation):

- STIX indicator pattern syntax (`[ipv4-addr:value = ...]`)
  The pattern field is stored as-is but not evaluated by Splunk.
- Relationships (SROs) -- no mapping path in Splunk KV store
- Threat actors, campaigns, attack patterns, malware (SDOs)
  These require custom KV store schemas if desired.

## Direction B -- Splunk results -> STIX (for data export from Splunk)

Search result rows from Splunk's notable / threat events are converted
to STIX 2.1 Observed Data SCO bundles for downstream GNAT processing.

Field mapping tables are based on Splunk's CIM (Common Information Model)
field names as they appear in search results.

## References

- https://docs.splunk.com/Documentation/CIM/latest/User/Overview
- https://docs.splunk.com/Documentation/ES/latest/Admin/Threatsources
- https://stix2.readthedocs.io/en/latest/
  """

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from .exceptions import SplunkSTIXError

# ── Splunk ES intel field schemas ─────────────────────────────────────────────

# Maps STIX SCO property names to Splunk KV store field names per collection.

# Key: stix_property, Value: splunk_field_name

_IP_FIELD_MAP: dict[str, str] = {
"value": "ip",
"x_gnat_description": "description",
"x_gnat_threat_type": "threat_key",
"x_gnat_weight": "weight",
}

_DOMAIN_FIELD_MAP: dict[str, str] = {
"value": "domain",
"x_gnat_description": "description",
"x_gnat_threat_type": "threat_key",
"x_gnat_weight": "weight",
}

_URL_FIELD_MAP: dict[str, str] = {
"value": "url",
"x_gnat_description": "description",
"x_gnat_threat_type": "threat_key",
"x_gnat_weight": "weight",
}

_FILE_FIELD_MAP: dict[str, str] = {
"name": "file_name",
"hashes.MD5": "md5",
"hashes.SHA-1": "sha1",
"hashes.SHA-256": "sha256",
"x_gnat_description": "description",
"x_gnat_threat_type": "threat_key",
"x_gnat_weight": "weight",
}

_EMAIL_FIELD_MAP: dict[str, str] = {
"value": "src_user",
"display_name": "user",
"x_gnat_description": "description",
"x_gnat_threat_type": "threat_key",
"x_gnat_weight": "weight",
}

_PROCESS_FIELD_MAP: dict[str, str] = {
"name": "process",
"command_line": "process_exec",
"x_gnat_description": "description",
"x_gnat_threat_type": "threat_key",
"x_gnat_weight": "weight",
}

_REGISTRY_FIELD_MAP: dict[str, str] = {
"key": "registry_key_name",
"x_gnat_description": "description",
"x_gnat_threat_type": "threat_key",
"x_gnat_weight": "weight",
}

_CERT_FIELD_MAP: dict[str, str] = {
"hashes.SHA-256": "ssl_hash",
"serial_number": "ssl_serial",
"subject": "ssl_subject",
"issuer": "ssl_issuer",
"x_gnat_description": "description",
"x_gnat_threat_type": "threat_key",
"x_gnat_weight": "weight",
}

_USER_FIELD_MAP: dict[str, str] = {
"user_id": "user",
"account_login": "src_user",
"x_gnat_description": "description",
"x_gnat_threat_type": "threat_key",
"x_gnat_weight": "weight",
}

# Map STIX SCO type -> (collection_key, field_map)

_SCO_COLLECTION_MAP: dict[str, tuple[str, dict]] = {
"ipv4-addr": ("ip", _IP_FIELD_MAP),
"ipv6-addr": ("ip", _IP_FIELD_MAP),
"domain-name": ("domain", _DOMAIN_FIELD_MAP),
"url": ("url", _URL_FIELD_MAP),
"file": ("file", _FILE_FIELD_MAP),
"email-addr": ("email", _EMAIL_FIELD_MAP),
"process": ("process", _PROCESS_FIELD_MAP),
"windows-registry-key": ("registry", _REGISTRY_FIELD_MAP),
"x509-certificate": ("certificate", _CERT_FIELD_MAP),
"user-account": ("user", _USER_FIELD_MAP),
}

class SplunkSTIXMapper:
    """
    Bidirectional mapper between STIX 2.1 objects and Splunk KV store records.

    This class does NOT import the GNAT STIX ORM directly to avoid
    circular imports. It operates on plain dicts that conform to the
    STIX 2.1 JSON representation, which is what the GNAT ORM produces
    via its ``.to_dict()`` / ``.serialize()`` methods.

    Usage
    -----
    mapper = SplunkSTIXMapper()

    # STIX -> Splunk
    records = mapper.stix_objects_to_splunk_records(stix_objects)
    # -> [{"collection": "ip", "record": {"ip": "1.2.3.4", ...}}, ...]

    # Splunk search row -> STIX
    bundle = mapper.splunk_notable_to_stix_bundle(notable_row)
    """

    # ── STIX -> Splunk ──────────────────────────────────────────────────────

    def stix_objects_to_splunk_records(
        self,
        stix_objects: list[dict],
        default_weight: int = 50,
    ) -> list[dict[str, Any]]:
        """
        Convert a list of STIX 2.1 object dicts to Splunk KV store records.

        Parameters
        ----------
        stix_objects : list[dict]
            List of STIX 2.1 object dicts (from ORM ``.to_dict()``).
        default_weight : int
            Default threat intel weight to assign if not present in the object.

        Returns
        -------
        list[dict]
            Each item has keys:
              - ``collection`` -- Splunk intel collection key (e.g. 'ip')
              - ``record``     -- Flat dict ready for KV store upsert

        Raises
        ------
        SplunkSTIXError
            If an unsupported STIX object type is encountered.
        """
        results = []
        for obj in stix_objects:
            obj_type = obj.get("type", "")
            if obj_type in _SCO_COLLECTION_MAP:
                record_info = self._sco_to_record(obj, default_weight)
            elif obj_type == "indicator":
                record_info = self._indicator_to_record(obj, default_weight)
            elif obj_type == "observed-data":
                # observed-data wraps refs to SCOs; expand each ref
                nested = self._extract_observed_data_objects(obj)
                for nested_obj in nested:
                    try:
                        record_info = self._sco_to_record(
                            nested_obj, default_weight
                        )
                        results.append(record_info)
                    except SplunkSTIXError:
                        pass
                continue
            else:
                # Unsupported SDOs (threat-actor, malware, etc.)
                raise SplunkSTIXError(
                    f"STIX type '{obj_type}' has no Splunk KV store mapping. "
                    "Skipping. Use upload_stix_file() for STIX bundle upload."
                )
            results.append(record_info)

        return results

    def stix_bundle_to_splunk_records(
        self,
        bundle: dict,
        default_weight: int = 50,
    ) -> list[dict[str, Any]]:
        """
        Convenience wrapper: convert a full STIX 2.1 bundle dict.

        Parameters
        ----------
        bundle : dict
            STIX 2.1 bundle with ``type: "bundle"`` and ``objects`` list.
        default_weight : int
            Default weight for unmapped objects.

        Returns
        -------
        list[dict]
            Splunk KV store records.
        """
        if bundle.get("type") != "bundle":
            raise SplunkSTIXError(
                "Expected a STIX 2.1 bundle (type='bundle'). "
                f"Got type='{bundle.get('type')}'."
            )
        return self.stix_objects_to_splunk_records(
            bundle.get("objects", []),
            default_weight=default_weight,
        )

    # ── Splunk -> STIX ──────────────────────────────────────────────────────

    def splunk_notable_to_stix_bundle(self, notable: dict) -> dict:
        """
        Convert a Splunk ES notable event row to a minimal STIX 2.1 bundle.

        Produces a bundle containing:
          - One ``observed-data`` SDO wrapping the notable's observables
          - ``ipv4-addr`` SCOs for src/dest fields
          - ``user-account`` SCO for the user field

        Parameters
        ----------
        notable : dict
            Normalised notable event dict from ``SplunkAlertCommands``.

        Returns
        -------
        dict
            STIX 2.1 bundle dict.
        """
        now_ts = _now_stix_ts()
        objects: list[dict] = []
        refs: list[str] = []

        # src IP
        if src := notable.get("src"):
            ip_id = f"ipv4-addr--{_deterministic_uuid('ipv4-addr', src)}"
            objects.append({"type": "ipv4-addr", "id": ip_id, "value": src})
            refs.append(ip_id)

        # dest IP
        if (dest := notable.get("dest")) and dest != notable.get("src"):
            dst_id = f"ipv4-addr--{_deterministic_uuid('ipv4-addr', dest)}"
            objects.append({"type": "ipv4-addr", "id": dst_id, "value": dest})
            refs.append(dst_id)

        # user account
        if user := notable.get("user"):
            user_id = f"user-account--{_deterministic_uuid('user-account', user)}"
            objects.append({
                "type": "user-account",
                "id": user_id,
                "user_id": user,
            })
            refs.append(user_id)

        # observed-data SDO
        observed_id = f"observed-data--{str(uuid.uuid4())}"
        observed = {
            "type": "observed-data",
            "id": observed_id,
            "spec_version": "2.1",
            "created": now_ts,
            "modified": now_ts,
            "first_observed": notable.get("timestamp") or now_ts,
            "last_observed": notable.get("timestamp") or now_ts,
            "number_observed": 1,
            "object_refs": refs,
            "x_gnat_source": "splunk_es",
            "x_gnat_rule_name": notable.get("rule_name"),
            "x_gnat_urgency": notable.get("urgency"),
            "x_gnat_severity": notable.get("severity"),
            "x_gnat_event_id": notable.get("event_id"),
        }
        objects.append(observed)

        return {
            "type": "bundle",
            "id": f"bundle--{str(uuid.uuid4())}",
            "spec_version": "2.1",
            "objects": objects,
        }

    def splunk_search_rows_to_stix_bundle(
        self,
        rows: list[dict],
        first_observed: str | None = None,
        last_observed: str | None = None,
    ) -> dict:
        """
        Convert a list of Splunk search result rows to a STIX 2.1 bundle.

        This is a best-effort mapper using CIM field name heuristics.
        Field detection order:
          src_ip / src -> ipv4-addr
          dest_ip / dest -> ipv4-addr
          url / http_url -> url
          domain / dns_query -> domain-name
          md5 / sha256 -> file
          src_user / user -> user-account

        Parameters
        ----------
        rows : list[dict]
            Splunk search result row dicts.
        first_observed : str | None
            ISO 8601 timestamp. Defaults to now.
        last_observed : str | None
            ISO 8601 timestamp. Defaults to now.

        Returns
        -------
        dict
            STIX 2.1 bundle.
        """
        now_ts = _now_stix_ts()
        fo = first_observed or now_ts
        lo = last_observed or now_ts
        objects: list[dict] = []
        seen: set[str] = set()

        for row in rows:
            refs: list[str] = []

            # IPs
            for field in ("src_ip", "src", "source_ip"):
                if val := row.get(field):
                    uid = f"ipv4-addr--{_deterministic_uuid('ipv4-addr', val)}"
                    if uid not in seen:
                        seen.add(uid)
                        objects.append({"type": "ipv4-addr", "id": uid, "value": val})
                    refs.append(uid)
                    break

            for field in ("dest_ip", "dest", "destination_ip"):
                if val := row.get(field):
                    uid = f"ipv4-addr--{_deterministic_uuid('ipv4-addr', val)}"
                    if uid not in seen:
                        seen.add(uid)
                        objects.append({"type": "ipv4-addr", "id": uid, "value": val})
                    refs.append(uid)
                    break

            # Domain
            for field in ("domain", "dns_query", "query"):
                if val := row.get(field):
                    uid = f"domain-name--{_deterministic_uuid('domain-name', val)}"
                    if uid not in seen:
                        seen.add(uid)
                        objects.append({"type": "domain-name", "id": uid, "value": val})
                    refs.append(uid)
                    break

            # URL
            for field in ("url", "http_url", "uri_path"):
                if val := row.get(field):
                    uid = f"url--{_deterministic_uuid('url', val)}"
                    if uid not in seen:
                        seen.add(uid)
                        objects.append({"type": "url", "id": uid, "value": val})
                    refs.append(uid)
                    break

            # File hashes
            hashes: dict = {}
            if md5 := row.get("md5"):
                hashes["MD5"] = md5
            if sha1 := row.get("sha1"):
                hashes["SHA-1"] = sha1
            if sha256 := row.get("sha256"):
                hashes["SHA-256"] = sha256
            if hashes:
                key_val = next(iter(hashes.values()))
                uid = f"file--{_deterministic_uuid('file', key_val)}"
                if uid not in seen:
                    seen.add(uid)
                    file_obj: dict = {
                        "type": "file",
                        "id": uid,
                        "hashes": hashes,
                    }
                    if name := row.get("file_name"):
                        file_obj["name"] = name
                    objects.append(file_obj)
                refs.append(uid)

            # User
            for field in ("src_user", "user", "user_name"):
                if val := row.get(field):
                    uid = f"user-account--{_deterministic_uuid('user-account', val)}"
                    if uid not in seen:
                        seen.add(uid)
                        objects.append({
                            "type": "user-account",
                            "id": uid,
                            "user_id": val,
                        })
                    refs.append(uid)
                    break

            if refs:
                obs_id = f"observed-data--{str(uuid.uuid4())}"
                objects.append({
                    "type": "observed-data",
                    "id": obs_id,
                    "spec_version": "2.1",
                    "created": now_ts,
                    "modified": now_ts,
                    "first_observed": fo,
                    "last_observed": lo,
                    "number_observed": 1,
                    "object_refs": refs,
                    "x_gnat_source": "splunk_search",
                    "x_gnat_raw": row,
                })

        return {
            "type": "bundle",
            "id": f"bundle--{str(uuid.uuid4())}",
            "spec_version": "2.1",
            "objects": objects,
        }

    # ── Internal helpers ───────────────────────────────────────────────────

    def _sco_to_record(
        self,
        obj: dict,
        default_weight: int,
    ) -> dict[str, Any]:
        """Convert a single STIX SCO dict to a Splunk KV store record dict."""
        obj_type = obj.get("type", "")
        mapping = _SCO_COLLECTION_MAP.get(obj_type)
        if not mapping:
            raise SplunkSTIXError(
                f"STIX type '{obj_type}' is not supported by Splunk. "
                f"Supported types: {list(_SCO_COLLECTION_MAP)}"
            )
        collection_key, field_map = mapping
        record = self._map_fields(obj, field_map, default_weight)
        record.setdefault("_key", obj.get("id", str(uuid.uuid4())))
        return {"collection": collection_key, "record": record}

    def _indicator_to_record(
        self,
        obj: dict,
        default_weight: int,
    ) -> dict[str, Any]:
        """
        Convert a STIX indicator to a Splunk KV store record.

        Splunk does not evaluate STIX patterns, so this extracts
        metadata from the indicator and stores the pattern as a string
        for reference. Collection is determined by indicator_types
        heuristic or defaults to 'ip'.
        """
        indicator_types = obj.get("indicator_types", [])
        # Heuristic: pick collection from indicator_types
        collection = "ip"
        type_hints = {
            "malicious-url": "url",
            "benign": "ip",
            "anonymization": "ip",
            "attribution": "domain",
            "compromised": "ip",
        }
        for itype in indicator_types:
            if itype in type_hints:
                collection = type_hints[itype]
                break

        record: dict = {
            "_key": obj.get("id", str(uuid.uuid4())),
            "description": obj.get("description", obj.get("name", "")),
            "threat_key": ",".join(indicator_types) if indicator_types else "",
            "weight": str(obj.get("x_gnat_weight", default_weight)),
            "stix_pattern": obj.get("pattern", ""),  # stored, not evaluated
            "stix_id": obj.get("id", ""),
            "valid_from": obj.get("valid_from", ""),
            "valid_until": obj.get("valid_until", ""),
        }
        # Try to extract an observable value from the pattern string
        self._extract_pattern_value(obj.get("pattern", ""), collection, record)
        return {"collection": collection, "record": record}

    @staticmethod
    def _extract_pattern_value(
        pattern: str,
        collection: str,
        record: dict,
    ) -> None:
        """
        Best-effort extraction of a plain value from a STIX pattern string.

        Only handles simple single-comparison patterns like:
          [ipv4-addr:value = '1.2.3.4']
          [domain-name:value = 'evil.com']
          [url:value = 'https://evil.com/path']
        """
        import re
        match = re.search(r"=\s*'([^']+)'", pattern)
        if not match:
            return
        value = match.group(1)
        field_hints = {
            "ip": "ip",
            "domain": "domain",
            "url": "url",
            "file": "sha256",
            "email": "src_user",
        }
        if field := field_hints.get(collection):
            record.setdefault(field, value)

    @staticmethod
    def _map_fields(
        obj: dict,
        field_map: dict[str, str],
        default_weight: int,
    ) -> dict:
        """Apply a field mapping dict to a STIX object dict."""
        record: dict = {}
        for stix_field, splunk_field in field_map.items():
            if "." in stix_field:
                # Nested field (e.g. hashes.MD5)
                parts = stix_field.split(".", 1)
                val = obj.get(parts[0], {})
                if isinstance(val, dict):
                    val = val.get(parts[1])
                else:
                    val = None
            else:
                val = obj.get(stix_field)

            if val is not None:
                record[splunk_field] = str(val)

        record.setdefault("weight", str(default_weight))
        return record

    @staticmethod
    def _extract_observed_data_objects(obj: dict) -> list[dict]:
        """
        Extract referenced SCO objects from an observed-data SDO.

        GNAT's STIX ORM inlines the SCO dicts under ``object_refs``
        when serialized for transport. If the ORM uses ID references
        only, this returns an empty list (caller skips).
        """
        refs = obj.get("object_refs", [])
        # If refs are dicts (inlined), return them directly
        return [r for r in refs if isinstance(r, dict)]



# ── Module-level utility functions ────────────────────────────────────────────

def _deterministic_uuid(stix_type: str, value: str) -> str:
    """
    Generate a deterministic UUID5 for a STIX object.

    Uses the STIX 2.1 spec namespace UUID for identity objects.
    Ensures the same (type, value) pair always produces the same ID,
    enabling deduplication without round-tripping to the platform.
    """
    STIX_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")
    return str(uuid.uuid5(STIX_NAMESPACE, f"{stix_type}:{value}"))


def _now_stix_ts() -> str:
    """Return current UTC time in STIX 2.1 timestamp format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
