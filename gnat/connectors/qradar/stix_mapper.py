"""
ctm_sak.connectors.qradar.stix_mapper
========================================
STIX 2.1 mapping layer for the QRadar connector.

QRadar has no native STIX support. This mapper converts:

Direction A — QRadar → STIX (for export / downstream processing)
-----------------------------------------------------------------
  Offense record  → STIX observed-data SDO wrapping:
                     • ipv4-addr SCOs (offense_source IPs, src/dst)
                     • user-account SCO (username offenses)
                     • domain-name SCO (hostname offenses)
                     • network-traffic SCO (port/protocol offenses)
                    + x-qradar-offense custom extension on observed-data

  Ariel event row → STIX observed-data SDO wrapping:
                     • ipv4-addr SCOs (sourceip, destinationip)
                     • user-account SCO (username)
                     • network-traffic SCO (ports/protocol)
                    + x-qradar-event extension

Direction B — STIX → QRadar (for IOC ingestion into reference sets)
---------------------------------------------------------------------
  STIX 2.1 bundle → QRadar reference set entries grouped by type:
                      ipv4-addr / ipv6-addr values → IP reference set
                      domain-name values → ALN reference set
                      url values → ALN reference set
                      file hash values → ALN reference set
                      indicator SDOs → extracted value + type routing

  Returns a dict of {set_type: [values]} for the caller to push
  via QRadarReferenceDataCommands.

Extension naming
----------------
  x-qradar-offense  — offense metadata (id, magnitude, type, categories)
  x-qradar-event    — Ariel event metadata (logsourceid, category, qid)

References
----------
- https://www.ibm.com/docs/en/qradar-siem/7.5?topic=api-siem-offenses
"""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone

from .exceptions import QRadarSTIXError


_STIX_NS = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")
_SEVERITY_LABELS = {0: "informational", 1: "low", 2: "medium", 3: "high", 4: "critical"}


class QRadarSTIXMapper:
    """
    Bidirectional mapper between QRadar data structures and STIX 2.1.

    Usage
    -----
    mapper = QRadarSTIXMapper()

    # Offense → STIX bundle
    bundle = mapper.offense_to_stix_bundle(normalised_offense)

    # Ariel events → STIX bundle
    bundle = mapper.events_to_stix_bundle(event_rows)

    # STIX bundle → reference set IOC groups
    ioc_groups = mapper.stix_bundle_to_reference_sets(bundle)
    # → {"ip": ["1.2.3.4", "5.6.7.8"], "domain": ["evil.com"], "hash": [...]}
    """

    # ── A: QRadar → STIX ──────────────────────────────────────────────────

    def offense_to_stix_bundle(self, offense: dict) -> dict:
        """
        Convert a normalised QRadar offense to a STIX 2.1 bundle.

        Parameters
        ----------
        offense : dict
            Normalised offense from QRadarOffenseCommands.normalise_offense().

        Returns
        -------
        dict
            STIX 2.1 bundle.
        """
        now = _now_ts()
        ts = offense.get("start_time") or now
        objects: list[dict] = []
        refs: list[str] = []
        seen: set[str] = set()

        offense_type = offense.get("offense_type", 0)
        source = offense.get("offense_source", "")

        # ── Source observable based on offense_type ────────────────────
        if offense_type in (0, 11):  # Source IP / Post NAT Source IP
            if source and _looks_like_ip(source):
                obj = _ipv4(source)
                if obj["id"] not in seen:
                    seen.add(obj["id"])
                    objects.append(obj)
                refs.append(obj["id"])

        elif offense_type in (1, 12):  # Destination IP
            if source and _looks_like_ip(source):
                obj = _ipv4(source)
                if obj["id"] not in seen:
                    seen.add(obj["id"])
                    objects.append(obj)
                refs.append(obj["id"])

        elif offense_type == 3:  # Username
            if source:
                obj = _user_account(source)
                if obj["id"] not in seen:
                    seen.add(obj["id"])
                    objects.append(obj)
                refs.append(obj["id"])

        elif offense_type == 6:  # Hostname
            if source:
                obj = _domain(source)
                if obj["id"] not in seen:
                    seen.add(obj["id"])
                    objects.append(obj)
                refs.append(obj["id"])

        # ── Network traffic when port info is available ────────────────
        raw = offense.get("_raw", {})
        src_port = raw.get("local_destination_port")
        if src_port and offense_type in (7,):  # Port offense
            nt = _network_traffic_stub(str(src_port))
            if nt and nt["id"] not in seen:
                seen.add(nt["id"])
                objects.append(nt)
                refs.append(nt["id"])

        # ── Observed-data SDO ──────────────────────────────────────────
        magnitude = offense.get("magnitude", 0)
        severity = offense.get("severity", 0)
        obs_id = f"observed-data--{uuid.uuid4()}"
        objects.append({
            "type": "observed-data",
            "id": obs_id,
            "spec_version": "2.1",
            "created": now,
            "modified": now,
            "first_observed": ts,
            "last_observed": offense.get("last_updated_time") or ts,
            "number_observed": max(1, offense.get("event_count", 1)),
            "object_refs": refs,
            "x_qradar_offense": {
                "offense_id": offense.get("id"),
                "description": offense.get("description"),
                "status": offense.get("status"),
                "magnitude": magnitude,
                "severity": severity,
                "severity_label": offense.get("severity_label"),
                "offense_type": offense.get("offense_type"),
                "offense_type_label": offense.get("offense_type_label"),
                "offense_source": source,
                "event_count": offense.get("event_count"),
                "categories": offense.get("categories", []),
                "assigned_to": offense.get("assigned_to"),
            },
        })

        return _make_bundle(objects)

    def offenses_to_stix_bundle(self, offenses: list[dict]) -> dict:
        """
        Convert a list of normalised offenses to a single STIX bundle.

        Deduplicates shared SCOs (same IP appearing in multiple offenses).

        Parameters
        ----------
        offenses : list[dict]
            Normalised offense records.

        Returns
        -------
        dict
            Merged STIX 2.1 bundle.
        """
        all_objects: list[dict] = []
        seen: set[str] = set()
        for offense in offenses:
            for obj in self.offense_to_stix_bundle(offense).get("objects", []):
                if obj["id"] not in seen:
                    seen.add(obj["id"])
                    all_objects.append(obj)
        return _make_bundle(all_objects)

    def event_to_stix_bundle(self, event: dict) -> dict:
        """
        Convert a normalised Ariel event row to a STIX 2.1 bundle.

        Parameters
        ----------
        event : dict
            Normalised event row from QRadarArielCommands.normalise_event_row().

        Returns
        -------
        dict
            STIX 2.1 bundle.
        """
        now = _now_ts()
        ts = event.get("timestamp") or now
        objects: list[dict] = []
        refs: list[str] = []
        seen: set[str] = set()

        # Source IP
        if src := event.get("src_ip"):
            obj = _ipv4(src)
            if obj["id"] not in seen:
                seen.add(obj["id"])
                objects.append(obj)
            refs.append(obj["id"])

        # Destination IP
        if dst := event.get("dst_ip"):
            obj = _ipv4(dst)
            if obj["id"] not in seen:
                seen.add(obj["id"])
                objects.append(obj)
            refs.append(obj["id"])

        # Network traffic if both IPs + ports present
        src_port = event.get("src_port")
        dst_port = event.get("dst_port")
        if event.get("src_ip") and event.get("dst_ip") and (src_port or dst_port):
            net_id = f"network-traffic--{_det_uuid('network-traffic', f'{event.get(\"src_ip\")}:{src_port}-{event.get(\"dst_ip\")}:{dst_port}')}"
            if net_id not in seen:
                src_ref = f"ipv4-addr--{_det_uuid('ipv4-addr', event['src_ip'])}"
                dst_ref = f"ipv4-addr--{_det_uuid('ipv4-addr', event['dst_ip'])}"
                net_obj: dict = {
                    "type": "network-traffic",
                    "id": net_id,
                    "spec_version": "2.1",
                    "src_ref": src_ref,
                    "dst_ref": dst_ref,
                    "protocols": [str(event.get("protocol", "tcp")).lower()],
                }
                if src_port:
                    try:
                        net_obj["src_port"] = int(src_port)
                    except (ValueError, TypeError):
                        pass
                if dst_port:
                    try:
                        net_obj["dst_port"] = int(dst_port)
                    except (ValueError, TypeError):
                        pass
                seen.add(net_id)
                objects.append(net_obj)
                refs.append(net_id)

        # Username
        if user := event.get("username"):
            obj = _user_account(user)
            if obj["id"] not in seen:
                seen.add(obj["id"])
                objects.append(obj)
            refs.append(obj["id"])

        # Observed-data SDO
        obs_id = f"observed-data--{uuid.uuid4()}"
        objects.append({
            "type": "observed-data",
            "id": obs_id,
            "spec_version": "2.1",
            "created": now,
            "modified": now,
            "first_observed": ts,
            "last_observed": ts,
            "number_observed": max(1, int(event.get("event_count") or 1)),
            "object_refs": refs,
            "x_qradar_event": {
                "log_source_id": event.get("log_source_id"),
                "log_source": event.get("log_source"),
                "category": event.get("category"),
                "category_name": event.get("category_name"),
                "severity": event.get("severity"),
                "event_name": event.get("event_name"),
            },
        })

        return _make_bundle(objects)

    def events_to_stix_bundle(self, events: list[dict]) -> dict:
        """
        Convert a list of normalised Ariel events to a single STIX bundle.

        Parameters
        ----------
        events : list[dict]
            Normalised event rows.

        Returns
        -------
        dict
            Merged STIX 2.1 bundle.
        """
        all_objects: list[dict] = []
        seen: set[str] = set()
        for event in events:
            for obj in self.event_to_stix_bundle(event).get("objects", []):
                if obj["id"] not in seen:
                    seen.add(obj["id"])
                    all_objects.append(obj)
        return _make_bundle(all_objects)

    # ── B: STIX → QRadar reference set groups ─────────────────────────────

    def stix_bundle_to_reference_sets(
        self,
        bundle: dict,
    ) -> dict[str, list[str]]:
        """
        Extract IOC values from a STIX 2.1 bundle, grouped by QRadar
        reference set type.

        Parameters
        ----------
        bundle : dict
            STIX 2.1 bundle.

        Returns
        -------
        dict[str, list[str]]
            Keys:
              "ip"     — IPv4/IPv6 addresses (for IP element_type sets)
              "domain" — domain names (for ALN element_type sets)
              "url"    — URLs (for ALN element_type sets)
              "hash"   — file hashes (for ALN element_type sets)
              "email"  — email addresses (for ALN element_type sets)

        Raises
        ------
        QRadarSTIXError
            If the bundle is malformed.
        """
        if bundle.get("type") != "bundle":
            raise QRadarSTIXError(
                f"Expected STIX bundle, got type='{bundle.get('type')}'."
            )

        groups: dict[str, list[str]] = {
            "ip": [], "domain": [], "url": [], "hash": [], "email": []
        }

        for obj in bundle.get("objects", []):
            obj_type = obj.get("type", "")

            if obj_type in ("ipv4-addr", "ipv6-addr"):
                if v := obj.get("value"):
                    groups["ip"].append(v)

            elif obj_type == "domain-name":
                if v := obj.get("value"):
                    groups["domain"].append(v)

            elif obj_type == "url":
                if v := obj.get("value"):
                    groups["url"].append(v)

            elif obj_type == "email-addr":
                if v := obj.get("value"):
                    groups["email"].append(v)

            elif obj_type == "file":
                for algo in ("SHA-256", "SHA-1", "MD5"):
                    if v := obj.get("hashes", {}).get(algo):
                        groups["hash"].append(v)
                        break  # one hash per file object

            elif obj_type == "indicator":
                # Extract value from simple STIX patterns
                extracted = self._extract_from_pattern(obj.get("pattern", ""))
                for ioc_type, value in extracted:
                    groups.get(ioc_type, []).append(value)

        # Deduplicate each group
        return {k: list(dict.fromkeys(v)) for k, v in groups.items()}

    # ── Internal ───────────────────────────────────────────────────────────

    @staticmethod
    def _extract_from_pattern(pattern: str) -> list[tuple[str, str]]:
        """
        Extract (ioc_type, value) pairs from a STIX pattern string.

        Handles simple equality patterns:
          [ipv4-addr:value = '1.2.3.4']       → ('ip', '1.2.3.4')
          [domain-name:value = 'evil.com']     → ('domain', 'evil.com')
          [url:value = 'https://evil.com']     → ('url', 'https://evil.com')
          [file:hashes.'SHA-256' = 'abc123']   → ('hash', 'abc123')
          [email-addr:value = 'x@y.com']       → ('email', 'x@y.com')
        """
        results: list[tuple[str, str]] = []
        matches = re.findall(r"\[([^\]]+)\]", pattern)
        for clause in matches:
            # Extract value from  'type:field = 'value''
            m = re.search(r"=\s*'([^']+)'", clause)
            if not m:
                continue
            value = m.group(1)
            if "ipv4-addr" in clause or "ipv6-addr" in clause:
                results.append(("ip", value))
            elif "domain-name" in clause:
                results.append(("domain", value))
            elif "url:" in clause:
                results.append(("url", value))
            elif "email-addr" in clause:
                results.append(("email", value))
            elif "file:hashes" in clause:
                results.append(("hash", value))
        return results


# ── STIX object factory helpers ───────────────────────────────────────────────

def _ipv4(value: str) -> dict:
    return {
        "type": "ipv4-addr",
        "id": f"ipv4-addr--{_det_uuid('ipv4-addr', value)}",
        "spec_version": "2.1",
        "value": value,
    }


def _domain(value: str) -> dict:
    return {
        "type": "domain-name",
        "id": f"domain-name--{_det_uuid('domain-name', value)}",
        "spec_version": "2.1",
        "value": value,
    }


def _user_account(user_id: str) -> dict:
    return {
        "type": "user-account",
        "id": f"user-account--{_det_uuid('user-account', user_id)}",
        "spec_version": "2.1",
        "user_id": user_id,
    }


def _network_traffic_stub(dst_port: str) -> dict | None:
    try:
        nid = f"network-traffic--{_det_uuid('network-traffic', f'port:{dst_port}')}"
        return {
            "type": "network-traffic",
            "id": nid,
            "spec_version": "2.1",
            "dst_port": int(dst_port),
            "protocols": ["tcp"],
        }
    except (ValueError, TypeError):
        return None


def _make_bundle(objects: list[dict]) -> dict:
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "spec_version": "2.1",
        "objects": objects,
    }


def _det_uuid(stix_type: str, value: str) -> str:
    return str(uuid.uuid5(_STIX_NS, f"{stix_type}:{value}"))


def _now_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _looks_like_ip(value: str) -> bool:
    """Heuristic check: does a string look like an IP address?"""
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", value) or ":" in value)
