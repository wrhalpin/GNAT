"""STIX ↔ Cribl object translation helpers."""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class CriblSTIXMapper:
    """
    Converts between Cribl-native objects and STIX 2.1 representations.

    Uses a stable UUID5 namespace so that identical inputs always produce
    the same STIX object identifier.
    """

    _NAMESPACE = uuid.UUID("6e8d26c8-7b56-4c9b-b7cd-b7d3d5c4a6e1")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _make_id(self, stix_type: str, value: str) -> str:
        """
        Generate a deterministic STIX 2.1 identifier.

        Parameters
        ----------
        stix_type : str
            STIX object type, e.g. ``"observed-data"``.
        value : str
            Unique string for the object (used as UUID5 seed).

        Returns
        -------
        str
            STIX id string in ``<type>--<uuid>`` format.
        """
        return f"{stix_type}--{uuid.uuid5(self._NAMESPACE, value)}"

    # ------------------------------------------------------------------
    # Event → STIX observed-data
    # ------------------------------------------------------------------

    def event_to_observed_data(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert a Cribl search event dict to a STIX ``observed-data`` SDO.

        Parameters
        ----------
        event : dict
            Raw Cribl search event, typically containing ``_raw``,
            ``_time``, and ``cribl_pipe`` keys.

        Returns
        -------
        dict
            STIX 2.1 ``observed-data`` object.
        """
        raw = event.get("_raw", "")
        ts_val = event.get("_time")
        if ts_val:
            try:
                ts = datetime.fromtimestamp(float(ts_val), tz=timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                )
            except (TypeError, ValueError, OSError):
                ts = _now_iso()
        else:
            ts = _now_iso()

        scos = self._extract_scos_from_event(event)
        object_refs = [s["id"] for s in scos if "id" in s]

        obj: Dict[str, Any] = {
            "type": "observed-data",
            "id": self._make_id("observed-data", raw or ts),
            "created": ts,
            "modified": ts,
            "first_observed": ts,
            "last_observed": ts,
            "number_observed": 1,
            "object_refs": object_refs,
            "x_cribl_raw": raw,
            "x_cribl_source": event.get("cribl_pipe", ""),
        }
        return obj

    def _extract_scos_from_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract STIX SCOs from common fields in a Cribl search event.

        Parameters
        ----------
        event : dict
            Cribl event dict.  Inspects ``ip``, ``src_ip``, ``dest_ip``,
            ``domain``, ``hostname``, ``url``, ``hash``, ``md5``,
            ``sha256``, and ``sha1`` keys.

        Returns
        -------
        list of dict
            List of STIX SCO dicts (ipv4-addr, domain-name, url, file).
        """
        scos: List[Dict[str, Any]] = []

        for field in ("ip", "src_ip", "dest_ip"):
            val = event.get(field)
            if val:
                scos.append(
                    {
                        "type": "ipv4-addr",
                        "id": self._make_id("ipv4-addr", str(val)),
                        "value": str(val),
                    }
                )

        for field in ("domain", "hostname"):
            val = event.get(field)
            if val:
                scos.append(
                    {
                        "type": "domain-name",
                        "id": self._make_id("domain-name", str(val)),
                        "value": str(val),
                    }
                )

        url_val = event.get("url")
        if url_val:
            scos.append(
                {
                    "type": "url",
                    "id": self._make_id("url", str(url_val)),
                    "value": str(url_val),
                }
            )

        hashes: Dict[str, str] = {}
        if event.get("md5"):
            hashes["MD5"] = str(event["md5"])
        if event.get("sha256"):
            hashes["SHA-256"] = str(event["sha256"])
        if event.get("sha1"):
            hashes["SHA-1"] = str(event["sha1"])
        if event.get("hash"):
            hashes.setdefault("MD5", str(event["hash"]))
        if hashes:
            seed = next(iter(hashes.values()))
            scos.append(
                {
                    "type": "file",
                    "id": self._make_id("file", seed),
                    "hashes": hashes,
                }
            )

        return scos

    # ------------------------------------------------------------------
    # Pipeline → STIX course-of-action
    # ------------------------------------------------------------------

    def pipeline_to_course_of_action(self, pipeline: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert a Cribl pipeline config dict to a STIX ``course-of-action`` SDO.

        Parameters
        ----------
        pipeline : dict
            Cribl pipeline object (must contain an ``id`` key at top level
            or inside ``conf``).

        Returns
        -------
        dict
            STIX 2.1 ``course-of-action`` object.
        """
        pipeline_id = pipeline.get("id", "")
        conf = pipeline.get("conf", pipeline)
        functions = conf.get("functions", []) if isinstance(conf, dict) else []
        function_types = [f.get("id", f.get("type", "")) for f in functions if isinstance(f, dict)]
        worker_group = pipeline.get("worker_group", "")
        ts = _now_iso()

        return {
            "type": "course-of-action",
            "id": self._make_id("course-of-action", pipeline_id),
            "name": pipeline_id,
            "description": f"Cribl pipeline: {pipeline_id}",
            "created": ts,
            "modified": ts,
            "x_cribl_pipeline_id": pipeline_id,
            "x_cribl_worker_group": worker_group,
            "x_cribl_functions": function_types,
        }

    # ------------------------------------------------------------------
    # STIX indicator → Cribl lookup config
    # ------------------------------------------------------------------

    def stix_indicator_to_lookup(self, stix_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert a STIX ``indicator`` SDO to a Cribl lookup configuration dict.

        Parameters
        ----------
        stix_dict : dict
            STIX 2.1 ``indicator`` object.

        Returns
        -------
        dict
            Cribl lookup config ready for the Lookups API.
        """
        stix_id = stix_dict.get("id", "")
        short_id = stix_id.replace("indicator--", "")[:8]
        pattern = stix_dict.get("pattern", "")

        fields = _extract_fields_from_pattern(pattern)

        return {
            "id": f"lookup-{short_id}",
            "type": "lookup",
            "fileType": "csv",
            "description": stix_dict.get("description", stix_dict.get("name", "")),
            "x_stix_id": stix_id,
            "x_stix_pattern": pattern,
            "fields": fields,
        }

    # ------------------------------------------------------------------
    # Dispatch helpers
    # ------------------------------------------------------------------

    def node_to_stix(self, native: Dict[str, Any]) -> Dict[str, Any]:
        """
        Dispatch a Cribl native object to the appropriate STIX conversion.

        Parameters
        ----------
        native : dict
            Either a Cribl search event (contains ``_raw``) or a pipeline
            config (contains ``conf``).

        Returns
        -------
        dict
            STIX 2.1 object.
        """
        if "_raw" in native:
            return self.event_to_observed_data(native)
        if "conf" in native or ("id" in native and "functions" not in native):
            return self.pipeline_to_course_of_action(native)
        return {
            "type": "x-cribl-object",
            "id": self._make_id("x-cribl-object", str(native)),
            "data": native,
        }

    def stix_to_native(self, stix_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Convert a STIX object to a Cribl-native representation.

        Parameters
        ----------
        stix_dict : dict
            STIX 2.1 object dict.

        Returns
        -------
        dict
            Cribl-native object (lookup config for indicators; passthrough
            otherwise).
        """
        if stix_dict.get("type") == "indicator":
            return self.stix_indicator_to_lookup(stix_dict)
        return dict(stix_dict)


# ------------------------------------------------------------------
# Module-level helpers
# ------------------------------------------------------------------

def _extract_fields_from_pattern(pattern: str) -> List[str]:
    """
    Extract observable field names from a STIX pattern string.

    Parameters
    ----------
    pattern : str
        STIX pattern, e.g. ``"[ipv4-addr:value = '1.2.3.4']"``.

    Returns
    -------
    list of str
        List of field names found in the pattern.
    """
    fields: List[str] = []
    matches = re.findall(r"(\w[\w.:-]*)\s*=", pattern)
    for m in matches:
        if m not in fields:
            fields.append(m)
    return fields
