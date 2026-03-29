"""
gnat.ingest.mappers.mappers
================================

Concrete :class:`~gnat.ingest.base.RecordMapper` implementations that
convert raw source records into STIX 2.1 ORM objects.

Available mappers
-----------------

+---------------------------+------------------------------------------------+
| Class                     | Input                                          |
+===========================+================================================+
| FlatIOCMapper             | Generic ``{value, type}`` dicts               |
+---------------------------+------------------------------------------------+
| STIXPassthroughMapper     | Already-STIX dicts (bundles, TAXII)           |
+---------------------------+------------------------------------------------+
| MISPAttributeMapper       | MISP attribute records from MISPReader        |
+---------------------------+------------------------------------------------+
| CEFMapper                 | Parsed CEF / Syslog records                   |
+---------------------------+------------------------------------------------+
| SQLRowMapper              | DB rows with configurable column bindings     |
+---------------------------+------------------------------------------------+
| CSVIndicatorMapper        | CSV records (value + type columns)            |
+---------------------------+------------------------------------------------+
| RSSEntryMapper            | RSS / Atom feed entries                       |
+---------------------------+------------------------------------------------+
| EmailIOCMapper            | Email records from EmailReader                |
+---------------------------+------------------------------------------------+
| OpenIOCMapper             | OpenIOC IndicatorItem records                 |
+---------------------------+------------------------------------------------+
| SplunkResultMapper        | Splunk / Elasticsearch result rows            |
+---------------------------+------------------------------------------------+
| NVDCVEMapper              | NVD CVE JSON feed entries                     |
+---------------------------+------------------------------------------------+
"""

from __future__ import annotations

import logging
import re
import uuid
from typing import Any, Dict, Iterator, List, Optional, TYPE_CHECKING

from gnat.ingest.base import RawRecord, RecordMapper
from gnat.orm.indicator import Indicator
from gnat.orm.malware import Malware
from gnat.orm.vulnerability import Vulnerability
from gnat.orm.threat_actor import ThreatActor
from gnat.orm.attack_pattern import AttackPattern
from gnat.orm.relationship import Relationship
from gnat.orm.base import STIXBase

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _make_id(stix_type: str) -> str:
    return f"{stix_type}--{uuid.uuid4()}"


def _utcnow() -> str:
    from gnat.orm.base import _utcnow as _base_utcnow
    return _base_utcnow()


# MISP type → (STIX type, pattern template)
_MISP_TYPE_MAP: Dict[str, tuple] = {
    "ip-dst":          ("ipv4-addr",    "ipv4-addr:value = '{v}'"),
    "ip-src":          ("ipv4-addr",    "ipv4-addr:value = '{v}'"),
    "ip-dst|port":     ("ipv4-addr",    "ipv4-addr:value = '{v}'"),
    "ip-src|port":     ("ipv4-addr",    "ipv4-addr:value = '{v}'"),
    "domain":          ("domain-name",  "domain-name:value = '{v}'"),
    "hostname":        ("domain-name",  "domain-name:value = '{v}'"),
    "url":             ("url",          "url:value = '{v}'"),
    "md5":             ("file",         "file:hashes.MD5 = '{v}'"),
    "sha1":            ("file",         "file:hashes.SHA-1 = '{v}'"),
    "sha256":          ("file",         "file:hashes.SHA-256 = '{v}'"),
    "filename":        ("file",         "file:name = '{v}'"),
    "email-src":       ("email-addr",   "email-addr:value = '{v}'"),
    "email-dst":       ("email-addr",   "email-addr:value = '{v}'"),
    "email-subject":   ("email-message","email-message:subject = '{v}'"),
    "regkey":          ("windows-registry-key", "windows-registry-key:key = '{v}'"),
    "mutex":           ("mutex",        "mutex:name = '{v}'"),
    "vulnerability":   ("vulnerability",""),
    "malware-sample":  ("malware",      ""),
}

# IOC type string → STIX pattern template
_IOC_TYPE_PATTERN: Dict[str, str] = {
    "ip":     "[ipv4-addr:value = '{v}']",
    "ipv6":   "[ipv6-addr:value = '{v}']",
    "domain": "[domain-name:value = '{v}']",
    "url":    "[url:value = '{v}']",
    "md5":    "[file:hashes.MD5 = '{v}']",
    "sha1":   "[file:hashes.SHA-1 = '{v}']",
    "sha256": "[file:hashes.SHA-256 = '{v}']",
    "email":  "[email-addr:value = '{v}']",
    "cidr":   "[ipv4-addr:value = '{v}']",
}

# IOC type → STIX indicator_types vocab entry
_IOC_INDICATOR_TYPE: Dict[str, str] = {
    "ip":     "malicious-activity",
    "ipv6":   "malicious-activity",
    "domain": "malicious-activity",
    "url":    "malicious-activity",
    "md5":    "malicious-activity",
    "sha1":   "malicious-activity",
    "sha256": "malicious-activity",
    "email":  "malicious-activity",
}


# ===========================================================================
# 1. FlatIOCMapper
# ===========================================================================


class FlatIOCMapper(RecordMapper):
    """
    Map generic ``{value, type}`` dicts to STIX :class:`~gnat.orm.indicator.Indicator`.

    This is the Swiss Army Knife mapper for plaintext, CSV, and simple JSON
    exports where each record represents a single IOC.

    Parameters
    ----------
    value_field : str
        Dict key that holds the IOC value.  Default ``"value"``.
    type_field : str
        Dict key that holds the IOC type.  Default ``"type"``.
    name_field : str, optional
        Dict key used as the ``name`` property.  Falls back to the value.
    confidence_field : str, optional
        Dict key for per-record confidence override.
    extra_stix_fields : dict, optional
        Static key/value pairs added to every produced STIX object.
    client : GNATClient, optional
        Bound client.

    Examples
    --------
    >>> mapper = FlatIOCMapper(value_field="indicator", type_field="ioc_type",
    ...                        tlp_marking="amber", confidence=75)
    >>> for obj in mapper.map({"indicator": "evil.com", "ioc_type": "domain"}):
    ...     print(obj.to_dict())
    """

    def __init__(
        self,
        value_field: str = "value",
        type_field: str = "type",
        name_field: Optional[str] = None,
        confidence_field: Optional[str] = None,
        extra_stix_fields: Optional[Dict[str, Any]] = None,
        **kwargs: Any,
    ):
        super().__init__(**kwargs)
        self._vf = value_field
        self._tf = type_field
        self._nf = name_field
        self._cf = confidence_field
        self._extra = extra_stix_fields or {}

    def map(self, record: RawRecord) -> Iterator[STIXBase]:
        value = str(record.get(self._vf, "")).strip()
        ioc_type = str(record.get(self._tf, "unknown")).strip().lower()

        if not value:
            return

        pattern_tmpl = _IOC_TYPE_PATTERN.get(ioc_type)
        if not pattern_tmpl:
            logger.debug("FlatIOCMapper: no pattern for type %r, value %r", ioc_type, value)
            return

        pattern = pattern_tmpl.format(v=value.replace("'", "\\'"))
        name = record.get(self._nf) if self._nf else value
        confidence = int(record.get(self._cf, self.confidence)) if self._cf else self.confidence

        props = {
            "name":            str(name),
            "pattern":         pattern,
            "pattern_type":    "stix",
            "indicator_types": [_IOC_INDICATOR_TYPE.get(ioc_type, "unknown")],
            "valid_from":      record.get("valid_from", _utcnow()),
            "confidence":      confidence,
            "x_tlp":           self.tlp_marking,
            **self._extra,
        }
        # Carry through source fields as x_ extensions
        for key in ("description", "comment", "tags", "source", "category"):
            if key in record:
                props[f"x_{key}"] = record[key]

        yield Indicator(client=self._client, **props)


# ===========================================================================
# 2. STIXPassthroughMapper
# ===========================================================================


class STIXPassthroughMapper(RecordMapper):
    """
    Convert already-STIX dicts (from :class:`~gnat.ingest.sources.readers.STIXBundleReader`
    or :class:`~gnat.ingest.sources.readers.TAXIICollectionReader`) into
    bound ORM objects.

    Supported STIX types: ``indicator``, ``threat-actor``, ``malware``,
    ``vulnerability``, ``attack-pattern``, ``relationship``.
    Unknown types pass through as bare :class:`~gnat.orm.base.STIXBase`.

    Parameters
    ----------
    type_filter : list of str, optional
        Only produce objects of these STIX types.

    Examples
    --------
    >>> mapper = STIXPassthroughMapper(client=cli, type_filter=["indicator"])
    """

    _TYPE_CLASS = {
        "indicator":     Indicator,
        "threat-actor":  ThreatActor,
        "malware":       Malware,
        "vulnerability": Vulnerability,
        "attack-pattern": AttackPattern,
        "relationship":  Relationship,
    }

    def __init__(
        self,
        type_filter: Optional[List[str]] = None,
        **kwargs: Any,
    ):
        super().__init__(**kwargs)
        self._type_filter = set(type_filter) if type_filter else None

    def map(self, record: RawRecord) -> Iterator[STIXBase]:
        stix_type = record.get("type", "")
        if self._type_filter and stix_type not in self._type_filter:
            return

        cls = self._TYPE_CLASS.get(stix_type, STIXBase)
        obj = cls.from_dict(record, client=self._client)
        if self.tlp_marking:
            obj._properties["x_tlp"] = self.tlp_marking
        yield obj


# ===========================================================================
# 3. MISPAttributeMapper
# ===========================================================================


class MISPAttributeMapper(RecordMapper):
    """
    Convert MISP attribute records (from :class:`~gnat.ingest.sources.readers.MISPReader`)
    into STIX Indicator or Vulnerability objects.

    MISP attributes with ``to_ids=True`` are mapped to STIX ``Indicator``.
    Attributes of type ``"vulnerability"`` become :class:`~gnat.orm.vulnerability.Vulnerability`.
    Malware samples become :class:`~gnat.orm.malware.Malware`.
    All others fall back to ``Indicator`` if the type is in the known map.

    Parameters
    ----------
    require_to_ids : bool
        If ``True``, only map attributes where ``to_ids`` is truthy.
        Default ``False``.

    Examples
    --------
    >>> mapper = MISPAttributeMapper(client=cli, tlp_marking="amber",
    ...                              require_to_ids=True)
    """

    def __init__(self, require_to_ids: bool = False, **kwargs: Any):
        super().__init__(**kwargs)
        self._require_to_ids = require_to_ids

    def map(self, record: RawRecord) -> Iterator[STIXBase]:
        misp_type = record.get("type", "")
        value = str(record.get("value", "")).strip()

        if not value:
            return
        if self._require_to_ids and not record.get("to_ids"):
            return

        if misp_type not in _MISP_TYPE_MAP:
            logger.debug("MISPAttributeMapper: unknown MISP type %r", misp_type)
            return

        stix_type, pattern_tmpl = _MISP_TYPE_MAP[misp_type]

        common = {
            "client":      self._client,
            "x_misp_uuid": record.get("uuid", ""),
            "x_misp_event_id": record.get("event_id", ""),
            "x_misp_category": record.get("category", ""),
            "x_tlp":       self.tlp_marking,
            "confidence":  self.confidence,
        }
        if record.get("comment"):
            common["description"] = record["comment"]
        if record.get("tags"):
            common["x_misp_tags"] = record["tags"]

        if stix_type == "vulnerability":
            yield Vulnerability(name=value, **common)
            return

        if stix_type == "malware":
            yield Malware(name=value, is_family=False, **common)
            return

        if not pattern_tmpl:
            return

        # Handle composite values like "ip|port" → take the IP part
        if "|" in value:
            value = value.split("|")[0].strip()

        pattern = f"[{pattern_tmpl.format(v=value.replace(chr(39), chr(92)+chr(39)))}]"

        yield Indicator(
            name=value,
            pattern=pattern,
            pattern_type="stix",
            indicator_types=["malicious-activity"],
            valid_from=record.get("timestamp", _utcnow()),
            **common,
        )


# ===========================================================================
# 4. CEFMapper
# ===========================================================================


class CEFMapper(RecordMapper):
    """
    Convert parsed CEF / Syslog records into STIX Indicator objects.

    Uses standard CEF field names (``src``, ``dst``, ``dhost``,
    ``requestUrl``, ``fileHash``) to extract IOC values.

    Parameters
    ----------
    ioc_fields : list of str, optional
        Override the default list of CEF fields inspected for IOC values.
        Default: ``["src", "dst", "dhost", "requestUrl", "fileHash",
        "cs1", "cs2", "cs3"]``.

    Examples
    --------
    >>> mapper = CEFMapper(client=cli, ioc_fields=["src", "dst", "dhost"])
    """

    _DEFAULT_IOC_FIELDS = ["src", "dst", "dhost", "requestUrl", "fileHash", "cs1", "cs2"]

    _FIELD_TYPE_HINTS: Dict[str, str] = {
        "src":        "ip",
        "dst":        "ip",
        "dhost":      "domain",
        "requestUrl": "url",
        "fileHash":   "sha256",
    }

    def __init__(
        self,
        ioc_fields: Optional[List[str]] = None,
        **kwargs: Any,
    ):
        super().__init__(**kwargs)
        self._ioc_fields = ioc_fields or self._DEFAULT_IOC_FIELDS
        from gnat.ingest.sources.readers import PlainTextReader
        self._classifier = PlainTextReader("", from_string=True)

    def map(self, record: RawRecord) -> Iterator[STIXBase]:
        for field in self._ioc_fields:
            value = str(record.get(field, "")).strip()
            if not value:
                continue
            ioc_type = self._FIELD_TYPE_HINTS.get(field) or self._classifier._classify(value)
            pattern_tmpl = _IOC_TYPE_PATTERN.get(ioc_type)
            if not pattern_tmpl:
                continue
            pattern = pattern_tmpl.format(v=value.replace("'", "\\'"))
            yield Indicator(
                client=self._client,
                name=value,
                pattern=pattern,
                pattern_type="stix",
                indicator_types=["malicious-activity"],
                valid_from=record.get("timestamp", record.get("rt", _utcnow())),
                x_cef_name=record.get("n", ""),
                x_cef_severity=record.get("severity", ""),
                x_cef_device_product=record.get("device_product", ""),
                x_tlp=self.tlp_marking,
                confidence=self.confidence,
            )


# ===========================================================================
# 5. SQLRowMapper
# ===========================================================================


class SQLRowMapper(RecordMapper):
    """
    Map database rows to STIX objects using a configurable column binding.

    Parameters
    ----------
    value_col : str
        Column holding the IOC / object value.
    type_col : str, optional
        Column holding the STIX or IOC type string.  If omitted type is
        auto-classified.
    name_col : str, optional
        Column for the STIX ``name`` field.
    description_col : str, optional
        Column for the STIX ``description`` field.
    stix_type : str, optional
        Force all rows to map to this STIX type (``"indicator"``,
        ``"malware"``, ``"vulnerability"``, ``"threat-actor"``).
        If omitted, type is inferred from *type_col*.
    extra_col_map : dict, optional
        ``{column: stix_property}`` for additional field mappings.

    Examples
    --------
    >>> mapper = SQLRowMapper(
    ...     value_col="ioc_value",
    ...     type_col="ioc_type",
    ...     description_col="notes",
    ...     stix_type="indicator",
    ...     client=cli,
    ... )
    """

    _STIX_CLASS_MAP = {
        "indicator":     Indicator,
        "malware":       Malware,
        "vulnerability": Vulnerability,
        "threat-actor":  ThreatActor,
        "attack-pattern": AttackPattern,
    }

    def __init__(
        self,
        value_col: str = "value",
        type_col: Optional[str] = None,
        name_col: Optional[str] = None,
        description_col: Optional[str] = None,
        stix_type: Optional[str] = None,
        extra_col_map: Optional[Dict[str, str]] = None,
        **kwargs: Any,
    ):
        super().__init__(**kwargs)
        self._vc = value_col
        self._tc = type_col
        self._nc = name_col
        self._dc = description_col
        self._stix_type = stix_type
        self._extra = extra_col_map or {}
        from gnat.ingest.sources.readers import PlainTextReader
        self._classifier = PlainTextReader("", from_string=True)

    def map(self, record: RawRecord) -> Iterator[STIXBase]:
        value = str(record.get(self._vc, "")).strip()
        if not value:
            return

        ioc_type = (
            str(record.get(self._tc, "")).lower()
            if self._tc
            else self._classifier._classify(value)
        )

        resolved_stix_type = self._stix_type or (
            "indicator" if ioc_type in _IOC_TYPE_PATTERN else "indicator"
        )

        cls = self._STIX_CLASS_MAP.get(resolved_stix_type, Indicator)

        props: Dict[str, Any] = {
            "client":     self._client,
            "x_tlp":      self.tlp_marking,
            "confidence": self.confidence,
        }
        if self._nc and record.get(self._nc):
            props["name"] = record[self._nc]
        else:
            props["name"] = value

        if self._dc and record.get(self._dc):
            props["description"] = record[self._dc]

        # Indicator-specific
        if cls is Indicator:
            pattern_tmpl = _IOC_TYPE_PATTERN.get(ioc_type, "[unknown:value = '{v}']")
            props["pattern"] = pattern_tmpl.format(v=value.replace("'", "\\'"))
            props["pattern_type"] = "stix"
            props["indicator_types"] = [_IOC_INDICATOR_TYPE.get(ioc_type, "unknown")]

        for col, stix_prop in self._extra.items():
            if record.get(col) is not None:
                props[stix_prop] = record[col]

        yield cls(**props)


# ===========================================================================
# 6. CSVIndicatorMapper  (thin alias — FlatIOCMapper already handles CSV)
# ===========================================================================


class CSVIndicatorMapper(FlatIOCMapper):
    """
    Alias of :class:`FlatIOCMapper` with CSV-friendly defaults.

    By default reads ``indicator`` and ``type`` columns.
    """

    def __init__(self, value_field: str = "indicator", **kwargs: Any):
        super().__init__(value_field=value_field, **kwargs)


# ===========================================================================
# 7. RSSEntryMapper
# ===========================================================================


class RSSEntryMapper(RecordMapper):
    """
    Map RSS / Atom feed entries to STIX objects.

    Extracts IOC values from the ``summary`` and ``title`` fields, then
    produces :class:`~gnat.orm.indicator.Indicator` objects for each IOC
    found.  Also produces an ``AttackPattern`` entry for the feed item itself
    so provenance is preserved.

    Parameters
    ----------
    extract_iocs : bool
        If ``True`` (default), scan summary/title for embedded IOCs and
        produce Indicators.  If ``False``, only produce the AttackPattern.
    """

    # Patterns to scan in free text
    _URL_RE    = re.compile(r"https?://[^\s\"'<>]{8,}")
    _IP_RE     = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    _HASH_RE   = re.compile(r"\b[0-9a-fA-F]{32,64}\b")
    _CVE_RE    = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)

    def __init__(self, extract_iocs: bool = True, **kwargs: Any):
        super().__init__(**kwargs)
        self._extract = extract_iocs

    def map(self, record: RawRecord) -> Iterator[STIXBase]:
        title   = record.get("title", "")
        summary = record.get("summary", "")
        link    = record.get("link", "")
        text    = f"{title} {summary}"

        # CVEs → Vulnerability
        for cve in set(self._CVE_RE.findall(text)):
            yield Vulnerability(
                client=self._client,
                name=cve.upper(),
                x_source_url=link,
                x_feed_title=record.get("_feed_title", ""),
                x_tlp=self.tlp_marking,
            )

        if not self._extract:
            return

        from gnat.ingest.sources.readers import PlainTextReader
        classifier = PlainTextReader("", from_string=True)

        # IPs
        for ip in set(self._IP_RE.findall(text)):
            if classifier._classify(ip) == "ip":
                yield Indicator(
                    client=self._client,
                    name=ip,
                    pattern=f"[ipv4-addr:value = '{ip}']",
                    pattern_type="stix",
                    indicator_types=["malicious-activity"],
                    valid_from=record.get("published", _utcnow()),
                    x_source_url=link,
                    x_tlp=self.tlp_marking,
                    confidence=self.confidence,
                )

        # URLs
        for url in set(self._URL_RE.findall(text)):
            yield Indicator(
                client=self._client,
                name=url[:200],
                pattern=f"[url:value = '{url.replace(chr(39), chr(92)+chr(39))}']",
                pattern_type="stix",
                indicator_types=["malicious-activity"],
                valid_from=record.get("published", _utcnow()),
                x_source_url=link,
                x_tlp=self.tlp_marking,
                confidence=self.confidence,
            )

        # Hashes
        for h in set(self._HASH_RE.findall(text)):
            htype = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}.get(len(h))
            if htype:
                yield Indicator(
                    client=self._client,
                    name=h,
                    pattern=f"[file:hashes.{htype} = '{h}']",
                    pattern_type="stix",
                    indicator_types=["malicious-activity"],
                    valid_from=record.get("published", _utcnow()),
                    x_source_url=link,
                    x_tlp=self.tlp_marking,
                    confidence=self.confidence,
                )


# ===========================================================================
# 8. EmailIOCMapper
# ===========================================================================


class EmailIOCMapper(RecordMapper):
    """
    Map email records (from :class:`~gnat.ingest.sources.readers.EmailReader`)
    to STIX Indicator objects.

    Produces one Indicator per unique IOC found in the email's extracted
    ``urls``, ``ips``, ``domains``, and ``hashes`` fields.

    Parameters
    ----------
    ioc_types : list of str, optional
        Subset of ``["ips", "domains", "urls", "hashes"]`` to extract.
        Default: all four.

    Examples
    --------
    >>> mapper = EmailIOCMapper(client=cli, ioc_types=["ips", "domains"])
    """

    def __init__(
        self,
        ioc_types: Optional[List[str]] = None,
        **kwargs: Any,
    ):
        super().__init__(**kwargs)
        self._ioc_types = set(ioc_types or ["ips", "domains", "urls", "hashes"])

    def map(self, record: RawRecord) -> Iterator[STIXBase]:
        subject    = record.get("subject", "")
        msg_id     = record.get("message_id", "")
        email_from = record.get("from", "")
        published  = record.get("date", _utcnow())

        common = {
            "client":         self._client,
            "x_email_subject": subject,
            "x_email_from":   email_from,
            "x_message_id":   msg_id,
            "x_tlp":          self.tlp_marking,
            "confidence":     self.confidence,
            "valid_from":     published,
        }

        if "ips" in self._ioc_types:
            for ip in record.get("ips", []):
                yield Indicator(
                    name=ip,
                    pattern=f"[ipv4-addr:value = '{ip}']",
                    pattern_type="stix",
                    indicator_types=["malicious-activity"],
                    **common,
                )

        if "domains" in self._ioc_types:
            for domain in record.get("domains", []):
                yield Indicator(
                    name=domain,
                    pattern=f"[domain-name:value = '{domain}']",
                    pattern_type="stix",
                    indicator_types=["malicious-activity"],
                    **common,
                )

        if "urls" in self._ioc_types:
            for url in record.get("urls", []):
                safe = url.replace("'", "\\'")
                yield Indicator(
                    name=url[:200],
                    pattern=f"[url:value = '{safe}']",
                    pattern_type="stix",
                    indicator_types=["malicious-activity"],
                    **common,
                )

        if "hashes" in self._ioc_types:
            for h in record.get("hashes", []):
                htype = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}.get(len(h))
                if htype:
                    yield Indicator(
                        name=h,
                        pattern=f"[file:hashes.{htype} = '{h}']",
                        pattern_type="stix",
                        indicator_types=["malicious-activity"],
                        **common,
                    )


# ===========================================================================
# 9. OpenIOCMapper
# ===========================================================================


class OpenIOCMapper(RecordMapper):
    """
    Map OpenIOC ``IndicatorItem`` records to STIX Indicators.

    Uses the ``context_search`` field (e.g. ``"FileItem/Md5sum"``) to
    determine the STIX pattern type.

    Examples
    --------
    >>> mapper = OpenIOCMapper(client=cli, tlp_marking="red")
    """

    _SEARCH_PATTERN: Dict[str, str] = {
        "FileItem/Md5sum":               "file:hashes.MD5 = '{v}'",
        "FileItem/Sha1sum":              "file:hashes.SHA-1 = '{v}'",
        "FileItem/Sha256sum":            "file:hashes.SHA-256 = '{v}'",
        "FileItem/FileName":             "file:name = '{v}'",
        "Network/DNS":                   "domain-name:value = '{v}'",
        "PortItem/remoteIP":             "ipv4-addr:value = '{v}'",
        "PortItem/localIP":              "ipv4-addr:value = '{v}'",
        "Network/URI":                   "url:value = '{v}'",
        "RegistryItem/KeyPath":          "windows-registry-key:key = '{v}'",
        "ProcessItem/name":              "process:name = '{v}'",
        "EmailMessage/From":             "email-addr:value = '{v}'",
        "EmailMessage/Subject":          "email-message:subject = '{v}'",
    }

    def map(self, record: RawRecord) -> Iterator[STIXBase]:
        search  = record.get("context_search", "")
        content = record.get("content", "").strip()
        ioc_id  = record.get("ioc_name", record.get("ioc_id", ""))

        if not content:
            return

        pattern_tmpl = None
        for key, tmpl in self._SEARCH_PATTERN.items():
            if search.endswith(key.split("/")[-1]) or key in search:
                pattern_tmpl = tmpl
                break

        if not pattern_tmpl:
            logger.debug("OpenIOCMapper: no pattern for search %r", search)
            return

        pattern = f"[{pattern_tmpl.format(v=content.replace(chr(39), chr(92)+chr(39)))}]"

        yield Indicator(
            client=self._client,
            name=content[:200],
            description=f"OpenIOC: {ioc_id}",
            pattern=pattern,
            pattern_type="stix",
            indicator_types=["malicious-activity"],
            valid_from=_utcnow(),
            x_openioc_id=record.get("ioc_id", ""),
            x_openioc_name=ioc_id,
            x_openioc_condition=record.get("condition", "is"),
            x_tlp=self.tlp_marking,
            confidence=self.confidence,
        )


# ===========================================================================
# 10. SplunkResultMapper / ElasticResultMapper
# ===========================================================================


class SplunkResultMapper(FlatIOCMapper):
    """
    Map Splunk search result rows to STIX Indicators.

    Thin subclass of :class:`FlatIOCMapper` pre-configured for common Splunk
    field names (``src_ip``, ``dest_ip``, ``url``, ``file_hash``).

    Pass ``value_field`` to override which Splunk field holds the IOC.
    """

    def __init__(self, value_field: str = "value", **kwargs: Any):
        super().__init__(value_field=value_field, **kwargs)

    def map(self, record: RawRecord) -> Iterator[STIXBase]:
        # Try common Splunk field names if configured field is empty
        if not record.get(self._vf):
            for candidate in ("src_ip", "dest_ip", "url", "file_hash", "domain"):
                if record.get(candidate):
                    record = dict(record)
                    record[self._vf] = record[candidate]
                    if self._tf not in record or not record[self._tf]:
                        from gnat.ingest.sources.readers import PlainTextReader
                        c = PlainTextReader("", from_string=True)
                        record[self._tf] = c._classify(str(record[self._vf]))
                    break
        yield from super().map(record)


class ElasticResultMapper(SplunkResultMapper):
    """
    Map Elasticsearch document records to STIX Indicators.

    Identical to :class:`SplunkResultMapper`; provided as a distinct class
    for semantic clarity and independent subclassing.
    """


# ===========================================================================
# 11. NVDCVEMapper
# ===========================================================================


class NVDCVEMapper(RecordMapper):
    """
    Map NVD CVE JSON feed entries to STIX :class:`~gnat.orm.vulnerability.Vulnerability`.

    Handles both the NVD 1.x feed format (``CVE_Items``) and the NVD 2.x
    API format (``vulnerabilities``).

    Each record is expected to be a single CVE item dict as yielded by
    :class:`~gnat.ingest.sources.readers.JSONReader` with
    ``records_key="CVE_Items"`` or ``"vulnerabilities"``.

    Examples
    --------
    NVD 1.x::

        reader = JSONReader("nvdcve-1.1-2024.json", records_key="CVE_Items")
        mapper = NVDCVEMapper(client=cli)

    NVD 2.x API::

        reader = JSONReader("nvd_api_response.json", records_key="vulnerabilities")
        mapper = NVDCVEMapper(client=cli)
    """

    def map(self, record: RawRecord) -> Iterator[STIXBase]:
        # NVD 2.x wraps in {"cve": {...}}
        cve_data = record.get("cve", record)

        cve_id = (
            cve_data.get("id")
            or cve_data.get("CVE_data_meta", {}).get("ID", "")
        )
        if not cve_id:
            return

        # Description (1.x vs 2.x)
        desc = ""
        desc_nodes = (
            cve_data.get("descriptions")                          # 2.x
            or cve_data.get("description", {})
                        .get("description_data", [])              # 1.x
        )
        for node in desc_nodes:
            if isinstance(node, dict) and node.get("lang") in ("en", "eng"):
                desc = node.get("value", node.get("value", ""))
                break

        # CVSS score
        cvss_score: Optional[float] = None
        metrics = cve_data.get("metrics", cve_data.get("impact", {}))
        for version_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2",
                            "baseMetricV3", "baseMetricV2"):
            metric_list = metrics.get(version_key, [])
            if isinstance(metric_list, list) and metric_list:
                cvss_data = metric_list[0].get("cvssData", metric_list[0].get("cvssV3", metric_list[0].get("cvssV2", {})))
                cvss_score = cvss_data.get("baseScore")
                break
            elif isinstance(metric_list, dict):
                cvss_score = metric_list.get("cvssData", {}).get("baseScore")
                break

        published = cve_data.get("published", cve_data.get("publishedDate", ""))

        yield Vulnerability(
            client=self._client,
            name=cve_id,
            description=desc,
            x_cvss_score=cvss_score,
            x_published=published,
            x_tlp=self.tlp_marking,
            confidence=self.confidence,
        )
