"""
gnat.ingest.sources.readers
================================

Concrete :class:`~gnat.ingest.base.SourceReader` implementations for all
supported source types.

Available readers
-----------------

+----------------------+------------------------------------------------------+
| Class                | Source                                               |
+======================+======================================================+
| PlainTextReader      | One IOC per line (IP, domain, hash, URL)            |
+----------------------+------------------------------------------------------+
| CSVReader            | Delimited files with configurable column mapping    |
+----------------------+------------------------------------------------------+
| JSONReader           | Single JSON object or array file                    |
+----------------------+------------------------------------------------------+
| JSONLReader          | Newline-delimited JSON (NDJSON / JSONL)             |
+----------------------+------------------------------------------------------+
| STIXBundleReader     | STIX 2.x bundle JSON files                          |
+----------------------+------------------------------------------------------+
| TAXIICollectionReader| TAXII 2.x collection (requires ``taxii2-client``)   |
+----------------------+------------------------------------------------------+
| SQLReader            | Any DB-API 2.0 compliant database                   |
+----------------------+------------------------------------------------------+
| MISPReader           | MISP event export JSON (``/events/restSearch``)     |
+----------------------+------------------------------------------------------+
| SyslogReader         | Syslog/CEF/LEEF plaintext log files                 |
+----------------------+------------------------------------------------------+
| RSSReader            | RSS 2.0 / Atom 1.0 threat intel feeds               |
+----------------------+------------------------------------------------------+
| EmailReader          | RFC 2822 / MIME email files (.eml)                  |
+----------------------+------------------------------------------------------+
| OpenIOCReader        | OpenIOC 1.1 XML indicator files                     |
+----------------------+------------------------------------------------------+
| SplunkReader         | Splunk REST Search API results                      |
+----------------------+------------------------------------------------------+
| ElasticReader        | Elasticsearch scroll/search API results             |
+----------------------+------------------------------------------------------+
"""

from __future__ import annotations

import csv
import json
import logging
import re

try:
    import defusedxml.ElementTree as ET  # type: ignore[import-untyped]
except ImportError:
    import xml.etree.ElementTree as ET  # type: ignore[no-redef]  # nosec B314 — defusedxml preferred; install with pip install defusedxml
from collections.abc import Iterator
from itertools import islice
from pathlib import Path
from typing import Any

from gnat.ingest._ioc_classifier import classify_ioc as _fast_classify
from gnat.ingest._ioc_classifier import defang as _fast_defang
from gnat.ingest.base import RawRecord, SourceReader

logger = logging.getLogger(__name__)


# ===========================================================================
# 1. Plain-text IOC lists
# ===========================================================================


class PlainTextReader(SourceReader):
    """
    Read one IOC per line from a plain-text file or string.

    Each line is classified by a configurable set of regex patterns into
    one of: ``ip``, ``domain``, ``url``, ``md5``, ``sha1``, ``sha256``,
    ``email``, or ``unknown``.

    Lines beginning with ``#`` or empty lines are skipped.

    Parameters
    ----------
    source : str or Path
        File path, or a multiline string of IOCs when ``from_string=True``.
    from_string : bool
        If ``True``, treat *source* as raw text rather than a file path.
    encoding : str
        File encoding.  Default ``"utf-8"``.
    skip_unknown : bool
        Drop lines that cannot be classified.  Default ``True``.
    extra_patterns : dict, optional
        Additional ``{type_name: compiled_regex}`` entries appended to the
        built-in classifier.

    Examples
    --------
    >>> reader = PlainTextReader("iocs.txt")
    >>> for rec in reader:
    ...     print(rec["value"], rec["type"])

    >>> reader = PlainTextReader("1.2.3.4\\nevil.com", from_string=True)
    """

    _PATTERNS: dict[str, re.Pattern] = {
        "sha256":  re.compile(r"^[0-9a-fA-F]{64}$"),
        "sha1":    re.compile(r"^[0-9a-fA-F]{40}$"),
        "md5":     re.compile(r"^[0-9a-fA-F]{32}$"),
        "ip":      re.compile(
            r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
            r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?:/\d{1,2})?$"
        ),
        "ipv6":    re.compile(r"^[0-9a-fA-F:]{2,39}(?:/\d{1,3})?$"),
        "url":     re.compile(r"^https?://", re.IGNORECASE),
        "email":   re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$"),
        "domain":  re.compile(
            r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
            r"[a-zA-Z]{2,}$"
        ),
    }

    def __init__(
        self,
        source: str | Path,
        from_string: bool = False,
        encoding: str = "utf-8",
        skip_unknown: bool = True,
        extra_patterns: dict[str, re.Pattern] | None = None,
        **kwargs: Any,
    ):
        super().__init__(source_id=str(source)[:60], **kwargs)
        self._source = source
        self._from_string = from_string
        self._encoding = encoding
        self._skip_unknown = skip_unknown
        self._patterns = dict(self._PATTERNS)
        if extra_patterns:
            self._patterns.update(extra_patterns)

    def _classify(self, value: str) -> str:
        # Use the fast path when no custom extra_patterns are registered
        if self._patterns is self.__class__._PATTERNS:
            return _fast_classify(value)
        for ioc_type, pattern in self._patterns.items():
            if pattern.match(value):
                return ioc_type
        return "unknown"

    def _iter_records(self) -> Iterator[RawRecord]:
        if self._from_string:
            lines = str(self._source).splitlines()
        else:
            lines = Path(self._source).read_text(self._encoding).splitlines()

        for lineno, raw in enumerate(lines, 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            # Strip defang markers: [.] hxxp, etc.
            value = _fast_defang(line)
            ioc_type = self._classify(value)
            if ioc_type == "unknown" and self._skip_unknown:
                logger.debug("PlainTextReader: skipping unknown line %d: %r", lineno, value)
                continue
            yield {"value": value, "type": ioc_type, "_line": lineno, "_raw": raw}


# ===========================================================================
# 2. CSV
# ===========================================================================


class CSVReader(SourceReader):
    """
    Read a CSV/TSV file with configurable column-to-field mapping.

    Parameters
    ----------
    source : str or Path
        Path to the CSV file.
    value_col : str
        Column name that holds the IOC value.  Default ``"value"``.
    type_col : str, optional
        Column that holds the IOC type.  If omitted the value is
        auto-classified using the same regex logic as :class:`PlainTextReader`.
    delimiter : str
        Field delimiter.  Default ``","``; use ``"\\t"`` for TSV.
    encoding : str
        File encoding.  Default ``"utf-8-sig"`` (handles BOM).
    field_map : dict, optional
        ``{csv_column: output_key}`` renames specific columns in the output
        record dict.  Unmapped columns are included as-is.
    skip_rows : int
        Number of header rows to skip before the column header row.
        Default ``0``.

    Examples
    --------
    >>> reader = CSVReader(
    ...     "indicators.csv",
    ...     value_col="indicator",
    ...     type_col="indicator_type",
    ...     field_map={"confidence_score": "confidence"},
    ... )
    """

    def __init__(
        self,
        source: str | Path,
        value_col: str = "value",
        type_col: str | None = None,
        delimiter: str = ",",
        encoding: str = "utf-8-sig",
        field_map: dict[str, str] | None = None,
        skip_rows: int = 0,
        **kwargs: Any,
    ):
        super().__init__(source_id=str(source)[:60], **kwargs)
        self._source = Path(source)
        self._value_col = value_col
        self._type_col = type_col
        self._delimiter = delimiter
        self._encoding = encoding
        self._field_map = field_map or {}
        self._skip_rows = skip_rows
        self._classifier = PlainTextReader("", from_string=True)

    def _iter_records(self) -> Iterator[RawRecord]:
        with self._source.open(encoding=self._encoding, newline="") as fh:
            for _ in range(self._skip_rows):
                try:
                    next(fh)
                except StopIteration:
                    return
            reader = csv.DictReader(fh, delimiter=self._delimiter)
            for rownum, row in enumerate(reader, 1):
                rec: RawRecord = {}
                for key, val in row.items():
                    if key is None:
                        continue
                    out_key = self._field_map.get(key, key)
                    rec[out_key] = val.strip() if isinstance(val, str) else val

                value = rec.get(self._value_col, "")
                if not value:
                    continue
                if self._type_col and self._type_col in rec:
                    rec["type"] = rec[self._type_col]
                elif "type" not in rec:
                    rec["type"] = self._classifier._classify(value)

                rec["value"] = value
                rec["_row"] = rownum
                yield rec


# ===========================================================================
# 3. JSON (single file)
# ===========================================================================


class JSONReader(SourceReader):
    """
    Read a JSON file containing either an array of records or a single
    object wrapping a list.

    Parameters
    ----------
    source : str or Path
        Path to the JSON file, or a JSON string when ``from_string=True``.
    records_key : str, optional
        If the top-level JSON is a dict, this key selects the list of
        records within it (e.g. ``"indicators"``).  If omitted the whole
        top-level value is used.
    from_string : bool
        Treat *source* as raw JSON text.

    Examples
    --------
    >>> reader = JSONReader("export.json", records_key="data")
    >>> reader = JSONReader('{"indicators": [...]}', from_string=True, records_key="indicators")
    """

    def __init__(
        self,
        source: str | Path,
        records_key: str | None = None,
        from_string: bool = False,
        **kwargs: Any,
    ):
        super().__init__(source_id=str(source)[:60], **kwargs)
        self._source = source
        self._records_key = records_key
        self._from_string = from_string

    def _iter_records(self) -> Iterator[RawRecord]:
        if self._from_string:
            data = json.loads(str(self._source))
        else:
            data = json.loads(Path(self._source).read_text("utf-8"))

        if self._records_key and isinstance(data, dict):
            data = data.get(self._records_key, [])

        if isinstance(data, dict):
            data = [data]
        elif not isinstance(data, list):
            logger.warning("JSONReader: unexpected top-level type %s", type(data))
            return

        for i, record in enumerate(data):
            if not isinstance(record, dict):
                logger.debug("JSONReader: skipping non-dict item at index %d", i)
                continue
            record["_index"] = i
            yield record


# ===========================================================================
# 4. JSONL / NDJSON
# ===========================================================================


class JSONLReader(SourceReader):
    """
    Read a newline-delimited JSON file (JSONL / NDJSON).

    Each non-empty line must be a valid JSON object.

    Parameters
    ----------
    source : str or Path
        Path to the JSONL file.
    encoding : str
        File encoding.  Default ``"utf-8"``.

    Examples
    --------
    >>> for rec in JSONLReader("feed.jsonl"):
    ...     print(rec)
    """

    def __init__(
        self,
        source: str | Path,
        encoding: str = "utf-8",
        **kwargs: Any,
    ):
        super().__init__(source_id=str(source)[:60], **kwargs)
        self._source = Path(source)
        self._encoding = encoding

    def _iter_records(self) -> Iterator[RawRecord]:
        with self._source.open(encoding=self._encoding) as fh:
            for lineno, raw in enumerate(fh, 1):
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    record = json.loads(line)
                    if isinstance(record, dict):
                        record["_line"] = lineno
                        yield record
                    else:
                        logger.debug("JSONLReader: non-dict JSON at line %d", lineno)
                except json.JSONDecodeError as exc:
                    logger.warning("JSONLReader: parse error at line %d: %s", lineno, exc)


# ===========================================================================
# 5. STIX bundle
# ===========================================================================


class STIXBundleReader(SourceReader):
    """
    Read STIX 2.x bundle JSON files, yielding each STIX object as a record.

    Works with both STIX 2.0 and 2.1 bundles.  The ``"type"`` field of each
    object is preserved in the output record dict.

    Parameters
    ----------
    source : str or Path
        Path to a STIX bundle JSON file, or a raw JSON string when
        ``from_string=True``.
    stix_types : list of str, optional
        Filter to only yield objects of these STIX types.  If omitted all
        objects are yielded.
    from_string : bool
        Treat *source* as raw JSON.

    Examples
    --------
    >>> reader = STIXBundleReader("bundle.json", stix_types=["indicator", "malware"])
    """

    def __init__(
        self,
        source: str | Path,
        stix_types: list[str] | None = None,
        from_string: bool = False,
        **kwargs: Any,
    ):
        super().__init__(source_id=str(source)[:60], **kwargs)
        self._source = source
        self._stix_types = set(stix_types) if stix_types else None
        self._from_string = from_string

    def _iter_records(self) -> Iterator[RawRecord]:
        if self._from_string:
            data = json.loads(str(self._source))
        else:
            data = json.loads(Path(self._source).read_text("utf-8"))

        objects = data if isinstance(data, list) else data.get("objects", [])

        for obj in objects:
            if not isinstance(obj, dict):
                continue
            obj_type = obj.get("type", "")
            if obj_type in ("bundle",):
                continue
            if self._stix_types and obj_type not in self._stix_types:
                continue
            yield dict(obj)


# ===========================================================================
# 6. TAXII 2.x collection
# ===========================================================================


class TAXIICollectionReader(SourceReader):
    """
    Read objects from a TAXII 2.x collection.

    Requires ``taxii2-client`` (``pip install taxii2-client``).

    Parameters
    ----------
    collection : taxii2client.v21.Collection or v20.Collection
        An authenticated TAXII collection object.
    added_after : str, optional
        ISO 8601 timestamp; only objects added after this time are returned.
    stix_types : list of str, optional
        Filter results to these STIX type strings.
    limit : int, optional
        Maximum total objects to fetch.  ``None`` means no limit.

    Examples
    --------
    >>> from taxii2client.v21 import Server
    >>> server = Server("https://limo.anomali.com/api/v1/taxii2/",
    ...                 user="guest", password="guest")
    >>> col = server.api_roots[0].collections[0]
    >>> reader = TAXIICollectionReader(col, stix_types=["indicator"])
    """

    def __init__(
        self,
        collection: Any,
        added_after: str | None = None,
        stix_types: list[str] | None = None,
        limit: int | None = None,
        **kwargs: Any,
    ):
        super().__init__(source_id=getattr(collection, "title", "taxii"), **kwargs)
        self._collection = collection
        self._added_after = added_after
        self._stix_types = set(stix_types) if stix_types else None
        self._limit = limit

    def _iter_records(self) -> Iterator[RawRecord]:
        try:
            kwargs: dict[str, Any] = {}
            if self._added_after:
                kwargs["added_after"] = self._added_after

            bundle = self._collection.get_objects(**kwargs)
            objects = bundle.get("objects", []) if isinstance(bundle, dict) else []

            count = 0
            for obj in objects:
                if not isinstance(obj, dict):
                    continue
                obj_type = obj.get("type", "")
                if self._stix_types and obj_type not in self._stix_types:
                    continue
                yield dict(obj)
                count += 1
                if self._limit and count >= self._limit:
                    break

        except Exception as exc:  # noqa: BLE001
            logger.error("TAXIICollectionReader: error fetching collection — %s", exc)
            raise


# ===========================================================================
# 7. SQL / relational database
# ===========================================================================


class SQLReader(SourceReader):
    """
    Read rows from any DB-API 2.0 database (SQLite, PostgreSQL, MySQL, MSSQL,
    Oracle, etc.).

    Parameters
    ----------
    connection : DB-API 2.0 connection
        An open database connection (from ``sqlite3.connect()``,
        ``psycopg2.connect()``, ``pyodbc.connect()``, etc.).
    query : str
        SQL SELECT statement to execute.
    params : tuple or dict, optional
        Bind parameters for the query (prevents SQL injection).
    column_map : dict, optional
        ``{db_column: output_field}`` rename map.  Unmapped columns pass
        through unchanged.
    close_connection : bool
        If ``True``, the DB connection is closed when the reader closes.
        Default ``False`` (caller manages connection lifetime).

    Examples
    --------
    SQLite::

        import sqlite3
        conn = sqlite3.connect("iocs.db")
        reader = SQLReader(
            conn,
            query="SELECT value, type, confidence FROM indicators WHERE active = 1",
            column_map={"confidence": "confidence_score"},
        )

    PostgreSQL (psycopg2)::

        import psycopg2
        conn = psycopg2.connect("host=db dbname=ti user=ro password=secret")
        reader = SQLReader(
            conn,
            query="SELECT * FROM threat_indicators WHERE created > %s",
            params=("2024-01-01",),
        )
    """

    def __init__(
        self,
        connection: Any,
        query: str,
        params: Any = None,
        column_map: dict[str, str] | None = None,
        close_connection: bool = False,
        **kwargs: Any,
    ):
        super().__init__(source_id="sql", **kwargs)
        self._conn = connection
        self._query = query
        self._params = params
        self._column_map = column_map or {}
        self._close_conn = close_connection

    def close(self) -> None:
        if self._close_conn:
            try:
                self._conn.close()
            except Exception:  # noqa: BLE001
                pass
        super().close()

    def _iter_records(self) -> Iterator[RawRecord]:
        cursor = self._conn.cursor()
        try:
            if self._params is not None:
                cursor.execute(self._query, self._params)
            else:
                cursor.execute(self._query)

            columns = [
                self._column_map.get(desc[0], desc[0])
                for desc in cursor.description
            ]

            while True:
                rows = cursor.fetchmany(self.batch_size)
                if not rows:
                    break
                for row in rows:
                    yield dict(zip(columns, row))
        finally:
            cursor.close()


# ===========================================================================
# 8. MISP event export JSON
# ===========================================================================


class MISPReader(SourceReader):
    """
    Read MISP event export JSON (from ``/events/restSearch`` or exported files).

    Yields one record per MISP *attribute*, enriched with event-level fields
    (``event_id``, ``event_info``, ``threat_level_id``, ``tags``).

    Parameters
    ----------
    source : str, Path, or list
        Path to a MISP JSON export file, a raw JSON string
        (``from_string=True``), or a pre-parsed list of MISP event dicts.
    from_string : bool
        Treat *source* as raw JSON text.
    attribute_types : list of str, optional
        Filter to only yield attributes of these MISP types
        (e.g. ``["ip-dst", "domain", "md5"]``).

    Examples
    --------
    >>> reader = MISPReader("misp_export.json", attribute_types=["ip-dst", "domain"])
    """

    def __init__(
        self,
        source: str | Path | list,
        from_string: bool = False,
        attribute_types: list[str] | None = None,
        **kwargs: Any,
    ):
        super().__init__(source_id="misp", **kwargs)
        self._source = source
        self._from_string = from_string
        self._attr_types = set(attribute_types) if attribute_types else None

    def _load(self) -> list:
        if isinstance(self._source, list):
            return self._source
        if self._from_string:
            data = json.loads(str(self._source))
        else:
            data = json.loads(Path(self._source).read_text("utf-8"))
        # MISP REST wraps in {"response": [...]} or returns list directly
        if isinstance(data, dict):
            data = data.get("response", data.get("Event", [data]))
        if isinstance(data, dict):
            data = [data]
        return data

    def _iter_records(self) -> Iterator[RawRecord]:
        for event_wrapper in self._load():
            event = event_wrapper.get("Event", event_wrapper)
            event_meta = {
                "event_id":        event.get("id", ""),
                "event_uuid":      event.get("uuid", ""),
                "event_info":      event.get("info", ""),
                "threat_level_id": event.get("threat_level_id", ""),
                "event_tags":      [
                    t.get("Tag", {}).get("name", "")
                    for t in event.get("Tag", [])
                ],
                "org":             event.get("Orgc", {}).get("name", ""),
                "distribution":    event.get("distribution", ""),
                "timestamp":       event.get("timestamp", ""),
            }
            for attr in event.get("Attribute", []):
                if self._attr_types and attr.get("type") not in self._attr_types:
                    continue
                record = {
                    "value":   attr.get("value", ""),
                    "type":    attr.get("type", ""),
                    "uuid":    attr.get("uuid", ""),
                    "comment": attr.get("comment", ""),
                    "tags":    [
                        t.get("Tag", {}).get("name", "")
                        for t in attr.get("Tag", [])
                    ],
                    "to_ids":  attr.get("to_ids", False),
                    "category": attr.get("category", ""),
                }
                record.update(event_meta)
                yield record


# ===========================================================================
# 9. Syslog / CEF / LEEF
# ===========================================================================


class SyslogReader(SourceReader):
    """
    Read syslog, CEF (Common Event Format), or LEEF (Log Event Extended Format)
    log files.

    Each line is parsed into a structured record dict.

    Parameters
    ----------
    source : str or Path
        Path to the log file.
    format : str
        One of ``"syslog"``, ``"cef"``, ``"leef"``, or ``"auto"`` (default).
        ``"auto"`` detects the format per line.
    encoding : str
        File encoding.  Default ``"utf-8"``.

    Output keys (common across formats):
        ``timestamp``, ``host``, ``program``, ``severity``, ``message``,
        ``_format``, ``_raw``

    CEF-specific: all CEF extension fields are parsed into top-level keys.

    Examples
    --------
    >>> for rec in SyslogReader("/var/log/syslog"):
    ...     print(rec["timestamp"], rec["message"])
    """

    # RFC 5424 syslog pattern (simplified)
    _SYSLOG_RE = re.compile(
        r"(?P<priority><\d+>)?"
        r"(?P<timestamp>\w{3}\s+\d+\s+[\d:]+|\d{4}-\d{2}-\d{2}T[\d:.Z+\-]+)?\s*"
        r"(?P<host>\S+)?\s+"
        r"(?P<program>[^\[:]+)?"
        r"(?:\[(?P<pid>\d+)\])?:\s*"
        r"(?P<message>.*)"
    )
    # CEF header: CEF:version|device_vendor|device_product|device_version|signature|name|severity|ext
    _CEF_RE = re.compile(
        r"CEF:(?P<version>\d+)\|"
        r"(?P<device_vendor>[^|]*)\|"
        r"(?P<device_product>[^|]*)\|"
        r"(?P<device_version>[^|]*)\|"
        r"(?P<signature_id>[^|]*)\|"
        r"(?P<name>[^|]*)\|"
        r"(?P<severity>[^|]*)\|"
        r"(?P<extensions>.*)"
    )
    _LEEF_RE = re.compile(
        r"LEEF:(?P<version>[\d.]+)\|"
        r"(?P<vendor>[^|]*)\|"
        r"(?P<product>[^|]*)\|"
        r"(?P<product_version>[^|]*)\|"
        r"(?P<event_id>[^|]*)\|?"
        r"(?P<pairs>.*)"
    )

    def __init__(
        self,
        source: str | Path,
        fmt: str = "auto",
        encoding: str = "utf-8",
        **kwargs: Any,
    ):
        super().__init__(source_id=str(source)[:60], **kwargs)
        self._source = Path(source)
        self._format = fmt
        self._encoding = encoding

    def _iter_records(self) -> Iterator[RawRecord]:
        with self._source.open(encoding=self._encoding, errors="replace") as fh:
            for lineno, raw in enumerate(fh, 1):
                line = raw.rstrip("\n\r")
                if not line:
                    continue
                detected = self._format
                if detected == "auto":
                    if "CEF:" in line:
                        detected = "cef"
                    elif "LEEF:" in line:
                        detected = "leef"
                    else:
                        detected = "syslog"

                try:
                    if detected == "cef":
                        rec = self._parse_cef(line)
                    elif detected == "leef":
                        rec = self._parse_leef(line)
                    else:
                        rec = self._parse_syslog(line)
                    rec["_line"] = lineno
                    rec["_raw"] = raw
                    rec["_format"] = detected
                    yield rec
                except Exception as exc:  # noqa: BLE001
                    logger.debug("SyslogReader: parse error at line %d: %s", lineno, exc)

    def _parse_syslog(self, line: str) -> RawRecord:
        m = self._SYSLOG_RE.match(line)
        if m:
            return {k: v or "" for k, v in m.groupdict().items()}
        return {"message": line}

    def _parse_cef(self, line: str) -> RawRecord:
        # Strip syslog prefix before CEF header
        cef_start = line.find("CEF:")
        m = self._CEF_RE.match(line[cef_start:])
        if not m:
            return {"message": line}
        rec = {k: v for k, v in m.groupdict().items() if k != "extensions"}
        # Parse key=value extension pairs
        ext = m.group("extensions")
        for kv in re.findall(r"(\w+)=((?:[^=\\]|\\.)*?)(?=\s+\w+=|$)", ext):
            rec[kv[0]] = kv[1].replace("\\=", "=").replace("\\n", "\n")
        return rec

    def _parse_leef(self, line: str) -> RawRecord:
        leef_start = line.find("LEEF:")
        m = self._LEEF_RE.match(line[leef_start:])
        if not m:
            return {"message": line}
        rec = {k: v for k, v in m.groupdict().items() if k != "pairs"}
        pairs = m.group("pairs")
        # LEEF uses tab or custom delimiter for key=value pairs
        delim = "\t" if "\t" in pairs else "&"
        for pair in pairs.split(delim):
            if "=" in pair:
                k, _, v = pair.partition("=")
                rec[k.strip()] = v.strip()
        return rec


# ===========================================================================
# 10. RSS / Atom feeds
# ===========================================================================


class RSSReader(SourceReader):
    """
    Read threat intelligence from RSS 2.0 or Atom 1.0 feeds.

    Yields one record per feed entry with keys: ``title``, ``link``,
    ``summary``, ``published``, ``id``, ``tags``.

    Requires ``feedparser`` (``pip install feedparser``).

    Parameters
    ----------
    url : str
        URL of the RSS/Atom feed.  May also be a local file path.
    http_client : BaseClient, optional
        A configured :class:`~gnat.clients.base.BaseClient` to use for
        fetching.  If omitted ``feedparser`` fetches directly.
    max_entries : int, optional
        Maximum number of entries to yield.

    Examples
    --------
    >>> reader = RSSReader("https://www.cisa.gov/cybersecurity-advisories/all.xml")
    >>> reader = RSSReader("https://nvd.nist.gov/feeds/xml/cve/misc/nvd-rss.xml")
    """

    def __init__(
        self,
        url: str,
        http_client: Any = None,
        max_entries: int | None = None,
        **kwargs: Any,
    ):
        super().__init__(source_id=url[:80], **kwargs)
        self._url = url
        self._http_client = http_client
        self._max_entries = max_entries

    def _iter_records(self) -> Iterator[RawRecord]:
        try:
            import feedparser  # type: ignore
        except ImportError:
            raise ImportError(
                "feedparser is required for RSSReader: pip install feedparser"
            )

        if self._http_client:
            raw_content = self._http_client._request("GET", self._url)
            feed = feedparser.parse(raw_content)
        else:
            feed = feedparser.parse(self._url)

        entries = feed.entries
        if self._max_entries:
            entries = list(islice(entries, self._max_entries))

        for entry in entries:
            yield {
                "title":      getattr(entry, "title", ""),
                "link":       getattr(entry, "link", ""),
                "summary":    getattr(entry, "summary", ""),
                "published":  getattr(entry, "published", ""),
                "id":         getattr(entry, "id", ""),
                "author":     getattr(entry, "author", ""),
                "tags":       [t.get("term", "") for t in getattr(entry, "tags", [])],
                "_feed_title": feed.feed.get("title", ""),
                "_feed_url":   self._url,
            }


# ===========================================================================
# 11. Email / MIME (.eml files)
# ===========================================================================


class EmailReader(SourceReader):
    """
    Parse RFC 2822 / MIME email files for threat intelligence extraction.

    Yields one record per email with keys:
    ``subject``, ``from``, ``to``, ``date``, ``message_id``,
    ``body_text``, ``body_html``, ``attachments``, ``headers``,
    ``urls``, ``ips``, ``domains``, ``hashes``.

    The reader extracts IOCs from the body automatically using the same
    regex patterns as :class:`PlainTextReader`.

    Parameters
    ----------
    source : str or Path
        Directory of ``.eml`` files, or a single ``.eml`` file path.
    recursive : bool
        If ``True`` and *source* is a directory, recurse into subdirectories.

    Examples
    --------
    >>> for rec in EmailReader("phishing_samples/"):
    ...     print(rec["subject"], rec["urls"])
    """

    def __init__(
        self,
        source: str | Path,
        recursive: bool = False,
        **kwargs: Any,
    ):
        super().__init__(source_id=str(source)[:60], **kwargs)
        self._source = Path(source)
        self._recursive = recursive

    def _iter_records(self) -> Iterator[RawRecord]:
        import email as email_lib
        from email import policy as email_policy

        paths: list[Path] = []
        if self._source.is_dir():
            glob = "**/*.eml" if self._recursive else "*.eml"
            paths = list(self._source.glob(glob))
        elif self._source.suffix == ".eml":
            paths = [self._source]
        else:
            logger.warning("EmailReader: source %s is not a .eml or directory", self._source)
            return

        for path in paths:
            try:
                raw = path.read_bytes()
                msg = email_lib.message_from_bytes(raw, policy=email_policy.default)
                yield self._extract_record(msg, str(path))
            except Exception as exc:  # noqa: BLE001
                logger.warning("EmailReader: failed to parse %s — %s", path, exc)

    def _extract_record(self, msg: Any, path: str) -> RawRecord:
        body_text = ""
        body_html = ""
        attachments: list[dict[str, Any]] = []

        for part in msg.walk():
            ct = part.get_content_type()
            disp = str(part.get("Content-Disposition", ""))
            if "attachment" in disp:
                attachments.append({
                    "filename": part.get_filename(""),
                    "content_type": ct,
                    "size": len(part.get_payload(decode=True) or b""),
                })
            elif ct == "text/plain" and not body_text:
                body_text = part.get_content() or ""
            elif ct == "text/html" and not body_html:
                body_html = part.get_content() or ""

        combined_text = body_text + " " + body_html
        classifier = PlainTextReader("", from_string=True)

        urls     = re.findall(r"https?://[^\s\"'<>]+", combined_text)
        ips      = [v for v in re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", combined_text)
                    if classifier._classify(v) == "ip"]
        domains  = re.findall(
            r"(?<![/@])\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
            r"[a-zA-Z]{2,}\b", combined_text
        )
        hashes   = re.findall(r"\b[0-9a-fA-F]{32,64}\b", combined_text)

        return {
            "subject":    str(msg.get("Subject", "")),
            "from":       str(msg.get("From", "")),
            "to":         str(msg.get("To", "")),
            "date":       str(msg.get("Date", "")),
            "message_id": str(msg.get("Message-ID", "")),
            "body_text":  body_text,
            "body_html":  body_html,
            "attachments": attachments,
            "headers":    dict(msg.items()),
            "urls":       list(set(urls)),
            "ips":        list(set(ips)),
            "domains":    list(set(domains)),
            "hashes":     list(set(hashes)),
            "_path":      path,
        }


# ===========================================================================
# 12. OpenIOC XML
# ===========================================================================


class OpenIOCReader(SourceReader):
    """
    Read OpenIOC 1.1 XML indicator files.

    Parses ``<IndicatorItem>`` elements and yields one record per item with
    keys: ``ioc_id``, ``ioc_name``, ``context_document``, ``context_search``,
    ``content_type``, ``content``.

    Parameters
    ----------
    source : str or Path
        Path to a single ``.ioc`` file or a directory of ``.ioc`` files.

    Examples
    --------
    >>> for rec in OpenIOCReader("indicators/"):
    ...     print(rec["context_search"], rec["content"])
    """

    _NS = {
        "ioc":  "http://schemas.mandiant.com/2010/ioc",
        "ioc2": "http://openioc.org/schemas/OpenIOC_1.1",
    }

    def __init__(self, source: str | Path, **kwargs: Any):
        super().__init__(source_id=str(source)[:60], **kwargs)
        self._source = Path(source)

    def _iter_records(self) -> Iterator[RawRecord]:
        paths = (
            list(self._source.glob("*.ioc"))
            if self._source.is_dir()
            else [self._source]
        )
        for path in paths:
            try:
                yield from self._parse_file(path)
            except Exception as exc:  # noqa: BLE001
                logger.warning("OpenIOCReader: failed to parse %s — %s", path, exc)

    def _parse_file(self, path: Path) -> Iterator[RawRecord]:
        tree = ET.parse(str(path))  # nosec B314 — defusedxml used when installed; see import block above
        root = tree.getroot()

        # Detect namespace
        ns_tag = root.tag
        ns = ""
        if ns_tag.startswith("{"):
            ns = ns_tag.split("}")[0] + "}"

        ioc_id   = root.get("id", "")
        ioc_name_el = root.find(f"{ns}short_description")
        ioc_name = ioc_name_el.text if ioc_name_el is not None else path.stem

        for item in root.iter(f"{ns}IndicatorItem"):
            context  = item.find(f"{ns}Context")
            content  = item.find(f"{ns}Content")
            yield {
                "ioc_id":           ioc_id,
                "ioc_name":         ioc_name,
                "item_id":          item.get("id", ""),
                "condition":        item.get("condition", "is"),
                "context_document": context.get("document", "") if context is not None else "",
                "context_search":   context.get("search", "") if context is not None else "",
                "content_type":     content.get("type", "") if content is not None else "",
                "content":          content.text or "" if content is not None else "",
                "_file":            str(path),
            }


# ===========================================================================
# 13. Splunk REST API
# ===========================================================================


class SplunkReader(SourceReader):
    """
    Execute a Splunk SPL search and yield result rows.

    Uses the Splunk REST API (``/services/search/jobs``) directly via
    :class:`~gnat.clients.base.BaseClient` so no Splunk SDK is required.

    Parameters
    ----------
    base_client : BaseClient
        An authenticated :class:`~gnat.clients.base.BaseClient` pointing
        at the Splunk management port (usually ``https://splunk:8089``).
    search : str
        SPL search string (e.g. ``"search index=threat_intel | table src_ip type"``).
    earliest : str
        Splunk time modifier for the search window (e.g. ``"-24h"``).
    latest : str
        End of the search window.  Default ``"now"``.
    max_results : int
        Maximum rows to fetch.  Default ``10000``.

    Examples
    --------
    >>> from gnat.clients.base import BaseClient
    >>> class SplunkClient(BaseClient):
    ...     def authenticate(self):
    ...         self._auth_headers["Authorization"] = "Splunk my-token"
    >>> client = SplunkClient("https://splunk:8089")
    >>> reader = SplunkReader(client, search="search index=iocs | table ip domain hash")
    """

    def __init__(
        self,
        base_client: Any,
        search: str,
        earliest: str = "-24h",
        latest: str = "now",
        max_results: int = 10_000,
        **kwargs: Any,
    ):
        super().__init__(source_id="splunk", **kwargs)
        self._client = base_client
        self._search = search if search.startswith("search") else f"search {search}"
        self._earliest = earliest
        self._latest = latest
        self._max_results = max_results

    def _iter_records(self) -> Iterator[RawRecord]:
        # Create search job
        job = self._client.post(
            "/services/search/jobs",
            data={
                "search": self._search,
                "earliest_time": self._earliest,
                "latest_time": self._latest,
                "output_mode": "json",
                "exec_mode": "blocking",
                "count": str(self._max_results),
            },
        )
        sid = job.get("sid") if isinstance(job, dict) else None
        if not sid:
            logger.error("SplunkReader: failed to create search job")
            return

        results = self._client.get(
            f"/services/search/jobs/{sid}/results",
            params={"output_mode": "json", "count": str(self._max_results)},
        )
        for row in results.get("results", []):
            if isinstance(row, dict):
                yield row


# ===========================================================================
# 14. Elasticsearch
# ===========================================================================


class ElasticReader(SourceReader):
    """
    Fetch documents from Elasticsearch using the Search / Scroll API.

    Parameters
    ----------
    base_client : BaseClient
        An authenticated :class:`~gnat.clients.base.BaseClient` pointing
        at the Elasticsearch cluster (e.g. ``https://elastic:9200``).
    index : str
        Index or index pattern to search (e.g. ``"threat-intel-*"``).
    query : dict
        Elasticsearch query DSL dict.  Defaults to ``{"match_all": {}}``.
    source_fields : list of str, optional
        Fields to include in the ``_source``.  ``None`` returns all fields.
    scroll_ttl : str
        Scroll context TTL.  Default ``"2m"``.
    page_size : int
        Documents per scroll page.  Default ``500``.

    Examples
    --------
    >>> reader = ElasticReader(
    ...     client,
    ...     index="threat-intel-*",
    ...     query={"term": {"type": "ip"}},
    ...     source_fields=["value", "type", "confidence"],
    ... )
    """

    def __init__(
        self,
        base_client: Any,
        index: str,
        query: dict[str, Any] | None = None,
        source_fields: list[str] | None = None,
        scroll_ttl: str = "2m",
        page_size: int = 500,
        **kwargs: Any,
    ):
        super().__init__(source_id=f"elastic:{index}", batch_size=page_size, **kwargs)
        self._client = base_client
        self._index = index
        self._query = query or {"match_all": {}}
        self._source_fields = source_fields
        self._scroll_ttl = scroll_ttl

    def _iter_records(self) -> Iterator[RawRecord]:
        body: dict[str, Any] = {
            "query": self._query,
            "size": self.batch_size,
        }
        if self._source_fields:
            body["_source"] = self._source_fields

        resp = self._client.post(
            f"/{self._index}/_search",
            params={"scroll": self._scroll_ttl},
            json=body,
        )

        scroll_id = resp.get("_scroll_id")
        hits = resp.get("hits", {}).get("hits", [])

        while hits:
            for hit in hits:
                source = hit.get("_source", {})
                source["_es_id"] = hit.get("_id", "")
                source["_es_index"] = hit.get("_index", "")
                yield source

            if not scroll_id:
                break

            resp = self._client.post(
                "/_search/scroll",
                json={"scroll": self._scroll_ttl, "scroll_id": scroll_id},
            )
            scroll_id = resp.get("_scroll_id")
            hits = resp.get("hits", {}).get("hits", [])

        # Clear scroll context
        if scroll_id:
            try:
                self._client.delete(f"/_search/scroll/{scroll_id}")
            except Exception:  # noqa: BLE001
                pass
