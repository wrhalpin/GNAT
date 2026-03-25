# “””
ctm_sak.connectors.splunk.threat_intel

Enterprise Security Threat Intelligence API commands.

Requires `es_enabled = true` in [splunk] config.

## Splunk ES Threat Intel API

The Threat Intel API lives at:
/servicesNS/<owner>/SplunkEnterpriseSecuritySuite/services/configs/conf-<collection>

Key threat intelligence KV store collections (accessed via REST):

- ip_intel         — IP address indicators
- domain_intel     — Domain indicators
- url_intel        — URL indicators
- file_intel       — File hash indicators (MD5, SHA1, SHA256)
- email_intel      — Email address indicators
- process_intel    — Process name indicators
- registry_intel   — Registry key indicators
- certificate_intel — Certificate indicators
- user_intel       — Username indicators
- http_intel       — HTTP user agent / cookie indicators

## STIX 2.1 / IOC file upload

Splunk ES accepts STIX 2.0 and 2.1 files at:
POST /servicesNS/…/SplunkEnterpriseSecuritySuite/
services/data/threat_intel_by_source/<collection_name>

Supported STIX object types:

- observed-data (maps to indicator collections)
- indicator    → PARTIALLY supported (observable objects only,
  STIX pattern syntax is ignored by Splunk)

The SplunkSTIXMapper handles pre-processing STIX 2.1 ORM objects
from CTM-SAK’s ORM into the flat KV store format Splunk expects
before calling the upload/upsert methods here.

## References

- https://docs.splunk.com/Documentation/ES/latest/Admin/Threatsources
- https://docs.splunk.com/Documentation/ES/latest/API/Threatsources
  “””

import json
import urllib.parse

from .client import SplunkClient
from .exceptions import SplunkThreatIntelError

# ── Supported intel collections ───────────────────────────────────────────────

INTEL_COLLECTIONS = {
“ip”,
“domain”,
“url”,
“file”,
“email”,
“process”,
“registry”,
“certificate”,
“user”,
“http”,
}

# KV store collection names as Splunk expects them

_COLLECTION_MAP: dict[str, str] = {
“ip”: “ip_intel”,
“domain”: “domain_intel”,
“url”: “url_intel”,
“file”: “file_intel”,
“email”: “email_intel”,
“process”: “process_intel”,
“registry”: “registry_intel”,
“certificate”: “certificate_intel”,
“user”: “user_intel”,
“http”: “http_intel”,
}

# ES app namespace for threat intel endpoints

_ES_APP = “SplunkEnterpriseSecuritySuite”

class SplunkThreatIntelCommands:
“””
Enterprise Security Threat Intelligence operations.

```
Parameters
----------
client : SplunkClient
    Authenticated HTTP client.
"""

def __init__(self, client: SplunkClient) -> None:
    self._client = client

# ── Guard ──────────────────────────────────────────────────────────────

def _require_es(self) -> None:
    if not self._client.config.es_enabled:
        raise SplunkThreatIntelError(
            "Threat Intel commands require 'es_enabled = true' "
            "in [splunk] config."
        )

def _es_path(self, endpoint: str) -> str:
    """Build an ES-namespaced path."""
    owner = self._client.config.owner
    base = self._client.config.base_url
    return f"{base}/servicesNS/{owner}/{_ES_APP}/{endpoint.lstrip('/')}"

# ── IOC CRUD ───────────────────────────────────────────────────────────

def list_iocs(
    self,
    collection: str,
    count: int = 100,
    offset: int = 0,
    query: dict | None = None,
) -> list[dict]:
    """
    List IOCs from a specific threat intel collection.

    Parameters
    ----------
    collection : str
        Collection key: 'ip', 'domain', 'url', 'file', etc.
        See ``INTEL_COLLECTIONS`` for all valid values.
    count : int
        Max records to return per call.
    offset : int
        Pagination offset.
    query : dict | None
        KV store query filter dict (Splunk JSON query syntax).

    Returns
    -------
    list[dict]
        IOC records.

    Raises
    ------
    SplunkThreatIntelError
        If the collection name is invalid or ES is not enabled.
    """
    self._require_es()
    coll_name = self._validate_collection(collection)
    params = {
        "output_mode": "json",
        "count": count,
        "offset": offset,
    }
    if query:
        params["query"] = json.dumps(query)

    url = self._es_path(f"storage/collections/data/{coll_name}")
    response = self._client.get(url, params=params, namespaced=False)
    # KV store endpoints return a list directly, not wrapped in 'entry'
    if isinstance(response, list):
        return response
    return response.get("entry", [])

def get_ioc(self, collection: str, key: str) -> dict | None:
    """
    Retrieve a single IOC record by its KV store ``_key``.

    Parameters
    ----------
    collection : str
        Collection key (e.g. 'ip', 'domain').
    key : str
        The ``_key`` value of the IOC record.

    Returns
    -------
    dict | None
        IOC record, or None if not found.
    """
    self._require_es()
    coll_name = self._validate_collection(collection)
    safe_key = urllib.parse.quote(key, safe="")
    url = self._es_path(
        f"storage/collections/data/{coll_name}/{safe_key}"
    )
    try:
        return self._client.get(url, namespaced=False)
    except Exception:
        return None

def upsert_ioc(self, collection: str, record: dict) -> dict:
    """
    Insert or update a single IOC record in a KV store collection.

    If ``record`` contains ``_key``, Splunk will update or create
    the record at that key. If ``_key`` is absent, Splunk assigns one.

    Parameters
    ----------
    collection : str
        Collection key.
    record : dict
        IOC field dict. Required fields vary by collection type
        (see Splunk ES documentation for field schemas).

    Returns
    -------
    dict
        Response body containing the assigned ``_key``.
    """
    self._require_es()
    coll_name = self._validate_collection(collection)
    key = record.get("_key")

    if key:
        safe_key = urllib.parse.quote(key, safe="")
        url = self._es_path(
            f"storage/collections/data/{coll_name}/{safe_key}"
        )
        return self._client.put(url, data=record, namespaced=False)

    url = self._es_path(f"storage/collections/data/{coll_name}")
    return self._client.post(
        url,
        raw_body=json.dumps(record).encode("utf-8"),
        content_type="application/json",
        namespaced=False,
    )

def upsert_iocs_bulk(
    self,
    collection: str,
    records: list[dict],
    batch_size: int = 500,
) -> list[dict]:
    """
    Bulk insert/update IOC records using the KV store batch endpoint.

    Splunk's batch endpoint accepts up to ~500 records per call.
    This method automatically chunks larger lists.

    Parameters
    ----------
    collection : str
        Collection key.
    records : list[dict]
        List of IOC field dicts.
    batch_size : int
        Records per batch POST (max ~500 for Splunk KV store).

    Returns
    -------
    list[dict]
        Aggregated response bodies from all batch calls.
    """
    self._require_es()
    coll_name = self._validate_collection(collection)
    url = self._es_path(f"storage/collections/data/{coll_name}/batch_save")

    responses = []
    for i in range(0, len(records), batch_size):
        batch = records[i:i + batch_size]
        resp = self._client.post(
            url,
            raw_body=json.dumps(batch).encode("utf-8"),
            content_type="application/json",
            namespaced=False,
        )
        responses.append(resp)
    return responses

def delete_ioc(self, collection: str, key: str) -> None:
    """
    Delete a single IOC record by its KV store ``_key``.

    Parameters
    ----------
    collection : str
        Collection key.
    key : str
        The ``_key`` of the record to delete.
    """
    self._require_es()
    coll_name = self._validate_collection(collection)
    safe_key = urllib.parse.quote(key, safe="")
    url = self._es_path(
        f"storage/collections/data/{coll_name}/{safe_key}"
    )
    self._client.delete(url, namespaced=False)

def clear_collection(self, collection: str) -> None:
    """
    Delete ALL records from a KV store intel collection.

    Use with caution — this is irreversible without a backup.

    Parameters
    ----------
    collection : str
        Collection key to purge.
    """
    self._require_es()
    coll_name = self._validate_collection(collection)
    url = self._es_path(f"storage/collections/data/{coll_name}")
    self._client.delete(url, namespaced=False)

# ── STIX / IOC file upload ─────────────────────────────────────────────

def upload_stix_file(
    self,
    stix_content: bytes,
    source_name: str,
    collection: str = "ip",
    weight: int = 50,
) -> dict:
    """
    Upload a STIX 2.0/2.1 file to Splunk ES via the Threat Intel upload API.

    Splunk parses STIX ``observed-data`` objects from the bundle and
    maps them into the appropriate KV store collection.

    Note: STIX ``indicator`` pattern objects are accepted by the
    upload but the STIX pattern syntax is silently ignored — only
    the embedded observable references are processed.

    Parameters
    ----------
    stix_content : bytes
        Raw STIX 2.1 JSON bundle bytes.
    source_name : str
        Friendly name for this threat intel source (shown in ES UI).
    collection : str
        Target collection hint: 'ip', 'domain', etc.
    weight : int
        Threat intel weight (0–100) applied in ES risk scoring.

    Returns
    -------
    dict
        Splunk ES upload response.

    Raises
    ------
    SplunkThreatIntelError
        On upload failure or invalid collection.
    """
    self._require_es()
    coll_name = self._validate_collection(collection)

    # Splunk ES threat intel upload endpoint
    url = self._es_path(
        f"services/data/threat_intel_by_source/{source_name}"
    )

    # Build multipart-style POST body; Splunk accepts raw file POST here
    data = {
        "name": source_name,
        "type": "stix2",          # tells Splunk the parser to use
        "collection": coll_name,
        "weight": str(weight),
        "output_mode": "json",
    }

    # Post the STIX JSON directly as the body with metadata as query params
    import urllib.parse as _up
    url_with_params = f"{url}?{_up.urlencode(data)}"

    try:
        return self._client.post(
            url_with_params,
            raw_body=stix_content,
            content_type="application/json",
            namespaced=False,
        )
    except Exception as exc:
        raise SplunkThreatIntelError(
            f"STIX file upload to '{source_name}' failed: {exc}"
        ) from exc

def upload_stix_bundle_dict(
    self,
    bundle: dict,
    source_name: str,
    collection: str = "ip",
    weight: int = 50,
) -> dict:
    """
    Upload a STIX 2.1 bundle dict (from CTM-SAK ORM) to Splunk ES.

    Parameters
    ----------
    bundle : dict
        STIX 2.1 bundle as a Python dict.
    source_name : str
        Friendly name for the threat intel source.
    collection : str
        Target collection key.
    weight : int
        Threat intel weight.

    Returns
    -------
    dict
        Splunk ES upload response.
    """
    return self.upload_stix_file(
        stix_content=json.dumps(bundle).encode("utf-8"),
        source_name=source_name,
        collection=collection,
        weight=weight,
    )

# ── Threat intel source management ─────────────────────────────────────

def list_intel_sources(self) -> list[dict]:
    """
    List configured threat intelligence sources in Splunk ES.

    Returns
    -------
    list[dict]
        Intel source configuration records.
    """
    self._require_es()
    url = self._es_path("services/data/threat_intel_manager")
    response = self._client.get(url, namespaced=False)
    results = []
    for entry in response.get("entry", []):
        content = entry.get("content", {})
        results.append({
            "name": entry.get("name"),
            "type": content.get("type"),
            "collection": content.get("collection"),
            "weight": content.get("weight"),
            "disabled": content.get("disabled"),
            "status": content.get("status"),
            "last_updated": content.get("last_successful_execution"),
        })
    return results

def enable_intel_source(self, source_name: str) -> dict:
    """Enable a disabled threat intel source."""
    self._require_es()
    safe = urllib.parse.quote(source_name, safe="")
    url = self._es_path(f"services/data/threat_intel_manager/{safe}")
    return self._client.post(
        url,
        data={"disabled": "false"},
        namespaced=False,
    )

def disable_intel_source(self, source_name: str) -> dict:
    """Disable an active threat intel source."""
    self._require_es()
    safe = urllib.parse.quote(source_name, safe="")
    url = self._es_path(f"services/data/threat_intel_manager/{safe}")
    return self._client.post(
        url,
        data={"disabled": "true"},
        namespaced=False,
    )

# ── Internal ───────────────────────────────────────────────────────────

@staticmethod
def _validate_collection(collection: str) -> str:
    """
    Validate and return the full KV store collection name.

    Parameters
    ----------
    collection : str
        Short collection key (e.g. 'ip').

    Returns
    -------
    str
        Full collection name (e.g. 'ip_intel').

    Raises
    ------
    SplunkThreatIntelError
        If the collection key is not recognised.
    """
    key = collection.lower().replace("_intel", "").strip()
    if key not in _COLLECTION_MAP:
        raise SplunkThreatIntelError(
            f"Unknown intel collection '{collection}'. "
            f"Valid options: {sorted(INTEL_COLLECTIONS)}"
        )
    return _COLLECTION_MAP[key]
```