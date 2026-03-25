"""
ctm_sak.async_client.connectors
================================

Async connector clients for all six supported platforms.

Each class inherits from :class:`~ctm_sak.async_client.base.AsyncBaseClient`
and mirrors its sync counterpart's auth + translation logic as async methods.
The STIX translation methods (``to_stix``, ``from_stix``) are kept synchronous
since they are CPU-bound; only the HTTP I/O methods are awaited.
"""

from __future__ import annotations

import base64
import logging
from typing import Any, Dict, List, Optional

from ctm_sak.async_client.base import AsyncBaseClient
from ctm_sak.clients.base import SAKClientError
from ctm_sak.connectors.base_connector import ConnectorMixin

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# ThreatQ
# ---------------------------------------------------------------------------

class AsyncThreatQClient(AsyncBaseClient, ConnectorMixin):
    """Async ThreatQ connector — OAuth2 client-credentials."""

    stix_type_map = {
        "indicator": "indicator", "threat-actor": "adversary",
        "malware": "malware", "vulnerability": "vulnerability",
        "attack-pattern": "attack-pattern",
    }

    def __init__(self, host: str, client_id: str = "",
                 client_secret: str = "", **kwargs: Any):
        super().__init__(host=host, **kwargs)
        self._client_id = client_id
        self._client_secret = client_secret

    async def authenticate(self) -> None:
        resp = await self.post("/api/token", data={
            "grant_type": "client_credentials",
            "client_id": self._client_id,
            "client_secret": self._client_secret,
        })
        token = resp.get("access_token") if isinstance(resp, dict) else None
        if not token:
            raise SAKClientError("AsyncThreatQ: failed to obtain access token")
        self._auth_headers["Authorization"] = f"Bearer {token}"

    async def health_check(self) -> bool:
        await self.get("/api/ping")
        return True

    async def get_object(self, stix_type: str, object_id: str) -> Dict[str, Any]:
        resource = self._resolve(stix_type)
        tq_id = object_id.split("--")[-1] if "--" in object_id else object_id
        return await self.get(f"/api/{resource}/{tq_id}", params={"with": "tags,score"})

    async def list_objects(self, stix_type: str,
                           filters: Optional[Dict[str, Any]] = None,
                           page: int = 1, page_size: int = 100) -> List[Dict[str, Any]]:
        resource = self._resolve(stix_type)
        params: Dict[str, Any] = {"limit": page_size, "offset": (page - 1) * page_size}
        if filters:
            params.update(filters)
        resp = await self.get(f"/api/{resource}", params=params)
        return resp.get("data", []) if isinstance(resp, dict) else []

    async def upsert_object(self, stix_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        resource = self._resolve(stix_type)
        tq_id = payload.pop("id", None)
        if tq_id:
            return await self.put(f"/api/{resource}/{tq_id}", json=payload)
        return await self.post(f"/api/{resource}", json=payload)

    async def delete_object(self, stix_type: str, object_id: str) -> None:
        resource = self._resolve(stix_type)
        tq_id = object_id.split("--")[-1] if "--" in object_id else object_id
        await self.delete(f"/api/{resource}/{tq_id}")

    def to_stix(self, native: Dict[str, Any]) -> Dict[str, Any]:
        d = native.get("data", native)
        return {
            "type": "indicator",
            "id": f"indicator--{d.get('id', '')}",
            "name": d.get("value", ""),
            "pattern": f"[ipv4-addr:value = '{d.get('value', '')}']",
            "pattern_type": "stix",
            "created": d.get("created_at", ""),
            "modified": d.get("updated_at", ""),
            "indicator_types": [d.get("class", "unknown")],
        }

    def from_stix(self, stix_dict: Dict[str, Any]) -> Dict[str, Any]:
        return {"value": stix_dict.get("name", ""), "status": {"name": "Active"}}

    def _resolve(self, stix_type: str) -> str:
        r = self.stix_type_map.get(stix_type)
        if not r:
            raise SAKClientError(f"AsyncThreatQ: unsupported STIX type '{stix_type}'")
        return r + "s"


# ---------------------------------------------------------------------------
# CrowdStrike
# ---------------------------------------------------------------------------

class AsyncCrowdStrikeClient(AsyncBaseClient, ConnectorMixin):
    """Async CrowdStrike Falcon connector — OAuth2."""

    stix_type_map = {"indicator": "iocs", "malware": "detections"}

    def __init__(self, host: str, client_id: str = "",
                 client_secret: str = "", **kwargs: Any):
        super().__init__(host=host, **kwargs)
        self._client_id = client_id
        self._client_secret = client_secret

    async def authenticate(self) -> None:
        resp = await self.post("/oauth2/token", data={
            "client_id": self._client_id, "client_secret": self._client_secret,
        })
        token = resp.get("access_token") if isinstance(resp, dict) else None
        if not token:
            raise SAKClientError("AsyncCrowdStrike: failed to obtain access token")
        self._auth_headers["Authorization"] = f"Bearer {token}"

    async def health_check(self) -> bool:
        await self.get("/sensors/queries/installers/v1", params={"limit": 1})
        return True

    async def get_object(self, stix_type: str, object_id: str) -> Dict[str, Any]:
        resp = await self.get("/indicators/entities/iocs/v1", params={"ids": object_id})
        resources = resp.get("resources", []) if isinstance(resp, dict) else []
        return resources[0] if resources else {}

    async def list_objects(self, stix_type: str,
                           filters: Optional[Dict[str, Any]] = None,
                           page: int = 1, page_size: int = 100) -> List[Dict[str, Any]]:
        params: Dict[str, Any] = {"limit": page_size, "offset": (page - 1) * page_size}
        resp = await self.get("/indicators/queries/iocs/v1", params=params)
        return resp.get("resources", []) if isinstance(resp, dict) else []

    async def upsert_object(self, stix_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        resp = await self.post("/indicators/entities/iocs/v1",
                               json={"indicators": [payload]})
        resources = resp.get("resources", []) if isinstance(resp, dict) else []
        return resources[0] if resources else {}

    async def delete_object(self, stix_type: str, object_id: str) -> None:
        await self.delete(f"/indicators/entities/iocs/v1?ids={object_id}")

    def to_stix(self, native: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "type": "indicator",
            "id": f"indicator--{native.get('id', '')}",
            "name": native.get("value", ""),
            "pattern": f"[ipv4-addr:value = '{native.get('value', '')}']",
            "pattern_type": "stix",
            "created": native.get("created_timestamp", ""),
            "modified": native.get("modified_timestamp", ""),
        }

    def from_stix(self, stix_dict: Dict[str, Any]) -> Dict[str, Any]:
        return {"type": "ipv4", "value": stix_dict.get("name", ""),
                "action": "detect", "severity": "medium"}


# ---------------------------------------------------------------------------
# Proofpoint
# ---------------------------------------------------------------------------

class AsyncProofpointClient(AsyncBaseClient, ConnectorMixin):
    """Async Proofpoint TAP connector — HTTP Basic."""

    stix_type_map = {"indicator": "threat"}

    def __init__(self, host: str, service_principal: str = "",
                 secret: str = "", **kwargs: Any):
        super().__init__(host=host, **kwargs)
        self._sp = service_principal
        self._secret = secret

    async def authenticate(self) -> None:
        encoded = base64.b64encode(f"{self._sp}:{self._secret}".encode()).decode()
        self._auth_headers["Authorization"] = f"Basic {encoded}"

    async def health_check(self) -> bool:
        await self.get("/v2/siem/all", params={"format": "json", "sinceSeconds": 60})
        return True

    async def get_object(self, stix_type: str, object_id: str) -> Dict[str, Any]:
        resp = await self.get("/v2/forensics", params={"threatId": object_id})
        return resp if isinstance(resp, dict) else {}

    async def list_objects(self, stix_type: str,
                           filters: Optional[Dict[str, Any]] = None,
                           page: int = 1, page_size: int = 100) -> List[Dict[str, Any]]:
        params: Dict[str, Any] = {"format": "json", "sinceSeconds": 3600}
        if filters:
            params.update(filters)
        resp = await self.get("/v2/siem/all", params=params)
        return resp.get("messagesDelivered", []) if isinstance(resp, dict) else []

    async def upsert_object(self, stix_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        raise SAKClientError("Proofpoint TAP API does not support object creation.")

    async def delete_object(self, stix_type: str, object_id: str) -> None:
        raise SAKClientError("Proofpoint TAP API does not support object deletion.")

    def to_stix(self, native: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "type": "indicator",
            "id": f"indicator--{native.get('id', native.get('threatId', ''))}",
            "name": native.get("subject", native.get("url", "")),
            "pattern_type": "stix",
            "created": native.get("messageTime", ""),
            "modified": native.get("messageTime", ""),
        }

    def from_stix(self, stix_dict: Dict[str, Any]) -> Dict[str, Any]:
        return {"threatId": stix_dict.get("id", "").split("--")[-1]}


# ---------------------------------------------------------------------------
# Netskope
# ---------------------------------------------------------------------------

class AsyncNetskopeClient(AsyncBaseClient, ConnectorMixin):
    """Async Netskope REST API v2 connector — API token."""

    stix_type_map = {"indicator": "urllist"}

    def __init__(self, host: str, api_token: str = "", **kwargs: Any):
        super().__init__(host=host, **kwargs)
        self._api_token = api_token

    async def authenticate(self) -> None:
        self._auth_headers["Netskope-Api-Token"] = self._api_token

    async def health_check(self) -> bool:
        await self.get("/api/v2/policy/urllist", params={"limit": 1})
        return True

    async def get_object(self, stix_type: str, object_id: str) -> Dict[str, Any]:
        return await self.get(f"/api/v2/policy/urllist/{object_id}")

    async def list_objects(self, stix_type: str,
                           filters: Optional[Dict[str, Any]] = None,
                           page: int = 1, page_size: int = 100) -> List[Dict[str, Any]]:
        params: Dict[str, Any] = {"limit": page_size, "skip": (page - 1) * page_size}
        if filters:
            params.update(filters)
        resp = await self.get("/api/v2/policy/urllist", params=params)
        return resp.get("data", []) if isinstance(resp, dict) else []

    async def upsert_object(self, stix_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        list_id = payload.pop("id", None)
        if list_id:
            return await self.patch(f"/api/v2/policy/urllist/{list_id}", json=payload)
        return await self.post("/api/v2/policy/urllist", json=payload)

    async def delete_object(self, stix_type: str, object_id: str) -> None:
        await self.delete(f"/api/v2/policy/urllist/{object_id}")

    def to_stix(self, native: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "type": "indicator",
            "id": f"indicator--{native.get('id', '')}",
            "name": native.get("name", ""),
            "created": native.get("modify_by", ""),
            "modified": native.get("modify_by", ""),
        }

    def from_stix(self, stix_dict: Dict[str, Any]) -> Dict[str, Any]:
        return {"name": stix_dict.get("name", ""), "type": "exact", "data": {"urls": []}}


# ---------------------------------------------------------------------------
# XSOAR
# ---------------------------------------------------------------------------

class AsyncXSOARClient(AsyncBaseClient, ConnectorMixin):
    """Async XSOAR 6 connector — API key."""

    stix_type_map = {"indicator": "indicator", "malware": "indicator",
                     "threat-actor": "indicator", "vulnerability": "indicator"}

    def __init__(self, host: str, api_key: str = "",
                 auth_id: str = "", **kwargs: Any):
        super().__init__(host=host, **kwargs)
        self._api_key = api_key
        self._auth_id = auth_id

    async def authenticate(self) -> None:
        self._auth_headers["Authorization"] = self._api_key
        if self._auth_id:
            self._auth_headers["x-xdr-auth-id"] = self._auth_id

    async def health_check(self) -> bool:
        await self.get("/health")
        return True

    async def get_object(self, stix_type: str, object_id: str) -> Dict[str, Any]:
        resp = await self.post("/indicators/search",
                               json={"query": f"id:{object_id}", "size": 1})
        items = resp.get("iocObjects", []) if isinstance(resp, dict) else []
        return items[0] if items else {}

    async def list_objects(self, stix_type: str,
                           filters: Optional[Dict[str, Any]] = None,
                           page: int = 1, page_size: int = 100) -> List[Dict[str, Any]]:
        query = filters.get("query", "") if filters else ""
        resp = await self.post("/indicators/search",
                               json={"query": query, "size": page_size, "page": page - 1})
        return resp.get("iocObjects", []) if isinstance(resp, dict) else []

    async def upsert_object(self, stix_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        return await self.post("/indicators/edit", json=payload)

    async def delete_object(self, stix_type: str, object_id: str) -> None:
        await self.post("/indicators/delete",
                        json={"id": object_id, "doNotWhitelist": False})

    def to_stix(self, native: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "type": "indicator",
            "id": f"indicator--{native.get('id', '')}",
            "name": native.get("value", ""),
            "pattern": f"[ipv4-addr:value = '{native.get('value', '')}']",
            "pattern_type": "stix",
            "created": native.get("timestamp", ""),
            "modified": native.get("modified", ""),
        }

    def from_stix(self, stix_dict: Dict[str, Any]) -> Dict[str, Any]:
        return {"value": stix_dict.get("name", ""), "indicator_type": "IP", "score": 2}


# ---------------------------------------------------------------------------
# Recorded Future
# ---------------------------------------------------------------------------

class AsyncRecordedFutureClient(AsyncBaseClient, ConnectorMixin):
    """Async Recorded Future Connect API connector — API token."""

    stix_type_map = {"indicator": "ip", "malware": "malware",
                     "threat-actor": "threat-actor", "vulnerability": "vulnerability"}

    def __init__(self, host: str, api_token: str = "", **kwargs: Any):
        super().__init__(host=host, **kwargs)
        self._api_token = api_token

    async def authenticate(self) -> None:
        self._auth_headers["X-RFToken"] = self._api_token

    async def health_check(self) -> bool:
        await self.get("/v2/ip/search", params={"limit": 1})
        return True

    async def get_object(self, stix_type: str, object_id: str) -> Dict[str, Any]:
        resource = self.stix_type_map.get(stix_type, stix_type)
        resp = await self.get(f"/v2/{resource}/{object_id}",
                              params={"fields": "entity,risk,timestamps"})
        return resp.get("data", {}) if isinstance(resp, dict) else {}

    async def list_objects(self, stix_type: str,
                           filters: Optional[Dict[str, Any]] = None,
                           page: int = 1, page_size: int = 100) -> List[Dict[str, Any]]:
        resource = self.stix_type_map.get(stix_type, stix_type)
        params: Dict[str, Any] = {"limit": page_size, "from": (page - 1) * page_size}
        if filters:
            params.update(filters)
        resp = await self.get(f"/v2/{resource}/search", params=params)
        return resp.get("data", {}).get("results", []) if isinstance(resp, dict) else []

    async def upsert_object(self, stix_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        raise SAKClientError("Recorded Future API is read-only.")

    async def delete_object(self, stix_type: str, object_id: str) -> None:
        raise SAKClientError("Recorded Future API is read-only.")

    def to_stix(self, native: Dict[str, Any]) -> Dict[str, Any]:
        entity = native.get("entity", {})
        risk = native.get("risk", {})
        return {
            "type": "indicator",
            "id": f"indicator--{entity.get('id', '')}",
            "name": entity.get("name", ""),
            "pattern": f"[ipv4-addr:value = '{entity.get('name', '')}']",
            "pattern_type": "stix",
            "created": native.get("timestamps", {}).get("firstSeen", ""),
            "modified": native.get("timestamps", {}).get("lastSeen", ""),
            "x_rf_risk_score": risk.get("score", 0),
            "x_rf_criticality": risk.get("criticalityLabel", ""),
        }

    def from_stix(self, stix_dict: Dict[str, Any]) -> Dict[str, Any]:
        return {"entity": stix_dict.get("name", "")}


# ---------------------------------------------------------------------------
# GreyMatter
# ---------------------------------------------------------------------------

class AsyncGreyMatterClient(AsyncBaseClient, ConnectorMixin):
    """Async GreyMatter connector — OAuth2."""
    stix_type_map = {"indicator": "observables", "threat-actor": "threat-actors",
                     "malware": "malware", "vulnerability": "vulnerabilities"}
    def __init__(self, host, client_id="", client_secret="", **kw):
        super().__init__(host=host, **kw)
        self._client_id = client_id; self._client_secret = client_secret
    async def authenticate(self):
        resp = await self.post("/v1/auth/token", data={
            "grant_type": "client_credentials",
            "client_id": self._client_id, "client_secret": self._client_secret})
        token = resp.get("access_token") if isinstance(resp, dict) else None
        if not token: raise SAKClientError("AsyncGreyMatter: no token")
        self._auth_headers["Authorization"] = f"Bearer {token}"
    async def health_check(self): await self.get("/v1/health"); return True
    async def get_object(self, t, oid): return await self.get(f"/v1/{t}/{oid.split('--')[-1]}")
    async def list_objects(self, t, f=None, page=1, ps=100):
        r = await self.get(f"/v1/{t}", params={"limit": ps, "offset": (page-1)*ps})
        return r.get("data", []) if isinstance(r, dict) else []
    async def upsert_object(self, t, p):
        gid = p.pop("id", None)
        return await (self.put(f"/v1/{t}/{gid}", json=p) if gid else self.post(f"/v1/{t}", json=p))
    async def delete_object(self, t, oid): await self.delete(f"/v1/{t}/{oid.split('--')[-1]}")
    def to_stix(self, n):
        from ctm_sak.connectors.greymatter.client import GreyMatterClient
        return GreyMatterClient(host=self.host).to_stix(n)
    def from_stix(self, d):
        from ctm_sak.connectors.greymatter.client import GreyMatterClient
        return GreyMatterClient(host=self.host).from_stix(d)


# ---------------------------------------------------------------------------
# Whistic
# ---------------------------------------------------------------------------

class AsyncWhisticClient(AsyncBaseClient, ConnectorMixin):
    """Async Whistic connector — API key."""
    stix_type_map = {"threat-actor": "vendors", "x-assessment": "assessments"}
    def __init__(self, host, api_key="", **kw):
        super().__init__(host=host, **kw)
        self._api_key = api_key
    async def authenticate(self): self._auth_headers["X-Whistic-Token"] = self._api_key
    async def health_check(self): await self.get("/v1/vendors", params={"limit": 1}); return True
    async def get_object(self, t, oid):
        ep = "/v1/vendors" if t == "threat-actor" else "/v1/assessments"
        return await self.get(f"{ep}/{oid}")
    async def list_objects(self, t, f=None, page=1, ps=100):
        ep = "/v1/vendors" if t == "threat-actor" else "/v1/assessments"
        r = await self.get(ep, params={"limit": ps, "offset": (page-1)*ps})
        return r.get("vendors", r.get("assessments", [])) if isinstance(r, dict) else []
    async def upsert_object(self, t, p): raise SAKClientError("Whistic: direct create not supported")
    async def delete_object(self, t, oid): await self.delete(f"/v1/vendors/{oid}")
    def to_stix(self, n):
        from ctm_sak.connectors.whistic.client import WhisticClient
        return WhisticClient(host=self.host).to_stix(n)
    def from_stix(self, d):
        from ctm_sak.connectors.whistic.client import WhisticClient
        return WhisticClient(host=self.host).from_stix(d)


# ---------------------------------------------------------------------------
# RiskRecon
# ---------------------------------------------------------------------------

class AsyncRiskReconClient(AsyncBaseClient, ConnectorMixin):
    """Async RiskRecon connector — OAuth2."""
    stix_type_map = {"threat-actor": "companies", "vulnerability": "findings"}
    def __init__(self, host, client_id="", client_secret="", **kw):
        super().__init__(host=host, **kw)
        self._client_id = client_id; self._client_secret = client_secret
    async def authenticate(self):
        resp = await self.post("/oauth2/token", data={
            "grant_type": "client_credentials",
            "client_id": self._client_id, "client_secret": self._client_secret})
        token = resp.get("access_token") if isinstance(resp, dict) else None
        if not token: raise SAKClientError("AsyncRiskRecon: no token")
        self._auth_headers["Authorization"] = f"Bearer {token}"
    async def health_check(self): await self.get("/companies", params={"limit": 1}); return True
    async def get_object(self, t, oid): return await self.get(f"/{t}/{oid.split('--')[-1]}")
    async def list_objects(self, t, f=None, page=1, ps=100):
        r = await self.get("/companies", params={"limit": ps, "offset": (page-1)*ps})
        return r.get("companies", []) if isinstance(r, dict) else []
    async def upsert_object(self, t, p): return await self.post("/companies", json=p)
    async def delete_object(self, t, oid): await self.delete(f"/companies/{oid.split('--')[-1]}")
    def to_stix(self, n):
        from ctm_sak.connectors.riskrecon.client import RiskReconClient
        return RiskReconClient(host=self.host).to_stix(n)
    def from_stix(self, d):
        from ctm_sak.connectors.riskrecon.client import RiskReconClient
        return RiskReconClient(host=self.host).from_stix(d)


# ---------------------------------------------------------------------------
# Feedly
# ---------------------------------------------------------------------------

class AsyncFeedlyClient(AsyncBaseClient, ConnectorMixin):
    """Async Feedly connector — Bearer token, read-only."""
    stix_type_map = {"indicator": "iocFeed", "vulnerability": "cvesFeed"}
    def __init__(self, host, api_token="", **kw):
        super().__init__(host=host, **kw)
        self._api_token = api_token
    async def authenticate(self): self._auth_headers["Authorization"] = f"Bearer {self._api_token}"
    async def health_check(self): await self.get("/v3/profile"); return True
    async def get_object(self, t, oid): return await self.get(f"/v3/entities/{oid}")
    async def list_objects(self, t, f=None, page=1, ps=100):
        import time; nt = int((time.time() - 86400) * 1000)
        endpoint = "/v3/enterprise/iocFeed" if t == "indicator" else "/v3/enterprise/cvesFeed"
        r = await self.get(endpoint, params={"newerThan": nt, "count": ps})
        return r.get("indicators", r.get("cves", [])) if isinstance(r, dict) else []
    async def upsert_object(self, t, p): raise SAKClientError("Feedly is read-only")
    async def delete_object(self, t, oid): raise SAKClientError("Feedly is read-only")
    def to_stix(self, n):
        from ctm_sak.connectors.feedly.client import FeedlyClient
        return FeedlyClient(host=self.host).to_stix(n)
    def from_stix(self, d): return {"note": "Feedly read-only"}


# ---------------------------------------------------------------------------
# Splunk
# ---------------------------------------------------------------------------

class AsyncSplunkClient(AsyncBaseClient, ConnectorMixin):
    """Async Splunk connector — token or username/password."""
    stix_type_map = {"indicator": "threat_activity", "vulnerability": "notable"}
    def __init__(self, host, api_token="", username="", password="", **kw):
        super().__init__(host=host, **kw)
        self._api_token = api_token; self._username = username; self._password = password
    async def authenticate(self):
        if self._api_token:
            self._auth_headers["Authorization"] = f"Bearer {self._api_token}"; return
        resp = await self.post("/services/auth/login",
                               data={"username": self._username, "password": self._password,
                                     "output_mode": "json"})
        key = resp.get("sessionKey") if isinstance(resp, dict) else None
        if not key: raise SAKClientError("AsyncSplunk: auth failed")
        self._auth_headers["Authorization"] = f"Splunk {key}"
    async def health_check(self):
        await self.get("/services/server/info", params={"output_mode": "json"}); return True
    async def get_object(self, t, oid): return {}
    async def list_objects(self, t, f=None, page=1, ps=100): return []
    async def upsert_object(self, t, p): return {}
    async def delete_object(self, t, oid): pass
    def to_stix(self, n):
        from ctm_sak.connectors.splunk.client import SplunkClient
        return SplunkClient(host=self.host).to_stix(n)
    def from_stix(self, d):
        from ctm_sak.connectors.splunk.client import SplunkClient
        return SplunkClient(host=self.host).from_stix(d)
