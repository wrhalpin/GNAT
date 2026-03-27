# “””
ctm_sak.connectors.elastic.config

Configuration schema for the Elastic Security connector.

## INI example — self-hosted

[elastic]
es_host           = elasticsearch.corp.example.com
es_port           = 9200
kibana_host       = kibana.corp.example.com
kibana_port       = 5601
scheme            = https
api_key_id        = VuaCfGcBCdbkQm-e5aOx
api_key_secret    = ui2lp2axTNmsyakw9tvNnw
verify_ssl        = true
timeout           = 30
max_results       = 1000
es_index_alerts   = .alerts-security.*
es_index_ti       = logs-ti_*
kibana_space      = default

## INI example — Elastic Cloud

[elastic]
cloud_id          = my-cluster:dXMtZWFzdC0xLmF3cy5mb3VuZC5pbyQ…
api_key_id        = VuaCfGcBCdbkQm-e5aOx
api_key_secret    = ui2lp2axTNmsyakw9tvNnw
verify_ssl        = true
timeout           = 30
max_results       = 1000
kibana_space      = default

## Notes

- `cloud_id` takes precedence over es_host/es_port/kibana_host/kibana_port.
  When cloud_id is provided, hosts are decoded from it automatically.
- `api_key_id` and `api_key_secret` together form the API key credential.
  The Authorization header sent is: `ApiKey <base64(id:secret)>`
- `kibana_space` scopes all Kibana Security API calls to a specific space.
  Use ‘default’ for the default space.
- `max_results` applies to Kibana paginated endpoints. Elasticsearch search
  uses a separate `size` parameter per query (max 10,000 without PIT).
- `es_index_alerts` and `es_index_ti` are index patterns used as defaults
  in search operations.
  “””

import base64
import configparser
from dataclasses import dataclass, field

from .exceptions import ElasticConfigError

_REQUIRED_WITH_CLOUD = {“api_key_id”, “api_key_secret”}
_REQUIRED_WITHOUT_CLOUD = {“es_host”, “api_key_id”, “api_key_secret”}

*DEFAULTS: dict = {
“es_host”: “”,
“es_port”: “9200”,
“kibana_host”: “”,
“kibana_port”: “5601”,
“scheme”: “https”,
“api_key_id”: “”,
“api_key_secret”: “”,
“verify_ssl”: “true”,
“timeout”: “30”,
“max_results”: “1000”,
“es_index_alerts”: “.alerts-security.*”,
“es_index_ti”: “logs-ti**”,
“kibana_space”: “default”,
“cloud_id”: “”,
}

@dataclass
class ElasticConfig:
“””
Validated configuration for the Elastic Security connector.

```
Attributes
----------
es_host : str
    Elasticsearch hostname (ignored when cloud_id is set).
es_port : int
    Elasticsearch port (default 9200).
kibana_host : str
    Kibana hostname. Defaults to es_host if not set.
kibana_port : int
    Kibana port (default 5601).
scheme : str
    'https' or 'http'.
api_key_id : str
    Elastic API key ID component.
api_key_secret : str
    Elastic API key secret component.
verify_ssl : bool
    Whether to verify TLS certificates.
timeout : int
    HTTP timeout in seconds.
max_results : int
    Default page size for Kibana paginated endpoints.
es_index_alerts : str
    Default index pattern for alert searches.
es_index_ti : str
    Default index pattern for threat intelligence.
kibana_space : str
    Kibana space ID for Security API scoping.
cloud_id : str
    Elastic Cloud deployment ID. Overrides host/port when set.
es_base_url : str
    Computed Elasticsearch base URL.
kibana_base_url : str
    Computed Kibana base URL.
api_key_header : str
    Computed base64-encoded API key header value.
"""

api_key_id: str
api_key_secret: str
es_host: str = ""
es_port: int = 9200
kibana_host: str = ""
kibana_port: int = 5601
scheme: str = "https"
verify_ssl: bool = True
timeout: int = 30
max_results: int = 1000
es_index_alerts: str = ".alerts-security.*"
es_index_ti: str = "logs-ti_*"
kibana_space: str = "default"
cloud_id: str = ""
es_base_url: str = field(init=False)
kibana_base_url: str = field(init=False)
api_key_header: str = field(init=False)

def __post_init__(self) -> None:
    if self.cloud_id:
        self._decode_cloud_id()
    else:
        if not self.kibana_host:
            self.kibana_host = self.es_host
        self.es_base_url = f"{self.scheme}://{self.es_host}:{self.es_port}"
        self.kibana_base_url = f"{self.scheme}://{self.kibana_host}:{self.kibana_port}"

    raw_key = f"{self.api_key_id}:{self.api_key_secret}"
    self.api_key_header = base64.b64encode(raw_key.encode()).decode()
    self._validate()

def _decode_cloud_id(self) -> None:
    """
    Decode an Elastic Cloud ID into ES and Kibana base URLs.

    Cloud ID format:
      <cluster_name>:<base64(region:es_uuid.region.dns:port$kb_uuid.region.dns:port)>
    """
    try:
        _, encoded = self.cloud_id.split(":", 1)
        decoded = base64.b64decode(encoded + "==").decode("utf-8")
        parts = decoded.split("$")
        region_host = parts[0]
        es_host_part = parts[1] if len(parts) > 1 else ""
        kb_host_part = parts[2] if len(parts) > 2 else es_host_part

        # Strip trailing port if present in host part
        es_fqdn = f"{es_host_part}.{region_host}"
        kb_fqdn = f"{kb_host_part}.{region_host}"

        self.es_host = es_fqdn
        self.kibana_host = kb_fqdn
        self.es_base_url = f"https://{es_fqdn}"
        self.kibana_base_url = f"https://{kb_fqdn}"
    except Exception as exc:
        raise ElasticConfigError(
            f"Invalid cloud_id format: {exc}"
        ) from exc

def _validate(self) -> None:
    if not self.api_key_id:
        raise ElasticConfigError("'api_key_id' is required in [elastic] config.")
    if not self.api_key_secret:
        raise ElasticConfigError("'api_key_secret' is required in [elastic] config.")
    if not self.cloud_id and not self.es_host:
        raise ElasticConfigError(
            "Either 'es_host' or 'cloud_id' is required in [elastic] config."
        )
    if self.scheme not in ("http", "https"):
        raise ElasticConfigError(
            f"Invalid scheme '{self.scheme}'. Must be 'http' or 'https'."
        )
    if self.timeout <= 0:
        raise ElasticConfigError("'timeout' must be a positive integer.")
    if self.max_results <= 0:
        raise ElasticConfigError("'max_results' must be a positive integer.")

def es_url(self, path: str) -> str:
    """Build a full Elasticsearch API URL."""
    return f"{self.es_base_url}/{path.lstrip('/')}"

def kibana_url(self, path: str) -> str:
    """
    Build a full Kibana API URL, scoped to the configured space.

    Kibana Security API paths are scoped under:
      /s/<space_id>/api/...  (non-default spaces)
      /api/...               (default space — no /s/ prefix)
    """
    path = path.lstrip("/")
    if self.kibana_space and self.kibana_space != "default":
        return f"{self.kibana_base_url}/s/{self.kibana_space}/{path}"
    return f"{self.kibana_base_url}/{path}"

@property
def auth_headers(self) -> dict[str, str]:
    """Return the Authorization header dict for both ES and Kibana."""
    return {"Authorization": f"ApiKey {self.api_key_header}"}

@property
def kibana_headers(self) -> dict[str, str]:
    """Return full headers required for Kibana API write operations."""
    return {
        **self.auth_headers,
        "kbn-xsrf": "true",
        "Content-Type": "application/json",
    }

@property
def kibana_get_headers(self) -> dict[str, str]:
    """Return headers for Kibana GET requests (no kbn-xsrf needed)."""
    return {
        **self.auth_headers,
        "Content-Type": "application/json",
    }
```

def load_elastic_config(
config: configparser.ConfigParser,
section: str = “elastic”,
) -> ElasticConfig:
“””
Parse [elastic] section from a ctm_sak.ini ConfigParser instance.

```
Parameters
----------
config : configparser.ConfigParser
    Already-loaded ConfigParser.
section : str
    INI section name.

Returns
-------
ElasticConfig

Raises
------
ElasticConfigError
"""
if not config.has_section(section):
    raise ElasticConfigError(
        f"Configuration section '[{section}]' not found in ctm_sak.ini."
    )

raw = dict(_DEFAULTS)
raw.update(dict(config.items(section)))

def _bool(v: str) -> bool:
    return v.strip().lower() in ("true", "1", "yes")

return ElasticConfig(
    es_host=raw["es_host"].strip(),
    es_port=int(raw["es_port"]),
    kibana_host=raw["kibana_host"].strip(),
    kibana_port=int(raw["kibana_port"]),
    scheme=raw["scheme"].strip().lower(),
    api_key_id=raw["api_key_id"].strip(),
    api_key_secret=raw["api_key_secret"].strip(),
    verify_ssl=_bool(raw["verify_ssl"]),
    timeout=int(raw["timeout"]),
    max_results=int(raw["max_results"]),
    es_index_alerts=raw["es_index_alerts"].strip(),
    es_index_ti=raw["es_index_ti"].strip(),
    kibana_space=raw["kibana_space"].strip(),
    cloud_id=raw["cloud_id"].strip(),
)
```