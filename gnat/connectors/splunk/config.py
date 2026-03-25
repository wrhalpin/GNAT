# “””
ctm_sak.connectors.splunk.config

Configuration schema for the Splunk connector.

Reads from the [splunk] section of ctm_sak.ini.
All fields have safe defaults; host/port/credentials are required at runtime.

## INI example

[splunk]
host            = splunk.corp.example.com
port            = 8089
scheme          = https
username        = svc_ctm_sak
password        = s3cr3t                    ; omit if using token
token           =                           ; pre-generated token (preferred)
verify_ssl      = true
app_context     = search
es_enabled      = true
default_index   = main
timeout         = 30
max_results     = 10000
“””

import configparser
from dataclasses import dataclass, field
from typing import Optional

from .exceptions import SplunkConfigError

# ── Required keys ────────────────────────────────────────────────────────────

_REQUIRED = {“host”}

# ── Defaults ─────────────────────────────────────────────────────────────────

_DEFAULTS: dict = {
“port”: “8089”,
“scheme”: “https”,
“username”: “”,
“password”: “”,
“token”: “”,
“verify_ssl”: “true”,
“app_context”: “search”,
“es_enabled”: “false”,
“default_index”: “main”,
“timeout”: “30”,
“max_results”: “10000”,
}

@dataclass
class SplunkConfig:
“””
Validated configuration for the Splunk connector.

```
Attributes
----------
host : str
    Hostname or IP of the Splunk instance (splunkd management port).
port : int
    Management port (default 8089).
scheme : str
    'https' (strongly recommended) or 'http'.
username : str
    Splunk username. Not needed when ``token`` is supplied.
password : str
    Splunk password. Not needed when ``token`` is supplied.
token : str
    Pre-generated Splunk auth token. Takes precedence over
    username/password when present.
verify_ssl : bool
    Whether to verify the server's TLS certificate.
app_context : str
    Splunk app namespace for scoped API calls (e.g. 'search', 'SplunkES').
es_enabled : bool
    True when Splunk Enterprise Security is installed; unlocks the
    Threat Intel API commands.
default_index : str
    Index used as default target for search commands.
timeout : int
    HTTP request timeout in seconds.
max_results : int
    Default result count cap for search/list operations.
base_url : str
    Computed from scheme + host + port.
"""

host: str
port: int = 8089
scheme: str = "https"
username: str = ""
password: str = ""
token: str = ""
verify_ssl: bool = True
app_context: str = "search"
es_enabled: bool = False
default_index: str = "main"
timeout: int = 30
max_results: int = 10000
base_url: str = field(init=False)

def __post_init__(self) -> None:
    self.base_url = f"{self.scheme}://{self.host}:{self.port}"
    self._validate()

def _validate(self) -> None:
    if not self.host:
        raise SplunkConfigError("'host' is required in [splunk] config section.")
    if not self.token and not (self.username and self.password):
        raise SplunkConfigError(
            "Either 'token' or both 'username' and 'password' "
            "must be provided in [splunk] config section."
        )
    if self.scheme not in ("http", "https"):
        raise SplunkConfigError(
            f"Invalid scheme '{self.scheme}'. Must be 'http' or 'https'."
        )
    if not (1 <= self.port <= 65535):
        raise SplunkConfigError(f"Invalid port {self.port}.")
    if self.timeout <= 0:
        raise SplunkConfigError("'timeout' must be a positive integer.")
    if self.max_results <= 0:
        raise SplunkConfigError("'max_results' must be a positive integer.")

@property
def uses_token_auth(self) -> bool:
    """True when a pre-generated token is configured."""
    return bool(self.token)

@property
def owner(self) -> str:
    """Owner segment for Splunk REST namespace paths."""
    return self.username or "nobody"

def namespace_path(self, endpoint: str) -> str:
    """
    Build a namespaced endpoint URL.

    Splunk REST paths follow:
      /servicesNS/<owner>/<app>/<endpoint>

    For global (non-namespaced) endpoints use:
      /services/<endpoint>
    """
    return f"{self.base_url}/servicesNS/{self.owner}/{self.app_context}/{endpoint}"

def services_path(self, endpoint: str) -> str:
    """Build a global (non-namespaced) endpoint URL."""
    return f"{self.base_url}/services/{endpoint}"
```

# ── Factory ───────────────────────────────────────────────────────────────────

def load_splunk_config(
config: configparser.ConfigParser,
section: str = “splunk”,
) -> SplunkConfig:
“””
Parse [splunk] section from a ctm_sak.ini ConfigParser instance.

```
Parameters
----------
config : configparser.ConfigParser
    Already-loaded ConfigParser (caller is responsible for reading the file).
section : str
    INI section name. Defaults to 'splunk'.

Returns
-------
SplunkConfig

Raises
------
SplunkConfigError
    If the section is missing or required keys are absent.
"""
if not config.has_section(section):
    raise SplunkConfigError(
        f"Configuration section '[{section}]' not found in ctm_sak.ini."
    )

raw = dict(_DEFAULTS)
raw.update(dict(config.items(section)))

missing = _REQUIRED - set(k for k, v in raw.items() if v.strip())
if missing:
    raise SplunkConfigError(
        f"Missing required [splunk] config keys: {', '.join(sorted(missing))}"
    )

return SplunkConfig(
    host=raw["host"].strip(),
    port=int(raw["port"]),
    scheme=raw["scheme"].strip().lower(),
    username=raw["username"].strip(),
    password=raw["password"].strip(),
    token=raw["token"].strip(),
    verify_ssl=raw["verify_ssl"].strip().lower() in ("true", "1", "yes"),
    app_context=raw["app_context"].strip(),
    es_enabled=raw["es_enabled"].strip().lower() in ("true", "1", "yes"),
    default_index=raw["default_index"].strip(),
    timeout=int(raw["timeout"]),
    max_results=int(raw["max_results"]),
)
```