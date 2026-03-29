"""
gnat.connectors.misp.config
=================================
Configuration schema for the MISP connector.

INI example
-----------
[misp]
url                   = https://misp.corp.example.com
api_key               =
verify_ssl            = true
timeout               = 30
max_results           = 100
default_distribution  = 0
default_threat_level  = 2
default_analysis      = 0

Distribution values
-------------------
  0 = Your organisation only
  1 = This community only
  2 = Connected communities
  3 = All communities
  4 = Sharing group (requires sharing_group_id)

Threat level values
-------------------
  1 = High
  2 = Medium
  3 = Low
  4 = Undefined

Analysis values
---------------
  0 = Initial
  1 = Ongoing
  2 = Completed
"""

import configparser
from dataclasses import dataclass

from .exceptions import MISPConfigError

_REQUIRED = {"url", "api_key"}
_DEFAULTS: dict = {
    "url": "", "api_key": "",
    "verify_ssl": "true", "timeout": "30", "max_results": "100",
    "default_distribution": "0",
    "default_threat_level": "2",
    "default_analysis": "0",
}


@dataclass
class MISPConfig:
    """Validated configuration for the MISP connector."""

    url: str
    api_key: str
    verify_ssl: bool = True
    timeout: int = 30
    max_results: int = 100
    default_distribution: int = 0
    default_threat_level: int = 2
    default_analysis: int = 0

    def __post_init__(self) -> None:
        self.url = self.url.rstrip("/")
        self._validate()

    def _validate(self) -> None:
        if not self.url:
            raise MISPConfigError("'url' is required in [misp] config.")
        if not self.api_key:
            raise MISPConfigError("'api_key' is required in [misp] config.")
        if not self.url.startswith(("http://", "https://")):
            raise MISPConfigError(f"'url' must start with http:// or https://.")

    def endpoint(self, path: str) -> str:
        """Build a full MISP API URL."""
        return f"{self.url}/{path.lstrip('/')}"

    @property
    def base_headers(self) -> dict[str, str]:
        """Return standard MISP API request headers."""
        return {
            "Authorization": self.api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        }


def load_misp_config(
    config: configparser.ConfigParser,
    section: str = "misp",
) -> MISPConfig:
    """Parse [misp] section from gnat.ini."""
    if not config.has_section(section):
        raise MISPConfigError(
            f"Configuration section '[{section}]' not found in gnat.ini."
        )
    raw = dict(_DEFAULTS)
    raw.update(dict(config.items(section)))

    missing = {k for k in _REQUIRED if not raw.get(k, "").strip()}
    if missing:
        raise MISPConfigError(
            f"Missing required [misp] config keys: {', '.join(sorted(missing))}"
        )

    def _bool(v: str) -> bool:
        return v.strip().lower() in ("true", "1", "yes")

    return MISPConfig(
        url=raw["url"].strip(),
        api_key=raw["api_key"].strip(),
        verify_ssl=_bool(raw["verify_ssl"]),
        timeout=int(raw["timeout"]),
        max_results=int(raw["max_results"]),
        default_distribution=int(raw["default_distribution"]),
        default_threat_level=int(raw["default_threat_level"]),
        default_analysis=int(raw["default_analysis"]),
    )
