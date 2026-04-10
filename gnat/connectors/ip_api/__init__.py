# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
GNAT ip-api.com Connector
==============================
IP geolocation connector for ip-api.com.

Provides country, region, city, latitude/longitude, ISP, ASN, proxy
detection, and hosting detection for any IPv4/IPv6 address or hostname.

Tiers
-----
Free tier (no key):
  - ``http://ip-api.com``  (HTTP only)
  - 45 req/min single, 15 batch req/min

Pro tier (API key via ``?key=``):
  - ``https://pro.ip-api.com``
  - Higher rate limits, HTTPS

STIX 2.1 mapping
----------------
ip-api.com response → ``observed-data`` SDO with embedded ``ipv4-addr``
SCO and ``x_ipapi_*`` extension fields (country, city, lat/lon, ISP, etc.)

Configuration section (gnat.ini):
  [ip_api]
  host        = http://ip-api.com
  ; api_key   = YOUR_PRO_API_KEY
  timeout     = 30
  batch_delay = 4.0
"""

from .client import IPAPIClient

__all__ = ["IPAPIClient"]

__version__ = "0.1.0"
__platform__ = "ip-api.com"
__api_versions__ = ["v1"]
__stix_support__ = "read-only"
