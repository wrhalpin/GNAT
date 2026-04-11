# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.cloudflare_intel
====================================

Cloudflare Threat Intelligence API connector.

Wraps the domain / IP / ASN / WHOIS / passive-DNS intel endpoints published
under ``/client/v4/accounts/{account_id}/intel/``.  Cloudflare's 2026
Threat Report positions these endpoints as the productized view of the
telemetry that powers their public DNS resolver, WAF, and Radar services.
"""

from .client import CloudflareIntelClient

__all__ = ["CloudflareIntelClient"]
