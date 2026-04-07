# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.controlup
=========================

Connector for the ControlUp Digital Employee Experience (DEX) platform.

ControlUp is an endpoint monitoring and management platform covering:

- **DEX / Desktops** (formerly Edge DX): endpoint health, device metrics,
  user experience scores, processes, and security events for physical and
  cloud-managed endpoints.
- **VDI & DaaS**: session monitoring for Citrix, VMware Horizon, Azure
  Virtual Desktop, and similar virtualisation platforms.

This connector targets the **DEX Platform REST API** at
``https://api.controlup.io``.

Auth
----
API key (Bearer token) created at ``app.controlup.com`` → profile icon →
*API Key Management*. The key is scoped to your ControlUp organisation and
the permissions of the account that generated it.

INI config::

    [controlup]
    host        = https://api.controlup.io
    api_key     = eyJhbGciOi...
    org_id      = <your-organisation-id>
    product     = dex          # or: vdi
    auth_type   = token

References
----------
- API reference: https://api.controlup.io/reference
- Create API key: https://support.controlup.com/docs/create-an-api-key
- DEX API guide:  https://api.controlup.io/reference/how-to-use-the-edge-dx-api
"""

from gnat.connectors.controlup.client import ControlUpClient

__all__ = ["ControlUpClient"]
