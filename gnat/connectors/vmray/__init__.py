# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.vmray
=========================

VMRay connector — hypervisor-level dynamic malware analysis platform.
Wraps ``https://cloud.vmray.com/rest/``.
"""

from .client import VMRayClient

__all__ = ["VMRayClient"]
