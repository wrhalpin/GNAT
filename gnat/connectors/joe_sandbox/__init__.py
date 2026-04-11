# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.joe_sandbox
===============================

Joe Sandbox Cloud connector — dynamic malware analysis with detailed
behavioral reports. Wraps ``https://jbxcloud.joesecurity.org/api/v2/``.
"""

from .client import JoeSandboxClient

__all__ = ["JoeSandboxClient"]
