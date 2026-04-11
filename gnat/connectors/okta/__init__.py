# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.okta
========================

Okta Identity Cloud connector. Wraps the v1 REST API at
``https://<tenant>.okta.com/api/v1/``.
"""

from .client import OktaClient

__all__ = ["OktaClient"]
