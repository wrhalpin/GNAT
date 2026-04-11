# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.trm_labs
============================

TRM Labs connector — blockchain / cryptocurrency threat intelligence and
wallet-risk screening. Wraps ``https://api.trmlabs.com/public/v2/``.
"""

from .client import TRMLabsClient

__all__ = ["TRMLabsClient"]
