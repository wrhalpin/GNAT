# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.gurucul
===========================

Gurucul UEBA connector. Wraps the REST API at
``https://<tenant>.gurucul.com/api/v1/``.
"""

from .client import GuruculClient

__all__ = ["GuruculClient"]
