# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.any_run
===========================

ANY.RUN interactive sandbox connector. Wraps the public API at
``https://api.any.run/v1/``.
"""

from .client import AnyRunClient

__all__ = ["AnyRunClient"]
