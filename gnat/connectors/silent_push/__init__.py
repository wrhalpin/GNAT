# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.silent_push
===============================

Silent Push connector — pre-weaponization attack infrastructure telemetry
and actor-behavior profiling. Wraps ``https://api.silentpush.com/``.
"""

from .client import SilentPushClient

__all__ = ["SilentPushClient"]
