# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.human_security
==================================

HUMAN Security (formerly White Ops) bot-defense connector. Wraps the
v1 REST API at ``https://api.humansecurity.com/``.
"""

from .client import HumanSecurityClient

__all__ = ["HumanSecurityClient"]
