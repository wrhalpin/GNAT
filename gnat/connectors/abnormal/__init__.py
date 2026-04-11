# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.abnormal
============================

Abnormal Security connector — behavioral AI for BEC, credential
phishing, and vendor impersonation detection. Wraps
``https://api.abnormalplatform.com/v1/``.
"""

from .client import AbnormalClient

__all__ = ["AbnormalClient"]
