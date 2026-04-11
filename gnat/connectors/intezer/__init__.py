# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.intezer
===========================

Intezer Analyze connector — binary DNA / code-reuse malware family
attribution. Wraps ``https://analyze.intezer.com/api/v2-0/``.
"""

from .client import IntezerClient

__all__ = ["IntezerClient"]
