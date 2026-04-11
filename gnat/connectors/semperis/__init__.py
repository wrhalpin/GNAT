# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.semperis
============================

Semperis Directory Services Protector (DSP) connector — Active Directory
and Entra ID posture management, Indicators of Exposure (IoE), and
Indicators of Compromise (IoC).
"""

from .client import SemperisClient

__all__ = ["SemperisClient"]
