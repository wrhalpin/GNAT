# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.hybrid_analysis
===================================

Hybrid Analysis (CrowdStrike Falcon Sandbox) connector. Wraps the public
API at ``https://www.hybrid-analysis.com/api/v2/``.
"""

from .client import HybridAnalysisClient

__all__ = ["HybridAnalysisClient"]
