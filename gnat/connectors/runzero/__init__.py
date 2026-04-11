# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.connectors.runzero
===========================

runZero CAASM connector.  Exposes the bulk asset / service / software /
vulnerability exports and single-asset lookups from runZero's v1.0 REST
API so that runZero-discovered inventory becomes available to GNAT as
STIX ``observed-data`` SCO bundles.
"""

from .client import RunZeroClient

__all__ = ["RunZeroClient"]
