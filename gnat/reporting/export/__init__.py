# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.reporting.export
======================

Export pipeline for published intelligence reports.

Currently provides:

- :func:`~.stix.report_to_stix_bundle` — serialize a published
  :class:`~gnat.reporting.models.Report` to a STIX 2.1 bundle dict.
"""

from gnat.reporting.export.stix import report_to_stix_bundle

__all__ = ["report_to_stix_bundle"]
