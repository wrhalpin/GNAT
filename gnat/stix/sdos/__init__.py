# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.stix.sdos
==============

Custom STIX 2.1 Domain Objects (SDOs) for GNAT Phase 4 reasoning and
evidence tracking.

Custom SDO types follow the STIX 2.1 ``x-<namespace>-<name>`` naming
convention and are stored via the existing workspace ORM path.
"""

from gnat.stix.sdos.hypothesis import STIXHypothesis
from gnat.stix.sdos.negative_evidence import NegativeEvidenceRecord

__all__ = ["STIXHypothesis", "NegativeEvidenceRecord"]
