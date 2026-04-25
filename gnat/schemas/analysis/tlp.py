# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Pydantic v2 schema for TLP classification levels."""

from enum import Enum


class TLPLevelSchema(str, Enum):
    """Traffic Light Protocol 2.0 classification levels (schema mirror)."""

    WHITE = "white"
    CLEAR = "clear"
    GREEN = "green"
    AMBER = "amber"
    AMBER_STRICT = "amber+strict"
    RED = "red"
