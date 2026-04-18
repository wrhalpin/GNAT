# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.plugins.huntgnat.errors
================================

Error types for HuntGNAT rule translation.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class UntranslatableError(Exception):
    """
    Raised when a STIX pattern cannot be faithfully rendered in a
    target detection language.

    Per the HuntGNAT design contract, silent semantic drops are
    forbidden. If a construct cannot be expressed, this error is
    raised with a structured reason so the caller can decide whether
    to skip, log, or alert.
    """

    reason: str
    pattern: str
    target_language: str

    def __str__(self) -> str:
        return (
            f"cannot translate to {self.target_language}: {self.reason} "
            f"(pattern: {self.pattern!r})"
        )
