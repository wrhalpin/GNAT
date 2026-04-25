# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""Pydantic v2 schema for investigation seeds."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class SeedSchema(BaseModel):
    """A single investigation seed value."""

    model_config = ConfigDict(from_attributes=True)

    value: str = Field(
        description="The seed string (IP address, case ID, hostname, hash, etc.).",
    )
    seed_type: Literal[
        "ioc_value",
        "ip",
        "domain",
        "hash",
        "email",
        "url",
        "hostname",
        "username",
        "alert_id",
        "case_id",
        "ticket_ref",
        "email_subject",
    ] = Field(
        description="Tells the builder how to query each connector.",
    )
    hint_platform: str | None = Field(
        default=None,
        description="Restrict expansion to a single platform name.",
    )

    @classmethod
    def from_domain(cls, obj: object) -> SeedSchema:
        """Hydrate from a domain Seed dataclass."""
        return cls.model_validate(obj, from_attributes=True)
