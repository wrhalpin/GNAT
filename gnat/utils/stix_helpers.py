# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Bill Halpin
"""
gnat.utils.stix_helpers
===========================
Utility functions for working with STIX 2.1 objects and bundles.
"""

import uuid
from datetime import datetime, timezone
from typing import Any


def utcnow() -> str:
    """Return current UTC time in STIX timestamp format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def make_bundle(objects: list[dict[str, Any]]) -> dict[str, Any]:
    """Wrap a list of STIX objects in a STIX 2.1 bundle."""
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "spec_version": "2.1",
        "objects": objects,
    }


def extract_objects(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    """Extract the objects list from a STIX bundle."""
    return bundle.get("objects", [])


def filter_by_type(objects: list[dict[str, Any]], stix_type: str) -> list[dict[str, Any]]:
    """Filter a list of STIX objects by type."""
    return [o for o in objects if o.get("type") == stix_type]


def validate_stix_id(stix_id: str) -> bool:
    """Return True if *stix_id* follows the STIX id format ``<type>--<uuid4>``."""
    parts = stix_id.split("--", 1)
    if len(parts) != 2:
        return False
    try:
        uuid.UUID(parts[1])
        return True
    except ValueError:
        return False
