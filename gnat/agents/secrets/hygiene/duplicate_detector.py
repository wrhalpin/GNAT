from __future__ import annotations

import hashlib
from collections import defaultdict
from collections.abc import Iterable

from ..models import DuplicateSecretFinding


class DuplicateSecretDetector:
    def fingerprint(self, value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    def find_duplicates(self, secrets: Iterable[tuple[str, str]]) -> list[DuplicateSecretFinding]:
        buckets: dict[str, list[str]] = defaultdict(list)
        for location, value in secrets:
            if not value:
                continue
            buckets[self.fingerprint(value)].append(location)
        return [
            DuplicateSecretFinding(value_fingerprint=fingerprint, locations=locations)
            for fingerprint, locations in buckets.items()
            if len(locations) > 1
        ]
