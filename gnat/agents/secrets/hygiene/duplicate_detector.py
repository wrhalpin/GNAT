from __future__ import annotations

import hashlib
from collections import defaultdict
from typing import Dict, Iterable, List, Tuple

from ..models import DuplicateSecretFinding


class DuplicateSecretDetector:
    def fingerprint(self, value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    def find_duplicates(self, secrets: Iterable[Tuple[str, str]]) -> List[DuplicateSecretFinding]:
        buckets: Dict[str, List[str]] = defaultdict(list)
        for location, value in secrets:
            if not value:
                continue
            buckets[self.fingerprint(value)].append(location)
        return [
            DuplicateSecretFinding(value_fingerprint=fingerprint, locations=locations)
            for fingerprint, locations in buckets.items()
            if len(locations) > 1
        ]
