from __future__ import annotations

import re
from collections.abc import Iterable


def redact_text(text: str, secrets: Iterable[str]) -> str:
    redacted = text
    for secret in secrets:
        if not secret:
            continue
        redacted = redacted.replace(secret, "***REDACTED***")
    return redacted


COMMON_SECRET_PATTERNS = [
    re.compile(r"""(?i)(api[_-]?key|token|secret|password)\s*[:=]\s*['"]?([A-Za-z0-9_\-\./+=]{8,})"""),
]


def scrub_obvious_secrets(text: str) -> str:
    scrubbed = text
    for pattern in COMMON_SECRET_PATTERNS:
        scrubbed = pattern.sub(lambda m: f"{m.group(1)}=***REDACTED***", scrubbed)
    return scrubbed
