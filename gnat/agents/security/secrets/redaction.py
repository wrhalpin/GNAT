from typing import Iterable
def redact_text(text: str, secrets: Iterable[str]) -> str:
    for secret in secrets:
        if secret:
            text = text.replace(secret, "***REDACTED***")
    return text
