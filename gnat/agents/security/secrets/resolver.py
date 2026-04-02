from __future__ import annotations
from typing import Any, Dict
from .broker import SecretsBroker

class ConnectorConfigResolver:
    def __init__(self, broker: SecretsBroker) -> None:
        self.broker = broker
    def resolve_credentials(self, config: Dict[str, Any], *, caller: str = "runtime") -> Dict[str, Any]:
        resolved = dict(config)
        creds = dict(resolved.get("credentials", {}))
        for k, v in list(creds.items()):
            if isinstance(v, dict) and "secret_ref" in v:
                ref = self.broker.parse_ref(v["secret_ref"])
                creds[k] = self.broker.resolve(ref, caller=caller).value
        resolved["credentials"] = creds
        return resolved
