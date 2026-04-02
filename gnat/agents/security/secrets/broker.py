from __future__ import annotations
from typing import Dict
from urllib.parse import parse_qs, urlparse
from .audit import InMemoryAuditRecorder
from .exceptions import SecretPolicyError, SecretProviderError, UnsupportedProviderAction
from .models import SecretRef, SecretValue, SecretVersionInfo, StoreSecretRequest
from .policy import SecretPolicyEngine
from .providers.base import SecretProvider

class SecretsBroker:
    def __init__(self, providers: Dict[str, SecretProvider], policy: SecretPolicyEngine, audit: InMemoryAuditRecorder | None = None) -> None:
        self.providers = providers
        self.policy = policy
        self.audit = audit or InMemoryAuditRecorder()
    def parse_ref(self, uri: str) -> SecretRef:
        parsed = urlparse(uri); params = parse_qs(parsed.query)
        return SecretRef(provider=parsed.scheme, vault=parsed.netloc or None, path=parsed.path.lstrip("/"), version=params.get("version", [None])[0])
    def resolve(self, ref: SecretRef, *, caller: str) -> SecretValue:
        decision = self.policy.decide(ref, action="resolve", caller=caller)
        self.audit.record(action="resolve", actor=caller, ref=ref, allowed=decision.allowed, provider=ref.provider, reason=decision.reason)
        if not decision.allowed: raise SecretPolicyError(decision.reason)
        provider = self._provider(ref.provider)
        if not provider.capabilities().supports_read: raise UnsupportedProviderAction(f"provider does not support resolve: {ref.provider}")
        return provider.resolve(ref)
    def store(self, request: StoreSecretRequest, *, caller: str) -> SecretVersionInfo:
        decision = self.policy.decide(request.ref, action="store", caller=caller, overwrite=request.allow_overwrite)
        self.audit.record(action="store", actor=caller, ref=request.ref, allowed=decision.allowed, provider=request.ref.provider, reason=decision.reason)
        if not decision.allowed: raise SecretPolicyError(decision.reason)
        provider = self._provider(request.ref.provider); caps = provider.capabilities()
        if not caps.supports_write: raise UnsupportedProviderAction(f"provider does not support store: {request.ref.provider}")
        if request.tags and not caps.supports_tagging: raise UnsupportedProviderAction(f"provider does not support tags: {request.ref.provider}")
        return provider.store(request)
    def checkout(self, ref: SecretRef, *, caller: str):
        decision = self.policy.decide(ref, action="checkout", caller=caller)
        self.audit.record(action="checkout", actor=caller, ref=ref, allowed=decision.allowed, provider=ref.provider, reason=decision.reason)
        if not decision.allowed: raise SecretPolicyError(decision.reason)
        provider = self._provider(ref.provider)
        if not provider.capabilities().supports_checkout: raise UnsupportedProviderAction(f"provider does not support checkout: {ref.provider}")
        return provider.checkout(ref)
    def _provider(self, name: str) -> SecretProvider:
        if name not in self.providers: raise SecretProviderError(f"unknown provider: {name}")
        return self.providers[name]
