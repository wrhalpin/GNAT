from gnat.agents.security.hygiene.leak_scanner import LeakScanner
from gnat.agents.security.hygiene.unsafe_patterns import UnsafePatternDetector
from gnat.agents.security.secrets.audit import InMemoryAuditRecorder
from gnat.agents.security.secrets.broker import SecretsBroker
from gnat.agents.security.secrets.exceptions import SecretPolicyError
from gnat.agents.security.secrets.models import SecretRef, StoreSecretRequest
from gnat.agents.security.secrets.policy import PolicyRule, SecretPolicyEngine
from gnat.agents.security.secrets.providers.memory import MemorySecretProvider
from gnat.agents.security.secrets.resolver import ConnectorConfigResolver


def test_broker_stores_and_resolves_secret() -> None:
    provider = MemorySecretProvider()
    policy = SecretPolicyEngine(
        [
            PolicyRule(
                path_prefix="dev/",
                actions=["store", "resolve"],
                allowed_callers=["runtime", "ci"],
                overwrite=True,
            )
        ]
    )
    audit = InMemoryAuditRecorder()
    broker = SecretsBroker(providers={"memory": provider}, policy=policy, audit=audit)
    ref = SecretRef(provider="memory", vault="local", path="dev/alienvault/api-key")
    broker.store(
        StoreSecretRequest(
            ref=ref, value="super-secret", tags={"connector": "alienvault"}, allow_overwrite=True
        ),
        caller="ci",
    )
    resolved = broker.resolve(ref, caller="runtime")
    assert resolved.value == "super-secret"
    assert len(audit.events) == 2


def test_broker_blocks_policy_violation() -> None:
    provider = MemorySecretProvider()
    policy = SecretPolicyEngine(
        [PolicyRule(path_prefix="dev/", actions=["resolve"], allowed_callers=["runtime"])]
    )
    broker = SecretsBroker(providers={"memory": provider}, policy=policy)
    ref = SecretRef(provider="memory", vault="local", path="dev/alienvault/api-key")
    try:
        broker.store(StoreSecretRequest(ref=ref, value="denied"), caller="ci")
        raise AssertionError()
    except SecretPolicyError:
        assert True


def test_connector_config_resolver_replaces_secret_ref() -> None:
    provider = MemorySecretProvider()
    policy = SecretPolicyEngine(
        [
            PolicyRule(
                path_prefix="dev/",
                actions=["store", "resolve"],
                allowed_callers=["runtime", "ci"],
                overwrite=True,
            )
        ]
    )
    broker = SecretsBroker(providers={"memory": provider}, policy=policy)
    ref = SecretRef(provider="memory", vault="local", path="dev/cribl/token")
    broker.store(
        StoreSecretRequest(ref=ref, value="resolved-token", allow_overwrite=True), caller="ci"
    )
    resolver = ConnectorConfigResolver(broker)
    config = {"credentials": {"api_token": {"secret_ref": "memory://local/dev/cribl/token"}}}
    resolved = resolver.resolve_credentials(config, caller="runtime")
    assert resolved["credentials"]["api_token"] == "resolved-token"


def test_leak_scanner_finds_obvious_secret(tmp_path) -> None:
    test_file = tmp_path / "sample.py"
    test_file.write_text('api_key = "abcdef1234567890"\n', encoding="utf-8")
    findings = LeakScanner().scan_paths([str(tmp_path)])
    assert findings and findings[0].rule == "generic_token_assignment"


def test_unsafe_pattern_detector_flags_inline_credentials() -> None:
    findings = UnsafePatternDetector().inspect_connector_config(
        {"credentials": {"api_key": "plain-text-value", "token": {"value": "still-plain-text"}}}
    )
    assert len(findings) == 2
