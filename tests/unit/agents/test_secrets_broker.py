from gnat.agents.secrets.broker import SecretsBroker
from gnat.agents.secrets.exceptions import SecretPolicyError
from gnat.agents.secrets.models import SecretGetRequest, SecretPurpose, SecretPutRequest, SecretRef
from gnat.agents.secrets.policy import SecretsPolicy
from gnat.agents.secrets.providers.memory import InMemorySecretsProvider


def build_broker():
    return SecretsBroker(
        providers={"memory": InMemorySecretsProvider()},
        policy=SecretsPolicy.default(),
    )


def test_broker_can_store_and_retrieve_dev_secret():
    broker = build_broker()
    ref = SecretRef(provider="memory", vault="gnat-dev", name="dev/alienvault/api-key")
    broker.put_secret(
        SecretPutRequest(
            ref=ref,
            value="super-secret-value",
            requested_by="developer",
            purpose=SecretPurpose.DEVELOPMENT,
        )
    )
    record = broker.get_secret(
        SecretGetRequest(
            ref=ref,
            requested_by="developer",
            purpose=SecretPurpose.DEVELOPMENT,
        )
    )
    assert record.value == "super-secret-value"
    assert record.ref.name == "dev/alienvault/api-key"


def test_prod_write_is_blocked_for_non_rotation_request():
    broker = build_broker()
    ref = SecretRef(provider="memory", vault="gnat-prod", name="prod/alienvault/api-key")
    try:
        broker.put_secret(
            SecretPutRequest(
                ref=ref,
                value="not-allowed",
                requested_by="developer",
                purpose=SecretPurpose.DEVELOPMENT,
            )
        )
    except SecretPolicyError:
        pass
    else:
        raise AssertionError("expected SecretPolicyError")
