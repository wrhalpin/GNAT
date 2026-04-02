from __future__ import annotations

import argparse
import json

from .broker import SecretsBroker
from .models import SecretGetRequest, SecretPutRequest, SecretRef, SecretPurpose
from .policy import SecretsPolicy
from .providers.memory import InMemorySecretsProvider


def build_demo_broker() -> SecretsBroker:
    return SecretsBroker(
        providers={"memory": InMemorySecretsProvider()},
        policy=SecretsPolicy.default(),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="GNAT secrets broker demo CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    put_parser = subparsers.add_parser("put")
    put_parser.add_argument("name")
    put_parser.add_argument("value")
    put_parser.add_argument("--vault", default="gnat-dev")
    put_parser.add_argument("--provider", default="memory")

    get_parser = subparsers.add_parser("get")
    get_parser.add_argument("name")
    get_parser.add_argument("--vault", default="gnat-dev")
    get_parser.add_argument("--provider", default="memory")
    get_parser.add_argument("--metadata-only", action="store_true")

    args = parser.parse_args()
    broker = build_demo_broker()

    if args.command == "put":
        result = broker.put_secret(
            SecretPutRequest(
                ref=SecretRef(provider=args.provider, vault=args.vault, name=args.name),
                value=args.value,
                requested_by="developer",
                purpose=SecretPurpose.DEVELOPMENT,
            )
        )
        print(json.dumps(result.redacted_dict(), indent=2))
        return 0

    result = broker.get_secret(
        SecretGetRequest(
            ref=SecretRef(provider=args.provider, vault=args.vault, name=args.name),
            include_value=not args.metadata_only,
            requested_by="developer",
            purpose=SecretPurpose.DEVELOPMENT,
        )
    )
    payload = result.redacted_dict()
    if not args.metadata_only:
        payload["value"] = result.value
    print(json.dumps(payload, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
