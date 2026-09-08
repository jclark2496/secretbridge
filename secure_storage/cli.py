"""Local CLI request creation for encrypted handoff."""
from __future__ import annotations

import argparse
import urllib.parse
from pathlib import Path

from .key_protector import DEFAULT_KEYCHAIN_ACCOUNT, DEFAULT_KEYCHAIN_SERVICE, KeyProtector, KeyProtectorError, MacOSKeychainAESGCMKeyProtector
from .server import DEFAULT_ALLOWED_EXTERNAL_ORIGINS, validate_external_origin
from .store import DEFAULT_DESTINATION_ID, RequestStore

DEFAULT_STATE = Path(__file__).with_name("secure_handoff.sqlite3")


def create_request(
    state_path: Path,
    base_url: str,
    *,
    ttl_seconds: int,
    destination_label: str,
    destination_id: str = DEFAULT_DESTINATION_ID,
    allowed_origins: tuple[str, ...] = DEFAULT_ALLOWED_EXTERNAL_ORIGINS,
    key_protector: KeyProtector | None = None,
    require_protected_keys: bool = False,
    lifecycle_scope: str | None = None,
) -> str:
    if ttl_seconds <= 0:
        raise ValueError("ttl must be positive")
    base_url = validate_external_origin(base_url, allowed_origins)
    request_id, auth_token = RequestStore(
        state_path,
        key_protector=key_protector,
        require_protected_keys=require_protected_keys,
    ).create_request(ttl_seconds=ttl_seconds, destination_id=destination_id, destination_label=destination_label, lifecycle_scope=lifecycle_scope)
    return urllib.parse.urljoin(base_url.rstrip("/") + "/", f"handoff/{request_id}?auth={urllib.parse.quote(auth_token)}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create local encrypted handoff request. No HTTP creation endpoint exists.")
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create")
    create.add_argument("--state", type=Path, default=DEFAULT_STATE)
    create.add_argument("--encrypted-state", type=Path, help="explicit opt-in protected SQLite path; refuses the default plaintext-compatible DB path")
    create.add_argument("--origin", required=True, help="explicit HTTPS origin from the allowlist")
    create.add_argument(
        "--allowed-origin",
        action="append",
        dest="allowed_origins",
        default=None,
        help="allowed HTTPS origin; repeatable; defaults to https://handoff-mac.example-tailnet.ts.net",
    )
    create.add_argument("--ttl-seconds", type=int, default=300)
    create.add_argument("--destination-label", required=True, help="server-side destination label; browser cannot change it")
    create.add_argument("--destination-id", default=DEFAULT_DESTINATION_ID)
    create.add_argument("--keychain-service", default=DEFAULT_KEYCHAIN_SERVICE)
    create.add_argument("--keychain-account", default=DEFAULT_KEYCHAIN_ACCOUNT)
    create.add_argument("--keychain", help="optional explicit keychain-db path for wrapping-key lookup")
    args = parser.parse_args(argv)
    if args.command == "create":
        state_path = args.encrypted_state if args.encrypted_state is not None else args.state
        key_protector = None
        require_protected_keys = False
        if args.encrypted_state is not None:
            if args.encrypted_state == DEFAULT_STATE:
                parser.error("--encrypted-state must be an isolated non-default path")
            key_protector = MacOSKeychainAESGCMKeyProtector(
                service=args.keychain_service,
                account=args.keychain_account,
                keychain=args.keychain,
            )
            require_protected_keys = True
        try:
            url = create_request(
                state_path,
                args.origin,
                ttl_seconds=args.ttl_seconds,
                destination_label=args.destination_label,
                destination_id=args.destination_id,
                allowed_origins=tuple(args.allowed_origins) if args.allowed_origins else DEFAULT_ALLOWED_EXTERNAL_ORIGINS,
                key_protector=key_protector,
                require_protected_keys=require_protected_keys,
            )
        except (ValueError, KeyProtectorError) as exc:
            parser.exit(2, f"{exc}\n")
        print("Encrypted handoff request created locally. Do not enter live credentials until reviewed.")
        print(url)
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
