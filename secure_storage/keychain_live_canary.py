#!/usr/bin/env python3
"""Explicit live macOS Keychain wrapping-key canary.

Default mode refuses to touch Keychain. With --live, this creates one throwaway generic
password item using the native create-only helper, reads it back through the no-UI runtime
protector path, verifies duplicate creation is rejected, and prints only sanitized metadata.
It never accepts or prints a secret value and never passes secret material through argv.
"""
from __future__ import annotations

import argparse
import json
import time

from .key_protector import (
    DEFAULT_KEYCHAIN_ACCOUNT,
    DEFAULT_KEYCHAIN_SERVICE,
    KeyProtectorError,
    MacOSKeychainAESGCMKeyProtector,
    MissingKeychainSecretError,
    provision_wrapping_key_create_only,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run explicit live Keychain provision/readback canary.")
    parser.add_argument("--live", action="store_true", help="required: actually create a throwaway Keychain item")
    parser.add_argument("--service-prefix", default=DEFAULT_KEYCHAIN_SERVICE + " Canary")
    parser.add_argument("--account-prefix", default=DEFAULT_KEYCHAIN_ACCOUNT + "-canary")
    parser.add_argument("--keychain", help="optional explicit keychain-db path")
    args = parser.parse_args(argv)

    if not args.live:
        print(json.dumps({"ok": False, "error": "refusing Keychain mutation without --live"}, sort_keys=True))
        return 2

    suffix = str(int(time.time()))
    service = f"{args.service_prefix} {suffix}"
    account = f"{args.account_prefix}-{suffix}"
    try:
        provision_wrapping_key_create_only(service=service, account=account, keychain=args.keychain)
        protector = MacOSKeychainAESGCMKeyProtector(service=service, account=account, keychain=args.keychain)
        protector.assert_available()
        duplicate_rejected = False
        try:
            provision_wrapping_key_create_only(service=service, account=account, keychain=args.keychain)
        except KeyProtectorError:
            duplicate_rejected = True
        if not duplicate_rejected:
            raise KeyProtectorError("duplicate Keychain canary item was not rejected")
    except (KeyProtectorError, MissingKeychainSecretError) as exc:
        print(json.dumps({"ok": False, "error": str(exc), "service": service, "account": account}, sort_keys=True))
        return 1

    print(json.dumps({
        "ok": True,
        "service": service,
        "account": account,
        "readback_verified_no_ui": True,
        "duplicate_create_rejected": True,
        "cleanup": "Remove the throwaway item in Keychain Access or run: security delete-generic-password -a '<account>' -s '<service>'",
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
