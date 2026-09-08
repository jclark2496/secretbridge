#!/usr/bin/env python3
"""Safe local operator helper for protected Hermes Handoff."""
from __future__ import annotations

import argparse
import json
import sys
import urllib.parse
from pathlib import Path

from .cli import create_request
from .key_protector import DEFAULT_KEYCHAIN_ACCOUNT, DEFAULT_KEYCHAIN_SERVICE, KeyProtectorError, MacOSKeychainAESGCMKeyProtector
from .production import DEFAULT_ALLOWED_EXTERNAL_ORIGINS, DEFAULT_STATE, PRODUCTION_LIFECYCLE_SCOPE
from .server import validate_external_origin
from .store import DEFAULT_DESTINATION_ID, RequestStore

DEFAULT_ORIGIN = "https://handoff-mac.example-tailnet.ts.net:9443"
DEFAULT_TTL_SECONDS = 300


def _protector(args: argparse.Namespace) -> MacOSKeychainAESGCMKeyProtector:
    return MacOSKeychainAESGCMKeyProtector(service=args.keychain_service, account=args.keychain_account, keychain=args.keychain)


def _request_id_from_args(args: argparse.Namespace) -> str:
    if args.request_id:
        return args.request_id
    parsed = urllib.parse.urlparse(args.url or "")
    parts = [p for p in parsed.path.split("/") if p]
    if len(parts) == 2 and parts[0] == "handoff":
        return parts[1]
    raise ValueError("status requires --request-id or a handoff --url")


def issue(args: argparse.Namespace) -> dict[str, object]:
    allowed = tuple(args.allowed_origins) if args.allowed_origins else DEFAULT_ALLOWED_EXTERNAL_ORIGINS + (DEFAULT_ORIGIN,)
    origin = validate_external_origin(args.origin, allowed)
    protector = _protector(args)
    protector.assert_available()
    url = create_request(args.state, origin, ttl_seconds=args.ttl_seconds, destination_id=args.destination_id, destination_label=args.destination_label, allowed_origins=allowed, key_protector=protector, require_protected_keys=True, lifecycle_scope=PRODUCTION_LIFECYCLE_SCOPE)
    store = RequestStore(args.state, key_protector=protector, require_protected_keys=True)
    purged = store.purge_expired_unused(lifecycle_scope=PRODUCTION_LIFECYCLE_SCOPE)
    request_id = urllib.parse.urlparse(url).path.rsplit("/", 1)[-1]
    metadata = store.receipt_metadata(request_id)
    return {"ok": True, "action": "issue", "url": url, "request_id": request_id, "expires_at": metadata["expires_at"], "status": metadata["status"], "state_path": str(args.state), "destination_id": metadata["destination_id"], "destination_label": metadata["destination_label"], "protected_keys": metadata["protected_private_key"], "purged_expired_unused": purged, "receipt_contains_plaintext": False}


def status(args: argparse.Namespace) -> dict[str, object]:
    protector = _protector(args)
    protector.assert_available()
    store = RequestStore(args.state, key_protector=protector, require_protected_keys=True)
    metadata = store.receipt_metadata(_request_id_from_args(args))
    return {"ok": True, "action": "status", "state_path": str(args.state), "receipt": metadata, "receipt_contains_plaintext": False}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Safe local operator helper for protected Hermes Handoff.")
    sub = parser.add_subparsers(dest="command", required=True)
    def add_common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--state", type=Path, default=DEFAULT_STATE)
        p.add_argument("--keychain-service", default=DEFAULT_KEYCHAIN_SERVICE)
        p.add_argument("--keychain-account", default=DEFAULT_KEYCHAIN_ACCOUNT)
        p.add_argument("--keychain", help="optional explicit keychain-db path for wrapping-key lookup")
    issue_parser = sub.add_parser("issue", help="issue one short-lived protected request URL")
    add_common(issue_parser)
    issue_parser.add_argument("--origin", default=DEFAULT_ORIGIN)
    issue_parser.add_argument("--allowed-origin", action="append", dest="allowed_origins", default=None)
    issue_parser.add_argument("--ttl-seconds", type=int, default=DEFAULT_TTL_SECONDS)
    issue_parser.add_argument("--destination-id", default=DEFAULT_DESTINATION_ID)
    issue_parser.add_argument("--destination-label", required=True, help="fixed destination bound before browser entry")
    status_parser = sub.add_parser("status", help="read sanitized local receipt metadata only")
    add_common(status_parser)
    status_group = status_parser.add_mutually_exclusive_group(required=True)
    status_group.add_argument("--request-id")
    status_group.add_argument("--url", help="handoff URL; only the request id is read from it")
    args = parser.parse_args(argv)
    try:
        result = issue(args) if args.command == "issue" else status(args)
    except (ValueError, LookupError, KeyProtectorError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
