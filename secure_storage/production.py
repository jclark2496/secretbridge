#!/usr/bin/env python3
"""Provider-neutral Mac-hosted protected Hermes Handoff entrypoint.

This module is fail-closed: private keys are protected by macOS Keychain in protected
mode, browser input cannot choose a destination, and serving requires an explicitly
configured durable sink unless the operator opts into the non-durable demo sink.
"""
from __future__ import annotations

import argparse
import importlib
import json
import logging
import os
import stat
import sys
from pathlib import Path

from .cli import create_request
from .key_protector import DEFAULT_KEYCHAIN_ACCOUNT, DEFAULT_KEYCHAIN_SERVICE, KeyProtectorError, MacOSKeychainAESGCMKeyProtector
from .server import DEFAULT_ALLOWED_EXTERNAL_ORIGINS, ServerConfig, make_server, validate_external_origin, validate_tailscale_user_login
from .sinks import DurableSink, EphemeralDemoSink
from .store import DEFAULT_DESTINATION_ID, RequestStore

DEFAULT_HOME = Path.home() / ".hermes" / "hermes-handoff"
DEFAULT_STATE = DEFAULT_HOME / "secure-handoff.sqlite3"
DEFAULT_LOG = DEFAULT_HOME / "secure-handoff.log"
DEFAULT_PORT = 9127
PRODUCTION_LIFECYCLE_SCOPE = "hermes-handoff-protected-v1"


def _reject_symlink_path(path: Path) -> None:
    current = path.expanduser()
    existing = []
    while True:
        existing.append(current)
        if current.exists() or current.parent == current:
            break
        current = current.parent
    for candidate in reversed(existing):
        try:
            mode = candidate.lstat().st_mode
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(mode):
            raise ValueError("production state/log path must not traverse symlinks")


def _ensure_private_dedicated_directory(directory: Path) -> None:
    _reject_symlink_path(directory)
    directory.mkdir(parents=True, mode=0o700, exist_ok=True)
    mode = directory.lstat().st_mode
    if stat.S_ISLNK(mode) or not stat.S_ISDIR(mode):
        raise ValueError("production state/log directory must be a real directory")
    os.chmod(directory, 0o700)


def _prepare_default_production_path(path: Path) -> None:
    path = path.expanduser()
    if path.parent == DEFAULT_HOME or path.parent.name == DEFAULT_HOME.name:
        _reject_symlink_path(path)
        _ensure_private_dedicated_directory(path.parent)
        if path.exists():
            if stat.S_ISLNK(path.lstat().st_mode):
                raise ValueError("production state/log path must not be a symlink")
            os.chmod(path, 0o600)


def _touch_private_file(path: Path) -> None:
    _prepare_default_production_path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    os.close(fd)
    os.chmod(path, 0o600)


def _protector(args: argparse.Namespace) -> MacOSKeychainAESGCMKeyProtector:
    return MacOSKeychainAESGCMKeyProtector(service=args.keychain_service, account=args.keychain_account, keychain=args.keychain)


def _configure_logger(path: Path) -> logging.Logger:
    _touch_private_file(path)
    logger = logging.getLogger("secure_handoff.production")
    logger.handlers.clear()
    logger.setLevel(logging.INFO)
    logger.propagate = False
    handler = logging.FileHandler(path, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(handler)
    return logger


def _load_sink(spec: str | None, *, allow_demo: bool) -> DurableSink:
    if allow_demo:
        return EphemeralDemoSink()
    if not spec:
        raise ValueError("--sink is required for durable serving")
    if ":" not in spec:
        raise ValueError("sink spec must be module:Class")
    module_name, class_name = spec.split(":", 1)
    cls = getattr(importlib.import_module(module_name), class_name)
    sink = cls()
    if getattr(sink, "durable", None) is not True:
        raise ValueError("configured sink is not durable")
    if not callable(getattr(sink, "store", None)):
        raise ValueError("configured sink must implement the structured store contract")
    return sink


def _add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--state", type=Path, default=DEFAULT_STATE, help="protected SQLite state path")
    parser.add_argument("--keychain-service", default=DEFAULT_KEYCHAIN_SERVICE)
    parser.add_argument("--keychain-account", default=DEFAULT_KEYCHAIN_ACCOUNT)
    parser.add_argument("--keychain", help="optional explicit keychain-db path for wrapping-key lookup")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Mac-hosted provider-neutral protected handoff entrypoint.")
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create", help="create one protected request URL locally")
    _add_common(create)
    create.add_argument("--origin", required=True)
    create.add_argument("--allowed-origin", action="append", dest="allowed_origins", default=None)
    create.add_argument("--ttl-seconds", type=int, default=300)
    create.add_argument("--destination-id", default=DEFAULT_DESTINATION_ID)
    create.add_argument("--destination-label", required=True)

    serve = sub.add_parser("serve", help="run loopback collector with real Keychain + configured sink")
    _add_common(serve)
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=DEFAULT_PORT)
    serve.add_argument("--external-origin", required=True)
    serve.add_argument("--allowed-origin", action="append", dest="allowed_origins", default=None)
    serve.add_argument("--tailscale-user-login", required=True)
    serve.add_argument("--sink", help="durable sink adapter as module:Class; constructor must need no secrets from env")
    serve.add_argument("--allow-ephemeral-demo-sink", action="store_true", help="demo only; not durable storage")
    serve.add_argument("--log", type=Path, default=DEFAULT_LOG)

    args = parser.parse_args(argv)
    allowed = tuple(args.allowed_origins) if getattr(args, "allowed_origins", None) else DEFAULT_ALLOWED_EXTERNAL_ORIGINS
    try:
        _prepare_default_production_path(args.state)
        if args.command == "serve":
            _prepare_default_production_path(args.log)
        protector = _protector(args)
        protector.assert_available()
        if args.command == "create":
            url = create_request(args.state, validate_external_origin(args.origin, allowed), ttl_seconds=args.ttl_seconds, destination_id=args.destination_id, destination_label=args.destination_label, allowed_origins=allowed, key_protector=protector, require_protected_keys=True, lifecycle_scope=PRODUCTION_LIFECYCLE_SCOPE)
            metadata = RequestStore(args.state, key_protector=protector, require_protected_keys=True).receipt_metadata(url.split('/handoff/',1)[1].split('?',1)[0])
            print(json.dumps({"ok": True, "state_path": str(args.state), "destination_id": metadata["destination_id"], "destination_label": metadata["destination_label"], "url": url}, sort_keys=True))
            return 0
        sink = _load_sink(args.sink, allow_demo=args.allow_ephemeral_demo_sink)
        server = make_server(ServerConfig(state_path=args.state, host=args.host, port=args.port, external_origin=validate_external_origin(args.external_origin, allowed), allowed_external_origins=allowed, tailscale_user_login=validate_tailscale_user_login(args.tailscale_user_login), sink=sink, allow_ephemeral_demo_sink=args.allow_ephemeral_demo_sink, logger=_configure_logger(args.log), key_protector=protector, require_protected_keys=True))
    except (ValueError, KeyProtectorError, ImportError, AttributeError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(json.dumps({"ok": True, "serving": server.handoff_config.external_origin, "loopback": f"127.0.0.1:{server.server_address[1]}", "state_path": str(args.state), "sink_durable": bool(getattr(sink, 'durable', False)), "protected_keys": True}, sort_keys=True))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
