#!/usr/bin/env python3
"""Provider-free fake browser canary harness.

This demo uses EphemeralDemoSink, which acknowledges only in memory and is not real durable
storage. It exists to prove the browser encryption/collector/receipt path without SDKs,
provider credentials, Keychain mutations, or network writes.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import sqlite3
import sys
import tempfile
import threading
import time
import urllib.parse
from contextlib import closing
from pathlib import Path
from typing import Any

PACKAGE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = PACKAGE_DIR.parent
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from secure_storage.key_protector import AESGCMKeyProtector  # noqa: E402
from secure_storage.server import ServerConfig, make_server  # noqa: E402
from secure_storage.sinks import EphemeralDemoSink  # noqa: E402
from secure_storage.store import DEFAULT_DESTINATION_ID, RequestStore  # noqa: E402

DEFAULT_TTL_SECONDS = 120


class CanaryError(RuntimeError):
    """Sanitized harness error; must not include canary values."""


def _make_canary() -> tuple[str, str]:
    return f"Browser Canary {int(time.time())}", "synthetic non-secret browser canary " + hashlib.sha256(os.urandom(32)).hexdigest()


def _receipt_row(state_path: Path, request_id: str) -> dict[str, Any]:
    with closing(sqlite3.connect(state_path, timeout=5, isolation_level=None)) as conn:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA query_only = ON")
        row = conn.execute("SELECT request_id, destination_label, destination_id, expires_at, used, used_at, encrypted_envelope_json, storage_id, storage_durable FROM requests WHERE request_id = ?", (request_id,)).fetchone()
    if row is None:
        raise CanaryError("local receipt row was not recorded")
    envelope_json = row["encrypted_envelope_json"] or ""
    return {"request_id": row["request_id"], "destination_label": row["destination_label"], "destination_id": row["destination_id"], "expires_at": int(row["expires_at"]), "used": bool(row["used"]), "used_at": int(row["used_at"]) if row["used_at"] is not None else None, "status": "ephemeral-demo" if row["storage_id"] and int(row["storage_durable"] or 0) == 0 else "stored" if row["storage_id"] else "pending", "storage_id": row["storage_id"], "storage_durable": bool(row["storage_durable"]) if row["storage_durable"] is not None else None, "encrypted_envelope_sha256": hashlib.sha256(envelope_json.encode("utf-8")).hexdigest() if envelope_json else None, "encrypted_envelope_bytes": len(envelope_json.encode("utf-8"))}


def _drive_browser(url: str, value: str, *, headful: bool) -> str:
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        raise CanaryError("playwright is not installed") from None
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=not headful)
        page = browser.new_page()
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=10000)
            page.locator("#value").fill(value)
            page.locator("button[type=submit]").click()
            page.wait_for_selector("text=Ephemeral demo recorded", timeout=10000)
            body = page.locator("body").inner_text(timeout=5000)
        finally:
            browser.close()
    if value in body:
        raise CanaryError("browser receipt leaked submitted value")
    return body


def _write_receipt(path: Path, receipt: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(path, 0o600)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run provider-free local browser canary against an ephemeral demo sink.")
    parser.add_argument("--ttl-seconds", type=int, default=DEFAULT_TTL_SECONDS)
    parser.add_argument("--state", type=Path, help="SQLite state path; default is isolated temp file")
    parser.add_argument("--protected-test-memory", action="store_true")
    parser.add_argument("--evidence-dir", type=Path, default=PACKAGE_DIR / "canary_evidence")
    parser.add_argument("--headful", action="store_true")
    args = parser.parse_args(argv)
    if args.ttl_seconds <= 0 or args.ttl_seconds > 600:
        print("ttl must be 1..600 seconds", file=sys.stderr); return 2
    temp_dir: tempfile.TemporaryDirectory[str] | None = None
    state_path = args.state
    if state_path is None:
        temp_dir = tempfile.TemporaryDirectory(prefix="secure-handoff-canary-")
        state_path = Path(temp_dir.name) / "state.sqlite3"
    started_at = int(time.time())
    destination_label, canary_value = _make_canary()
    request_id = ""
    server = None; thread = None
    log_path = args.evidence_dir / f"browser-canary-demo-{started_at}.log"
    receipt_path = args.evidence_dir / f"browser-canary-demo-{started_at}.json"
    logger = logging.getLogger(f"secure-handoff-browser-canary-{started_at}")
    logger.handlers.clear(); logger.setLevel(logging.INFO); logger.propagate = False
    log_path.parent.mkdir(parents=True, exist_ok=True)
    logger.addHandler(logging.FileHandler(log_path, encoding="utf-8"))
    try:
        key_protector = AESGCMKeyProtector(os.urandom(32)) if args.protected_test_memory else None
        store = RequestStore(state_path, key_protector=key_protector, require_protected_keys=args.protected_test_memory)
        request_id, auth = store.create_request(ttl_seconds=args.ttl_seconds, destination_id=DEFAULT_DESTINATION_ID, destination_label=destination_label)
        sink = EphemeralDemoSink()
        server = make_server(ServerConfig(state_path=state_path, host="127.0.0.1", port=0, sink=sink, allow_ephemeral_demo_sink=True, logger=logger, key_protector=key_protector, require_protected_keys=args.protected_test_memory))
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        host, port = server.server_address
        url = f"http://{host}:{port}/handoff/{request_id}?auth={urllib.parse.quote(auth)}"
        body = _drive_browser(url, canary_value, headful=args.headful)
        match = re.search(r"Storage ID:\s*([\w:./@+-]+)", body)
        local_receipt = _receipt_row(state_path, request_id)
        storage_id = str(local_receipt.get("storage_id") or "")
        if not storage_id or (match and match.group(1) != storage_id):
            raise CanaryError("browser and local receipt mismatch")
        receipt = {"mode": "ephemeral-demo", "storage_durability": "ephemeral-not-real-storage", "server_bind": "127.0.0.1:0(loopback ephemeral)", "state_path": str(state_path), "log_path": str(log_path), "request_id": request_id, "destination_id": DEFAULT_DESTINATION_ID, "destination_label": destination_label, "storage_id": storage_id, "local_receipt": local_receipt, "demo_sink_records": sink.records, "browser_receipt_contains_value": False, "limits": {"ttl_seconds": args.ttl_seconds, "max_value_bytes": 4096, "max_body_bytes": 49152, "no_browser_logs_or_network_payloads_recorded": True, "protected_test_memory": args.protected_test_memory}}
        _write_receipt(receipt_path, receipt)
        print(json.dumps({"ok": True, "mode": "ephemeral-demo", "receipt_path": str(receipt_path), "log_path": str(log_path)}, sort_keys=True))
        return 0
    except Exception as exc:
        message = str(exc) if isinstance(exc, CanaryError) else "browser canary failed before verification"
        print(json.dumps({"ok": False, "mode": "ephemeral-demo", "error": message, "receipt_path": str(receipt_path)}, sort_keys=True), file=sys.stderr)
        return 1
    finally:
        if server is not None:
            server.shutdown(); server.server_close()
        if thread is not None:
            thread.join(timeout=2)
        if temp_dir is not None:
            temp_dir.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
