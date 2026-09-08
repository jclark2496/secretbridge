from __future__ import annotations

import io
import json
import os
import stat
import sys
import tempfile
import types
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from secure_storage import production
from secure_storage.key_protector import AESGCMKeyProtector, KeyProtectorError
from secure_storage.sinks import EphemeralDemoSink, HandoffDestination, HandoffReceipt
from secure_storage.store import DEFAULT_DESTINATION_ID, RequestStore


class AvailableProtector(AESGCMKeyProtector):
    def assert_available(self) -> None:
        return None


class UnavailableProtector:
    protector_id = "unavailable-test"
    def assert_available(self) -> None:
        raise KeyProtectorError("mock Keychain unavailable")
    def protect_private_pem(self, private_pem: str, *, request_id: str) -> str:
        raise AssertionError("must not protect after unavailable assert")
    def unprotect_private_pem(self, ciphertext: str, *, request_id: str) -> str:
        raise AssertionError("must not unprotect")


class FakeDurableSink:
    durable = True
    def store(self, *, destination: HandoffDestination, value: str, request_id: str) -> HandoffReceipt:
        return HandoffReceipt(request_id, destination.destination_id, destination.label, "fake-durable-receipt", True, True)

class OnlyTruthyDurableSink:
    durable = "yes"
    def store(self, *, destination: HandoffDestination, value: str, request_id: str) -> HandoffReceipt:
        return HandoffReceipt(request_id, destination.destination_id, destination.label, "fake-durable-receipt", True, True)

class NoStructuredStoreSink:
    durable = True
    def __call__(self, label: str, value: str, request_id: str) -> str:
        return "legacy-storage-id"


class FakeServer:
    def __init__(self) -> None:
        self.server_address = ("127.0.0.1", 9127); self.served = False; self.closed = False
    def serve_forever(self) -> None:
        self.served = True; raise KeyboardInterrupt
    def server_close(self) -> None:
        self.closed = True


class ProductionEntrypointTests(unittest.TestCase):
    def test_create_uses_protected_state_and_never_writes_plaintext_private_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "secure-handoff.sqlite3"
            protector = AvailableProtector(os.urandom(32), protector_id="entrypoint-test")
            stdout = io.StringIO(); stderr = io.StringIO()
            with patch.object(production, "_protector", return_value=protector), redirect_stdout(stdout), redirect_stderr(stderr):
                rc = production.main(["create", "--state", str(state), "--origin", "https://handoff-mac.example-tailnet.ts.net:9443", "--allowed-origin", "https://handoff-mac.example-tailnet.ts.net:9443", "--destination-label", "EntryPointProtectedDestination", "--ttl-seconds", "30"])
            self.assertEqual(rc, 0, stderr.getvalue())
            result = json.loads(stdout.getvalue())
            self.assertEqual(result["destination_id"], DEFAULT_DESTINATION_ID)
            self.assertEqual(result["destination_label"], "EntryPointProtectedDestination")
            raw = state.read_bytes() + (Path(str(state) + "-wal").read_bytes() if Path(str(state) + "-wal").exists() else b"")
            self.assertIn(b"aesgcm.1.", raw); self.assertNotIn(b"PRIVATE KEY", raw)

    def test_create_fails_before_state_creation_when_keychain_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "not-created.sqlite3"
            stdout = io.StringIO(); stderr = io.StringIO()
            with patch.object(production, "_protector", return_value=UnavailableProtector()), redirect_stdout(stdout), redirect_stderr(stderr):
                rc = production.main(["create", "--state", str(state), "--origin", "https://handoff-mac.example-tailnet.ts.net:9443", "--allowed-origin", "https://handoff-mac.example-tailnet.ts.net:9443", "--destination-label", "NoState"])
            self.assertEqual(rc, 2); self.assertFalse(state.exists()); self.assertIn("mock Keychain unavailable", stderr.getvalue())

    def test_serve_fails_closed_without_configured_durable_sink(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "serve.sqlite3"; log = Path(tmp) / "serve.log"
            protector = AvailableProtector(os.urandom(32), protector_id="serve-test")
            stdout = io.StringIO(); stderr = io.StringIO()
            with patch.object(production, "_protector", return_value=protector), redirect_stdout(stdout), redirect_stderr(stderr):
                rc = production.main(["serve", "--state", str(state), "--external-origin", "https://handoff-mac.example-tailnet.ts.net:9443", "--allowed-origin", "https://handoff-mac.example-tailnet.ts.net:9443", "--tailscale-user-login", "operator@example.com", "--log", str(log)])
            self.assertEqual(rc, 2); self.assertIn("--sink is required", stderr.getvalue())

    def test_load_sink_requires_boolean_durable_and_structured_store(self) -> None:
        module = types.ModuleType("fake_handoff_sinks_for_test")
        module.FakeDurableSink = FakeDurableSink
        module.OnlyTruthyDurableSink = OnlyTruthyDurableSink
        module.NoStructuredStoreSink = NoStructuredStoreSink
        old = sys.modules.get(module.__name__)
        sys.modules[module.__name__] = module
        try:
            self.assertIsInstance(production._load_sink(f"{module.__name__}:FakeDurableSink", allow_demo=False), FakeDurableSink)
            with self.assertRaisesRegex(ValueError, "not durable"):
                production._load_sink(f"{module.__name__}:OnlyTruthyDurableSink", allow_demo=False)
            with self.assertRaisesRegex(ValueError, "structured store contract"):
                production._load_sink(f"{module.__name__}:NoStructuredStoreSink", allow_demo=False)
        finally:
            if old is None:
                sys.modules.pop(module.__name__, None)
            else:
                sys.modules[module.__name__] = old

    def test_serve_allows_explicit_ephemeral_demo_sink_only_when_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "serve.sqlite3"; log = Path(tmp) / "serve.log"
            protector = AvailableProtector(os.urandom(32), protector_id="serve-test")
            fake_server = FakeServer(); captured = {}
            def fake_make_server(config):
                captured["config"] = config; fake_server.handoff_config = config; return fake_server
            stdout = io.StringIO(); stderr = io.StringIO()
            with patch.object(production, "_protector", return_value=protector), patch.object(production, "make_server", side_effect=fake_make_server), redirect_stdout(stdout), redirect_stderr(stderr):
                rc = production.main(["serve", "--state", str(state), "--external-origin", "https://handoff-mac.example-tailnet.ts.net:9443", "--allowed-origin", "https://handoff-mac.example-tailnet.ts.net:9443", "--tailscale-user-login", "operator@example.com", "--allow-ephemeral-demo-sink", "--log", str(log)])
            self.assertEqual(rc, 0, stderr.getvalue())
            self.assertIsInstance(captured["config"].sink, EphemeralDemoSink)
            self.assertTrue(captured["config"].allow_ephemeral_demo_sink)
            self.assertFalse(json.loads(stdout.getvalue().splitlines()[0])["sink_durable"])

    def test_default_production_state_dir_files_and_sidecars_are_private(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            default_home = Path(tmp) / "hermes-handoff"; state = default_home / "secure-handoff.sqlite3"
            protector = AvailableProtector(os.urandom(32), protector_id="entrypoint-test")
            with patch.object(production, "DEFAULT_HOME", default_home), patch.object(production, "_protector", return_value=protector), redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(production.main(["create", "--state", str(state), "--origin", "https://handoff-mac.example-tailnet.ts.net:9443", "--allowed-origin", "https://handoff-mac.example-tailnet.ts.net:9443", "--destination-label", "PrivatePermissionsDestination"]), 0)
            self.assertEqual(stat.S_IMODE(default_home.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(state.stat().st_mode), 0o600)

    def test_default_production_path_rejects_symlinked_dedicated_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "real"; target.mkdir(); linked_home = Path(tmp) / "hermes-handoff"; linked_home.symlink_to(target, target_is_directory=True)
            with patch.object(production, "DEFAULT_HOME", linked_home):
                with self.assertRaisesRegex(ValueError, "symlinks"):
                    production._prepare_default_production_path(linked_home / "secure-handoff.sqlite3")


if __name__ == "__main__":
    unittest.main(verbosity=2)
