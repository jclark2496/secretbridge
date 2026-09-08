from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from secure_storage import operator_helper
from secure_storage.key_protector import AESGCMKeyProtector, KeyProtectorError
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


class OperatorHelperTests(unittest.TestCase):
    def test_issue_outputs_only_url_and_sanitized_fixed_destination_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "secure-handoff.sqlite3"
            protector = AvailableProtector(os.urandom(32), protector_id="operator-test")
            stdout = io.StringIO(); stderr = io.StringIO()
            with patch.object(operator_helper, "_protector", return_value=protector), redirect_stdout(stdout), redirect_stderr(stderr):
                rc = operator_helper.main(["issue", "--state", str(state), "--origin", "https://handoff-mac.example-tailnet.ts.net:9443", "--allowed-origin", "https://handoff-mac.example-tailnet.ts.net:9443", "--destination-label", "OperatorFixedDestination", "--ttl-seconds", "300"])
            self.assertEqual(rc, 0, stderr.getvalue())
            result = json.loads(stdout.getvalue())
            self.assertTrue(result["ok"])
            self.assertEqual(result["destination_label"], "OperatorFixedDestination")
            self.assertEqual(result["destination_id"], DEFAULT_DESTINATION_ID)
            self.assertEqual(result["status"], "pending")
            self.assertTrue(result["protected_keys"])
            self.assertFalse(result["receipt_contains_plaintext"])
            self.assertNotIn("auth_token", result)
            raw = state.read_bytes() + (Path(str(state) + "-wal").read_bytes() if Path(str(state) + "-wal").exists() else b"")
            self.assertIn(b"aesgcm.1.", raw)
            self.assertNotIn(b"PRIVATE KEY", raw)

    def test_status_reads_receipt_metadata_only_in_protected_mode(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "secure-handoff.sqlite3"
            protector = AvailableProtector(os.urandom(32), protector_id="operator-test")
            request_id, auth = RequestStore(state, key_protector=protector, require_protected_keys=True).create_request(ttl_seconds=60, destination_id=DEFAULT_DESTINATION_ID, destination_label="StatusFixedDestination", lifecycle_scope=operator_helper.PRODUCTION_LIFECYCLE_SCOPE)
            url = f"https://handoff-mac.example-tailnet.ts.net:9443/handoff/{request_id}?auth={auth}"
            stdout = io.StringIO(); stderr = io.StringIO()
            with patch.object(operator_helper, "_protector", return_value=protector), redirect_stdout(stdout), redirect_stderr(stderr):
                rc = operator_helper.main(["status", "--state", str(state), "--url", url])
            self.assertEqual(rc, 0, stderr.getvalue())
            receipt = json.loads(stdout.getvalue())["receipt"]
            self.assertEqual(receipt["request_id"], request_id)
            self.assertEqual(receipt["destination_label"], "StatusFixedDestination")
            self.assertNotIn("auth", json.dumps(receipt))
            self.assertNotIn("private_key", json.dumps(receipt).replace("protected_private_key", ""))

    def test_helper_fails_before_state_creation_when_protector_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "not-created.sqlite3"
            stdout = io.StringIO(); stderr = io.StringIO()
            with patch.object(operator_helper, "_protector", return_value=UnavailableProtector()), redirect_stdout(stdout), redirect_stderr(stderr):
                rc = operator_helper.main(["issue", "--state", str(state), "--allowed-origin", "https://handoff-mac.example-tailnet.ts.net:9443", "--destination-label", "NoState"])
            self.assertEqual(rc, 2)
            self.assertEqual(stdout.getvalue(), "")
            self.assertIn("mock Keychain unavailable", stderr.getvalue())
            self.assertFalse(state.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
