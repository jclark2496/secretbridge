from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from secure_storage.registry import SQLiteApprovalRegistry
from secure_storage.store import DEFAULT_DESTINATION_ID, RequestStore, now


class BrowserCanaryHarnessTests(unittest.TestCase):
    def test_fake_harness_drives_real_browser_and_records_sanitized_receipt(self) -> None:
        root = Path(__file__).resolve().parents[2]
        script = root / "secure_storage" / "run_browser_canary.py"
        with tempfile.TemporaryDirectory() as tmp:
            evidence_dir = Path(tmp) / "evidence"
            state = Path(tmp) / "state.sqlite3"
            proc = subprocess.run(
                [sys.executable, str(script), "--state", str(state), "--evidence-dir", str(evidence_dir)],
                cwd=root,
                text=True,
                capture_output=True,
                timeout=30,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertEqual(proc.stderr, "")
            result = json.loads(proc.stdout)
            self.assertTrue(result["ok"])
            self.assertEqual(result["mode"], "ephemeral-demo")
            receipt_path = Path(result["receipt_path"])
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))

            self.assertEqual(receipt["mode"], "ephemeral-demo")
            self.assertEqual(receipt["destination_id"], str(DEFAULT_DESTINATION_ID))
            self.assertTrue(receipt["local_receipt"]["used"])
            self.assertEqual(receipt["local_receipt"]["destination_label"], receipt["destination_label"])
            self.assertEqual(receipt["local_receipt"]["request_id"], receipt["request_id"])
            self.assertEqual(receipt["local_receipt"]["destination_id"], DEFAULT_DESTINATION_ID)
            self.assertEqual(receipt["local_receipt"]["status"], "ephemeral-demo")
            self.assertFalse(receipt["local_receipt"]["storage_durable"])
            self.assertIsNotNone(receipt["local_receipt"]["encrypted_envelope_sha256"])
            self.assertGreater(receipt["local_receipt"]["encrypted_envelope_bytes"], 0)
            self.assertFalse(receipt["browser_receipt_contains_value"])
            self.assertEqual(receipt["storage_durability"], "ephemeral-not-real-storage")
            self.assertEqual(len(receipt["demo_sink_records"]), 1)
            self.assertIn("value_sha256", receipt["demo_sink_records"][0])
            self.assertNotIn("synthetic non-secret browser canary", receipt_path.read_text(encoding="utf-8"))

            self.assertEqual(receipt["limits"]["no_browser_logs_or_network_payloads_recorded"], True)

    def test_sqlite_registry_requires_exact_active_request(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp) / "state.sqlite3"
            request_id, _auth = RequestStore(state).create_request(
                ttl_seconds=60,
                destination_id=DEFAULT_DESTINATION_ID,
                destination_label="Hermes Browser Canary registry test",
            )
            registry = SQLiteApprovalRegistry(state)
            self.assertTrue(
                registry.is_approved(
                    request_id=request_id,
                    destination_label="Hermes Browser Canary registry test",
                    destination_id=DEFAULT_DESTINATION_ID,
                )
            )
            self.assertFalse(
                registry.is_approved(
                    request_id=request_id,
                    destination_label="wrong name",
                    destination_id=DEFAULT_DESTINATION_ID,
                )
            )
            self.assertFalse(
                registry.is_approved(
                    request_id=request_id,
                    destination_label="Hermes Browser Canary registry test",
                    destination_id="00000000-0000-4000-8000-000000000000",
                )
            )
            with closing(RequestStore(state)._connect()) as conn:
                conn.execute("UPDATE requests SET expires_at = ? WHERE request_id = ?", (now() - 1, request_id))
            self.assertFalse(
                registry.is_approved(
                    request_id=request_id,
                    destination_label="Hermes Browser Canary registry test",
                    destination_id=DEFAULT_DESTINATION_ID,
                )
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
