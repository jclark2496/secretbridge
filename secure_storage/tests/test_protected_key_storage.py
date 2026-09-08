from __future__ import annotations

import ctypes
import io
import json
import logging
import os
import re
import tempfile
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request
from contextlib import closing, redirect_stderr, redirect_stdout
from pathlib import Path

from playwright.sync_api import sync_playwright

from secure_storage.cli import create_request
from secure_storage.key_protector import (
    AESGCMKeyProtector,
    KeyProtectorError,
    MacOSKeychainAESGCMKeyProtector,
    MissingKeychainSecretError,
    decode_wrapping_key_b64url,
    encode_wrapping_key_b64url,
    provision_wrapping_key_create_only,
)
from secure_storage.server import DEFAULT_ALLOWED_EXTERNAL_ORIGINS, ServerConfig, make_server
from secure_storage.sinks import HandoffDestination, HandoffReceipt
from secure_storage.store import DEFAULT_DESTINATION_ID, RequestStore

VALUE = "protected browser supplied credential value"
DESTINATION = "ProtectedMacBoundDestination"
ORIGIN = DEFAULT_ALLOWED_EXTERNAL_ORIGINS[0]


class FakeSink:
    durable = True

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str]] = []

    def store(self, *, destination: HandoffDestination, value: str, request_id: str) -> HandoffReceipt:
        self.calls.append((destination.label, value, request_id))
        return HandoffReceipt(request_id, destination.destination_id, destination.label, "fake-protected-storage-1", True, True)


class UnavailableProtector:
    protector_id = "unavailable"

    def assert_available(self) -> None:
        raise KeyProtectorError("mock protector unavailable")

    def protect_private_pem(self, private_pem: str, *, request_id: str) -> str:
        raise AssertionError("must fail before use")

    def unprotect_private_pem(self, ciphertext: str, *, request_id: str) -> str:
        raise AssertionError("must fail before use")


class FailingProtectProtector:
    protector_id = "failing-protect"

    def protect_private_pem(self, private_pem: str, *, request_id: str) -> str:
        raise KeyProtectorError("mock protection unavailable")

    def unprotect_private_pem(self, ciphertext: str, *, request_id: str) -> str:
        raise AssertionError("must not decrypt")


class FakeNativeKeychainBackend:
    def __init__(self, secret: bytes | Exception) -> None:
        self.secret = secret
        self.find_calls = []
        self.add_calls = []

    def find_generic_password_no_ui(self, *, service: str, account: str, keychain: str | None = None) -> bytes:
        self.find_calls.append((service, account, keychain))
        if isinstance(self.secret, Exception):
            raise self.secret
        return self.secret

    def add_generic_password_create_only(self, *, service: str, account: str, password: bytes, keychain: str | None = None) -> None:
        self.add_calls.append((service, account, password, keychain))
        if self.add_calls[:-1]:
            raise KeyProtectorError("macOS Keychain wrapping key already exists")


class ProtectedStorageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.state = Path(self.tmp.name) / "protected.sqlite3"
        self.protector = AESGCMKeyProtector(os.urandom(32), protector_id="unit-test-aesgcm-v1")
        self.sink = FakeSink()
        self.log_stream = io.StringIO()
        self.logger = logging.getLogger(f"protected-handoff-test-{id(self)}")
        self.logger.handlers.clear()
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False
        handler = logging.StreamHandler(self.log_stream)
        handler.setFormatter(logging.Formatter("%(message)s"))
        self.logger.addHandler(handler)
        self.server = make_server(ServerConfig(
            state_path=self.state,
            port=0,
            sink=self.sink,
            logger=self.logger,
            key_protector=self.protector,
            require_protected_keys=True,
        ))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        self.base_url = f"http://{host}:{port}"
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor())

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.tmp.cleanup()

    def create_url(self) -> str:
        request_id, auth = RequestStore(
            self.state,
            key_protector=self.protector,
            require_protected_keys=True,
        ).create_request(ttl_seconds=30, destination_id=DEFAULT_DESTINATION_ID, destination_label=DESTINATION)
        return f"{self.base_url}/handoff/{request_id}?auth={urllib.parse.quote(auth)}"

    def open(self, url: str, *, data=None, headers=None, method=None):
        req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
        try:
            with self.opener.open(req, timeout=5) as resp:
                return resp.status, resp.read().decode("utf-8"), resp.headers
        except urllib.error.HTTPError as exc:
            try:
                return exc.code, exc.read().decode("utf-8"), exc.headers
            finally:
                exc.close()

    def scan_state_bytes(self) -> bytes:
        chunks = []
        for suffix in ("", "-wal", "-shm"):
            path = Path(str(self.state) + suffix)
            if path.exists():
                chunks.append(path.read_bytes())
        return b"\n".join(chunks)

    def get_page_bits(self, url: str):
        status, body, _headers = self.open(url)
        self.assertEqual(status, 200, body)
        csrf = re.search(r"const CSRF = (\"[^\"]+\");", body)
        jwk = re.search(r"const PUBLIC_JWK = (\{.*?\});", body, re.S)
        self.assertIsNotNone(csrf)
        self.assertIsNotNone(jwk)
        request_id = urllib.parse.urlparse(url).path.rsplit("/", 1)[-1]
        post_url = urllib.parse.urljoin(url, urllib.parse.urlparse(url).path)
        return post_url, json.loads(csrf.group(1)), json.loads(jwk.group(1)), request_id

    def make_envelope_in_browser(self, request_id: str, jwk: dict, value: str = VALUE) -> dict:
        script = r"""
        async ({requestId, jwk, value}) => {
          function b64url(bytes) { let s = ''; for (const b of bytes) s += String.fromCharCode(b); return btoa(s).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_'); }
          const enc = new TextEncoder();
          const aesKey = await crypto.subtle.generateKey({name:'AES-GCM', length:256}, true, ['encrypt']);
          const rawKey = await crypto.subtle.exportKey('raw', aesKey);
          const rsaKey = await crypto.subtle.importKey('jwk', jwk, {name:'RSA-OAEP', hash:'SHA-256'}, false, ['encrypt']);
          const iv = crypto.getRandomValues(new Uint8Array(12));
          const aad = enc.encode(`secure-handoff:v1:${requestId}`);
          const ciphertext = await crypto.subtle.encrypt({name:'AES-GCM', iv, additionalData:aad}, aesKey, enc.encode(value));
          const wrapped = await crypto.subtle.encrypt({name:'RSA-OAEP'}, rsaKey, rawKey);
          return {version:1, request_id:requestId, wrapped_key:b64url(new Uint8Array(wrapped)), iv:b64url(iv), ciphertext:b64url(new Uint8Array(ciphertext))};
        }
        """
        with sync_playwright() as p:
            browser = p.chromium.launch()
            try:
                page = browser.new_page()
                page.goto(self.base_url + "/missing")
                return page.evaluate(script, {"requestId": request_id, "jwk": jwk, "value": value})
            finally:
                browser.close()

    def post(self, post_url: str, csrf: str, envelope: dict):
        body = json.dumps(envelope, separators=(",", ":")).encode()
        return self.open(post_url, data=body, headers={"Content-Type": "application/json", "X-CSRF-Token": csrf, "Origin": self.base_url}, method="POST")

    def test_private_pem_encrypted_at_rest_and_browser_roundtrip_decrypts(self) -> None:
        post_url, csrf, jwk, request_id = self.get_page_bits(self.create_url())
        state_bytes = self.scan_state_bytes()
        self.assertNotIn(b"PRIVATE KEY", state_bytes)
        self.assertNotIn(b"BEGIN PRIVATE KEY", state_bytes)
        self.assertIn(b"aesgcm.1.", state_bytes)

        envelope = self.make_envelope_in_browser(request_id, jwk)
        status, body, _headers = self.post(post_url, csrf, envelope)
        self.assertEqual(status, 200, body)
        self.assertEqual(self.sink.calls, [(DESTINATION, VALUE, request_id)])
        after_bytes = self.scan_state_bytes()
        self.assertNotIn(b"PRIVATE KEY", after_bytes)
        self.assertNotIn(VALUE.encode(), after_bytes)
        self.assertNotIn(VALUE, self.log_stream.getvalue())
        with closing(self.server.handoff_store._connect()) as conn:
            row = conn.execute(
                "SELECT used, private_key_ciphertext, private_key_pem, storage_id FROM requests WHERE request_id=?",
                (request_id,),
            ).fetchone()
        self.assertEqual(int(row["used"]), 1)
        self.assertIsNone(row["private_key_ciphertext"])
        self.assertEqual(row["private_key_pem"], "")
        self.assertEqual(row["storage_id"], "fake-protected-storage-1")

    def test_purge_expired_unused_is_scoped_to_new_production_rows_only(self) -> None:
        store = RequestStore(self.state, key_protector=self.protector, require_protected_keys=True)
        protected_expired, _ = store.create_request(
            ttl_seconds=1,
            destination_id=DEFAULT_DESTINATION_ID,
            destination_label="ExpiredProductionScope",
            lifecycle_scope="secure-storage-production-v1",
        )
        protected_other_scope, _ = store.create_request(
            ttl_seconds=1,
            destination_id=DEFAULT_DESTINATION_ID,
            destination_label="ExpiredOtherScope",
            lifecycle_scope="other-scope",
        )
        protected_unscoped, _ = store.create_request(
            ttl_seconds=1,
            destination_id=DEFAULT_DESTINATION_ID,
            destination_label="ExpiredUnscoped",
        )
        future = 2**31
        self.assertEqual(store.purge_expired_unused(lifecycle_scope="secure-storage-production-v1", before=future), 1)
        with closing(store._connect()) as conn:
            remaining = {row["request_id"] for row in conn.execute("SELECT request_id FROM requests")}
        self.assertNotIn(protected_expired, remaining)
        self.assertIn(protected_other_scope, remaining)
        self.assertIn(protected_unscoped, remaining)

    def test_wrong_key_wrong_aad_and_malformed_ciphertext_fail_closed(self) -> None:
        post_url, csrf, jwk, request_id = self.get_page_bits(self.create_url())
        envelope = self.make_envelope_in_browser(request_id, jwk)
        with closing(self.server.handoff_store._connect()) as conn:
            row = conn.execute("SELECT private_key_ciphertext FROM requests WHERE request_id=?", (request_id,)).fetchone()
            ciphertext = row["private_key_ciphertext"]
            conn.execute("UPDATE requests SET private_key_ciphertext=? WHERE request_id=?", ("aesgcm.1.bad.bad", request_id))
        with self.assertRaises(KeyProtectorError):
            self.protector.unprotect_private_pem(ciphertext, request_id="wrong-aad")
        wrong_key = AESGCMKeyProtector(os.urandom(32))
        with self.assertRaises(KeyProtectorError):
            wrong_key.unprotect_private_pem(ciphertext, request_id=request_id)
        status, _body, _headers = self.post(post_url, csrf, envelope)
        self.assertEqual(status, 400)
        self.assertEqual(self.sink.calls, [])

    def test_protected_mode_refuses_unavailable_backend_and_plaintext_rows(self) -> None:
        with self.assertRaisesRegex(KeyProtectorError, "unavailable"):
            RequestStore(self.state.with_name("missing.sqlite3"), key_protector=UnavailableProtector(), require_protected_keys=True)

        legacy = self.state.with_name("legacy.sqlite3")
        RequestStore(legacy).create_request(ttl_seconds=30, destination_id=DEFAULT_DESTINATION_ID, destination_label=DESTINATION)
        with self.assertRaisesRegex(KeyProtectorError, "plaintext private key row refused"):
            store = RequestStore(legacy, key_protector=self.protector, require_protected_keys=True)
            with closing(store._connect()) as conn:
                row = conn.execute("SELECT * FROM requests LIMIT 1").fetchone()
            store._private_pem_for_row(row)

        protected = self.state.with_name("protect-fails.sqlite3")
        with self.assertRaisesRegex(KeyProtectorError, "private key protection failed"):
            RequestStore(protected, key_protector=FailingProtectProtector()).create_request(
                ttl_seconds=30,
                destination_id=DEFAULT_DESTINATION_ID,
                destination_label=DESTINATION,
            )
        self.assertEqual(RequestStore(protected).count_requests(), 0)

    def test_cli_injected_protector_uses_isolated_encrypted_state_without_secret_output(self) -> None:
        state = self.state.with_name("cli-protected.sqlite3")
        sentinel_key = b"K" * 32
        protector = AESGCMKeyProtector(sentinel_key, protector_id="cli-test-aesgcm-v1")
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            url = create_request(
                state,
                ORIGIN,
                ttl_seconds=30,
                destination_label=DESTINATION,
                key_protector=protector,
                require_protected_keys=True,
            )
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "")
        self.assertIn("https://handoff-mac.example-tailnet.ts.net/handoff/", url)
        raw = state.read_bytes() + (Path(str(state) + "-wal").read_bytes() if Path(str(state) + "-wal").exists() else b"")
        self.assertNotIn(b"PRIVATE KEY", raw)
        self.assertNotIn(sentinel_key.hex().encode(), repr(protector).encode())
        self.assertNotIn("KKKK", repr(protector))
    def test_native_keychain_backend_is_mocked_no_ui_and_single_encoding(self) -> None:
        raw_key = os.urandom(32)
        encoded = encode_wrapping_key_b64url(raw_key)
        self.assertEqual(len(encoded), 43)
        self.assertEqual(decode_wrapping_key_b64url(encoded), raw_key)
        for bad in (
            raw_key.hex(),
            encoded + "=",
            encode_wrapping_key_b64url(raw_key)[:-1],
            encode_wrapping_key_b64url(os.urandom(32)) + "A",
        ):
            with self.subTest(bad=bad):
                with self.assertRaises(KeyProtectorError):
                    decode_wrapping_key_b64url(bad)
        with self.assertRaisesRegex(KeyProtectorError, "exactly 32 bytes"):
            AESGCMKeyProtector(os.urandom(16))

        backend = FakeNativeKeychainBackend(encoded.encode("ascii"))
        protector = MacOSKeychainAESGCMKeyProtector(
            service="svc",
            account="acct",
            keychain="/tmp/mock.keychain-db",
            backend=backend,
        )
        from secure_storage.crypto import generate_key_pair
        synthetic_pem = generate_key_pair().private_pem
        ciphertext = protector.protect_private_pem(
            synthetic_pem,
            request_id="req1",
        )
        self.assertEqual(
            protector.unprotect_private_pem(ciphertext, request_id="req1"),
            synthetic_pem,
        )
        self.assertEqual(backend.find_calls[0], ("svc", "acct", "/tmp/mock.keychain-db"))
        self.assertNotIn(encoded, repr(protector))
        self.assertNotIn(raw_key.hex(), repr(protector))

    def test_native_keychain_failures_are_sanitized_and_closed(self) -> None:
        secret = "SECRET-SENTINEL-DO-NOT-LEAK"
        cases = [
            b"",
            b"not-base64url",
            secret.encode("ascii"),
            RuntimeError(f"locked keychain exposed {secret}"),
            MissingKeychainSecretError(f"inaccessible {secret}"),
        ]
        for material in cases:
            with self.subTest(material=type(material).__name__):
                protector = MacOSKeychainAESGCMKeyProtector(backend=FakeNativeKeychainBackend(material))
                with self.assertRaises(KeyProtectorError) as raised:
                    protector.assert_available()
                self.assertNotIn(secret, str(raised.exception))
                self.assertNotIn(secret, repr(raised.exception))

    def test_native_backend_no_ui_lookup_shape_is_mocked_without_real_keychain(self) -> None:
        from secure_storage.key_protector import NativeMacOSKeychainBackend

        encoded = encode_wrapping_key_b64url(os.urandom(32)).encode("ascii")

        class FakeSecurityFramework:
            def __init__(self) -> None:
                self.calls = []

            def SecKeychainGetUserInteractionAllowed(self, state_ptr):
                self.calls.append(("get-ui",))
                state_ptr._obj.value = 1
                return 0

            def SecKeychainSetUserInteractionAllowed(self, state):
                self.calls.append(("set-ui", int(state)))
                return 0

            def SecKeychainFindGenericPassword(self, keychain_ref, service_len, service, account_len, account, password_len_ptr, password_data_ptr, item_ref_ptr):
                self.calls.append(("find", service_len, service, account_len, account))
                buf = ctypes.create_string_buffer(encoded)
                self.buf = buf
                password_len_ptr._obj.value = len(encoded)
                password_data_ptr._obj.value = ctypes.addressof(buf)
                item_ref_ptr._obj.value = 0xBEEF
                return 0

            def SecKeychainItemFreeContent(self, attrs, data):
                self.calls.append(("free", bool(data.value)))
                return 0

        class FakeCoreFoundation:
            def __init__(self) -> None:
                self.released = []

            def CFRelease(self, ref):
                self.released.append(ref.value)

        native = object.__new__(NativeMacOSKeychainBackend)
        native._security = FakeSecurityFramework()
        native._core_foundation = FakeCoreFoundation()
        self.assertEqual(
            native.find_generic_password_no_ui(service="svc", account="acct"),
            encoded,
        )
        self.assertEqual(native._security.calls[0], ("get-ui",))
        self.assertEqual(native._security.calls[1], ("set-ui", 0))
        self.assertEqual(native._security.calls[-1], ("set-ui", 1))
        self.assertIn(("find", 3, b"svc", 4, b"acct"), native._security.calls)
        self.assertIn(("free", True), native._security.calls)
        self.assertEqual(native._core_foundation.released, [0xBEEF])



    def test_native_keychain_no_ui_sequence_is_serialized_across_backend_instances(self) -> None:
        from secure_storage.key_protector import NativeMacOSKeychainBackend

        encoded = encode_wrapping_key_b64url(os.urandom(32)).encode("ascii")

        class CoordinatedSecurityFramework:
            def __init__(self) -> None:
                self.calls = []
                self.calls_lock = threading.Lock()
                self.first_find_entered = threading.Event()
                self.release_first_find = threading.Event()
                self.second_get_before_release = threading.Event()
                self.find_count = 0
                self.buffers = []

            def _record(self, call):
                with self.calls_lock:
                    self.calls.append(call)

            def SecKeychainGetUserInteractionAllowed(self, state_ptr):
                self._record(("get-ui", threading.current_thread().name))
                if self.first_find_entered.is_set() and not self.release_first_find.is_set():
                    self.second_get_before_release.set()
                state_ptr._obj.value = 1
                return 0

            def SecKeychainSetUserInteractionAllowed(self, state):
                self._record(("set-ui", int(state), threading.current_thread().name))
                return 0

            def SecKeychainFindGenericPassword(self, keychain_ref, service_len, service, account_len, account, password_len_ptr, password_data_ptr, item_ref_ptr):
                self._record(("find", threading.current_thread().name))
                with self.calls_lock:
                    self.find_count += 1
                    find_index = self.find_count
                if find_index == 1:
                    self.first_find_entered.set()
                    self.release_first_find.wait(timeout=2)
                buf = ctypes.create_string_buffer(encoded)
                self.buffers.append(buf)
                password_len_ptr._obj.value = len(encoded)
                password_data_ptr._obj.value = ctypes.addressof(buf)
                item_ref_ptr._obj.value = 0
                return 0

            def SecKeychainItemFreeContent(self, attrs, data):
                self._record(("free", bool(data.value), threading.current_thread().name))
                return 0

        class FakeCoreFoundation:
            def CFRelease(self, ref):
                return None

        security = CoordinatedSecurityFramework()
        native1 = object.__new__(NativeMacOSKeychainBackend)
        native1._security = security
        native1._core_foundation = FakeCoreFoundation()
        native2 = object.__new__(NativeMacOSKeychainBackend)
        native2._security = security
        native2._core_foundation = FakeCoreFoundation()
        results = []
        errors = []

        def lookup(native):
            try:
                results.append(native.find_generic_password_no_ui(service="svc", account="acct"))
            except Exception as exc:  # pragma: no cover - assertion below reports details
                errors.append(exc)

        t1 = threading.Thread(target=lookup, args=(native1,), name="lookup-1")
        t2 = threading.Thread(target=lookup, args=(native2,), name="lookup-2")
        t1.start()
        self.assertTrue(security.first_find_entered.wait(timeout=1))
        t2.start()
        self.assertFalse(security.second_get_before_release.wait(timeout=0.1))
        with security.calls_lock:
            calls_before_release = list(security.calls)
        self.assertNotIn(("set-ui", 1, "lookup-1"), calls_before_release)
        security.release_first_find.set()
        t1.join(timeout=2)
        t2.join(timeout=2)
        self.assertFalse(t1.is_alive())
        self.assertFalse(t2.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(results, [encoded, encoded])
        find_indexes = [i for i, call in enumerate(security.calls) if call[0] == "find"]
        restore_indexes = [i for i, call in enumerate(security.calls) if call[0] == "set-ui" and call[1] == 1]
        self.assertLess(find_indexes[0], restore_indexes[0])
        self.assertLess(restore_indexes[0], find_indexes[1])

    def test_create_only_provisioning_helper_uses_native_backend_contract_without_real_keychain(self) -> None:
        backend = FakeNativeKeychainBackend(b"")
        generated = provision_wrapping_key_create_only(
            service="svc",
            account="acct",
            keychain="/tmp/mock.keychain-db",
            backend=backend,
        )
        self.assertEqual(decode_wrapping_key_b64url(generated), backend.add_calls[0][2] and decode_wrapping_key_b64url(backend.add_calls[0][2].decode("ascii")))
        self.assertEqual(backend.add_calls[0][0:2], ("svc", "acct"))
        self.assertEqual(backend.add_calls[0][3], "/tmp/mock.keychain-db")
        self.assertEqual(backend.find_calls, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
