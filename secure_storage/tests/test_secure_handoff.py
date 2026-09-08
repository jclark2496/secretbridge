from __future__ import annotations

import io
import json
import logging
import re
import socket
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from http.cookiejar import CookieJar
from pathlib import Path

from playwright.sync_api import sync_playwright

from secure_storage.crypto import decrypt_envelope
from secure_storage.server import ServerConfig, make_server, validate_external_origin
from secure_storage.sinks import HandoffDestination, HandoffReceipt
from secure_storage.store import DEFAULT_DESTINATION_ID, RequestStore

VALUE = "browser supplied credential value"
DESTINATION = "MacBoundDestination"
TAILSCALE_ORIGIN = "https://handoff-mac.example-tailnet.ts.net"
TAILSCALE_HOST = "handoff-mac.example-tailnet.ts.net"
TAILSCALE_LOGIN = "operator@example.com"


class HttpResult:
    def __init__(self, status: int, body: str, headers):
        self.status = status
        self.body = body
        self.headers = headers


class FakeSink:
    durable = True

    def __init__(self, *, fail: bool = False):
        self.fail = fail
        self.calls: list[tuple[str, str, str]] = []
        self.lock = threading.Lock()

    def store(self, *, destination: HandoffDestination, value: str, request_id: str) -> HandoffReceipt:
        if self.fail:
            raise RuntimeError("fake sink failure")
        with self.lock:
            self.calls.append((destination.label, value, request_id))
            return HandoffReceipt(request_id, destination.destination_id, destination.label, f"fake-storage-{len(self.calls)}", True, True)


class BadReceiptSink(FakeSink):
    def __init__(self, **overrides):
        super().__init__()
        self.overrides = overrides

    def store(self, *, destination: HandoffDestination, value: str, request_id: str):
        self.calls.append((destination.label, value, request_id))
        if self.overrides.get("raw") is not None:
            return self.overrides["raw"]
        fields = {
            "request_id": request_id,
            "destination_id": destination.destination_id,
            "destination_label": destination.label,
            "receipt_id": "bad-receipt",
            "storage_confirmed": True,
            "durable": True,
        }
        fields.update(self.overrides)
        return HandoffReceipt(**fields)


class LegacyCallableOnlySink:
    durable = True

    def __call__(self, name: str, value: str, request_id: str) -> str:
        return "legacy-storage-id"


class SecureHandoffTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.state = Path(self.tmp.name) / "state.sqlite3"
        self.log_stream = io.StringIO()
        self.logger = logging.getLogger(f"secure-handoff-test-{id(self)}")
        self.logger.handlers.clear()
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False
        handler = logging.StreamHandler(self.log_stream)
        handler.setFormatter(logging.Formatter("%(message)s"))
        self.logger.addHandler(handler)
        self.sink = FakeSink()
        self.server = make_server(ServerConfig(state_path=self.state, port=0, sink=self.sink, logger=self.logger))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        self.base_url = f"http://{host}:{port}"
        self.jar = CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.tmp.cleanup()

    def create_url(self, ttl: int = 30) -> str:
        request_id, auth = RequestStore(self.state).create_request(ttl_seconds=ttl, destination_id=DEFAULT_DESTINATION_ID, destination_label=DESTINATION)
        return f"{self.base_url}/handoff/{request_id}?auth={urllib.parse.quote(auth)}"

    def open(self, url: str, *, opener=None, data=None, headers=None, method=None) -> HttpResult:
        req = urllib.request.Request(url, data=data, headers=headers or {}, method=method)
        try:
            with (opener or self.opener).open(req, timeout=5) as resp:
                return HttpResult(resp.status, resp.read().decode("utf-8"), resp.headers)
        except urllib.error.HTTPError as exc:
            try:
                return HttpResult(exc.code, exc.read().decode("utf-8"), exc.headers)
            finally:
                exc.close()

    def get_page_bits(self, url: str) -> tuple[str, str, dict, str, HttpResult]:
        result = self.open(url)
        self.assertEqual(result.status, 200, result.body)
        self.assertEqual(result.headers.get("Referrer-Policy"), "same-origin")
        self.assertIn("no-store", result.headers.get("Cache-Control", ""))
        self.assertEqual(result.headers.get("X-Frame-Options"), "DENY")
        self.assertIn("frame-ancestors 'none'", result.headers.get("Content-Security-Policy", ""))
        csrf = re.search(r"const CSRF = (\"[^\"]+\");", result.body)
        jwk = re.search(r"const PUBLIC_JWK = (\{.*?\});", result.body, re.S)
        self.assertIsNotNone(csrf)
        self.assertIsNotNone(jwk)
        request_id = urllib.parse.urlparse(url).path.rsplit("/", 1)[-1]
        post_url = urllib.parse.urljoin(url, urllib.parse.urlparse(url).path)
        return post_url, json.loads(csrf.group(1)), json.loads(jwk.group(1)), request_id, result  # type: ignore[union-attr]

    def cookie_header(self) -> str:
        return "; ".join(f"{c.name}={c.value}" for c in self.jar)

    def make_envelope_in_browser(self, request_id: str, jwk: dict, value: str = VALUE) -> dict:
        script = r"""
        async ({requestId, jwk, value}) => {
          function b64url(bytes) {
            let s = '';
            for (const b of bytes) s += String.fromCharCode(b);
            return btoa(s).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
          }
          const enc = new TextEncoder();
          const aesKey = await crypto.subtle.generateKey({name: 'AES-GCM', length: 256}, true, ['encrypt']);
          const rawKey = await crypto.subtle.exportKey('raw', aesKey);
          const rsaKey = await crypto.subtle.importKey('jwk', jwk, {name: 'RSA-OAEP', hash: 'SHA-256'}, false, ['encrypt']);
          const iv = crypto.getRandomValues(new Uint8Array(12));
          const aad = enc.encode(`secure-handoff:v1:${requestId}`);
          const ciphertext = await crypto.subtle.encrypt({name: 'AES-GCM', iv, additionalData: aad}, aesKey, enc.encode(value));
          const wrapped = await crypto.subtle.encrypt({name: 'RSA-OAEP'}, rsaKey, rawKey);
          return {version: 1, request_id: requestId, wrapped_key: b64url(new Uint8Array(wrapped)), iv: b64url(iv), ciphertext: b64url(new Uint8Array(ciphertext))};
        }
        """
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            page.goto(self.base_url + "/missing")
            envelope = page.evaluate(script, {"requestId": request_id, "jwk": jwk, "value": value})
            browser.close()
        return envelope

    def post_envelope(self, post_url: str, csrf: str, envelope: dict, *, origin: str | None = None, cookie: str | None = None) -> HttpResult:
        headers = {"Content-Type": "application/json", "X-CSRF-Token": csrf}
        headers["Origin"] = self.base_url if origin is None else origin
        if cookie is not None:
            headers["Cookie"] = cookie
        body = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
        return self.open(post_url, data=body, headers=headers, method="POST")

    def test_browser_webcrypto_roundtrip_decrypts_and_sink_confirms(self) -> None:
        url = self.create_url()
        request_id = urllib.parse.urlparse(url).path.rsplit("/", 1)[-1]
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            page.goto(url)
            page.locator("#value").fill(VALUE)
            page.locator("button").click()
            page.wait_for_selector("text=Stored", timeout=5000)
            body = page.locator("body").inner_text()
            browser.close()
        self.assertIn("fake-storage-1", body)
        self.assertNotIn(VALUE, body)
        self.assertEqual(self.sink.calls, [(DESTINATION, VALUE, request_id)])
        db_text = RequestStore(self.state).dump_text_for_tests()
        self.assertNotIn(VALUE, db_text)
        self.assertNotIn(VALUE, self.log_stream.getvalue())
        self.assertIn("encrypted_envelope", "encrypted_envelope_json")

    def test_browser_form_warns_and_preserves_leading_trailing_whitespace(self) -> None:
        exact_value = "  browser supplied credential value  "
        url = self.create_url()
        request_id = urllib.parse.urlparse(url).path.rsplit("/", 1)[-1]
        with sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page()
            page.goto(url)
            page.locator("#value").fill(exact_value)
            warning = page.locator("#whitespace-warning")
            self.assertTrue(warning.is_visible())
            self.assertIn("Hermes will preserve the value exactly as typed", warning.inner_text())
            page.locator("button[type=submit]").click()
            self.assertEqual(self.sink.calls, [])
            self.assertIn("Confirm that leading or trailing whitespace is intentional", page.locator("#status").inner_text())
            page.locator("#whitespace-acknowledge").check()
            page.locator("#value").fill(exact_value + "x")
            self.assertFalse(page.locator("#whitespace-acknowledge").is_checked())
            page.locator("#whitespace-acknowledge").check()
            final_value = exact_value + "x"
            page.locator("button[type=submit]").click()
            page.wait_for_selector("text=Stored", timeout=5000)
            body = page.locator("body").inner_text()
            browser.close()
        self.assertIn("fake-storage-1", body)
        self.assertNotIn(final_value, body)
        self.assertEqual(self.sink.calls, [(DESTINATION, final_value, request_id)])
        self.assertNotEqual(self.sink.calls[0][1], self.sink.calls[0][1].strip())
        self.assertNotIn(final_value, RequestStore(self.state).dump_text_for_tests())
        self.assertNotIn(final_value, self.log_stream.getvalue())

    def test_python_decrypt_rejects_wrong_request_context(self) -> None:
        url = self.create_url()
        post_url, _csrf, jwk, request_id, _ = self.get_page_bits(url)
        envelope = self.make_envelope_in_browser(request_id, jwk)
        with closing(self.server.handoff_store._connect()) as conn:
            row = conn.execute("SELECT private_key_pem FROM requests WHERE request_id = ?", (request_id,)).fetchone()
            private_key_pem = row["private_key_pem"]
        self.assertEqual(decrypt_envelope(envelope, request_id=request_id, private_pem=private_key_pem), VALUE)
        envelope["request_id"] = "wrong"
        with self.assertRaises(ValueError):
            decrypt_envelope(envelope, request_id=request_id, private_pem=private_key_pem)
        self.assertTrue(post_url.endswith(request_id))

    def test_malformed_envelope_rejected(self) -> None:
        post_url, csrf, _jwk, _request_id, _ = self.get_page_bits(self.create_url())
        result = self.post_envelope(post_url, csrf, {"version": 1, "request_id": "bad", "wrapped_key": "not*base64", "iv": "x", "ciphertext": "y"})
        self.assertEqual(result.status, 400)
        self.assertEqual(self.sink.calls, [])

    def test_wrong_request_context_rejected_by_submit(self) -> None:
        post_url, csrf, jwk, request_id, _ = self.get_page_bits(self.create_url())
        envelope = self.make_envelope_in_browser(request_id, jwk)
        envelope["request_id"] = "wrong"
        result = self.post_envelope(post_url, csrf, envelope)
        self.assertEqual(result.status, 400)
        self.assertEqual(self.sink.calls, [])

    def test_browser_supplied_destination_field_rejected(self) -> None:
        post_url, csrf, jwk, request_id, _ = self.get_page_bits(self.create_url())
        envelope = self.make_envelope_in_browser(request_id, jwk)
        envelope["destination_label"] = "browser-chosen-name"
        result = self.post_envelope(post_url, csrf, envelope)
        self.assertEqual(result.status, 400)
        self.assertEqual(self.sink.calls, [])

    def test_oversize_rejected(self) -> None:
        post_url, csrf, _jwk, request_id, _ = self.get_page_bits(self.create_url())
        result = self.post_envelope(post_url, csrf, {"version": 1, "request_id": request_id, "wrapped_key": "A" * 40000, "iv": "A" * 16, "ciphertext": "A"})
        self.assertEqual(result.status, 413)

    def test_expired_rejected(self) -> None:
        url = self.create_url(ttl=1)
        time.sleep(1.2)
        result = self.open(url)
        self.assertEqual(result.status, 410)
        self.assertIn("expired", result.body)

    def test_replay_rejected(self) -> None:
        post_url, csrf, jwk, request_id, _ = self.get_page_bits(self.create_url())
        envelope = self.make_envelope_in_browser(request_id, jwk)
        self.assertEqual(self.post_envelope(post_url, csrf, envelope).status, 200)
        self.assertEqual(self.post_envelope(post_url, csrf, envelope).status, 410)
        self.assertEqual(len(self.sink.calls), 1)

    def test_concurrent_submission_one_success(self) -> None:
        post_url, csrf, jwk, request_id, _ = self.get_page_bits(self.create_url())
        envelope = self.make_envelope_in_browser(request_id, jwk)
        cookie = self.cookie_header()

        def submit() -> int:
            opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(CookieJar()))
            headers = {"Content-Type": "application/json", "X-CSRF-Token": csrf, "Origin": self.base_url, "Cookie": cookie}
            body = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
            return self.open(post_url, opener=opener, data=body, headers=headers, method="POST").status

        with ThreadPoolExecutor(max_workers=12) as pool:
            statuses = list(pool.map(lambda _: submit(), range(12)))
        self.assertEqual(statuses.count(200), 1, statuses)
        self.assertEqual(statuses.count(410), 11, statuses)
        self.assertEqual(len(self.sink.calls), 1)

    def test_sink_failure_does_not_mark_used_or_claim_stored(self) -> None:
        self.server.handoff_config.sink = FakeSink(fail=True)
        post_url, csrf, jwk, request_id, _ = self.get_page_bits(self.create_url())
        envelope = self.make_envelope_in_browser(request_id, jwk)
        result = self.post_envelope(post_url, csrf, envelope)
        self.assertEqual(result.status, 502)
        with closing(self.server.handoff_store._connect()) as conn:
            row = conn.execute("SELECT used, storage_id FROM requests WHERE request_id = ?", (request_id,)).fetchone()
            self.assertEqual(int(row["used"]), 0)
            self.assertIsNone(row["storage_id"])

    def test_sink_receipt_must_match_bound_request_destination_and_durability(self) -> None:
        cases = [
            ("wrong request", {"request_id": "wrong-request"}),
            ("wrong destination", {"destination_id": "attacker-dest"}),
            ("wrong label", {"destination_label": "attacker-label"}),
            ("missing confirmation", {"storage_confirmed": False}),
            ("non durable", {"durable": False}),
            ("truthy confirmation", {"storage_confirmed": "yes"}),
            ("string ack", {"raw": "truthy-storage-id"}),
        ]
        for _name, overrides in cases:
            with self.subTest(_name):
                self.server.handoff_config.sink = BadReceiptSink(**overrides)
                post_url, csrf, jwk, request_id, _ = self.get_page_bits(self.create_url())
                envelope = self.make_envelope_in_browser(request_id, jwk)
                result = self.post_envelope(post_url, csrf, envelope)
                self.assertEqual(result.status, 502)
                meta = RequestStore(self.state).receipt_metadata(request_id)
                self.assertEqual(meta["status"], "pending")
                self.assertIsNone(meta["storage_id"])

    def test_legacy_callable_sink_and_missing_store_are_rejected(self) -> None:
        for sink in (LegacyCallableOnlySink(), object()):
            with self.subTest(sink=type(sink).__name__):
                with self.assertRaisesRegex(ValueError, "structured store contract|durable flag"):
                    make_server(ServerConfig(state_path=self.state.with_name(f"{type(sink).__name__}.sqlite3"), port=0, sink=sink))

    def test_no_plaintext_in_db_or_logs_after_rejections(self) -> None:
        post_url, csrf, jwk, request_id, _ = self.get_page_bits(self.create_url())
        envelope = self.make_envelope_in_browser(request_id, jwk, VALUE)
        envelope["ciphertext"] = envelope["ciphertext"][:-2] + "AA"
        result = self.post_envelope(post_url, csrf, envelope)
        self.assertEqual(result.status, 400)
        self.assertNotIn(VALUE, RequestStore(self.state).dump_text_for_tests())
        self.assertNotIn(VALUE, self.log_stream.getvalue())

    def test_local_creation_only_no_http_create(self) -> None:
        result = self.open(self.base_url + "/create", method="POST", data=b"{}", headers={"Origin": self.base_url, "Content-Type": "application/json"})
        self.assertEqual(result.status, 404)

    def test_origin_null_and_bad_origin_rejected(self) -> None:
        post_url, csrf, jwk, request_id, _ = self.get_page_bits(self.create_url())
        envelope = self.make_envelope_in_browser(request_id, jwk)
        self.assertEqual(self.post_envelope(post_url, csrf, envelope, origin="null").status, 403)
        self.assertEqual(self.post_envelope(post_url, csrf, envelope, origin="http://evil.example").status, 403)
        self.assertEqual(self.sink.calls, [])

    def test_server_refuses_public_bind(self) -> None:
        with self.assertRaises(ValueError):
            make_server(ServerConfig(state_path=self.state, host="0.0.0.0", sink=self.sink))


class TailscaleGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.state = Path(self.tmp.name) / "state.sqlite3"
        self.server = make_server(ServerConfig(
            state_path=self.state,
            port=0,
            external_origin=TAILSCALE_ORIGIN,
            tailscale_user_login=TAILSCALE_LOGIN,
            sink=FakeSink(),
        ))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        host, port = self.server.server_address
        self.loopback = f"http://{host}:{port}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.tmp.cleanup()

    def request_url(self) -> str:
        request_id, auth = RequestStore(self.state).create_request(ttl_seconds=30, destination_id=DEFAULT_DESTINATION_ID, destination_label=DESTINATION)
        return f"{TAILSCALE_ORIGIN}/handoff/{request_id}?auth={urllib.parse.quote(auth)}"

    def proxied(self, external_url: str) -> str:
        parsed = urllib.parse.urlparse(external_url)
        return self.loopback + urllib.parse.urlunparse(("", "", parsed.path, "", parsed.query, ""))

    def open(self, url: str, *, headers=None) -> HttpResult:
        req = urllib.request.Request(url, headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return HttpResult(resp.status, resp.read().decode("utf-8"), resp.headers)
        except urllib.error.HTTPError as exc:
            try:
                return HttpResult(exc.code, exc.read().decode("utf-8"), exc.headers)
            finally:
                exc.close()

    def raw_request(self, request: bytes) -> tuple[int, str]:
        with socket.create_connection(self.server.server_address, timeout=5) as sock:
            sock.sendall(request)
            sock.shutdown(socket.SHUT_WR)
            chunks = []
            while True:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                chunks.append(chunk)
        text = b"".join(chunks).decode("iso-8859-1")
        return int(text.split(" ", 2)[1]), text

    def gate_headers(self, **overrides: str) -> dict[str, str]:
        headers = {"Host": TAILSCALE_HOST, "Tailscale-User-Login": TAILSCALE_LOGIN}
        headers.update(overrides)
        return headers

    def test_tailscale_identity_host_and_secure_cookie(self) -> None:
        url = self.proxied(self.request_url())
        self.assertEqual(self.open(url, headers={"Host": TAILSCALE_HOST}).status, 401)
        self.assertEqual(self.open(url, headers=self.gate_headers(**{"Tailscale-User-Login": "other@example.com"})).status, 401)
        self.assertEqual(self.open(url, headers=self.gate_headers(Host="evil.example")).status, 400)
        ok = self.open(url, headers=self.gate_headers())
        self.assertEqual(ok.status, 200, ok.body)
        self.assertIn("Secure", ok.headers.get("Set-Cookie", ""))

    def test_duplicate_identity_and_host_rejected(self) -> None:
        parsed = urllib.parse.urlparse(self.request_url())
        request = (
            f"GET {parsed.path}?{parsed.query} HTTP/1.1\r\n"
            f"Host: {TAILSCALE_HOST}\r\n"
            f"Tailscale-User-Login: {TAILSCALE_LOGIN}\r\n"
            f"Tailscale-User-Login: {TAILSCALE_LOGIN}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        self.assertEqual(self.raw_request(request)[0], 401)
        request = (
            f"GET {parsed.path}?{parsed.query} HTTP/1.1\r\n"
            f"Host: {TAILSCALE_HOST}\r\n"
            "Host: evil.example\r\n"
            f"Tailscale-User-Login: {TAILSCALE_LOGIN}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        self.assertEqual(self.raw_request(request)[0], 400)

    def test_config_validation(self) -> None:
        self.assertEqual(validate_external_origin("https://handoff-mac.example-tailnet.ts.net/"), "https://handoff-mac.example-tailnet.ts.net")
        for bad in ("http://handoff-mac.example-tailnet.ts.net", "https://evil.ts.net", "https://handoff-mac.example-tailnet.ts.net/path"):
            with self.assertRaises(ValueError):
                validate_external_origin(bad)
        with self.assertRaises(ValueError):
            validate_external_origin("https://handoff-relay.example-tailnet.ts.net")
        self.assertEqual(
            validate_external_origin(
                "https://handoff-mac.example-tailnet.ts.net:9443",
                ("https://handoff-mac.example-tailnet.ts.net:9443",),
            ),
            "https://handoff-mac.example-tailnet.ts.net:9443",
        )
        with self.assertRaises(ValueError):
            make_server(ServerConfig(
                state_path=self.state,
                port=0,
                external_origin="https://not-allowed.example-tailnet.ts.net",
                allowed_external_origins=(TAILSCALE_ORIGIN,),
                tailscale_user_login=TAILSCALE_LOGIN,
                sink=FakeSink(),
            ))
        with self.assertRaises(ValueError):
            make_server(ServerConfig(state_path=self.state, port=0, external_origin=TAILSCALE_ORIGIN, sink=FakeSink()))


if __name__ == "__main__":
    unittest.main(verbosity=2)
