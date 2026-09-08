"""Loopback HTTP collector for encrypted handoff."""
from __future__ import annotations

import argparse
import html
import http.cookies
import json
import logging
import secrets
import sys
import urllib.parse
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .crypto import VERSION
from .key_protector import (
    DEFAULT_KEYCHAIN_ACCOUNT,
    DEFAULT_KEYCHAIN_SERVICE,
    KeyProtector,
    KeyProtectorError,
    MacOSKeychainAESGCMKeyProtector,
)
from .sinks import DurableSink, NoConfiguredSink
from .store import RequestStore, is_urlsafe_token

SESSION_COOKIE = "secure_handoff_session"
MAX_BODY_BYTES = 49152
MAC_MINI_TAILSCALE_HOSTNAME = "handoff-mac.example-tailnet.ts.net"
DEFAULT_ALLOWED_EXTERNAL_ORIGINS = (f"https://{MAC_MINI_TAILSCALE_HOSTNAME}",)


@dataclass
class ServerConfig:
    state_path: Path
    host: str = "127.0.0.1"
    port: int = 8765
    external_origin: str | None = None
    allowed_external_origins: tuple[str, ...] = DEFAULT_ALLOWED_EXTERNAL_ORIGINS
    tailscale_user_login: str | None = None
    sink: DurableSink = NoConfiguredSink()
    allow_ephemeral_demo_sink: bool = False
    logger: logging.Logger | None = None
    key_protector: KeyProtector | None = None
    require_protected_keys: bool = False

    @property
    def tailscale_mode(self) -> bool:
        return self.external_origin is not None or self.tailscale_user_login is not None


def validate_external_origin(value: str, allowed_origins: tuple[str, ...] = DEFAULT_ALLOWED_EXTERNAL_ORIGINS) -> str:
    allowed = tuple(_normalize_external_origin(origin) for origin in allowed_origins)
    normalized = _normalize_external_origin(value)
    if normalized not in allowed:
        raise ValueError(f"external origin must be one of explicit allowlist: {', '.join(allowed)}")
    return normalized


def _normalize_external_origin(value: str) -> str:
    parsed = urllib.parse.urlparse(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path not in ("", "/")
        or parsed.params
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("external origin must be an https origin with no path, query, fragment, or credentials")
    return f"https://{parsed.netloc}"


def validate_tailscale_user_login(value: str) -> str:
    if not value or value.strip() != value or any(ch in value for ch in "\r\n"):
        raise ValueError("tailscale user login must be one exact nonempty login string")
    return value


def html_page(title: str, body: str) -> bytes:
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta destination_label="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(title)}</title>
  <style>
    body {{ font-family: system-ui, -apple-system, sans-serif; margin: 2rem; max-width: 760px; }}
    label, input, button {{ display: block; font-size: 1rem; margin: .7rem 0; }}
    input {{ width: 100%; padding: .55rem; }}
    .warning {{ border: 1px solid #b45309; background: #fffbeb; padding: .75rem; }}
    .muted {{ color: #555; }}
  </style>
</head>
<body>
  <p class="warning"><strong>Encrypted local handoff prototype.</strong> Do not enter live credentials until reviewed.</p>
  {body}
</body>
</html>""".encode("utf-8")


def encryption_script(request_id: str, public_jwk_json: str, csrf: str) -> str:
    # Browser WebCrypto only; Python decrypts with cryptography on the Mac side.
    return rf"""
<script>
const REQUEST_ID = {json.dumps(request_id)};
const VERSION = {VERSION};
const PUBLIC_JWK = {public_jwk_json};
const CSRF = {json.dumps(csrf)};
const EDGE_WHITESPACE_RE = /^\s|\s$/u;
function b64url(bytes) {{
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}}
async function encryptValue(value) {{
  const enc = new TextEncoder();
  const aesKey = await crypto.subtle.generateKey({{name: 'AES-GCM', length: 256}}, true, ['encrypt']);
  const rawKey = await crypto.subtle.exportKey('raw', aesKey);
  const rsaKey = await crypto.subtle.importKey(
    'jwk', PUBLIC_JWK, {{name: 'RSA-OAEP', hash: 'SHA-256'}}, false, ['encrypt']
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aad = enc.encode(`secure-handoff:v${{VERSION}}:${{REQUEST_ID}}`);
  const ciphertext = await crypto.subtle.encrypt({{name: 'AES-GCM', iv, additionalData: aad}}, aesKey, enc.encode(value));
  const wrapped = await crypto.subtle.encrypt({{name: 'RSA-OAEP'}}, rsaKey, rawKey);
  return {{
    version: VERSION,
    request_id: REQUEST_ID,
    wrapped_key: b64url(new Uint8Array(wrapped)),
    iv: b64url(iv),
    ciphertext: b64url(new Uint8Array(ciphertext))
  }};
}}
const valueInput = document.getElementById('value');
const whitespaceWarning = document.getElementById('whitespace-warning');
const whitespaceAcknowledge = document.getElementById('whitespace-acknowledge');
function valueHasEdgeWhitespace() {{
  return EDGE_WHITESPACE_RE.test(valueInput.value);
}}
function refreshWhitespaceWarning() {{
  const needsAck = valueHasEdgeWhitespace();
  whitespaceWarning.hidden = !needsAck;
  if (!needsAck || whitespaceAcknowledge.dataset.lastValue !== valueInput.value) {{
    whitespaceAcknowledge.checked = false;
    whitespaceAcknowledge.dataset.lastValue = valueInput.value;
  }}
}}
valueInput.addEventListener('input', refreshWhitespaceWarning);
whitespaceAcknowledge.addEventListener('change', () => {{
  whitespaceAcknowledge.dataset.lastValue = valueInput.value;
}});
document.getElementById('handoff-form').addEventListener('submit', async (event) => {{
  event.preventDefault();
  const status = document.getElementById('status');
  refreshWhitespaceWarning();
  if (valueHasEdgeWhitespace() && !whitespaceAcknowledge.checked) {{
    status.textContent = 'Confirm that leading or trailing whitespace is intentional before submitting.';
    whitespaceAcknowledge.focus();
    return;
  }}
  status.textContent = 'Encrypting locally in browser...';
  try {{
    const envelope = await encryptValue(valueInput.value);
    valueInput.value = '';
    const response = await fetch(`/handoff/${{encodeURIComponent(REQUEST_ID)}}`, {{
      method: 'POST',
      credentials: 'same-origin',
      headers: {{'Content-Type': 'application/json', 'X-CSRF-Token': CSRF}},
      body: JSON.stringify(envelope)
    }});
    const text = await response.text();
    if (!response.ok) throw new Error(text || `HTTP ${{response.status}}`);
    document.open(); document.write(text); document.close();
  }} catch (err) {{
    status.textContent = 'Submission failed.';
  }}
}});
</script>
"""


class SecureHandoffHandler(BaseHTTPRequestHandler):
    server_version = "SecureLocalHandoff/0.1"

    @property
    def config(self) -> ServerConfig:
        return self.server.handoff_config  # type: ignore[attr-defined]

    @property
    def store(self) -> RequestStore:
        return self.server.handoff_store  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: object) -> None:
        logger = self.config.logger or logging.getLogger("secure_handoff")
        logger.info("event=http_message remote=%s", self.client_address[0])

    def log_request(self, code: int | str = "-", size: int | str = "-") -> None:
        logger = self.config.logger or logging.getLogger("secure_handoff")
        logger.info("event=http_request method=%s status=%s size=%s remote=%s", self.command, code, size, self.client_address[0])

    def _log_reject(self, reason: str, request_id: str | None = None) -> None:
        logger = self.config.logger or logging.getLogger("secure_handoff")
        if request_id and is_urlsafe_token(request_id, max_len=128):
            logger.info("event=request_rejected reason=%s request_id=%s", reason, request_id)
        else:
            logger.info("event=request_rejected reason=%s", reason)

    def _send(self, status: int, body: bytes, content_type: str = "text/html; charset=utf-8", extra_headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, status: int, text: str) -> None:
        self._send(status, text.encode("utf-8"), "text/plain; charset=utf-8")

    def _server_origin(self) -> str:
        if self.config.external_origin:
            return self.config.external_origin
        return f"http://{self.server.server_address[0]}:{self.server.server_address[1]}"

    def _expected_host(self) -> str:
        if self.config.external_origin:
            return urllib.parse.urlparse(self.config.external_origin).netloc
        return f"{self.server.server_address[0]}:{self.server.server_address[1]}"

    def _preflight_allowed(self) -> bool:
        if self.config.tailscale_mode:
            values = self.headers.get_all("Tailscale-User-Login", failobj=[])
            if len(values) != 1 or values[0] != self.config.tailscale_user_login:
                self._log_reject("tailscale_identity")
                self._send_text(HTTPStatus.UNAUTHORIZED, "unauthorized")
                return False
        hosts = self.headers.get_all("Host", failobj=[])
        if len(hosts) != 1 or hosts[0] != self._expected_host():
            self._log_reject("bad_host")
            self._send_text(HTTPStatus.BAD_REQUEST, "bad host")
            return False
        return True

    def _origin_allowed(self) -> bool:
        expected = self._server_origin()
        origins = self.headers.get_all("Origin", failobj=[])
        referers = self.headers.get_all("Referer", failobj=[])
        if len(origins) > 1 or len(referers) > 1:
            return False
        if origins:
            return origins[0] == expected
        if referers:
            return referers[0].startswith(expected + "/")
        return False

    def _parse_request_id(self) -> tuple[str | None, urllib.parse.ParseResult]:
        parsed = urllib.parse.urlparse(self.path)
        parts = [p for p in parsed.path.split("/") if p]
        if len(parts) == 2 and parts[0] == "handoff" and is_urlsafe_token(parts[1], max_len=128):
            return parts[1], parsed
        return None, parsed

    def _auth_param(self, parsed: urllib.parse.ParseResult) -> str | None:
        try:
            query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True, max_num_fields=1)
        except (ValueError, TypeError):
            return None
        values = query.get("auth")
        if not values or len(values) != 1 or not is_urlsafe_token(values[0], max_len=256):
            return None
        return values[0]

    def do_GET(self) -> None:
        if not self._preflight_allowed():
            return
        request_id, parsed = self._parse_request_id()
        if not request_id:
            self._send_text(HTTPStatus.NOT_FOUND, "not found")
            return
        auth = self._auth_param(parsed)
        if auth is None:
            self._log_reject("bad_auth", request_id)
            self._send_text(HTTPStatus.UNAUTHORIZED, "unauthorized")
            return
        session_id = secrets.token_urlsafe(24)
        csrf = secrets.token_urlsafe(24)
        ok, reason, record = self.store.open_session(request_id, auth, session_id, csrf)
        if not ok or record is None:
            self._log_reject(reason.replace(" ", "_"), request_id)
            self._send_text(HTTPStatus.UNAUTHORIZED if reason == "unauthorized" else HTTPStatus.GONE, reason)
            return
        body = html_page("Encrypted handoff", f"""
<h1>Encrypted local handoff</h1>
<p>Destination is fixed by the operator-created request: <strong>{html.escape(record['destination_label'])}</strong>.</p>
<p class="muted">The browser cannot choose the destination.</p>
<form id="handoff-form">
  <label for="value">Value to encrypt in this browser</label>
  <input id="value" destination_label="value" autocomplete="off" required maxlength="4096">
  <div id="whitespace-warning" class="warning" hidden>
    <p><strong>Whitespace warning:</strong> this value starts or ends with whitespace. Hermes will preserve the value exactly as typed; it will not trim spaces, tabs, or newlines.</p>
    <label><input id="whitespace-acknowledge" type="checkbox"> I understand the leading/trailing whitespace is intentional.</label>
  </div>
  <button type="submit">Encrypt and submit</button>
</form>
<p id="status" role="status"></p>
{encryption_script(request_id, record['public_jwk_json'], csrf)}
""")
        cookie = http.cookies.SimpleCookie()
        cookie[SESSION_COOKIE] = session_id
        cookie[SESSION_COOKIE]["path"] = "/"
        cookie[SESSION_COOKIE]["httponly"] = True
        cookie[SESSION_COOKIE]["samesite"] = "Strict"
        if self.config.tailscale_mode:
            cookie[SESSION_COOKIE]["secure"] = True
        self._send(HTTPStatus.OK, body, extra_headers={"Set-Cookie": cookie.output(header="").strip()})

    def _read_json(self) -> dict | None:
        if self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
            return None
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None
        if length <= 0 or length > MAX_BODY_BYTES:
            return None
        raw = self.rfile.read(length)
        if len(raw) != length:
            return None
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return None
        return data if isinstance(data, dict) else None

    def _session_cookie(self) -> str:
        try:
            cookie = http.cookies.SimpleCookie(self.headers.get("Cookie", ""))
        except http.cookies.CookieError:
            return ""
        morsel = cookie.get(SESSION_COOKIE)
        return morsel.value if morsel else ""

    def do_POST(self) -> None:
        if not self._preflight_allowed():
            return
        request_id, _ = self._parse_request_id()
        if not request_id:
            self._send_text(HTTPStatus.NOT_FOUND, "not found")
            return
        if not self._origin_allowed():
            self._log_reject("origin", request_id)
            self._send_text(HTTPStatus.FORBIDDEN, "bad origin")
            return
        csrf_values = self.headers.get_all("X-CSRF-Token", failobj=[])
        if len(csrf_values) != 1:
            self._log_reject("csrf", request_id)
            self._send_text(HTTPStatus.FORBIDDEN, "bad csrf")
            return
        envelope = self._read_json()
        if envelope is None:
            self._log_reject("bad_json", request_id)
            self._send_text(HTTPStatus.BAD_REQUEST, "bad request")
            return
        ok, reason, status, storage_id = self.store.submit_envelope(
            request_id,
            cookie_session=self._session_cookie(),
            csrf=csrf_values[0],
            envelope=envelope,
            sink=self.config.sink,
        )
        if not ok:
            self._log_reject(reason.replace(" ", "_"), request_id)
            self._send_text(status, reason)
            return
        if self.config.allow_ephemeral_demo_sink:
            title = "Ephemeral demo recorded"
            heading = "Ephemeral demo recorded"
            note = "Encrypted handoff was decrypted locally and acknowledged by the in-memory demo sink only; this is not durable storage."
        else:
            title = "Stored"
            heading = "Stored"
            note = "Encrypted handoff was decrypted locally and recorded only after durable sink acknowledgement."
        body = html_page(title, f"""
<h1>{heading}</h1>
<p>{note}</p>
<p>Storage ID: <code>{html.escape(storage_id or '')}</code></p>
<p>No submitted value is displayed in this receipt.</p>
""")
        self._send(HTTPStatus.OK, body)


def make_server(config: ServerConfig) -> ThreadingHTTPServer:
    if config.host != "127.0.0.1":
        raise ValueError("server must bind only to 127.0.0.1")
    if isinstance(config.sink, NoConfiguredSink):
        raise ValueError("no configured durable sink")
    sink_durable = getattr(config.sink, "durable", None)
    if sink_durable is not True and sink_durable is not False:
        raise ValueError("sink durable flag must be boolean")
    if not callable(getattr(config.sink, "store", None)):
        raise ValueError("sink must implement the structured store contract")
    if not config.allow_ephemeral_demo_sink and sink_durable is not True:
        raise ValueError("no configured durable sink")
    if config.allow_ephemeral_demo_sink and sink_durable is True:
        raise ValueError("ephemeral demo mode must not use a durable sink")
    if config.tailscale_mode:
        if not config.external_origin or not config.tailscale_user_login:
            raise ValueError("tailscale mode requires external origin and exact user login")
        config.external_origin = validate_external_origin(config.external_origin, config.allowed_external_origins)
        config.tailscale_user_login = validate_tailscale_user_login(config.tailscale_user_login)
    server = ThreadingHTTPServer((config.host, config.port), SecureHandoffHandler)
    server.handoff_config = config  # type: ignore[attr-defined]
    server.handoff_store = RequestStore(
        config.state_path,
        key_protector=config.key_protector,
        require_protected_keys=config.require_protected_keys,
    )  # type: ignore[attr-defined]
    return server


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run encrypted local-only handoff collector prototype.")
    parser.add_argument("--state", type=Path, default=Path(__file__).with_name("secure_handoff.sqlite3"))
    parser.add_argument(
        "--encrypted-state",
        type=Path,
        help="explicit opt-in protected SQLite path; refuses the default plaintext-compatible DB path",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--external-origin", required=True, help="explicit HTTPS origin from the allowlist")
    parser.add_argument(
        "--allowed-origin",
        action="append",
        dest="allowed_origins",
        default=None,
        help="allowed HTTPS origin; repeatable; defaults to https://handoff-mac.example-tailnet.ts.net",
    )
    parser.add_argument("--tailscale-user-login", required=True, help="exact Tailscale-User-Login value allowed")
    parser.add_argument("--keychain-service", default=DEFAULT_KEYCHAIN_SERVICE)
    parser.add_argument("--keychain-account", default=DEFAULT_KEYCHAIN_ACCOUNT)
    parser.add_argument("--keychain", help="optional explicit keychain-db path for wrapping-key lookup")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    state_path = args.encrypted_state if args.encrypted_state is not None else args.state
    key_protector = None
    require_protected_keys = False
    if args.encrypted_state is not None:
        if args.encrypted_state == Path(__file__).with_name("secure_handoff.sqlite3"):
            print("--encrypted-state must be an isolated non-default path", file=sys.stderr)
            return 2
        key_protector = MacOSKeychainAESGCMKeyProtector(
            service=args.keychain_service,
            account=args.keychain_account,
            keychain=args.keychain,
        )
        require_protected_keys = True
    try:
        server = make_server(ServerConfig(
            state_path=state_path,
            host=args.host,
            port=args.port,
            external_origin=args.external_origin,
            allowed_external_origins=tuple(args.allowed_origins) if args.allowed_origins else DEFAULT_ALLOWED_EXTERNAL_ORIGINS,
            tailscale_user_login=args.tailscale_user_login,
            logger=logging.getLogger("secure_handoff"),
            key_protector=key_protector,
            require_protected_keys=require_protected_keys,
        ))
    except (ValueError, KeyProtectorError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(f"Serving {args.external_origin} through loopback {args.host}:{server.server_address[1]}; no durable sink configured.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
