# Secure Storage encrypted handoff prototype

Local-only prototype for encrypted credential handoff. This directory is isolated from the older dummy app and does not include deployment scripts, built-in durable provider writes, live secret reads, or external state changes.

## Scope

- Local request creation only; there is no HTTP request-creation endpoint.
- Python HTTP collector binds only to `127.0.0.1`.
- Optional browser access is intended only through explicitly allowlisted Tailscale Serve HTTPS origins. The Mac-hosted production-readiness default is exactly `https://handoff-mac.example-tailnet.ts.net`; arbitrary hosts, paths, queries, and non-HTTPS origins are rejected.
- Tailscale mode requires one exact `Tailscale-User-Login` header from the loopback identity proxy before GET or POST handling.
- Browser cannot choose destination metadata. The local Mac request registry binds `destination_label` at request creation and may also bind an operator-defined opaque `destination_id`.
- The collector accepts an injected sink only. The public package ships no built-in durable provider integration.

The sink returns a storage ID. The HTTP receipt only claims storage after the sink returns a valid storage ID. The included tests use fake or ephemeral in-memory sinks.

## Crypto shape

- Browser WebCrypto generates a random AES-256-GCM key per submission.
- Browser encrypts the submitted value with AES-GCM.
- Browser wraps the raw AES key with RSA-OAEP SHA-256 using the Mac-generated public key in the local request record.
- AES-GCM additional authenticated data is exactly:

```text
secure-handoff:v1:<request_id>
```

- Python `cryptography` unwraps and decrypts on the Mac side.
- No custom cryptographic primitive is implemented.

Envelope fields:

```json
{
  "version": 1,
  "request_id": "...",
  "wrapped_key": "base64url...",
  "iv": "base64url 12-byte nonce...",
  "ciphertext": "base64url AES-GCM ciphertext+tag..."
}
```

## Registry behavior

SQLite stores request metadata, local private key material for the request, session/CSRF state while open, the encrypted envelope JSON after successful sink confirmation, and the sink storage ID. It does not store submitted plaintext values.

Default/legacy state remains plaintext-compatible for prototype regression tests. Production must opt in to protected state with a new isolated DB path. Protected rows store an AES-GCM-wrapped private PEM (`private_key_ciphertext`) instead of PEM text, authenticated with AAD:

```text
secure-handoff-private-pem:v1:<request_id>
```

Production wrapping-key lookup is via macOS Keychain metadata only; tests inject random in-memory keys.

Requests are one-use and expire. Replay and concurrent duplicate submissions are rejected after one successful sink-confirmed consume.

## HTTP boundary

- Strict configured Host check; forwarded host/proto headers are ignored.
- POST requires exact same configured Origin, or same-origin Referer when Origin is absent.
- `Origin: null` is rejected. The response uses `Referrer-Policy: same-origin` because `no-referrer` produced `Origin: null` in the pilot path.
- Session cookie is `HttpOnly`, `SameSite=Strict`, path `/`, and `Secure` in Tailscale HTTPS mode.
- Responses include no-store cache headers, frame denial, and a restrictive CSP for this single page.
- Logs intentionally avoid request line/path/query/body logging.

## Trust boundary

This prototype protects against the relay/store retaining plaintext when the delivered JavaScript is honest and the Mac-side collector is the only decryptor. It does **not** prove secrecy from a malicious or compromised VPS-delivered page. If the VPS or Serve-delivered JavaScript is compromised, that JavaScript can exfiltrate the value before or instead of encrypting it. Transporting ciphertext through the VPS is therefore not a malicious-server secrecy proof.

## Local use

Create a request locally:

```bash
python3 -m secure_storage.cli create \
  --origin https://handoff-mac.example-tailnet.ts.net \
  --destination-label ExampleDestination \
  --ttl-seconds 300
```

Protected-state request creation requires an explicit non-default path and Keychain-backed wrapping key:

```bash
python3 -m secure_storage.cli create \
  --encrypted-state /path/to/new/protected-secure-handoff.sqlite3 \
  --origin https://handoff-mac.example-tailnet.ts.net \
  --destination-label ExampleDestination \
  --ttl-seconds 300 \
  --keychain-service "Hermes Handoff Wrapping Key" \
  --keychain-account secure-storage-production-v1
```

Run the loopback collector with an injected sink from application code. The CLI server entrypoint deliberately has no real sink configured and will reject submissions at the sink stage until integration code supplies one.

```bash
python3 -m secure_storage.server \
  --encrypted-state /path/to/new/protected-secure-handoff.sqlite3 \
  --external-origin https://handoff-mac.example-tailnet.ts.net \
  --tailscale-user-login operator@example.com \
  --keychain-service "Hermes Handoff Wrapping Key" \
  --keychain-account secure-storage-production-v1
```

Use `--allowed-origin` on both request creation and server startup only for an explicitly reviewed alternate HTTPS origin. Do not deploy this prototype or enter live credentials until the integration and trust model are reviewed.

## Reviewed Mac-hosted protected entrypoint

`secure_storage.production` is the protected-only deployment entrypoint. It defaults state to `~/.hermes/hermes-handoff/secure-handoff.sqlite3`, verifies the real macOS Keychain protector before creating state, and serves only with an explicitly configured durable `--sink module:Class` adapter unless the operator opts into `--allow-ephemeral-demo-sink` for demos. It has no default plaintext/private-PEM fallback.

Reviewed commands and the LaunchAgent/Tailscale proposal live in `../deploy/mac-hosted/RUNBOOK.md`. The deployed handoff route is a separate private HTTPS port `https://handoff-mac.example-tailnet.ts.net:9443`, preserving the existing dashboard root route to `localhost:9119`.

Normal local Hermes operator workflow uses the production-protected helper:

```bash
python -m secure_storage.operator_helper issue \
  --state ~/.hermes/hermes-handoff/secure-handoff.sqlite3 \
  --origin https://handoff-mac.example-tailnet.ts.net:9443 \
  --allowed-origin https://handoff-mac.example-tailnet.ts.net:9443 \
  --destination-label REVIEWED_DESTINATION_NAME \
  --ttl-seconds 300

python -m secure_storage.operator_helper status \
  --state ~/.hermes/hermes-handoff/secure-handoff.sqlite3 \
  --url 'PASTE_ISSUED_HANDOFF_URL'
```

The issue output intentionally includes the short-lived one-use URL. Status output is receipt metadata only: pending/stored/expired state, fixed destination metadata, storage id when present, envelope byte count/digest flags only where applicable; no submitted value, auth token, private key, encrypted envelope JSON, provider token, or Keychain material is printed. The older `secure_storage.production create` command remains compatible and uses the same protected request creation primitive; `operator_helper` adds the paired safe status path for normal operator work.

Whitespace handling: the browser form warns when a submitted value starts or ends with whitespace, requires explicit acknowledgement, clears that acknowledgement when the value changes, and still preserves the value exactly.

Operational pending boundary: local documentation/code/tests may be updated here, but child work must not edit live service/plist/Tailscale/Keychain/provider tokens/production SQLite state, restart the collector, delete canaries, deploy, or publish a repo.

Safe bounded canaries:

```bash
# provider-free browser integration only; ephemeral demo sink, no Keychain/provider/network write
python3 -m secure_storage.run_browser_canary --protected-test-memory

# explicit live Keychain throwaway provision/readback; no secret argv/output
python3 -m secure_storage.keychain_live_canary --live
```

For Mac-hosted production-readiness gaps, including the current unencrypted private-key-at-rest limitation and deployment blockers, see `MAC-HOSTED-PRODUCTION-GAPS.md`.

## Split ciphertext relay prototype

An isolated split prototype lives under `secure_storage/split` and preserves the original working local collector/server modules. In the split path, the browser-facing relay stores only public request metadata, public JWK, hashed browser/session/CSRF capabilities, encrypted envelope JSON, and receipt/failure metadata. It never stores the Mac private key, plaintext value, provider token, or collector transport token.

The Mac-side collector registry owns destination binding, expiry, identity approval, and private key material. Its local SQLite file is chmod `0600`, but private keys are still unencrypted at rest in SQLite; this is documented as not production-ready. The fake transport is authenticated and bounded but in-process only. The fake request-bound sink models create-only exact-readback idempotency and crash-after-sink-before-relay-receipt reconciliation without duplicate create.

See `secure_storage/split/README.md` for protocol details, sink contract, test coverage, and production gaps. The malicious-VPS JavaScript caveat remains: ciphertext relay does not protect against a compromised server replacing browser-delivered JavaScript.

## Tests

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -v
```

The tests start ephemeral loopback servers, use Playwright for real browser WebCrypto submission roundtrips, and use only fake sink callbacks.
