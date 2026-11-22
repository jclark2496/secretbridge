# SecretBridge

Give your agent a credential through a one-use browser form and keep its value
out of the chat. SecretBridge lets the operator choose where the value goes
and gives the person who submitted it a receipt.

[Run the local browser demo](#quickstart) · [Review the security limitations](#security-limitations)

<img src="https://forkthis.ai/assets/shots/secretbridge.jpg" width="700" alt="SecretBridge's empty credential form with a destination selected">

The demo uses a generated sample value and an in-memory destination.

<a id="what-is-included"></a>

## What it can do

- **Issue a request.** The local operator picks a destination and an expiry,
  then shares a one-use handoff URL. The form shows the destination before the
  visitor enters anything.
- **Collect the value as typed.** The browser warns about leading or trailing
  whitespace and preserves it when the visitor confirms. WebCrypto encrypts
  the submission before it goes to the loopback collector.
- **Check the result.** The submitter sees a receipt without the value. The
  operator can use the `status` command to see whether the request is pending,
  expired, or stored, along with its destination and receipt ID when available.
- **Choose storage.** The Mac entrypoint protects request keys with macOS
  Keychain. To store real credentials, supply your own durable storage adapter.
  The included browser demo exercises the whole submission with an in-memory
  adapter and a generated sample value.

<a id="quickstart-clean-standalone-install"></a>

## Quickstart

Use Git and Python 3.12 or newer. The demo runs locally with Chromium and
needs no Hermes installation, provider account, or Keychain entry.

```bash
git clone https://github.com/jclark2496/secretbridge.git
cd secretbridge
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m playwright install chromium
python -m secure_storage.run_browser_canary \
  --protected-test-memory \
  --evidence-dir /tmp/hermes-handoff-demo
```

Chromium opens the form headlessly and submits a generated sample. Look for
`"ok": true` and `"mode": "ephemeral-demo"` in the terminal. Open the JSON
file named by `receipt_path` to see the destination and the explicit
`"storage_durable": false` flag in the local receipt. Add `--headful` to the
canary command to watch the browser. The demo uses temporary SQLite state and
an in-memory wrapping key.

## Why I built this

After seeing credential-entry experiences in Grok Bot and Instinct, I wanted a
similar interaction in my own Hermes workflow. When an agent needs a key, I
want a dedicated place to enter it.

SecretBridge explores that interaction as a provider-neutral reference
implementation. Entering a value and confirming storage are separate from
activating the credential later. The inspiration was the interaction itself.
The underlying architecture and security guarantees of those products are
their own.

## Public release status

The public package ships with the ephemeral demo sink. A real provider
integration is operator-supplied through `--sink module:Class`. The existing
module names and deployment identifiers are retained for compatibility with
Hermes Handoff installations.

SecretBridge is independent of Nous Research and the Hermes Agent project. It
has no official endorsement, maintenance, or support from Nous Research. The
[MIT license](LICENSE) covers the project's original code. Tailscale, Hermes
Agent, operator-supplied adapters, and other dependencies have their own terms.

## Security model, briefly

![Provider-neutral architecture](docs/images/hermes-handoff-neutral-architecture.png)

### Actual demo screenshots

These captures use the project's original name, Hermes Handoff.

![The demo form shows its fixed destination](docs/images/hermes-handoff-neutral-form.png)

The browser highlights potentially accidental whitespace before it encrypts the
value. In the synthetic demo, the confirmation screen identifies the storage
as ephemeral.

![Whitespace warning preserves the submitted value](docs/images/hermes-handoff-neutral-whitespace-warning.png)

![Ephemeral demo receipt — not durable storage](docs/images/hermes-handoff-neutral-ephemeral-receipt.png)

Browser JavaScript encrypts the value with a fresh AES-GCM key, wraps that key
to the request's RSA public key, and posts the envelope. The local collector
unwraps it and passes the plaintext to the configured storage adapter.

## One design decision

**The operator fixes the destination before sharing the link.** At submission
time, the collector loads the destination from the local request record. It
checks that the adapter's receipt identifies the same request and destination
and agrees with the adapter's durability setting before marking the request
used. A successful demo can therefore show its receipt without claiming a
write to a real vault. The tests include both a browser-supplied destination
and a mismatched receipt. [Request store](secure_storage/store.py) ·
[Handoff tests](secure_storage/tests/test_secure_handoff.py)

## Security limitations

- Prototype/publication candidate, not audited production software.
- The served JavaScript must be trusted. A compromised page delivery path can exfiltrate the value before encryption; ciphertext relay is not a malicious-server secrecy proof.
- Same-user local processes are inside the trust boundary. A local process that steals a bearer URL/cookies or can spoof the local proxy path can interfere.
- Tailscale Serve/private HTTPS examples trust the local identity proxy to supply correct `Tailscale-User-Login` headers.
- Do not enter real credentials until you have reviewed and adapted the threat model, destination project isolation, service lifecycle, logging, dependency licenses, and recovery behavior for your environment.

## CI

Run the offline unit and integration tests from the activated environment.

```bash
PYTHONDONTWRITEBYTECODE=1 python -m unittest discover -v
```

The GitHub Actions workflow installs the requirements and Chromium, runs the
tests, and runs the synthetic browser demo. All of these use fake or ephemeral
storage. [CI workflow](.github/workflows/offline-tests.yml)

## Durable sink configuration

To connect a storage provider in your fork, pass an importable adapter class as
`--sink module:Class` to `secure_storage.production serve`. It needs a
zero-argument constructor that requires no secrets from environment variables,
`durable = True`, and a `store` method accepting the keyword arguments
`destination`, `value`, and `request_id`. Use the request ID as an idempotency
key. Return a structured receipt after the provider has acknowledged durable
storage of the exact value. [Adapter contract](secure_storage/sinks.py)

Browser clients cannot choose the destination. Request creation binds `--destination-label` locally, with optional `--destination-id` if the operator adapter needs a stable opaque destination identifier.

Example protected request creation:

```bash
python -m secure_storage.production create \
  --state ~/.hermes/hermes-handoff/secure-handoff.sqlite3 \
  --origin https://handoff-mac.example-tailnet.ts.net:9443 \
  --allowed-origin https://handoff-mac.example-tailnet.ts.net:9443 \
  --destination-label REVIEWED_DESTINATION_NAME \
  --ttl-seconds 300
```

Example protected collector startup with an operator-supplied durable adapter:

```bash
python -m secure_storage.production serve \
  --state ~/.hermes/hermes-handoff/secure-handoff.sqlite3 \
  --host 127.0.0.1 \
  --port 9127 \
  --external-origin https://handoff-mac.example-tailnet.ts.net:9443 \
  --allowed-origin https://handoff-mac.example-tailnet.ts.net:9443 \
  --tailscale-user-login operator@example.com \
  --sink your_package.your_sink:YourDurableSink \
  --log ~/.hermes/hermes-handoff/secure-handoff.log
```

For local demonstrations only, `secure_storage.production serve --allow-ephemeral-demo-sink` uses non-durable in-memory storage and must not be treated as real secret storage.

## Sample placeholder values

Checked-in docs/tests use coherent placeholders only:

- Origin: `https://handoff-mac.example-tailnet.ts.net:9443`
- Operator identity: `operator@example.com`
- Example destination ID: `11111111-1111-4111-8111-111111111111`

Replace placeholders with private values outside git when deploying.

The Mac-hosted runbook has template settings for private HTTPS and the
protected collector, plus examples of issuing requests and reading their
receipts. [Mac-hosted runbook](deploy/mac-hosted/RUNBOOK.md)

[Read the SecretBridge build note on Forkthis](https://forkthis.ai/secretbridge/).
