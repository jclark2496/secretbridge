# Mac-hosted protected credential handoff runbook

Status: reviewed package artifact only. Do not apply Tailscale Serve, launchd, Keychain, or durable provider live actions until Main reviews and runs the commands.

## Fixed deployment shape

- Python collector binds only to `127.0.0.1:9127`.
- Protected state path: `~/.hermes/hermes-handoff/secure-handoff.sqlite3`.
- Existing Hermes dashboard route must remain untouched: `https://handoff-mac.example-tailnet.ts.net/ -> localhost:9119`.
- Proposed private handoff origin is a separate HTTPS port: `https://handoff-mac.example-tailnet.ts.net:9443`.
- Browser-created values are decrypted on the Mac and stored through an operator-supplied durable sink only after exact local registry approval.
- Production handoff destinations are bound locally by `--destination-label` and, if needed by the operator adapter, optional `--destination-id`.
- The public package has no built-in durable provider integration; configure durable storage with an operator-supplied `--sink module:Class` adapter.
- No plaintext private-key fallback exists in `secure_storage.production`.

## Preflight commands for Main to review/run

```zsh
cd "/Users/example/Projects/Hermes Handoff"
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -v
```

Fake browser integration, no Keychain/provider/network write:

```zsh
cd "/Users/example/Projects/Hermes Handoff"
. .venv-secure/bin/activate
python -m secure_storage.run_browser_canary \
  --protected-test-memory \
  --evidence-dir /tmp/hermes-hermes-handoff-fake-evidence
```

## Live Keychain canary, explicit mutation

Creates one throwaway Keychain item, reads it through the no-UI native path, verifies duplicate create rejection, and prints no key material. It leaves the throwaway item for Main to remove after evidence review.

```zsh
cd "/Users/example/Projects/Hermes Handoff"
. .venv-secure/bin/activate
python -m secure_storage.keychain_live_canary --live
```

Cleanup command is printed by the canary with exact service/account metadata. Do not add a secret value to argv.

## Durable provider canary boundary

The public candidate does not ship a live provider canary. `secure_storage.run_browser_canary` is provider-free and always uses the ephemeral demo sink. Operators may build a separate private canary around their own durable `--sink module:Class` adapter after review; do not document provider tokens or SDK-specific flags in this public runbook.

## Production request/server commands, after live canaries pass

### Normal operator helper (preferred for local requests)

Issue one short-lived URL with production protected key storage and a locally bound destination label. The JSON output intentionally includes the one-use URL; do not paste it into logs except the target chat. It does not output auth separately, private keys, encrypted envelope JSON, provider tokens, or submitted values.

```zsh
cd "/Users/example/Projects/Hermes Handoff"
. .venv-secure/bin/activate
python -m secure_storage.operator_helper issue \
  --state ~/.hermes/hermes-handoff/secure-handoff.sqlite3 \
  --origin https://handoff-mac.example-tailnet.ts.net:9443 \
  --allowed-origin https://handoff-mac.example-tailnet.ts.net:9443 \
  --destination-label 'REVIEWED_DESTINATION_NAME' \
  --ttl-seconds 300
```

Check pending/stored/expired receipt metadata only. This reads the protected production state and returns no plaintext value, auth token, private key, or envelope JSON:

```zsh
cd "/Users/example/Projects/Hermes Handoff"
. .venv-secure/bin/activate
python -m secure_storage.operator_helper status \
  --state ~/.hermes/hermes-handoff/secure-handoff.sqlite3 \
  --url 'PASTE_ISSUED_HANDOFF_URL'

# or, if only the request id is available:
python -m secure_storage.operator_helper status \
  --state ~/.hermes/hermes-handoff/secure-handoff.sqlite3 \
  --request-id 'REQUEST_ID'
```

Existing helper compatibility: `secure_storage.production create` remains supported and uses the same production primitives. Prefer `operator_helper issue/status` for normal Hermes operator work because it gives the paired receipt-status command and fixed sanitized output shape.

Create one protected request URL with the lower-level production entrypoint:

```zsh
cd "/Users/example/Projects/Hermes Handoff"
. .venv-secure/bin/activate
python -m secure_storage.production create \
  --state ~/.hermes/hermes-handoff/secure-handoff.sqlite3 \
  --origin https://handoff-mac.example-tailnet.ts.net:9443 \
  --allowed-origin https://handoff-mac.example-tailnet.ts.net:9443 \
  --destination-label 'REVIEWED_DESTINATION_NAME' \
  --ttl-seconds 300
```

Run the loopback collector with real Keychain protector, exact SQLite registry, and an operator-supplied durable sink adapter. The adapter must be importable as `module:Class`, expose `durable = True`, and keep its own private credential handling outside this public template:

```zsh
cd "/Users/example/Projects/Hermes Handoff"
. .venv-secure/bin/activate
python -m secure_storage.production serve \
  --state ~/.hermes/hermes-handoff/secure-handoff.sqlite3 \
  --host 127.0.0.1 \
  --port 9127 \
  --external-origin https://handoff-mac.example-tailnet.ts.net:9443 \
  --allowed-origin https://handoff-mac.example-tailnet.ts.net:9443 \
  --tailscale-user-login 'REPLACE_WITH_EXACT_TAILSCALE_USER_LOGIN' \
  --sink your_package.your_sink:YourDurableSink \
  --log ~/.hermes/hermes-handoff/secure-handoff.log
```

## LaunchAgent template

Template: `deploy/mac-hosted/com.hermes.hermes-handoff.plist.template`

Review and replace the Tailscale user-login and `--sink module:Class` placeholders before loading. The template is intentionally not `RunAtLoad`, not `KeepAlive`, scoped to loopback port `9127`, and does not embed provider tokens. Keep provider credentials in the operator-owned adapter or its private configuration; do not put plaintext tokens in the plist or depend on `launchctl setenv` from an interactive shell.

## Tailscale Serve proposal, do not apply here

Keep dashboard root as-is. Add a separate HTTPS port mapping only after review, for example conceptually:

```zsh
# DO NOT RUN WITHOUT MAIN APPROVAL
# Existing root / dashboard on 443 must remain localhost:9119.
tailscale serve --https=9443 127.0.0.1:9127
```

Acceptance after applying elsewhere: `https://handoff-mac.example-tailnet.ts.net/` still serves dashboard from `localhost:9119`, and `https://handoff-mac.example-tailnet.ts.net:9443/handoff/...` reaches only the credential handoff collector with Tailscale identity headers preserved.


## Observed phone test facts and pending operational boundary

- The browser form warns when a submitted value starts or ends with whitespace. Submission is blocked until the operator acknowledges that whitespace is intentional; changing the value clears the acknowledgement. The value itself is preserved exactly and never silently trimmed.
- Operationally pending remains: child/subagent work must not edit the live LaunchAgent plist, Tailscale Serve mapping, Keychain items, provider tokens, or production SQLite state. Parent/Main owns activation, restarts, Tailscale changes, deletion/cleanup of live canaries, and any public/git publishing.
