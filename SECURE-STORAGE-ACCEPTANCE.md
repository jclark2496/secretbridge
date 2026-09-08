# Secure storage integration — acceptance and boundaries

## Approved direction

Extend the verified dummy Telegram/Tailscale handoff into secure storage. Work locally first. Do not enable real-key submission until the full deployed path is reviewed and independently exercised. Do not overwrite, delete, rotate, or automatically activate existing credentials.

## Current architecture decision — Mac hosted

Jason approved hosting both the credential-entry form and storage handler on the Mac that runs main Hermes. Access is private through Tailscale. Durable storage is operator-supplied through an explicit adapter; the public candidate has no built-in durable provider integration. The VPS relay prototype is retained but is not the deployment target; do not extend or activate it for this feature. Existing VPS websites and secondary Hermes are out of scope.

Preserve the existing Mac Tailscale Serve dashboard at https://handoff-mac.example-tailnet.ts.net/ → localhost:9119. Isolate the handoff endpoint without replacing that route. Review exact origin/identity gating, request-bound write recovery, local key protection and service lifecycle before real-key deployment.

## Historical relay architecture (superseded; prototype reference only)

- Browser encrypts payload with standard WebCrypto primitives; Mac decrypts with the reviewed cryptography library.
- VPS holds request metadata and ciphertext, never the Mac private key or a provider token.
- Mac collector binds the request to an approved destination label, optional destination id, recipient, and expiry. Browser-supplied destinations cannot override that binding.
- Production handoff intake destination is bound locally by operator-supplied `destination_label` and optional `destination_id`; any durable provider mapping belongs to the operator adapter outside the public core.
- Operator-supplied durable adapters must avoid putting secret values in argv, logs, receipts, or other process-observable metadata.
- Model/conversation sees metadata and a verified storage receipt only. Do not globally sync or activate a credential as a side effect of storing it.

## Threat-model limitation

Encrypting in JavaScript served by VPS2 protects stored/relayed ciphertext, not against malicious replacement of that JavaScript by a compromised VPS. Do not market this as protection from a malicious VPS. Stronger protection requires a separately trusted client/code-delivery path. Tailscale restricts reachability; it does not remove this trust boundary.

## Required evidence before real credentials

1. Actual browser encryption and submission; no hand-crafted Origin header as a substitute.
2. Fixed destination authorization on both issuance and Mac consumption.
3. Strict identity, origin, Host, CSRF, body/envelope limits, expiry, and replay rejection.
4. Same-origin Referrer-Policy: no-referrer caused real form POST Origin:null in the dummy pilot.
5. Ciphertext-only relay persistence and secret-free logs, exceptions, stdout, CLI argv, and receipts.
6. Create-only durable sink operation with exact destination/value readback in-process; never print value.
7. Ambiguous remote write, crash, and retry handled without overwriting existing keys or blind duplicate creation.
8. Stable receipt state distinguishes submitted, pending, stored, expired, and failed. Submission alone is not storage success.
9. Initial live write uses a uniquely named non-sensitive synthetic canary, retained unless user authorizes deletion.
10. Decryption key storage, rotation, backup, collector execution, restart/expiry cleanup and endpoint isolation reviewed separately before deployment.

## Existing pilot

Dummy-only VPS service timed out as designed; readback showed Serve empty and ShieldsUp true. systemd reports Result=timeout because RuntimeMaxSec deliberately bounded the service. This is not a production secure-store service.
