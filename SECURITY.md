# Security policy

## Reporting a vulnerability

Please do not open public issues for security problems. Email the maintainers (see the repository
profile) with a description, a proof of concept if you have one, and the affected component and version.
You will get an acknowledgement within 72 hours and a fix or mitigation plan within 14 days for issues
that affect confidentiality of typed values, session keys or the master key.

## Scope

- `core/` (libskp), the server bindings (`bindings/*`), the clients (`clients/*`), and the protocol in
  `spec/`.
- Out of scope: the example servers (`examples/*`) other than as demonstrations of misuse of the SDKs, and
  attacks that require a fully compromised device (see `spec/THREAT-MODEL.md`).

## What we consider a vulnerability

- Any way for a client, a network observer, or a store/log reader to learn a typed character without the
  master key.
- Any character identifier reaching the client (codes, per-character ids, per-character image sizes).
- Key, seed, layout or plaintext bytes surviving in server memory after a call returns (the residue test
  in `core/tests/test_residue.c` is the regression gate).
- Signature or authentication bypasses, nonce reuse, replay of a consumed session.

## Hardening checklist for integrators

- Generate the master key with `skp-keygen`, store it with mode 0600 or in a secrets manager, and rotate
  it on a schedule (sessions in flight during a rotation fail closed).
- Serve the client's `serverPublicKey` from configuration, not from the same endpoint an attacker could
  spoof, and enable `strict` mode.
- Bind sessions to the login attempt with `ctx`, rate-limit the session endpoint, and keep sessions
  single-use (the default).
- Never log or echo decrypted values; wipe `Secret` objects as soon as the credential check is done.
