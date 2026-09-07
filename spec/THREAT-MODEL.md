# secure-keypad Threat Model

## Assets

- The characters the user enters.
- The per-session mapping from screen position to character.
- Session keys (`k_s2c`, `k_c2s`) and the server master key.

## What the design protects against

| Adversary | Capability | Mitigation |
|---|---|---|
| Keylogger, malicious IME, accessibility service | reads system keyboard input | the system keyboard is never used; the accessibility tree exposes no key labels |
| Client memory reader or tamperer | dumps or modifies app memory | no plaintext, no character codes, no position→character mapping exist on the client; only coordinates (meaningless without the server's layout) and session keys that become worthless once the session is consumed |
| Network observer, TLS-terminating proxy, WAF, APM body logging | reads request and response bodies | tiles and coordinates are AEAD-encrypted under per-session keys; the input batch has constant length |
| Active attacker on the path, even with TLS broken | swaps in a keypad whose layout it knows | the server signs its ephemeral key, the session id and the ciphertext hash with its long-term Ed25519 key; clients that pin the public key reject substitutions |
| Replay, cross-user reuse | resubmits a captured payload | sessions are single-use, nonces are counters, the integrator's `ctx` is bound into the sealed state |
| Server log, store, or core dump | reads server-side artefacts | stores hold only sealed blobs; plaintext exists only inside `create`/`decrypt` in locked memory and is wiped before return; nothing secret is ever logged |
| Compromise of the master key after the fact | decrypts recorded traffic | session keys come from ephemeral-ephemeral X25519; the master key only signs and seals state, so recorded sessions stay confidential |
| Screenshot or screen recording where the platform allows blocking | captures the keypad | Android `FLAG_SECURE`; iOS capture detection hides the keypad; the keypad is covered before app-switcher snapshots |

## What the design does not protect against

- A device whose OS is fully compromised such that the attacker captures both the frame buffer and touch
  events. Image plus coordinates reconstruct the input. This is inherent to any visual keypad. The design
  raises the cost (per-session shuffled layout, no character identifiers, capture blocking, optional per-key
  reshuffle) but cannot remove it.
- Web deployments are inspectable JavaScript and therefore weaker than native code. The invariant that no
  plaintext ever exists in the browser still holds.
- `layout: "fixed"` makes characters inferable from coordinates by geometry alone. It defends only against
  keyloggers and network observers and is logged as a warning at session creation.
- Denial of service against the session endpoint. Integrators must authenticate and rate-limit it.

## Invariants every implementation must keep

1. No character identifier leaves the server: no codes, no per-character ids, no per-character image sizes.
   Slots are numbered in spatial order and tiles live in one sprite.
2. Coordinates are meaningless without the session seed, which exists only inside the sealed blob.
3. Every payload is AEAD-encrypted independently of TLS, with direction-specific keys and counter nonces.
4. Session keys are fresh per session; the server's ephemeral private key is wiped right after derivation.
5. Plaintext (layouts, keys, decrypted value) lives only for the duration of a call, in locked memory.
6. The core library is stateless; stores hold ciphertext only.
7. Client-side secrets lose all value once the session is consumed; the real guarantee is server-side
   destruction.
8. Control keys are never transmitted; only character taps are.

## Reporting

See `SECURITY.md` for the disclosure process.
