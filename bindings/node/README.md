# @secure-keypad/server

Node.js server SDK for secure-keypad (native binding of `libskp`). Creates shuffled keypad sessions, seals
their state, and turns encrypted tap coordinates back into the typed value.

```ts
import { SecureKeypadServer } from "@secure-keypad/server";

const skp = new SecureKeypadServer({ masterKeyPath: "/etc/skp/master.key" }); // or masterKey / SKP_MASTER_KEY

app.post("/keypad/session", async (req, res) => res.json(await skp.createSession(req.body, { ctx: req.session.id })));
app.post("/keypad/relayout", async (req, res) => res.json(await skp.relayout(req.body)));
app.post("/login", async (req, res) => {
  const secret = await skp.decrypt(req.body.password_enc, { ctx: req.session.id });
  try {
    await verifyPassword(req.body.userId, secret.bytes); // Buffer, UTF-8
  } finally {
    secret.wipe();
  }
});
```

## Install / build

The package compiles the C core during `npm install` (node-gyp; needs a C/C++ toolchain, Python 3, and
libsodium via `pkg-config`, e.g. `brew install libsodium` or `apt install libsodium-dev`). Prebuilt
binaries (`prebuildify`) are planned for releases so most installs skip the compiler.

```
npm run build:native        # rebuild the addon
npm run build               # TypeScript → dist
npm test                    # vitest (needs the addon built)
```

## API

- `new SecureKeypadServer({ masterKeyPath | masterKey, store?, defaultTtl?, maxLenCap? })`
  Master key: 64 hex chars, base64, or 32 raw bytes. `SKP_MASTER_KEY` / `SKP_MASTER_KEY_PATH` are read when
  neither option is given. Generate one with `keygen()` or `skp-keygen`.
- `publicKey`, `keyId` — for client configuration.
- `createSession(request, { ctx?, layout?, blank?, ttl?, maxLen? })` → response JSON for the client. The
  sealed state goes into the store keyed by `sid`.
- `relayout(request)` → response JSON; the stored state is replaced.
- `decrypt(payload, { ctx?, keep? })` → `Secret` (`bytes: Buffer`, `toString()`, `wipe()`). The session is
  removed from the store unless `keep` is set, so a payload can be used once.
- `sessionInfo(sealed)` → `{ expires, sid }` for custom stores.
- `SessionStore` interface (`put/get/take/delete`) and `MemoryStore`. Multi-instance deployments plug in
  Redis or similar; the stored blobs are ciphertext.
- Errors are `SkpError` with `kind`: `EXPIRED`, `BAD_MAC`, `TAMPERED`, `CTX_MISMATCH`, `SID_MISMATCH`,
  `SESSION_NOT_FOUND`, `BAD_REQUEST`, `UNSUPPORTED`, `BAD_KEY`, `IO`, `CRYPTO`, …

## Wiping

The native library keeps every secret in locked memory and zeroes it before returning. The decrypted value
is copied once into a `Buffer`; call `wipe()` as soon as you are done and avoid converting it to a string
unless the consumer needs one (strings cannot be zeroed). Never log the value.
