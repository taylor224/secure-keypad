# secure-keypad-server (Python)

Server SDK for [secure-keypad](../../README.md): creates per-session shuffled keypads, re-renders them for
new viewports, and decrypts the client's tap batch into the typed value. The C core (`libskp`) and
libsodium are linked **statically** into the extension module; there is no runtime dependency beyond
`cffi`.

## Build and install

Requirements: Python ≥ 3.9, a C compiler, CMake ≥ 3.20 (on `PATH` or `CMAKE=/path/to/cmake`),
`pkg-config`, libsodium (headers + `libsodium.a`), zlib.

```sh
cd bindings/python
pip install -e .                    # runs CMake on ../../core, then builds secure_keypad_server._skp
pip install -e '.[test]' && pytest  # tests use tools/reference as the client
```

Release wheels are produced from the monorepo with cibuildwheel (see `.github/workflows`); the sdist
alone does not contain the C core.

## API

```python
from secure_keypad_server import SecureKeypadServer, SkpError, SessionNotFound, keygen

skp = SecureKeypadServer(master_key_path="/etc/skp/master.key")   # or master_key="<hex|base64|32 raw bytes>"
                                                                   # or SKP_MASTER_KEY in the environment
skp.public_key      # base64 Ed25519 verification key for the clients
skp.key_id          # 8-hex-char key id

response = skp.create_session(client_request, ctx=attempt_id,
                              layout="shuffle",   # "shuffle" | "full" | "fixed"
                              blank="fixed",      # number pad: "fixed" | "random"
                              ttl=180, max_len=None,
                              languages=None)     # ["ko", "en"], ["en"], "en,ko"; None → client's request, else en + ko
response2 = skp.relayout(client_relayout_request)

with skp.decrypt(client_payload, ctx=attempt_id) as secret:   # session consumed here
    verify(secret.bytes)                                        # bytearray; zeroed when the block ends
```

- `create_session` stores the sealed session blob in the configured `SessionStore` (default:
  thread-safe `MemoryStore`, single process). Implement `put/get/take/delete` for Redis etc.; blobs
  are ciphertext, so the store never sees layouts or keys.
- `decrypt` removes the blob from the store before decrypting (`take`); pass `keep=True` to leave it
  in place, e.g. for a second attempt within the TTL. A failed attempt consumes the session too.
- Errors raise `SkpError` with `.code` and `.name` (`EXPIRED`, `BAD_MAC`, `TAMPERED`, `CTX_MISMATCH`,
  `SID_MISMATCH`, `BAD_REQUEST`, `UNSUPPORTED`, `BAD_KEY`, `IO`, `CRYPTO`, ...). A missing blob raises
  `SessionNotFound` (`.name == "SESSION_NOT_FOUND"`).
- `keygen()` returns a fresh base64 master key.
- Korean: the QWERTY keypad carries a 2-set jamo layout when `ko` is among the languages; `decrypt` returns
  composed syllables (`spec/HANGUL.md`). `SecureKeypadServer(font_fallback_path=...)` replaces the embedded
  Noto Sans KR subset used for the jamo labels.

## Wiping

- The core keeps every secret in locked memory and zeroes it before returning; the binding copies the
  value into a `bytearray` and frees the core copy immediately.
- `Secret.wipe()` zeroes that `bytearray` in place (`ctypes.memset`); the context manager does it on exit,
  `__del__` as a last resort.
- `Secret.text` returns a `str`: Python strings are immutable and cannot be wiped, so prefer `.bytes` and
  `hmac.compare_digest`.
- The response JSON, the sealed blobs and the payload are ciphertext or public data and are handled as
  ordinary `bytes`/`dict`.
