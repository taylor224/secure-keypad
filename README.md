# secure-keypad

Open-source secure keypad: the server renders per-session shuffled keypads, the client shows a native-looking
keyboard and sends back only encrypted tap coordinates, and the server SDK turns them into the typed value.
The client never knows what was typed; nothing secret survives the session.

Design plan: [docs/PLAN.md](docs/PLAN.md) (Korean). Specification: [spec/PROTOCOL.md](spec/PROTOCOL.md),
[spec/LAYOUT.md](spec/LAYOUT.md), [spec/THREAT-MODEL.md](spec/THREAT-MODEL.md).

| Component | Path | Status |
|---|---|---|
| C core (`libskp`) | `core/` | done: crypto, sealed sessions, layouts, glyph sprites, `skp-keygen`; vector/API/render/memory-residue tests |
| Node server SDK | `bindings/node` | done: N-API addon, `SecureKeypadServer`, stores, vitest round trips |
| Python server SDK | `bindings/python` | done: cffi extension, `SecureKeypadServer`, pytest |
| Java server SDK | `bindings/java` | done: JNI, `SecureKeypadServer`, JUnit |
| Web client | `clients/web` | done: canvas keypad (iOS / Material styles), `@noble` crypto, vector tests |
| React bindings | `clients/react` | done: provider, hook, `SecureKeypadInput` |
| iOS client | `clients/ios` | done: Swift Package (CryptoKit, `UIInputView`), simulator tests |
| Android client | `clients/android` | done: AAR (BouncyCastle), demo app, JVM vector tests |
| Reference implementation and vectors | `tools/reference`, `spec/vectors` | done: 7 vectors replayed by every implementation |
| Examples | `examples/` | Express (+ web demo + Playwright E2E), FastAPI, JDK HttpServer |

## Quick start

```
# server key
core/build/skp-keygen > master.key && core/build/skp-keygen --pubkey master.key

# C core
cmake -S core -B core/build -G Ninja && cmake --build core/build && (cd core/build && ctest)

# JS workspaces: Node SDK + web/react clients + example server with E2E
npm install && npm run build && npm test && npm run e2e

# reference implementation + vectors
python -m pytest -q tools/reference/test_ref.py && python tools/reference/gen_vectors.py
```

Each package directory has its own README with build, test and integration instructions.

License: Apache-2.0. Bundled fonts: Inter (SIL OFL 1.1), Roboto (Apache-2.0). Bundled code: libsodium (ISC),
stb (MIT / public domain), cJSON (MIT).
