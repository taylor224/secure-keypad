# secure-keypad

Open-source secure keypad: the server renders per-session shuffled keypads, the client shows a native-looking
keyboard and sends back only encrypted tap coordinates, and the server SDK turns them into the typed value.
The client never knows what was typed; nothing secret survives the session.

Keyboards: number pad and QWERTY with **English + Korean (2-set / 두벌식)** by default, switched with a
globe key; Hangul syllables are composed on the server ([spec/HANGUL.md](spec/HANGUL.md)). The language set
is chosen by the server (`languages: ["ko", "en"]`), else requested by the client, else `en, ko`.

Playground: <https://taylor224.github.io/secure-keypad/> — a demo bank ("차돌이뱅크 / Chadole Bank", not a real
bank) that asks for a withdrawal password on the number pad and a certificate password on the full keyboard,
as web banking, as an app inside iPhone and Pixel frames, and as native SDK examples. With
no backend configured the page runs the server SDK's WebAssembly build in-browser (a demo of the mechanics, not of
the security model); point it at a real example server with `?api=…` (see [examples/server-node](examples/server-node/README.md)). Design plan: [docs/PLAN.md](docs/PLAN.md) (Korean). Specification: [spec/PROTOCOL.md](spec/PROTOCOL.md),
[spec/LAYOUT.md](spec/LAYOUT.md), [spec/HANGUL.md](spec/HANGUL.md), [spec/THREAT-MODEL.md](spec/THREAT-MODEL.md).

| Component | Path | Status |
|---|---|---|
| C core (`libskp`) | `core/` | done: crypto, sealed sessions, layouts (en/ko), Hangul composition, glyph sprites, `skp-keygen`; vector/API/render/Hangul/memory-residue tests |
| Node server SDK | `bindings/node` | done: N-API addon, `SecureKeypadServer`, stores, vitest round trips |
| Python server SDK | `bindings/python` | done: cffi extension, `SecureKeypadServer`, pytest |
| Java server SDK | `bindings/java` | done: JNI, `SecureKeypadServer`, JUnit |
| Web client | `clients/web` | done: canvas keypad (iOS / Material styles), `@noble` crypto, vector tests |
| React bindings | `clients/react` | done: provider, hook, `SecureKeypadInput` |
| iOS client | `clients/ios` | done: Swift Package (CryptoKit, `UIInputView`), simulator tests |
| Android client | `clients/android` | done: AAR (BouncyCastle), demo app, JVM vector tests |
| Reference implementation and vectors | `tools/reference`, `spec/vectors` | done: 11 vectors (+ Hangul composition cases) replayed by every implementation |
| WebAssembly server | `bindings/wasm` | done: Emscripten build of the core for the zero-backend playground / addon-less hosts |
| Examples | `examples/` | Express (+ web playground + Playwright E2E), FastAPI, JDK HttpServer |

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

License: Apache-2.0. Bundled fonts: Inter (SIL OFL 1.1), Roboto (Apache-2.0), Noto Sans KR Hangul-jamo subset
(SIL OFL 1.1). Bundled code: libsodium (ISC), stb (MIT / public domain), cJSON (MIT).
