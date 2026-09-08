# @secure-keypad/server-wasm

The C core compiled to WebAssembly with Emscripten. Same code as the native server bindings, two uses:

1. **Zero-backend playground.** The GitHub Pages site loads this module and runs the "server" inside the
   page when no real backend is configured. That is a demonstration of the UI and the protocol, not of the
   security model: a server that lives in the same browser as the keypad has no secrecy against that
   browser. The pages say so in a banner.
2. **Fallback for Node hosts without a prebuilt native addon.** The API mirrors `@secure-keypad/server`
   (`createSession`, `relayout`, `decrypt`, in-memory store). Memory locking and page protection are not
   available in wasm, so prefer the native addon where it builds.

## Build

```
brew install emscripten           # or the emsdk
bindings/wasm/build.sh            # → dist/skp.js + dist/skp.wasm (libsodium is compiled for wasm once and cached)
```

## Use

```html
<script src="dist/skp.js"></script>
<script src="src/skp-wasm-server.js"></script>
<script>
  const server = await SkpWasmServer.create({ moduleUrl: "dist/skp.js" });   // random master key
  const fetchImpl = server.makeFetch({ echo: false });                         // serves /keypad/* and /login
  const kp = SecureKeypad.createSecureKeypad({ sessionUrl: "/keypad/session", fetch: fetchImpl, serverPublicKey: server.publicKey, type: "number" });
</script>
```
