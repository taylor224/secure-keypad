# Express example + web playground

```
npm install && npm run build          # from the repository root (builds the Node SDK and the web client)
cd examples/server-node
npm run demo                          # http://localhost:3789
```

`npm run demo` starts the server with switches that exist only for the playground:

| Variable | Effect |
|---|---|
| `SKP_ALLOW_CLIENT_LAYOUT=1` | honours the `X-Keypad-Layout` header so the pages can switch `shuffle / full / fixed` |
| `SKP_DEMO_ECHO=1` | `/login` returns the decrypted values so the result panel can show them. **Never** in production |
| `SKP_CORS_ORIGIN=https://<user>.github.io` | lets the statically hosted playground (GitHub Pages) call this server |

`npm start` runs without them. Configure the key with `SKP_MASTER_KEY_PATH` or `SKP_MASTER_KEY`; without
either a throw-away key is generated for the process.

## Pages (`examples/web-vanilla`)

| Page | What it shows |
|---|---|
| `/` | A normal web login page; mouse on desktop, touch on phones. Style and layout selectable. |
| `/ios.html` | iPhone frame (390 × 844 pt) running the app screen with the iOS-style keypad, popups, dynamic island, home indicator. |
| `/android.html` | Pixel frame (412 × 915 dp) with the Material-style keypad, camera hole, gesture bar. |
| `/app.html?device=ios\|android` | The app screen itself; open it directly on a real phone. |

Routes: `GET /keypad/public-key`, `POST /keypad/session`, `POST /keypad/relayout`, `POST /login`.

## E2E

```
npm run e2e        # Playwright: iPhone WebKit, Pixel Chromium, desktop Chromium
```

## Hosting the playground on GitHub Pages

GitHub Pages only serves static files. The published site (`.github/workflows/pages.yml`) therefore ships
the **WebAssembly build of the server SDK** (`bindings/wasm`) and, when no backend is configured, runs the
"server" inside the page: sessions, rendering and decryption all happen in the browser through the same C
core. That makes the UI and protocol fully explorable with zero infrastructure — but it is a demo of the
mechanics, not of the security model, and the page shows a banner saying so. Force it locally with
`?mode=wasm` (after `bindings/wasm/build.sh`).

For the real thing point the pages at a backend (any host that runs Node with a C toolchain, or this image):

```
docker build -f examples/server-node/Dockerfile -t secure-keypad-example .
docker run -p 3789:3789 -e SKP_MASTER_KEY=$(core/build/skp-keygen) -e SKP_DEMO_ECHO=1 \
  -e SKP_ALLOW_CLIENT_LAYOUT=1 -e SKP_CORS_ORIGIN=https://<user>.github.io secure-keypad-example
```

Then either set the repository variable `SKP_API_BASE` to the backend URL (the workflow bakes it into
`config.js`) or open the site with `?api=https://your-backend` once (remembered in localStorage).
