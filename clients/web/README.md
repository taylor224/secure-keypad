# @secure-keypad/web

Native-looking secure keypad for the web. The server renders a shuffled keypad per session and sends only
glyph images; the browser draws the keyboard chrome, records tap **coordinates**, and returns them encrypted.
Nothing in the page ever holds the typed characters.

```html
<input id="pin" type="password">
<script src="https://…/secure-keypad.iife.js"></script>
<script>
  const kp = SecureKeypad.createSecureKeypad({
    sessionUrl: "/keypad/session",
    relayoutUrl: "/keypad/relayout",
    serverPublicKey: "BASE64_ED25519_FROM_skp-keygen",
    type: "number", maxLen: 6,
  });
  kp.attach(document.getElementById("pin"));
  // later, e.g. on your form submit:
  const payload = kp.submit();     // opaque JSON string → send to your server → SDK decrypt()
</script>
```

ESM / bundlers:

```ts
import { createSecureKeypad } from "@secure-keypad/web";
```

## Configuration

| Option | Default | Notes |
|---|---|---|
| `sessionUrl` | required | POST endpoint forwarding to the server SDK's `createSession` |
| `relayoutUrl` | — | POST endpoint forwarding to `relayout`; without it the session is recreated on resize when nothing was typed |
| `serverPublicKey` | — | Ed25519 public key (base64). Strongly recommended; `strict: true` makes it mandatory |
| `type` | required | `"qwerty"` or `"number"` |
| `maxLen` | 32 / 16 | maximum characters (the server caps it) |
| `languages` | server default (`["en", "ko"]`) | QWERTY keyboard languages in switch order, e.g. `["ko", "en"]` or `["en"]`; the server may override. Two or more show a globe key |
| `languageNames` | English / 한국어 | space-bar labels per language code |
| `style` | `"auto"` | `"ios"` on Apple devices, `"material"` elsewhere |
| `theme` | `"auto"` | follows `prefers-color-scheme`; `themeOverrides` replaces colour tokens |
| `haptics`, `popups` | `true` | vibration on Android touch; key popup bubbles on touch |
| `desktopWidth` | 520 | width of the sheet on desktop pointers, in CSS px; set it to your content column's width so the keypad lines up |
| `accessory` | `"auto"` | Done bar for number pads (`"always"` / `"never"`) |
| `prefetch` | `true` | create the session on `attach` so the keypad opens instantly |
| `hiddenInputName` | — | keeps a hidden input filled with the payload on classic form submits |
| `headers`, `credentials`, `fetch` | — | transport customisation (CSRF tokens, cookies, custom fetch) |

## API

- `attach(input)` / `detach()` — the input becomes read-only with `inputmode="none"`; it only ever shows dots.
- `open()` / `close()` / `isOpen`
- `submit(): string` — encrypts the taps, **consumes the session**, returns the payload. Synchronous.
- `reset()` — drop the session and typed input; a new session is created lazily.
- `length`, `ready`, `language` (current keyboard language code), `setLanguage(code)`
- `on("open" | "close" | "ready" | "change" | "done" | "submit" | "error" | "expire" | "lang", handler)`
- `destroy()`

## Behaviour worth knowing

- The keypad surface is a canvas sized in device pixels exactly as the server rendered it; glyph tiles are
  blitted 1:1, so nothing is stretched on any DPR. Rotation and resizes trigger a relayout.
- Only character taps are recorded; shift, mode switches, the globe (language) key and Done are handled
  locally, backspace pops. Taps are recorded at key centres.
- Korean input: the keypad shows the 2-set jamo layout; the server composes syllables (backspace removes one
  jamo, as on native keyboards). The page never sees jamo either.
- Sessions expire (server TTL, 180 s by default). With nothing typed the session renews silently; with
  input pending an `expire` event fires and the input is cleared.
- After `submit()` a new session is required (`open()` or `reset()`), including after a failed login.
- Requires `<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">` on
  mobile pages.

## Security notes

- The page never receives characters, only rects, roles and images. Read `spec/THREAT-MODEL.md`.
- Configure `serverPublicKey`. Without it a network attacker who also breaks TLS could substitute a keypad
  whose layout they know.
- Do not build UI that reveals the value (no "show password" toggle is possible by design).
