# secure-keypad Android client

Kotlin library that shows a Material-style keypad whose glyphs come from the server as per-session
shuffled sprites, records only tap coordinates, and hands your app one opaque encrypted payload.
The characters the user types never exist on the device. Protocol: `spec/PROTOCOL.md` v1.

- Module `secure-keypad`, coordinates `dev.securekeypad:secure-keypad-android:0.1.0` (placeholder until published)
- minSdk 24, Kotlin 2.2, no AndroidX dependency
- Crypto: BouncyCastle lightweight API (X25519, Ed25519, ChaCha20-Poly1305), JCA HMAC-SHA256 / SHA-256
- Network: `HttpURLConnection` by default; plug in OkHttp or pinning through the `Transport` interface

## Integration

```kotlin
val keypad = SecureKeypad(this, SecureKeypad.Config(
    sessionUrl = "https://api.example.com/keypad/session",
    relayoutUrl = "https://api.example.com/keypad/relayout",
    serverPublicKey = "BASE64 from `skp-keygen --pubkey master.key`",
    type = KeypadType.NUMBER,     // or KeypadType.QWERTY
    maxLen = 6,
    languages = listOf("ko", "en"),   // QWERTY only: Korean first, globe key switches; omit → server default (en, ko)
    theme = ThemeMode.AUTO,       // LIGHT / DARK
    haptics = true, sound = true, showPopup = true,
    headers = mapOf("Authorization" to "Bearer …"),   // optional
))
keypad.attach(pinEditText)        // field becomes masked; tapping it opens the keypad
keypad.onChange = { length -> submitButton.isEnabled = length == 6 }

lifecycleScope.launch {
    val payload = keypad.submit() // '{"v":1,"sid":"…","ct":"…"}' — send it with your login request
    api.login(userId, pinPayload = payload)
}
```

Your backend passes the payload to the server SDK (`decrypt(payload, ctx)`), which returns the typed
value and destroys the session.

What `attach` does to the `EditText`: disables the system keyboard (`showSoftInputOnFocus = false`),
sets a password input type without suggestions, blocks selection, copy and paste, rejects every edit
that does not come from the keypad, and shows `•` per character. Do not read `editText.text`; it only
ever contains bullets.

## Behaviour

- **Session**: prefetched on `attach`, so the keypad appears immediately. Sessions expire (server TTL,
  default 180 s); the library resets and fetches a new one, calling `onError` with code `EXPIRED`.
- **Relayout**: when the panel width changes (rotation, multi-window) the library requests a relayout;
  taps made before keep their generation and stay valid.
- **Keys**: shift is one-shot, double tap for caps lock; `?123` / `=\<` / `ABC` switch layers; the globe
  key cycles the installed languages (`onLanguageChange`, `language`, `setLanguage`) and the space bar shows
  the current one; backspace repeats while held. Only character and space taps are recorded; control keys
  never leave the device. Korean jamo are composed into syllables by the server.
- **Feedback**: darkened key, preview popup above character keys (Gboard style), haptic
  `KEYBOARD_TAP` and the system key-press sound (both follow the user's system settings and can be
  disabled in `Config`).
- **Theme**: `ThemeMode.AUTO` follows night mode. Only colors are customisable
  (`SecureKeypad.view.theme = KeypadTheme(...)`); geometry always comes from the server.

## Security notes

- `FLAG_SECURE` is added to the activity window while the keypad is visible (screenshots and screen
  recording are blocked) and restored afterwards.
- The keypad view rejects touches when another window overlays it (`filterTouchesWhenObscured`) and
  exposes a single accessibility node ("Secure keypad") with no key labels.
- The payload is opaque: it is useless to anyone but your backend, is bound to the session id, is
  single-use, and has constant length. Sending it over TLS is still required.
- Pin the server public key (`serverPublicKey`). Without it a network attacker who also defeats TLS
  could substitute a keypad with a known layout. The demo leaves it `null` for development only.
- The client wipes session keys after `submit()` / `reset()`; the real guarantee is that the server
  destroys the session on decrypt.
- Read `spec/THREAT-MODEL.md`: a fully compromised OS that captures both the screen and touch events
  can still reconstruct input. The layout shuffle, the absence of character identifiers and the
  capture blocking raise the cost; they do not remove it.

## Build

```
cd clients/android
./gradlew :secure-keypad:assembleRelease :secure-keypad:testDebugUnitTest :demo:assembleDebug
```

`local.properties` must point `sdk.dir` at an Android SDK (compileSdk 36). The JVM unit tests replay
`spec/vectors/*.json`: key agreement, signature verification, inner-frame decoding, relayout, and the
encrypted input batch must match the reference byte for byte.

## Demo

`demo/` is a one-activity app (PIN + password fields). It talks to `http://10.0.2.2:3000` (the host
machine from an emulator); run one of the example servers in `examples/` there and paste its public key
into `DemoActivity.SERVER_PUBLIC_KEY`.

## Known limitations

- The panel is attached to the activity's decor view; dialogs and Compose-only hosts need
  `SecureKeypad.view` placed manually (a `-compose` artifact is planned).
- Multi-touch typing is not supported (one active pointer).
- The keypad height comes from the server metrics table; it is not yet tuned pixel-for-pixel against
  Gboard on every device class (milestone M2 follow-up).
- No instrumented tests yet; the UI was compiled but not exercised on an emulator in this build.
