# SecureKeypad for iOS

Swift Package implementing the client side of [secure-keypad](../../README.md) on iOS 14+ with no
third-party dependencies (CryptoKit, UIKit, Foundation).

The keypad replaces the system keyboard for one text field. The server renders the glyphs of a
per-session shuffled layout; this SDK draws an iOS-style keyboard around them, records where the user
tapped, and returns an encrypted payload. The app never sees the entered value.

## Install

Swift Package Manager: add `https://github.com/YOUR-ORG/secure-keypad` (path `clients/ios`) or a local
package reference, product `SecureKeypad`.

## Server side

The app talks to **your** backend, which uses the secure-keypad server SDK:

| Endpoint (yours) | Server SDK call |
|---|---|
| `POST /keypad/session` | `createSession(body, { ctx })` |
| `POST /keypad/relayout` | `relayout(body)` |
| your login / form endpoint | `decrypt(payload, { ctx })` |

Print the server's public key once with `skp-keygen --pubkey master.key` and ship it in the app
configuration. With it the SDK rejects keypads that were not signed by your server, even if TLS is
intercepted.

## UIKit

```swift
import SecureKeypad

var config = SecureKeypad.Config(
    sessionURL: URL(string: "https://api.example.com/keypad/session")!,
    type: .number,
    serverPublicKey: "BASE64_ED25519_PUBLIC_KEY")
config.relayoutURL = URL(string: "https://api.example.com/keypad/relayout")
config.maxLen = 6
config.haptics = true

let keypad = SecureKeypad(config: config)
keypad.attach(to: pinTextField)          // sets inputView / inputAccessoryView, secure entry
keypad.onChange = { count in submitButton.isEnabled = count == 6 }
keypad.onDone = { [weak self] in self?.login() }

func login() {
    do {
        let payload = try keypad.submit()   // opaque JSON string {"v":1,"sid":"…","ct":"…"}
        api.login(userId: userField.text ?? "", passwordEnc: payload) { result in
            if case .failure = result { keypad.reset() }   // the session is single-use
        }
    } catch {
        keypad.reset()
    }
}
```

`attach(to:)` keeps the field's text as bullets only. Never read `textField.text` for the value; it is
not there. Keep a `SecureKeypad` instance alive for as long as the field is on screen.

## SwiftUI

```swift
struct LoginView: View {
    @StateObject private var model = LoginModel()   // holds `let keypad = SecureKeypad(config: …)`

    var body: some View {
        VStack {
            SecureKeypadField(keypad: model.keypad, placeholder: "PIN")
            Button("Sign in") { model.signIn() }
        }
    }
}
```

## Configuration

| Field | Default | Meaning |
|---|---|---|
| `sessionURL` | required | your session endpoint |
| `relayoutURL` | nil | your relayout endpoint; without it a rotation starts a new session and clears input |
| `serverPublicKey` | nil | base64 Ed25519 key; `strict = true` refuses to run without it |
| `type` | required | `.qwerty` or `.number` |
| `maxLen` | server default (32 / 16) | requested maximum length; the server may cap it |
| `theme` | `.auto` | `.light`, `.dark`, or follow the trait collection |
| `haptics`, `sound` | true | light impact on key down; key click respects the system keyboard-click setting |
| `captureAction` | `.warn` | `.warn` covers the keypad while the screen is captured, `.close` also dismisses it and clears input, `.ignore` does nothing |
| `transport` | `URLSessionTransport()` | implement `SecureKeypadTransport` to add auth headers or pinning |

Callbacks: `onChange(Int)`, `onDone()`, `onStateChange(State)`, `onExpire()` (a new session starts
automatically), `onError(Error)`.

## Behaviour

- Shift is one-shot; double-tap for caps lock. `123` / `#+=` / `ABC` switch layers. Backspace repeats when
  held. Number pads get an accessory bar with Done.
- Rotation or a width change requests a relayout; taps made before it keep their generation, so nothing
  typed is lost.
- The input view is one accessibility element ("Secure keypad"); keys are deliberately not announced.
- Screen recording (`UIScreen.isCaptured`) and screenshots cover the keypad; the keypad is also covered
  before the app-switcher snapshot.

## Security notes

- The payload is opaque. Store it nowhere; send it once. A session can be submitted once; after a failed
  login call `reset()` to get a fresh layout.
- Session keys and sprites are wiped when the session is consumed (`Data` zeroing is best effort in Swift;
  the server-side destruction is the real guarantee).
- `serverPublicKey` is optional for development only. Production builds should set `strict = true`.
- Do not log `taps`, the layout set, or sprites.

## Tests

```sh
cd clients/ios
Tests/sync-vectors.sh                 # refresh the spec vectors copied into the test bundle
swift test                            # protocol tests on the Mac host
xcodebuild test -scheme SecureKeypad -destination 'platform=iOS Simulator,name=iPhone 15'
```

The vector tests reproduce the derived keys, decrypted layout JSON and encrypted input payload of every
vector in `spec/vectors` byte for byte.
