# @secure-keypad/react

React bindings for `@secure-keypad/web`.

```tsx
import { SecureKeypadProvider, SecureKeypadInput } from "@secure-keypad/react";

<SecureKeypadProvider config={{ sessionUrl: "/keypad/session", relayoutUrl: "/keypad/relayout", serverPublicKey }}>
  <form onSubmit={...}>
    <SecureKeypadInput type="number" maxLen={6} payloadName="pin_enc" placeholder="PIN" />
    <SecureKeypadInput type="qwerty" maxLen={32} payloadName="password_enc" placeholder="Password" />
    <button>Sign in</button>
  </form>
</SecureKeypadProvider>
```

- `payloadName` adds a hidden input that carries the encrypted payload on a classic form submit.
- For JSON submits use the hook: `const { inputRef, submit, length, ready } = useSecureKeypad({ type: "qwerty" })`,
  render `<input ref={inputRef} type="password" />`, and call `submit()` to get the payload.
- `onSubmit(payload)` fires when the user presses Done; the session is consumed at that point.
- Every option of `createSecureKeypad` can be passed through `keypad={{ ... }}` or the provider.
