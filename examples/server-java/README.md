# Example: Java server (JDK HttpServer)

A minimal integration of `dev.securekeypad:skp-server` with no framework. The binding is consumed
through a Gradle composite build (`includeBuild("../../bindings/java")`), so it is built from source.

```sh
cd examples/server-java
SKP_MASTER_KEY=$(../../core/build/skp-keygen) ./gradlew run     # or SKP_MASTER_KEY_PATH=/etc/skp/master.key
```

Without a key the server prints a warning and uses a throw-away key. `PORT` (default 8080) and
`SKP_LAYOUT` (`shuffle` | `full` | `fixed`) are honoured.

| Route | Body | Response |
|---|---|---|
| `POST /keypad/session` | client request JSON (from the client SDK) | session response JSON, returned verbatim |
| `POST /keypad/relayout` | client relayout JSON | relayout response JSON |
| `POST /login` | client payload `{v, sid, ct}` | `{"ok":true,"length":N}` |

The `X-Login-Ctx` header is used as the binding context on both `/keypad/session` and `/login`; a real
application binds to its own login attempt or user session instead.

Try it with the Python reference client:

```sh
python3 - <<'EOF'
import json, os, sys, urllib.request
sys.path.insert(0, "../../tools/reference")
import skp_ref as R
sk = os.urandom(32)
req = {"v": 1, "kp": R.b64(R.x25519_public(sk)), "type": "number", "viewport": {"w": 390, "dpr": 3, "platform": "ios"}}
r = urllib.request.Request("http://localhost:8080/keypad/session", json.dumps(req).encode(), {"Content-Type": "application/json"})
print(urllib.request.urlopen(r).read()[:120])
EOF
```
