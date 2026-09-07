# Example: Python (FastAPI) server

Wires the three endpoints the client SDKs expect to the `secure-keypad-server` binding.

```sh
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt            # builds the C core; needs cmake, a C compiler, libsodium, zlib

# a master key (keep it out of git, mode 0600)
python -c "import secure_keypad_server as s; print(s.keygen())" > master.key && chmod 600 master.key

SKP_MASTER_KEY_PATH=$PWD/master.key uvicorn app:app --port 8000
```

| Method | Path | Body | Response |
|---|---|---|---|
| GET | `/keypad/public-key` | – | `{publicKey, kid}` for client pinning |
| POST | `/keypad/session` | client session request, optional `ctx` | session response for the client |
| POST | `/keypad/relayout` | client relayout request | relayout response |
| POST | `/login` | `{ctx, password_enc}` | `{ok, length}` (compares with `SKP_DEMO_PASSWORD`, default `1234`) |

Environment: `SKP_MASTER_KEY_PATH` or `SKP_MASTER_KEY`, optional `SKP_LAYOUT` (`shuffle` | `full` | `fixed`),
`SKP_BLANK` (`fixed` | `random`), `SKP_DEMO_PASSWORD`.

Quick check without a client:

```sh
python - <<'EOF'
import json, sys, urllib.request
sys.path.insert(0, "../../tools/reference"); import skp_ref as R
c_sk = b"\x21" * 32
req = {"v": 1, "kp": R.b64(R.x25519_public(c_sk)), "type": "number",
       "viewport": {"w": 390, "dpr": 3, "platform": "ios"}, "ctx": "demo"}
r = urllib.request.urlopen(urllib.request.Request("http://127.0.0.1:8000/keypad/session",
        json.dumps(req).encode(), {"content-type": "application/json"}))
print(json.load(r)["sid"])
EOF
```
