"""Example integration: FastAPI server exposing the three secure-keypad endpoints.

    export SKP_MASTER_KEY_PATH=/path/to/master.key     # or SKP_MASTER_KEY=<base64|hex>
    uvicorn app:app --port 8000

Endpoints
    POST /keypad/session   body: the client SDK's session request (+ optional "ctx")
    POST /keypad/relayout  body: the client SDK's relayout request
    POST /login            body: {"ctx": ..., "password_enc": <payload from the client SDK>}
                           → {"ok": bool, "length": n}   (the value itself is never echoed)

"ctx" is an opaque string the application chooses (a login attempt id, a user id). It binds the session
to the login that created it: a payload replayed under another ctx fails with CTX_MISMATCH.
"""
import hmac
import os
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException, Request

from secure_keypad_server import SecureKeypadServer, SessionNotFound, SkpError

DEMO_PASSWORD = os.environ.get("SKP_DEMO_PASSWORD", "1234")


def make_server() -> SecureKeypadServer:
    path = os.environ.get("SKP_MASTER_KEY_PATH")
    if path:
        return SecureKeypadServer(master_key_path=path)
    return SecureKeypadServer()  # falls back to SKP_MASTER_KEY


skp = make_server()
app = FastAPI(title="secure-keypad example server")


def _ctx(body: Dict[str, Any]) -> Optional[str]:
    ctx = body.get("ctx")
    return ctx if isinstance(ctx, str) and ctx else None


def _bad(e: SkpError) -> HTTPException:
    status = 404 if isinstance(e, SessionNotFound) else 400
    return HTTPException(status_code=status, detail={"error": e.name})


@app.get("/keypad/public-key")
def public_key():
    return {"publicKey": skp.public_key, "kid": skp.key_id}


@app.post("/keypad/session")
async def create_session(req: Request):
    body = await req.json()
    try:
        return skp.create_session(body, ctx=_ctx(body), layout=os.environ.get("SKP_LAYOUT", "shuffle"),
                                  blank=os.environ.get("SKP_BLANK", "fixed"),
                                  languages=os.environ.get("SKP_LANGUAGES") or None)  # e.g. "en,ko" or "ko"
    except SkpError as e:
        raise _bad(e)


@app.post("/keypad/relayout")
async def relayout(req: Request):
    body = await req.json()
    try:
        return skp.relayout(body)
    except SkpError as e:
        raise _bad(e)


@app.post("/login")
async def login(req: Request):
    body = await req.json()
    payload = body.get("password_enc")
    if not isinstance(payload, (dict, str)):
        raise HTTPException(status_code=400, detail={"error": "password_enc missing"})
    try:
        with skp.decrypt(payload, ctx=_ctx(body)) as secret:
            ok = hmac.compare_digest(bytes(secret.bytes), DEMO_PASSWORD.encode("utf-8"))
            return {"ok": ok, "length": len(secret)}
    except SkpError as e:
        raise _bad(e)
