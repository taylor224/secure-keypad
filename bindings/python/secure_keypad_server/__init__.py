"""secure-keypad server SDK for Python.

Wraps the C core (libskp, statically linked) so an application server can create keypad sessions,
re-layout them, and turn a client's encrypted tap batch back into the typed value.

    from secure_keypad_server import SecureKeypadServer

    skp = SecureKeypadServer(master_key_path="/etc/skp/master.key")
    response = skp.create_session(request_body, ctx=login_attempt_id)      # return to the client
    ...
    with skp.decrypt(payload, ctx=login_attempt_id) as secret:             # session is consumed
        verify_password(user, secret.bytes)                                  # bytearray, wiped on exit

Every secret returned by the core is copied into a ``bytearray`` and the core's own copy is freed
(zeroed) immediately. Wipe the bytearray with :meth:`Secret.wipe` (or use it as a context manager)
as soon as the application has used it. Python ``str`` objects cannot be wiped: avoid ``Secret.text``
unless you must.
"""
from __future__ import annotations

import ctypes
import json
import os
import threading
import time
from typing import Any, Dict, Iterable, Optional, Union

from ._skp import ffi, lib

__all__ = [
    "SecureKeypadServer",
    "Secret",
    "SessionStore",
    "MemoryStore",
    "SkpError",
    "SessionNotFound",
    "keygen",
    "__version__",
]

__version__ = "0.1.0"

_ERROR_NAMES = {
    0: "OK",
    -1: "NOMEM",
    -2: "INVALID_ARG",
    -3: "BAD_KEY",
    -4: "BAD_REQUEST",
    -5: "CRYPTO",
    -6: "EXPIRED",
    -7: "BAD_MAC",
    -8: "TAMPERED",
    -9: "CTX_MISMATCH",
    -10: "SID_MISMATCH",
    -11: "RENDER",
    -12: "IO",
    -13: "UNSUPPORTED",
}

JsonLike = Union[str, bytes, Dict[str, Any]]


class SkpError(Exception):
    """An error reported by the core. ``code`` is the C error code, ``name`` its symbolic name."""

    def __init__(self, code: int, message: Optional[str] = None):
        self.code = int(code)
        self.name = _ERROR_NAMES.get(self.code, "UNKNOWN")
        if message is None:
            message = f"{self.name}: {ffi.string(lib.skp_strerror(self.code)).decode('ascii')}"
        super().__init__(message)


class SessionNotFound(SkpError):
    """The session store has no sealed blob for this sid (never created, expired, or already consumed)."""

    def __init__(self, sid: str):
        super().__init__(-10, f"SESSION_NOT_FOUND: no session {sid!r} in the store")
        self.name = "SESSION_NOT_FOUND"
        self.sid = sid


def _check(rc: int) -> None:
    if rc != 0:
        raise SkpError(rc)


def _take_buf(buf) -> bytes:
    """Copies and releases a skp_buf produced by the core."""
    try:
        return bytes(ffi.buffer(buf.data, buf.len)) if buf.len else b""
    finally:
        lib.skp_buf_free(buf)


def _wipe_cdata(cdata, length: int) -> None:
    if length:
        ffi.memmove(cdata, bytes(length), length)


def _to_json_bytes(value: JsonLike) -> bytes:
    if isinstance(value, dict):
        return json.dumps(value, separators=(",", ":")).encode("utf-8")
    if isinstance(value, str):
        return value.encode("utf-8")
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    raise TypeError("expected a dict, str, or bytes containing JSON")


def _sid_of(value: JsonLike, raw: bytes) -> str:
    obj = value if isinstance(value, dict) else json.loads(raw)
    sid = obj.get("sid") if isinstance(obj, dict) else None
    if not isinstance(sid, str) or not sid:
        raise SkpError(-4, "BAD_REQUEST: missing sid")
    return sid


# --------------------------------------------------------------------------------------- secrets


class Secret:
    """The decrypted value, held in a mutable ``bytearray`` so it can be zeroed."""

    __slots__ = ("_bytes", "_wiped")

    def __init__(self, data: bytearray):
        self._bytes = data
        self._wiped = False

    @property
    def bytes(self) -> bytearray:
        """UTF-8 bytes of the typed value. Raises ``ValueError`` once wiped."""
        if self._wiped:
            raise ValueError("secret has been wiped")
        return self._bytes

    @property
    def text(self) -> str:
        """The typed value as ``str``.

        Warning: Python strings are immutable and interned; a ``str`` copy cannot be wiped and may
        linger in memory until the interpreter exits. Prefer :attr:`bytes` and compare with
        ``hmac.compare_digest`` where possible.
        """
        return self.bytes.decode("utf-8")

    @property
    def wiped(self) -> bool:
        return self._wiped

    def __len__(self) -> int:
        return 0 if self._wiped else len(self._bytes)

    def wipe(self) -> None:
        """Zeroes the buffer in place. Idempotent."""
        if self._wiped:
            return
        n = len(self._bytes)
        if n:
            view = (ctypes.c_char * n).from_buffer(self._bytes)
            ctypes.memset(view, 0, n)
            del view
        self._wiped = True

    def __enter__(self) -> "Secret":
        return self

    def __exit__(self, *exc) -> bool:
        self.wipe()
        return False

    def __del__(self):
        try:
            self.wipe()
        except Exception:
            pass

    def __repr__(self) -> str:
        return f"<Secret len={len(self)} wiped={self._wiped}>"


# --------------------------------------------------------------------------------------- stores


class SessionStore:
    """Interface for keeping sealed session blobs between calls.

    Blobs are ciphertext: a store never sees keys or layouts. ``take`` must be atomic (get + delete)
    so a session can be consumed exactly once even with concurrent requests.
    """

    def put(self, sid: str, sealed: bytes, ttl_sec: int) -> None:
        raise NotImplementedError

    def get(self, sid: str) -> Optional[bytes]:
        raise NotImplementedError

    def take(self, sid: str) -> Optional[bytes]:
        raise NotImplementedError

    def delete(self, sid: str) -> None:
        raise NotImplementedError


class MemoryStore(SessionStore):
    """Thread-safe in-process store with lazy expiry. Suitable for a single process only."""

    def __init__(self, sweep_every: int = 256):
        self._lock = threading.Lock()
        self._entries: Dict[str, tuple] = {}
        self._ops = 0
        self._sweep_every = max(int(sweep_every), 1)

    def _tick(self) -> None:
        self._ops += 1
        if self._ops % self._sweep_every == 0:
            now = time.monotonic()
            for sid in [s for s, (_, deadline) in self._entries.items() if deadline <= now]:
                del self._entries[sid]

    def put(self, sid: str, sealed: bytes, ttl_sec: int) -> None:
        with self._lock:
            self._tick()
            self._entries[sid] = (bytes(sealed), time.monotonic() + max(int(ttl_sec), 0))

    def get(self, sid: str) -> Optional[bytes]:
        with self._lock:
            self._tick()
            entry = self._entries.get(sid)
            if entry is None:
                return None
            sealed, deadline = entry
            if deadline <= time.monotonic():
                del self._entries[sid]
                return None
            return sealed

    def take(self, sid: str) -> Optional[bytes]:
        with self._lock:
            self._tick()
            entry = self._entries.pop(sid, None)
            if entry is None:
                return None
            sealed, deadline = entry
            return sealed if deadline > time.monotonic() else None

    def delete(self, sid: str) -> None:
        with self._lock:
            self._entries.pop(sid, None)

    def ttl(self, sid: str) -> Optional[float]:
        """Seconds until the blob expires, or None when absent."""
        with self._lock:
            entry = self._entries.get(sid)
            if entry is None:
                return None
            return max(entry[1] - time.monotonic(), 0.0)

    def __len__(self) -> int:
        with self._lock:
            return len(self._entries)


# --------------------------------------------------------------------------------------- server


def keygen() -> str:
    """Generates a new master key and returns it as base64 (store it with mode 0600).

    The returned ``str`` cannot be wiped; write it to its file promptly.
    """
    buf = ffi.new("char[64]")
    try:
        _check(lib.skp_keygen_b64(buf, 64))
        return ffi.string(buf).decode("ascii")
    finally:
        _wipe_cdata(buf, 64)


class SecureKeypadServer:
    """One instance per master key. Safe to share between threads."""

    def __init__(
        self,
        master_key_path: Optional[str] = None,
        master_key: Union[str, bytes, bytearray, None] = None,
        *,
        default_ttl: int = 180,
        max_len_cap: int = 256,
        store: Optional[SessionStore] = None,
        font_fallback_path: Optional[str] = None,
    ):
        if master_key_path is not None and master_key is not None:
            raise ValueError("pass either master_key_path or master_key, not both")
        if master_key_path is None and master_key is None:
            env = os.environ.get("SKP_MASTER_KEY")
            if not env:
                raise ValueError("no master key: pass master_key_path / master_key or set SKP_MASTER_KEY")
            master_key = env
        self._ctx = None
        self._store: SessionStore = store if store is not None else MemoryStore()
        cfg = ffi.new("skp_config *")
        keep = []
        if master_key_path is not None:
            p = ffi.new("char[]", os.fsencode(master_key_path))
            keep.append(p)
            cfg.master_key_path = p
        else:
            if isinstance(master_key, (bytes, bytearray)) and len(master_key) == 32:
                k = ffi.new("char[]", bytes(master_key))
                cfg.master_key_len = 32
            else:
                text = master_key.decode("ascii") if isinstance(master_key, (bytes, bytearray)) else str(master_key)
                k = ffi.new("char[]", text.encode("ascii"))
                cfg.master_key_len = 0
            keep.append(k)
            cfg.master_key = k
        if font_fallback_path is not None:
            f = ffi.new("char[]", os.fsencode(font_fallback_path))
            keep.append(f)
            cfg.font_fallback_path = f
        cfg.default_ttl_sec = int(default_ttl)
        cfg.max_len_cap = int(max_len_cap)
        out = ffi.new("skp_ctx **")
        try:
            _check(lib.skp_init(out, cfg))
        finally:
            for c in keep:
                _wipe_cdata(c, len(c))
        self._ctx = out[0]

    # -- lifecycle ------------------------------------------------------------------------
    def close(self) -> None:
        """Releases the core context (keys are wiped). The instance is unusable afterwards."""
        ctx, self._ctx = self._ctx, None
        if ctx is not None:
            lib.skp_free(ctx)

    def __enter__(self) -> "SecureKeypadServer":
        return self

    def __exit__(self, *exc) -> bool:
        self.close()
        return False

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def _c(self):
        if self._ctx is None:
            raise RuntimeError("SecureKeypadServer is closed")
        return self._ctx

    @property
    def store(self) -> SessionStore:
        return self._store

    @property
    def public_key(self) -> str:
        """Ed25519 verification key (base64) to configure in clients."""
        buf = ffi.new("char[64]")
        _check(lib.skp_public_key(self._c(), buf, 64))
        return ffi.string(buf).decode("ascii")

    @property
    def key_id(self) -> str:
        buf = ffi.new("char[9]")
        _check(lib.skp_key_id(self._c(), buf, 9))
        return ffi.string(buf).decode("ascii")

    @staticmethod
    def version() -> str:
        return ffi.string(lib.skp_version()).decode("ascii")

    # -- helpers --------------------------------------------------------------------------
    def _ttl_of(self, sealed: bytes) -> int:
        expires = ffi.new("int64_t *")
        _check(lib.skp_session_info(self._c(), ffi.from_buffer("uint8_t[]", sealed), len(sealed), expires, ffi.NULL, 0))
        return max(int(expires[0]) - int(time.time()), 0)

    # -- API ------------------------------------------------------------------------------
    def create_session(
        self,
        request: JsonLike,
        *,
        ctx: Optional[str] = None,
        layout: str = "shuffle",
        blank: str = "fixed",
        ttl: Optional[int] = None,
        max_len: Optional[int] = None,
        languages: Union[Iterable[str], str, None] = None,
    ) -> Dict[str, Any]:
        """Creates a session from the client's request. Returns the response to send to the client.

        The sealed session state is stored under the response ``sid`` with the session's TTL.
        ``ctx`` binds the session to an application context (user id, login attempt); the same value
        must be passed to :meth:`decrypt`. ``layout`` is ``"shuffle"`` (default), ``"full"``, or
        ``"fixed"`` (the native QWERTY / 2-set / phone-pad order; warning: coordinates reveal characters
        by geometry). ``blank`` places a shuffled number pad's empty cell (``"fixed"`` | ``"random"``). ``languages`` lists the QWERTY keypad's languages in
        switch order (``["en", "ko"]``, ``["ko"]``, or ``"en,ko"``); ``None`` honours the client's request
        (``opts.langs``) and otherwise defaults to English + Korean. Ignored for number pads.
        """
        req = _to_json_bytes(request)
        opts = ffi.new("skp_session_opts *")
        keep = []
        if languages is not None and not isinstance(languages, str):
            languages = ",".join(languages)
        for field, value in (("ctx", ctx), ("layout", layout), ("blank", blank), ("languages", languages)):
            if value:
                c = ffi.new("char[]", str(value).encode("utf-8"))
                keep.append(c)
                setattr(opts, field, c)
        opts.ttl_sec = int(ttl or 0)
        opts.max_len = int(max_len or 0)
        resp = ffi.new("skp_buf *")
        sealed = ffi.new("skp_buf *")
        _check(lib.skp_session_create(self._c(), req, len(req), opts, resp, sealed))
        response = json.loads(_take_buf(resp))
        sealed_bytes = _take_buf(sealed)
        self._store.put(response["sid"], sealed_bytes, self._ttl_of(sealed_bytes))
        return response

    def relayout(self, request: JsonLike) -> Dict[str, Any]:
        """Re-renders an existing session for a new viewport. Replaces the stored blob."""
        req = _to_json_bytes(request)
        sid = _sid_of(request, req)
        sealed = self._store.get(sid)
        if sealed is None:
            raise SessionNotFound(sid)
        resp = ffi.new("skp_buf *")
        sealed_out = ffi.new("skp_buf *")
        _check(lib.skp_session_relayout(self._c(), ffi.from_buffer("uint8_t[]", sealed), len(sealed), req, len(req), resp, sealed_out))
        response = json.loads(_take_buf(resp))
        new_sealed = _take_buf(sealed_out)
        self._store.put(sid, new_sealed, self._ttl_of(new_sealed))
        return response

    def decrypt(self, payload: JsonLike, *, ctx: Optional[str] = None, keep: bool = False) -> Secret:
        """Turns the client's payload into the typed value.

        The session is consumed (removed from the store) before decryption unless ``keep`` is true,
        so a payload can be used exactly once; a failed attempt consumes it too. Raises
        :class:`SessionNotFound` when the store has no blob and :class:`SkpError` (``EXPIRED``,
        ``BAD_MAC``, ``TAMPERED``, ``CTX_MISMATCH``, ``SID_MISMATCH``, ...) on verification failures.
        """
        raw = _to_json_bytes(payload)
        sid = _sid_of(payload, raw)
        sealed = self._store.get(sid) if keep else self._store.take(sid)
        if sealed is None:
            raise SessionNotFound(sid)
        keep_alive = []
        if ctx:
            c_ctx = ffi.new("char[]", ctx.encode("utf-8"))
            keep_alive.append(c_ctx)
        else:
            c_ctx = ffi.NULL
        out = ffi.new("skp_secret **")
        _check(lib.skp_session_decrypt(self._c(), ffi.from_buffer("uint8_t[]", sealed), len(sealed), raw, len(raw), c_ctx, out))
        secret = out[0]
        try:
            n = int(lib.skp_secret_len(secret))
            data = bytearray(n)
            if n:
                ffi.memmove(data, lib.skp_secret_bytes(secret), n)
        finally:
            lib.skp_secret_free(secret)
        del keep_alive
        return Secret(data)
