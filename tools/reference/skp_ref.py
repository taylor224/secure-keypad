"""Reference implementation of the secure-keypad protocol, version 1.

Pure Python (PyNaCl for the primitives). Implements both the server side (master key
derivation, session creation, relayout, sealed state, decrypt) and the client side
(key agreement, signature check, input batch) so that test vectors can be produced with
injected randomness and every other implementation can be checked against them.

It is a *reference*, not a product: it never renders glyphs (sprite sections are empty)
and it does not lock or wipe memory.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import struct
from dataclasses import dataclass, field
from typing import Optional

from nacl import bindings as nb
from nacl.exceptions import CryptoError
from nacl.signing import SigningKey, VerifyKey

import hangul

VERSION = 1
LABEL_MASTER = b"skp/v1/master"
LABEL_SESSION_SALT = b"skp/v1"
AAD_SESSION = b"skp/v1/session"
AAD_RELAYOUT = b"skp/v1/relayout"
AAD_INPUT = b"skp/v1/input"
AAD_STATE = b"skp/v1/state"
SIG_LABEL = b"skp/v1/session"

TYPE_QWERTY, TYPE_NUMBER = 1, 2
TYPES = {"qwerty": TYPE_QWERTY, "number": TYPE_NUMBER}
TYPE_NAMES = {v: k for k, v in TYPES.items()}
POLICIES = {"shuffle": 0, "full": 1, "fixed": 2}
BLANKS = {"fixed": 0, "random": 1}
STYLES = {"ios": 1, "material": 2}
STYLE_NAMES = {v: k for k, v in STYLES.items()}
PLATFORMS = {"ios": 1, "android": 2, "web": 3}
MODE_LOWER, MODE_UPPER, MODE_SYM1, MODE_SYM2, MODE_NUMBER = 0, 1, 2, 3, 4
MODE_NAMES = {0: "lower", 1: "upper", 2: "sym1", 3: "sym2", 4: "number"}
LANG_EN, LANG_KO = 1, 2
LANG_IDS = {"en": LANG_EN, "ko": LANG_KO}
LANG_CODES = {v: k for k, v in LANG_IDS.items()}
DEFAULT_LANGS = [LANG_EN, LANG_KO]
MAX_LANGS = 3
DEFAULT_TTL = 180
DEFAULT_CAP = 256
MAX_GENS = 32
RECORD_SIZE = 8

ERRORS = {
    -1: "NOMEM", -2: "INVALID_ARG", -3: "BAD_KEY", -4: "BAD_REQUEST", -5: "CRYPTO", -6: "EXPIRED",
    -7: "BAD_MAC", -8: "TAMPERED", -9: "CTX_MISMATCH", -10: "SID_MISMATCH", -11: "RENDER", -12: "IO",
    -13: "UNSUPPORTED",
}
ERROR_CODES = {v: k for k, v in ERRORS.items()}


class SkpError(Exception):
    def __init__(self, name: str, detail: str = ""):
        super().__init__(f"{name}: {detail}" if detail else name)
        self.name = name
        self.code = ERROR_CODES[name]


# --------------------------------------------------------------------------- crypto helpers

def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


def nonce12(ctr: int) -> bytes:
    return b"\x00\x00\x00\x00" + struct.pack(">Q", ctr)


def aead_encrypt(key: bytes, n: bytes, aad: bytes, pt: bytes) -> bytes:
    return nb.crypto_aead_chacha20poly1305_ietf_encrypt(pt, aad, n, key)


def aead_decrypt(key: bytes, n: bytes, aad: bytes, ct: bytes) -> bytes:
    try:
        return nb.crypto_aead_chacha20poly1305_ietf_decrypt(ct, aad, n, key)
    except CryptoError as e:
        raise SkpError("BAD_MAC") from e


def xaead_encrypt(key: bytes, n24: bytes, aad: bytes, pt: bytes) -> bytes:
    return nb.crypto_aead_xchacha20poly1305_ietf_encrypt(pt, aad, n24, key)


def xaead_decrypt(key: bytes, n24: bytes, aad: bytes, ct: bytes) -> bytes:
    try:
        return nb.crypto_aead_xchacha20poly1305_ietf_decrypt(ct, aad, n24, key)
    except CryptoError as e:
        raise SkpError("BAD_MAC", "sealed state") from e


def x25519_public(sk: bytes) -> bytes:
    return nb.crypto_scalarmult_base(sk)


def x25519(sk: bytes, pk: bytes) -> bytes:
    try:
        return nb.crypto_scalarmult(sk, pk)
    except CryptoError as e:
        raise SkpError("CRYPTO", "x25519") from e


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def unb64(s: str) -> bytes:
    return base64.b64decode(s, validate=True)


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def unb64url(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def canonical_json(obj) -> bytes:
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


# --------------------------------------------------------------------------- master key

@dataclass
class MasterKeys:
    master: bytes
    sk_sign: SigningKey
    pk_sign: bytes
    k_state: bytes
    kid: str


def parse_master(value) -> bytes:
    """Accepts raw 32 bytes, 64 hex chars, or standard base64 of 32 bytes (text may have whitespace)."""
    if isinstance(value, (bytes, bytearray)) and len(value) == 32:
        return bytes(value)
    text = value.decode("ascii") if isinstance(value, (bytes, bytearray)) else value
    text = text.strip()
    if len(text) == 64:
        try:
            return bytes.fromhex(text)
        except ValueError:
            pass
    try:
        raw = base64.b64decode(text, validate=True)
    except Exception as e:
        raise SkpError("BAD_KEY", "not hex, base64, or 32 raw bytes") from e
    if len(raw) != 32:
        raise SkpError("BAD_KEY", "decoded key is not 32 bytes")
    return raw


def derive_master(master: bytes) -> MasterKeys:
    if len(master) != 32:
        raise SkpError("BAD_KEY", "master key must be 32 bytes")
    prk = hkdf_extract(LABEL_MASTER, master)
    seed_sign = hkdf_expand(prk, b"sign", 32)
    k_state = hkdf_expand(prk, b"state", 32)
    sk = SigningKey(seed_sign)
    pk = sk.verify_key.encode()
    return MasterKeys(master, sk, pk, k_state, sha256(pk)[:4].hex())


# --------------------------------------------------------------------------- deterministic randomness

class Drbg:
    """Sequential reader over libsodium's randombytes_buf_deterministic keystream."""

    def __init__(self, seed: bytes):
        assert len(seed) == 32
        self.seed = seed
        self.buf = b""
        self.pos = 0

    def _ensure(self, n: int) -> None:
        if self.pos + n > len(self.buf):
            size = max(4096, 2 * (self.pos + n))
            self.buf = nb.randombytes_buf_deterministic(size, self.seed)

    def u32(self) -> int:
        self._ensure(4)
        v = struct.unpack(">I", self.buf[self.pos:self.pos + 4])[0]
        self.pos += 4
        return v

    def uniform(self, n: int) -> int:
        if n <= 1:
            return 0
        limit = (1 << 32) - ((1 << 32) % n)
        while True:
            r = self.u32()
            if r < limit:
                return r % n

    def fy(self, items: list) -> list:
        for i in range(len(items) - 1, 0, -1):
            j = self.uniform(i + 1)
            items[i], items[j] = items[j], items[i]
        return items


# --------------------------------------------------------------------------- layout

METRICS = {
    STYLES["ios"]: dict(inset_x=3000, gap=6000, top=8000, key_h=42000, pitch=54000, H=216000,
                        side_key=42000, mode_key=87000, num_key_h=46000, glyph=22500, popup_glyph=34000),
    STYLES["material"]: dict(inset_x=4000, gap=4000, top=6000, key_h=44000, pitch=52000, H=214000,
                             side_key=52000, mode_key=56000, num_key_h=44000, glyph=22000, popup_glyph=30000),
}

# letter rows per language (LAYOUT.md §3) and the shift mapping of each
LANG_ROWS = {
    LANG_EN: ["qwertyuiop", "asdfghjkl", "zxcvbnm"],
    LANG_KO: ["ㅂㅈㄷㄱㅅㅛㅕㅑㅐㅔ", "ㅁㄴㅇㄹㅎㅗㅓㅏㅣ", "ㅋㅌㅊㅍㅠㅜㅡ"],
}
LANG_SHIFT = {
    LANG_EN: None,  # ASCII uppercase
    LANG_KO: {"ㅂ": "ㅃ", "ㅈ": "ㅉ", "ㄷ": "ㄸ", "ㄱ": "ㄲ", "ㅅ": "ㅆ", "ㅐ": "ㅒ", "ㅔ": "ㅖ"},
}
ROWS_SYM1 = ["1234567890", "-/:;()$&@\"", ".,?!'"]
ROWS_SYM2 = ["[]{}#%^*+=", "_\\|~<>€£¥•", ".,?!'"]
DIGITS = "0123456789"


def shifted(lang: int, ch: str) -> str:
    m = LANG_SHIFT[lang]
    return ch.upper() if m is None else m.get(ch, ch)


def parse_langs(value) -> list:
    """Server option: list of codes or a comma-separated string → list of ids. UNSUPPORTED on bad input."""
    if isinstance(value, str):
        value = [v.strip() for v in value.split(",")]
    if not isinstance(value, list) or not (1 <= len(value) <= MAX_LANGS):
        raise SkpError("UNSUPPORTED", "languages")
    ids = []
    for code in value:
        lid = LANG_IDS.get(code) if isinstance(code, str) else None
        if lid is None or lid in ids:
            raise SkpError("UNSUPPORTED", f"language {code!r}")
        ids.append(lid)
    return ids


def rnd(a: int, b: int) -> int:
    assert a >= 0 and b > 0
    return (2 * a + b) // (2 * b)


def px(mu: int, dpr_milli: int) -> int:
    return rnd(mu * dpr_milli, 1_000_000)


def row_rects(L: int, R: int, n: int, g: int, y: int, kh: int) -> list:
    keys_w = (R - L) - (n - 1) * g
    out = []
    for i in range(n):
        left = L + i * g + rnd(i * keys_w, n)
        right = L + i * g + rnd((i + 1) * keys_w, n)
        out.append([left, y, right - left, kh])
    return out


@dataclass
class Key:
    r: list
    role: str
    ch: Optional[str] = None   # server-only
    t: Optional[int] = None    # sprite index for char keys


@dataclass
class Layer:
    mode: int
    keys: list
    lang: int = 0  # language id for letter layers, 0 for symbol / number layers


@dataclass
class Layout:
    type: int
    style: int
    W: int
    H: int
    dpr_milli: int
    layers: list  # layers[slot]
    tile_w: int
    tile_h: int
    tile_count: int
    popup_w: int
    popup_h: int
    langs: list = field(default_factory=list)


def shuffle_charsets(type_: int, policy: int, blank: int, langs: list, seed: bytes):
    """Returns (letters-per-language, sym1 rows, sym2 rows) for qwerty or the 12 number cells (None/'\b')."""
    d = Drbg(seed)
    if type_ == TYPE_QWERTY:
        letters = [[list(r) for r in LANG_ROWS[lang]] for lang in langs]
        sym1 = [list(r) for r in ROWS_SYM1]
        sym2 = [list(r) for r in ROWS_SYM2]
        if policy == POLICIES["shuffle"]:
            for layer in letters + [sym1, sym2]:
                for r in layer:
                    d.fy(r)
        elif policy == POLICIES["full"]:
            def full(layer):
                flat = d.fy([c for r in layer for c in r])
                out, pos = [], 0
                for r in layer:
                    out.append(flat[pos:pos + len(r)])
                    pos += len(r)
                return out
            letters = [full(rows) for rows in letters]
            sym1, sym2 = full(sym1), full(sym2)
        elif policy != POLICIES["fixed"]:
            raise SkpError("UNSUPPORTED", "policy")
        return letters, sym1, sym2
    if type_ == TYPE_NUMBER:
        digits = d.fy(list(DIGITS))
        b = d.uniform(11) if blank == BLANKS["random"] else 9
        cells, it = [], iter(digits)
        for c in range(12):
            if c == 11:
                cells.append("\b")
            elif c == b:
                cells.append(None)
            else:
                cells.append(next(it))
        return cells
    raise SkpError("UNSUPPORTED", "type")


def build_layout(type_: int, policy: int, blank: int, style: int, langs: list, W: int, dpr_milli: int, seed: bytes) -> Layout:
    m = METRICS[style]
    ix, g, kh, sk = px(m["inset_x"], dpr_milli), px(m["gap"], dpr_milli), px(m["key_h"], dpr_milli), px(m["side_key"], dpr_milli)
    top, pitch, H = px(m["top"], dpr_milli), px(m["pitch"], dpr_milli), px(m["H"], dpr_milli)
    ys = [top + r * pitch for r in range(4)]
    if type_ == TYPE_QWERTY:
        if not (1 <= len(langs) <= MAX_LANGS) or len(set(langs)) != len(langs) or any(lang not in LANG_ROWS for lang in langs):
            raise SkpError("UNSUPPORTED", "languages")
    else:
        langs = []
    charsets = shuffle_charsets(type_, policy, blank, langs, seed)
    layers = []
    if type_ == TYPE_QWERTY:
        # geometry shared by all layers
        row0 = row_rects(ix, W - ix, 10, g, ys[0], kh)
        keys_w0 = (W - 2 * ix) - 9 * g
        L1 = ix + rnd(keys_w0 + 10 * g, 20)
        R1 = W - L1
        row1 = row_rects(L1, R1, 9, g, ys[1], kh)
        row1_sym = row_rects(ix, W - ix, 10, g, ys[1], kh)
        keys_w1 = (R1 - L1) - 8 * g
        step = rnd(keys_w1, 9) + g
        letters2 = row_rects(L1 + step, R1 - step, 7, g, ys[2], kh)
        syms2 = row_rects(ix + sk + g, W - ix - sk - g, 5, g, ys[2], kh)
        left2 = [ix, ys[2], sk, kh]
        backspace2 = [W - ix - sk, ys[2], sk, kh]
        mw = min(px(m["mode_key"], dpr_milli), rnd(W, 4))
        has_lang = len(langs) >= 2
        lw = min(sk, mw)
        if has_lang:
            mode3 = [ix, ys[3], lw, kh]
            lang3 = [ix + lw + g, ys[3], lw, kh]
            space3 = [ix + 2 * lw + 2 * g, ys[3], W - 2 * ix - 2 * lw - mw - 3 * g, kh]
        else:
            mode3 = [ix, ys[3], mw, kh]
            lang3 = None
            space3 = [ix + mw + g, ys[3], W - 2 * ix - 2 * mw - 2 * g, kh]
        done3 = [W - ix - mw, ys[3], mw, kh]
        letters, sym1, sym2 = charsets

        def bottom(keys, mode_role):
            keys.append(Key(mode3, mode_role))
            if has_lang:
                keys.append(Key(lang3, "lang"))
            keys.append(Key(space3, "space", " "))
            keys.append(Key(done3, "done"))

        for lang, rows in zip(langs, letters):
            for mode in (MODE_LOWER, MODE_UPPER):
                up = mode == MODE_UPPER
                ch = (lambda c: shifted(lang, c)) if up else (lambda c: c)
                keys = []
                keys += [Key(r, "char", ch(c)) for r, c in zip(row0, rows[0])]
                keys += [Key(r, "char", ch(c)) for r, c in zip(row1, rows[1])]
                keys.append(Key(left2, "shift"))
                keys += [Key(r, "char", ch(c)) for r, c in zip(letters2, rows[2])]
                keys.append(Key(backspace2, "backspace"))
                bottom(keys, "mode_sym1")
                layers.append(Layer(mode, keys, lang))
        for mode, rows in ((MODE_SYM1, sym1), (MODE_SYM2, sym2)):
            keys = []
            keys += [Key(r, "char", c) for r, c in zip(row0, rows[0])]
            keys += [Key(r, "char", c) for r, c in zip(row1_sym, rows[1])]
            keys.append(Key(left2, "mode_sym2" if mode == MODE_SYM1 else "mode_sym1"))
            keys += [Key(r, "char", c) for r, c in zip(syms2, rows[2])]
            keys.append(Key(backspace2, "backspace"))
            bottom(keys, "mode_abc")
            layers.append(Layer(mode, keys))
        tile_h = kh
    else:
        nkh = px(m["num_key_h"], dpr_milli)
        cols = row_rects(ix, W - ix, 3, g, 0, nkh)
        keys = []
        for c, ch in enumerate(charsets):
            r, col = divmod(c, 3)
            rect = [cols[col][0], ys[r], cols[col][2], nkh]
            if ch == "\b":
                keys.append(Key(rect, "backspace"))
            elif ch is None:
                keys.append(Key(rect, "blank"))
            else:
                keys.append(Key(rect, "char", ch))
        layers.append(Layer(MODE_NUMBER, keys))
        tile_h = nkh
    t = 0
    tile_w = 0
    for layer in layers:
        for k in layer.keys:
            if k.role == "char":
                k.t = t
                t += 1
                tile_w = max(tile_w, k.r[2])
    popup_w = min(rnd(3 * tile_w, 2), rnd(3 * tile_h, 2))
    return Layout(type_, style, W, H, dpr_milli, layers, tile_w, tile_h, t, popup_w, rnd(7 * tile_h, 5), list(langs))


def layout_id(gen: int, slot: int) -> int:
    return (gen << 3) | slot


def inner_json(layout: Layout, gen: int, max_len: int, exp: int) -> dict:
    layers = []
    for slot, layer in enumerate(layout.layers):
        keys = []
        for k in layer.keys:
            o = {"r": list(k.r), "role": k.role}
            if k.role == "char":
                o["t"] = k.t
            keys.append(o)
        lo = {"id": layout_id(gen, slot), "mode": MODE_NAMES[layer.mode]}
        if layer.lang:
            lo["lang"] = LANG_CODES[layer.lang]
        lo["keys"] = keys
        layers.append(lo)
    return {
        "v": VERSION, "type": TYPE_NAMES[layout.type], "style": STYLE_NAMES[layout.style],
        "w": layout.W, "h": layout.H, "gen": gen, "maxLen": max_len, "exp": exp,
        "langs": [LANG_CODES[lang] for lang in layout.langs],
        "layouts": layers,
        "tile": {"w": layout.tile_w, "h": layout.tile_h, "cols": 10, "count": layout.tile_count},
        "popup": {"w": layout.popup_w, "h": layout.popup_h, "cols": 10, "count": layout.tile_count},
    }


def hit_test(layer: Layer, x: int, y: int) -> Key:
    best, best_d = None, None
    for k in layer.keys:
        rx, ry, rw, rh = k.r
        dx = max(rx - x, 0, x - (rx + rw - 1))
        dy = max(ry - y, 0, y - (ry + rh - 1))
        d = dx * dx + dy * dy
        if best is None or d < best_d:
            best, best_d = k, d
    return best


def frame(inner: bytes, tiles: bytes = b"", popups: bytes = b"") -> bytes:
    return struct.pack(">I", len(inner)) + inner + struct.pack(">I", len(tiles)) + tiles + struct.pack(">I", len(popups)) + popups


def unframe(buf: bytes):
    parts, pos = [], 0
    for _ in range(3):
        if pos + 4 > len(buf):
            raise SkpError("TAMPERED", "frame")
        n = struct.unpack(">I", buf[pos:pos + 4])[0]
        pos += 4
        if pos + n > len(buf):
            raise SkpError("TAMPERED", "frame")
        parts.append(buf[pos:pos + n])
        pos += n
    if pos != len(buf):
        raise SkpError("TAMPERED", "frame trailing")
    return parts


# --------------------------------------------------------------------------- sealed state

@dataclass
class Gen:
    seed: bytes
    W: int
    dpr_milli: int
    platform: int


@dataclass
class State:
    type: int
    policy: int
    blank: int
    style: int
    max_len: int
    created: int
    expires: int
    sid: bytes
    ctx_hash: bytes
    k_s2c: bytes
    k_c2s: bytes
    s2c_ctr: int
    gens: list = field(default_factory=list)
    langs: list = field(default_factory=list)


HEAD_FMT = ">BBBBBBHHQQ16s32s32s32sQB3s"
GEN_FMT = ">32sHHB"
HEAD_SIZE = struct.calcsize(HEAD_FMT)   # 150
GEN_SIZE = struct.calcsize(GEN_FMT)     # 37


def pack_state(st: State) -> bytes:
    langs = bytes(st.langs) + bytes(MAX_LANGS - len(st.langs))
    out = struct.pack(HEAD_FMT, 1, st.type, st.policy, st.blank, st.style, len(st.gens), st.max_len, 0,
                      st.created, st.expires, st.sid, st.ctx_hash, st.k_s2c, st.k_c2s, st.s2c_ctr, len(st.langs), langs)
    for g in st.gens:
        out += struct.pack(GEN_FMT, g.seed, g.W, g.dpr_milli, g.platform)
    return out


def unpack_state(buf: bytes) -> State:
    if len(buf) < HEAD_SIZE:
        raise SkpError("TAMPERED", "state short")
    (v, type_, policy, blank, style, n, max_len, flags, created, expires, sid, ctx_hash,
     k_s2c, k_c2s, s2c_ctr, nlangs, langs_raw) = struct.unpack(HEAD_FMT, buf[:HEAD_SIZE])
    if v != 1 or flags != 0 or not (1 <= n <= MAX_GENS) or len(buf) != HEAD_SIZE + n * GEN_SIZE:
        raise SkpError("TAMPERED", "state header")
    if nlangs > MAX_LANGS or any(langs_raw[i] != 0 for i in range(nlangs, MAX_LANGS)):
        raise SkpError("TAMPERED", "state languages")
    langs = list(langs_raw[:nlangs])
    if any(lang not in LANG_CODES for lang in langs) or len(set(langs)) != nlangs:
        raise SkpError("TAMPERED", "state languages")
    if (type_ == TYPE_QWERTY and nlangs < 1) or (type_ == TYPE_NUMBER and nlangs != 0):
        raise SkpError("TAMPERED", "state languages")
    gens = []
    for i in range(n):
        off = HEAD_SIZE + i * GEN_SIZE
        seed, W, dpr_milli, platform = struct.unpack(GEN_FMT, buf[off:off + GEN_SIZE])
        gens.append(Gen(seed, W, dpr_milli, platform))
    return State(type_, policy, blank, style, max_len, created, expires, sid, ctx_hash, k_s2c, k_c2s, s2c_ctr, gens, langs)


def seal(mk: MasterKeys, st: State, nonce24: bytes) -> bytes:
    assert len(nonce24) == 24
    return nonce24 + xaead_encrypt(mk.k_state, nonce24, AAD_STATE + mk.kid.encode("ascii"), pack_state(st))


def unseal(mk: MasterKeys, sealed: bytes) -> State:
    if len(sealed) < 24 + 16:
        raise SkpError("TAMPERED", "sealed short")
    pt = xaead_decrypt(mk.k_state, sealed[:24], AAD_STATE + mk.kid.encode("ascii"), sealed[24:])
    return unpack_state(pt)


# --------------------------------------------------------------------------- server

@dataclass
class Hooks:
    s_sk: Optional[bytes] = None
    sid: Optional[bytes] = None
    seed: Optional[bytes] = None
    nonce24: Optional[bytes] = None
    now: Optional[int] = None


def _rand(n: int) -> bytes:
    return nb.randombytes(n)


def _now(h: Optional[Hooks]) -> int:
    import time
    return h.now if h and h.now is not None else int(time.time())


def parse_viewport(vp) -> tuple:
    if not isinstance(vp, dict):
        raise SkpError("BAD_REQUEST", "viewport")
    w, dpr, platform = vp.get("w"), vp.get("dpr"), vp.get("platform")
    if not isinstance(w, (int, float)) or isinstance(w, bool) or w <= 0:
        raise SkpError("BAD_REQUEST", "viewport.w")
    if not isinstance(dpr, (int, float)) or isinstance(dpr, bool) or dpr <= 0:
        raise SkpError("BAD_REQUEST", "viewport.dpr")
    if platform not in PLATFORMS:
        raise SkpError("BAD_REQUEST", "viewport.platform")
    import math
    dpr_milli = min(max(int(math.floor(dpr * 1000 + 0.5)), 500), 10000)
    W = rnd(int(math.floor(w * 1000 + 0.5)) * dpr_milli, 1_000_000)
    if not (200 <= W <= 8192):
        raise SkpError("BAD_REQUEST", "viewport width out of range")
    style = vp.get("style")
    if style is None:
        style = "ios" if platform == "ios" else "material"
    if style not in STYLES:
        raise SkpError("BAD_REQUEST", "viewport.style")
    return W, dpr_milli, PLATFORMS[platform], STYLES[style]


def create_session(mk: MasterKeys, request: dict, opts: Optional[dict] = None, hooks: Optional[Hooks] = None):
    """Returns (response_json_dict, sealed_bytes, debug_dict)."""
    opts = opts or {}
    if not isinstance(request, dict) or request.get("v") != VERSION:
        raise SkpError("BAD_REQUEST", "v")
    try:
        c_pk = unb64(request["kp"])
    except Exception as e:
        raise SkpError("BAD_REQUEST", "kp") from e
    if len(c_pk) != 32:
        raise SkpError("BAD_REQUEST", "kp length")
    if request.get("type") not in TYPES:
        raise SkpError("BAD_REQUEST", "type")
    type_ = TYPES[request["type"]]
    W, dpr_milli, platform, style = parse_viewport(request.get("viewport"))
    ropts = request.get("opts") or {}
    policy = POLICIES.get(opts.get("layout", "shuffle"))
    blank = BLANKS.get(opts.get("blank", "fixed"))
    if policy is None or blank is None:
        raise SkpError("UNSUPPORTED", "layout/blank option")
    ttl = int(opts.get("ttl") or DEFAULT_TTL)
    cap = int(opts.get("cap") or DEFAULT_CAP)
    max_len = int(opts.get("maxLen") or 0)
    if max_len <= 0:
        max_len = ropts.get("maxLen") if isinstance(ropts.get("maxLen"), int) else (32 if type_ == TYPE_QWERTY else 16)
    max_len = min(max(max_len, 1), cap)
    ctx = opts.get("ctx")
    ctx_hash = sha256(ctx.encode("utf-8")) if ctx else bytes(32)
    # languages: the integrator's option, else the client's opts.langs, else Korean + English
    langs = []
    if type_ == TYPE_QWERTY:
        if opts.get("languages"):
            langs = parse_langs(opts["languages"])
        elif "langs" in ropts and ropts["langs"] is not None:
            rl = ropts["langs"]
            if not isinstance(rl, list) or not (1 <= len(rl) <= MAX_LANGS):
                raise SkpError("BAD_REQUEST", "opts.langs")
            for code in rl:
                lid = LANG_IDS.get(code) if isinstance(code, str) else None
                if lid is None or lid in langs:
                    raise SkpError("BAD_REQUEST", "opts.langs")
                langs.append(lid)
        else:
            langs = list(DEFAULT_LANGS)

    now = _now(hooks)
    sid = hooks.sid if hooks and hooks.sid else _rand(16)
    s_sk = hooks.s_sk if hooks and hooks.s_sk else _rand(32)
    seed = hooks.seed if hooks and hooks.seed else _rand(32)
    nonce24 = hooks.nonce24 if hooks and hooks.nonce24 else _rand(24)
    s_pk = x25519_public(s_sk)
    ss = x25519(s_sk, c_pk)
    prk = hkdf_extract(LABEL_SESSION_SALT + sid, ss)
    k_s2c = hkdf_expand(prk, b"s2c" + c_pk + s_pk, 32)
    k_c2s = hkdf_expand(prk, b"c2s" + c_pk + s_pk, 32)

    layout = build_layout(type_, policy, blank, style, langs, W, dpr_milli, seed)
    inner = inner_json(layout, 0, max_len, ttl)
    inner_bytes = canonical_json(inner)
    ct = aead_encrypt(k_s2c, nonce12(0), AAD_SESSION + sid, frame(inner_bytes))
    sig = mk.sk_sign.sign(SIG_LABEL + mk.kid.encode("ascii") + sid + c_pk + s_pk + sha256(ct)).signature
    st = State(type_, policy, blank, style, max_len, now, now + ttl, sid, ctx_hash, k_s2c, k_c2s, 1,
               [Gen(seed, W, dpr_milli, platform)], langs)
    response = {"v": VERSION, "sid": b64url(sid), "kid": mk.kid, "sp": b64(s_pk), "sig": b64(sig), "ct": b64(ct)}
    debug = {"k_s2c": k_s2c, "k_c2s": k_c2s, "inner": inner, "layout": layout, "state": st, "s_pk": s_pk}
    return response, seal(mk, st, nonce24), debug


def relayout(mk: MasterKeys, sealed: bytes, request: dict, hooks: Optional[Hooks] = None):
    st = unseal(mk, sealed)
    now = _now(hooks)
    if now > st.expires:
        raise SkpError("EXPIRED")
    if not isinstance(request, dict) or request.get("v") != VERSION:
        raise SkpError("BAD_REQUEST", "v")
    try:
        sid = unb64url(request["sid"])
    except Exception as e:
        raise SkpError("BAD_REQUEST", "sid") from e
    if sid != st.sid:
        raise SkpError("SID_MISMATCH")
    if len(st.gens) >= MAX_GENS:
        raise SkpError("UNSUPPORTED", "too many generations")
    W, dpr_milli, platform, _style = parse_viewport(request.get("viewport"))
    gen = len(st.gens)
    st.gens.append(Gen(st.gens[-1].seed, W, dpr_milli, platform))
    layout = build_layout(st.type, st.policy, st.blank, st.style, st.langs, W, dpr_milli, st.gens[-1].seed)
    inner = inner_json(layout, gen, st.max_len, st.expires - now)
    ct = aead_encrypt(st.k_s2c, nonce12(st.s2c_ctr), AAD_RELAYOUT + sid, frame(canonical_json(inner)))
    st.s2c_ctr += 1
    nonce24 = hooks.nonce24 if hooks and hooks.nonce24 else _rand(24)
    response = {"v": VERSION, "sid": b64url(sid), "gen": gen, "ct": b64(ct)}
    return response, seal(mk, st, nonce24), {"inner": inner, "layout": layout, "state": st}


def decrypt(mk: MasterKeys, sealed: bytes, payload: dict, ctx: Optional[str] = None, now: Optional[int] = None) -> str:
    st = unseal(mk, sealed)
    if now is None:
        import time
        now = int(time.time())
    if now > st.expires:
        raise SkpError("EXPIRED")
    if not isinstance(payload, dict) or payload.get("v") != VERSION:
        raise SkpError("BAD_REQUEST", "v")
    try:
        sid = unb64url(payload["sid"])
        ct = unb64(payload["ct"])
    except Exception as e:
        raise SkpError("BAD_REQUEST", "sid/ct") from e
    if sid != st.sid:
        raise SkpError("SID_MISMATCH")
    if st.ctx_hash == bytes(32):
        if ctx:
            raise SkpError("CTX_MISMATCH")
    else:
        if not ctx or not hmac.compare_digest(sha256(ctx.encode("utf-8")), st.ctx_hash):
            raise SkpError("CTX_MISMATCH")
    batch = aead_decrypt(st.k_c2s, nonce12(0), AAD_INPUT + sid, ct)
    if len(batch) != 4 + RECORD_SIZE * st.max_len:
        raise SkpError("TAMPERED", "batch length")
    ver, rsv, count = struct.unpack(">BBH", batch[:4])
    if ver != 1 or rsv != 0 or count > st.max_len:
        raise SkpError("TAMPERED", "batch header")
    layouts_cache = {}
    out = []
    for i in range(st.max_len):
        rec = batch[4 + i * RECORD_SIZE: 4 + (i + 1) * RECORD_SIZE]
        if i >= count:
            if rec != bytes(RECORD_SIZE):
                raise SkpError("TAMPERED", "padding")
            continue
        seq, lid, flags, x, y = struct.unpack(">HBBHH", rec)
        if seq != i or flags != 0:
            raise SkpError("TAMPERED", "record")
        gen, slot = lid >> 3, lid & 7
        if gen >= len(st.gens):
            raise SkpError("TAMPERED", "gen")
        if gen not in layouts_cache:
            g = st.gens[gen]
            layouts_cache[gen] = build_layout(st.type, st.policy, st.blank, st.style, st.langs, g.W, g.dpr_milli, g.seed)
        layout = layouts_cache[gen]
        if slot >= len(layout.layers):
            raise SkpError("TAMPERED", "slot")
        if x >= layout.W or y >= layout.H:
            raise SkpError("TAMPERED", "coords")
        key = hit_test(layout.layers[slot], x, y)
        if key.role not in ("char", "space"):
            raise SkpError("TAMPERED", "non-character key")
        out.append(key.ch)
    # Korean jamo compose into syllables (spec/HANGUL.md); other characters pass through
    return hangul.compose("".join(out))


# --------------------------------------------------------------------------- client

def client_derive(c_sk: bytes, s_pk: bytes, sid: bytes):
    c_pk = x25519_public(c_sk)
    ss = x25519(c_sk, s_pk)
    prk = hkdf_extract(LABEL_SESSION_SALT + sid, ss)
    return hkdf_expand(prk, b"s2c" + c_pk + s_pk, 32), hkdf_expand(prk, b"c2s" + c_pk + s_pk, 32)


def client_open(response: dict, c_sk: bytes, pk_sign: Optional[bytes] = None):
    """Verify, derive, decrypt. Returns dict(sid, k_s2c, k_c2s, inner, tiles, popups)."""
    if response.get("v") != VERSION:
        raise SkpError("UNSUPPORTED", "v")
    sid, s_pk, sig, ct = unb64url(response["sid"]), unb64(response["sp"]), unb64(response["sig"]), unb64(response["ct"])
    c_pk = x25519_public(c_sk)
    if pk_sign is not None:
        msg = SIG_LABEL + response["kid"].encode("ascii") + sid + c_pk + s_pk + sha256(ct)
        try:
            VerifyKey(pk_sign).verify(msg, sig)
        except Exception as e:
            raise SkpError("CRYPTO", "bad signature") from e
    k_s2c, k_c2s = client_derive(c_sk, s_pk, sid)
    inner_bytes, tiles, popups = unframe(aead_decrypt(k_s2c, nonce12(0), AAD_SESSION + sid, ct))
    return {"sid": sid, "k_s2c": k_s2c, "k_c2s": k_c2s, "inner": json.loads(inner_bytes), "tiles": tiles, "popups": popups}


def client_open_relayout(k_s2c: bytes, ctr: int, sid: bytes, response: dict):
    ct = unb64(response["ct"])
    inner_bytes, tiles, popups = unframe(aead_decrypt(k_s2c, nonce12(ctr), AAD_RELAYOUT + sid, ct))
    return {"inner": json.loads(inner_bytes), "tiles": tiles, "popups": popups}


def client_build_input(k_c2s: bytes, sid: bytes, max_len: int, taps: list) -> dict:
    """taps: list of (layout_id, x, y). Returns the payload dict."""
    if len(taps) > max_len:
        raise ValueError("too many taps")
    batch = struct.pack(">BBH", 1, 0, len(taps))
    for i, (lid, x, y) in enumerate(taps):
        batch += struct.pack(">HBBHH", i, lid, 0, x, y)
    batch += bytes(RECORD_SIZE * (max_len - len(taps)))
    ct = aead_encrypt(k_c2s, nonce12(0), AAD_INPUT + sid, batch)
    return {"v": VERSION, "sid": b64url(sid), "ct": b64(ct)}


# --------------------------------------------------------------------------- helpers for tests / vectors

def taps_for_text(layout: Layout, gen: int, text: str, offset=(0, 0)) -> list:
    """Server-side helper: produce (layout_id, x, y) at key centres (plus offset) for a text.

    Hangul syllables are decomposed into the jamo key presses that type them (hangul.decompose)."""
    taps = []
    for ch in hangul.decompose(text):
        found = None
        for slot, layer in enumerate(layout.layers):
            for k in layer.keys:
                if k.role in ("char", "space") and k.ch == ch:
                    found = (slot, k)
                    break
            if found:
                break
        if not found:
            raise ValueError(f"character {ch!r} not on keypad")
        slot, k = found
        x = k.r[0] + k.r[2] // 2 + offset[0]
        y = k.r[1] + k.r[3] // 2 + offset[1]
        taps.append((layout_id(gen, slot), x, y))
    return taps


def find_layer(layout: Layout, mode: int, lang: int = 0) -> tuple:
    """(slot, layer) for a mode and language id (0 for symbol / number layers)."""
    return next((slot, l) for slot, l in enumerate(layout.layers) if l.mode == mode and l.lang == lang)


def find_key(layout: Layout, mode: int, role: str, lang: int = 0) -> Key:
    _, layer = find_layer(layout, mode, lang)
    return next(k for k in layer.keys if k.role == role)
