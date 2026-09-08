# secure-keypad Protocol, version 1

Status: draft, frozen for v1.0 test vectors. Any change to this document that alters bytes on the wire
requires bumping `v` and regenerating `spec/vectors/`.

## 1. Overview

A *session* is one keypad presentation. The server renders the secret parts of the keypad (glyph tiles),
encrypts them for the client with a fresh session key, and records the layout in a sealed blob that only the
server can open. The client draws the keypad chrome itself, blits the tiles, records tap coordinates, and
returns them encrypted. The server maps coordinates to characters and destroys the session.

Two parties hold keys:

| Party  | Long-term                           | Per session                              |
|--------|-------------------------------------|------------------------------------------|
| Server | master key (32 B) → Ed25519 signing key, state sealing key | ephemeral X25519 key pair (discarded after key derivation) |
| Client | optional pinned Ed25519 public key  | ephemeral X25519 key pair                |

## 2. Notation

- `a || b` is byte concatenation. Integers are big-endian unless stated: `u8`, `u16`, `u32`, `u64`.
- `b64(x)` is standard base64 with padding (RFC 4648 §4). `b64url(x)` is URL-safe base64 without padding (RFC 4648 §5).
- Labels such as `"skp/v1"` are ASCII bytes with no terminator.
- `HKDF-Extract(salt, ikm)` and `HKDF-Expand(prk, info, L)` are RFC 5869 with SHA-256.
- `X25519` is RFC 7748. `Ed25519` is RFC 8032 (pure, no prehash, no context).
- `AEAD(key, nonce, aad, pt)` is ChaCha20-Poly1305 per RFC 8439 (96-bit nonce). Output is ciphertext followed by the 16-byte tag.
- `XAEAD(key, nonce24, aad, pt)` is XChaCha20-Poly1305 (libsodium `crypto_aead_xchacha20poly1305_ietf`), server-only.
- `SHA-256` is FIPS 180-4.

## 3. Master key and derived long-term keys

The master key is 32 random bytes. Accepted encodings when loading from a file or a string: 64 lowercase or
uppercase hex characters, or standard base64 of 32 bytes; surrounding whitespace and a trailing newline are
ignored. A raw 32-byte value may be passed directly through the API.

```
prk_m     = HKDF-Extract(salt = "skp/v1/master", ikm = master)
seed_sign = HKDF-Expand(prk_m, "sign", 32)      → Ed25519 key pair from seed (RFC 8032 §5.1.5)
k_state   = HKDF-Expand(prk_m, "state", 32)     → sealing key for session state (§9)
kid       = lowercase hex of SHA-256(pk_sign)[0..4]   (8 ASCII characters)
```

The server exposes `pk_sign` (base64) for client configuration. `kid` identifies the master key in every
session response so that keys can be rotated later.

## 4. Session establishment

### 4.1 Request (client → server), JSON

```json
{ "v": 1,
  "kp": "<b64 X25519 public key, 32 B>",
  "type": "qwerty",
  "viewport": { "w": 390, "dpr": 3, "platform": "ios", "style": "ios" },
  "opts": { "maxLen": 32, "langs": ["ko", "en"] } }
```

| Field | Required | Meaning |
|---|---|---|
| `v` | yes | protocol version, must be `1` |
| `kp` | yes | client ephemeral X25519 public key |
| `type` | yes | `"qwerty"` or `"number"` |
| `viewport.w` | yes | keypad width in logical units (CSS px / pt / dp), `> 0` |
| `viewport.dpr` | yes | device pixel ratio, `> 0` |
| `viewport.platform` | yes | `"ios"`, `"android"`, or `"web"` |
| `viewport.style` | no | `"ios"` or `"material"`; default `"ios"` when platform is `ios`, else `"material"` |
| `opts.maxLen` | no | requested maximum input length |
| `opts.langs` | no | requested keyboard languages in switch order, 1–3 distinct codes from LAYOUT.md §3 (`"en"`, `"ko"`); anything else is `BAD_REQUEST`. Ignored for number pads |

Server-side options are supplied by the integrator's code, never by the client:

| Option | Default | Meaning |
|---|---|---|
| `ctx` | none | opaque binding string (user id, login attempt id). Must be presented again at decrypt |
| `layout` | `"shuffle"` | `"shuffle"`, `"full"`, or `"fixed"` (see LAYOUT.md §4) |
| `blank` | `"fixed"` | `"fixed"` or `"random"` (number pad only) |
| `languages` | none | keyboard languages in switch order (`"en,ko"`, `"ko"`, …). Overrides `opts.langs`; unknown or repeated codes are `UNSUPPORTED`. Ignored for number pads |
| `ttl` | 180 s | session lifetime |
| `maxLen` | 0 | if `> 0`, overrides the client's request |

Effective values:

```
dpr_milli = floor(dpr × 1000 + 0.5), clamped to [500, 10000]
w_milli   = floor(w × 1000 + 0.5)
W         = rnd(w_milli × dpr_milli, 1000000)   (device pixels, must be in [200, 8192])
style     = viewport.style, else "ios" if platform == "ios" else "material"
max_len   = server maxLen if > 0, else opts.maxLen if present, else 32 (qwerty) / 16 (number)
            then clamped to [1, cap]  (cap defaults to 256)
langs     = [] for number pads; else server languages if set, else opts.langs if present, else ["en", "ko"]
```

`rnd(a, b) = floor((2a + b) / (2b))` for `a ≥ 0, b > 0` (round half up). All geometry uses this helper so
that independent implementations agree bit for bit.

### 4.2 Server processing

```
sid          = random(16)
(s_sk, s_pk) = X25519 key pair
ss           = X25519(s_sk, c_pk)              — reject if all zero (low-order point)
prk          = HKDF-Extract(salt = "skp/v1" || sid, ikm = ss)
k_s2c        = HKDF-Expand(prk, "s2c" || c_pk || s_pk, 32)
k_c2s        = HKDF-Expand(prk, "c2s" || c_pk || s_pk, 32)
s_sk, ss, prk are wiped immediately.

seed         = random(32)
layouts      = LAYOUT(type, policy, blank, style, langs, W, dpr_milli, seed, gen = 0)   (LAYOUT.md)
tiles, popups = RENDER(layouts, style, dpr_milli)                                   (LAYOUT.md §6)
inner        = u32(len(json)) || json || u32(len(tiles)) || tiles || u32(len(popups)) || popups
ct           = AEAD(k_s2c, NONCE(0), "skp/v1/session" || sid, inner)
sig          = Ed25519.Sign(sk_sign, "skp/v1/session" || kid || sid || c_pk || s_pk || SHA-256(ct))
s2c_ctr      = 1
created      = now, expires = now + ttl
```

The server then produces the sealed blob (§9) and returns both the response and the blob to the caller.

### 4.3 Response (server → client), JSON

```json
{ "v": 1, "sid": "<b64url sid>", "kid": "a1b2c3d4", "sp": "<b64 s_pk>", "sig": "<b64 sig>", "ct": "<b64 ct>" }
```

### 4.4 Client processing

1. If a server public key is configured, verify `sig` over `"skp/v1/session" || kid || sid || c_pk || s_pk || SHA-256(ct)`.
   Reject on failure. If no key is configured the client proceeds but should warn in development builds.
2. Derive `k_s2c`, `k_c2s` exactly as in §4.2 (`ss = X25519(c_sk, s_pk)`), wipe `c_sk`, `ss`, `prk`.
3. Decrypt `ct` with `NONCE(0)` and aad `"skp/v1/session" || sid`. Parse the inner frame.
4. Decode the two PNG sprites, draw the chrome, blit tiles.

### 4.5 Inner JSON (inside `ct`)

```json
{ "v": 1, "type": "qwerty", "style": "ios", "w": 1170, "h": 648, "gen": 0, "maxLen": 32, "exp": 180,
  "langs": ["en", "ko"],
  "layouts": [
    { "id": 0, "mode": "lower", "lang": "en",
      "keys": [ { "r": [9, 24, 99, 126], "role": "char", "t": 0 }, ... ] },
    { "id": 1, "mode": "upper", "lang": "en", "keys": [ ... ] },
    { "id": 2, "mode": "lower", "lang": "ko", "keys": [ ... ] },
    { "id": 3, "mode": "upper", "lang": "ko", "keys": [ ... ] },
    { "id": 4, "mode": "sym1",  "keys": [ ... ] },
    { "id": 5, "mode": "sym2",  "keys": [ ... ] } ],
  "tile":  { "w": 99, "h": 126, "cols": 10, "count": 154 },
  "popup": { "w": 149, "h": 176, "cols": 10, "count": 154 } }
```

- `w`, `h`: keypad surface size in device pixels. All rects are relative to the surface's top-left corner.
- `langs`: the keyboard languages in switch order (LAYOUT.md §3); empty for number pads.
- `id`: `layout_id = (gen << 3) | slot`, where `slot` is the layer's position in `layouts` (0..7). Clients
  treat ids as opaque and echo them with each tap.
- `mode`: `lower`, `upper`, `sym1`, `sym2`, `number`; `lang` names the language of a `lower` / `upper` layer.
- `role`: one of `char`, `space`, `shift`, `backspace`, `mode_abc`, `mode_sym1`, `mode_sym2`, `done`,
  `blank`, `lang`.
- `t`: sprite cell index, present only for `role == "char"`. Indices are assigned in listing order (spatial
  order) and never depend on the character. Both sprites use the same index.
- `exp`: seconds until expiry at the time of rendering.
- Sprites are 8-bit grayscale PNG where the sample value is glyph coverage (255 = fully inked). Cell `t` is
  at column `t mod cols`, row `t div cols`. The client tints coverage with its theme's text color.
- Canonical field order (required for test vectors, recommended for all implementations): objects are
  emitted with keys in the order shown above (`lang` between `mode` and `keys`, only when present); numbers
  are integers; no whitespace.

Everything a client needs to *display* a key is in this object. Nothing in it identifies a character.

## 5. Nonces and directions

```
NONCE(ctr) = 0x00000000 || u64(ctr)
```

Each direction has its own key and its own counter. Server → client: session response uses counter 0, the
i-th relayout response uses counter i. Client → server: the batch input uses counter 0. Counters are never
reused under a key; a session that would exceed 2^32 messages must be abandoned.

## 6. Relayout

Sent when the client's viewport changes (rotation, resize, DPR change). The mapping slot → character is
unchanged; only geometry and tiles are regenerated.

Request: `{ "v": 1, "sid": "<b64url>", "viewport": { ... } }`

Server: open the sealed blob, check expiry, require `gen_count < 32`, append generation
`g = gen_count` with the previous generation's seed and the new viewport, then

```
inner = same framing as §4.2 with "gen": g and layout ids (g << 3) | mode
ct    = AEAD(k_s2c, NONCE(s2c_ctr), "skp/v1/relayout" || sid, inner);  s2c_ctr += 1
```

Response: `{ "v": 1, "sid": "<b64url>", "gen": g, "ct": "<b64>" }`. The caller must replace the stored
sealed blob with the new one; the old blob no longer decrypts inputs that reference generation `g`.
Taps recorded before the relayout keep their original `layout_id` and coordinates.

## 7. Input (client → server)

The client records one 8-byte record per *character* tap. Control keys (shift, mode switches, the language
key, done) are handled locally and never transmitted; backspace removes the last record. `space` is recorded
like a character. The batch is always padded to `max_len` records so its length reveals nothing.

```
record = u16 seq || u8 layout_id || u8 flags (0) || u16 x || u16 y        (x, y in device pixels)
batch  = u8 version (1) || u8 reserved (0) || u16 count || max_len × record   (padding records are all zero)
ct     = AEAD(k_c2s, NONCE(0), "skp/v1/input" || sid, batch)
```

Payload: `{ "v": 1, "sid": "<b64url>", "ct": "<b64>" }`. `seq` is the record's index (0-based). The client
must wipe `k_c2s`, `k_s2c`, and the records after producing the payload; the session is consumed.

## 8. Decrypt (server)

Inputs: sealed blob, payload JSON, `ctx` (optional), `keep` flag.

1. Open the sealed blob with `k_state` (§9). Reject if `now > expires` → `EXPIRED`.
2. `sid` in the payload must equal the blob's `sid` → else `SID_MISMATCH`.
3. `ctx`: if the blob's `ctx_hash` is all zero, `ctx` must be absent or empty; otherwise `SHA-256(ctx)` must
   equal `ctx_hash` (constant-time compare) → else `CTX_MISMATCH`.
4. Decrypt `ct` with `k_c2s`, `NONCE(0)`, aad `"skp/v1/input" || sid` → else `BAD_MAC`.
5. Validate: `version == 1`, `reserved == 0`, `len == 4 + 8 × max_len`, `count ≤ max_len`, every record with
   index `≥ count` is all zero, `seq == index`, `flags == 0`, `gen(layout_id) < gen_count`,
   `slot(layout_id) < layer count` of that generation, `x < W_gen`, `y < H_gen` → else `TAMPERED`.
6. For each record, regenerate the layout of its generation (deterministic from the blob) and hit-test (§10)
   the layer at `slot`. The hit key must have role `char` or `space` → else `TAMPERED`. Append its character.
7. Compose runs of Hangul jamo into syllables (HANGUL.md); every other code point is kept as is.
8. Return the UTF-8 result in locked memory. Unless `keep` is set, the caller's store must discard the blob;
   the library wipes every derived value before returning in all cases.

Errors never carry values or coordinates; they are enumerated codes only.

## 9. Sealed session state

```
sealed = nonce24 || XAEAD(k_state, nonce24, "skp/v1/state" || kid, state)
```

`state` (big-endian, fixed layout, `150 + 37 × gen_count` bytes):

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | version = 1 |
| 1 | 1 | type: 1 qwerty, 2 number |
| 2 | 1 | policy: 0 shuffle, 1 full, 2 fixed |
| 3 | 1 | blank: 0 fixed, 1 random |
| 4 | 1 | style: 1 ios, 2 material |
| 5 | 1 | gen_count (1..32) |
| 6 | 2 | max_len |
| 8 | 2 | flags (0) |
| 10 | 8 | created, unix seconds |
| 18 | 8 | expires, unix seconds |
| 26 | 16 | sid |
| 42 | 32 | ctx_hash = SHA-256(ctx), or all zero when no ctx |
| 74 | 32 | k_s2c |
| 106 | 32 | k_c2s |
| 138 | 8 | s2c_ctr |
| 146 | 1 | language count (0 for number pads, 1..3 for qwerty) |
| 147 | 3 | language ids in switch order (1 en, 2 ko), zero padded |
| 150 | 37 × n | generations: `seed[32] || u16 W || u16 dpr_milli || u8 platform (1 ios, 2 android, 3 web)` |

The blob is opaque to everyone but the server library. Stores may keep it anywhere; it reveals nothing
without `k_state`.

## 10. Hit testing

A tap `(x, y)` with `0 ≤ x < W`, `0 ≤ y < H` maps to the key with the smallest squared distance to its rect,
where `dx = max(rx − x, 0, x − (rx + rw − 1))`, `dy = max(ry − y, 0, y − (ry + rh − 1))`, `d² = dx² + dy²`.
Ties resolve to the key listed first. Points inside a rect have `d² = 0`. This reproduces native behaviour
where the gaps between keys belong to the nearest key.

## 11. Error codes

| Code | Name | Meaning |
|---|---|---|
| 0 | `OK` | |
| -1 | `NOMEM` | allocation failure |
| -2 | `INVALID_ARG` | bad pointer / size |
| -3 | `BAD_KEY` | master key unreadable or wrong length |
| -4 | `BAD_REQUEST` | JSON does not match the schema |
| -5 | `CRYPTO` | key agreement or signing failed |
| -6 | `EXPIRED` | session past `expires` |
| -7 | `BAD_MAC` | AEAD authentication failed |
| -8 | `TAMPERED` | payload structurally invalid or hit a non-character key |
| -9 | `CTX_MISMATCH` | binding context differs |
| -10 | `SID_MISMATCH` | payload does not belong to this blob |
| -11 | `RENDER` | glyph rendering failed |
| -12 | `IO` | file access failed |
| -13 | `UNSUPPORTED` | unknown version / option |

## 12. Test vectors

`spec/vectors/*.json` are produced by `tools/reference` with injected randomness (`s_sk`, `sid`, `seed`,
`nonce24`, `now`) and rendering disabled (empty sprite sections). Every implementation must reproduce:

- the server's response (`sp`, `sig`, `ct`) and sealed blob byte for byte,
- the client's derived keys and decrypted inner JSON,
- the client's input payload for a given tap list,
- the server's decrypted string (with Hangul composed).

`spec/vectors/hangul/compose.json` lists jamo sequences and the text they compose to (HANGUL.md).
