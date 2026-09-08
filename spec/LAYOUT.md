# secure-keypad Layout, version 1

Defines the geometry, the character sets, the shuffle procedure, and the sprite rules. Server-side
implementations (C core, Python reference) must agree bit for bit; clients only consume the result.

## 1. Units and rounding

- Metric constants are in *milli-units* (mu): 1 pt / dp / CSS px = 1000 mu.
- `dpr_milli` is the device pixel ratio × 1000 (PROTOCOL.md §4.1).
- `px(mu) = rnd(mu × dpr_milli, 1_000_000)` where `rnd(a, b) = floor((2a + b) / (2b))`.
- `W` is the surface width in device pixels (given). `H = px(H_mu)`.

Row helper `row(L, R, n, g)` places `n` keys between `L` and `R` (device px) with gap `g`:

```
keys_w  = (R − L) − (n − 1) × g
left_i  = L + i × g + rnd(i × keys_w, n)
right_i = L + i × g + rnd((i + 1) × keys_w, n)
rect_i  = [left_i, y, right_i − left_i, key_h]
```

## 2. Metrics

| Constant (mu) | iOS style | Material style |
|---|---|---|
| `inset_x` | 3000 | 4000 |
| `gap` | 6000 | 4000 |
| `top` | 8000 | 6000 |
| `key_h` | 42000 | 44000 |
| `pitch` (row to row) | 54000 | 52000 |
| `H` | 216000 | 214000 |
| `side_key` (shift, backspace, sym mode) | 42000 | 52000 |
| `mode_key` (bottom-row mode / done) | 87000 | 56000 |
| `num_key_h` | 46000 | 44000 |
| `glyph` (key label size) | 22500 | 22000 |
| `popup_glyph` | 34000 | 30000 |

Rows sit at `y_r = px(top) + r × px(pitch)`, `r = 0..3`. Initial values; refined against device screenshots
in milestone M2 by editing this table and regenerating vectors.

## 3. QWERTY (type 1)

A QWERTY keypad has 1 to 3 **languages** (`langs`, in switch order; the first is shown initially) and
two letter layers per language plus two shared symbol layers, listed in this order (the position is the
layer's *slot*, 0..7):

```
for each language in order: lower, upper
sym1, sym2
```

`lower` / `upper` carry the language code (`lang`); symbol layers do not. Two languages therefore give six
layers: `en/lower`, `en/upper`, `ko/lower`, `ko/upper`, `sym1`, `sym2`. Modes are named `lower`, `upper`,
`sym1`, `sym2`, `number` (§5) regardless of language.

Languages and their letter rows (before shuffling), 10 / 9 / 7 keys:

| code | id | rows | shift |
|---|---|---|---|
| `en` | 1 | `qwertyuiop` \| `asdfghjkl` \| `zxcvbnm` | ASCII uppercase |
| `ko` | 2 | `ㅂㅈㄷㄱㅅㅛㅕㅑㅐㅔ` \| `ㅁㄴㅇㄹㅎㅗㅓㅏㅣ` \| `ㅋㅌㅊㅍㅠㅜㅡ` | ㅂ→ㅃ ㅈ→ㅉ ㄷ→ㄸ ㄱ→ㄲ ㅅ→ㅆ ㅐ→ㅒ ㅔ→ㅖ, others unchanged |

`upper` is `lower` with the shift mapping applied in place. The Korean layout is the 2-set (두벌식) jamo
keyboard; the server composes syllables from the tapped jamo (HANGUL.md). The default language list, when
neither the integrator nor the client names one, is `en, ko`.

Symbol rows (before shuffling):

```
sym1  : "1234567890" | "-/:;()$&@\"" | ".,?!'"
sym2  : "[]{}#%^*+=" | "_\\|~<>€£¥•" | ".,?!'"
```

Geometry per layer (`g = px(gap)`, `ix = px(inset_x)`, `kh = px(key_h)`, `sk = px(side_key)`):

```
row 0 : row(ix, W − ix, 10, g)
row 1 : letters layers (lower, upper): 9 keys offset by half a key
          keys_w0 = (W − 2ix) − 9g
          L1 = ix + rnd(keys_w0 + 10g, 20);  R1 = W − L1
          row(L1, R1, 9, g)
        symbol layers (sym1, sym2): 10 keys, same geometry as row 0
          row(ix, W − ix, 10, g)
row 2 : letters layers (lower, upper):
          keys_w1 = (R1 − L1) − 8g;  step = rnd(keys_w1, 9) + g
          shift     = [ix, y2, sk, kh]
          letters   = row(L1 + step, R1 − step, 7, g)
          backspace = [W − ix − sk, y2, sk, kh]
        symbol layers (sym1, sym2):
          mode      = [ix, y2, sk, kh]          role mode_sym2 on sym1, mode_sym1 on sym2
          chars     = row(ix + sk + g, W − ix − sk − g, 5, g)
          backspace = [W − ix − sk, y2, sk, kh]
row 3 : mw = min(px(mode_key), rnd(W, 4))
        one language:
          mode  = [ix, y3, mw, kh]                role mode_sym1 on letters layers, mode_abc on symbol layers
          space = [ix + mw + g, y3, W − 2ix − 2mw − 2g, kh]
          done  = [W − ix − mw, y3, mw, kh]
        two or more languages (lw = min(sk, mw)):
          mode  = [ix, y3, lw, kh]
          lang  = [ix + lw + g, y3, lw, kh]       role lang (globe key), on every qwerty layer
          space = [ix + 2lw + 2g, y3, W − 2ix − 2lw − mw − 3g, kh]
          done  = [W − ix − mw, y3, mw, kh]
```

Listing order of keys: row 0 left to right, row 1, row 2 (`shift`/`mode`, characters, `backspace`), row 3
(`mode`, `lang` if present, `space`, `done`).

## 4. Shuffle

Randomness comes from a deterministic stream `DRBG(seed)` = ChaCha20 (IETF, RFC 8439 block function)
keystream with `key = seed` and `nonce = "LibsodiumDRG"` (this is libsodium's
`randombytes_buf_deterministic`). Readers consume the stream sequentially:

```
u32()      : next 4 bytes, big-endian
uniform(n) : if n ≤ 1 → 0;  limit = 2^32 − (2^32 mod n);  loop r = u32() until r < limit;  return r mod n
fy(list)   : for i = len − 1 down to 1: j = uniform(i + 1); swap(list[i], list[j])
```

Policies:

| policy | qwerty | number |
|---|---|---|
| `shuffle` (0) | for each language in order, `fy` each of its three rows; then each row of `sym1`, then each row of `sym2` (stream order). `upper` mirrors `lower` through the shift mapping. | `fy(digits)` |
| `full` (1) | for each language in order, `fy` its concatenated 26 characters and split 10/9/7; then `sym1` (25) split 10/10/5; then `sym2` | same as shuffle |
| `fixed` (2) | no stream consumption | the native phone pad `1 2 3 / 4 5 6 / 7 8 9 / blank 0 backspace`: digits `1…9, 0` in order, blank in cell 9 (`blank` is ignored), no stream consumption |

Number pad blank placement follows the digit shuffle: `blank = fixed` puts the blank in cell 9;
`blank = random` draws `b = uniform(11)` and blanks the `b`-th cell among cells 0..10 (cell 11 is always
`backspace`). Digits fill the remaining cells in row-major order. As with QWERTY, a `fixed` number pad lets
coordinates reveal digits; the server logs the same warning.

## 5. Number pad (type 2)

Single layer (slot 0), mode `number`, no languages (`langs` is empty). Grid 3 × 4, cell `c = r × 3 + col`,
rows at `y_r`, `key_h = px(num_key_h)`, columns `row(ix, W − ix, 3, g)`. Roles: 10 × `char` (digits), one
`blank`, `backspace` at cell 11.

## 6. Sprites

- `tile.w = max(rect.w over char keys)`, `tile.h = kh` (or `px(num_key_h)`), `tile.cols = 10`,
  `tile.count = number of char keys across all layers` (52 per language + 50 for the symbol layers: 102 for
  one language, 154 for two; 10 for number).
- `popup.w = min(rnd(3 × tile.w, 2), rnd(3 × tile.h, 2))`, `popup.h = rnd(7 × tile.h, 5)`, same `cols` and
  `count`. The width cap keeps number-pad popup cells (whose keys are very wide) compact.
- Sprite image size = `cols × cell.w` by `ceil(count / cols) × cell.h`, 8-bit grayscale PNG. Unused cells are
  zero.
- Glyph rendering: font `Inter-Regular` for iOS style, `Roboto-Regular` for Material; glyphs those fonts
  lack (the Hangul jamo) come from a fallback font, by default a Noto Sans KR subset; size `px(glyph)` for
  tiles, `px(popup_glyph)` for popups. The glyph's ink box is centred horizontally in the cell. Vertically,
  a shared baseline is used for every cell of a sprite: `baseline = rnd(cell.h + cap_h, 2)` where `cap_h`
  is the ink height of `H` in the style font at the same size. This mirrors native keyboards, where labels
  share a baseline.
- Renderers may differ in anti-aliasing; sprites are therefore excluded from test vectors (vectors are
  produced with rendering disabled, yielding zero-length sprite sections).

## 7. Client drawing contract

For each key: draw the chrome for its role (background, shadow, icon for control keys) at `r`; for `char`
keys blit sprite cell `t` centred in `r`, tinted with the theme text color, without scaling. On press, draw
the platform's feedback (popup bubble with popup cell `t`, or darkened key). Never draw text for `char`
keys; the client has no text to draw.

Language state: the client shows the `lower` / `upper` layers of the current language (initially
`langs[0]`); the `lang` key (globe icon) advances to the next language, returning to the letter layers with
shift off. With two or more languages the space bar may show the current language's name (English,
한국어). Neither the language switch nor the language itself is transmitted: the layout id of each tap
identifies the layer, and therefore the language, to the server.
