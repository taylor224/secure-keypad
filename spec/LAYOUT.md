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

Four layers, listed in this order: `lower` (mode 0), `upper` (1), `sym1` (2), `sym2` (3).

Character rows (before shuffling):

```
lower : "qwertyuiop" | "asdfghjkl" | "zxcvbnm"
upper : uppercase of lower, same positions
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
        mode  = [ix, y3, mw, kh]                role mode_sym1 on letters layers, mode_abc on symbol layers
        space = [ix + mw + g, y3, W − 2ix − 2mw − 2g, kh]
        done  = [W − ix − mw, y3, mw, kh]
```

Listing order (and therefore slot order): row 0 left to right, row 1, row 2 (`shift`/`mode`, characters,
`backspace`), row 3 (`mode`, `space`, `done`).

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
| `shuffle` (0) | `fy` each row of `lower`, then each row of `sym1`, then each row of `sym2` (stream order). `upper` mirrors `lower`. | `fy(digits)` |
| `full` (1) | `fy` the concatenated characters of `lower` (26), split 10/9/7; then `sym1` (25) split 10/10/5; then `sym2` | same as shuffle |
| `fixed` (2) | no stream consumption | `fy(digits)` (a fixed number pad is never generated) |

Number pad blank placement follows the digit shuffle: `blank = fixed` puts the blank in cell 9;
`blank = random` draws `b = uniform(11)` and blanks the `b`-th cell among cells 0..10 (cell 11 is always
`backspace`). Digits fill the remaining cells in row-major order.

## 5. Number pad (type 2)

Single layer, mode 4. Grid 3 × 4, cell `c = r × 3 + col`, rows at `y_r`, `key_h = px(num_key_h)`,
columns `row(ix, W − ix, 3, g)`. Roles: 10 × `char` (digits), one `blank`, `backspace` at cell 11.

## 6. Sprites

- `tile.w = max(rect.w over char keys)`, `tile.h = kh` (or `px(num_key_h)`), `tile.cols = 10`,
  `tile.count = number of char keys across all layers` (102 for qwerty, 10 for number).
- `popup.w = min(rnd(3 × tile.w, 2), rnd(3 × tile.h, 2))`, `popup.h = rnd(7 × tile.h, 5)`, same `cols` and
  `count`. The width cap keeps number-pad popup cells (whose keys are very wide) compact.
- Sprite image size = `cols × cell.w` by `ceil(count / cols) × cell.h`, 8-bit grayscale PNG. Unused cells are
  zero.
- Glyph rendering: font `Inter-Regular` for iOS style, `Roboto-Regular` for Material; size `px(glyph)` for
  tiles, `px(popup_glyph)` for popups. The glyph's ink box is centred horizontally in the cell. Vertically,
  a shared baseline is used for every cell of a sprite: `baseline = rnd(cell.h + cap_h, 2)` where `cap_h`
  is the ink height of `H` at the same size. This mirrors native keyboards, where labels share a baseline.
- Renderers may differ in anti-aliasing; sprites are therefore excluded from test vectors (vectors are
  produced with rendering disabled, yielding zero-length sprite sections).

## 7. Client drawing contract

For each key: draw the chrome for its role (background, shadow, icon for control keys) at `r`; for `char`
keys blit sprite cell `t` centred in `r`, tinted with the theme text color, without scaling. On press, draw
the platform's feedback (popup bubble with popup cell `t`, or darkened key). Never draw text for `char`
keys; the client has no text to draw.
