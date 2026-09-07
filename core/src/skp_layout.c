#include "skp_internal.h"
#include "../third_party/cJSON.h"
#include <stdlib.h>

const char *const skp_role_names[] = {"char",      "space",     "shift",     "backspace", "mode_abc",
                                      "mode_sym1", "mode_sym2", "done",      "blank"};

typedef struct {
    int64_t inset_x, gap, top, key_h, pitch, H, side_key, mode_key, num_key_h, glyph, popup_glyph;
} skp_metrics;

static const skp_metrics METRICS_IOS = {3000, 6000, 8000, 42000, 54000, 216000, 42000, 87000, 46000, 22500, 34000};
static const skp_metrics METRICS_MATERIAL = {4000, 4000, 6000, 44000, 52000, 214000, 52000, 56000, 44000, 22000, 30000};

static const uint32_t ROW_L0[] = {'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p'};
static const uint32_t ROW_L1[] = {'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l'};
static const uint32_t ROW_L2[] = {'z', 'x', 'c', 'v', 'b', 'n', 'm'};
static const uint32_t ROW_S10[] = {'1', '2', '3', '4', '5', '6', '7', '8', '9', '0'};
static const uint32_t ROW_S11[] = {'-', '/', ':', ';', '(', ')', '$', '&', '@', '"'};
static const uint32_t ROW_S12[] = {'.', ',', '?', '!', '\''};
static const uint32_t ROW_S20[] = {'[', ']', '{', '}', '#', '%', '^', '*', '+', '='};
static const uint32_t ROW_S21[] = {'_', '\\', '|', '~', '<', '>', 0x20AC, 0x00A3, 0x00A5, 0x2022};
static const uint32_t ROW_S22[] = {'.', ',', '?', '!', '\''};

int64_t skp_rnd(int64_t a, int64_t b) { return (2 * a + b) / (2 * b); }
int32_t skp_px(int64_t mu, uint32_t dpr_milli) { return (int32_t)skp_rnd(mu * (int64_t)dpr_milli, 1000000); }

/* ---- deterministic stream ------------------------------------------------------------------ */
typedef struct {
    uint8_t seed[SKP_SEED_BYTES];
    uint8_t *buf;
    size_t len, pos;
} skp_drbg;

static int drbg_init(skp_drbg *d, const uint8_t seed[SKP_SEED_BYTES]) {
    memcpy(d->seed, seed, SKP_SEED_BYTES);
    d->len = 4096;
    d->pos = 0;
    d->buf = sodium_malloc(d->len);
    if (!d->buf)
        return SKP_ERR_NOMEM;
    randombytes_buf_deterministic(d->buf, d->len, d->seed);
    return SKP_OK;
}

static void drbg_free(skp_drbg *d) {
    if (d->buf)
        sodium_free(d->buf);
    sodium_memzero(d->seed, sizeof d->seed);
    d->buf = NULL;
}

static uint32_t drbg_u32(skp_drbg *d) {
    if (d->pos + 4 > d->len) {
        size_t nl = d->len * 2;
        uint8_t *nb = sodium_malloc(nl);
        if (!nb)
            return 0; /* cannot happen in practice: the stream is consumed ~100 times per layout */
        randombytes_buf_deterministic(nb, nl, d->seed);
        sodium_free(d->buf);
        d->buf = nb;
        d->len = nl;
    }
    uint32_t v = ((uint32_t)d->buf[d->pos] << 24) | ((uint32_t)d->buf[d->pos + 1] << 16) |
                 ((uint32_t)d->buf[d->pos + 2] << 8) | (uint32_t)d->buf[d->pos + 3];
    d->pos += 4;
    return v;
}

static uint32_t drbg_uniform(skp_drbg *d, uint32_t n) {
    if (n <= 1)
        return 0;
    /* 64-bit limit: for n dividing 2^32 the limit is 2^32 itself and every draw is accepted */
    uint64_t limit = 0x100000000ULL - (0x100000000ULL % n);
    for (;;) {
        uint32_t r = drbg_u32(d);
        if ((uint64_t)r < limit)
            return r % n;
    }
}

static void drbg_fy(skp_drbg *d, uint32_t *items, int n) {
    for (int i = n - 1; i > 0; i--) {
        uint32_t j = drbg_uniform(d, (uint32_t)i + 1);
        uint32_t t = items[i];
        items[i] = items[j];
        items[j] = t;
    }
}

/* ---- geometry ------------------------------------------------------------------------------- */
typedef struct {
    int32_t x, y, w, h;
} rect_t;

static void row_rects(rect_t *out, int32_t L, int32_t R, int n, int32_t g, int32_t y, int32_t kh) {
    int64_t keys_w = (int64_t)(R - L) - (int64_t)(n - 1) * g;
    for (int i = 0; i < n; i++) {
        int32_t left = L + i * g + (int32_t)skp_rnd((int64_t)i * keys_w, n);
        int32_t right = L + i * g + (int32_t)skp_rnd((int64_t)(i + 1) * keys_w, n);
        out[i].x = left;
        out[i].y = y;
        out[i].w = right - left;
        out[i].h = kh;
    }
}

static void add_key(skp_layer *layer, rect_t r, skp_role role, uint32_t cp) {
    skp_key *k = &layer->keys[layer->nkeys++];
    k->x = r.x;
    k->y = r.y;
    k->w = r.w;
    k->h = r.h;
    k->role = role;
    k->cp = cp;
    k->t = -1;
}

static void copy_row(uint32_t *dst, const uint32_t *src, int n) { memcpy(dst, src, sizeof(uint32_t) * (size_t)n); }

static void full_shuffle(skp_drbg *d, uint32_t *r0, int n0, uint32_t *r1, int n1, uint32_t *r2, int n2) {
    uint32_t flat[32];
    copy_row(flat, r0, n0);
    copy_row(flat + n0, r1, n1);
    copy_row(flat + n0 + n1, r2, n2);
    drbg_fy(d, flat, n0 + n1 + n2);
    copy_row(r0, flat, n0);
    copy_row(r1, flat + n0, n1);
    copy_row(r2, flat + n0 + n1, n2);
    sodium_memzero(flat, sizeof flat);
}

static uint32_t upper_of(uint32_t c) { return (c >= 'a' && c <= 'z') ? c - 32 : c; }

int skp_layout_build(skp_layout *out, int type, int policy, int blank, int style, int32_t W, uint32_t dpr_milli,
                     const uint8_t seed[SKP_SEED_BYTES]) {
    memset(out, 0, sizeof *out);
    const skp_metrics *m = style == SKP_STYLE_IOS ? &METRICS_IOS : &METRICS_MATERIAL;
    out->type = type;
    out->style = style;
    out->W = W;
    out->dpr_milli = dpr_milli;
    int32_t ix = skp_px(m->inset_x, dpr_milli), g = skp_px(m->gap, dpr_milli), kh = skp_px(m->key_h, dpr_milli);
    int32_t sk = skp_px(m->side_key, dpr_milli), top = skp_px(m->top, dpr_milli), pitch = skp_px(m->pitch, dpr_milli);
    out->H = skp_px(m->H, dpr_milli);
    out->glyph_px = skp_px(m->glyph, dpr_milli);
    out->popup_glyph_px = skp_px(m->popup_glyph, dpr_milli);
    int32_t ys[4];
    for (int r = 0; r < 4; r++)
        ys[r] = top + r * pitch;

    skp_drbg d;
    int rc = drbg_init(&d, seed);
    if (rc)
        return rc;

    if (type == SKP_TYPE_QWERTY) {
        uint32_t l0[10], l1[9], l2[7], s10[10], s11[10], s12[5], s20[10], s21[10], s22[5];
        copy_row(l0, ROW_L0, 10);
        copy_row(l1, ROW_L1, 9);
        copy_row(l2, ROW_L2, 7);
        copy_row(s10, ROW_S10, 10);
        copy_row(s11, ROW_S11, 10);
        copy_row(s12, ROW_S12, 5);
        copy_row(s20, ROW_S20, 10);
        copy_row(s21, ROW_S21, 10);
        copy_row(s22, ROW_S22, 5);
        if (policy == SKP_POLICY_SHUFFLE) {
            drbg_fy(&d, l0, 10);
            drbg_fy(&d, l1, 9);
            drbg_fy(&d, l2, 7);
            drbg_fy(&d, s10, 10);
            drbg_fy(&d, s11, 10);
            drbg_fy(&d, s12, 5);
            drbg_fy(&d, s20, 10);
            drbg_fy(&d, s21, 10);
            drbg_fy(&d, s22, 5);
        } else if (policy == SKP_POLICY_FULL) {
            full_shuffle(&d, l0, 10, l1, 9, l2, 7);
            full_shuffle(&d, s10, 10, s11, 10, s12, 5);
            full_shuffle(&d, s20, 10, s21, 10, s22, 5);
        } else if (policy != SKP_POLICY_FIXED) {
            drbg_free(&d);
            return SKP_ERR_UNSUPPORTED;
        }
        rect_t row0[10], row1[9], row1s[10], letters2[7], syms2[5];
        row_rects(row0, ix, W - ix, 10, g, ys[0], kh);
        int64_t keys_w0 = (int64_t)(W - 2 * ix) - 9 * (int64_t)g;
        int32_t L1 = ix + (int32_t)skp_rnd(keys_w0 + 10 * (int64_t)g, 20);
        int32_t R1 = W - L1;
        row_rects(row1, L1, R1, 9, g, ys[1], kh);
        row_rects(row1s, ix, W - ix, 10, g, ys[1], kh);
        int64_t keys_w1 = (int64_t)(R1 - L1) - 8 * (int64_t)g;
        int32_t step = (int32_t)skp_rnd(keys_w1, 9) + g;
        row_rects(letters2, L1 + step, R1 - step, 7, g, ys[2], kh);
        row_rects(syms2, ix + sk + g, W - ix - sk - g, 5, g, ys[2], kh);
        rect_t left2 = {ix, ys[2], sk, kh};
        rect_t backspace2 = {W - ix - sk, ys[2], sk, kh};
        int32_t mw = skp_px(m->mode_key, dpr_milli);
        int32_t wq = (int32_t)skp_rnd(W, 4);
        if (wq < mw)
            mw = wq;
        rect_t mode3 = {ix, ys[3], mw, kh};
        rect_t space3 = {ix + mw + g, ys[3], W - 2 * ix - 2 * mw - 2 * g, kh};
        rect_t done3 = {W - ix - mw, ys[3], mw, kh};

        const uint32_t *rows[4][3] = {{l0, l1, l2}, {NULL, NULL, NULL}, {s10, s11, s12}, {s20, s21, s22}};
        uint32_t u0[10], u1[9], u2[7];
        for (int i = 0; i < 10; i++)
            u0[i] = upper_of(l0[i]);
        for (int i = 0; i < 9; i++)
            u1[i] = upper_of(l1[i]);
        for (int i = 0; i < 7; i++)
            u2[i] = upper_of(l2[i]);
        rows[1][0] = u0;
        rows[1][1] = u1;
        rows[1][2] = u2;
        out->nlayers = 4;
        for (int mode = 0; mode < 4; mode++) {
            skp_layer *layer = &out->layers[mode];
            layer->mode = mode;
            layer->nkeys = 0;
            int letters = (mode == SKP_MODE_LOWER || mode == SKP_MODE_UPPER);
            for (int i = 0; i < 10; i++)
                add_key(layer, row0[i], SKP_ROLE_CHAR, rows[mode][0][i]);
            if (letters)
                for (int i = 0; i < 9; i++)
                    add_key(layer, row1[i], SKP_ROLE_CHAR, rows[mode][1][i]);
            else
                for (int i = 0; i < 10; i++)
                    add_key(layer, row1s[i], SKP_ROLE_CHAR, rows[mode][1][i]);
            if (letters) {
                add_key(layer, left2, SKP_ROLE_SHIFT, 0);
                for (int i = 0; i < 7; i++)
                    add_key(layer, letters2[i], SKP_ROLE_CHAR, rows[mode][2][i]);
                add_key(layer, backspace2, SKP_ROLE_BACKSPACE, 0);
                add_key(layer, mode3, SKP_ROLE_MODE_SYM1, 0);
            } else {
                add_key(layer, left2, mode == SKP_MODE_SYM1 ? SKP_ROLE_MODE_SYM2 : SKP_ROLE_MODE_SYM1, 0);
                for (int i = 0; i < 5; i++)
                    add_key(layer, syms2[i], SKP_ROLE_CHAR, rows[mode][2][i]);
                add_key(layer, backspace2, SKP_ROLE_BACKSPACE, 0);
                add_key(layer, mode3, SKP_ROLE_MODE_ABC, 0);
            }
            add_key(layer, space3, SKP_ROLE_SPACE, ' ');
            add_key(layer, done3, SKP_ROLE_DONE, 0);
        }
        out->tile_h = kh;
        /* the shuffled rows are the secret mapping: do not leave them on the stack */
        sodium_memzero(l0, sizeof l0);
        sodium_memzero(l1, sizeof l1);
        sodium_memzero(l2, sizeof l2);
        sodium_memzero(u0, sizeof u0);
        sodium_memzero(u1, sizeof u1);
        sodium_memzero(u2, sizeof u2);
        sodium_memzero(s10, sizeof s10);
        sodium_memzero(s11, sizeof s11);
        sodium_memzero(s12, sizeof s12);
        sodium_memzero(s20, sizeof s20);
        sodium_memzero(s21, sizeof s21);
        sodium_memzero(s22, sizeof s22);
    } else if (type == SKP_TYPE_NUMBER) {
        uint32_t digits[10] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'};
        drbg_fy(&d, digits, 10);
        uint32_t b = blank == SKP_BLANK_RANDOM ? drbg_uniform(&d, 11) : 9;
        int32_t nkh = skp_px(m->num_key_h, dpr_milli);
        rect_t cols[3];
        row_rects(cols, ix, W - ix, 3, g, 0, nkh);
        out->nlayers = 1;
        skp_layer *layer = &out->layers[0];
        layer->mode = SKP_MODE_NUMBER;
        layer->nkeys = 0;
        int di = 0;
        for (int c = 0; c < 12; c++) {
            int r = c / 3, col = c % 3;
            rect_t rect = {cols[col].x, ys[r], cols[col].w, nkh};
            if (c == 11)
                add_key(layer, rect, SKP_ROLE_BACKSPACE, 0);
            else if ((uint32_t)c == b)
                add_key(layer, rect, SKP_ROLE_BLANK, 0);
            else
                add_key(layer, rect, SKP_ROLE_CHAR, digits[di++]);
        }
        out->tile_h = nkh;
        sodium_memzero(digits, sizeof digits);
    } else {
        drbg_free(&d);
        return SKP_ERR_UNSUPPORTED;
    }
    drbg_free(&d);

    int32_t t = 0, tw = 0;
    for (int l = 0; l < out->nlayers; l++)
        for (int k = 0; k < out->layers[l].nkeys; k++) {
            skp_key *key = &out->layers[l].keys[k];
            if (key->role == SKP_ROLE_CHAR) {
                key->t = t++;
                if (key->w > tw)
                    tw = key->w;
            }
        }
    out->tile_w = tw;
    out->tile_count = t;
    out->popup_w = (int32_t)skp_rnd(3 * (int64_t)tw, 2);
    {
        int32_t cap = (int32_t)skp_rnd(3 * (int64_t)out->tile_h, 2);
        if (out->popup_w > cap)
            out->popup_w = cap;
    }
    out->popup_h = (int32_t)skp_rnd(7 * (int64_t)out->tile_h, 5);
    return SKP_OK;
}

const skp_layer *skp_layout_layer(const skp_layout *l, int mode) {
    for (int i = 0; i < l->nlayers; i++)
        if (l->layers[i].mode == mode)
            return &l->layers[i];
    return NULL;
}

const skp_key *skp_layout_hit(const skp_layer *layer, int32_t x, int32_t y) {
    const skp_key *best = NULL;
    int64_t best_d = 0;
    for (int i = 0; i < layer->nkeys; i++) {
        const skp_key *k = &layer->keys[i];
        int64_t dx = 0, dy = 0;
        if (k->x - x > dx)
            dx = k->x - x;
        if (x - (k->x + k->w - 1) > dx)
            dx = x - (k->x + k->w - 1);
        if (k->y - y > dy)
            dy = k->y - y;
        if (y - (k->y + k->h - 1) > dy)
            dy = y - (k->y + k->h - 1);
        int64_t dd = dx * dx + dy * dy;
        if (!best || dd < best_d) {
            best = k;
            best_d = dd;
        }
    }
    return best;
}

static const char *mode_name(int mode) {
    static const char *const names[] = {"lower", "upper", "sym1", "sym2", "number"};
    return names[mode];
}

char *skp_layout_json(const skp_layout *l, int gen, uint32_t max_len, int64_t exp) {
    cJSON *root = cJSON_CreateObject();
    if (!root)
        return NULL;
    cJSON_AddNumberToObject(root, "v", SKP_PROTOCOL_VERSION);
    cJSON_AddStringToObject(root, "type", l->type == SKP_TYPE_QWERTY ? "qwerty" : "number");
    cJSON_AddStringToObject(root, "style", l->style == SKP_STYLE_IOS ? "ios" : "material");
    cJSON_AddNumberToObject(root, "w", l->W);
    cJSON_AddNumberToObject(root, "h", l->H);
    cJSON_AddNumberToObject(root, "gen", gen);
    cJSON_AddNumberToObject(root, "maxLen", (double)max_len);
    cJSON_AddNumberToObject(root, "exp", (double)exp);
    cJSON *layouts = cJSON_AddArrayToObject(root, "layouts");
    for (int i = 0; i < l->nlayers; i++) {
        const skp_layer *layer = &l->layers[i];
        cJSON *lo = cJSON_CreateObject();
        cJSON_AddNumberToObject(lo, "id", (gen << 3) | layer->mode);
        cJSON_AddStringToObject(lo, "mode", mode_name(layer->mode));
        cJSON *keys = cJSON_AddArrayToObject(lo, "keys");
        for (int k = 0; k < layer->nkeys; k++) {
            const skp_key *key = &layer->keys[k];
            cJSON *ko = cJSON_CreateObject();
            cJSON *r = cJSON_AddArrayToObject(ko, "r");
            cJSON_AddItemToArray(r, cJSON_CreateNumber(key->x));
            cJSON_AddItemToArray(r, cJSON_CreateNumber(key->y));
            cJSON_AddItemToArray(r, cJSON_CreateNumber(key->w));
            cJSON_AddItemToArray(r, cJSON_CreateNumber(key->h));
            cJSON_AddStringToObject(ko, "role", skp_role_names[key->role]);
            if (key->role == SKP_ROLE_CHAR)
                cJSON_AddNumberToObject(ko, "t", key->t);
            cJSON_AddItemToArray(keys, ko);
        }
        cJSON_AddItemToArray(layouts, lo);
    }
    cJSON *tile = cJSON_AddObjectToObject(root, "tile");
    cJSON_AddNumberToObject(tile, "w", l->tile_w);
    cJSON_AddNumberToObject(tile, "h", l->tile_h);
    cJSON_AddNumberToObject(tile, "cols", 10);
    cJSON_AddNumberToObject(tile, "count", l->tile_count);
    cJSON *popup = cJSON_AddObjectToObject(root, "popup");
    cJSON_AddNumberToObject(popup, "w", l->popup_w);
    cJSON_AddNumberToObject(popup, "h", l->popup_h);
    cJSON_AddNumberToObject(popup, "cols", 10);
    cJSON_AddNumberToObject(popup, "count", l->tile_count);
    char *s = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return s;
}
