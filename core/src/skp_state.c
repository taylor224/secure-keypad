#include "skp_internal.h"
#include <stdlib.h>

static void put16(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}
static void put64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++)
        p[i] = (uint8_t)(v >> (56 - 8 * i));
}
static uint32_t get16(const uint8_t *p) { return ((uint32_t)p[0] << 8) | p[1]; }
static uint64_t get64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++)
        v = (v << 8) | p[i];
    return v;
}

static size_t state_size(const skp_state *st) { return SKP_STATE_HEAD + (size_t)SKP_STATE_GEN * (size_t)st->ngens; }

static void state_pack(const skp_state *st, uint8_t *p) {
    p[0] = 1;
    p[1] = st->type;
    p[2] = st->policy;
    p[3] = st->blank;
    p[4] = st->style;
    p[5] = (uint8_t)st->ngens;
    put16(p + 6, st->max_len);
    put16(p + 8, 0);
    put64(p + 10, (uint64_t)st->created);
    put64(p + 18, (uint64_t)st->expires);
    memcpy(p + 26, st->sid, 16);
    memcpy(p + 42, st->ctx_hash, 32);
    memcpy(p + 74, st->k_s2c, 32);
    memcpy(p + 106, st->k_c2s, 32);
    put64(p + 138, st->s2c_ctr);
    p[146] = (uint8_t)st->nlangs;
    memset(p + 147, 0, 3);
    for (int i = 0; i < st->nlangs && i < SKP_MAX_LANGS; i++)
        p[147 + i] = st->langs[i];
    for (int i = 0; i < st->ngens; i++) {
        uint8_t *g = p + SKP_STATE_HEAD + (size_t)i * SKP_STATE_GEN;
        memcpy(g, st->gens[i].seed, 32);
        put16(g + 32, (uint32_t)st->gens[i].W);
        put16(g + 34, st->gens[i].dpr_milli);
        g[36] = st->gens[i].platform;
    }
}

static int state_unpack(skp_state *st, const uint8_t *p, size_t len) {
    if (len < SKP_STATE_HEAD)
        return SKP_ERR_TAMPERED;
    int n = p[5];
    if (p[0] != 1 || n < 1 || n > SKP_MAX_GENS || get16(p + 8) != 0 ||
        len != SKP_STATE_HEAD + (size_t)SKP_STATE_GEN * (size_t)n)
        return SKP_ERR_TAMPERED;
    memset(st, 0, sizeof *st);
    st->type = p[1];
    st->policy = p[2];
    st->blank = p[3];
    st->style = p[4];
    st->ngens = n;
    st->max_len = get16(p + 6);
    st->created = (int64_t)get64(p + 10);
    st->expires = (int64_t)get64(p + 18);
    memcpy(st->sid, p + 26, 16);
    memcpy(st->ctx_hash, p + 42, 32);
    memcpy(st->k_s2c, p + 74, 32);
    memcpy(st->k_c2s, p + 106, 32);
    st->s2c_ctr = get64(p + 138);
    st->nlangs = p[146];
    if (st->nlangs > SKP_MAX_LANGS)
        return SKP_ERR_TAMPERED;
    for (int i = 0; i < SKP_MAX_LANGS; i++) {
        uint8_t id = p[147 + i];
        if (i < st->nlangs) {
            if (!skp_lang_code(id))
                return SKP_ERR_TAMPERED;
            for (int k = 0; k < i; k++)
                if (st->langs[k] == id)
                    return SKP_ERR_TAMPERED;
            st->langs[i] = id;
        } else if (id != 0) {
            return SKP_ERR_TAMPERED;
        }
    }
    for (int i = 0; i < n; i++) {
        const uint8_t *g = p + SKP_STATE_HEAD + (size_t)i * SKP_STATE_GEN;
        memcpy(st->gens[i].seed, g, 32);
        st->gens[i].W = (int32_t)get16(g + 32);
        st->gens[i].dpr_milli = get16(g + 34);
        st->gens[i].platform = g[36];
    }
    if ((st->type != SKP_TYPE_QWERTY && st->type != SKP_TYPE_NUMBER) || st->policy > 2 || st->blank > 1 ||
        (st->style != SKP_STYLE_IOS && st->style != SKP_STYLE_MATERIAL) || st->max_len == 0)
        return SKP_ERR_TAMPERED;
    if ((st->type == SKP_TYPE_QWERTY && st->nlangs < 1) || (st->type == SKP_TYPE_NUMBER && st->nlangs != 0))
        return SKP_ERR_TAMPERED;
    return SKP_OK;
}

/* key page guard: see skp.c */
int skp_ctx_keys_acquire(const skp_ctx *ctx);
void skp_ctx_keys_release(const skp_ctx *ctx);

int skp_state_seal(const skp_ctx *ctx, const skp_state *st, const uint8_t nonce24[24], skp_buf *out) {
    size_t n = state_size(st);
    uint8_t *pt = sodium_malloc(n);
    if (!pt)
        return SKP_ERR_NOMEM;
    state_pack(st, pt);
    int rc = skp_buf_alloc(out, 24 + n + crypto_aead_xchacha20poly1305_ietf_ABYTES);
    if (rc) {
        sodium_free(pt);
        return rc;
    }
    memcpy(out->data, nonce24, 24);
    uint8_t aad[32];
    size_t aad_len = strlen(SKP_AAD_STATE);
    memcpy(aad, SKP_AAD_STATE, aad_len);
    memcpy(aad + aad_len, ctx->kid, 8);
    aad_len += 8;
    unsigned long long clen = 0;
    if (skp_ctx_keys_acquire(ctx) != 0) {
        sodium_free(pt);
        skp_buf_free(out);
        return SKP_ERR_CRYPTO;
    }
    rc = crypto_aead_xchacha20poly1305_ietf_encrypt(out->data + 24, &clen, pt, n, aad, aad_len, NULL, nonce24,
                                                    ctx->k_state);
    skp_ctx_keys_release(ctx);
    sodium_free(pt);
    if (rc != 0) {
        skp_buf_free(out);
        return SKP_ERR_CRYPTO;
    }
    out->len = 24 + (size_t)clen;
    return SKP_OK;
}

int skp_state_unseal(const skp_ctx *ctx, const uint8_t *sealed, size_t len, skp_state *out) {
    if (!sealed || len < 24 + crypto_aead_xchacha20poly1305_ietf_ABYTES + SKP_STATE_HEAD)
        return SKP_ERR_TAMPERED;
    size_t clen = len - 24;
    uint8_t *pt = sodium_malloc(clen);
    if (!pt)
        return SKP_ERR_NOMEM;
    uint8_t aad[32];
    size_t aad_len = strlen(SKP_AAD_STATE);
    memcpy(aad, SKP_AAD_STATE, aad_len);
    memcpy(aad + aad_len, ctx->kid, 8);
    aad_len += 8;
    unsigned long long plen = 0;
    if (skp_ctx_keys_acquire(ctx) != 0) {
        sodium_free(pt);
        return SKP_ERR_CRYPTO;
    }
    int rc = crypto_aead_xchacha20poly1305_ietf_decrypt(pt, &plen, NULL, sealed + 24, clen, aad, aad_len, sealed,
                                                        ctx->k_state);
    skp_ctx_keys_release(ctx);
    if (rc != 0) {
        sodium_free(pt);
        return SKP_ERR_BAD_MAC;
    }
    rc = state_unpack(out, pt, (size_t)plen);
    sodium_free(pt);
    if (rc)
        skp_state_wipe(out);
    sodium_stackzero(8192);
    return rc;
}

void skp_state_wipe(skp_state *st) { sodium_memzero(st, sizeof *st); }
