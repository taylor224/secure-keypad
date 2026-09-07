#include "skp_internal.h"
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

void skp_hkdf_extract(uint8_t prk[32], const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len) {
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, salt, salt_len);
    crypto_auth_hmacsha256_update(&st, ikm, ikm_len);
    crypto_auth_hmacsha256_final(&st, prk);
    sodium_memzero(&st, sizeof st);
}

void skp_hkdf_expand(uint8_t *out, size_t out_len, const uint8_t prk[32], const uint8_t *info, size_t info_len) {
    uint8_t t[32];
    size_t tlen = 0, pos = 0;
    uint8_t counter = 1;
    while (pos < out_len) {
        crypto_auth_hmacsha256_state st;
        crypto_auth_hmacsha256_init(&st, prk, 32);
        if (tlen)
            crypto_auth_hmacsha256_update(&st, t, tlen);
        crypto_auth_hmacsha256_update(&st, info, info_len);
        crypto_auth_hmacsha256_update(&st, &counter, 1);
        crypto_auth_hmacsha256_final(&st, t);
        sodium_memzero(&st, sizeof st);
        tlen = 32;
        size_t n = out_len - pos < 32 ? out_len - pos : 32;
        memcpy(out + pos, t, n);
        pos += n;
        counter++;
    }
    sodium_memzero(t, sizeof t);
}

void skp_nonce12(uint8_t n[12], uint64_t ctr) {
    memset(n, 0, 4);
    for (int i = 0; i < 8; i++)
        n[4 + i] = (uint8_t)(ctr >> (56 - 8 * i));
}

int skp_derive_master(skp_ctx *ctx, const uint8_t master[32]) {
    uint8_t prk[32], seed[32];
    skp_hkdf_extract(prk, (const uint8_t *)SKP_LABEL_MASTER, strlen(SKP_LABEL_MASTER), master, 32);
    skp_hkdf_expand(seed, 32, prk, (const uint8_t *)"sign", 4);
    skp_hkdf_expand(ctx->k_state, 32, prk, (const uint8_t *)"state", 5);
    int rc = crypto_sign_seed_keypair(ctx->pk_sign, ctx->sk_sign, seed);
    sodium_memzero(prk, sizeof prk);
    sodium_memzero(seed, sizeof seed);
    if (rc != 0)
        return SKP_ERR_CRYPTO;
    uint8_t h[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(h, ctx->pk_sign, sizeof ctx->pk_sign);
    static const char hexd[] = "0123456789abcdef";
    for (int i = 0; i < 4; i++) {
        ctx->kid[2 * i] = hexd[h[i] >> 4];
        ctx->kid[2 * i + 1] = hexd[h[i] & 15];
    }
    ctx->kid[8] = 0;
    return SKP_OK;
}

int skp_hex_decode(uint8_t *out, size_t cap, const char *in, size_t in_len) {
    if (in_len % 2 || in_len / 2 > cap)
        return -1;
    for (size_t i = 0; i < in_len; i += 2) {
        int v = 0;
        for (int k = 0; k < 2; k++) {
            char c = in[i + k];
            int d;
            if (c >= '0' && c <= '9')
                d = c - '0';
            else if (c >= 'a' && c <= 'f')
                d = c - 'a' + 10;
            else if (c >= 'A' && c <= 'F')
                d = c - 'A' + 10;
            else
                return -1;
            v = v * 16 + d;
        }
        out[i / 2] = (uint8_t)v;
    }
    return (int)(in_len / 2);
}

int skp_parse_master(const char *text, size_t len, uint8_t out[32]) {
    if (!text)
        return SKP_ERR_BAD_KEY;
    if (len == 0)
        len = strlen(text);
    if (len == 32) { /* raw bytes only when explicitly sized 32 and not printable hex/base64 text */
        int printable = 1;
        for (size_t i = 0; i < 32; i++)
            if (!isprint((unsigned char)text[i]))
                printable = 0;
        if (!printable) {
            memcpy(out, text, 32);
            return SKP_OK;
        }
    }
    while (len && isspace((unsigned char)text[len - 1]))
        len--;
    while (len && isspace((unsigned char)*text)) {
        text++;
        len--;
    }
    if (len == 64 && skp_hex_decode(out, 32, text, 64) == 32)
        return SKP_OK;
    size_t got = 0;
    if (sodium_base642bin(out, 32, text, len, NULL, &got, NULL, sodium_base64_VARIANT_ORIGINAL) == 0 && got == 32)
        return SKP_OK;
    sodium_memzero(out, 32);
    return SKP_ERR_BAD_KEY;
}

int skp_b64_encode(char **out, const uint8_t *in, size_t len, int url_nopad) {
    int variant = url_nopad ? sodium_base64_VARIANT_URLSAFE_NO_PADDING : sodium_base64_VARIANT_ORIGINAL;
    size_t cap = sodium_base64_encoded_len(len, variant);
    char *s = malloc(cap);
    if (!s)
        return SKP_ERR_NOMEM;
    sodium_bin2base64(s, cap, in, len, variant);
    *out = s;
    return SKP_OK;
}

int skp_b64_decode(uint8_t *out, size_t cap, size_t *out_len, const char *in, size_t in_len, int url_nopad) {
    int variant = url_nopad ? sodium_base64_VARIANT_URLSAFE_NO_PADDING : sodium_base64_VARIANT_ORIGINAL;
    const char *end = NULL;
    size_t got = 0;
    if (sodium_base642bin(out, cap, in, in_len, NULL, &got, &end, variant) != 0)
        return -1;
    if (end != in + in_len)
        return -1;
    *out_len = got;
    return 0;
}

/* ---- randomness, clock, test hooks -------------------------------------------------------- */
#ifdef SKP_TESTING
static skp_test_hooks g_hooks;
static int g_hooks_set = 0;
void skp_test_set_hooks(const skp_test_hooks *hooks) {
    if (hooks) {
        g_hooks = *hooks;
        g_hooks_set = 1;
    } else {
        memset(&g_hooks, 0, sizeof g_hooks);
        g_hooks_set = 0;
    }
}
#endif

void skp_random(uint8_t *buf, size_t len, int which) {
#ifdef SKP_TESTING
    if (g_hooks_set) {
        const uint8_t *src = NULL;
        switch (which) {
        case SKP_RAND_SID: src = g_hooks.sid; break;
        case SKP_RAND_SSK: src = g_hooks.s_sk; break;
        case SKP_RAND_SEED: src = g_hooks.seed; break;
        case SKP_RAND_NONCE24: src = g_hooks.nonce24; break;
        default: break;
        }
        if (src) {
            memcpy(buf, src, len);
            return;
        }
    }
#else
    (void)which;
#endif
    randombytes_buf(buf, len);
}

int64_t skp_now(void) {
#ifdef SKP_TESTING
    if (g_hooks_set && g_hooks.now)
        return g_hooks.now;
#endif
    return (int64_t)time(NULL);
}

int skp_render_disabled(void) {
#ifdef SKP_TESTING
    return g_hooks_set && g_hooks.no_render;
#else
    return 0;
#endif
}

void skp_wipe(void *p, size_t n) {
    if (p && n)
        sodium_memzero(p, n);
}

int skp_buf_alloc(skp_buf *b, size_t n) {
    b->data = malloc(n ? n : 1);
    b->len = n;
    return b->data ? SKP_OK : SKP_ERR_NOMEM;
}

void skp_log_warn(const char *msg) {
    fprintf(stderr, "[secure-keypad] warning: %s\n", msg);
}
