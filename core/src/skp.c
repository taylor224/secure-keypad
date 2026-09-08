#include "skp_internal.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

/* The signing key and the state key live in sodium_malloc'd pages that are no-access while idle.
 * Concurrent callers share the readable window through a counted guard. Platforms without page
 * protection (WebAssembly) report ENOSYS; the keys then simply stay readable. */
static pthread_mutex_t g_guard = PTHREAD_MUTEX_INITIALIZER;
static int g_guard_count = 0;
static const skp_ctx *g_guard_ctx = NULL;

static int protect_readonly(void *p) {
    if (sodium_mprotect_readonly(p) == 0)
        return 0;
    return errno == ENOSYS ? 0 : -1;
}

int skp_ctx_keys_acquire(const skp_ctx *ctx) {
    int rc = 0;
    pthread_mutex_lock(&g_guard);
    if (g_guard_count == 0 || g_guard_ctx == ctx) {
        if (g_guard_count == 0) {
            if (protect_readonly(ctx->sk_sign) != 0 || protect_readonly(ctx->k_state) != 0)
                rc = -1;
        }
        if (rc == 0) {
            g_guard_ctx = ctx;
            g_guard_count++;
        }
    } else {
        /* a different context is currently open: open ours too (pages are independent) */
        if (protect_readonly(ctx->sk_sign) != 0 || protect_readonly(ctx->k_state) != 0)
            rc = -1;
        else
            g_guard_count++;
    }
    pthread_mutex_unlock(&g_guard);
    return rc;
}

void skp_ctx_keys_release(const skp_ctx *ctx) {
    pthread_mutex_lock(&g_guard);
    if (g_guard_count > 0)
        g_guard_count--;
    if (g_guard_count == 0) {
        sodium_mprotect_noaccess(ctx->sk_sign);
        sodium_mprotect_noaccess(ctx->k_state);
        g_guard_ctx = NULL;
    }
    pthread_mutex_unlock(&g_guard);
}

const char *skp_version(void) { return SKP_VERSION_STRING; }

const char *skp_strerror(int err) {
    switch (err) {
    case SKP_OK: return "ok";
    case SKP_ERR_NOMEM: return "out of memory";
    case SKP_ERR_INVALID_ARG: return "invalid argument";
    case SKP_ERR_BAD_KEY: return "master key unreadable or wrong length";
    case SKP_ERR_BAD_REQUEST: return "request does not match the protocol schema";
    case SKP_ERR_CRYPTO: return "cryptographic operation failed";
    case SKP_ERR_EXPIRED: return "session expired";
    case SKP_ERR_BAD_MAC: return "authentication failed";
    case SKP_ERR_TAMPERED: return "payload structurally invalid or hit a non-character key";
    case SKP_ERR_CTX_MISMATCH: return "binding context mismatch";
    case SKP_ERR_SID_MISMATCH: return "payload does not belong to this session";
    case SKP_ERR_RENDER: return "glyph rendering failed";
    case SKP_ERR_IO: return "file access failed";
    case SKP_ERR_UNSUPPORTED: return "unsupported version or option";
    default: return "unknown error";
    }
}

static int read_key_file(const char *path, uint8_t out[32]) {
    FILE *fp = fopen(path, "rb");
    if (!fp)
        return SKP_ERR_IO;
    char buf[512];
    size_t n = fread(buf, 1, sizeof buf, fp);
    int trunc = !feof(fp);
    fclose(fp);
    if (trunc || n == 0) {
        sodium_memzero(buf, sizeof buf);
        return SKP_ERR_BAD_KEY;
    }
    int rc = skp_parse_master(buf, n, out);
    sodium_memzero(buf, sizeof buf);
    return rc;
}

int skp_init(skp_ctx **out, const skp_config *cfg) {
    if (!out || !cfg)
        return SKP_ERR_INVALID_ARG;
    *out = NULL;
    if (sodium_init() < 0)
        return SKP_ERR_CRYPTO;
    if (!cfg->master_key_path == !cfg->master_key)
        return SKP_ERR_INVALID_ARG; /* exactly one source */
    skp_ctx *ctx = calloc(1, sizeof *ctx);
    if (!ctx)
        return SKP_ERR_NOMEM;
    ctx->sk_sign = sodium_malloc(crypto_sign_SECRETKEYBYTES);
    ctx->k_state = sodium_malloc(SKP_KEY_BYTES);
    ctx->glyphs = skp_glyph_cache_new();
    if (!ctx->sk_sign || !ctx->k_state || !ctx->glyphs) {
        skp_free(ctx);
        return SKP_ERR_NOMEM;
    }
    ctx->default_ttl = cfg->default_ttl_sec ? cfg->default_ttl_sec : SKP_DEFAULT_TTL;
    ctx->max_len_cap = cfg->max_len_cap ? cfg->max_len_cap : SKP_DEFAULT_CAP;
    if (ctx->max_len_cap > 65535)
        ctx->max_len_cap = 65535;

    uint8_t *master = sodium_malloc(32);
    if (!master) {
        skp_free(ctx);
        return SKP_ERR_NOMEM;
    }
    int rc;
    if (cfg->master_key_path)
        rc = read_key_file(cfg->master_key_path, master);
    else
        rc = skp_parse_master(cfg->master_key, cfg->master_key_len, master);
    if (rc == SKP_OK)
        rc = skp_derive_master(ctx, master);
    sodium_free(master);
    if (rc) {
        skp_free(ctx);
        return rc;
    }
    rc = skp_font_load(&ctx->fonts[0], cfg->font_ios_path, skp_font_inter, skp_font_inter_len);
    if (rc == SKP_OK)
        rc = skp_font_load(&ctx->fonts[1], cfg->font_material_path, skp_font_roboto, skp_font_roboto_len);
    if (rc == SKP_OK)
        rc = skp_font_load(&ctx->fonts[2], cfg->font_fallback_path, skp_font_hangul, skp_font_hangul_len);
    if (rc) {
        skp_free(ctx);
        return rc;
    }
    sodium_mprotect_noaccess(ctx->sk_sign);
    sodium_mprotect_noaccess(ctx->k_state);
    *out = ctx;
    return SKP_OK;
}

void skp_free(skp_ctx *ctx) {
    if (!ctx)
        return;
    if (ctx->sk_sign) {
        sodium_mprotect_readwrite(ctx->sk_sign);
        sodium_free(ctx->sk_sign);
    }
    if (ctx->k_state) {
        sodium_mprotect_readwrite(ctx->k_state);
        sodium_free(ctx->k_state);
    }
    skp_font_free(&ctx->fonts[0]);
    skp_font_free(&ctx->fonts[1]);
    skp_font_free(&ctx->fonts[2]);
    skp_glyph_cache_free(ctx->glyphs);
    sodium_memzero(ctx, sizeof *ctx);
    free(ctx);
}

int skp_public_key(const skp_ctx *ctx, char *b64_out, size_t cap) {
    if (!ctx || !b64_out)
        return SKP_ERR_INVALID_ARG;
    char *s = NULL;
    int rc = skp_b64_encode(&s, ctx->pk_sign, sizeof ctx->pk_sign, 0);
    if (rc)
        return rc;
    if (strlen(s) + 1 > cap) {
        free(s);
        return SKP_ERR_INVALID_ARG;
    }
    memcpy(b64_out, s, strlen(s) + 1);
    free(s);
    return SKP_OK;
}

int skp_key_id(const skp_ctx *ctx, char *out, size_t cap) {
    if (!ctx || !out || cap < SKP_KID_CAP)
        return SKP_ERR_INVALID_ARG;
    memcpy(out, ctx->kid, SKP_KID_CAP);
    return SKP_OK;
}

int skp_keygen(uint8_t out[SKP_MASTER_KEY_BYTES]) {
    if (!out)
        return SKP_ERR_INVALID_ARG;
    if (sodium_init() < 0)
        return SKP_ERR_CRYPTO;
    randombytes_buf(out, SKP_MASTER_KEY_BYTES);
    return SKP_OK;
}

int skp_keygen_b64(char *out, size_t cap) {
    uint8_t k[32];
    int rc = skp_keygen(k);
    if (rc)
        return rc;
    char *s = NULL;
    rc = skp_b64_encode(&s, k, 32, 0);
    sodium_memzero(k, 32);
    if (rc)
        return rc;
    if (strlen(s) + 1 > cap) {
        sodium_memzero(s, strlen(s));
        free(s);
        return SKP_ERR_INVALID_ARG;
    }
    memcpy(out, s, strlen(s) + 1);
    sodium_memzero(s, strlen(s));
    free(s);
    return SKP_OK;
}

size_t skp_secret_len(const skp_secret *s) { return s ? s->len : 0; }
const uint8_t *skp_secret_bytes(const skp_secret *s) { return s ? s->data : NULL; }

void skp_secret_free(skp_secret *s) {
    if (!s)
        return;
    if (s->data)
        sodium_free(s->data); /* zeroes */
    sodium_memzero(s, sizeof *s);
    free(s);
}

void skp_buf_free(skp_buf *b) {
    if (!b)
        return;
    if (b->data) {
        sodium_memzero(b->data, b->len);
        free(b->data);
    }
    b->data = NULL;
    b->len = 0;
}
