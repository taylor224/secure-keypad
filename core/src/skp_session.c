#include "skp_internal.h"
#include "../third_party/cJSON.h"
#include <math.h>
#include <stdlib.h>

int skp_ctx_keys_acquire(const skp_ctx *ctx);
void skp_ctx_keys_release(const skp_ctx *ctx);

/* ---- request parsing ------------------------------------------------------------------------ */
typedef struct {
    uint8_t c_pk[32];
    int type;
    int32_t W;
    uint32_t dpr_milli;
    int platform, style;
    int has_max_len;
    uint32_t max_len;
    int has_langs, nlangs;
    uint8_t langs[SKP_MAX_LANGS];
} skp_request;

static int json_int(const cJSON *n, int64_t *out) {
    if (!cJSON_IsNumber(n))
        return 0;
    double d = n->valuedouble;
    if (d != floor(d) || d < -1e15 || d > 1e15)
        return 0;
    *out = (int64_t)d;
    return 1;
}

static int parse_viewport(const cJSON *vp, skp_request *r, int need_style) {
    if (!cJSON_IsObject(vp))
        return SKP_ERR_BAD_REQUEST;
    const cJSON *w = cJSON_GetObjectItemCaseSensitive(vp, "w");
    const cJSON *dpr = cJSON_GetObjectItemCaseSensitive(vp, "dpr");
    const cJSON *platform = cJSON_GetObjectItemCaseSensitive(vp, "platform");
    const cJSON *style = cJSON_GetObjectItemCaseSensitive(vp, "style");
    if (!cJSON_IsNumber(w) || !(w->valuedouble > 0) || !cJSON_IsNumber(dpr) || !(dpr->valuedouble > 0) ||
        !cJSON_IsString(platform))
        return SKP_ERR_BAD_REQUEST;
    if (!(w->valuedouble < 1e7) || !(dpr->valuedouble < 1e4))
        return SKP_ERR_BAD_REQUEST;
    int64_t dm = (int64_t)floor(dpr->valuedouble * 1000.0 + 0.5);
    if (dm < 500)
        dm = 500;
    if (dm > 10000)
        dm = 10000;
    int64_t wm = (int64_t)floor(w->valuedouble * 1000.0 + 0.5);
    int64_t W = skp_rnd(wm * dm, 1000000);
    if (W < SKP_MIN_W || W > SKP_MAX_W)
        return SKP_ERR_BAD_REQUEST;
    r->W = (int32_t)W;
    r->dpr_milli = (uint32_t)dm;
    if (!strcmp(platform->valuestring, "ios"))
        r->platform = SKP_PLATFORM_IOS;
    else if (!strcmp(platform->valuestring, "android"))
        r->platform = SKP_PLATFORM_ANDROID;
    else if (!strcmp(platform->valuestring, "web"))
        r->platform = SKP_PLATFORM_WEB;
    else
        return SKP_ERR_BAD_REQUEST;
    if (need_style) {
        if (cJSON_IsString(style)) {
            if (!strcmp(style->valuestring, "ios"))
                r->style = SKP_STYLE_IOS;
            else if (!strcmp(style->valuestring, "material"))
                r->style = SKP_STYLE_MATERIAL;
            else
                return SKP_ERR_BAD_REQUEST;
        } else if (style && !cJSON_IsNull(style)) {
            return SKP_ERR_BAD_REQUEST;
        } else {
            r->style = r->platform == SKP_PLATFORM_IOS ? SKP_STYLE_IOS : SKP_STYLE_MATERIAL;
        }
    }
    return SKP_OK;
}

static int parse_request(const char *json, size_t len, skp_request *r) {
    memset(r, 0, sizeof *r);
    cJSON *root = cJSON_ParseWithLength(json, len);
    if (!root)
        return SKP_ERR_BAD_REQUEST;
    int rc = SKP_ERR_BAD_REQUEST;
    int64_t v;
    const cJSON *kp = cJSON_GetObjectItemCaseSensitive(root, "kp");
    const cJSON *type = cJSON_GetObjectItemCaseSensitive(root, "type");
    const cJSON *opts = cJSON_GetObjectItemCaseSensitive(root, "opts");
    if (!json_int(cJSON_GetObjectItemCaseSensitive(root, "v"), &v) || v != SKP_PROTOCOL_VERSION)
        goto done;
    if (!cJSON_IsString(kp))
        goto done;
    size_t got = 0;
    if (skp_b64_decode(r->c_pk, 32, &got, kp->valuestring, strlen(kp->valuestring), 0) != 0 || got != 32)
        goto done;
    if (!cJSON_IsString(type))
        goto done;
    if (!strcmp(type->valuestring, "qwerty"))
        r->type = SKP_TYPE_QWERTY;
    else if (!strcmp(type->valuestring, "number"))
        r->type = SKP_TYPE_NUMBER;
    else
        goto done;
    rc = parse_viewport(cJSON_GetObjectItemCaseSensitive(root, "viewport"), r, 1);
    if (rc)
        goto done;
    if (cJSON_IsObject(opts)) {
        int64_t ml;
        const cJSON *m = cJSON_GetObjectItemCaseSensitive(opts, "maxLen");
        if (m && !cJSON_IsNull(m)) {
            if (!json_int(m, &ml) || ml < 1 || ml > 65535) {
                rc = SKP_ERR_BAD_REQUEST;
                goto done;
            }
            r->has_max_len = 1;
            r->max_len = (uint32_t)ml;
        }
        const cJSON *langs = cJSON_GetObjectItemCaseSensitive(opts, "langs");
        if (langs && !cJSON_IsNull(langs)) {
            int n = cJSON_IsArray(langs) ? cJSON_GetArraySize(langs) : -1;
            if (n < 1 || n > SKP_MAX_LANGS) {
                rc = SKP_ERR_BAD_REQUEST;
                goto done;
            }
            for (int i = 0; i < n; i++) {
                const cJSON *item = cJSON_GetArrayItem(langs, i);
                int id = cJSON_IsString(item) ? skp_lang_by_code(item->valuestring, strlen(item->valuestring)) : 0;
                for (int k = 0; k < i; k++)
                    if (r->langs[k] == id)
                        id = 0;
                if (!id) {
                    rc = SKP_ERR_BAD_REQUEST;
                    goto done;
                }
                r->langs[i] = (uint8_t)id;
            }
            r->has_langs = 1;
            r->nlangs = n;
        }
    }
    rc = SKP_OK;
done:
    cJSON_Delete(root);
    return rc;
}

static int parse_opts(const skp_ctx *ctx, const skp_session_opts *o, int *policy, int *blank, uint32_t *ttl,
                      uint32_t *max_len_override, uint8_t langs[SKP_MAX_LANGS], int *nlangs) {
    *policy = SKP_POLICY_SHUFFLE;
    *blank = SKP_BLANK_FIXED;
    *ttl = ctx->default_ttl;
    *max_len_override = 0;
    *nlangs = 0;
    if (!o)
        return SKP_OK;
    if (o->languages && *o->languages) {
        int rc = skp_parse_langs(o->languages, langs, nlangs);
        if (rc)
            return rc;
    }
    if (o->layout && *o->layout) {
        if (!strcmp(o->layout, "shuffle"))
            *policy = SKP_POLICY_SHUFFLE;
        else if (!strcmp(o->layout, "full"))
            *policy = SKP_POLICY_FULL;
        else if (!strcmp(o->layout, "fixed"))
            *policy = SKP_POLICY_FIXED;
        else
            return SKP_ERR_UNSUPPORTED;
    }
    if (o->blank && *o->blank) {
        if (!strcmp(o->blank, "fixed"))
            *blank = SKP_BLANK_FIXED;
        else if (!strcmp(o->blank, "random"))
            *blank = SKP_BLANK_RANDOM;
        else
            return SKP_ERR_UNSUPPORTED;
    }
    if (o->ttl_sec)
        *ttl = o->ttl_sec;
    *max_len_override = o->max_len;
    return SKP_OK;
}

/* ---- inner frame ----------------------------------------------------------------------------- */
static void put32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

/* Builds json + sprites, encrypts under key/ctr/aad. ct_out is malloc'd. */
static int build_inner_ct(const skp_ctx *ctx, const skp_layout *layout, int gen, uint32_t max_len, int64_t exp,
                          const uint8_t key[32], uint64_t ctr, const char *aad_label, const uint8_t sid[16],
                          skp_buf *ct_out) {
    char *json = skp_layout_json(layout, gen, max_len, exp);
    if (!json)
        return SKP_ERR_NOMEM;
    skp_buf tiles = {0}, popups = {0};
    int rc = SKP_OK;
    if (!skp_render_disabled()) {
        rc = skp_render_sprites(ctx, layout, &tiles, &popups);
        if (rc) {
            free(json);
            return rc;
        }
    }
    size_t jl = strlen(json);
    size_t pl = 12 + jl + tiles.len + popups.len;
    uint8_t *pt = sodium_malloc(pl);
    if (!pt) {
        rc = SKP_ERR_NOMEM;
        goto done;
    }
    put32(pt, (uint32_t)jl);
    memcpy(pt + 4, json, jl);
    put32(pt + 4 + jl, (uint32_t)tiles.len);
    if (tiles.len)
        memcpy(pt + 8 + jl, tiles.data, tiles.len);
    put32(pt + 8 + jl + tiles.len, (uint32_t)popups.len);
    if (popups.len)
        memcpy(pt + 12 + jl + tiles.len, popups.data, popups.len);
    rc = skp_buf_alloc(ct_out, pl + crypto_aead_chacha20poly1305_ietf_ABYTES);
    if (rc) {
        sodium_free(pt);
        goto done;
    }
    uint8_t nonce[12];
    skp_nonce12(nonce, ctr);
    uint8_t aad[48];
    size_t al = strlen(aad_label);
    memcpy(aad, aad_label, al);
    memcpy(aad + al, sid, 16);
    al += 16;
    unsigned long long clen = 0;
    if (crypto_aead_chacha20poly1305_ietf_encrypt(ct_out->data, &clen, pt, pl, aad, al, NULL, nonce, key) != 0) {
        skp_buf_free(ct_out);
        rc = SKP_ERR_CRYPTO;
    } else {
        ct_out->len = (size_t)clen;
    }
    sodium_free(pt);
done:
    skp_wipe(json, jl);
    free(json);
    skp_buf_free(&tiles);
    skp_buf_free(&popups);
    return rc;
}

static int json_to_buf(cJSON *obj, skp_buf *out) {
    char *s = cJSON_PrintUnformatted(obj);
    if (!s)
        return SKP_ERR_NOMEM;
    out->data = (uint8_t *)s;
    out->len = strlen(s);
    return SKP_OK;
}

/* ---- create ---------------------------------------------------------------------------------- */
int skp_session_create(const skp_ctx *ctx, const char *req_json, size_t req_len, const skp_session_opts *opts,
                       skp_buf *resp_json, skp_buf *sealed) {
    if (!ctx || !req_json || !resp_json || !sealed)
        return SKP_ERR_INVALID_ARG;
    resp_json->data = NULL;
    resp_json->len = 0;
    sealed->data = NULL;
    sealed->len = 0;
    if (!req_len)
        req_len = strlen(req_json);
    skp_request r;
    int rc = parse_request(req_json, req_len, &r);
    if (rc)
        return rc;
    int policy, blank, opt_nlangs = 0;
    uint32_t ttl, ml_override;
    uint8_t opt_langs[SKP_MAX_LANGS] = {0};
    rc = parse_opts(ctx, opts, &policy, &blank, &ttl, &ml_override, opt_langs, &opt_nlangs);
    if (rc)
        return rc;
    uint32_t max_len = ml_override ? ml_override : (r.has_max_len ? r.max_len : (r.type == SKP_TYPE_QWERTY ? 32 : 16));
    if (max_len < 1)
        max_len = 1;
    if (max_len > ctx->max_len_cap)
        max_len = ctx->max_len_cap;
    /* languages: the integrator's choice wins, then the client's request, then Korean + English */
    uint8_t langs[SKP_MAX_LANGS] = {0};
    int nlangs = 0;
    if (r.type == SKP_TYPE_QWERTY) {
        if (opt_nlangs) {
            memcpy(langs, opt_langs, (size_t)opt_nlangs);
            nlangs = opt_nlangs;
        } else if (r.has_langs) {
            memcpy(langs, r.langs, (size_t)r.nlangs);
            nlangs = r.nlangs;
        } else {
            langs[0] = SKP_LANG_EN;
            langs[1] = SKP_LANG_KO;
            nlangs = 2;
        }
    }
    if (policy == SKP_POLICY_FIXED) {
        static int warned = 0;
        if (!warned) {
            warned = 1;
            skp_log_warn("layout=\"fixed\": characters are inferable from coordinates; use only where a native "
                         "layout matters more than memory-tamper resistance");
        }
    }

    skp_state *st = sodium_malloc(sizeof *st);
    uint8_t *secrets = sodium_malloc(32 + 32 + 32 + 32); /* s_sk | ss | prk | s_pk */
    if (!st || !secrets) {
        if (st)
            sodium_free(st);
        if (secrets)
            sodium_free(secrets);
        return SKP_ERR_NOMEM;
    }
    uint8_t *s_sk = secrets, *ss = secrets + 32, *prk = secrets + 64, *s_pk = secrets + 96;
    memset(st, 0, sizeof *st);
    st->type = (uint8_t)r.type;
    st->policy = (uint8_t)policy;
    st->blank = (uint8_t)blank;
    st->style = (uint8_t)r.style;
    st->nlangs = nlangs;
    memcpy(st->langs, langs, sizeof st->langs);
    st->max_len = max_len;
    st->created = skp_now();
    st->expires = st->created + ttl;
    if (opts && opts->ctx && *opts->ctx)
        crypto_hash_sha256(st->ctx_hash, (const uint8_t *)opts->ctx, strlen(opts->ctx));
    skp_random(st->sid, 16, SKP_RAND_SID);
    skp_random(s_sk, 32, SKP_RAND_SSK);
    st->ngens = 1;
    skp_random(st->gens[0].seed, 32, SKP_RAND_SEED);
    st->gens[0].W = r.W;
    st->gens[0].dpr_milli = r.dpr_milli;
    st->gens[0].platform = (uint8_t)r.platform;

    skp_buf ct = {0};
    cJSON *resp = NULL;
    char *b64 = NULL;
    uint8_t sig[crypto_sign_BYTES];
    uint8_t nonce24[24];
    skp_layout *layout = NULL;

    crypto_scalarmult_base(s_pk, s_sk);
    if (crypto_scalarmult(ss, s_sk, r.c_pk) != 0) {
        rc = SKP_ERR_CRYPTO;
        goto done;
    }
    {
        uint8_t salt[6 + 16];
        memcpy(salt, SKP_LABEL_SESSION_SALT, 6);
        memcpy(salt + 6, st->sid, 16);
        skp_hkdf_extract(prk, salt, sizeof salt, ss, 32);
        uint8_t info[3 + 64];
        memcpy(info, "s2c", 3);
        memcpy(info + 3, r.c_pk, 32);
        memcpy(info + 35, s_pk, 32);
        skp_hkdf_expand(st->k_s2c, 32, prk, info, sizeof info);
        memcpy(info, "c2s", 3);
        skp_hkdf_expand(st->k_c2s, 32, prk, info, sizeof info);
    }
    sodium_memzero(s_sk, 32);
    sodium_memzero(ss, 32);
    sodium_memzero(prk, 32);

    layout = sodium_malloc(sizeof *layout);
    if (!layout) {
        rc = SKP_ERR_NOMEM;
        goto done;
    }
    rc = skp_layout_build(layout, r.type, policy, blank, r.style, st->langs, st->nlangs, r.W, r.dpr_milli,
                          st->gens[0].seed);
    if (rc)
        goto done;
    rc = build_inner_ct(ctx, layout, 0, max_len, (int64_t)ttl, st->k_s2c, 0, SKP_AAD_SESSION, st->sid, &ct);
    if (rc)
        goto done;
    st->s2c_ctr = 1;

    /* signature over label || kid || sid || c_pk || s_pk || sha256(ct) */
    {
        uint8_t msg[14 + 8 + 16 + 32 + 32 + 32];
        size_t p = 0;
        memcpy(msg + p, SKP_SIG_LABEL, 14);
        p += 14;
        memcpy(msg + p, ctx->kid, 8);
        p += 8;
        memcpy(msg + p, st->sid, 16);
        p += 16;
        memcpy(msg + p, r.c_pk, 32);
        p += 32;
        memcpy(msg + p, s_pk, 32);
        p += 32;
        crypto_hash_sha256(msg + p, ct.data, ct.len);
        p += 32;
        if (skp_ctx_keys_acquire(ctx) != 0) {
            rc = SKP_ERR_CRYPTO;
            goto done;
        }
        int src = crypto_sign_detached(sig, NULL, msg, p, ctx->sk_sign);
        skp_ctx_keys_release(ctx);
        if (src != 0) {
            rc = SKP_ERR_CRYPTO;
            goto done;
        }
    }
    skp_random(nonce24, 24, SKP_RAND_NONCE24);
    rc = skp_state_seal(ctx, st, nonce24, sealed);
    if (rc)
        goto done;

    resp = cJSON_CreateObject();
    if (!resp) {
        rc = SKP_ERR_NOMEM;
        goto done;
    }
    cJSON_AddNumberToObject(resp, "v", SKP_PROTOCOL_VERSION);
    rc = skp_b64_encode(&b64, st->sid, 16, 1);
    if (rc)
        goto done;
    cJSON_AddStringToObject(resp, "sid", b64);
    free(b64);
    b64 = NULL;
    cJSON_AddStringToObject(resp, "kid", ctx->kid);
    rc = skp_b64_encode(&b64, s_pk, 32, 0);
    if (rc)
        goto done;
    cJSON_AddStringToObject(resp, "sp", b64);
    free(b64);
    b64 = NULL;
    rc = skp_b64_encode(&b64, sig, sizeof sig, 0);
    if (rc)
        goto done;
    cJSON_AddStringToObject(resp, "sig", b64);
    free(b64);
    b64 = NULL;
    rc = skp_b64_encode(&b64, ct.data, ct.len, 0);
    if (rc)
        goto done;
    cJSON_AddStringToObject(resp, "ct", b64);
    free(b64);
    b64 = NULL;
    rc = json_to_buf(resp, resp_json);
done:
    if (rc) {
        skp_buf_free(sealed);
        skp_buf_free(resp_json);
    }
    free(b64);
    cJSON_Delete(resp);
    skp_buf_free(&ct);
    if (layout)
        sodium_free(layout);
    sodium_free(secrets);
    sodium_free(st);
    sodium_stackzero(16384);
    return rc;
}

/* ---- relayout -------------------------------------------------------------------------------- */
int skp_session_relayout(const skp_ctx *ctx, const uint8_t *sealed, size_t sealed_len, const char *req_json,
                         size_t req_len, skp_buf *resp_json, skp_buf *sealed_out) {
    if (!ctx || !sealed || !req_json || !resp_json || !sealed_out)
        return SKP_ERR_INVALID_ARG;
    resp_json->data = NULL;
    resp_json->len = 0;
    sealed_out->data = NULL;
    sealed_out->len = 0;
    if (!req_len)
        req_len = strlen(req_json);
    skp_state *st = sodium_malloc(sizeof *st);
    skp_layout *layout = sodium_malloc(sizeof *layout);
    if (!st || !layout) {
        if (st)
            sodium_free(st);
        if (layout)
            sodium_free(layout);
        return SKP_ERR_NOMEM;
    }
    cJSON *root = NULL, *resp = NULL;
    skp_buf ct = {0};
    char *b64 = NULL;
    int rc = skp_state_unseal(ctx, sealed, sealed_len, st);
    if (rc)
        goto done;
    if (skp_now() > st->expires) {
        rc = SKP_ERR_EXPIRED;
        goto done;
    }
    root = cJSON_ParseWithLength(req_json, req_len);
    if (!root) {
        rc = SKP_ERR_BAD_REQUEST;
        goto done;
    }
    {
        int64_t v;
        const cJSON *sid = cJSON_GetObjectItemCaseSensitive(root, "sid");
        if (!json_int(cJSON_GetObjectItemCaseSensitive(root, "v"), &v) || v != SKP_PROTOCOL_VERSION || !cJSON_IsString(sid)) {
            rc = SKP_ERR_BAD_REQUEST;
            goto done;
        }
        uint8_t sidb[16];
        size_t got = 0;
        if (skp_b64_decode(sidb, 16, &got, sid->valuestring, strlen(sid->valuestring), 1) != 0 || got != 16) {
            rc = SKP_ERR_BAD_REQUEST;
            goto done;
        }
        if (sodium_memcmp(sidb, st->sid, 16) != 0) {
            rc = SKP_ERR_SID_MISMATCH;
            goto done;
        }
    }
    if (st->ngens >= SKP_MAX_GENS) {
        rc = SKP_ERR_UNSUPPORTED;
        goto done;
    }
    skp_request r;
    memset(&r, 0, sizeof r);
    rc = parse_viewport(cJSON_GetObjectItemCaseSensitive(root, "viewport"), &r, 0);
    if (rc)
        goto done;
    int gen = st->ngens;
    memcpy(st->gens[gen].seed, st->gens[gen - 1].seed, 32);
    st->gens[gen].W = r.W;
    st->gens[gen].dpr_milli = r.dpr_milli;
    st->gens[gen].platform = (uint8_t)r.platform;
    st->ngens = gen + 1;
    rc = skp_layout_build(layout, st->type, st->policy, st->blank, st->style, st->langs, st->nlangs, r.W, r.dpr_milli,
                          st->gens[gen].seed);
    if (rc)
        goto done;
    rc = build_inner_ct(ctx, layout, gen, st->max_len, st->expires - skp_now(), st->k_s2c, st->s2c_ctr,
                        SKP_AAD_RELAYOUT, st->sid, &ct);
    if (rc)
        goto done;
    st->s2c_ctr += 1;
    uint8_t nonce24[24];
    skp_random(nonce24, 24, SKP_RAND_NONCE24);
    rc = skp_state_seal(ctx, st, nonce24, sealed_out);
    if (rc)
        goto done;
    resp = cJSON_CreateObject();
    if (!resp) {
        rc = SKP_ERR_NOMEM;
        goto done;
    }
    cJSON_AddNumberToObject(resp, "v", SKP_PROTOCOL_VERSION);
    rc = skp_b64_encode(&b64, st->sid, 16, 1);
    if (rc)
        goto done;
    cJSON_AddStringToObject(resp, "sid", b64);
    free(b64);
    b64 = NULL;
    cJSON_AddNumberToObject(resp, "gen", gen);
    rc = skp_b64_encode(&b64, ct.data, ct.len, 0);
    if (rc)
        goto done;
    cJSON_AddStringToObject(resp, "ct", b64);
    free(b64);
    b64 = NULL;
    rc = json_to_buf(resp, resp_json);
done:
    if (rc) {
        skp_buf_free(sealed_out);
        skp_buf_free(resp_json);
    }
    free(b64);
    cJSON_Delete(resp);
    cJSON_Delete(root);
    skp_buf_free(&ct);
    sodium_free(layout);
    sodium_free(st);
    sodium_stackzero(16384);
    return rc;
}

/* ---- decrypt --------------------------------------------------------------------------------- */
static size_t utf8_encode(uint8_t *out, uint32_t cp) {
    if (cp < 0x80) {
        out[0] = (uint8_t)cp;
        return 1;
    }
    if (cp < 0x800) {
        out[0] = (uint8_t)(0xC0 | (cp >> 6));
        out[1] = (uint8_t)(0x80 | (cp & 0x3F));
        return 2;
    }
    if (cp < 0x10000) {
        out[0] = (uint8_t)(0xE0 | (cp >> 12));
        out[1] = (uint8_t)(0x80 | ((cp >> 6) & 0x3F));
        out[2] = (uint8_t)(0x80 | (cp & 0x3F));
        return 3;
    }
    out[0] = (uint8_t)(0xF0 | (cp >> 18));
    out[1] = (uint8_t)(0x80 | ((cp >> 12) & 0x3F));
    out[2] = (uint8_t)(0x80 | ((cp >> 6) & 0x3F));
    out[3] = (uint8_t)(0x80 | (cp & 0x3F));
    return 4;
}

static uint32_t get16(const uint8_t *p) { return ((uint32_t)p[0] << 8) | p[1]; }

int skp_session_decrypt(const skp_ctx *ctx, const uint8_t *sealed, size_t sealed_len, const char *payload_json,
                        size_t payload_len, const char *bind_ctx, skp_secret **out) {
    if (!ctx || !sealed || !payload_json || !out)
        return SKP_ERR_INVALID_ARG;
    *out = NULL;
    if (!payload_len)
        payload_len = strlen(payload_json);
    skp_state *st = sodium_malloc(sizeof *st);
    if (!st)
        return SKP_ERR_NOMEM;
    cJSON *root = NULL;
    uint8_t *ctbuf = NULL, *batch = NULL, *result = NULL;
    uint32_t *cps = NULL, *composed = NULL;
    skp_layout *layouts = NULL; /* one per generation, lazily built */
    uint8_t built[SKP_MAX_GENS] = {0};
    int rc = skp_state_unseal(ctx, sealed, sealed_len, st);
    if (rc)
        goto done;
    if (skp_now() > st->expires) {
        rc = SKP_ERR_EXPIRED;
        goto done;
    }
    root = cJSON_ParseWithLength(payload_json, payload_len);
    if (!root) {
        rc = SKP_ERR_BAD_REQUEST;
        goto done;
    }
    int64_t v;
    const cJSON *sid = cJSON_GetObjectItemCaseSensitive(root, "sid");
    const cJSON *ct = cJSON_GetObjectItemCaseSensitive(root, "ct");
    if (!json_int(cJSON_GetObjectItemCaseSensitive(root, "v"), &v) || v != SKP_PROTOCOL_VERSION || !cJSON_IsString(sid) ||
        !cJSON_IsString(ct)) {
        rc = SKP_ERR_BAD_REQUEST;
        goto done;
    }
    {
        uint8_t sidb[16];
        size_t got = 0;
        if (skp_b64_decode(sidb, 16, &got, sid->valuestring, strlen(sid->valuestring), 1) != 0 || got != 16) {
            rc = SKP_ERR_BAD_REQUEST;
            goto done;
        }
        if (sodium_memcmp(sidb, st->sid, 16) != 0) {
            rc = SKP_ERR_SID_MISMATCH;
            goto done;
        }
    }
    {
        static const uint8_t zero[32] = {0};
        int has_ctx = bind_ctx && *bind_ctx;
        if (sodium_memcmp(st->ctx_hash, zero, 32) == 0) {
            if (has_ctx) {
                rc = SKP_ERR_CTX_MISMATCH;
                goto done;
            }
        } else {
            uint8_t h[32];
            if (!has_ctx) {
                rc = SKP_ERR_CTX_MISMATCH;
                goto done;
            }
            crypto_hash_sha256(h, (const uint8_t *)bind_ctx, strlen(bind_ctx));
            if (sodium_memcmp(h, st->ctx_hash, 32) != 0) {
                rc = SKP_ERR_CTX_MISMATCH;
                goto done;
            }
        }
    }
    size_t ctl = strlen(ct->valuestring), ctb_len = 0;
    ctbuf = malloc(ctl + 1);
    if (!ctbuf) {
        rc = SKP_ERR_NOMEM;
        goto done;
    }
    if (skp_b64_decode(ctbuf, ctl + 1, &ctb_len, ct->valuestring, ctl, 0) != 0 ||
        ctb_len < crypto_aead_chacha20poly1305_ietf_ABYTES) {
        rc = SKP_ERR_BAD_REQUEST;
        goto done;
    }
    size_t expect_len = 4 + (size_t)SKP_RECORD_SIZE * st->max_len;
    if (ctb_len - crypto_aead_chacha20poly1305_ietf_ABYTES != expect_len) {
        /* still authenticate first so a wrong-key payload reports BAD_MAC, not TAMPERED */
    }
    batch = sodium_malloc(ctb_len);
    if (!batch) {
        rc = SKP_ERR_NOMEM;
        goto done;
    }
    {
        uint8_t nonce[12], aad[12 + 16];
        skp_nonce12(nonce, 0);
        memcpy(aad, SKP_AAD_INPUT, 12);
        memcpy(aad + 12, st->sid, 16);
        unsigned long long plen = 0;
        if (crypto_aead_chacha20poly1305_ietf_decrypt(batch, &plen, NULL, ctbuf, ctb_len, aad, sizeof aad, nonce,
                                                      st->k_c2s) != 0) {
            rc = SKP_ERR_BAD_MAC;
            goto done;
        }
        if ((size_t)plen != expect_len) {
            rc = SKP_ERR_TAMPERED;
            goto done;
        }
    }
    uint32_t count = get16(batch + 2);
    if (batch[0] != 1 || batch[1] != 0 || count > st->max_len) {
        rc = SKP_ERR_TAMPERED;
        goto done;
    }
    layouts = sodium_malloc(sizeof(skp_layout) * (size_t)st->ngens);
    result = sodium_malloc((size_t)st->max_len * 4 + 1);
    cps = sodium_malloc(sizeof(uint32_t) * ((size_t)st->max_len + 1));
    composed = sodium_malloc(sizeof(uint32_t) * ((size_t)st->max_len + 1));
    if (!layouts || !result || !cps || !composed) {
        rc = SKP_ERR_NOMEM;
        goto done;
    }
    size_t ncps = 0;
    for (uint32_t i = 0; i < st->max_len; i++) {
        const uint8_t *rec = batch + 4 + (size_t)i * SKP_RECORD_SIZE;
        if (i >= count) {
            if (!sodium_is_zero(rec, SKP_RECORD_SIZE)) {
                rc = SKP_ERR_TAMPERED;
                goto done;
            }
            continue;
        }
        uint32_t seq = get16(rec), lid = rec[2], flags = rec[3], x = get16(rec + 4), y = get16(rec + 6);
        if (seq != i || flags != 0) {
            rc = SKP_ERR_TAMPERED;
            goto done;
        }
        int gen = (int)(lid >> 3), slot = (int)(lid & 7);
        if (gen >= st->ngens) {
            rc = SKP_ERR_TAMPERED;
            goto done;
        }
        if (!built[gen]) {
            const skp_gen *g = &st->gens[gen];
            rc = skp_layout_build(&layouts[gen], st->type, st->policy, st->blank, st->style, st->langs, st->nlangs, g->W,
                                  g->dpr_milli, g->seed);
            if (rc)
                goto done;
            built[gen] = 1;
        }
        const skp_layout *l = &layouts[gen];
        if ((int32_t)x >= l->W || (int32_t)y >= l->H) {
            rc = SKP_ERR_TAMPERED;
            goto done;
        }
        const skp_layer *layer = skp_layout_slot(l, slot);
        const skp_key *k = layer ? skp_layout_hit(layer, (int32_t)x, (int32_t)y) : NULL;
        if (!k || (k->role != SKP_ROLE_CHAR && k->role != SKP_ROLE_SPACE)) {
            rc = SKP_ERR_TAMPERED;
            goto done;
        }
        cps[ncps++] = k->cp;
    }
    /* Korean jamo compose into syllables (spec/HANGUL.md); everything else passes through */
    size_t ncomposed = skp_hangul_compose(cps, ncps, composed);
    size_t rlen = 0;
    for (size_t i = 0; i < ncomposed; i++)
        rlen += utf8_encode(result + rlen, composed[i]);
    skp_secret *s = malloc(sizeof *s);
    if (!s) {
        rc = SKP_ERR_NOMEM;
        goto done;
    }
    s->data = sodium_malloc(rlen ? rlen : 1);
    if (!s->data) {
        free(s);
        rc = SKP_ERR_NOMEM;
        goto done;
    }
    memcpy(s->data, result, rlen);
    s->len = rlen;
    *out = s;
    rc = SKP_OK;
done:
    if (result)
        sodium_free(result);
    if (cps)
        sodium_free(cps);
    if (composed)
        sodium_free(composed);
    if (layouts)
        sodium_free(layouts);
    if (batch)
        sodium_free(batch);
    free(ctbuf);
    cJSON_Delete(root);
    sodium_free(st);
    sodium_stackzero(16384);
    return rc;
}

int skp_session_info(const skp_ctx *ctx, const uint8_t *sealed, size_t sealed_len, int64_t *expires_out,
                     char *sid_b64url_out, size_t sid_cap) {
    if (!ctx || !sealed)
        return SKP_ERR_INVALID_ARG;
    skp_state *st = sodium_malloc(sizeof *st);
    if (!st)
        return SKP_ERR_NOMEM;
    int rc = skp_state_unseal(ctx, sealed, sealed_len, st);
    if (rc == SKP_OK) {
        if (expires_out)
            *expires_out = st->expires;
        if (sid_b64url_out) {
            char *b = NULL;
            rc = skp_b64_encode(&b, st->sid, 16, 1);
            if (rc == SKP_OK) {
                if (strlen(b) + 1 > sid_cap)
                    rc = SKP_ERR_INVALID_ARG;
                else
                    memcpy(sid_b64url_out, b, strlen(b) + 1);
                free(b);
            }
        }
    }
    sodium_free(st);
    return rc;
}
