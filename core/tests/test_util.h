/* Shared helpers for the C test programs (not part of the library). */
#ifndef SKP_TEST_UTIL_H
#define SKP_TEST_UTIL_H

#include "skp.h"
#include "skp_internal.h"
#include "../third_party/cJSON.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int g_failures = 0;
#define CHECK(cond, ...)                                                                                     \
    do {                                                                                                     \
        if (!(cond)) {                                                                                       \
            g_failures++;                                                                                    \
            fprintf(stderr, "  FAIL %s:%d: ", __FILE__, __LINE__);                                           \
            fprintf(stderr, __VA_ARGS__);                                                                    \
            fprintf(stderr, "\n");                                                                           \
        }                                                                                                    \
    } while (0)

/* Reads a whole file with unbuffered syscalls (no stdio buffer copies linger). */
static char *read_file(const char *path, size_t *len_out) {
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return NULL;
    size_t cap = 1 << 16, len = 0;
    char *buf = malloc(cap);
    if (!buf) {
        close(fd);
        return NULL;
    }
    for (;;) {
        if (len + 4096 > cap) {
            cap *= 2;
            char *nb = realloc(buf, cap);
            if (!nb) {
                free(buf);
                close(fd);
                return NULL;
            }
            buf = nb;
        }
        ssize_t n = read(fd, buf + len, cap - len - 1);
        if (n < 0) {
            free(buf);
            close(fd);
            return NULL;
        }
        if (n == 0)
            break;
        len += (size_t)n;
    }
    close(fd);
    buf[len] = 0;
    if (len_out)
        *len_out = len;
    return buf;
}

static size_t unhex(uint8_t *out, size_t cap, const char *hex) {
    size_t n = strlen(hex);
    int r = skp_hex_decode(out, cap, hex, n);
    return r < 0 ? 0 : (size_t)r;
}

static char *to_hex(const uint8_t *b, size_t n) {
    char *s = malloc(2 * n + 1);
    static const char d[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        s[2 * i] = d[b[i] >> 4];
        s[2 * i + 1] = d[b[i] & 15];
    }
    s[2 * n] = 0;
    return s;
}

static const char *jstr(const cJSON *o, const char *k) {
    const cJSON *i = cJSON_GetObjectItemCaseSensitive(o, k);
    return cJSON_IsString(i) ? i->valuestring : NULL;
}

static int64_t jint(const cJSON *o, const char *k) {
    const cJSON *i = cJSON_GetObjectItemCaseSensitive(o, k);
    return cJSON_IsNumber(i) ? (int64_t)i->valuedouble : 0;
}

/* Zeroes every string value in a cJSON tree before it is deleted. */
static void json_wipe(cJSON *n) {
    for (; n; n = n->next) {
        if (n->valuestring)
            sodium_memzero(n->valuestring, strlen(n->valuestring));
        if (n->child)
            json_wipe(n->child);
    }
}

static int error_code_by_name(const char *name) {
    static const struct {
        const char *n;
        int c;
    } t[] = {{"NOMEM", -1},    {"INVALID_ARG", -2},  {"BAD_KEY", -3},      {"BAD_REQUEST", -4},
             {"CRYPTO", -5},   {"EXPIRED", -6},      {"BAD_MAC", -7},      {"TAMPERED", -8},
             {"CTX_MISMATCH", -9}, {"SID_MISMATCH", -10}, {"RENDER", -11}, {"IO", -12}, {"UNSUPPORTED", -13}};
    for (size_t i = 0; i < sizeof t / sizeof t[0]; i++)
        if (!strcmp(t[i].n, name))
            return t[i].c;
    return 999;
}

/* ---- a minimal client, used by tests to open a session response ------------------------------ */
typedef struct {
    uint8_t sid[16], k_s2c[32], k_c2s[32];
    char *inner_json;
    uint8_t *tiles, *popups;
    size_t tiles_len, popups_len;
} test_client;

static uint32_t rd32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static int client_open(test_client *c, const char *resp_json, const uint8_t c_sk[32], const uint8_t *pk_sign) {
    memset(c, 0, sizeof *c);
    cJSON *r = cJSON_Parse(resp_json);
    if (!r)
        return -1;
    uint8_t s_pk[32], sig[64], c_pk[32];
    size_t got;
    const char *sid = jstr(r, "sid"), *sp = jstr(r, "sp"), *sg = jstr(r, "sig"), *ct = jstr(r, "ct"), *kid = jstr(r, "kid");
    if (!sid || !sp || !sg || !ct || !kid)
        return -2;
    if (skp_b64_decode(c->sid, 16, &got, sid, strlen(sid), 1) || got != 16)
        return -3;
    if (skp_b64_decode(s_pk, 32, &got, sp, strlen(sp), 0) || got != 32)
        return -4;
    if (skp_b64_decode(sig, 64, &got, sg, strlen(sg), 0) || got != 64)
        return -5;
    size_t ctl = strlen(ct);
    uint8_t *ctb = malloc(ctl);
    size_t ctb_len;
    if (skp_b64_decode(ctb, ctl, &ctb_len, ct, ctl, 0))
        return -6;
    crypto_scalarmult_base(c_pk, c_sk);
    if (pk_sign) {
        uint8_t msg[14 + 8 + 16 + 32 + 32 + 32];
        memcpy(msg, "skp/v1/session", 14);
        memcpy(msg + 14, kid, 8);
        memcpy(msg + 22, c->sid, 16);
        memcpy(msg + 38, c_pk, 32);
        memcpy(msg + 70, s_pk, 32);
        crypto_hash_sha256(msg + 102, ctb, ctb_len);
        if (crypto_sign_verify_detached(sig, msg, sizeof msg, pk_sign) != 0) {
            free(ctb);
            cJSON_Delete(r);
            return -7;
        }
    }
    uint8_t ss[32], prk[32], salt[22], info[67];
    if (crypto_scalarmult(ss, c_sk, s_pk) != 0)
        return -8;
    memcpy(salt, "skp/v1", 6);
    memcpy(salt + 6, c->sid, 16);
    skp_hkdf_extract(prk, salt, 22, ss, 32);
    memcpy(info, "s2c", 3);
    memcpy(info + 3, c_pk, 32);
    memcpy(info + 35, s_pk, 32);
    skp_hkdf_expand(c->k_s2c, 32, prk, info, 67);
    memcpy(info, "c2s", 3);
    skp_hkdf_expand(c->k_c2s, 32, prk, info, 67);
    uint8_t nonce[12], aad[30];
    skp_nonce12(nonce, 0);
    memcpy(aad, "skp/v1/session", 14);
    memcpy(aad + 14, c->sid, 16);
    uint8_t *pt = malloc(ctb_len);
    unsigned long long pl;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(pt, &pl, NULL, ctb, ctb_len, aad, 30, nonce, c->k_s2c) != 0) {
        free(pt);
        free(ctb);
        cJSON_Delete(r);
        return -9;
    }
    free(ctb);
    cJSON_Delete(r);
    size_t pos = 0;
    uint32_t jl = rd32(pt + pos);
    pos += 4;
    c->inner_json = malloc(jl + 1);
    memcpy(c->inner_json, pt + pos, jl);
    c->inner_json[jl] = 0;
    pos += jl;
    c->tiles_len = rd32(pt + pos);
    pos += 4;
    c->tiles = malloc(c->tiles_len + 1);
    memcpy(c->tiles, pt + pos, c->tiles_len);
    pos += c->tiles_len;
    c->popups_len = rd32(pt + pos);
    pos += 4;
    c->popups = malloc(c->popups_len + 1);
    memcpy(c->popups, pt + pos, c->popups_len);
    pos += c->popups_len;
    sodium_memzero(pt, pl);
    free(pt);
    return pos == pl ? 0 : -10;
}

static void client_free(test_client *c) {
    if (c->inner_json)
        sodium_memzero(c->inner_json, strlen(c->inner_json));
    free(c->inner_json);
    free(c->tiles);
    free(c->popups);
    sodium_memzero(c, sizeof *c);
}

/* Builds the encrypted input payload JSON for a tap list. taps: {layout_id, x, y} triples. */
static char *client_build_payload(const test_client *c, uint32_t max_len, const int32_t (*taps)[3], size_t ntaps) {
    size_t bl = 4 + 8 * (size_t)max_len;
    uint8_t *batch = calloc(bl, 1);
    batch[0] = 1;
    batch[2] = (uint8_t)(ntaps >> 8);
    batch[3] = (uint8_t)ntaps;
    for (size_t i = 0; i < ntaps; i++) {
        uint8_t *r = batch + 4 + 8 * i;
        r[0] = (uint8_t)(i >> 8);
        r[1] = (uint8_t)i;
        r[2] = (uint8_t)taps[i][0];
        r[3] = 0;
        r[4] = (uint8_t)(taps[i][1] >> 8);
        r[5] = (uint8_t)taps[i][1];
        r[6] = (uint8_t)(taps[i][2] >> 8);
        r[7] = (uint8_t)taps[i][2];
    }
    uint8_t nonce[12], aad[28];
    skp_nonce12(nonce, 0);
    memcpy(aad, "skp/v1/input", 12);
    memcpy(aad + 12, c->sid, 16);
    uint8_t *ct = malloc(bl + 16);
    unsigned long long cl;
    crypto_aead_chacha20poly1305_ietf_encrypt(ct, &cl, batch, bl, aad, 28, NULL, nonce, c->k_c2s);
    sodium_memzero(batch, bl);
    free(batch);
    char *sid_b64 = NULL, *ct_b64 = NULL;
    skp_b64_encode(&sid_b64, c->sid, 16, 1);
    skp_b64_encode(&ct_b64, ct, (size_t)cl, 0);
    free(ct);
    char *json = malloc(strlen(sid_b64) + strlen(ct_b64) + 64);
    sprintf(json, "{\"v\":1,\"sid\":\"%s\",\"ct\":\"%s\"}", sid_b64, ct_b64);
    free(sid_b64);
    free(ct_b64);
    return json;
}

#endif
