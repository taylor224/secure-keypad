/* API-level tests with real randomness and rendering: key loading, full round trip, relayout, errors. */
#include "test_util.h"

static const char *REQ_Q =
    "{\"v\":1,\"kp\":\"%s\",\"type\":\"qwerty\",\"viewport\":{\"w\":390,\"dpr\":3,\"platform\":\"ios\"},\"opts\":{\"maxLen\":16}}";
static const char *REQ_N =
    "{\"v\":1,\"kp\":\"%s\",\"type\":\"number\",\"viewport\":{\"w\":412,\"dpr\":2.625,\"platform\":\"android\"}}";

static void make_request(char *out, size_t cap, const char *tmpl, const uint8_t c_sk[32]) {
    uint8_t c_pk[32];
    crypto_scalarmult_base(c_pk, c_sk);
    char *b = NULL;
    skp_b64_encode(&b, c_pk, 32, 0);
    snprintf(out, cap, tmpl, b);
    free(b);
}

/* Finds the centre of the key carrying codepoint cp in the given layout/mode (server-side knowledge). */
static int tap_for(const skp_layout *l, int gen, uint32_t cp, int32_t out[3]) {
    for (int i = 0; i < l->nlayers; i++)
        for (int k = 0; k < l->layers[i].nkeys; k++) {
            const skp_key *key = &l->layers[i].keys[k];
            if ((key->role == SKP_ROLE_CHAR || key->role == SKP_ROLE_SPACE) && key->cp == cp) {
                out[0] = (gen << 3) | l->layers[i].mode;
                out[1] = key->x + key->w / 2;
                out[2] = key->y + key->h / 2;
                return 1;
            }
        }
    return 0;
}

static void test_key_loading(void) {
    printf("key loading\n");
    uint8_t raw[32];
    CHECK(skp_keygen(raw) == SKP_OK, "keygen");
    char b64[64];
    CHECK(skp_keygen_b64(b64, sizeof b64) == SKP_OK && strlen(b64) == 44, "keygen b64");
    char path[] = "/tmp/skp_test_key_XXXXXX";
    int fd = mkstemp(path);
    CHECK(fd >= 0, "mkstemp");
    dprintf(fd, "  %s\n", b64);
    close(fd);
    skp_config cfg = {0};
    cfg.master_key_path = path;
    skp_ctx *a = NULL, *b = NULL, *c = NULL;
    CHECK(skp_init(&a, &cfg) == SKP_OK, "init from file");
    skp_config cfg2 = {0};
    cfg2.master_key = b64;
    CHECK(skp_init(&b, &cfg2) == SKP_OK, "init from string");
    char ka[64], kb[64];
    skp_public_key(a, ka, sizeof ka);
    skp_public_key(b, kb, sizeof kb);
    CHECK(!strcmp(ka, kb), "same key → same public key");
    /* hex form */
    uint8_t rawb[32];
    size_t got;
    skp_b64_decode(rawb, 32, &got, b64, strlen(b64), 0);
    char *hex = to_hex(rawb, 32);
    skp_config cfg3 = {0};
    cfg3.master_key = hex;
    CHECK(skp_init(&c, &cfg3) == SKP_OK, "init from hex");
    char kc[64];
    skp_public_key(c, kc, sizeof kc);
    CHECK(!strcmp(ka, kc), "hex form → same public key");
    free(hex);
    /* raw 32 bytes */
    skp_ctx *d = NULL;
    skp_config cfg4 = {0};
    cfg4.master_key = (const char *)rawb;
    cfg4.master_key_len = 32;
    CHECK(skp_init(&d, &cfg4) == SKP_OK, "init from raw");
    if (d) {
        char kd[64];
        skp_public_key(d, kd, sizeof kd);
        CHECK(!strcmp(ka, kd), "raw form → same public key");
        skp_free(d);
    }
    /* errors */
    skp_ctx *e = NULL;
    skp_config bad = {0};
    CHECK(skp_init(&e, &bad) == SKP_ERR_INVALID_ARG, "no key source");
    bad.master_key = "not-a-key";
    CHECK(skp_init(&e, &bad) == SKP_ERR_BAD_KEY, "garbage key");
    bad.master_key = NULL;
    bad.master_key_path = "/nonexistent/skp.key";
    CHECK(skp_init(&e, &bad) == SKP_ERR_IO, "missing file");
    unlink(path);
    skp_free(a);
    skp_free(b);
    skp_free(c);
}

static void test_roundtrip(void) {
    printf("round trip with rendering\n");
    skp_config cfg = {0};
    cfg.master_key = "0f1e2d3c4b5a69788796a5b4c3d2e1f0f0e1d2c3b4a5968778695a4b3c2d1e0f";
    skp_ctx *ctx = NULL;
    CHECK(skp_init(&ctx, &cfg) == SKP_OK, "init");
    uint8_t pk[32], c_sk[32] = {7};
    {
        char b[64];
        size_t got;
        skp_public_key(ctx, b, sizeof b);
        skp_b64_decode(pk, 32, &got, b, strlen(b), 0);
    }
    /* inject the seed only so the test can rebuild the layout; everything else stays random */
    uint8_t seed[32];
    randombytes_buf(seed, 32);
    skp_test_hooks h = {NULL, NULL, seed, NULL, 0, 0};
    skp_test_set_hooks(&h);

    char req[512];
    make_request(req, sizeof req, REQ_Q, c_sk);
    skp_session_opts opts = {"attempt-1", "shuffle", NULL, 0, 0};
    skp_buf resp = {0}, sealed = {0};
    int rc = skp_session_create(ctx, req, 0, &opts, &resp, &sealed);
    CHECK(rc == SKP_OK, "create: %s", skp_strerror(rc));
    int64_t exp = 0;
    char sid[32];
    CHECK(skp_session_info(ctx, sealed.data, sealed.len, &exp, sid, sizeof sid) == SKP_OK, "info");
    CHECK(exp > skp_now() + 170 && exp <= skp_now() + 180, "expiry ~180s");
    test_client cl;
    rc = client_open(&cl, (const char *)resp.data, c_sk, pk);
    CHECK(rc == 0, "client open %d", rc);
    CHECK(cl.tiles_len > 100 && cl.popups_len > 100, "sprites present (%zu, %zu)", cl.tiles_len, cl.popups_len);
    CHECK(!memcmp(cl.tiles, "\x89PNG", 4) && !memcmp(cl.popups, "\x89PNG", 4), "sprites are PNG");
    cJSON *inner = cJSON_Parse(cl.inner_json);
    CHECK(inner && jint(inner, "maxLen") == 16 && jint(inner, "w") == 1170 && jint(inner, "h") == 648, "inner json");
    CHECK(cJSON_GetArraySize(cJSON_GetObjectItemCaseSensitive(inner, "layouts")) == 4, "4 layers");
    /* rebuild the server layout from the injected seed to find where characters are */
    skp_layout *l = malloc(sizeof *l);
    CHECK(skp_layout_build(l, SKP_TYPE_QWERTY, SKP_POLICY_SHUFFLE, SKP_BLANK_FIXED, SKP_STYLE_IOS, 1170, 3000, seed) == SKP_OK, "layout");
    const char *text = "Pw 9!";
    int32_t taps[8][3];
    size_t n = 0;
    for (const char *p = text; *p; p++)
        CHECK(tap_for(l, 0, (uint32_t)*p, taps[n++]), "tap for %c", *p);
    char *payload = client_build_payload(&cl, 16, taps, n);
    skp_secret *s = NULL;
    rc = skp_session_decrypt(ctx, sealed.data, sealed.len, payload, 0, "attempt-1", &s);
    CHECK(rc == SKP_OK, "decrypt: %s", skp_strerror(rc));
    if (s) {
        CHECK(skp_secret_len(s) == strlen(text) && !memcmp(skp_secret_bytes(s), text, strlen(text)), "plaintext");
        skp_secret_free(s);
    }
    /* wrong ctx */
    CHECK(skp_session_decrypt(ctx, sealed.data, sealed.len, payload, 0, "attempt-2", &s) == SKP_ERR_CTX_MISMATCH, "ctx mismatch");
    /* a tap on shift is rejected */
    const skp_layer *lower = skp_layout_layer(l, SKP_MODE_LOWER);
    for (int k = 0; k < lower->nkeys; k++)
        if (lower->keys[k].role == SKP_ROLE_SHIFT) {
            int32_t bad[1][3] = {{0, lower->keys[k].x + 2, lower->keys[k].y + 2}};
            char *bp = client_build_payload(&cl, 16, bad, 1);
            CHECK(skp_session_decrypt(ctx, sealed.data, sealed.len, bp, 0, "attempt-1", &s) == SKP_ERR_TAMPERED, "shift tap");
            free(bp);
        }
    /* too many taps → wrong batch length is a MAC failure at the client, here: tamper via count */
    /* relayout to landscape and type more using generation 1 */
    char rreq[256];
    snprintf(rreq, sizeof rreq, "{\"v\":1,\"sid\":\"%s\",\"viewport\":{\"w\":844,\"dpr\":3,\"platform\":\"ios\"}}", sid);
    skp_buf rresp = {0}, sealed2 = {0};
    rc = skp_session_relayout(ctx, sealed.data, sealed.len, rreq, 0, &rresp, &sealed2);
    CHECK(rc == SKP_OK, "relayout: %s", skp_strerror(rc));
    if (rc == SKP_OK) {
        skp_layout *l2 = malloc(sizeof *l2);
        skp_layout_build(l2, SKP_TYPE_QWERTY, SKP_POLICY_SHUFFLE, SKP_BLANK_FIXED, SKP_STYLE_IOS, 2532, 3000, seed);
        int32_t taps2[8][3];
        size_t n2 = n;
        memcpy(taps2, taps, sizeof(int32_t) * 3 * n);
        CHECK(tap_for(l2, 1, 'z', taps2[n2++]), "tap gen1");
        char *p2 = client_build_payload(&cl, 16, taps2, n2);
        rc = skp_session_decrypt(ctx, sealed2.data, sealed2.len, p2, 0, "attempt-1", &s);
        CHECK(rc == SKP_OK, "decrypt after relayout: %s", skp_strerror(rc));
        if (s) {
            CHECK(skp_secret_len(s) == 6 && !memcmp(skp_secret_bytes(s), "Pw 9!z", 6), "plaintext gen1");
            skp_secret_free(s);
        }
        /* the old blob does not know generation 1 */
        CHECK(skp_session_decrypt(ctx, sealed.data, sealed.len, p2, 0, "attempt-1", &s) == SKP_ERR_TAMPERED, "old blob");
        /* wrong sid for relayout */
        char rreq2[256];
        snprintf(rreq2, sizeof rreq2, "{\"v\":1,\"sid\":\"AAAAAAAAAAAAAAAAAAAAAA\",\"viewport\":{\"w\":844,\"dpr\":3,\"platform\":\"ios\"}}");
        skp_buf r3 = {0}, s3 = {0};
        CHECK(skp_session_relayout(ctx, sealed.data, sealed.len, rreq2, 0, &r3, &s3) == SKP_ERR_SID_MISMATCH, "relayout sid");
        free(p2);
        sodium_memzero(l2, sizeof *l2);
        free(l2);
    }
    /* expired */
    skp_test_hooks late = {NULL, NULL, seed, NULL, skp_now() + 1000, 0};
    skp_test_set_hooks(&late);
    CHECK(skp_session_decrypt(ctx, sealed.data, sealed.len, payload, 0, "attempt-1", &s) == SKP_ERR_EXPIRED, "expired");
    skp_test_set_hooks(NULL);
    /* garbage inputs */
    CHECK(skp_session_decrypt(ctx, sealed.data, sealed.len, "{}", 0, NULL, &s) == SKP_ERR_BAD_REQUEST, "bad payload json");
    CHECK(skp_session_decrypt(ctx, sealed.data, sealed.len - 3, payload, 0, "attempt-1", &s) == SKP_ERR_BAD_MAC, "truncated blob");
    CHECK(skp_session_create(ctx, "{\"v\":2}", 0, NULL, &rresp, &sealed2) == SKP_ERR_BAD_REQUEST, "bad request");
    skp_session_opts bad_opts = {NULL, "diagonal", NULL, 0, 0};
    CHECK(skp_session_create(ctx, req, 0, &bad_opts, &rresp, &sealed2) == SKP_ERR_UNSUPPORTED, "bad layout option");

    free(payload);
    cJSON_Delete(inner);
    client_free(&cl);
    sodium_memzero(l, sizeof *l);
    free(l);
    skp_buf_free(&resp);
    skp_buf_free(&sealed);
    skp_buf_free(&rresp);
    skp_buf_free(&sealed2);
    skp_free(ctx);
}

static void test_number_pad_and_limits(void) {
    printf("number pad, max_len cap, fixed layout\n");
    skp_config cfg = {0};
    cfg.master_key = "0f1e2d3c4b5a69788796a5b4c3d2e1f0f0e1d2c3b4a5968778695a4b3c2d1e0f";
    cfg.max_len_cap = 6;
    skp_ctx *ctx = NULL;
    CHECK(skp_init(&ctx, &cfg) == SKP_OK, "init");
    uint8_t c_sk[32] = {9};
    char req[512];
    make_request(req, sizeof req, REQ_N, c_sk);
    skp_session_opts opts = {NULL, NULL, "random", 0, 0};
    skp_buf resp = {0}, sealed = {0};
    CHECK(skp_session_create(ctx, req, 0, &opts, &resp, &sealed) == SKP_OK, "create number");
    test_client cl;
    CHECK(client_open(&cl, (const char *)resp.data, c_sk, NULL) == 0, "open");
    cJSON *inner = cJSON_Parse(cl.inner_json);
    CHECK(jint(inner, "maxLen") == 6, "cap applied (16 → 6)");
    const cJSON *layouts = cJSON_GetObjectItemCaseSensitive(inner, "layouts");
    CHECK(cJSON_GetArraySize(layouts) == 1, "one layer");
    const cJSON *keys = cJSON_GetObjectItemCaseSensitive(cJSON_GetArrayItem(layouts, 0), "keys");
    int chars = 0, blanks = 0, bs = 0;
    const cJSON *k;
    cJSON_ArrayForEach(k, keys) {
        const char *role = jstr(k, "role");
        chars += !strcmp(role, "char");
        blanks += !strcmp(role, "blank");
        bs += !strcmp(role, "backspace");
    }
    CHECK(chars == 10 && blanks == 1 && bs == 1, "number pad roles %d %d %d", chars, blanks, bs);
    CHECK(jint(cJSON_GetObjectItemCaseSensitive(inner, "tile"), "count") == 10, "tile count");
    cJSON_Delete(inner);
    client_free(&cl);
    skp_buf_free(&resp);
    skp_buf_free(&sealed);
    /* fixed layout warning path */
    skp_session_opts fixed = {NULL, "fixed", NULL, 0, 0};
    make_request(req, sizeof req, REQ_Q, c_sk);
    CHECK(skp_session_create(ctx, req, 0, &fixed, &resp, &sealed) == SKP_OK, "create fixed");
    skp_buf_free(&resp);
    skp_buf_free(&sealed);
    skp_free(ctx);
}

int main(void) {
    test_key_loading();
    test_roundtrip();
    test_number_pad_and_limits();
    printf("%d failures\n", g_failures);
    return g_failures ? 1 : 0;
}
