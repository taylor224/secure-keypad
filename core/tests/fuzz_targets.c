/* Fuzz targets for the wire parsers and the sealed-state opener.
 *
 * Built two ways:
 *   - with clang -fsanitize=fuzzer (CMake option SKP_FUZZ=ON): each target is a libFuzzer binary
 *     selected by the SKP_FUZZ_TARGET compile definition;
 *   - as the `fuzz_smoke` test everywhere else: a deterministic mutation loop over valid inputs that
 *     asserts the library only ever answers with a documented error code and never crashes.
 */
#include "test_util.h"
#include <stdint.h>

static skp_ctx *g_ctx;
static skp_buf g_sealed;
static char *g_payload;      /* valid payload for g_sealed */
static char *g_request;      /* valid session request */
static uint8_t g_seed[32] = {0x77, 0x01};

static void setup(void) {
    if (g_ctx)
        return;
    skp_config cfg = {0};
    cfg.master_key = "0f1e2d3c4b5a69788796a5b4c3d2e1f0f0e1d2c3b4a5968778695a4b3c2d1e0f";
    if (skp_init(&g_ctx, &cfg) != SKP_OK)
        abort();
    static const uint8_t s_sk[32] = {1}, sid[16] = {2}, nonce[24] = {3};
    skp_test_hooks h = {s_sk, sid, g_seed, nonce, 1757000000, 1};
    skp_test_set_hooks(&h);
    uint8_t c_sk[32] = {9}, c_pk[32];
    crypto_scalarmult_base(c_pk, c_sk);
    char *kp = NULL;
    skp_b64_encode(&kp, c_pk, 32, 0);
    g_request = malloc(256);
    snprintf(g_request, 256, "{\"v\":1,\"kp\":\"%s\",\"type\":\"number\",\"viewport\":{\"w\":390,\"dpr\":3,\"platform\":\"ios\"}}", kp);
    free(kp);
    skp_buf resp = {0};
    skp_session_opts opts = {"ctx", "shuffle", "fixed", 0, 0, NULL}; /* blank is cell 9: the top row is always digits */
    if (skp_session_create(g_ctx, g_request, 0, &opts, &resp, &g_sealed) != SKP_OK)
        abort();
    test_client cl;
    if (client_open(&cl, (const char *)resp.data, c_sk, NULL) != 0)
        abort();
    int32_t taps[3][3] = {{0, 100, 100}, {0, 500, 100}, {0, 900, 100}}; /* slot 0 = the number layer */
    g_payload = client_build_payload(&cl, 16, taps, 3);
    client_free(&cl);
    skp_buf_free(&resp);
}

static void check_rc(int rc) {
    if (rc > 0 || rc < SKP_ERR_UNSUPPORTED)
        abort(); /* undocumented error code */
}

/* --- targets ---------------------------------------------------------------------------------- */
static void target_unseal(const uint8_t *data, size_t len) {
    skp_secret *s = NULL;
    check_rc(skp_session_decrypt(g_ctx, data, len, g_payload, 0, "ctx", &s));
    if (s)
        skp_secret_free(s);
    int64_t exp;
    char sid[32];
    check_rc(skp_session_info(g_ctx, data, len, &exp, sid, sizeof sid));
}

static void target_payload(const uint8_t *data, size_t len) {
    char *p = malloc(len + 1);
    memcpy(p, data, len);
    p[len] = 0;
    skp_secret *s = NULL;
    int rc = skp_session_decrypt(g_ctx, g_sealed.data, g_sealed.len, p, len, "ctx", &s);
    check_rc(rc);
    if (s)
        skp_secret_free(s);
    free(p);
}

static void target_request(const uint8_t *data, size_t len) {
    char *p = malloc(len + 1);
    memcpy(p, data, len);
    p[len] = 0;
    skp_buf resp = {0}, sealed = {0};
    check_rc(skp_session_create(g_ctx, p, len, NULL, &resp, &sealed));
    skp_buf_free(&resp);
    skp_buf_free(&sealed);
    check_rc(skp_session_relayout(g_ctx, g_sealed.data, g_sealed.len, p, len, &resp, &sealed));
    skp_buf_free(&resp);
    skp_buf_free(&sealed);
    free(p);
}

#ifdef SKP_LIBFUZZER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    setup();
#if SKP_FUZZ_TARGET == 1
    target_unseal(data, size);
#elif SKP_FUZZ_TARGET == 2
    target_payload(data, size);
#else
    target_request(data, size);
#endif
    return 0;
}
#else
/* Smoke mode: xorshift-driven byte/bit mutations of the valid inputs plus truncations. */
static uint64_t rng = 0x9E3779B97F4A7C15ULL;
static uint64_t next(void) {
    rng ^= rng << 13;
    rng ^= rng >> 7;
    rng ^= rng << 17;
    return rng;
}

static void mutate(uint8_t *buf, size_t len) {
    int ops = 1 + (int)(next() % 4);
    for (int i = 0; i < ops && len; i++) {
        size_t at = next() % len;
        switch (next() % 3) {
        case 0: buf[at] ^= (uint8_t)(1u << (next() % 8)); break;
        case 1: buf[at] = (uint8_t)next(); break;
        default: buf[at] = (uint8_t)"{}[]\":,0123456789abcdefAZ+/=\\ "[next() % 30]; break;
        }
    }
}

static void run(void (*target)(const uint8_t *, size_t), const uint8_t *valid, size_t len, int iters, const char *name) {
    uint8_t *buf = malloc(len + 1);
    for (int i = 0; i < iters; i++) {
        size_t n = len;
        memcpy(buf, valid, len);
        if (next() % 8 == 0)
            n = next() % (len + 1); /* truncation */
        else
            mutate(buf, n);
        target(buf, n);
    }
    free(buf);
    printf("  %s: %d mutations survived\n", name, iters);
}

int main(int argc, char **argv) {
    setup();
    int iters = argc > 1 ? atoi(argv[1]) : 4000;
    /* the untouched inputs must still work */
    skp_secret *s = NULL;
    CHECK(skp_session_decrypt(g_ctx, g_sealed.data, g_sealed.len, g_payload, 0, "ctx", &s) == SKP_OK, "baseline decrypt");
    CHECK(s && skp_secret_len(s) == 3, "baseline length");
    if (s)
        skp_secret_free(s);
    run(target_unseal, g_sealed.data, g_sealed.len, iters, "sealed blob");
    run(target_payload, (const uint8_t *)g_payload, strlen(g_payload), iters, "input payload");
    run(target_request, (const uint8_t *)g_request, strlen(g_request), iters, "session/relayout request");
    /* random garbage of assorted sizes */
    uint8_t junk[512];
    for (int i = 0; i < iters / 4; i++) {
        size_t n = next() % sizeof junk;
        for (size_t k = 0; k < n; k++)
            junk[k] = (uint8_t)next();
        target_unseal(junk, n);
        target_payload(junk, n);
        target_request(junk, n);
    }
    printf("  garbage: %d rounds survived\n", iters / 4);
    skp_test_set_hooks(NULL);
    skp_buf_free(&g_sealed);
    free(g_payload);
    free(g_request);
    skp_free(g_ctx);
    printf("%d failures\n", g_failures);
    return g_failures ? 1 : 0;
}
#endif
