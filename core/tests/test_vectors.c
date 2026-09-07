/* Replays every JSON vector in spec/vectors against the C core: every byte of the server output must match. */
#include "test_util.h"
#include <dirent.h>

static void run_vector(const char *path) {
    size_t len;
    char *text = read_file(path, &len);
    if (!text) {
        CHECK(0, "cannot read %s", path);
        return;
    }
    cJSON *v = cJSON_ParseWithLength(text, len);
    free(text);
    if (!v) {
        CHECK(0, "cannot parse %s", path);
        return;
    }
    printf("vector %s\n", jstr(v, "name"));

    skp_config cfg = {0};
    cfg.master_key = jstr(v, "master_key");
    skp_ctx *ctx = NULL;
    int rc = skp_init(&ctx, &cfg);
    CHECK(rc == SKP_OK, "init: %s", skp_strerror(rc));
    if (rc)
        return;
    const cJSON *em = cJSON_GetObjectItemCaseSensitive(v, "expect_master");
    char kid[SKP_KID_CAP], pk[SKP_PUBLIC_KEY_B64_CAP];
    skp_key_id(ctx, kid, sizeof kid);
    skp_public_key(ctx, pk, sizeof pk);
    CHECK(!strcmp(kid, jstr(em, "kid")), "kid %s != %s", kid, jstr(em, "kid"));
    {
        uint8_t pkb[32];
        size_t got;
        skp_b64_decode(pkb, 32, &got, pk, strlen(pk), 0);
        char *h = to_hex(pkb, 32);
        CHECK(!strcmp(h, jstr(em, "pk_sign")), "pk_sign mismatch");
        free(h);
    }

    const cJSON *hooks = cJSON_GetObjectItemCaseSensitive(v, "hooks");
    uint8_t s_sk[32], sid[16], seed[32], nonce24[24];
    unhex(s_sk, 32, jstr(hooks, "s_sk"));
    unhex(sid, 16, jstr(hooks, "sid"));
    unhex(seed, 32, jstr(hooks, "seed"));
    unhex(nonce24, 24, jstr(hooks, "nonce24"));
    skp_test_hooks h = {s_sk, sid, seed, nonce24, jint(hooks, "now"), 1};
    skp_test_set_hooks(&h);

    const cJSON *so = cJSON_GetObjectItemCaseSensitive(v, "server_opts");
    skp_session_opts opts = {0};
    opts.ctx = jstr(so, "ctx");
    opts.layout = jstr(so, "layout");
    opts.blank = jstr(so, "blank");
    opts.ttl_sec = (uint32_t)jint(so, "ttl");
    opts.max_len = (uint32_t)jint(so, "maxLen");

    char *req = cJSON_PrintUnformatted(cJSON_GetObjectItemCaseSensitive(v, "request"));
    skp_buf resp = {0}, sealed = {0};
    rc = skp_session_create(ctx, req, strlen(req), &opts, &resp, &sealed);
    free(req);
    CHECK(rc == SKP_OK, "create: %s", skp_strerror(rc));
    const cJSON *es = cJSON_GetObjectItemCaseSensitive(v, "expect_session");
    if (rc == SKP_OK) {
        cJSON *got = cJSON_ParseWithLength((const char *)resp.data, resp.len);
        const cJSON *exp = cJSON_GetObjectItemCaseSensitive(es, "response");
        const char *fields[] = {"sid", "kid", "sp", "sig", "ct"};
        for (size_t i = 0; i < 5; i++) {
            const char *a = jstr(got, fields[i]), *b = jstr(exp, fields[i]);
            CHECK(a && b && !strcmp(a, b), "response.%s mismatch", fields[i]);
        }
        CHECK(jint(got, "v") == 1, "response.v");
        cJSON_Delete(got);
        char *sh = to_hex(sealed.data, sealed.len);
        CHECK(!strcmp(sh, jstr(es, "sealed")), "sealed mismatch");
        free(sh);
    }

    skp_buf final_sealed = sealed;
    skp_buf sealed2 = {0};
    const cJSON *rl = cJSON_GetObjectItemCaseSensitive(v, "relayout");
    if (cJSON_IsObject(rl)) {
        const cJSON *rh = cJSON_GetObjectItemCaseSensitive(rl, "hooks");
        uint8_t n2[24];
        unhex(n2, 24, jstr(rh, "nonce24"));
        skp_test_hooks h2 = {s_sk, sid, seed, n2, jint(rh, "now"), 1};
        skp_test_set_hooks(&h2);
        char *rreq = cJSON_PrintUnformatted(cJSON_GetObjectItemCaseSensitive(rl, "request"));
        skp_buf rresp = {0};
        rc = skp_session_relayout(ctx, sealed.data, sealed.len, rreq, strlen(rreq), &rresp, &sealed2);
        free(rreq);
        CHECK(rc == SKP_OK, "relayout: %s", skp_strerror(rc));
        if (rc == SKP_OK) {
            const cJSON *rexp = cJSON_GetObjectItemCaseSensitive(rl, "expect");
            cJSON *got = cJSON_ParseWithLength((const char *)rresp.data, rresp.len);
            const cJSON *exp = cJSON_GetObjectItemCaseSensitive(rexp, "response");
            CHECK(!strcmp(jstr(got, "ct"), jstr(exp, "ct")), "relayout ct mismatch");
            CHECK(!strcmp(jstr(got, "sid"), jstr(exp, "sid")), "relayout sid mismatch");
            CHECK(jint(got, "gen") == jint(exp, "gen"), "relayout gen mismatch");
            cJSON_Delete(got);
            char *sh = to_hex(sealed2.data, sealed2.len);
            CHECK(!strcmp(sh, jstr(rexp, "sealed")), "relayout sealed mismatch");
            free(sh);
            final_sealed = sealed2;
        }
        skp_buf_free(&rresp);
    }

    const cJSON *in = cJSON_GetObjectItemCaseSensitive(v, "input");
    skp_test_hooks h3 = {NULL, NULL, NULL, NULL, jint(in, "decrypt_now"), 1};
    skp_test_set_hooks(&h3);
    char *payload = cJSON_PrintUnformatted(cJSON_GetObjectItemCaseSensitive(in, "payload"));
    skp_secret *sec = NULL;
    rc = skp_session_decrypt(ctx, final_sealed.data, final_sealed.len, payload, strlen(payload), opts.ctx, &sec);
    CHECK(rc == SKP_OK, "decrypt: %s", skp_strerror(rc));
    if (rc == SKP_OK) {
        const char *exp = jstr(in, "expect_plain");
        CHECK(skp_secret_len(sec) == strlen(exp) && !memcmp(skp_secret_bytes(sec), exp, strlen(exp)),
              "plaintext mismatch: got %.*s", (int)skp_secret_len(sec), (const char *)skp_secret_bytes(sec));
        skp_secret_free(sec);
    }
    free(payload);

    const cJSON *errs = cJSON_GetObjectItemCaseSensitive(v, "errors");
    if (cJSON_IsArray(errs)) {
        const cJSON *e;
        cJSON_ArrayForEach(e, errs) {
            skp_test_hooks he = {NULL, NULL, NULL, NULL, jint(e, "now"), 1};
            skp_test_set_hooks(&he);
            char *p = cJSON_PrintUnformatted(cJSON_GetObjectItemCaseSensitive(e, "payload"));
            skp_secret *s2 = NULL;
            rc = skp_session_decrypt(ctx, final_sealed.data, final_sealed.len, p, strlen(p), jstr(e, "ctx"), &s2);
            int want = error_code_by_name(jstr(e, "expect"));
            CHECK(rc == want, "error case %s: got %d (%s) want %s", jstr(e, "name"), rc, skp_strerror(rc), jstr(e, "expect"));
            if (s2)
                skp_secret_free(s2);
            free(p);
        }
    }

    skp_buf_free(&resp);
    skp_buf_free(&sealed);
    skp_buf_free(&sealed2);
    skp_test_set_hooks(NULL);
    skp_free(ctx);
    cJSON_Delete(v);
}

int main(int argc, char **argv) {
    const char *dir = argc > 1 ? argv[1] : SKP_VECTORS_DIR;
    DIR *d = opendir(dir);
    if (!d) {
        fprintf(stderr, "cannot open %s\n", dir);
        return 2;
    }
    struct dirent *e;
    int n = 0;
    while ((e = readdir(d))) {
        size_t l = strlen(e->d_name);
        if (l > 5 && !strcmp(e->d_name + l - 5, ".json")) {
            char path[4096];
            snprintf(path, sizeof path, "%s/%s", dir, e->d_name);
            run_vector(path);
            n++;
        }
    }
    closedir(d);
    printf("%d vectors, %d failures\n", n, g_failures);
    return (n == 0 || g_failures) ? 1 : 0;
}
