/* Decodes the rendered sprites and checks their geometry; writes PNGs next to the binary for eyeballing. */
#include "test_util.h"
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-compare"
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#endif
#define STB_IMAGE_IMPLEMENTATION
#define STBI_ONLY_PNG
#define STBI_NO_STDIO
#include "../third_party/stb_image.h"
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

static void check_sprite(const char *name, const uint8_t *png, size_t len, int cell_w, int cell_h, int count) {
    int w, h, comp;
    unsigned char *img = stbi_load_from_memory(png, (int)len, &w, &h, &comp, 1);
    CHECK(img != NULL, "%s: decode", name);
    if (!img)
        return;
    int rows = (count + 9) / 10;
    CHECK(w == 10 * cell_w && h == rows * cell_h, "%s: size %dx%d expected %dx%d", name, w, h, 10 * cell_w, rows * cell_h);
    int inked = 0, empty_used = 0;
    for (int c = 0; c < rows * 10; c++) {
        int cx = (c % 10) * cell_w, cy = (c / 10) * cell_h;
        long sum = 0;
        int touches_edge = 0;
        for (int y = 0; y < cell_h; y++)
            for (int x = 0; x < cell_w; x++) {
                unsigned char v = img[(cy + y) * w + cx + x];
                sum += v;
                if (v && (x == 0 || y == 0 || x == cell_w - 1 || y == cell_h - 1))
                    touches_edge = 1;
            }
        if (c < count) {
            if (sum > 0)
                inked++;
            CHECK(!touches_edge, "%s: glyph %d clipped at the cell edge", name, c);
        } else {
            CHECK(sum == 0, "%s: unused cell %d not empty", name, c);
        }
        (void)empty_used;
    }
    CHECK(inked == count, "%s: %d/%d cells have ink", name, inked, count);
    stbi_image_free(img);
    char path[256];
    snprintf(path, sizeof path, "%s.png", name);
    FILE *f = fopen(path, "wb");
    if (f) {
        fwrite(png, 1, len, f);
        fclose(f);
    }
}

static void render_case(skp_ctx *ctx, const char *name, const char *type, const char *platform, double w, double dpr,
                        const char *languages) {
    printf("render %s\n", name);
    uint8_t c_sk[32] = {3}, c_pk[32];
    crypto_scalarmult_base(c_pk, c_sk);
    char *kp = NULL;
    skp_b64_encode(&kp, c_pk, 32, 0);
    char req[512];
    snprintf(req, sizeof req, "{\"v\":1,\"kp\":\"%s\",\"type\":\"%s\",\"viewport\":{\"w\":%g,\"dpr\":%g,\"platform\":\"%s\"}}",
             kp, type, w, dpr, platform);
    free(kp);
    skp_buf resp = {0}, sealed = {0};
    skp_session_opts opts = {NULL, NULL, NULL, 0, 0, languages};
    int rc = skp_session_create(ctx, req, 0, &opts, &resp, &sealed);
    CHECK(rc == SKP_OK, "create: %s", skp_strerror(rc));
    if (rc)
        return;
    test_client cl;
    CHECK(client_open(&cl, (const char *)resp.data, c_sk, NULL) == 0, "open");
    cJSON *inner = cJSON_Parse(cl.inner_json);
    const cJSON *tile = cJSON_GetObjectItemCaseSensitive(inner, "tile");
    const cJSON *popup = cJSON_GetObjectItemCaseSensitive(inner, "popup");
    char n1[128], n2[128];
    snprintf(n1, sizeof n1, "%s-tiles", name);
    snprintf(n2, sizeof n2, "%s-popups", name);
    check_sprite(n1, cl.tiles, cl.tiles_len, (int)jint(tile, "w"), (int)jint(tile, "h"), (int)jint(tile, "count"));
    check_sprite(n2, cl.popups, cl.popups_len, (int)jint(popup, "w"), (int)jint(popup, "h"), (int)jint(popup, "count"));
    printf("  tiles %zu B, popups %zu B, inner json %zu B\n", cl.tiles_len, cl.popups_len, strlen(cl.inner_json));
    cJSON_Delete(inner);
    client_free(&cl);
    skp_buf_free(&resp);
    skp_buf_free(&sealed);
}

int main(void) {
    skp_config cfg = {0};
    cfg.master_key = "0f1e2d3c4b5a69788796a5b4c3d2e1f0f0e1d2c3b4a5968778695a4b3c2d1e0f";
    skp_ctx *ctx = NULL;
    CHECK(skp_init(&ctx, &cfg) == SKP_OK, "init");
    render_case(ctx, "qwerty-ios-390x3", "qwerty", "ios", 390, 3, "en");
    render_case(ctx, "qwerty-material-360x2.625", "qwerty", "android", 360, 2.625, "en");
    render_case(ctx, "number-ios-390x3", "number", "ios", 390, 3, NULL);
    render_case(ctx, "number-material-412x2.625", "number", "android", 412, 2.625, NULL);
    render_case(ctx, "qwerty-web-1024x1", "qwerty", "web", 1024, 1, "en");
    /* Korean layers use the fallback font: every jamo cell must be inked */
    render_case(ctx, "qwerty-ios-390x3-ko-en", "qwerty", "ios", 390, 3, NULL);
    render_case(ctx, "qwerty-material-412x2.625-ko", "qwerty", "android", 412, 2.625, "ko");
    skp_free(ctx);
    printf("%d failures\n", g_failures);
    return g_failures ? 1 : 0;
}
