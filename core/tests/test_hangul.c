/* Replays spec/vectors/hangul/compose.json against the composer, plus structural checks. */
#include "test_util.h"

static size_t utf8_decode(const char *s, uint32_t *out, size_t cap) {
    size_t n = 0;
    const unsigned char *p = (const unsigned char *)s;
    while (*p && n < cap) {
        uint32_t c = *p;
        int extra = c >= 0xF0 ? 3 : c >= 0xE0 ? 2 : c >= 0xC0 ? 1 : 0;
        c &= extra == 3 ? 0x07 : extra == 2 ? 0x0F : extra == 1 ? 0x1F : 0xFF;
        p++;
        for (int i = 0; i < extra && *p; i++)
            c = (c << 6) | (*p++ & 0x3F);
        out[n++] = c;
    }
    return n;
}

static size_t utf8_encode_all(const uint32_t *cps, size_t n, char *out) {
    size_t len = 0;
    for (size_t i = 0; i < n; i++) {
        uint32_t cp = cps[i];
        if (cp < 0x80)
            out[len++] = (char)cp;
        else if (cp < 0x800) {
            out[len++] = (char)(0xC0 | (cp >> 6));
            out[len++] = (char)(0x80 | (cp & 0x3F));
        } else if (cp < 0x10000) {
            out[len++] = (char)(0xE0 | (cp >> 12));
            out[len++] = (char)(0x80 | ((cp >> 6) & 0x3F));
            out[len++] = (char)(0x80 | (cp & 0x3F));
        } else {
            out[len++] = (char)(0xF0 | (cp >> 18));
            out[len++] = (char)(0x80 | ((cp >> 12) & 0x3F));
            out[len++] = (char)(0x80 | ((cp >> 6) & 0x3F));
            out[len++] = (char)(0x80 | (cp & 0x3F));
        }
    }
    out[len] = 0;
    return len;
}

int main(int argc, char **argv) {
    char path[4096];
    snprintf(path, sizeof path, "%s/hangul/compose.json", argc > 1 ? argv[1] : SKP_VECTORS_DIR);
    size_t len;
    char *text = read_file(path, &len);
    if (!text) {
        fprintf(stderr, "cannot read %s\n", path);
        return 2;
    }
    cJSON *v = cJSON_ParseWithLength(text, len);
    free(text);
    if (!v) {
        fprintf(stderr, "cannot parse %s\n", path);
        return 2;
    }
    int n = 0;
    const cJSON *c;
    cJSON_ArrayForEach(c, cJSON_GetObjectItemCaseSensitive(v, "cases")) {
        uint32_t in[64], out[64];
        char got[256];
        size_t ni = utf8_decode(jstr(c, "jamo"), in, 64);
        size_t no = skp_hangul_compose(in, ni, out);
        CHECK(no <= ni, "composition never grows (%zu → %zu)", ni, no);
        utf8_encode_all(out, no, got);
        CHECK(!strcmp(got, jstr(c, "expect")), "case %d: %s → %s, expected %s", n, jstr(c, "jamo"), got, jstr(c, "expect"));
        n++;
    }
    cJSON_Delete(v);
    /* every syllable decomposes and recomposes to itself: exhaustive over the 11172 syllables */
    static const uint32_t CHO[19] = {0x3131, 0x3132, 0x3134, 0x3137, 0x3138, 0x3139, 0x3141, 0x3142, 0x3143, 0x3145,
                                     0x3146, 0x3147, 0x3148, 0x3149, 0x314A, 0x314B, 0x314C, 0x314D, 0x314E};
    static const uint32_t JONG[28] = {0,      0x3131, 0x3132, 0x3133, 0x3134, 0x3135, 0x3136, 0x3137, 0x3139, 0x313A,
                                      0x313B, 0x313C, 0x313D, 0x313E, 0x313F, 0x3140, 0x3141, 0x3142, 0x3144, 0x3145,
                                      0x3146, 0x3147, 0x3148, 0x314A, 0x314B, 0x314C, 0x314D, 0x314E};
    static const uint32_t VP[7][3] = {{0x3157, 0x314F, 0x3158}, {0x3157, 0x3150, 0x3159}, {0x3157, 0x3163, 0x315A},
                                      {0x315C, 0x3153, 0x315D}, {0x315C, 0x3154, 0x315E}, {0x315C, 0x3163, 0x315F},
                                      {0x3161, 0x3163, 0x3162}};
    static const uint32_t FP[11][3] = {{0x3131, 0x3145, 0x3133}, {0x3134, 0x3148, 0x3135}, {0x3134, 0x314E, 0x3136},
                                       {0x3139, 0x3131, 0x313A}, {0x3139, 0x3141, 0x313B}, {0x3139, 0x3142, 0x313C},
                                       {0x3139, 0x3145, 0x313D}, {0x3139, 0x314C, 0x313E}, {0x3139, 0x314D, 0x313F},
                                       {0x3139, 0x314E, 0x3140}, {0x3142, 0x3145, 0x3144}};
    int ok = 0;
    for (int ci = 0; ci < 19; ci++)
        for (int ji = 0; ji < 21; ji++)
            for (int fi = 0; fi < 28; fi++) {
                uint32_t seq[6], out[6];
                size_t k = 0;
                seq[k++] = CHO[ci];
                uint32_t vowel = 0x314F + (uint32_t)ji;
                int split = 0;
                for (int i = 0; i < 7; i++)
                    if (VP[i][2] == vowel) {
                        seq[k++] = VP[i][0];
                        seq[k++] = VP[i][1];
                        split = 1;
                    }
                if (!split)
                    seq[k++] = vowel;
                if (fi) {
                    split = 0;
                    for (int i = 0; i < 11; i++)
                        if (FP[i][2] == JONG[fi]) {
                            seq[k++] = FP[i][0];
                            seq[k++] = FP[i][1];
                            split = 1;
                        }
                    if (!split)
                        seq[k++] = JONG[fi];
                }
                uint32_t want = 0xAC00 + ((uint32_t)ci * 21 + (uint32_t)ji) * 28 + (uint32_t)fi;
                size_t no = skp_hangul_compose(seq, k, out);
                if (no == 1 && out[0] == want)
                    ok++;
                else
                    CHECK(0, "syllable U+%04X did not round trip", want);
            }
    CHECK(ok == 11172, "all syllables round trip (%d)", ok);
    printf("%d cases, %d syllables, %d failures\n", n, ok, g_failures);
    return (n == 0 || g_failures) ? 1 : 0;
}
