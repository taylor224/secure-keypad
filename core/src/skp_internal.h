#ifndef SKP_INTERNAL_H
#define SKP_INTERNAL_H

#include "skp.h"
#include <sodium.h>
#include <pthread.h>
#include <stdbool.h>
#include <string.h>
#include "../third_party/stb_truetype.h"

/* ---- protocol constants ---------------------------------------------------------------- */
#define SKP_LABEL_MASTER "skp/v1/master"
#define SKP_LABEL_SESSION_SALT "skp/v1"
#define SKP_AAD_SESSION "skp/v1/session"
#define SKP_AAD_RELAYOUT "skp/v1/relayout"
#define SKP_AAD_INPUT "skp/v1/input"
#define SKP_AAD_STATE "skp/v1/state"
#define SKP_SIG_LABEL "skp/v1/session"

#define SKP_SID_BYTES 16
#define SKP_SEED_BYTES 32
#define SKP_KEY_BYTES 32
#define SKP_STATE_NONCE_BYTES 24
#define SKP_MAX_GENS 32
#define SKP_RECORD_SIZE 8
#define SKP_DEFAULT_TTL 180
#define SKP_DEFAULT_CAP 256
#define SKP_MIN_W 200
#define SKP_MAX_W 8192
#define SKP_STATE_HEAD 146
#define SKP_STATE_GEN 37

enum { SKP_TYPE_QWERTY = 1, SKP_TYPE_NUMBER = 2 };
enum { SKP_POLICY_SHUFFLE = 0, SKP_POLICY_FULL = 1, SKP_POLICY_FIXED = 2 };
enum { SKP_BLANK_FIXED = 0, SKP_BLANK_RANDOM = 1 };
enum { SKP_STYLE_IOS = 1, SKP_STYLE_MATERIAL = 2 };
enum { SKP_PLATFORM_IOS = 1, SKP_PLATFORM_ANDROID = 2, SKP_PLATFORM_WEB = 3 };
enum { SKP_MODE_LOWER = 0, SKP_MODE_UPPER = 1, SKP_MODE_SYM1 = 2, SKP_MODE_SYM2 = 3, SKP_MODE_NUMBER = 4 };

typedef enum {
    SKP_ROLE_CHAR = 0,
    SKP_ROLE_SPACE,
    SKP_ROLE_SHIFT,
    SKP_ROLE_BACKSPACE,
    SKP_ROLE_MODE_ABC,
    SKP_ROLE_MODE_SYM1,
    SKP_ROLE_MODE_SYM2,
    SKP_ROLE_DONE,
    SKP_ROLE_BLANK
} skp_role;

extern const char *const skp_role_names[];

/* ---- layout --------------------------------------------------------------------------- */
#define SKP_MAX_KEYS_PER_LAYER 40
#define SKP_MAX_LAYERS 4

typedef struct {
    int32_t x, y, w, h;
    skp_role role;
    uint32_t cp; /* codepoint for char/space keys (server only) */
    int32_t t;   /* sprite index for char keys, -1 otherwise */
} skp_key;

typedef struct {
    int mode;
    int nkeys;
    skp_key keys[SKP_MAX_KEYS_PER_LAYER];
} skp_layer;

typedef struct {
    int type, style;
    int32_t W, H;
    uint32_t dpr_milli;
    int nlayers;
    skp_layer layers[SKP_MAX_LAYERS];
    int32_t tile_w, tile_h, tile_count;
    int32_t popup_w, popup_h;
    int32_t glyph_px, popup_glyph_px;
} skp_layout;

int skp_layout_build(skp_layout *out, int type, int policy, int blank, int style, int32_t W,
                     uint32_t dpr_milli, const uint8_t seed[SKP_SEED_BYTES]);
const skp_key *skp_layout_hit(const skp_layer *layer, int32_t x, int32_t y);
const skp_layer *skp_layout_layer(const skp_layout *l, int mode);
/* Canonical inner JSON (no sprites). Returns malloc'd NUL-terminated string. */
char *skp_layout_json(const skp_layout *l, int gen, uint32_t max_len, int64_t exp);
int64_t skp_rnd(int64_t a, int64_t b);
int32_t skp_px(int64_t mu, uint32_t dpr_milli);

/* ---- rendering ------------------------------------------------------------------------ */
typedef struct {
    stbtt_fontinfo info;
    const unsigned char *data; /* embedded or loaded file */
    unsigned char *owned;      /* non-NULL when loaded from a file */
    size_t len;
} skp_font;

typedef struct skp_glyph_cache skp_glyph_cache;

int skp_font_load(skp_font *f, const char *path, const unsigned char *embedded, size_t embedded_len);
void skp_font_free(skp_font *f);
skp_glyph_cache *skp_glyph_cache_new(void);
void skp_glyph_cache_free(skp_glyph_cache *c);
/* Renders the tile and popup sprites as 8-bit grayscale PNGs. */
int skp_render_sprites(const skp_ctx *ctx, const skp_layout *l, skp_buf *tiles, skp_buf *popups);

extern const unsigned char skp_font_inter[];
extern const size_t skp_font_inter_len;
extern const unsigned char skp_font_roboto[];
extern const size_t skp_font_roboto_len;

/* ---- context ---------------------------------------------------------------------------- */
struct skp_ctx {
    unsigned char *sk_sign; /* sodium_malloc, crypto_sign_SECRETKEYBYTES */
    unsigned char pk_sign[crypto_sign_PUBLICKEYBYTES];
    unsigned char *k_state; /* sodium_malloc, 32 */
    char kid[SKP_KID_CAP];
    uint32_t default_ttl;
    uint32_t max_len_cap;
    skp_font fonts[2]; /* [0] ios, [1] material */
    skp_glyph_cache *glyphs;
};

struct skp_secret {
    uint8_t *data; /* sodium_malloc */
    size_t len;
};

/* ---- sealed state --------------------------------------------------------------------- */
typedef struct {
    uint8_t seed[SKP_SEED_BYTES];
    int32_t W;
    uint32_t dpr_milli;
    uint8_t platform;
} skp_gen;

typedef struct {
    uint8_t type, policy, blank, style;
    uint32_t max_len;
    int64_t created, expires;
    uint8_t sid[SKP_SID_BYTES];
    uint8_t ctx_hash[32];
    uint8_t k_s2c[SKP_KEY_BYTES];
    uint8_t k_c2s[SKP_KEY_BYTES];
    uint64_t s2c_ctr;
    int ngens;
    skp_gen gens[SKP_MAX_GENS];
} skp_state;

int skp_state_seal(const skp_ctx *ctx, const skp_state *st, const uint8_t nonce24[24], skp_buf *out);
int skp_state_unseal(const skp_ctx *ctx, const uint8_t *sealed, size_t len, skp_state *out);
void skp_state_wipe(skp_state *st);

/* ---- crypto helpers ------------------------------------------------------------------- */
void skp_hkdf_extract(uint8_t prk[32], const uint8_t *salt, size_t salt_len, const uint8_t *ikm, size_t ikm_len);
void skp_hkdf_expand(uint8_t *out, size_t out_len, const uint8_t prk[32], const uint8_t *info, size_t info_len);
int skp_derive_master(skp_ctx *ctx, const uint8_t master[32]);
int skp_parse_master(const char *text, size_t len, uint8_t out[32]);
void skp_nonce12(uint8_t n[12], uint64_t ctr);
int skp_b64_encode(char **out, const uint8_t *in, size_t len, int url_nopad);
int skp_b64_decode(uint8_t *out, size_t cap, size_t *out_len, const char *in, size_t in_len, int url_nopad);
int skp_hex_decode(uint8_t *out, size_t cap, const char *in, size_t in_len);

/* ---- randomness / clock (test hooks) ------------------------------------------------- */
void skp_random(uint8_t *buf, size_t len, int which);
int64_t skp_now(void);
int skp_render_disabled(void);
enum { SKP_RAND_SID = 1, SKP_RAND_SSK = 2, SKP_RAND_SEED = 3, SKP_RAND_NONCE24 = 4 };

/* ---- misc ------------------------------------------------------------------------------- */
void skp_wipe(void *p, size_t n);
int skp_buf_alloc(skp_buf *b, size_t n);
void skp_log_warn(const char *msg);

#endif
