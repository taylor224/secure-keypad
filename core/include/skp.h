/*
 * secure-keypad core library (libskp) — public API.
 *
 * The library is stateless: session state travels as a sealed blob that only this library
 * (initialised with the same master key) can open. Every secret lives in locked memory for
 * the duration of a call and is wiped before the call returns.
 *
 * Thread safety: an skp_ctx is immutable after skp_init and may be shared by any number of
 * threads. Output buffers belong to the caller and must be released with skp_buf_free /
 * skp_secret_free.
 */
#ifndef SKP_H
#define SKP_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(_WIN32) && defined(SKP_SHARED)
#define SKP_API __declspec(dllexport)
#elif defined(__GNUC__)
#define SKP_API __attribute__((visibility("default")))
#else
#define SKP_API
#endif

#define SKP_VERSION_STRING "0.1.0"
#define SKP_PROTOCOL_VERSION 1
#define SKP_MASTER_KEY_BYTES 32
#define SKP_PUBLIC_KEY_B64_CAP 64 /* buffer size for skp_public_key */
#define SKP_KID_CAP 9

/* Error codes (spec/PROTOCOL.md §11) */
enum {
    SKP_OK = 0,
    SKP_ERR_NOMEM = -1,
    SKP_ERR_INVALID_ARG = -2,
    SKP_ERR_BAD_KEY = -3,
    SKP_ERR_BAD_REQUEST = -4,
    SKP_ERR_CRYPTO = -5,
    SKP_ERR_EXPIRED = -6,
    SKP_ERR_BAD_MAC = -7,
    SKP_ERR_TAMPERED = -8,
    SKP_ERR_CTX_MISMATCH = -9,
    SKP_ERR_SID_MISMATCH = -10,
    SKP_ERR_RENDER = -11,
    SKP_ERR_IO = -12,
    SKP_ERR_UNSUPPORTED = -13
};

typedef struct skp_ctx skp_ctx;
typedef struct skp_secret skp_secret;

/* A caller-owned byte buffer produced by the library. Release with skp_buf_free. */
typedef struct {
    uint8_t *data;
    size_t len;
} skp_buf;

typedef struct {
    /* Exactly one of master_key_path / master_key must be set. The key is 32 bytes given as
     * a file or string containing 64 hex characters or standard base64, or as 32 raw bytes
     * (master_key_len == 32). */
    const char *master_key_path;
    const char *master_key;
    size_t master_key_len; /* 0 → treat master_key as a NUL-terminated string */

    /* Optional TrueType files replacing the embedded Inter (iOS style) / Roboto (Material style). */
    const char *font_ios_path;
    const char *font_material_path;

    uint32_t default_ttl_sec; /* 0 → 180 */
    uint32_t max_len_cap;     /* 0 → 256 */
} skp_config;

typedef struct {
    const char *ctx;    /* integrator binding context (user id, attempt id), NULL/"" for none */
    const char *layout; /* "shuffle" (default) | "full" | "fixed" */
    const char *blank;  /* "fixed" (default) | "random" — number pad only */
    uint32_t ttl_sec;   /* 0 → ctx default */
    uint32_t max_len;   /* 0 → honour the client's request (bounded by max_len_cap) */
} skp_session_opts;

/* Lifecycle */
SKP_API int skp_init(skp_ctx **out, const skp_config *cfg);
SKP_API void skp_free(skp_ctx *ctx);
SKP_API const char *skp_version(void);
SKP_API const char *skp_strerror(int err);

/* Ed25519 verification key (base64) and key id for client configuration. */
SKP_API int skp_public_key(const skp_ctx *ctx, char *b64_out, size_t cap);
SKP_API int skp_key_id(const skp_ctx *ctx, char *out, size_t cap);

/* Generate a fresh master key (32 raw bytes) and its base64 encoding. */
SKP_API int skp_keygen(uint8_t out[SKP_MASTER_KEY_BYTES]);
SKP_API int skp_keygen_b64(char *out, size_t cap);

/* Session creation. req_json is the client's request; resp_json receives the JSON to return to
 * the client, sealed the blob to keep in the session store under the response's "sid". */
SKP_API int skp_session_create(const skp_ctx *ctx, const char *req_json, size_t req_len,
                               const skp_session_opts *opts, skp_buf *resp_json, skp_buf *sealed);

/* Relayout: same mapping, new viewport. sealed_out replaces the stored blob. */
SKP_API int skp_session_relayout(const skp_ctx *ctx, const uint8_t *sealed, size_t sealed_len,
                                 const char *req_json, size_t req_len, skp_buf *resp_json,
                                 skp_buf *sealed_out);

/* Decrypt the client's input payload. The result lives in locked memory; wipe it with
 * skp_secret_free. The caller must delete the sealed blob from its store afterwards unless it
 * deliberately keeps the session alive. */
SKP_API int skp_session_decrypt(const skp_ctx *ctx, const uint8_t *sealed, size_t sealed_len,
                                const char *payload_json, size_t payload_len, const char *bind_ctx,
                                skp_secret **out);

/* Convenience: read the expiry (unix seconds) and sid (base64url) of a sealed blob, e.g. to set a
 * store TTL. Does not expose anything else. */
SKP_API int skp_session_info(const skp_ctx *ctx, const uint8_t *sealed, size_t sealed_len,
                             int64_t *expires_out, char *sid_b64url_out, size_t sid_cap);

SKP_API size_t skp_secret_len(const skp_secret *s);
SKP_API const uint8_t *skp_secret_bytes(const skp_secret *s); /* UTF-8, not NUL-terminated */
SKP_API void skp_secret_free(skp_secret *s);
SKP_API void skp_buf_free(skp_buf *b);

#ifdef SKP_TESTING
/* Test builds only: inject randomness and the clock, disable glyph rendering. Pointers must stay
 * valid while set; pass NULL to restore real randomness. Not thread safe. */
typedef struct {
    const uint8_t *s_sk;    /* 32 */
    const uint8_t *sid;     /* 16 */
    const uint8_t *seed;    /* 32 */
    const uint8_t *nonce24; /* 24 */
    int64_t now;            /* 0 → real clock */
    int no_render;
} skp_test_hooks;
SKP_API void skp_test_set_hooks(const skp_test_hooks *hooks);
#endif

#ifdef __cplusplus
}
#endif
#endif /* SKP_H */
