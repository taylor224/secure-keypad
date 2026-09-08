"""cffi builder for the API-mode extension secure_keypad_server._skp.

The declarations below mirror core/include/skp.h (without the SKP_API decoration and the test-only hooks).
Keep them in sync when the public header changes."""
import os
import shutil
import subprocess
import sys

from cffi import FFI

HERE = os.path.abspath(os.path.dirname(__file__))
CORE_DIR = os.environ.get("SKP_CORE_DIR", os.path.normpath(os.path.join(HERE, "..", "..", "core")))
CORE_BUILD = os.path.join(HERE, "build", "core")
LIBSKP = os.path.join(CORE_BUILD, "libskp.a")

CDEF = r"""
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

typedef struct {
    uint8_t *data;
    size_t len;
} skp_buf;

typedef struct {
    const char *master_key_path;
    const char *master_key;
    size_t master_key_len;
    const char *font_ios_path;
    const char *font_material_path;
    const char *font_fallback_path;
    uint32_t default_ttl_sec;
    uint32_t max_len_cap;
} skp_config;

typedef struct {
    const char *ctx;
    const char *layout;
    const char *blank;
    uint32_t ttl_sec;
    uint32_t max_len;
    const char *languages;
} skp_session_opts;

int skp_init(skp_ctx **out, const skp_config *cfg);
void skp_free(skp_ctx *ctx);
const char *skp_version(void);
const char *skp_strerror(int err);
int skp_public_key(const skp_ctx *ctx, char *b64_out, size_t cap);
int skp_key_id(const skp_ctx *ctx, char *out, size_t cap);
int skp_keygen(uint8_t *out);
int skp_keygen_b64(char *out, size_t cap);
int skp_session_create(const skp_ctx *ctx, const char *req_json, size_t req_len,
                       const skp_session_opts *opts, skp_buf *resp_json, skp_buf *sealed);
int skp_session_relayout(const skp_ctx *ctx, const uint8_t *sealed, size_t sealed_len,
                         const char *req_json, size_t req_len, skp_buf *resp_json, skp_buf *sealed_out);
int skp_session_decrypt(const skp_ctx *ctx, const uint8_t *sealed, size_t sealed_len,
                        const char *payload_json, size_t payload_len, const char *bind_ctx,
                        skp_secret **out);
int skp_session_info(const skp_ctx *ctx, const uint8_t *sealed, size_t sealed_len,
                     int64_t *expires_out, char *sid_b64url_out, size_t sid_cap);
size_t skp_secret_len(const skp_secret *s);
const uint8_t *skp_secret_bytes(const skp_secret *s);
void skp_secret_free(skp_secret *s);
void skp_buf_free(skp_buf *b);
"""


def pkg_config(*args):
    exe = shutil.which("pkg-config") or shutil.which("pkgconf")
    if not exe:
        return ""
    try:
        return subprocess.check_output([exe, *args], text=True).strip()
    except (OSError, subprocess.CalledProcessError):
        return ""


def sodium_link():
    """Static archive when SKP_SODIUM_STATIC_LIB points at one, or on macOS where Homebrew builds a PIC
    archive; elsewhere the shared libsodium (distro archives are non-PIC and cannot go into a .so)."""
    explicit = os.environ.get("SKP_SODIUM_STATIC_LIB")
    if explicit and os.path.exists(explicit):
        return [explicit], [], []
    libdir = pkg_config("--variable=libdir", "libsodium")
    if libdir:
        if sys.platform == "darwin":
            path = os.path.join(libdir, "libsodium.a")
            if os.path.exists(path):
                return [path], [], []
        return [], ["sodium"], [libdir]
    return [], ["sodium"], []


extra_objects, libraries, library_dirs = sodium_link()
extra_objects.insert(0, LIBSKP)
libraries.append("z")
if sys.platform.startswith("linux"):
    libraries += ["pthread", "m"]

ffibuilder = FFI()
ffibuilder.cdef(CDEF)
ffibuilder.set_source(
    "secure_keypad_server._skp",
    '#include "skp.h"\n',
    include_dirs=[os.path.join(CORE_DIR, "include")],
    extra_objects=extra_objects,
    libraries=libraries,
    library_dirs=library_dirs,
)

if __name__ == "__main__":
    ffibuilder.compile(verbose=True)
