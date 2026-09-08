#!/usr/bin/env bash
# Builds libskp as a WebAssembly module (bindings/wasm/dist/skp.js + skp.wasm).
#
# Requires emcc (Emscripten). libsodium is compiled for wasm on first use and cached in
# $SKP_WASM_CACHE (default: bindings/wasm/.cache).
#
#   bindings/wasm/build.sh            # release build
#   SKP_WASM_TESTING=1 build.sh       # with test hooks (vectors replay in the browser/node)
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
CORE="$ROOT/core"
CACHE="${SKP_WASM_CACHE:-$HERE/.cache}"
OUT="$HERE/dist"
SODIUM_VERSION="${SKP_SODIUM_VERSION:-1.0.21}"
SODIUM_PREFIX="$CACHE/libsodium-$SODIUM_VERSION-wasm"

command -v emcc >/dev/null || { echo "emcc not found: install Emscripten (brew install emscripten / emsdk)" >&2; exit 1; }
mkdir -p "$CACHE" "$OUT"

# ---- libsodium for wasm ------------------------------------------------------------------------
if [ ! -f "$SODIUM_PREFIX/lib/libsodium.a" ]; then
  echo "building libsodium $SODIUM_VERSION for wasm ..."
  SRC="$CACHE/libsodium-$SODIUM_VERSION"
  if [ ! -d "$SRC" ]; then
    TARBALL="${SKP_SODIUM_TARBALL:-}"
    if [ -z "$TARBALL" ]; then
      TARBALL="$CACHE/libsodium-$SODIUM_VERSION.tar.gz"
      curl -sSfL -o "$TARBALL" "https://github.com/jedisct1/libsodium/releases/download/$SODIUM_VERSION-RELEASE/libsodium-$SODIUM_VERSION.tar.gz"
    fi
    tar -xzf "$TARBALL" -C "$CACHE"
  fi
  ( cd "$SRC" && emconfigure ./configure --disable-shared --enable-static --disable-ssp --disable-asm \
      --without-pthreads --disable-pie --prefix="$SODIUM_PREFIX" CFLAGS="-O2" >"$CACHE/sodium-configure.log" 2>&1 \
    && emmake make -j"$(sysctl -n hw.ncpu 2>/dev/null || nproc)" >"$CACHE/sodium-make.log" 2>&1 \
    && emmake make install >>"$CACHE/sodium-make.log" 2>&1 )
  echo "libsodium ready: $SODIUM_PREFIX"
fi

# ---- embedded fonts ------------------------------------------------------------------------------
GEN="$CACHE/gen"
mkdir -p "$GEN"
node "$ROOT/bindings/node/scripts/embed.js" "$CORE/fonts/Inter-Regular.ttf" "$GEN/skp_font_inter.c" skp_font_inter
node "$ROOT/bindings/node/scripts/embed.js" "$CORE/fonts/Roboto-Regular.ttf" "$GEN/skp_font_roboto.c" skp_font_roboto

# ---- the module -----------------------------------------------------------------------------------
DEFS="-DSKP_HAVE_ZLIB=1"
if [ "${SKP_WASM_TESTING:-0}" = "1" ]; then DEFS="$DEFS -DSKP_TESTING=1"; fi
EXPORTS='_skp_init,_skp_free,_skp_version,_skp_strerror,_skp_public_key,_skp_key_id,_skp_keygen_b64,_skp_session_create,_skp_session_relayout,_skp_session_decrypt,_skp_session_info,_skp_secret_len,_skp_secret_bytes,_skp_secret_free,_skp_buf_free,_malloc,_free'
if [ "${SKP_WASM_TESTING:-0}" = "1" ]; then EXPORTS="$EXPORTS,_skp_test_set_hooks"; fi

emcc -O2 -std=gnu11 $DEFS \
  -I"$CORE/include" -I"$CORE/src" -I"$SODIUM_PREFIX/include" \
  "$CORE/src/skp.c" "$CORE/src/skp_crypto.c" "$CORE/src/skp_layout.c" "$CORE/src/skp_render.c" \
  "$CORE/src/skp_state.c" "$CORE/src/skp_session.c" "$CORE/third_party/cJSON.c" \
  "$GEN/skp_font_inter.c" "$GEN/skp_font_roboto.c" \
  "$SODIUM_PREFIX/lib/libsodium.a" \
  -sUSE_ZLIB=1 -sMODULARIZE=1 -sEXPORT_NAME=createSkpModule -sENVIRONMENT=web,worker,node \
  -sALLOW_MEMORY_GROWTH=1 -sINITIAL_MEMORY=33554432 -sFILESYSTEM=0 \
  -sEXPORTED_FUNCTIONS="[$EXPORTS]" \
  -sEXPORTED_RUNTIME_METHODS='[ccall,cwrap,getValue,setValue,UTF8ToString,stringToUTF8,lengthBytesUTF8,HEAPU8]' \
  -o "$OUT/skp.js"
ls -la "$OUT"
echo "ok: $OUT/skp.js + skp.wasm"
