#include "skp_internal.h"
#include <stdio.h>
#include <stdlib.h>

#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wsign-compare"
#pragma GCC diagnostic ignored "-Wcast-qual"
#endif
#define STB_TRUETYPE_IMPLEMENTATION
#define STBTT_STATIC
#include "../third_party/stb_truetype.h"
#ifdef SKP_HAVE_ZLIB
/* Real deflate makes the mostly-empty sprites 2-4x smaller than stb's built-in compressor. */
#include <zlib.h>
static unsigned char *skp_zlib_compress(unsigned char *data, int data_len, int *out_len, int quality) {
    uLongf cap = compressBound((uLong)data_len);
    unsigned char *out = malloc(cap);
    if (!out)
        return NULL;
    if (compress2(out, &cap, data, (uLong)data_len, quality > 0 ? 9 : Z_DEFAULT_COMPRESSION) != Z_OK) {
        free(out);
        return NULL;
    }
    *out_len = (int)cap;
    return out;
}
#define STBIW_ZLIB_COMPRESS skp_zlib_compress
#endif
#define STB_IMAGE_WRITE_IMPLEMENTATION
#define STBI_WRITE_NO_STDIO
#define STBIW_ASSERT(x) ((void)0)
#include "../third_party/stb_image_write.h"
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

/* ---- fonts --------------------------------------------------------------------------------- */
int skp_font_load(skp_font *f, const char *path, const unsigned char *embedded, size_t embedded_len) {
    memset(f, 0, sizeof *f);
    if (path) {
        FILE *fp = fopen(path, "rb");
        if (!fp)
            return SKP_ERR_IO;
        if (fseek(fp, 0, SEEK_END) != 0) {
            fclose(fp);
            return SKP_ERR_IO;
        }
        long n = ftell(fp);
        if (n <= 0 || n > 64 * 1024 * 1024) {
            fclose(fp);
            return SKP_ERR_IO;
        }
        rewind(fp);
        f->owned = malloc((size_t)n);
        if (!f->owned) {
            fclose(fp);
            return SKP_ERR_NOMEM;
        }
        if (fread(f->owned, 1, (size_t)n, fp) != (size_t)n) {
            fclose(fp);
            free(f->owned);
            f->owned = NULL;
            return SKP_ERR_IO;
        }
        fclose(fp);
        f->data = f->owned;
        f->len = (size_t)n;
    } else {
        f->data = embedded;
        f->len = embedded_len;
    }
    int off = stbtt_GetFontOffsetForIndex(f->data, 0);
    if (off < 0 || !stbtt_InitFont(&f->info, f->data, off)) {
        skp_font_free(f);
        return SKP_ERR_RENDER;
    }
    return SKP_OK;
}

void skp_font_free(skp_font *f) {
    free(f->owned);
    memset(f, 0, sizeof *f);
}

/* ---- glyph cache ----------------------------------------------------------------------------- */
typedef struct glyph_entry {
    int style, size_px;
    uint32_t cp;
    int w, h, x0, y0; /* ink box relative to baseline origin */
    unsigned char *bitmap;
    struct glyph_entry *next;
} glyph_entry;

#define GLYPH_BUCKETS 1024

struct skp_glyph_cache {
    pthread_rwlock_t lock;
    glyph_entry *buckets[GLYPH_BUCKETS];
};

skp_glyph_cache *skp_glyph_cache_new(void) {
    skp_glyph_cache *c = calloc(1, sizeof *c);
    if (!c)
        return NULL;
    if (pthread_rwlock_init(&c->lock, NULL) != 0) {
        free(c);
        return NULL;
    }
    return c;
}

void skp_glyph_cache_free(skp_glyph_cache *c) {
    if (!c)
        return;
    for (int i = 0; i < GLYPH_BUCKETS; i++) {
        glyph_entry *e = c->buckets[i];
        while (e) {
            glyph_entry *n = e->next;
            free(e->bitmap);
            free(e);
            e = n;
        }
    }
    pthread_rwlock_destroy(&c->lock);
    free(c);
}

static unsigned bucket_of(int style, int size_px, uint32_t cp) {
    unsigned h = (unsigned)style * 0x9E3779B1u ^ (unsigned)size_px * 0x85EBCA6Bu ^ cp * 0xC2B2AE35u;
    h ^= h >> 15;
    return h % GLYPH_BUCKETS;
}

static const glyph_entry *cache_find(skp_glyph_cache *c, int style, int size_px, uint32_t cp) {
    for (glyph_entry *e = c->buckets[bucket_of(style, size_px, cp)]; e; e = e->next)
        if (e->style == style && e->size_px == size_px && e->cp == cp)
            return e;
    return NULL;
}

static const glyph_entry *glyph_get(const skp_ctx *ctx, int style, int size_px, uint32_t cp) {
    skp_glyph_cache *c = ctx->glyphs;
    pthread_rwlock_rdlock(&c->lock);
    const glyph_entry *e = cache_find(c, style, size_px, cp);
    pthread_rwlock_unlock(&c->lock);
    if (e)
        return e;
    const skp_font *f = &ctx->fonts[style == SKP_STYLE_IOS ? 0 : 1];
    float scale = stbtt_ScaleForMappingEmToPixels(&f->info, (float)size_px);
    int x0, y0, x1, y1;
    stbtt_GetCodepointBitmapBox(&f->info, (int)cp, scale, scale, &x0, &y0, &x1, &y1);
    int w = x1 - x0, h = y1 - y0;
    glyph_entry *ne = calloc(1, sizeof *ne);
    if (!ne)
        return NULL;
    ne->style = style;
    ne->size_px = size_px;
    ne->cp = cp;
    ne->w = w;
    ne->h = h;
    ne->x0 = x0;
    ne->y0 = y0;
    if (w > 0 && h > 0) {
        ne->bitmap = calloc((size_t)w * (size_t)h, 1);
        if (!ne->bitmap) {
            free(ne);
            return NULL;
        }
        stbtt_MakeCodepointBitmap(&f->info, ne->bitmap, w, h, w, scale, scale, (int)cp);
    }
    pthread_rwlock_wrlock(&c->lock);
    const glyph_entry *race = cache_find(c, style, size_px, cp);
    if (race) { /* another thread inserted meanwhile */
        pthread_rwlock_unlock(&c->lock);
        free(ne->bitmap);
        free(ne);
        return race;
    }
    unsigned b = bucket_of(style, size_px, cp);
    ne->next = c->buckets[b];
    c->buckets[b] = ne;
    pthread_rwlock_unlock(&c->lock);
    return ne;
}

/* ---- sprite composition ---------------------------------------------------------------------- */
typedef struct {
    uint8_t *data;
    size_t len, cap;
    int oom;
} png_sink;

static void png_write_cb(void *user, void *data, int size) {
    png_sink *s = user;
    if (s->oom || size <= 0)
        return;
    if (s->len + (size_t)size > s->cap) {
        size_t nc = s->cap ? s->cap * 2 : 16384;
        while (nc < s->len + (size_t)size)
            nc *= 2;
        uint8_t *nd = realloc(s->data, nc);
        if (!nd) {
            s->oom = 1;
            return;
        }
        s->data = nd;
        s->cap = nc;
    }
    memcpy(s->data + s->len, data, (size_t)size);
    s->len += (size_t)size;
}

static int render_sprite(const skp_ctx *ctx, const skp_layout *l, int cell_w, int cell_h, int glyph_px, skp_buf *out) {
    const int cols = 10;
    int rows = (l->tile_count + cols - 1) / cols;
    if (l->tile_count <= 0 || cell_w <= 0 || cell_h <= 0)
        return SKP_ERR_RENDER;
    size_t iw = (size_t)cols * (size_t)cell_w, ih = (size_t)rows * (size_t)cell_h;
    if (iw > 16384 || ih > 16384)
        return SKP_ERR_RENDER;
    unsigned char *img = calloc(iw * ih, 1);
    if (!img)
        return SKP_ERR_NOMEM;
    const glyph_entry *capg = glyph_get(ctx, l->style, glyph_px, 'H');
    if (!capg) {
        free(img);
        return SKP_ERR_RENDER;
    }
    int cap_h = capg->h;
    int baseline = (int)skp_rnd(cell_h + cap_h, 2);
    for (int li = 0; li < l->nlayers; li++) {
        const skp_layer *layer = &l->layers[li];
        for (int ki = 0; ki < layer->nkeys; ki++) {
            const skp_key *k = &layer->keys[ki];
            if (k->role != SKP_ROLE_CHAR)
                continue;
            const glyph_entry *g = glyph_get(ctx, l->style, glyph_px, k->cp);
            if (!g) {
                free(img);
                return SKP_ERR_RENDER;
            }
            if (g->w <= 0 || g->h <= 0)
                continue;
            int cx = (k->t % cols) * cell_w, cy = (k->t / cols) * cell_h;
            int left = cx + (cell_w - g->w) / 2;
            int top = cy + baseline + g->y0;
            for (int yy = 0; yy < g->h; yy++) {
                int iy = top + yy;
                if (iy < cy || iy >= cy + cell_h)
                    continue;
                for (int xx = 0; xx < g->w; xx++) {
                    int ix = left + xx;
                    if (ix < cx || ix >= cx + cell_w)
                        continue;
                    unsigned char v = g->bitmap[yy * g->w + xx];
                    unsigned char *dst = &img[(size_t)iy * iw + (size_t)ix];
                    if (v > *dst)
                        *dst = v;
                }
            }
        }
    }
    png_sink sink = {0};
    int ok = stbi_write_png_to_func(png_write_cb, &sink, (int)iw, (int)ih, 1, img, (int)iw);
    free(img);
    if (!ok || sink.oom) {
        free(sink.data);
        return SKP_ERR_RENDER;
    }
    out->data = sink.data;
    out->len = sink.len;
    return SKP_OK;
}

int skp_render_sprites(const skp_ctx *ctx, const skp_layout *l, skp_buf *tiles, skp_buf *popups) {
    tiles->data = NULL;
    tiles->len = 0;
    popups->data = NULL;
    popups->len = 0;
    int rc = render_sprite(ctx, l, l->tile_w, l->tile_h, l->glyph_px, tiles);
    if (rc)
        return rc;
    rc = render_sprite(ctx, l, l->popup_w, l->popup_h, l->popup_glyph_px, popups);
    if (rc) {
        skp_buf_free(tiles);
        return rc;
    }
    return SKP_OK;
}
