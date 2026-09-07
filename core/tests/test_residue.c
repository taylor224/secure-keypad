/* Memory residue test: after a session is created, decrypted and freed, none of the session keys, the
 * seed, or the decrypted value may remain anywhere in readable process memory. Runs a vector with the
 * vector JSON wiped, keeps its reference copies XOR-masked, then scans every readable mapping. */
#include "test_util.h"
#include <inttypes.h>

#if defined(__APPLE__)
#include <mach/mach.h>
#include <mach/mach_vm.h>
#endif

#define MAX_PATTERNS 8
typedef struct {
    uint8_t masked[64];
    size_t len;
    const char *name;
    int hits;
} pattern;

static uint8_t g_mask[64];
static pattern g_pat[MAX_PATTERNS];
static int g_npat = 0;

static void add_pattern(const char *name, const uint8_t *data, size_t len) {
    pattern *p = &g_pat[g_npat++];
    p->name = name;
    p->len = len;
    for (size_t i = 0; i < len; i++)
        p->masked[i] = data[i] ^ g_mask[i];
    p->hits = 0;
}

/* Compares memory against the masked pattern without ever materialising the unmasked bytes. */
static void scan_chunk(const uint8_t *mem, size_t len) {
    for (int pi = 0; pi < g_npat; pi++) {
        pattern *p = &g_pat[pi];
        if (len < p->len)
            continue;
        for (size_t i = 0; i + p->len <= len; i++) {
            size_t j = 0;
            while (j < p->len && (mem[i + j] ^ g_mask[j]) == p->masked[j])
                j++;
            if (j == p->len) {
                /* ignore our own masked copies (they never match unmasked) and the mask itself */
                p->hits++;
                i += p->len - 1;
            }
        }
    }
}

#if defined(__APPLE__)
static void scan_process(void) {
    mach_vm_address_t addr = 0;
    mach_vm_size_t size = 0;
    natural_t depth = 0;
    uint8_t *buf = malloc(1 << 20);
    for (;;) {
        vm_region_submap_info_data_64_t info;
        mach_msg_type_number_t cnt = VM_REGION_SUBMAP_INFO_COUNT_64;
        kern_return_t kr = mach_vm_region_recurse(mach_task_self(), &addr, &size, &depth, (vm_region_recurse_info_t)&info, &cnt);
        if (kr != KERN_SUCCESS)
            break;
        if (info.is_submap) {
            depth++;
            continue;
        }
        if ((info.protection & VM_PROT_READ) && !(info.protection & VM_PROT_EXECUTE) && info.share_mode != SM_EMPTY) {
            for (mach_vm_size_t off = 0; off < size; off += (1 << 20)) {
                mach_vm_size_t want = size - off < (1 << 20) ? size - off : (1 << 20);
                mach_vm_size_t got = 0;
                if (mach_vm_read_overwrite(mach_task_self(), addr + off, want, (mach_vm_address_t)buf, &got) == KERN_SUCCESS)
                    scan_chunk(buf, (size_t)got);
            }
        }
        addr += size;
    }
    free(buf);
}
#elif defined(__linux__)
static void scan_process(void) {
    FILE *maps = fopen("/proc/self/maps", "r");
    int mem = open("/proc/self/mem", O_RDONLY);
    if (!maps || mem < 0) {
        CHECK(0, "cannot open /proc/self");
        return;
    }
    char line[512];
    uint8_t *buf = malloc(1 << 20);
    while (fgets(line, sizeof line, maps)) {
        unsigned long lo, hi;
        char perms[8];
        if (sscanf(line, "%lx-%lx %7s", &lo, &hi, perms) != 3)
            continue;
        if (perms[0] != 'r' || perms[2] == 'x' || strstr(line, "[vvar]") || strstr(line, "[vsyscall]"))
            continue;
        for (unsigned long off = lo; off < hi; off += (1 << 20)) {
            size_t want = hi - off < (1 << 20) ? hi - off : (1 << 20);
            ssize_t got = pread(mem, buf, want, (off_t)off);
            if (got > 0)
                scan_chunk(buf, (size_t)got);
        }
    }
    free(buf);
    fclose(maps);
    close(mem);
}
#else
static void scan_process(void) { printf("  residue scan not implemented on this platform\n"); }
#endif

int main(int argc, char **argv) {
    const char *path = argc > 1 ? argv[1] : SKP_VECTORS_DIR "/qwerty-ios-390x3-shuffle.json";
    randombytes_buf(g_mask, sizeof g_mask);
    size_t len;
    char *text = read_file(path, &len);
    if (!text) {
        fprintf(stderr, "cannot read %s\n", path);
        return 2;
    }
    cJSON *v = cJSON_ParseWithLength(text, len);
    sodium_memzero(text, len);
    free(text);
    if (!v)
        return 2;

    /* copy what we need, then wipe and drop the JSON */
    char master[65], ctxs[64] = {0};
    strncpy(master, jstr(v, "master_key"), 64);
    master[64] = 0;
    const cJSON *so = cJSON_GetObjectItemCaseSensitive(v, "server_opts");
    if (jstr(so, "ctx"))
        strncpy(ctxs, jstr(so, "ctx"), 63);
    char layout_opt[16] = {0}, blank_opt[16] = {0};
    if (jstr(so, "layout"))
        strncpy(layout_opt, jstr(so, "layout"), 15);
    if (jstr(so, "blank"))
        strncpy(blank_opt, jstr(so, "blank"), 15);
    uint32_t ttl = (uint32_t)jint(so, "ttl"), max_len = (uint32_t)jint(so, "maxLen");
    const cJSON *hooks = cJSON_GetObjectItemCaseSensitive(v, "hooks");
    uint8_t s_sk[32], sid[16], seed[32], nonce24[24];
    unhex(s_sk, 32, jstr(hooks, "s_sk"));
    unhex(sid, 16, jstr(hooks, "sid"));
    unhex(seed, 32, jstr(hooks, "seed"));
    unhex(nonce24, 24, jstr(hooks, "nonce24"));
    int64_t now = jint(hooks, "now");
    char *req = cJSON_PrintUnformatted(cJSON_GetObjectItemCaseSensitive(v, "request"));
    const cJSON *in = cJSON_GetObjectItemCaseSensitive(v, "input");
    char *payload = cJSON_PrintUnformatted(cJSON_GetObjectItemCaseSensitive(in, "payload"));
    int64_t decrypt_now = jint(in, "decrypt_now");
    const cJSON *es = cJSON_GetObjectItemCaseSensitive(v, "expect_session");
    uint8_t k_s2c[32], k_c2s[32];
    unhex(k_s2c, 32, jstr(es, "k_s2c"));
    unhex(k_c2s, 32, jstr(es, "k_c2s"));
    size_t plain_len = strlen(jstr(in, "expect_plain"));
    char *plain = malloc(plain_len + 1);
    memcpy(plain, jstr(in, "expect_plain"), plain_len + 1);
    add_pattern("k_s2c", k_s2c, 32);
    add_pattern("k_c2s", k_c2s, 32);
    add_pattern("seed", seed, 32);
    add_pattern("plaintext", (const uint8_t *)plain, plain_len);
    sodium_memzero(k_s2c, 32);
    sodium_memzero(k_c2s, 32);
    json_wipe(v);
    cJSON_Delete(v);

    /* sanity: the scanner must find a live copy */
    {
        uint8_t live[32];
        memcpy(live, seed, 32);
        scan_process();
        CHECK(g_pat[2].hits >= 1, "scanner cannot see a live copy of the seed (hits=%d)", g_pat[2].hits);
        sodium_memzero(live, 32);
        for (int i = 0; i < g_npat; i++)
            g_pat[i].hits = 0;
    }

    skp_config cfg = {0};
    cfg.master_key = master;
    skp_ctx *ctx = NULL;
    int rc = skp_init(&ctx, &cfg);
    CHECK(rc == SKP_OK, "init %s", skp_strerror(rc));
    skp_test_hooks h = {s_sk, sid, seed, nonce24, now, 0};
    skp_test_set_hooks(&h);
    skp_session_opts opts = {ctxs[0] ? ctxs : NULL, layout_opt[0] ? layout_opt : NULL, blank_opt[0] ? blank_opt : NULL, ttl, max_len};
    skp_buf resp = {0}, sealed = {0};
    rc = skp_session_create(ctx, req, 0, &opts, &resp, &sealed);
    CHECK(rc == SKP_OK, "create %s", skp_strerror(rc));
    skp_test_hooks h2 = {NULL, NULL, NULL, NULL, decrypt_now, 0};
    skp_test_set_hooks(&h2);
    skp_secret *s = NULL;
    rc = skp_session_decrypt(ctx, sealed.data, sealed.len, payload, 0, ctxs[0] ? ctxs : NULL, &s);
    CHECK(rc == SKP_OK, "decrypt %s", skp_strerror(rc));
    if (s) {
        CHECK(skp_secret_len(s) == plain_len && !memcmp(skp_secret_bytes(s), plain, plain_len), "plaintext");
        skp_secret_free(s);
    }
    skp_buf_free(&resp);
    skp_buf_free(&sealed);
    skp_test_set_hooks(NULL);
    skp_free(ctx);
    /* drop our own copies of the inputs */
    sodium_memzero(s_sk, 32);
    sodium_memzero(seed, 32);
    sodium_memzero(sid, 16);
    sodium_memzero(master, sizeof master);
    sodium_memzero(req, strlen(req));
    free(req);
    sodium_memzero(payload, strlen(payload));
    free(payload);
    sodium_memzero(plain, plain_len);
    free(plain);

    scan_process();
    for (int i = 0; i < g_npat; i++) {
        printf("  %-10s residue hits: %d\n", g_pat[i].name, g_pat[i].hits);
        CHECK(g_pat[i].hits == 0, "%s found in memory after the session was destroyed", g_pat[i].name);
    }
    printf("%d failures\n", g_failures);
    return g_failures ? 1 : 0;
}
