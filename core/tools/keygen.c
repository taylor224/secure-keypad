/* skp-keygen: generate a master key, or print the public key / key id of an existing one.
 *
 *   skp-keygen                 → prints a new base64 master key to stdout (store it with mode 0600)
 *   skp-keygen --pubkey FILE   → prints the Ed25519 public key (base64) and kid for FILE
 */
#include "skp.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc == 1) {
        char b64[64];
        int rc = skp_keygen_b64(b64, sizeof b64);
        if (rc) {
            fprintf(stderr, "keygen failed: %s\n", skp_strerror(rc));
            return 1;
        }
        printf("%s\n", b64);
        return 0;
    }
    if (argc == 3 && !strcmp(argv[1], "--pubkey")) {
        skp_config cfg = {0};
        cfg.master_key_path = argv[2];
        skp_ctx *ctx = NULL;
        int rc = skp_init(&ctx, &cfg);
        if (rc) {
            fprintf(stderr, "cannot load %s: %s\n", argv[2], skp_strerror(rc));
            return 1;
        }
        char pk[SKP_PUBLIC_KEY_B64_CAP], kid[SKP_KID_CAP];
        skp_public_key(ctx, pk, sizeof pk);
        skp_key_id(ctx, kid, sizeof kid);
        printf("public_key=%s\nkid=%s\n", pk, kid);
        skp_free(ctx);
        return 0;
    }
    fprintf(stderr, "usage: skp-keygen | skp-keygen --pubkey <master.key>\n");
    return 2;
}
