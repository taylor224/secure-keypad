/* Build-time helper: turns a binary file into a C array. Usage: embed <in> <out.c> <symbol> */
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "usage: embed <input> <output.c> <symbol>\n");
        return 2;
    }
    FILE *in = fopen(argv[1], "rb");
    if (!in) {
        perror(argv[1]);
        return 1;
    }
    FILE *out = fopen(argv[2], "w");
    if (!out) {
        perror(argv[2]);
        return 1;
    }
    fprintf(out, "#include <stddef.h>\nconst unsigned char %s[] = {\n", argv[3]);
    unsigned char buf[4096];
    size_t n, total = 0;
    while ((n = fread(buf, 1, sizeof buf, in)) > 0) {
        for (size_t i = 0; i < n; i++) {
            fprintf(out, "%u,", buf[i]);
            if ((++total % 32) == 0)
                fputc('\n', out);
        }
    }
    fprintf(out, "\n};\nconst size_t %s_len = %zu;\n", argv[3], total);
    fclose(in);
    fclose(out);
    return 0;
}
