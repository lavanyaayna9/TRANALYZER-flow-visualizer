#include "macLbl.h"
#include "t2log.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#define MAXSTACK 20

int main(int argc, char *argv[]) {

    if (argc < 2) {
        printf("Usage: ./ucv <outfile>\n");
        exit(EXIT_FAILURE);
    }

    FILE *fout;
    if (!(fout = fopen(argv[1], "w"))) {
        T2_ERR("Failed to open file '%s' for writing: %s", argv[3], strerror(errno));
        exit(EXIT_FAILURE);
    }

    uint64_t a = 0, O[20];
    uint64_t ouiEt;
    uint32_t mask, bef;
    uint32_t M[MAXSTACK], B[MAXSTACK], T[MAXSTACK];
    uint32_t G[MAXSTACK] = {};
    uint32_t t, i = 0, j = 0, l = 0, b = 0;
    char bsoo[MAC_ORGLEN+301];
    char BSO[MAXSTACK][MAC_ORGLEN+301] = {};

    ssize_t read;
    size_t len = 0;
    char *line = NULL;
    while ((read = getline(&line, &len, stdin)) != -1) {
        if (line[0] == '\n' || line[0] == '#' || line[0] == ' ' || line[0] == '\t') continue;

        sscanf(line, "0x%" SCNx64"\t %" SCNu32 "\t %" SCNu32 "\t%[^\n]", &ouiEt, &mask, &bef, bsoo);

        const uint64_t c = ouiEt & 0xffffffffffff0000L;

        if (c != a) {
            if (bef) {
                for (uint_fast32_t k = 1; k <= j; k++) {
                    if (O[k] & 0x000000000000ffffL) fprintf(fout, "0x%016" PRIX64 "\t%" PRIu32 "\t%" PRIu32 "\t%" PRIu32 "\t%s\n", O[k], M[k], T[k], (b << 1) | B[k], BSO[k]);
                    else fprintf(fout, "0x%016" PRIX64 "\t%" PRIu32 "\t%" PRIu32 "\t%" PRIu32 "\t%s\n", O[k], M[k], T[k], B[k], BSO[k]);
                }
            } else {
                for (uint_fast32_t k = j; k >= 1; k--) {
                    if (O[k] & 0x000000000000ffffL) fprintf(fout, "0x%016" PRIX64 "\t%" PRIu32 "\t%" PRIu32 "\t%" PRIu32 "\t%s\n", O[k], M[k], T[k], (b << 1) | B[k], BSO[k]);
                    else fprintf(fout, "0x%016" PRIX64 "\t%" PRIu32 "\t%" PRIu32 "\t%" PRIu32 "\t%s\n", O[k], M[k], T[k], B[k], BSO[k]);
                }
            }
            j = 0;
            a = c;
        }

        i++;

        if (mask == 48) t = G[l];
        else if (!(bef & 1)) {t = G[l]; G[++l] = i;}
        else {l--; if (j) t = G[l+1]; else t = G[l];}
//fprintf(fout, "%d %d %d %d %d\n", t,G[l],l,i,j);

        j++;

        O[j] = ouiEt;
        M[j] = mask;
        B[j] = bef;
        T[j] = t;

        const int z = strlen(bsoo) + 1;
        memcpy(BSO[j], bsoo, z);
        b = i;
    }

    free(line);

    if (bef) {
        for (uint_fast32_t k = 1; k <= j; k++) {
            if (O[k] & 0x000000000000ffffL) fprintf(fout, "0x%016" PRIX64 "\t%" PRIu32 "\t%" PRIu32 "\t%" PRIu32 "\t%s\n", O[k], M[k], T[k], (b << 1) | B[k], BSO[k]);
            else fprintf(fout, "0x%016" PRIX64 "\t%" PRIu32 "\t%" PRIu32 "\t%" PRIu32 "\t%s\n", O[k], M[k], T[k], B[k], BSO[k]);
        }
    } else {
        for (uint_fast32_t k = j; k >= 1; k--) {
            if (O[k] & 0x000000000000ffffL) fprintf(fout, "0x%016" PRIX64 "\t%" PRIu32 "\t%" PRIu32 "\t%" PRIu32 "\t%s\n", O[k], M[k], T[k], (b << 1) | B[k], BSO[k]);
            else fprintf(fout, "0x%016" PRIX64 "\t%" PRIu32 "\t%" PRIu32 "\t%" PRIu32 "\t%s\n", O[k], M[k], T[k], B[k], BSO[k]);
        }
    }

    fclose(fout);

    return EXIT_SUCCESS;
}
