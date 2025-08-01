#include "macLbl.h"
#include "t2log.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>


int main(int argc, char *argv[]) {

    if (argc < 3) {
        printf("Usage: ./mbm <infile> <outfile>\n");
        exit(EXIT_FAILURE);
    }

    FILE *fin;
    if (!(fin = fopen(argv[1], "r"))) {
        T2_ERR("Failed to open file '%s' for reading: %s", argv[2], strerror(errno));
        exit(EXIT_FAILURE);
    }

    FILE *fout;
    if (!(fout = fopen(argv[2], "wb"))) {
        T2_ERR("Failed to open file '%s' for writing: %s", argv[3], strerror(errno));
        exit(EXIT_FAILURE);
    }

    maclbl_t srec = {};
    fwrite(&srec, sizeof(maclbl_t), 1, fout);

    char sorg[MAC_SORGLEN+11] = {};
    char org[MAC_ORGLEN+201] = {};
    uint32_t mask;
    int32_t count = 0;

    ssize_t read;
    size_t len = 0;
    char *line = NULL;
    while ((read = getline(&line, &len, fin)) != -1) {
        if (line[0] == '\n' || line[0] == '#' || line[0] == ' ' || line[0] == '\t') continue;

        sscanf(line, "0x%" SCNx64"\t %" SCNu32 "\t%" SCNu32 "\t%" SCNu32 "\t%[^\t]\t%[^\n\t]", &srec.ouiEt, &mask, &srec.vec, &srec.beF, sorg, org);

        //srec.mask = MASK64 << (64-mask);

#if MR_MACLBL == 2
        memcpy(srec.org, sorg, MAC_SORGLEN);
        srec.org[MAC_SORGLEN] = '\0';
#elif MR_MACLBL == 3
        memcpy(srec.org, org, MAC_ORGLEN);
        srec.org[MAC_ORGLEN] = '\0';
#endif // MR_MACLBL == 3

       fwrite(&srec, sizeof(maclbl_t), 1, fout);
       count++;
    }

    free(line);

    fseek(fout, 0, SEEK_SET);

    memset(&srec, '\0', sizeof(maclbl_t));
    srec.ouiEt = count;
    srec.beF = MR_MACLBL;
    fwrite(&srec, sizeof(maclbl_t), 1, fout);

    fclose(fout);

    return EXIT_SUCCESS;
}
