/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "subnetHL.h"
#include "t2log.h"


static void usage() {
    printf("Usage:\n");
    printf("    sbm6 subnets_in.txt subnets_out.bin version revision\n");
    printf("    sbm6 subnets.bin # returns the version of the subnet file\n");
}


// Extract and print version information from binary file
static void print_version_info(const char *filename) {
    FILE *file;
    if (!(file = fopen(filename, "r"))) {
        T2_ERR("Failed to open file '%s' for reading: %s", filename, strerror(errno));
        exit(EXIT_FAILURE);
    }

    subnet6_t srec;
    if (fread(&srec, sizeof(srec), 1, file) == 0) {
        T2_ERR("Failed to read record in file '%s'", filename);
        exit(EXIT_FAILURE);
    }

    fclose(file);

    printf("Version: %" PRIu32 "\n", (srec.net.IPv4x[1] & VERMSK));
    printf("Revision: %08" PRIu32 "\n", srec.net.IPv4x[2]);
    printf("Range_Mode: %lu\n", (unsigned long)(srec.net.IPv4x[1] & ~VERMSK) >> 31);
    printf("Num_Subnets: %" PRIu32 "\n", srec.net.IPv4x[0]/2);
}


int main(int argc, char *argv[]) {

    if (argc < 2 || argc > 5 ||
        (argc == 2 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)))
    {
        usage();
        exit(argc == 2 ? EXIT_SUCCESS : EXIT_FAILURE);
    }

    if (argc == 2) {
        print_version_info(argv[1]);
        exit(EXIT_SUCCESS);
    }

    FILE *fin;
    if (!(fin = fopen(argv[1], "r"))) {
        T2_ERR("Failed to open file '%s' for reading: %s", argv[1], strerror(errno));
        exit(EXIT_FAILURE);
    }

    FILE *fout;
    if (!(fout = fopen(argv[2], "wb"))) {
        T2_ERR("Failed to open file '%s' for writing: %s", argv[2], strerror(errno));
        exit(EXIT_FAILURE);
    }

    subnet6_t srec;
    memset(&srec, '\0', sizeof(srec));
    fwrite(&srec, sizeof(srec), 1, fout);

    int32_t count = 0;
#if SUBRNG == 0
    int32_t i;
    uint32_t mask;
#endif // SUBRNG

    char cnty[SMLINE], cty[SMLINE];
    size_t len = 0;
    char *line = NULL;
    while (getline(&line, &len, fin) != -1) {
        if (line[0] == '#' || isspace(line[0])) continue;
        memset(&srec, '\0', sizeof(srec));

#if SUBRNG == 1
        sscanf(line, "0x%" SCNx64 " %" SCNx64 "\t%" SCNd32 "\t0x%" SCNx8 "\t0x%08x\t%" SCNu32 "\t%f\t%f\t%f\t%2[^\n\t]\t%[^\n\t]\t%[^\n\t]\t%" STR(WHOLEN) "[^\n\t]",
                &srec.net.IPv6L[0], &srec.net.IPv6L[1], &srec.netVec, &srec.beF, &srec.netID, &srec.asn, &srec.oP, &srec.lat, &srec.lng, srec.loc, cnty, cty, srec.org);
#else // SUBRNG == 0
        sscanf(line, "0x%" SCNx64" %" SCNx64 "\t%" SCNd32 "\t%" SCNd32 "\t%d\t0x%08x\t%" SCNu32 "\t%f\t%f\t%f\t%2[^\n\t]\t%[^\n\t]\t%[^\n\t]\t%" STR(WHOLEN) "[^\n\t]",
                &srec.net.IPv6L[0], &srec.net.IPv6L[1], &mask, &srec.netVec, &i, &srec.netID, &srec.asn, &srec.oP, &srec.lat, &srec.lng, srec.loc, cnty, cty, srec.org);
        if (mask > 64) {
            srec.mask.IPv6L[1] = MASK64 << (128-mask);
            srec.mask.IPv6L[0] = MASK64;
        } else {
            srec.mask.IPv6L[1] = 0;
            srec.mask.IPv6L[0] = MASK64 << (64-mask);
        }
#endif // SUBRNG

#if CNTYCTY == 1
        memcpy(srec.cnty, cnty, CNTYLEN);
        memcpy(srec.cty, cty, CTYLEN);
#endif // CNTYCTY == 1

        fwrite(&srec, sizeof(srec), 1, fout);
        count++;
    }

    fclose(fin);
    free(line);

    // Write version information
    fseek(fout, 0, SEEK_SET);
    memset(&srec, '\0', sizeof(srec));
    srec.net.IPv4x[0] = count;
    srec.net.IPv4x[1] = atol(argv[3]) | ((long)SUBRNG << 31);
    srec.net.IPv4x[2] = atol(argv[4]);
    // TODO are those memcpy really necessary?
    memcpy(srec.loc, SUBNET_UNK, strlen(SUBNET_UNK));
#if CNTYCTY == 1
    memcpy(srec.cnty, SUBNET_UNK, strlen(SUBNET_UNK));
    memcpy(srec.cty, SUBNET_UNK, strlen(SUBNET_UNK));
#endif // CNTYCTY == 1
    memcpy(srec.org, SUBNET_UNK, strlen(SUBNET_UNK));
    fwrite(&srec, sizeof(srec), 1, fout);

    fclose(fout);

    return EXIT_SUCCESS;
}
