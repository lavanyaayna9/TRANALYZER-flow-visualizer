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

#include "t2log.h"

#define SMLINE 40


int main(int argc, char *argv[]) {

    if (argc != 2 || (argc == 2 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0))) {
        printf("Usage: %s fbinfile\n", argv[0]);
        exit(argc == 2 ? EXIT_SUCCESS : EXIT_FAILURE);
    }

    FILE *fout;
    if (!(fout = fopen(argv[1], "wb"))) {
        T2_FATAL("Failed to open file '%s' for writing: %s", argv[1], strerror(errno));
    }

    uint64_t fndx = 0;
    fwrite(&fndx, sizeof(fndx), 1, fout);

    size_t len = 0;
    ssize_t read;
    char *line = NULL;

    uint64_t count = 0;
    while ((read = getline(&line, &len, stdin)) != -1) {
        if (line[0] < '0' || line[0] > '9' || read < 1) continue;
        sscanf(line, "%" SCNd64, &fndx);
        fwrite(&fndx, sizeof(fndx), 1, fout);
        count++;
    }

    free(line);

    // Write information
    fseek(fout, 0, SEEK_SET);
    fwrite(&count, sizeof(fndx), 1, fout);

    fclose(fout);

    return EXIT_SUCCESS;
}
