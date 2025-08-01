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

#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "subnetHL.h"
#include "t2log.h"


int main(int argc, char *argv[]) {

    if (argc < 2) {
        printf("Usage: ext4 subnets4.txt\n");
        exit(EXIT_FAILURE);
    }

    FILE *fin;
    if (!(fin = fopen(argv[1], "r"))) {
        T2_ERR("Failed to open file '%s' for reading: %s", argv[1], strerror(errno));
        exit(EXIT_FAILURE);
    }

    uint32_t n, e, add = 0;
    int m;

#if SUBRNG == 1
    uint32_t adde = 0;
    char netE[20];
#else // SUBRNG == 0
    int madd = 0;
    uint32_t ip, mm;
#endif // SUBRNG == 0

    char line[SMLINE+1], rline[SMLINE], netA[20], netr[40];
    while (fgets(line, SMLINE, fin)) {
        if (line[0] == '\n' || line[0] == '#' || line[0] == ' ' || line[0] == '\t') continue;

#if SUBRNG == 0
        if (*line == '-') continue;

        sscanf(line, "%15[^/]/%d\t%32[^\t]\t%500[^\n]", netA, &m, netr, rline);

        inet_pton(AF_INET, netA, &ip);

        if (ip == add && m == madd) continue;

        add = ip;
        madd = m;

        if (m < 0 || m > 32) continue;

        if (m) {
            mm = ntohl(0xffffffff << (32-m));
            n = ip & mm;
            e = ip | ~mm;
        } else {
            n = 0;
            e = 0xffffffff;
        }
#else // SUBRNG == 1
        sscanf(line, "%15[^/]/%d\t%15[^-]-%15[^\t]\t%500[^\n]", netr, &m, netA, netE, rline);

        inet_pton(AF_INET, netA, &n);
        inet_pton(AF_INET, netE, &e);

        if (n == add && e == adde) continue;

        add = n;
        adde = e;
#endif // SUBRNG == 0

        if (m < 32) printf("0x%08x\t%02d\t0\t%s\n", ntohl(n), m, rline);
        printf("0x%08x\t%02d\t1\t%s\n", ntohl(e), m, rline);
    }

    fclose(fin);

    return EXIT_SUCCESS;
}
