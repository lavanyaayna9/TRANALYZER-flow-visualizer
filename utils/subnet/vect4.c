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

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

#include "subnetHL.h"


#define MAXRNGSTACK 100


int main(int argc __attribute__((__unused__)), char *argv[] __attribute__((__unused__))) {
    int i = 1, j = 1, m, d;
    uint32_t net;
    int32_t A[MAXRNGSTACK] = {0};
    char line[SMLINE+1], rline[SMLINE];

    while (fgets(line, SMLINE, stdin)) {
        if (line[0] != '0') continue;

        sscanf(line, "0x%" SCNx32 "\t%d\t%d\t%500[^\n]", &net, &m, &d, rline);

        if (m == 32) {
#if SUBRNG == 1
            printf("0x%08" PRIx32 "\t%d\t0x%02x\t%s\n", net, A[j], SINGLE4 | d, rline);
#else // SUBRNG == 0
            printf("0x%08" PRIx32 "\t%02d\t%d\t%d\t%s\n", net, m, A[j], d, rline);
#endif // SUBRNG == 0
            i++;
            continue;
        }

        if ((d & 1) == 0) {
#if SUBRNG == 1
            printf("0x%08" PRIx32 "\t%d\t0x%02x\t%s\n", net, A[j], d, rline);
#else // SUBRNG == 0
            printf("0x%08" PRIx32 "\t%02d\t%d\t%d\t%s\n", net, m, A[j], d, rline);
#endif // SUBRNG == 0
            A[++j] = i;
        } else if (j) {
            j--;
#if SUBRNG == 1
            printf("0x%08" PRIx32 "\t%d\t0x%02x\t%s\n", net, A[j], d, rline);
#else // SUBRNG == 0
            printf("0x%08" PRIx32 "\t%02d\t%d\t%d\t%s\n", net, m, A[j], d, rline);
#endif // SUBRNG == 0
        }
        i++;

    }

    return EXIT_SUCCESS;
}
