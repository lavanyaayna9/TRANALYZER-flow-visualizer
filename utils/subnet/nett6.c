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
#include <string.h>

#include "subnetHL.h"


int main(int argc __attribute__((__unused__)), char *argv[] __attribute__((__unused__))) {
    int i = 0, j;
    int sw, l, d, dl = 0, m, ml = 0;
    uint64_t net[2], netl[2] = {0};
    char line[SMLINE+1], lineC[50][SMLINE+1], rline[SMLINE+1];

    while (fgets(line, SMLINE, stdin)) {
        if (line[0] != '0') continue;

        sscanf(line, "0x%" SCNx64 " %" SCNx64 "\t%d\t%d\t%512[^\n]", &net[0], &net[1], &m, &d, rline);

        if (net[0] == netl[0] && net[1] == netl[1]) sw = 1;
        else {
            netl[0] = net[0];
            netl[1] = net[1];
            sw = 0;
        }

        l = (ml == m) ? 0 : 1;

        if ((sw | (dl & l)) & d) {
            memcpy(lineC[i++], line, strlen(line)+1);
        } else {
            for (j = i - 1; j >= 0; j--) fputs(lineC[j], stdout);
            i = 0;
            if (d && !sw) memcpy(lineC[i++], line, strlen(line)+1);
            else fputs(line, stdout);
        }

        ml = m;
        dl = !d;
    }

    for (j = i - 1; j >= 0; j--) fputs(lineC[j], stdout);

    return EXIT_SUCCESS;
}
