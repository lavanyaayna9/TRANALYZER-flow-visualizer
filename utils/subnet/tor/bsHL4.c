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

#include "subnetHL4.h"
#include "t2log.h"


FILE *dooF;


int main(int argc, char *argv[]) {

    dooF = stdout;

    if (argc < 2) {
        printf("Usage: bsHL4 torfile\n");
        exit(EXIT_FAILURE);
    }

    uint32_t addr;
    uint32_t subnetNr, asn, netID;
    float lat, lng;

    subnet4_t *subnP;

    char net[INET_ADDRSTRLEN];
    char loc[4], cnty[SMLINE], cty[SMLINE], who[SMLINE];

    FILE *file;
    if (UNLIKELY(!(file = fopen(argv[1], "r")))) {
        T2_ERR("Failed to open file '%s' for reading: %s", argv[1], strerror(errno));
        exit(EXIT_FAILURE);
    }

    subnettable4_t *bfo_subnet_table4P = subnet_init4(NULL, SUBNETFILE4);

    size_t len = 0;
    char *line = NULL;
    while (getline(&line, &len, file) != -1) {
        if (line[0] == '#') continue;

        sscanf(line, "%[^\n\t]\t%" SCNu32 "\t%f\t%f\t%[^\n\t]\t%[^\n\t]\t%[^\n\t]\t%[^\n\t]", net, &asn, &lat, &lng, loc, cnty, cty, who);

        inet_pton(AF_INET, net, &addr);

        subnetNr = subnet_testHL4(bfo_subnet_table4P, addr);
        subnP = &bfo_subnet_table4P->subnets[subnetNr];
        netID = TOR_MSK;
        if (subnetNr) {
            if (asn == 0) asn = subnP->asn;
            if (*loc == '-') memcpy(loc, subnP->loc, 4);
#if CNTYCTY == 1
            if (*cnty == '-') {
                memcpy(cnty, subnP->cnty, SMLINE);
                memcpy(cty, subnP->cty, SMLINE);
            }
#endif // CNTYCTY == 1
            netID |= subnP->netID;
        }

        addr = ntohl(addr);

        printf("0x%08x\t32\t1\t0x%08x\t%d\t80.0\t%f\t%f\t%s\t%s\t%s\t%s\n", addr, netID, asn, lng, lat, loc, cnty, cty, who);
    }

    fclose(file);

    subnettable4_destroy(bfo_subnet_table4P);

    return EXIT_SUCCESS;
}
