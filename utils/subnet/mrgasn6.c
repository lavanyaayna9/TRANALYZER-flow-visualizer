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

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>

#include "subnetHL6.h"
#include "t2utils.h"


#if WHOADDR == 0
#error "Set WHOADDR to 1 in subnetHL.h: t2conf tranalyzer2 -D WHOADDR=1"
#endif


FILE *dooF;


int main(int argc, char *argv[]) {

    if (argc < 3) {
        printf("Usage: %s ip2asn-v6_HLP.bin subnetfile.txt\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    uint32_t subnetNr;
    subnet6_t *subnP;
    ipAddr_t add = {};
    int msk;
    float lat, lng;
    char ip[INET6_ADDRSTRLEN];
    char iprng[2 * INET6_ADDRSTRLEN + 3];
    char loc[4];
    char org[SMLINE+1];
    char id[12];
    char cnty[SMLINE+1];
    char cty[SMLINE+1];
    char p[12];
    char addr[5000];
    char asns[SMLINE];
    char asnn[25];
    char *asn;

    size_t len = 0;
    ssize_t read;
    char *line = NULL;
    dooF = stdout;

    FILE *file;
    if (!(file = fopen(argv[2], "r"))) {
        T2_FATAL("Failed to open file '%s' for reading: %s", argv[2], strerror(errno));
    }

    subnettable6_t *subnet_table6P = subnet_init6(NULL, argv[1]);

    while ((read = getline(&line, &len, file)) != -1) {
        // Skip comments and empty lines
        if (line[0] == '#' || line[0] == '%' || line[0] == '\n' || read < 1) {
            fputs(line, stdout);
            continue;
        }

        *addr = '\0';
        *asnn = '\0';

        sscanf(line, "%[^/]/%d\t%[^\t]\t%[^\t]\t%[^\t]\t%[^\t]\t%f\t%f\t%03[^\t]\t%[^\n\t]\t%[^\n\t]\t%[^\n\t]\t%[^\n]",
                ip, &msk, iprng, id, asns, p, &lat, &lng, loc, cnty, cty, org, addr);
        if (asns[2] == '.') memcpy(asns, "0", 2);
        inet_pton(AF_INET6, ip, &add);
        subnetNr = subnet_testHL6(subnet_table6P, add); // subnet test source ip
        if (!subnetNr) {
            fputs(line, stdout);
        } else {
            subnP = &subnet_table6P->subnets[subnetNr];
            if (!subnP) {
                fputs(line, stdout);
            } else {
                if (*asns == '0' && subnP->asn != 0) {
                    snprintf(asnn, 24, "%" PRIu32, subnP->asn);
                    asn = asnn;
                } else {
                    asn = asns;
                }
                printf("%s/%d\t%s\t%s\t%s\t%s\t%f\t%f\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
                        ip, msk, iprng, id, asn, p, lat, lng, loc, cnty, cty, org, addr, subnP->loc, subnP->org, subnP->addr);
            }
        }
    }

    free(line);
    fclose(file);

    subnettable6_destroy(subnet_table6P);

    return EXIT_SUCCESS;
}
