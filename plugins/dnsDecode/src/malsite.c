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

#include "malsite.h"

#include <errno.h>      // for errno
#include <stdio.h>      // for FILE, fopen
#include <string.h>     // for memcpy, strcmp


// Static variables
static const char * const plugin_name = "dnsDecode";


// local functions

// returns the number of subnets and file table, if given
static inline uint32_t malsite_load(const char *filename, malsite_t *malsites) {
    if (UNLIKELY(!filename)) return 0;

    FILE *file = fopen(filename, "r");
    if (UNLIKELY(!file)) {
        T2_PERR(plugin_name, "failed to open file '%s' for reading: %s", filename, strerror(errno));
        exit(EXIT_FAILURE);
    }

#if DNS_MAL_DOMAIN == 1
    char domain[DMMXLN+1] = {};
    size_t len;
#else // DNS_MAL_DOMAIN == 0
    ipAddr_t ip = {};
#endif // DNS_MAL_DOMAIN

    uint32_t count = 1, id;
    char line[LNMXLN+1], malTyp[MTMXLN+1] = {};

    while (fgets(line, LNMXLN, file)) {
        // Skip comments and empty lines
        if (line[0] == '\n' || line[0] == '#' || line[0] == ' ' || line[0] == '\t') continue;
        if (malsites) {
#if DNS_MAL_DOMAIN == 1
            sscanf(line, "%" SNUM(DMMXLN) "[^\t]\t%" SCNu32 "\t%" SNUM(MTMXLN) "[^\t\n]", domain, &id, malTyp);
            len = strlen(domain);
            malsites[count].len = len;
            memcpy(malsites[count].malDomain, domain, len+1);
            memcpy(malsites[count].malTyp, malTyp, strlen(malTyp)+1);
#else // DNS_MAL_DOMAIN == 0
            sscanf(line, "%x\t%x\n", &ip.IPv4x[0], &id);
            malsites[count].malIp = ip;
#endif // DNS_MAL_DOMAIN
            malsites[count].malId = id;
        }
        count++;
    }

    if (malsites) {
#if DNS_MAL_DOMAIN == 1
        T2_PINF(plugin_name, "%" PRIu32 " blacklisted domains", count);
#else // DNS_MAL_DOMAIN == 0
        T2_PINF(plugin_name, "%" PRIu32 " blacklisted IPs", count);
#endif // DNS_MAL_DOMAIN
    }

    fclose(file);

    return count;
}


inline malsitetable_t *malsite_init() {
    const size_t plen = pluginFolder_len;
    const size_t len = plen + sizeof(DNS_TMALFILE);
    if (UNLIKELY(len > MAX_FILENAME_LEN)) {
        T2_PERR(plugin_name, "Filename to malsite file is too long");
        exit(EXIT_FAILURE);
    }

    char filename[len];
    memcpy(filename, pluginFolder, plen);
    memcpy(filename + plen, DNS_TMALFILE, sizeof(DNS_TMALFILE));

    malsitetable_t *table = t2_malloc_fatal(sizeof(*table));

    table->count = malsite_load(filename, NULL); // return the numbers of lines in the malsite file.
    if (table->count == 0) {
        T2_PWRN(plugin_name, "No valid entries in '%s'", filename);
        table->malsites = NULL;
        return table;
    }

    table->malsites = t2_malloc_fatal((table->count + 1) * sizeof(malsite_t));
    table->count = malsite_load(filename, table->malsites);

    return table;
}


inline void malsite_destroy(malsitetable_t *table) {
    if (UNLIKELY(!table)) return;

    if (LIKELY(table->malsites != NULL)) {
        free(table->malsites);
        table->malsites = NULL;
    }

    free(table);
}


#if DNS_MAL_DOMAIN == 1

// this function tests whether a given domain name is a malware host defined in the config file
inline uint32_t maldomain_test(malsitetable_t *table, const char *dname) {
    if (!dname || *dname == '\0') return 0;

    int middle, i;
    int start = 1;
    int end = table->count;
    const malsite_t * const malsiteP = table->malsites;

    while (start <= end) {
        middle = (end + start) / 2;
        i = strcmp(dname, malsiteP[middle].malDomain);
        if (i == 0) {
            return middle; // return the located malsite codes.
        } else if (i < 0) {
            end = middle - 1; // set the endpoint one under the currently middle.
        } else {
            start = middle + 1; // set the startpoint one over the currently middle.
        }
    }

    return 0; // in case the ip isn't in the file, return 0.
}

#else // DNS_MAL_DOMAIN == 0

// this function tests whether a given IP is a malware IP defined in the config file, currently only in non aggregated mode
inline uint32_t malip_test(malsitetable_t *table, ipAddr_t ip) {
    if (!ip.IPv6L[0] || !ip.IPv6L[1]) return 0;

    uint32_t i;
    ip.IPv4x[0] = ntohl(ip.IPv4x[0]);

    int middle;
    int start = 0;
    int end = table->count - 1;
    const malsite_t * const malsiteP = table->malsites;

    while (start <= end) {
        middle = (end + start) / 2; // define middle as middle between start and end.
        i = (uint32_t) malsiteP[middle].malIp.IPv4x[0];
        if (ip.IPv4x[0] == i) {
            return middle; // return the located malsite codes.
        } else if (ip.IPv4x[0] < i) {
            end = middle - 1; // set the endpoint one under the currently middle.
        } else {
            start = middle + 1; // set the startpoint one over the currently middle.
        }
    }

    return 0; // in case the ip isn't in the file, return 0.
}
#endif // DNS_MAL_DOMAIN
