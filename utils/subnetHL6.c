/*
 * subnetHL6.c
 *
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

#include "subnetHL6.h"

#include <errno.h>              // for errno
#include <fcntl.h>              // for open, O_RDONLY
#include <inttypes.h>           // for PRId32, PRIu32, PRIu8
#include <stdio.h>              // for fclose, fread, FILE
#include <stdlib.h>             // for exit, free, malloc
#include <string.h>             // for strerror, NULL
#include <sys/mman.h>           // for mmap, MAP_FAILED, MAP_PRIVATE, PROT_READ
#include <sys/stat.h>           // for fstat, stat
#include <unistd.h>             // for close, ssize_t

#ifndef __APPLE__
#include <endian.h>             // for htobe64
#else // __APPLE__
#include "missing/missing.h"    // for htobe64
#endif // __APPLE__

#include "t2log.h"              // for T2_ERR, T2_INF2
#include "t2utils.h"            // for UNLIKELY, t2_build_filename, t2_fopen_in_dir
#include "tranalyzer.h"         // for MAX_FILENAME_LEN


subnettable6_t* subnet_init6(const char *dir, const char *filename) {

    subnettable6_t * const tableP = t2_malloc_fatal(sizeof(*tableP));

#if SUB_MAP == 1
    char path[MAX_FILENAME_LEN];
    t2_build_filename(path, sizeof(path), dir, filename, NULL);

    const int fdmap = open(path, O_RDONLY);
    if (UNLIKELY(fdmap < 0)) {
        T2_ERR("Failed to open IPv6 subnet file '%s' read-only: %s", path, strerror(errno));
        free(tableP);
        exit(EXIT_FAILURE);
    }

    tableP->fdmap = fdmap;

    struct stat fst;
    if (UNLIKELY(fstat(fdmap, &fst) != 0)) {
        T2_ERR("fstat failed for IPv6 subnet file '%s': %s", path, strerror(errno));
        free(tableP);
        close(fdmap);
        exit(EXIT_FAILURE);
    }

    const ssize_t size = fst.st_size;
    if (UNLIKELY(size < 0)) {
        T2_ERR("Failed to determine size of IPv6 subnet file '%s'", path);
        free(tableP);
        close(fdmap);
        exit(EXIT_FAILURE);
    }

    subnet6_t * const subnP = mmap(NULL, size, PROT_READ /*| PROT_WRITE*/, MAP_PRIVATE, fdmap, 0);
    if (UNLIKELY(subnP == MAP_FAILED)) {
        T2_ERR("Failed to mmap IPv6 subnet file '%s': %s", path, strerror(errno));
        free(tableP);
        close(fdmap);
        exit(EXIT_FAILURE);
    }

    tableP->subnets = subnP;

    const subnet6_t srec = subnP[0];
#else // SUB_MAP == 0
    FILE * const file = t2_fopen_in_dir(dir, filename, "r");

    if (UNLIKELY(!file)) {
        free(tableP);
        exit(EXIT_FAILURE);
    }

    subnet6_t srec;
    if (UNLIKELY(fread(&srec, sizeof(srec), 1, file) != 1)) {
        T2_ERR("Failed to read first IPv6 record in '%s'", filename);
        T2_INF2("Try rebuilding the subnet file with 't2build -f tranalyzer2'");
        free(tableP);
        fclose(file);
        exit(EXIT_FAILURE);
    }
#endif // SUB_MAP == 0

    const int32_t count = (int32_t)srec.net.IPv4x[0];

    const uint32_t ver = srec.net.IPv4x[1];
    const uint32_t rev = srec.net.IPv4x[2];

    const uint32_t subver = ver & VERMSK;
    const uint8_t subrng = (ver & ~VERMSK) >> 31;

    if (UNLIKELY(subver != SUBVER || subrng != SUBRNG)) {
        T2_ERR("IPv6 subnet file (version %" PRIu32 ", range mode %" PRIu8 ") does not match core configuration (version %d, range mode %d)", subver, subrng, SUBVER, SUBRNG);
        T2_INF2("Try rebuilding the subnet file with 't2build -f tranalyzer2'");
        free(tableP);
#if SUB_MAP == 1
        close(fdmap);
#else // SUB_MAP == 0
        fclose(file);
#endif // SUB_MAP == 0
        exit(EXIT_FAILURE);
    }

    tableP->count = count;
    tableP->ver = ver;
    tableP->rev = rev;

#if SUB_MAP == 1
    if (UNLIKELY(!count || count + 1 != (int32_t)(size / sizeof(srec)))) {
        T2_ERR("Zero or inconsistent element count in IPv6 subnet file '%s': found %" PRId32 ", expected %ld", filename, count, size / sizeof(srec));
        close(fdmap);
#else // SUB_MAP == 0
    if (UNLIKELY(!count)) {
        T2_ERR("Zero elements in IPv6 subnet file '%s'", filename);
        fclose(file);
#endif // SUB_MAP == 0
        T2_INF2("Try rebuilding the subnet file with 't2build -f tranalyzer2'");
        free(tableP);
        exit(EXIT_FAILURE);
    }

#if SUB_MAP == 1
/*
    subnP->net.IPv6L[0] = 0;
    subnP->net.IPv6L[1] = 0;
    subnP->netVec = 0;
    subnP->netID = 0;
*/
#else // SUB_MAP == 0
    if (UNLIKELY(!(tableP->subnets = t2_malloc(sizeof(*tableP->subnets) * (count + 1))))) {
        T2_ERR("Failed to allocate memory for IPv6 table->subnets: %zu bytes", count * sizeof(*tableP->subnets));
        free(tableP);
        fclose(file);
        exit(EXIT_FAILURE);
    }

    subnet6_t * const subnP = tableP->subnets;
    memset(subnP, 0, sizeof(*subnP));

    const size_t unk_len = sizeof(SUBNET_UNK) - 1;

    memcpy(subnP[0].loc, SUBNET_UNK, unk_len);
    memcpy(subnP[0].org, SUBNET_UNK, unk_len);
#if CNTYCTY == 1
    memcpy(subnP[0].cnty, SUBNET_UNK, unk_len);
    memcpy(subnP[0].cty, SUBNET_UNK, unk_len);
#endif // CNTYCTY == 1

    const size_t nrec = fread(&subnP[1], sizeof(*subnP), count, file);
    if (UNLIKELY((int32_t)nrec != count)) {
        T2_WRN("Expected %" PRId32 " records in IPv6 subnet file '%s', but found %zu", count, filename, nrec);
    }

    fclose(file);
#endif // SUB_MAP

    return tableP;
}


// Test whether a given IPv6 is a member of a known subnet
inline uint32_t subnet_testHL6(subnettable6_t *table, ipAddr_t net6) {

    if (!((net6.IPv6L[0] || net6.IPv6L[1]) && table->count)) return 0;

    int start = 1, i = 0, end = table->count;
    ipAddr_t k = {};

    ipAddr_t net;
    net.IPv6L[0] = htobe64(net6.IPv6L[0]);
    net.IPv6L[1] = htobe64(net6.IPv6L[1]);

    while (start <= end) {
        i = (end + start) / 2;
        k = table->subnets[i].net;

        if (net.IPv6L[0] < k.IPv6L[0]) {
            end = i - 1;  // set the endpoint one under the current middle.
            continue;
        }

        if (net.IPv6L[0] == k.IPv6L[0]) {
            if (net.IPv6L[1] == k.IPv6L[1]) {
                return i;
            } else if (net.IPv6L[1] < k.IPv6L[1]) {
                end = i - 1;
                continue;
            }
        }

        start = i + 1;  // set the startpoint one over the current middle.
    }

#if SUBRNG == 0
    const ipAddr_t mask = table->subnets[i].mask;
    if ((k.IPv6L[0] & mask.IPv6L[0]) == (net.IPv6L[0] & mask.IPv6L[0]) &&
        (k.IPv6L[1] & mask.IPv6L[1]) == (net.IPv6L[1] & mask.IPv6L[1]))
    {
        return i;
    }
#else // SUBRNG == 1
    const uint8_t beF = table->subnets[i].beF;
    if (beF & 0x01) {
        if (net.IPv6L[0] <= k.IPv6L[0] && net.IPv6L[1] <= k.IPv6L[1]) return i;
    } else {
        //if (beF == SINGLE6) goto vectup;
        if (net.IPv6L[0] >= k.IPv6L[0] && net.IPv6L[1] >= k.IPv6L[1]) return i;
        i = table->subnets[i].netVec;
        if (i < 1) return 0;
        if (net.IPv6L[0] == table->subnets[i].net.IPv6L[0] &&
            net.IPv6L[1] == table->subnets[i].net.IPv6L[1])
        {
            return table->subnets[i].netVec;
        }
        return i;
    }

//vectup:
#endif // SUBRNG

    if (i > 0 && i <= table->count) {
        i = table->subnets[i].netVec;
        if (i > 0 && i <= table->count) return i;
    }

    return 0;
}


void subnettable6_destroy(subnettable6_t *table) {
    if (UNLIKELY(!table)) return;

#if SUB_MAP == 1
    close(table->fdmap);
#else // SUB_MAP == 0
    free(table->subnets);
#endif // SUB_MAP == 0
    table->subnets = NULL;
    free(table);
}
