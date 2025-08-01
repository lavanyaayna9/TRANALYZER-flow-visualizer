/*
 * tp0flist.c
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

#include "tp0flist.h"

#include <errno.h>       // for errno
#include <inttypes.h>    // for SCNu8, SCNx8, SCNu32, SCNx16, PRIu32, SCNu16
#include <stdint.h>      // for uint_fast32_t
#include <stdio.h>       // for FILE, sscanf, fclose, getline, NULL, fopen
#include <stdlib.h>      // for free
#include <string.h>      // for strerror
#include <stdbool.h>     // for bool, true, false

#include "t2Plugin.h"


// Skip comments and empty lines
#define TP0F_SKIP_COMMENTS(line) if (line[0] == '\n' || line[0] == '#' || line[0] == '%' || line[0] == ' ' || line[0] == '\t') continue


// Static variables
static const char * const plugin_name = "tp0f";


// static functions prototypes

static bool tp0flist_load(const char *filename, tp0flist_table_t *table);


// Returned valued MUST be free'd with tp0flist_table_free()
tp0flist_table_t *tp0flist_table_create(const char *filename) {
    tp0flist_table_t *table = t2_calloc_fatal(1, sizeof(*table));
    if (UNLIKELY(!tp0flist_load(filename, table))) {
        tp0flist_table_free(table);
        return NULL;
    }
    return table;
}


void tp0flist_table_free(tp0flist_table_t *table) {
    if (UNLIKELY(!table)) return;
    free(table->tp0flists);
    free(table);
}


static bool tp0flist_load(const char *filename, tp0flist_table_t *table) {
    FILE *file;
    if (UNLIKELY(!(file = fopen(filename, "r")))) {
        T2_PERR(plugin_name, "failed to open file '%s' for reading: %s", filename, strerror(errno));
        return false;
    }

    char tcpopt[256];

    char *line = NULL;
    size_t len = 0;
    ssize_t read;

    // Count the number of rows
    uint32_t count = 0;
    while ((read = getline(&line, &len, file)) != -1) {
        TP0F_SKIP_COMMENTS(line);
        count++;
    }

    table->count = count;

    if (count == 0) {
        T2_PERR(plugin_name, "file '%s' is empty", filename);
        table->tp0flists = NULL;
        free(line);
        fclose(file);
        return false;
    }

    table->tp0flists = t2_calloc_fatal(count, sizeof(tp0flist_t));
    tp0flist_t *tp0fLc = table->tp0flists;

    rewind(file);

    while ((read = getline(&line, &len, file)) != -1) {
        TP0F_SKIP_COMMENTS(line);

        sscanf(line, "%" SCNu16 "\t%" SCNx8  "\t%" SCNx8 "\t%" SCNx8 "\t"   // id, clst, ipv, ipF
                     "%" SCNx8  "\t%" SCNx16 "\t%" SCNu8 "\t%" SCNu8 "\t"   // tcpF, qoptF, ttl, olen
                     "%" SCNu32 "\t%" SCNu32 ",%"  SCNu8 "\t%" SCNu8 "\t"   // mss, wsize, ws, ntcpopt
                     "%[^\t\n]" "\t%" SCNu8  "\t%" SCNu8 "\t%" SCNu8 "\t"   // tcpopt, pldl, nclass, nprog
                     "%" SCNu8,                                             // nver
                     &tp0fLc->id, &tp0fLc->clst, &tp0fLc->ipv, &tp0fLc->ipF,
                     &tp0fLc->tcpF, &tp0fLc->qoptF, &tp0fLc->ttl, &tp0fLc->olen,
                     &tp0fLc->mss, &tp0fLc->wsize, &tp0fLc->ws, &tp0fLc->ntcpopt,
                     tcpopt, &tp0fLc->pldl, &tp0fLc->nclass, &tp0fLc->nprog,
                     &tp0fLc->nver);

        if (tp0fLc->ntcpopt) {
            const char *tcpoptP = tcpopt;

            uint_fast32_t i;
            for (i = 0; i < (uint8_t)(tp0fLc->ntcpopt - 1) && i < TCPOPTMAX - 1; i++) {
                sscanf(tcpoptP, "%" SCNx8, &tp0fLc->tcpopt[i]);
                tcpoptP += 5;
            }

            uint16_t t;
            sscanf(tcpoptP, "%" SCNx16, &t);
            tp0fLc->tcpopt[i] = (uint8_t)t;
            tp0fLc->pad = (t >> 8);
        }

        tp0fLc++;
    }

    free(line);
    fclose(file);

#if VERBOSE > 0
    T2_PINF(plugin_name, "%" PRIu32 " rules loaded", count);
#endif

    return true;
}
