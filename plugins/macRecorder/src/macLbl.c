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

#include "macLbl.h"

#include <stdlib.h>  // for free, exit

#include "macRecorder.h"
#include "t2log.h"


// Static variables

static const char * const MRMLBLS[] = {
    "",
    "index",
    "short org name",
    "full org name"
};

static const char * const plugin_name = "macRecorder";


maclbltable_t* maclbl_init(const char *dir, const char *filename) {
    FILE *file = t2_fopen_in_dir(dir, filename, "r");
    if (UNLIKELY(!file)) exit(EXIT_FAILURE);

    maclbl_t srec;
    if (UNLIKELY(fread(&srec, sizeof(maclbl_t), 1, file) != 1)) {
        T2_PERR(plugin_name, "Failed to read first record in maclblfile");
        fclose(file);
        exit(EXIT_FAILURE);
    }

    if (srec.beF != MR_MACLBL) {
        T2_PERR(plugin_name, "Mismatch! plugin %d - '%s' %" PRIu32 ", recompile: t2build -f macRecorder", MR_MACLBL, filename, srec.beF);
        fclose(file);
        exit(EXIT_FAILURE);
    }

    const int32_t count = (int32_t)srec.ouiEt;

    maclbltable_t *tableP = t2_malloc_fatal(sizeof(*tableP));
    tableP->count = count;

    if (UNLIKELY(!tableP->count)) {
        T2_PERR(plugin_name, "Zero elements in maclblfile");
        free(tableP);
        fclose(file);
        exit(EXIT_FAILURE);
    }

    tableP->maclbls = t2_malloc_fatal(sizeof(maclbl_t) * (count+1));

    maclbl_t *maclP = tableP->maclbls;
    memset(&maclP[0], '\0', sizeof(*maclP));

#if MR_MACLBL > 1
    maclP[0].org[0] = '-';
#endif // MR_MACLBL > 1

    const int32_t nrec = fread(&maclP[1], sizeof(maclbl_t), count, file);
#if VERBOSE > 0
    if (UNLIKELY(nrec != count)) {
        T2_PWRN(plugin_name, "Expected %" PRId32 " records from '%s', but found %" PRId32, count, filename, nrec);
    } else {
        char hrnum[64];
        T2_CONV_NUM(nrec, hrnum);
        T2_PINF(plugin_name, "%" PRId32 "%s %s records loaded", nrec, hrnum, MRMLBLS[MR_MACLBL]);
    }
#endif // VERBOSE > 0

    fclose(file);

    return tableP;
}


// Test whether a given mac/ethType is a member of a known maclbl
inline uint32_t maclbl_test(maclbltable_t *table, uint64_t mac, uint16_t ethType) {

    if (!(mac && table->count)) return 0;

    uint64_t k = 0;
    int_fast32_t i = 0, start = 1, end = table->count;
    int s = 0;

    mac = htobe64(mac);

a:  while (start <= end) {
        i = (end + start) / 2;
        k = table->maclbls[i].ouiEt;
        if (mac < k) {
            end = i - 1;  // set the endpoint one under the current middle.
            continue;
        }
        if (mac == k) {
            return i;
        } else start = i + 1;  // set the startpoint one over the current middle.
    }

    if (s) return 0;

    if (table->maclbls[i].beF & 0x01) {
        if (mac <= k) return i;
    } else {
        if (i >= table->count) return 0;

        if (mac >= k && (table->maclbls[i+1].beF & 0x01)) return i;

        if (k & 0x000000000000ffff) {
            mac = ethType | mac;
            end = table->maclbls[i+1].beF >> 1;
            s = 1;
            goto a;
        }
    }

    return 0;
}


void maclbltable_destroy(maclbltable_t *table) {
    if (UNLIKELY(!table)) return;

    free(table->maclbls);
    free(table);
}
