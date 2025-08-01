/*
 * tac_list.c
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

#include "tac_list.h"

#include "t2log.h"   // for T2_PERR, T2_PWRN
#include "t2utils.h" // for t2_fopen, UNLIKELY, ...

#include <ctype.h>   // for isspace
#include <stdio.h>   // for FILE


gsm_tac_list_t gsm_tac_list_load(const char *dir, const char *filename) {
    FILE *file = t2_fopen_in_dir(dir, filename, "r");
    if (UNLIKELY(!file)) exit(EXIT_FAILURE);

    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    uint32_t num_rec = 0;
    // skip comments and empty lines
    while ((read = getline(&line, &len, file)) != -1) {
        if (line[0] == '\n' || line[0] == '#' || isspace(line[0])) continue;
        if (line[0] == '%') {
            read = sscanf(line, "%% %" SCNu32 "\n", &num_rec);
            if (UNLIKELY(read != 1)) {
                T2_PERR("gsmDecode", "expected leading '%%' followed by number of rows, found '%s'", line);
                free(line);
                fclose(file);
                exit(EXIT_FAILURE);
            }
            break;
        }
    }

    gsm_tac_list_t tac_list = { .size = num_rec };
    tac_list.item = t2_calloc_fatal(num_rec, sizeof(gsm_tac_t));

    uint32_t count = 0;
    while ((read = getline(&line, &len, file)) != -1) {
        // skip comments and empty lines
        if (line[0] == '\n' || line[0] == '#' || line[0] == '%' || isspace(line[0])) continue;

        if (count < num_rec) {
            read = sscanf(line, "%" SCNu32 "\t%[^\t]\t%[^\t]\t", &tac_list.item[count].tac, tac_list.item[count].manuf, tac_list.item[count].model);
            if (UNLIKELY(read != 3)) {
                T2_PWRN("gsmDecode", "failed to parse line '%s' from '%s'", line, filename);
                tac_list.item[count].tac = 0;
                tac_list.item[count].manuf[0] = '\0';
                tac_list.item[count].model[0] = '\0';
                continue;
            }
        }

        count++;
    }

    free(line);
    fclose(file);

    if (count < num_rec) {
        T2_PWRN("gsmDecode", "Read %" PRIu32 " records, expected %" PRIu32, count, num_rec);
        tac_list.size = count;
    } else if (count > num_rec) {
        T2_PWRN("gsmDecode", "Read %" PRIu32 " records out of %" PRIu32, num_rec, count);
    }

    return tac_list;
}


const gsm_tac_t *gsm_tac_list_lookup(gsm_tac_list_t *list, uint32_t tac) {
    int start = 0;
    int end = list->size - 1;

    while (start <= end) {
        const int middle = (end + start) / 2;
        if (tac == list->item[middle].tac) return &list->item[middle];
        else if (tac < list->item[middle].tac) end = middle - 1;
        else start = middle + 1;
    }

    return NULL;
}


void gsm_tac_list_free(gsm_tac_list_t *list) {
    if (UNLIKELY(!list)) return;
    free(list->item);
    list->item = NULL;
    list->size = 0;
}
