/*
 * sslBlist.c
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

#include "sslBlist.h"
#include "t2utils.h"

#include <ctype.h>


ssl_blist_t *ssl_blist_load(const char *plugin, const char *filename, size_t hash_len, size_t desc_len) {
    FILE *file = t2_fopen(filename, "r");
    if (UNLIKELY(!file)) exit(EXIT_FAILURE);

    ssl_blist_t *sslbl = t2_calloc_fatal(1, sizeof(*sslbl));

    sslbl->hash_len = hash_len;
    sslbl->desc_len = desc_len;

    char *line = NULL;
    size_t len = 0;

    ssize_t read = getline(&line, &len, file);
    if (UNLIKELY(read == -1)) {
        T2_PERR(plugin, "failed to read first line from '%s'", filename);
        ssl_blist_free(sslbl);
        fclose(file);
        exit(EXIT_FAILURE);
    }

    // read number of rows
    read = sscanf(line, "%% %" SCNu32 "\n", &sslbl->count);
    if (UNLIKELY(read != 1)) {
        T2_PERR(plugin, "expected leading '%%' followed by number of rows, found '%s'", line);
        ssl_blist_free(sslbl);
        free(line);
        fclose(file);
        exit(EXIT_FAILURE);
    }

    sslbl->hash = t2_malloc_fatal(hash_len * sslbl->count + 1);
    sslbl->desc = t2_malloc_fatal(desc_len * sslbl->count + 1);

    char format[64];
    snprintf(format, sizeof(format), "%%%zu[0-9a-zA-Z_,]\t%%%zu[^\t\n]",
            hash_len, desc_len);

    uint32_t d = 0, h = 0;
    uint32_t count = 0;
    while ((read = getline(&line, &len, file)) != -1) {
        // skip comments and empty lines
        if (line[0] == '\n' || line[0] == '#' || isspace(line[0])) continue;

        if (count < sslbl->count) {
            read = sscanf(line, format, &sslbl->hash[h], &sslbl->desc[d]);
            if (UNLIKELY(read != 2)) {
                T2_PWRN(plugin, "failed to parse line '%s' from '%s'", line, filename);
                sslbl->hash[h] = '\0';
                sslbl->desc[d] = '\0';
                continue;
            }
            h += hash_len;
            d += desc_len;
            sslbl->desc[d-1] = '\0';
        }

        count++;
    }

    sslbl->hash[h] = '\0';

    free(line);
    fclose(file);

    if (count < sslbl->count) {
        T2_PWRN(plugin, "Read %" PRIu32 " fingerprints, expected %" PRIu32, count, sslbl->count);
        sslbl->count = count;
    } else if (count > sslbl->count) {
        T2_PWRN(plugin, "Read %" PRIu32 " fingerprints out of %" PRIu32, sslbl->count, count);
    }

    return sslbl;
}


const char *ssl_blist_lookup(const ssl_blist_t * const sslbl, const char *hash) {
    int start = 0;
    int end = sslbl->count - 1;

    while (start <= end) {
        const int middle = (end + start) / 2;
        const int cmp = memcmp(hash, SSL_BLIST_HASH(sslbl, middle), sslbl->hash_len);
        if (cmp == 0) return SSL_BLIST_DESC(sslbl, middle);
        else if (cmp < 0) end = middle - 1;
        else start = middle + 1;
    }

    return NULL;
}


void ssl_blist_free(ssl_blist_t *sslbl) {
    if (UNLIKELY(!sslbl)) return;

    free(sslbl->hash);
    free(sslbl->desc);
    free(sslbl);
}
