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

#include "regfile_pcre.h"

#include <errno.h>  // for errno
#include <stdio.h>  // for FILE


// Static variables
static const char * const plugin_name = "regex_pcre";


bool rex_load(const char *filename, rex_table_t *preg_table) {

    FILE *file;
    if (UNLIKELY(!(file = fopen(filename, "r")))) {
        T2_PERR(plugin_name, "failed to open file '%s' for reading: %s", filename, strerror(errno));
        preg_table->count = 0;
        return false;
    }

    uint32_t pcount = 1;

    ssize_t read;
    size_t len = 0;
    char *line = NULL;
    while ((read = getline(&line, &len, file)) != -1) {
        if (line[0] == '#' || line[0] == '\n' || line[0] == ' ') continue;
        pcount++;
    }

    preg_table->count = pcount;

    preg_table->compRex = t2_malloc_fatal(pcount * sizeof(pcre*));
#if RULE_OPTIMIZE == 1
    preg_table->studyRex = t2_malloc_fatal(pcount * sizeof(pcre_extra*));
#endif

    uint32_t i, j, k;
    preg_table->id = t2_malloc_fatal(pcount * sizeof(uint16_t));
    preg_table->flags = t2_malloc_fatal(pcount * sizeof(uint16_t));
    preg_table->offset = t2_malloc_fatal(pcount * sizeof(uint16_t));

    for (i = 0; i < PREIDMX; i++) preg_table->preID[i] = t2_malloc_fatal(pcount * sizeof(uint16_t));
    for (i = 0; i < HDRSELMX; i++) preg_table->hdrSel[i] = t2_malloc_fatal(pcount * sizeof(uint32_t));

    preg_table->alarmcl = t2_malloc_fatal(pcount * sizeof(uint8_t));
    preg_table->severity = t2_malloc_fatal(pcount * sizeof(uint8_t));

    uint8_t flags, alarmcl, severity;
    uint16_t id, pID[PREIDMX]={}, proto, srcPort, dstPort, offset;
    uint32_t hdrSel, flowstat, regexmd;
    int z, erroffset;
    char *s, *wurst, preID[BUFPREIDMX], regex[BUFREGMAX];

    i = 1;
    rewind(file);

    uint32_t lineno = 0;
    while ((read = getline(&line, &len, file)) != -1) {
        lineno++;

        if (line[0] == '#' || line[0] == '\n' || line[0] == ' ') continue;

        z = sscanf(line, "%" SCNu16 "\t%[^\t]\t0x%" SCNx8 "\t%" SCNu8 "\t"            // id, preID, flags, classID
                         "%" SCNu8 "\t0x%" SCNx32 "\t0x%" SCNx32 "\t0x%" SCNx32 "\t"  // severity, hdrSel, regexmd, flowstat
                         "%" SCNu16 "\t%" SCNu16 "\t%" SCNu16 "\t%" SCNu16 "\t"       // proto, srcPort, dstPort, offset
                         "%[^\n\t]",                                                  // regex
                         &id, preID, &flags, &alarmcl,
                         &severity, &hdrSel, &regexmd, &flowstat,
                         &proto, &srcPort, &dstPort, &offset,
                         regex);

        if (UNLIKELY(z == 0)) {
            T2_PERR(plugin_name, "Failed to parse record at line %" PRIu32 ": %s", lineno, regex);
            exit(EXIT_FAILURE);
        }

        k = 0;
        wurst = preID;
        while ((s = strtok_r(wurst, ",", &wurst)) && k < PREIDMX) pID[k++] = atoi(s);

        if (!(hdrSel & PCREMDMSK)) regexmd = REGEX_MODE;

        const char *errPtr = NULL;
        if (!(preg_table->compRex[i] = pcre_compile(regex, regexmd, &errPtr, &erroffset, NULL))) {
#if VERBOSE > 0
            T2_PWRN(plugin_name, "PCRE ignored - # %u, ID %" PRIu16 ", @ %d: %s", i, id, erroffset, errPtr);
#endif
            continue;
        }

#if RULE_OPTIMIZE == 1
        preg_table->studyRex[i] = pcre_study(preg_table->compRex[i], 0, &errPtr);
        if (errPtr != NULL) {
#if VERBOSE > 0
            T2_PWRN(plugin_name, "study rule ignored: # %u, @ %" PRIu16 ": %s", i, id, errPtr);
#endif
            continue;
        }
#endif // RULE_OPTIMIZE == 1

        preg_table->id[i] = id;
        for (j = 0; j < k; j++) preg_table->preID[j][i] = pID[j];
        preg_table->hdrSel[0][i] = flowstat;
        preg_table->hdrSel[1][i] = proto;
        preg_table->hdrSel[2][i] = srcPort;
        preg_table->hdrSel[3][i] = dstPort;
        preg_table->hdrSel[4][i] = hdrSel;
        preg_table->offset[i] = offset;
        preg_table->flags[i] = flags;
        preg_table->alarmcl[i] = alarmcl;
        preg_table->severity[i] = severity;

        //printf("%d\t%" PRIu16 "\t%s\t0x%02" B2T_PRIX8 "\t%" PRIu8 "\t%02" PRIu8 "\t0x%08" B2T_PRIX32 "\t0x%08" B2T_PRIX32 "\t0x%08" B2T_PRIX32 "\t%" PRIu16 "\t%" PRIu16 "\t%" PRIu16 "\t%" PRIu16 "\t%s\n",
        //  i, id, preID, flags, alarmcl, severity, hdrSel, regexmd, flowstat, proto, srcPort, dstPort, offset, regex);

        i++;
    }

    free(line);
    fclose(file);

    preg_table->count = i-1;

#if VERBOSE > 0
    T2_PINF(plugin_name, "%" PRIu32 " regexes loaded", i-1);
#endif

    if (i < pcount) {
#if VERBOSE > 0
        T2_PWRN(plugin_name, "%" PRIu32 " rules have no predecessor", pcount-i);
#endif
        return false;
    }

    return true;
}
