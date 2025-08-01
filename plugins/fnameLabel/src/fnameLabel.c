/*
 * fnameLabel.c
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

#include "fnameLabel.h"
#include "t2Plugin.h"

#if FNL_LBL == 1
#include <ctype.h> // for isdigit
#endif


// plugin variables

fnFlow_t *fnFlows;


// Tranalyzer functions

T2_PLUGIN_INIT("fnameLabel", "0.9.3", 0, 9);


void t2Init() {
    T2_PLUGIN_STRUCT_NEW(fnFlows);

#if FNL_LBL == 1 || FNL_HASH == 1 || FNL_FLNM == 1
    if (sPktFile) {
#if FNL_LBL == 1
        fputs("fnLabel" SEP_CHR, sPktFile);
#endif
#if FNL_HASH == 1
        fputs("fnHash" SEP_CHR, sPktFile);
#endif
#if FNL_FLNM == 1
        fputs("fnName" SEP_CHR, sPktFile);
#endif
    }
#endif // FNL_LBL == 1 || FNL_HASH == 1 || FNL_FLNM == 1
}


#if FNL_LBL == 1 || FNL_HASH == 1 || FNL_FLNM == 1

binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;

#if FNL_LBL == 1
    BV_APPEND_U32(bv, "fnLabel", "FNL_IDX letter of filename");
#endif
#if FNL_HASH == 1
    BV_APPEND_U64(bv, "fnHash", "Hash of filename");
#endif
#if FNL_FLNM == 1
    BV_APPEND_STR(bv, "fnName", "Filename");
#endif
    return bv;
}

#endif // FNL_LBL == 1 || FNL_HASH == 1 || FNL_FLNM == 1


void t2OnNewFlow(packet_t* packet UNUSED, unsigned long flowIndex) {
    fnFlow_t * const fnFlowP = &fnFlows[flowIndex];

    const char *name;
#if FNL_FREL == 1
    const char *relname;
#endif

    if (capType & DIRFILE) {
        name = globFName;
#if FNL_FREL == 1
        FN_RELNAME(relname, name);
#endif
#if FNL_LBL == 1
        fnFlowP->label = fileNum;
#endif
    } else { // !(capType & DIRFILE)
        name = (capType & LISTFILE) ? caplist_elem->name : capName;
#if FNL_FREL == 1
        FN_RELNAME(relname, name);
#endif
#if FNL_LBL == 1
#if FNL_FREL == 1
        const char * const lname = relname;
#else
        const char * const lname = name;
#endif
        if (lname && FNL_IDX < strlen(lname)) {
            // use the 'FNL_IDX' letter of the filename as label
            // (but keep numbers as numbers, e.g., eth1 -> 1 and not 49)
            if (isdigit(lname[FNL_IDX])) {
                fnFlowP->label = atoi(&lname[FNL_IDX]);
            } else {
                fnFlowP->label = lname[FNL_IDX];
            }
        }
#endif
    } // !(capType & DIRFILE)

#if FNL_FREL == 1
    name = relname;
#endif

    t2_strcpy(fnFlowP->capname, name, sizeof(fnFlowP->capname), T2_STRCPY_TRUNC);

#if FNL_HASH == 1
    const size_t len = strlen(name);
    fnFlowP->hash = hashTable_hash(name, len);
#endif
}


#if FNL_LBL == 1 || FNL_HASH == 1 || FNL_FLNM == 1

static inline void claimInfo(packet_t *packet UNUSED, unsigned long flowIndex) {
    if (!sPktFile) return;

    const fnFlow_t * const fnFlowP = &fnFlows[flowIndex];

#if FNL_LBL == 1
    fprintf(sPktFile, "%" PRIu32 /* fnLabel */ SEP_CHR, fnFlowP->label);
#endif

#if FNL_HASH == 1
    fprintf(sPktFile, "%" PRIu64 /* fnHash */ SEP_CHR, fnFlowP->hash);
#endif

#if FNL_FLNM == 1
    fprintf(sPktFile, "%s" /* fnName */ SEP_CHR, fnFlowP->capname);
#endif
}


#if ETH_ACTIVATE > 0
void t2OnLayer2(packet_t *packet UNUSED, unsigned long flowIndex) {
    if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;
    claimInfo(packet, flowIndex);
}
#endif // ETH_ACTIVATE > 0


void t2OnLayer4(packet_t *packet UNUSED, unsigned long flowIndex) {
    claimInfo(packet, flowIndex);
}


void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {
    const fnFlow_t * const fnFlowP = &fnFlows[flowIndex];

#if FNL_LBL == 1
    OUTBUF_APPEND_U32(buf, fnFlowP->label);
#endif

#if FNL_HASH == 1
    OUTBUF_APPEND_U64(buf, fnFlowP->hash);
#endif

#if FNL_FLNM == 1
    const char * const capname = fnFlowP->capname;
    OUTBUF_APPEND_STR(buf, capname);
#endif
}

#endif // FNL_LBL == 1 || FNL_HASH == 1 || FNL_FLNM == 1


void t2Finalize() {
    free(fnFlows);
}
