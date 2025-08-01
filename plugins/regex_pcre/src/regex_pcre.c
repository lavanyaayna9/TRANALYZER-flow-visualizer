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

#include "regex_pcre.h"

#include <string.h>  // for memcpy, memset


// Static variables

static rex_table_t *rex_tableP;
static uint64_t pcreAlarms, pcreAlarmFlows;
static uint32_t sevmax;


// function prototypes
void tree_reset(uint32_t preID);

#define RGXP_SPKTMD_PRI_NONE() \
    if (sPktFile) { \
        fputs("0" /* rgxCnt           */ SEP_CHR \
                  /* rgxRID_cType_sev */ SEP_CHR \
              , sPktFile); \
    }


// Tranalyzer functions

T2_PLUGIN_INIT("regex_pcre", "0.9.3", 0, 9);


void t2Init() {
    T2_PLUGIN_STRUCT_NEW(rexFlow);

#if ENVCNTRL > 0
    t2_env_t env[ENV_RGX_N] = {};
    t2_get_env(PLUGIN_SRCH, ENV_RGX_N, env);
    const char * const rgxPsFl = T2_ENV_VAL(RGX_POSIX_FILE);
#else // ENVCNTRL == 0
    const char * const rgxPsFl = RGX_POSIX_FILE;
#endif // ENVCNTRL

    if (sPktFile) {
        fputs("rgxCnt"           SEP_CHR
              "rgxRID_cType_sev" SEP_CHR
              , sPktFile);
    }

    const size_t plen = pluginFolder_len;
    const size_t rgxPsFlLen = strlen(rgxPsFl)+1;
    const size_t len = plen + rgxPsFlLen;
    if (UNLIKELY(len > MAX_FILENAME_LEN)) {
        T2_PFATAL(plugin_name, "Filename to regex file is too long");
    }

    char filename[len];
    memcpy(filename, pluginFolder, plen);
    memcpy(filename + plen, rgxPsFl, rgxPsFlLen);

    rex_tableP = t2_malloc_fatal(sizeof(*rex_tableP));

    if (UNLIKELY(!rex_load(filename, rex_tableP))) {
        free(rexFlow);
        exit(EXIT_FAILURE);
    }

#if ENVCNTRL > 0
    t2_free_env(ENV_RGX_N, env);
#endif // ENVCNTRL > 0
}


binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;

    BV_APPEND_U16(bv, "rgxCnt", "Regex match count");

#if EXPERTMODE == 1
#if PKTTIME == 1
    BV_APPEND_R(bv, "rgxRID_cType_sev_pktN_bPos_time", "Regex ID, class type, severity, time, packet number, byte position and time", 6, bt_uint_16, bt_uint_8, bt_uint_8, bt_uint_32, bt_uint_16, bt_timestamp);
#else // PKTTIME == 0
    BV_APPEND_R(bv, "rgxRID_cType_sev_pktN_bPos", "Regex ID, class type, severity, packet number and byte position", 5, bt_uint_16, bt_uint_8, bt_uint_8, bt_uint_32, bt_uint_16);
#endif // PKTTIME
#else // EXPERTMODE == 0
    BV_APPEND_R(bv, "rgxRID_cType_sev", "Regex ID, class type and severity", 3, bt_uint_16, bt_uint_8, bt_uint_8);
#endif // EXPERTMODE

    return bv;
}


void t2OnNewFlow(packet_t* packet UNUSED, unsigned long flowIndex) {
    rexFlow_t * const rexFlowP = &rexFlow[flowIndex];
    memset(rexFlowP, '\0', sizeof(rexFlow_t));
}


#if ETH_ACTIVATE > 0
void t2OnLayer2(packet_t *packet UNUSED, unsigned long flowIndex) {
    if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;
    RGXP_SPKTMD_PRI_NONE();
}
#endif // ETH_ACTIVATE > 0


void t2OnLayer4(packet_t* packet, unsigned long flowIndex) {
    rexFlow_t * const rexFlowP = &rexFlow[flowIndex];

    unsigned int count = rexFlowP->count;
    int32_t length = packet->snapL7Len;
    if (count >= MAXREGPOS || length == 0) {
        RGXP_SPKTMD_PRI_NONE();
        return;
    }

#if EXPERTMODE == 1
    rexFlowP->pktN++;
#endif // EXPERTMODE == 1

    flow_t *flowP = &flows[flowIndex];
    const uint32_t hdrSel[HDRSELMX] = {
        (uint32_t)(flowP->status),
        flowP->l4Proto,
        flowP->srcPort,
        flowP->dstPort,
    };

    // match all loaded patterns
    unsigned int alrmPCnt = 0, j, k, l;
    uint16_t alrmP[MAXREGPOS];
    char *regstart = (char*)packet->l7HdrP;
    for (uint_fast32_t i = 1; i <= rex_tableP->count; i++) {
        l = rex_tableP->hdrSel[HDRSELMX-1][i] & SEL_F_P;
        if (l) {
            k = HDRSELMSK;
            if ((l & k) && (hdrSel[0] & rex_tableP->hdrSel[0][i]) != rex_tableP->hdrSel[0][i]) goto nxtrex;
            for (j = 1; j < HDRSELMX-1; j++) {
                k >>= 1;
                if ((l & k) && (hdrSel[j] != rex_tableP->hdrSel[j][i])) goto nxtrex;
            }
        }

        switch (rex_tableP->hdrSel[HDRSELMX-1][i] & SEL_F_L) {
            case SEL_F_L2:
                regstart = (char*)packet->l2HdrP + rex_tableP->offset[i];
                length = packet->snapL2Len - rex_tableP->offset[i];
                break;
            case SEL_F_L3:
                regstart = (char*)packet->l3HdrP + rex_tableP->offset[i];
                length = packet->snapL3Len - rex_tableP->offset[i];
                break;
            case SEL_F_L4:
                regstart = (char*)packet->l4HdrP + rex_tableP->offset[i];
                length = packet->snapL4Len - rex_tableP->offset[i];
                break;
            case SEL_F_L7:
                regstart = (char*)packet->l7HdrP + rex_tableP->offset[i];
                length = packet->snapL7Len - rex_tableP->offset[i];
                break;
            default:
                goto nxtrex;
                break;
        }

        if (length <= 0) goto nxtrex;

        int ovector[OVECCOUNT];
#if RULE_OPTIMIZE == 1
        pcre_extra *extra = rex_tableP->studyRex[i];
#else // RULE_OPTIMIZE == 0
        pcre_extra *extra = NULL;
#endif // RULE_OPTIMIZE

        if (pcre_exec(rex_tableP->compRex[i], extra, regstart, length, 0, 0, ovector, OVECCOUNT) < 0) continue;
        if (ovector[1] <= ovector[0]) continue;

        uint32_t s = 0;
        switch (rex_tableP->flags[i] & REG_F_OP) {
            case REG_F_NON:
                break;

            case REG_F_AND:
                for (j = 0; rex_tableP->preID[j][i] && j < PREIDMX; j++) {
                    if (!(rex_tableP->flags[rex_tableP->preID[j][i]] & REG_F_MTCH)) goto nxtrex;  // and
                }
                break;

            case REG_F_OR:
                for (j = 0; rex_tableP->preID[j][i] && j < PREIDMX; j++) {
                    if (rex_tableP->flags[rex_tableP->preID[j][i]] & REG_F_MTCH) goto prematsch;  // or
                }
                continue;

            case REG_F_XOR:
                for (j = 0; rex_tableP->preID[j][i] && j < PREIDMX; j++) {
                    s += rex_tableP->flags[rex_tableP->preID[j][i]] & REG_F_MTCH;  // xor
                    if (s > 2) goto nxtrex;
                }
                break;

            default:
                continue;
        }

prematsch:
#if AGGR == 1
        for (l = 0; l < count; l++) {
            if (rexFlowP->id[l] == i) goto nxtrex;
        }
#endif // AGGR == 1

        l = count;

        if ((rex_tableP->flags[i] & REG_F_RLF) == REG_F_RLF) {
            rex_tableP->flags[i] &= ~REG_F_MTCH;
            for (j = 0; rex_tableP->preID[j][i] && j < PREIDMX ; j++) {
                tree_reset(rex_tableP->preID[j][i]);
            }
        } else {
            rex_tableP->flags[i] |= REG_F_MTCH;
        }

        rexFlowP->id[l] = i;
        rexFlowP->flags[l] = rex_tableP->flags[i];
#if EXPERTMODE == 1
#if PKTTIME == 1
        rexFlowP->time[l] = flowP->lastSeen;
#endif
        rexFlowP->pkt[l] = rexFlowP->pktN;
        rexFlowP->pregPos[l] = ovector[0];
#endif // EXPERTMODE == 1

#if SALRMFLG == 1
        T2_SET_STATUS(flowP, FL_ALARM);
#endif // SALRMFLG == 1

        //if (sPktFile && alrmPCnt < MAXREGPOS && (rexFlowP->flags[l] & REG_F_MTCH)) alrmP[alrmPCnt++] = i;
        if (sPktFile && alrmPCnt < MAXREGPOS) alrmP[alrmPCnt++] = i;

        if (++count >= MAXREGPOS) break;

nxtrex:
        continue;
    }

    if (sPktFile) {
        fprintf(sPktFile, "%d" /* rgxCnt */ SEP_CHR, alrmPCnt);
        for (uint_fast32_t i = 0; i < alrmPCnt; i++) {
            if (i) fputc(';', sPktFile);
            const uint16_t alp = alrmP[i];
            fprintf(sPktFile, "%" PRIu16 "_%" PRIu8 "_%" PRIu8, rex_tableP->id[alp], rex_tableP->alarmcl[alp], rex_tableP->severity[alp]);
        }
        fputs(SEP_CHR, sPktFile);
    }

    rexFlowP->count = count;
}


void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {
    rexFlow_t * const rexFlowP = &rexFlow[flowIndex];

    const uint16_t rgxCnt = rexFlowP->count;
    uint_fast32_t j;

    uint32_t alarms = 0;
    for (uint_fast32_t i = 0; i < rgxCnt; i++) {
        if (rexFlowP->flags[i] & REG_F_PALRM) alarms++;
        j = rex_tableP->severity[rexFlowP->id[i]];
        if (j > sevmax) sevmax = j;
    }

    if (alarms) {
        pcreAlarms += alarms;
        pcreAlarmFlows++;
        T2_REPORT_ALARMS(alarms);
    }

    OUTBUF_APPEND_U16(buf, alarms);

    OUTBUF_APPEND_NUMREP(buf, alarms);
    for (uint_fast32_t i = 0; i < rgxCnt; i++) {
        if (rexFlowP->flags[i] & REG_F_PALRM) {
            j = rexFlowP->id[i];
            OUTBUF_APPEND_U16(buf, rex_tableP->id[j]);
            OUTBUF_APPEND_U8(buf, rex_tableP->alarmcl[j]);
            OUTBUF_APPEND_U8(buf, rex_tableP->severity[j]);
#if EXPERTMODE == 1
            OUTBUF_APPEND_U32(buf, rexFlowP->pkt[i]);
            OUTBUF_APPEND_U16(buf, rexFlowP->pregPos[i]);
#if PKTTIME == 1
            const uint64_t secs = rexFlowP->time[i].tv_sec;
            const uint32_t usecs = rexFlowP->time[i].tv_usec;
            OUTBUF_APPEND_TIME(buf, secs, usecs);
#endif // PKTTIME == 1
#endif // EXPERTMODE == 1
        }
    }
}


void t2PluginReport(FILE *stream) {
    if (pcreAlarms) {
        char hrnum1[64], hrnum2[64];
        T2_CONV_NUM(pcreAlarms, hrnum1);
        T2_CONV_NUM(pcreAlarmFlows, hrnum2);
        T2_FPWRN_NP(stream, plugin_name,
                    "%" PRIu64 "%s alarms in %" PRIu64 "%s flows [%.2f%%] with max severity %" PRIu32,
                    pcreAlarms, hrnum1, pcreAlarmFlows, hrnum2, 100.0 * ((float)pcreAlarmFlows / (float)totalFlows), sevmax);
    }
}


void t2Finalize() {
    free(rexFlow);

    if (UNLIKELY(!rex_tableP)) return;

    free(rex_tableP->id);
    free(rex_tableP->flags);
    free(rex_tableP->offset);

    uint_fast32_t i;
    for (i = 0; i < PREIDMX; i++) free(rex_tableP->preID[i]);
    for (i = 0; i < HDRSELMX; i++) free(rex_tableP->hdrSel[i]);

    free(rex_tableP->alarmcl);
    free(rex_tableP->severity);

    for (i = 1; i <= rex_tableP->count; i++) {
        pcre_free(rex_tableP->compRex[i]);
#if RULE_OPTIMIZE == 1
        pcre_free_study(rex_tableP->studyRex[i]);
#endif
    }

    free(rex_tableP->compRex);
#if RULE_OPTIMIZE == 1
    free(rex_tableP->studyRex);
#endif

    free(rex_tableP);
}


void tree_reset(uint32_t preID) {
    for (uint_fast32_t j = 0, s; (s = rex_tableP->preID[j][preID]) && j < PREIDMX; j++) {
        if (rex_tableP->flags[s] & REG_F_RMT) {
            rex_tableP->flags[s] &= ~REG_F_MTCH;
            tree_reset(s);
        }
    }
}
