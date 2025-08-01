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

//TODO: L7Range checks

#include "syslogDecode.h"


// Global variables

syslogFlow_t *syslogFlow;


// Static variables

static uint64_t numSyslogPkt;
static uint64_t numSysMsgCnt;
static uint8_t syslogStat;


#define SYSLOG_SPKT_PRI_NONE() \
    if (sPktFile) { \
        fputs("0x00" /* syslogStat */ SEP_CHR \
                     /* syslogSev  */ SEP_CHR \
                     /* syslogFac  */ SEP_CHR \
              , sPktFile); \
    }


// Tranalyzer functions

T2_PLUGIN_INIT("syslogDecode", "0.9.3", 0, 9);


void t2Init() {
    T2_PLUGIN_STRUCT_NEW(syslogFlow);

    if (sPktFile) {
        fputs("syslogStat" SEP_CHR
              "syslogSev"  SEP_CHR
              "syslogFac"  SEP_CHR
              , sPktFile);
    }
}


binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;

    BV_APPEND_H8(bv,  "syslogStat", "Syslog status");
    BV_APPEND_U32(bv, "syslogMCnt", "Syslog message count");
#if SYSL_FSN > 0
    BV_APPEND_R(bv, "syslogSev_Fac_Cnt", "Syslog number of severity/facility messages", 3, bt_string_class, bt_string_class, bt_uint_16);
#else // SYSL_FSN == 0
    BV_APPEND_R(bv, "syslogSev_Fac_Cnt", "Syslog number of severity/facility messages", 3, bt_uint_8, bt_uint_8, bt_uint_16);
#endif // SYSL_FSN

    return bv;
}


void t2OnNewFlow(packet_t *packet UNUSED, unsigned long flowIndex) {
    syslogFlow_t * const sysFlowP = &syslogFlow[flowIndex];
    memset(sysFlowP, '\0', sizeof(syslogFlow_t));

    if (flows[flowIndex].dstPort == SYSLOG_PORT) {
        sysFlowP->syslogStat |= SYS_DET;
    }
}


#if ETH_ACTIVATE > 0
void t2OnLayer2(packet_t *packet UNUSED, unsigned long flowIndex) {
    if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;

    // This packet does not have a layer 4.
    // Print tabs to keep the packet file aligned
    SYSLOG_SPKT_PRI_NONE();
}
#endif // ETH_ACTIVATE > 0


void t2OnLayer4(packet_t *packet, unsigned long flowIndex) {
    syslogFlow_t * const sysFlowP = &syslogFlow[flowIndex];
    if (!sysFlowP->syslogStat) {
        SYSLOG_SPKT_PRI_NONE();
        return;
    }

    const unsigned char * const l7P = (unsigned char*)packet->l7HdrP;
    const uint32_t plen = packet->snapL7Len;
    if (plen < 10) {
        SYSLOG_SPKT_PRI_NONE();
        return;
    }

    char *p = memchr(l7P, '<', 2);
    if (p == NULL) {
        sysFlowP->syslogStat = 0x00;
        SYSLOG_SPKT_PRI_NONE();
        return;
    }

    uint32_t i = atoi(++p);
    const uint8_t sev = i & 0x07;
    const uint8_t fac = i >> 3;
    //plen -= (p - l7P);

    if (sev >= SYS_NUM_SEV || fac >= SYS_NUM_FAC) {
        sysFlowP->syslogStat = 0x00;
        SYSLOG_SPKT_PRI_NONE();
        return;
    }

    if (sysFlowP->cnt[sev][fac] < UINT16_MAX) {
        if (sysFlowP->cnt[sev][fac]++ == 0) sysFlowP->sum++;
    } else sysFlowP->syslogStat |= SYS_CNTOVRN;

    p = memchr(p, '>', 4);
    if (p == NULL) {
        sysFlowP->syslogStat = 0x00;
        SYSLOG_SPKT_PRI_NONE();
        return;
    }

    i = atoi(++p);
    if (i) {
        p = memchr(p, ' ', 12);
        if (!p) {
            sysFlowP->syslogStat = 0x00;
            SYSLOG_SPKT_PRI_NONE();
            return;
        }
    }

    if (memchr(p + 14, ' ', 6) == NULL) {
        sysFlowP->syslogStat = 0x00;
        SYSLOG_SPKT_PRI_NONE();
        return;
    }

    numSyslogPkt++;

    if (sPktFile) {
#if SYSL_FSN > 0
        fprintf(sPktFile,
                "0x%02" B2T_PRIX8 /* syslogStat */ SEP_CHR
                "%s"              /* syslogSev  */ SEP_CHR
                "%s"              /* syslogFac  */ SEP_CHR
                , sysFlowP->syslogStat, sevType[sev], facType[fac]);
#else // SYSL_FSN == 0
        fprintf(sPktFile,
                "0x%02" B2T_PRIX8 /* syslogStat */ SEP_CHR
                "%"     PRIu8     /* syslogSev  */ SEP_CHR
                "%"     PRIu8     /* syslogFac  */ SEP_CHR
                , sysFlowP->syslogStat, sev, fac);
#endif // SYSL_FSN
    }
}


void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {
    syslogFlow_t * const sysFlowP = &syslogFlow[flowIndex];

    if (!sysFlowP->syslogStat) {
        sysFlowP->sum = 0;
    } else {
        numSysMsgCnt += sysFlowP->sum;
        syslogStat |= sysFlowP->syslogStat;
    }

    // syslogStat
    OUTBUF_APPEND_U8(buf, sysFlowP->syslogStat);

    // syslogMCnt
    OUTBUF_APPEND_U32(buf, sysFlowP->sum);

    // syslogSev_Fac_Cnt
    OUTBUF_APPEND_NUMREP(buf, sysFlowP->sum);
    if (sysFlowP->sum) {
        for (uint8_t i = 0 ; i < SYS_NUM_SEV; i++) {
            for (uint8_t j = 0 ; j < SYS_NUM_FAC; j++) {
                if (sysFlowP->cnt[i][j]) {
#if SYSL_FSN > 0
                    OUTBUF_APPEND_STR(buf, sevType[i]);
                    OUTBUF_APPEND_STR(buf, facType[j]);
#else // SYSL_FSN == 0
                    OUTBUF_APPEND_U8(buf, i);
                    OUTBUF_APPEND_U8(buf, j);
#endif // SYSL_FSN
                    OUTBUF_APPEND_U16(buf, sysFlowP->cnt[i][j]);
                }
            }
        }
    }
}


void t2PluginReport(FILE *stream) {
    T2_FPLOG_AGGR_HEX(stream, plugin_name, syslogStat);
    T2_FPLOG_NUMP(stream, plugin_name, "Number of Syslog packets", numSyslogPkt, numPackets);
    T2_FPLOG_NUM(stream, plugin_name, "Number of Syslog message types", numSysMsgCnt);
}


void t2Finalize() {
    free(syslogFlow);
}
