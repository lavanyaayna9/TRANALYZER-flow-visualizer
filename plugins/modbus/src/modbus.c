/*
 * modbus.c
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

#include "modbus.h"


// Global variables

modbus_flow_t *modbus_flows;


// Static variables

static uint16_t modbusStat;
static uint64_t num_mb_pkts, num_mb_pkts0;


#define MB_SPKTMD_PRI_NONE() \
    if (sPktFile) { \
        fputs(/* mbTranId   */ SEP_CHR \
              /* mbProtId   */ SEP_CHR \
              /* mbLen      */ SEP_CHR \
              /* mbUnitId   */ SEP_CHR \
              /* mbFuncCode */ SEP_CHR \
              , sPktFile); \
    }


// Tranalyzer functions

T2_PLUGIN_INIT("modbus", "0.9.3", 0, 9);


void t2Init() {
    T2_PLUGIN_STRUCT_NEW(modbus_flows);

    if (sPktFile) {
        fputs("mbTranId"   SEP_CHR
              "mbProtId"   SEP_CHR
              "mbLen"      SEP_CHR
              "mbUnitId"   SEP_CHR
              "mbFuncCode" SEP_CHR
              , sPktFile);
    }
}


binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;

    BV_APPEND_H16(bv, "modbusStat" , "Modbus status");
    BV_APPEND_U8(bv , "modbusUID"  , "Modbus unit identifier");
    BV_APPEND_U32(bv, "modbusNPkts", "Modbus number of packets");
    BV_APPEND_U16(bv, "modbusNumEx", "Modbus number of exceptions");
    BV_APPEND_H64(bv, "modbusFCBF" , "Modbus aggregated function codes");
#if MB_NUM_FUNC > 0
    BV_APPEND_R(bv  , "modbusFC"   , "Modbus list of function codes", 1, MB_FE_TYP);
#endif // MB_NUM_FUNC > 0
    BV_APPEND_H64(bv, "modbusFExBF", "Modbus aggregated function codes which caused exceptions");
#if MB_NUM_FEX > 0
    BV_APPEND_R(bv  , "modbusFEx"  , "Modbus list of function codes which caused exceptions", 1, MB_FE_TYP);
#endif // MB_NUM_FEX > 0
    BV_APPEND_H16(bv, "modbusExCBF", "Modbus aggregated exception codes");
#if MB_NUM_EX > 0
    BV_APPEND_R(bv  , "modbusExC"  , "Modbus list of exception codes", 1, MB_FE_TYP);
#endif // MB_NUM_EX > 0

    return bv;
}


void t2OnNewFlow(packet_t* packet UNUSED, unsigned long flowIndex) {
    modbus_flow_t *mbFlowP = &modbus_flows[flowIndex];
    memset(mbFlowP, '\0', sizeof(*mbFlowP)); // set everything to 0

    const flow_t * const flowP = &flows[flowIndex];
    if (flowP->status & L2_FLOW) return; // Layer 2 flow. No L3/4 pointers, so return

    if (flowP->l4Proto == L3_TCP && (flowP->srcPort == MODBUS_PORT || flowP->dstPort == MODBUS_PORT))
        mbFlowP->stat |= MB_STAT_MODBUS;
}


#if ETH_ACTIVATE > 0
void t2OnLayer2(packet_t* packet UNUSED, unsigned long flowIndex) {
    if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;
    MB_SPKTMD_PRI_NONE();
}
#endif // ETH_ACTIVATE > 0


void t2OnLayer4(packet_t* packet, unsigned long flowIndex) {
    modbus_flow_t *mbFlowP = &modbus_flows[flowIndex];
    if (!mbFlowP->stat) {
        // not a modbus packet
        MB_SPKTMD_PRI_NONE();
        return;
    }

    // only 1. frag packet will be processed
    if (!t2_is_first_fragment(packet)) return;

    const uint16_t snaplen = packet->snapL7Len;
    if (snaplen < sizeof(modbus_hdr_t)) {
        mbFlowP->stat |= MB_STAT_SNAP;
        MB_SPKTMD_PRI_NONE();
        return;
    }

    const modbus_hdr_t *mb = (modbus_hdr_t*)packet->l7HdrP;

    if (sPktFile) {
        fprintf(sPktFile,
            "%" PRIu16 /* mbTranId   */ SEP_CHR
            "%" PRIu16 /* mbProtId   */ SEP_CHR
            "%" PRIu16 /* mbLen      */ SEP_CHR
            "%" PRIu8  /* mbUnitId   */ SEP_CHR
            MB_PRI_FE  /* mbFuncCode */ SEP_CHR
            , ntohs(mb->tid), ntohs(mb->pid), ntohs(mb->len),
              mb->uid, mb->fc);
    }

    // Protocol Identifier
    if (mb->pid != MODBUS_PROTO) {
        MB_DBG("Non-Modbus Protocol Identifier %d in flow %" PRIu64, mb->pid, flows[flowIndex].findex);
        mbFlowP->stat |= MB_STAT_PROTO;
        return;
    }

    num_mb_pkts++;
    mbFlowP->nmp++;

    // Unit Identifier
    if (mbFlowP->uid != 0 && mbFlowP->uid != mb->uid) {
        MB_DBG("Multiple UID in flow %" PRIu64 ": %d and %d", flows[flowIndex].findex, mbFlowP->uid, mb->uid);
        mbFlowP->stat |= MB_STAT_UID;
    }
    mbFlowP->uid = mb->uid;

    uint8_t tmp;

    /* Function Codes */
    if (mb->fc < 64) {
        mbFlowP->fcbf |= (1 << mb->fc);
#if MB_NUM_FUNC > 0
#if MB_UNIQ_FUNC == 1
        for (uint16_t i = 0; i < mbFlowP->nfc; i++) {
            if (mbFlowP->fc[i] == mb->fc) return;
        }
#endif // MB_UNIQ_FUNC == 1
        if (mbFlowP->nfc < MB_NUM_FUNC) {
            mbFlowP->fc[mbFlowP->nfc++] = mb->fc;
        } else {
            mbFlowP->stat |= MB_STAT_NFUNC;
        }
#endif // MB_NUM_FUNC > 0

    /* Exception codes (function code + 128) */
    } else if (mb->fc >= 128 && mb->fc < 64+128) {
        mbFlowP->nex++;
        tmp = mb->fc - 128;
        mbFlowP->fexbf |= (1 << tmp);
#if MB_NUM_FEX > 0
#if MB_UNIQ_FEX == 1
        for (uint16_t i = 0; i < mbFlowP->nfex; i++) {
            if (mbFlowP->fex[i] == tmp) return;
        }
#endif // MB_UNIQ_FEX == 1
        if (mbFlowP->nfex < MB_NUM_FEX) {
            mbFlowP->fex[mbFlowP->nfex++] = tmp;
        } else {
            mbFlowP->stat |= MB_STAT_NFEX;
        }
#endif // MB_NUM_FEX > 0

        tmp = *(((uint8_t*)&mb->fc)+1);
        if (tmp < 16) mbFlowP->exbf |= (1 << tmp);
        else mbFlowP->stat |= MB_STAT_EX;
#if MB_NUM_EX > 0
#if MB_UNIQ_EX == 1
        for (uint16_t i = 0; i < mbFlowP->nsex; i++) {
            if (mbFlowP->exc[i] == tmp) return;
        }
#endif // MB_UNIQ_EX == 1
        if (mbFlowP->nsex < MB_NUM_EX) {
            mbFlowP->exc[mbFlowP->nsex++] = tmp;
        } else {
            mbFlowP->stat |= MB_STAT_NEXCP;
        }
#endif // MB_NUM_EX > 0

    } else {
        MB_DBG("Unknown function code in flow %" PRIu64 ": %d", flows[flowIndex].findex, mb->fc);
        mbFlowP->stat |= MB_STAT_FUNC;
    }
}


void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {
    modbus_flow_t *mbFlowP = &modbus_flows[flowIndex];

    modbusStat |= mbFlowP->stat;

    OUTBUF_APPEND_U16(buf, mbFlowP->stat); // modbusStat
    OUTBUF_APPEND_U8(buf , mbFlowP->uid);  // modbusUID
    OUTBUF_APPEND_U32(buf, mbFlowP->nmp);  // modbusNPkts
    OUTBUF_APPEND_U16(buf, mbFlowP->nex);  // modbusNumEx
    OUTBUF_APPEND_U64(buf, mbFlowP->fcbf); // modbusFCBF

#if MB_NUM_FUNC > 0
    OUTBUF_APPEND_ARRAY_U8(buf, mbFlowP->fc, mbFlowP->nfc);   // modbusFC
#endif // MB_NUM_FUNC > 0

    OUTBUF_APPEND_U64(buf, mbFlowP->fexbf);                   // modbusFExBF

#if MB_NUM_FEX > 0
    OUTBUF_APPEND_ARRAY_U8(buf, mbFlowP->fex, mbFlowP->nfex); // modbusFEx
#endif // MB_NUM_FEX > 0

    OUTBUF_APPEND_U16(buf, mbFlowP->exbf);                    // modbusExCBF

#if MB_NUM_EX > 0
    OUTBUF_APPEND_ARRAY_U8(buf, mbFlowP->exc, mbFlowP->nsex); // modbusExC
#endif // MB_NUM_EX > 0
}


static inline void modbus_pluginReport(FILE *stream) {
    if (modbusStat) {
        T2_FPLOG_AGGR_HEX0(stream, plugin_name, modbusStat);
        T2_FPLOG_DIFFNUMP(stream, plugin_name, "Number of Modbus packets", num_mb_pkts, numPackets);
    }
}


void t2Monitoring(FILE *stream, uint8_t state) {

    switch (state) {

        // Print the name of the variables that will be output
        case T2_MON_PRI_HDR:
            fputs("modbusNPkts" SEP_CHR
                  "modbusStat"  SEP_CHR
                  , stream);
            return;

        // Print the variables to monitor
        case T2_MON_PRI_VAL:
            fprintf(stream,
                    "%"     PRIu64     /* modbusNPkts */ SEP_CHR
                    "0x%04" B2T_PRIX16 /* modbusStat  */ SEP_CHR
                    , num_mb_pkts - num_mb_pkts0
                    , modbusStat);
            break;

        // Print a report similar to t2PluginReport()
        case T2_MON_PRI_REPORT:
            modbus_pluginReport(stream);
            break;

        // Invalid state, do nothing
        default:
            return;
    }

#if DIFF_REPORT == 1
    num_mb_pkts0 = num_mb_pkts;
#endif
}


void t2PluginReport(FILE *stream) {
#if DIFF_REPORT == 1
    num_mb_pkts0 = 0;
#endif
    modbus_pluginReport(stream);
}


void t2Finalize() {
    free(modbus_flows);
}
