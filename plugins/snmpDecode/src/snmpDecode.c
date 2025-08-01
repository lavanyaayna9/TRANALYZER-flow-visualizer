/*
 * snmpDecode.c
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

#include "snmpDecode.h"
#include "t2buf.h"


#define SNMP_SPKTMD_PRI_NONE() \
    if (sPktFile) { \
        fputs(/* snmpVersion   */ SEP_CHR \
              /* snmpCommunity */ SEP_CHR \
              /* snmpUser      */ SEP_CHR \
              /* snmpType      */ SEP_CHR \
              , sPktFile); \
    }

#define SNMP_SKIP_BER_VAL(t2buf) \
        t2buf_skip_u8(t2buf); \
        t2buf_read_u8(t2buf, &len); \
        t2buf_skip_n(t2buf, len);


// Global variables

snmp_flow_t *snmp_flows;


// Static variables

static uint8_t snmpStat;
static uint64_t num_snmp[SNMP_NUM_PDU_TYPES+1];

static const char *snmp_types[] = {
    "GetRequest",
    "GetNextRequest",
    "GetResponse",
    "SetRequest",
    "Trap v1",
    "GetBulkRequest",
    "InformRequest ",
    "Trap v2",
    "Report",
};


// Tranalyzer functions

T2_PLUGIN_INIT("snmpDecode", "0.9.3", 0, 9);


void t2Init() {
    T2_PLUGIN_STRUCT_NEW(snmp_flows);

    if (sPktFile) {
        fputs("snmpVersion"   SEP_CHR
              "snmpCommunity" SEP_CHR
              "snmpUser"      SEP_CHR
              "snmpType"      SEP_CHR
              , sPktFile);
    }
}


binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;

    BV_APPEND_H8(bv , "snmpStat"     , "SNMP status");
    BV_APPEND_U8(bv , "snmpVersion"  , "SNMP version");
    BV_APPEND_STR(bv, "snmpCommunity", "SNMP community");
    BV_APPEND_STR(bv, "snmpUser"     , "SNMP username");
    BV_APPEND_H16(bv, "snmpMsgT"     , "SNMP message types bitfield");
    BV_APPEND(bv, "snmpNumReq_Next_Resp_Set_Trap1_Bulk_Info_Trap2_Rep", "SNMP number of GetRequest, GetNextRequest, GetResponse, SetRequest, Trapv1, GetBulkRequest, InformRequest, Trapv2, and Report packets", SNMP_NUM_PDU_TYPES, SNMP_NPDU_BVTYPES);

    return bv;
}


void t2OnNewFlow(packet_t *packet UNUSED, unsigned long flowIndex) {
    snmp_flow_t * const snmpFlowP = &snmp_flows[flowIndex];
    memset(snmpFlowP, '\0', sizeof(*snmpFlowP));

    const flow_t * const flowP = &flows[flowIndex];
    if (flowP->status & L2_FLOW) return; // Layer 2 flow. No L3/4 pointers, so return

    const uint_fast8_t proto = flowP->l4Proto;
    if (proto == L3_UDP || proto == L3_TCP) {
        const uint_fast16_t sport = flowP->srcPort;
        const uint_fast16_t dport = flowP->dstPort;
        if (sport == SNMP_PORT || sport == SNMP_TRAP_PORT ||
            dport == SNMP_PORT || dport == SNMP_TRAP_PORT)
        {
            snmpFlowP->stat |= SNMP_STAT_SNMP;
        }
    }
}


#if ETH_ACTIVATE > 0
void t2OnLayer2(packet_t *packet UNUSED, unsigned long flowIndex) {
    if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;
    SNMP_SPKTMD_PRI_NONE();
}
#endif


void t2OnLayer4(packet_t *packet, unsigned long flowIndex) {
    snmp_flow_t * const snmpFlowP = &snmp_flows[flowIndex];
    const uint16_t snaplen = packet->snapL7Len;

    if (!snmpFlowP->stat || snaplen < SNMP_MIN_HDRSIZE) { // not a SNMP packet
        SNMP_SPKTMD_PRI_NONE();
        return;
    }

    // only 1. frag packet will be processed
    if (!t2_is_first_fragment(packet)) {
        SNMP_SPKTMD_PRI_NONE();
        return;
    }

    num_snmp[SNMP_NUM_PDU_TYPES]++;

    const uint8_t * const l7HdrP = packet->l7HdrP;
    t2buf_t t2buf = t2buf_create(l7HdrP, snaplen);

    // SNMP packets are structured as follows:
    //    Sequence:
    //      - Integer (version),
    //      - OctetString (community),
    //      - data (get-request, get-response, set-request, ...)
    //          - request-id (integer32)
    //          - error-status (integer32)
    //          - error-index (integer32)
    //          - variable-bindings list (sequence)
    //              - variable-bindings (sequence)
    //                  - object-identifier (OID)
    //                  - value (variable type)

    uint8_t tag, len;

    // TODO test return value of t2buf_* functions

    // total length of the SNMP message = len+2
    t2buf_read_u8(&t2buf, &tag);
    if (tag != SNMP_T_SEQ) {
        snmpFlowP->stat |= SNMP_STAT_MALFORMED;
        SNMP_SPKTMD_PRI_NONE();
        return;
    }
    t2buf_read_u8(&t2buf, &len);
    // TODO test len against l7len

    // version
    t2buf_read_u8(&t2buf, &tag);
    t2buf_read_u8(&t2buf, &len);
    if (tag != SNMP_T_INT || len != 1) {
        // XXX for some reason, it seems there is
        // sometimes one or two extra uint8...
        tag = len;
        t2buf_read_u8(&t2buf, &len);
        if (tag != SNMP_T_INT || len != 1) {
            tag = len;
            t2buf_read_u8(&t2buf, &len);
            if (tag != SNMP_T_INT || len != 1) {
                snmpFlowP->stat |= SNMP_STAT_MALFORMED;
                SNMP_SPKTMD_PRI_NONE();
                return;
            }
        }
    }
    t2buf_read_u8(&t2buf, &snmpFlowP->version);

    // Ignore SNMPv3 for now...
    if (snmpFlowP->version > SNMP_V2 || t2buf_left(&t2buf) < 2) {
        // msgGlobalData
        //  - msgID (Integer)
        //  - msgMaxSize (Integer)
        //  - msgFlags (OctetString)
        //  - msgSecurityModel (Integer)
        SNMP_SKIP_BER_VAL(&t2buf);
        // XXX WTF is that?
        t2buf_skip_n(&t2buf, 4);
        // msgAuthoritativeEngineID (OctetString)
        SNMP_SKIP_BER_VAL(&t2buf);
        // msgAuthoritativeEngineBoots (Integer)
        SNMP_SKIP_BER_VAL(&t2buf);
        // msgAuthoritativeEngineTime (Integer)
        SNMP_SKIP_BER_VAL(&t2buf);
        // msgUserName (OctetString)
        t2buf_read_u8(&t2buf, &tag);
        t2buf_read_u8(&t2buf, &len);
        ssize_t buflen = MIN((size_t)len+1, sizeof(snmpFlowP->username));
        t2buf_readstr(&t2buf, snmpFlowP->username, len+1, T2BUF_UTF8, true);
        if (buflen != len+1) {
            snmpFlowP->stat |= SNMP_STAT_TRUNC;
            t2buf_skip_n(&t2buf, len+1-sizeof(snmpFlowP->username));
        }
        // msgAuthenticationParameters (OctetString)
        SNMP_SKIP_BER_VAL(&t2buf);
        // msgPrivacyParameters (OctetString)
        SNMP_SKIP_BER_VAL(&t2buf);
        // msgData (Sequence)
        t2buf_read_u8(&t2buf, &tag);
        t2buf_read_u8(&t2buf, &len);
        //  - contextEngineID (OctetString)
        SNMP_SKIP_BER_VAL(&t2buf);
        //  - contextName (OctetString)
        SNMP_SKIP_BER_VAL(&t2buf);
    } else {
        // community
        t2buf_read_u8(&t2buf, &tag);
        t2buf_read_u8(&t2buf, &len);
        if (tag != 0x04) {
            snmpFlowP->stat |= SNMP_STAT_MALFORMED;
            if (sPktFile) {
                fprintf(sPktFile,
                        "%u" /* snmpVersion   */ SEP_CHR
                             /* snmpCommunity */ SEP_CHR
                             /* snmpUser      */ SEP_CHR
                             /* snmpType      */ SEP_CHR
                        , snmpFlowP->version);
            }
            return;
        }
        ssize_t buflen = MIN((size_t)len+1, sizeof(snmpFlowP->community));
        t2buf_readstr(&t2buf, snmpFlowP->community, buflen, T2BUF_UTF8, true);
        if (buflen != len+1) {
            snmpFlowP->stat |= SNMP_STAT_TRUNC;
            t2buf_skip_n(&t2buf, len+1-sizeof(snmpFlowP->community));
        }

        if (t2buf_left(&t2buf) < 2) {
            if (sPktFile) {
                fprintf(sPktFile,
                        "%u" /* snmpVersion   */ SEP_CHR
                        "%s" /* snmpCommunity */ SEP_CHR
                        "%s" /* snmpUser      */ SEP_CHR
                             /* snmpType      */ SEP_CHR
                        , snmpFlowP->version, snmpFlowP->community, snmpFlowP->username);
            }
            return;
        }
    }

    // Data
    uint8_t pdu_type;
    t2buf_read_u8(&t2buf, &pdu_type);
    t2buf_read_u8(&t2buf, &len);

    if (sPktFile) {
        fprintf(sPktFile,
                "%u"              /* snmpVersion   */ SEP_CHR
                "%s"              /* snmpCommunity */ SEP_CHR
                "%s"              /* snmpUser      */ SEP_CHR
                "0x%02" B2T_PRIX8 /* snmpType      */ SEP_CHR
                , snmpFlowP->version, snmpFlowP->community, snmpFlowP->username, pdu_type);
    }

    if (pdu_type == SNMP_PDU_TRAP || pdu_type == SNMP_PDU_TRAPv2) {
        // TODO
        /* enterprise (OID) */
        /* agent-addr (OID) */
        /* generic-trap (integer32) */
        /* specific-trap (integer32) */
        /* time-stamp (timeticks) */
        /* variable-bindings (sequence) */
        const uint8_t idx = pdu_type - 0xa0;
        snmpFlowP->msgT |= (1 << idx);
        snmpFlowP->num_pkt[idx]++;
        num_snmp[idx]++;
    } else if (pdu_type >= SNMP_PDU_GET_REQ && pdu_type <= SNMP_PDU_GET_BULK_REQ) {
        // TODO
        /* request-id (integer32) */
        /* error-status (integer32) */
        /* error-index (integer32) */
        /* variable-bindings (sequence) */
        const uint8_t idx = pdu_type - 0xa0;
        snmpFlowP->msgT |= (1 << idx);
        snmpFlowP->num_pkt[idx]++;
        num_snmp[idx]++;
    } else if (pdu_type == SNMP_PDU_INFO_REQ || pdu_type == SNMP_PDU_REPORT) {
        // TODO
        const uint8_t idx = pdu_type - 0xa0;
        snmpFlowP->msgT |= (1 << idx);
        snmpFlowP->num_pkt[idx]++;
        num_snmp[idx]++;
    } else {
        //T2_PERR(plugin_name, "Unhandled data type 0x%02" B2T_PRIX8, pdu_type);
        snmpFlowP->stat |= SNMP_STAT_MALFORMED;
    }
}


void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {
    const snmp_flow_t * const snmpFlowP = &snmp_flows[flowIndex];

    snmpStat |= snmpFlowP->stat;

    OUTBUF_APPEND_U8( buf, snmpFlowP->stat);
    OUTBUF_APPEND_U8( buf, snmpFlowP->version);
    OUTBUF_APPEND_STR(buf, snmpFlowP->community);
    OUTBUF_APPEND_STR(buf, snmpFlowP->username);
    OUTBUF_APPEND_U16(buf, snmpFlowP->msgT);
    OUTBUF_APPEND(buf, snmpFlowP->num_pkt, SNMP_NUM_PDU_TYPES * sizeof(uint64_t));
}


void t2PluginReport(FILE *stream) {
    T2_FPLOG_AGGR_HEX(stream, plugin_name, snmpStat);
    if (num_snmp[SNMP_NUM_PDU_TYPES]) {
        T2_FPLOG_NUMP0(stream, plugin_name, "Number of SNMP packets", num_snmp[SNMP_NUM_PDU_TYPES], numPackets);
        char hrnum[64];
        for (uint_fast8_t i = 0; i < SNMP_NUM_PDU_TYPES; i++) {
            if (num_snmp[i]) {
                T2_CONV_NUM(num_snmp[i], hrnum);
                T2_FPLOG(stream, plugin_name, "Number of SNMP %s packets: %" PRIu64 "%s [%.2f%%]", snmp_types[i], num_snmp[i], hrnum, 100.0*num_snmp[i]/(double)num_snmp[SNMP_NUM_PDU_TYPES]);
            }
        }
    }
}


void t2Finalize() {
    free(snmp_flows);
}
