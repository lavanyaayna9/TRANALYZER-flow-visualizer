/*
 * stunDecode.c
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

#include "stunDecode.h"


#define NAT_OB_APPEND_OPT_ADDR_PORT(buf, a, p) \
    if (!a) { \
        OUTBUF_APPEND_NUMREP_ZERO(buf); \
    } else { \
        OUTBUF_APPEND_NUMREP_ONE(buf); \
        OUTBUF_APPEND_U32(buf, a); \
        OUTBUF_APPEND_U16_NTOH(buf, p); \
    }

// Store mapped address and port into provided 'a' and 'p'
#define NAT_MA_DECODE(a, p) { \
    const stun_mapped_addr_t * const mapped_addr = (stun_mapped_addr_t*)(STUN_ATTR_DATA(rp)); \
    (p) = mapped_addr->port; \
    if (mapped_addr->family == STUN_MA_FAMILY_IP4) { \
        (a) = mapped_addr->addr4; \
    } else if (mapped_addr->family == STUN_MA_FAMILY_IP6) { \
        /* TODO IPv6 */ \
    } \
}
// Store decoded mapped address and port into provided 'a' and 'p'
#define NAT_XMA_DECODE(a, p) { \
    const stun_mapped_addr_t * const mapped_addr = (stun_mapped_addr_t*)(STUN_ATTR_DATA(rp)); \
    (p) = STUN_XMA_PORT(mapped_addr->port); \
    if (mapped_addr->family == STUN_MA_FAMILY_IP4) { \
        (a) = STUN_XMA_ADDR4(mapped_addr->addr4); \
    } else if (mapped_addr->family == STUN_MA_FAMILY_IP6) { \
        /* TODO IPv6 */ \
    } \
}


// Global variables

nat_flow_t *nat_flows;


// Static variables

static uint32_t natErr;
static uint32_t natStat;
static uint64_t num_stun;
static uint64_t num_natpmp;


// Tranalyzer functions

T2_PLUGIN_INIT("stunDecode", "0.9.3", 0, 9);


void t2Init() {
    T2_PLUGIN_STRUCT_NEW(nat_flows);
}


binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;
    BV_APPEND_H32(bv, "natStat", "NAT status");
    BV_APPEND_H32(bv, "natErr" , "NAT error code");
    BV_APPEND(bv, "natMCReq_Ind_Succ_Err", "NAT message class (REQ, INDIC, SUCC RESP, ERR RESP) (STUN)",
            STUN_MT_CLASS_N, bt_uint_16, bt_uint_16, bt_uint_16, bt_uint_16);
    BV_APPEND_R(bv, "natAddr_Port"     , "NAT mapped address and port (STUN)"          , 2, bt_ip4_addr, bt_uint_16);
    BV_APPEND_R(bv, "natXAddr_Port"    , "NAT xor mapped address and port (STUN)"      , 2, bt_ip4_addr, bt_uint_16);
    BV_APPEND_R(bv, "natPeerAddr_Port" , "NAT xor peer address and port (TURN)"        , 2, bt_ip4_addr, bt_uint_16);
    BV_APPEND_R(bv, "natOrigAddr_Port" , "NAT response origin address and port (STUN)" , 2, bt_ip4_addr, bt_uint_16);
    BV_APPEND_R(bv, "natRelayAddr_Port", "NAT relayed address and port (TURN)"         , 2, bt_ip4_addr, bt_uint_16);
    BV_APPEND_R(bv, "natDstAddr_Port"  , "NAT destination address and port (TURN)"     , 2, bt_ip4_addr, bt_uint_16);
    //BV_APPEND_R(bv, "natAltAddrPort"   , "NAT alternate server address and port (STUN)", 2, bt_ip4_addr, bt_uint_16);
    BV_APPEND_R(bv, "natOtherAddr_Port" , "NAT other address and port (STUN)"           , 2, bt_ip4_addr, bt_uint_16);
    BV_APPEND_U32(bv, "natLifetime"    , "NAT binding lifetime [seconds] (STUN)");
    //BV_APPEND(bv, "natBWSenmin_SenMax_RcvMin_RcvMax", "NAT bandwidth reservation amount (min/max send, min/max received) (MS-TURN)",
    //      TURN_BW_N, bt_uint_32, bt_uint_32, bt_uint_32, bt_uint_32));
    BV_APPEND_STR_R(bv, "natUser"    , "NAT username (STUN)");
    BV_APPEND_STR_R(bv, "natPass"    , "NAT password (STUN)");
    BV_APPEND_STR_R(bv, "natRealm"   , "NAT realm (STUN)");
    BV_APPEND_STR_R(bv, "natSoftware", "NAT software (STUN)");
#if NAT_PMP == 1
    BV_APPEND(bv, "natPMPReqEA_MU_MT" , "NAT-PMP number of requests (External Address, Map UDP, Map TCP)" , 3, bt_uint_16, bt_uint_16, bt_uint_16);
    BV_APPEND(bv, "natPMPRespEA_MU_MT", "NAT-PMP number of responses (External Address, Map UDP, Map TCP)", 3, bt_uint_16, bt_uint_16, bt_uint_16);
    BV_APPEND_U32(bv, "natPMPSSSOE", "NAT-PMP seconds since start of epoch");
#endif // NAT_PMP == 1
    return bv;
}


void t2OnNewFlow(packet_t* packet UNUSED, unsigned long flowIndex) {
    nat_flow_t * const natFlowP = &nat_flows[flowIndex];
    memset(natFlowP, '\0', sizeof(*natFlowP));
}


void t2OnLayer4(packet_t* packet, unsigned long flowIndex) {
    const uint_fast8_t proto = packet->l4Proto;
    if (proto != L3_UDP && proto != L3_TCP) return;

    const flow_t * const flowP = &flows[flowIndex];
    nat_flow_t * const natFlowP = &nat_flows[flowIndex];

    uint16_t snaplen = packet->snapL7Len;
    uint8_t *rp = (uint8_t*)packet->l7HdrP;

    // NAT PMP
    if (proto == L3_UDP && (flowP->srcPort == NATPMP_PORT || flowP->dstPort == NATPMP_PORT)) {
        const nat_pmp_t * const pmp_hdr = (nat_pmp_t*)rp;
        num_natpmp++;
        natFlowP->stat |= NAT_STAT_PMP;
        if (snaplen < sizeof(nat_pmp_t)) return;
        const uint8_t op = pmp_hdr->opcode;
        switch (op) {
            case NATPMP_OP_EXTADDR_REQ:
                // No more data
                return;
            case NATPMP_OP_EXTADDR_RESP: {
                const nat_pmp_resp_t * const resp = (nat_pmp_resp_t*)rp;
                if (snaplen < sizeof(nat_pmp_resp_t)) return;
                natFlowP->natpmp_start = resp->start;
                if (resp->result == 0) natFlowP->mapped_addr = resp->ext_ip;
                else natFlowP->err |= (1 << resp->result); // See NAT-PMP result codes (NATPMP_R_*)
                break;
            }
            case NATPMP_OP_MAP_UDP_REQ:
            case NATPMP_OP_MAP_TCP_REQ: {
               //nat_pmp_map_req_t *req = (nat_pmp_map_req_t*)rp;
               break;
            }
            case NATPMP_OP_MAP_UDP_RESP:
            case NATPMP_OP_MAP_TCP_RESP: {
               //nat_pmp_map_resp_t *resp = (nat_pmp_map_resp_t*)rp;
               break;
            }
            default:
               // unknown opcode
               natFlowP->stat |= NAT_STAT_MALFORMED;
               break;
        }

        // Count the number of NAT-PMP messages
        if (op <= NATPMP_OP_MAP_TCP_REQ) {
            natFlowP->num_natpmp_op[op]++;
            return;
        } else if (op >= NATPMP_OP_EXTADDR_RESP && op <= NATPMP_OP_MAP_TCP_RESP) {
            natFlowP->num_natpmp_op[op-125]++;
            return;
        }

        // opcode was unknown... try to decode the message as STUN
    }

    const stun_header_t * const stun_hdr = (stun_header_t*)rp;
    if (snaplen < sizeof(stun_header_t)) return;

    // No magic cookie, no STUN!
    if (stun_hdr->magic_cookie != STUN_MAGIC_COOKIE) return;
    else if (!STUN_LEN_IS_VALID(stun_hdr->len)) return;
    else if (stun_hdr->zero != 0) return;

    if (flowP->srcPort != STUN_PORT || flowP->srcPort != STUNS_PORT ||
        flowP->dstPort != STUN_PORT || flowP->dstPort != STUNS_PORT)
    {
        natFlowP->stat |= NAT_STAT_STUN_OVER_NSP;
    }

    natFlowP->num_mt_class[STUN_MT_CLASS_TO_INT(STUN_MT_CLASS(stun_hdr->type))]++;
    const uint16_t meth = STUN_MT_METH(stun_hdr->type);
    if (meth >= STUN_M_ALLOC && meth <= STUN_M_CONNECT_ATTEMPT)
        natFlowP->stat |= NAT_STAT_TURN;

    snaplen -= sizeof(stun_header_t);
    rp += sizeof(stun_header_t);

    uint16_t len = ntohs(stun_hdr->len);

    size_t str_len;
    uint8_t *tmp_str;

    while (len >= sizeof(stun_attr_t) && snaplen >= sizeof(stun_attr_t)) {
        const stun_attr_t * const attr = (stun_attr_t*)rp;

        uint16_t alen = ntohs(attr->len);
        if (len < alen) {
            natFlowP->stat |= NAT_STAT_MALFORMED;
            // TODO report the type of the faulty record
            return;
        }

        if (snaplen < alen) {
            natFlowP->stat |= NAT_STAT_SNAPLEN;
            return;
        }

        switch (ntohs(attr->type)) {

            // Address/port
            case STUN_AT_MAPPED_ADDR:
                NAT_MA_DECODE(natFlowP->mapped_addr, natFlowP->mapped_port);
                break;
            case STUN_AT_ALT_SERVER: // FIXME not tested
                NAT_MA_DECODE(natFlowP->alt_server_addr, natFlowP->alt_server_port);
                break;
            case STUN_AT_RESPONSE_ORIGIN:
                NAT_MA_DECODE(natFlowP->resp_orig_addr, natFlowP->resp_orig_port);
                break;
            case STUN_AT_DEST_ADDR:
                NAT_MA_DECODE(natFlowP->dest_addr, natFlowP->dest_port);
                natFlowP->stat |= NAT_STAT_TURN;
                break;
            case STUN_AT_OTHER_ADDRESS: // FIXME not tested
                NAT_MA_DECODE(natFlowP->other_addr, natFlowP->other_port);
                break;

            // XOR address/port
            case STUN_AT_XOR_MAPPED_ADDR:
                NAT_XMA_DECODE(natFlowP->xor_mapped_addr, natFlowP->xor_mapped_port);
                break;
            case STUN_AT_XOR_PEER_ADDR:
                // TODO it seems there can be more than one...
                NAT_XMA_DECODE(natFlowP->xor_peer_addr, natFlowP->xor_peer_port);
                natFlowP->stat |= NAT_STAT_TURN;
                break;
            case STUN_AT_XOR_RELAYED_ADDR:
                NAT_XMA_DECODE(natFlowP->relayed_addr, natFlowP->relayed_port);
                natFlowP->stat |= NAT_STAT_TURN;
                break;

            // Error
            case STUN_AT_ERR_CODE: {
                const stun_error_t * const err = (stun_error_t*)(STUN_ATTR_DATA(rp));
                STUN_ERR_TO_BF(STUN_ERR_CODE(err->res_cl_num), natFlowP);
                break;
            }

            // Strings
            case STUN_AT_USERNAME:
                str_len = MIN(alen, STUN_USERNAME_MAXLEN-1);
                if ((tmp_str = memchr(STUN_ATTR_DATA(rp), ':', alen))) {
                    str_len -= (++tmp_str - (STUN_ATTR_DATA(rp)));
                    memcpy(&natFlowP->password, tmp_str, str_len);
                    natFlowP->password[str_len+1] = '\0';
                    str_len = tmp_str - (STUN_ATTR_DATA(rp)) - 1; // ignore ':'
                    memcpy(&natFlowP->username, STUN_ATTR_DATA(rp), str_len);
                    natFlowP->username[str_len+1] = '\0';
                } else {
                    memcpy(&natFlowP->username, STUN_ATTR_DATA(rp), str_len);
                    natFlowP->username[str_len+1] = '\0';
                }
                break;
            case STUN_AT_PASSWORD: // deprecated
                natFlowP->stat |= NAT_STAT_DEPRECATED;
                str_len = MIN(alen, STUN_USERNAME_MAXLEN-1);
                memcpy(&natFlowP->password, STUN_ATTR_DATA(rp), str_len);
                natFlowP->password[str_len+1] = '\0';
                break;
            case STUN_AT_REALM:
                str_len = MIN(alen, STUN_ATTR_STR_MAXLEN-1);
                memcpy(&natFlowP->realm, STUN_ATTR_DATA(rp), str_len);
                natFlowP->realm[str_len+1] = '\0';
                break;
            case STUN_AT_SOFTWARE:
                str_len = MIN(alen, STUN_ATTR_STR_MAXLEN-1);
                memcpy(&natFlowP->software, STUN_ATTR_DATA(rp), str_len);
                natFlowP->software[str_len+1] = '\0';
                break;

            // Flag
            case STUN_AT_DONT_FRAGMENT:
                natFlowP->stat |= NAT_STAT_TURN;
                natFlowP->stat |= NAT_STAT_DF;
                break;
            case STUN_AT_NONCE: // TODO store nonce? (older version had NONCE and REALM swapped...)
                natFlowP->stat |= NAT_STAT_NONCE;
                break;

            // Uint32
            case STUN_AT_LIFETIME:
                natFlowP->stat |= NAT_STAT_TURN;
                natFlowP->lifetime = ntohl(*(uint32_t*)(STUN_ATTR_DATA(rp)));
                break;
            case STUN_AT_BANDWIDTH:
                natFlowP->stat |= (NAT_STAT_TURN | NAT_STAT_DEPRECATED);
                natFlowP->bandwidth = ntohl(*(uint32_t*)(STUN_ATTR_DATA(rp)));
                break;
            case STUN_AT_PRIORITY:
                natFlowP->stat |= NAT_STAT_ICE;
                natFlowP->priority = ntohl(*(uint32_t*)(STUN_ATTR_DATA(rp)));
                break;

            // Uint16
            case STUN_AT_CHANNEL_NUMBER: // FIXME not tested
                natFlowP->stat |= NAT_STAT_TURN;
                natFlowP->channel = ntohs(*(uint16_t*)(STUN_ATTR_DATA(rp)));
                break;

            // Uint8
            case STUN_AT_REQ_TRANSPORT:
                natFlowP->stat |= NAT_STAT_TURN;
                natFlowP->req_proto = *(STUN_ATTR_DATA(rp));
                break;
            case STUN_AT_REQ_ADDR_FAMILY:
                natFlowP->stat |= NAT_STAT_TURN;
                natFlowP->req_family = *(STUN_ATTR_DATA(rp));
                break;

            // TURN
            case STUN_AT_EVEN_PORT: // FIXME not tested
                natFlowP->stat |= (NAT_STAT_TURN | NAT_STAT_EVEN_PORT);
                if (*(STUN_ATTR_DATA(rp)) & 0x1) natFlowP->stat |= NAT_STAT_RES_NEXT_PORT;
                break;
            case STUN_AT_TIMER_VAL:
                natFlowP->stat |= (NAT_STAT_TURN | NAT_STAT_DEPRECATED);
                break;
            case STUN_AT_MAGIC_COOKIE:
                natFlowP->stat |= NAT_STAT_TURN;
                if (*(uint32_t*)(STUN_ATTR_DATA(rp)) != TURN_MAGIC_COOKIE) natFlowP->stat |= NAT_STAT_MALFORMED;
                break;

            case STUN_AT_DATA:
            case STUN_AT_RESERVATION_TOKEN:
                natFlowP->stat |= NAT_STAT_TURN;
                break;

            // ICE
            case STUN_AT_USE_CANDIDATE:
            case STUN_AT_ICE_CONTROLLED:
            case STUN_AT_ICE_CONTROLLING:
                natFlowP->stat |= NAT_STAT_ICE;
                break;

            // MS-TURN
            case STUN_AT_MS_VERSION:
            case STUN_AT_MS_XOR_MAPPED_ADDR:
            case STUN_AT_MS_SEQ_NUM:
            case STUN_AT_MS_SERVICE_QUALITY:
            case STUN_AT_MS_ALT_MAPPED_ADDR:
                natFlowP->stat |= (NAT_STAT_TURN | NAT_STAT_MS);
                break;

            // MS-TURNBW
            case STUN_AT_BANDWIDTH_RSV_AMOUNT: {
                natFlowP->stat |= (NAT_STAT_TURN | NAT_STAT_MS);
                const turn_bw_rsv_amount_t * const bw_amount = (turn_bw_rsv_amount_t*)(STUN_ATTR_DATA(rp));
                natFlowP->ms_bandwidth[TURN_BW_MIN_SEND] = ntohl(bw_amount->min_send);
                natFlowP->ms_bandwidth[TURN_BW_MAX_SEND] = ntohl(bw_amount->max_send);
                natFlowP->ms_bandwidth[TURN_BW_MIN_RCV] = ntohl(bw_amount->min_rcv);
                natFlowP->ms_bandwidth[TURN_BW_MAX_RCV] = ntohl(bw_amount->max_rcv);
                break;
            }
            case STUN_AT_SIP_DIALOG_ID:
            case STUN_AT_SIP_CALL_ID:
                natFlowP->stat |= NAT_STAT_SIP;
                /* FALLTHRU */
            case STUN_AT_BANDWIDTH_ACM:
            case STUN_AT_BANDWIDTH_RSV_ID:
            case STUN_AT_REMOTE_SITE_ADDR:
            case STUN_AT_REMOTE_RELAY_SITE:
            case STUN_AT_LOCAL_SITE_ADDR:
            case STUN_AT_LOCAL_RELAY_SITE:
            case STUN_AT_REMOTE_SITE_ADDR_RP:
            case STUN_AT_REMOTE_RELAY_SITE_RP:
            case STUN_AT_LOCAL_SITE_ADDR_RP:
            case STUN_AT_LOCAL_RELAY_SITE_RP:
            case STUN_AT_LOCATION_PROFILE:
                natFlowP->stat |= (NAT_STAT_TURN | NAT_STAT_MS);
                break;

            // MS-ICE
            case STUN_AT_CANDIDATE_ID:
            case STUN_AT_IMPLEM_VER:
                natFlowP->stat |= (NAT_STAT_ICE | NAT_STAT_MS);
                break;

            // deprecated
            case STUN_AT_RESP_ADDR:
            case STUN_AT_CHANGE_ADDR:
            case STUN_AT_SOURCE_ADDR:
            case STUN_AT_CHANGED_ADDR:
            case STUN_AT_REFLECTED_FROM:
                natFlowP->stat |= NAT_STAT_DEPRECATED;
                break;

            // do nothing
            case STUN_AT_MSG_INTEGRITY:
            case STUN_AT_FINGERPRINT:
                break;

            default:
                T2_PDBG(plugin_name, "Unhandled attribute %#04x", ntohs(attr->type));
                break;
        }

        uint16_t padding = alen % 4;
        if (padding > 0) padding = 4 - padding;
        alen += STUN_ATTR_HDR_LEN + padding;
        if (alen > len) { // Bogus length
            natFlowP->stat |= NAT_STAT_MALFORMED;
            break;
        }

        len -= alen;
        snaplen -= alen;
        rp += alen;
    }

    natFlowP->stat |= NAT_STAT_STUN;
    num_stun++;
}


void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {
    nat_flow_t * const natFlowP = &nat_flows[flowIndex];

    natStat |= natFlowP->stat;
    natErr  |= natFlowP->err;

    OUTBUF_APPEND_U32(buf, natFlowP->stat);
    OUTBUF_APPEND_U32(buf, natFlowP->err);

    for (uint_fast32_t i = 0; i < STUN_MT_CLASS_N; i++) {
        OUTBUF_APPEND_U16(buf, natFlowP->num_mt_class[i]);
    }

    // Addr_Port
    NAT_OB_APPEND_OPT_ADDR_PORT(buf, natFlowP->mapped_addr, natFlowP->mapped_port);
    NAT_OB_APPEND_OPT_ADDR_PORT(buf, natFlowP->xor_mapped_addr, natFlowP->xor_mapped_port);
    NAT_OB_APPEND_OPT_ADDR_PORT(buf, natFlowP->xor_peer_addr, natFlowP->xor_peer_port);
    NAT_OB_APPEND_OPT_ADDR_PORT(buf, natFlowP->resp_orig_addr, natFlowP->resp_orig_port);
    NAT_OB_APPEND_OPT_ADDR_PORT(buf, natFlowP->relayed_addr, natFlowP->relayed_port);
    NAT_OB_APPEND_OPT_ADDR_PORT(buf, natFlowP->dest_addr, natFlowP->dest_port);
    //NAT_OB_APPEND_OPT_ADDR_PORT(buf, natFlowP->alt_server_addr, natFlowP->alt_server_port);
    NAT_OB_APPEND_OPT_ADDR_PORT(buf, natFlowP->other_addr, natFlowP->other_port);

    OUTBUF_APPEND_U32(buf, natFlowP->lifetime);

    //for (uint_fast32_t i = 0; i < TURN_BW_N; i++) {
    //    OUTBUF_APPEND_U32(buf, natFlowP->ms_bandwidth[i]);
    //}

    // Str
    OUTBUF_APPEND_OPT_STR(buf, natFlowP->username);
    OUTBUF_APPEND_OPT_STR(buf, natFlowP->password);
    OUTBUF_APPEND_OPT_STR(buf, natFlowP->realm);
    OUTBUF_APPEND_OPT_STR(buf, natFlowP->software);

#if NAT_PMP == 1
    for (uint_fast32_t i = 0; i < 6; i++) {
        OUTBUF_APPEND_U16(buf, natFlowP->num_natpmp_op[i]);
    }

    OUTBUF_APPEND_U32(buf, natFlowP->natpmp_start);
#endif // NAT_PMP == 1
}


void t2PluginReport(FILE *stream) {
    if (natStat) {
        T2_FPLOG_AGGR_HEX0(stream, plugin_name, natStat);
        T2_FPLOG_AGGR_HEX(stream, plugin_name, natErr);
        T2_FPLOG_NUMP(stream, plugin_name, "Number of NAT-PMP packets", num_natpmp, numPackets);
        T2_FPLOG_NUMP(stream, plugin_name, "Number of STUN packets", num_stun, numPackets);
    }
}


void t2Finalize() {
    free(nat_flows);
}
