/*
 * radiusDecode.c
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

#include "radiusDecode.h"

#include <arpa/inet.h>      // for inet_ntoa


// Global variables

radius_flow_t *radius_flows;


// Static variables

static uint8_t radiusStat;
static uint64_t num_radius, num_radius0;
static uint64_t num_axs, num_axs0;
static uint64_t num_axs_acc, num_axs_acc0;
static uint64_t num_axs_rej, num_axs_rej0;
static uint64_t num_acc, num_acc0;


// Tranalyzer functions

T2_PLUGIN_INIT("radiusDecode", "0.9.3", 0, 9);


void t2Init() {
    T2_PLUGIN_STRUCT_NEW(radius_flows);

    if (sPktFile) {
        fputs("radiusStat"       SEP_CHR
#if RADIUS_NMS > 1
              "radiusCodeNm"     SEP_CHR
#elif RADIUS_NMS == 1
              "radiusCode"       SEP_CHR
#endif // RADIUS_NMS
#if RADIUS_AVPTYPE == 1
#if RADIUS_NMS > 1
              "radiusAVPTypeNms" SEP_CHR
#elif RADIUS_NMS == 1
              "radiusAVPTypes"   SEP_CHR
#endif // RADIUS_NMS
#endif // RADIUS_AVPTYPE == 1
              , sPktFile);
    }
}


binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;

    BV_APPEND_H8(bv,  "radiusStat", "RADIUS status");
#if RADIUS_CNTS == 1
    BV_APPEND(bv,     "radiusAxsReq_Acc_Rej_Chal", "RADIUS Access-Request/Accept/Reject/Challenge", 4, bt_uint_16, bt_uint_16, bt_uint_16, bt_uint_16);
    BV_APPEND(bv,     "radiusAccReq_Resp"  , "RADIUS Accounting-Request/Response", 2, bt_uint_16, bt_uint_16);
    BV_APPEND(bv,     "radiusAccStart_Stop", "RADIUS Accounting Start/Stop"      , 2, bt_uint_16, bt_uint_16);
#endif // RADIUS_CNTS == 1

#if RADIUS_NMS > 1
    BV_APPEND_STR_R(bv,"radiusCodeNms", "RADIUS code names");
#elif RADIUS_NMS == 1
    BV_APPEND_U8_R(bv,"radiusCodes", "RADIUS codes");
#endif // RADIUS_NMS
#if RADIUS_AVPTYPE == 1
#if RADIUS_NMS > 1
    BV_APPEND_STR_R(bv,"radiusAVPTypeNms", "RADIUS Attribute Value Pair Type Names");
#elif RADIUS_NMS == 1
    BV_APPEND_U8_R(bv,"radiusAVPTypes", "RADIUS Attribute Value Pair Types");
#endif // RADIUS_NMS
#endif // RADIUS_AVPTYPE == 1

    BV_APPEND_STR(bv, "radiusUser"         , "RADIUS username");
    BV_APPEND_STR(bv, "radiusPW"           , "RADIUS password");
    BV_APPEND_U32(bv, "radiusServiceType"  , "RADIUS service type");
    BV_APPEND_U32(bv, "radiusLoginService" , "RADIUS login-service");
    BV_APPEND_U32(bv, "radiusVendor"       , "RADIUS vendor ID (SMI)");

#if RADIUS_NAS == 1
    BV_APPEND_STR(bv, "radiusNasId"      , "RADIUS NAS Identifier");
    BV_APPEND_IP4(bv, "radiusNasIp"      , "RADIUS NAS IP address");
    BV_APPEND_U32(bv, "radiusNasPort"    , "RADIUS NAS IP port");
#if RADIUS_NMS > 1
    BV_APPEND_STR(bv, "radiusNasPortTypeNm", "RADIUS NAS Port Type Name");
#elif RADIUS_NMS == 1
    BV_APPEND_U32(bv, "radiusNasPortType", "RADIUS NAS Port Type");
#endif // RADIUS_NMS
    BV_APPEND_STR(bv, "radiusNasPortId"  , "RADIUS NAS Port ID");
#endif // RADIUS_NAS == 1

#if RADIUS_FRAMED == 1
    BV_APPEND_IP4(bv, "radiusFramedIp"   , "RADIUS framed IP address");
    BV_APPEND_IP4(bv, "radiusFramedMask" , "RADIUS framed IP netmask");
    BV_APPEND_U32(bv, "radiusFramedProto", "RADIUS framed protocol");
    BV_APPEND_U32(bv, "radiusFramedComp" , "RADIUS framed compression");
    BV_APPEND_U32(bv, "radiusFramedMtu"  , "RADIUS framed MTU");
#endif // RADIUS_FRAMED == 1

#if RADIUS_TUNNEL == 1
    // TODO tag_tunnelType_tunnelMedium tag_tunnelCli tag_tunnelSrv
    BV_APPEND(bv    , "radiusTunnel_Medium", "RADIUS tunnel type and medium type", 2, bt_uint_32, bt_uint_32);
    BV_APPEND_STR(bv, "radiusTunnelCli"    , "RADIUS tunnel client endpoint");
    BV_APPEND_STR(bv, "radiusTunnelSrv"    , "RADIUS tunnel server endpoint");
    BV_APPEND_STR(bv, "radiusTunnelCliAId" , "RADIUS tunnel client authentication Id");
    BV_APPEND_STR(bv, "radiusTunnelSrvAId" , "RADIUS tunnel server authentication Id");
    BV_APPEND_U32(bv, "radiusTunnelPref"   , "RADIUS tunnel preference");
#endif // RADIUS_TUNNEL == 1

#if RADIUS_ACCT == 1
    //BV_APPEND_TIMESTAMP(bv, "radiusAcctEvtTs", "RADIUS Accounting Event Timestamp");
    BV_APPEND_STR(bv, "radiusAcctSessId"      , "RADIUS Accounting Session Id");
    //repeating?
    BV_APPEND_U32(bv, "radiusAcctSessTime"    , "RADIUS Accounting Session Time (seconds)");
    BV_APPEND_U32(bv, "radiusAcctStatType"    , "RADIUS Accounting Status Type");
    BV_APPEND_U32(bv, "radiusAcctTerm"        , "RADIUS Accounting Terminate Cause");
    BV_APPEND(bv    , "radiusAcctInOct_OutOct", "RADIUS Accounting Input/Output Octets"   , 2, bt_uint_32, bt_uint_32);
    BV_APPEND(bv    , "radiusAcctInPkt_OutPkt", "RADIUS Accounting Input/Output Packets"  , 2, bt_uint_32, bt_uint_32);
    BV_APPEND(bv    , "radiusAcctInGw_OutGw"  , "RADIUS Accounting Input/Output Gigawords", 2, bt_uint_32, bt_uint_32);
#endif // RADIUS_ACCT == 1

    BV_APPEND_STR(bv, "radiusConnInfo" , "RADIUS user connection info");
    BV_APPEND_STR(bv, "radiusFilterId" , "RADIUS filter Identifier");
    BV_APPEND_STR(bv, "radiusCalledId" , "RADIUS Called Station Identifier");
    BV_APPEND_STR(bv, "radiusCallingId", "RADIUS Calling Station Identifier");
    BV_APPEND_STR(bv, "radiusReplyMsg" , "RADIUS reply message");

    return bv;
}


void t2OnNewFlow(packet_t* packet UNUSED, unsigned long flowIndex) {
    radius_flow_t * const radiusFlowP = &radius_flows[flowIndex];
    memset(radiusFlowP, '\0', sizeof(*radiusFlowP)); // set everything to 0

    const flow_t * const flowP = &flows[flowIndex];
    if (flowP->l4Proto == L3_UDP) {
        const uint_fast16_t src_port = flowP->srcPort;
        const uint_fast16_t dst_port = flowP->dstPort;
        if ((src_port == RADIUS_AUTH_PORT     && dst_port > 1024) ||
            (dst_port == RADIUS_AUTH_PORT     && src_port > 1024) ||
            (src_port == RADIUS_ACC_PORT      && dst_port > 1024) ||
            (dst_port == RADIUS_ACC_PORT      && src_port > 1024) ||
            (src_port == RADIUS_AUTH_OLD_PORT && dst_port > 1024) ||
            (dst_port == RADIUS_AUTH_OLD_PORT && src_port > 1024) ||
            (src_port == RADIUS_ACC_OLD_PORT  && dst_port > 1024) ||
            (dst_port == RADIUS_ACC_OLD_PORT  && src_port > 1024))
        {
            radiusFlowP->stat |= RADIUS_STAT_RADIUS;
        }
    }
}


void t2OnLayer2(packet_t* packet UNUSED, unsigned long flowIndex UNUSED) {
    if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;

    if (sPktFile) {
        fputs("0x00" /* radiusStat                      */ SEP_CHR
#if RADIUS_NMS > 0
                     /* radiusCodeNm/radiusCode         */ SEP_CHR
#endif // RADIUS_NMS > 0
#if RADIUS_AVPTYPE == 1
                     /* radiusAVPTypeNms/radiusAVPTypes */ SEP_CHR
#endif // RADIUS_AVPTYPE == 1
              , sPktFile);
    }
}


void t2OnLayer4(packet_t* packet, unsigned long flowIndex) {

    radius_flow_t * const radiusFlowP = &radius_flows[flowIndex];
    if (radiusFlowP->stat == 0x00) {
        // not a RADIUS packet
        if (sPktFile) {
            fputs("0x00" /* radiusStat                      */ SEP_CHR
#if RADIUS_NMS > 0
                         /* radiusCodeNm/radiusCode         */ SEP_CHR
#endif // RADIUS_NMS > 0
#if RADIUS_AVPTYPE == 1
                         /* radiusAVPTypeNms/radiusAVPTypes */ SEP_CHR
#endif // RADIUS_AVPTYPE == 1
                  , sPktFile);
        }
        return;
    }

    // Those variables MUST be declared here because of goto radpkt
#if RADIUS_AVPTYPE == 1 && RADIUS_NMS > 0
    uint16_t avpTypeCnt = 0;
#endif // RADIUS_AVPTYPE == 1 && RADIUS_NMS > 0

    uint8_t code = 0;

    // only 1. frag packet will be processed
    if (!t2_is_first_fragment(packet)) goto radpkt;

    num_radius++;

    uint16_t snaplen = packet->snapL7Len;
    if (snaplen < sizeof(radius_t)) goto radpkt;

    uint8_t *pktptr = (uint8_t*)packet->l7HdrP;
    const radius_t * const radius = (radius_t*)pktptr;
    pktptr += sizeof(radius_t);
    snaplen -= sizeof(radius_t);

    code = radius->code;

    uint16_t len = ntohs(radius->len);
    if (UNLIKELY(len < RADIUS_LEN_MIN || len > RADIUS_LEN_MAX)) {
        radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
    }

    const unsigned long revFlowIndex = flows[flowIndex].oppositeFlowIndex;
#if RADIUS_NMS > 0
    if (radiusFlowP->codeCnt >= RAD_CNTMX) goto cdexit;

    for (uint_fast32_t j = 0; j < radiusFlowP->codeCnt; j++) {
        if (radiusFlowP->rcode[j] == code) goto cdexit;
    }
    radiusFlowP->rcode[radiusFlowP->codeCnt++] = code;

cdexit: ;
#endif // RADIUS_NMS > 0

    switch (code) {
        case RADIUS_C_AXS_REQ:
            num_axs++;
#if RADIUS_CNTS == 1
            radiusFlowP->num_axs[0]++;
#endif // RADIUS_CNTS == 1
            radiusFlowP->stat |= RADIUS_STAT_AXS;
            break;
        case RADIUS_C_AXS_ACC:
            num_axs++;
            num_axs_acc++;
#if RADIUS_CNTS == 1
            radiusFlowP->num_axs[1]++;
#endif // RADIUS_CNTS == 1
            radiusFlowP->stat |= (RADIUS_STAT_CONN_SUCC | RADIUS_STAT_AXS);
            if (revFlowIndex != HASHTABLE_ENTRY_NOT_FOUND) {
                radius_flow_t * const revFlowP = &radius_flows[revFlowIndex];
                revFlowP->stat |= RADIUS_STAT_CONN_SUCC;
            }
            break;
        case RADIUS_C_AXS_REJ:
            num_axs++;
            num_axs_rej++;
#if RADIUS_CNTS == 1
            radiusFlowP->num_axs[2]++;
#endif // RADIUS_CNTS == 1
            radiusFlowP->stat |= (RADIUS_STAT_CONN_FAIL | RADIUS_STAT_AXS);
            if (revFlowIndex != HASHTABLE_ENTRY_NOT_FOUND) {
                radius_flow_t * const revFlowP = &radius_flows[revFlowIndex];
                revFlowP->stat |= RADIUS_STAT_CONN_FAIL;
            }
            break;
        case RADIUS_C_AXS_CHAL:
            num_axs++;
#if RADIUS_CNTS == 1
            radiusFlowP->num_axs[3]++;
#endif // RADIUS_CNTS == 1
            radiusFlowP->stat |= RADIUS_STAT_AXS;
            break;
        case RADIUS_C_ACC_REQ:
            num_acc++;
#if RADIUS_CNTS == 1
            radiusFlowP->num_acc[0]++;
#endif // RADIUS_CNTS == 1
            radiusFlowP->stat |= RADIUS_STAT_ACC;
            break;
        case RADIUS_C_ACC_RESP:
            num_acc++;
#if RADIUS_CNTS == 1
            radiusFlowP->num_acc[1]++;
#endif // RADIUS_CNTS == 1
            radiusFlowP->stat |= RADIUS_STAT_ACC;
            break;
        default:
            break;
    }

#if RADIUS_ACCT == 1
    uint32_t u32;
#endif // RADIUS_ACCT == 1
    uint8_t *avppptr;
    uint16_t len2;
    radius_avp_t *avp;
#if RADIUS_AVPTYPE == 1 && RADIUS_NMS > 0
    uint8_t avpType[RAD_CNTMX];
#endif // RADIUS_AVPTYPE == 1 && RADIUS_NMS != 0
    while (snaplen > sizeof(radius_avp_t)) {
        avp = (radius_avp_t*)(pktptr);

#if RADIUS_AVPTYPE == 1 && RADIUS_NMS > 0
        if (sPktFile && avpTypeCnt < RAD_CNTMX) avpType[avpTypeCnt++] = avp->type;

        if (radiusFlowP->avpTypeCnt >= RAD_CNTMX) goto rexist;

        for (uint_fast32_t j = 0; j < radiusFlowP->avpTypeCnt; j++) {
            if (radiusFlowP->avpType[j] == avp->type) goto rexist;
        }
        radiusFlowP->avpType[radiusFlowP->avpTypeCnt++] = avp->type;

rexist: ;
#endif // RADIUS_AVPTYPE == 1 && RADIUS_NMS > 0
        len = avp->len;
        avppptr = pktptr + sizeof(radius_avp_t);
        if (UNLIKELY(len < sizeof(radius_avp_t))) {
            radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
            break;
        }
        if (snaplen < len) break;
        switch (avp->type) {
            case 1:
                if (UNLIKELY(len < 3)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                len2 = MIN(len - sizeof(radius_avp_t), RADIUS_STRMAX);
                strncpy(radiusFlowP->user, (char*)avppptr, len2);
                radiusFlowP->user[len2] = '\0';
                break;
            case 2:
                if (UNLIKELY(len < 18 || len > 130)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                len2 = MIN(len - sizeof(radius_avp_t), RADIUS_STRMAX);

                strncpy(radiusFlowP->upw, (char*)avppptr, len2);
                radiusFlowP->upw[len2] = '\0';
                break;
            case 3:
                if (UNLIKELY(len != 19)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                len2 = MIN(len - sizeof(radius_avp_t), RADIUS_STRMAX);
                strncpy(radiusFlowP->upw, (char*)avppptr, len2);
                radiusFlowP->upw[len2] = '\0';
                break;
            case 4:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
#if RADIUS_NAS == 1
                radiusFlowP->nasip = *(uint32_t*)avppptr;
#endif // RADIUS_NAS == 1
                break;
            case 5:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
#if RADIUS_NAS == 1
                radiusFlowP->nasport = ntohl(*(uint32_t*)avppptr);
#endif // RADIUS_NAS == 1
                break;
            case 6:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                radiusFlowP->serviceType = ntohl(*(uint32_t*)avppptr);
                break;
            case 7:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
#if RADIUS_FRAMED == 1
                radiusFlowP->fproto = ntohl(*(uint32_t*)avppptr);
#endif // RADIUS_FRAMED == 1
                break;
            case 8:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
#if RADIUS_FRAMED == 1
                radiusFlowP->fip = *(uint32_t*)avppptr;
#endif // RADIUS_FRAMED == 1
                break;
            case 9:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
#if RADIUS_FRAMED == 1
                radiusFlowP->fmask = *(uint32_t*)avppptr;
#endif // RADIUS_FRAMED == 1
                break;
            case 10:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                //RADIUS_DBG("Framed-Routing(10): %d\n", ntohl(*(uint32_t*)avppptr));
                // 0 None
                // 1 Send routing packets
                // 2 Listen for routing packets
                // 3 Send and Listen
                break;
            case 11:
                if (UNLIKELY(len < 3)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                len2 = MIN(len - sizeof(radius_avp_t), RADIUS_STRMAX);
                strncpy(radiusFlowP->filter, (char*)avppptr, len2);
                radiusFlowP->filter[len2] = '\0';
                //RADIUS_DBG("Filter-Id(11): %s\n", radiusFlowP->filter);
                break;
            case 12:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                // 64-65535
#if RADIUS_FRAMED == 1
                radiusFlowP->fmtu = ntohl(*(uint32_t*)avppptr);
                //RADIUS_DBG("Framed-MTU(12): %d\n", radiusFlowP->fmtu);
#endif // RADIUS_FRAMED == 1
                break;
            case 13:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
#if RADIUS_FRAMED == 1
                radiusFlowP->fcomp = ntohl(*(uint32_t*)avppptr);
                //RADIUS_DBG("Framed-Compression(13): %d\n", radiusFlowP->fcomp);
#endif // RADIUS_FRAMED == 1
                break;
            case 14:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                //RADIUS_DBG("Login-IP-Host(14): %s\n", inet_ntoa(*(struct in_addr*)avppptr));
                break;
            case 15:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                radiusFlowP->logSer = ntohl(*(uint32_t*)avppptr);
                //RADIUS_DBG("Login-Service(15): %d\n",  radiusFlowP->logSer);
                break;
            case 16:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                // MAX 65535
                //RADIUS_DBG("Login-TCP-Port(16): %d\n",  ntohl(*(uint32_t*)avppptr));
                break;
            case 18:
                if (UNLIKELY(len < 3)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                len2 = MIN(len - sizeof(radius_avp_t), RADIUS_STRMAX);
                strncpy(radiusFlowP->replymsg, (char*)avppptr, len2);
                radiusFlowP->replymsg[len2] = '\0';
                //RADIUS_DBG("Reply-Message(18): %s\n", radiusFlowP->replymsg);
                break;
            case 19:
                if (UNLIKELY(len < 3)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                //len2 = MIN(len - sizeof(radius_avp_t), RADIUS_STRMAX);
                //strncpy(str, (char*)avppptr, len2);
                //str[len2] = '\0';
                //RADIUS_DBG("Callback-Number(19): %s\n", str);
                break;
            case 20:
                if (UNLIKELY(len < 3)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                //len2 = MIN(len - sizeof(radius_avp_t), RADIUS_STRMAX);
                //strncpy(str, (char*)avppptr, len2);
                //str[len2] = '\0';
                //RADIUS_DBG("Callback-Id(20): %s\n", str);
                break;
            case 22:
                if (UNLIKELY(len < 3)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                //len2 = MIN(len - sizeof(radius_avp_t), RADIUS_STRMAX);
                //strncpy(str, (char*)avppptr, len2);
                //str[len2] = '\0';
                //RADIUS_DBG("Framed-Route(22): %s\n", str);
                break;
            case 23:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                //RADIUS_DBG("Framed-IPX-Network(22): %s\n", inet_ntoa(*(struct in_addr*)avppptr));
                break;
            case 24:
                if (UNLIKELY(len < 3)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                //len2 = MIN(len - sizeof(radius_avp_t), RADIUS_STRMAX);
                //strncpy(str, (char*)avppptr, len2);
                //str[len2] = '\0';
                //RADIUS_DBG("State(24): %s\n", str);
                break;
            case 25:
                if (UNLIKELY(len < 3)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                //len2 = MIN(len - sizeof(radius_avp_t), RADIUS_STRMAX);
                //strncpy(str, (char*)avppptr, len2);
                //str[len2] = '\0';
                // not always human readable
                //RADIUS_DBG("Class(25): %s\n", str);
                break;
            case 26:
                if (UNLIKELY(len < 7)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                // vendor id (SMI)
                radiusFlowP->vendor = ntohl(*(uint32_t*)avppptr);
                // https://www.iana.org/assignments/enterprise-numbers/enterprise-numbers
                avppptr += sizeof(uint32_t);
                // string (vendor type, length, attribute)
                //len2 = MIN(len - sizeof(radius_avp_t) - sizeof(uint32_t), RADIUS_STRMAX);
                //strncpy(str, (char*)avppptr, len2);
                //str[len2] = '\0';
                break;
            case 27:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                //RADIUS_DBG("Session-Timeout(27): %d\n",  ntohl(*(uint32_t*)avppptr));
                break;
            case 28:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                //RADIUS_DBG("Idle-Timeout(28): %d\n",  ntohl(*(uint32_t*)avppptr));
                break;
            case 29:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                //RADIUS_DBG("Termination-Action(29): %d\n",  ntohl(*(uint32_t*)avppptr));
                // 0 Default
                // 1 RADIUS-Request
                break;
            case 30:
                if (UNLIKELY(len < 3)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                len2 = MIN(len - sizeof(radius_avp_t), RADIUS_STRMAX);
                strncpy(radiusFlowP->calledid, (char*)avppptr, len2);
                radiusFlowP->calledid[len2] = '\0';
                break;
            case 31:
                if (UNLIKELY(len < 3)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                len2 = MIN(len - sizeof(radius_avp_t), RADIUS_STRMAX);
                strncpy(radiusFlowP->callingid, (char*)avppptr, len2);
                radiusFlowP->callingid[len2] = '\0';
                //RADIUS_DBG("Calling-Station-Id(31): %s\n", radiusFlowP->callingid);
                break;
            case 32:
                if (UNLIKELY(len < 3)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
#if RADIUS_NAS == 1
                len2 = MIN(len - sizeof(radius_avp_t), RADIUS_STRMAX);
                strncpy(radiusFlowP->nasid, (char*)avppptr, len2);
                radiusFlowP->nasid[len2] = '\0';
#endif // RADIUS_NAS == 1
                break;
            case 33:
                if (UNLIKELY(len < 3)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                //len2 = MIN(len - sizeof(radius_avp_t), RADIUS_STRMAX);
                //strncpy(str, (char*)avppptr, len2);
                //str[len2] = '\0';
                //RADIUS_DBG("Proxy-State(33): %s\n", str);
                break;
            case 34:
                if (UNLIKELY(len < 3)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                //len2 = MIN(len - sizeof(radius_avp_t), RADIUS_STRMAX);
                //strncpy(str, (char*)avppptr, len2);
                //str[len2] = '\0';
                //RADIUS_DBG("Login-LAT-Service(34): %s\n", str);
                break;
            case 35:
                if (UNLIKELY(len < 3)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                //len2 = MIN(len - sizeof(radius_avp_t), RADIUS_STRMAX);
                //strncpy(str, (char*)avppptr, len2);
                //str[len2] = '\0';
                //RADIUS_DBG("Login-LAT-Node(35): %s\n", str);
                break;
            case 36:
                if (UNLIKELY(len != 34)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                //len2 = MIN(len - sizeof(radius_avp_t), RADIUS_STRMAX);
                //strncpy(str, (char*)avppptr, len2);
                //str[len2] = '\0';
                //RADIUS_DBG("Login-LAT-Group(36): %s\n", str);
                break;
            case 37:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                // 0:65535
                //RADIUS_DBG("Framed-AppleTalk-Link(37): %d\n", ntohl(*(uint32_t*)avppptr));
                break;
            case 38:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                // 0:65535
                //RADIUS_DBG("Framed-AppleTalk-Network(38): %d\n", ntohl(*(uint32_t*)avppptr));
                break;
            case 39:
                if (UNLIKELY(len < 3)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                //len2 = MIN(len - sizeof(radius_avp_t), RADIUS_STRMAX);
                //strncpy(str, (char*)avppptr, len2);
                //str[len2] = '\0';
                break;
            case 40:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
#if RADIUS_ACCT == 1
                u32 = ntohl(*(uint32_t*)avppptr);
                radiusFlowP->acctStatType = u32;
                //RADIUS_DBG("Acct-Status-Type(40): %d\n", u32);
#if RADIUS_CNTS == 1
                switch (u32) {
                    case 1: // start
                        radiusFlowP->num_acc_start++;
                        break;
                    case 2: // stop
                        radiusFlowP->num_acc_stop++;
                        break;
                    default:
                        break;
                }
#endif // RADIUS_CNTS == 1
                //  1 Start
                //  2 Stop
                //  3 Interim-Update
                //  7 Accounting-On
                //  8 Accounting-Off
                //  9 Tunnel-Start
                // 10 Tunnel-Stop
                // 11 Tunnel-Reject
                // 12 Tunnel-Link-Start
                // 13 Tunnel-Link-Stop
                // 14 Tunnel-Link-Reject
                // 15 Failed

#endif // RADIUS_ACCT == 1
                break;
            case 41:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                RADIUS_DBG("Acct-Delay-Time(41): %d\n", ntohl(*(uint32_t*)avppptr));
                break;
            case 42:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
#if RADIUS_ACCT == 1
                radiusFlowP->in_oct = ntohl(*(uint32_t*)avppptr);
#endif // RADIUS_ACCT == 1
                break;
            case 43:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
#if RADIUS_ACCT == 1
                radiusFlowP->out_oct = ntohl(*(uint32_t*)avppptr);
#endif // RADIUS_ACCT == 1
                break;
            case 44:
                if (UNLIKELY(len < 3)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
#if RADIUS_ACCT == 1
                len2 = MIN(len - sizeof(radius_avp_t), RADIUS_STRMAX);
                strncpy(radiusFlowP->acctSessId, (char*)avppptr, len2);
                radiusFlowP->acctSessId[len2] = '\0';
#endif // RADIUS_ACCT == 1
                break;
            case 45:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                RADIUS_DBG("Acct-Authentic(45): %d\n", ntohl(*(uint32_t*)avppptr));
                // 1 RADIUS
                // 2 Local
                // 3 Remote
                // 4 Diameter
                break;
            case 46:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                //TODO: repeating?
                radiusFlowP->sessTime = ntohl(*(uint32_t*)avppptr);
                break;
            case 47:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
#if RADIUS_ACCT == 1
                radiusFlowP->in_pkt = ntohl(*(uint32_t*)avppptr);
#endif // RADIUS_ACCT == 1
                break;
            case 48:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
#if RADIUS_ACCT == 1
                radiusFlowP->out_pkt = ntohl(*(uint32_t*)avppptr);
#endif // RADIUS_ACCT == 1
                break;
            case 49:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
#if RADIUS_ACCT == 1
                radiusFlowP->acctTerm = ntohl(*(uint32_t*)avppptr);
#endif // RADIUS_ACCT == 1
                break;
            case 50:
                if (UNLIKELY(len < 3)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                //len2 = MIN(len - sizeof(radius_avp_t), RADIUS_STRMAX);
                //strncpy(str, (char*)avppptr, len2);
                //str[len2] = '\0';
                break;
            case 51:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                //RADIUS_DBG("Acct-Link-Count(51): %d\n", ntohl(*(uint32_t*)avppptr));
                break;
            case 52:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
#if RADIUS_ACCT == 1
                radiusFlowP->in_gw = ntohl(*(uint32_t*)avppptr);
#endif // RADIUS_ACCT == 1
                break;
            case 53:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
#if RADIUS_ACCT == 1
                radiusFlowP->out_gw = ntohl(*(uint32_t*)avppptr);
#endif // RADIUS_ACCT == 1
                break;
            case 55:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                //radiusFlowP->acct_evt_ts = ntohl(*(uint32_t*)avppptr);
                break;
            case 60:
                if (UNLIKELY(len < 7)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                //len2 = MIN(len - sizeof(radius_avp_t), RADIUS_STRMAX);
                //strncpy(str, (char*)avppptr, len2);
                //str[len2] = '\0';
                //RADIUS_DBG("CHAP-Challenge(60): %s\n", str);
                break;
            case 61:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
#if RADIUS_NAS == 1
                radiusFlowP->nasporttype = ntohl(*(uint32_t*)avppptr);
#endif // RADIUS_NAS == 1
                break;
            case 62:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                RADIUS_DBG("Port-Limit(62): %d\n", ntohl(*(uint32_t*)avppptr));
                break;
            case 63:
                if (UNLIKELY(len < 3)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                //len2 = MIN(len - sizeof(radius_avp_t), RADIUS_STRMAX);
                //strncpy(str, (char*)avppptr, len2);
                //str[len2] = '\0';
                //RADIUS_DBG("Login-LAT-Port(63): %s\n", str);
                break;
            case 64:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
#if RADIUS_TUNNEL == 1
                radiusFlowP->tunnel = ntohl(*(uint32_t*)avppptr) & 0x00ffffff;
                //u32 = *(uint32_t*)avppptr & 0xff; // tag
                //radiusFlowP->tunnel[u32] = ntohl(*(uint32_t*)avppptr) & 0x00ffffff;
#endif // RADIUS_TUNNEL == 1
                break;
            case 65:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
#if RADIUS_TUNNEL == 1
                radiusFlowP->tunnel_med = ntohl(*(uint32_t*)avppptr) & 0x00ffffff;
                //u32 = *(uint32_t*)avppptr & 0xff; // tag
                //radiusFlowP->tunnel_med[u32] = ntohl(*(uint32_t*)avppptr) & 0x00ffffff;
#endif // RADIUS_TUNNEL == 1
                break;
            case 66:
                if (UNLIKELY(len < 3)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                len2 = len - sizeof(radius_avp_t);
                if (*avppptr <= 0x1f) {
                    avppptr += sizeof(uint8_t); // skip tag
                    len2 -= sizeof(uint8_t);
                }
                if (UNLIKELY(len2 < 1)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
#if RADIUS_TUNNEL == 1
                len2 = MIN(len2, RADIUS_STRMAX);
                strncpy(radiusFlowP->tunnelCli, (char*)avppptr, len2);
                radiusFlowP->tunnelCli[len2] = '\0';
#endif // RADIUS_TUNNEL == 1
                break;
            case 67:
                if (UNLIKELY(len < 3)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                len2 = len - sizeof(radius_avp_t);
                if (*avppptr <= 0x1f) {
                    avppptr += sizeof(uint8_t); // skip tag
                    len2 -= sizeof(uint8_t);
                }
                if (UNLIKELY(len2 < 1)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
#if RADIUS_TUNNEL == 1
                len2 = MIN(len2, RADIUS_STRMAX);
                strncpy(radiusFlowP->tunnelSrv, (char*)avppptr, len2);
                radiusFlowP->tunnelSrv[len2] = '\0';
#endif // RADIUS_TUNNEL == 1
                break;
            case 68:
                if (UNLIKELY(len < 3)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                //len2 = MIN(len - sizeof(radius_avp_t), RADIUS_STRMAX);
                //strncpy(str, (char*)avppptr, len2);
                //str[len2] = '\0';
                // not always human readable, implementation dependent
                break;
            case 69:
                if (UNLIKELY(len < 5)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                avppptr += sizeof(uint8_t); // skip tag
                avppptr += sizeof(uint16_t); // skip salt
                //len2 = MIN(len - sizeof(radius_avp_t) - sizeof(uint8_t) - sizeof(uint16_t), RADIUS_STRMAX);
                //strncpy(str, (char*)avppptr, len2);
                //str[len2] = '\0';
                break;
            case 77:
                if (UNLIKELY(len < 3)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                len2 = MIN(len - sizeof(radius_avp_t), RADIUS_STRMAX);
                strncpy(radiusFlowP->connInfo, (char*)avppptr, len2);
                radiusFlowP->connInfo[len2] = '\0';
                break;
            case 79:
                if (UNLIKELY(len < 3)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                //len2 = MIN(len - sizeof(radius_avp_t), RADIUS_STRMAX);
                //strncpy(str, (char*)avppptr, len2);
                //str[len2] = '\0';
                //RADIUS_DBG("EAP-Message(79): %s\n", str);
                break;
            case 80:
                if (UNLIKELY(len != 18)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                //len2 = MIN(len - sizeof(radius_avp_t), RADIUS_STRMAX);
                //strncpy(str, (char*)avppptr, len2);
                //str[len2] = '\0';
                //RADIUS_DBG("Message-Authenticator(80): %s\n", str);
                break;
            case 81:
                if (UNLIKELY(len < 3)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                len2 = len - sizeof(radius_avp_t);
                if (*avppptr <= 0x1f) {
                    avppptr += sizeof(uint8_t); // skip tag
                    len2 -= sizeof(uint8_t);
                }
                if (UNLIKELY(len2 < 1)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                //len2 = MIN(len2, RADIUS_STRMAX);
                //strncpy(str, (char*)avppptr, len2);
                //str[len2] = '\0';
                //RADIUS_DBG("Tunnel-Private-Group-ID(81): %s\n", str);
                break;
            case 82:
                if (UNLIKELY(len < 3)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                len2 = len - sizeof(radius_avp_t);
                if (*avppptr <= 0x1f) {
                    avppptr += sizeof(uint8_t); // skip tag
                    len2 -= sizeof(uint8_t);
                }
                if (UNLIKELY(len2 < 1)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                //len2 = MIN(len2, RADIUS_STRMAX);
                //strncpy(str, (char*)avppptr, len2);
                //str[len2] = '\0';
                // not always human readable
                //RADIUS_DBG("Tunnel-Assignment-ID(82): %s\n", str);
                break;
            case 83:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
#if RADIUS_TUNNEL == 1
                //u32 = *(uint32_t*)avppptr & 0xff; // tag
                radiusFlowP->tunnelPref = ntohl(*(uint32_t*)avppptr) & 0x00ffffff;
#endif // RADIUS_TUNNEL == 1
                break;
            case 85:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                //RADIUS_DBG("Acct-Interim-Interval(85): %d\n", ntohl(*(uint32_t*)avppptr));
                break;
            case 86:
                if (UNLIKELY(len != 6)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                //RADIUS_DBG("Acct-Tunnel-Packets-Lost(86): %d\n", ntohl(*(uint32_t*)avppptr));
                break;
            case 87:
                if (UNLIKELY(len < 3)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
#if RADIUS_NAS == 1
                len2 = MIN(len - sizeof(radius_avp_t), RADIUS_STRMAX);
                strncpy(radiusFlowP->nasportid, (char*)avppptr, len2);
                radiusFlowP->nasportid[len2] = '\0';
#endif // RADIUS_NAS == 1
                break;
            case 90:
                if (UNLIKELY(len < 3)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                len2 = len - sizeof(radius_avp_t);
                if (*avppptr <= 0x1f) {
                    avppptr += sizeof(uint8_t); // skip tag
                    len2 -= sizeof(uint8_t);
                }
                if (UNLIKELY(len2 < 1)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
#if RADIUS_TUNNEL == 1
                len2 = MIN(len2, RADIUS_STRMAX);
                strncpy(radiusFlowP->tunnelCliAId, (char*)avppptr, len2);
                radiusFlowP->tunnelCliAId[len2] = '\0';
#endif // RADIUS_TUNNEL == 1
                break;
            case 91:
                if (UNLIKELY(len < 3)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
                len2 = len - sizeof(radius_avp_t);
                if (*avppptr <= 0x1f) {
                    avppptr += sizeof(uint8_t); // skip tag
                    len2 -= sizeof(uint8_t);
                }
                if (UNLIKELY(len2 < 1)) {
                    radiusFlowP->stat |= RADIUS_STAT_MALFORMED;
                    break;
                }
#if RADIUS_TUNNEL == 1
                len2 = MIN(len2, RADIUS_STRMAX);
                strncpy(radiusFlowP->tunnelSrvAId, (char*)avppptr, len2);
                radiusFlowP->tunnelSrvAId[len2] = '\0';
#endif // RADIUS_TUNNEL == 1
                break;
            default:
                T2_PDBG(plugin_name, "Unhandled attribute type %d\n", avp->type);
                RADIUS_DBG("Unhandled attribute type %d\n", avp->type);
                break;
        }
        pktptr += len;
        if (snaplen > len) snaplen -= len;
        else snaplen = 0; // TODO set bit
    }

radpkt:
    if (sPktFile) {
        fprintf(sPktFile,
                "0x%02" B2T_PRIX8 /* radiusStat   */ SEP_CHR
#if RADIUS_NMS > 1
                "%s"              /* radiusCodeNm */ SEP_CHR
#elif RADIUS_NMS == 1
                "%d"              /* radiusCode   */ SEP_CHR
#endif // RADIUS_NMS
            , radiusFlowP->stat
#if RADIUS_NMS > 1
            , ((code < 52) ? codeNM[code] : "")
#elif RADIUS_NMS == 1
            , code
#endif // RADIUS_NMS
        );

#if (RADIUS_AVPTYPE == 1 && RADIUS_NMS > 0)
        for (uint_fast32_t j = 0; j < avpTypeCnt; j++) {
#if RADIUS_NMS > 1
            if (avpType[j] < 191) fprintf(sPktFile, "%s;", avpNM[avpType[j]]);
            else fputs(";", sPktFile);
#elif RADIUS_NMS == 1
            fprintf(sPktFile, "%" PRIu8 ";", avpType[j]);
#endif // RADIUS_NMS
        }
        fputs(SEP_CHR, sPktFile);
#endif // (RADIUS_AVPTYPE == 1 && RADIUS_NMS > 0)
    }

#if (FORCE_MODE == 1 && RADIUS_CNTS == 1)
    if (radiusFlowP->num_axs[1] || radiusFlowP->num_axs[2]) {
        flow_t * const flowP = &flows[flowIndex];
        T2_RM_FLOW(flowP);
    }
#endif // (FORCE_MODE == 1 && RADIUS_CNTS == 1)
}


void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {
    radius_flow_t *radiusFlowP = &radius_flows[flowIndex];

    radiusStat |= radiusFlowP->stat;

    OUTBUF_APPEND_U8(buf, radiusFlowP->stat); // radiusStat

#if RADIUS_CNTS == 1
    OUTBUF_APPEND(buf, radiusFlowP->num_axs, 4 * sizeof(uint16_t)); // radiusAxsReq_Acc_Rej_Chal
    OUTBUF_APPEND(buf, radiusFlowP->num_acc, 2 * sizeof(uint16_t)); // radiusAccReq_Resp

    // radiusAccStart_Stop
    OUTBUF_APPEND_U16(buf, radiusFlowP->num_acc_start);
    OUTBUF_APPEND_U16(buf, radiusFlowP->num_acc_stop);
#endif // RADIUS_CNTS == 1

    // radiusCodeNms/radiusCodes
#if RADIUS_NMS > 1
    // radiusCodeNms
    OUTBUF_APPEND_NUMREP(buf, radiusFlowP->codeCnt);
    for (uint_fast32_t i = 0; i < radiusFlowP->codeCnt; i++) {
        if (radiusFlowP->rcode[i] < 52) OUTBUF_APPEND_STR(buf, codeNM[radiusFlowP->rcode[i]]);
        else OUTBUF_APPEND_STR_EMPTY(buf);
    }
#elif RADIUS_NMS == 1
    // radiusCodes
    OUTBUF_APPEND_ARRAY_U8(buf, radiusFlowP->rcode, radiusFlowP->codeCnt);
#endif // RADIUS_NMS

    // radiusAVPTypeNms/radiusAVPTypes
#if RADIUS_AVPTYPE == 1
    // radiusAVPTypeNms
#if RADIUS_NMS > 1
    OUTBUF_APPEND_NUMREP(buf, radiusFlowP->avpTypeCnt);
    for (uint_fast32_t i = 0; i < radiusFlowP->avpTypeCnt; i++) {
        if (radiusFlowP->avpType[i] < 191) OUTBUF_APPEND_STR(buf, avpNM[radiusFlowP->avpType[i]]);
        else OUTBUF_APPEND_STR_EMPTY(buf);
    }
#elif RADIUS_NMS == 1
    // radiusAVPTypes
    OUTBUF_APPEND_ARRAY_U8(buf, radiusFlowP->avpType, radiusFlowP->avpTypeCnt);
#endif // RADIUS_NMS
#endif // RADIUS_AVPTYPE == 1

    OUTBUF_APPEND_STR(buf, radiusFlowP->user);        // radiusUser
    OUTBUF_APPEND_STR(buf, radiusFlowP->upw);         // radiusPW
    OUTBUF_APPEND_U32(buf, radiusFlowP->serviceType); // radiusServiceType
    OUTBUF_APPEND_U32(buf, radiusFlowP->logSer);      // radiusLoginService
    OUTBUF_APPEND_U32(buf, radiusFlowP->vendor);      // radiusVendor

#if RADIUS_NAS == 1
    OUTBUF_APPEND_STR(buf, radiusFlowP->nasid);       // radiusNasId
    OUTBUF_APPEND_U32(buf, radiusFlowP->nasip);       // radiusNasIp
    OUTBUF_APPEND_U32(buf, radiusFlowP->nasport);     // radiusNasPort
#if RADIUS_NMS > 1
    // radiusNasPortTypeNm
    const uint32_t nasPortType = radiusFlowP->nasporttype;
    if (nasPortType < 44) OUTBUF_APPEND_STR(buf, nasptpNM[nasPortType]);
    else OUTBUF_APPEND_STR_EMPTY(buf);
#elif RADIUS_NMS == 1
    OUTBUF_APPEND_U32(buf, radiusFlowP->nasporttype); // radiusNasPortType
#endif // RADIUS_NMS
    OUTBUF_APPEND_STR(buf, radiusFlowP->nasportid);   // radiusNasPortId
#endif // RADIUS_NAS == 1

#if RADIUS_FRAMED == 1
    OUTBUF_APPEND_U32(buf, radiusFlowP->fip);    // radiusFramedIp
    OUTBUF_APPEND_U32(buf, radiusFlowP->fmask);  // radiusFramedMask
    OUTBUF_APPEND_U32(buf, radiusFlowP->fproto); // radiusFramedProto
    OUTBUF_APPEND_U32(buf, radiusFlowP->fcomp);  // radiusFramedComp
    OUTBUF_APPEND_U32(buf, radiusFlowP->fmtu);   // radiusFramedMtu
#endif // RADIUS_FRAMED == 1

#if RADIUS_TUNNEL == 1
    // radiusTunnel_Medium
    OUTBUF_APPEND_U32(buf, radiusFlowP->tunnel);
    OUTBUF_APPEND_U32(buf, radiusFlowP->tunnel_med);

    OUTBUF_APPEND_STR(buf, radiusFlowP->tunnelCli);    // radiusTunnelCli
    OUTBUF_APPEND_STR(buf, radiusFlowP->tunnelSrv);    // radiusTunnelSrv
    OUTBUF_APPEND_STR(buf, radiusFlowP->tunnelCliAId); // radiusTunnelCliAId
    OUTBUF_APPEND_STR(buf, radiusFlowP->tunnelSrvAId); // radiusTunnelSrvAId
    OUTBUF_APPEND_U32(buf, radiusFlowP->tunnelPref);   // radiusTunnelPref
#endif // RADIUS_TUNNEL == 1

#if RADIUS_ACCT == 1
    //OUTBUF_APPEND_TIME_SEC(buf, radiusFlowP->acct_evt_ts); // radiusAcctEvtTs
    OUTBUF_APPEND_STR(buf, radiusFlowP->acctSessId);   // radiusAcctSessId
    OUTBUF_APPEND_U32(buf, radiusFlowP->sessTime);     // radiusAcctSessTime
    OUTBUF_APPEND_U32(buf, radiusFlowP->acctStatType); // radiusAcctStatType
    OUTBUF_APPEND_U32(buf, radiusFlowP->acctTerm);     // radiusAcctTerm

    // radiusAcctInOct_OutOct
    OUTBUF_APPEND_U32(buf, radiusFlowP->in_oct);
    OUTBUF_APPEND_U32(buf, radiusFlowP->out_oct);

    // radiusAcctInPkt_OutPkt
    OUTBUF_APPEND_U32(buf, radiusFlowP->in_pkt);
    OUTBUF_APPEND_U32(buf, radiusFlowP->out_pkt);

    // radiusAcctInGw_OutGw
    OUTBUF_APPEND_U32(buf, radiusFlowP->in_gw);
    OUTBUF_APPEND_U32(buf, radiusFlowP->out_gw);
#endif // RADIUS_ACCT == 1

    OUTBUF_APPEND_STR(buf, radiusFlowP->connInfo);  // radiusConnInfo
    OUTBUF_APPEND_STR(buf, radiusFlowP->filter);    // radiusFilterId
    OUTBUF_APPEND_STR(buf, radiusFlowP->calledid);  // radiusCalledId
    OUTBUF_APPEND_STR(buf, radiusFlowP->callingid); // radiusCallingId
    OUTBUF_APPEND_STR(buf, radiusFlowP->replymsg);  // radiusReplyMsg
}


static inline void radius_pluginReport(FILE *stream) {
    if (radiusStat) {
        T2_FPLOG_AGGR_HEX0(stream, plugin_name, radiusStat);
        T2_FPLOG_DIFFNUMP0(stream, plugin_name, "Number of RADIUS packets", num_radius, numPackets);
        T2_FPLOG_DIFFNUMP(stream , plugin_name, "Number of RADIUS Access packets", num_axs, num_radius);
        T2_FPLOG_DIFFNUMP(stream , plugin_name, "Number of RADIUS Access-Accept packets", num_axs_acc, num_radius);
        T2_FPLOG_DIFFNUMP(stream , plugin_name, "Number of RADIUS Access-Reject packets", num_axs_rej, num_radius);
        T2_FPLOG_DIFFNUMP(stream , plugin_name, "Number of RADIUS Accounting packets", num_acc, num_radius);
    }
}


void t2PluginReport(FILE *stream) {
#if DIFF_REPORT == 1
    num_radius0 = 0;
    num_axs0 = 0;
    num_axs_acc0 = 0;
    num_axs_rej0 = 0;
    num_acc0 = 0;
#endif // DIFF_REPORT == 1
    radius_pluginReport(stream);
}


void t2Monitoring(FILE *stream, uint8_t state) {

    switch (state) {

        case T2_MON_PRI_HDR:
            fputs("radiusPkts"       SEP_CHR
                  "radiusAxsPkts"    SEP_CHR
                  "radiusAxsAccPkts" SEP_CHR
                  "radiusAxsRejPkts" SEP_CHR
                  "radiusAccPkts"    SEP_CHR
                  , stream);
            return;

        case T2_MON_PRI_VAL:
            fprintf(stream,
                    "%" PRIu64 /* radiusPkts       */ SEP_CHR
                    "%" PRIu64 /* radiusAxsPkts    */ SEP_CHR
                    "%" PRIu64 /* radiusAxsAccPkts */ SEP_CHR
                    "%" PRIu64 /* radiusAxsRejPkts */ SEP_CHR
                    "%" PRIu64 /* radiusAccPkts    */ SEP_CHR
                    , num_radius - num_radius0
                    , num_axs - num_axs0
                    , num_axs_acc - num_axs_acc0
                    , num_axs_rej - num_axs_rej0
                    , num_acc - num_acc0);
            break;

        case T2_MON_PRI_REPORT:
            radius_pluginReport(stream);
            break;

        // Invalid state, do nothing
        default:
            return;
    }

#if DIFF_REPORT == 1
    num_radius0 = num_radius;
    num_axs0 = num_axs;
    num_axs_acc0 = num_axs_acc;
    num_axs_rej0 = num_axs_rej;
    num_acc0 = num_acc;
#endif // DIFF_REPORT == 1
}


void t2Finalize() {
    free(radius_flows);
}
