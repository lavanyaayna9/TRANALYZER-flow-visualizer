/*
 * lldpDecode.c
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

#include "lldpDecode.h"

#include <arpa/inet.h>  // for inet_ntop

#include "t2buf.h"


// Global variables

lldpFlow_t *lldpFlows;


#if ETH_ACTIVATE > 0

// Static variables

static uint64_t numLldpPkts, numLldpPkts0;
static uint32_t lldpTLVTypes;
static uint16_t lldpStat, lldpCaps, lldpEnCaps;


#if LLDP_OPT_TLV == 1
#define LLDP_SPKT_PRI_NONE() \
    if (sPktFile) { \
        fputs("0x0000" /* lldpStat        */ SEP_CHR \
                       /* lldpTTL         */ SEP_CHR \
                       /* lldpTLVTypes    */ SEP_CHR \
                       /* lldpChassis     */ SEP_CHR \
                       /* lldpPort        */ SEP_CHR \
                       /* lldpPortDesc    */ SEP_CHR \
                       /* lldpSysName     */ SEP_CHR \
                       /* lldpCaps_enCaps */ SEP_CHR \
                       /* lldpMngmtAddr   */ SEP_CHR \
              , sPktFile); \
    }
#else // LLDP_OPT_TLV == 0
#define LLDP_SPKT_PRI_NONE() \
    if (sPktFile) { \
        fputs("0x0000" /* lldpStat     */ SEP_CHR \
                       /* lldpTTL      */ SEP_CHR \
                       /* lldpTLVTypes */ SEP_CHR \
                       /* lldpChassis  */ SEP_CHR \
                       /* lldpPort     */ SEP_CHR \
              , sPktFile); \
    }
#endif // LLDP_OPT_TLV

#define LLDP_READ_HEX(t2buf, dest, len, maxlen) { \
    const size_t read = MIN(len, (maxlen)/2); \
    if (read != (size_t)len) { \
        lldpFlowP->lldpStat |= LLDP_STAT_STR; \
    } \
    if (t2buf_hexdecode(t2buf, read, dest, 0) != read) { \
        lldpFlowP->lldpStat |= LLDP_STAT_SNAP; \
        goto lldp_pktmd; \
    } \
    dest[2*read] = '\0'; \
    if (read != (size_t)len) t2buf_skip_n(t2buf, len - read); \
}

#define LLDP_READ_STR(t2buf, dest, len, maxlen) { \
    const size_t read = MIN(len, maxlen); \
    if (read != (size_t)len) { \
        lldpFlowP->lldpStat |= LLDP_STAT_STR; \
    } \
    if (!t2buf_read_n(t2buf, (uint8_t*)dest, read)) { \
        lldpFlowP->lldpStat |= LLDP_STAT_SNAP; \
        goto lldp_pktmd; \
    } \
    dest[read] = '\0'; \
    if (read != (size_t)len) t2buf_skip_n(t2buf, len - read); \
}

#define LLDP_READ_N(t2buf, dest, n) \
    if (!t2buf_read_n(t2buf, dest, n)) { \
        lldpFlowP->lldpStat |= LLDP_STAT_SNAP; \
        goto lldp_pktmd; \
    }

#define LLDP_READ_U8(t2buf, dest) \
    if (!t2buf_read_u8(t2buf, dest)) { \
        lldpFlowP->lldpStat |= LLDP_STAT_SNAP; \
        goto lldp_pktmd; \
    }

#define LLDP_READ_U16(t2buf, dest) \
    if (!t2buf_read_u16(t2buf, dest)) { \
        lldpFlowP->lldpStat |= LLDP_STAT_SNAP; \
        goto lldp_pktmd; \
    }

#define LLDP_READ_U32(t2buf, dest) \
    if (!t2buf_read_u32(t2buf, dest)) { \
        lldpFlowP->lldpStat |= LLDP_STAT_SNAP; \
        goto lldp_pktmd; \
    }

#define LLDP_READ_LE_U32(t2buf, dest) \
    if (!t2buf_read_le_u32(t2buf, dest)) { \
        lldpFlowP->lldpStat |= LLDP_STAT_SNAP; \
        goto lldp_pktmd; \
    }

#define LLDP_CHECK_MIN_LEN(len, min) \
    if (len < min) { \
        lldpFlowP->lldpStat |= LLDP_STAT_LEN; \
        goto lldp_pktmd; \
    }

#endif // ETH_ACTIVATE > 0


// Tranalyzer functions

T2_PLUGIN_INIT("lldpDecode", "0.9.3", 0, 9);


void t2Init() {
#if ETH_ACTIVATE == 0
    T2_PWRN(plugin_name, "ETH_ACTIVATE is set to 0 in 'networkHeaders.h', no output will be produced");
#else // ETH_ACTIVATE > 0
    T2_PLUGIN_STRUCT_NEW(lldpFlows);
    if (sPktFile) {
        fputs("lldpStat"        SEP_CHR
              "lldpTTL"         SEP_CHR
              "lldpTLVTypes"    SEP_CHR
              "lldpChassis"     SEP_CHR
              "lldpPort"        SEP_CHR
#if LLDP_OPT_TLV == 1
              "lldpPortDesc"    SEP_CHR
              "lldpSysName"     SEP_CHR
              "lldpCaps_enCaps" SEP_CHR
              "lldpMngmtAddr"   SEP_CHR
#endif // LLDP_OPT_TLV == 1
              , sPktFile);
    }
#endif // ETH_ACTIVATE > 0
}


// If ETH_ACTIVATE == 0, the plugin does not produce any output.
// All the code below is therefore not activated.


#if ETH_ACTIVATE > 0

binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;

    BV_APPEND_H16(  bv, "lldpStat"    , "LLDP status");
    BV_APPEND_U16_R(bv, "lldpTTL"     , "LLDP Time To Live (sec)");
    BV_APPEND_H32(  bv, "lldpTLVTypes", "LLDP TLV types");
    // TODO: could there be more than one time a given TLV? For TTL yes.
    // Mandatory TLVs
    BV_APPEND_STRC( bv, "lldpChassis" , "LLDP chassis ID");
    BV_APPEND_STR(  bv, "lldpPort"    , "LLDP port ID");

#if LLDP_OPT_TLV == 1
    // Optional TLVs
    BV_APPEND_STR( bv, "lldpPortDesc"   , "LLDP port description");
    BV_APPEND_STR( bv, "lldpSysName"    , "LLDP system name");
    BV_APPEND_STR( bv, "lldpSysDesc"    , "LLDP system description");
    BV_APPEND(     bv, "lldpCaps_enCaps", "LLDP supported and enabled capabilities", 2, bt_hex_16, bt_hex_16);
    BV_APPEND_STRC(bv, "lldpMngmtAddr"  , "LLDP management address"); // TODO There could be more than 1
#endif // LLDP_OPT_TLV == 1

    return bv;
}


void t2OnNewFlow(packet_t *packet, unsigned long flowIndex) {
    lldpFlow_t * const lldpFlowP = &lldpFlows[flowIndex];
    memset(lldpFlowP, '\0', sizeof(*lldpFlowP));

    if (!(packet->status & L2_LLDP)) return;

    lldpFlowP->lldpStat |= LLDP_STAT_LLDP;
}


void t2OnLayer2(packet_t *packet, unsigned long flowIndex) {
    if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;

    lldpFlow_t * const lldpFlowP = &lldpFlows[flowIndex];
    if (!(packet->status & L2_LLDP)) {
        LLDP_SPKT_PRI_NONE();
        return;
    }

    numLldpPkts++;

    const uint16_t snaplen = packet->snapL7Len;
    const uint8_t * const l7hdr = packet->l7HdrP;
    t2buf_t t2buf = t2buf_create(l7hdr, snaplen);
    uint16_t ttl;

    uint8_t mandatory = 0;
    uint8_t type = UINT8_MAX;

    while (t2buf_left(&t2buf) > 1 && type != LLDP_TLV_END) {

        /* TLV type and length */
        uint16_t type_len;
        LLDP_READ_U16(&t2buf, &type_len);
        type = LLDP_TYPE(type_len);
        const uint16_t len = LLDP_LEN(type_len);

        if (type < 31) lldpFlowP->lldpTLVTypes |= (1U << type);
        else lldpFlowP->lldpTLVTypes |= 0x80000000;

        if (type < LLDP_TLV_PORT_DESC) {
            mandatory |= (1 << type);
        } else if (type <= LLDP_TLV_MNGMT_ADDR) {
            lldpFlowP->lldpStat |= LLDP_STAT_OPT;
        }

        switch (type) {

            // Mandatory TLVs

            /* Chassis Id */
            case LLDP_TLV_CHASSIS_ID: {

                /* Chassis Id subtype */
                uint8_t subtype;
                LLDP_READ_U8(&t2buf, &subtype);

                switch (subtype) {

                    case LLDP_CID_CHASSIS_COMP: /* Chassis component */
                    case LLDP_CID_IF_ALIAS:     /* Interface alias   */
                    case LLDP_CID_IF_NAME:      /* Interface name    */
                    case LLDP_CID_LOCAL: {      /* Locally assigned  */
                        LLDP_CHECK_MIN_LEN(len, 2);
                        LLDP_READ_STR(&t2buf, lldpFlowP->chassis, len-1, LLDP_STRLEN);
                        break;
                    }

                    case LLDP_CID_PORT_COMP: {  /* Port component */
                        LLDP_CHECK_MIN_LEN(len, 2);
                        LLDP_READ_HEX(&t2buf, lldpFlowP->chassis, len-1, LLDP_STRLEN);
                        break;
                    }

                    /* MAC address */
                    case LLDP_CID_MAC_ADDR: {
                        LLDP_CHECK_MIN_LEN(len, 7);
                        uint8_t mac[len];
                        LLDP_READ_STR(&t2buf, mac, len-1, LLDP_STRLEN);
                        size_t dsize = 2*(len-1)+6;
                        if (dsize > sizeof(lldpFlowP->chassis)) {
                            lldpFlowP->lldpStat |= LLDP_STAT_STR;
                            dsize = sizeof(lldpFlowP->chassis);
                        }
                        t2_mac_to_str(mac, lldpFlowP->chassis, sizeof(lldpFlowP->chassis));
                        break;
                    }

                    /* Network address */
                    case LLDP_CID_NET_ADDR: {
                        uint8_t family;
                        LLDP_READ_U8(&t2buf, &family);
                        if (family == 1) { // IPv4
                            uint32_t ip;
                            LLDP_READ_LE_U32(&t2buf, &ip);
                            inet_ntop(AF_INET, &ip, lldpFlowP->chassis, LLDP_STRLEN);
                        } else if (family == 2) { // IPv6
                            uint8_t ip[16];
                            LLDP_READ_N(&t2buf, ip, 16);
                            inet_ntop(AF_INET6, ip, lldpFlowP->chassis, LLDP_STRLEN);
                        } else {
#if DEBUG > 0
                            T2_PERR(plugin_name, "Network address family %u not implemented", family);
#endif // DEBUG > 0
                            LLDP_CHECK_MIN_LEN(len, 3);
                            LLDP_READ_HEX(&t2buf, lldpFlowP->chassis, len-2, LLDP_STRLEN);
                            // 0: reserved
                            // 4: HDLC (8-bit multidrop)
                        }
                        break;
                    }

                    default:
#if DEBUG > 0
                        T2_PERR(plugin_name, "Chassis subtype %u not implemented (reserved)", subtype);
#endif // DEBUG > 0
                        lldpFlowP->lldpStat |= LLDP_STAT_RSVD;
                        LLDP_CHECK_MIN_LEN(len, 1);
                        t2buf_skip_n(&t2buf, len-1);
                        break;
                }
                break;
            } // LLDP_TLV_CHASSIS_ID

            /* Port Id */
            case LLDP_TLV_PORT_ID: {

                /* Port Id subtype */
                uint8_t subtype;
                LLDP_READ_U8(&t2buf, &subtype);

                switch (subtype) {

                    case LLDP_PID_IF_ALIAS: /* Interface alias  */
                    case LLDP_PID_IF_NAME:  /* Interface name   */
                    case LLDP_PID_LOCAL: {  /* Locally assigned */
                        LLDP_CHECK_MIN_LEN(len, 2);
                        LLDP_READ_STR(&t2buf, lldpFlowP->portID, len-1, LLDP_STRLEN);
                        break;
                    }

                    /* Port component */
                    case LLDP_PID_PORT_COMP: {
                        LLDP_CHECK_MIN_LEN(len, 2);
                        LLDP_READ_HEX(&t2buf, lldpFlowP->portID, len-1, LLDP_STRLEN);
                        break;
                    }

                    /* MAC address */
                    case LLDP_PID_MAC_ADDR: {
                        LLDP_CHECK_MIN_LEN(len, 2);
                        uint8_t mac[len];
                        LLDP_READ_STR(&t2buf, mac, len-1, LLDP_STRLEN);
                        size_t dsize = 2*(len-1)+6;
                        if (dsize > sizeof(lldpFlowP->portID)) {
                            lldpFlowP->lldpStat |= LLDP_STAT_STR;
                            dsize = sizeof(lldpFlowP->portID);
                        }
                        t2_mac_to_str(mac, lldpFlowP->portID, sizeof(lldpFlowP->portID));
                        break;
                    }

                    /* Network address */
                    case LLDP_PID_NET_ADDR: {
                        uint8_t family;
                        LLDP_READ_U8(&t2buf, &family);
                        if (family == 1) { // IPv4
                            uint32_t ip;
                            LLDP_READ_LE_U32(&t2buf, &ip);
                            inet_ntop(AF_INET, &ip, lldpFlowP->portID, LLDP_STRLEN);
                        } else if (family == 2) { // IPv6
                            uint8_t ip[16];
                            LLDP_READ_N(&t2buf, ip, 16);
                            inet_ntop(AF_INET6, ip, lldpFlowP->portID, LLDP_STRLEN);
                        } else {
#if DEBUG > 0
                            T2_PERR(plugin_name, "Network address family %u not implemented", family);
#endif // DEBUG > 0
                            LLDP_CHECK_MIN_LEN(len, 3);
                            LLDP_READ_HEX(&t2buf, lldpFlowP->portID, len-2, LLDP_STRLEN);
                        }
                        break;
                    }

                    /* Agent Circuit Id */
                    case LLDP_PID_CIRC_ID: // TODO
#if DEBUG > 0
                        T2_PERR(plugin_name, "Port subtype Agent Circuit ID not implemented");
#endif // DEBUG > 0
                        LLDP_CHECK_MIN_LEN(len, 2);
                        t2buf_skip_n(&t2buf, len-1);
                        break;

                    default:
#if DEBUG > 0
                        T2_PERR(plugin_name, "Port subtype %u not implemented (reserved)", subtype);
#endif // DEBUG > 0
                        lldpFlowP->lldpStat |= LLDP_STAT_RSVD;
                        LLDP_CHECK_MIN_LEN(len, 1);
                        t2buf_skip_n(&t2buf, len-1);
                        break;
                }
                break;
            }

            /* Time To Live */
            case LLDP_TLV_TTL: {
                LLDP_READ_U16(&t2buf, &ttl);
#if LLDP_TTL_AGGR == 1
                uint_fast32_t i;
                for (i = 0; i < lldpFlowP->numTTL; i++) {
                    if (ttl == lldpFlowP->ttl[i]) goto endttl;
                }
#endif // LLDP_TTL_AGGR == 1
                if (lldpFlowP->numTTL < LLDP_NUM_TTL) {
                    lldpFlowP->ttl[lldpFlowP->numTTL++] = ttl;
                } else {
                    lldpFlowP->lldpStat |= LLDP_STAT_TTL;
                }
#if LLDP_TTL_AGGR == 1
endttl:
                break;
#endif // LLDP_TTL_AGGR == 1
            }

            /* End of LLDPDU */
            case LLDP_TLV_END:
                break;

            // Optional TLVs

#if LLDP_OPT_TLV == 1
            /* Port Description */
            case LLDP_TLV_PORT_DESC: {
                LLDP_CHECK_MIN_LEN(len, 1);
                LLDP_READ_STR(&t2buf, lldpFlowP->portdesc, len, LLDP_STRLEN);
                break;
            }

            /* System Name */
            case LLDP_TLV_SYS_NAME: {
                LLDP_CHECK_MIN_LEN(len, 1);
                LLDP_READ_STR(&t2buf, lldpFlowP->sysname, len, LLDP_STRLEN);
                break;
            }

            /* System Description */
            case LLDP_TLV_SYS_DESC: {
                LLDP_CHECK_MIN_LEN(len, 1);
                LLDP_READ_STR(&t2buf, lldpFlowP->sysdesc, len, LLDP_LSTRLEN);
                break;
            }

            /* System Capabilities */
            case LLDP_TLV_SYS_CAPS: {
                /* Supported capabilities */
                uint16_t caps;
                LLDP_READ_U16(&t2buf, &caps);
                lldpFlowP->caps |= caps;
                /* Enabled capabilities */
                uint16_t enabled;
                LLDP_READ_U16(&t2buf, &enabled);
                lldpFlowP->enabledCaps |= enabled;
                break;
            }

            /* Management address */
            case LLDP_TLV_MNGMT_ADDR: {
                /* Management address string length */
                uint8_t addrLen;
                LLDP_READ_U8(&t2buf, &addrLen);
                /* Management address subtype */
                uint8_t family;
                LLDP_READ_U8(&t2buf, &family);
                /* Management address */
                if (family == 1) {
                    uint32_t ip;
                    LLDP_READ_LE_U32(&t2buf, &ip);
                    inet_ntop(AF_INET, &ip, lldpFlowP->mngmtAddr, LLDP_STRLEN);
                } else if (family == 2) { // IPv6
                    uint8_t ip[16];
                    LLDP_READ_N(&t2buf, ip, 16);
                    inet_ntop(AF_INET6, ip, lldpFlowP->mngmtAddr, LLDP_STRLEN);
                } else {
#if DEBUG > 0
                    T2_PERR(plugin_name, "Network address family %u not implemented", family);
#endif // DEBUG > 0
                    LLDP_CHECK_MIN_LEN(addrLen, 2);
                    LLDP_READ_HEX(&t2buf, lldpFlowP->mngmtAddr, addrLen-1, LLDP_STRLEN);
                }
                /* Interface numbering subtype address */
                uint8_t iface_type;
                LLDP_READ_U8(&t2buf, &iface_type);
                /* Interface number */
                uint32_t iface;
                LLDP_READ_U32(&t2buf, &iface);
                /* OID string length */
                uint8_t oid_len;
                LLDP_READ_U8(&t2buf, &oid_len);
                if (oid_len > 1) {
                    /* Object identifier */
                    char oid[2*oid_len+1];
                    LLDP_READ_HEX(&t2buf, oid, oid_len, 2*oid_len);
                }
                //if (family == 1) {
                //    T2_WRN("Management Address: %u.%u.%u.%u", addr[0], addr[1], addr[2], addr[3]);
                //} else {
                //    T2_WRN("Management Address: %s", addr);
                //}
                break;
            }

            /* Organization specific */
            case LLDP_TLV_ORG_SPEC: {
//#if DEBUG > 0
//                T2_PERR(plugin_name, "Organization specific TLV not implemented");
//#endif // DEBUG > 0
                lldpFlowP->lldpStat |= LLDP_STAT_SPEC;
                /* Organization Unique Code (OUI) */
                char oui[7]; // 2*3 + 1
                LLDP_READ_HEX(&t2buf, oui, 3, 6);
                /* Subtype */
                uint8_t subtype;
                LLDP_READ_U8(&t2buf, &subtype);
                // TODO
                LLDP_CHECK_MIN_LEN(len, 4);
                t2buf_skip_n(&t2buf, len - 4);
                break;
            }
#endif // LLDP_OPT_TLV == 1

            default:
                if (type > LLDP_TLV_MNGMT_ADDR && type < LLDP_TLV_ORG_SPEC) {
                    lldpFlowP->lldpStat |= LLDP_STAT_RSVD;
                } else if (type > LLDP_TLV_ORG_SPEC) {
                    lldpFlowP->lldpStat |= LLDP_STAT_UNK;
#if DEBUG > 0
                    T2_PERR(plugin_name, "Unhandled TLV type %u", type);
#endif // DEBUG > 0
                }
                t2buf_skip_n(&t2buf, len);
                break;
        }
    }

    if (mandatory != 0x0f) lldpFlowP->lldpStat |= LLDP_STAT_MAND;

lldp_pktmd:
    if (!sPktFile) return;

    fprintf(sPktFile,
            "0x%"   B2T_PRIX16                     /* lldpStat        */ SEP_CHR
            "%"     PRIu16                         /* lldpTTL         */ SEP_CHR
            "0x%08" B2T_PRIX32                     /* lldpTLVTypes    */ SEP_CHR
            "%s"                                   /* lldpChassis     */ SEP_CHR
            "%s"                                   /* lldpPort        */ SEP_CHR
#if LLDP_OPT_TLV == 1
            "%s"                                   /* lldpPortDesc    */ SEP_CHR
            "%s"                                   /* lldpSysName     */ SEP_CHR
            "0x%04" B2T_PRIX16 "_0x%04" B2T_PRIX16 /* lldpCaps_enCaps */ SEP_CHR
            "%s"                                   /* lldpMngmtAddr   */ SEP_CHR
#endif // LLDP_OPT_TLV == 1
            , lldpFlowP->lldpStat, ttl, lldpFlowP->lldpTLVTypes, lldpFlowP->chassis, lldpFlowP->portID
#if LLDP_OPT_TLV == 1
            , lldpFlowP->portdesc, lldpFlowP->sysname, lldpFlowP->caps, lldpFlowP->enabledCaps, lldpFlowP->mngmtAddr
#endif // LLDP_OPT_TLV == 1
    );
}


void t2OnLayer4(packet_t* packet UNUSED, unsigned long flowIndex UNUSED) {
    LLDP_SPKT_PRI_NONE();
}


void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {
    const lldpFlow_t * const lldpFlowP = &lldpFlows[flowIndex];

    lldpStat |= lldpFlowP->lldpStat;
    lldpCaps |= lldpFlowP->caps;
    lldpEnCaps |= lldpFlowP->enabledCaps;
    lldpTLVTypes |= lldpFlowP->lldpTLVTypes;

    OUTBUF_APPEND_U16(buf, lldpFlowP->lldpStat);
    OUTBUF_APPEND_ARRAY_U16(buf, lldpFlowP->ttl, lldpFlowP->numTTL);
    OUTBUF_APPEND_U32(buf, lldpFlowP->lldpTLVTypes);
    // Mandatory TLVs
    OUTBUF_APPEND_STR(buf, lldpFlowP->chassis);
    OUTBUF_APPEND_STR(buf, lldpFlowP->portID);
#if LLDP_OPT_TLV == 1
    OUTBUF_APPEND_STR(buf, lldpFlowP->portdesc);
    OUTBUF_APPEND_STR(buf, lldpFlowP->sysname);
    OUTBUF_APPEND_STR(buf, lldpFlowP->sysdesc);
    OUTBUF_APPEND_U16(buf, lldpFlowP->caps);
    OUTBUF_APPEND_U16(buf, lldpFlowP->enabledCaps);
    OUTBUF_APPEND_STR(buf, lldpFlowP->mngmtAddr);
#endif // LLDP_OPT_TLV == 1
}


static inline void lldp_pluginReport(FILE *stream) {
    if (numLldpPkts) {
        T2_FPLOG_AGGR_HEX(stream, plugin_name, lldpStat);
        T2_FPLOG_AGGR_HEX(stream, plugin_name, lldpTLVTypes);
        T2_FPLOG(stream, plugin_name, "Aggregated lldpCaps=0x%04" B2T_PRIX16 ", lldpEnCaps=0x%04" B2T_PRIX16, lldpCaps, lldpEnCaps);
        T2_FPLOG_DIFFNUMP(stream, plugin_name, "Number of LLDP packets", numLldpPkts, numPackets);
    }
}


void t2Monitoring(FILE *stream, uint8_t state) {
    switch (state) {

        case T2_MON_PRI_HDR:
            fputs("lldpPkts" SEP_CHR
                  , stream);
            return;

        case T2_MON_PRI_VAL:
            fprintf(stream,
                    "%" PRIu64 /* lldpPkts */ SEP_CHR
                    , numLldpPkts - numLldpPkts0);
            break;

        case T2_MON_PRI_REPORT:
            lldp_pluginReport(stream);
            break;

        // Invalid state, do nothing
        default:
            return;
    }

#if DIFF_REPORT == 1
    numLldpPkts0 = numLldpPkts;
#endif // DIFF_REPORT == 1
}


void t2PluginReport(FILE *stream) {
#if DIFF_REPORT == 1
    numLldpPkts0 = 0;
#endif // DIFF_REPORT == 1
    lldp_pluginReport(stream);
}


void t2Finalize() {
    free(lldpFlows);
}

#endif // ETH_ACTIVATE > 0
