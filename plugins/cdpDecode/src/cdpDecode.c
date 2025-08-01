/*
 * cdpDecode.c
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

#include "cdpDecode.h"
#include "proto/ethertype.h"
#include "t2buf.h"


// plugin variables

cdpFlow_t *cdpFlows;


#if ETH_ACTIVATE > 0

// Static variables

static uint64_t numCdpPkts, numCdpPkts0;
static uint32_t cdpTLVTypes, cdpCaps;
static uint8_t cdpStat;


#define CDP_SPKTMD_PRI_NONE() \
    if (sPktFile) { \
        fputs("0x00" /* cdpStat        */ SEP_CHR \
                     /* cdpVer         */ SEP_CHR \
                     /* cdpTTL         */ SEP_CHR \
                     /* cdpTLVTypes    */ SEP_CHR \
                     /* cdpDevice      */ SEP_CHR \
                     /* cdpPlatform    */ SEP_CHR \
                     /* cdpPortID      */ SEP_CHR \
                     /* cdpCaps        */ SEP_CHR \
                     /* cdpDuplex      */ SEP_CHR \
                     /* cdpNVLAN       */ SEP_CHR \
                     /* cdpVoipVLAN    */ SEP_CHR \
                     /* cdpVTPMngmtDmn */ SEP_CHR \
                     /* cdpMAddrs      */ SEP_CHR \
                     /* cdpAddrs       */ SEP_CHR \
              , sPktFile); \
    }

#define CDP_READ_STR(t2buf, dest, len, maxlen) { \
    const size_t read = MIN(len, maxlen); \
    if (read != len) { \
        cdpFlowP->cdpStat |= CDP_STAT_STR; \
    } \
    if (!t2buf_read_n(t2buf, (uint8_t*)dest, read)) { \
        cdpFlowP->cdpStat |= CDP_STAT_SNAP; \
        goto cdp_pktout; \
    } \
    dest[read] = '\0'; \
    if (read != len) CDP_SKIP_N(t2buf, len - read); \
}

#define CDP_CHECK_MIN_LEN(len, min) \
    if (len < min) { \
        cdpFlowP->cdpStat |= CDP_STAT_LEN; \
        goto cdp_pktout; \
    }

#endif // ETH_ACTIVATE > 0


// Tranalyzer functions

T2_PLUGIN_INIT("cdpDecode", "0.9.3", 0, 9);


void t2Init() {
#if ETH_ACTIVATE == 0
    T2_PWRN(plugin_name, "ETH_ACTIVATE is set to 0 in 'networkHeaders.h', no output will be produced");
#else // ETH_ACTIVATE > 0
    T2_PLUGIN_STRUCT_NEW(cdpFlows);
    if (sPktFile) {
        fputs("cdpStat"        SEP_CHR
              "cdpVer"         SEP_CHR
              "cdpTTL"         SEP_CHR
              "cdpTLVTypes"    SEP_CHR
              "cdpDevice"      SEP_CHR
              "cdpPlatform"    SEP_CHR
              "cdpPortID"      SEP_CHR
              "cdpCaps"        SEP_CHR
              "cdpDuplex"      SEP_CHR
              "cdpNVLAN"       SEP_CHR
              "cdpVoipVLAN"    SEP_CHR
              "cdpVTPMngmtDmn" SEP_CHR
              "cdpMAddrs"      SEP_CHR
              "cdpAddrs"       SEP_CHR
              , sPktFile);
    }
#endif // ETH_ACTIVATE
}


// If ETH_ACTIVATE == 0, the plugin does not produce any output.
// All the code below is therefore not activated.


#if ETH_ACTIVATE > 0

binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;
    BV_APPEND_H8(bv,    "cdpStat"         , "CDP status");
    BV_APPEND_U8(bv,    "cdpVer"          , "CDP version");
    BV_APPEND_U8(bv,    "cdpTTL"          , "CDP Time To Live (sec)");
    BV_APPEND_H32(bv,   "cdpTLVTypes"     , "CDP TLV types");
    BV_APPEND_STRC(bv,  "cdpDevice"       , "CDP device ID");
    BV_APPEND_STR(bv,   "cdpPlatform"     , "CDP platform");
    BV_APPEND_STR(bv,   "cdpSWVersion"    , "CDP Software Version");
    BV_APPEND_STRC(bv,  "cdpPortID"       , "CDP port ID");
    BV_APPEND_H32(bv,   "cdpCaps"         , "CDP capabilities");
    BV_APPEND_H8(bv,    "cdpDuplex"       , "CDP duplex");
    BV_APPEND_U16(bv,   "cdpNVLAN"        , "CDP native VLAN");
    BV_APPEND_U16(bv,   "cdpVoipVLAN"     , "CDP VoIP VLAN");
    BV_APPEND_STRC(bv,  "cdpVTPMngmtDmn"  , "CDP VTP management domain");
    BV_APPEND_IP4_R(bv, "cdpMAddrs"       , "CDP management addresses");
    BV_APPEND_IP4_R(bv, "cdpAddrs"        , "CDP addresses");
    BV_APPEND_R(bv,     "cdpIPPref_cdr"   , "CDP IP prefix, CIDR", 2, bt_ip4_addr, bt_uint_8);
    return bv;
}


void t2OnNewFlow(packet_t *packet, unsigned long flowIndex) {
    cdpFlow_t * const cdpFlowP = &cdpFlows[flowIndex];
    memset(cdpFlowP, '\0', sizeof(*cdpFlowP));

    if (packet->ethType != ETHERTYPE_CDP) return;

    cdpFlowP->cdpStat |= CDP_STAT_CDP;
}


void t2OnLayer2(packet_t *packet, unsigned long flowIndex) {
    if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;

    cdpFlow_t * const cdpFlowP = &cdpFlows[flowIndex];
    if (packet->ethType != ETHERTYPE_CDP) {
        CDP_SPKTMD_PRI_NONE()
        return;
    }

    numCdpPkts++;

    const uint16_t snaplen = packet->snapL7Len;
    const uint8_t * const l7hdr = packet->l7HdrP;
    t2buf_t t2buf = t2buf_create(l7hdr, snaplen);

    /* Version */
    CDP_READ_U8(&t2buf, &cdpFlowP->version);

    /* TTL */
    CDP_READ_U8(&t2buf, &cdpFlowP->ttl);

    /* Checksum */
    CDP_SKIP_U16(&t2buf);

    uint32_t addr = 0, maddr = 0;
    uint16_t type;
    while (t2buf_left(&t2buf) > 3) {

        CDP_READ_U16(&t2buf, &type);

        uint16_t len;
        CDP_READ_U16(&t2buf, &len);

        CDP_CHECK_MIN_LEN(len, 4);

        len -= 4; // length include type and length fields (4 bytes)

        if (type < 31) {
            cdpFlowP->cdpTLVTypes |= (1U << type);
        } else {
            cdpFlowP->cdpTLVTypes |= 0x80000000;
        }

        switch (type) {

            case CDP_TLV_DEVICE_ID:
                CDP_READ_STR(&t2buf, cdpFlowP->device, len, CDP_STRLEN);
                break;

            case CDP_TLV_ADDRESSES: {
                uint32_t naddr;
                CDP_READ_U32(&t2buf, &naddr);
                for (uint_fast32_t i = 0; i < naddr; i++) {
                    uint8_t ptype;
                    CDP_READ_U8(&t2buf, &ptype);
                    uint8_t plen;
                    CDP_READ_U8(&t2buf, &plen);
                    uint8_t proto;
                    CDP_READ_U8(&t2buf, &proto);
                    uint16_t alen;
                    CDP_READ_U16(&t2buf, &alen);
                    if (cdpFlowP->naddr < CDP_NADDR) {
                        CDP_READ_LE_U32(&t2buf, &addr);
                        for (uint_fast32_t j = 0; j < cdpFlowP->naddr; j++) {
                            if (cdpFlowP->addr[j] == addr) goto aexist;
                        }
                        cdpFlowP->addr[cdpFlowP->naddr++] = addr;
                    }
aexist:             ;
                }
                break;
            }

            case CDP_TLV_PORT_ID:
                CDP_READ_STR(&t2buf, cdpFlowP->port, len, CDP_STRLEN);
                break;

            case CDP_TLV_CAPS: {
                uint32_t caps;
                CDP_READ_U32(&t2buf, &caps);
                cdpFlowP->cdpCaps |= caps;
                break;
            }

            case CDP_TLV_SW_VERSION: {
                CDP_READ_STR(&t2buf, cdpFlowP->swver, len, CDP_LSTRLEN);
                break;
            }

            case CDP_TLV_PLATFORM:
                CDP_READ_STR(&t2buf, cdpFlowP->platform, len, CDP_STRLEN);
                break;

            case CDP_TLV_IP_PREFIXES:
                while (t2buf_left(&t2buf) > 4 && len != 0) {
                    if (cdpFlowP->nippg < CDP_NIPPG) {
                        uint32_t net;
                        CDP_READ_LE_U32(&t2buf, &net);
                        uint8_t mask;
                        CDP_READ_U8(&t2buf, &mask);
                        for (uint_fast32_t j = 0; j < cdpFlowP->nippg; j++) {
                            if (cdpFlowP->IPPG[j] == net && cdpFlowP->IPPGcdr[j] == mask) goto iexist;
                        }
                        cdpFlowP->IPPG[cdpFlowP->nippg] = net;
                        cdpFlowP->IPPGcdr[cdpFlowP->nippg++] = mask;
                    }
iexist:
                    CDP_CHECK_MIN_LEN(len, 5);
                    len -= 5;
                }
                break;

            /* Protocol Hello */
            //case CDP_TLV_PROTO_HELLO: {
            //    /* OUI */
            //    uint8_t oui[3];
            //    CDP_READ_N(&t2buf, oui, 3);
            //    /* Protocol ID */
            //    uint16_t protoid;
            //    CDP_READ_U16(&t2buf, &protoid);
            //    // TODO (proto dependent)
            //    CDP_CHECK_MIN_LEN(len, 5);
            //    CDP_SKIP_N(&t2buf, len-5);
            //    break;
            //}

            case CDP_TLV_VTP_MNGMT:
                CDP_READ_STR(&t2buf, cdpFlowP->vtpdom, len, CDP_STRLEN);
                break;

            case CDP_TLV_NATIVE_VLAN:
                CDP_READ_U16(&t2buf, &cdpFlowP->vlan);
                break;

            case CDP_TLV_DUPLEX: {
                uint8_t duplex;
                CDP_READ_U8(&t2buf, &duplex);
                cdpFlowP->duplex |= (1 << duplex);
                break;
            }

            case CDP_TLV_VOIP_VLAN_R: {
                uint8_t data;
                CDP_READ_U8(&t2buf, &data);
                CDP_READ_U16(&t2buf, &cdpFlowP->voipVlan);
                break;
            }

            /* Power Consumption (mW) */
            //case CDP_TLV_POWER_CONS: {
            //    uint16_t pwcons;
            //    CDP_READ_U16(&t2buf, &pwcons);
            //    break;
            //}

            /* Trust Bitmap */
            //case CDP_TLV_TRUST_BMAP: {
            //    uint8_t bmap;
            //    CDP_READ_U8(&t2buf, &bmap);
            //    break;
            //}

            /* Untrusted port CoS */
            //case CDP_TLV_UNTRUST_PORT: {
            //    uint8_t cos;
            //    CDP_READ_U8(&t2buf, &cos);
            //    break;
            //}

            case CDP_TLV_MNGMT_ADDR: {
                uint32_t naddr;
                CDP_READ_U32(&t2buf, &naddr);
                for (uint_fast32_t i = 0; i < naddr; i++) {
                    /* Protocol type */
                    uint8_t ptype;
                    CDP_READ_U8(&t2buf, &ptype);
                    /* Protocol length */
                    uint8_t plen;
                    CDP_READ_U8(&t2buf, &plen);
                    /* Protocol */
                    uint8_t proto;
                    CDP_READ_U8(&t2buf, &proto);
                    /* Address length */
                    uint16_t alen;
                    CDP_READ_U16(&t2buf, &alen);
                    /* Address */
                    if (cdpFlowP->nmaddr < CDP_NMADDR) {
                        CDP_READ_LE_U32(&t2buf, &maddr);
                        for (uint_fast32_t j = 0; j < cdpFlowP->nmaddr; j++) {
                            if (cdpFlowP->maddr[j] == maddr) goto bexist;
                        }
                        cdpFlowP->maddr[cdpFlowP->nmaddr++] = maddr;
                    }
bexist:             ;
                }
                break;
            }

            /* Power Requested (mW) */
            //case CDP_TLV_POWER_REQ: {
            //    /* Request-ID */
            //    uint16_t reqid;
            //    CDP_READ_U16(&t2buf, &reqid);
            //    /* Management-ID */
            //    uint16_t mngmtid;
            //    CDP_READ_U16(&t2buf, &mngmtid);
            //    /* Power Requested */
            //    uint16_t pwreq;
            //    CDP_READ_U16(&t2buf, &pwreq);
            //    break;
            //}

            /* Power Available (mW) */
            //case CDP_TLV_POWER_AVAIL: {
            //    /* Request-ID */
            //    uint16_t reqid;
            //    CDP_READ_U16(&t2buf, &reqid);
            //    /* Management-ID */
            //    uint16_t mngmtid;
            //    CDP_READ_U16(&t2buf, &mngmtid);
            //    // TODO check whether the two values are really min/max
            //    /* Power Available */
            //    uint32_t pwmin;
            //    CDP_READ_U32(&t2buf, &pwmin);
            //    /* Power Available */
            //    uint32_t pwmax;
            //    CDP_READ_U32(&t2buf, &pwmax);
            //    break;
            //}

            // Not implemented
            case CDP_TLV_VOIP_VLAN_Q:
            // Those are implemented above, but not used
            case CDP_TLV_PROTO_HELLO:
            case CDP_TLV_POWER_CONS:
            case CDP_TLV_UNTRUST_PORT:
            case CDP_TLV_TRUST_BMAP:
            case CDP_TLV_POWER_REQ:
            case CDP_TLV_POWER_AVAIL:
                CDP_SKIP_N(&t2buf, len);
                break;

            default:
#if DEBUG > 0
                T2_PWRN(plugin_name, "%" PRIu64 " Unhandled TLV type 0x%04" B2T_PRIX16, numPackets, type);
#endif // DEBUG > 0
                CDP_SKIP_N(&t2buf, len);
                break;
        }
    }

cdp_pktout:

    if (!sPktFile) return;

    char ip[INET_ADDRSTRLEN], mip[INET_ADDRSTRLEN];
    t2_ipv4_to_str(*(struct in_addr*)&maddr, mip, INET_ADDRSTRLEN);
    t2_ipv4_to_str(*(struct in_addr*)&addr, ip, INET_ADDRSTRLEN);

    fprintf(sPktFile,
            "0x%02" B2T_PRIX8  /* cdpStat        */ SEP_CHR
            "%"     PRIu8      /* cdpVer         */ SEP_CHR
            "%"     PRIu8      /* cdpTTL         */ SEP_CHR
            "%"     PRIu16     /* cdpTLVTypes    */ SEP_CHR
            "%s"               /* cdpDevice      */ SEP_CHR
            "%s"               /* cdpPlatform    */ SEP_CHR
            "%s"               /* cdpPortID      */ SEP_CHR
            "0x%08" B2T_PRIX32 /* cdpCaps        */ SEP_CHR
            "0x%02" B2T_PRIX8  /* cdpDuplex      */ SEP_CHR
            "%"     PRIu16     /* cdpNVLAN       */ SEP_CHR
            "%"     PRIu16     /* cdpVoipVLAN    */ SEP_CHR
            "%s"               /* cdpVTPMngmtDmn */ SEP_CHR
            "%s"               /* cdpMAddrs      */ SEP_CHR
            "%s"               /* cdpAddrs       */ SEP_CHR
            , cdpFlowP->cdpStat, cdpFlowP->version, cdpFlowP->ttl,
              ntohs(type), cdpFlowP->device, cdpFlowP->platform,
              cdpFlowP->port, cdpFlowP->cdpCaps, cdpFlowP->duplex,
              cdpFlowP->vlan, cdpFlowP->voipVlan, cdpFlowP->vtpdom,
              mip, ip);
}


void t2OnLayer4(packet_t* packet UNUSED, unsigned long flowIndex UNUSED) {
    CDP_SPKTMD_PRI_NONE()
}


void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {
    const cdpFlow_t * const cdpFlowP = &cdpFlows[flowIndex];

    cdpStat |= cdpFlowP->cdpStat;
    cdpCaps |= cdpFlowP->cdpCaps;
    cdpTLVTypes |= cdpFlowP->cdpTLVTypes;

    OUTBUF_APPEND_U8(buf , cdpFlowP->cdpStat);       // cdpStat
    OUTBUF_APPEND_U8(buf , cdpFlowP->version);       // cdpVer
    OUTBUF_APPEND_U8(buf , cdpFlowP->ttl);           // cdpTTL
    OUTBUF_APPEND_U32(buf, cdpFlowP->cdpTLVTypes);   // cdpTLVTypes
    OUTBUF_APPEND_STR(buf, cdpFlowP->device);        // cdpDevice
    OUTBUF_APPEND_STR(buf, cdpFlowP->platform);      // cdpPlatform
    OUTBUF_APPEND_STR(buf, cdpFlowP->swver);         // cdpSWVersion
    OUTBUF_APPEND_STR(buf, cdpFlowP->port);          // cdpPortID
    OUTBUF_APPEND_U32(buf, cdpFlowP->cdpCaps);       // cdpCaps
    OUTBUF_APPEND_U8(buf , cdpFlowP->duplex);        // cdpDuplex
    OUTBUF_APPEND_U16(buf, cdpFlowP->vlan);          // cdpNVLAN
    OUTBUF_APPEND_U16(buf, cdpFlowP->voipVlan);      // cdpVoipVLAN
    OUTBUF_APPEND_STR(buf, cdpFlowP->vtpdom);        // cdpVTPMngmtDmn

    OUTBUF_APPEND_ARRAY_U32(buf, cdpFlowP->maddr, cdpFlowP->nmaddr); // cdpMAddrs
    OUTBUF_APPEND_ARRAY_U32(buf, cdpFlowP->addr , cdpFlowP->naddr);  // cdpAddrs

    // cdpIPPref_cdr
    OUTBUF_APPEND_NUMREP(buf, cdpFlowP->nippg);
    for (uint_fast8_t i = 0; i < cdpFlowP->nippg; i++) {
        OUTBUF_APPEND_U32(buf, cdpFlowP->IPPG[i]);
        OUTBUF_APPEND_U8(buf, cdpFlowP->IPPGcdr[i]);
    }
}


void t2Monitoring(FILE *stream, uint8_t state) {
    switch (state) {

        case T2_MON_PRI_HDR:
            fputs("cdpPkts" SEP_CHR
                  , stream);
            return;

        case T2_MON_PRI_VAL:
            fprintf(stream,
                    "%" PRIu64 /* cdpPkts */ SEP_CHR
                    , numCdpPkts - numCdpPkts0);
            break;

        case T2_MON_PRI_REPORT:
            T2_FPLOG_DIFFNUMP(stream, plugin_name, "Number of CDP packets", numCdpPkts, numPackets);
            break;

        // Invalid state, do nothing
        default:
            return;
    }

#if DIFF_REPORT == 1
    numCdpPkts0 = numCdpPkts;
#endif // DIFF_REPORT == 1
}


void t2PluginReport(FILE *stream) {
#if DIFF_REPORT == 1
    numCdpPkts0 = 0;
#endif // DIFF_REPORT == 1
    if (numCdpPkts) {
        T2_FPLOG_AGGR_HEX(stream, plugin_name, cdpStat);
        T2_FPLOG_AGGR_HEX(stream, plugin_name, cdpTLVTypes);
        T2_FPLOG_AGGR_HEX(stream, plugin_name, cdpCaps);
        T2_FPLOG_DIFFNUMP(stream, plugin_name, "Number of CDP packets", numCdpPkts, numPackets);
    }
}


void t2Finalize() {
    free(cdpFlows);
}

#endif // ETH_ACTIVATE > 0
