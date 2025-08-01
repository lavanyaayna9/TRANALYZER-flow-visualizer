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

#include "dhcpDecode.h"
#include "dhcp_utils.h"
#include "t2buf.h"
#include "memdebug.h"


// Global variables

dhcpFlow_t *dhcpFlow;


// Static variables

#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
static uint64_t numDHCPmsgT[DHCP_NUM_MSGT];
static uint64_t numDHCPPkts4;
static uint64_t numDHCPQR[2];
#endif

#if IPV6_ACTIVATE > 0
static uint64_t numDHCPmsgT6[DHCP_NUM_MSGT6];
static uint64_t numDHCPPkts6;
#endif

#if DHCP_FLAG_MAC == 1 && (IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2)
static hashMap_t *macMap;
static uint64_t *macArray;
#endif

static uint16_t dhcpStat;


// Typedefs

#if IPV6_ACTIVATE > 0
typedef ipAddr_t dhcp_ip_t;
#else // IPV6_ACTIVATE == 0
typedef ip4Addr_t dhcp_ip_t;
#endif // IPV6_ACTIVATE == 0


// Functions prototypes

#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
static void dhcp4decode(packet_t *packet, unsigned long flowIndex);
#endif

#if IPV6_ACTIVATE > 0
static void dhcp6decode(packet_t *packet, unsigned long flowIndex);
#endif


#define DHCP_SPKTMD_PRI_NONE() \
    if (sPktFile) { \
        fputs("0x0000" /* dhcpStat                               */ SEP_CHR \
                       /* dhcpMTypeBF/dhcpMType/dhcpMTypeNms     */ SEP_CHR \
                       /* dhcpHops                               */ SEP_CHR \
                       /* dhcpHWType                             */ SEP_CHR \
                       /* dhcpTransID                            */ SEP_CHR \
                       /* dhcpOptBF1_BF2_BF3/dhcpOpts/dhcpOptNms */ SEP_CHR \
                       /* dhcpLFlow                              */ SEP_CHR \
              , sPktFile); \
    }


// Tranalyzer functions

T2_PLUGIN_INIT("dhcpDecode", "0.9.3", 0, 9);


void t2Init() {
    T2_PLUGIN_STRUCT_NEW(dhcpFlow);

#if DHCP_FLAG_MAC == 1 && (IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2)
    macMap = hashTable_init(1.0f, sizeof(dhcp_ip_t), "dhcp");
    macArray = t2_calloc_fatal(macMap->hashChainTableSize, sizeof(*macArray));
#endif

    if (sPktFile) {
        fputs("dhcpStat"           SEP_CHR
#if DHCPMOTOUT == 0
              "dhcpMTypeBF"        SEP_CHR
#elif DHCPMOTOUT == 1
              "dhcpMType"          SEP_CHR
#else // DHCPMOTOUT > 1
              "dhcpMTypeNms"       SEP_CHR
#endif // DHCPMOTOUT
              "dhcpHops"           SEP_CHR
              "dhcpHWType"         SEP_CHR
              "dhcpTransID"        SEP_CHR
#if DHCPMOTOUT == 0
              "dhcpOptBF1_BF2_BF3" SEP_CHR
#elif DHCPMOTOUT == 1
              "dhcpOpts"           SEP_CHR
#else // DHCPMOTOUT > 1
              "dhcpOptNms"         SEP_CHR
#endif // DHCPMOTOUT
              "dhcpLFlow"          SEP_CHR
              , sPktFile);
    }
}


binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;

    BV_APPEND_H16(bv , "dhcpStat"  , "DHCP status");

#if DHCPMOTOUT == 0
    BV_APPEND_H32(bv, "dhcpMTypeBF" , "DHCP message type bitfield");
#elif DHCPMOTOUT == 1
    BV_APPEND_U8_R(bv, "dhcpMType", "DHCP message types");
#else // DHCPMOTOUT > 1
    BV_APPEND_STRC_R(bv, "dhcpMTypeNms", "DHCP message type names");
#endif // DHCPMOTOUT
    BV_APPEND_H64(bv , "dhcpHWType", "DHCP hardware type");

#if DHCP_ADD_CNT == 1
    BV_APPEND_R(bv, "dhcpCHWAdd_HWCnt", "DHCP client hardware addresses and count", 2, bt_mac_addr, bt_uint_32);
#else // DHCP_ADD_CNT == 0
    BV_APPEND_MAC_R(bv, "dhcpCHWAdd", "DHCP client hardware addresses");
#endif // DHCP_ADD_CNT == 0

#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
    BV_APPEND_TYPE(bv, "dhcpNetmask" , "DHCP network mask", DHCPMASKTYP);
    BV_APPEND_IP4(bv , "dhcpGWIP"    , "DHCP gateway IP");
    BV_APPEND_IP4(bv , "dhcpDnsIP"   , "DHCP DNS");
    BV_APPEND_H32(bv , "dhcpHopCnt"  , "DHCP hop count");
    BV_APPEND_STR(bv , "dhcpSrvName" , "DHCP server host name");
    BV_APPEND_STR(bv , "dhcpBootFile", "DHCP boot file name");
    BV_APPEND_U16(bv , "dhcpOptCnt"  , "DHCP option count");
#if DHCPMOTOUT == 0
    BV_APPEND(bv, "dhcpOptBF1_BF2_BF3", "DHCP options bitfield", 3, bt_hex_64, bt_hex_64, bt_hex_64);
#elif DHCPMOTOUT == 1
    BV_APPEND_U8_R(bv, "dhcpOpts", "DHCP options");
#else // DHCPMOTOUT > 1
    BV_APPEND_STR_R(bv, "dhcpOptNms", "DHCP option names");
#endif // DHCPMOTOUT
#if DHCP_ADD_CNT == 1
    BV_APPEND_R(bv, "dhcpHosts_HCnt", "DHCP hosts and count", 2, bt_string, bt_uint_16);
#else // DHCP_ADD_CNT == 0
    BV_APPEND_STR_R(bv, "dhcpHosts", "DHCP hosts");
#endif // DHCP_ADD_CNT == 0
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2

#if DHCP_ADD_CNT == 1
    BV_APPEND_R(bv, "dhcpDomains_DCnt", "DHCP domains and count", 2, bt_string, bt_uint_16);
#else // DHCP_ADD_CNT == 0
    BV_APPEND_STR_R(bv, "dhcpDomains", "DHCP domains");
#endif // DHCP_ADD_CNT == 0

#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
    BV_APPEND_U16(bv, "dhcpMaxSecEl"  , "DHCP maximum seconds elapsed");
    BV_APPEND_U32(bv, "dhcpLeaseT"    , "DHCP lease time (seconds)");
    BV_APPEND_U32(bv, "dhcpRenewT"    , "DHCP renewal time (seconds)");
    BV_APPEND_U32(bv, "dhcpRebindT"   , "DHCP rebind time (seconds)");
    BV_APPEND_IP4(bv, "dhcpReqIP"     , "DHCP requested IP");
    BV_APPEND_IP4(bv, "dhcpCliIP"     , "DHCP client IP");
    BV_APPEND_IP4(bv, "dhcpYourIP"    , "DHCP your (client) IP");
    BV_APPEND_IP4(bv, "dhcpNextServer", "DHCP next server IP");
    BV_APPEND_IP4(bv, "dhcpRelay"     , "DHCP relay agent IP");
    BV_APPEND_IP4(bv, "dhcpSrvId"     , "DHCP server identifier");
    BV_APPEND_STR(bv, "dhcpMsg"       , "DHCP message");
    BV_APPEND_U64(bv, "dhcpLFlow"     , "DHCP linked flow");

#if DHCP_FLAG_MAC == 1
    BV_APPEND_MAC(bv, "dhcpSrcMac", "DHCP source MAC address");
    BV_APPEND_MAC(bv, "dhcpDstMac", "DHCP destination MAC address");
#endif

#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2

    return bv;
}


void t2OnNewFlow(packet_t* packet, unsigned long flowIndex) {
    dhcpFlow_t * const dhcpFlowP = &dhcpFlow[flowIndex];
    memset(dhcpFlowP, '\0', sizeof(dhcpFlow_t)); // set everything to 0

    flow_t * const flowP = &flows[flowIndex];
    if (flowP->l4Proto != L3_UDP) return;

    const uint_fast16_t sp = flowP->srcPort;
    const uint_fast16_t dp = flowP->dstPort;

    if (
#if IPV6_ACTIVATE > 0
            (sp == DHCP6UDPCP && dp == DHCP6UDPSP) ||
            (sp == DHCP6UDPSP && (dp == DHCP6UDPCP || dp == DHCP6UDPSP))
#endif
#if IPV6_ACTIVATE == 2
            ||
#endif
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
            (sp == DHCP4UDPCP && dp == DHCP4UDPSP) ||
            (sp == DHCP4UDPSP && (dp == DHCP4UDPCP || dp == DHCP4UDPSP))
#endif
        )
    {
        if (!FLOW_HAS_OPPOSITE(flowP) && PACKET_IS_IPV4(packet)) {
            const dhcpHeader_t * const dhcpHdr = (dhcpHeader_t*)packet->l7HdrP;
            if (dhcpHdr->opcode == 2) flowP->status |= L3FLOWINVERT; // boot reply should be a B flow
            else if (dhcpHdr->opcode == 1) flowP->status &= ~L3FLOWINVERT;
        }

        dhcpFlowP->dhcpStat = DHCPPRTDT;
    }
}


#if ETH_ACTIVATE > 0
void t2OnLayer2(packet_t *packet UNUSED, unsigned long flowIndex) {
    if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;
    DHCP_SPKTMD_PRI_NONE();
}
#endif


void t2OnLayer4(packet_t* packet, unsigned long flowIndex) {
    dhcpFlow_t * const dhcpFlowP = &dhcpFlow[flowIndex];
    if (!dhcpFlowP->dhcpStat) {
        DHCP_SPKTMD_PRI_NONE();
        return; // only DHCP
    }

    // only 1. frag packet will be processed
    if (!t2_is_first_fragment(packet)) {
        DHCP_SPKTMD_PRI_NONE();
        return;
    }

    if (PACKET_IS_IPV6(packet)) {
#if IPV6_ACTIVATE > 0
        numDHCPPkts6++;
        dhcp6decode(packet, flowIndex);
#endif
    } else { // IPv4
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
        numDHCPPkts4++;
        dhcp4decode(packet, flowIndex);
#endif
    }
}


#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
/**
 * Safe strlen which does not read further than max bytes.
 * Returns -1 if no NULL byte found in the first max bytes
 */
static ssize_t safe_strlen(const void *s, size_t max) {
    const void * const end = memchr(s, 0, max);
    return end == NULL ? -1 : end - s;
}
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2


#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
static void dhcp4decode(packet_t *packet, unsigned long flowIndex) {
    const uint16_t snaplen = packet->snapL7Len;
    if (snaplen < DHCP_HDRLEN) {
        DHCP_SPKTMD_PRI_NONE();
        return;
    }

    const dhcpHeader_t * const dhcpHdr = (dhcpHeader_t*)packet->l7HdrP;

    flow_t * const flowP = &flows[flowIndex];
    dhcpFlow_t * const dhcpFlowP = &dhcpFlow[flowIndex];

    if (UNLIKELY(dhcpHdr->opcode == 0 || dhcpHdr->opcode > 2)) {
        dhcpFlowP->dhcpStat |= DHCPMALFORMD; // Invalid opcode
    } else {
        dhcpFlowP->dhcpStat |= 1 << dhcpHdr->opcode; // 1: boot request, 2: boot reply
        numDHCPQR[dhcpHdr->opcode-1]++;
    }

    dhcpFlowP->hwType |= 1 << MIN(dhcpHdr->hwType, 63);

    if (dhcpHdr->hopCnt <= 16) dhcpFlowP->hopCnt |= 1 << dhcpHdr->hopCnt;
    else dhcpFlowP->hopCnt |= 1U << 31; // invalid hopcount

    if (dhcpHdr->flags & DHCPBCST) dhcpFlowP->dhcpStat |= DHCPBCAST;

    // XXX Most versions of Windows encode this field as little-endian...
    uint16_t secEl = ntohs(dhcpHdr->num_sec);
    if (secEl > dhcpHdr->num_sec) {
        dhcpFlowP->dhcpStat |= DHCPSECELNDIAN;
        secEl = dhcpHdr->num_sec;
    }
    if (secEl > dhcpFlowP->maxSecEl) dhcpFlowP->maxSecEl = secEl;

    dhcpFlowP->cliIP = dhcpHdr->clientIP;
    dhcpFlowP->yourIP = dhcpHdr->yourIP;
    dhcpFlowP->nextSrvr = dhcpHdr->servIP;
    dhcpFlowP->relay = dhcpHdr->gwIP;

    int_fast32_t i;
    // Client MAC address
    if (dhcpHdr->hwType != 1 || dhcpHdr->hwAddrLen != ETH_ALEN) {
        // Not a MAC address
        dhcpFlowP->dhcpStat |= DHCPNONETHHW;
    } else if (dhcpFlowP->HWAddCnt >= DHCPNMMAX) {
        dhcpFlowP->dhcpStat |= DHCPNMTRUNC;
    } else {
        for (i = 0; i < dhcpFlowP->HWAddCnt; i++) {
            // MAC address already seen
            if (dhcpFlowP->clHWAdd[i][0] == dhcpHdr->clientHWaddr[0] &&
                dhcpFlowP->clHWAdd[i][1] == dhcpHdr->clientHWaddr[1])
            {
                break;
            }
        }

        // MAC address was never seen
        if (i == dhcpFlowP->HWAddCnt) {
            dhcpFlowP->clHWAdd[i][0] = dhcpHdr->clientHWaddr[0];
            dhcpFlowP->clHWAdd[i][1] = dhcpHdr->clientHWaddr[1];
            dhcpFlowP->HWAddCnt++;
        }

#if DHCP_ADD_CNT == 1
        dhcpFlowP->clHWAdd[i][2]++;
#endif
    }

    // Server host name
    size_t len;
    ssize_t slen = safe_strlen((char*)dhcpHdr->servHostName, sizeof(dhcpHdr->servHostName));
    if (slen > 0) {
        len = MIN((size_t)slen, sizeof(dhcpFlowP->serverName)-1);
        memcpy(dhcpFlowP->serverName, dhcpHdr->servHostName, len);
        dhcpFlowP->serverName[len] = '\0';
    }

    // Boot file name
    slen = safe_strlen((char*)dhcpHdr->bootFname, sizeof(dhcpHdr->bootFname));
    if (slen > 0) {
        len = MIN((size_t)slen, sizeof(dhcpFlowP->bootFile)-1);
        memcpy(dhcpFlowP->bootFile, dhcpHdr->bootFname, len);
        dhcpFlowP->bootFile[len] = '\0';
    }

    // Magic cookie
    if (dhcpHdr->optMagNum != MAGICNUMBERn) {
        dhcpFlowP->dhcpStat |= DHCPMAGNUMERR;
        DHCP_SPKTMD_PRI_NONE();
        return;
    }

    const udpHeader_t * const udpHdrP = UDP_HEADER(packet);
    const int32_t dhcpOptLen = ntohs(udpHdrP->len) - DHCPOPTUDPOFF;
    if ((int32_t)(snaplen - DHCP_HDRLEN) < dhcpOptLen) {
        // warning: crafted packet or option field not acquired
        dhcpFlowP->dhcpStat |= DHCPOPTCORRPT;
        DHCP_SPKTMD_PRI_NONE();
        return;
    }

    // Process DHCP options

    const uint8_t * const dhcpOpt = (uint8_t *)dhcpHdr + DHCP_HDRLEN;

    uint8_t msgT = 0;
    for (i = 0; i < dhcpOptLen && dhcpOpt[i] && dhcpOpt[i] != DHCPOPTEND; i += dhcpOpt[i+1] + 2) {
        const uint8_t optC = dhcpOpt[i];
        const uint8_t optL = dhcpOpt[i+1];
        switch (optC) {

            case 1: // Subnet Mask
                dhcpFlowP->netMsk = *(uint32_t*)&dhcpOpt[i+2];
                break;

            case 3: // Router
                dhcpFlowP->gw = *(uint32_t*)&dhcpOpt[i+2];
                break;

            case 6: // Domain Name Server
                dhcpFlowP->dns = *(uint32_t*)&dhcpOpt[i+2];
                break;

            case 12: // Host Name
                if (dhcpFlowP->hostNCnt >= DHCPNMMAX) {
                    dhcpFlowP->dhcpStat |= DHCPNMTRUNC;
                } else {
                    uint_fast32_t j;
                    for (j = 0; j < dhcpFlowP->hostNCnt; j++) {
                        const size_t k = strlen(dhcpFlowP->hostN[j]);
                        // host name is sometimes null terminated...
                        if ((k == optL || k+1 == optL) && memcmp(dhcpFlowP->hostN[j], &dhcpOpt[i+2], k) == 0) break;
                    }
                    if (j == dhcpFlowP->hostNCnt) {
                        char *hostP = t2_malloc_fatal(optL+1);
                        memcpy(hostP, &dhcpOpt[i+2], optL);
                        hostP[optL] = '\0';
                        dhcpFlowP->hostN[dhcpFlowP->hostNCnt] = hostP;
                        dhcpFlowP->hostNCnt++;
                    }
#if DHCP_ADD_CNT == 1
                    dhcpFlowP->hostrep[j]++;
#endif
                }
                break;

            case 15: // Domain Name
                if (dhcpFlowP->domainNCnt >= DHCPNMMAX) {
                    dhcpFlowP->dhcpStat |= DHCPNMTRUNC;
                } else {
                    uint_fast32_t j;
                    for (j = 0; j < dhcpFlowP->domainNCnt; j++) {
                        const size_t k = strlen(dhcpFlowP->domainN[j]);
                        // domain name is sometimes null terminated...
                        if ((k == optL || k+1 == optL) && memcmp(dhcpFlowP->domainN[j], &dhcpOpt[i+2], k) == 0) break;
                    }
                    if (j == dhcpFlowP->domainNCnt) {
                        char *domainP = t2_malloc_fatal(optL+1);
                        memcpy(domainP, &dhcpOpt[i+2], optL);
                        domainP[optL] = '\0';
                        dhcpFlowP->domainN[dhcpFlowP->domainNCnt] = domainP;
                        dhcpFlowP->domainNCnt++;
                    }
#if DHCP_ADD_CNT == 1
                    dhcpFlowP->domainrep[j]++;
#endif
                }
                break;

            case 50: // Requested IP address
                dhcpFlowP->reqIP = *(uint32_t*)&dhcpOpt[i+2];
                break;

            case 51: // IP Address Lease Time
                dhcpFlowP->leaseT = *(uint32_t*)&dhcpOpt[i+2];
                break;

            case 52: // Option Overload
                dhcpFlowP->dhcpStat |= DHCPOPTOVERL;
                break;

            case 53: // DHCP Message Type
                msgT = dhcpOpt[i+2];
                if (msgT > DHCP_NUM_MSGT || msgT == 0) {
#if DHCP_FM_DEBUG == 1
                    T2_PWRN(plugin_name, "unhandled message type %" PRIu8, msgT);
#endif // DHCP_FM_DEBUG == 1
                    dhcpFlowP->dhcpStat |= DHCPMSGTPUNK;
                } else {
                    numDHCPmsgT[msgT-1]++;
#if DHCPMOTOUT == 0
                    dhcpFlowP->MType |= 1 << msgT;
#else // DHCPMOTOUT > 0
                    if (dhcpFlowP->msgTNum >= DHCPMSGMAX) {
                        dhcpFlowP->dhcpStat |= DHCPNMTRUNC;
                    } else {
                        for (uint_fast32_t j = 0; j < dhcpFlowP->msgTNum; j++) {
                            if (dhcpFlowP->msgT[j] == msgT) goto typex4;
                        }
                        dhcpFlowP->msgT[dhcpFlowP->msgTNum++] = msgT;
                    }
typex4: ;
#endif // DHCPMOTOUT
                }
                break;

            case 54: // Server Identifier
                dhcpFlowP->srvId = *(uint32_t*)&dhcpOpt[i+2];
                break;

            //case 55: // Parameter Request List

            case 56: // Message
                len = MIN(optL, sizeof(dhcpFlowP->msg)-1);
                memcpy(dhcpFlowP->msg, &dhcpOpt[i+2], len);
                dhcpFlowP->msg[len] = '\0';
                break;

            //case 57: // Maximum DHCP Message Size

            case 58: // Renewal Time Value
                dhcpFlowP->renewT = *(uint32_t*)&dhcpOpt[i+2];
                break;

            case 59: // Rebinding Time Value
                dhcpFlowP->rebindT = *(uint32_t*)&dhcpOpt[i+2];
                break;

            //case 60: // Vendor class identifier

            case 61: // Client Identifier
                if (dhcpOpt[i+2] != 0 && dhcpOpt[i+2] != 254) {
                    if (dhcpHdr->hwType != dhcpOpt[i+2] ||
                        memcmp(&dhcpHdr->clientHWaddr[0], &dhcpOpt[i+3], optL-1) != 0)
                    {
                        //T2_PWRN(plugin_name, "Client identifier different from client MAC address");
                        dhcpFlowP->dhcpStat |= DHCPMISCLID;
                    }
                } else {
                    // Client Identifier is not a MAC address (254: uuid, 0: fqdn)
                }
                break;

            //case 81: // Client Fully Qualified Domain Name
            //case 93: // Client System Architecture
            //case 94: // Client Network Device Interface
            //case 97: // UUID/GUID-based Client Identifier

            default:
                break;
        }

#if DHCPMOTOUT == 0
        if (optC < 64) dhcpFlowP->optT[2] |= (uint64_t)1 << (optC & DHCP64MSK);
        else if (optC < 128) dhcpFlowP->optT[1] |= (uint64_t)1 << ((optC - 64) & DHCP64MSK);
        else dhcpFlowP->optT[0] |= (uint64_t)1 << ((optC - 128) & DHCP64MSK);
#else // DHCPMOTOUT > 0
        if (dhcpFlowP->optNum >= DHCPOPTMAX) {
            dhcpFlowP->dhcpStat |= DHCPOPTTRUNC;
        } else {
            for (uint_fast32_t j = 0; j < dhcpFlowP->optNum; j++) {
                if (dhcpFlowP->opt[j] == optC) goto optex4;
            }
            dhcpFlowP->opt[dhcpFlowP->optNum++] = optC;
optex4:     ;
        }
#endif // DHCPMOTOUT

        dhcpFlowP->optCntT++;
    }

    // Missing End marker (0xff) in DHCP options
    if (dhcpOptLen > 0 && dhcpOpt[i] != DHCPOPTEND) dhcpFlowP->dhcpStat |= DHCPOPTCORRPT;

    if (msgT == DHCP_MSGT_REQUEST) {
        const uint16_t srcPort = ntohs(udpHdrP->source);
        const uint16_t dstPort = ntohs(udpHdrP->dest);
        const flow_t parent = {
#if ETH_ACTIVATE == 2
            .ethDS = ((ethernetHeader_t*)packet->l2HdrP)->ethDS,
#endif // ETH_ACTIVATE == 2
#if IPV6_ACTIVATE == 2 || ETH_ACTIVATE > 0
            .ethType = packet->ethType,
#endif // IPV6_ACTIVATE == 2 || ETH_ACTIVATE > 0
#if SCTP_ACTIVATE & 1
            .sctpStrm = flowP->sctpStrm,
#endif // SCTP_ACTIVATE & 1
#if SCTP_ACTIVATE & 2
            .sctpVtag = flowP->sctpVtag,
#endif // SCTP_ACTIVATE & 2
            .vlanId = flowP->vlanId,
            .srcIP.IPv4 = *(struct in_addr*)&dhcpFlowP->srvId,
            .dstIP.IPv4 = *(struct in_addr*)&dhcpFlowP->reqIP,
            .l4Proto = flowP->l4Proto,
            .srcPort = dstPort,
            .dstPort = srcPort,
        };
        const uint64_t hasParent = hashTable_lookup(mainHashMap, (char*)&parent.srcIP);
        if (hasParent != HASHTABLE_ENTRY_NOT_FOUND) {
            dhcpFlowP->lflow = flows[hasParent].findex;
            dhcpFlow[hasParent].lflow = flowP->findex;
        }
#if DHCP_FLAG_MAC == 1
    } else if (msgT == DHCP_MSGT_ACK) {
        const dhcp_ip_t cliIP = {
            .IPv4x[0] = (dhcpHdr->yourIP ? dhcpHdr->yourIP : dhcpHdr->clientIP)
        };
        const uint8_t cliMac[ETH_ALEN] = {
            (dhcpHdr->clientHWaddr[0] & 0x000000ff),
            (dhcpHdr->clientHWaddr[0] & 0x0000ff00) >>  8,
            (dhcpHdr->clientHWaddr[0] & 0x00ff0000) >> 16,
            (dhcpHdr->clientHWaddr[0] & 0xff000000) >> 24,
            (dhcpHdr->clientHWaddr[1] & 0x000000ff),
            (dhcpHdr->clientHWaddr[1] & 0x0000ff00) >>  8,
        };
#if DHCP_FM_DEBUG == 1
        char ipstr[INET_ADDRSTRLEN] = {};
        t2_ipv4_to_str(cliIP.IPv4, ipstr, INET_ADDRSTRLEN);
        char macNew[T2_MAC_STRLEN+1] = {};
        t2_mac_to_str(cliMac, macNew, sizeof(macNew));
#endif
        uint64_t mac_idx = hashTable_lookup(macMap, (char*)&cliIP);
        if (mac_idx == HASHTABLE_ENTRY_NOT_FOUND) {
            mac_idx = hashTable_insert(macMap, (char*)&cliIP);
            if (UNLIKELY(mac_idx == HASHTABLE_ENTRY_NOT_FOUND)) {
                // If hashMap is full, we stop adding entries...
                static bool warn = true;
                if (warn) {
                    T2_PWRN(plugin_name, "%s HashMap full", macMap->name);
                    warn = false;
                }
#if DHCP_FM_DEBUG == 1
            } else {
                T2_PINF(plugin_name, "Packet %" PRIu64 ": Added entry for IP %s: %s", numPackets, ipstr, macNew);
#endif
            }
#if DHCP_FM_DEBUG == 1
        } else {
            const uint64_t mac = macArray[mac_idx];
            if (mac != t2_mac_to_uint64(cliMac)) {
                uint8_t mac8[ETH_ALEN] = {};
                t2_uint64_to_mac(mac, mac8);
                char macOld[T2_MAC_STRLEN+1] = {};
                t2_mac_to_str(mac8, macOld, sizeof(macOld));
                T2_PWRN(plugin_name, "Packet %" PRIu64 ": An entry for IP %s already exists: %s (new value: %s)",
                        numPackets, ipstr, macOld, macNew);
            }
#endif // DHCP_FM_DEBUG == 1
        }

        if (LIKELY(mac_idx != HASHTABLE_ENTRY_NOT_FOUND)) {
            const uint64_t mac_u64 = t2_mac_to_uint64(cliMac);
            macArray[mac_idx] = mac_u64;
        }
    } else  if (msgT == DHCP_MSGT_DECLINE || msgT == DHCP_MSGT_RELEASE) {
        const dhcp_ip_t cliIP = {
            .IPv4x[0] = (dhcpHdr->yourIP ? dhcpHdr->yourIP : dhcpHdr->clientIP)
        };
#if DHCP_FM_DEBUG == 1
        char ipstr[INET_ADDRSTRLEN] = {};
        t2_ipv4_to_str(cliIP.IPv4, ipstr, INET_ADDRSTRLEN);
        T2_PINF(plugin_name, "Packet %" PRIu64 ": Removing entry for IP %s", numPackets, ipstr);
#endif
        hashTable_remove(macMap, (char*)&cliIP);
#endif // DHCP_FLAG_MAC == 1
    }

    if (sPktFile) {
        fprintf(sPktFile, "0x%04" B2T_PRIX16 SEP_CHR, dhcpFlowP->dhcpStat); // dhcpStat

        // dhcpMTypeBF/dhcpMType/dhcpMTypeNms
#if DHCPMOTOUT == 0
        fprintf(sPktFile, "%08" B2T_PRIX32 SEP_CHR, dhcpFlowP->MType);  // dhcpMTypeBF
#elif DHCPMOTOUT <= 1
        fprintf(sPktFile, "%" PRIu8 SEP_CHR, msgT);                     // dhcpMType
#else // DHCPMOTOUT > 1
        // dhcpMTypeNms
        if (msgT <= DHCP_NUM_MSGT) {
            fprintf(sPktFile, "%s" SEP_CHR, dhcpState53[msgT]);
        } else {
            fprintf(sPktFile, "%" PRIu8 SEP_CHR, msgT);
        }
#endif // DHCPMOTOUT

        // dhcpHops, dhcpHWType, dhcpTransID
        fprintf(sPktFile,
                "%"     PRIu8      /* dhcpHops    */ SEP_CHR
                "%"     PRIu8      /* dhcpHWType  */ SEP_CHR
                "0x%08" B2T_PRIX32 /* dhcpTransID */ SEP_CHR
                , dhcpHdr->hopCnt, dhcpHdr->hwType, ntohl(dhcpHdr->transID));

        // dhcpOptBF1_BF2_BF3/dhcpOpts/dhcpOptNms
#if DHCPMOTOUT == 0
        // dhcpOptBF1_BF2_BF3
        fprintf(sPktFile, "0x%016" B2T_PRIX64 "_0x%016" B2T_PRIX64 "_0x%016" B2T_PRIX64 SEP_CHR,
                dhcpFlowP->optT[0], dhcpFlowP->optT[1], dhcpFlowP->optT[2]);
#elif DHCPMOTOUT == 1
        // dhcpOpts
        const int32_t optNum = dhcpFlowP->optNum;
        for (int_fast32_t i = 0; i < optNum - 1; i++)
            fprintf(sPktFile, "%" PRIu8 ";", dhcpFlowP->opt[i]);
        fprintf(sPktFile, "%" PRIu8 SEP_CHR, dhcpFlowP->opt[optNum]);
#else // DHCPMOTOUT > 1
        // dhcpOptNms
        const int32_t optNum = dhcpFlowP->optNum;
        for (int_fast32_t i = 0; i < optNum - 1; i++)
            fprintf(sPktFile, "%s;", dhcpOptNm[dhcpFlowP->opt[i]]);
        fprintf(sPktFile, "%s" SEP_CHR, dhcpOptNm[dhcpFlowP->opt[optNum]]);
#endif // DHCPMOTOUT

        // dhcpLFlow
        if (dhcpFlowP->lflow) fprintf(sPktFile, "%" PRIu64, dhcpFlowP->lflow);

        fputs(/* dhcpLFlow */ SEP_CHR, sPktFile);
    }
}
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2


void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {
    dhcpFlow_t * const dhcpFlowP = &dhcpFlow[flowIndex];

    dhcpStat |= dhcpFlowP->dhcpStat;

    uint_fast32_t i;
    uint32_t j;

#if DHCPMOTOUT > 1 || ((IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2) && DHCP_FLAG_MAC == 1)
    const flow_t * const flowP = &flows[flowIndex];
#endif

    // dhcpStat
    OUTBUF_APPEND_U16(buf, dhcpFlowP->dhcpStat);

    // dhcpMType
#if DHCPMOTOUT == 0
    OUTBUF_APPEND_U32(buf, dhcpFlowP->MType);
#elif DHCPMOTOUT == 1
    OUTBUF_APPEND_ARRAY_U8(buf, dhcpFlowP->msgT, dhcpFlowP->msgTNum);
#else // DHCPMOTOUT > 1
    j = dhcpFlowP->msgTNum;
    OUTBUF_APPEND_NUMREP(buf, j);
    for (i = 0; i < j; i++) {
        if (FLOW_IS_IPV6(flowP)) OUTBUF_APPEND_STR(buf, dhcpMT6[dhcpFlowP->msgT[i]]);
        else OUTBUF_APPEND_STR(buf, dhcpState53[dhcpFlowP->msgT[i]]);
    }
#endif // DHCPMOTOUT

    // dhcpHWType
    OUTBUF_APPEND_U64(buf, dhcpFlowP->hwType);

    // dhcpCHWAdd / dhcpCHWAdd_HWCnt
    j = dhcpFlowP->HWAddCnt;
    OUTBUF_APPEND_NUMREP(buf, j);
    for (i = 0; i < j; i++) {
        OUTBUF_APPEND(buf, dhcpFlowP->clHWAdd[i][0], ETH_ALEN); // dhcpCHWAdd
#if DHCP_ADD_CNT == 1
        OUTBUF_APPEND_U32(buf, dhcpFlowP->clHWAdd[i][2]);       // dhcpHWCnt
#endif
    }

#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2

#if DHCPMASKFRMT == 0
    dhcpFlowP->netMsk = ntohl(dhcpFlowP->netMsk);
#endif

    OUTBUF_APPEND_U32(buf, dhcpFlowP->netMsk);     // dhcpNetmask
    OUTBUF_APPEND_U32(buf, dhcpFlowP->gw);         // dhcpGWIP
    OUTBUF_APPEND_U32(buf, dhcpFlowP->dns);        // dhcpDnsIP
    OUTBUF_APPEND_U32(buf, dhcpFlowP->hopCnt);     // dhcpHopCnt
    OUTBUF_APPEND_STR(buf, dhcpFlowP->serverName); // dhcpSrvName
    OUTBUF_APPEND_STR(buf, dhcpFlowP->bootFile);   // dhcpBootFile
    OUTBUF_APPEND_U16(buf, dhcpFlowP->optCntT);    // dhcpOptCnt

#if DHCPMOTOUT == 0
    // dhcpOptBF1_BF2_BF3
    OUTBUF_APPEND(buf, dhcpFlowP->optT, 3 * sizeof(uint64_t));
#elif DHCPMOTOUT == 1
    // dhcpOpts
    OUTBUF_APPEND_ARRAY_U8(buf, dhcpFlowP->opt, dhcpFlowP->optNum);
#else // DHCPMOTOUT > 1
    j = dhcpFlowP->optNum;
    OUTBUF_APPEND_NUMREP(buf, j);
    for (i = 0; i < j; i++) {
        OUTBUF_APPEND_STR(buf, dhcpOptNm[dhcpFlowP->opt[i]]);
    }
#endif // DHCPMOTOUT

    // dhcpHosts(_HCnt)
    j = dhcpFlowP->hostNCnt;
    OUTBUF_APPEND_NUMREP(buf, j);
    for (i = 0; i < j; i++) {
        OUTBUF_APPEND_STR(buf, dhcpFlowP->hostN[i]);
#if DHCP_ADD_CNT == 1
        OUTBUF_APPEND_U16(buf, dhcpFlowP->hostrep[i]);
#endif
        free(dhcpFlowP->hostN[i]);
    }

#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2

    // dhcpDomains(_DCnt)
    j = dhcpFlowP->domainNCnt;
    OUTBUF_APPEND_NUMREP(buf, j);
    for (i = 0; i < j; i++) {
        OUTBUF_APPEND_STR(buf, dhcpFlowP->domainN[i]);
#if DHCP_ADD_CNT == 1
        OUTBUF_APPEND_U16(buf, dhcpFlowP->domainrep[i]);
#endif
        free(dhcpFlowP->domainN[i]);
    }

#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
    // dhcpMaxSecEl
    OUTBUF_APPEND_U16(buf, dhcpFlowP->maxSecEl);

    // dhcpLeaseT
    dhcpFlowP->leaseT = ntohl(dhcpFlowP->leaseT);
    OUTBUF_APPEND_U32(buf, dhcpFlowP->leaseT);

    // dhcpRenewT
    dhcpFlowP->renewT = ntohl(dhcpFlowP->renewT);
    OUTBUF_APPEND_U32(buf, dhcpFlowP->renewT);

    // dhcpRebindT
    dhcpFlowP->rebindT = ntohl(dhcpFlowP->rebindT);
    OUTBUF_APPEND_U32(buf, dhcpFlowP->rebindT);

    OUTBUF_APPEND_U32(buf, dhcpFlowP->reqIP);    // dhcpReqIP
    OUTBUF_APPEND_U32(buf, dhcpFlowP->cliIP);    // dhcpCliIP
    OUTBUF_APPEND_U32(buf, dhcpFlowP->yourIP);   // dhcpYourIP
    OUTBUF_APPEND_U32(buf, dhcpFlowP->nextSrvr); // dhcpNextServer
    OUTBUF_APPEND_U32(buf, dhcpFlowP->relay);    // dhcpRelay
    OUTBUF_APPEND_U32(buf, dhcpFlowP->srvId);    // dhcpSrvId
    OUTBUF_APPEND_STR(buf, dhcpFlowP->msg);      // dhcpMsg
    OUTBUF_APPEND_U64(buf, dhcpFlowP->lflow);    // dhcpLFlow

#if DHCP_FLAG_MAC == 1
    //const flow_t * const flowP = &flows[flowIndex];
    const dhcp_ip_t ip[2] = { flowP->srcIP, flowP->dstIP };

    // dhcpSrcMac, dhcpDstMac
    for (i = 0; i < 2; i++) {
        const uint64_t mac_idx = hashTable_lookup(macMap, (char*)&ip[i]);
        if (mac_idx == HASHTABLE_ENTRY_NOT_FOUND) {
            OUTBUF_APPEND_MAC_ZERO(buf);
        } else {
            const uint64_t mac = macArray[mac_idx];
            uint8_t mac_u8[ETH_ALEN] = {};
            t2_uint64_to_mac(mac, mac_u8);
            OUTBUF_APPEND(buf, mac_u8, ETH_ALEN);
        }
    }
#endif // DHCP_FLAG_MAC == 1

#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
}


void t2PluginReport(FILE *stream) {
    char hrnum[64] = {};

    T2_FPLOG_AGGR_HEX(stream, plugin_name, dhcpStat);

#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
    if (numDHCPPkts4 > 0) {
        T2_FPLOG_NUMP0(stream, plugin_name, "Number of DHCP packets", numDHCPPkts4, numPackets);
        T2_FPLOG_NUMP(stream, plugin_name, "Number of DHCP queries", numDHCPQR[0], numDHCPPkts4);
        T2_FPLOG_NUMP(stream, plugin_name, "Number of DHCP replies", numDHCPQR[1], numDHCPPkts4);
        for (uint_fast32_t i = 0; i < DHCP_NUM_MSGT; i++) {
            if (numDHCPmsgT[i] > 0) {
                T2_CONV_NUM(numDHCPmsgT[i], hrnum);
                T2_FPLOG(stream, plugin_name, "Number of DHCP %s messages: %" PRIu64 "%s [%.2f%%]",
                        dhcpMsgTToStr[i], numDHCPmsgT[i], hrnum, 100.0*numDHCPmsgT[i]/(double)numDHCPPkts4);
            }
        }
    }
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2

#if IPV6_ACTIVATE > 0
    if (numDHCPPkts6 > 0) {
        T2_FPLOG_NUMP0(stream, plugin_name, "Number of DHCPv6 packets", numDHCPPkts6, numPackets);
        for (uint_fast32_t i = 0; i < DHCP_NUM_MSGT6; i++) {
            if (numDHCPmsgT6[i] > 0) {
                T2_CONV_NUM(numDHCPmsgT6[i], hrnum);
                T2_FPLOG(stream, plugin_name, "Number of DHCPv6 %s messages: %" PRIu64 "%s [%.2f%%]",
                        dhcpMsgT6ToStr[i], numDHCPmsgT6[i], hrnum, 100.0*numDHCPmsgT6[i]/(double)numDHCPPkts6);
            }
        }
    }
#endif // IPV6_ACTIVATE > 0
}


void t2Finalize() {
#if DHCP_FLAG_MAC == 1 && (IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2)
    hashTable_destroy(macMap);
    free(macArray);
#endif
    free(dhcpFlow);
}


#if IPV6_ACTIVATE > 0
static void dhcp6decode(packet_t *packet, unsigned long flowIndex) {
    const uint32_t remaining = packet->snapL7Len;
    if (remaining < 1) {
        DHCP_SPKTMD_PRI_NONE();
        return;
    }

    const uint8_t * const ptr = packet->l7HdrP;
    // TODO check return value of t2buf_* functions
    t2buf_t t2buf = t2buf_create(ptr, remaining);

    dhcpFlow_t * const dhcpFlowP = &dhcpFlow[flowIndex];

    /* Message Type */
    uint8_t msgT;
    t2buf_read_u8(&t2buf, &msgT);

    if (msgT > 0 && msgT <= DHCP_NUM_MSGT) {
#if DHCPMOTOUT == 0
        dhcpFlowP->MType |= 1 << msgT;
#endif // DHCPMOTOUT == 0
        numDHCPmsgT6[msgT-1]++;
    }

#if DHCPMOTOUT > 0
    if (dhcpFlowP->msgTNum >= DHCPMSGMAX) {
        dhcpFlowP->dhcpStat |= DHCPOPTTRUNC;
    } else {
        for (uint_fast32_t j = 0; j < dhcpFlowP->msgTNum; j++) {
            if (dhcpFlowP->msgT[j] == msgT) goto typex6;
        }
        dhcpFlowP->msgT[dhcpFlowP->msgTNum++] = msgT;
    }
typex6: ;
#endif // DHCPMOTOUT

    /* Transaction ID */
    uint32_t transID;
    t2buf_read_u24(&t2buf, &transID);

    /* Options */
    while (t2buf_left(&t2buf) > 4) {
        /* Option */
        uint16_t opt;
        t2buf_read_u16(&t2buf, &opt);

        /* Option Length */
        uint16_t optlen;
        t2buf_read_u16(&t2buf, &optlen);

        /* Option Value */
        switch (opt) {

            //case 8: { // Elapsed Time
            //    uint16_t ms;
            //    t2buf_read_u16(&t2buf, &ms);
            //    dhcpFlowP->maxSecEl = ms / 1000.0;
            //    break;
            //}

            case 13: // Status Code
                /* Status Code */
                t2buf_skip_u16(&t2buf);
                /* Status Message */
                uint8_t msg[255] = {};
                if (optlen < 2) {
                    DHCP_SPKTMD_PRI_NONE();
                    dhcpFlowP->dhcpStat |= DHCPINVALIDLEN;
                    return;
                }
                t2buf_readnstr(&t2buf, msg, 255, optlen-2, T2BUF_UTF8, true);
                //T2_PERR(plugin_name, "DHCP Status Message: %s", msg);
                break;

            //case 16: // Vendor Class
            //    /* Enterprise ID */
            //    t2buf_skip_u32(&t2buf);
            //    /* Vendor-class-data */
            //    if (optlen < 4) {
            //        dhcpFlowP->dhcpStat |= DHCPINVALIDLEN;
            //        return;
            //    }
            //    t2buf_skip_n(&t2buf, optlen-4);
            //    break;

            case 1: { // ClientID
            //case 2: { // ServerID
                /* DUID type */
                uint16_t duid_type;
                t2buf_read_u16(&t2buf, &duid_type);
                if (duid_type != 1 && duid_type != 3) { // link-layer address (plus time)
                    // 2: Vendor-assigned unique ID based on Enterprise Number
                    t2buf_skip_n(&t2buf, optlen-2);
                    break;
                }
                /* Hardware type */
                uint16_t hw_type;
                t2buf_read_u16(&t2buf, &hw_type);
                dhcpFlowP->hwType |= 1UL << MIN(hw_type, 63);
                if (duid_type == 1) { // link-layer address plus time
                    /* DUID time */
                    t2buf_skip_u32(&t2buf);
                }
                if (hw_type != 1) {
                    // Not a MAC address
                    if (duid_type == 1) {
                        t2buf_skip_n(&t2buf, optlen-8);
                    } else {
                        t2buf_skip_n(&t2buf, optlen-4);
                    }
                    dhcpFlowP->dhcpStat |= DHCPNONETHHW;
                    break;
                }
                /* Link-layer address */
                uint8_t mac[ETH_ALEN] = {};
                for (uint_fast8_t i = 0; i < ETH_ALEN; i++) {
                    t2buf_read_u8(&t2buf, &mac[i]);
                }
                // Client MAC address
                if (dhcpFlowP->HWAddCnt >= DHCPNMMAX) {
                    dhcpFlowP->dhcpStat |= DHCPNMTRUNC;
                } else {
                    uint_fast32_t i;
                    const uint32_t cliMac[2] = {
                        ((mac[3] << 24) | (mac[2] << 16) | (mac[1] << 8) | mac[0]),
                        ((mac[5] << 8) | mac[4]),
                    };
                    for (i = 0; i < dhcpFlowP->HWAddCnt; i++) {
                        // MAC address already seen
                        if (dhcpFlowP->clHWAdd[i][0] == cliMac[0] &&
                            dhcpFlowP->clHWAdd[i][1] == cliMac[1])
                        {
                            break;
                        }
                    }

                    // MAC address was never seen
                    if (i == dhcpFlowP->HWAddCnt) {
                        dhcpFlowP->clHWAdd[i][0] = cliMac[0];
                        dhcpFlowP->clHWAdd[i][1] = cliMac[1];
                        dhcpFlowP->HWAddCnt++;
                    }
#if DHCP_ADD_CNT == 1
                    dhcpFlowP->clHWAdd[i][2]++;
#endif
                }
                break;
            }

            //case 6: // Option request
            //    while (optlen > 1 && t2buf_left(&t2buf) > 0) {
            //        /* Requested option code */
            //        t2buf_skip_u16(&t2buf);
            //        optlen -= 2;
            //    }
            //    break;

            //case 3: // Identity Association for Non-temporary Address
            //    /* IAID */
            //    t2buf_skip_u32(&t2buf);
            //    /* T1 */
            //    t2buf_skip_u32(&t2buf);
            //    /* T2 */
            //    t2buf_skip_u32(&t2buf);
            //    break;

            //case 25: // Identity Association for Prefix Delegation
            //    /* IAID */
            //    t2buf_skip_u32(&t2buf);
            //    /* T1 */
            //    t2buf_skip_u32(&t2buf);
            //    /* T2 */
            //    t2buf_skip_u32(&t2buf);
            //    /* IA Prefix */
            //    /* Preferred lifetime */
            //    t2buf_skip_u32(&t2buf);
            //    /* Valid lifetime */
            //    t2buf_skip_u32(&t2buf);
            //    /* Prefix length */
            //    t2buf_skip_u8(&t2buf);
            //    /* Prefix */
            //    t2buf_skip_n(&t2buf, 16);
            //    break;

            case 39: // Fully Qualified Domain Name
                /* Flags */
                t2buf_skip_u8(&t2buf);
                /* Reserved */
                if (optlen < 2) {
                    dhcpFlowP->dhcpStat |= DHCPINVALIDLEN;
                    DHCP_SPKTMD_PRI_NONE();
                    return;
                }
                uint8_t fqdn[255] = {};
                uint_fast32_t pos = 0;
                uint8_t len;
                t2buf_read_u8(&t2buf, &len);
                while (len > 0 && t2buf_left(&t2buf) > len+1) {
                    t2buf_readnstr(&t2buf, &fqdn[pos], sizeof(fqdn), len, T2BUF_UTF8, true);
                    pos += len;
                    t2buf_read_u8(&t2buf, &len);
                    if (len > 0) fqdn[pos++] = '.';
                }
                //T2_PDBG(plugin_name, "DHCP FQDN: %s", fqdn);
                if (dhcpFlowP->domainNCnt >= DHCPNMMAX) {
                    dhcpFlowP->dhcpStat |= DHCPNMTRUNC;
                } else {
                    uint_fast32_t j;
                    for (j = 0; j < dhcpFlowP->domainNCnt; j++) {
                        const size_t k = strlen(dhcpFlowP->domainN[j]);
                        // domain name is sometimes null terminated...
                        if ((k == pos || k+1 == pos) && memcmp(dhcpFlowP->domainN[j], fqdn, pos) == 0) break;
                    }
                    if (j == dhcpFlowP->domainNCnt) {
                        char *domainP = t2_malloc_fatal(pos+1);
                        memcpy(domainP, fqdn, pos);
                        domainP[pos] = '\0';
                        dhcpFlowP->domainN[dhcpFlowP->domainNCnt] = domainP;
                        dhcpFlowP->domainNCnt++;
                    }
#if DHCP_ADD_CNT == 1
                    dhcpFlowP->domainrep[j]++;
#endif
                }
                break;

            default:
                t2buf_skip_n(&t2buf, optlen);
                break;
        }
    }

    if (sPktFile) {
        fprintf(sPktFile, "0x%04" B2T_PRIX16 SEP_CHR, dhcpFlowP->dhcpStat); // dhcpStat

        // dhcpMTypeBF/dhcpMType/dhcpMTypeNms
#if DHCPMOTOUT == 0
        fprintf(sPktFile, "%08" B2T_PRIX32 SEP_CHR, dhcpFlowP->MType); // dhcpMTypeBF
#elif DHCPMOTOUT <= 1
        fprintf(sPktFile, "%" PRIu8 SEP_CHR, msgT);                    // dhcpMType
#else // DHCPMOTOUT > 1
        // dhcpMTypeNms
        if (msgT > 0 && msgT <= DHCP_NUM_MSGT6) {
            fprintf(sPktFile, "%s" SEP_CHR, dhcpMsgT6ToStr[msgT]);
        } else {
            fprintf(sPktFile, "%" PRIu8 SEP_CHR, msgT);
        }
#endif // DHCPMOTOUT

        // dhcpHops, dhcpHWType, dhcpTransID, dhcpOptBF1_BF2_BF3/dhcpOpts/dhcpOptNms, dhcpLFlow
        fprintf(sPktFile,
                                   /* dhcpHops                               */ SEP_CHR
                                   /* dhcpHWType                             */ SEP_CHR
                "0x%08" B2T_PRIX32 /* dhcpTransID                            */ SEP_CHR
                                   /* dhcpOptBF1_BF2_BF3/dhcpOpts/dhcpOptNms */ SEP_CHR
                                   /* dhcpLFlow                              */ SEP_CHR
                , transID);
    }
}
#endif // IPV6_ACTIVATE > 0
