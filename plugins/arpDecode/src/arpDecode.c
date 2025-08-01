/*
 * arpDecode.c
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

#include "arpDecode.h"


// Global variables

arpFlow_t *arpFlows;


#if ETH_ACTIVATE > 0

// Static variables

static uint8_t arpStat;

static hashMap_t *arpTable;
static uint64_t  *macTable;


#define ARP_SPKTMD_PRI_NONE() \
    if (sPktFile) { \
        fputs("0x00" /* arpStat      */ SEP_CHR \
                     /* arpHwType    */ SEP_CHR \
                     /* arpProtoType */ SEP_CHR \
                     /* arpHwSize    */ SEP_CHR \
                     /* arpProtoSize */ SEP_CHR \
                     /* arpOpcode    */ SEP_CHR \
                     /* arpSenderMAC */ SEP_CHR \
                     /* arpSenderIP  */ SEP_CHR \
                     /* arpTargetMAC */ SEP_CHR \
                     /* arpTargetIP  */ SEP_CHR \
              , sPktFile); \
    }

// TODO make sure counters do not overflow
#define ARP_APPEND_MAC_IP(arpFlowP, mac_addr, ip_addr) \
    if ((arpFlowP)->cnt < ARP_MAX_IP) { \
        const uint_fast32_t cnt = (arpFlowP)->cnt; \
        memcpy((arpFlowP)->mac[cnt], (mac_addr), ETH_ALEN); \
        (arpFlowP)->ip[cnt] = (ip_addr); \
        (arpFlowP)->ipCnt[cnt]++; \
    } else { \
        (arpFlowP)->stat |= ARP_STAT_FULL; \
        if (!(arpStat & ARP_STAT_FULL)) { \
            T2_PWRN(plugin_name, "MAC/IP list full... increase ARP_MAX_IP"); \
            arpStat |= ARP_STAT_FULL; \
        } \
    } \
    (arpFlowP)->cnt++; \

#endif // ETH_ACTIVATE > 0


// Tranalyzer functions

T2_PLUGIN_INIT("arpDecode", "0.9.3", 0, 9);


void t2Init() {
#if ETH_ACTIVATE == 0
    T2_PWRN(plugin_name, "ETH_ACTIVATE is set to 0 in 'networkHeaders.h', no output will be produced");
#else // ETH_ACTIVATE > 0

    T2_PLUGIN_STRUCT_NEW(arpFlows);

    arpTable = hashTable_init(1.0f, sizeof(uint32_t), "arp");
    macTable = t2_calloc_fatal(arpTable->hashChainTableSize, sizeof(*macTable));

    if (sPktFile) {
        fputs("arpStat"      SEP_CHR
              "arpHwType"    SEP_CHR
              "arpProtoType" SEP_CHR
              "arpHwSize"    SEP_CHR
              "arpProtoSize" SEP_CHR
              "arpOpcode"    SEP_CHR
              "arpSenderMAC" SEP_CHR
              "arpSenderIP"  SEP_CHR
              "arpTargetMAC" SEP_CHR
              "arpTargetIP"  SEP_CHR
              , sPktFile);
    }
#endif // ETH_ACTIVATE > 0
}


// If ETH_ACTIVATE == 0, the plugin does not produce any output.
// All the code below is therefore not activated.


#if ETH_ACTIVATE > 0

binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;
    BV_APPEND_H8(bv , "arpStat"      , "ARP status");
    BV_APPEND_U16(bv, "arpHwType"    , "ARP hardware type");
    BV_APPEND_H16(bv, "arpOpcode"    , "ARP opcode");
    BV_APPEND_U16(bv, "arpIpMacCnt"  , "ARP Number of distinct MAC / IP pairs");
    BV_APPEND_R(bv  , "arpMac_Ip_Cnt", "ARP MAC/IP pairs found and number of times the pair appeared", 3, bt_mac_addr, bt_ip4_addr, bt_uint_16);
    return bv;
}


void t2OnNewFlow(packet_t* packet, unsigned long flowIndex) {
    arpFlow_t * const arpFlowP = &arpFlows[flowIndex];
    memset(arpFlowP, '\0', sizeof(*arpFlowP));

    if ((packet->status & (L2_ARP | L2_RARP)) == 0) return;

    const arpMsg_t * const arpP = (arpMsg_t*)packet->l7HdrP;

    arpFlowP->stat |= ARP_STAT_DET;
    arpFlowP->hwType = ntohs(arpP->hwType);
}


void t2OnLayer2(packet_t* packet, unsigned long flowIndex) {
    if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;

    arpFlow_t * const arpFlowP = &arpFlows[flowIndex];
    if (!arpFlowP->stat) {
        ARP_SPKTMD_PRI_NONE();
        return;
    }

    const arpMsg_t * const arpP = (arpMsg_t*)packet->l7HdrP;

    const uint_fast16_t opCode = ntohs(arpP->opCode);
    arpFlowP->opCode |= (1 << opCode);

    const uint_fast8_t hwSize = arpP->hwSize;
    const uint_fast8_t protoSize = arpP->protoSize;

    const uint32_t srcIP = arpP->srcIP;
    const uint32_t dstIP = arpP->dstIP;

    const uint8_t * const srcMAC = arpP->srcMAC;
    const uint8_t * const dstMAC = arpP->dstMAC;

    const uint64_t dstMAC64 = *(uint64_t*)dstMAC & ARP_MAC_MASK;

    if (srcIP == dstIP && (opCode == ARP_OPCODE_REQ || opCode == ARP_OPCODE_REP)) {
        arpFlowP->stat |= ARP_STAT_GRAT;
        if (opCode == ARP_OPCODE_REQ && (dstMAC64 == 0 || dstMAC64 == ARP_MAC_MASK)) {
            arpFlowP->stat |= ARP_STAT_ANNOUNCE;
        }
    } else if (opCode == ARP_OPCODE_REQ && dstMAC64 == 0 && srcIP == 0) {
        arpFlowP->stat |= ARP_STAT_PROBE;
    }

    if (((1 << opCode) & ARP_SUPPORTED_OPCODE) &&  // ARP request/reply and RARP reply
        (hwSize == ETH_ALEN && protoSize == 4))    // MAC/IPv4 pairs only
    {
        const uint32_t ip[] = { srcIP, dstIP };
        const uint8_t * const mac[] = { srcMAC, dstMAC };
        const uint_fast32_t naddr = (opCode == ARP_OPCODE_REQ) ? 1 : 2;

        for (uint_fast32_t i = 0; i < naddr; i++) {
            const mac64_t mac64 = { .u64 = *(uint64_t*)mac[i] & ARP_MAC_MASK };
            unsigned long hash = hashTable_lookup(arpTable, (char*)&ip[i]);
            if (hash == HASHTABLE_ENTRY_NOT_FOUND) {
                // First time seeing this IP, add it to the ARP table
                hash = hashTable_insert(arpTable, (char*)&ip[i]);
                macTable[hash] = mac64.u64;
                ARP_APPEND_MAC_IP(arpFlowP, mac[i], ip[i]);
            } else {
                // IP already seen... make sure the MAC matches
                const mac64_t prevMAC = { .u64 = macTable[hash] };

                bool add_prev_mac;
                if (prevMAC.u64 == mac64.u64) {
                    // Same MAC
                    add_prev_mac = false;
                } else {
                    // Different MAC
                    // TODO which mac to store in macTable?
                    if (ip[i]) arpFlowP->stat |= ARP_STAT_SPOOF; // don't flag 0.0.0.0
                    add_prev_mac = true;
                }

                bool add_mac = true;

                const uint32_t cnt = MIN(arpFlowP->cnt, ARP_MAX_IP);
                for (uint_fast32_t j = 0; j < cnt; j++) {
                    if (arpFlowP->ip[j] != ip[i]) continue; // TODO set the ARP_STAT_MAC_SPOOF bit if MAC different
                    if (memcmp(arpFlowP->mac[j], mac[i], ETH_ALEN) == 0) {
                        // MAC/IP pair found... increment counter
                         arpFlowP->ipCnt[j]++;
                         add_mac = false;
                    } else if (add_prev_mac && memcmp(arpFlowP->mac[j], prevMAC.u8, ETH_ALEN) == 0) {
                        // prevMAC/IP pair already exists... do not add it again
                        add_prev_mac = false;
                    }
                }

                if (add_mac) {
                    ARP_APPEND_MAC_IP(arpFlowP, mac[i], ip[i]);
                }

                if (add_prev_mac) {
                    // This MAC/IP pair was actually not seen in this flow,
                    // report it anyway, but do not increment the counter
                    ARP_APPEND_MAC_IP(arpFlowP, prevMAC.u8, ip[i]);
                    if (arpFlowP->cnt <= ARP_MAX_IP) {
                        arpFlowP->ipCnt[arpFlowP->cnt-1] = 0;
                    }
                }
            }
        }
    }

    if (sPktFile) {
        // Source and Destination MAC
        char srcMacStr[T2_MAC_STRLEN+1] = {}, dstMacStr[T2_MAC_STRLEN+1] = {};
        if (hwSize == ETH_ALEN) {
            t2_mac_to_str(srcMAC, srcMacStr, sizeof(srcMacStr));
            t2_mac_to_str(dstMAC, dstMacStr, sizeof(dstMacStr));
        }

        // Source and Destination IP
        char srcIPStr[INET_ADDRSTRLEN], dstIPStr[INET_ADDRSTRLEN];
        if (protoSize == 4) {
            t2_ipv4_to_str(*(struct in_addr*)&srcIP, srcIPStr, sizeof(srcIPStr));
            t2_ipv4_to_str(*(struct in_addr*)&dstIP, dstIPStr, sizeof(dstIPStr));
        }

        fprintf(sPktFile,
                "0x%02" B2T_PRIX8  /* arpStat      */ SEP_CHR
                "%"     PRIu16     /* arpHwType    */ SEP_CHR
                "0x%04" B2T_PRIX16 /* arpProtoType */ SEP_CHR
                "%"     PRIuFAST8  /* arpHwSize    */ SEP_CHR
                "%"     PRIuFAST8  /* arpProtoSize */ SEP_CHR
                "%"     PRIuFAST16 /* arpOpcode    */ SEP_CHR
                "%s"               /* arpSenderMAC */ SEP_CHR
                "%s"               /* arpSenderIP  */ SEP_CHR
                "%s"               /* arpTargetMAC */ SEP_CHR
                "%s"               /* arpTargetIP  */ SEP_CHR
                , arpFlowP->stat, ntohs(arpP->hwType), ntohs(arpP->protoType),
                  hwSize, protoSize, opCode, srcMacStr, srcIPStr, dstMacStr, dstIPStr);
    }
}


void t2OnLayer4(packet_t* packet UNUSED, unsigned long flowIndex UNUSED) {
    ARP_SPKTMD_PRI_NONE();
}


void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {
    const arpFlow_t * const arpFlowP = &arpFlows[flowIndex];

    arpStat |= arpFlowP->stat;

    OUTBUF_APPEND_U8(buf , arpFlowP->stat);   // arpStat
    OUTBUF_APPEND_U16(buf, arpFlowP->hwType); // arpHwType
    OUTBUF_APPEND_U16(buf, arpFlowP->opCode); // arpOpcode
    OUTBUF_APPEND_U16(buf, arpFlowP->cnt);    // arpIpMacCnt

    // arpMac_Ip_Cnt
    const uint32_t cnt = MIN(arpFlowP->cnt, ARP_MAX_IP);
    OUTBUF_APPEND_NUMREP(buf, cnt);
    for (uint_fast32_t i = 0; i < cnt; i++) {
        OUTBUF_APPEND_MAC(buf, arpFlowP->mac[i]);
        OUTBUF_APPEND_U32(buf, arpFlowP->ip[i]);
        OUTBUF_APPEND_U16(buf, arpFlowP->ipCnt[i]);
    }
}


static inline void arp_pluginReport(FILE *stream) {
    T2_FPLOG_AGGR_HEX(stream, plugin_name, arpStat);
}


void t2PluginReport(FILE *stream) {
    arp_pluginReport(stream);
}


void t2Monitoring(FILE *stream, uint8_t state) {

    switch (state) {

        case T2_MON_PRI_HDR:
            fputs("arpStat" SEP_CHR
                  , stream);
            return;

        case T2_MON_PRI_VAL:
            fprintf(stream,
                    "%" B2T_PRIX8 /* arpStat */ SEP_CHR
                    , arpStat);
            break;

        case T2_MON_PRI_REPORT:
            arp_pluginReport(stream);
            break;

        // Invalid state, do nothing
        default:
            return;
    }
}


void t2SaveState(FILE *stream) {
    fprintf(stream, "%" PRIx8, arpStat);
}


void t2RestoreState(const char *str) {
    sscanf(str, "%" SCNx8, &arpStat);
}


void t2Finalize() {
    hashTable_destroy(arpTable);
    free(macTable);
    free(arpFlows);
}

#endif // ETH_ACTIVATE > 0
