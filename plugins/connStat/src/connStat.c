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

/*
 * Counts the number of connections between two hosts regarding the initiation
 * and termination of a communication and the number of distinct connections of
 * one host. Here, distinct means that only the number of different hosts the
 * actual host is connected to, are counted.
 *
 * Please note that because of the nature of this program, not all connections
 * of a host might be observed. For example if the program is sniffing the
 * traffic between a gateway and a local intranet, it is not able to observe
 * the connections between two hosts inside the intranet. Therefore, these
 * values are to be handled with care.
 */

#include "connStat.h"

#include <ctype.h> // for isdigit and toupper


// Static variables

// hashMaps for the number of connections
#if CS_MR_SPOOF > 0
static macSC_t *macSC;
#endif // CS_MR_SPOOF > 0

static hashMap_t *ipPHashMap;
static hashMap_t *ipSHashMap;
static hashMap_t *ipDHashMap;
static hashMap_t *portHashMap;
static uint32_t *ipPairConn;
static uint32_t *ipSConn;
static uint32_t *ipDConn;
static uint32_t *portConn;
static pbCnt_t *numPBCnt;
static uint64_t numSIP, numSIP0;
static uint64_t numDIP, numDIP0;
static uint64_t numPort, numPort0;
static uint64_t numSDIP, numSDIP0;

// Keep track of the IP with max connections
static struct {
#if IPV6_ACTIVATE > 0
    ipAddr_t     addr;
#else // IPV6_ACTIVATE == 0
    ip4Addr_t    addr;
#endif // IPV6_ACTIVATE == 0
#if SUBNET_INIT != 0
    uint32_t     subnet;
#endif // SUBNET_INIT != 0
    uint32_t     count;
    uint_fast8_t ipver;
} ipSConnMx, ipDConnMx;

#if (CS_PBNMAX == 1 && ANONYM_IP == 0)
static struct {
#if IPV6_ACTIVATE > 0
    ipAddr_t     addr;
#else // IPV6_ACTIVATE == 0
    ip4Addr_t    addr;
#endif // IPV6_ACTIVATE == 0
#if SUBNET_INIT != 0
    uint32_t     subnet;
#endif // SUBNET_INIT != 0
    uint64_t     count;
    uint_fast8_t ipver;
} ipPkt, ipByte;
#endif // (CS_PBNMAX == 1 && ANONYM_IP == 0)


// Tranalyzer function

T2_PLUGIN_INIT("connStat", "0.9.3", 0, 9);


void t2Init() {
    // initialize the hashMaps
    ipPHashMap = hashTable_init(1.0f, sizeof(ipPID_t), "ipP");
    ipSHashMap = hashTable_init(1.0f, sizeof(ipHash_t), "ipS");
    ipDHashMap = hashTable_init(1.0f, sizeof(ipHash_t), "ipD");
    portHashMap = hashTable_init(1.0f, sizeof(ipPort_t), "port");

    // initialize the counter arrays
    ipPairConn = t2_calloc_fatal(ipPHashMap->hashChainTableSize, sizeof(*ipPairConn));
    ipSConn = t2_calloc_fatal(ipSHashMap->hashChainTableSize, sizeof(*ipSConn));
    ipDConn = t2_calloc_fatal(ipDHashMap->hashChainTableSize, sizeof(*ipDConn));
    portConn = t2_calloc_fatal(portHashMap->hashChainTableSize, sizeof(*portConn));
    numPBCnt = t2_calloc_fatal(portHashMap->hashChainTableSize, sizeof(*numPBCnt));

#if CS_MR_SPOOF > 0
    macSC = t2_calloc_fatal(ipSHashMap->hashChainTableSize, sizeof(macSC_t));
#endif // CS_MR_SPOOF > 0
}


binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;
    BV_APPEND_U32(bv, "connSip"    , "Number of unique source IPs");
    BV_APPEND_U32(bv, "connDip"    , "Number of unique destination IPs");
    BV_APPEND_U32(bv, "connSipDip" , "Number of connections between source and destination IP");
    BV_APPEND_U32(bv, "connSipDprt", "Number of connections between source IP and destination port");
#if CS_MR_SPOOF > 0
    BV_APPEND_U32(bv, "connMacSpf" , "Number of MAC addresses per source IP");
#endif // CS_MR_SPOOF > 0
    BV_APPEND_FLT(bv, "connF"      , "The 'f' number: connSipDprt / connSip [EXPERIMENTAL]");
    BV_APPEND_FLT(bv, "connG"      , "The 'g' number: connSipDprt / connSipDip [EXPERIMENTAL]");
#if CS_PBNMAX == 1
    BV_APPEND_U64(bv, "connNumPCnt", "Number of unique IP's source packet count");
    BV_APPEND_U64(bv, "connNumBCnt", "Number of unique IP's source byte count");
#endif // CS_PBNMAX == 1
    return bv;
}


void t2OnNewFlow(packet_t *packet UNUSED, unsigned long flowIndex) {
    const flow_t * const flowP = &flows[flowIndex];
    if (flowP->status & L2_FLOW) return;

#if CS_MR_SPOOF > 0
    const ethernetHeader_t * const l2HdrP = (ethernetHeader_t*)packet->l2HdrP;
#endif // CS_MR_SPOOF > 0

#if IPV6_ACTIVATE == 2
    const uint8_t ipver = FLOW_IPVER(flowP);
#endif // IPV6_ACTIVATE == 2

#if IPV6_ACTIVATE > 0
    ipAddr_t srcIP, dstIP;
#else // IPV6_ACTIVATE == 0
    ip4Addr_t srcIP, dstIP;
#endif // IPV6_ACTIVATE == 0

#if CS_MR_SPOOF > 0
    uint8_t macS[ETH_ALEN];
#endif // CS_MR_SPOOF > 0

    uint16_t dstPort;

    if (FLOW_IS_B(flowP)) {
        srcIP = flowP->dstIP;
        dstIP = flowP->srcIP;
#if CS_MR_SPOOF > 0
        memcpy(macS, l2HdrP->ethDS.ether_dhost, ETH_ALEN);
#endif // CS_MR_SPOOF > 0
        dstPort = flowP->srcPort;
    } else {
        srcIP = flowP->srcIP;
        dstIP = flowP->dstIP;
#if CS_MR_SPOOF > 0
        memcpy(macS, l2HdrP->ethDS.ether_shost, ETH_ALEN);
#endif // CS_MR_SPOOF > 0
        dstPort = flowP->dstPort;
    }

    const ipPID_t ipPair = {
#if IPV6_ACTIVATE == 2
        .ver = ipver,
#endif // IPV6_ACTIVATE == 2
        .srcIP = srcIP,
        .dstIP = dstIP,
    };

    unsigned long ipPairIndex = hashTable_lookup(ipPHashMap, (char*)&ipPair);
    if (ipPairIndex != HASHTABLE_ENTRY_NOT_FOUND) {
        // Index was found -> increment counter
        ipPairConn[ipPairIndex]++;
    } else {
        // First connection between these two hosts
        // -> new hashMap entry and store info in array
        ipPairIndex = hashTable_insert(ipPHashMap, (char*)&ipPair);
        ipPairConn[ipPairIndex] = 1;

        // check if an entry for lower IP exists
        const ipHash_t hSIP = {
#if IPV6_ACTIVATE == 2
            .ver = ipver,
#endif // IPV6_ACTIVATE == 2
            .addr = srcIP,
        };

        unsigned long ipSIndex = hashTable_lookup(ipSHashMap, (char*)&hSIP);
        if (ipSIndex != HASHTABLE_ENTRY_NOT_FOUND) {
            // There is already an index, so increment it;
            ipSConn[ipSIndex]++;
#if CS_MR_SPOOF > 0
            if (memcmp(macSC[ipSIndex].macS, macS, ETH_ALEN) && macSC[ipSIndex].macCnt < 65535) {
                macSC[ipSIndex].macCnt++;
            }
#endif // CS_MR_SPOOF > 0
        } else {
            // There is no entry, so generate one
            ipSIndex = hashTable_insert(ipSHashMap, (char*)&hSIP);
            ipSConn[ipSIndex] = 1;
            numSIP++;
#if CS_MR_SPOOF > 0
            memcpy(macSC[ipSIndex].macS, macS, ETH_ALEN);
            macSC[ipSIndex].macCnt = 1;
#endif // CS_MR_SPOOF > 0
        }

        if (ipSConnMx.count < ipSConn[ipSIndex]) {
            ipSConnMx.count = ipSConn[ipSIndex];
#if IPV6_ACTIVATE == 2
            ipSConnMx.ipver = ipver;
#endif // IPV6_ACTIVATE == 2
            ipSConnMx.addr = hSIP.addr;
#if SUBNET_INIT != 0
            if (FLOW_IS_B(flowP)) ipSConnMx.subnet = flowP->subnetNrDst;
            else ipSConnMx.subnet = flowP->subnetNrSrc;
#endif // SUBNET_INIT != 0
        }

        const ipHash_t hDIP = {
#if IPV6_ACTIVATE == 2
            .ver = ipver,
#endif // IPV6_ACTIVATE == 2
            .addr = dstIP,
        };

        unsigned long ipDIndex = hashTable_lookup(ipDHashMap, (char*)&hDIP);
        if (ipDIndex != HASHTABLE_ENTRY_NOT_FOUND) {
            // Index exists, so increment it;
            ipDConn[ipDIndex]++;
#if CS_MR_SPOOF > 0
            if (memcmp(macSC[ipDIndex].macS, macS, ETH_ALEN) && macSC[ipDIndex].macCnt < 65535) {
                macSC[ipDIndex].macCnt++;
            }
#endif // CS_MR_SPOOF > 0
        } else {
            // There is no entry, so generate one
            ipDIndex = hashTable_insert(ipDHashMap, (char*)&hDIP);
            ipDConn[ipDIndex] = 1;
            numDIP++;
#if CS_MR_SPOOF > 0
            memcpy(macSC[ipDIndex].macS, macS, ETH_ALEN);
            macSC[ipDIndex].macCnt = 1;
#endif // CS_MR_SPOOF > 0
        }

        if (ipDConnMx.count < ipDConn[ipDIndex]) {
            ipDConnMx.count = ipDConn[ipDIndex];
#if IPV6_ACTIVATE == 2
            ipDConnMx.ipver = ipver;
#endif // IPV6_ACTIVATE == 2
            ipDConnMx.addr = hDIP.addr;
#if SUBNET_INIT != 0
            if (FLOW_IS_B(flowP)) ipDConnMx.subnet = flowP->subnetNrSrc;
            else ipDConnMx.subnet = flowP->subnetNrDst;
#endif // SUBNET_INIT != 0
        }
    }

#if CS_SDIPMAX == 1
    numSDIP = MAX(numSDIP, ipPairConn[ipPairIndex]);
#else // CS_SDIPMAX == 0
    numSDIP++;
#endif // CS_SDIPMAX == 0

    const ipPort_t ipPort = {
#if IPV6_ACTIVATE == 2
        .ver = ipver,
#endif // IPV6_ACTIVATE == 2
        .port = dstPort,
        .addr = srcIP,
    };

    unsigned long ipPortIndex = hashTable_lookup(portHashMap, (char*)&ipPort);
    if (ipPortIndex != HASHTABLE_ENTRY_NOT_FOUND) {
        portConn[ipPortIndex]++;
    } else {
        ipPortIndex = hashTable_insert(portHashMap, (char*)&ipPort);
        portConn[ipPortIndex] = 1;
    }

    numPort = MAX(numPort, portConn[ipPortIndex]);
}


#if CS_PBNMAX == 1
void t2OnLayer4(packet_t *packet, unsigned long flowIndex) {
    const flow_t * const flowP = &flows[flowIndex];
#if IPV6_ACTIVATE == 2
    const uint8_t ipver = FLOW_IPVER(flowP);
#endif // IPV6_ACTIVATE == 2
    const ipHash_t sIP = {
#if IPV6_ACTIVATE == 2
        .ver = ipver,
#endif // IPV6_ACTIVATE == 2
        .addr = flowP->srcIP,
    };
    unsigned long ipSIndex = hashTable_lookup(ipSHashMap, (char*)&sIP);
    if (ipSIndex != HASHTABLE_ENTRY_NOT_FOUND) {
        pbCnt_t * const numPBCP = &numPBCnt[ipSIndex];
        numPBCP->numPCnt++;
        numPBCP->numBCnt += packet->len;
    } else {
        ipSIndex = hashTable_insert(ipSHashMap, (char*)&sIP);
        pbCnt_t * const numPBCP = &numPBCnt[ipSIndex];
        numPBCP->numPCnt = 1;
        numPBCP->numBCnt = packet->len;
    }
}
#endif // CS_PBNMAX == 1


void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {
    const flow_t * const flowP = &flows[flowIndex];

    if (flowP->status & L2_FLOW) {
        OUTBUF_APPEND_U32_ZERO(buf);       // connSip
        OUTBUF_APPEND_U32_ZERO(buf);       // connDip
        OUTBUF_APPEND_U32_ZERO(buf);       // connSipDip
        OUTBUF_APPEND_U32_ZERO(buf);       // connSipDprt
#if CS_MR_SPOOF > 0
        OUTBUF_APPEND_U32_ZERO(buf);       // connMacSpf
#endif // CS_MR_SPOOF > 0
        OUTBUF_APPEND_FLT_ZERO(buf);       // connF
        OUTBUF_APPEND_FLT_ZERO(buf);       // connG

#if CS_PBNMAX == 1
        OUTBUF_APPEND_U64_ZERO(buf);       // connNumPCnt
        OUTBUF_APPEND_U64_ZERO(buf);       // connNumBCnt
#endif // CS_PBNMAX == 1

#if ESOM_DEP == 1
        sconn = 0;
        dconn = 0;
        iconn = 0;
        pconn = 0;
        fconn = 0.0f;
        gconn = 0.0f;
#endif // ESOM_DEP == 1

        return;
    }

#if IPV6_ACTIVATE == 2
    const uint8_t ipver = FLOW_IPVER(flowP);
#endif // IPV6_ACTIVATE == 2

#if IPV6_ACTIVATE > 0
    ipAddr_t srcIP, dstIP;
#else // IPV6_ACTIVATE == 0
    ip4Addr_t srcIP, dstIP;
#endif // IPV6_ACTIVATE
    uint16_t dstPort;

    if (FLOW_IS_B(flowP)) {
        srcIP = flowP->dstIP;
        dstIP = flowP->srcIP;
        dstPort = flowP->srcPort;
    } else {
        srcIP = flowP->srcIP;
        dstIP = flowP->dstIP;
        dstPort = flowP->dstPort;
    }

    const ipPID_t ipPair = {
#if IPV6_ACTIVATE == 2
        .ver = ipver,
#endif // IPV6_ACTIVATE == 2
        .srcIP = srcIP,
        .dstIP = dstIP,
    };

    const unsigned long ipPairIndex = hashTable_lookup(ipPHashMap, (char*)&ipPair);
    if (ipPairIndex == HASHTABLE_ENTRY_NOT_FOUND) {
        T2_PWRN(plugin_name,
                "flowIndex: %lu, findex: %" PRIu64 " has no IP pair number connections entry! 0x%016" B2T_PRIX64,
                flowIndex, flowP->findex, flowP->status);
    }

    const ipPort_t ipPort = {
#if IPV6_ACTIVATE == 2
        .ver = ipver,
#endif // IPV6_ACTIVATE == 2
        .port = dstPort,
        .addr = srcIP,
    };

    const unsigned long ipPortIndex = hashTable_lookup(portHashMap, (char*)&ipPort);
    if (ipPortIndex == HASHTABLE_ENTRY_NOT_FOUND) {
        T2_PWRN(plugin_name,
                "flowIndex %lu, findex: %" PRIu64 " has no srcIP, dstPort connections entry! 0x%016" B2T_PRIX64,
                flowIndex, flowP->findex, flowP->status);
    }

    const ipHash_t hSIP = {
#if IPV6_ACTIVATE == 2
        .ver = ipver,
#endif // IPV6_ACTIVATE == 2
        .addr = srcIP,
    };

    const unsigned long ipSIndex = hashTable_lookup(ipSHashMap, (char*)&hSIP);
    if (ipSIndex == HASHTABLE_ENTRY_NOT_FOUND) {
        T2_PWRN(plugin_name,
                "flowIndex %lu, findex: %" PRIu64 " has no src IP connections entry! 0x%016" B2T_PRIX64,
                flowIndex, flowP->findex, flowP->status);
    }

    const ipHash_t hDIP = {
#if IPV6_ACTIVATE == 2
        .ver = ipver,
#endif // IPV6_ACTIVATE == 2
        .addr = dstIP,
    };

    const unsigned long ipDIndex = hashTable_lookup(ipDHashMap, (char*)&hDIP);
    if (ipDIndex == HASHTABLE_ENTRY_NOT_FOUND) {
        T2_PWRN(plugin_name,
                "flowIndex %lu, findex: %" PRIu64 " has no dst IP connections entry! 0x%016" B2T_PRIX64,
                flowIndex, flowP->findex, flowP->status);
    }

    uint32_t *srcConn, *dstConn;
    unsigned long srcIPIndex, dstIPIndex;

    if (FLOW_IS_B(flowP)) {
        srcIPIndex = ipDIndex;
        dstIPIndex = ipSIndex;
        srcConn = ipDConn;
        dstConn = ipSConn;
    } else {
        srcIPIndex = ipSIndex;
        dstIPIndex = ipDIndex;
        srcConn = ipSConn;
        dstConn = ipDConn;
    }

    const uint32_t connSip = (srcIPIndex != HASHTABLE_ENTRY_NOT_FOUND) ? srcConn[srcIPIndex] : 0;
    const uint32_t connDip = (dstIPIndex != HASHTABLE_ENTRY_NOT_FOUND) ? dstConn[dstIPIndex] : 0;
    const uint32_t connSipDip = (ipPairIndex != HASHTABLE_ENTRY_NOT_FOUND) ? ipPairConn[ipPairIndex] : 0;
    const uint32_t connSipDprt = (ipPortIndex != HASHTABLE_ENTRY_NOT_FOUND) ? portConn[ipPortIndex] : 0;
    const float connF = (connSip != 0) ? connSipDprt / (float)connSip : 0.0f;
    const float connG = (connSipDip != 0) ? connSipDprt / (float)connSipDip : 0.0f;

#if ESOM_DEP == 1
    sconn = connSip;
    dconn = connDip;
    iconn = connSipDip;
    pconn = connSipDprt;
    fconn = connF;
    gconn = connG;
#endif // ESOM_DEP == 1

    OUTBUF_APPEND_U32(buf, connSip);
    OUTBUF_APPEND_U32(buf, connDip);
    OUTBUF_APPEND_U32(buf, connSipDip);
    OUTBUF_APPEND_U32(buf, connSipDprt);

#if CS_MR_SPOOF > 0
    // connMacSpf
    const uint32_t macSCC = (srcIPIndex != HASHTABLE_ENTRY_NOT_FOUND) ? macSC[srcIPIndex].macCnt : 0;
    OUTBUF_APPEND_U32(buf, macSCC);
#endif // CS_MR_SPOOF > 0

    OUTBUF_APPEND_FLT(buf, connF);
    OUTBUF_APPEND_FLT(buf, connG);

#if CS_PBNMAX == 1 && ANONYM_IP == 0
    // connNumPCnt, connNumBCnt
    if (srcIPIndex == HASHTABLE_ENTRY_NOT_FOUND) {
        OUTBUF_APPEND_U64_ZERO(buf); // connNumPCnt
        OUTBUF_APPEND_U64_ZERO(buf); // connNumBCnt
    } else {
        const ipHash_t sIP = {
#if IPV6_ACTIVATE == 2
            .ver = ipver,
#endif // IPV6_ACTIVATE == 2
            .addr = flowP->srcIP,
        };
        unsigned long ipSI = hashTable_lookup(ipSHashMap, (char*)&sIP);
        const pbCnt_t * const numPBCP = &numPBCnt[ipSI];
        OUTBUF_APPEND_U64(buf, numPBCP->numPCnt);
        OUTBUF_APPEND_U64(buf, numPBCP->numBCnt);

        if (ipPkt.count < numPBCP->numPCnt) {
            ipPkt.addr = flowP->srcIP;
#if IPV6_ACTIVATE == 2
            ipPkt.ipver = ipver;
#endif // IPV6_ACTIVATE == 2
            ipPkt.count = numPBCP->numPCnt;
#if SUBNET_INIT != 0
            ipPkt.subnet = flowP->subnetNrSrc;
#endif // SUBNET_INIT != 0
        }

        if (ipByte.count < numPBCP->numBCnt) {
            ipByte.addr = flowP->srcIP;
#if IPV6_ACTIVATE == 2
            ipByte.ipver = ipver;
#endif // IPV6_ACTIVATE == 2
            ipByte.count = numPBCP->numBCnt;
#if SUBNET_INIT != 0
            ipByte.subnet = flowP->subnetNrSrc;
#endif // SUBNET_INIT != 0
        }
    }
#endif // CS_PBNMAX == 1 && ANONYM_IP == 0

#if CS_HSDRM == 1
    portConn[ipPortIndex]--;

    if (portConn[ipPortIndex] == 0) {
        hashTable_remove(portHashMap, (char*)&ipPort);
    }

    // decrement the ip pair connection counter until A,B flows are processed
    ipPairConn[ipPairIndex]--;

    // if all connections between src and dst are closed,
    // then decrement all other vars
    if (ipPairConn[ipPairIndex] == 0) {
        // Last connection between these two hosts, so remove entry in
        // hashTable and decrement ip connection counters for both hosts
        // and delete them if they are zero.
        hashTable_remove(ipPHashMap, (char*)&ipPair);

        // Decrement the source ip counter
        ipSConn[ipSIndex]--;

        // Check if it is zero. If it is, remove the hashTable entry
        if (ipSConn[ipSIndex] == 0) {
            hashTable_remove(ipSHashMap, (char*)&hSIP);
        }

        // Decrement the dest ip counter
        ipDConn[ipDIndex]--;

        // Check if it is zero. If it is, remove the hashTable entry
        if (ipDConn[ipDIndex] == 0) {
            hashTable_remove(ipDHashMap, (char*)&hDIP);
        }
    }
#endif // CS_HSDRM == 1
}


static inline void connStat_pluginReport(FILE *stream) {
    const uint64_t numSIPDiff = numSIP - numSIP0;
    T2_FPLOG_NUM(stream, plugin_name, "Number of unique source IPs", numSIPDiff);

    const uint64_t numDIPDiff = numDIP - numDIP0;
    T2_FPLOG_NUM(stream, plugin_name, "Number of unique destination IPs", numDIPDiff);

    const uint64_t numSDIPDiff = numSDIP - numSDIP0;
    T2_FPLOG_NUM(stream, plugin_name, "Number of unique source/destination IPs connections", numSDIPDiff);

    const uint64_t numPortDiff = numPort - numPort0;
    T2_FPLOG_NUM(stream, plugin_name, "Max unique number of source IP / destination port connections", numPortDiff);

    const float connF = ((numSIPDiff != 0) ? (numPortDiff / (float)numSIPDiff) : 0.0f);
    if (connF) T2_FPLOG(stream, plugin_name, "IP connF=connSipDprt/connSip: %f", connF);

    const float connG = ((numSDIPDiff != 0) ? (numPortDiff / (float)numSDIPDiff) : 0.0f);
    if (connG) T2_FPLOG(stream, plugin_name, "IP connG=connSipDprt/connSipDip: %f", connG);
}


#if ANONYM_IP == 0 && SUBNET_INIT != 0
#define CS_FORMAT_LOC(loc) \
    if ((loc)[0] == '-' || isdigit((loc)[0])) { \
        loc = ""; \
    } else { \
        loc_str[2] = toupper((loc)[0]); \
        loc_str[3] = toupper((loc)[1]); \
        loc = loc_str; \
    }
#endif // ANONYM_IP == 0 && SUBNET_INIT != 0


#if ANONYM_IP == 0
static void report_ip_with_most_connections(FILE *stream) {
    char *loc = "";
#if SUBNET_INIT != 0
    char loc_str[] = " (XX)"; // XX will be replaced by the country code
#endif // SUBNET_INIT != 0
    char str[64];
#if (AGGREGATIONFLAG & SUBNET) == 0
    char ipstr[INET6_ADDRSTRLEN];
#else // (AGGREGATIONFLAG & SUBNET) != 0
    static const char * const ipstr = "N/A";
#endif // (AGGREGATIONFLAG & SUBNET) != 0

    if (ipSConnMx.count) {
        const uint_fast8_t ipver = (((IPV6_ACTIVATE == 2) ? ipSConnMx.ipver :
                                    ((IPV6_ACTIVATE == 1) ? 6 : 4)));
#if (AGGREGATIONFLAG & SUBNET) == 0
        T2_IP_TO_STR(ipSConnMx.addr, ipver, ipstr, INET6_ADDRSTRLEN);
#endif // (AGGREGATIONFLAG & SUBNET)
        T2_CONV_NUM(ipSConnMx.count, str);
#if SUBNET_INIT != 0
        SUBNET_LOC(loc, ipver, ipSConnMx.subnet);
        CS_FORMAT_LOC(loc);
#endif // SUBNET_INIT != 0
        T2_FPLOG(stream, plugin_name, "Source IP with max connections: %s%s: %" PRIu32 "%s connections",
                 ipstr, loc, ipSConnMx.count, str);
    }

    if (ipDConnMx.count) {
        const uint_fast8_t ipver = (((IPV6_ACTIVATE == 2) ? ipDConnMx.ipver :
                                    ((IPV6_ACTIVATE == 1) ? 6 : 4)));
#if (AGGREGATIONFLAG & SUBNET) == 0
        T2_IP_TO_STR(ipDConnMx.addr, ipver, ipstr, INET6_ADDRSTRLEN);
#endif // (AGGREGATIONFLAG & SUBNET)
        T2_CONV_NUM(ipDConnMx.count, str);
#if SUBNET_INIT != 0
        SUBNET_LOC(loc, ipver, ipDConnMx.subnet);
        CS_FORMAT_LOC(loc);
#endif // SUBNET_INIT != 0
        T2_FPLOG(stream, plugin_name, "Destination IP with max connections: %s%s: %" PRIu32 "%s connections",
                 ipstr, loc, ipDConnMx.count, str);
    }

#if CS_PBNMAX == 1
    if (ipPkt.count) {
        const uint_fast8_t ipver = (((IPV6_ACTIVATE == 2) ? ipPkt.ipver :
                                    ((IPV6_ACTIVATE == 1) ? 6 : 4)));
        T2_IP_TO_STR(ipPkt.addr, ipver, ipstr, INET6_ADDRSTRLEN);
        T2_CONV_NUM(ipPkt.count, str);
#if SUBNET_INIT != 0
        SUBNET_LOC(loc, ipver, ipPkt.subnet);
        CS_FORMAT_LOC(loc);
#endif // SUBNET_INIT != 0
        T2_FPLOG(stream, plugin_name, "Biggest L3 talker: %s%s: %"PRIu64 "%s [%.2f%%] packets",
                 ipstr, loc, ipPkt.count, str, 100.0*ipPkt.count/numPackets);
    }

    if (ipByte.count) {
        const uint_fast8_t ipver = (((IPV6_ACTIVATE == 2) ? ipByte.ipver :
                                    ((IPV6_ACTIVATE == 1) ? 6 : 4)));
        T2_IP_TO_STR(ipByte.addr, ipver, ipstr, INET6_ADDRSTRLEN);
        T2_CONV_NUM(ipByte.count, str);
#if SUBNET_INIT != 0
        SUBNET_LOC(loc, ipver, ipByte.subnet);
        CS_FORMAT_LOC(loc);
#endif // SUBNET_INIT != 0
        T2_FPLOG(stream, plugin_name, "Biggest L3 talker: %s%s: %"PRIu64 "%s [%.2f%%] bytes",
                 ipstr, loc, ipByte.count, str, 100.0*ipByte.count/(numABytes + numBBytes));
    }
#endif // CS_PBNMAX == 1
}
#endif // ANONYM_IP == 0


void t2PluginReport(FILE *stream) {
#if DIFF_REPORT == 1
    numSIP0 = 0;
    numDIP0 = 0;
    numSDIP0 = 0;
    numPort0 = 0;
#endif // DIFF_REPORT == 1

    connStat_pluginReport(stream);

#if ANONYM_IP == 0
    report_ip_with_most_connections(stream);
#endif // ANONYM_IP == 0
}


void t2Monitoring(FILE *stream, uint8_t state) {

    switch (state) {

        case T2_MON_PRI_HDR:
            fputs("connSip"     SEP_CHR
                  "connDip"     SEP_CHR
                  "connSipDip"  SEP_CHR
                  "connSipDprt" SEP_CHR
                  "connF"       SEP_CHR
                  "connG"       SEP_CHR
                  , stream);
            return;

        case T2_MON_PRI_REPORT:
            connStat_pluginReport(stream);
#if ANONYM_IP == 0 && DIFF_REPORT == 0
            report_ip_with_most_connections(stream);
#endif // ANONYM_IP == 0 && DIFF_REPORT == 0
            break;

        case T2_MON_PRI_VAL: {
            const uint64_t numPortDiff = numPort - numPort0;
            const uint64_t numSIPDiff = numSIP - numSIP0;
            const uint64_t numSDIPDiff = numSDIP - numSDIP0;
            const float connF = ((numSIPDiff != 0) ? (numPortDiff / (float)numSIPDiff)  : 0.0f);
            const float connG = ((numSDIPDiff != 0) ? (numPortDiff / (float)numSDIPDiff) : 0.0f);
            fprintf(stream,
                    "%" PRIu64 /* connSip     */ SEP_CHR
                    "%" PRIu64 /* connDip     */ SEP_CHR
                    "%" PRIu64 /* connSipDip  */ SEP_CHR
                    "%" PRIu64 /* connSipDprt */ SEP_CHR
                    "%.3f"     /* connF       */ SEP_CHR
                    "%.3f"     /* connG       */ SEP_CHR
                    , numSIPDiff
                    , numDIP - numDIP0
                    , numSDIPDiff
                    , numPortDiff
                    , connF
                    , connG);
            break;
        }

        // Invalid state, do nothing
        default:
            return;
    }

#if DIFF_REPORT == 1
    numSIP0 = numSIP;
    numDIP0 = numDIP;
    numSDIP0 = numSDIP;
    numPort0 = numPort;
#endif // DIFF_REPORT == 1
}


void t2SaveState(FILE *stream) {
    fprintf(stream, "%" PRIu64 "\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu64,
            numSIP, numDIP, numSDIP, numPort);
}


void t2RestoreState(const char *str) {
    sscanf(str, "%" SCNu64 "\t%" SCNu64 "\t%" SCNu64 "\t%" SCNu64,
            &numSIP, &numDIP, &numSDIP, &numPort);

#if DIFF_REPORT == 1
    numSIP0 = numSIP;
    numDIP0 = numDIP;
    numSDIP0 = numSDIP;
    numPort0 = numPort;
#endif //DIFF_REPORT == 1
}


void t2Finalize() {
    hashTable_destroy(ipPHashMap);
    hashTable_destroy(ipSHashMap);
    hashTable_destroy(ipDHashMap);
    hashTable_destroy(portHashMap);

    free(ipPairConn);
    free(ipSConn);
    free(ipDConn);
    free(portConn);
    free(numPBCnt);
#if CS_MR_SPOOF > 0
    free(macSC);
#endif // CS_MR_SPOOF > 0
}
