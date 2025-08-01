/*
 * pcapd.c
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

#include "pcapd.h"

#include <ctype.h> // for isspace
#include <errno.h> // for errno

#if PD_VLNSHFT == 1
#include "proto/vlan.h"
#endif // PD_VLNSHFT == 1

#if PD_MODE_OUT == 1
#include "uthash.h"


#define HASH_FIND_UINT64(head, key, out) \
    HASH_FIND(hh, head, key, sizeof(uint64_t), out)
#define HASH_ADD_UINT64(head, key, add) \
    HASH_ADD(hh, head, key, sizeof(uint64_t), add)


typedef struct {
    uint64_t key; // flowIndex
    pcap_dumper_t *val;
    UT_hash_handle hh;
} pd_lru_item_t;


#define PD_LRU_ITEM_FREE(item) \
    pcap_dump_close(item->val); \
    item->val = NULL; \
    free(item);


static pd_lru_item_t *cache;
#endif // PD_MODE_OUT == 1


// Plugin variables

pcpdFlow_t *pcpdFlows;


// Static variables

static pcap_dumper_t *pd;
static pcap_t *fdPcap;
static uint64_t *findexP;
static uint64_t pd_npkts;
static uint32_t pdIndexCnt;
static char filename[MAX_FILENAME_LEN];

//#if PD_VLNSHFT == 1
//static pdFlow_t *pdFlows;
//#endif // PD_VLNSHFT == 1

#if PD_SPLIT == 1 || PD_MODE_OUT == 1
// -W option
static char *oFileNumP;
#if PD_MODE_OUT == 0
static uint64_t oFileNum, oFileLn;
#endif
#endif // PD_SPLIT == 1 || PD_MODE_OUT == 1

#if PD_MODE_OUT == 1
#if ENVCNTRL > 0
static uint32_t pdMxFd;
#else // ENVCNTRL == 0
static const uint32_t pdMxFd = PD_MAX_FD;
#endif // ENVCNTRL
#endif // PD_MODE_OUT == 1


// Function prototypes

static inline void pcapd_load_input_file(const char *filename);
static inline void claimInfo(packet_t* packet, unsigned long flowIndex);


// Tranalyzer plugin functions

T2_PLUGIN_INIT("pcapd", "0.9.3", 0, 9);


void t2Init() {
#if PD_MODE_IN == 0
    T2_PLUGIN_STRUCT_NEW(pcpdFlows);
#endif // PD_MODE_IN == 0

#if ENVCNTRL > 0
    t2_env_t env[ENV_PD_N] = {};
    t2_get_env(PLUGIN_SRCH, ENV_PD_N, env);
#if PD_MODE_OUT == 1
    pdMxFd = T2_ENV_VAL_UINT(PD_MAX_FD);
#endif // PD_MODE_OUT == 1
    const char * const suffix = T2_ENV_VAL(PD_SUFFIX);
#else // ENVCNTRL == 0
    const char * const suffix = PD_SUFFIX;
#endif // ENVCNTRL

    if (esomFileName) pcapd_load_input_file(esomFileName);
    else pdIndexCnt = 1;

    const char * const temp = (esomFileName ? esomFileName : baseFileName);
    t2_strcat(filename, sizeof(filename), temp, suffix, NULL);

    const int snapLen = pcap_snapshot(captureDescriptor);
#if TSTAMP_PREC == 1
    fdPcap = pcap_open_dead_with_tstamp_precision(DLT_EN10MB, snapLen, PCAP_TSTAMP_PRECISION_NANO);
#else // TSTAMP_PREC == 0
    fdPcap = pcap_open_dead(DLT_EN10MB, snapLen);
#endif // TSTAMP_PREC

#if PD_MODE_OUT == 0
    if (UNLIKELY(!(pd = pcap_dump_open(fdPcap, filename)))) {
        T2_PFATAL(plugin_name, "Failed to open file '%s' for writing: %s", filename, pcap_geterr(fdPcap));
    }
#endif

#if PD_MODE_OUT == 0 && PD_SPLIT == 1
    if (capType & OFILELN) {
        oFileLn = (uint64_t)oFragFsz;
#endif // PD_MODE_OUT == 0 && PD_SPLIT == 1
#if PD_MODE_OUT == 1 || PD_SPLIT == 1
        oFileNumP = filename + strlen(filename);
#endif // PD_MODE_OUT == 1 || PD_SPLIT == 1
#if PD_MODE_OUT == 0 && PD_SPLIT == 1
        oFileNum = oFileNumB;
        sprintf(oFileNumP, "%" PRIu64, oFileNum);
    }
#endif // PD_MODE_OUT == 0 && PD_SPLIT == 1

#if ENVCNTRL > 0
    t2_free_env(ENV_PD_N, env);
#endif // ENVCNTRL == 0
}


static inline void pcapd_load_input_file(const char *filename) {
#if PD_LBSRCH == 1
    FILE * const file = t2_fopen(filename, "rb");
    if (UNLIKELY(!file)) exit(EXIT_FAILURE);

    uint64_t findex;
    fread(&findex, sizeof(findex), 1, file);
    pdIndexCnt = (uint32_t)findex;
    findexP = t2_malloc_fatal(sizeof(*findexP) * (pdIndexCnt+1));
    findexP[0] = 0;
    const size_t nrec = fread(&findexP[1], sizeof(findexP[1]), pdIndexCnt, file);
    if (UNLIKELY((uint32_t)nrec != pdIndexCnt)) {
        T2_WRN("Expected %" PRId32 " records in file '%s', but found %zu", pdIndexCnt, filename, nrec);
    }
#else // PD_LBSRCH == 0
    FILE * const file = t2_fopen(filename, "r");
    if (UNLIKELY(!file)) exit(EXIT_FAILURE);

    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    while ((read = getline(&line, &len, file)) != -1) {
        if (line[0] < '0' || line[0] > '9') continue;
        pdIndexCnt++;
    }

    if (UNLIKELY(pdIndexCnt == 0)) {
        T2_PFATAL(plugin_name, "No usable information in file '%s'", filename);
    }

    findexP = t2_malloc_fatal(sizeof(*findexP) * pdIndexCnt);
    rewind(file);

    uint32_t i = 0;
    while ((read = getline(&line, &len, file)) != -1 && i < pdIndexCnt) {
        if (line[0] < '0' || line[0] > '9') continue;
        sscanf(line, "%" SCNu64, &findexP[i++]); // user index file
    }

    free(line);
#endif // PD_LBSRCH

    fclose(file);

    T2_PINF(plugin_name, "%" PRIu32 " flow indices", pdIndexCnt);
}


#if PD_MODE_IN == 0 && PD_LBSRCH == 1
static inline uint64_t fndfindex(uint64_t findex) {
    if (!findex) return 0;

    int middle;
#if PD_LBSRCH == 1
    int start = 1;
    int end = pdIndexCnt;
#else // PD_LBSRCH == 0
    int start = 0;
    int end = pdIndexCnt - 1;
#endif // PD_LBSRCH

    while (start <= end) {
        middle = (end + start) / 2; // define middle as middle between start and end.
        const uint64_t i = findexP[middle];
        if (findex == i) {
            return i; // return the located malsite codes.
        } else if (findex < i) {
            end = middle - 1; // set the endpoint one under the currently middle.
        } else {
            start = middle + 1; // set the startpoint one over the currently middle.
        }
    }

    return 0; // in case the ip isn't in the file, return 0.
}
#endif // PD_MODE_IN == 0 && PD_LBSRCH == 1


#if PD_MODE_OUT == 1
static inline pcap_dumper_t *pdOpenDump(uint64_t flowIndex) {
    const flow_t * const flowP = &flows[flowIndex];

    pd_lru_item_t *item;
    HASH_FIND_UINT64(cache, &flowIndex, item);
    if (item) { // file already open
        HASH_DEL(cache, item);
        HASH_ADD_UINT64(cache, key, item);
        return item->val;
    }

    // open the file
    sprintf(oFileNumP, "%" PRIu64, flowP->findex);
    if (UNLIKELY(!(pd = pcap_dump_open_append(fdPcap, filename)))) {
        if (UNLIKELY(!(pd = pcap_dump_open(fdPcap, filename)))) {
            T2_PFATAL(plugin_name, "Failed to open file '%s' for writing: %s", filename, pcap_geterr(fdPcap));
        }
    }

    item = t2_malloc_fatal(sizeof(*item));
    item->key = flowIndex;
    item->val = pd;
    HASH_ADD_UINT64(cache, key, item);

    if (HASH_COUNT(cache) > pdMxFd) {
        pd_lru_item_t *tmp_item;
        // close least recently used file
        HASH_ITER(hh, cache, item, tmp_item) {
            HASH_DEL(cache, item);
            PD_LRU_ITEM_FREE(item);
            break;
        }
    }

    return pd;
}
#endif // PD_MODE_OUT == 1


#if PD_MODE_IN == 0
void t2OnNewFlow(packet_t *packet UNUSED, unsigned long flowIndex) {
    pcpdFlow_t * const pcpdFlowP = &pcpdFlows[flowIndex];
    memset(pcpdFlowP, '\0', sizeof(*pcpdFlowP));

    if (!esomFileName) return;

    const flow_t * const flowP = &flows[flowIndex];

#if PD_DIRSEL == 2    // Select A flows only
    if (FLOW_IS_B(flowP)) return;
#elif PD_DIRSEL == 3  // Select B flows only
    if (FLOW_IS_A(flowP)) return;
#endif // PD_DIRSEL

#if PD_EQ == 0
    pcpdFlowP->stat = PCPD_DMP;
#endif // PD_EQ == 0

#if PD_LBSRCH == 1
    if (fndfindex(flowP->findex)) {
#else // PD_LBSRCH == 0
    for (uint_fast32_t i = 0; i < pdIndexCnt; i++) {
        if (flowP->findex == findexP[i]) {
#endif // PD_LBSRCH
#if PD_EQ == 1
            pcpdFlowP->stat = PCPD_DMP;
#else // PD_EQ == 0
            pcpdFlowP->stat = 0;
#endif // PD_EQ
#if PD_LBSRCH == 0
        }
#endif // PD_LBSRCH == 0
    }
}
#endif // PD_MODE_IN == 0


void t2OnLayer2(packet_t* packet, unsigned long flowIndex) {
    if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;
    claimInfo(packet, flowIndex);
}


void t2OnLayer4(packet_t* packet, unsigned long flowIndex) {
    claimInfo(packet, flowIndex);
}


static inline void claimInfo(packet_t* packet, unsigned long flowIndex
#if PD_MODE_IN != 0 && PD_MODE_OUT != 1
    UNUSED
#endif
) {

#if PD_MODE_PKT == 1
    if (numPackets < PD_STRTPKT) return;
#if PD_ENDPKT > 0
    if (numPackets > PD_ENDPKT) return;
#endif // PD_ENDPKT > 0
#endif // PD_MODE_PKT == 1

#if PD_MODE_IN == 0
    flow_t * const flowP = &flows[flowIndex];
#endif // PD_MODE_IN == 0

#if PD_MODE_IN == 0
    pcpdFlow_t * const pcpdFlowP = &pcpdFlows[flowIndex];
    if (!esomFileName) {
#if PD_EQ == 0
        if ((flowP->status & FL_ALARM) == 0) {
#else // PD_EQ == 1
        if ((flowP->status & FL_ALARM)) {
#endif // PD_EQ
            pcpdFlowP->stat = PCPD_DMP;
#if PD_OPP == 1
            const uint64_t revFlowInd = flowP->oppositeFlowIndex;
            if ((revFlowInd != HASHTABLE_ENTRY_NOT_FOUND)) pcpdFlows[revFlowInd].stat = PCPD_DMP;
#endif // PD_OPP == 1
        }
    }

    if (!pcpdFlowP->stat) return;
#endif // PD_MODE_IN == 0

#if PD_MODE_OUT == 1
    pd = pdOpenDump(flowIndex);
#endif // PD_MODE_OUT == 1

#if PD_TSHFT == 1
    struct timeval *tm = (struct timeval*)&packet->pcapHdrP->ts;
    tm->tv_usec += PD_TTSFTNMS;
    if (tm->tv_usec >= TSTAMPFAC) {
        tm->tv_usec -= TSTAMPFAC;
        tm->tv_sec++;
    }
    tm->tv_sec += PD_TTSFTS;
#endif // PD_TSHFT == 1

#if PD_MACSHFT == 1
    ethDS_t * const ethDS = &((ethernetHeader_t*)packet->l2HdrP)->ethDS;
    ethDS->ether_dhost[5] += PD_MACDSHFT;
    ethDS->ether_shost[5] += PD_MACSSHFT;
#endif // PD_MACSHFT == 1

#if PD_VLNSHFT == 1
    if ((packet->status & L2_VLAN) && packet->vlanHdrP) {
        int i = 0;
        uint16_t ethType;
        do {
            ethType = (ntohl(packet->vlanHdrP[i]) & VLAN_ETYPE_MASK32);
            i++;
        } while (i < PDMXNUMVLN && ETHERTYPE_IS_VLAN(ethType));

        if (i > 0) {
            uint32_t *ivl = (uint32_t*)&packet->vlanHdrP[--i];
            const uint32_t k = (*ivl & ~VLAN_ID_MASK32n);
            *ivl = (k | ntohl(((ntohl(*ivl) & VLAN_ID_MASK32) + (PD_VLNISHFT << 16)) & VLAN_ID_MASK32));
        }
    }
#endif // PD_VLNSHFT == 1

#if (PD_IPSHFT == 1 || PD_TTLSHFT == 1 || PD_CHKSUML3 == 1)
    const uint_fast8_t ipver = PACKET_IPVER(packet);
    if (ipver == 4) {
        ipHeader_t * const ipHdrP = IPV4_HEADER(packet);

#if PD_IPSHFT == 1
        ipHdrP->ip_src.s_addr = htonl(ntohl(ipHdrP->ip_src.s_addr) + PD_IP4SHFT);
        ipHdrP->ip_dst.s_addr = htonl(ntohl(ipHdrP->ip_dst.s_addr) + PD_IP4SHFT);
#endif // PD_IPSHFT

#if PD_TTLSHFT == 2
        ipHdrP->ip_ttl = (ipHdrP->ip_ttl - rand() % PD_TTL) % PD_TTLMOD;
#elif PD_TTLSHFT == 1
        ipHdrP->ip_ttl = (ipHdrP->ip_ttl - PD_TTL) % PD_TTLMOD;
#endif // PD_TTLSHFT

#if PD_CHKSUML3 == 1
        const uint8_t * const hdr8 = (uint8_t*)ipHdrP;
        const uint16_t * const hdr16 = (uint16_t*)hdr8;
        ipHdrP->ip_sum = ~(Checksum(hdr16, 0, packet->l3HdrLen, 5));
#endif // PD_CHKSUML3 == 1
#if PD_IPSHFT == 1 || PD_TTLSHFT == 1
    } else if (ipver == 6) {
        ip6Header_t * const ip6HdrP = IPV6_HEADER(packet);

#if PD_IPSHFT == 1
        ip6HdrP->ip_src.IPv6L[1] = htonl(ntohl(ip6HdrP->ip_src.IPv6L[1]) + PD_IP6SHFT);
        ip6HdrP->ip_dst.IPv6L[1] = htonl(ntohl(ip6HdrP->ip_dst.IPv6L[1]) + PD_IP6SHFT);
#endif // PD_IPSHFT

#if PD_TTLSHFT == 2
        ip6HdrP->ip_ttl = (ip6HdrP->ip_ttl - rand() % PD_TTL) % PD_TTLMOD;
#elif PD_TTLSHFT == 1
        ip6HdrP->ip_ttl = (ip6HdrP->ip_ttl - PD_TTL) % PD_TTLMOD;
#endif // PD_TTLSHFT
#endif // PD_IPSHFT == 1 || PD_TTLSHFT == 1
    }
#endif // (PD_IPSHFT == 1 || PD_TTLSHFT == 1 || PD_CHKSUML3 == 1)

    pcap_dump((u_char*)pd, packet->pcapHdrP, packet->raw_packet);

    pd_npkts++;

#if (PD_MODE_OUT == 0 && PD_SPLIT == 1)
    if (capType & OFILELN) {
        const uint64_t offset = pcap_dump_ftell(pd);
        if (offset >= oFileLn) {
            pcap_dump_close(pd);
            oFileNum++;
            sprintf(oFileNumP, "%" PRIu64, oFileNum);
            if (UNLIKELY(!(pd = pcap_dump_open(fdPcap, filename)))) {
                T2_PFATAL(plugin_name, "Failed to open file '%s' for writing: %s", filename, pcap_geterr(fdPcap));
            }
        }
    }
#endif // (PD_MODE_OUT == 0 && PD_SPLIT == 1)
}


#if PD_MODE_OUT == 1
void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf UNUSED) {
    pd_lru_item_t *item;
    HASH_FIND_UINT64(cache, &flowIndex, item);
    if (item) {
        HASH_DEL(cache, item);
        PD_LRU_ITEM_FREE(item);
    }
}
#endif // PD_MODE_OUT == 1


void t2PluginReport(FILE *stream) {
    T2_FPLOG_NUMP(stream, plugin_name, "number of packets extracted", pd_npkts, numPackets);
}


void t2Finalize() {
    // TODO delete file if empty
#if PD_MODE_OUT == 0
    if (LIKELY(pd != NULL)) {
        pcap_dump_close(pd);
        free(findexP);
    }
#endif
}
