/*
 * payloadDumper.c
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

#include "payloadDumper.h"

#include <errno.h>  // for errno, EEXIST


// Number of elements in array 'arr'
#define PLDUMP_ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

// Flag flows if number of ethertypes is 0 or if the ethertype matches
#if PLDUMP_L2 == 1
#define PLDUMP_FLAG_IF_NOETHTYPE_OR_MATCH(plDumpFlowP, flowP, plDumpEthTypes) { \
    const uint16_t ethTypes[] = plDumpEthTypes; \
    const size_t numEthTypes = PLDUMP_ARRAY_SIZE(ethTypes); \
    if (numEthTypes == 0) { \
        (plDumpFlowP)->stat |= PLDUMP_MTCH; \
    } else { \
        const uint16_t ethType = (flowP)->ethType; \
        for (uint_fast32_t i = 0; i < numEthTypes; i++) { \
            if (ethType == ethTypes[i]) { \
                (plDumpFlowP)->stat |= PLDUMP_MTCH; \
                break; \
            } \
        } \
    } \
}
#endif // PLDUMP_L2

// Flag flows if number of ports is 0 or if one of src/dst port matches
#define PLDUMP_FLAG_IF_NOPORT_OR_MATCH(plDumpFlowP, flowP, plDumpPorts) { \
    const uint16_t ports[] = plDumpPorts; \
    const size_t numPorts = PLDUMP_ARRAY_SIZE(ports); \
    if (numPorts == 0) { \
        (plDumpFlowP)->stat |= PLDUMP_MTCH; \
    } else { \
        const uint16_t srcPort = (flowP)->srcPort; \
        const uint16_t dstPort = (flowP)->dstPort; \
        for (uint_fast32_t i = 0; i < numPorts; i++) { \
            if (srcPort == ports[i] || dstPort == ports[i]) { \
                (plDumpFlowP)->stat |= PLDUMP_MTCH; \
                break; \
            } \
        } \
    } \
}


// Plugin variables

plDumpFlow_t *plDumpFlows;


// Static variables

#if ENVCNTRL > 0
static t2_env_t env[ENV_PLDUMP_N];
static const char *pldFld;
static const char *pldPrfx;
static const char *pldSffx;
#else // ENVCNTRL == 0
static const char * const pldFld = PLDUMP_FOLDER;
static const char * const pldPrfx = PLDUMP_PREFIX;
static const char * const pldSffx = PLDUMP_SUFFIX;
#endif // ENVCNTRL

static uint32_t pldFCnt;
static uint8_t pldStat;


// Static functions
static inline void dump_payload(packet_t *packet, unsigned long flowIndex);


// Tranalyzer functions

T2_PLUGIN_INIT("payloadDumper", "0.9.3", 0, 9);


void t2Init() {
    T2_PLUGIN_STRUCT_NEW(plDumpFlows);

#if ENVCNTRL > 0
    t2_get_env(PLUGIN_SRCH, ENV_PLDUMP_N, env);
    const uint8_t rmdir = T2_ENV_VAL_UINT(PLDUMP_RMDIR);
    pldFld = T2_ENV_VAL(PLDUMP_FOLDER);
    pldPrfx = T2_ENV_VAL(PLDUMP_PREFIX);
    pldSffx = T2_ENV_VAL(PLDUMP_SUFFIX);
#else // ENVCNTRL == 0
    const uint8_t rmdir = PLDUMP_RMDIR;
#endif // ENVCNTRL

    T2_MKPATH(pldFld, rmdir);

    if (sPktFile) fputs("pldStat" SEP_CHR, sPktFile);
}


binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;
    BV_APPEND_H8(bv, "pldStat", "payloadDumper status");
    return bv;
}


void t2OnNewFlow(packet_t *packet UNUSED, unsigned long flowIndex) {
    plDumpFlow_t * const plDumpFlowP = &plDumpFlows[flowIndex];
    memset(plDumpFlowP, '\0', sizeof(*plDumpFlowP));

#if (PLDUMP_L2 | PLDUMP_TCP | PLDUMP_UDP | PLDUMP_SCTP)
    const flow_t * const flowP = &flows[flowIndex];

#if PLDUMP_L2 == 1
    if (flowP->status & L2_FLOW) {
        PLDUMP_FLAG_IF_NOETHTYPE_OR_MATCH(plDumpFlowP, flowP, PLDUMP_ETHERTYPES);
    } else
#endif
        switch (flowP->l4Proto) {
#if PLDUMP_TCP == 1
            case L3_TCP:
                PLDUMP_FLAG_IF_NOPORT_OR_MATCH(plDumpFlowP, flowP, PLDUMP_TCP_PORTS);
                break;
#endif // PLDUMP_TCP == 1

#if PLDUMP_UDP == 1
            case L3_UDP:
                PLDUMP_FLAG_IF_NOPORT_OR_MATCH(plDumpFlowP, flowP, PLDUMP_UDP_PORTS);
                break;
#endif // PLDUMP_UDP == 1

#if PLDUMP_SCTP == 1
            case L3_SCTP:
                PLDUMP_FLAG_IF_NOPORT_OR_MATCH(plDumpFlowP, flowP, PLDUMP_SCTP_PORTS);
                break;
#endif // PLDUMP_SCTP == 1

            default:
                break;
        }
#endif // (PLDUMP_L2 | PLDUMP_TCP | PLDUMP_UDP | PLDUMP_SCTP)
}


#if ETH_ACTIVATE > 0
void t2OnLayer2(packet_t *packet UNUSED, unsigned long flowIndex) {
    if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;

    dump_payload(packet, flowIndex);
}
#endif // ETH_ACTIVATE > 0


void t2OnLayer4(packet_t *packet, unsigned long flowIndex) {
    dump_payload(packet, flowIndex);
}


static inline void dump_payload(packet_t *packet, unsigned long flowIndex) {
    plDumpFlow_t * const plDumpFlowP = &plDumpFlows[flowIndex];
    const flow_t * const flowP = &flows[flowIndex];
    const uint_fast8_t l4Proto = flowP->l4Proto;

#if PLDUMP_TCP == 1
    const tcpHeader_t * const tcpHdrP = TCP_HEADER(packet);
    const uint32_t tcpSeq = ((l4Proto == L3_TCP) ? ntohl(tcpHdrP->seq) : 0);
#endif // PLDUMP_TCP

#if (PLDUMP_L2 | PLDUMP_TCP | PLDUMP_UDP)
#if PLDUMP_START_OFF == 0
    const
#endif // PLDUMP_START_OFF
    uint16_t l7Len = packet->l7Len;
#endif // (PLDUMP_L2 | PLDUMP_TCP | PLDUMP_UDP)

    uint8_t pldStat = (plDumpFlowP->stat & PLDUMP_MTCH);

    if (!plDumpFlowP->stat) goto pldpkt;

    // only 1. frag packet will be processed
    if (!(flowP->status & L2_FLOW) && !t2_is_first_fragment(packet)) goto pldpkt;

#if (PLDUMP_MAX_BYTES == 0 && PLDUMP_START_OFF == 0 && PLDUMP_L2 == 0 && PLDUMP_SCTP == 0)
    const
#endif
    uint16_t snapL7len = packet->snapL7Len;

    const uint8_t *l7HdrP = packet->l7HdrP; // will be overwritten for SCTP

#if (PLDUMP_L2 | PLDUMP_UDP) && PLDUMP_START_OFF > 0
    if (FLOW_IS_L2(flowP) || l4Proto == L3_UDP) {
        if (snapL7len <= PLDUMP_START_OFF || l7Len <= PLDUMP_START_OFF) goto pldpkt;
        l7HdrP += PLDUMP_START_OFF;
        l7Len -= PLDUMP_START_OFF;
        snapL7len -= PLDUMP_START_OFF;
    }
#endif

    if (snapL7len == 0) goto pldpkt;

    pldStat |= (plDumpFlowP->stat & PLDUMP_DUMP); // TODO  what if an error occurs ?

    if (!plDumpFlowP->fd) {
        char filepath[MAX_FILENAME_LEN] = {};
        size_t len = snprintf(filepath, sizeof(filepath), "%s/%s", pldFld, pldPrfx);

#if PLDUMP_NAMES > 0
        char saddr[INET6_ADDRSTRLEN] = {};
        char daddr[INET6_ADDRSTRLEN] = {};

#if PLDUMP_L2 == 1
        if (FLOW_IS_L2(flowP)) {
            t2_mac_to_str(flowP->ethDS.ether_shost, saddr, sizeof(saddr));
            t2_mac_to_str(flowP->ethDS.ether_dhost, daddr, sizeof(daddr));
        } else
#endif // PLDUMP_L2 == 1
#if IPV6_ACTIVATE > 0
        if (FLOW_IS_IPV6(flowP)) {
            t2_ipv6_to_uncompressed(flowP->srcIP.IPv6, saddr, sizeof(saddr));
            t2_ipv6_to_uncompressed(flowP->dstIP.IPv6, daddr, sizeof(daddr));
        } else
#endif // IPV6_ACTIVATE > 0
        if (FLOW_IS_IPV4(flowP)) {
            t2_ipv4_to_uncompressed(flowP->srcIP.IPv4, saddr, sizeof(saddr));
            t2_ipv4_to_uncompressed(flowP->dstIP.IPv4, daddr, sizeof(daddr));
        }

#if PLDUMP_NAMES == 2
        const time_t sec = flowP->firstSeen.tv_sec;
        const intmax_t usec = flowP->firstSeen.tv_usec;
        len += snprintf(filepath+len, sizeof(filepath)-len, "%ld.%06jdT", sec, usec); // timestampT (sec, usec)
#endif // PLDUMP_NAMES == 2

        if (FLOW_IS_L2(flowP)) {
            len += snprintf(filepath+len, sizeof(filepath)-len, "%s-%s-0x%04" B2T_PRIX16, saddr, daddr, flowP->ethType);
        } else {
            len += snprintf(filepath+len, sizeof(filepath)-len, "%s.%05" PRIu16 "-%s.%05" PRIu16 "-%" PRIu8,
                    saddr, flowP->srcPort, daddr, flowP->dstPort, l4Proto);

#if PLDUMP_SCTP == 1
            if (l4Proto == L3_SCTP) {
                len += snprintf(filepath+len, sizeof(filepath)-len, "_%d", flowP->sctpStrm);
            }
#endif // PLDUMP_SCTP == 1
        }

#else // PLDUMP_NAMES == 0
        len += snprintf(filepath+len, sizeof(filepath)-len, "%" PRIu64 "_%c", flowP->findex, FLOW_DIR_C(flowP));

#if PLDUMP_SCTP == 1
        if (l4Proto == L3_SCTP) {
            len += snprintf(filepath+len, sizeof(filepath)-len, "_%d", flowP->sctpStrm);
        }
#endif // PLDUMP_SCTP == 1
#endif // PLDUMP_NAMES

        len += snprintf(filepath+len, sizeof(filepath)-len, "%s", pldSffx);

        if (len >= sizeof(filepath)) pldStat |= PLDUMP_FTRNC; // filename was truncated...

        plDumpFlowP->fd = file_manager_open(t2_file_manager, filepath, "w+b");
        if (!plDumpFlowP->fd) {
            T2_PERR(plugin_name, "Failed to open file '%s': %s", filepath, strerror(errno));
            pldStat |= PLDUMP_ERR;
            goto pldpkt;
        }

#if PLDUMP_TCP == 1
#if (PLDUMP_L2 | PLDUMP_UDP | PLDUMP_SCTP)
        if (l4Proto == L3_TCP) {
#endif // (PLDUMP_L2 | PLDUMP_UDP | PLDUMP_SCTP)
            plDumpFlowP->seqInit = tcpSeq;
            plDumpFlowP->seqNext = tcpSeq;  // Initialized here to prevent faulty detection of keep-alive
#if (PLDUMP_L2 | PLDUMP_UDP | PLDUMP_SCTP)
        }
#endif // (PLDUMP_L2 | PLDUMP_UDP | PLDUMP_SCTP)
#endif // PLDUMP_TCP == 1

        pldStat |= PLDUMP_DUMP;
        pldFCnt++;
    }

    long offset = 0;

#if PLDUMP_L2 == 1
    if (flowP->status & L2_FLOW) {
        offset = plDumpFlowP->lastOff;
        plDumpFlowP->lastOff += l7Len;
    } else
#endif // PLDUMP_L2 == 1
    switch (l4Proto) {
#if PLDUMP_TCP == 1
        case L3_TCP: {
            if (plDumpFlowP->seqInit > tcpSeq) {
                pldStat |= PLDUMP_TCP_SQERR;
                goto pldpkt;
            }

            const uint8_t tcpFlags = *((uint8_t*)tcpHdrP + 13);
            if (l7Len <= 1 && !(tcpFlags & TH_SYN_FIN_RST) && (tcpSeq == plDumpFlowP->seqNext - 1)) {
                // TCP keep-alive
                pldStat |= PLDUMP_TCP_SQERR;
                goto pldpkt;
            }

            offset = tcpSeq - plDumpFlowP->seqInit;
            break;
        }
#endif // PLDUMP_TCP == 1

#if PLDUMP_UDP == 1
        case L3_UDP: {
            offset = plDumpFlowP->lastOff;
            plDumpFlowP->lastOff += l7Len;
            break;
        }
#endif // PLDUMP_UDP == 1

#if PLDUMP_SCTP == 1
        case L3_SCTP: {
            const sctpChunk_t * const sctpChunkP = (sctpChunk_t*)packet->l7SctpHdrP;
            const int32_t sctpL7Len = packet->snapSctpL7Len;
            const int32_t sctpChnkLen = ntohs(sctpChunkP->len);
            if (sctpChnkLen == 0) goto pldpkt;
            if ((sctpChunkP->type & SCTP_C_TYPE) != SCTP_CT_DATA) goto pldpkt;
            if (sctpL7Len < sctpChnkLen) pldStat |= PLDUMP_PTRNC;
            const uint32_t tsn = ntohl(sctpChunkP->tsn_it_cta);
            if (!(plDumpFlowP->stat & PLDUMP_SCTP_FDP)) {
                plDumpFlowP->tsnInit = tsn;
                plDumpFlowP->tsnLst = tsn;
                pldStat |= PLDUMP_SCTP_FDP;
            } else if (tsn - plDumpFlowP->tsnLst != 1) {
                pldStat |= PLDUMP_SCTP_SQERR;
            }
            plDumpFlowP->tsnLst = tsn;
            if (plDumpFlowP->tsnInit > tsn) {
                pldStat |= PLDUMP_SCTP_SQERR;
                goto pldpkt;
            }
            offset = plDumpFlowP->lastOff;
            snapL7len = sctpChnkLen - 16;
            plDumpFlowP->lastOff += snapL7len;
            l7HdrP = (uint8_t*)sctpChunkP + 16;
            break;
        }
#endif // PLDUMP_SCTP == 1

        default:
            /* Should not happen */
            goto pldpkt;
    }

#if PLDUMP_MAX_BYTES > 0
    if (offset + snapL7len > PLDUMP_MAX_BYTES) {
        if (offset >= PLDUMP_MAX_BYTES) goto pldpkt;
        snapL7len = MIN(snapL7len, PLDUMP_MAX_BYTES - offset);
    }
#endif // PLDUMP_MAX_BYTES > 0

    FILE * const fp = file_manager_fp(t2_file_manager, plDumpFlowP->fd);
    if (UNLIKELY(!fp)) {
        plDumpFlowP->stat |= PLDUMP_ERR;
        T2_PERR(plugin_name, "Failed to get file pointer for flow %" PRIu64, flowP->findex);
        goto pldpkt;
    }

    if (offset >= 0) fseek(fp, offset, SEEK_SET);

    fwrite(l7HdrP, 1, snapL7len, fp);

pldpkt:

#if PLDUMP_TCP == 1
    if (l4Proto == L3_TCP) plDumpFlowP->seqNext = tcpSeq + l7Len;
#endif // PLDUMP_TCP == 1

    plDumpFlowP->stat |= pldStat;

    if (sPktFile) fprintf(sPktFile, "0x%02" B2T_PRIX8 SEP_CHR, pldStat);
}


void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {
    plDumpFlow_t * const plDumpFlowP = &plDumpFlows[flowIndex];

    pldStat |= plDumpFlowP->stat;

    OUTBUF_APPEND_U8(buf, plDumpFlowP->stat);

    if (plDumpFlowP->fd) {
        file_manager_close(t2_file_manager, plDumpFlowP->fd);
        // Defensive programming
        plDumpFlowP->fd = NULL;
    }
}


void t2PluginReport(FILE *stream) {
    if (pldStat) {
        T2_FPLOG_AGGR_HEX(stream, plugin_name, pldStat)
        T2_FPLOG_NUMP(stream, plugin_name, "Number of non zero content dumped flows", pldFCnt, totalFlows);
    }
}


void t2Finalize() {
#if ENVCNTRL > 0
    t2_free_env(ENV_PLDUMP_N, env);
#endif // ENVCNTRL > 0

    free(plDumpFlows);
}
