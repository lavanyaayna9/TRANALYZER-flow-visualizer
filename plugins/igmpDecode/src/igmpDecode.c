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

#include "igmpDecode.h"


// Global variables

igmp_flow_t *igmp_flows;


// Static variables

static uint8_t igmpStat;
static uint64_t numIGMPPackets;
static uint64_t numIGMPQueries;
static uint64_t numIGMPReports;
static uint64_t numIGMPGeneralQueries;
static uint64_t numIGMPInvalidQueries;
static uint64_t numIGMPBadChksum;
static uint64_t numIGMPBadLength;
static uint64_t numIGMPBadTTL;
static uint64_t numIGMPGroupSpecificQueries;
static uint64_t numIGMPLeave;
static uint64_t numIGMPJoin;
static uint64_t num_igmp_v[IGMP_V_N];
static uint64_t num_igmp[IGMP_TYPE_N];
static uint64_t num_dvmrp[DVMRP_CODES_N];
static uint64_t num_pimv1[PIM_V1_CODES_N];

#if IGMP_STATFILE == 1
static const char *dvmrp_code[] = {
    "__UNUSED__",
    "DVMRP_PROBE",
    "DVMRP_ROUTE_REPORT",
    "DVMRP_OLD_ASK_NEIGHBORS",
    "DVMRP_OLD_NEIGHBORS_REPLY",
    "DVMRP_ASK_NEIGHBORS",
    "DVMRP_NEIGHBORS_REPLY",
    "DVMRP_PRUNE",
    "DVMRP_GRAFT",
    "DVMRP_GRAFT_ACK"
};

static const char *pimv1_code[] = {
    "PIM_V1_QUERY",
    "PIM_V1_REGISTER",
    "PIM_V1_REGISTER_STOP",
    "PIM_V1_JOIN_PRUNE",
    "PIM_V1_RP_REACHABLE",
    "PIM_V1_ASSERT",
    "PIM_V1_GRAFT",
    "PIM_V1_GRAFT_ACK",
    "PIM_V1_MODE"
};
#endif // IGMP_STATFILE == 1


// Macros

#define IGMP_PERCENT(num, tot) (100.0f * (num) / (float)(tot))
#define IGMP_LOG_TYPE_CODE(stream, type, code, num, tot) \
    if ((num) > 0) { \
        fprintf((stream), "%s\t%s\t%30" PRIu64" [%6.02f%%]\n", \
                igmpTypeToStr(type), (code), (num), IGMP_PERCENT((num), (tot))); \
    }


// Function prototypes

#if IGMP_STATFILE == 1
static const char *igmpTypeToStr(uint16_t type);
#endif


// Tranalyzer function

T2_PLUGIN_INIT("igmpDecode", "0.9.3", 0, 9);


void t2Init() {
    T2_PLUGIN_STRUCT_NEW(igmp_flows);
}


binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;
    BV_APPEND_H8(bv  , "igmpStat"     , "IGMP status");
    BV_APPEND_I8_R(bv, "igmpVersion"  , "IGMP version");
#if IGMP_TC_MD == 0
    BV_APPEND_H32(bv , "igmpAType"    , "IGMP aggregated type");
#endif // IGMP_TC_MD == 0
    BV_APPEND_IP4(bv , "igmpMCastAddr", "IGMP multicast address");
    BV_APPEND_U16(bv , "igmpNRec"     , "IGMP number of records");
    return bv;
}


void t2OnNewFlow(packet_t *packet UNUSED, unsigned long flowIndex) {
    igmp_flow_t *igmpFlowP = &igmp_flows[flowIndex];
    memset(igmpFlowP, '\0', sizeof(*igmpFlowP));
}


#if IPV6_ACTIVATE == 1
void t2OnLayer4(packet_t *packet, unsigned long flowIndex UNUSED) {
#else // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
void t2OnLayer4(packet_t *packet, unsigned long flowIndex) {
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
    // Only allow IGMP messages to pass through here
    if (packet->l4Proto != IPPROTO_IGMP) return;

    const uint16_t snaplen = packet->snapL4Len;
    if (snaplen == 0) return;

    // only 1. frag packet will be processed
    if (!t2_is_first_fragment(packet)) return;

#if IPV6_ACTIVATE > 0
    // IGMP is used on IPv4 networks
    if (PACKET_IS_IPV6(packet)) return;
#endif // IPV6_ACTIVATE > 0

    const ipHeader_t * const ipHdrP = IPV4_HEADER(packet);
    if (ipHdrP->ip_off & FRAGID_N) return;

    igmp_flow_t *igmpFlowP = &igmp_flows[flowIndex];
    const igmpHeader_t * const igmpHdrP = IGMP_HEADER(packet);

    numIGMPPackets++;

    const uint8_t igmpType = igmpHdrP->type;
    num_igmp[igmpType]++;

    if (packet->snapL4Len < IGMP_MIN_LEN) {
        igmpFlowP->stat |= IGMP_STAT_BAD_LENGTH;
        numIGMPInvalidQueries++;
        numIGMPBadLength++;
        return;
    }

    const struct in_addr dstIp = ipHdrP->ip_dst;
    const uint8_t code = igmpHdrP->code;

    struct in_addr igmpGroup = igmpHdrP->group;
    int8_t igmpVersion = IGMP_UNKNOWN;

    const uint16_t calcChksum = ~Checksum((uint16_t*)packet->l4HdrP, 0, packet->snapL4Len, 1);

    if (igmpHdrP->checksum != calcChksum) {
        igmpFlowP->stat |= IGMP_STAT_BAD_CHECKSUM;
        numIGMPBadChksum++;
    }

    switch (igmpType) {

        case IGMP_MEMBERSHIP_QUERY: {
            numIGMPQueries++;
            // see rfc3376, section 7
            if (snaplen >= IGMP_V3_QUERY_MIN_LEN) {
                igmpVersion = IGMP_V3;
                igmpv3_query_t *query = (igmpv3_query_t*)packet->l4HdrP;
                if (query->nsrcs > 0) {
                    igmpFlowP->nrec += htons(query->nsrcs);
                } else if (igmpGroup.s_addr != 0) {
                    numIGMPGroupSpecificQueries++;
                } else {
                    numIGMPGeneralQueries++;
                }
                if (igmpGroup.s_addr != 0) igmpFlowP->stat |= IGMP_STAT_INVALID_QUERY;
            } else if (packet->snapL4Len == IGMP_MIN_LEN) {
                if (code == 0) {
                    igmpVersion = IGMP_V1;
                } else {
                    igmpVersion = IGMP_V2;
                    if (dstIp.s_addr == IGMP_ALL_HOSTS && igmpGroup.s_addr == 0) {
                        numIGMPGeneralQueries++;
                    } else if (dstIp.s_addr == igmpGroup.s_addr) {
                        numIGMPGroupSpecificQueries++;
                    }
                }
            } else {
                // Invalid query
                igmpFlowP->stat |= IGMP_STAT_BAD_LENGTH;
                numIGMPInvalidQueries++;
                numIGMPBadLength++;
            }
            break;
        }

        case IGMP_V1_MEMBERSHIP_REPORT:
            igmpVersion = IGMP_V1;
            numIGMPReports++;
            numIGMPJoin++;
            break;

        case IGMP_V2_MEMBERSHIP_REPORT:
            igmpVersion = IGMP_V2;
            numIGMPReports++;
            numIGMPJoin++;
            break;

        case IGMP_V2_LEAVE_GROUP:
            igmpVersion = IGMP_V2;
            numIGMPLeave++;
            if (dstIp.s_addr != IGMP_V2_ALL_ROUTERS) igmpFlowP->stat |= IGMP_STAT_INVALID_QUERY;
            break;

        case IGMP_V3_MEMBERSHIP_REPORT: {
            igmpVersion = IGMP_V3;
            numIGMPReports++;
            igmpv3_report_t *report = (igmpv3_report_t*)packet->l4HdrP;
            if (snaplen < sizeof(*report)) break;
            const uint16_t ngrec = htons(report->ngrec);
            if (packet->snapL4Len < sizeof(*report) + (ngrec-1)*sizeof(igmpv3_grec_t)) break;
            igmpFlowP->nrec += ngrec;
            igmpGroup = dstIp;
            if (dstIp.s_addr != IGMP_V3_ALL_ROUTERS) igmpFlowP->stat |= IGMP_STAT_INVALID_QUERY;
            for (uint_fast16_t i = 0; i < ngrec; i++) {
                switch (report->grec[i].type) {
                    case IGMP_V3_MODE_IS_INCLUDE:
                    case IGMP_V3_CHANGE_TO_INCLUDE:
                       numIGMPLeave++;
                       break;
                    case IGMP_V3_MODE_IS_EXCLUDE:
                    case IGMP_V3_CHANGE_TO_EXCLUDE:
                       numIGMPJoin++;
                       break;
                }
            }
            break;
        }

        /* IGMPv0 */
        case IGMP_V0_CREATE_GROUP_REQUEST:
        case IGMP_V0_CREATE_GROUP_REPLY:
            igmpVersion = IGMP_V0;
            break;
        case IGMP_V0_JOIN_GROUP_REQUEST:
            igmpVersion = IGMP_V0;
            numIGMPJoin++;
            break;
        case IGMP_V0_JOIN_GROUP_REPLY:
            igmpVersion = IGMP_V0;
            break;
        case IGMP_V0_LEAVE_GROUP_REQUEST:
            igmpVersion = IGMP_V0;
            numIGMPLeave++;
            break;
        case IGMP_V0_LEAVE_GROUP_REPLY:
        case IGMP_V0_CONFIRM_GROUP_REQUEST:
        case IGMP_V0_CONFIRM_GROUP_REPLY:
            igmpVersion = IGMP_V0;
            break;

        /* DVMRP */
        case IGMP_DVMRP: {
            if (code < DVMRP_CODES_N) num_dvmrp[code]++;
            if (code == DVMRP_PROBE) {
                if (ipHdrP->ip_ttl != 1) {
                    numIGMPBadTTL++;
                    igmpFlowP->stat |= IGMP_STAT_BAD_TTL;
                }
            }
            //igmp_dvmrp_t *dvmrp = (igmp_dvmrp_t*)packet->l4HdrP;
            //igmpVersion = dvmrp->maj_version;
            break;
        }

        /* PIMv1 */
        case IGMP_PIM_V1:
            if (code < PIM_V1_CODES_N) num_pimv1[code]++;
            break;

        /* Mtrace */
        case IGMP_MTRACE:
        case IGMP_MTRACE_RESP: {
            igmp_mtrace_t *mtrace = (igmp_mtrace_t*)packet->l4HdrP;
            if (snaplen < sizeof(*mtrace)) break;
            igmpFlowP->nrec += mtrace->hops;
            break;
        }

        /* MRD */
        case IGMP_MRD_ROUTER_ADVERT:
        case IGMP_MRD_ROUTER_SOLICIT:
        case IGMP_MRD_ROUTER_TERM:
            if (ipHdrP->ip_ttl != 1) {
                numIGMPBadTTL++;
                igmpFlowP->stat |= IGMP_STAT_BAD_TTL;
            }
            break;

        /* RGMP */
        case IGMP_RGMP_LEAVE_GROUP:
        case IGMP_RGMP_JOIN_GROUP:
        case IGMP_RGMP_BYE:
        case IGMP_RGMP_HELLO:
            if (ipHdrP->ip_ttl != 1) {
                numIGMPBadTTL++;
                igmpFlowP->stat |= IGMP_STAT_BAD_TTL;
            }
            if (dstIp.s_addr != IGMP_RGMP_ADDR) {
                numIGMPInvalidQueries++;
                igmpFlowP->stat |= IGMP_STAT_INVALID_QUERY;
            }
            break;
    }

    if (igmpVersion >= 0) {
        num_igmp_v[igmpVersion]++;
        if (ipHdrP->ip_ttl != 1) {
            numIGMPBadTTL++;
            igmpFlowP->stat |= IGMP_STAT_BAD_TTL;
        }
    }

    igmpFlowP->version = igmpVersion;
    igmpFlowP->mcast_addr.IPv4 = igmpGroup;

#if IGMP_TC_MD == 0
    if (igmpType < IGMP_TYPEFIELD-1) igmpFlowP->type_bfield |= (1 << igmpType);
#endif // IGMP_TC_MD == 0
}


void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {
    const igmp_flow_t * const igmpFlowP = &igmp_flows[flowIndex];

    igmpStat |= igmpFlowP->stat;

    OUTBUF_APPEND_U8(buf, igmpFlowP->stat);  // igmpStat

    // igmpVersion
    if (igmpFlowP->version == 0) {
        OUTBUF_APPEND_NUMREP_ZERO(buf);
    } else {
        OUTBUF_APPEND_NUMREP_ONE(buf);
        OUTBUF_APPEND_I8(buf, igmpFlowP->version);
    }

#if IGMP_TC_MD == 0
    OUTBUF_APPEND_U32(buf, igmpFlowP->type_bfield); // igmpAType
#endif // IGMP_TC_MD == 0

    OUTBUF_APPEND_IP4(buf, igmpFlowP->mcast_addr);  // igmpMCastAddr
    OUTBUF_APPEND_U16(buf, igmpFlowP->nrec);        // igmpNRec
}


void t2PluginReport(FILE *stream) {
    if (numIGMPPackets) {
        T2_FPLOG_AGGR_HEX(stream, plugin_name, igmpStat);
        T2_FPLOG_NUMP0(stream, plugin_name, "Number of IGMP packets", numIGMPPackets, numPackets);
        T2_FPLOG_NUMP(stream, plugin_name, "Number of IGMP queries", numIGMPQueries, numIGMPPackets);
        if (numIGMPReports) {
            T2_FPLOG_NUMP0(stream, plugin_name, "Number of IGMP reports", numIGMPReports, numIGMPPackets);
            T2_FPLOG(stream, plugin_name, "IGMP query / report ratio: %.2f", numIGMPQueries/(double)numIGMPReports);
        }
    }
}


void t2Finalize() {
    free(igmp_flows);

#if IGMP_STATFILE == 1

    t2_env_t env[ENV_IGMP_N] = {};
#if ENVCNTRL > 0
    t2_get_env(PLUGIN_SRCH, ENV_IGMP_N, env);
#else // ENVCNTRL == 0
    T2_SET_ENV_STR(IGMP_NOCODE);
    T2_SET_ENV_STR(IGMP_SUFFIX);
#endif // ENVCNTRL

    // open IGMP statistics file
    FILE *file = t2_fopen_with_suffix(baseFileName, T2_ENV_VAL(IGMP_SUFFIX), "w");
    if (UNLIKELY(!file)) exit(EXIT_FAILURE);

    T2_FLOG_NUMP0(file, "Total number of IGMP packets", numIGMPPackets, numPackets);

    if (numIGMPPackets == 0) {
        fclose(file);
        return;
    }
    fputc('\n', file);

    char str[64];
    uint_fast16_t i;
    const double percent = 100.0 / (double)numIGMPPackets;
    for (i = 0; i < IGMP_V_N; i++) {
        if (num_igmp_v[i] > 0) {
            T2_CONV_NUM(num_igmp_v[i], str);
            fprintf(file, "Number of IGMPv%" PRIuFAST16 " packets: %" PRIu64 "%s [%.2f%%]\n",
                    i, num_igmp_v[i], str, num_igmp_v[i] * percent);
        }
    }

    T2_FLOG_NUMP(file, "Number of DVMRP packets", num_igmp[IGMP_DVMRP], numIGMPPackets);
    T2_FLOG_NUMP(file, "Number of PIMv1 packets", num_igmp[IGMP_PIM_V1], numIGMPPackets);
    fputc('\n', file);

    T2_FLOG_NUMP(file, "Number of query messages", numIGMPQueries, numIGMPPackets);
    T2_FLOG_NUMP(file, "Number of report messages", numIGMPReports, numIGMPPackets);
    fputc('\n', file);

    const float tmp = (numIGMPReports != 0) ? numIGMPQueries / (float)numIGMPReports : 0.0f;
    if (tmp) fprintf(file, "IGMP query / report ratio: %5.3f\n", tmp);
    fputc('\n', file);

    T2_FLOG_NUMP(file, "Number of JOIN requests", numIGMPJoin, numIGMPPackets);
    T2_FLOG_NUMP(file, "Number of LEAVE requests", numIGMPLeave, numIGMPPackets);
    T2_FLOG_NUMP(file, "Number of General queries", numIGMPGeneralQueries, numIGMPPackets);
    T2_FLOG_NUMP(file, "Number of Group Specific queries", numIGMPGroupSpecificQueries, numIGMPPackets);
    T2_FLOG_NUMP(file, "Number of invalid queries", numIGMPInvalidQueries, numIGMPPackets);
    // bad length: < 8, 9-11 (https://tools.ietf.org/html/rfc3376, Section 7.1)
    T2_FLOG_NUMP(file, "Number of messages with bad length", numIGMPBadLength, numIGMPPackets);
    T2_FLOG_NUMP(file, "Number of messages with bad checksum", numIGMPBadChksum, numIGMPPackets);
    T2_FLOG_NUMP(file, "Number of messages with bad TTL", numIGMPBadTTL, numIGMPPackets);

    uint_fast16_t j;
    fprintf(file, "\n# IGMP Type\tCode\t%30s\n", "Packets");
    for (i = 0; i < IGMP_TYPE_N; i++) {
        if (i == IGMP_DVMRP) {
            for (j = 1; j < DVMRP_CODES_N; j++) {
                IGMP_LOG_TYPE_CODE(file, i, dvmrp_code[j], num_dvmrp[j], numIGMPPackets);
            }
        } else if (i == IGMP_PIM_V1) {
            for (j = 0; j < PIM_V1_CODES_N; j++) {
                IGMP_LOG_TYPE_CODE(file, i, pimv1_code[j], num_pimv1[j], numIGMPPackets);
            }
        } else {
            IGMP_LOG_TYPE_CODE(file, i, T2_ENV_VAL(IGMP_NOCODE), num_igmp[i], numIGMPPackets);
        }
    }

    fclose(file);

#if ENVCNTRL > 0
    t2_free_env(ENV_IGMP_N, env);
#endif // ENVCNTRL > 0
#endif // IGMP_STATFILE == 1
}


#if IGMP_STATFILE == 1
static const char *igmpTypeToStr(uint16_t type) {
    switch (type) {
        case IGMP_V0_CREATE_GROUP_REQUEST:
            return "IGMP_V0_CREATE_GROUP_REQUEST";
        case IGMP_V0_CREATE_GROUP_REPLY:
            return "IGMP_V0_CREATE_GROUP_REPLY";
        case IGMP_V0_JOIN_GROUP_REQUEST:
            return "IGMP_V0_JOIN_GROUP_REQUEST";
        case IGMP_V0_JOIN_GROUP_REPLY:
            return "IGMP_V0_JOIN_GROUP_REPLY";
        case IGMP_V0_LEAVE_GROUP_REQUEST:
            return "IGMP_V0_LEAVE_GROUP_REQUEST";
        case IGMP_V0_LEAVE_GROUP_REPLY:
            return "IGMP_V0_LEAVE_GROUP_REPLY";
        case IGMP_V0_CONFIRM_GROUP_REQUEST:
            return "IGMP_V0_CONFIRM_GROUP_REQUEST";
        case IGMP_V0_CONFIRM_GROUP_REPLY:
            return "IGMP_V0_CONFIRM_GROUP_REPLY";
        case IGMP_MEMBERSHIP_QUERY:
            return "IGMP_MEMBERSHIP_QUERY";
        case IGMP_V1_MEMBERSHIP_REPORT:
            return "IGMP_V1_MEMBERSHIP_REPORT";
        case IGMP_DVMRP:
            return "IGMP_DVMRP";
        case IGMP_PIM_V1:
            return "IGMP_PIM_V1";
        case IGMP_CISCO_TRACE_MSG:
            return "IGMP_CISCO_TRACE_MSG";
        case IGMP_V2_MEMBERSHIP_REPORT:
            return "IGMP_V2_MEMBERSHIP_REPORT";
        case IGMP_V2_LEAVE_GROUP:
            return "IGMP_V2_LEAVE_GROUP";
        case IGMP_MTRACE_RESP:
            return "IGMP_MTRACE_RESP";
        case IGMP_MTRACE:
            return "IGMP_MTRACE";
        case IGMP_V3_MEMBERSHIP_REPORT:
            return "IGMP_V3_MEMBERSHIP_REPORT";
        case IGMP_MRD_ROUTER_ADVERT:
            return "IGMP_MRD_ROUTER_ADVERT";
        case IGMP_MRD_ROUTER_SOLICIT:
            return "IGMP_MRD_ROUTER_SOLICIT";
        case IGMP_MRD_ROUTER_TERM:
            return "IGMP_MRD_ROUTER_TERM";
        case IGMP_IGAP_MEMBERSHIP_REPORT:
            return "IGMP_IGAP_MEMBERSHIP_REPORT";
        case IGMP_IGAP_MEMBERSHIP_QUERY:
            return "IGMP_IGAP_MEMBERSHIP_QUERY";
        case IGMP_IGAP_LEAVE_GROUP:
            return "IGMP_IGAP_LEAVE_GROUP";
        case IGMP_RGMP_LEAVE_GROUP:
            return "IGMP_RGMP_LEAVE_GROUP";
        case IGMP_RGMP_JOIN_GROUP:
            return "IGMP_RGMP_JOIN_GROUP";
        case IGMP_RGMP_BYE:
            return "IGMP_RGMP_BYE";
        case IGMP_RGMP_HELLO:
            return "IGMP_RGMP_HELLO";
        default:
            return "IGMP type unknown";
    }
}
#endif // IGMP_STATFILE == 1
