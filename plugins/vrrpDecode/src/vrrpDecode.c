/*
 * vrrpDecode.c
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

#include "vrrpDecode.h"

#include <arpa/inet.h>  // for inet_ntop, inet_ntoa


// Global variables

vrrp_flow_t *vrrp_flows;


// Static variables

static uint16_t vrrpStat;
static uint64_t num_vrrp2, num_vrrp20;
static uint64_t num_vrrp3, num_vrrp30;

#if VRRP_RT == 1
static FILE *vrrpFile;
#endif // VRRP_RT


// Tranalyzer functions

T2_PLUGIN_INIT("vrrpDecode", "0.9.3", 0, 9);


void t2Init() {
    T2_PLUGIN_STRUCT_NEW(vrrp_flows);

#if VRRP_RT == 1
    t2_env_t env[ENV_VRRP_N] = {};
#if ENVCNTRL > 0
    t2_get_env(PLUGIN_SRCH, ENV_VRRP_N, env);
#else // ENVCNTRL == 0
    T2_SET_ENV_STR(VRRP_SUFFIX);
#endif // ENVCNTRL

    vrrpFile = t2_fopen_with_suffix(baseFileName, T2_ENV_VAL(VRRP_SUFFIX), "w");
    if (UNLIKELY(!vrrpFile)) {
        free(vrrp_flows);
        exit(EXIT_FAILURE);
    }
    fprintf(vrrpFile, "VirtualRtrID\tPriority\tSkewTime\tMasterDownInterval\tAddrCount\tAddresses\tVersion\tType\tAdverInt\tAuthType\tAuthString\tChecksum\tCalcChecksum\tflowInd\n");

#if ENVCNTRL > 0
    t2_free_env(ENV_VRRP_N, env);
#endif // ENVCNTRL > 0
#endif // VRRP_RT == 1
}


binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;
    BV_APPEND_H16(bv,    "vrrpStat",      "VRRP status");
    BV_APPEND_H8(bv,     "vrrpVer",       "VRRP version");
    BV_APPEND_H8(bv,     "vrrpType",      "VRRP type");
    BV_APPEND_U32(bv,    "vrrpVRIDCnt",   "VRRP virtual router ID count");
    BV_APPEND_U8_R(bv,   "vrrpVRID",      "VRRP virtual router ID");
    BV_APPEND_U8(bv,     "vrrpMinPri",    "VRRP minimum priority");
    BV_APPEND_U8(bv,     "vrrpMaxPri",    "VRRP maximum priority");
    BV_APPEND_U8(bv,     "vrrpMinAdvInt", "VRRP minimum advertisement interval (seconds)");
    BV_APPEND_U8(bv,     "vrrpMaxAdvInt", "VRRP maximum advertisement interval (seconds)");
    BV_APPEND_H8(bv,     "vrrpAuthType",  "VRRP authentication type");
    BV_APPEND_STRC(bv,   "vrrpAuth",      "VRRP authentication string");
    BV_APPEND_U32(bv,    "vrrpIPCnt",     "VRRP IP address count");
#if VRRP_NUM_IP > 0
    BV_APPEND_TYPE_R(bv, "vrrpIP",        "VRRP IP addresses", VRRP_IP_TYPE);
#endif // VRRP_NUM_IP > 0
    return bv;
}


void t2OnNewFlow(packet_t* packet, unsigned long flowIndex) {
    vrrp_flow_t * const vrrpFlowP = &vrrp_flows[flowIndex];
    memset(vrrpFlowP, '\0', sizeof(*vrrpFlowP));

    const flow_t * const flowP = &flows[flowIndex];
    if (flowP->status & L2_FLOW) return;

    if (L4_PROTO(flowP) == L3_VRRP) {
        vrrpFlowP->stat |= VRRP_STAT_VRRP;
        // TODO check src MAC address == 00:00:5e:00:01:VRID
        if (PACKET_IS_IPV4(packet)) {
            const ipHeader_t * const ipHdrP = IPV4_HEADER(packet);
            if (ipHdrP->ip_dst.s_addr != VRRP_MCAST_4ADDR) {
                vrrpFlowP->stat |= VRRP_STAT_DEST_IP;
            }
        }
    }

    vrrpFlowP->minadvint = 0xff;
    vrrpFlowP->minpri = 0xff;
}


void t2OnLayer4(packet_t* packet, unsigned long flowIndex) {
    vrrp_flow_t * const vrrpFlowP = &vrrp_flows[flowIndex];
    if (!vrrpFlowP->stat) return; // not a vrrp packet

    // only 1. frag packet will be processed
    if (!t2_is_first_fragment(packet)) return;

    const uint_fast8_t ipver = PACKET_IPVER(packet);

    if (ipver == 6) {
        const ip6Header_t * const ip6HdrP = IPV6_HEADER(packet);
        if (ip6HdrP->ip_ttl != VRRP_TTL) vrrpFlowP->stat |= VRRP_STAT_TTL;
    } else {
        const ipHeader_t * const ipHdrP = IPV4_HEADER(packet);
        if (ipHdrP->ip_ttl != VRRP_TTL) vrrpFlowP->stat |= VRRP_STAT_TTL;
    }

    const uint_fast16_t snaplen = packet->snapL4Len;
    if (snaplen < sizeof(vrrp_t)) {
        vrrpFlowP->stat |= VRRP_STAT_SNAP;
        return;
    }

    const vrrp_t * const v = (vrrp_t*)packet->l4HdrP;

    if (v->type != VRRP_TYPE_ADV) vrrpFlowP->stat |= VRRP_STAT_TYPE;

    switch (v->version) {
        case 2:
            if (ipver == 6) {
                vrrpFlowP->stat |= VRRP_STAT_MALFORMED;
                return;
            }
            num_vrrp2++;
            break;
        case 3:
            // Reserved MUST be 0
            if ((v->maxadvint & 0x00f0) != 0) {
                vrrpFlowP->stat |= VRRP_STAT_MALFORMED;
                return;
            }
            num_vrrp3++;
            break;
        default:
            vrrpFlowP->stat |= VRRP_STAT_VER;
            return;
    }

    // check if IPs + auth data (VRRP v2) <= end of non-snapped packet?
    const size_t vrrp_len = sizeof(*v) + \
        v->ip_cnt * (ipver == 6 ? sizeof(struct in6_addr) : sizeof(struct in_addr)) + \
        (v->version == 2 ? sizeof(uint64_t) : 0); // auth data (64 bits)
    if ((void *)v + vrrp_len > (void *)packet->raw_packet + packet->rawLen) {
        vrrpFlowP->stat |= VRRP_STAT_MALFORMED;
        return;
    }

    vrrpFlowP->version |= 1 << v->version;
    vrrpFlowP->type |= v->type;

    uint32_t i, imax = MIN(vrrpFlowP->vrid_cnt, VRRP_NUM_VRID);

    // Virtual Router ID
    for (i = 0; i < imax; i++) {
        if (vrrpFlowP->vrid[i] == v->vrid) goto after_vrid;
    }
    if (vrrpFlowP->vrid_cnt < VRRP_NUM_VRID) {
        vrrpFlowP->vrid[vrrpFlowP->vrid_cnt] = v->vrid;
    } else {
        vrrpFlowP->stat |= VRRP_STAT_TRUNC_VRID;
    }
    vrrpFlowP->vrid_cnt++;

after_vrid:

    vrrpFlowP->minpri = MIN(v->pri, vrrpFlowP->minpri);
    vrrpFlowP->maxpri = MAX(v->pri, vrrpFlowP->maxpri);

    uint8_t advint;
    if (v->version == 2) {
        vrrpFlowP->atype |= 1 << v->atype;
        advint = v->advint;
    } else {
        advint = (ntohs(v->maxadvint) & 0x0fff) / 100.0;
    }

    vrrpFlowP->minadvint = MIN(advint, vrrpFlowP->minadvint);
    vrrpFlowP->maxadvint = MAX(advint, vrrpFlowP->maxadvint);

    uint16_t calc_chksum;

    if (ipver == 6) {
        // TODO IPv6 checksum
        calc_chksum = 0;
    } else {
        calc_chksum = ~Checksum((uint16_t*)packet->l4HdrP, 0, packet->snapL4Len, 3);
        if (v->version == 3) calc_chksum = 0; // TODO checksum for v3
        else if (v->chksum != calc_chksum) vrrpFlowP->stat |= VRRP_STAT_CHKSUM;
    }

#if VRRP_RT == 1
    float mai;
    float skew = (256 - v->pri) / 256.0;
    if (v->version == 2) {
        mai = (3 * v->advint + skew);
    } else {
        skew *= ntohs(v->maxadvint) & 0x0fff;
        mai = (3 * (ntohs(v->maxadvint) & 0x0fff)) + skew;
    }
    fprintf(vrrpFile, "%" PRIu8 "\t%" PRIu8 "\t%f\t%f\t%" PRIu8 "\t", v->vrid, v->pri, skew, mai, v->ip_cnt);
#endif // VRRP_RT

    uint32_t *ptr = (uint32_t*)((uint8_t*)v + sizeof(*v));
    uint32_t j, n = v->ip_cnt;

    if (ipver == 6) {
        n = MIN(n, (snaplen - sizeof(*v)) / sizeof(struct in6_addr)); // for snapped packet
#if VRRP_RT == 1
        char str[INET6_ADDRSTRLEN];
#endif // VRRP_RT == 1
        static const size_t ipasize = (sizeof(vrrpFlowP->ip[0]) / sizeof(*vrrpFlowP->ip[0]));
        //imax = MIN(vrrpFlowP->sip_cnt, VRRP_NUM_IP);
        for (i = 0; i < n; i++) {
#if VRRP_RT == 1
            inet_ntop(AF_INET6, (struct in6_addr*)ptr, str, INET6_ADDRSTRLEN);
            fprintf(vrrpFile, "%s", str);
            if (i+1 < n) fputc(';', vrrpFile);
#endif // VRRP_RT == 1
            // TODO uniq for IPv6
            if (vrrpFlowP->sip_cnt < VRRP_NUM_IP) {
                for (j = 0; j < ipasize; j++) {
                    vrrpFlowP->ip[vrrpFlowP->sip_cnt][j] = *ptr;
                    ptr++;
                }
                vrrpFlowP->sip_cnt++;
            } else {
                vrrpFlowP->stat |= VRRP_STAT_TRUNC_IP;
                ptr += 4;
            }
        }
    } else { // IPv4
        uint32_t ip;
        n = MIN(n, (snaplen - sizeof(*v)) / sizeof(struct in_addr)); // for snapped packet
        imax = MIN(vrrpFlowP->sip_cnt, VRRP_NUM_IP);
        for (i = 0; i < n; i++) {
            ip = *ptr;
            ptr++;
#if VRRP_RT == 1
            fprintf(vrrpFile, "%s", inet_ntoa(*(struct in_addr*)&ip));
            if (i+1 < n) fputc(';', vrrpFile);
#endif // VRRP_RT == 1
            for (j = 0; j < imax; j++) {
                if (vrrpFlowP->ip[j][0] == ip) {
                    j = UINT32_MAX;
                    break;
                }
            }
            if (j != UINT32_MAX) {
                if (vrrpFlowP->sip_cnt >= VRRP_NUM_IP) {
                    vrrpFlowP->stat |= VRRP_STAT_TRUNC_IP;
                } else {
                    vrrpFlowP->ip[vrrpFlowP->sip_cnt][0] = ip;
                }
                vrrpFlowP->sip_cnt++;
            }
        }
    }

#if VRRP_RT == 1
    fprintf(vrrpFile, "\t%" PRIu8 "\t%" PRIu8 "\t%d\t%" PRIu8 "\t", v->version, v->type,
            v->version == 2 ? v->advint : (ntohs(v->maxadvint) & 0x0fff) / 100, v->atype);
#endif // VRRP_RT == 1

    if (v->atype == VRRP_AUTH_SIMPLE) {
        t2_strcpy(vrrpFlowP->auth, (char*)ptr, sizeof(vrrpFlowP->auth), T2_STRCPY_TRUNC);
#if VRRP_RT == 1
        fprintf(vrrpFile, "%s", vrrpFlowP->auth);
#endif // VRRP_RT == 1
    } else if (v->version == 2 && *(uint64_t*)ptr != 0)
        vrrpFlowP->stat |= VRRP_STAT_MALFORMED;

#if VRRP_RT == 1
    const flow_t * const flowP = &flows[flowIndex];
    fprintf(vrrpFile, "\t0x%04" B2T_PRIX16 "\t0x%04" B2T_PRIX16 "\t%" PRIu64 "\n",
            ntohs(v->chksum), ntohs(calc_chksum), flowP->findex);
#endif // VRRP_RT == 1
}


void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {
    vrrp_flow_t *vrrpFlowP = &vrrp_flows[flowIndex];

    vrrpStat |= vrrpFlowP->stat;

    OUTBUF_APPEND_U16(buf, vrrpFlowP->stat);      // vrrpStat
    OUTBUF_APPEND_U8(buf , vrrpFlowP->version);   // vrrpVer
    OUTBUF_APPEND_U8(buf , vrrpFlowP->type);      // vrrpType
    OUTBUF_APPEND_U32(buf, vrrpFlowP->vrid_cnt);  // vrrpVRIDCnt

    // vrrpVRID
    uint32_t imax = MIN(vrrpFlowP->vrid_cnt, VRRP_NUM_VRID);
    OUTBUF_APPEND_ARRAY_U8(buf, vrrpFlowP->vrid, imax);

    OUTBUF_APPEND_U8(buf , vrrpFlowP->minpri);    // vrrpMinPri
    OUTBUF_APPEND_U8(buf , vrrpFlowP->maxpri);    // vrrpMaxPri
    OUTBUF_APPEND_U8(buf , vrrpFlowP->minadvint); // vrrpMinAdvInt
    OUTBUF_APPEND_U8(buf , vrrpFlowP->maxadvint); // vrrpMaxAdvInt
    OUTBUF_APPEND_U8(buf , vrrpFlowP->atype);     // vrrpAuthType
    OUTBUF_APPEND_STR(buf, vrrpFlowP->auth);      // vrrpAuth
    OUTBUF_APPEND_U32(buf, vrrpFlowP->sip_cnt);   // vrrpIPCnt

#if IPV6_ACTIVATE == 2
    const flow_t * const flowP = &flows[flowIndex];
    const uint8_t version = FLOW_IPVER(flowP);
#endif // IPV6_ACTIVATE == 2

    // vrrpIP
    imax = MIN(vrrpFlowP->sip_cnt, VRRP_NUM_IP);
    OUTBUF_APPEND_NUMREP(buf, imax);
    for (uint_fast32_t i = 0; i < imax; i++) {
#if IPV6_ACTIVATE == 2
        OUTBUF_APPEND_U8(buf, version);
        if (version == 6) {
            OUTBUF_APPEND(buf, vrrpFlowP->ip[i], 4 * sizeof(uint32_t));
        } else {
            OUTBUF_APPEND_U32(buf, vrrpFlowP->ip[i]);
        }
#else // IPV6_ACTIVATE != 2
        OUTBUF_APPEND(buf, vrrpFlowP->ip[i], VRRP_IP_SIZE);
#endif // IPV6_ACTIVATE != 2
    }
}


static inline void vrrp_pluginReport(FILE *stream) {
    if (vrrpStat) {
        T2_FPLOG_AGGR_HEX0(stream, plugin_name, vrrpStat);
        T2_FPLOG_DIFFNUMP(stream, plugin_name, "Number of VRRPv2 packets", num_vrrp2, numPackets);
        T2_FPLOG_DIFFNUMP(stream, plugin_name, "Number of VRRPv3 packets", num_vrrp3, numPackets);
    }
}


void t2Monitoring(FILE *stream, uint8_t state) {

    switch (state) {

        // Print the name of the variables that will be output
        case T2_MON_PRI_HDR:
            fputs("vrrp2NPkts" SEP_CHR
                  "vrrp3NPkts" SEP_CHR
                  "vrrpStat"   SEP_CHR
                  , stream);
            return;

        // Print the variables to monitor
        case T2_MON_PRI_VAL:
            fprintf(stream,
                    "%"     PRIu64     /* vrrp2NPkts */ SEP_CHR
                    "%"     PRIu64     /* vrrp3NPkts */ SEP_CHR
                    "0x%04" B2T_PRIX16 /* vrrpStat   */ SEP_CHR
                    , num_vrrp2 - num_vrrp20
                    , num_vrrp3 - num_vrrp30
                    , vrrpStat);
            break;

        // Print a report similar to t2PluginReport()
        case T2_MON_PRI_REPORT:
            vrrp_pluginReport(stream);
            break;

        // Invalid state, do nothing
        default:
            return;
    }

#if DIFF_REPORT == 1
    num_vrrp20 = num_vrrp2;
    num_vrrp30 = num_vrrp3;
#endif
}


void t2PluginReport(FILE *stream) {
#if DIFF_REPORT == 1
    num_vrrp20 = 0;
    num_vrrp30 = 0;
#endif
    vrrp_pluginReport(stream);
}


void t2Finalize() {
#if VRRP_RT == 1
    fclose(vrrpFile);
#endif // VRRP_RT == 1

    free(vrrp_flows);
}
