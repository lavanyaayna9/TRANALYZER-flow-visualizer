/*
 * bgpDecode.c
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

#include "bgpDecode.h"
#include "t2buf.h"


#define BGP_LOG_ANOM(tag, format, args...) \
    fprintf(anom_file, "%s\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu32 "\t" format "\n", \
            tag, flowP->findex, numPackets, rec, ##args);


bgp_flow_t *bgp_flows;

static uint16_t bgpAFlgs, bgpStat, bgpCaps;
static uint32_t bgpPAttr;
static uint32_t rec; // record counter
static uint64_t num_bgp[BGP_T_RTE_REFRSH+1];
static bgp_flow_update_t *bgp_update;

#if BGP_RT == 1
static hashMap_t *routing_table;
static bgp_rt_elem_t *bgp_rt;
#endif // BGP_RT == 1

static const char bgp_marker[] = {
    0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff
};

static FILE *moas_file;
static FILE *anom_file;

#if BGP_OUTPUT_RT == 1
static FILE *bgp_file;

static inline const char *bgp_orig_to_str(uint8_t orig);
#endif // BGP_OUTPUT_RT

static inline const char *bgp_type_to_str(uint8_t type);

#if BGP_NOTIF_FORMAT == 1
static inline const char *bgp_notif_to_str(uint8_t code);
#endif // BGP_NOTIF_FORMAT == 1

#if BGP_AS_FORMAT > 0
static inline void bgp_asplain_to_asdot(uint32_t as, char *asdot);
#endif // BGP_AS_FORMAT > 0

#if BGP_OUTPUT_RT == 1
static void bgp_print_update(bgp_flow_update_t *bgp_update, uint64_t flowIndex);
#endif // BGP_OUTPUT_RT == 1

typedef void (*bgp_func_t)(t2buf_t *t2buf, uint64_t flowIndex);

static void bgp_decode_open(t2buf_t *t2buf, uint64_t flowIndex);
static void bgp_decode_update(t2buf_t *t2buf, uint64_t flowIndex);
static void bgp_decode_notification(t2buf_t *t2buf, uint64_t flowIndex);
static void bgp_decode_keep_alive(t2buf_t *t2buf, uint64_t flowIndex);
static void bgp_decode_route_refresh(t2buf_t *t2buf, uint64_t flowIndex);

static const bgp_func_t bgp_funcs[BGP_T_RTE_REFRSH] = {
    &bgp_decode_open,
    &bgp_decode_update,
    &bgp_decode_notification,
    &bgp_decode_keep_alive,
    &bgp_decode_route_refresh
};


// Tranalyzer functions

T2_PLUGIN_INIT("bgpDecode", "0.9.3", 0, 9);


void t2Init() {
    T2_PLUGIN_STRUCT_NEW(bgp_flows);

    bgp_update = t2_calloc_fatal(1, sizeof(*bgp_update));

    t2_env_t env[ENV_BGP_N] = {};
#if ENVCNTRL > 0
    t2_get_env(PLUGIN_SRCH, ENV_BGP_N, env);
#else // ENVCNTRL == 0
    T2_SET_ENV_STR(BGP_SUFFIX);
    T2_SET_ENV_STR(BGP_ANOM_SUFFIX);
    T2_SET_ENV_STR(BGP_MOAS_SUFFIX);
#endif // ENVCNTRL

#if BGP_RT == 1
    if (UNLIKELY(!(routing_table = hashTable_init(1.0f, sizeof(bgp_nlri_t), "bgp")))) {
        T2_PERR(plugin_name, "failed to initialize routing_table");
        free(bgp_update);
        free(bgp_flows);
        exit(EXIT_FAILURE);
    }

    bgp_rt = t2_calloc_fatal(routing_table->hashChainTableSize, sizeof(*bgp_rt));
#endif // BGP_RT == 1

    moas_file = t2_fopen_with_suffix(baseFileName, T2_ENV_VAL(BGP_MOAS_SUFFIX), "w");
    if (UNLIKELY(!moas_file)) {
#if BGP_RT == 1
        hashTable_destroy(routing_table);
        free(bgp_rt);
#endif // BGP_RT == 1
        free(bgp_update);
        free(bgp_flows);
        exit(EXIT_FAILURE);
    }
    fprintf(moas_file, "%%Network\tMask\tOldOrigAS\tNewOrigAS\tflowInd\tpktNo\tRecNum\n");

    anom_file = t2_fopen_with_suffix(baseFileName, T2_ENV_VAL(BGP_ANOM_SUFFIX), "w");
    if (UNLIKELY(!anom_file)) {
#if BGP_RT == 1
        hashTable_destroy(routing_table);
        free(bgp_rt);
#endif // BGP_RT == 1
        free(bgp_update);
        free(bgp_flows);
        fclose(moas_file);
        exit(EXIT_FAILURE);
    }
    //fprintf(anom_file, "%%Anomaly\tASorNet\tRepsOrMask\tNewMask\tflowInd\tpktNo\tRecNum\n");
    fprintf(anom_file, "%%Anomaly\tflowInd\tpktNo\tRecNum\tASorNet\tRepsOrMask\tNewMask\n");

#if BGP_OUTPUT_RT == 1
    bgp_file = t2_fopen_with_suffix(baseFileName, T2_ENV_VAL(BGP_SUFFIX), "w");
    if (UNLIKELY(!bgp_file)) {
#if BGP_RT == 1
        hashTable_destroy(routing_table);
        free(bgp_rt);
#endif // BGP_RT == 1
        free(bgp_update);
        free(bgp_flows);
        fclose(anom_file);
        fclose(moas_file);
        exit(EXIT_FAILURE);
    }

    fprintf(bgp_file, "%%NLRI\tAS\tNextHop\tMED\tLocPref\tOrigin");
#if BGP_ORIG_ID == 1
    fprintf(bgp_file, "\tOriginatorID");
#endif
    fprintf(bgp_file, "\tOriginAS\tUpstreamAS\tDestAS");
#if BGP_AGGR == 1
    fprintf(bgp_file, "\tAggregator");
#endif
    fprintf(bgp_file, "\tASPath\tASPathLen\tMaxNPrepAS");
#if BGP_CLUSTER == 1
    fprintf(bgp_file, "\tClusterList\tClusterListLen");
#endif
#if BGP_COMMUNITIES == 1
    fprintf(bgp_file, "\tCommunities");
#endif
    fprintf(bgp_file, "\tWithdrawnRoutes\tflowInd\tpktNo\tRecNum\ttime\n");
#endif // BGP_OUTPUT_RT == 1

#if ENVCNTRL > 0
    t2_free_env(ENV_BGP_N, env);
#endif // ENVCNTRL > 0
}


binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;
    BV_APPEND_H16(bv, "bgpStat"         , "BGP status");
    BV_APPEND_H16(bv, "bgpAFlgs"        , "BGP anomaly flags");
    BV_APPEND_H8( bv, "bgpMsgT"         , "BGP message types");
    BV_APPEND(    bv, "bgpNOpen_Upd_Notif_KeepAl_RteRefr", "Number of BGP messages: OPEN, UPDATE, NOTIFICATION, KEEPALIVE and ROUTE-REFRESH", 5, bt_uint_32, bt_uint_32, bt_uint_32, bt_uint_32, bt_uint_32);
    // OPEN Message
    BV_APPEND_U8( bv, "bgpVersion"      , "BGP version");
    BV_APPEND(    bv, "bgpSrcAS_dstAS"  , "BGP source and destination Autonomous System (AS)", 2, BGP_AS_TYPE, BGP_AS_TYPE);
    BV_APPEND(    bv, "bgpSrcId_dstId"  , "BGP source and destination ID", 2, BGP_IP_TYPE, BGP_IP_TYPE);
    BV_APPEND_U16(bv, "bgpHTime"        , "BGP hold time (sec)");
    BV_APPEND_H16(bv, "bgpCaps"         , "BGP capabilities");
    // UPDATE Messages
    BV_APPEND_H32(bv, "bgpPAttr"        , "BGP path attributes");
    BV_APPEND_U32(bv, "bgpNAdver"       , "BGP total number of advertised routes");
    BV_APPEND_U32(bv, "bgpNWdrwn"       , "BGP total number of withdrawn routes");
    BV_APPEND_U32(bv, "bgpMaxAdver"     , "BGP maximum number of advertised routes per record");
    BV_APPEND_DBL(bv, "bgpAvgAdver"     , "BGP average number of advertised routes per record");
    BV_APPEND_U32(bv, "bgpMaxWdrwn"     , "BGP maximum number of withdrawn routes per record");
    BV_APPEND_DBL(bv, "bgpAvgWdrwn"     , "BGP average number of withdrawn routes per record");
    BV_APPEND_H32(bv, "bgpAdvPref"      , "BGP advertised prefixes");
    BV_APPEND_H32(bv, "bgpWdrnPref"     , "BGP withdrawn prefixes");
    BV_APPEND(    bv, "bgpNIGP_EGP_INC" , "BGP number of routes from origin IGP, EGP, INCOMPLETE", 3, bt_uint_32, bt_uint_32, bt_uint_32);
    BV_APPEND_U8( bv, "bgpMinASPLen"    , "BGP minimum AS path length");
    BV_APPEND_U8( bv, "bgpMaxASPLen"    , "BGP maximum AS path length");
    BV_APPEND_DBL(bv, "bgpAvgASPLen"    , "BGP average AS path length");
    BV_APPEND_U32(bv, "bgpMaxNPrepAS"   , "BGP maximum number of prepended AS");
    BV_APPEND_DBL(bv, "bgpMinIatUp"     , "BGP minimum inter-arrival time for update messages");
    BV_APPEND_DBL(bv, "bgpMaxIatUp"     , "BGP maximum inter-arrival time for update messages");
    BV_APPEND_DBL(bv, "bgpAvgIatUp"     , "BGP average inter-arrival time for update messages");
    // KEEPALIVE Messages
    BV_APPEND_DBL(bv, "bgpMinIatKA"     , "BGP minimum inter-arrival time for keep-alive messages");
    BV_APPEND_DBL(bv, "bgpMaxIatKA"     , "BGP maximum inter-arrival time for keep-alive messages");
    BV_APPEND_DBL(bv, "bgpAvgIatKA"     , "BGP average inter-arrival time for keep-alive messages");
    // NOTIFICATION Message
    BV_APPEND(bv, "bgpNotifCode_Subcode", "BGP notification (fatal error) code and subcode", 2, BGP_NOTIF_TYPE, bt_uint_8);
    return bv;
}


void t2OnNewFlow(packet_t* packet, unsigned long flowIndex) {
    bgp_flow_t * const bgpFlowP = &bgp_flows[flowIndex];
    memset(bgpFlowP, '\0', sizeof(*bgpFlowP));

    const flow_t * const flowP = &flows[flowIndex];
    if (packet->l4Proto == L3_TCP && (flowP->srcPort == BGP_PORT || flowP->dstPort == BGP_PORT)) {
        bgpFlowP->stat |= BGP_STAT_BGP;
    }
}


void t2OnLayer4(packet_t* packet, unsigned long flowIndex) {

    bgp_flow_t * const bgpFlowP = &bgp_flows[flowIndex];
    const uint16_t snaplen = packet->snapL7Len;
    if (!bgpFlowP->stat || snaplen < BGP_HDRLEN) return; // Not a BGP flow

    // only 1. frag packet will be processed
    if (!t2_is_first_fragment(packet)) return;

    const uint8_t * const l7hdr = packet->l7HdrP;
    t2buf_t t2buf = t2buf_create(l7hdr, snaplen);

    num_bgp[0]++;

    bgpFlowP->now = packet->pcapHdrP->ts.tv_sec + packet->pcapHdrP->ts.tv_usec / TSTAMPFAC;

    rec = 0;
    while (t2buf_left(&t2buf) >= BGP_HDRLEN) {

        rec++;

        uint64_t marker[2];
        BGP_READ_U64(&t2buf, &marker[0]);
        BGP_READ_U64(&t2buf, &marker[1]);

        if (marker[0] != BGP_MARKER || marker[1] != BGP_MARKER) {
            t2buf_seek(&t2buf, -16, SEEK_CUR);
            // Search for the next marker
            if (!t2buf_memmem(&t2buf, bgp_marker, 16)) {
#if BGP_DEBUG == 1
                T2_PWRN(plugin_name, "pkt %" PRIu64 ": Connection not synchronized", numPackets);
#endif // BGP_DEBUG == 1
                bgpFlowP->stat |= BGP_STAT_CONN_SYNC;
                return;
            }
#if BGP_DEBUG == 1
            T2_PINF(plugin_name, "pkt %" PRIu64 ": Found a new marker at offset %ld", numPackets, t2buf_tell(&t2buf));
#endif // BGP_DEBUG == 1
            BGP_SKIP_N(&t2buf, 16); // skip the marker
        }

        /* record length */
        BGP_READ_U16(&t2buf, &bgpFlowP->hdrlen);

        if (bgpFlowP->hdrlen < BGP_HDRLEN || bgpFlowP->hdrlen > BGP_MAXLEN) {
            T2_PDBG(plugin_name, "pkt %" PRIu64 ": Bad message length %u", numPackets, bgpFlowP->hdrlen);
            bgpFlowP->stat |= BGP_STAT_BAD_LEN;
            return;
        }

        /* Record type */
        uint8_t type;
        BGP_READ_U8(&t2buf, &type);

        if (type == 0 || type > BGP_T_RTE_REFRSH) {
#if BGP_DEBUG == 1
            T2_PDBG(plugin_name, "pkt %" PRIu64 ": Bad message type %u", numPackets, type);
#endif // BGP_DEBUG == 1
            bgpFlowP->stat |= BGP_STAT_BAD_TYPE;
            BGP_SKIP_N(&t2buf, bgpFlowP->hdrlen - BGP_HDRLEN);
            continue;
        }

        bgpFlowP->msgT |= (1 << type);
        bgpFlowP->num_t[type]++;
        num_bgp[type]++;

        // decode the record
        bgp_funcs[type-1](&t2buf, flowIndex);
    }
}


static void bgp_decode_open(t2buf_t *t2buf, uint64_t flowIndex) {
    bgp_flow_t * const bgpFlowP = &bgp_flows[flowIndex];

    /* Protocol version */
    BGP_READ_U8(t2buf, &bgpFlowP->version);
    if (bgpFlowP->version != 4) bgpFlowP->stat |= BGP_STAT_VERSION;

    /* AS of the sender */
    uint16_t my_as;
    BGP_READ_U16(t2buf, &my_as);
    bgpFlowP->src_as = my_as;

    /* Hold time (sec) */
    BGP_READ_U16(t2buf, &bgpFlowP->htime);
    if (bgpFlowP->htime == 1 || bgpFlowP->htime == 2) {
        bgpFlowP->stat |= BGP_STAT_HTIME;
    }

    /* BGP identifier (IPv4 address) */
    BGP_READ_IP4(t2buf, &bgpFlowP->src_id);

    const flow_t * const flowP = &flows[flowIndex];
    if (FLOW_HAS_OPPOSITE(flowP)) {
        const uint_fast64_t ofidx = flowP->oppositeFlowIndex;
        bgp_flows[ofidx].dst_as = bgpFlowP->src_as;
        bgp_flows[ofidx].dst_id = bgpFlowP->src_id;
        bgpFlowP->dst_as = bgp_flows[ofidx].src_as;
        bgpFlowP->dst_id = bgp_flows[ofidx].src_id;
    }

    /* Optional parameter length */
    uint8_t optlen;
    BGP_READ_U8(t2buf, &optlen);

    /* Optional parameters */
    while (t2buf_left(t2buf) >= 2 && optlen >= 2) {
        uint8_t type;
        BGP_READ_U8(t2buf, &type);
        if (type != 2) return; // capability only TODO

        uint8_t caplen;
        BGP_READ_U8(t2buf, &caplen);

        if (LIKELY(optlen >= caplen+2)) optlen -= (caplen + 2);
        else optlen = 0;

        while (t2buf_left(t2buf) >= 2 && caplen >= 2) {
            /* Capability type */
            BGP_READ_U8(t2buf, &type);

            /* Capability length */
            uint8_t len;
            BGP_READ_U8(t2buf, &len);

            if (LIKELY(caplen >= len+2)) caplen -= (len + 2);
            else caplen = 0;

            switch (type) {
                //case BGP_C_MULTI_PROTO:
                //    // AFI(16), RESERVED(8), SAFI(8)
                //    break;

                case BGP_C_GRACE_RSTART:
                    bgpFlowP->caps |= (1 << 5);
                    break;

                case BGP_C_AS4_SUPPORT: {
                    bgpFlowP->caps |= (1 << 6);
                    uint32_t as;
                    BGP_READ_U32(t2buf, &as);
                    if (as != bgpFlowP->src_as && bgpFlowP->src_as != BGP_AS_TRANS) {
                        bgpFlowP->stat |= BGP_STAT_AS_MISMATCH;
                    }
                    bgpFlowP->src_as = as;
                    t2buf_seek(t2buf, -4, SEEK_CUR);
                    break;
                }

                case BGP_C_DYN_SUPPORT:
                    bgpFlowP->caps |= (1 << 7);
                    break;

                case BGP_C_MULTISESS:
                    bgpFlowP->caps |= (1 << 8);
                    break;

                case BGP_C_ADD_PATH:
                    // AFI(16), SAFI(8), Send/Receive(8)
                    bgpFlowP->caps |= (1 << 9);
                    break;

                case BGP_C_ENH_RFRSH:
                    bgpFlowP->caps |= (1 << 10);
                    break;

                case BGP_C_LLGR:
                    bgpFlowP->caps |= (1 << 11);
                    break;

                case BGP_C_FQDN:
                    bgpFlowP->caps |= (1 << 12);
                    break;

                default:
                    if (type > 0 && type <= 5) {
                        bgpFlowP->caps |= (1 << (type-1));
                    } else {
#if BGP_DEBUG == 1
                        T2_PWRN(plugin_name, "Unhandled capability type %u", type);
#endif // BGP_DEBUG == 1
                        bgpFlowP->caps |= (1 << 15);
                    }
                    break;
            }

            // Skip the capability
            BGP_SKIP_N(t2buf, len);
        }
    }
}


static void bgp_decode_update(t2buf_t *t2buf, uint64_t flowIndex) {
    bgp_flow_t * const bgpFlowP = &bgp_flows[flowIndex];
    const flow_t * const flowP = &flows[flowIndex];

    memset(bgp_update, '\0', sizeof(*bgp_update));

    // min/max/average inter arrival time for update messages
    if (bgpFlowP->num_t[BGP_T_UPDATE] > 1) { // no iat for first update
        const double iat = bgpFlowP->now - bgpFlowP->lastup;
        if (LIKELY(iat > 0)) {
            bgpFlowP->avgiatup += (iat - bgpFlowP->avgiatup) / (bgpFlowP->num_t[BGP_T_UPDATE]-1);
            bgpFlowP->miniatup = MIN(iat, bgpFlowP->miniatup);
            bgpFlowP->maxiatup = MAX(iat, bgpFlowP->maxiatup);
        } else if (!(bgpFlowP->stat & BGP_STAT_IAT)) {
#if BGP_DEBUG == 1
            T2_PWRN(plugin_name, "pkt %" PRIu64 ": IAT < 0", numPackets);
#endif // BGP_DEBUG == 1
            bgpFlowP->stat |= BGP_STAT_IAT;
        }
    }

    bgpFlowP->lastup = bgpFlowP->now;

    /* Withdrawn Routes Length */
    uint16_t wr;
    BGP_READ_U16(t2buf, &wr);
    const uint16_t wr_len = wr;

    /* Withdrawn Routes */
    uint32_t nwdrwn = 0;
    while (wr > 1) {
        bgp_nlri_t nlri = {};

        BGP_READ_U8(t2buf, &nlri.mask);
        if (nlri.mask > 32) {
            bgpFlowP->stat |= BGP_STAT_INVMASK;
            return;
        }
        bgpFlowP->wdrnpref |= (1 << (nlri.mask-1));

        bgpFlowP->nwdrwn++;
        nwdrwn++;

        const uint_fast8_t s = (nlri.mask+7)/8;
        if (t2buf_left(t2buf) < s) {
            // Record is snapped... update statistics and return
            bgpFlowP->stat |= BGP_STAT_SNAPLEN;
            bgpFlowP->maxwdrwn = MAX(nwdrwn, bgpFlowP->maxwdrwn);
            if (bgpFlowP->num_t[BGP_T_UPDATE] == 1) {
                bgpFlowP->avgwdrwn = nwdrwn;
            } else {
                bgpFlowP->avgwdrwn += (nwdrwn - bgpFlowP->avgwdrwn) / (bgpFlowP->num_t[BGP_T_UPDATE]);
            }
            return;
        }

        for (uint_fast8_t i = 0; i < s; i++) {
            BGP_READ_U8(t2buf, &nlri.prefix[i]);
        }

        //if (PACKET_IS_IPV4(packet)) {
        //    BGP_INF("Route to %u.%u.%u.%u/%u withdrawn by %s",
        //        nlri.prefix[0], nlri.prefix[1], nlri.prefix[2], nlri.prefix[3], nlri.mask,
        //        inet_ntoa(flowP->srcIP));
        //}

        if (bgp_update->nw < BGP_ASIZE) {
            bgp_update->withdrawn[bgp_update->nw++] = nlri;
        } else if (!(bgpFlowP->stat & BGP_STAT_AFULL)) {
            T2_PWRN(plugin_name, "pkt %" PRIu64 ": Array for withdrawn routes is full... increase BGP_ASIZE", numPackets);
            bgpFlowP->stat |= BGP_STAT_AFULL;
        }

        if (LIKELY(wr >= (1+s))) wr -= (1+s);
        else wr = 0;

#if BGP_RT == 1
        const uint8_t mask = nlri.mask;
        nlri.mask = 0;
        if (hashTable_remove(routing_table, (char*)&nlri) == HASHTABLE_ENTRY_NOT_FOUND) {
            //BGP_INF("No route to %u.%u.%u.%u/%u in routing table",
            //        nlri.prefix[0], nlri.prefix[1], nlri.prefix[2], nlri.prefix[3], nlri.mask);
        } else {
            //BGP_INF("Route to %u.%u.%u.%u/%u withdrawn from routing table",
            //        nlri.prefix[0], nlri.prefix[1], nlri.prefix[2], nlri.prefix[3], nlri.mask);
        }
        nlri.mask = mask;
#endif // BGP_RT == 1
    }

    bgpFlowP->maxwdrwn = MAX(nwdrwn, bgpFlowP->maxwdrwn);
    if (bgpFlowP->num_t[BGP_T_UPDATE] == 1) {
        bgpFlowP->avgwdrwn = nwdrwn;
    } else {
        bgpFlowP->avgwdrwn += (nwdrwn - bgpFlowP->avgwdrwn) / (bgpFlowP->num_t[BGP_T_UPDATE]);
    }

    /* Total Path Attribute Length */
    uint16_t tpa_len;
    BGP_READ_U16(t2buf, &tpa_len);

    /* Path Attributes */
    int32_t nlri_len = bgpFlowP->hdrlen - 23 - tpa_len - wr_len;
    while (tpa_len >= 3) {
        /* Flags */
        uint8_t flags;
        BGP_READ_U8(t2buf, &flags);

        /* Type Code */
        uint8_t type;
        BGP_READ_U8(t2buf, &type);
        if (LIKELY(type > 0 && type <= 32)) {
            bgpFlowP->attr |= (1U << (type-1));
        }

        /* Length */
        uint8_t len;
        BGP_READ_U8(t2buf, &len);

        switch (type) {

            case BGP_A_ORIGIN:
                BGP_READ_U8(t2buf, &bgp_update->orig);
                if (bgp_update->orig < 3) bgpFlowP->origin[bgp_update->orig]++;
                break;

            case BGP_A_AS4_PATH:
#if BGP_DEBUG == 1
                if (bgp_update->nas4 != 0) {
                    T2_PDBG(plugin_name, "MANY AS4 PATH");
                }
#endif // BGP_DEBUG == 1
                bgp_update->nas4 = bgp_update->nas;
                /* FALLTHRU */
            case BGP_A_AS_PATH: {
                uint_fast8_t as4 = 0;
                uint16_t alen = len;
                uint32_t off;
                /* Guess whether to use 16 or 32 bits for AS numbers */
                if (type == BGP_A_AS4_PATH) {
                    as4 = 1;
                } else {
                    off = 0;
                    const long start = t2buf_tell(t2buf);
                    while (alen > 0) {
                        uint8_t stype;
                        BGP_READ_U8(t2buf, &stype);
                        if (stype == 0 || stype > 4) {
                            as4 = 1;
                            break;
                        }
                        uint8_t nasn;
                        BGP_READ_U8(t2buf, &nasn);
                        alen -= 2 + 2 * nasn;
                        off += 2 + 2 * nasn;
                    }
                    if (off != len) as4 = 1;
                    t2buf_seek(t2buf, start, SEEK_SET);
                }
                alen = len;
                if (alen == 0) break; // AS PATH is empty
                off = 0;
                while (alen > 0) {
                    uint8_t stype;
                    BGP_READ_U8(t2buf, &stype);

                    uint8_t nasn;
                    BGP_READ_U8(t2buf, &nasn);

                    alen -= 2;
                    // min/max/average AS path length
                    if (bgpFlowP->nasp++ == 0) {
                        bgpFlowP->minasplen = nasn;
                        bgpFlowP->maxasplen = nasn;
                        bgpFlowP->avgasplen = nasn;
                    } else {
                        bgpFlowP->minasplen = MIN(nasn, bgpFlowP->minasplen);
                        bgpFlowP->maxasplen = MAX(nasn, bgpFlowP->maxasplen);
                        bgpFlowP->avgasplen += (nasn - bgpFlowP->avgasplen) / bgpFlowP->nasp;
                    }

                    if (bgp_update->nas < BGP_ASIZE) {
                        bgp_update->aspath[bgp_update->nas].stype = stype;
                    } else if (!(bgpFlowP->stat & BGP_STAT_AFULL)) {
                        T2_PWRN(plugin_name, "pkt %" PRIu64 ": Array for ASPath is full... increase BGP_ASIZE", numPackets);
                        bgpFlowP->stat |= BGP_STAT_AFULL;
                    }

                    uint32_t maxprepas = 0, nprepas = 0, prevas = 0;
                    for (uint_fast8_t i = 0; i < nasn && off < len && t2buf_left(t2buf) >= 2; i++) {
                        uint32_t as;
                        if (as4 == 1) {
                            BGP_READ_U32(t2buf, &as);
                            alen -= 4;

                            if (bgp_update->nas < BGP_ASIZE) {
                                if (bgp_update->aspath[bgp_update->nas].nasn < BGP_ASIZE) {
                                    bgp_update->aspath[bgp_update->nas].as[bgp_update->aspath[bgp_update->nas].nasn++] = as;
                                } else if (!(bgpFlowP->stat & BGP_STAT_AFULL)) {
                                    T2_PWRN(plugin_name, "pkt %" PRIu64 ": Array for AS is full... increase BGP_ASIZE", numPackets);
                                    bgpFlowP->stat |= BGP_STAT_AFULL;
                                }
                            }
                            if (as >= 4200000000 && as <= 4294967294) {
                                bgpFlowP->aFlgs |= BGP_AFLGS_RESRVD_AS;
                                // TODO as path?
                                BGP_LOG_ANOM("PRIVAS", "%" PRIu32, as);
                                //fprintf(anom_file, "PRIVAS\t%u\t\t\t%lu\t%lu\t%u\n",
                                //        as, flowP->findex, numPackets, rec);
                            }
                        } else { // as4 == 0
                            uint16_t as2;
                            BGP_READ_U16(t2buf, &as2);
                            as = as2;
                            alen -= 2;
                            if (bgp_update->nas < BGP_ASIZE) {
                                if (bgp_update->aspath[bgp_update->nas].nasn < BGP_ASIZE) {
                                    bgp_update->aspath[bgp_update->nas].as[bgp_update->aspath[bgp_update->nas].nasn++] = as;
                                } else if (!(bgpFlowP->stat & BGP_STAT_AFULL)) {
                                    T2_PWRN(plugin_name, "pkt %" PRIu64 ": Array for AS is full... increase BGP_ASIZE", numPackets);
                                    bgpFlowP->stat |= BGP_STAT_AFULL;
                                }
                            }
                            if (as >= 64512 && as <= 65534) {
                                bgpFlowP->aFlgs |= BGP_AFLGS_RESRVD_AS;
                                // TODO as path?
                                BGP_LOG_ANOM("PRIVAS", "%" PRIu32, as);
                                //fprintf(anom_file, "PRIVAS\t%u\t\t\t%lu\t%lu\t%u\n",
                                //        as, flowP->findex, numPackets, rec);
                            }
                        }

                        // loop detection
                        uint32_t das;
                        if (FLOW_IS_B(flowP)) {
                            das = bgpFlowP->src_as;
                        } else {
                            das = bgpFlowP->dst_as;
                        }
                        if (as == das) {
                            bgpFlowP->aFlgs |= BGP_AFLGS_LOOP;
                            // TODO as path?
                            BGP_LOG_ANOM("PRIVAS", "%" PRIu32, as);
                            //fprintf(anom_file, "LOOP\t%u\t\t\t%lu\t%lu\t%u\n",
                            //        as, flowP->findex, numPackets, rec);
                        }

                        // prepended AS path
                        if (prevas == as) nprepas++;
                        else nprepas = 0;
                        if (nprepas > bgpFlowP->maxnprepas) {
                            bgpFlowP->maxnprepas = nprepas;
                            maxprepas = as;
                        }
                        prevas = as;
                    }

                    if (bgpFlowP->maxnprepas > 10 && maxprepas != 0) {
                        bgpFlowP->aFlgs |= BGP_AFLGS_NPREPAS;
                        // TODO as path?
                        BGP_LOG_ANOM("NPREPAS", "%u\t%u", maxprepas, bgpFlowP->maxnprepas);
                        //fprintf(anom_file, "NPREPAS\t%u\t%u\t\t%lu\t%lu\t%u\n",
                        //        maxprepas, bgpFlowP->maxnprepas, flowP->findex, numPackets, rec);
                    }
                    bgp_update->nas++;
                    off += 2;
                    if (as4 == 1) off += 4 * nasn;
                    else off += 2 * nasn;
                }
                break;
            }

            case BGP_A_NEXT_HOP:
                if (len > 0) {
                    if (len != 4) {
                        T2_PDBG(plugin_name, "pkt %" PRIu64 ": Not an IPv4", numPackets);
                    } else {
                        BGP_READ_IP4(t2buf, &bgp_update->nexthop);
                    }
                }
                break;

            case BGP_A_MUL_EXIT_DISC:
                BGP_READ_U32(t2buf, &bgp_update->med);
                break;

            case BGP_A_LOCAL_PREF:
                BGP_READ_U32(t2buf, &bgp_update->locpref);
                break;

            case BGP_A_ORIG_ID:
                BGP_READ_U32(t2buf, &bgp_update->orig_id);
                break;

            case BGP_A_ATOMIC_AGGR:
                bgpFlowP->stat |= BGP_STAT_ATOMIC_AGGR;
                break;

            case BGP_A_AGGR:
            case BGP_A_AS4_AGGR: {
                if (len == 6) {
                    uint16_t aggr;
                    BGP_READ_U16(t2buf, &aggr);
                    bgp_update->aggr[0] = aggr;
                    BGP_READ_U32(t2buf, &bgp_update->aggr[1]);
                } else {
                    BGP_READ_U32(t2buf, &bgp_update->aggr[0]);
                    BGP_READ_U32(t2buf, &bgp_update->aggr[1]);
                }
                break;
            }

            case BGP_A_CLUSTER_LIST: {
                uint16_t i = 0;
                while (i < len) {
                    if (bgp_update->nclust < BGP_ASIZE) {
                        BGP_READ_U32(t2buf, &bgp_update->cluster[bgp_update->nclust++]);
                    } else if (!(bgpFlowP->stat & BGP_STAT_AFULL)) {
                        T2_PWRN(plugin_name, "pkt %" PRIu64 ": Array for cluster is full... increase BGP_ASIZE", numPackets);
                        bgpFlowP->stat |= BGP_STAT_AFULL;
                    }
                    i += 4;
                }
                break;
            }

            case BGP_A_COMMUNITIES: {
                uint32_t i = 0;
                while (i < len) {
                    uint16_t cas;
                    BGP_READ_U16(t2buf, &cas);
                    uint16_t tag;
                    BGP_READ_U16(t2buf, &tag);
                    if (bgp_update->nc < BGP_ASIZE) {
                        bgp_update->comm[bgp_update->nc][0] = cas;
                        bgp_update->comm[bgp_update->nc][1] = tag;
                    } else if (!(bgpFlowP->stat & BGP_STAT_AFULL)) {
                        T2_PWRN(plugin_name, "pkt %" PRIu64 ": Array for communities is full... increase BGP_ASIZE", numPackets);
                        bgpFlowP->stat |= BGP_STAT_AFULL;
                    }
                    bgp_update->nc++;
                    if (tag == BGP_COM_TAG_BLACKHOLE || ((uint32_t)(cas << 16 | tag) == BGP_COM_BLACKHOLE)) {
                        bgpFlowP->aFlgs |= BGP_AFLGS_BLACKHOLE;
                        BGP_LOG_ANOM("BLACKHOLE", "%u\t%u", cas, tag);
                        //fprintf(anom_file, "BLACKHOLE\t%u:%u\t\t%lu\t%lu\t%u\n",
                        //        cas, tag, flowP->findex, numPackets, rec);
                    }
                    i += 4;
                }
                break;
            }

            //case BGP_A_EXT_COMM:
            //case BGP_A_MP_REACH_NLRI: // TODO IPv6: next hop, nlri
            default:
                BGP_SKIP_N(t2buf, len);
                break;
        }

        if (LIKELY(tpa_len >= (3 + len))) tpa_len -= (3 + len);
        else tpa_len = 0;
    }

#if BGP_RT == 1
    uint32_t orig_as = 0;
#endif // BGP_RT == 1

    /* Network Layer Reachability Information (NLRI) */
    uint32_t nadver = 0;
    while (nlri_len > 1) {
        if (bgpFlowP->caps & 0x0200) { // ADD-PATH
            BGP_SKIP_U32(t2buf);
            if (LIKELY(nlri_len >= 4)) nlri_len -= 4;
            else nlri_len = 0;
        }

        bgp_nlri_t nlri = {};
        BGP_READ_U8(t2buf, &nlri.mask);
        if (nlri.mask > 32) {
            bgpFlowP->stat |= BGP_STAT_INVMASK;
            return;
        }
        bgpFlowP->advpref |= (1 << (nlri.mask-1));

        bgpFlowP->nadver++;
        nadver++;

        const uint_fast8_t s = (nlri.mask+7)/8;
        if (t2buf_left(t2buf) < s) {
            // Record is snapped... update statistics and return
            bgpFlowP->stat |= BGP_STAT_SNAPLEN;
            bgpFlowP->maxadver = MAX(nadver, bgpFlowP->maxadver);
            if (bgpFlowP->num_t[BGP_T_UPDATE] == 1) {
                bgpFlowP->avgadver = nadver;
            } else {
                bgpFlowP->avgadver += (nadver - bgpFlowP->avgadver) / (bgpFlowP->num_t[BGP_T_UPDATE]);
            }
            return;
        }

        for (uint_fast8_t i = 0; i < s; i++) {
            BGP_READ_U8(t2buf, &nlri.prefix[i]);
        }

        if (nlri.mask > 24) {
            bgpFlowP->aFlgs |= BGP_AFLGS_SPEC_PREF;
            BGP_LOG_ANOM("SPEC24", "%u.%u.%u.%u\t%u", nlri.prefix[0], nlri.prefix[1], nlri.prefix[2], nlri.prefix[3], nlri.mask);
            //fprintf(anom_file, "MSPEC\t%u.%u.%u.%u\t%u\t\t%lu\t%lu\t%u\n",
            //    nlri.prefix[0], nlri.prefix[1], nlri.prefix[2], nlri.prefix[3], nlri.mask,
            //    flowP->findex, numPackets, rec);
        } else if (nlri.mask <  8) {
            bgpFlowP->aFlgs |= BGP_AFLGS_LSPEC_PREF;
            BGP_LOG_ANOM("SPEC8", "%u.%u.%u.%u\t%u", nlri.prefix[0], nlri.prefix[1], nlri.prefix[2], nlri.prefix[3], nlri.mask);
            //fprintf(anom_file, "LSPEC\t%u.%u.%u.%u\t%u\t\t%lu\t%lu\t%u\n",
            //    nlri.prefix[0], nlri.prefix[1], nlri.prefix[2], nlri.prefix[3], nlri.mask,
            //    flowP->findex, numPackets, rec);
        }

#if BGP_TRAD_BOGONS == 1
        // check for traditional bogons
        if (
            /* 0.0.0.0/8       */ (nlri.mask >=  8 && nlri.prefix[0] ==   0) ||
            /* 10.0.0.0/8      */ (nlri.mask >=  8 && nlri.prefix[0] ==  10) ||
            /* 100.64.0.0/10   */ (nlri.mask >= 10 && nlri.prefix[0] == 100 && (nlri.prefix[1] & 0xc0) == 64) ||
            /* 127.0.0.0/8     */ (nlri.mask >=  8 && nlri.prefix[0] == 127) ||
            /* 169.254.0.0/16  */ (nlri.mask >= 16 && nlri.prefix[0] == 169 && nlri.prefix[1] == 254) ||
            /* 172.16.0.0/12   */ (nlri.mask >= 12 && nlri.prefix[0] == 172 && (nlri.prefix[1] & 0xf0) == 16) ||
            /* 192.0.[02].0/24 */ (nlri.mask >= 24 && nlri.prefix[0] == 192 && nlri.prefix[1] == 0 && (nlri.prefix[2] == 0 || nlri.prefix[2] == 2)) ||
            /* 192.168.0.0/16  */ (nlri.mask >= 16 && nlri.prefix[0] == 192 && nlri.prefix[1] == 168) ||
            /* 198.18.0.0/15   */ (nlri.mask >= 15 && nlri.prefix[0] == 198 && (nlri.prefix[1] & 0xfe) == 18) ||
            /* 198.51.100.0/24 */ (nlri.mask >= 24 && nlri.prefix[0] == 198 && nlri.prefix[1] == 51 && nlri.prefix[2] == 100) ||
            /* 203.0.113.0/24  */ (nlri.mask >= 24 && nlri.prefix[0] == 203 && nlri.prefix[1] ==  0 && nlri.prefix[2] == 113) ||
            /* 224.0.0.0/3     */ (nlri.mask >=  3 && (nlri.prefix[0] & 0xe0) == 224))
        {
            bgpFlowP->aFlgs |= BGP_AFLGS_BOGON;
            BGP_LOG_ANOM("BOGON", "%u.%u.%u.%u\t%u", nlri.prefix[0], nlri.prefix[1], nlri.prefix[2], nlri.prefix[3], nlri.mask);
            //fprintf(anom_file, "BOGON\t%u.%u.%u.%u\t%u\t\t%lu\t%lu\t%u\n",
            //        nlri.prefix[0], nlri.prefix[1], nlri.prefix[2], nlri.prefix[3], nlri.mask,
            //        flowP->findex, numPackets, rec);
        }
        // TODO full bogons: https://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt
#endif // BGP_TRAD_BOGONS == 1

#if BGP_RT == 1
        orig_as = bgp_update->aspath[bgp_update->nas-1].as[bgp_update->aspath[bgp_update->nas-1].nasn-1];

        uint32_t asplen = 0;
        for (uint_fast16_t i = 0; i < bgp_update->nas; i++) {
            if (bgp_update->aspath[i].stype == BGP_AS_SEQUENCE) {
                asplen += bgp_update->aspath[i].nasn;
            //} else if (bgp_update->aspath[i].stype == BGP_AS_SET) {
            //    asplen++;
            } else {
                //T2_WRN("Not implemented");
                asplen++;
            }
        }

        //if (PACKET_IS_IPV4(packet)) {
        //    BGP_INF("Route to %u.%u.%u.%u/%u advertised by %s",
        //        nlri.prefix[0], nlri.prefix[1], nlri.prefix[2], nlri.prefix[3], nlri.mask,
        //        inet_ntoa(flowP->srcIP));
        //}
        const uint8_t stype = bgp_update->aspath[bgp_update->nas-1].stype;
        //if (stype == BGP_AS_SET) {
        //    //T2_WRN("Origin AS is a SET..."); // TODO
        //}
        uint_fast8_t update = 0;
        // save and reset the mask
        const uint8_t mask = nlri.mask;
#if BGP_RT_MASK == 0
        nlri.mask = 0;
#endif // BGP_RT_MASK == 0
        unsigned long hash = hashTable_lookup(routing_table, (char*)&nlri);
        if (hash != HASHTABLE_ENTRY_NOT_FOUND) {
            bgp_rt_elem_t *e = &bgp_rt[hash];
            //BGP_INF("A route to %u.%u.%u.%u/%u already exists in the routing table (advertised by %s)",
            //        nlri.prefix[0], nlri.prefix[1], nlri.prefix[2], nlri.prefix[3], nlri.mask,
            //        inet_ntoa(*(struct in_addr*)&e->rid));

            // 1. Prefer the path with the highest WEIGHT
            // 2. Prefer the path with the highest LOCAL_PREF
            // 3. Prefer the path that was locally originate via a network or
            //    aggregate BGP subcommand or through redistribution from an IGP.
            // 4. Prefer the path with the shortest AS_PATH
            // 5. Prefer the path with the lowest ORIGIN_TYPE (IGP < EGP < INCOMPLETE)
            // 6. Prefer the path with the lowest multi-exit-discriminator (MED)
            // 7. Prefer eBGP over iBGP paths

            if (bgp_update->nexthop != e->nexthop) {
                //char oldnh[16] = {};
                //memcpy(oldnh, inet_ntoa(*(struct in_addr*)&e->nexthop), sizeof(oldnh));
                //T2_WRN("New route has a different NEXT_HOP: %s (was %s)", inet_ntoa(*(struct in_addr*)&bgp_update->nexthop), oldnh);
            }

            if (bgp_update->locpref > e->locpref) {
                //T2_WRN("New route has higher LOCAL_PREF (%u > %u), updating routing table", bgp_update->locpref, e->locpref);
                //goto update_rt;
                update = 1;
            }

            if (bgp_update->orig < e->orig) {
                //T2_WRN("New route has lowest ORIGIN_TYPE (%s < %s), updating routing table", bgp_orig_to_str(bgp_update->orig), bgp_orig_to_str(e->orig));
                //goto update_rt;
                update = 1;
            }

            if (asplen < e->nas) {
                //T2_WRN("%lu,%u: New route has shorter AS path (%u < %u), updating routing table", numPackets, rec, asplen, e->nas);
                //} else if (asplen > e->nas) {
                //    T2_WRN("%lu,%u: New route has equal or longer AS path (%u >= %u), ignoring new route", numPackets, rec, asplen, e->nas);
                //} else {
                //    T2_INF("%lu,%u: New route has AS path of same length", numPackets, rec);
                //goto update_rt;
                update = 1;
            }

            if (bgp_update->med < e->med) {
                //T2_WRN("New route has lowest MED (%u < %u), updating routing table", bgp_update->med, e->med);
                //goto update_rt;
                update = 1;
            }

            // has the AS path changed?
            if (stype == BGP_AS_SEQUENCE) {
                if (orig_as != e->orig_as) {
                    //BGP_LOG_ANOM("MOAS", "%u.%u.%u.%u\t%u\t%u\t%u",
                    //        nlri.prefix[0], nlri.prefix[1], nlri.prefix[2], nlri.prefix[3],
                    //        mask, e->orig_as, orig_as);
                    fprintf(moas_file, "%u.%u.%u.%u\t%u\t%u\t%u\t%" PRIu64 "\t%" PRIu64 "\t%u\n",
                            nlri.prefix[0], nlri.prefix[1], nlri.prefix[2], nlri.prefix[3], mask,
                            e->orig_as, orig_as, flowP->findex, numPackets, rec);
                    bgpFlowP->aFlgs |= BGP_AFLGS_MOAS;
                    //moas = 1;
                }
                //} else {
                // T2_WRN("Origin AS is a SET..."); // TODO
            }

            if (mask > e->mask) { // more specific prefix announced
                //T2_ERR("Mask has changed: %u.%u.%u.%u/%u -> %u",
                //        nlri.prefix[0], nlri.prefix[1], nlri.prefix[2], nlri.prefix[3],
                //        e->mask, mask);
                bgpFlowP->aFlgs |= BGP_AFLGS_MSPEC_PREF;
                BGP_LOG_ANOM("MSPEC", "%u.%u.%u.%u\t%u\t%u", nlri.prefix[0], nlri.prefix[1], nlri.prefix[2], nlri.prefix[3], e->mask, mask);
                //fprintf(anom_file, "MSPEC\t%u.%u.%u.%u\t%u\t%u\t%lu\t%lu\t%u\n",
                //        nlri.prefix[0], nlri.prefix[1], nlri.prefix[2], nlri.prefix[3],
                //        e->mask, mask, flowP->findex, numPackets, rec);
                update = 1;
            }

            // TODO edit distance between AS Path
            //for (i = 0; i < bgp_update->nas; i++) {
            //    if (bgp_update->aspath[i].stype == BGP_AS_SET)
            //        for (j = 0; j < bgp_update->aspath[i].nasn; j++) {
            //            bgp_update->aspath[i].as[j];
            //        }
            //    } else if (bgp_update->aspath[i].stype == BGP_AS_SEQUENCE)
            //        for (j = 0; j < bgp_update->aspath[i].nasn; j++) {
            //            bgp_update->aspath[i].as[j];
            //        }
            //    }
            //}

            // Entry will be updated
            if (update == 1) hashTable_remove(routing_table, (char*)&nlri);
        }

        // add or update the entry in the routing table
        if (hash == HASHTABLE_ENTRY_NOT_FOUND || update == 1) {
            //BGP_INF("Adding %03u.%03u.%03u.%03u/%02u to the routing table (advertised by %s)",
            //        nlri.prefix[0], nlri.prefix[1], nlri.prefix[2], nlri.prefix[3], nlri.mask,
            //        inet_ntoa(flowP->srcIP));
            hash = hashTable_insert(routing_table, (char*)&nlri);
            bgp_rt[hash].mask = mask;
            if (FLOW_IS_IPV6(flowP)) {
                bgp_rt[hash].rid = bgpFlowP->src_id;
            } else { // IPv4
                const struct in_addr srcIP = flowP->srcIP.IPv4;
                bgp_rt[hash].rid = bgpFlowP->src_id != 0 ? bgpFlowP->src_id : *((uint32_t*)&srcIP);
            }
            bgp_rt[hash].nexthop = bgp_update->nexthop;
            bgp_rt[hash].med = bgp_update->med;
            bgp_rt[hash].locpref = bgp_update->locpref;
            bgp_rt[hash].med = bgp_update->med;
            bgp_rt[hash].nas = asplen;
            bgp_rt[hash].orig = bgp_update->orig;
            bgp_rt[hash].orig_as = orig_as;
            // TODO populate old
            //BGP_INF("Route added: %s", inet_ntoa(*(struct in_addr*)&bgp_rt[hash].rid));
        }

#if BGP_RT_MASK == 0
        // reset the mask
        nlri.mask = mask;
#endif // BGP_RT_MASK == 0

#endif // BGP_RT == 1

        if (bgp_update->nn < BGP_ASIZE) {
            bgp_update->nlri[bgp_update->nn++] = nlri;
        } else if (!(bgpFlowP->stat & BGP_STAT_AFULL)) {
            T2_PWRN(plugin_name, "pkt %" PRIu64 ": Array for NLRI is full... increase BGP_ASIZE", numPackets);
            bgpFlowP->stat |= BGP_STAT_AFULL;
        }

        if (LIKELY(nlri_len >= (1 + s))) nlri_len -= (1 + s);
        else nlri_len = 0;
    }

    bgpFlowP->maxadver = MAX(nadver, bgpFlowP->maxadver);
    if (bgpFlowP->num_t[BGP_T_UPDATE] == 1) {
        bgpFlowP->avgadver = nadver;
    } else {
        bgpFlowP->avgadver += (nadver - bgpFlowP->avgadver) / (bgpFlowP->num_t[BGP_T_UPDATE]);
    }

#if BGP_OUTPUT_RT == 1
    /* Print routing tables */
    bgp_print_update(bgp_update, flowIndex);
#endif // BGP_OUTPUT_RT == 1
}


static void bgp_decode_notification(t2buf_t *t2buf, uint64_t flowIndex) {
    bgp_flow_t * const bgpFlowP = &bgp_flows[flowIndex];

    BGP_READ_U8(t2buf, &bgpFlowP->notif[0]);
    BGP_READ_U8(t2buf, &bgpFlowP->notif[1]);

#if BGP_DEBUG == 1
    T2_PINF(plugin_name, "NOTIFICATION: error code: %u, error subcode %u", bgpFlowP->notif[0], bgpFlowP->notif[1]);
#endif // BGP_DEBUG
}


static void bgp_decode_keep_alive(t2buf_t *t2buf UNUSED, uint64_t flowIndex) {
    bgp_flow_t * const bgpFlowP = &bgp_flows[flowIndex];

    if (bgpFlowP->hdrlen != BGP_HDRLEN) bgpFlowP->stat |= BGP_STAT_BAD_LEN;

    // min/max/average inter arrival time for keep-alive messages
    if (bgpFlowP->num_t[BGP_T_KEEPALIVE] > 1) { // no iat for first keep-alive
        const double iat = bgpFlowP->now - bgpFlowP->lastka;
        if (LIKELY(iat >= 0)) {
            bgpFlowP->miniatka = MIN(iat, bgpFlowP->miniatka);
            bgpFlowP->maxiatka = MAX(iat, bgpFlowP->maxiatka);
            bgpFlowP->avgiatka += (iat - bgpFlowP->avgiatka) / (bgpFlowP->num_t[BGP_T_KEEPALIVE]-1);
        } else if (!(bgpFlowP->stat & BGP_STAT_IAT)) {
#if BGP_DEBUG == 1
            T2_PWRN(plugin_name, "pkt %" PRIu64 ": IAT < 0", numPackets);
#endif // BGP_DEBUG == 1
            bgpFlowP->stat |= BGP_STAT_IAT;
        }
    }

    bgpFlowP->lastka = bgpFlowP->now;
}


static void bgp_decode_route_refresh(t2buf_t *t2buf, uint64_t flowIndex) {
    bgp_flow_t * const bgpFlowP = &bgp_flows[flowIndex];

    uint16_t afi;
    BGP_READ_U16(t2buf, &afi);

    uint8_t subtype;
    BGP_READ_U8(t2buf, &subtype);

    uint8_t safi;
    BGP_READ_U8(t2buf, &safi);

#if BGP_DEBUG == 1
    T2_PINF(plugin_name, "ROUTE-REFRESH: AFI: %u, SUBTYPE: %u, SAFI: %u", afi, subtype, safi);
#endif // BGP_DEBUG

    if (t2buf_left(t2buf) > 4) { // Message contains ORF entries

        /* Flag */
        BGP_SKIP_U8(t2buf);

        /* Type */
        BGP_SKIP_U8(t2buf);

        /* Length */
        uint16_t len;
        BGP_READ_U16(t2buf, &len);

        if (t2buf_left(t2buf) < len) {
            T2_PDBG(plugin_name, "pkt %" PRIu64 ": Malformed ORF entries (snaplen)", numPackets);
            bgpFlowP->stat |= BGP_STAT_SNAPLEN;
            return;
        }

        // TODO Analyze ORF entries
    }
}


void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {
    const bgp_flow_t * const bgpFlowP = &bgp_flows[flowIndex];

    bgpAFlgs |= bgpFlowP->aFlgs;
    bgpCaps  |= bgpFlowP->caps;
    bgpPAttr |= bgpFlowP->attr;
    bgpStat  |= bgpFlowP->stat;

    OUTBUF_APPEND_U16(buf, bgpFlowP->stat);
    OUTBUF_APPEND_U16(buf, bgpFlowP->aFlgs);
    OUTBUF_APPEND_U8( buf, bgpFlowP->msgT);

    for (uint_fast8_t i = 1; i <= BGP_T_RTE_REFRSH; i++) {
        OUTBUF_APPEND_U32(buf, bgpFlowP->num_t[i]);
    }

    // OPEN Message
    OUTBUF_APPEND_U8(buf, bgpFlowP->version);
#if BGP_AS_FORMAT > 0
    char asdot[BGP_ASDOT_LEN];
    bgp_asplain_to_asdot(bgpFlowP->src_as, &asdot[0]);
    OUTBUF_APPEND_STR(buf, asdot);
    bgp_asplain_to_asdot(bgpFlowP->dst_as, &asdot[0]);
    OUTBUF_APPEND_STR(buf, asdot);
#else // BGP_AS_FORMAT == 0
    OUTBUF_APPEND_U32(buf, bgpFlowP->src_as);
    OUTBUF_APPEND_U32(buf, bgpFlowP->dst_as);
#endif // BGP_AS_FORMAT == 0
    OUTBUF_APPEND_U32(buf, bgpFlowP->src_id);
    OUTBUF_APPEND_U32(buf, bgpFlowP->dst_id);
    OUTBUF_APPEND_U16(buf, bgpFlowP->htime);
    OUTBUF_APPEND_U16(buf, bgpFlowP->caps);

    // UPDATE Messages
    OUTBUF_APPEND_U32(buf, bgpFlowP->attr);
    OUTBUF_APPEND_U32(buf, bgpFlowP->nadver);
    OUTBUF_APPEND_U32(buf, bgpFlowP->nwdrwn);
    OUTBUF_APPEND_U32(buf, bgpFlowP->maxadver);
    OUTBUF_APPEND_DBL(buf, bgpFlowP->avgadver);
    OUTBUF_APPEND_U32(buf, bgpFlowP->maxwdrwn);
    OUTBUF_APPEND_DBL(buf, bgpFlowP->avgwdrwn);
    OUTBUF_APPEND_U32(buf, bgpFlowP->advpref);
    OUTBUF_APPEND_U32(buf, bgpFlowP->wdrnpref);
    for (uint_fast8_t i = 0; i < 3; i++) {
        OUTBUF_APPEND_U32(buf, bgpFlowP->origin[i]);
    }
    OUTBUF_APPEND_U8( buf, bgpFlowP->minasplen);
    OUTBUF_APPEND_U8( buf, bgpFlowP->maxasplen);
    OUTBUF_APPEND_DBL(buf, bgpFlowP->avgasplen);
    OUTBUF_APPEND_U32(buf, bgpFlowP->maxnprepas);
    OUTBUF_APPEND_DBL(buf, bgpFlowP->miniatup);
    OUTBUF_APPEND_DBL(buf, bgpFlowP->maxiatup);
    OUTBUF_APPEND_DBL(buf, bgpFlowP->avgiatup);

    // KEEPALIVE Messages
    OUTBUF_APPEND_DBL(buf, bgpFlowP->miniatka);
    OUTBUF_APPEND_DBL(buf, bgpFlowP->maxiatka);
    OUTBUF_APPEND_DBL(buf, bgpFlowP->avgiatka);

    // NOTIFICATION Message
#if BGP_NOTIF_FORMAT == 1
    const char * const notif = bgp_notif_to_str(bgpFlowP->notif[0]);
    OUTBUF_APPEND_STR(buf, notif);
#else // BGP_NOTIF_FORMAT == 0
    OUTBUF_APPEND_U8(buf, bgpFlowP->notif[0]);
#endif // BGP_NOTIF_FORMAT
    OUTBUF_APPEND_U8(buf, bgpFlowP->notif[1]);
}


void t2PluginReport(FILE *stream) {
    if (num_bgp[0] > 0) {
        T2_FPLOG_AGGR_HEX(stream, plugin_name, bgpStat);
        T2_FPLOG_AGGR_HEX(stream, plugin_name, bgpAFlgs);
        T2_FPLOG_AGGR_HEX(stream, plugin_name, bgpCaps);
        T2_FPLOG_AGGR_HEX(stream, plugin_name, bgpPAttr);
        T2_FPLOG_NUMP0(stream, plugin_name, "Number of BGP packets", num_bgp[0], numPackets);
        char hrnum[64];
        for (uint_fast8_t i = 1; i <= BGP_T_RTE_REFRSH; i++) {
            if (num_bgp[i] > 0) {
                T2_CONV_NUM(num_bgp[i], hrnum);
                T2_FPLOG(stream, plugin_name, "Number of BGP %s messages: %" PRIu64 "%s [%.2f%%]",
                        bgp_type_to_str(i), num_bgp[i], hrnum, 100.0*num_bgp[i]/(double)num_bgp[0]);
            }
        }
    }
}


void t2Finalize() {
    free(bgp_flows);
    free(bgp_update);

#if BGP_RT == 1
    hashTable_destroy(routing_table);
    free(bgp_rt);
#endif // BGP_RT == 1

    if (LIKELY(moas_file != NULL)) {
        fclose(moas_file);
        moas_file = NULL;
    }

    if (LIKELY(anom_file != NULL)) {
        fclose(anom_file);
        anom_file = NULL;
    }

#if BGP_OUTPUT_RT == 1
    if (LIKELY(bgp_file != NULL)) {
        fclose(bgp_file);
        bgp_file = NULL;
    }
#endif // BGP_OUTPUT_RT == 1
}


#if BGP_OUTPUT_RT == 1
static inline const char *bgp_orig_to_str(uint8_t orig) {
    switch (orig) {
        case 0:  return "IGP";
        case 1:  return "EGP";
        case 2:  return "INCOMPLETE";
        default: return "UNKNOWN";
    }
}
#endif // BGP_OUTPUT_RT == 1


static inline const char *bgp_type_to_str(uint8_t type) {
    switch (type) {
        case BGP_T_OPEN:       return "OPEN";
        case BGP_T_UPDATE:     return "UPDATE";
        case BGP_T_NOTIF:      return "NOTIFICATION";
        case BGP_T_KEEPALIVE:  return "KEEPALIVE";
        case BGP_T_RTE_REFRSH: return "ROUTE-REFRESH";
        default:               return "UNKNOWN";
    }
}


#if BGP_NOTIF_FORMAT == 1
static inline const char *bgp_notif_to_str(uint8_t code) {
    switch (code) {
        case 0:              return "0";
        case BGP_E_MSG_HDR:  return "MSGHDR";
        case BGP_E_OPEN_MSG: return "OPEN";
        case BGP_E_UPD_MSG:  return "UPDATE";
        case BGP_E_HT_EXPIR: return "HOLDTIMER";
        case BGP_E_FSM:      return "FSM";
        case BGP_E_CEASE:    return "CEASE";
        case BGP_E_RTE_REFR: return "RTEREFR";
        default:             return "UNKNOWN";
    }
}
#endif // BGP_NOTIF_FORMAT


#if BGP_AS_FORMAT > 0
static inline void bgp_asplain_to_asdot(uint32_t as, char *asdot) {
    uint32_t a1, a2;
    if (as < 65536) {
#if BGP_AS_FORMAT == 1 // ASDOT
        snprintf(&asdot[0], BGP_ASDOT_LEN, "%" PRIu32, as);
        return;
#endif // BGP_AS_FORMAT == 1
        a1 = 0;
        a2 = as;
    } else {
        a1 = as / 65536;
        a2 = as - a1 * 65536;
    }
    snprintf(&asdot[0], BGP_ASDOT_LEN, "%" PRIu32 ".%" PRIu32, a1, a2);
}
#endif // BGP_AS_FORMAT > 0


#if BGP_OUTPUT_RT == 1
static void bgp_print_update(bgp_flow_update_t *bgp_update, uint64_t flowIndex) {
    bgp_flow_t * const bgpFlowP = &bgp_flows[flowIndex];
    const flow_t * const flowP = &flows[flowIndex];

    uint32_t imax = MIN(bgp_update->nn, BGP_ASIZE);
    for (uint_fast32_t i = 0; i < imax; i++) {
        fprintf(bgp_file, "%u.%u.%u.%u/%u",
                bgp_update->nlri[i].prefix[0],
                bgp_update->nlri[i].prefix[1],
                bgp_update->nlri[i].prefix[2],
                bgp_update->nlri[i].prefix[3],
                bgp_update->nlri[i].mask);
        if (i+1 < imax) fputc(';', bgp_file);
    }
    fputc('\t', bgp_file);
    //fprintf(bgp_file, "%u_%s_", bgpFlowP->src_as, inet_ntoa(*(struct in_addr*)&bgpFlowP->src_id));
    //fprintf(bgp_file, "%s_", inet_ntoa(*(struct in_addr*)&flowP->srcIP));
    //fprintf(bgp_file, "%s_", inet_ntoa(*(struct in_addr*)&flowP->dstIP));
    //fprintf(bgp_file, "%u_%s\t", bgpFlowP->dst_as, inet_ntoa(*(struct in_addr*)&bgpFlowP->dst_id));
    uint32_t sas;
    if (FLOW_IS_B(flowP)) {
        sas = bgpFlowP->dst_as;
    } else {
        sas = bgpFlowP->src_as;
    }

#if BGP_AS_FORMAT > 0
    char asdot[BGP_ASDOT_LEN];
    bgp_asplain_to_asdot(sas, asdot);
    fprintf(bgp_file, "%s\t", asdot);
#else // BGP_AS_FORMAT == 0
    fprintf(bgp_file, "%" PRIu32 "\t", sas);
#endif // BGP_AS_FORMAT == 0

    fprintf(bgp_file, "%s\t", inet_ntoa(*(struct in_addr*)&bgp_update->nexthop));
    fprintf(bgp_file, "%" PRIu32 "\t", bgp_update->med);
    fprintf(bgp_file, "%" PRIu32 "\t", bgp_update->locpref);
    fprintf(bgp_file, "%s\t", bgp_orig_to_str(bgp_update->orig));

#if BGP_ORIG_ID == 1
    fprintf(bgp_file, "%s\t", inet_ntoa(*(struct in_addr*)&bgp_update->orig_id));
#endif

    const uint32_t dest_as = bgp_update->aspath[0].as[0];
    const uint32_t orig_as = bgp_update->aspath[bgp_update->nas-1].as[bgp_update->aspath[bgp_update->nas-1].nasn-1];

    /* Origin AS */
    uint_fast8_t stype = bgp_update->aspath[bgp_update->nas-1].stype;
    if (stype == BGP_AS_SET) {
        fprintf(bgp_file, "%u", bgp_update->aspath[bgp_update->nas-1].as[0]);
        for (uint_fast8_t i = 1; i < bgp_update->aspath[bgp_update->nas-1].nasn; i++) {
            fprintf(bgp_file, ";%u", bgp_update->aspath[bgp_update->nas-1].as[i]);
        }
    } else {
        fprintf(bgp_file, "%u", orig_as);
    }

    fputc('\t', bgp_file);

    /* Upstream AS */
    if (stype == BGP_AS_SET) {
        stype = bgp_update->aspath[bgp_update->nas-2].stype;
        if (stype == BGP_AS_SET) {
            fprintf(bgp_file, "%u", bgp_update->aspath[bgp_update->nas-2].as[0]);
            for (uint_fast8_t i = 1; i < bgp_update->aspath[bgp_update->nas-2].nasn; i++) {
                fprintf(bgp_file, ";%u", bgp_update->aspath[bgp_update->nas-2].as[i]);
            }
        } else {
            uint32_t i = 2;
            uint32_t upst_as = bgp_update->aspath[bgp_update->nas-2].as[bgp_update->aspath[bgp_update->nas-2].nasn-1];
            // Make sure not to report prepended AS as upstream AS
            while (upst_as == orig_as && bgp_update->aspath[bgp_update->nas-2].nasn >= i) {
                upst_as = bgp_update->aspath[bgp_update->nas-2].as[bgp_update->aspath[bgp_update->nas-2].nasn-i];
                i++;
            }
            // TODO if upst_as == orig_as
            fprintf(bgp_file, "%u", upst_as);
        }
    } else if (bgp_update->aspath[bgp_update->nas-1].nasn >= 2) {
        uint32_t i = 3;
        uint32_t upst_as = bgp_update->aspath[bgp_update->nas-1].as[bgp_update->aspath[bgp_update->nas-1].nasn-2];
        // Make sure not to report prepended AS as upstream AS
        while (upst_as == orig_as && bgp_update->aspath[bgp_update->nas-1].nasn >= i) {
            upst_as = bgp_update->aspath[bgp_update->nas-1].as[bgp_update->aspath[bgp_update->nas-1].nasn-i];
            i++;
        }
        // TODO if upst_as == orig_as
        fprintf(bgp_file, "%u", upst_as);
    } else {
        // Should not happen?
    }

    /* Destination AS */
    fprintf(bgp_file, "\t%u\t", dest_as);

#if BGP_AGGR == 1
    fprintf(bgp_file, "%" PRIu32 ":%s\t", bgp_update->aggr[0], inet_ntoa(*(struct in_addr*)&bgp_update->aggr[1]));
#endif

    uint16_t alen = 0;
    imax = MIN(bgp_update->nas, BGP_ASIZE);
    uint32_t prevas = 0, nprepas = 0, maxnprepas = 0;
    for (uint_fast16_t i = bgp_update->nas4; i < imax; i++) {
        if (bgp_update->aspath[i].stype == BGP_AS_SET) {
            alen++;
            fprintf(bgp_file, "{");
        } else {
            alen += bgp_update->aspath[i].nasn;
        }
        const uint32_t jmax = MIN(bgp_update->aspath[i].nasn, BGP_ASIZE);
        for (uint_fast32_t j = 0; j < jmax; j++) {
            // AS Path can have repetitions of the same AS (AS-Path Prepending)
            // (this can be used to render a route less attractive for BGP (longer))
            // TODO instead of ignoring repetitions, replace them with AS_NUMREP
            if (prevas == bgp_update->aspath[i].as[j]) {
                nprepas++;
            } else {
                nprepas = 0;
            }
            maxnprepas = MAX(nprepas, maxnprepas);
            prevas = bgp_update->aspath[i].as[j];
#if BGP_AS_PATH_AGGR == 1
            if (j == 0 || bgp_update->aspath[i].as[j] != bgp_update->aspath[i].as[j-1]) {
#endif // BGP_AS_PATH_AGGR == 1
#if BGP_AS_FORMAT > 0
                bgp_asplain_to_asdot(bgp_update->aspath[i].as[j], asdot);
                fprintf(bgp_file, "%s", asdot);
#else // BGP_AS_FORMAT == 0
                fprintf(bgp_file, "%" PRIu32, bgp_update->aspath[i].as[j]);
#endif // BGP_AS_FORMAT == 0
                if (j+1 < jmax) {
#if BGP_AS_PATH_AGGR == 1
                    uint16_t tmp16 = 1;
                    while (j+tmp16 < bgp_update->aspath[i].nasn) {
                        if (bgp_update->aspath[i].as[j] != bgp_update->aspath[i].as[j+tmp16]) {
#endif // BGP_AS_PATH_AGGR == 1
                            fputc(';', bgp_file);
#if BGP_AS_PATH_AGGR == 1
                            break;
                        }
                        //nprepas++;
                        tmp16++;
                        // TODO increment j?
                    }
#endif // BGP_AS_PATH_AGGR == 1
                }
#if BGP_AS_PATH_AGGR == 1
            }
#endif // BGP_AS_PATH_AGGR == 1
        }
        if (bgp_update->aspath[i].stype == BGP_AS_SET) fprintf(bgp_file, "}");
        if (i+1 < imax) fputc(';', bgp_file);
    }
    fprintf(bgp_file, "\t%u\t%u\t", alen, maxnprepas);

#if BGP_CLUSTER == 1
    imax = MIN(bgp_update->nclust, BGP_ASIZE);
    for (uint_fast32_t i = 0; i < imax; i++) {
        fprintf(bgp_file, "%s", inet_ntoa(*(struct in_addr*)&bgp_update->cluster[i]));
        if (i+1 < imax) fputc(';', bgp_file);
    }
    fprintf(bgp_file, "\t%u\t", bgp_update->nclust);
#endif

#if BGP_COMMUNITIES == 1
    imax = MIN(bgp_update->nc, BGP_ASIZE);
    for (uint_fast32_t i = 0; i < imax; i++) {
        switch (bgp_update->comm[i][0] << 16 | bgp_update->comm[i][1]) {
            case BGP_COM_PLAN_SHUT:     fprintf(bgp_file, "planned-shut");               break;
            case BGP_COM_ACCEPT_OWN:    fprintf(bgp_file, "ACCEPT-OWN");                 break;
            case BGP_COM_RTE_FILTR_TR4: fprintf(bgp_file, "ROUTE_FILTER_TRANSLATED_v4"); break;
            case BGP_COM_RTE_FILTR_4:   fprintf(bgp_file, "ROUTE_FILTER_v4");            break;
            case BGP_COM_RTE_FILTR_TR6: fprintf(bgp_file, "ROUTE_FILTER_TRANSLATED_v6"); break;
            case BGP_COM_RTE_FILTR_6:   fprintf(bgp_file, "ROUTE_FILTER_v6");            break;
            case BGP_COM_LLGR_STALE:    fprintf(bgp_file, "LLGR_STALE");                 break;
            case BGP_COM_NO_LLGR:       fprintf(bgp_file, "NO_LLGR");                    break;
            case BGP_COM_ACCEPT_OWN_NH: fprintf(bgp_file, "accept-own-nexthop");         break;
            case BGP_COM_BLACKHOLE:     fprintf(bgp_file, "BLACKHOLE");                  break;
            case BGP_COM_NO_EXPORT:     fprintf(bgp_file, "NO_EXPORT");                  break;
            case BGP_COM_NO_ADVERT:     fprintf(bgp_file, "NO_ADVERTISE");               break;
            case BGP_COM_NO_EXP_SUB:    fprintf(bgp_file, "NO_EXPORT_SUBCONFED");        break;
            case BGP_COM_NOPEER:        fprintf(bgp_file, "NOPEER");                     break;
            default: fprintf(bgp_file, "%u:%u", bgp_update->comm[i][0], bgp_update->comm[i][1]); break;
        }
        if (i+1 < imax) fputc(';', bgp_file);
    }
    fputc('\t', bgp_file);
#endif // BGP_COMMUNITIES == 1

    imax = MIN(bgp_update->nw, BGP_ASIZE);
    for (uint_fast16_t i = 0; i < imax; i++) {
        fprintf(bgp_file, "%u.%u.%u.%u/%u",
                bgp_update->withdrawn[i].prefix[0],
                bgp_update->withdrawn[i].prefix[1],
                bgp_update->withdrawn[i].prefix[2],
                bgp_update->withdrawn[i].prefix[3],
                bgp_update->withdrawn[i].mask);
        if (i+1 < imax) fputc(';', bgp_file);
    }

    //fprintf(bgp_file, "\t%s", inet_ntoa(*(struct in_addr*)&flowP->srcIP));
    //fprintf(bgp_file, "\t%s", inet_ntoa(*(struct in_addr*)&flowP->dstIP));
    fprintf(bgp_file, "\t%" PRIu64 "\t%" PRIu64 "\t%" PRIu32 "\t%f\n", flowP->findex, numPackets, rec, bgpFlowP->now);
}
#endif // BGP_OUTPUT_RT == 1
