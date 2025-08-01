/*
 * vtpDecode.c
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

#include "vtpDecode.h"

#include "t2buf.h"


vtpFlow_t *vtpFlows;


// Packet mode

#define VTP_SPKTMD_PRI_HDR() \
    if (sPktFile) { \
        fputs("vtpStat"       SEP_CHR \
              "vtpVer"        SEP_CHR \
              "vtpCode"       SEP_CHR \
              "vtpDomain"     SEP_CHR \
              "vtpVlanTypeBF" SEP_CHR \
              , sPktFile); \
    }

#define VTP_SPKTMD_PRI0() \
    if (sPktFile) { \
        fputs("0x0000" /* vtpStat       */ SEP_CHR \
                       /* vtpVer        */ SEP_CHR \
                       /* vtpCode       */ SEP_CHR \
                       /* vtpDomain     */ SEP_CHR \
                       /* vtpVlanTypeBF */ SEP_CHR \
              , sPktFile); \
    }

#define VTP_SPKTMD_PRI1() \
    if (sPktFile) { \
        fprintf(sPktFile, \
                "0x%04" B2T_PRIX16 /* vtpStat       */ SEP_CHR \
                                   /* vtpVer        */ SEP_CHR \
                                   /* vtpCode       */ SEP_CHR \
                                   /* vtpDomain     */ SEP_CHR \
                                   /* vtpVlanTypeBF */ SEP_CHR \
                , vtpFlowP->stat); \
    }

#define VTP_SPKTMD_PRI2() \
    if (sPktFile) { \
        fprintf(sPktFile, \
                "0x%04" B2T_PRIX16 /* vtpStat       */ SEP_CHR \
                "0x%02" B2T_PRIX8  /* vtpVer        */ SEP_CHR \
                                   /* vtpCode       */ SEP_CHR \
                                   /* vtpDomain     */ SEP_CHR \
                                   /* vtpVlanTypeBF */ SEP_CHR \
                , vtpFlowP->stat, ver); \
    }

#define VTP_SPKTMD_PRI() \
    if (sPktFile) { \
        fprintf(sPktFile, \
                "0x%04" B2T_PRIX16 /* vtpStat       */ SEP_CHR \
                "0x%02" B2T_PRIX8  /* vtpVer        */ SEP_CHR \
                "0x%02" B2T_PRIX8  /* vtpCode       */ SEP_CHR \
                "%s"               /* vtpDomain     */ SEP_CHR \
                "0x%02" B2T_PRIX8  /* vtpVlanTypeBF */ SEP_CHR \
                , vtpFlowP->stat, ver, code, domain, vtpFlowP->vlanTypeBF); \
    }


#define VTP_OUTBUF_APPEND_TS(buf, src) { \
    struct tm t = {}; \
    if (strptime(src, "%y-%m-%d %H:%M:%S", &t)) { \
        const uint64_t epoch = mktime(&t); \
        OUTBUF_APPEND_TIME_SEC(buf, epoch); \
    } else { \
        OUTBUF_APPEND_TIME_ZERO(buf); \
    } \
}

#define VTP_TS_TO_STR(src, dst) \
    sprintf(dst, "%.2s-%.2s-%.2s %.2s:%.2s:%.2s", \
            &src[0], &src[2], &src[4], \
            &src[6], &src[8], &src[10]); \
    if (strlen(dst) != 17) { \
        dst[0] = '\0'; \
    }


// Static variables

static uint64_t numVtpPkts[VTP_V_LAST+1];     // store sum of all VTP packets at pos 0
static uint64_t numVtpCodes[VTP_NUM_CODES+1]; // store unknown codes at pos 0
static uint16_t vtpStat;
static uint8_t  vtpCodeBF;
static uint8_t  vtpVlanTypeBF;

#if VTP_SAVE == 1
static FILE *vtpFile;
#endif


// Tranalyzer functions

T2_PLUGIN_INIT("vtpDecode", "0.9.3", 0, 9);


void t2Init() {
    T2_PLUGIN_STRUCT_NEW(vtpFlows);

#if VTP_SAVE == 1
    t2_env_t env[ENV_VTP_N] = {};
#if ENVCNTRL > 0
    t2_get_env(PLUGIN_SRCH, ENV_VTP_N, env);
#else // ENVCNTRL == 0
    T2_SET_ENV_STR(VTP_SUFFIX);
#endif // ENVCNTRL

    vtpFile = t2_fopen_with_suffix(baseFileName, T2_ENV_VAL(VTP_SUFFIX), "w");
    if (UNLIKELY(!vtpFile)) exit(EXIT_FAILURE);

    fputs(HDR_CHR "pktNo\tflowInd\tsrcMac\t"
          "vtpVer\tvtpDomain\tvtpRevNum\tvtpVlanType\tvtpVlanID\t"
          "vtpVlanName\tvtpVlanSAID\tvtpVlanMTU\tvtpVlanSusp\n"
          , vtpFile);

#if ENVCNTRL > 0
    t2_free_env(ENV_VTP_N, env);
#endif // ENVCNTRL
#endif // VTP_SAVE == 1

    VTP_SPKTMD_PRI_HDR();
}


binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;
    BV_APPEND_H16(bv,   "vtpStat"      , "VTP status");
    BV_APPEND_H8(bv,    "vtpVer"       , "VTP version");
    BV_APPEND_H8(bv,    "vtpCodeBF"    , "VTP aggregated codes");
    BV_APPEND_H8(bv,    "vtpVlanTypeBF", "VTP aggregated VLAN types");
    BV_APPEND_STR(bv,   "vtpDomain"    , "VTP Management Domain");
#if VTP_NUM_UPDID > 0
    BV_APPEND_U32(bv,   "vtpNumUpdId"  , "VTP number Updater Identity");
    BV_APPEND_IP4_R(bv, "vtpUpdId"     , "VTP Updater Identity");
#endif // VTP_NUM_UPDID > 0
    BV_APPEND_TYPE(bv,  "vtpFirstUpdTS", "VTP Timestamp of first update", VTP_TS_TYPE);
    BV_APPEND_TYPE(bv,  "vtpLastUpdTS" , "VTP Timestamp of last update" , VTP_TS_TYPE);
    return bv;
}


void t2OnNewFlow(packet_t *packet UNUSED, unsigned long flowIndex) {
    vtpFlow_t * const vtpFlowP = &vtpFlows[flowIndex];
    memset(vtpFlowP, '\0', sizeof(*vtpFlowP));

    const flow_t * const flowP = &flows[flowIndex];
    if (!(flowP->status & L2_FLOW)) return;

    if (packet->ethType == ETHERTYPE_VTP) {
        vtpFlowP->stat |= VTP_STAT_VTP;
    }
}


#if ETH_ACTIVATE > 0
void t2OnLayer2(packet_t *packet, unsigned long flowIndex) {
    if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;

    vtpFlow_t * const vtpFlowP = &vtpFlows[flowIndex];

    if (!(vtpFlowP->stat & VTP_STAT_VTP)) {
        VTP_SPKTMD_PRI0();
        return;
    }

#if VTP_SAVE == 1
    const flow_t * const flowP = &flows[flowIndex];
    const uint64_t findex = flowP->findex;
#endif // VTP_SAVE == 1

    numVtpPkts[0]++;

    const uint16_t snaplen = packet->snapL7Len;
    const uint8_t * const l7HdrP = packet->l7HdrP;
    t2buf_t t2buf = t2buf_create(l7HdrP, snaplen);

    // Used for packet mode
    char domain[VTP_STR_MAX+1] = {};

    /* Version */
    uint8_t ver;
    if (!t2buf_read_u8(&t2buf, &ver)) {
        vtpFlowP->stat |= VTP_STAT_SNAP;
        VTP_SPKTMD_PRI1();
        return;
    }
    if (ver > 0 && ver <= VTP_V_LAST) {
        numVtpPkts[ver]++;
    } else {
        vtpFlowP->stat |= VTP_STAT_IVER;
    }
    if (vtpFlowP->codeBF && ver != vtpFlowP->ver) {
        vtpFlowP->stat |= VTP_STAT_DVER;
    }
    vtpFlowP->ver = ver; // only store last version

    /* Code */
    uint8_t code;
    if (!t2buf_read_u8(&t2buf, &code)) {
        vtpFlowP->stat |= VTP_STAT_SNAP;
        VTP_SPKTMD_PRI2();
        return;
    }
    if (code > 0 && code <= VTP_NUM_CODES) {
        numVtpCodes[code]++;
        vtpFlowP->codeBF |= (1 << code);
    } else {
        numVtpCodes[0]++;
        vtpFlowP->codeBF |= (1 << VTP_C_UNKNOWN);
        vtpFlowP->stat |= VTP_STAT_CODE;
    }

    /*
     * Followers       (code == 1)
     * Sequence Number (code == 2)
     * Reserved        (code == 3, 4)
     */
    VTP_SKIP_U8(&t2buf);
    //uint8_t byte3;
    //VTP_READ_U8(&t2buf, &byte3);
    //if (code == 2 && byte3 > vtpFlowP->lastSeqNum) {
    //    vtpFlowP->lastSeqNum = byte3;
    //}

    /* Management Domain Length */
    uint8_t mdLen;
    VTP_READ_U8(&t2buf, &mdLen);
    if (mdLen > 32) {
        vtpFlowP->stat |= VTP_STAT_MDLEN;
    }

    /* Management Domain (padded with 0 to 32) */
    VTP_READ_STR(&t2buf, domain, 32, VTP_STR_MAX);
    if (vtpFlowP->domain[0] == '\0') {
        memcpy(vtpFlowP->domain, domain, MIN(32, VTP_STR_MAX));
    } else if (memcmp(domain, vtpFlowP->domain, MIN(32, VTP_STR_MAX) + 1) != 0) {
        vtpFlowP->stat |= VTP_STAT_DMD;
    }

    switch (code) {
        /* Summary Advertisement */
        case VTP_C_SUMADV: {
            /* Configuration Revision Number */
            VTP_SKIP_U32(&t2buf);
            /* Updater Identity */
            uint32_t updId;
            VTP_READ_LE_U32(&t2buf, &updId);
#if VTP_NUM_UPDID > 0
#if VTP_AGGR == 1
            bool found = false;
            for (uint_fast32_t i = 0; i < vtpFlowP->numUpdId; i++) {
                if (updId == vtpFlowP->updId[i]) {
                    found = true;
                    break;
                }
            }
            if (!found) {
#endif
                if (vtpFlowP->numUpdId < VTP_NUM_UPDID) {
                    vtpFlowP->updId[vtpFlowP->numUpdId++] = updId;
                } else {
                    vtpFlowP->stat |= VTP_STAT_ARR;
                }
#if VTP_AGGR == 1
            } // !found
#endif
#endif // VTP_NUM_UPDID > 0
            /* Update Timestamp */
            uint8_t upTS[VTP_TS_LEN];
            VTP_READ_N(&t2buf, upTS, VTP_TS_LEN);
            static const uint8_t ts0[VTP_TS_LEN] = {};
            if (memcmp(vtpFlowP->firstUpTS, ts0, VTP_TS_LEN) == 0 ||
                memcmp(upTS, vtpFlowP->firstUpTS, VTP_TS_LEN) < 0)
            {
                memcpy(vtpFlowP->firstUpTS, upTS, VTP_TS_LEN);
            }
            if (memcmp(upTS, vtpFlowP->lastUpTS, VTP_TS_LEN) > 0) {
                memcpy(vtpFlowP->lastUpTS, upTS, VTP_TS_LEN);
            }
            /* MD5 Digest */
            char md5[VTP_MD5_STRLEN+1];
            VTP_READ_HEX(&t2buf, md5, 16, VTP_MD5_STRLEN)
            break;
        }

        /* Subset Advertisement */
        case VTP_C_SUBADV: {
            /* Configuration Revision Number */
            uint32_t revNum;
            VTP_READ_U32(&t2buf, &revNum);
            /* VLAN Information */
            while (t2buf_left(&t2buf) > 0) {
                const long start = t2buf_tell(&t2buf);
                /* VLAN Information Length */
                uint8_t viLen;
                VTP_READ_U8(&t2buf, &viLen);
                const long end = start + viLen;
                /* Status */
                uint8_t status;
                VTP_READ_U8(&t2buf, &status);
                /* VLAN Type */
                uint8_t type;
                VTP_READ_U8(&t2buf, &type);
                if (type > 0 && type < VTP_VLAN_UNKNOWN) {
                    vtpFlowP->vlanTypeBF |= (1 << type);
                } else {
                    vtpFlowP->stat |= VTP_STAT_VLAN_TYPE;
                }
                /* VLAN Name Length */
                uint8_t vnLen;
                VTP_READ_U8(&t2buf, &vnLen);
                /* ISL VLAN ID */
                uint16_t vlanId;
                VTP_READ_U16(&t2buf, &vlanId);
                /* MTU Size */
                uint16_t mtu;
                VTP_READ_U16(&t2buf, &mtu);
                /* 802.10 Index (IEEE 802.10 security association identifier for this VLAN) */
                uint32_t vlan80210;
                VTP_READ_U32(&t2buf, &vlan80210);
                /* VLAN Name */
                vnLen = 4 * ((vnLen + 3) / 4); // rounded up to a multiple of 4
                char vlan[VTP_STR_MAX+1];
                VTP_READ_STR(&t2buf, vlan, vnLen, VTP_STR_MAX);

#if VTP_SAVE == 1
                char srcMac[T2_MAC_STRLEN+1] = {};
                t2_mac_to_str(ETH_HEADER(packet)->ethDS.ether_shost, srcMac, sizeof(srcMac));
                fprintf(vtpFile, "%" PRIu64 "\t"         // pktNo
                                 "%" PRIu64 "\t"         // flowInd
                                 "%s\t"                  // srcMac
                                 "0x%02" B2T_PRIX8 "\t"  // vtpVer
                                 "%s\t"                  // vtpDomain
                                 "%" PRIu32 "\t"         // vtpRevNum
                                 "0x%02" B2T_PRIX8 "\t"  // vtpVlanType
#if VTP_VLANID_FRMT == 0
                                 "%" PRIu16 "\t"         // vtpVlanID
#else // VTP_VLANID_FRMT == 1
                                 "0x%04" B2T_PRIX16 "\t" // vtpVlanID
#endif // VTP_VLANID_FRMT == 1
                                 "%s\t"                  // vtpVlanName
                                 "0x%08" B2T_PRIX32 "\t" // vtpVlanSAID
                                 "%" PRIu16 "\t"         // vtpVlanMTU
                                 "%d\n",                 // vtpVlanSuspended
                        numPackets, findex,
                        srcMac, ver, domain,
                        revNum, type, vlanId, vlan,
                        vlan80210, mtu, status & 1);
#endif // VTP_SAVE == 1

                viLen -= (12 + vnLen);
                while (viLen > 0) {
                    // VLAN Info TLV
                    /* TLV Type */
                    uint8_t tlvtype;
                    VTP_READ_U8(&t2buf, &tlvtype);
                    /* TLV Length */
                    uint8_t tlvlen;
                    VTP_READ_U8(&t2buf, &tlvlen);
                    tlvlen *= 2;
                    /* TLV Length */
                    VTP_SKIP_N(&t2buf, tlvlen);
                    viLen -= (2 + tlvlen);
                }

                // Jump over the VLAN Information block
                t2buf_seek(&t2buf, end, SEEK_SET);
            }
            break;
        }

        /* Advertisement Request */
        case VTP_C_ADVREQ: {
            /* Start Value */
            VTP_SKIP_U16(&t2buf);
            break;
        }

        /* Join/Prune Message */
        case VTP_C_JOIN: {
            /* First VLAN ID */
            uint16_t first;
            VTP_READ_U16(&t2buf, &first);
            /* Last VLAN ID */
            VTP_SKIP_U16(&t2buf);
            /* Advertised active (i.e. not pruned) VLANs */
            while (t2buf_left(&t2buf) > 0) {
                uint8_t bitmap;
                VTP_READ_U8(&t2buf, &bitmap);
                //uint16_t vlan = first;
                for (uint_fast8_t i = 0; i < 8; i++) {
                    if (bitmap & 0x80) {
                       // VLAN ID won't be pruned
                    }
                    //vlan++;
                    bitmap <<= 1;
                }
            }
            break;
        }

        default:
#if VTP_DEBUG == 1
            T2_PWRN(plugin_name, "packet %" PRIu64 ": Invalid VTP code 0x%02" B2T_PRIX8, numPackets, code);
#endif
            break;
    }

    VTP_SPKTMD_PRI();
}
#endif // ETH_ACTIVATE > 0


void t2OnLayer4(packet_t *packet UNUSED, unsigned long flowIndex UNUSED) {
    VTP_SPKTMD_PRI0();
}


void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {

    const vtpFlow_t * const vtpFlowP = &vtpFlows[flowIndex];

    vtpStat |= vtpFlowP->stat;
    vtpCodeBF |= vtpFlowP->codeBF;
    vtpVlanTypeBF |= vtpFlowP->vlanTypeBF;

    OUTBUF_APPEND_U16(buf, vtpFlowP->stat);       // vtpStat
    OUTBUF_APPEND_U8(buf, vtpFlowP->ver);         // vtpVer
    OUTBUF_APPEND_U8(buf, vtpFlowP->codeBF);      // vtpCodeBF
    OUTBUF_APPEND_U8(buf, vtpFlowP->vlanTypeBF);  // vtpVlanTypeBF
    OUTBUF_APPEND_STR(buf, vtpFlowP->domain);     // vtpDomain

#if VTP_NUM_UPDID > 0
    OUTBUF_APPEND_U32(buf, vtpFlowP->numUpdId);   // vtpNumUpdId
    OUTBUF_APPEND_ARRAY_U32(buf, vtpFlowP->updId, vtpFlowP->numUpdId);   // vtpUpdId
#endif // VTP_NUM_UPDID > 0

    char ts[18] = {};

    // vtpFirstUpTS
    VTP_TS_TO_STR(vtpFlowP->firstUpTS, ts);
#if VTP_TS_FRMT == 1
    VTP_OUTBUF_APPEND_TS(buf, ts);
#else // VTP_TS_FRMT == 0
    OUTBUF_APPEND_STR(buf, ts);
#endif // VTP_TS_FRMT == 0

    // vtpLastUpTS
    VTP_TS_TO_STR(vtpFlowP->lastUpTS, ts);
#if VTP_TS_FRMT == 1
    VTP_OUTBUF_APPEND_TS(buf, ts);
#else // VTP_TS_FRMT == 0
    OUTBUF_APPEND_STR(buf, ts);
#endif // VTP_TS_FRMT == 0
}


void t2PluginReport(FILE *stream) {
    if (vtpStat) {
        T2_FPLOG_AGGR_HEX0(stream, plugin_name, vtpStat);
        T2_FPLOG_AGGR_HEX(stream, plugin_name, vtpCodeBF);
        T2_FPLOG_AGGR_HEX(stream, plugin_name, vtpVlanTypeBF);
        T2_FPLOG_NUMP0(stream, plugin_name, "Number of VTP packets", numVtpPkts[0], numPackets);
        T2_FPLOG_NUMP(stream, plugin_name, "Number of VTPv1 packets", numVtpPkts[VTP_V1], numVtpPkts[0]);
        T2_FPLOG_NUMP(stream, plugin_name, "Number of VTPv2 packets", numVtpPkts[VTP_V2], numVtpPkts[0]);
        T2_FPLOG_NUMP(stream, plugin_name, "Number of VTPv3 packets", numVtpPkts[VTP_V3], numVtpPkts[0]);
        T2_FPLOG_NUMP(stream, plugin_name, "Number of VTP Summary Advertisement packets", numVtpCodes[VTP_C_SUMADV], numVtpPkts[0]);
        T2_FPLOG_NUMP(stream, plugin_name, "Number of VTP Subset Advertisement packets", numVtpCodes[VTP_C_SUBADV], numVtpPkts[0]);
        T2_FPLOG_NUMP(stream, plugin_name, "Number of VTP Advertisement Request packets", numVtpCodes[VTP_C_ADVREQ], numVtpPkts[0]);
        T2_FPLOG_NUMP(stream, plugin_name, "Number of VTP Join/Prune Message packets", numVtpCodes[VTP_C_JOIN], numVtpPkts[0]);
        T2_FPLOG_NUMP(stream, plugin_name, "Number of VTP packets with unknown type", numVtpCodes[0], numVtpPkts[0]);
    }
}


void t2Finalize() {
    free(vtpFlows);
#if VTP_SAVE == 1
    fclose(vtpFile);
#endif
}
