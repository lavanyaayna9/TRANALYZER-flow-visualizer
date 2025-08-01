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

#include "voipDetector.h"

#include <errno.h>  // for errno


// Global variables

voipFlow_t *voipFlows;


// Static variables

#if VOIP_SIP > 0
#if VOIP_SIP > 1
static hashMap_t *voipHashMap;
static uint64_t  *voipFindex;
static uint32_t  *voipSSRC;
#endif // VOIP_SIP > 1

static uint64_t sipPktCnt, sipPktCnt0;
static uint64_t sdpPktCnt, sdpPktCnt0;
static uint64_t sipFdxMtch, sipFdxMtch0;
static uint64_t sipAPCnt, sipAPCnt0;
static uint64_t sipMethPkts[VOIP_METH_N], sipMethPkts0[VOIP_METH_N];

static uint16_t sipMethods;
#endif // VOIP_SIP > 0

#if VOIP_RTP == 1
static uint64_t rtpPktCnt, rtpPktCnt0;
#endif // VOIP_RTP == 1

#if VOIP_RTCP == 1
static uint64_t rtcpPktCnt, rtcpPktCnt0;
#endif // VOIP_RTCP == 1

static uint16_t voipStat;

#if VOIP_SAVE == 1
static int32_t voipFdCnt;
static int32_t voipFdCntMax, voipFdCntMax0;
#endif // VOIP_SAVE == 1

#if ENVCNTRL > 0 && VOIP_SAVE == 1
static t2_env_t env[ENV_VOIP_N];
#endif // ENVCNTRL > 0 && VOIP_SAVE == 1

#if VOIP_SAVE == 1
#if ENVCNTRL > 0
static char *fname;
static char *vpath;
#else // ENVCNTRL == 0
static const char * const fname = VOIP_FNAME;
static const char * const vpath = VOIP_V_PATH;
#endif // ENVCNTRL == 0
#endif // VOIP_SAVE == 1

#if VOIP_RTP == 1 && VOIP_SAVE == 1 && VOIP_SILREST == 1 && VOIP_BUFMODE != 1
#define SILENCE_BUF_LEN 4096
static uint8_t ulaw_silence[SILENCE_BUF_LEN];
static uint8_t alaw_silence[SILENCE_BUF_LEN];
#endif // VOIP_RTP == 1 && VOIP_SAVE == 1 && VOIP_SILREST == 1 && VOIP_BUFMODE != 1


// Macros

#define VOIP_SPKTMD_PRI_NONE(stat) \
    if (sPktFile) { \
        fprintf(sPktFile, \
                "0x%04" B2T_PRIX16 /* voipStat   */ SEP_CHR \
                                   /* voipType   */ SEP_CHR \
                                   /* voipSeqN   */ SEP_CHR \
                                   /* voipTs     */ SEP_CHR \
                                   /* voipTsDiff */ SEP_CHR \
                                   /* voipSSRC   */ SEP_CHR \
                , (uint16_t)(stat)); \
    }


// Tranalyzer functions

T2_PLUGIN_INIT("voipDetector", "0.9.3", 0, 9);


#if VOIP_RTP == 1 && VOIP_SAVE == 1
static inline void open_new_chunk(voipFlow_t *voipFP, const flow_t *flowP) {
    const uint8_t typ = voipFP->typ[0];

    const char *a;
    if (typ < 35) a = voipRTPFEL[typ];
    else if (typ >= 96 && typ <= 127) a = voipRTPFEH[typ-96];
    else a = voipRTPFEL[35];

#if VOIP_SVFDX == 1
    snprintf(voipFP->vname, sizeof(voipFP->vname),
                "%s/%s_%" PRIu32 "_%" PRIu64 "_%s_%" PRIu8 "_%c.raw",
                vpath, fname, sensorID, flowP->findex, a, typ, FLOW_DIR_C(flowP));

    // do not delete file from other file of the same ssrc
    if (!(voipFP->fd = file_manager_open(t2_file_manager, voipFP->vname, "r+b"))) {
        voipFP->fd = file_manager_open(t2_file_manager, voipFP->vname, "w+b");
    }

    if (UNLIKELY(!voipFP->fd)) {
        T2_PFATAL(plugin_name, "failed to open file '%s' (%d) for writing: %s",
                               voipFP->vname, voipFdCnt, strerror(errno));
    }
#else // VOIP_SVFDX == 0
    snprintf(voipFP->vname, sizeof(voipFP->vname),\
                "%s/%s_%" PRIu32 "_%" PRIu64 "_%" PRIx32 "_%s_%" PRIu8 "_%c.raw",
                vpath, fname, sensorID, flowP->findex, voipFP->ssN[voipFP->actSSRCi],
                a, typ, FLOW_DIR_C(flowP));

    // do not delete file from other file of the same ssrc
    if (!(voipFP->fd[voipFP->actSSRCi] = file_manager_open(t2_file_manager, voipFP->vname, "r+b"))) {
        voipFP->fd[voipFP->actSSRCi] = file_manager_open(t2_file_manager, voipFP->vname, "w+b");
    }

    if (UNLIKELY(!voipFP->fd[voipFP->actSSRCi])) {
        T2_PFATAL(plugin_name, "failed to open file '%s' (%d) for writing: %s",
                               voipFP->vname, voipFdCnt, strerror(errno));
    }
#endif // VOIP_SVFDX

    if (++voipFdCnt > voipFdCntMax) voipFdCntMax = voipFdCnt;
}


#if VOIP_SILREST == 1
static inline void restore_silence(voipFlow_t *voipFP, const flow_t *flowP, uint8_t payload_type, uint32_t timestamp) {
    if (voipFP->next_timestamp == 0 || voipFP->next_timestamp >= timestamp) {
        return;
    }

    // number of missing silent 8-bit samples
    size_t len = timestamp - voipFP->next_timestamp;
    if (len > 8000 * FLOW_TIMEOUT) {
        return; // silence cannot be longer than flow timeout
    }

#if VOIP_BUFMODE == 1
    const uint8_t silence_byte = (payload_type == PT_PCMU) ? 0xff : 0xd5;
    if (voipFP->rtpbufpos + len <= RTPBUFSIZE) {
        memset(voipFP->rtpbuf + voipFP->rtpbufpos, silence_byte, len);
        voipFP->rtpbufpos += len;
        return;
    }
#endif // VOIP_BUFMODE == 1

#if VOIP_SVFDX == 1
    if (!voipFP->fd) open_new_chunk(voipFP, flowP);
    FILE * const fp = file_manager_fp(t2_file_manager, voipFP->fd);
#else // VOIP_SVFDX == 0
    if (!voipFP->fd[voipFP->actSSRCi]) open_new_chunk(voipFP, flowP);
    FILE * const fp = file_manager_fp(t2_file_manager, voipFP->fd[voipFP->actSSRCi]);
#endif // VOIP_SVFDX

    fseek(fp, 0, SEEK_END);

#if VOIP_BUFMODE == 1
    const size_t bufspace = RTPBUFSIZE - voipFP->rtpbufpos;
    if (bufspace > 0) {
        memset(voipFP->rtpbuf + voipFP->rtpbufpos, silence_byte, bufspace);
        len -= bufspace;
    }
    fwrite(voipFP->rtpbuf, RTPBUFSIZE, 1, fp);
    memset(voipFP->rtpbuf, silence_byte, RTPBUFSIZE);
    while (len >= RTPBUFSIZE) {
        fwrite(voipFP->rtpbuf, RTPBUFSIZE, 1, fp);
        len -= RTPBUFSIZE;
    }
    voipFP->rtpbufpos = len;
#else  // VOIP_BUFMODE == 0
    const uint8_t * const silence_bytes = payload_type == PT_PCMU ? ulaw_silence : alaw_silence;
    while (len > 0) {
        const size_t towrite = len > SILENCE_BUF_LEN ? SILENCE_BUF_LEN : len;
        fwrite(silence_bytes, towrite, 1, fp);
        len -= towrite;
    }
#endif // VOIP_BUFMODE == 1
}
#endif // VOIP_SILREST == 1

#endif // VOIP_RTP == 1 && VOIP_SAVE == 1


void t2Init() {
    T2_PLUGIN_STRUCT_NEW(voipFlows);

#if VOIP_SAVE == 1
#if ENVCNTRL > 0
    t2_get_env(PLUGIN_SRCH, ENV_VOIP_N, env);
    const uint8_t rmdir = T2_ENV_VAL_UINT(VOIP_RMDIR);
    vpath = T2_ENV_VAL(VOIP_V_PATH);
    fname = T2_ENV_VAL(VOIP_FNAME);
#else // ENVCNTRL == 0
    //T2_SET_ENV_STR(VOIP_V_PATH);
    //T2_SET_ENV_STR(VOIP_FNAME);
    const uint8_t rmdir = VOIP_RMDIR;
#endif // ENVCNTRL

    T2_MKPATH_WITH_FLAGS(vpath, VOIP_PERM, rmdir);

#if RTPSUBDIRS > 1
    char pathbuf[sizeof(VOIP_V_PATH) + 100] = {}; // some margin for longer env based path
    for (int i = 0; i < RTPSUBDIRS; ++i) {
        if (snprintf(pathbuf, sizeof(VOIP_V_PATH) + 100 - 1, "%s/%06d", vpath, i) < 0) {
            T2_PFATAL(plugin_name, "Failed to build directory path %s/%06d: %s", vpath, i, strerror(errno));
        }
        T2_MKPATH_WITH_FLAGS(pathbuf, VOIP_PERM, rmdir);
    }
#endif // RTPSUBDIRS > 1
#endif // VOIP_SAVE == 1

#if VOIP_SIP > 1
    // initialize voip SIP/RTP data pair hash and the index arrays
    voipHashMap = hashTable_init(1.0f, sizeof(ipPrt_t), "voip");
    voipFindex = t2_calloc_fatal(voipHashMap->hashChainTableSize, sizeof(uint64_t));
    voipSSRC = t2_calloc_fatal(voipHashMap->hashChainTableSize, sizeof(uint32_t));
#endif // VOIP_SIP > 1

#if VOIP_RTP == 1 && VOIP_SAVE == 1 && VOIP_SILREST == 1 && VOIP_BUFMODE == 0
    memset(ulaw_silence, 0xff, SILENCE_BUF_LEN);
    memset(alaw_silence, 0xd5, SILENCE_BUF_LEN);
#endif // VOIP_RTP == 1 && VOIP_SAVE == 1 && VOIP_SILREST == 1 && VOIP_BUFMODE == 0

    if (sPktFile) {
        fputs("voipStat"   SEP_CHR
              "voipType"   SEP_CHR
              "voipSeqN"   SEP_CHR
              "voipTs"     SEP_CHR
              "voipTsDiff" SEP_CHR
              "voipSSRC"   SEP_CHR
              , sPktFile);
    }
}


binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;

    BV_APPEND_H16(bv   , "voipStat"   , "VoIP status");

#if VOIP_RTP == 1 || VOIP_RTCP == 1
    BV_APPEND_U8_R(bv  , "voipType"   , "VoIP RTP / RTCP Type");
    BV_APPEND_H32_R(bv , "voipSSRC"   , "VoIP RTP / RTCP Synchronization Source Identifier");
    BV_APPEND_H32_R(bv , "voipCSRC"   , "VoIP RTP / RTCP Contributing Sources");
    BV_APPEND_U8(bv    , "voipSRCnt"  , "VoIP RTP SID / RTCP record count");
#endif // VOIP_RTP == 1 || VOIP_RTCP == 1

#if VOIP_RTP == 1
    // RTP
    BV_APPEND_U32(bv   , "rtpPMCnt"   , "VoIP RTP packet miss count");
    BV_APPEND_FLT(bv   , "rtpPMr"     , "VoIP RTP packet miss ratio");
#endif // VOIP_RTP == 1

#if VOIP_SIP > 0
    // SIP
    BV_APPEND_H16(bv   , "sipMethods" , "VoIP SIP methods");
    BV_APPEND_U8(bv    , "sipStatCnt" , "VoIP SIP stat count");
    BV_APPEND_U8(bv    , "sipReqCnt"  , "VoIP SIP request count");
    BV_APPEND_STR(bv   , "sipUsrAgnt" , "VoIP SIP User-Agent");
    BV_APPEND_STR(bv   , "sipRealIP"  , "VoIP SIP X-Real-IP");
    BV_APPEND_STR_R(bv , "sipFrom"    , "VoIP SIP Caller");
    BV_APPEND_STR_R(bv , "sipTo"      , "VoIP SIP Callee");
    BV_APPEND_STR_R(bv , "sipCallID"  , "VoIP SIP Call-ID");
    BV_APPEND_STR_R(bv , "sipContact" , "VoIP SIP Contact");
    BV_APPEND_U16_R(bv , "sipStat"    , "VoIP SIP stat");
    BV_APPEND_STRC_R(bv, "sipReq"     , "VoIP SIP request");

    // SDP
    BV_APPEND_STR_R(bv , "sdpSessID"  , "VoIP SDP session ID");
    BV_APPEND_R(bv     , "sdpRFAdd"   , "VoIP SDP RTP audio/video flow address", 1, VOIP_IP_TYPE);
    BV_APPEND_U16_R(bv , "sdpRAFPrt"  , "VoIP SDP RTP audio flow port");
    BV_APPEND_U16_R(bv , "sdpRVFPrt"  , "VoIP SDP RTP video flow port");
    BV_APPEND_STRC_R(bv, "sdpRTPMap"  , "VoIP SIP SDP rtpmap");

#if VOIP_SIP > 1
    BV_APPEND_U64_R(bv , "voipFindex" , "VoIP SIP RTP findex");
#endif // VOIP_SIP > 1
#endif // VOIP_SIP > 0

#if VOIP_RTCP == 1
    // RTCP
    BV_APPEND_U32(bv   , "rtcpTPCnt"  , "VoIP RTCP cumulated transmitter packet count");
    BV_APPEND_U32(bv   , "rtcpTBCnt"  , "VoIP RTCP cumulated transmitter byte count");
    BV_APPEND_U8(bv    , "rtcpFracLst", "VoIP RTCP cumulated fraction lost");
    BV_APPEND_U32(bv   , "rtcpCPMCnt" , "VoIP RTCP cumulated packet miss count");
    BV_APPEND_U32(bv   , "rtcpMaxIAT" , "VoIP RTCP max inter-arrival time");
#endif // VOIP_RTCP == 1

#if VOIP_SAVE == 1
    BV_APPEND_STR(bv   , "voipFname"  , "VoIP RTP content filename");
#endif // VOIP_SAVE == 1

    return bv;
}


void t2OnNewFlow(packet_t *packet, unsigned long flowIndex) {
    voipFlow_t * const voipFP = &voipFlows[flowIndex];
    memset(voipFP, '\0', sizeof(voipFlow_t));

    const flow_t * const flowP = &flows[flowIndex];
    const uint_fast8_t l4Proto = flowP->l4Proto;
    const uint_fast16_t sport = flowP->srcPort;
    const uint_fast16_t dport = flowP->dstPort;

#if VOIP_SIP > 0
    // SIP can be transported over UDP or TCP
    if ((l4Proto != L3_UDP && l4Proto != L3_TCP) || sport < 1024 || dport < 1024) return;
#else // VOIP_SIP == 0
    if (l4Proto != L3_UDP || sport < 1024 || dport < 1024) return;
#endif // VOIP_SIP

    uint64_t snaplen = packet->snapL7Len;

#if VOIP_SIP > 0
    uint8_t *dP8 = (uint8_t*)packet->l7HdrP;

    if (sport == 3483 || dport == 3483) {
        if (snaplen <= 12) return;
        snaplen -= 10;
        dP8 += 2;
        if (snaplen - 10 == ntohs(*(uint16_t*)dP8)) {
            voipFP->stat = STUN;
            return;
        } else if (snaplen != ntohs(*(uint16_t*)dP8)) {
            return;
        }

        dP8 += 10;
        snaplen -= 2;
        voipFP->stat = STUN;
    }

    if (memmem(dP8, snaplen, VSIP, sizeof(VSIP)-1) || sport == 5060 || sport == 5070 || dport == 5060 || dport == 5070) {
        voipFP->stat |= SIP;
        /*uint8_t *cp;
        if ((cp = memmem(dP8, snaplen, "To:", 3))) cp += 3;
        else cp = dP8;

        if (!(cp = memmem(cp, snaplen, "sip:", 4))) return;

        cp += 4; // skip sip:

        const uint8_t * const cpe = dP8 + snaplen;
        const uint8_t * const cpa = cp--;
        while (++cp <= cpe) {
            if (*cp > 63) continue;
            if ((len = ((uint64_t)1 << *cp) & SCMASK)) break;
        }

        if (len) {
            len = MIN(cp - cpa, SIPNMMAX);
            memcpy(voipFP->sipTo, cpa, len);
            voipFP->sipTo[len] = '\0';
        }*/

        uint64_t len = 0;
        uint8_t *ua = memmem(dP8, snaplen, "User-Agent: ", 12);
        if (ua) {
            ua += 12; // skip User-Agent:
            const uint8_t * const ue = memchr(ua, '\r', snaplen - (ua - dP8) - 12);
            if (ue) {
                len = MIN(ue - ua, SIPNMMAX);
                memcpy(voipFP->usrAgnt, ua, len);
            }
        }

        ua = memmem(dP8, snaplen, "X-Real-IP: ", 11);
        if (ua) {
            ua += 11; // skip X-Real-IP:
            const uint8_t * const ue = memchr(ua, '\r', snaplen - (ua - dP8) - 12);
            if (ue) {
                len = MIN(ue - ua, SIPNMMAX);
                memcpy(voipFP->realIP, ua, len);
            }
        }

        return;
    }

    if (l4Proto == L3_TCP) return;
#endif // VOIP_SIP > 0

    if (snaplen <= 12) return;

#if VOIP_RTCP == 1 || VOIP_RTP == 1 || VOIP_SIP > 1
    const voipRtcpH_t * const voipRtcpHP = (voipRtcpH_t*)packet->l7HdrP;
    //if ((voipRtcpHP->vpr & RTPVERMASK) != RTPVER) return; // version 2 only
#endif // VOIP_RTCP == 1 || VOIP_RTP == 1 || VOIP_SIP > 1

    if (sport > 1023 && dport > 1023) {
        const bool spb = sport % 2;
        const bool dpb = dport % 2;
        if (spb & dpb) {
        //if (dpb) {
#if VOIP_RTCP == 1
            if (voipRtcpHP->typ > 199 && voipRtcpHP->typ < 211) {
                voipFP->stat |= RTCP | (voipRtcpHP->vpr & RTP_P);
                voipFP->rtcpSsN = voipRtcpHP->ssrc;
                voipFP->rCnt = (voipRtcpHP->vpr & 0x1f);
            } else {
#if VOIP_RTP == 1
                goto proc_rtp;
#endif // VOIP_RTP == 1
            }
#endif // VOIP_RTCP == 1
        //} else if (!(spb | dpb)) {
        } else {
#if VOIP_RTCP == 1 && VOIP_RTP == 1
proc_rtp:
#endif // VOIP_RTCP == 1 && VOIP_RTP == 1
#if VOIP_RTP == 1
            voipFP->stat |= (RTP | (voipRtcpHP->typ & 0x80) | (voipRtcpHP->vpr & (RTP_X | RTP_P)));
            voipFP->ssN[0] = voipRtcpHP->id;
            voipFP->rtpSeqN = ntohs(voipRtcpHP->len) - 1;
            voipFP->tsLst = ntohl(voipRtcpHP->ssrc);
#if VOIP_SILREST == 1
            voipFP->next_timestamp = voipFP->tsLst;
#endif // VOIP_SILREST == 1
            voipFP->rCnt = (voipRtcpHP->vpr & 0x0f);
#endif // VOIP_RTP == 1

#if VOIP_SIP > 1
            //const uint8_t ipver = FLOW_IPVER(flowP);
            ipPrt_t ipPrt = {
                //.ver = ipver,
                .addr = flowP->dstIP,
                .port = dport
            };

            unsigned long vpIndex = hashTable_lookup(voipHashMap, (char*)&ipPrt);
            if (vpIndex == HASHTABLE_ENTRY_NOT_FOUND) {
                vpIndex = hashTable_insert(voipHashMap, (char*)&ipPrt);
                voipSSRC[vpIndex] = ntohl(voipRtcpHP->id);
                voipFindex[vpIndex] = flowP->findex;
            }

#if VOIP_SIP_PRV > 0
            //const uint8_t ipver = FLOW_IPVER(flowP);
            ipPrt.addr = flowP->srcIP;
            ipPrt.port = sport;

            vpIndex = hashTable_lookup(voipHashMap, (char*)&ipPrt);
            if (vpIndex == HASHTABLE_ENTRY_NOT_FOUND) {
                vpIndex = hashTable_insert(voipHashMap, (char*)&ipPrt);
                voipSSRC[vpIndex] = ntohl(voipRtcpHP->id);
                voipFindex[vpIndex] = flowP->findex;
            }
#endif // VOIP_SIP_PRV > 0
#endif // VOIP_SIP > 1
        }
    }
}


#if ETH_ACTIVATE > 0
void t2OnLayer2(packet_t* packet UNUSED, unsigned long flowIndex UNUSED) {
    if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;
    VOIP_SPKTMD_PRI_NONE(0);
}
#endif // ETH_ACTIVATE > 0


void t2OnLayer4(packet_t *packet, unsigned long flowIndex) {
#if VOIP_SAVE == 1
    const flow_t * const flowP = &flows[flowIndex];
#endif // VOIP_SAVE == 1

    voipFlow_t * const voipFP = &voipFlows[flowIndex];
    if (!(voipFP->stat & RTP_CC)) {
        VOIP_SPKTMD_PRI_NONE(0);
        return;
    }

#if DTLS == 1
    const uint16_t dHOff = ((packet->status & L7_DTLS) ? sizeof(dtls12Header_t) : 0);
#endif // DTLS

    uint32_t rci = 0;

#if (VOIP_RTP == 1 || (VOIP_RTCP == 1 && VOIP_ANALEN == 1))
    uint16_t *dP16;
#endif // (VOIP_RTP == 1 || (VOIP_RTCP == 1 && VOIP_ANALEN == 1))

    uint16_t voipStat = voipFP->stat & RTP_CP;

#if DTLS == 1
    uint8_t *dP8 = (uint8_t*)packet->l7HdrP + dHOff;
#else // DTLS == 0
    uint8_t *dP8 = (uint8_t*)packet->l7HdrP;
#endif // DTLS

    const voipRtcpH_t *voipRtcpHP = (voipRtcpH_t*)dP8;
    uint8_t typ = voipRtcpHP->typ;
    uint8_t type[10] = {};

#if VOIP_SIP > 0 || VOIP_SAVE == 1
#if DTLS == 1
    const int32_t snapL7Len = packet->snapL7Len - dHOff;
#else // DTLS == 0
    const int32_t snapL7Len = packet->snapL7Len;
#endif // DTLS
#endif // VOIP_SIP > 0 || VOIP_SAVE == 1

    // only 1. frag packet will be processed
    if (!t2_is_first_fragment(packet)) goto pktout;

#if VOIP_SIP > 0
    int32_t status = -1;
    uint8_t *cp;

    if (voipFP->stat & STUN) {
        uint64_t i = snapL7Len - 4;
        if (i <= 2 || i != ntohs(*(uint16_t*)(dP8 + 2))) goto pktout;

        dP8 += 4;

        if (voipFP->stat & SIP) goto proc_sip;

        if (memmem(dP8, i, VSIP, sizeof(VSIP)-1)) {  // Response, e.g., SIP/2.0 200 OK
            voipFP->stat |= SIP;
            if ((cp = memmem(dP8, i, "To:", 3))) cp += 3;
            else cp = dP8;

            if ((cp = memmem(cp, i, "sip:", 4))) cp += 4;
            else {
                VOIP_SPKTMD_PRI_NONE(voipStat);
                return;
            }

            const uint8_t * const cpe = dP8 + snapL7Len;
            const uint8_t * const cpa = cp--;
            i = 0;
            while (++cp <= cpe) {
                if (*cp > 63) continue;
                if ((i = ((uint64_t)1 << *cp) & SCMASK)) break;
            }

            if (i) {
                i = MIN(cp - cpa, SIPNMMAX);
                memcpy(voipFP->sipTo[voipFP->sipToi], cpa, i);
                voipFP->sipTo[voipFP->sipToi++][i] = '\0';
            }

            goto pktout;
        }

        if ((voipRtcpHP->vpr & RTPVERMASK) != RTPVER) {
            voipFP->stat = voipStat = 0x0000;
            goto pktout; // version 2 only
        }
    } // voipFP->stat & STUN

proc_sip:
#if (VOIP_RTP == 1 || (VOIP_RTCP == 1 && VOIP_ANALEN == 1))
    dP16 = (uint16_t*)dP8;
#endif // (VOIP_RTP == 1 || (VOIP_RTCP == 1 && VOIP_ANALEN == 1))

    if (voipFP->stat & SIP) {
        typ = 0;
        sipPktCnt++;
        if (!memcmp(dP8, VSIP, sizeof(VSIP)-1)) {  // Response, e.g., SIP/2.0 200 OK
            if (voipFP->sipStatCnt < SIPSTATMAX && (cp = memchr(dP8 + 4, ' ', 4))) {
                status = strtoul((const char*)++cp, NULL, 0);
                for (uint32_t k = 0; k < voipFP->sipStatCnt; k++) {
                    if (status == voipFP->sipStat[k]) goto proc_from;
                }

                voipFP->sipStat[voipFP->sipStatCnt++] = status;
            }

        } else {  // Request, e.g., METHOD URI SIP/2.0
            if (*dP8 >= 65 && *dP8 <= 90) {  // A-Z
                // Parse method
                uint_fast32_t i;
                uint_fast32_t method = 0;
                for (i = 1; sip_methods[i].s_name; i++) {
                    if (memcmp(dP8, sip_methods[i].l_name, strlen(sip_methods[i].l_name)) == 0) {
                        method = i;
                        break;
                    }
                }

                sipMethPkts[method]++;
                voipFP->sipMethods |= (1 << method);

                if (voipFP->sipRqCnt < SIPSTATMAX) {
                    for (uint_fast32_t k = 0; k < voipFP->sipRqCnt; k++) {
                        if (!memcmp(dP8, voipFP->sipRq[k], strlen(voipFP->sipRq[k]))) goto proc_from;
                    }

                    memcpy(voipFP->sipRq[voipFP->sipRqCnt++], dP8, SIPCLMAX);
                }
            } else {
                sipPktCnt--;
                if ((snapL7Len == 2 && *(uint16_t*)dP8 == 0x0a0d) ||
                    (voipFP->sipRqCnt + voipFP->sipStatCnt > 0))
                {
                    // A request/response was already parsed for this flow,
                    // ignore this packet, but don't reset the status of the flow
                    VOIP_SPKTMD_PRI_NONE(voipStat);
                    return;
                } else {
                    voipFP->stat = voipStat = RTP;
                    goto test_rtp;
                }
            }
        }

proc_from:;
        const uint8_t *cpa = memmem(dP8, snapL7Len, "From: ", 6);
        //char *cpe = cpa;
        if (cpa) {
            cpa += 6; // jump over From:
            int len = (int)(packet->end_packet - cpa);
            const uint8_t * const cpa1 = memchr(cpa, '<', len);
            const uint8_t * const cpa2 = memchr(cpa, ':', len);
            if (!cpa1 && !cpa2) goto proc_to;
            cpa = MAX3(cpa1, cpa2, cpa);
            cpa++; // jump over <
            uint8_t *cpe = memchr(cpa, '\r', len);
            if (!cpe) goto proc_to; // No CR abort processing line
            uint8_t * const cpe1 = memchr(cpa, '>', len);
            uint8_t * const cpe2 = memchr(cpa, ';', len);
            if (cpe1 && cpe2) cpe = MIN3(cpe1, cpe2, cpe);
            else if (cpe1) cpe = MIN(cpe1, cpe);
            else if (cpe2) cpe = MIN(cpe2, cpe);
            len = cpe - cpa;
            //while (++cpe < (char*)packet->end_packet) {
            //    if (*cpe > 63) continue;
            //    if ((len = ((uint64_t)1 << *cpe) & SCMASK)) break;
            //}

            //if (cpe && voipFP->sipFrmi < SIPSTATMAX) {
            if (len && voipFP->sipFrmi < SIPSTATMAX) {
                len = MIN(len, SIPNMMAX);
                for (uint_fast32_t k = 0; k < voipFP->sipFrmi; k++) {
                    if (!memcmp(cpa, voipFP->sipFrm[k], len)) goto proc_to;
                }

                memcpy(voipFP->sipFrm[voipFP->sipFrmi], cpa, len);
                voipFP->sipFrm[voipFP->sipFrmi++][len] = '\0';
            }
        }

proc_to:
        cpa = memmem(dP8, snapL7Len, "To: ", 4);
        if (cpa) {
            cpa += 4; // jump over To:
            int len = (int)(packet->end_packet - cpa);
            const uint8_t * const cpa1 = memchr(cpa, '<', len);
            const uint8_t * const cpa2 = memchr(cpa, ':', len);
            if (!cpa1 && !cpa2) goto proc_callid;
            cpa = MAX3(cpa1, cpa2, cpa);
            cpa++; // jump over <
            uint8_t *cpe = memchr(cpa, '\r', len);
            if (!cpe) goto proc_callid; // No CR abort processing line
            uint8_t *cpe1 = memchr(cpa, '>', len);
            uint8_t *cpe2 = memchr(cpa, ';', len);
            if (cpe1 && cpe2) cpe = MIN3(cpe1, cpe2, cpe);
            else if (cpe1) cpe = MIN(cpe1, cpe);
            else if (cpe2) cpe = MIN(cpe2, cpe);
            len = cpe - cpa;

            if (len && voipFP->sipToi < SIPSTATMAX) {
                len = MIN(len, SIPNMMAX);
                for (uint_fast32_t k = 0; k < voipFP->sipToi; k++) {
                    if (!memcmp(cpa, voipFP->sipTo[k], len)) goto proc_callid;
                }

                memcpy(voipFP->sipTo[voipFP->sipToi], cpa, len);
                voipFP->sipTo[voipFP->sipToi++][len] = '\0';
            }
        }

proc_callid:
        cpa = memmem(dP8, snapL7Len, "Call-ID: ", 9);
        if (cpa) {
            cpa += 9; // jump over Call-ID:
            int len = (int)(packet->end_packet - cpa);
            uint8_t *cpe = memchr(cpa, '\r', len);
            if (!cpe) goto proc_contact;
            len = cpe - cpa;

            if (len && voipFP->sipCIDi < SIPSTATMAX) {
                len = MIN(len, SIPNMMAX);
                for (uint_fast32_t k = 0; k < voipFP->sipCIDi; k++) {
                    if (!memcmp(cpa, voipFP->sipCID[k], len)) goto proc_contact;
                }

                memcpy(voipFP->sipCID[voipFP->sipCIDi], cpa, len);
                voipFP->sipCID[voipFP->sipCIDi++][len] = '\0';
            }
        }

proc_contact:
        cpa = memmem(dP8, snapL7Len, "Contact: ", 9);
        if (cpa) {
            cpa += 9; // jump over Contact:
            int len = (int)(packet->end_packet - cpa);
            const uint8_t * const cpa1 = memchr(cpa, '<', len);
            const uint8_t * const cpa2 = memchr(cpa, ':', len);
            if (!cpa1 && !cpa2) goto proc_sdp;
            cpa = (cpa2) ? cpa2 : cpa1;
            if (!cpa) goto proc_sdp;
            cpa++; // jump over <
            uint8_t *cpe = memchr(cpa, '\r', len);
            if (!cpe) goto proc_sdp; // No CR abort processing line
            uint8_t *cpe1 = memchr(cpa, '>', len);
            uint8_t *cpe2 = memchr(cpa, ';', len);
            if (cpe1 && cpe2) cpe = MIN3(cpe1, cpe2, cpe);
            else if (cpe1) cpe = MIN(cpe1, cpe);
            else if (cpe2) cpe = MIN(cpe2, cpe);
            len = cpe - cpa;

            if (len && voipFP->sipContacti < SIPSTATMAX) {
                len = MIN(len, SIPNMMAX);
                for (uint_fast32_t k = 0; k < voipFP->sipContacti; k++) {
                    if (!memcmp(cpa, voipFP->sipContact[k], len)) goto proc_sdp;
                }

                memcpy(voipFP->sipContact[voipFP->sipContacti], cpa, len);
                voipFP->sipContact[voipFP->sipContacti++][len] = '\0';
            }
        }

proc_sdp:;
        const uint8_t * const pos = memmem(dP8, snapL7Len, SDP, sizeof(SDP)-1);
        if (pos) {
            voipStat |= VOIP_STAT_SDP;
            sdpPktCnt++;
            const uint8_t * const mp = pos + sizeof(SDP);
            const int l = (int)(packet->end_packet - pos);
            const uint8_t *midx = memmem(mp, l, "o=", 2);
            if (midx && voipFP->sdpSessIdi < SIPSTATMAX) {
                midx += 3;
                int ll = l - 3;
                while (*midx++ != ' ' && ll > 0) ll--; // skip username
                const uint8_t * const p = memchr(midx, ' ', ll);
                if (p) {
                    const int lp = (int)(p - midx);
                    for (uint_fast32_t k = 0; k < voipFP->sdpSessIdi; k++) {
                        if (!memcmp(midx, voipFP->sdpSessId[k], lp)) goto proc_c_in;
                    }

                    memcpy(voipFP->sdpSessId[voipFP->sdpSessIdi], midx, lp);
                    voipFP->sdpSessId[voipFP->sdpSessIdi++][lp+1] = '\0';
                }
            }

proc_c_in:
            if (voipFP->sipRAPi >= SIPRFXMAX) {
                voipFP->stat |= SIP_OVRN;
                goto pktout;
            }

            //midx = memmem(mp, l, "c=IN IP", 7);
            midx = memmem(dP8, snapL7Len, "c=IN IP", 7);
            if (midx) {
                midx += 7;
                uint8_t ipver;
                if (*midx == '4') ipver = 4;
                else if (*midx == '6') ipver = 6;
                else goto pktout;
                uint8_t * const p = memchr(midx, '\r', snapL7Len-9);

                if (p) {
                    //const int lp = (int)(p - midx);
                    midx += 2;
                    *p = '\0';
                    ipAddr_t ip = {};
                    if (ipver == 4) inet_pton(AF_INET, (char*)midx, &ip.IPv4);
                    else if (ipver == 6) inet_pton(AF_INET6, (char*)midx, &ip.IPv6);
                    *p = '\r';

                    midx = memmem(dP8, snapL7Len, "m=audio", 7);
                    if (midx && voipFP->sipRAPi < SIPRFXMAX) {
                        voipFP->stat |= SIP_AUDFP;
                        const uint16_t prt = strtoul((char*)(midx+8), NULL, 0);

                        for (uint_fast32_t k = 0; k < voipFP->sipRAPi; k++) {
                            if (voipFP->sipRTPFAdd[k].addr.IPv6L[0] == ip.IPv6L[0] &&
                                voipFP->sipRTPFAdd[k].addr.IPv6L[1] == ip.IPv6L[1] &&
                                voipFP->sipRAFPrt[k] == prt)
                            {
                                goto proc_m_video;
                            }
                        }

                        voipFP->sipRTPFAdd[voipFP->sipRAPi].addr = ip;
                        voipFP->sipRTPFAdd[voipFP->sipRAPi].ver = ipver;
                        voipFP->sipRAFPrt[voipFP->sipRAPi++] = prt;
                        sipAPCnt++;
                    }

proc_m_video:
                    midx = memmem(p, snapL7Len-9, "m=video", 7);
                    if (midx && voipFP->sipRAPi < SIPRFXMAX) {
                        voipFP->stat |= SIP_VIDFP;
                        const uint16_t prt = strtoul((char*)(midx+8), NULL, 0);

                        for (uint_fast32_t k = 0; k < voipFP->sipRAPi; k++) {
                            if (voipFP->sipRTPFAdd[k].addr.IPv6L[0] == ip.IPv6L[0] &&
                                voipFP->sipRTPFAdd[k].addr.IPv6L[1] == ip.IPv6L[1] &&
                                voipFP->sipRVFPrt[k] == prt)
                            {
                                goto proc_rtpmap;
                            }
                        }

                        voipFP->sipRTPFAdd[voipFP->sipRAPi].addr = ip;
                        voipFP->sipRTPFAdd[voipFP->sipRAPi].ver = ipver;
                        voipFP->sipRVFPrt[voipFP->sipRAPi++] = prt;
                    }
                } // p

proc_rtpmap:
                midx = p;
                int sL7Len = snapL7Len - 9;
                while ((midx = memmem(midx, sL7Len, RTPMAP, sizeof(RTPMAP)-1)) && voipFP->sdpRTPMi < SIPRFXMAX) {
                    midx += sizeof(RTPMAP) - 1;
                    uint8_t *ec = memchr(midx, '\r', snapL7Len-9);
                    if (ec) {
                        const int lp = (int)(ec - midx);
                        for (uint_fast32_t k = 0; k < voipFP->sdpRTPMi; k++) {
                            if (!memcmp(midx, voipFP->sdpRTPM[k], lp)) goto pktout;
                        }

                        memcpy(voipFP->sdpRTPM[voipFP->sdpRTPMi], midx, lp);
                        voipFP->sdpRTPM[voipFP->sdpRTPMi++][lp+1] = '\0';
                    }
                }
            } // c=IN
        } // SDP

        goto pktout;
    }
#else // VOIP_SIP == 0
#if (VOIP_RTP == 1 || (VOIP_RTCP == 1 && VOIP_ANALEN == 1)) // could use #elif above, but would make things confusing
    dP16 = (uint16_t*)dP8;
#endif // (VOIP_RTP == 1 || (VOIP_RTCP == 1 && VOIP_ANALEN == 1))
#endif // VOIP_SIP > 0

#if VOIP_SIP > 0
test_rtp:
#endif // VOIP_SIP > 0

    if (UNLIKELY((dP8[0] & RTPVERMASK) != RTPVER)) { // version 2
        if (voipFP->pCnt++ > RTPMAXVERS) {
            voipFP->stat = 0x0000;
            voipStat = 0x0000;
        }
        VOIP_SPKTMD_PRI_NONE(voipStat);
        return;
    }

    voipFP->pktCnt++;

    if (typ > 199 && typ < 211) voipStat |= (RTCP | (voipRtcpHP->vpr & RTP_P));
    else voipStat |= (RTP | (typ & 0x80) | (voipRtcpHP->vpr & (RTP_X | RTP_P)));

#if VOIP_RTP == 1
    const uint32_t ssrc = ntohl(voipRtcpHP->id);
    if (voipStat & RTP) {
        rtpPktCnt++;

        // Parse SSRC
        uint32_t actSSRCi;
        for (actSSRCi = 0; actSSRCi < voipFP->sipSSRCi; actSSRCi++) {
            if (voipFP->ssN[actSSRCi] == ssrc) {
                voipFP->actSSRCi = actSSRCi;
                goto exssrc;
            }
        }

        if (voipFP->sipSSRCi <= RTPFMAX) {
            voipFP->ssN[voipFP->sipSSRCi++] = ssrc;
            if (!(voipStat & RTP_M)) voipStat |= RTP_ERRMD;
        } else {
            actSSRCi = RTPFMAX;
        }

exssrc: ;
        const int32_t i = ntohs(voipRtcpHP->len) - voipFP->rtpSeqN - 1;
        if (i < 0) voipStat |= RTP_SEQPJ;

        if (!i) {
            voipFP->rtpScnt++;
            voipStat &= ~RTP_ERRMD;
        } else if (voipFP->rtpScnt < VOIPMINRPKTD) {
            voipStat |= RTP_ERRMD;
        }

        voipFP->rtpSeqN = ntohs(dP16[1]);
        typ &= 0x7f;

        dP8 += 12;

        const uint32_t numcsrc = (voipRtcpHP->vpr & RTPCSICNT);
        for (uint32_t n = 0; n < numcsrc; n++) {
            const uint32_t csrc = ntohl(*(uint32_t*)dP8);
            for (int m = 0; m < voipFP->csrci; m++) {
                if (csrc == voipFP->csrc[m]) goto nxtcsrc;
            }

            if (voipFP->csrci < NUMCSRCMX) {
                voipFP->csrc[voipFP->csrci++] = ntohl(*(uint32_t*)dP8);
            } else {
                break;
            }

nxtcsrc:
            dP8 += 4; // advance to next CSRC info
        }

#if VOIP_SAVE == 1
        if (voipFP->rtpScnt > VOIP_MINPKT) {

            if (voipRtcpHP->vpr & RTP_X) {  // extended header
                dP8 += 4;                   // jmp over bede and len
                dP16 += 7;                  // get extended header length
                dP8 += (ntohs(*dP16) * 4);  // add extended header length to data pointer
            }

            uint8_t pad = 0;
            if ((voipRtcpHP->vpr & RTP_P) && packet->l7Len == snapL7Len) {  // pad bit
                pad = *(packet->end_packet - 1);
            }

            int32_t len = (packet->end_packet - dP8) - pad - VOIP_PLDOFF;
            if (len <= 0) goto pktout; // invalid RTP / padding

            voipStat |= RTP_WROP;

#if VOIP_SILREST == 1
            // ->ssrc is in fact ->tS if the correct voipRtpH_t struct was used
            const uint32_t ts = ntohl(voipRtcpHP->ssrc);
            if (voipRtcpHP->typ == (PT_PCMU | RTP_M) || voipRtcpHP->typ == (PT_PCMA | RTP_M)) {
                // Marker bit with G.711 codecs is typically used to indicate that silence
                // suppression occured => pad output with enough bytes to restore this silence.
                restore_silence(voipFP, flowP, voipRtcpHP->typ & ~RTP_M, ts);
            }
            voipFP->next_timestamp = ts + len;
#endif // VOIP_SILREST == 1

#if VOIP_BUFMODE == 1
            if (voipFP->rtpbufpos + len <= RTPBUFSIZE) {
                memcpy(voipFP->rtpbuf + voipFP->rtpbufpos, dP8 + VOIP_PLDOFF, len);
                voipFP->rtpbufpos += len;
            } else {
#endif // VOIP_BUFMODE == 1

#if VOIP_SVFDX == 1
                if (!voipFP->fd) open_new_chunk(voipFP, flowP);
                FILE * const fp = file_manager_fp(t2_file_manager, voipFP->fd);
#else // VOIP_SVFDX == 0
                if (!voipFP->fd[voipFP->actSSRCi]) open_new_chunk(voipFP, flowP);
                FILE * const fp = file_manager_fp(t2_file_manager, voipFP->fd[voipFP->actSSRCi]);
#endif // VOIP_SVFDX

                fseek(fp, 0, SEEK_END);

#if VOIP_BUFMODE == 1
                const size_t bufspace = RTPBUFSIZE - voipFP->rtpbufpos;
                const uint8_t *datapos = dP8 + VOIP_PLDOFF;
                if (bufspace > 0) {
                    memcpy(voipFP->rtpbuf + voipFP->rtpbufpos, datapos, bufspace);
                    datapos += bufspace;
                    len -= bufspace;
                }

                fwrite(voipFP->rtpbuf, RTPBUFSIZE, 1, fp);
                if (UNLIKELY(len > RTPBUFSIZE)) {
                    const size_t towrite = len - (len % RTPBUFSIZE);
                    fwrite(datapos, towrite, 1, fp);
                    datapos += towrite;
                    len -= towrite;
                }

                if (len > 0) {
                    memcpy(voipFP->rtpbuf, datapos, len);
                }
                voipFP->rtpbufpos = len;
#else  // VOIP_BUFMODE == 0
                fwrite(dP8 + VOIP_PLDOFF, len, 1, fp);
#endif // VOIP_BUFMODE == 1
#if VOIP_BUFMODE == 1
            }
#endif // VOIP_BUFMODE == 1
        }
#endif // VOIP_SAVE == 1

        type[0] = typ;
        rci = 1;
        goto pktout;
    } // voipStat & RTP
#endif // VOIP_RTP == 1

#if VOIP_RTCP == 1
    if (voipStat & RTCP) {

        if (voipFP->rtcpSsN != voipRtcpHP->ssrc) {
            if (voipFP->stat & RTCP) {
                voipFP->stat = voipStat = RTP_ERRMD;
                goto pktout;
            }
        }

        voipFP->rtcpSsN = voipRtcpHP->ssrc;
        rtcpPktCnt++;

#if VOIP_ANALEN == 1
        const uint_fast32_t dLen = packet->l7Len / 4;
        uint64_t i = ntohs(voipRtcpHP->len) + 1;
        while (i < dLen) {
            i += ntohs(*(dP16 + i*2 + 1)) + 1;
        }

        if (i > dLen) {
            voipFP->stat = voipStat = RTP_ERRMD;
            goto pktout;
        }
#endif // VOIP_ANALEN == 1

        int_fast32_t sl7Len = packet->snapL7Len;
        rci = 0;
        while (sl7Len > 11) {
            typ = voipRtcpHP->typ;
            const int_fast32_t rLen = 4 * (ntohs(voipRtcpHP->len) + 1);
            if (rLen > sl7Len) {
                //if (voipFP->sipTypCnt) voipFP->sipTypCnt--;
                voipStat |= RTP_ERRMD;
                break;
            }

            const int_fast32_t rCnt = voipRtcpHP->vpr & RTCPSSRCNT;

            //voipFP->rtcpSsN = voipRtcpHP->ssrc;

            switch (typ) {
                case 200: {
                    const voipRtcpSR_t * const vsrP = (voipRtcpSR_t*)(&voipRtcpHP->id);
                    voipFP->tPktCnt = ntohl(vsrP->tPktCnt);
                    voipFP->tbytCnt = ntohl(vsrP->tbytCnt);
                    if (!rCnt) break;
                    voipRtcpHP = (voipRtcpH_t*)(dP8 + sizeof(voipRtcpSR_t));
                }
                /* FALLTHRU */
                case 201: {
                    voipRtcpRR_t *vrrP = (voipRtcpRR_t*)(&voipRtcpHP->id);
                    for (int_fast32_t i = 0; i < rCnt; i++) {
                        voipFP->cumNpcktLst = ntohl(vrrP->cumNpcktLst) & 0x00ffffff;
                        voipFP->fracLst = ntohl(vrrP->cumNpcktLst) >> 24;
                        if (ntohl(vrrP->iatJit) > voipFP->iatJit) voipFP->iatJit = ntohl(vrrP->iatJit);
                        voipFP->rtpSeqN = ntohl(vrrP->ESeqNrec);
                        vrrP++;
                    }
                    break;
                }
                case 202: {
                    //const voipRtcpSDES_t * const vsdesP = (voipRtcpSDES_t*)(&voipRtcpHP->id);
                    break;
                }
                case 203: {
                    //const voipRtcpBYE_t * const vbyeP = (voipRtcpBYE_t*)(&voipRtcpHP->id);
                    break;
                }
                case 204:
                case 205:
                case 206:
                case 207:
                case 208:
                    break;
                default:
                    goto pktout;
            }

            if (rci < sizeof(type)) type[rci++] = typ;

            sl7Len -= rLen;
            if (sl7Len <= 0) break;

            voipRtcpHP = (voipRtcpH_t*)(dP8 + rLen);
        } // end while
    } // voipStat & RTCP
#endif // VOIP_RTCP == 1

pktout:;
    uint_fast32_t k;
    const uint_fast32_t m = voipFP->sipTypCnt;
    for (k = 0; k < m; k++) {
        if (type[0] == voipFP->typ[k]) break;
    }

    if (m == k && m < SIPSTATMAX) {
        voipFP->typ[m] = type[0];
        voipFP->sipTypCnt++;
    }

    if (sPktFile) {
        if (voipStat & RTPTCP) {
            fprintf(sPktFile, "0x%04" B2T_PRIX16 /* voipStat */ SEP_CHR, voipStat);
            /* voipType */
            if (rci > 0) {
                const uint32_t kmax = ((rci < sizeof(type)) ? (rci - 1) : sizeof(type));
                for (k = 0; k < kmax; k++) {
                    fprintf(sPktFile, "%" PRIu8 ";", type[k]);
                }

                if (rci < sizeof(type)) {
                    fprintf(sPktFile, "%" PRIu8, type[k]);
                } else {
                    fputs("...", sPktFile); // truncated...
                }
            }

            if (voipStat & RTP) {
                const uint32_t ts = ntohl(voipRtcpHP->ssrc);
                const uint32_t ssrc = ntohl(voipRtcpHP->id);
                fprintf(sPktFile,
                                           /* voipType   */ SEP_CHR
                        "%"     PRIu32     /* voipSeqN   */ SEP_CHR
                        "%"     PRIu32     /* voipTs     */ SEP_CHR
                        "%"     PRId32     /* voipTsDiff */ SEP_CHR
                        "0x%08" B2T_PRIX32 /* voipSSRC   */ SEP_CHR
                        , voipFP->rtpSeqN
                        , ts
                        , (int32_t)(ts - voipFP->tsLst)
                        , ssrc);
                voipFP->tsLst = ts;
            } else {
                fprintf(sPktFile,
                                           /* voipTyp    */ SEP_CHR
                                           /* voipSeqN   */ SEP_CHR
                                           /* voipTs     */ SEP_CHR
                                           /* voipTsDiff */ SEP_CHR
                        "0x%08" B2T_PRIX32 /* voipSSRC   */ SEP_CHR
                        , ntohl(voipFP->rtcpSsN));
            }
        } else { // !(voipStat & RTPTCP)
            VOIP_SPKTMD_PRI_NONE(voipStat);
        }
    } // sPktFile

    voipFP->stat |= voipStat;
}


void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {

    voipFlow_t * const voipFP = &voipFlows[flowIndex];

    if (voipFP->stat) {
        voipStat |= voipFP->stat;
        globalWarn |= L7_SIPRTP;
    }

#if VOIP_SIP > 0
    sipMethods |= voipFP->sipMethods;
#endif // VOIP_SIP > 0

#if VOIP_RTP == 1 && VOIP_SAVE == 1
#if VOIP_SVFDX == 1
#if VOIP_BUFMODE == 1
    // write what's left in buffer
    if (voipFP->rtpbufpos > 0 && (voipFP->stat & RTP_WROP)) {
        if (!voipFP->fd) {
            const flow_t * const flowP = &flows[flowIndex];
            open_new_chunk(voipFP, flowP);
        }
        FILE * const fp = file_manager_fp(t2_file_manager, voipFP->fd);
        fwrite(voipFP->rtpbuf, voipFP->rtpbufpos, 1, fp);
        voipFP->rtpbufpos = 0;
#else // VOIP_BUFMODE == 0
    if (voipFP->fd) {
#endif // VOIP_BUFMODE
        file_manager_close(t2_file_manager, voipFP->fd);
        voipFP->fd = NULL;
        voipFdCnt--;
        if (!(voipFP->stat & RTP_WROP)) remove(voipFP->vname);
    }
#else // VOIP_SVFDX == 0
    for (uint32_t i = 0; i < voipFP->sipSSRCi; i++) {
        file_manager_close(t2_file_manager, voipFP->fd[i]);
        voipFP->fd[i] = NULL;
        voipFdCnt--;
    }
#endif // VOIP_SVFDX
#endif // VOIP_SAVE == 1 && VOIP_RTP == 1

#if VOIP_SIP > 1
    const flow_t * const flowP = &flows[flowIndex];
    if ((voipFP->stat & SIP) && voipFP->sipRAPi) {
        for (uint_fast32_t k = 0; k < voipFP->sipRAPi; k++) {
            ipPrt_t ipPrt = {
                .addr = voipFP->sipRTPFAdd[k].addr,
                .port = voipFP->sipRAFPrt[k]
            };
            unsigned long vpIndex = hashTable_lookup(voipHashMap, (char*)&ipPrt); // check only audio ports for now
            if (vpIndex != HASHTABLE_ENTRY_NOT_FOUND) {
#if VOIP_SIP_PRV > 1
chkhsh:
#endif // VOIP_SIP_PRV > 1
                sipFdxMtch++;
                const uint32_t vSSRC = voipSSRC[vpIndex];
                uint32_t n;
                for (n = 0; n < voipFP->sipSSRCi; n++) {
                    if (voipFP->ssN[n] == vSSRC) break;
                }

                if (n == voipFP->sipSSRCi && voipFP->sipSSRCi < SIPRFXMAX) {
                    voipFP->ssN[voipFP->sipSSRCi++] = vSSRC;
                }

                const uint64_t vfindx = voipFindex[vpIndex];
                for (n = 0; n < voipFP->sipFdxi; n++) {
                    if (voipFP->findex[n] == vfindx) break;
                }

                if (n == voipFP->sipFdxi && voipFP->sipFdxi < SIPRFXMAX) {
                    voipFP->findex[voipFP->sipFdxi++] = vfindx;
                }

                hashTable_remove(voipHashMap, (char*)&ipPrt);
            }
#if VOIP_SIP_PRV > 1
            else { // in case of private address, lets try the srcPrt of the sip
                ipPrt.addr = flows[flowIndex].srcIP;
                vpIndex = hashTable_lookup(voipHashMap, (char*)&ipPrt); // check only audio ports for now
                if (vpIndex != HASHTABLE_ENTRY_NOT_FOUND) goto chkhsh;
            }
#endif // VOIP_SIP_PRV > 1
        }
    }
#endif // VOIP_SIP > 1

#if VOIP_RTP == 1
    uint32_t pmCnt = 0;
    float f = 0.0f;
#endif // VOIP_RTP == 1

    if (!(voipFP->stat & RTPTCP)) {
        voipFP->sipTypCnt = 0;
        voipFP->rCnt = 0;

#if VOIP_RTCP == 1
        voipFP->tPktCnt = 0;
        voipFP->tbytCnt = 0;
        voipFP->cumNpcktLst = 0;
        voipFP->iatJit = 0;
#endif // VOIP_RTCP == 1

#if VOIP_SAVE == 1
        voipFP->vname[0] = '\0';
#endif // VOIP_SAVE == 1

#if VOIP_SIP > 1
        ipPrt_t ipPrt = {
            //.ver = ipver,
            .addr = flowP->dstIP,
            .port = flowP->dstPort
        };

        unsigned long vpIndex = hashTable_lookup(voipHashMap, (char*)&ipPrt);
        if (vpIndex != HASHTABLE_ENTRY_NOT_FOUND) hashTable_remove(voipHashMap, (char*)&ipPrt);
#endif // VOIP_SIP > 1
    } else if (voipFP->pktCnt < VOIPMINRPKTD) {
        memset(voipFP, '\0', sizeof(*voipFP));
        voipFP->stat = RTP_ERRMD;
#if VOIP_RTP == 1
    } else if (voipFP->stat & RTP) {
        pmCnt = voipFP->pktCnt - voipFP->rtpScnt;
        f = (float)pmCnt / voipFP->pktCnt;
        if (voipFP->pktCnt > voipFP->rtpScnt) voipFP->stat |= RTP_PKTLSS;
        //voipFP->sipSSRCi = 1;
        //voipFP->ssN[0] = ntohl(voipFP->ssN[0]);
#endif
#if VOIP_RTCP == 1
    } else if (voipFP->stat & RTCP) {
        voipFP->sipSSRCi = 1;
        voipFP->ssN[0] = ntohl(voipFP->rtcpSsN);
#endif // VOIP_RTCP == 1
    }

    OUTBUF_APPEND_U16(buf, voipFP->stat);                                   // voipStat

#if VOIP_RTP == 1 || VOIP_RTCP == 1
    OUTBUF_APPEND_ARRAY_U8(buf, voipFP->typ, voipFP->sipTypCnt);            // voipType
    OUTBUF_APPEND_ARRAY_U32(buf, voipFP->ssN, voipFP->sipSSRCi);            // voipSSRC
    OUTBUF_APPEND_ARRAY_U32(buf, voipFP->csrc, voipFP->csrci);              // voipCSRC
    OUTBUF_APPEND_U8(buf , voipFP->rCnt);                                   // voipSRCnt
#endif // VOIP_RTP == 1 || VOIP_RTCP == 1

#if VOIP_RTP == 1
    OUTBUF_APPEND_U32(buf, pmCnt);                                          // rtpPMCnt
    OUTBUF_APPEND_FLT(buf, f);                                              // rtpPMr
#endif // VOIP_RTP == 1

#if VOIP_SIP > 0
    OUTBUF_APPEND_U16(buf, voipFP->sipMethods);                             // sipMethods
    OUTBUF_APPEND_U8(buf , voipFP->sipStatCnt);                             // sipStatCnt
    OUTBUF_APPEND_U8(buf , voipFP->sipRqCnt);                               // sipReqCnt
    OUTBUF_APPEND_STR(buf, voipFP->usrAgnt);                                // sipUsrAgnt
    OUTBUF_APPEND_STR(buf, voipFP->realIP);                                 // sipRealIP
    OUTBUF_APPEND_ARRAY_STR(buf, voipFP->sipFrm, voipFP->sipFrmi);          // sipFrom
    OUTBUF_APPEND_ARRAY_STR(buf, voipFP->sipTo, voipFP->sipToi);            // sipTo
    OUTBUF_APPEND_ARRAY_STR(buf, voipFP->sipCID, voipFP->sipCIDi);          // sipCallID
    OUTBUF_APPEND_ARRAY_STR(buf, voipFP->sipContact, voipFP->sipContacti);  // sipContact
    OUTBUF_APPEND_ARRAY_U16(buf, voipFP->sipStat, voipFP->sipStatCnt);      // sipStat
    OUTBUF_APPEND_ARRAY_STR(buf, voipFP->sipRq, voipFP->sipRqCnt);          // sipReq

    // SDP
    OUTBUF_APPEND_ARRAY_STR(buf, voipFP->sdpSessId, voipFP->sdpSessIdi);    // sdpSessID

    // sdpRFAdd
    //OUTBUF_APPEND_ARRAY_IP4(buf, voipFP->sipRTPFAdd, voipFP->sipRAPi);      // sdpRFAdd
    const uint32_t srapi = voipFP->sipRAPi;
    OUTBUF_APPEND_NUMREP(buf, srapi);
    for (uint_fast32_t i = 0; i < srapi; i++) {
#if IPV6_ACTIVATE == 2
        OUTBUF_APPEND_IPVX(buf, voipFP->sipRTPFAdd[i].ver, voipFP->sipRTPFAdd[i].addr);
#elif IPV6_ACTIVATE == 1
        OUTBUF_APPEND_IP6(buf, voipFP->sipRTPFAdd[i].addr);
#else // IPV6_ACTIVATE == 0
        OUTBUF_APPEND_IP4(buf, voipFP->sipRTPFAdd[i].addr);
#endif // IPV6_ACTIVATE == 0
    }

    OUTBUF_APPEND_ARRAY_U16(buf, voipFP->sipRAFPrt, voipFP->sipRAPi);      // sdpRAFPrt
    OUTBUF_APPEND_ARRAY_U16(buf, voipFP->sipRVFPrt, voipFP->sipRAPi);      // sdpRVFPrt
    OUTBUF_APPEND_ARRAY_STR(buf, voipFP->sdpRTPM, voipFP->sdpRTPMi);       // sdpRTPMap

#if VOIP_SIP > 1
    OUTBUF_APPEND_ARRAY_U64(buf, voipFP->findex, voipFP->sipFdxi);         // voipFindex
#endif // VOIP_SIP > 1
#endif // VOIP_SIP > 0

#if VOIP_RTCP == 1
    OUTBUF_APPEND_U32(buf, voipFP->tPktCnt);      // rtcpTPCnt
    OUTBUF_APPEND_U32(buf, voipFP->tbytCnt);      // rtcpTBCnt
    OUTBUF_APPEND_U8(buf , voipFP->fracLst);      // rtcpFracLst
    OUTBUF_APPEND_U32(buf, voipFP->cumNpcktLst);  // rtcpCPMCnt
    OUTBUF_APPEND_U32(buf, voipFP->iatJit);       // rtcpMaxIAT
#endif // VOIP_RTCP == 1

#if VOIP_SAVE == 1
    OUTBUF_APPEND_STR(buf, voipFP->vname);        // voipFname
#endif // VOIP_SAVE == 1
}


static inline void voip_pluginReport(FILE *stream) {
    if (voipStat) {
        T2_FPLOG_AGGR_HEX0(stream, plugin_name, voipStat);

#if VOIP_SIP > 0
        T2_FPLOG_AGGR_HEX(stream, plugin_name, sipMethods);
        T2_FPLOG_NUMP(stream, plugin_name, "Number of SIP packets", sipPktCnt, numPackets);
        const double sipPktDiff = sipPktCnt - sipPktCnt0;
        for (uint_fast32_t i = 0; sip_methods[i].s_name; i++) {
            const uint64_t methDiff = sipMethPkts[i] - sipMethPkts0[i];
            if (methDiff > 0) {
                char hrnum[64];
                T2_CONV_NUM(methDiff, hrnum);
                T2_FPLOG(stream, plugin_name, "Number of SIP %s packets: %" PRIu64 "%s [%.2f%%]",
                        sip_methods[i].l_name, methDiff, hrnum, 100.0 * (methDiff / sipPktDiff));
            }
        }
        T2_FPLOG_NUMP(stream, plugin_name, "Number of SDP packets", sdpPktCnt, numPackets);
        T2_FPLOG_NUMP(stream, plugin_name, "Number of unique SDP audio address, port", sipAPCnt, sdpPktCnt);
        T2_FPLOG_NUM(stream, plugin_name, "Number of unique SIP/RTP flow matches", sipFdxMtch);
#endif // VOIP_SIP > 0

#if VOIP_RTP == 1
        T2_FPLOG_NUMP(stream, plugin_name, "Number of RTP packets", rtpPktCnt, numPackets);
#endif // VOIP_RTP == 1

#if VOIP_RTCP == 1
        T2_FPLOG_NUMP(stream, plugin_name, "Number of RTCP packets", rtcpPktCnt, numPackets);
#endif // VOIP_RTCP == 1

#if VOIP_SAVE == 1
        T2_FPLOG_NUM(stream, plugin_name, "Max number of file handles", voipFdCntMax);
#endif // VOIP_SAVE == 1
    }
}


void t2PluginReport(FILE *stream) {
#if DIFF_REPORT == 1
#if VOIP_SAVE == 1
    voipFdCntMax0 = 0;
#endif // VOIP_SAVE == 1
#if VOIP_SIP > 0
    sipPktCnt0 = 0;
    sdpPktCnt0 = 0;
    sipAPCnt0 = 0;
    sipFdxMtch0 = 0;
    for (uint_fast32_t i = 0; sip_methods[i].s_name; i++) {
        sipMethPkts[i] = 0;
    }
#endif // VOIP_SIP > 0
#if VOIP_RTP == 1
    rtpPktCnt0 = 0;
#endif // VOIP_RTP == 1
#if VOIP_RTCP == 1
    rtcpPktCnt0 = 0;
#endif // VOIP_RTCP == 1
#endif // DIFF_REPORT == 1

    voip_pluginReport(stream);
}


void t2Monitoring(FILE *stream, uint8_t state) {

    switch (state) {

#if (VOIP_SAVE == 1 || VOIP_SIP > 0 || VOIP_RTP == 1 || VOIP_RTCP == 1)

        case T2_MON_PRI_HDR:
#if VOIP_SAVE == 1
            fputs("voipFHndl" SEP_CHR, stream);
#endif // VOIP_SAVE == 1

#if VOIP_SIP > 0
            fputs("sipPkts" SEP_CHR, stream);

            for (uint_fast32_t i = 0; sip_methods[i].s_name; i++) {
                fprintf(stream, "%s" SEP_CHR, sip_methods[i].m_name);
            }

            fputs("sdpPkts"    SEP_CHR
                  "sipAPCnt"   SEP_CHR
                  "sipFdxMtch" SEP_CHR
                  , stream);
#endif // VOIP_SIP > 0

#if VOIP_RTP == 1
            fputs("rtpPkts" SEP_CHR, stream);
#endif // VOIP_RTP == 1

#if VOIP_RTCP == 1
            fputs("rtcpPkts" SEP_CHR, stream);
#endif // VOIP_RTCP == 1
            return;

        case T2_MON_PRI_VAL:
#if VOIP_SAVE == 1
            fprintf(stream, "%" PRId32 /* voipFHndl */ SEP_CHR, voipFdCntMax - voipFdCntMax0);
#endif // VOIP_SAVE == 1

#if VOIP_SIP > 0
            fprintf(stream, "%" PRIu64 /* sipPkts */ SEP_CHR, sipPktCnt - sipPktCnt0);

            for (uint_fast32_t i = 0; sip_methods[i].s_name; i++) {
                fprintf(stream, "%" PRIu64 /* sipMethPkts[i] */ SEP_CHR, sipMethPkts[i] - sipMethPkts0[i]);
            }

            fprintf(stream,
                    "%" PRIu64 /* sdpPkts    */ SEP_CHR
                    "%" PRIu64 /* sipAPCnt   */ SEP_CHR
                    "%" PRIu64 /* sipFdxMtch */ SEP_CHR
                    , sdpPktCnt - sdpPktCnt0
                    , sipAPCnt - sipAPCnt0
                    , sipFdxMtch - sipFdxMtch0);
#endif // VOIP_SIP > 0

#if VOIP_RTP == 1
            fprintf(stream, "%" PRIu64 /* rtpPkts  */ SEP_CHR, rtpPktCnt - rtpPktCnt0);
#endif // VOIP_RTP == 1

#if VOIP_RTCP == 1
            fprintf(stream, "%" PRIu64 /* rtcpPkts */ SEP_CHR, rtcpPktCnt - rtcpPktCnt0);
#endif // VOIP_RTCP == 1
            break;

#endif // (VOIP_SAVE == 1 || VOIP_SIP > 0 || VOIP_RTP == 1 || VOIP_RTCP == 1)

        case T2_MON_PRI_REPORT:
            voip_pluginReport(stream);
            break;

        // Invalid state, do nothing
        default:
            return;
    }

#if DIFF_REPORT == 1

#if VOIP_SAVE == 1
    voipFdCntMax0 = voipFdCntMax;
#endif // VOIP_SAVE == 1

#if VOIP_SIP > 0
    sipPktCnt0 = sipPktCnt;
    sdpPktCnt0 = sdpPktCnt;
    sipAPCnt0 = sipAPCnt;
    sipFdxMtch0 = sipFdxMtch;
    for (uint_fast32_t i = 0; sip_methods[i].s_name; i++) {
        sipMethPkts0[i] = sipMethPkts[i];
    }
#endif // VOIP_SIP > 0

#if VOIP_RTP == 1
    rtpPktCnt0 = rtpPktCnt;
#endif // VOIP_RTP == 1

#if VOIP_RTCP == 1
    rtcpPktCnt0 = rtcpPktCnt;
#endif // VOIP_RTCP == 1

#endif // DIFF_REPORT == 1
}


void t2Finalize() {
#if VOIP_SAVE == 1 && ENVCNTRL > 0
    t2_free_env(ENV_VOIP_N, env);
#endif // VOIP_SAVE == 1 && ENVCNTRL > 0

#if VOIP_SIP > 1
    hashTable_destroy(voipHashMap);
    free(voipFindex);
    free(voipSSRC);
#endif // VOIP_SIP > 1

    free(voipFlows);
}
