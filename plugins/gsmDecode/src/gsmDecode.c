/*
 * gsmDecode.c
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

#include "gsmDecode.h"

#include "gsm_a_dtap.h"   // for dissect_gsm_a_dtap
#include "gsm_amr.h"      // for rtp_amr_convert_and_write, is_rtp_amr_speech
#include "gsm_lapd.h"     // for dissect_lapd
#include "gsm_osmocore.h" // for rsl_msg_name, AMR_SID
#include "gsm_rsl.h"      // for dissect_gsm_abis_rsl
#include "gsm_utils.h"    // for channel_to_str
#include "gsmtap.h"       // for dissect_gsmtap
#include "mcc_list.h"     // for mcc_to_str, mnc_to_str
#include "tac_list.h"     // for gsm_tac_list_t, gsm_tac_list_load, ...

#include <errno.h>        // for errno, strerror
//#include <osmocom/gsm/gsm48.h>              // for gsm48_cc_cause_name, gsm48_rr_msg_name
//#include <osmocom/gsm/gsm_utils.h>          // for gsm_7bit_decode_n_hdr
//#include <osmocom/gsm/rsl.h>                // for rsl_err_name


#define GSM_FREOPEN(file_object, key, file, filename) { \
    if (file_object) close_and_rename_file(&(file_object), T2_ENV_VAL(GSM_FILES_TXT_EXT)); \
    build_txt_filename(filename, sizeof(filename), env[key].val, now); \
    file_object = file_manager_open(t2_file_manager, filename, "w"); \
    if (UNLIKELY(!file_object)) exit(EXIT_FAILURE); \
    file = file_manager_fp(t2_file_manager, file_object); \
}


// Global variables

gsmFlow_t *gsmFlows;

gsm_tac_list_t tac_list;

uint64_t numGSMTAP;
uint64_t numGSMDTAP;
uint64_t numGSMDTAPCC;
uint64_t numGSMDTAPMM;
uint64_t numGSMDTAPRR;
uint64_t numGSMDTAPSMS;
uint64_t numGSMDTAPSS;
uint64_t numGSMDTAPUnk;
uint64_t numGSMRSL;
uint64_t numGSMRSLRLM;
uint64_t numGSMRSLDCM;
uint64_t numGSMRSLCCM;
uint64_t numGSMRSLTRX;
uint64_t numGSMRSLLS;
uint64_t numGSMRSLIPA;
uint64_t numGSMRSLHUA;
uint64_t numGSMRSLUnk;
uint64_t numRsl[128];
uint64_t numGSMSMSMsg;
uint64_t numGSMSMSTPDU;
uint64_t numDtapCC[255];
uint64_t numDtapMM[255];
uint64_t numDtapRR[255];
#if GSM_SPEECHFILE == 1
uint64_t numAMRFrames[2];
uint64_t numAMRFiles;
uint64_t numAMR[AMR_SID+1][2];
#endif // GSM_SPEECHFILE == 1

#if GSM_ARFCNFILE == 1
file_object_t *arfcnFile;
#endif
#if GSM_CALLFILE == 1
file_object_t *callFile;
#endif
#if GSM_CDFILE == 1
file_object_t *cdFile;
#endif
#if GSM_IMMASSFILE == 1
file_object_t *immAssFile;
#endif
#if GSM_IMSIFILE == 1
file_object_t *imsiFile;
#endif
#if GSM_OPFILE == 1
file_object_t *opFile;
#endif
#if GSM_SMSFILE == 1
file_object_t *smsFile;
#endif


/*
 * Static variables
 */

static uint32_t gsmStat;

static t2_env_t env[ENV_GSM_N];
#if ENVCNTRL > 0
static uint32_t gsmRotateTime;
#else // ENVCNTRL == 0
static const uint32_t gsmRotateTime = GSM_ROTATE_TIME;
#endif // ENVCNTRL


/*
 * Function prototypes
 */

static inline void dissect_gsm(packet_t *packet, const flow_t * const flowP, unsigned long flowIndex)
    __attribute__((__nonnull__(1,2)));


#define GSM_SPKT_MD_PRI_NONE() \
    if (sPktFile) { \
        fputs("0x00000000" /* gsmStat           */ SEP_CHR \
                           /* gsmLapdSAPI       */ SEP_CHR \
                           /* gsmLapdTEI        */ SEP_CHR \
                           /* gsmRslMsgType     */ SEP_CHR \
                           /* gsmRslTN          */ SEP_CHR \
                           /* gsmRslSubCh       */ SEP_CHR \
                           /* gsmRslChannel     */ SEP_CHR \
                           /* gsmDtapTN         */ SEP_CHR \
                           /* gsmDtapChannel    */ SEP_CHR \
                           /* gsmHandoverRef    */ SEP_CHR \
                           /* gsmLAIMCC         */ SEP_CHR \
                           /* gsmLAIMCCCountry  */ SEP_CHR \
                           /* gsmLAIMNC         */ SEP_CHR \
                           /* gsmLAIMNCOperator */ SEP_CHR \
                           /* gsmLAILAC         */ SEP_CHR \
                           /* gsmEncryption     */ SEP_CHR \
                           /* gsmContent        */ SEP_CHR \
              , sPktFile); \
        if (GSM_SPEECHFILE == 1) { \
            fputs(/* gsmAMRCMR       */ SEP_CHR \
                  /* gsmAMRFrameType */ SEP_CHR \
                  /* gsmAMRFrameQ    */ SEP_CHR \
                  , sPktFile); \
        } \
    }


// Tranalyzer functions

T2_PLUGIN_INIT("gsmDecode", "0.9.3", 0, 9);


void t2Init() {
    T2_PLUGIN_STRUCT_NEW(gsmFlows);

#if ENVCNTRL > 0
    t2_get_env(PLUGIN_SRCH, ENV_GSM_N, env);
    const uint8_t rmdir = T2_ENV_VAL_UINT(GSM_RMDIR);
    gsmRotateTime = T2_ENV_VAL_UINT(GSM_ROTATE_TIME);
#else // ENVCNTRL == 0
    const uint8_t rmdir = GSM_RMDIR;
    T2_SET_ENV_STR(GSM_SPEECH_DIR);
    T2_SET_ENV_STR(GSM_TXT_DIR);
    T2_SET_ENV_STR(GSM_ARFCNFILE_SUFFIX);
    T2_SET_ENV_STR(GSM_CALLFILE_SUFFIX);
    T2_SET_ENV_STR(GSM_CALLFILE_SUFFIX);
    T2_SET_ENV_STR(GSM_IMMASSFILE_SUFFIX);
    T2_SET_ENV_STR(GSM_IMSIFILE_SUFFIX);
    T2_SET_ENV_STR(GSM_OPFILE_SUFFIX);
    T2_SET_ENV_STR(GSM_SMSFILE_SUFFIX);
    T2_SET_ENV_STR(GSM_STATFILE_SUFFIX);
    T2_SET_ENV_STR(GSM_FILES_AMR_EXT);
    T2_SET_ENV_STR(GSM_FILES_TMP_EXT);
    T2_SET_ENV_STR(GSM_FILES_TXT_EXT);
#endif // ENVCNTRL

#if GSM_SPEECHFILE == 1
    T2_MKPATH(T2_ENV_VAL(GSM_SPEECH_DIR), rmdir);
#endif // GSM_SPEECHFILE == 1

    T2_MKPATH(T2_ENV_VAL(GSM_TXT_DIR), rmdir);

#if GSM_IMSIFILE == 1
    tac_list = gsm_tac_list_load(pluginFolder, GSM_TAC_LIST);
#if VERBOSE > 0
    T2_PINF(plugin_name, "%" PRIu32 " TAC records loaded", tac_list.size);
#endif // VERBOSE > 0
#endif // GSM_IMSIFILE

    // Packet mode
    if (sPktFile) {
        fputs("gsmStat"           SEP_CHR
              "gsmLapdSAPI"       SEP_CHR
              "gsmLapdTEI"        SEP_CHR
              "gsmRslMsgType"     SEP_CHR
              "gsmRslTN"          SEP_CHR
              "gsmRslSubCh"       SEP_CHR
              "gsmRslChannel"     SEP_CHR
              "gsmDtapTN"         SEP_CHR
              "gsmDtapChannel"    SEP_CHR
              "gsmHandoverRef"    SEP_CHR
              "gsmLAIMCC"         SEP_CHR
              "gsmLAIMCCCountry"  SEP_CHR
              "gsmLAIMNC"         SEP_CHR
              "gsmLAIMNCOperator" SEP_CHR
              "gsmLAILAC"         SEP_CHR
              "gsmEncryption"     SEP_CHR
              "gsmContent"        SEP_CHR
#if GSM_SPEECHFILE == 1
              "gsmAMRCMR"         SEP_CHR
              "gsmAMRFrameType"   SEP_CHR
              "gsmAMRFrameQ"      SEP_CHR
#endif // GSM_SPEECHFILE == 1
              , sPktFile);
    }
}


#if GSM_SPEECHFILE == 1
static inline void build_amr_filename(char *dest, size_t dest_len, const flow_t * const flowP) {
#if GSM_SPEECH_SPLIT == 1
    const char * const dir = "";
#else // GSM_SPEECH_SPLIT == 1
    const char * const dir = ((flowP->status & L3FLOWINVERT) ? "_B" : "_A");
#endif // GSM_SPEECH_SPLIT == 1
    char sip[INET6_ADDRSTRLEN];
    char dip[INET6_ADDRSTRLEN];
    const uint_fast8_t version = FLOW_IPVER(flowP);
    T2_IP_TO_STR(flowP->srcIP, version, sip, sizeof(sip));
    T2_IP_TO_STR(flowP->dstIP, version, dip, sizeof(dip));
    const uint_fast8_t proto = flowP->l4Proto;
    char protostr[5] = {};
    switch (proto) {
        case L3_UDP : memcpy(protostr, "UDP" , 3); break;
        case L3_SCTP: memcpy(protostr, "SCTP", 4); break;
        case L3_TCP : memcpy(protostr, "TCP" , 3); break;
        default: snprintf(protostr, sizeof(protostr), "%" PRIuFAST8, proto); break;
    }
    const time_t sec = flowP->firstSeen.tv_sec;
    const intmax_t usec = flowP->firstSeen.tv_usec;
    const size_t len = snprintf(dest, dest_len,
                                "%s/%" PRIu64 "%s_%ld.%06jd_vlan%" PRIu16 "_%s_%" PRIu16 "_%s_%" PRIu16 "_%s%s"
                                , T2_ENV_VAL(GSM_SPEECH_DIR)
                                , flowP->findex
                                , dir
                                , sec, usec
                                , flowP->vlanId
                                , sip, flowP->srcPort
                                , dip, flowP->dstPort
                                , protostr
                                , T2_ENV_VAL(GSM_FILES_TMP_EXT));
}
#endif // GSM_SPEECHFILE == 1


#ifdef GSM_SAVE_FILES
static inline void build_txt_filename(char *dest, size_t dest_len, const char * const suffix, time_t now) {
    char *prefix = strrchr(baseFileName, '/');
    if (!prefix) prefix = baseFileName;
    size_t pos = t2_build_filename(dest, dest_len, T2_ENV_VAL(GSM_TXT_DIR), prefix, NULL);
    pos += t2_strcat(dest + pos, dest_len - pos, suffix, NULL);
    if (gsmRotateTime > 0) {
        pos += snprintf(dest + pos, dest_len - pos, "_%06jd", now);
    }
    t2_strcat(dest + pos, dest_len - pos, T2_ENV_VAL(GSM_FILES_TMP_EXT), NULL);
}
#endif // GSM_SAVE_FILES


#if defined(GSM_SAVE_FILES) || GSM_SPEECHFILE == 1
static inline void close_and_rename_file(file_object_t **object, const char * const ext) {
    if (!*object) return;
    const char * const tmpExt = T2_ENV_VAL(GSM_FILES_TMP_EXT);
    const char * const tmpName = file_object_get_path(*object);
    const size_t tmpLen = strlen(tmpName);
    const size_t extPos = tmpLen - strlen(tmpExt);
    char oldName[tmpLen+1];
    memcpy(oldName, tmpName, tmpLen+1);
    char newName[tmpLen+1];
    memcpy(newName, tmpName, extPos),
    memcpy(newName + extPos, ext, strlen(ext)+1);
    file_manager_close(t2_file_manager, *object);
    *object = NULL;
    // rename the file
    if (UNLIKELY(rename(oldName, newName) != 0)) {
        T2_PERR(plugin_name, "Failed to rename '%s' to '%s': %s", oldName, newName, strerror(errno));
    }
}
#endif // defined(GSM_SAVE_FILES) || GSM_SPEECHFILE == 1


#ifdef GSM_SAVE_FILES
static inline void open_output_files(time_t now) {
    static bool initialized = false;
    static time_t last;
    if (UNLIKELY(!initialized)) {
        initialized = true;
        last = now;
    } else if (gsmRotateTime == 0) {
        return;
    } else {
        if ((now - last) < gsmRotateTime) return;
        last = now;
    }

    FILE *file;
    char filename[MAX_FILENAME_LEN] = {};

#if GSM_ARFCNFILE == 1
    GSM_FREOPEN(arfcnFile, ENV_GSM_ARFCNFILE_SUFFIX, file, filename);
    fprintf(file,
            "%s "            /* HDR_CHR */
            "pktNo"          SEP_CHR
            "flowInd"        SEP_CHR
            "time"           SEP_CHR
            "vlanID"         SEP_CHR
            "lapdTEI"        SEP_CHR
            "gsmRslTN"       SEP_CHR
            "gsmRslSubCh"    SEP_CHR
            "gsmRslChannel"  SEP_CHR
            "gsmDtapTN"      SEP_CHR
            "gsmDtapChannel" SEP_CHR
            "gsmARFCN"       SEP_CHR
            "gsmBand"        SEP_CHR
            "gsmUpFreqMHz"   SEP_CHR
            "gsmDownFreqMHz" "\n"
            , HDR_CHR);
#endif // GSM_ARFCNFILE == 1

#if GSM_CALLFILE == 1
    GSM_FREOPEN(callFile, ENV_GSM_CALLFILE_SUFFIX, file, filename);
    fprintf(file,
            "%s "              /* HDR_CHR */
            "pktNo"            SEP_CHR
            "flowInd"          SEP_CHR
            "time"             SEP_CHR
            "vlanID"           SEP_CHR
            "lapdTEI"          SEP_CHR
            "gsmMsgType"       SEP_CHR
            "gsmCause"         SEP_CHR
            "gsmRslTN"         SEP_CHR
            "gsmRslSubCh"      SEP_CHR
            "gsmRslChannel"    SEP_CHR
            "gsmCaller"        SEP_CHR
            "gsmCallerCountry" SEP_CHR
            "gsmCallee"        SEP_CHR
            "gsmCalleeCountry" "\n"
            , HDR_CHR);
#endif // GSM_CALLFILE == 1

#if GSM_CDFILE == 1
    GSM_FREOPEN(cdFile, ENV_GSM_CDFILE_SUFFIX, file, filename);
    fprintf(file,
            "%s "              /* HDR_CHR */
            "pktNo"            SEP_CHR
            "flowInd"          SEP_CHR
            "time"             SEP_CHR
            "vlanID"           SEP_CHR
            "lapdTEI"          SEP_CHR
            "gsmMsgType"       SEP_CHR
            "gsmCause"         SEP_CHR
            "gsmRslTN"         SEP_CHR
            "gsmRslSubCh"      SEP_CHR
            "gsmRslChannel"    SEP_CHR
            "gsmChannelType"   SEP_CHR
            "gsmHandoverRef"   SEP_CHR
            "gsmFrameNumberT1" SEP_CHR
            "gsmFrameNumberT2" SEP_CHR
            "gsmFrameNumberT3" SEP_CHR
            "gsmFrameNumber"   SEP_CHR
            "gsmChannelInfo"   "\n"
            , HDR_CHR);
#endif // GSM_CDFILE == 1

#if GSM_IMMASSFILE == 1
    GSM_FREOPEN(immAssFile, ENV_GSM_IMMASSFILE_SUFFIX, file, filename);
    fprintf(file,
            "%s "                 /* HDR_CHR */
            "pktNo"               SEP_CHR
            "flowInd"             SEP_CHR
            "time"                SEP_CHR
            "vlanID"              SEP_CHR
            "lapdTEI"             SEP_CHR
            "gsmMsgType"          SEP_CHR
            "gsmCause"            SEP_CHR
            "gsmRslTN"            SEP_CHR
            "gsmRslSubCh"         SEP_CHR
            "gsmRslChannel"       SEP_CHR
            "gsmDtapTN"           SEP_CHR
            "gsmDtapChannel"      SEP_CHR
            "gsmTSC"              SEP_CHR
            "gsmHoppingChannel"   SEP_CHR
            "gsmARFCN"            SEP_CHR
            "gsmBand"             SEP_CHR
            "gsmUpFreqMHz"        SEP_CHR
            "gsmDownFreqMHz"      SEP_CHR
            "gsmMAIO"             SEP_CHR
            "gsmHoppingSeqNum"    SEP_CHR
            "gsmRandomAccessInfo" SEP_CHR
            "gsmRequestRefT1"     SEP_CHR
            "gsmRequestRefT2"     SEP_CHR
            "gsmRequestRefT3"     SEP_CHR
            "gsmRequestRefRFN"    SEP_CHR
            "gsmTimingAdvance"    SEP_CHR
            "gsmDistanceFromBTS"  SEP_CHR
            "gsmChannelMode"      SEP_CHR
            "gsmMultiRateConfig"  "\n"
            , HDR_CHR);
#endif // GSM_IMMASSFILE == 1

#if GSM_IMSIFILE == 1
    GSM_FREOPEN(imsiFile, ENV_GSM_IMSIFILE_SUFFIX, file, filename);
    fprintf(file,
            "%s "                   /* HDR_CHR */
            "pktNo"                 SEP_CHR
            "flowInd"               SEP_CHR
            "time"                  SEP_CHR
            "vlanID"                SEP_CHR
            "lapdTEI"               SEP_CHR
            "gsmRslTN"              SEP_CHR
            "gsmRslSubCh"           SEP_CHR
            "gsmRslChannel"         SEP_CHR
            "gsmMobileIdentityType" SEP_CHR
            "gsmIMSI"               SEP_CHR
            "gsmIMEITACManuf"       SEP_CHR
            "gsmIMEITACModel"       SEP_CHR
            "gsmIMSIMCC"            SEP_CHR
            "gsmIMSIMCCCountry"     SEP_CHR
            "gsmIMSIMNC"            SEP_CHR
            "gsmIMSIMNCOperator"    SEP_CHR
            "gsmLAIMCC"             SEP_CHR
            "gsmLAIMCCCountry"      SEP_CHR
            "gsmLAIMNC"             SEP_CHR
            "gsmLAIMNCOperator"     SEP_CHR
            "gsmLAILAC"             "\n"
            , HDR_CHR);
#endif // GSM_IMSIFILE

#if GSM_OPFILE == 1
    GSM_FREOPEN(opFile, ENV_GSM_OPFILE_SUFFIX, file, filename);
    fprintf(file,
            "%s "                 /* HDR_CHR */
            "pktNo"               SEP_CHR
            "flowInd"             SEP_CHR
            "time"                SEP_CHR
            "vlanID"              SEP_CHR
            "lapdTEI"             SEP_CHR
            "gsmRslTN"            SEP_CHR
            "gsmRslSubCh"         SEP_CHR
            "gsmRslChannel"       SEP_CHR
            "gsmFullNetworkName"  SEP_CHR
            "gsmShortNetworkName" SEP_CHR
            "gsmTimeZone"         SEP_CHR
            "gsmTimeAndTimeZone"  "\n"
            , HDR_CHR);
#endif // GSM_OPFILE == 1

#if GSM_SMSFILE == 1
    GSM_FREOPEN(smsFile, ENV_GSM_SMSFILE_SUFFIX, file, filename);
    fprintf(file,
            "%s "                      /* HDR_CHR */
            "pktNo"                    SEP_CHR
            "flowInd"                  SEP_CHR
            "time"                     SEP_CHR
            "vlanID"                   SEP_CHR
            "lapdTEI"                  SEP_CHR
            "direction"                SEP_CHR
            "gsmRslTN"                 SEP_CHR
            "gsmRslSubCh"              SEP_CHR
            "gsmRslChannel"            SEP_CHR
            //"l4Proto"                  SEP_CHR
            //"gsmAbisRSLChNoTN"         SEP_CHR
            //"gsmAbisRSLChNoCbits"      SEP_CHR
            "smsMsgType"               SEP_CHR
            "serviceCenterTimeStamp"   SEP_CHR
            "rpOriginatorAddr"         SEP_CHR
            "rpOriginatorAddrCountry"  SEP_CHR
            "rpDestinationAddr"        SEP_CHR
            "rpDestinationAddrCountry" SEP_CHR
            "tpOriginatingAddr"        SEP_CHR
            "tpOriginatingAddrCountry" SEP_CHR
            "tpDestinationAddr"        SEP_CHR
            "tpDestinationAddrCountry" SEP_CHR
            "tpRecipientAddr"          SEP_CHR
            "tpRecipientAddrCountry"   SEP_CHR
            "smsMsgRef"                SEP_CHR
            "smsMsgId"                 SEP_CHR
            "smsMsgPart"               SEP_CHR
            "smsMsg"                   "\n"
            , HDR_CHR);
#endif // GSM_SMSFILE == 1
}
#endif // GSM_SAVE_FILES


binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;

    BV_APPEND_H32(bv , "gsmStat"    , "GSM status");

    BV_APPEND_U8(bv  , "gsmLapdSAPI", "GSM LAPD Service Access Point Identifier (SAPI)");
    BV_APPEND_U8(bv  , "gsmLapdTEI" , "GSM LAPD Terminal Endpoint Identifier (TEI)");

    BV_APPEND_U8_R(bv, "gsmRslTN"   , "GSM RSL Timeslot Numbers");

#if GSM_SPEECHFILE == 1
    BV_APPEND_FLT(bv, "gsmAMRDuration", "GSM Duration of AMR conversation (seconds)");
    BV_APPEND(bv, "gsmNumAMRGood_bad", "GSM Number of AMR good/bad frames", 2, bt_uint_32, bt_uint_32);
#endif // GSM_SPEECHFILE == 1

    return bv;
}


void t2OnNewFlow(packet_t *packet UNUSED, unsigned long flowIndex) {
    gsmFlow_t * const gsmFlowP = &gsmFlows[flowIndex];
    memset(gsmFlowP, '\0', sizeof(*gsmFlowP));
}


#if ETH_ACTIVATE > 0
void t2OnLayer2(packet_t *packet UNUSED, unsigned long flowIndex) {

    if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;

#if LAPD_ACTIVATE == 1
    const flow_t * const flowP = &flows[flowIndex];
    if (!(flowP->status & LAPD_FLOW)) {
#endif // LAPD_ACTIVATE
        GSM_SPKT_MD_PRI_NONE();
#if LAPD_ACTIVATE == 1
        return;
    }

    dissect_gsm(packet, flowP, flowIndex);
#endif // LAPD_ACTIVATE
}
#endif // ETH_ACTIVATE > 0


void t2OnLayer4(packet_t *packet, unsigned long flowIndex) {
    const flow_t * const flowP = &flows[flowIndex];
    const uint_fast8_t proto = flowP->l4Proto;
    if (proto != L3_UDP && proto != L3_SCTP) {
        GSM_SPKT_MD_PRI_NONE();
        return;
    }

    // only 1. frag packet will be processed
    if (!t2_is_first_fragment(packet)) {
        GSM_SPKT_MD_PRI_NONE();
        return;
    }

    dissect_gsm(packet, flowP, flowIndex);
}


static inline void dissect_gsm(packet_t *packet, const flow_t * const flowP, unsigned long flowIndex) {
    gsmFlow_t * const gsmFlowP = &gsmFlows[flowIndex];
    gsmFlowP->pstat = 0;

    const uint16_t snaplen = packet->snapL7Len;
    const uint8_t * const l7Hdr = packet->l7HdrP;

    t2buf_t t2buf = t2buf_create(l7Hdr, snaplen);

    gsm_metadata_t md = {
        .gsmFlowP = gsmFlowP,
        .flowP = flowP,
        .packet = packet,
        .a_sms.msg_ref = -1,
        .a_sms.msg_id = -1,
    };

    if (snaplen == 0) {
        GSM_SPKT_MD_PRI_NONE();
        return;
    }

#ifdef GSM_SAVE_FILES
    open_output_files(flowP->lastSeen.tv_sec);
#endif // GSM_SAVE_FILES

#if GSM_SPEECHFILE == 1
    bool is_rsl = false;
    long start_off = (LAPD_ACTIVATE == 0) ? 4 : 0;
#endif

    /* --------------------------------------------------------------------- */
    /* Link Access Protocol for D Channel (LAPD)                             */
    /* --------------------------------------------------------------------- */

#if LAPD_ACTIVATE == 1
    if ((flowP->status & LAPD_FLOW)) {
        const lapdHdr_t * const lapdHdrP = LAPD_HEADER(packet);
        gsmFlowP->sapi = lapdHdrP->mdsapi;
        gsmFlowP->tei = lapdHdrP->atei;
        switch (gsmFlowP->sapi) {
            case  0:
                gsmFlowP->pstat |= GSM_STAT_LAPD_RSL;
#if GSM_SPEECHFILE == 1
                is_rsl =
#endif
                dissect_gsm_abis_rsl(&t2buf, &md);
                break;
            case 62:
                gsmFlowP->pstat |= GSM_STAT_LAPD_OML;
                break;
            case 63:
                gsmFlowP->pstat |= GSM_STAT_LAPD_L2M;
                break;
            default:
                break;
        }
    } else
#endif

    /* --------------------------------------------------------------------- */
    /* GSMTAP                                                                */
    /* --------------------------------------------------------------------- */

    if (packet->dstPort == GSMTAP_UDP_PORT || packet->srcPort == GSMTAP_UDP_PORT) {
        if (!dissect_gsmtap(&t2buf, &md)) {
            // Not GSMTAP... try LAPD
            if (dissect_lapd(&t2buf, &md)) {
#if GSM_SPEECHFILE == 1
                start_off = t2buf_tell(&t2buf);
                is_rsl =
#endif
                dissect_gsm_abis_rsl(&t2buf, &md);
            }
        }

    /* --------------------------------------------------------------------- */
    /* Link Access Protocol for D Channel (LAPD)                             */
    /* --------------------------------------------------------------------- */

    } else if (dissect_lapd(&t2buf, &md)) {
#if GSM_SPEECHFILE == 1
        start_off = t2buf_tell(&t2buf);
        is_rsl =
#endif
        dissect_gsm_abis_rsl(&t2buf, &md);
    }

    /* --------------------------------------------------------------------- */

#if GSM_SPEECHFILE == 1
    if (!is_rsl && snaplen > start_off + 6) {
        uint8_t amr_type_q = 0xff;
        uint32_t amr_len = 0;

        uint8_t amr_cmr = 0xff;
        uint8_t amr_f = 0xff;
        uint8_t amr_ft = 0xff;
        uint8_t amr_q = 0xff;

        bool case1 = false;
        bool case2 = false;

        const uint8_t *amr_ptr = l7Hdr + start_off;

        // Case 1: FT split over two bytes
        const uint8_t amr_cmr_1    =  ((*(amr_ptr)     & 0xf0) >> 4);
        const uint8_t amr_f_1      =  ((*(amr_ptr)     & 0x08) >> 3);
        const uint8_t amr_ft_1     = (((*(amr_ptr)     & 0x07) << 1) |
                                      ((*(amr_ptr + 1) & 0x80) >> 7));
        const uint8_t amr_q_1      =  ((*(amr_ptr + 1) & 0x40) >> 6);
        const uint8_t amr_type_q_1 = (((*(amr_ptr)     & 0x0f) << 4) |
                                      ((*(amr_ptr + 1) & 0xc0) >> 4));

        // Case 2: FT in one byte
        const uint8_t amr_cmr_2    = ((*(amr_ptr)     & 0x0f));
        const uint8_t amr_f_2      = ((*(amr_ptr + 1) & 0x80) >> 7);
        const uint8_t amr_ft_2     = ((*(amr_ptr + 1) & 0x78) >> 3);
        const uint8_t amr_q_2      = ((*(amr_ptr + 1) & 0x04) >> 2);
        const uint8_t amr_type_q_2 =  (*(amr_ptr + 1) & 0xfc);

        // Case 1: FT split over two bytes
        if (amr_f_1 == 0 && // F-bit = 0
            is_rtp_amr_speech(amr_ft_1) && // valid FT
            (amr_cmr_1 == 0x0f || amr_cmr_1 < AMR_SID) // valid CMR
            && (
                   snaplen - start_off     == (uint32_t)(amr_len_by_ft[amr_ft_1] + 1) // valid length
                || snaplen - start_off - 1 == (uint32_t)(amr_len_by_ft[amr_ft_1] + 1) // valid length
            )
        ) {
            case1 = true;
        }

        // Case 2: FT in one byte
        if (
            amr_f_2 == 0 && // F-bit = 0
            is_rtp_amr_speech(amr_ft_2) && // valid FT
            (amr_cmr_2 == 0x0f || amr_cmr_2 < AMR_SID) // valid CMR
            && (
                  snaplen - start_off     == (uint32_t)(amr_len_by_ft[amr_ft_2] + 1) // valid length
               || snaplen - start_off - 1 == (uint32_t)(amr_len_by_ft[amr_ft_2] + 1) // valid length
            )
        ) {
            if (case1 && amr_q_1 == 1) {
                case1 = (amr_q_2 == 0);
                case2 = (amr_q_2 == 1);
            } else {
                case1 = false;
                case2 = true;
            }
        }

        if (case1) {
            // FT split over two bytes
            amr_cmr = amr_cmr_1;
            amr_f   = amr_f_1;
            amr_ft  = amr_ft_1;
            amr_q   = amr_q_1;
            amr_type_q = amr_type_q_1;
        } else if (case2) {
            amr_cmr = amr_cmr_2;
            amr_f   = amr_f_2;
            amr_ft  = amr_ft_2;
            amr_q   = amr_q_2;
            amr_type_q = amr_type_q_2;
        }

        const uint8_t amr_type   = ((amr_type_q & 0x78) >> 3);
        const uint8_t good_frame = ((amr_type_q & 0x04) >> 2);

        if (amr_ft != 0xff && (good_frame || gsmFlowP->amr_file)) {
            numAMRFrames[good_frame]++;
            numAMR[amr_type][good_frame]++;
            gsmFlowP->num_amr[good_frame]++;
            //md.amr_cmr = osmo_amr_type_name(amr_cmr);
            md.amr_type = osmo_amr_type_name(amr_type);
            md.amr_q = good_frame ? "GOOD" : "BAD";
            if (good_frame) {
                if (!gsmFlowP->amr_file) {
#if GSM_SPEECH_SPLIT == 0
                    if (FLOW_HAS_OPPOSITE(flowP)) {
                        const gsmFlow_t revFlow = gsmFlows[flowP->oppositeFlowIndex];
                        gsmFlowP->amr_file = revFlow.amr_file;
                    }

                    if (!gsmFlowP->amr_file) {
#endif // GSM_SPEECH_SPLIT == 0
                        char filepath[MAX_FILENAME_LEN] = {};
                        build_amr_filename(filepath, sizeof(filepath), flowP);
                        gsmFlowP->amr_file = file_manager_open(t2_file_manager, filepath, "w+");
                        if (UNLIKELY(!gsmFlowP->amr_file)) {
                            T2_PERR(plugin_name, "Failed to open file '%s': %s", filepath, strerror(errno));
                            gsmFlowP->stat |= GSM_STAT_IO_ERR;
                        } else {
                            FILE * const amr_file = file_manager_fp(t2_file_manager, gsmFlowP->amr_file);
                            fwrite("#!AMR\n", 1, 6, amr_file);
                            gsmFlowP->pstat |= GSM_STAT_AMR;
                            numAMRFiles++;
                        }
#if GSM_SPEECH_SPLIT == 0
                    }
#endif // GSM_SPEECH_SPLIT == 0
                }

                if (gsmFlowP->amr_file) {
                    FILE * const amr_file = file_manager_fp(t2_file_manager, gsmFlowP->amr_file);
                    gsmFlowP->pstat |= GSM_STAT_AMR;
                    uint8_t conv[33] = {};
                    conv[0] = amr_type_q;
                    const uint_fast32_t dlen = amr_len_by_ft[amr_type] + 1;
                    amr_ptr++; // skip frame type

                    if (case2) {
                        for (uint_fast32_t i = 1; i < dlen; i++, amr_ptr++) {
                            conv[i] = (((*amr_ptr & 0x03) << 6) | ((*(amr_ptr + 1) & 0xfc) >> 2));
                        }
                    } else {
                        for (uint_fast32_t i = 1; i < dlen; i++, amr_ptr++) {
                            conv[i] = (((*amr_ptr & 0x3f) << 2) | ((*(amr_ptr + 1) & 0xc0) >> 6));
                        }
                    }

                    fwrite(conv, 1, dlen, amr_file);
                }
            } // good frame
        } // amr_ft != 0xff
    } // !is_rsl && snaplen > start_off + 6
#endif // GSM_SPEECHFILE == 1

    gsmFlowP->stat |= gsmFlowP->pstat;

    /* --------------------------------------------------------------------- */
    /* PACKET MODE                                                           */
    /* --------------------------------------------------------------------- */

    if (sPktFile) {
        const gsmChannel_t * const rsl_channel = &md.rsl.channel;
        if (!md.rsl.channel.str) {
            md.rsl.channel.str = channel_to_str(rsl_channel);
        }

        const char * const rsl_msg_type = (md.rsl.msg_type           ? rsl_msg_name(md.rsl.msg_type) : "");
        const char * const rsl_content  = (md.rsl.channel_content    ? md.rsl.channel_content        : "");
        const char * const dtap_channel = (md.a_dtap.channel.channel ? md.a_dtap.channel.channel     : "");
#if GSM_SPEECHFILE == 1
        const char * const amr_cmr  = (md.amr_cmr  ? md.amr_cmr  : "");
        const char * const amr_type = (md.amr_type ? md.amr_type : "");
        const char * const amr_q    = (md.amr_q    ? md.amr_q    : "");
#endif

        char rsl_tn[4] = {};
        char rsl_subch[4] = {};
        if (strlen(md.rsl.channel.str)) {
            snprintf(rsl_tn, sizeof(rsl_tn), "%" PRIu8, rsl_channel->tn);
            snprintf(rsl_subch, sizeof(rsl_subch), "%" PRIu8, rsl_channel->subchannel);
        }

        char dtap_tn[4] = {};
        if (md.a_dtap.channel.channel) {
            snprintf(dtap_tn, sizeof(dtap_tn), "%" PRIu8, md.a_dtap.channel.tn);
        }

        char handover[4] = {};
        if (md.rsl.ho_ref) {
            snprintf(handover, sizeof(handover), "%" PRIu8, md.rsl.ho_ref);
        }

        const char *mcc_str;
        const char *mnc_str;
        char lac_str[7] = {};
        if (md.a_dtap.lai.valid) {
            mcc_str = mcc_to_str(md.a_dtap.lai.mcc);
            mnc_str = mnc_to_str(md.a_dtap.lai.mcc, md.a_dtap.lai.mnc);
            snprintf(lac_str, sizeof(lac_str), "0x%04" B2T_PRIX16, md.a_dtap.lai.lac);
        } else {
            mcc_str = "";
            mnc_str = "";
        }

        fprintf(sPktFile,
                "0x%08" B2T_PRIX32 /* gsmStat            */ SEP_CHR
                "%"     PRIu8      /* gsmLapdSAPI        */ SEP_CHR
                "%"     PRIu8      /* gsmLapdTEI         */ SEP_CHR
                "%s"               /* gsmRslMsgType      */ SEP_CHR
                "%s"               /* gsmRslTN           */ SEP_CHR
                "%s"               /* gsmRslSubCh        */ SEP_CHR
                "\"%s\""           /* gsmRslChannel      */ SEP_CHR
                "%s"               /* gsmDtapTN          */ SEP_CHR
                "\"%s\""           /* gsmDtapChannel     */ SEP_CHR
                "%s"               /* gsmHandoverRef     */ SEP_CHR
                "%s"               /* gsmLAIMCC          */ SEP_CHR
                "\"%s\""           /* gsmLAIMCCCountry   */ SEP_CHR
                "%s"               /* gsmLAIMNC          */ SEP_CHR
                "\"%s\""           /* gsmLAIMNCOperator  */ SEP_CHR
                "%s"               /* gsmLAILAC          */ SEP_CHR
                "%s"               /* gsmEncryption      */ SEP_CHR
                "\"%s\""           /* gsmContent         */ SEP_CHR
#if GSM_SPEECHFILE == 1
                "\"%s\""           /* gsmAMRCMR          */ SEP_CHR
                "\"%s\""           /* gsmAMRFrameType    */ SEP_CHR
                "%s"               /* gsmAMRFrameQ       */ SEP_CHR
#endif
                , gsmFlowP->pstat
                , gsmFlowP->sapi
                , gsmFlowP->tei
                , rsl_msg_type
                , rsl_tn
                , rsl_subch
                , md.rsl.channel.str
                , dtap_tn
                , dtap_channel
                , handover
                , md.a_dtap.lai.mcc
                , mcc_str
                , md.a_dtap.lai.mnc
                , mnc_str
                , lac_str
                , md.a_dtap.enc
                , rsl_content
#if GSM_SPEECHFILE == 1
                , amr_cmr
                , amr_type
                , amr_q
#endif
        );
    }

    /* --------------------------------------------------------------------- */
    /* CLEANUP                                                               */
    /* --------------------------------------------------------------------- */

    gsm_metadata_free(&md);
}


void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {

    gsmFlow_t * const gsmFlowP = &gsmFlows[flowIndex];

    gsmStat |= gsmFlowP->stat;

    OUTBUF_APPEND_U32(buf, gsmFlowP->stat); // gsmStat
    OUTBUF_APPEND_U8(buf, gsmFlowP->sapi);  // gsmLapdSAPI
    OUTBUF_APPEND_U8(buf, gsmFlowP->tei);   // gsmLapdTEI

    // gsmRslTN
    uint32_t cnt = 0;
    for (uint_fast8_t i = 0; i < 8; i++) {
        if (gsmFlowP->tn[i] > 0) cnt++;
    }
    OUTBUF_APPEND_NUMREP(buf, cnt);
    for (uint_fast8_t i = 0; i < 8; i++) {
        if (gsmFlowP->tn[i] > 0) {
            OUTBUF_APPEND_U8(buf, i);
        }
    }

#if GSM_SPEECHFILE == 1
    // gsmAMRDuration
    const float duration = 20.0 * (gsmFlowP->num_amr[AMR_GOOD] + gsmFlowP->num_amr[AMR_BAD]) / 1000.0;
    OUTBUF_APPEND_FLT(buf, duration);

    // gsmNumAMRGood_bad
    OUTBUF_APPEND_U32(buf, gsmFlowP->num_amr[AMR_GOOD]);
    OUTBUF_APPEND_U32(buf, gsmFlowP->num_amr[AMR_BAD]);

    // Cleanup
    if (gsmFlowP->amr_file) {
#if GSM_SPEECH_SPLIT == 1
        close_and_rename_file(&gsmFlowP->amr_file, T2_ENV_VAL(GSM_FILES_AMR_EXT));
#else // GSM_SPEECH_SPLIT == 0
        const flow_t * const flowP = &flows[flowIndex];
        if (FLOW_HAS_OPPOSITE(flowP)) {
            const gsmFlow_t revFlow = gsmFlows[flowP->oppositeFlowIndex];
            if (!revFlow.amr_file) {
                close_and_rename_file(&gsmFlowP->amr_file, T2_ENV_VAL(GSM_FILES_AMR_EXT));
            }
        }
#endif // GSM_SPEECH_SPLIT == 0
    }
#endif // GSM_SPEECHFILE == 1
}


void t2PluginReport(FILE *stream) {
    if (gsmStat) {
        T2_FPLOG_AGGR_HEX0(stream, plugin_name, gsmStat);
        T2_FPLOG_NUMP(stream, plugin_name, "Number of GSMTAP packets", numGSMTAP, numPackets);
        T2_FPLOG_NUMP(stream, plugin_name, "Number of GSM RSL packets", numGSMRSL, numPackets);
        T2_FPLOG_NUMP(stream, plugin_name, "Number of GSM RSL RLM management packets", numGSMRSLRLM, numGSMRSL);
        T2_FPLOG_NUMP(stream, plugin_name, "Number of GSM RSL DCM management packets", numGSMRSLDCM, numGSMRSL);
        T2_FPLOG_NUMP(stream, plugin_name, "Number of GSM RSL CCM management packets", numGSMRSLCCM, numGSMRSL);
        T2_FPLOG_NUMP(stream, plugin_name, "Number of GSM RSL TRX management packets", numGSMRSLTRX, numGSMRSL);
        T2_FPLOG_NUMP(stream, plugin_name, "Number of GSM RSL Location Services packets", numGSMRSLLS, numGSMRSL);
        T2_FPLOG_NUMP(stream, plugin_name, "Number of GSM RSL ip.access Vendor Specific packets", numGSMRSLIPA, numGSMRSL);
        T2_FPLOG_NUMP(stream, plugin_name, "Number of GSM RSL HUAWEI Paging Extension packets", numGSMRSLHUA, numGSMRSL);
        T2_FPLOG_NUMP(stream, plugin_name, "Number of GSM RSL unknown packets", numGSMRSLUnk, numGSMRSL);
        T2_FPLOG_NUMP(stream, plugin_name, "Number of GSM DTAP packets", numGSMDTAP, numPackets);
        T2_FPLOG_NUMP(stream, plugin_name, "Number of GSM DTAP CC packets", numGSMDTAPCC, numGSMDTAP);
        T2_FPLOG_NUMP(stream, plugin_name, "Number of GSM DTAP MM packets", numGSMDTAPMM, numGSMDTAP);
        T2_FPLOG_NUMP(stream, plugin_name, "Number of GSM DTAP RR packets", numGSMDTAPRR, numGSMDTAP);
        T2_FPLOG_NUMP(stream, plugin_name, "Number of GSM DTAP SMS packets", numGSMDTAPSMS, numGSMDTAP);
        T2_FPLOG_NUMP(stream, plugin_name, "Number of GSM DTAP SS packets", numGSMDTAPSS, numGSMDTAP);
        T2_FPLOG_NUMP(stream, plugin_name, "Number of GSM DTAP unknown packets", numGSMDTAPUnk, numGSMDTAP);
        T2_FPLOG_NUMP(stream, plugin_name, "Number of GSM SMS packets", numGSMSMSTPDU, numPackets);
        T2_FPLOG_NUMP(stream, plugin_name, "Number of SMS messages", numGSMSMSMsg, numPackets);
#if GSM_SPEECHFILE == 1
        T2_FPLOG_NUM(stream, plugin_name, "Number of one-way AMR conversations", numAMRFiles);
        char hrnum_good[64], hrnum_bad[64];

        const double numAMRFramesTot = numAMRFrames[AMR_GOOD] + numAMRFrames[AMR_BAD];
        if (numAMRFramesTot) {
            T2_CONV_NUM(numAMRFrames[AMR_GOOD], hrnum_good);
            T2_CONV_NUM(numAMRFrames[AMR_BAD], hrnum_bad);
            T2_FPLOG(stream, plugin_name, "Number of AMR good/bad frames: %" PRIu64 "%s [%.2f%%] / %" PRIu64 "%s [%.2f%%]",
                    numAMRFrames[AMR_GOOD], hrnum_good, 100.0 * (numAMRFrames[AMR_GOOD] / numAMRFramesTot),
                    numAMRFrames[AMR_BAD], hrnum_bad, 100.0 * (numAMRFrames[AMR_BAD] / numAMRFramesTot));

            for (uint_fast32_t i = 0; i <= AMR_SID; i++) {
                if (numAMR[i][AMR_GOOD] + numAMR[i][AMR_BAD]) {
                    T2_CONV_NUM(numAMR[i][AMR_GOOD], hrnum_good);
                    T2_CONV_NUM(numAMR[i][AMR_BAD], hrnum_bad);
                    T2_FPLOG(stream, plugin_name, "Number of %s good/bad frames: %" PRIu64 "%s [%.2f%%] / %" PRIu64 "%s [%.2f%%]",
                            osmo_amr_type_name(i),
                            numAMR[i][AMR_GOOD], hrnum_good, 100.0 * (numAMR[i][AMR_GOOD] / numAMRFramesTot),
                            numAMR[i][AMR_BAD], hrnum_bad, 100.0 * (numAMR[i][AMR_BAD] / numAMRFramesTot));
                }
            }
        }
#endif // GSM_SPEECHFILE == 1
    }
}


void t2Finalize() {
    free(gsmFlows);
#if GSM_ARFCNFILE == 1
    close_and_rename_file(&arfcnFile, T2_ENV_VAL(GSM_FILES_TXT_EXT));
#endif
#if GSM_CALLFILE == 1
    close_and_rename_file(&callFile, T2_ENV_VAL(GSM_FILES_TXT_EXT));
#endif
#if GSM_CDFILE == 1
    close_and_rename_file(&cdFile, T2_ENV_VAL(GSM_FILES_TXT_EXT));
#endif
#if GSM_IMMASSFILE == 1
    close_and_rename_file(&immAssFile, T2_ENV_VAL(GSM_FILES_TXT_EXT));
#endif
#if GSM_IMSIFILE == 1
    close_and_rename_file(&imsiFile, T2_ENV_VAL(GSM_FILES_TXT_EXT));
    gsm_tac_list_free(&tac_list);
#endif
#if GSM_OPFILE == 1
    close_and_rename_file(&opFile, T2_ENV_VAL(GSM_FILES_TXT_EXT));
#endif
#if GSM_SMSFILE == 1
    close_and_rename_file(&smsFile, T2_ENV_VAL(GSM_FILES_TXT_EXT));
#endif

#if GSM_STATFILE == 1
    FILE * const statFile = t2_fopen_with_suffix(baseFileName, T2_ENV_VAL(GSM_STATFILE_SUFFIX), "w");
    if (UNLIKELY(!statFile)) exit(EXIT_FAILURE);

    if (numGSMDTAP > 0) {
        T2_FLOG_NUMP0(statFile, "Number of GSM A-I/F DTAP packets", numGSMDTAP, numPackets);

        fputc('\n', statFile);

        T2_FLOG_NUMP(statFile, "Number of GSM A-I/F DTAP Call Control (CC) packets", numGSMDTAPCC, numGSMDTAP);
        T2_FLOG_NUMP(statFile, "Number of GSM A-I/F DTAP Mobility Management (MM) packets", numGSMDTAPMM, numGSMDTAP);
        T2_FLOG_NUMP(statFile, "Number of GSM A-I/F DTAP Radio Resources Management (RR) packets", numGSMDTAPRR, numGSMDTAP);
        T2_FLOG_NUMP(statFile, "Number of GSM A-I/F DTAP SMS packets", numGSMDTAPSMS, numGSMDTAP);
        T2_FLOG_NUMP(statFile, "Number of GSM A-I/F DTAP Non call related SS packets", numGSMDTAPSS, numGSMDTAP);
        T2_FLOG_NUMP(statFile, "Number of GSM A-I/F DTAP unknown packets", numGSMDTAPUnk, numGSMDTAP);

        fputc('\n', statFile);

        const float tmp = (numDtapCC[GSM48_MT_CC_CONNECT] != 0) ? numDtapCC[GSM48_MT_CC_SETUP] / (float)numDtapCC[GSM48_MT_CC_CONNECT] : 0.0f;
        if (tmp) {
            fprintf(statFile, "GSM A-I/F DTAP CC SETUP / CONNECT ratio: %5.3f\n", tmp);
            fputc('\n', statFile);
        }

        fprintf(statFile, "# GSM A-I/F DTAP CC message type\tPackets\n");
        for (uint_fast32_t i = 0; i < 255; i++) {
            if (numDtapCC[i] > 0) {
                fprintf(statFile, "%s\t%30" PRIu64 " [%6.02f%%]\n",
                        gsm48_cc_msg_name(i), numDtapCC[i], 100.0f * numDtapCC[i] / (float)numGSMDTAP);
            }
        }

        fputc('\n', statFile);

        fprintf(statFile, "# GSM A-I/F DTAP MM message type\tPackets\n");
        for (uint_fast32_t i = 0; i < 255; i++) {
            if (numDtapMM[i] > 0) {
                fprintf(statFile, "%s\t%30" PRIu64 " [%6.02f%%]\n",
                        gsm48_mm_msg_name(i), numDtapMM[i], 100.0f * numDtapMM[i] / (float)numGSMDTAP);
            }
        }

        fputc('\n', statFile);

        fprintf(statFile, "# GSM A-I/F DTAP RR message type\tPackets\n");
        for (uint_fast32_t i = 0; i < 255; i++) {
            if (numDtapRR[i] > 0) {
                fprintf(statFile, "%s\t%30" PRIu64 " [%6.02f%%]\n",
                        gsm48_rr_msg_name(i), numDtapRR[i], 100.0f * numDtapRR[i] / (float)numGSMDTAP);
            }
        }

        if (numGSMRSL > 0) fputc('\n', statFile);
    } // numGSMDTAP > 0

    if (numGSMRSL > 0) {
        T2_FLOG_NUMP0(statFile, "Number of GSM RSL packets", numGSMRSL, numPackets);

        fputc('\n', statFile);

        T2_FLOG_NUMP(statFile, "Number of GSM RSL Radio Link Layer Management (RLM) management packets", numGSMRSLRLM, numGSMRSL);
        T2_FLOG_NUMP(statFile, "Number of GSM RSL Dedicated Channel Management (DCM) management packets", numGSMRSLDCM, numGSMRSL);
        T2_FLOG_NUMP(statFile, "Number of GSM RSL Common Channel Management (CCM) management packets", numGSMRSLCCM, numGSMRSL);
        T2_FLOG_NUMP(statFile, "Number of GSM RSL TRX management packets", numGSMRSLTRX, numGSMRSL);
        T2_FLOG_NUMP(statFile, "Number of GSM RSL Location Services packets", numGSMRSLLS, numGSMRSL);
        T2_FLOG_NUMP(statFile, "Number of GSM RSL ip.access Vendor Specific packets", numGSMRSLIPA, numGSMRSL);
        T2_FLOG_NUMP(statFile, "Number of GSM RSL HUAWEI Paging Extension packets", numGSMRSLHUA, numGSMRSL);
        T2_FLOG_NUMP(statFile, "Number of GSM RSL unknown packets", numGSMRSLUnk, numGSMRSL);

        fputc('\n', statFile);

        fprintf(statFile, "# GSM RSL message type\tPackets\n");
        for (uint_fast32_t i = 0; i < 128; i++) {
            if (numRsl[i] > 0) {
                fprintf(statFile, "%s\t%30" PRIu64 " [%6.02f%%]\n",
                        rsl_msg_name(i), numRsl[i], 100.0f * numRsl[i] / (float)numGSMRSL);
            }
        }
    } // numGSMRSL > 0

    fclose(statFile);
#endif // GSM_STATFILE

#if ENVCNTRL > 0
    t2_free_env(ENV_GSM_N, env);
#endif // ENVCNTRL > 0
}
