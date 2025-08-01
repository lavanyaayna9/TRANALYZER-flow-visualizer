/*
 * gsmDecode.h
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

#ifndef T2_GSMDECODE_H_INCLUDED
#define T2_GSMDECODE_H_INCLUDED

// Local includes

#include "t2Plugin.h"
#include "gsm_osmocore.h"
#include "t2buf.h"


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define GSM_ARFCNFILE     1 // Save ARFCN in a separate file
#define GSM_CALLFILE      1 // Save calls in a separate file
#define GSM_CDFILE        1 // Save channels in a separate file
#define GSM_IMMASSFILE    1 // Save Immediate Assignments in a separate file
#define GSM_IMSIFILE      1 // Save IMSI/TMSI/... in a separate file
#define GSM_OPFILE        1 // Save operator names in a separate file
#define GSM_SMSFILE       1 // Save SMS in a separate file
#define GSM_SPEECHFILE    1 // Save audio conversations
#define GSM_STATFILE      1 // Save GSM statistics in a separate file

#define GSM_SPEECH_SPLIT  1 // 0: Save A and B flows in the same file (experimental)
                            // 1: Create one file per direction
#define GSM_TMSI_FORMAT   1 // Format for TMSI: 0: Integer, 1: Hexadecimal

// Debug macros
#define GSM_DEBUG         0 // Print generic debug messages
#define GSM_DBG_UNK       0 // Report unknown values for other messages

/* +++++++++++++++++++++ ENV / RUNTIME - conf Variables +++++++++++++++++++++ */

#define GSM_ROTATE_TIME   0 // Create new files every GSM_ROTATE_TIME seconds
                            // (use 0 to deactivate the feature)

#define GSM_RMDIR         1 // empty GSM_SPEECH_DIR before starting (GSM_SPEECHFILE=1)
#define GSM_SPEECH_DIR    "/tmp/gsm_speech" // Folder for extracted audio conversations
#define GSM_TXT_DIR       "/tmp/gsm_txt"    // Folder for output files

// Suffix for output files
#define GSM_ARFCNFILE_SUFFIX  "_gsm_arfcn"
#define GSM_CALLFILE_SUFFIX   "_gsm_calls"
#define GSM_CDFILE_SUFFIX     "_gsm_channels"
#define GSM_IMMASSFILE_SUFFIX "_gsm_imm_ass"
#define GSM_IMSIFILE_SUFFIX   "_gsm_imsi"
#define GSM_OPFILE_SUFFIX     "_gsm_operators"
#define GSM_SMSFILE_SUFFIX    "_gsm_sms"

#define GSM_STATFILE_SUFFIX   "_gsm_stats.txt"

// Extension for output files
#define GSM_FILES_AMR_EXT     ".amr" // Audio files
#define GSM_FILES_TMP_EXT     ".tmp" // Temporary files
#define GSM_FILES_TXT_EXT     ".txt" // Text files

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// Environment var vector
// The elements in the enum below MUST be in the same order as above
enum {
    ENV_GSM_ROTATE_TIME,
    ENV_GSM_RMDIR,
    ENV_GSM_SPEECH_DIR,
    ENV_GSM_TXT_DIR,
    ENV_GSM_ARFCNFILE_SUFFIX,
    ENV_GSM_CALLFILE_SUFFIX,
    ENV_GSM_CDFILE_SUFFIX,
    ENV_GSM_IMMASSFILE_SUFFIX,
    ENV_GSM_IMSIFILE_SUFFIX,
    ENV_GSM_OPFILE_SUFFIX,
    ENV_GSM_SMSFILE_SUFFIX,
    ENV_GSM_STATFILE_SUFFIX,
    ENV_GSM_FILES_AMR_EXT,
    ENV_GSM_FILES_TMP_EXT,
    ENV_GSM_FILES_TXT_EXT,
    ENV_GSM_N
};


#define GSM_TAC_LIST "tacdb.csv"


#if GSM_ARFCNFILE  == 1 || \
    GSM_ARFCNFILE  == 1 || \
    GSM_CALLFILE   == 1 || \
    GSM_CDFILE     == 1 || \
    GSM_IMMASSFILE == 1 || \
    GSM_IMSIFILE   == 1 || \
    GSM_OPFILE     == 1 || \
    GSM_SMSFILE    == 1
#define GSM_SAVE_FILES
#endif


#if GSM_DEBUG == 1
#define GSM_DBG(format, args...) T2_ERR(format, ##args)
#else
#define GSM_DBG(format, args...)
#endif


// gsmStat

#define GSM_STAT_LAPD_RSL        0x00000001 // LAPD Radio Signalling Link (RSL, SAPI 0)
#define GSM_STAT_LAPD_OML        0x00000002 // LAPD O&M link (SAPI 62)
#define GSM_STAT_LAPD_L2M        0x00000004 // LAPD Layer 2 Management (SAPI 63)
#define GSM_STAT_RSL_RLM         0x00000008 // RSL Radio link layer management (RLM)
#define GSM_STAT_RSL_DCM         0x00000010 // RSL Dedicated channel management (DCM)
#define GSM_STAT_RSL_CCM         0x00000020 // RSL Common channel management (CCM)
#define GSM_STAT_RSL_TRX         0x00000040 // RSL TRX management
#define GSM_STAT_RSL_LS          0x00000080 // RSL Location Services
#define GSM_STAT_RSL_IPA         0x00000100 // RSL ip.access Vendor Specific
#define GSM_STAT_RSL_HUA         0x00000200 // RSL HUAWEI Paging Extension
#define GSM_STAT_DTAP            0x00000400 // GSM A-I/F DTAP
#define GSM_STAT_DTAP_CC         0x00000800 // GSM A-I/F DTAP Call Control (CC)
#define GSM_STAT_DTAP_MM         0x00001000 // GSM A-I/F DTAP Mobility Management (MM)
#define GSM_STAT_DTAP_RR         0x00002000 // GSM A-I/F DTAP Radio Resources Management (RR)
#define GSM_STAT_DTAP_SMS        0x00004000 // GSM A-I/F DTAP SMS
#define GSM_STAT_RP              0x00008000 // GSM A-I/F RP
#define GSM_STAT_SMS             0x00010000 // GSM SMS TPDU
#define GSM_STAT_GSM_MAP         0x00020000 // GSM Mobile Application (GSM MAP)
#define GSM_STAT_AMR             0x00040000 // AMR speech
// 0x00080000: unused
#define GSM_STAT_UPLINK          0x00100000 // Uplink
#define GSM_STAT_DOWNLINK        0x00200000 // Downlink
// 0x00400000: unused
// 0x00800000: unused
#define GSM_STAT_IO_ERR          0x01000000 // File I/O error
// 0x00200000: unused
#define GSM_STAT_LAPD_MALFORMED  0x04000000 // LAPD decoding error
#define GSM_STAT_LAPDM_MALFORMED 0x08000000 // LAPDm decoding error
#define GSM_STAT_RSL_MALFORMED   0x10000000 // RSL decoding error
#define GSM_STAT_DTAP_MALFORMED  0x20000000 // DTAP decoding error
#define GSM_STAT_SMS_MALFORMED   0x40000000 // SMS decoding error
#define GSM_STAT_MALFORMED       0x80000000 // Decoding error


// Structs

typedef struct {
    char mcc[4];
    char mnc[4];
    uint16_t lac;
    bool valid;
} gsmLAI_t;

typedef struct {
    uint8_t tn;         // Time slot number
    uint8_t c_bits;
    uint8_t type;       // 8: SDCCH/8, 4: SDCCH/4, 2: Lm, 1: Bm
    uint8_t subchannel;
    char *str;
} gsmChannel_t;

typedef struct {
    uint8_t tn;
    uint8_t c_bits;
    uint8_t tsc;
    bool hopping;
    uint16_t maio;
    uint8_t hsn;
    uint16_t arfcn;
    char *channel;
} gsmChannelDescription_t;

typedef struct {
   uint8_t t1;
   uint8_t t2;
   uint16_t t3;
   uint16_t fn;
} gsm_frame_number_t;

typedef struct {
   uint8_t ra; // random access
   uint8_t t1;
   uint8_t t2;
   uint16_t t3;
   uint16_t rfn;
} gsm_request_reference_t;

typedef struct {
    uint8_t country_code;
    char *number;
    const char *country;
    uint8_t type;           // 0: unknown
                            // 1: international
                            // 2: national
                            // 3 network specific
                            // 4: dedicated access, short code
                            // *: reserved
    uint8_t numbering_plan; // 0: unknown
                            // 1: E.164/E.163
                            // 3: X.121
                            // 4. F.69
                            // 8: national
                            // 9: private
                            // *: reserved
} gsmMobileNumber_t;

typedef struct {
    uint8_t  type;  // 0: No Identity
                    // 1: IMSI
                    // 2: IMEI
                    // 3: IMEISV
                    // 4: TMSI
                    // *: Reserved
    union {
        char    *str;
        uint32_t tmsi;
    };
} gsmMobileIdentity_t;

// Data to extract from RSL
typedef struct {
    uint8_t msg_dsc;    // Message discriminator
    bool transparent;   // T-bit
    uint8_t msg_type;   // Message type

    gsmChannel_t channel;

    bool amr;
    uint8_t speech_or_data;
    uint8_t rate_and_type;
    uint8_t ho_ref; // Handover reference
    gsm_frame_number_t frame_number;
    uint8_t cause;
    uint8_t ta; // Timing Advance
    uint16_t bts_dist;
    char *amr_config;
    char *channel_content;
} gsmRslPkt_t;

typedef struct {
    // CC
    int8_t cause;
    const char *gsmCCMsgTypeStr;
    gsmMobileNumber_t caller;
    gsmMobileNumber_t callee;
    // MM
    gsmLAI_t lai;
    uint16_t cell_id;
    char *full_network_name;
    char *short_network_name;
    char *network_time_zone;
    char *network_time_and_time_zone;
    // RR
    gsmChannelDescription_t channel;
    const char *mode;
    char *amr_config;
    char enc[5]; // encryption algorithm A5/X
    // CCCH
    uint8_t ta; // Timing Advance
    uint16_t bts_dist;
    gsm_request_reference_t req_ref; // Request Reference
} gsmADtapPkt_t;

typedef struct {
    gsmMobileNumber_t originator_addr;
    gsmMobileNumber_t destination_addr;
    char *destination;
    char *originator;
    bool ms_sc;
    uint8_t msg_type;
} gsmARpPkt_t;

typedef struct {
    gsmMobileNumber_t tp_originating_addr;
    gsmMobileNumber_t tp_destination_addr;
    gsmMobileNumber_t tp_recipient_addr;
    char *sctstamp;
    char *sender;
    char *msg;
    int16_t msg_ref;
    int32_t msg_id;
    uint8_t msg_part;
    uint8_t msg_parts;
} gsmASmsPkt_t;


// Plugin structure

typedef struct {
#if GSM_SPEECHFILE == 1
    file_object_t *amr_file;
    uint32_t num_amr[2]; // gsmNumAMRGood_bad
#endif

    uint32_t stat;  // flow status
    uint32_t pstat; // packet status

    uint16_t msg_id;
    uint8_t *sms_frag[4][160];

    uint8_t tn[8]; // Timeslot number

    // LAPD
    uint8_t sapi;
    uint8_t tei;
} gsmFlow_t;


typedef struct {
    gsmFlow_t * const gsmFlowP;
    const flow_t * const flowP;
    const packet_t * const packet;
    gsmRslPkt_t rsl;
    gsmADtapPkt_t a_dtap;
    gsmARpPkt_t a_rp;
    gsmASmsPkt_t a_sms;
    const char *amr_cmr;
    const char *amr_type;
    const char *amr_q;
} gsm_metadata_t;


#if GSM_ARFCNFILE == 1
extern file_object_t *arfcnFile;
#endif
#if GSM_CALLFILE == 1
extern file_object_t *callFile;
#endif
#if GSM_CDFILE == 1
extern file_object_t *cdFile;
#endif
#if GSM_IMMASSFILE == 1
extern file_object_t *immAssFile;
#endif
#if GSM_IMSIFILE == 1
extern file_object_t *imsiFile;
#endif
#if GSM_OPFILE == 1
extern file_object_t *opFile;
#endif
#if GSM_SMSFILE == 1
extern file_object_t *smsFile;
#endif

extern uint64_t numGSMTAP;
extern uint64_t numGSMDTAP;
extern uint64_t numGSMDTAPCC;
extern uint64_t numGSMDTAPMM;
extern uint64_t numGSMDTAPRR;
extern uint64_t numGSMDTAPSMS;
extern uint64_t numGSMDTAPSS;
extern uint64_t numGSMDTAPUnk;
extern uint64_t numGSMRSL;
extern uint64_t numGSMRSLRLM;
extern uint64_t numGSMRSLDCM;
extern uint64_t numGSMRSLCCM;
extern uint64_t numGSMRSLTRX;
extern uint64_t numGSMRSLLS;
extern uint64_t numGSMRSLIPA;
extern uint64_t numGSMRSLHUA;
extern uint64_t numGSMRSLUnk;
extern uint64_t numRsl[128];
extern uint64_t numGSMSMSMsg;
extern uint64_t numGSMSMSTPDU;
extern uint64_t numDtapCC[255];
extern uint64_t numDtapMM[255];
extern uint64_t numDtapRR[255];
extern uint64_t numAMRFrames[2];
extern uint64_t numAMR[AMR_SID+1][2];

// plugin struct pointer for potential dependencies
extern gsmFlow_t *gsmFlows;

#endif // T2_GSMDECODE_H_INCLUDED
