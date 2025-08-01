/*
 * gsm_rsl.c
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

#include "gsm_rsl.h"

#include "gsm_a_dtap.h"   // for dissect_gsm_a_dtap
#include "gsm_osmocore.h" // for rsl_err_name
#include "gsm_utils.h"    // for channel_to_str, t2buf_read_mobile_identity, ...


static const char * const msg_dsc_str[][2] = {
    { ""        , ""                                   },
    { "RadioLL" , "Radio Link Layer Management (RLM)"  }, // 0x01
    { ""        , ""                                   },
    { ""        , ""                                   },
    { "DedicCh" , "Dedicated Channel Management (DCM)" }, // 0x04
    { ""        , ""                                   },
    { "CommonCh", "Common Channel Management (CCM)"    }, // 0x06
    { ""        , ""                                   },
    { "TRX"     , "TRX Management"                     }, // 0x08
};

static const char * const msg_type_str[][2] = {
    /* 0x00 */ { ""                 , ""                                        },
    /* 0x01 */ { "DATA_REQ"         , "DATA REQuest"                            },
    /* 0x02 */ { "DATA_IND"         , "DATA INDication"                         },
    /* 0x03 */ { "ERR_INC"          , "ERROR INDication"                        },
    /* 0x04 */ { "EST_REQ"          , "ESTablish REQuest"                       },
    /* 0x05 */ { "EST_CON"          , "ESTablish CONFirm"                       },
    /* 0x06 */ { "EST_IND"          , "ESTablish INDication"                    },
    /* 0x07 */ { "REL_REQ"          , "RELease REQuest"                         },
    /* 0x08 */ { "REL_CONF"         , "RELease CONFirm"                         },
    /* 0x09 */ { "REL_IND"          , "RELease INDication"                      },
    /* 0x0a */ { "UNIT_DATA_REQ"    , "UNIT DATA REQuest"                       },
    /* 0x0b */ { "UNIT_DATA_IND"    , "UNIT DATA INDication"                    },
    /* 0x0c */ { ""                 , ""                                        },
    /* 0x0d */ { ""                 , ""                                        },
    /* 0x0e */ { ""                 , ""                                        },
    /* 0x0f */ { ""                 , ""                                        },
    /* 0x10 */ { ""                 , ""                                        },
    /* 0x11 */ { "BCCH_INFO"        , "BCCH INFOrmation"                        },
    /* 0x12 */ { "CCCH_LOAD_IND"    , "CCCH LOAD INDication"                    },
    /* 0x13 */ { "CHAN_RQD"         , "CHANnel ReQuireD"                        },
    /* 0x14 */ { "DEL_IND"          , "DELETE INDication"                       },
    /* 0x15 */ { "PAG_CMD"          , "PAGing CoMmanD"                          },
    /* 0x16 */ { "IM_ASS_CMD"       , "IMMediate ASSign CoMmanD"                },
    /* 0x17 */ { "SMS_BC_REQ"       , "SMS BroadCast REQuest"                   },
    /* 0x18 */ { ""                 , ""                                        },
    /* 0x19 */ { "RF_RES_IND"       , "RF RESource INDication"                  },
    /* 0x1a */ { "SACCH_FILL"       , "SACCH FILLing"                           },
    /* 0x1b */ { "OVERLOAD"         , "OVERLOAD"                                },
    /* 0x1c */ { "ERR_REPORT"       , "ERROR REPORT"                            },
    /* 0x1d */ { "SMS_BC_CMD"       , "SMS BroadCast CoMmanD"                   },
    /* 0x1e */ { "CBCH_LOAD_IND"    , "CBCH LOAD INDication"                    },
    /* 0x1f */ { "NOT_CMD"          , "NOTification CoMmanD"                    },
    /* 0x20 */ { ""                 , ""                                        },
    /* 0x21 */ { "CH_ACTIV"         , "CHANnel ACTivation"                      },
    /* 0x22 */ { "CH_ACTIV_ACK"     , "CHANnel ACTivation ACKnowledge"          },
    /* 0x23 */ { "CH_ACTIV_NACK"    , "CHANnel ACTivation Negative ACKnowledge" },
    /* 0x24 */ { "CONN_FAIL"        , "CONNection FAILure"                      },
    /* 0x25 */ { "DEACT_SACCH"      , "DEACTivate SACCH"                        },
    /* 0x26 */ { "ENC_CMD"          , "ENCRyption CoMmanD"                      },
    /* 0x27 */ { "HAND_DET"         , "HANDover DETect"                         },
    /* 0x28 */ { "MEAS_RES"         , "MEASurement RESult"                      },
    /* 0x29 */ { "MODE_MOD_REQ"     , "MODE MODify REQuest"                     },
    /* 0x2a */ { "MODE_MOD_ACK"     , "MODE MODify ACKnowledge"                 },
    /* 0x2b */ { "MODE_MOD_NACK"    , "MODE MODify Negative ACKnowledge"        },
    /* 0x2c */ { "PHY_CONTEXT_REQ"  , "PHYsical CONTEXT REQuest"                },
    /* 0x2d */ { "PHY_CONTEXT_CONF" , "PHYsical CONTEXT CONFirm"                },
    /* 0x2e */ { "RF_CHAN_REL"      , "RF CHANnel RELease"                      },
    /* 0x2f */ { "MS_POWER_CTRL"    , "MS POWER CONTROL"                        },
    /* 0x30 */ { "BS_POWER_CTRL"    , "BS POWER CONTROL"                        },
    /* 0x31 */ { "PREPROC_CONFIG"   , "PREPROCess CONFIGure"                    },
    /* 0x32 */ { "PREPRO_MEAS_RES"  , "PREPROcessed MEASurement RESult"         },
    /* 0x33 */ { "RF_CH_REL_ACK"    , "RF CHannel RELease ACKnowledge"          },
    /* 0x34 */ { "SACCH_INFO_MODIFY", "SACCH INFO MODIFY"                       },
    /* 0x35 */ { "TAKER_DET"        , "TALKER DETection"                        },
    /* 0x36 */ { "LISTENER_DET"     , "LISTENER DETection"                      }
};


static inline bool t2buf_dissect_rsl_ie_channel_number(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory, gsmChannel_t *channel)
    __attribute__((__nonnull__(1,2)));
static inline bool t2buf_dissect_rsl_ie_link_identifier(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory)
    __attribute__((__nonnull__(1,2)));
static inline bool t2buf_dissect_rsl_ie_l1_info(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory)
    __attribute__((__nonnull__(1,2)));
static inline bool t2buf_dissect_rsl_ie_l3_info(t2buf_t *t2buf, bool mandatory, uint8_t type, gsm_metadata_t *md)
    __attribute__((__nonnull__(1,4)));
static inline bool t2buf_dissect_rsl_ie_rlm_cause(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory)
    __attribute__((__nonnull__(1,2)));
static inline bool t2buf_dissect_rsl_ie_release_mode(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory)
    __attribute__((__nonnull__(1,2)));
static inline bool t2buf_dissect_rsl_ie_system_info_type(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory, uint8_t *type)
    __attribute__((__nonnull__(1,2,4)));
static inline bool t2buf_dissect_rsl_ie_full_bcch_info(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory)
    __attribute__((__nonnull__(1,2)));
static inline bool t2buf_dissect_rsl_ie_starting_time(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory)
    __attribute__((__nonnull__(1,2)));
static inline bool t2buf_dissect_rsl_ie_rach_load(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory)
    __attribute__((__nonnull__(1,2)));
static inline bool t2buf_dissect_rsl_ie_paging_load(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory)
    __attribute__((__nonnull__(1,2)));
static inline bool t2buf_dissect_rsl_ie_request_reference(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory, gsm_request_reference_t *ref)
    __attribute__((__nonnull__(1,2,4)));
static inline bool t2buf_dissect_rsl_ie_access_delay(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory)
    __attribute__((__nonnull__(1,2)));
static inline bool t2buf_dissect_rsl_ie_physical_context(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory)
    __attribute__((__nonnull__(1,2)));
static inline bool t2buf_dissect_rsl_ie_full_immediate_assign_info(t2buf_t *t2buf, bool mandatory, gsm_metadata_t *md)
    __attribute__((__nonnull__(1,3)));
static inline bool t2buf_dissect_rsl_ie_paging_group(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory)
    __attribute__((__nonnull__(1,2)));
static inline bool t2buf_dissect_rsl_ie_ms_identity(t2buf_t *t2buf, bool mandatory, gsm_metadata_t *md)
    __attribute__((__nonnull__(1,3)));
static inline bool t2buf_dissect_rsl_ie_channel_needed(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory)
    __attribute__((__nonnull__(1,2)));
static inline bool t2buf_dissect_rsl_ie_emlpp_priority(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory)
    __attribute__((__nonnull__(1,2)));
static inline bool t2buf_dissect_rsl_ie_smscb_info(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory)
    __attribute__((__nonnull__(1,2)));
static inline bool t2buf_dissect_rsl_ie_smscb_message(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory)
    __attribute__((__nonnull__(1,2)));
static inline bool t2buf_dissect_rsl_ie_smscb_channel_indicator(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory)
    __attribute__((__nonnull__(1,2)));
static inline bool t2buf_dissect_rsl_ie_resource_info(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory)
    __attribute__((__nonnull__(1,2)));
static inline bool t2buf_dissect_rsl_ie_cause(t2buf_t *t2buf, bool mandatory, gsm_metadata_t *md)
    __attribute__((__nonnull__(1,3)));
static inline bool t2buf_dissect_rsl_ie_message_identifier(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory)
    __attribute__((__nonnull__(1,2)));
static inline bool t2buf_dissect_rsl_ie_erroneous_message(t2buf_t *t2buf, bool mandatory, gsm_metadata_t *md)
    __attribute__((__nonnull__(1,3)));
static inline bool t2buf_dissect_rsl_ie_cb_command_type(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory)
    __attribute__((__nonnull__(1,2)));
static inline bool t2buf_dissect_rsl_ie_cbch_load_information(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory)
    __attribute__((__nonnull__(1,2)));
static inline bool t2buf_dissect_rsl_ie_command_indicator(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory)
    __attribute__((__nonnull__(1,2)));
static inline bool t2buf_dissect_rsl_ie_group_call_reference(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory)
    __attribute__((__nonnull__(1,2)));
static inline bool t2buf_dissect_rsl_ie_channel_description(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory)
    __attribute__((__nonnull__(1,2)));
static inline bool t2buf_dissect_rsl_ie_nch_drx_info(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory)
    __attribute__((__nonnull__(1,2)));
static inline bool t2buf_dissect_rsl_ie_activation_type(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory)
    __attribute__((__nonnull__(1,2)));
static inline bool t2buf_dissect_rsl_ie_channel_mode(t2buf_t *t2buf, bool mandatory, gsm_metadata_t *md)
    __attribute__((__nonnull__(1,3)));
static inline bool t2buf_dissect_rsl_ie_channel_identification(t2buf_t *t2buf, bool mandatory, gsm_metadata_t *md)
    __attribute__((__nonnull__(1,3)));
static inline bool t2buf_dissect_rsl_ie_encryption_info(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory)
    __attribute__((__nonnull__(1,2)));
static inline bool t2buf_dissect_rsl_ie_handover_reference(t2buf_t *t2buf, bool mandatory, gsm_metadata_t *md)
    __attribute__((__nonnull__(1,3)));
static inline bool t2buf_dissect_rsl_ie_bs_power(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory)
    __attribute__((__nonnull__(1,2)));
static inline bool t2buf_dissect_rsl_ie_bs_power_parameters(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory)
    __attribute__((__nonnull__(1,2)));
static inline bool t2buf_dissect_rsl_ie_ms_power(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory)
    __attribute__((__nonnull__(1,2)));
static inline bool t2buf_dissect_rsl_ie_ms_power_parameters(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory)
    __attribute__((__nonnull__(1,2)));
static inline bool t2buf_dissect_rsl_ie_timing_advance(t2buf_t *t2buf, bool mandatory, gsm_metadata_t *md)
    __attribute__((__nonnull__(1,3)));
static inline bool t2buf_dissect_rsl_ie_ms_timing_offset(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory)
    __attribute__((__nonnull__(1,2)));
static inline bool t2buf_dissect_rsl_ie_tfo_transparent_container(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory)
    __attribute__((__nonnull__(1,2)));
static inline bool t2buf_dissect_rsl_ie_tfo_status(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory)
    __attribute__((__nonnull__(1,2)));
static inline bool t2buf_dissect_rsl_ie_frame_number(t2buf_t *t2buf, bool mandatory, gsm_metadata_t *md)
    __attribute__((__nonnull__(1,3)));
static inline bool t2buf_dissect_rsl_ie_uic(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory)
    __attribute__((__nonnull__(1,2)));
static inline bool t2buf_dissect_rsl_ie_main_channel_reference(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory)
    __attribute__((__nonnull__(1,2)));
static inline bool t2buf_dissect_rsl_ie_sacch_info(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory)
    __attribute__((__nonnull__(1,2)));
static inline bool t2buf_dissect_rsl_ie_measurement_result_number(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory)
    __attribute__((__nonnull__(1,2)));
static inline bool t2buf_dissect_rsl_ie_uplink_measurements(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory)
    __attribute__((__nonnull__(1,2)));
static inline bool t2buf_dissect_rsl_ie_multirate_configuration(t2buf_t *t2buf, bool mandatory, gsm_metadata_t *md)
    __attribute__((__nonnull__(1,3)));
static inline bool t2buf_dissect_rsl_ie_multirate_control(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory)
    __attribute__((__nonnull__(1,2)));
static inline bool t2buf_dissect_rsl_ie_supported_codec_types(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory)
    __attribute__((__nonnull__(1,2)));
static inline bool t2buf_dissect_rsl_ie_codec_configuration(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory)
    __attribute__((__nonnull__(1,2)));
static inline bool t2buf_dissect_rsl_ie_round_trip_delay(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory)
    __attribute__((__nonnull__(1,2)));
// Returned value MUST be free'd with gsm_channel_free()
static inline gsmChannel_t t2buf_dissect_rsl_channel_number(t2buf_t *t2buf, gsmFlow_t *gsmFlowP)
    __attribute__((__nonnull__(1, 2)))
    __attribute__((__warn_unused_result__));


/* ========================================================================= */
/* Radio Signalling Link (RSL)                                               */
/* GSM 08.58                                                                 */
/* ========================================================================= */
inline bool dissect_gsm_abis_rsl(t2buf_t *t2buf, gsm_metadata_t *md) {
    /* Message discriminator */
    uint8_t octet;
    if (!t2buf_read_u8(t2buf, &octet)) return false;

    numGSMRSL++;

    //const bool transparent = (octet & 0x01);
    const uint8_t msg_dsc = ((octet & 0xfe) >> 1);
    md->rsl.msg_dsc = msg_dsc;

    switch (msg_dsc) {

        case 0x01: // Radio Link Layer Management (RLM)
            GSM_DBG_RSL("%" PRIu64 ": Radio Link Layer Management (RLM)", numPackets);
            md->gsmFlowP->pstat |= GSM_STAT_RSL_RLM;
            numGSMRSLRLM++;
            break;

        case 0x04: // Dedicated Channel Management (DCM)
            GSM_DBG_RSL("%" PRIu64 ": Dedicated Channel Management (DCM)", numPackets);
            md->gsmFlowP->pstat |= GSM_STAT_RSL_DCM;
            numGSMRSLDCM++;
            break;

        case 0x06: // Common Channel Management (CCM)
            GSM_DBG_RSL("%" PRIu64 ": Common Channel Management (CCM)", numPackets);
            md->gsmFlowP->pstat |= GSM_STAT_RSL_CCM;
            numGSMRSLCCM++;
            break;

        case 0x08: // TRX Management
            GSM_DBG_RSL("%" PRIu64 ": TRX Management", numPackets);
            md->gsmFlowP->pstat |= GSM_STAT_RSL_TRX;
            numGSMRSLTRX++;
            break;

        case 0x16: // Location Services
            // TODO
            GSM_DBG_RSL("%" PRIu64 ": Location Services messages", numPackets);
            md->gsmFlowP->pstat |= GSM_STAT_RSL_LS;
            md->rsl.msg_dsc = 0;
            numGSMRSLLS++;
            return false;

        case 0x3f: // ip.access Vendor Specific
            // TODO
            GSM_DBG_RSL("%" PRIu64 ": ip.access Vendor Specific messages", numPackets);
            md->gsmFlowP->pstat |= GSM_STAT_RSL_IPA;
            md->rsl.msg_dsc = 0;
            numGSMRSLIPA++;
            return false;

        case 0x55: // HUAWEI Paging Extension
            // TODO
            GSM_DBG_RSL("%" PRIu64 ": HUAWEI Paging Extension", numPackets);
            md->gsmFlowP->pstat |= GSM_STAT_RSL_HUA;
            md->rsl.msg_dsc = 0;
            numGSMRSLHUA++;
            return false;

        default:
#if GSM_DBG_RSL_UNK == 1
            GSM_DBG_RSL("%" PRIu64 ": Unknown (reserved) RSL message discriminator: 0x%02" B2T_PRIX8, numPackets, octet);
#endif
            md->gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
            md->rsl.msg_dsc = 0;
            numGSMRSLUnk++;
            return false;
    }

    /* Message type */
    if (!t2buf_read_u8(t2buf, &octet)) return false;

    //const uint8_t em = ((octet & 0x80) >> 7); // reserved
    const uint8_t msg_type = (octet & 0x7f);
    md->rsl.msg_type = msg_type;
    numRsl[msg_type]++;

    switch (msg_type) {

        /* ----------------------------------------------------------------- */
        /* Radio Link Layer Management (RLM)                                 */
        /* ----------------------------------------------------------------- */

        case 0x01: { // DATA REQuest
            GSM_DBG_RSL("%" PRIu64 ": RLM DATA REQuest", numPackets);
            /* Channel Number */
            t2buf_dissect_rsl_ie_channel_number(t2buf, md->gsmFlowP, true, &md->rsl.channel);
            /* Link Identifier */
            t2buf_dissect_rsl_ie_link_identifier(t2buf, md->gsmFlowP, true);
            /* L3 Information */
            t2buf_dissect_rsl_ie_l3_info(t2buf, true, 0, md);
            break;
        }

        case 0x02: { // DATA INDication
            GSM_DBG_RSL("%" PRIu64 ": RLM DATA INDication", numPackets);
            /* Channel Number */
            t2buf_dissect_rsl_ie_channel_number(t2buf, md->gsmFlowP, true, &md->rsl.channel);
            /* Link Identifier */
            t2buf_dissect_rsl_ie_link_identifier(t2buf, md->gsmFlowP, true);
            /* L3 Information */
            t2buf_dissect_rsl_ie_l3_info(t2buf, true, 0, md);
            break;
        }

        case 0x03: { // ERROR INDication
            GSM_DBG_RSL("%" PRIu64 ": RLM ERROR INDication", numPackets);
            /* Channel Number */
            t2buf_dissect_rsl_ie_channel_number(t2buf, md->gsmFlowP, true, &md->rsl.channel);
            /* Link Identifier */
            t2buf_dissect_rsl_ie_link_identifier(t2buf, md->gsmFlowP, true);
            /* RLM Cause */
            t2buf_dissect_rsl_ie_rlm_cause(t2buf, md->gsmFlowP, true);
            break;
        }

        case 0x04: { // ESTablish REQuest
            GSM_DBG_RSL("%" PRIu64 ": RLM ESTablish REQuest", numPackets);
            /* Channel Number */
            t2buf_dissect_rsl_ie_channel_number(t2buf, md->gsmFlowP, true, &md->rsl.channel);
            /* Link Identifier */
            t2buf_dissect_rsl_ie_link_identifier(t2buf, md->gsmFlowP, true);
            break;
        }

        case 0x05: { // ESTablish CONFirm
            GSM_DBG_RSL("%" PRIu64 ": RLM ESTablish CONFirm", numPackets);
            /* Channel Number */
            t2buf_dissect_rsl_ie_channel_number(t2buf, md->gsmFlowP, true, &md->rsl.channel);
            /* Link Identifier */
            t2buf_dissect_rsl_ie_link_identifier(t2buf, md->gsmFlowP, true);
            break;
        }

        case 0x06: { // ESTablish INDication
            GSM_DBG_RSL("%" PRIu64 ": RLM ESTablish INDication", numPackets);
            /* Channel Number */
            t2buf_dissect_rsl_ie_channel_number(t2buf, md->gsmFlowP, true, &md->rsl.channel);
            /* Link Identifier */
            t2buf_dissect_rsl_ie_link_identifier(t2buf, md->gsmFlowP, true);
            /* L3 Information */
            if (t2buf_left(t2buf) > 1) {
                t2buf_dissect_rsl_ie_l3_info(t2buf, false, 0, md);
            }
            break;
        }

        case 0x07: { // RELease REQuest
            GSM_DBG_RSL("%" PRIu64 ": RLM RELease REQuest", numPackets);
            /* Channel Number */
            t2buf_dissect_rsl_ie_channel_number(t2buf, md->gsmFlowP, true, &md->rsl.channel);
            /* Link Identifier */
            t2buf_dissect_rsl_ie_link_identifier(t2buf, md->gsmFlowP, true);
            /* Release Mode */
            t2buf_dissect_rsl_ie_release_mode(t2buf, md->gsmFlowP, true);
            break;
        }

        case 0x08: { // RELease CONFirm
            GSM_DBG_RSL("%" PRIu64 ": RLM RELease CONFirm", numPackets);
            /* Channel Number */
            t2buf_dissect_rsl_ie_channel_number(t2buf, md->gsmFlowP, true, &md->rsl.channel);
            /* Link Identifier */
            t2buf_dissect_rsl_ie_link_identifier(t2buf, md->gsmFlowP, true);
            break;
        }

        case 0x09: { // RELease INDication
            GSM_DBG_RSL("%" PRIu64 ": RLM RELease INDication", numPackets);
            /* Channel Number */
            t2buf_dissect_rsl_ie_channel_number(t2buf, md->gsmFlowP, true, &md->rsl.channel);
            /* Link Identifier */
            t2buf_dissect_rsl_ie_link_identifier(t2buf, md->gsmFlowP, true);
            break;
        }

        case 0x0a: { // UNIT DATA REQuest
            GSM_DBG_RSL("%" PRIu64 ": RLM UNIT DATA REQuest", numPackets);
            /* Channel Number */
            t2buf_dissect_rsl_ie_channel_number(t2buf, md->gsmFlowP, true, &md->rsl.channel);
            /* Link Identifier */
            t2buf_dissect_rsl_ie_link_identifier(t2buf, md->gsmFlowP, true);
            /* L3 Information */
            if (t2buf_left(t2buf) > 0) {
                t2buf_dissect_rsl_ie_l3_info(t2buf, false, 0, md);
            }
            break;
        }

        case 0x0b: { // UNIT DATA INDication
            GSM_DBG_RSL("%" PRIu64 ": RLM UNIT DATA INDication", numPackets);
            /* Channel Number */
            t2buf_dissect_rsl_ie_channel_number(t2buf, md->gsmFlowP, true, &md->rsl.channel);
            /* Link Identifier */
            t2buf_dissect_rsl_ie_link_identifier(t2buf, md->gsmFlowP, true);
            /* L3 Information */
            t2buf_dissect_rsl_ie_l3_info(t2buf, true, 0, md);
            break;
        }

        /* ----------------------------------------------------------------- */
        /* Common Channel Management (CCM) and TRX Management                */
        /* ----------------------------------------------------------------- */

        case 0x11: { // BCCH INFOrmation
            GSM_DBG_RSL("%" PRIu64 ": CCM/TRXM BCCH INFOrmation", numPackets);
            /* Channel Number */
            t2buf_dissect_rsl_ie_channel_number(t2buf, md->gsmFlowP, true, &md->rsl.channel);
            /* System Info Type */
            uint8_t type;
            t2buf_dissect_rsl_ie_system_info_type(t2buf, md->gsmFlowP, true, &type);
            /* Full BCCH Info */
            if (t2buf_left(t2buf) > 0) {
                t2buf_dissect_rsl_ie_full_bcch_info(t2buf, md->gsmFlowP, false);
            }
            /* Starting Time */
            if (t2buf_left(t2buf) > 0) {
                t2buf_dissect_rsl_ie_starting_time(t2buf, md->gsmFlowP, false);
            }
            break;
        }

        case 0x12: { // CCCH LOAD INDication
            GSM_DBG_RSL("%" PRIu64 ": CCM/TRXM LOAD INDication", numPackets);
            /* Channel Number */
            t2buf_dissect_rsl_ie_channel_number(t2buf, md->gsmFlowP, true, &md->rsl.channel);
            /* Either RACH Load or Paging Load present */
            /* RACH Load */
            t2buf_dissect_rsl_ie_rach_load(t2buf, md->gsmFlowP, false);
            /* Paging Load */
            if (t2buf_left(t2buf) > 0) {
                t2buf_dissect_rsl_ie_paging_load(t2buf, md->gsmFlowP, false);
            }
            break;
        }

        case 0x13: { // CHANnel ReQuireD
            GSM_DBG_RSL("%" PRIu64 ": CCM/TRXM CHANnel ReQuireD", numPackets);
            /* Channel Number */
            t2buf_dissect_rsl_ie_channel_number(t2buf, md->gsmFlowP, true, &md->rsl.channel);
            /* Request Reference */
            gsm_request_reference_t ref = {};
            t2buf_dissect_rsl_ie_request_reference(t2buf, md->gsmFlowP, true, &ref);
            /* Access Delay */
            t2buf_dissect_rsl_ie_access_delay(t2buf, md->gsmFlowP, true);
            /* Physical Context */
            if (t2buf_left(t2buf) > 0) {
                t2buf_dissect_rsl_ie_physical_context(t2buf, md->gsmFlowP, false);
            }
            break;
        }

        case 0x14: { // DELETE INDication
            GSM_DBG_RSL("%" PRIu64 ": CCM/TRXM DELETE INDication", numPackets);
            /* Channel Number */
            t2buf_dissect_rsl_ie_channel_number(t2buf, md->gsmFlowP, true, &md->rsl.channel);
            /* Full Immediate Assign Info */
            t2buf_dissect_rsl_ie_full_immediate_assign_info(t2buf, true, md);
            break;
        }

        case 0x15: { // PAGing CoMmanD
            GSM_DBG_RSL("%" PRIu64 ": CCM/TRXM PAGing CoMmanD", numPackets);
            /* Channel Number */
            t2buf_dissect_rsl_ie_channel_number(t2buf, md->gsmFlowP, true, &md->rsl.channel);
            /* Paging Group */
            t2buf_dissect_rsl_ie_paging_group(t2buf, md->gsmFlowP, true);
            /* MS Identity */
            t2buf_dissect_rsl_ie_ms_identity(t2buf, true, md);
            /* Channel Needed */
            if (t2buf_left(t2buf) > 0) {
                t2buf_dissect_rsl_ie_channel_needed(t2buf, md->gsmFlowP, false);
            }
            /* eMLPP Priority */
            if (t2buf_left(t2buf) > 0) {
                t2buf_dissect_rsl_ie_emlpp_priority(t2buf, md->gsmFlowP, false);
            }
            break;
        }

        case 0x16: { // IMMediate ASSign CoMmanD
            GSM_DBG_RSL("%" PRIu64 ": CCM/TRXM IMMediate ASSign CoMmanD", numPackets);
            /* Channel Number */
            t2buf_dissect_rsl_ie_channel_number(t2buf, md->gsmFlowP, true, &md->rsl.channel);
            /* Full Immediate Assign Info */
            t2buf_dissect_rsl_ie_full_immediate_assign_info(t2buf, true, md);
            break;
        }

        case 0x17: { // SMS BroadCast REQuest
            GSM_DBG_RSL("%" PRIu64 ": CCM/TRXM SMS BroadCast REQuest", numPackets);
            /* Channel Number */
            t2buf_dissect_rsl_ie_channel_number(t2buf, md->gsmFlowP, true, &md->rsl.channel);
            /* SMSCB Information */
            t2buf_dissect_rsl_ie_smscb_info(t2buf, md->gsmFlowP, true);
            /* SMSCB Channel Indicator */
            if (t2buf_left(t2buf) > 0) {
                t2buf_dissect_rsl_ie_smscb_channel_indicator(t2buf, md->gsmFlowP, false);
            }
            break;
        }

        /* ----------------------------------------------------------------- */
        /* TRX Management                                                    */
        /* ----------------------------------------------------------------- */

        case 0x19: { // RF RESource INDication
            GSM_DBG_RSL("%" PRIu64 ": TRXM RF RESource INDication", numPackets);
            /* Resource Information */
            t2buf_dissect_rsl_ie_resource_info(t2buf, md->gsmFlowP, true);
            break;
        }

        case 0x1a: { // SACCH FILLing
            GSM_DBG_RSL("%" PRIu64 ": TRXM SACCH FILLing", numPackets);
            /* System Info Type */
            uint8_t type;
            t2buf_dissect_rsl_ie_system_info_type(t2buf, md->gsmFlowP, true, &type);
            /* L3 Information */
            if (t2buf_left(t2buf) > 0) {
                t2buf_dissect_rsl_ie_l3_info(t2buf, false, ((type == 0x48) ? 1 : 2), md); // SACCH : CCCH
            }
            /* Starting Time */
            if (t2buf_left(t2buf) > 0) {
                t2buf_dissect_rsl_ie_starting_time(t2buf, md->gsmFlowP, false);
            }
            break;
        }

        case 0x1b: { // OVERLOAD
            GSM_DBG_RSL("%" PRIu64 ": TRXM OVERLOAD", numPackets);
            /* Cause */
            t2buf_dissect_rsl_ie_cause(t2buf, true, md);
            break;
        }

        case 0x1c: { // ERROR REPORT
            GSM_DBG_RSL("%" PRIu64 ": TRXM ERROR REPORT", numPackets);
            /* Cause */
            t2buf_dissect_rsl_ie_cause(t2buf, true, md);
            /* Message Identifier */
            if (t2buf_left(t2buf) > 0) {
                t2buf_dissect_rsl_ie_message_identifier(t2buf, md->gsmFlowP, false);
            }
            /* Channel Number */
            if (t2buf_left(t2buf) > 0) {
                t2buf_dissect_rsl_ie_channel_number(t2buf, md->gsmFlowP, false, &md->rsl.channel);
            }
            /* Link Identifier */
            if (t2buf_left(t2buf) > 0) {
                t2buf_dissect_rsl_ie_link_identifier(t2buf, md->gsmFlowP, false);
            }
            /* Erroneous Message */
            if (t2buf_left(t2buf) > 0) {
                t2buf_dissect_rsl_ie_erroneous_message(t2buf, false, md);
            }
            break;
        }

        case 0x1d: { // SMS BroadCast CoMmanD
            GSM_DBG_RSL("%" PRIu64 ": TRXM SMS BroadCast CoMmanD", numPackets);
            /* Channel Number */
            t2buf_dissect_rsl_ie_channel_number(t2buf, md->gsmFlowP, true, &md->rsl.channel);
            /* CB Command type */
            t2buf_dissect_rsl_ie_cb_command_type(t2buf, md->gsmFlowP, true);
            /* SMSCB message */
            t2buf_dissect_rsl_ie_smscb_message(t2buf, md->gsmFlowP, true);
            /* SMSCB Channel Indicator */
            if (t2buf_left(t2buf) > 0) {
                t2buf_dissect_rsl_ie_smscb_channel_indicator(t2buf, md->gsmFlowP, false);
            }
            break;
        }

        case 0x1e: { // CBCH LOAD INDication
            GSM_DBG_RSL("%" PRIu64 ": TRXM CBCH LOAD INDication", numPackets);
            /* Channel Number */
            t2buf_dissect_rsl_ie_channel_number(t2buf, md->gsmFlowP, true, &md->rsl.channel);
            /* CBCH Load Information */
            t2buf_dissect_rsl_ie_cbch_load_information(t2buf, md->gsmFlowP, true);
            /* SMSCB Channel Indicator */
            if (t2buf_left(t2buf) > 0) {
                t2buf_dissect_rsl_ie_smscb_channel_indicator(t2buf, md->gsmFlowP, false);
            }
            break;
        }

        case 0x1f: { // NOTification CoMmanD
            GSM_DBG_RSL("%" PRIu64 ": TRXM CBCH NOTification CoMmanD", numPackets);
            /* Channel Number */
            t2buf_dissect_rsl_ie_channel_number(t2buf, md->gsmFlowP, true, &md->rsl.channel);
            /* Command Indicator */
            t2buf_dissect_rsl_ie_command_indicator(t2buf, md->gsmFlowP, true);
            /* Group Call Reference */
            if (t2buf_left(t2buf) > 0) {
                t2buf_dissect_rsl_ie_group_call_reference(t2buf, md->gsmFlowP, false);
            }
            /* Channel Description */
            if (t2buf_left(t2buf) > 0) {
                t2buf_dissect_rsl_ie_channel_description(t2buf, md->gsmFlowP, false);
            }
            /* NCH DRX information */
            if (t2buf_left(t2buf) > 0) {
                t2buf_dissect_rsl_ie_nch_drx_info(t2buf, md->gsmFlowP, false);
            }
            break;
        }

        /* ----------------------------------------------------------------- */
        /* Dedicated Channel Management (DCM)                                */
        /* ----------------------------------------------------------------- */

        case 0x21: { // CHANnel ACTivation
            GSM_DBG_RSL("%" PRIu64 ": DCM CHANnel ACTivation", numPackets);
            /* Channel Number */
            t2buf_dissect_rsl_ie_channel_number(t2buf, md->gsmFlowP, true, &md->rsl.channel);
            /* Activation Type */
            t2buf_dissect_rsl_ie_activation_type(t2buf, md->gsmFlowP, true);
            /* Channel Mode */
            if (t2buf_left(t2buf) > 0) {
                t2buf_dissect_rsl_ie_channel_mode(t2buf, true, md); // May be optional
            }
            /* Channel Identification */
            if (t2buf_left(t2buf) > 0) {
                t2buf_dissect_rsl_ie_channel_identification(t2buf, false, md);
            }
            /* Encryption Information */
            if (t2buf_left(t2buf) > 0) {
                t2buf_dissect_rsl_ie_encryption_info(t2buf, md->gsmFlowP, false);
            }
            /* Handover Reference */
            if (t2buf_left(t2buf) > 0) {
                t2buf_dissect_rsl_ie_handover_reference(t2buf, false, md);
            }
            /* BS Power */
            if (t2buf_left(t2buf) > 0) {
                t2buf_dissect_rsl_ie_bs_power(t2buf, md->gsmFlowP, false);
            }
            /* MS Power */
            if (t2buf_left(t2buf) > 0) {
                t2buf_dissect_rsl_ie_ms_power(t2buf, md->gsmFlowP, false);
            }
            /* Timing Advance */
            if (t2buf_left(t2buf) > 0) {
                t2buf_dissect_rsl_ie_timing_advance(t2buf, false, md);
            }
            /* BS Power Parameters */
            if (t2buf_left(t2buf) > 0) {
                t2buf_dissect_rsl_ie_bs_power_parameters(t2buf, md->gsmFlowP, false);
            }
            /* MS Power Parameters */
            if (t2buf_left(t2buf) > 0) {
                t2buf_dissect_rsl_ie_ms_power_parameters(t2buf, md->gsmFlowP, false);
            }
            /* Physical Context */
            if (t2buf_left(t2buf) > 0) {
                t2buf_dissect_rsl_ie_physical_context(t2buf, md->gsmFlowP, false);
            }
            /* SACCH Information */
            if (t2buf_left(t2buf) > 0) {
                t2buf_dissect_rsl_ie_sacch_info(t2buf, md->gsmFlowP, false);
            }
            /* UIC */
            if (t2buf_left(t2buf) > 0) {
                t2buf_dissect_rsl_ie_uic(t2buf, md->gsmFlowP, false);
            }
            /* Main Channel reference */
            if (t2buf_left(t2buf) > 0) {
                t2buf_dissect_rsl_ie_main_channel_reference(t2buf, md->gsmFlowP, false);
            }
            /* MultiRate configuration */
            if (t2buf_left(t2buf) > 0) {
                t2buf_dissect_rsl_ie_multirate_configuration(t2buf, false, md);
            }
            /* MultiRate Control */
            if (t2buf_left(t2buf) > 0) {
                t2buf_dissect_rsl_ie_multirate_control(t2buf, md->gsmFlowP, false);
            }
            /* Supported Codec Types */
            if (t2buf_left(t2buf) > 0) {
                t2buf_dissect_rsl_ie_supported_codec_types(t2buf, md->gsmFlowP, false);
            }
            /* TFO Transparent Container */
            if (t2buf_left(t2buf) > 0) {
                t2buf_dissect_rsl_ie_tfo_transparent_container(t2buf, md->gsmFlowP, false);
            }
            break;
        }

        case 0x22: { // CHANnel ACTivation ACKnowledge
            GSM_DBG_RSL("%" PRIu64 ": DCM CHANnel ACTivation ACKnowledge", numPackets);
            /* Channel Number */
            t2buf_dissect_rsl_ie_channel_number(t2buf, md->gsmFlowP, true, &md->rsl.channel);
            /* Frame Number */
            t2buf_dissect_rsl_ie_frame_number(t2buf, true, md);
            break;
        }

        case 0x23: { // CHANnel ACTivation Negative ACKnowledge
            GSM_DBG_RSL("%" PRIu64 ": DCM CHANnel ACTivation Negative ACKnowledge", numPackets);
            /* Channel Number */
            t2buf_dissect_rsl_ie_channel_number(t2buf, md->gsmFlowP, true, &md->rsl.channel);
            /* Cause */
            t2buf_dissect_rsl_ie_cause(t2buf, true, md);
            break;
        }

        case 0x24: { // CONNection FAILure
            GSM_DBG_RSL("%" PRIu64 ": DCM CONNection FAILure", numPackets);
            /* Channel Number */
            t2buf_dissect_rsl_ie_channel_number(t2buf, md->gsmFlowP, true, &md->rsl.channel);
            /* Cause */
            t2buf_dissect_rsl_ie_cause(t2buf, true, md);
            break;
        }

        case 0x25: { // DEACTivate SACCH
            GSM_DBG_RSL("%" PRIu64 ": DCM DEACTivate SACCH", numPackets);
            /* Channel Number */
            t2buf_dissect_rsl_ie_channel_number(t2buf, md->gsmFlowP, true, &md->rsl.channel);
            break;
        }

        case 0x26: { // ENCRyption CoMmanD
            GSM_DBG_RSL("%" PRIu64 ": DCM ENCRyption CoMmanD", numPackets);
            /* Channel Number */
            t2buf_dissect_rsl_ie_channel_number(t2buf, md->gsmFlowP, true, &md->rsl.channel);
            /* Encryption Information */
            t2buf_dissect_rsl_ie_encryption_info(t2buf, md->gsmFlowP, true);
            /* Link Identifier */
            t2buf_dissect_rsl_ie_link_identifier(t2buf, md->gsmFlowP, true);
            /* L3 Information */
            t2buf_dissect_rsl_ie_l3_info(t2buf, true, 0, md);
            break;
        }

        case 0x27: { // HANDover DETection
            GSM_DBG_RSL("%" PRIu64 ": DCM HANDOVER DETection", numPackets);
            /* Channel Number */
            t2buf_dissect_rsl_ie_channel_number(t2buf, md->gsmFlowP, true, &md->rsl.channel);
            /* Access Delay */
            if (t2buf_left(t2buf) > 0) {
                t2buf_dissect_rsl_ie_access_delay(t2buf, md->gsmFlowP, false);
            }
            break;
        }

        case 0x28: { // MEASurement RESult
            GSM_DBG_RSL("%" PRIu64 ": DCM MEASurement RESult", numPackets);
            /* Channel Number */
            t2buf_dissect_rsl_ie_channel_number(t2buf, md->gsmFlowP, true, &md->rsl.channel);
            /* Measurement Result Number */
            t2buf_dissect_rsl_ie_measurement_result_number(t2buf, md->gsmFlowP, true);
            /* Uplink Measurements */
            t2buf_dissect_rsl_ie_uplink_measurements(t2buf, md->gsmFlowP, true);
            /* BS Power */
            t2buf_dissect_rsl_ie_bs_power(t2buf, md->gsmFlowP, true);
            /* L1 Information */
            if (t2buf_left(t2buf) > 0) {
                t2buf_dissect_rsl_ie_l1_info(t2buf, md->gsmFlowP, false);
            }
            /* L3 Information */
            if (t2buf_left(t2buf) > 0) {
                t2buf_dissect_rsl_ie_l3_info(t2buf, false, (((*(t2buf->buffer + t2buf->pos + 3) & 0xfe) == 0x10) ? 1 : 0), md);
            }
            /* MS Timing Offset */
            if (t2buf_left(t2buf) > 0) {
                t2buf_dissect_rsl_ie_ms_timing_offset(t2buf, md->gsmFlowP, false);
            }
            break;
        }

        case 0x29: { // MODE MODify REQuest
            GSM_DBG_RSL("%" PRIu64 ": DCM MODE MODify REQuest", numPackets);
            /* Channel Number */
            t2buf_dissect_rsl_ie_channel_number(t2buf, md->gsmFlowP, true, &md->rsl.channel);
            /* Channel Mode */
            t2buf_dissect_rsl_ie_channel_mode(t2buf, true, md);
            /* Encryption Information */
            if (t2buf_left(t2buf) > 0) {
                t2buf_dissect_rsl_ie_encryption_info(t2buf, md->gsmFlowP, false);
            }
            /* Main Channel Reference */
            if (t2buf_left(t2buf) > 0) {
                t2buf_dissect_rsl_ie_main_channel_reference(t2buf, md->gsmFlowP, false);
            }
            /* MultiRate Configuration */
            if (t2buf_left(t2buf) > 0) {
                t2buf_dissect_rsl_ie_multirate_configuration(t2buf, false, md);
            }
            /* MultiRate Control */
            if (t2buf_left(t2buf) > 0) {
                t2buf_dissect_rsl_ie_multirate_control(t2buf, md->gsmFlowP, false);
            }
            /* Supported Codec Types */
            if (t2buf_left(t2buf) > 0) {
                t2buf_dissect_rsl_ie_supported_codec_types(t2buf, md->gsmFlowP, false);
            }
            /* TFO Transparent Container */
            if (t2buf_left(t2buf) > 0) {
                t2buf_dissect_rsl_ie_tfo_transparent_container(t2buf, md->gsmFlowP, false);
            }
            break;
        }

        case 0x2a: { // MODE MODify ACKnowledge
            GSM_DBG_RSL("%" PRIu64 ": DCM MODE MODify ACKnowledge", numPackets);
            /* Channel Number */
            t2buf_dissect_rsl_ie_channel_number(t2buf, md->gsmFlowP, true, &md->rsl.channel);
            break;
        }

        case 0x2b: { // MODE MODify Negative ACKnowledge
            GSM_DBG_RSL("%" PRIu64 ": DCM MODE MODify Negative ACKnowledge", numPackets);
            /* Channel Number */
            t2buf_dissect_rsl_ie_channel_number(t2buf, md->gsmFlowP, true, &md->rsl.channel);
            /* Cause */
            t2buf_dissect_rsl_ie_cause(t2buf, true, md);
            break;
        }

        case 0x2c: { // PHYsical CONTEXT REQuest
            GSM_DBG_RSL("%" PRIu64 ": DCM PHYsical CONTEXT REQuest", numPackets);
            /* Channel Number */
            t2buf_dissect_rsl_ie_channel_number(t2buf, md->gsmFlowP, true, &md->rsl.channel);
            break;
        }

        case 0x2d: { // PHYsical CONTEXT CONFirm
            GSM_DBG_RSL("%" PRIu64 ": DCM PHYsical CONTEXT CONFirm", numPackets);
            /* Channel Number */
            t2buf_dissect_rsl_ie_channel_number(t2buf, md->gsmFlowP, true, &md->rsl.channel);
            /* BS Power */
            t2buf_dissect_rsl_ie_bs_power(t2buf, md->gsmFlowP, true);
            /* MS Power */
            t2buf_dissect_rsl_ie_ms_power(t2buf, md->gsmFlowP, true);
            /* Timing Advance */
            t2buf_dissect_rsl_ie_timing_advance(t2buf, true, md);
            /* Physical Context */
            if (t2buf_left(t2buf) > 0) {
                t2buf_dissect_rsl_ie_physical_context(t2buf, md->gsmFlowP, false);
            }
            break;
        }

        case 0x2e: { // RF CHANnel RELease
            GSM_DBG_RSL("%" PRIu64 ": DCM RF CHANnel RELease", numPackets);
            /* Channel Number */
            t2buf_dissect_rsl_ie_channel_number(t2buf, md->gsmFlowP, true, &md->rsl.channel);
            break;
        }

        case 0x2f: { // MS POWER CONTROL
            GSM_DBG_RSL("%" PRIu64 ": DCM MS POWER CONTROL", numPackets);
            /* Channel Number */
            t2buf_dissect_rsl_ie_channel_number(t2buf, md->gsmFlowP, true, &md->rsl.channel);
            /* MS Power */
            if (t2buf_left(t2buf) > 0) {
                t2buf_dissect_rsl_ie_ms_power(t2buf, md->gsmFlowP, false);
            }
            /* MS Power Parameters */
            if (t2buf_left(t2buf) > 0) {
                t2buf_dissect_rsl_ie_ms_power_parameters(t2buf, md->gsmFlowP, false);
            }
            break;
        }

        case 0x30: { // BS POWER CONTROL
            GSM_DBG_RSL("%" PRIu64 ": DCM BS POWER CONTROL", numPackets);
            /* Channel Number */
            t2buf_dissect_rsl_ie_channel_number(t2buf, md->gsmFlowP, true, &md->rsl.channel);
            /* BS Power */
            t2buf_dissect_rsl_ie_bs_power(t2buf, md->gsmFlowP, true);
            /* BS Power Parameters */
            if (t2buf_left(t2buf) > 0) {
                t2buf_dissect_rsl_ie_bs_power_parameters(t2buf, md->gsmFlowP, false);
            }
            break;
        }

        case 0x31: { // PREPROCess CONFIGure
            GSM_DBG_RSL("%" PRIu64 ": DCM PREPROCess CONFIGure", numPackets);
            /* Channel Number */
            t2buf_dissect_rsl_ie_channel_number(t2buf, md->gsmFlowP, true, &md->rsl.channel);
            /* Preproc. Parameters */
            T2BUF_SKIP_LV(t2buf);
            break;
        }

        case 0x32: { // PREPROcessed MEASurement RESult
            GSM_DBG_RSL("%" PRIu64 ": DCM PREPROcessed MEASurement RESult", numPackets);
            /* Channel Number */
            t2buf_dissect_rsl_ie_channel_number(t2buf, md->gsmFlowP, true, &md->rsl.channel);
            /* Preproc. Measurements */
            T2BUF_SKIP_LV(t2buf);
            break;
        }

        case 0x33: { // RF CHannel RELease ACKnowledge
            GSM_DBG_RSL("%" PRIu64 ": DCM RF CHannel RELease ACKnowledge", numPackets);
            /* Channel Number */
            t2buf_dissect_rsl_ie_channel_number(t2buf, md->gsmFlowP, true, &md->rsl.channel);
            break;
        }

        case 0x34: { // SACCH INFO MODIFY
            GSM_DBG_RSL("%" PRIu64 ": DCM SACCH INFO MODIFY", numPackets);
            /* Channel Number */
            t2buf_dissect_rsl_ie_channel_number(t2buf, md->gsmFlowP, true, &md->rsl.channel);
            /* System Info Type */
            uint8_t type;
            t2buf_dissect_rsl_ie_system_info_type(t2buf, md->gsmFlowP, true, &type);
            /* L3 Information */
            if (t2buf_left(t2buf) > 0) {
                t2buf_dissect_rsl_ie_l3_info(t2buf, false, ((type == 0x48) ? 1 : 2), md); // SACCH : CCCH
            }
            /* Starting Time */
            if (t2buf_left(t2buf) > 0) {
                t2buf_dissect_rsl_ie_starting_time(t2buf, md->gsmFlowP, false);
            }
            break;
        }

        case 0x35: { // TALKER DETection
            GSM_DBG_RSL("%" PRIu64 ": DCM TALKER DETection", numPackets);
            /* Channel Number */
            t2buf_dissect_rsl_ie_channel_number(t2buf, md->gsmFlowP, true, &md->rsl.channel);
            /* Access Delay */
            if (t2buf_left(t2buf) > 0) {
                t2buf_dissect_rsl_ie_access_delay(t2buf, md->gsmFlowP, false);
            }
            break;
        }

        case 0x36: { // LISTENER DETection
            GSM_DBG_RSL("%" PRIu64 ": DCM LISTENER DETection", numPackets);
            /* Channel Number */
            t2buf_dissect_rsl_ie_channel_number(t2buf, md->gsmFlowP, true, &md->rsl.channel);
            /* Access Delay */
            if (t2buf_left(t2buf) > 0) {
                t2buf_dissect_rsl_ie_access_delay(t2buf, md->gsmFlowP, false);
            }
            break;
        }

        case 0x37: { // REMOTE CODEC CONFiguration REPort
            GSM_DBG_RSL("%" PRIu64 ": DCM REMOTE CODEC CONFiguration REPort", numPackets);
            /* Channel Number */
            t2buf_dissect_rsl_ie_channel_number(t2buf, md->gsmFlowP, true, &md->rsl.channel);
            /* Codec Configuration */
            t2buf_dissect_rsl_ie_codec_configuration(t2buf, md->gsmFlowP, true);
            /* Supported Codec Types */
            if (t2buf_left(t2buf) > 0) {
                t2buf_dissect_rsl_ie_supported_codec_types(t2buf, md->gsmFlowP, false);
            }
            /* TFO Transparent Container */
            if (t2buf_left(t2buf) > 0) {
                t2buf_dissect_rsl_ie_tfo_transparent_container(t2buf, md->gsmFlowP, false);
            }
            break;
        }

        case 0x38: { // Round Trip Delay REPport
            GSM_DBG_RSL("%" PRIu64 ": DCM Round Trip Delay REPport", numPackets);
            /* Channel Number */
            t2buf_dissect_rsl_ie_channel_number(t2buf, md->gsmFlowP, true, &md->rsl.channel);
            /* Round Trip Delay */
            t2buf_dissect_rsl_ie_round_trip_delay(t2buf, md->gsmFlowP, true);
            break;
        }

        case 0x39: { // PRE-HANDOver NOTIFication
            GSM_DBG_RSL("%" PRIu64 ": DCM PRE-HANDOver NOTIFication", numPackets);
            /* Channel Number */
            t2buf_dissect_rsl_ie_channel_number(t2buf, md->gsmFlowP, true, &md->rsl.channel);
            /* MultiRate Control */
            t2buf_dissect_rsl_ie_multirate_control(t2buf, md->gsmFlowP, true);
            /* Codec Configuration */
            t2buf_dissect_rsl_ie_codec_configuration(t2buf, md->gsmFlowP, true);
            /* TFO Transparent Container */
            if (t2buf_left(t2buf) > 0) {
                t2buf_dissect_rsl_ie_tfo_transparent_container(t2buf, md->gsmFlowP, false);
            }
            break;
        }

        case 0x3a: { // MultiRate CODEC MODification REQuest
            GSM_DBG_RSL("%" PRIu64 ": DCM MultiRate CODEC MODification REQuest", numPackets);
            /* Channel Number */
            t2buf_dissect_rsl_ie_channel_number(t2buf, md->gsmFlowP, true, &md->rsl.channel);
            /* MultiRate Configuration */
            break;
        }

        case 0x3b: { // MultiRate CODEC MODification ACKnowledge
            GSM_DBG_RSL("%" PRIu64 ": DCM MultiRate CODEC MODification ACKnowledge", numPackets);
            /* Channel Number */
            t2buf_dissect_rsl_ie_channel_number(t2buf, md->gsmFlowP, true, &md->rsl.channel);
            /* MultiRate Configuration */
            if (t2buf_left(t2buf) > 0) {
                t2buf_dissect_rsl_ie_multirate_configuration(t2buf, false, md);
            }
            break;
        }

        case 0x3c: { // MultiRate CODEC MODification Negative ACKnowledge
            GSM_DBG_RSL("%" PRIu64 ": DCM MultiRate CODEC MODification Negative ACKnowledge", numPackets);
            /* Channel Number */
            t2buf_dissect_rsl_ie_channel_number(t2buf, md->gsmFlowP, true, &md->rsl.channel);
            /* Cause */
            t2buf_dissect_rsl_ie_cause(t2buf, true, md);
            break;
        }

        case 0x3d: { // MultiRate CODEC MODification PERformed
            GSM_DBG_RSL("%" PRIu64 ": DCM MultiRate CODEC MODification PERformed", numPackets);
            /* Channel Number */
            t2buf_dissect_rsl_ie_channel_number(t2buf, md->gsmFlowP, true, &md->rsl.channel);
            /* MultiRate Configuration */
            t2buf_dissect_rsl_ie_multirate_configuration(t2buf, true, md);
            break;
        }

        case 0x3e: { // TFO REPort
            GSM_DBG_RSL("%" PRIu64 ": DCM TFO REPort", numPackets);
            /* Channel Number */
            t2buf_dissect_rsl_ie_channel_number(t2buf, md->gsmFlowP, true, &md->rsl.channel);
            /* TFO Status */
            t2buf_dissect_rsl_ie_tfo_status(t2buf, md->gsmFlowP, true);
            break;
        }

        case 0x3f: { // TFO MODification REQuest
            GSM_DBG_RSL("%" PRIu64 ": DCM TFO MODification REQuest", numPackets);
            /* Channel Number */
            t2buf_dissect_rsl_ie_channel_number(t2buf, md->gsmFlowP, true, &md->rsl.channel);
            /* MultiRate Control */
            t2buf_dissect_rsl_ie_multirate_control(t2buf, md->gsmFlowP, true);
            /* Supported Codec Types */
            if (t2buf_left(t2buf) > 0) {
                t2buf_dissect_rsl_ie_supported_codec_types(t2buf, md->gsmFlowP, false);
            }
            /* TFO Transparent Container */
            if (t2buf_left(t2buf) > 0) {
                t2buf_dissect_rsl_ie_tfo_transparent_container(t2buf, md->gsmFlowP, false);
            }
            break;
        }

        /* ----------------------------------------------------------------- */
        /* Location Services messages                                        */
        /* ----------------------------------------------------------------- */

        case 0x41: { // Location Information
            GSM_DBG_RSL("%" PRIu64 ": LS Location Information", numPackets);
            /* LLP APDU */
            T2BUF_SKIP_LV(t2buf);
            break;
        }

        /* ----------------------------------------------------------------- */
        /* PAGING Huawei extension (TODO)                                    */
        /* ----------------------------------------------------------------- */

        //case 0x18: { // PAGING Huawei extension
        //    GSM_DBG_RSL("%" PRIu64 ": PAGING Huawei extension", numPackets);
        //    break;
        //}

        /* ----------------------------------------------------------------- */
        /* ip.access Vendor Specific Messages (TODO)                         */
        /* ----------------------------------------------------------------- */

        default: {
#if GSM_DBG_RSL_UNK == 1
            GSM_DBG_RSL("%" PRIu64 ": unknown message type: 0x%02" B2T_PRIX8, numPackets, msg_type);
#endif
            md->gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
            md->rsl.msg_type = 0;
            return false;
        }
    }

#if GSM_CDFILE == 1
    if (msg_type == 0x21 || msg_type == 0x22 || msg_type == 0x23 || msg_type == 0x2e || msg_type == 0x33) {
        const time_t sec = md->flowP->lastSeen.tv_sec;
        const intmax_t usec = md->flowP->lastSeen.tv_usec;
        char *handover = md->rsl.ho_ref ? t2_strdup_printf("HANDOVER ref:%" PRIu8, md->rsl.ho_ref) : NULL;
        if (!md->rsl.channel.str) {
            md->rsl.channel.str = channel_to_str(&md->rsl.channel);
        }

        FILE * const cdFp = file_manager_fp(t2_file_manager, cdFile);
        fprintf(cdFp,
                "%" PRIu64  /* pktNo      */ SEP_CHR
                "%" PRIu64  /* flowInd    */ SEP_CHR
                "%ld.%06jd" /* time       */ SEP_CHR
                "%" PRIu16  /* vlanID     */ SEP_CHR
                "%" PRIu8   /* lapdTEI    */ SEP_CHR
                "%s"        /* gsmMsgType */ SEP_CHR
                ,
                numPackets,
                md->flowP->findex,
                sec, usec,
                md->flowP->vlanId,
                md->gsmFlowP->tei,
                msg_type_str[md->rsl.msg_type][0]);

        if (msg_type == 0x23) {
            fprintf(cdFp, "%s" /* gsmCause */, rsl_err_name(md->rsl.cause));
        }

        fprintf(cdFp,
                          /* gsmCause       */ SEP_CHR
                "%" PRIu8 /* gsmRslTN       */ SEP_CHR
                "%" PRIu8 /* gsmRslSubCh    */ SEP_CHR
                "%s"      /* gsmRslChannel  */ SEP_CHR
                "%s"      /* gsmChannelType */ SEP_CHR
                ,
                md->rsl.channel.tn,
                md->rsl.channel.subchannel,
                md->rsl.channel.str,
                md->rsl.channel_content ? md->rsl.channel_content : "");

        if (md->rsl.ho_ref) {
            fprintf(cdFp, "%" PRIu8 /* gsmHandoverRef */, md->rsl.ho_ref);
        }

        if (msg_type == 0x22) {
            fprintf(cdFp,
                               /* gsmHandoverRef   */ SEP_CHR
                    "%" PRIu8  /* gsmFrameNumberT1 */ SEP_CHR
                    "%" PRIu8  /* gsmFrameNumberT2 */ SEP_CHR
                    "%" PRIu16 /* gsmFrameNumberT3 */ SEP_CHR
                    "%" PRIu16 /* gsmFrameNumber   */ SEP_CHR
                    ,
                    md->rsl.frame_number.t1,
                    md->rsl.frame_number.t2,
                    md->rsl.frame_number.t3,
                    md->rsl.frame_number.fn);
        } else {
            fputs(/* gsmHandoverRef   */ SEP_CHR
                  /* gsmFrameNumberT1 */ SEP_CHR
                  /* gsmFrameNumberT2 */ SEP_CHR
                  /* gsmFrameNumberT3 */ SEP_CHR
                  /* gsmFrameNumber   */ SEP_CHR
                  , cdFp);
        }

        fprintf(cdFp,
                "DL SAPI:%" PRIu8 "  TEI:%" PRIu8 " [%" PRIu8 "-%" PRIu8 " Type %" PRIu8 "] %s %s %s %s %s" /* gsmChannelInfo */ "\n"
                ,
                md->gsmFlowP->sapi,
                md->gsmFlowP->tei,
                md->rsl.channel.tn,
                md->rsl.channel.subchannel,
                md->rsl.channel.type,
                msg_dsc_str[md->rsl.msg_dsc][0],
                msg_type_str[md->rsl.msg_type][0],
                md->rsl.channel.str,
                handover ? handover : "",
                md->rsl.channel_content ? md->rsl.channel_content : "");

        free(handover);
    }
#endif

    return true;
}


static inline bool t2buf_dissect_rsl_ie_channel_number(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory, gsmChannel_t *channel) {
    uint8_t ie;

    if (!mandatory) {
        if (!t2buf_peek_u8(t2buf, &ie) || ie != 0x01) return false;
    }

    if (!t2buf_read_u8(t2buf, &ie)) return false;
    if (ie != 0x01) {
        GSM_DBG_RSL("%" PRIu64 ": Channel Number IE 0x01 expected, found 0x%02" B2T_PRIX8, numPackets, ie);
        gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
    }

    GSM_DBG_RSL("%" PRIu64 ": Channel Number IE", numPackets);

    gsmChannel_t c = t2buf_dissect_rsl_channel_number(t2buf, gsmFlowP);
    if (channel) *channel = c;
    else gsm_channel_free(&c);

    return true;
}


// Returned value MUST be free'd with gsm_channel_free()
static inline gsmChannel_t t2buf_dissect_rsl_channel_number(t2buf_t *t2buf, gsmFlow_t *gsmFlowP) {
    gsmChannel_t channel = {};

    uint8_t channel_number;
    if (!t2buf_read_u8(t2buf, &channel_number)) return channel;

    // Time slot number
    const uint8_t tn = (channel_number & 0x07);
    channel.tn = tn;
    gsmFlowP->tn[tn] = 1;

    // Channel
    const uint8_t c_bits = ((channel_number & 0xf8) >> 3);
    channel.c_bits = c_bits;
    switch (c_bits) {
        case 0x01: channel.type = 1; channel.subchannel = 0; break;
        case 0x02: channel.type = 2; channel.subchannel = 0; break;
        case 0x03: channel.type = 2; channel.subchannel = 1; break;
        case 0x04: channel.type = 4; channel.subchannel = 0; break;
        case 0x05: channel.type = 4; channel.subchannel = 1; break;
        case 0x06: channel.type = 4; channel.subchannel = 2; break;
        case 0x07: channel.type = 4; channel.subchannel = 3; break;
        case 0x08: channel.type = 8; channel.subchannel = 0; break;
        case 0x09: channel.type = 8; channel.subchannel = 1; break;
        case 0x0a: channel.type = 8; channel.subchannel = 2; break;
        case 0x0b: channel.type = 8; channel.subchannel = 3; break;
        case 0x0c: channel.type = 8; channel.subchannel = 4; break;
        case 0x0d: channel.type = 8; channel.subchannel = 5; break;
        case 0x0e: channel.type = 8; channel.subchannel = 6; break;
        case 0x0f: channel.type = 8; channel.subchannel = 7; break;
        case 0x10: channel.type = 0x10; channel.subchannel = 0; break;
        case 0x11: channel.type = 0x11; channel.subchannel = 0; break;
        case 0x12: channel.type = 0x12; channel.subchannel = 0; break;
        default:
#if GSM_DBG_UNK == 1
            GSM_DBG("%" PRIu64 ": Unknown channel number 0x%02" B2T_PRIX8, numPackets, c_bits);
#endif
            channel.type = c_bits;
            channel.subchannel = 0;
            break;
    }

    channel.str = channel_to_str(&channel);
    GSM_DBG("%" PRIu64 ": channel number %s", numPackets, channel.str);

    return channel;
}


static inline bool t2buf_dissect_rsl_ie_link_identifier(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory) {
    uint8_t ie;

    if (!mandatory) {
        if (!t2buf_peek_u8(t2buf, &ie) || ie != 0x02) return false;
    }

    if (!t2buf_read_u8(t2buf, &ie)) return false;
    if (ie != 0x02) {
        GSM_DBG_RSL("%" PRIu64 ": Link Identifier IE 0x02 expected, found 0x%02" B2T_PRIX8, numPackets, ie);
        gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
    }

    uint8_t linkID;
    if (!t2buf_read_u8(t2buf, &linkID)) return false;

    if ((linkID & 0x20) == 0x20) {
        // Link Identifier not applicable for this message
        return false;
    }

    const uint8_t priority = ((linkID & 0x18) >> 3);
    const uint8_t sapi = (linkID & 0x07);
    const uint8_t c_bits = ((linkID & 0xc0) >> 6);

    const char * const rsl_priority_str[] = {
        "Normal",
        "High",
        "Low",
        "???"
    };

    switch (c_bits) {
        case 0x00:
            GSM_DBG_RSL("%" PRIu64 ": Link Identifier IE: Main signalling channel (FACCH or SDCCH), SAPI: %" PRIu8 ", Priority: %" PRIu8 " (%s)",
                    numPackets, sapi, priority, rsl_priority_str[priority]);
            break;
        case 0x01:
            GSM_DBG_RSL("%" PRIu64 ": Link Identifier IE: SACCH, SAPI: %" PRIu8 ", Priority: %" PRIu8 " (%s)",
                    numPackets, sapi, priority, rsl_priority_str[priority]);
            break;
        default:
#if GSM_DBG_RSL_UNK == 1
            GSM_DBG_RSL("%" PRIu64 ": Link Identifier IE: Unknown link ID 0x%02" B2T_PRIX8 ", SAPI: %" PRIu8 ", Priority: %" PRIu8 " (%s)",
                    numPackets, c_bits, sapi, priority, rsl_priority_str[priority]);
#endif
            break;
    }

    switch (sapi) {
        case 0: // Signalling
            GSM_DBG_RSL("%" PRIu64 ": Link Identifier IE: SAPI 0: Signalling", numPackets);
            break;
        case 3: // SMS
            GSM_DBG_RSL("%" PRIu64 ": Link Identifier IE: SAPI 3: SMS", numPackets);
            break;
        default:
#if GSM_DBG_RSL_UNK == 1
            GSM_DBG_RSL("%" PRIu64 ": Link Identifier IE: Unknown SAPI %" PRIu8 "", numPackets, sapi);
#endif
            gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
            break;
    }

    return true;
}


static inline bool t2buf_dissect_rsl_ie_l3_info(t2buf_t *t2buf, bool mandatory, uint8_t type, gsm_metadata_t *md) {
    uint8_t ie;

    if (!mandatory) {
        if (!t2buf_peek_u8(t2buf, &ie) || ie != 0x0b) return false;
    }

    if (!t2buf_read_u8(t2buf, &ie)) return false;
    if (ie != 0x0b) {
        GSM_DBG_RSL("%" PRIu64 ": L3 Information IE 0x0b expected, found 0x%02" B2T_PRIX8, numPackets, ie);
        md->gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
    }

    uint16_t len;
    if (!t2buf_read_u16(t2buf, &len)) return false;
    // TODO
//    if (len != pktlen - t2buf_tell(t2buf)) {
//#if GSM_DBG_RSL_UNK == 1
//        GSM_DBG_RSL("%" PRIu64 ": Byte %lu is not the PDU length: 0x%02" B2T_PRIX8, numPackets, t2buf_tell(t2buf), len);
//#endif
//        gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
//        return false;
//    }

    GSM_DBG_RSL("%" PRIu64 ": L3 Information IE", numPackets);

    if (type == 2) { // CCCH
        // TODO t2buf_dissect_gsm_a_ccch()
        t2buf_skip_n(t2buf, len);
    } else if (type == 1) { // SACCH
        // TODO t2buf_dissect_gsm_a_sacch()
        t2buf_skip_n(t2buf, len);
    } else { // DTAP
        return dissect_gsm_a_dtap(t2buf, md);
    }

    return true;
}


static inline bool t2buf_dissect_rsl_ie_rlm_cause(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory) {
    uint8_t ie;

    if (!mandatory) {
        if (!t2buf_peek_u8(t2buf, &ie) || ie != 0x16) return false;
    }

    if (!t2buf_read_u8(t2buf, &ie)) return false;
    if (ie != 0x16) {
        GSM_DBG_RSL("%" PRIu64 ": RLM Cause IE 0x16 expected, found 0x%02" B2T_PRIX8, numPackets, ie);
        gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
    }

    uint8_t len;
    if (!t2buf_read_u8(t2buf, &len)) return false;

    GSM_DBG_RSL("%" PRIu64 ": RLM Cause IE", numPackets);

    return t2buf_skip_n(t2buf, len);
}


static inline bool t2buf_dissect_rsl_ie_release_mode(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory) {
    uint8_t ie;

    if (!mandatory) {
        if (!t2buf_peek_u8(t2buf, &ie) || ie != 0x14) return false;
    }

    if (!t2buf_read_u8(t2buf, &ie)) return false;
    if (ie != 0x14) {
        GSM_DBG_RSL("%" PRIu64 ": Release Mode IE 0x14 expected, found 0x%02" B2T_PRIX8, numPackets, ie);
        gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
    }

    /* Release Mode */
    uint8_t mode;
    if (!t2buf_read_u8(t2buf, &mode)) return false;

    // Release Mode & 0x01 (0: normal release, 1: local end release), & 0xfe: reserved
    const uint8_t m_bit = (mode & 0x01);

    GSM_DBG_RSL("%" PRIu64 ": Release Mode: %" PRIu8 " (%s release)", numPackets, mode, ((m_bit == 0) ? "normal" : "local end"));

    return true;
}


static inline bool t2buf_dissect_rsl_ie_system_info_type(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory, uint8_t *type) {
    uint8_t ie;

    if (!mandatory) {
        if (!t2buf_peek_u8(t2buf, &ie) || ie != 0x1e) {
            *type = 0xff;
            return false;
        }
    }

    if (!t2buf_read_u8(t2buf, &ie)) return false;
    if (ie != 0x1e) {
        GSM_DBG_RSL("%" PRIu64 ": System Info Type IE 0x1e expected, found 0x%02" B2T_PRIX8, numPackets, ie);
        gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
    }

    if (!t2buf_read_u8(t2buf, type)) {
        GSM_DBG_RSL("%" PRIu64 ": System Info Type IE", numPackets);
        return false;
    }

    GSM_DBG_RSL("%" PRIu64 ": System Info Type IE: 0x%02" B2T_PRIX8, numPackets, *type);

    return true;
}


static inline bool t2buf_dissect_rsl_ie_full_bcch_info(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory) {
    uint8_t ie;

    if (!mandatory) {
        if (!t2buf_peek_u8(t2buf, &ie) || ie != 0x27) return false;
    }

    if (!t2buf_read_u8(t2buf, &ie)) return false;
    if (ie != 0x27) {
        GSM_DBG_RSL("%" PRIu64 ": Full BCCH Information IE 0x27 expected, found 0x%02" B2T_PRIX8, numPackets, ie);
        gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
    }

    uint8_t len;
    if (!t2buf_read_u8(t2buf, &len)) return false;

    GSM_DBG_RSL("%" PRIu64 ": Full BCCH Information", numPackets);

    return t2buf_skip_n(t2buf, len);
    // TODO return t2buf_dissect_gsm_a_ccch()
}


static inline bool t2buf_dissect_rsl_ie_starting_time(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory) {
    uint8_t ie;

    if (!mandatory) {
        if (!t2buf_peek_u8(t2buf, &ie) || ie != 0x17) return false;
    }

    if (!t2buf_read_u8(t2buf, &ie)) return false;
    if (ie != 0x17) {
        GSM_DBG_RSL("%" PRIu64 ": Starting Time IE 0x17 expected, found 0x%02" B2T_PRIX8, numPackets, ie);
        gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
    }

    // absolute frame number (FN) module 42432
    uint8_t octet2;
    uint8_t octet3;
    if (!t2buf_read_u8(t2buf, &octet2) ||
        !t2buf_read_u8(t2buf, &octet3))
    {
        return false;
    }

    const uint8_t t1 = ((octet2 & 0xf8) >> 3);
    const uint8_t t3_high = (octet2 & 0x07);
    const uint8_t t3_low = ((octet3 & 0xe0) >> 5);
    const uint8_t t2 = (octet3 & 0x1f);
    const uint16_t t3 = ((t3_high << 3) | t3_low);
    int16_t t = (t3 - t2) % 26;
    if (t < 0) t += 26;
    const uint16_t st = 51 * t + t3 + 51 * 26 * t1;

    GSM_DBG_RSL("%" PRIu64 ": Starting Time: T1': %" PRIu8 ", T2: %" PRIu8 ", T3: %" PRIu16 " => ST: %" PRIu16, numPackets, t1, t2, t3, st);

    return true;
}


static inline bool t2buf_dissect_rsl_ie_rach_load(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory) {
    uint8_t ie;

    if (!mandatory) {
        if (!t2buf_peek_u8(t2buf, &ie) || ie != 0x12) return false;
    }

    if (!t2buf_read_u8(t2buf, &ie)) return false;
    if (ie != 0x12) {
        GSM_DBG_RSL("%" PRIu64 ": RACH Load IE 0x12 expected, found 0x%02" B2T_PRIX8, numPackets, ie);
        gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
    }

    uint8_t len;
    if (!t2buf_read_u8(t2buf, &len)) return false;

    GSM_DBG_RSL("%" PRIu64 ": RACH Load IE", numPackets);

    return t2buf_skip_n(t2buf, len);
}


static inline bool t2buf_dissect_rsl_ie_paging_load(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory) {
    uint8_t ie;

    if (!mandatory) {
        if (!t2buf_peek_u8(t2buf, &ie) || ie != 0x0f) return false;
    }

    if (!t2buf_read_u8(t2buf, &ie)) return false;
    if (ie != 0x0f) {
        GSM_DBG_RSL("%" PRIu64 ": Paging Load IE 0x0f expected, found 0x%02" B2T_PRIX8, numPackets, ie);
        gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
    }

    /* Paging Buffer Space */
    uint16_t space;
    if (!t2buf_read_u16(t2buf, &space)) {
        GSM_DBG_RSL("%" PRIu64 ": Paging Load IE", numPackets);
        return false;
    }

    GSM_DBG_RSL("%" PRIu64 ": Paging Load IE: %" PRIu16, numPackets, space);

    return true;
}


static inline bool t2buf_dissect_rsl_ie_request_reference(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory, gsm_request_reference_t *ref) {
    uint8_t ie;

    if (!mandatory) {
        if (!t2buf_peek_u8(t2buf, &ie) || ie != 0x13) return false;
    }

    if (!t2buf_read_u8(t2buf, &ie)) return false;
    if (ie != 0x13) {
        GSM_DBG_RSL("%" PRIu64 ": Request Reference IE 0x13 expected, found 0x%02" B2T_PRIX8, numPackets, ie);
        gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
    }

    GSM_DBG_RSL("%" PRIu64 ": Request Reference IE", numPackets);

    return t2buf_read_request_reference(t2buf, ref);
}


static inline bool t2buf_dissect_rsl_ie_access_delay(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory) {
    uint8_t ie;

    if (!mandatory) {
        if (!t2buf_peek_u8(t2buf, &ie) || ie != 0x11) return false;
    }

    if (!t2buf_read_u8(t2buf, &ie))  return false;
    if (ie != 0x11) {
        GSM_DBG_RSL("%" PRIu64 ": Access Delay IE 0x11 expected, found 0x%02" B2T_PRIX8, numPackets, ie);
        gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
    }

    uint8_t delay;
    if (!t2buf_read_u8(t2buf, &delay)) {
        GSM_DBG_RSL("%" PRIu64 ": Access Delay IE", numPackets);
        return false;
    }

    GSM_DBG_RSL("%" PRIu64 ": Access Delay IE: %" PRIu8, numPackets, delay);

    return true;
}


static inline bool t2buf_dissect_rsl_ie_physical_context(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory) {
    uint8_t ie;

    if (!mandatory) {
        if (!t2buf_peek_u8(t2buf, &ie) || ie != 0x10) return false;
    }

    if (!t2buf_read_u8(t2buf, &ie)) return false;
    if (ie != 0x10) {
        GSM_DBG_RSL("%" PRIu64 ": Physical Context IE 0x10 expected, found 0x%02" B2T_PRIX8, numPackets, ie);
        gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
    }

    uint8_t len;
    if (!t2buf_read_u8(t2buf, &len)) return false;

    GSM_DBG_RSL("%" PRIu64 ": Physical Context IE", numPackets);

    return t2buf_skip_n(t2buf, len); // Physical Context Information
}


static inline bool t2buf_dissect_rsl_ie_full_immediate_assign_info(t2buf_t *t2buf, bool mandatory, gsm_metadata_t *md) {
    uint8_t ie;

    if (!mandatory) {
        if (!t2buf_peek_u8(t2buf, &ie) || ie != 0x2b) return false;
    }

    if (!t2buf_read_u8(t2buf, &ie)) return false;
    if (ie != 0x2b) {
        GSM_DBG_RSL("%" PRIu64 ": Full Immediate Assign Info IE 0x2b expected, found 0x%02" B2T_PRIX8, numPackets, ie);
        md->gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
    }

    uint8_t len;
    if (!t2buf_read_u8(t2buf, &len)) return false;

    if (!t2buf_skip_u8(t2buf)) return false; // L2 Pseudo Length

    GSM_DBG_RSL("%" PRIu64 ": Full Immediate Assign Info IE", numPackets);

    return dissect_gsm_a_dtap(t2buf, md);
}


static inline bool t2buf_dissect_rsl_ie_paging_group(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory) {
    uint8_t ie;

    if (!mandatory) {
        if (!t2buf_peek_u8(t2buf, &ie) || ie != 0x0e) return false;
    }

    if (!t2buf_read_u8(t2buf, &ie)) return false;
    if (ie != 0x0e) {
        GSM_DBG_RSL("%" PRIu64 ": Paging Group IE 0x0e expected, found 0x%02" B2T_PRIX8, numPackets, ie);
        gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
    }

    uint8_t group;
    if (!t2buf_read_u8(t2buf, &group)) {
        GSM_DBG_RSL("%" PRIu64 ": Paging Group IE", numPackets);
        return false;
    }

    GSM_DBG_RSL("%" PRIu64 ": Paging Group IE: 0x%02" B2T_PRIX8, numPackets, group);

    return true;
}


static inline bool t2buf_dissect_rsl_ie_ms_identity(t2buf_t *t2buf, bool mandatory, gsm_metadata_t *md) {
    uint8_t ie;

    if (!mandatory) {
        if (!t2buf_peek_u8(t2buf, &ie) || ie != 0x0c) return false;
    }

    if (!t2buf_read_u8(t2buf, &ie)) return false;
    if (ie != 0x0c) {
        GSM_DBG_RSL("%" PRIu64 ": MS Identity IE 0x0c expected, found 0x%02" B2T_PRIX8, numPackets, ie);
        md->gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
    }

    gsmMobileIdentity_t id = t2buf_read_mobile_identity(t2buf, md);
    gsm_mobile_identity_free(&id);

    return true;
}


static inline bool t2buf_dissect_rsl_ie_channel_needed(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory) {
    uint8_t ie;

    if (!mandatory) {
        if (!t2buf_peek_u8(t2buf, &ie) || ie != 0x28) return false;
    }

    if (!t2buf_read_u8(t2buf, &ie)) return false;
    if (ie != 0x28) {
        GSM_DBG_RSL("%" PRIu64 ": Channel Needed IE 0x28 expected, found 0x%02" B2T_PRIX8, numPackets, ie);
        gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
    }

    uint8_t channel;
    if (!t2buf_read_u8(t2buf, &channel)) return false;

    // & 0x03: Channel, & 0xfc: reserved
    channel &= 0x03;

    char *c_str = NULL;
    switch (channel) {
        case 0x00:
            c_str = "Any Channel";
            break;
        case 0x01:
            c_str = "SDCCH";
            break;
        case 0x02:
            c_str = "TCH/F (Full rate)";
            break;
        case 0x03:
            c_str = "TCH/F or TCH/H (Dual rate)";
            break;
        default:
            // Should not happen...
            c_str = "N/A";
            break;
    }

    GSM_DBG_RSL("%" PRIu64 ": MS Channel Needed IE: %s", numPackets, c_str);

    return true;
}


static inline bool t2buf_dissect_rsl_ie_emlpp_priority(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory) {
    uint8_t ie;

    if (!mandatory) {
        if (!t2buf_peek_u8(t2buf, &ie) || ie != 0x33) return false;
    }

    if (!t2buf_read_u8(t2buf, &ie)) return false;
    if (ie != 0x33) {
        GSM_DBG_RSL("%" PRIu64 ": eMLPP Priority IE 0x33 expected, found 0x%02" B2T_PRIX8, numPackets, ie);
        gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
    }

    uint8_t priority;
    if (!t2buf_read_u8(t2buf, &priority)) return false;

    // priority & 0x07, & 0xf8 reserved
    priority &= 0x07;

    const char * const priority_str[] = {
        "no priority applied",
        "call priority level 4",
        "call priority level 3",
        "call priority level 2",
        "call priority level 1",
        "call priority level 0",
        "call priority level B",
        "call priority level A",
    };

    GSM_DBG_RSL("%" PRIu64 ": eMLPP Priority IE: %" PRIu8 " (%s)", numPackets, priority, priority_str[priority]);

    return true;
}


static inline bool t2buf_dissect_rsl_ie_smscb_info(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory) {
    uint8_t ie;

    if (!mandatory) {
        if (!t2buf_peek_u8(t2buf, &ie) || ie != 0x24) return false;
    }

    if (!t2buf_read_u8(t2buf, &ie)) return false;
    if (ie != 0x24) {
        GSM_DBG_RSL("%" PRIu64 ": SMSCB Information IE 0x24 expected, found 0x%02" B2T_PRIX8, numPackets, ie);
        gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
    }

    uint8_t len;
    if (!t2buf_read_u8(t2buf, &len)) return false;

    GSM_DBG_RSL("%" PRIu64 ": SMSCB Information IE", numPackets);

    return t2buf_skip_n(t2buf, len);
}


static inline bool t2buf_dissect_rsl_ie_smscb_message(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory) {
    uint8_t ie;

    if (!mandatory) {
        if (!t2buf_peek_u8(t2buf, &ie) || ie != 0x2a) return false;
    }

    if (!t2buf_read_u8(t2buf, &ie)) return false;
    if (ie != 0x2a) {
        GSM_DBG_RSL("%" PRIu64 ": SMSCB Message IE 0x2a expected, found 0x%02" B2T_PRIX8, numPackets, ie);
        gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
    }

    uint8_t len;
    if (!t2buf_read_u8(t2buf, &len)) return false;

    GSM_DBG_RSL("%" PRIu64 ": SMSCB Message IE", numPackets);

    return t2buf_skip_n(t2buf, len);
}


static inline bool t2buf_dissect_rsl_ie_smscb_channel_indicator(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory) {
    uint8_t ie;

    if (!mandatory) {
        if (!t2buf_peek_u8(t2buf, &ie) || ie != 0x2e) return false;
    }

    if (!t2buf_read_u8(t2buf, &ie)) return false;
    if (ie != 0x2e) {
        GSM_DBG_RSL("%" PRIu64 ": SMSCB Channel Indicator IE 0x2e expected, found 0x%02" B2T_PRIX8, numPackets, ie);
        gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
    }

    uint8_t octet;
    if (!t2buf_read_u8(t2buf, &octet)) return false;

    octet &= 0x0f; // & 0xf0 reserved

    switch (octet) {
        case 0x00:
            GSM_DBG_RSL("%" PRIu64 ": SMSCB Channel Indicator IE: Basic CBCH", numPackets);
            break;
        case 0x01:
            GSM_DBG_RSL("%" PRIu64 ": SMSCB Channel Indicator IE: Extended CBCH", numPackets);
            break;
        default:
#if GSM_DBG_RSL_UNK == 1
            GSM_DBG_RSL("%" PRIu64 ": SMSCB Channel Indicator IE: 0x%02" B2T_PRIX8 " (Reserved)", numPackets, octet);
#endif
            break;
    }

    return true;
}


static inline bool t2buf_dissect_rsl_ie_resource_info(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory) {
    uint8_t ie;

    if (!mandatory) {
        if (!t2buf_peek_u8(t2buf, &ie) || ie != 0x15) return false;
    }

    if (!t2buf_read_u8(t2buf, &ie)) return false;
    if (ie != 0x15) {
        GSM_DBG_RSL("%" PRIu64 ": Resource Information IE 0x15 expected, found 0x%02" B2T_PRIX8, numPackets, ie);
        gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
    }

    uint8_t len;
    if (!t2buf_read_u8(t2buf, &len)) return false;

    GSM_DBG_RSL("%" PRIu64 ": Resource Information IE", numPackets);

    while (len > 0 && t2buf_left(t2buf) > 0) {
        gsmChannel_t channel = t2buf_dissect_rsl_channel_number(t2buf, gsmFlowP);
        gsm_channel_free(&channel);
        t2buf_skip_u8(t2buf); // Interference Band (& 0xe0), Interference Band reserved bits (& 0x1f)
        len -= 2;
    }

    return true;
}


static inline bool t2buf_dissect_rsl_ie_cause(t2buf_t *t2buf, bool mandatory, gsm_metadata_t *md) {
    uint8_t ie;

    if (!mandatory) {
        if (!t2buf_peek_u8(t2buf, &ie) || ie != 0x1a) return false;
    }

    if (!t2buf_read_u8(t2buf, &ie)) return false;
    if (ie != 0x1a) {
        GSM_DBG_RSL("%" PRIu64 ": Cause IE 0x1a expected, found 0x%02" B2T_PRIX8, numPackets, ie);
        md->gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
    }

    uint8_t len;
    if (!t2buf_read_u8(t2buf, &len)) return false;

    if (!t2buf_read_u8(t2buf, &md->rsl.cause)) return false;

    const char * const class_str[] = {
        "Normal event",
        "Normal event",
        "Resource unavailable",
        "Service or option not available",
        "Service or option not implemented",
        "Invalid message (e.g., parameter out of range)",
        "Protocol error",
        "Interworking"
    };

    if ((md->rsl.cause & 0x80) == 0x80) {
        GSM_DBG_RSL("%" PRIu64 ": Cause IE: cause extension", numPackets);
        return t2buf_skip_u8(t2buf); // Cause Extension
    } else {
        const uint8_t class = ((md->rsl.cause & 0x70) >> 4);
        const uint8_t cause_value = (md->rsl.cause & 0x7f);
        GSM_DBG_RSL("%" PRIu64 ": Cause IE: class: %" PRIu8 " (%s), cause value: 0x%02" B2T_PRIX8, numPackets, class, class_str[class], cause_value);
        return true;
    }
}


static inline bool t2buf_dissect_rsl_ie_message_identifier(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory) {
    uint8_t ie;

    if (!mandatory) {
        if (!t2buf_peek_u8(t2buf, &ie) || ie != 0x1c) return false;
    }

    if (!t2buf_read_u8(t2buf, &ie)) return false;
    if (ie != 0x1c) {
        GSM_DBG_RSL("%" PRIu64 ": Message Identifier IE 0x1c expected, found 0x%02" B2T_PRIX8, numPackets, ie);
        gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
    }

    /* message type */
    uint8_t type;
    if (!t2buf_read_u8(t2buf, &type)) return false;

    type &= 0x7f;

#if GSM_DEBUG_RSL == 1
    const char *type_str = ((type < 0x37) ? msg_type_str[type][1] : "unknown");
    GSM_DBG_RSL("%" PRIu64 ": Message Identifier IE: 0x%02" B2T_PRIX8 " (%s)", numPackets, type, type_str);
#endif

    return true;
}


static inline bool t2buf_dissect_rsl_ie_erroneous_message(t2buf_t *t2buf, bool mandatory, gsm_metadata_t *md) {
    uint8_t ie;

    if (!mandatory) {
        if (!t2buf_peek_u8(t2buf, &ie) || ie != 0x26) return false;
    }

    if (!t2buf_read_u8(t2buf, &ie)) return false;
    if (ie != 0x26) {
        GSM_DBG_RSL("%" PRIu64 ": Erroneous Message IE 0x26 expected, found 0x%02" B2T_PRIX8, numPackets, ie);
        md->gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
    }

    uint8_t len;
    if (!t2buf_read_u8(t2buf, &len)) return false;

    GSM_DBG_RSL("%" PRIu64 ": Erroneous Message IE", numPackets);

    return dissect_gsm_abis_rsl(t2buf, md);
}


static inline bool t2buf_dissect_rsl_ie_cb_command_type(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory) {
    uint8_t ie;

    if (!mandatory) {
        if (!t2buf_peek_u8(t2buf, &ie) || ie != 0x29) return false;
    }

    if (!t2buf_read_u8(t2buf, &ie)) return false;
    if (ie != 0x29) {
        GSM_DBG_RSL("%" PRIu64 ": CB Command Type IE 0x29 expected, found 0x%02" B2T_PRIX8, numPackets, ie);
        gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
    }

    uint8_t octet;
    if (!t2buf_read_u8(t2buf, &octet)) return false;

    const uint8_t command = ((octet & 0xf0) >> 4);

    const uint8_t default_broadcast = ((octet & 0x08) >> 3);
    const char * const default_broadcast_str[] = {
        "Normal Message",
        "Null Message"
    };
    // bit 3 is reserved
    const uint8_t last_block = (octet & 0x03);
    const char * const last_block_str[] = {
        "Block 4/4",
        "Block 1/4",
        "Block 2/4",
        "Block 3/4"
    };

    switch (command) {
        case 0x00:
            GSM_DBG_RSL("%" PRIu64 ": CB Command type IE: Normal Message Broadcast, %s, %s",
                    numPackets, default_broadcast_str[default_broadcast], last_block_str[last_block]);
            break;
        case 0x08:
            GSM_DBG_RSL("%" PRIu64 ": CB Command type IE: Schedule Message Broadcast, %s, %s",
                    numPackets, default_broadcast_str[default_broadcast], last_block_str[last_block]);
            break;
        case 0x0e:
            GSM_DBG_RSL("%" PRIu64 ": CB Command type IE: Default Message Broadcast, %s, %s",
                    numPackets, default_broadcast_str[default_broadcast], last_block_str[last_block]);
            break;
        case 0x0f:
            GSM_DBG_RSL("%" PRIu64 ": CB Command type IE: Null Message Broadcast, %s, %s",
                    numPackets, default_broadcast_str[default_broadcast], last_block_str[last_block]);
            break;
        default:
#if GSM_DBG_RSL_UNK == 1
            GSM_DBG_RSL("%" PRIu64 ": CB Command type IE: Unknown command 0x%02" B2T_PRIX8 ", %s, %s",
                    numPackets, command, default_broadcast_str[default_broadcast], last_block_str[last_block]);
#endif
            break;
    }

    return true;
}


static inline bool t2buf_dissect_rsl_ie_cbch_load_information(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory) {
    uint8_t ie;

    if (!mandatory) {
        if (!t2buf_peek_u8(t2buf, &ie) || ie != 0x2d) return false;
    }

    if (!t2buf_read_u8(t2buf, &ie)) return false;
    if (ie != 0x2d) {
        GSM_DBG_RSL("%" PRIu64 ": CBCH Load Information IE 0x2d expected, found 0x%02" B2T_PRIX8, numPackets, ie);
        gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
    }

    uint8_t octet;
    if (!t2buf_read_u8(t2buf, &octet)) return false;

    const uint8_t load_type = ((octet & 0x80) >> 7); // 0: underflow, 1: overflow
    // bits 7,6,5 are reserved
    const uint8_t message_slot_count = (octet & 0x0f);

    if (load_type == 0) {
        GSM_DBG_RSL("%" PRIu64 ": CBCH Load Information IE: Amount of delay in message slots (1 to 15) that is needed immediately by BTS: %" PRIu8, numPackets, message_slot_count);
    } else {
        GSM_DBG_RSL("%" PRIu64 ": CBCH Load Information IE: Amount of SMSCB messages (1 to 15) that are needed immediately by BTS: %" PRIu8, numPackets, message_slot_count);
    }

    return true;
}


static inline bool t2buf_dissect_rsl_ie_command_indicator(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory) {
    uint8_t ie;

    if (!mandatory) {
        if (!t2buf_peek_u8(t2buf, &ie) || ie != 0x32) return false;
    }

    if (!t2buf_read_u8(t2buf, &ie)) return false;
    if (ie != 0x32) {
        GSM_DBG_RSL("%" PRIu64 ": Command Indicator IE 0x32 expected, found 0x%02" B2T_PRIX8, numPackets, ie);
        gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
    }

    uint8_t octet;
    if (!t2buf_peek_u8(t2buf, &octet)) return false;

    if ((octet & 0x80) == 0x80) {
        // Command Extension
        uint16_t cmd;
        if (!t2buf_read_u16(t2buf, &cmd)) return false;
        GSM_DBG_RSL("%" PRIu64 ": Command Indicator IE: 0x%04" B2T_PRIX16, numPackets, cmd);
    } else {
        uint8_t cmd;
        t2buf_read_u8(t2buf, &cmd); // We know this byte exists as we peeked it
        GSM_DBG_RSL("%" PRIu64 ": Command Indicator IE: 0x%02" B2T_PRIX8, numPackets, cmd);
    }

    return true;
}


static inline bool t2buf_dissect_rsl_ie_group_call_reference(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory) {
    uint8_t ie;

    if (!mandatory) {
        if (!t2buf_peek_u8(t2buf, &ie) || ie != 0x2f) return false;
    }

    if (!t2buf_read_u8(t2buf, &ie)) return false;
    if (ie != 0x2f) {
        GSM_DBG_RSL("%" PRIu64 ": Group Call Reference IE 0x2f expected, found 0x%02" B2T_PRIX8, numPackets, ie);
        gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
    }

    uint8_t len;
    if (!t2buf_read_u8(t2buf, &len)) return false;

    GSM_DBG_RSL("%" PRIu64 ": Group Call Reference IE", numPackets);

    return t2buf_skip_n(t2buf, len);
}


static inline bool t2buf_dissect_rsl_ie_channel_description(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory) {
    uint8_t ie;

    if (!mandatory) {
        if (!t2buf_peek_u8(t2buf, &ie) || ie != 0x30) return false;
    }

    if (!t2buf_read_u8(t2buf, &ie)) return false;
    if (ie != 0x30) {
        GSM_DBG_RSL("%" PRIu64 ": Channel Description IE 0x30 expected, found 0x%02" B2T_PRIX8, numPackets, ie);
        gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
    }

    /* Group Channel Description */
    uint8_t len;
    if (!t2buf_read_u8(t2buf, &len)) return false;

    GSM_DBG_RSL("%" PRIu64 ": Channel Description IE", numPackets);

    return t2buf_skip_n(t2buf, len);
}


static inline bool t2buf_dissect_rsl_ie_nch_drx_info(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory) {
    uint8_t ie;

    if (!mandatory) {
        if (!t2buf_peek_u8(t2buf, &ie) || ie != 0x31) return false;
    }

    if (!t2buf_read_u8(t2buf, &ie)) return false;
    if (ie != 0x31) {
        GSM_DBG_RSL("%" PRIu64 ": NCH DRX Information IE 0x31 expected, found 0x%02" B2T_PRIX8, numPackets, ie);
        gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
    }

    uint8_t len;
    if (!t2buf_read_u8(t2buf, &len)) return false;

    GSM_DBG_RSL("%" PRIu64 ": NCH DRX Information IE", numPackets);

    return t2buf_skip_n(t2buf, len);
}


static inline bool t2buf_dissect_rsl_ie_activation_type(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory) {
    uint8_t ie;

    if (!mandatory) {
        if (!t2buf_peek_u8(t2buf, &ie) || ie != 0x03) return false;
    }

    if (!t2buf_read_u8(t2buf, &ie)) return false;
    if (ie != 0x03) {
        GSM_DBG_RSL("%" PRIu64 ": Activation Type IE 0x03 expected, found 0x%02" B2T_PRIX8, numPackets, ie);
        gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
    }

    uint8_t type;
    if (!t2buf_read_u8(t2buf, &type)) return false;

    const uint8_t r_bit = ((type & 0x80) >> 7); // 0: initial activation, 1: reactivation
    const uint8_t a3a2 = ((type & 0x06) >> 1);
    const uint8_t a1 = (type & 0x01);

    const char *a3a2_str;
    const char *a1_str;
    switch (a3a2) {
        case 0:
            a3a2_str = "Activation related to intra-cell channel change";
            if (a1 == 0) {
                a1_str = "related to immediate assignment procedure";
            } else {
                a1_str = "related to normal assignment procedure";
            }
            break;
        case 1:
            a3a2_str = "Activation related to intra-cell channel change (handover)";
            if (a1 == 0) {
                a1_str = "related to asynchronous handover procedure";
            } else {
                a1_str = "related to synchronous handover procedure";
            }
            break;
        case 2:
            a3a2_str = "Activation related to secondary channels";
            if (a1 == 0) {
                a1_str = "related to additional assignment procedure";
            } else {
                a1_str = "related to multislot configuration";
            }
            break;
        case 3:
            a3a2_str = "Activation related to packet data channel (Ericsson)";
            a1_str = "";
            break;
        default:
            a1_str = "";
            a3a2_str = "";
            break;
    }

    GSM_DBG_RSL("%" PRIu64 ": Activation Type IE: %s, %s %s", numPackets, ((r_bit == 0) ? "Initial activation" : "Reactivation"), a3a2_str, a1_str);

    return true;
}


static inline bool t2buf_dissect_rsl_ie_channel_mode(t2buf_t *t2buf, bool mandatory, gsm_metadata_t *md) {
    uint8_t ie;

    if (!mandatory) {
        if (!t2buf_peek_u8(t2buf, &ie) || ie != 0x06) return false;
    }

    if (!t2buf_read_u8(t2buf, &ie)) return false;
    if (ie != 0x06) {
        GSM_DBG_RSL("%" PRIu64 ": Channel Mode IE 0x06 expected, found 0x%02" B2T_PRIX8, numPackets, ie);
        md->gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
    }

    uint8_t len;
    if (!t2buf_read_u8(t2buf, &len)) return false;

    uint8_t flags;
    if (!t2buf_read_u8(t2buf, &flags)) return false;

    // DTXd (& 0x02), DTXu (& 0x01)
#if GSM_DEBUG_RSL == 1
    const bool dtxd = ((flags & 0x02) >> 1);
    const bool dtxu = (flags & 0x01);
#endif

    /* Speech or data indicator */
    uint8_t speech_or_data;
    if (!t2buf_read_u8(t2buf, &speech_or_data)) return false;
    md->rsl.speech_or_data = speech_or_data;

    md->rsl.amr = false;

    /* Channel rate and type */
    uint8_t rate_and_type;
    if (!t2buf_read_u8(t2buf, &rate_and_type)) return false;
    md->rsl.rate_and_type = rate_and_type;

    /* Speech coding algorithm / data rate + transparent indicator */
    uint8_t octet6;
    if (!t2buf_read_u8(t2buf, &octet6)) return false;

    char *chann = NULL;
    switch (rate_and_type) {
        case 0x01:
            chann = "SDCCH";
            break;
        case 0x08:
            chann = "Full rate TCH channel Bm";
            break;
        case 0x09:
            chann = "Half rate TCH channel Lm";
            break;
        case 0x0a:
            chann = "Full rate TCH channel bi-directional Bm, Multislot configuration";
            break;
        case 0x18:
            chann = "Full rate TCH channel Bm Group call channel";
            break;
        case 0x19:
            chann = "Half rate TCH channel Lm Group call channel";
            break;
        case 0x1a:
            chann = "Full rate TCH channel uni-directional downlink Bm, Multislot configuration";
            break;
        case 0x28:
            chann = "Full rate TCH channel Bm Broadcast call channel";
            break;
        case 0x29:
            chann = "Half rate TCH channel Lm Broadcast call channel";
            break;
        default:
#if GSM_DBG_RSL_UNK == 1
            GSM_DBG_RSL("%" PRIu64 ": Unknown channel rate and type: 0x%02" B2T_PRIX8, numPackets, rate_and_type);
#endif
            break;
    }

    char *channel_content = NULL;
    switch (speech_or_data) {
        case 0x01: {
            /* Speech coding algorithm */
            switch (octet6) {
                case 0x01: // GSM speech coding algorithm version 1: GSM FR or GSM HR
                    channel_content = strdup("Speech (GSM FR or GSM HR)");
                    break;
                case 0x11: // GSM speech coding algorithm version 2: GSM EFR
                    channel_content = strdup("Speech (GSM EFR)");
                    break;
                case 0x21: // GSM speech coding algorithm version 3: FR AMR or HR AMR
                    channel_content = strdup("Speech (FR AMR or HR AMR)");
                    md->rsl.amr = true;
                    break;
                case 0x31: // GSM speech coding algorithm version 4: OFR AMR-WB or OHR AMR-WB
                    channel_content = strdup("Speech (OFR AMR-WB or OHR AMR-WB)");
                    md->rsl.amr = true;
                    break;
                case 0x09: // GSM speech coding algorithm version 5: FR AMR-WB
                    channel_content = strdup("Speech (FR AMR-WB)");
                    md->rsl.amr = true;
                    break;
                case 0x0d: // GSM speech coding algorithm version 5: OHR AMR
                    channel_content = strdup("Speech (OHR AMR)");
                    md->rsl.amr = true;
                    break;
                default:
                    channel_content = strdup("Speech");
#if GSM_DBG_RSL_UNK == 1
                    GSM_DBG_RSL("%" PRIu64 ": Speech: unknown coding algorithm: 0x%02" B2T_PRIX8, numPackets, octet6);
#endif
                    break;
            }
            break;
        }
        case 0x02: {
            //const uint8_t ext = ((octet6 & 0x80) >> 7); // Reserved for extension
            const uint8_t non_transparent = ((octet6 & 0x40) >> 6); // 0: transparent service, 1: non-transparent service
            const uint8_t rate = (octet6 & 0x3f);
            switch (rate) {
                case 0x21: channel_content = strdup("Data (asymmetric 43.5 kbit/s (downlink) + 14.5 kbit/s (uplink))"); break;
                case 0x22: channel_content = strdup("Data (asymmetric 29.0 kbit/s (downlink) + 14.5 kbit/s (uplink))"); break;
                case 0x23: channel_content = strdup("Data (asymmetric 43.5 kbit/s (downlink) + 29.0 kbit/s (uplink))"); break;
                case 0x29: channel_content = strdup("Data (asymmetric 14.5 kbit/s (downlink) + 43.5 kbit/s (uplink))"); break;
                case 0x2a: channel_content = strdup("Data (asymmetric 14.5 kbit/s (downlink) + 29.0 kbit/s (uplink))"); break;
                case 0x2b: channel_content = strdup("Data (asymmetric 29.0 kbit/s (downlink) + 43.5 kbit/s (uplink))"); break;
                case 0x34: channel_content = strdup("Data (43.5 kbit/s)"); break;
                case 0x31: channel_content = strdup("Data (28.8 kbit/s)"); break;
                case 0x18: channel_content = strdup("Data (14.5 kbit/s)"); break;
                case 0x10: channel_content = strdup("Data (12 kbit/s)"); break;
                case 0x11: channel_content = strdup("Data (6 kbit/s)"); break;
                default:
                    channel_content = strdup("Data");
                    break;
            }
            break;
        }
        case 0x03: {
            channel_content = strdup("Signalling");
            if (octet6 == 0) {
                /* No resources required */
            } else {
                /* All values != 0 are reserved */
                md->gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
            }
            break;
        }
        default:
            md->rsl.speech_or_data = 0;
            channel_content = t2_strdup_printf("speech_or_data: Reserved (0x%02" B2T_PRIX8 ")", speech_or_data);
            len -= 3;
            t2buf_skip_n(t2buf, len);
            break;
    }

    GSM_DBG_RSL("%" PRIu64 ": Channel Mode IE: %s%s%s%s%s (%s)", numPackets,
            dtxd ? "DTXd" : "",
            dtxu && dtxd ? ", " : "",
            dtxu ? "DTXu" : " ",
            dtxu || dtxd ? ", " : "",
            chann, channel_content);

    md->rsl.channel_content = channel_content;

    return true;
}


static inline bool t2buf_dissect_rsl_ie_channel_identification(t2buf_t *t2buf, bool mandatory, gsm_metadata_t *md) {
    uint8_t ie;

    if (!mandatory) {
        if (!t2buf_peek_u8(t2buf, &ie) || ie != 0x05) return false;
    }

    if (!t2buf_read_u8(t2buf, &ie)) return false;
    if (ie != 0x05) {
        GSM_DBG_RSL("%" PRIu64 ": Channel Identification IE 0x05 expected, found 0x%02" B2T_PRIX8, numPackets, ie);
        md->gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
    }

    uint8_t len;
    if (!t2buf_read_u8(t2buf, &len)) return false;

    uint8_t iei;
    if (!t2buf_read_u8(t2buf, &iei)) return false;
    if (iei != 0x64) {
        GSM_DBG_RSL("%" PRIu64 ": Channel Identification IE: expected IE 0x64 (Channel Description), found 0x%02" B2T_PRIX8, numPackets, iei);
        md->gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
    }

    gsmChannelDescription_t channel = t2buf_read_channel_description(t2buf, md);

    /* Mobile Allocation */
    if (!t2buf_read_u8(t2buf, &iei)) return false;
    if (iei != 0x72) {
        GSM_DBG_RSL("%" PRIu64 ": Channel Identification IE: expected IE 0x72 (Mobile Allocation), found 0x%02" B2T_PRIX8, numPackets, iei);
        md->gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
    }

    /* Mobile Allocation */
    if (!t2buf_read_u8(t2buf, &len)) return false;
    // TODO (deprecated, length should be 0)
    // t2buf_read_mobile_allocation(t2buf);
    bool ret = t2buf_skip_n(t2buf, len);

    GSM_DBG_RSL("%" PRIu64 ": Channel Identification IE: %s", numPackets, channel.channel);

    gsm_channel_description_free(&channel);

    return ret;
}


static inline bool t2buf_dissect_rsl_ie_encryption_info(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory) {
    uint8_t ie;

    if (!mandatory) {
        if (!t2buf_peek_u8(t2buf, &ie) || ie != 0x07) return false;
    }

    if (!t2buf_read_u8(t2buf, &ie)) return false;
    if (ie != 0x07) {
        GSM_DBG_RSL("%" PRIu64 ": Encryption Information IE 0x07 expected, found 0x%02" B2T_PRIX8, numPackets, ie);
        gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
    }

    GSM_DBG_RSL("%" PRIu64 ": Encryption Information IE", numPackets);

    uint8_t len;
    if (!t2buf_read_u8(t2buf, &len)) return false;

    uint8_t algo;
    if (!t2buf_read_u8(t2buf, &algo)) return false;

    switch (algo) {
        //case 0x00: // Reserved
        case 0x01: // No encryption shall be used
            GSM_DBG_RSL("%" PRIu64 ": No encryption shall be used", numPackets);
            break;
        case 0x02: // GSM encryption algorithm version 1 (A5/1)
            GSM_DBG_RSL("%" PRIu64 ": GSM encryption algorithm version 1 (A5/1)", numPackets);
            break;
        case 0x03: // GSM A5/2
            GSM_DBG_RSL("%" PRIu64 ": GSM A5/2", numPackets);
            break;
        case 0x04: // GSM A5/3
            GSM_DBG_RSL("%" PRIu64 ": GSM A5/3", numPackets);
            break;
        case 0x05: // GSM A5/4
            GSM_DBG_RSL("%" PRIu64 ": GSM A5/4", numPackets);
            break;
        case 0x06: // GSM A5/5
            GSM_DBG_RSL("%" PRIu64 ": GSM A5/5", numPackets);
            break;
        case 0x07: // GSM A5/6
            GSM_DBG_RSL("%" PRIu64 ": GSM A5/6", numPackets);
            break;
        case 0x08: // GSM A5/7
            GSM_DBG_RSL("%" PRIu64 ": GSM A5/7", numPackets);
            break;
        default: // reserved
#if GSM_DBG_RSL_UNK == 1
            GSM_DBG_RSL("%" PRIu64 ": Reserved (0x%02" B2T_PRIX8 ")", numPackets, algo);
#endif
            break;
    }

    // key
    return t2buf_skip_n(t2buf, len-1);
}


static inline bool t2buf_dissect_rsl_ie_handover_reference(t2buf_t *t2buf, bool mandatory, gsm_metadata_t *md) {
    uint8_t ie;

    if (!mandatory) {
        if (!t2buf_peek_u8(t2buf, &ie) || ie != 0x09) return false;
    }

    if (!t2buf_read_u8(t2buf, &ie)) return false;
    if (ie != 0x09) {
        GSM_DBG_RSL("%" PRIu64 ": Handover Reference IE 0x09 expected, found 0x%02" B2T_PRIX8, numPackets, ie);
        md->gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
    }

    /* Handover Reference */
    if (!t2buf_read_u8(t2buf, &md->rsl.ho_ref)) return false;

    GSM_DBG_RSL("%" PRIu64 ": Handover Reference IE: %" PRIu8, numPackets, md->rsl.ho_ref);

    return true;
}


static inline bool t2buf_dissect_rsl_ie_bs_power(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory) {
    uint8_t ie;

    if (!mandatory) {
        if (!t2buf_peek_u8(t2buf, &ie) || ie != 0x04) return false;
    }

    if (!t2buf_read_u8(t2buf, &ie)) return false;
    if (ie != 0x04) {
        GSM_DBG_RSL("%" PRIu64 ": BS Power IE 0x04 expected, found 0x%02" B2T_PRIX8, numPackets, ie);
        gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
    }

    uint8_t power;
    if (!t2buf_read_u8(t2buf, &power)) return false;

    const uint8_t epc_mode = ((power & 0x20) >> 5);
    const uint8_t fpc_epc_mode = ((power & 0x10) >> 4);

    const uint8_t level = (power & 0x0f);
    if (level == 0) {
        GSM_DBG_RSL("%" PRIu64 ": BS Power IE: Pn, Channel %sin EPC mode, Fast Power Control %sin use", numPackets, (epc_mode ? "" : "not "), (fpc_epc_mode ? "" : "not "));
    //} else if (level > 15) {
    //    GSM_DBG_RSL("%" PRIu64 ": BS Power IE: Reserved value %" PRIu8 " used as power level", numPackets, level);
    } else {
        GSM_DBG_RSL("%" PRIu64 ": BS Power IE: Pn - %" PRIu8 " dB, Channel %sin EPC mode, Fast Power Control %sin use",
                numPackets, (uint8_t)(level * 2), (epc_mode ? "" : "not "), (fpc_epc_mode ? "" : "not "));
    }

    return true;
}


static inline bool t2buf_dissect_rsl_ie_ms_power(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory) {
    uint8_t ie;

    if (!mandatory) {
        if (!t2buf_peek_u8(t2buf, &ie) || ie != 0x0d) return false;
    }

    if (!t2buf_read_u8(t2buf, &ie)) return false;
    if (ie != 0x0d) {
        GSM_DBG_RSL("%" PRIu64 ": MS Power IE 0x0d expected, found 0x%02" B2T_PRIX8, numPackets, ie);
        gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
    }

    uint8_t power;
    if (!t2buf_read_u8(t2buf, &power)) return false;

    const uint8_t ms_fpc = ((power & 0x20) >> 5);

    const uint8_t level = (power & 0x1f);
    GSM_DBG_RSL("%" PRIu64 ": MS Power IE: Power level: %" PRIu8 ", FPC/EPC %sin use", numPackets, level, (ms_fpc ? "" : "not "));

    return true;
}


static inline bool t2buf_dissect_rsl_ie_timing_advance(t2buf_t *t2buf, bool mandatory, gsm_metadata_t *md) {
    uint8_t ie;

    if (!mandatory) {
        if (!t2buf_peek_u8(t2buf, &ie) || ie != 0x18) return false;
    }

    if (!t2buf_read_u8(t2buf, &ie)) return false;
    if (ie != 0x18) {
        GSM_DBG_RSL("%" PRIu64 ": Timing Advance IE 0x18 expected, found 0x%02" B2T_PRIX8, numPackets, ie);
        md->gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
    }

    return t2buf_read_timing_advance(t2buf, &md->rsl.ta, &md->rsl.bts_dist);
}


static inline bool t2buf_dissect_rsl_ie_ms_power_parameters(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory) {
    uint8_t ie;

    if (!mandatory) {
        if (!t2buf_peek_u8(t2buf, &ie) || ie != 0x1f) return false;
    }

    if (!t2buf_read_u8(t2buf, &ie)) return false;
    if (ie != 0x1f) {
        GSM_DBG_RSL("%" PRIu64 ": MS Power Parameters IE 0x1f expected, found 0x%02" B2T_PRIX8, numPackets, ie);
        gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
    }

    uint8_t len;
    if (!t2buf_read_u8(t2buf, &len)) return false;

    GSM_DBG_RSL("%" PRIu64 ": MS Power Parameters IE", numPackets);

    return t2buf_skip_n(t2buf, len);
}


static inline bool t2buf_dissect_rsl_ie_bs_power_parameters(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory) {
    uint8_t ie;

    if (!mandatory) {
        if (!t2buf_peek_u8(t2buf, &ie) || ie != 0x20) return false;
    }

    if (!t2buf_read_u8(t2buf, &ie)) return false;
    if (ie != 0x20) {
        GSM_DBG_RSL("%" PRIu64 ": BS Power Parameters IE 0x20 expected, found 0x%02" B2T_PRIX8, numPackets, ie);
        gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
    }

    uint8_t len;
    if (!t2buf_read_u8(t2buf, &len)) return false;

    GSM_DBG_RSL("%" PRIu64 ": BS Power Parameters IE", numPackets);

    return t2buf_skip_n(t2buf, len);
}


static inline bool t2buf_dissect_rsl_ie_ms_timing_offset(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory) {
    uint8_t ie;

    if (!mandatory) {
        if (!t2buf_peek_u8(t2buf, &ie) || ie != 0x25) return false;
    }

    if (!t2buf_read_u8(t2buf, &ie)) return false;
    if (ie != 0x25) {
        GSM_DBG_RSL("%" PRIu64 ": MS Timing Offset IE 0x25 expected, found 0x%02" B2T_PRIX8, numPackets, ie);
        gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
    }

    uint8_t octet;
    if (!t2buf_read_u8(t2buf, &octet)) return false;

    int offset = octet - 63;

    GSM_DBG_RSL("%" PRIu64 ": MS Timing Offset IE: %d", numPackets, offset);

    return true;
}


static inline bool t2buf_dissect_rsl_ie_tfo_transparent_container(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory) {
    uint8_t ie;

    if (!mandatory) {
        if (!t2buf_peek_u8(t2buf, &ie) || ie != 0x61) return false;
    }

    if (!t2buf_read_u8(t2buf, &ie)) return false;
    if (ie != 0x61) {
        GSM_DBG_RSL("%" PRIu64 ": TFO Transparent Container IE 0x61 expected, found 0x%02" B2T_PRIX8, numPackets, ie);
        gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
    }

    uint8_t len;
    if (!t2buf_read_u8(t2buf, &len)) return false;

    GSM_DBG_RSL("%" PRIu64 ": TFO Transparent Container IE", numPackets);

    return t2buf_skip_n(t2buf, len);
}


static inline bool t2buf_dissect_rsl_ie_tfo_status(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory) {
    uint8_t ie;

    if (!mandatory) {
        if (!t2buf_peek_u8(t2buf, &ie) || ie != 0x3b) return false;
    }

    if (!t2buf_read_u8(t2buf, &ie)) return false;
    if (ie != 0x3b) {
        GSM_DBG_RSL("%" PRIu64 ": TFO Status IE 0x3b expected, found 0x%02" B2T_PRIX8, numPackets, ie);
        gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
    }

    uint8_t octet;
    if (!t2buf_read_u8(t2buf, &octet)) return false;

    const uint8_t status = (octet & 0x01);

    GSM_DBG_RSL("%" PRIu64 ": TFO Status IE: TFO is %sestablished", numPackets, ((status == 0) ? "" : "not "));

    return true;
}


static inline bool t2buf_dissect_rsl_ie_frame_number(t2buf_t *t2buf, bool mandatory, gsm_metadata_t *md) {
    uint8_t ie;

    if (!mandatory) {
        if (!t2buf_peek_u8(t2buf, &ie) || ie != 0x08) return false;
    }

    if (!t2buf_read_u8(t2buf, &ie)) return false;
    if (ie != 0x08) {
        GSM_DBG_RSL("%" PRIu64 ": Frame Number IE 0x08 expected, found 0x%02" B2T_PRIX8, numPackets, ie);
        md->gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
    }

    // Absolute frame number modulo 42432
    uint8_t frame_number1;
    uint8_t frame_number2;
    if (!t2buf_read_u8(t2buf, &frame_number1) ||
        !t2buf_read_u8(t2buf, &frame_number2))
    {
        return false;
    }

    md->rsl.frame_number.t1 = ((frame_number1 & 0xf8) >> 3);
    const uint8_t t3_high = (frame_number1 & 0x07);
    const uint8_t t3_low = ((frame_number2 & 0xe0) >> 5);
    md->rsl.frame_number.t2 = (frame_number2 & 0x1f);
    md->rsl.frame_number.t3 = ((t3_high << 3) | t3_low);
    int16_t t = (md->rsl.frame_number.t3 - md->rsl.frame_number.t2) % 26;
    if (t < 0) t += 26;
    md->rsl.frame_number.fn = 51 * t + md->rsl.frame_number.t3 + 51 * 26 * md->rsl.frame_number.t1;

    GSM_DBG_RSL("%" PRIu64 ": Frame Number IE: T1': %" PRIu8 ", T2: %" PRIu8 ", T3: %" PRIu16 " => FN: %" PRIu16, numPackets, md->rsl.frame_number.t1, md->rsl.frame_number.t2, md->rsl.frame_number.t3, md->rsl.frame_number.fn);

    return true;
}


static inline bool t2buf_dissect_rsl_ie_uic(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory) {
    uint8_t ie;

    if (!mandatory) {
        if (!t2buf_peek_u8(t2buf, &ie) || ie != 0x34) return false;
    }

    if (!t2buf_read_u8(t2buf, &ie)) return false;
    if (ie != 0x34) {
        GSM_DBG_RSL("%" PRIu64 ": UIC IE 0x34 expected, found 0x%02" B2T_PRIX8, numPackets, ie);
        gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
    }

    uint8_t len;
    if (!t2buf_read_u8(t2buf, &len)) return false;

    GSM_DBG_RSL("%" PRIu64 ": UIC IE", numPackets);

    return t2buf_skip_n(t2buf, len); // UIC information (GSM 04.08)
}


static inline bool t2buf_dissect_rsl_ie_main_channel_reference(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory) {
    uint8_t ie;

    if (!mandatory) {
        if (!t2buf_peek_u8(t2buf, &ie) || ie != 0x35) return false;
    }

    if (!t2buf_read_u8(t2buf, &ie)) return false;
    if (ie != 0x35) {
        GSM_DBG_RSL("%" PRIu64 ": Main Channel Reference IE 0x35 expected, found 0x%02" B2T_PRIX8, numPackets, ie);
        gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
    }

    uint8_t tn;
    if (!t2buf_read_u8(t2buf, &tn)) return false;

    // main channel reference of a multislot connection
    tn &= 0x07; // 0xf8: reserved

    GSM_DBG_RSL("%" PRIu64 ": Main channel reference IE: TN%" PRIu8, numPackets, tn);

    return true;
}


static inline bool t2buf_dissect_rsl_ie_sacch_info(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory) {
    uint8_t ie;

    if (!mandatory) {
        if (!t2buf_peek_u8(t2buf, &ie) || ie != 0x2c) return false;
    }

    if (!t2buf_read_u8(t2buf, &ie)) return false;
    if (ie != 0x2c) {
        GSM_DBG_RSL("%" PRIu64 ": SACCH Information IE 0x2c expected, found 0x%02" B2T_PRIX8, numPackets, ie);
        gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
    }

    uint8_t len;
    if (!t2buf_read_u8(t2buf, &len)) return false;

    GSM_DBG_RSL("%" PRIu64 ": SACCH Information IE", numPackets);

    return t2buf_skip_n(t2buf, len);
}


static inline bool t2buf_dissect_rsl_ie_l1_info(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory) {
    uint8_t ie;

    if (!mandatory) {
        if (!t2buf_peek_u8(t2buf, &ie) || ie != 0x0a) return false;
    }

    if (!t2buf_read_u8(t2buf, &ie)) return false;
    if (ie != 0x0a) {
        GSM_DBG_RSL("%" PRIu64 ": L1 Information IE 0x0a expected, found 0x%02" B2T_PRIX8, numPackets, ie);
        gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
    }

    uint8_t octet1;
    if (!t2buf_read_u8(t2buf, &octet1)) return false;

    // MS power level (& 0xf8), FPC/EPC, SRR (SACCH Repetition)
    const uint8_t power_level = ((octet1 & 0xf8) >> 3);
    const uint8_t fpc = ((octet1 & 0x04) >> 2);
    const uint8_t srr = ((octet1 & 0x02) >> 1);

    uint8_t act_ta = 0;
    uint16_t bts_dist = 0;
    if (!t2buf_read_timing_advance(t2buf, &act_ta, &bts_dist)) return false;

    GSM_DBG_RSL("%" PRIu64 ": Actual Timing Advance: %" PRIu8 " (distance from BTS ~ %" PRIu16 " m)", numPackets, act_ta, bts_dist);

    if (power_level == 0) {
        GSM_DBG_RSL("%" PRIu64 ": L1 Information IE: Pn, FPC/EPC %sin use, SRR (SACCH Repetition) %srequired",
                numPackets, (fpc ? "" : "not "), (srr ? "" : "not "));
    } else if (power_level > 15) {
        GSM_DBG_RSL("%" PRIu64 ": L1 Information IE: Reserved value %" PRIu8 " used as power level, FPC/EPC %sin use, SRR (SACCH Repetition) %srequired",
                numPackets, power_level, (fpc ? "" : "not "), (srr ? "" : "not "));
    } else {
        GSM_DBG_RSL("%" PRIu64 ": L1 Information IE: Pn - %" PRIu8 " dB, FPC/EPC %sin use, SRR (SACCH Repetition) %srequired",
                numPackets, (uint8_t)(power_level * 2), (fpc ? "" : "not "), (srr ? "" : "not "));
    }

    return true;
}


static inline bool t2buf_dissect_rsl_ie_measurement_result_number(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory) {
    uint8_t ie;

    if (!mandatory) {
        if (!t2buf_peek_u8(t2buf, &ie) || ie != 0x1b) return false;
    }

    if (!t2buf_read_u8(t2buf, &ie)) return false;
    if (ie != 0x1b) {
        GSM_DBG_RSL("%" PRIu64 ": Measurement Result Number IE 0x1b expected, found 0x%02" B2T_PRIX8, numPackets, ie);
        gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
    }

    /* Measurement Result Number */
    uint8_t num;
    if (!t2buf_read_u8(t2buf, &num)) return false;

    GSM_DBG_RSL("%" PRIu64 ": Measurement Result Number IE: 0x%02" B2T_PRIX8, numPackets, num);

    return true;
}


static inline bool t2buf_dissect_rsl_ie_uplink_measurements(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory) {
    uint8_t ie;

    if (!mandatory) {
        if (!t2buf_peek_u8(t2buf, &ie) || ie != 0x19) return false;
    }

    if (!t2buf_read_u8(t2buf, &ie)) return false;
    if (ie != 0x19) {
        GSM_DBG_RSL("%" PRIu64 ": Uplink Measurements IE 0x19 expected, found 0x%02" B2T_PRIX8, numPackets, ie);
        gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
    }

    uint8_t len;
    if (!t2buf_read_u8(t2buf, &len)) return false;

    GSM_DBG_RSL("%" PRIu64 ": Uplink Measurements IE", numPackets);

    return t2buf_skip_n(t2buf, len);
}


static inline bool t2buf_dissect_rsl_ie_multirate_configuration(t2buf_t *t2buf, bool mandatory, gsm_metadata_t *md) {
    uint8_t ie;

    if (!mandatory) {
        if (!t2buf_peek_u8(t2buf, &ie) || ie != 0x36) return false;
    }

    if (!t2buf_read_u8(t2buf, &ie)) return false;
    if (ie != 0x36) {
        GSM_DBG_RSL("%" PRIu64 ": MultiRate Configuration IE 0x36 expected, found 0x%02" B2T_PRIX8, numPackets, ie);
        md->gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
    }

    md->rsl.amr_config = t2buf_read_multirate_configuration(t2buf, md);

    return true;
}


static inline bool t2buf_dissect_rsl_ie_multirate_control(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory) {
    uint8_t ie;

    if (!mandatory) {
        if (!t2buf_peek_u8(t2buf, &ie) || ie != 0x37) return false;
    }

    if (!t2buf_read_u8(t2buf, &ie)) return false;
    if (ie != 0x37) {
        GSM_DBG_RSL("%" PRIu64 ": MultiRate Control IE 0x37 expected, found 0x%02" B2T_PRIX8, numPackets, ie);
        gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
    }

    t2buf_skip_u8(t2buf);

    return true;
}


static inline bool t2buf_dissect_rsl_ie_supported_codec_types(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory) {
    uint8_t ie;

    if (!mandatory) {
        if (!t2buf_peek_u8(t2buf, &ie) || ie != 0x38) return false;
    }

    if (!t2buf_read_u8(t2buf, &ie)) return false;
    if (ie != 0x38) {
        GSM_DBG_RSL("%" PRIu64 ": Supported Codec Types IE 0x38 expected, found 0x%02" B2T_PRIX8, numPackets, ie);
        gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
    }

    uint8_t len;
    if (!t2buf_read_u8(t2buf, &len)) return false;

    GSM_DBG_RSL("%" PRIu64 ": Supported Codec Types IE", numPackets);

    return t2buf_skip_n(t2buf, len);
}


static inline bool t2buf_dissect_rsl_ie_codec_configuration(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory) {
    uint8_t ie;

    if (!mandatory) {
        if (!t2buf_peek_u8(t2buf, &ie) || ie != 0x39) return false;
    }

    if (!t2buf_read_u8(t2buf, &ie)) return false;
    if (ie != 0x39) {
        GSM_DBG_RSL("%" PRIu64 ": Codec Configuration IE 0x39 expected, found 0x%02" B2T_PRIX8, numPackets, ie);
        gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
    }

    uint8_t len;
    if (!t2buf_read_u8(t2buf, &len)) return false;

    GSM_DBG_RSL("%" PRIu64 ": Codec Configuration IE", numPackets);

    return t2buf_skip_n(t2buf, len);
}


static inline bool t2buf_dissect_rsl_ie_round_trip_delay(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory) {
    uint8_t ie;

    if (!mandatory) {
        if (!t2buf_peek_u8(t2buf, &ie) || ie != 0x3a) return false;
    }

    if (!t2buf_read_u8(t2buf, &ie)) return false;
    if (ie != 0x3a) {
        GSM_DBG_RSL("%" PRIu64 ": Round Trip Delay IE 0x3a expected, found 0x%02" B2T_PRIX8, numPackets, ie);
        gsmFlowP->pstat |= GSM_STAT_RSL_MALFORMED;
    }

    uint8_t octet;
    if (!t2buf_read_u8(t2buf, &octet)) return false;

    const uint8_t rtd = ((octet & 0xfe) >> 1) * 20;
    const uint8_t delay_ind = (octet & 0x01);

    GSM_DBG_RSL("%" PRIu64 ": Round Trip Delay IE: BTS-%s round trip delay: %" PRIu8 " ms", numPackets, (delay_ind ? "Remote BTS" : "Transcoder"), rtd);

    return true;
}
