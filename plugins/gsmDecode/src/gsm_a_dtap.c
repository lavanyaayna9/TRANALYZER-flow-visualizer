/*
 * gsm_a_dtap.c
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

#include "gsm_a_dtap.h"

#include "gsm_a_rp.h"     // for dissect_gsm_a_rp
#include "gsm_osmocore.h" // for gsm48_cc_cause_name, gsm48_rr_msg_name
#include "gsm_utils.h"    // for t2buf_read_bcd_number, t2buf_read_mobile_identity, ...
#include "mcc_list.h"     // for mcc_to_str, mnc_to_str


#define GSM_DTAP_PEEK_IEI(t2buf, iei_p) \
    if (!t2buf_peek_u8((t2buf), (iei_p))) { \
        has_next_layer = false; \
        break; \
    }


/*
 * Function prototypes
 */

static inline bool dissect_gsm_a_dtap_cc(t2buf_t *t2buf, uint8_t msg_type, gsm_metadata_t *md)
    __attribute__((__nonnull__(1,3)));
static inline bool dissect_gsm_a_dtap_mm(t2buf_t *t2buf, uint8_t msg_type, gsm_metadata_t *md)
    __attribute__((__nonnull__(1,3)));
static inline bool dissect_gsm_a_dtap_rr(t2buf_t *t2buf, uint8_t msg_type, gsm_metadata_t *md)
    __attribute__((__nonnull__(1,3)));

static inline uint8_t t2buf_dissect_dtap_cause(t2buf_t *t2buf)
    __attribute__((__nonnull__(1)));
static inline bool t2buf_dissect_dtap_cell_channel_description(t2buf_t *t2buf, gsmFlow_t *gsmFlowP)
    __attribute__((__nonnull__(1, 2)));
// Returned value MUST be free'd with free()
static inline gsmChannelDescription_t t2buf_dissect_dtap_channel_description_2(t2buf_t *t2buf, gsm_metadata_t *md)
    __attribute__((__nonnull__(1, 2)))
    __attribute__((__warn_unused_result__));
static inline bool t2buf_dissect_dtap_channel_description_3(t2buf_t *t2buf, gsm_metadata_t *md)
    __attribute__((__nonnull__(1, 2)));
static inline const char *t2buf_dissect_dtap_channel_mode(t2buf_t *t2buf)
    __attribute__((__nonnull__(1)));
static inline const char *t2buf_dissect_dtap_channel_mode_2(t2buf_t *t2buf)
    __attribute__((__nonnull__(1)));
static inline bool t2buf_dissect_dtap_ie_cell_channel_description(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory)
    __attribute__((__nonnull__(1,2)));
static inline gsmLAI_t t2buf_dissect_dtap_lai(t2buf_t *t2buf)
    __attribute__((__nonnull__(1)));
static inline uint32_t t2buf_dissect_dtap_tmsi(t2buf_t *t2buf, gsm_metadata_t *md)
    __attribute__((__nonnull__(1,2)));


/* ========================================================================= */
/* GSM A-I/F DTAP (Direct Transfer Application Part)                         */
/* GSM 04.07, 04.08                                                          */
/* ========================================================================= */
inline bool dissect_gsm_a_dtap(t2buf_t *t2buf, gsm_metadata_t *md) {

    const uint16_t pktlen = md->packet->l7Len;

    numGSMDTAP++;
    md->gsmFlowP->pstat |= GSM_STAT_DTAP;

    /*
     * Protocol discriminator
     *
     * x... .... : TI flag
     * .xxx .... : TIO
     * .... xxxx : Protocol discriminator
     */
    uint8_t proto_disc;
    t2buf_read_u8(t2buf, &proto_disc);

    //if ((proto_disc & 0xf0) == 0x70) {
    //    const uint8_t tio = ((proto_disc & 0x70) >> 4);
    //    GSM_DBG_DTAP("%" PRIu64 ": TIO: %u", numPackets, tio);
    //}

    /*
     * DTAP Supplementary Service Message Type
     *
     * x... .... : 0
     * .x.. .... : N(SD) (send sequence number, MM and CM messages using SAPI=0, 9 otherwise)
     * ..xx xxxx : Message type
     */

    uint8_t msg_type;
    t2buf_read_u8(t2buf, &msg_type);

    //const uint8_t seqnum = ((msg_type & 0xc0) >> 6);

    bool has_next_layer = false;

    proto_disc &= 0x0f;
    switch (proto_disc) {

        /* ----------------------------------------------------------------- */
        /* Call Control; call related SS messages (CC)                       */
        /* ----------------------------------------------------------------- */

        case 0x03: {
            has_next_layer = dissect_gsm_a_dtap_cc(t2buf, (msg_type & 0x3f), md);
            break;
        }

        /* ----------------------------------------------------------------- */
        /* Mobility Management messages (MM)                                 */
        /* ----------------------------------------------------------------- */

        case 0x05: {
            has_next_layer = dissect_gsm_a_dtap_mm(t2buf, (msg_type & 0x3f), md);
            break;
        }

        /* ----------------------------------------------------------------- */
        /* Radio Resources Management messages (RR)                          */
        /* ----------------------------------------------------------------- */

        case 0x06: {
            has_next_layer = dissect_gsm_a_dtap_rr(t2buf, (msg_type & 0x7f), md);
            break;
        }

        /* ----------------------------------------------------------------- */
        /* SMS Messages (SMS)                                                */
        /* GSM 03.40?                                                        */
        /* ----------------------------------------------------------------- */

        case 0x09: {
            numGSMDTAPSMS++;
            md->gsmFlowP->pstat |= GSM_STAT_DTAP_SMS;
            switch (msg_type) {
                case 0x01: // CP-DATA
                    GSM_DBG_DTAP("%" PRIu64 ": SMS message: CP-DATA", numPackets);
                    has_next_layer = true;
                    break;
                case 0x04: // CP-ACK
                    GSM_DBG_DTAP("%" PRIu64 ": SMS message: CP-ACK", numPackets);
                    break;
                case 0x10: // CP-ERROR
                    GSM_DBG_DTAP("%" PRIu64 ": SMS message: CP-Error", numPackets);
                    md->gsmFlowP->pstat |= GSM_STAT_UPLINK;
                    break;
                default:
#if GSM_DBG_DTAP_UNK == 1
                    GSM_DBG_DTAP("%" PRIu64 ": Unknown SMS message type 0x%02" B2T_PRIX8, numPackets, msg_type);
#endif
                    md->gsmFlowP->pstat |= GSM_STAT_DTAP_MALFORMED;
                    break;
            }

            if (has_next_layer) {
                /* CP-User Data Length */
                uint8_t len;
                t2buf_read_u8(t2buf, &len);
                GSM_DBG_DTAP("%" PRIu64 ": CP-User Data Length: %u (0x%02" B2T_PRIX8 ")", numPackets, len, len);

                if (len != pktlen - t2buf_tell(t2buf)) {
#if GSM_DBG_DTAP_UNK == 1
                    T2_WRN("%" PRIu64 ": Byte %lu (DTAP) is not the PDU length: found %u (0x%02" B2T_PRIX8 "), expected %u (0x%02" B2T_PRIX8 ")",
                           numPackets, t2buf_tell(t2buf), len, len, (uint8_t)(pktlen - t2buf_tell(t2buf)), (uint8_t)(pktlen - t2buf_tell(t2buf)));
#endif
                    md->gsmFlowP->pstat |= GSM_STAT_DTAP_MALFORMED;
                    return false;
                }

                has_next_layer = dissect_gsm_a_rp(t2buf, md);
            }
            break;
        }

        //case 0x00: // Group call control (GCC)
        //case 0x01: // Broadcast call control (BCC)
        //case 0x02: // EPS session management messages
        //case 0x04: // GPRS Transparent Transport Protocol (GTTP)
        //case 0x07: // EPS mobility management messages
        //case 0x08: // GPRS mobility management messages (GMM)
        //case 0x0a: // GPRS session management messages (SM)

        case 0x0b: { // Non call related SS messages (SS)
            numGSMDTAPSS++;
            // TODO
            break;
        }

        //case 0x0c: // Location services specified in 3GPP TS 44.071 (LS)
        //case 0x0d: // Unknown
        //case 0x0e: // Reserved for extension of the PD to one octet length
        //case 0x0f: // Tests procedures described in 3GPP TS 44.014, 3GPP TS 34.109 and 3GPP TS 36.5 (TP)

        default:
#if GSM_DBG_DTAP_UNK == 1
            GSM_DBG_DTAP("%" PRIu64 ": Unknown DTAP protocol discriminator 0x%02" B2T_PRIX8, numPackets, proto_disc);
#endif
            numGSMDTAPUnk++;
            break;
    }

    return has_next_layer;
}


/* ========================================================================= */
/* Call Control; call related SS messages (CC)                               */
/* ========================================================================= */
static inline bool dissect_gsm_a_dtap_cc(t2buf_t *t2buf, uint8_t msg_type, gsm_metadata_t *md) {

    numGSMDTAPCC++;
    numDtapCC[msg_type]++;
    md->gsmFlowP->pstat |= GSM_STAT_DTAP_CC;

    bool has_next_layer = false;

    switch (msg_type) {

        /* ----------------------------------------------------------------- */
        /* CC Call establishment messages                                    */
        /* ----------------------------------------------------------------- */

        case 0x01: { // Alerting
            md->a_dtap.gsmCCMsgTypeStr = "Alerting";
            md->gsmFlowP->pstat |= GSM_STAT_UPLINK;
            GSM_DBG_DTAP("%" PRIu64 ": CC Call Establishment message: Alerting", numPackets);
            uint8_t iei;
            GSM_DTAP_PEEK_IEI(t2buf, &iei);
            /* 0x1c Facility [O] */
            if (iei == 0x1c) {
                GSM_DBG_DTAP("%" PRIu64 ": Facility", numPackets);
                md->gsmFlowP->pstat |= GSM_STAT_GSM_MAP;
                T2BUF_SKIP_TLV(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x1e Progress Indicator [O] */
            if (iei == 0x1e) {
                GSM_DBG_DTAP("%" PRIu64 ": Progress Indicator", numPackets);
                T2BUF_SKIP_TLV(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x7e User-user [O] */
            if (iei == 0x7e) {
                GSM_DBG_DTAP("%" PRIu64 ": User-user", numPackets);
                T2BUF_SKIP_TLV(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x7f SS version [O] */
            if (iei == 0x7f) {
                GSM_DBG_DTAP("%" PRIu64 ": SS Version", numPackets);
                T2BUF_SKIP_TLV(t2buf);
            }
            break;
        }

        case 0x08: { // Call Confirmed
            md->a_dtap.gsmCCMsgTypeStr = "Call Confirmed";
            md->gsmFlowP->pstat |= GSM_STAT_UPLINK;
            GSM_DBG_DTAP("%" PRIu64 ": CC Call Establishment message: Call Confirmed", numPackets);
            uint8_t iei;
            GSM_DTAP_PEEK_IEI(t2buf, &iei);
            /* 0xd- Repeat Indicator [C] */
            if ((iei & 0xf0) == 0xd0) {
                t2buf_skip_u8(t2buf); // iei
                GSM_DBG_DTAP("%" PRIu64 ": Repeat Indicator", numPackets);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x04 Bearer Capability 1 [O] */
            if (iei == 0x04) {
                GSM_DBG_DTAP("%" PRIu64 ": Bearer Capability 1", numPackets);
                T2BUF_SKIP_TLV(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
                /* 0x04 Bearer Capability 2 [O] */
                if (iei == 0x04) {
                    GSM_DBG_DTAP("%" PRIu64 ": Bearer Capability 2", numPackets);
                    T2BUF_SKIP_TLV(t2buf);
                    GSM_DTAP_PEEK_IEI(t2buf, &iei);
                }
            }
            /* 0x08 Cause [O] */
            if (iei == 0x08) {
                t2buf_skip_u8(t2buf); // iei
                uint8_t cause1 = t2buf_dissect_dtap_cause(t2buf);
                md->a_dtap.cause = cause1;
                GSM_DBG_DTAP("%" PRIu64 ": Cause: %u (%s)", numPackets, cause1, gsm48_cc_cause_name(cause1));
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x15 CC Capabilities [O] */
            if (iei == 0x08) {
                t2buf_skip_u8(t2buf); // iei
                GSM_DBG_DTAP("%" PRIu64 ": CC Capabilities", numPackets);
                T2BUF_SKIP_TLV(t2buf);
            }
            break;
        }

        case 0x02: { // Call Proceeding
            md->a_dtap.gsmCCMsgTypeStr = "Call Proceeding";
            md->gsmFlowP->pstat |= GSM_STAT_DOWNLINK;
            GSM_DBG_DTAP("%" PRIu64 ": CC Call Establishment message: Call Proceeding", numPackets);
            uint8_t iei;
            GSM_DTAP_PEEK_IEI(t2buf, &iei);
            /* 0xd- Repeat Indicator [C] */
            if ((iei & 0xf0) == 0xd0) {
                t2buf_skip_u8(t2buf); // iei
                GSM_DBG_DTAP("%" PRIu64 ": Repeat Indicator", numPackets);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x04 Bearer Capability 1 [O] */
            if (iei == 0x04) {
                GSM_DBG_DTAP("%" PRIu64 ": Bearer Capability 1", numPackets);
                T2BUF_SKIP_TLV(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
                /* 0x04 Bearer Capability 2 [O] */
                if (iei == 0x04) {
                    GSM_DBG_DTAP("%" PRIu64 ": Bearer Capability 2", numPackets);
                    T2BUF_SKIP_TLV(t2buf);
                    GSM_DTAP_PEEK_IEI(t2buf, &iei);
                }
            }
            /* 0x1c Facility [O] */
            if (iei == 0x1c) {
                GSM_DBG_DTAP("%" PRIu64 ": Facility", numPackets);
                md->gsmFlowP->pstat |= GSM_STAT_GSM_MAP;
                T2BUF_SKIP_TLV(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x1e Progress Indicator [O] */
            if (iei == 0x1e) {
                GSM_DBG_DTAP("%" PRIu64 ": Progress Indicator", numPackets);
                T2BUF_SKIP_TLV(t2buf);
            }
            break;
        }

        case 0x07: { // Connect
            md->a_dtap.gsmCCMsgTypeStr = "Connect";
            md->gsmFlowP->pstat |= GSM_STAT_UPLINK;
            GSM_DBG_DTAP("%" PRIu64 ": CC Call Establishment message: Connect", numPackets);
            uint8_t iei;
            GSM_DTAP_PEEK_IEI(t2buf, &iei);
            /* 0x1c Facility [O] */
            if (iei == 0x1c) {
                GSM_DBG_DTAP("%" PRIu64 ": Facility", numPackets);
                md->gsmFlowP->pstat |= GSM_STAT_GSM_MAP;
                T2BUF_SKIP_TLV(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x1e Progress Indicator [O] */
            if (iei == 0x1e) {
                GSM_DBG_DTAP("%" PRIu64 ": Progress Indicator", numPackets);
                T2BUF_SKIP_TLV(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x4c Connected Number [O] */
            if (iei == 0x4c) {
                t2buf_skip_u8(t2buf); // iei
                gsmMobileNumber_t number = t2buf_read_bcd_number(t2buf);
                GSM_DBG_DTAP("%" PRIu64 ": Connected Number: %s", numPackets, number.number);
                gsm_mobile_number_free(&number);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x4d Connected Subaddress [O] */
            if (iei == 0x4d) {
                GSM_DBG_DTAP("%" PRIu64 ": Connected Subaddress", numPackets);
                T2BUF_SKIP_TLV(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x7e User-user [O] */
            if (iei == 0x7e) {
                GSM_DBG_DTAP("%" PRIu64 ": User-user", numPackets);
                T2BUF_SKIP_TLV(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x7f SS version [O] */
            if (iei == 0x7f) {
                GSM_DBG_DTAP("%" PRIu64 ": SS Version", numPackets);
                T2BUF_SKIP_TLV(t2buf);
            }
            break;
        }

        case 0x0f:{ // Connect Acknowledge
            md->a_dtap.gsmCCMsgTypeStr = "Connect Acknowledge";
            GSM_DBG_DTAP("%" PRIu64 ": CC Call Establishment message: Connect Acknowledge", numPackets);
            break;
        }

        case 0x0e: { // Emergency Setup
            md->gsmFlowP->pstat |= GSM_STAT_UPLINK;
            GSM_DBG_DTAP("%" PRIu64 ": CC Call Establishment message: Emergency Setup", numPackets);
            uint8_t iei;
            GSM_DTAP_PEEK_IEI(t2buf, &iei);
            /* 0x04 Bearer Capability [O] */
            if (iei == 0x04) {
                GSM_DBG_DTAP("%" PRIu64 ": Bearer Capability", numPackets);
                T2BUF_SKIP_TLV(t2buf);
            }
            break;
        }

        case 0x03: { // Progress
            GSM_DBG_DTAP("%" PRIu64 ": CC Call Establishment message: Progress", numPackets);
            md->gsmFlowP->pstat |= GSM_STAT_DOWNLINK;
            /* Progress Indicator */
            T2BUF_SKIP_LV(t2buf);
            uint8_t iei;
            GSM_DTAP_PEEK_IEI(t2buf, &iei);
            /* 0x7e User-user [O] */
            if (iei == 0x7e) {
                GSM_DBG_DTAP("%" PRIu64 ": User-user", numPackets);
                T2BUF_SKIP_TLV(t2buf);
            }
            break;
        }

        case 0x05: { // Setup
            md->a_dtap.gsmCCMsgTypeStr = "Setup";
            md->gsmFlowP->pstat |= GSM_STAT_UPLINK;
            GSM_DBG_DTAP("%" PRIu64 ": CC Call Establishment message: SETUP", numPackets);
            uint8_t iei;
            GSM_DTAP_PEEK_IEI(t2buf, &iei);
            /* 0xd- BC Repeat Indicator [C] */
            if ((iei & 0xf0) == 0xd0) {
                t2buf_skip_u8(t2buf); // iei
                GSM_DBG_DTAP("%" PRIu64 ": BC Repeat Indicator", numPackets);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x04 Bearer Capability 1 [O] */
            if (iei == 0x04) {
                GSM_DBG_DTAP("%" PRIu64 ": Bearer Capability 1", numPackets);
                T2BUF_SKIP_TLV(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
                /* 0x04 Bearer Capability 2 [O] */
                if (iei == 0x04) {
                    GSM_DBG_DTAP("%" PRIu64 ": Bearer Capability 2", numPackets);
                    T2BUF_SKIP_TLV(t2buf);
                    GSM_DTAP_PEEK_IEI(t2buf, &iei);
                }
            }
            /* 0x1c Facility [O] */
            if (iei == 0x1c) {
                GSM_DBG_DTAP("%" PRIu64 ": Facility", numPackets);
                md->gsmFlowP->pstat |= GSM_STAT_GSM_MAP;
                T2BUF_SKIP_TLV(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x1e Progress Indicator [O] */
            if (iei == 0x1e) {
                GSM_DBG_DTAP("%" PRIu64 ": Progress Indicator", numPackets);
                T2BUF_SKIP_TLV(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x34 Signal [O] */
            if (iei == 0x34) {
                t2buf_skip_u8(t2buf); // iei
                GSM_DBG_DTAP("%" PRIu64 ": Signal", numPackets);
                t2buf_skip_u8(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x5c Calling Party BCD Number [O] */
            if (iei == 0x5c) {
                t2buf_skip_u8(t2buf); // iei
                if (md->a_dtap.caller.number) {
                    GSM_DBG_DTAP("%" PRIu64 ": DTAP Caller number already exists: %s", numPackets, md->a_dtap.caller.number);
                    gsm_mobile_number_free(&md->a_dtap.caller);
                }
                md->a_dtap.caller = t2buf_read_bcd_number(t2buf);
                GSM_DBG_DTAP("%" PRIu64 ": Calling Party BCD Number: %s", numPackets, md->a_dtap.caller.number);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x5d Calling Party BCD Subaddress [O] */
            if (iei == 0x5d) {
                GSM_DBG_DTAP("%" PRIu64 ": Calling Party BCD Subaddress", numPackets);
                T2BUF_SKIP_TLV(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x5e Called Party BCD Number [O] */
            if (iei == 0x5e) {
                t2buf_skip_u8(t2buf); // iei
                if (md->a_dtap.callee.number) {
                    GSM_DBG_DTAP("%" PRIu64 ": DTAP Callee number already exists: %s", numPackets, md->a_dtap.callee.number);
                    gsm_mobile_number_free(&md->a_dtap.callee);
                }
                md->a_dtap.callee = t2buf_read_bcd_number(t2buf);
                GSM_DBG_DTAP("%" PRIu64 ": Called Party BCD Number: %s", numPackets, md->a_dtap.callee.number);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x6d Called Party BCD Subaddress [O] */
            if (iei == 0x6d) {
                GSM_DBG_DTAP("%" PRIu64 ": Called Party BCD Subaddress", numPackets);
                T2BUF_SKIP_TLV(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0xd- LLC Repeat Indicator [O] */
            if ((iei & 0xf0) == 0xd0) {
                t2buf_skip_u8(t2buf); // iei
                GSM_DBG_DTAP("%" PRIu64 ": LLC Repeat Indicator", numPackets);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x7c Low Layer Compatibility I [O] */
            if (iei == 0x7c) {
                GSM_DBG_DTAP("%" PRIu64 ": Low Layer Compatibility I", numPackets);
                T2BUF_SKIP_TLV(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
                /* 0x7c Low Layer Compatibility II [C] */
                if (iei == 0x7c) {
                    GSM_DBG_DTAP("%" PRIu64 ": Low Layer Compatibility II", numPackets);
                    T2BUF_SKIP_TLV(t2buf);
                    GSM_DTAP_PEEK_IEI(t2buf, &iei);
                }
            }
            /* 0xd- HLC Repeat Indicator [O] */
            if ((iei & 0xf0) == 0xd0) {
                t2buf_skip_u8(t2buf); // iei
                GSM_DBG_DTAP("%" PRIu64 ": HLC Repeat Indicator", numPackets);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x7d High Layer Compatibility I [O] */
            if (iei == 0x7d) {
                GSM_DBG_DTAP("%" PRIu64 ": High Layer Compatibility I", numPackets);
                T2BUF_SKIP_TLV(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
                /* 0x7d High Layer Compatibility II [C] */
                if (iei == 0x7d) {
                    GSM_DBG_DTAP("%" PRIu64 ": High Layer Compatibility II", numPackets);
                    T2BUF_SKIP_TLV(t2buf);
                    GSM_DTAP_PEEK_IEI(t2buf, &iei);
                }
            }
            /* 0x7e User-user [O] */
            if (iei == 0x7e) {
                GSM_DBG_DTAP("%" PRIu64 ": User-user", numPackets);
                T2BUF_SKIP_TLV(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x7f SS version [O] */
            if (iei == 0x7f) {
                GSM_DBG_DTAP("%" PRIu64 ": SS Version", numPackets);
                T2BUF_SKIP_TLV(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0xa1 CLIR Suppression [C] */
            if (iei == 0xa1) {
                t2buf_skip_u8(t2buf); // iei
                GSM_DBG_DTAP("%" PRIu64 ": CLIR Suppression", numPackets);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0xa2 CLIR Invocation [C] */
            if (iei == 0xa2) {
                t2buf_skip_u8(t2buf); // iei
                GSM_DBG_DTAP("%" PRIu64 ": CLIR Invocation", numPackets);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x15 CC Capabilities [O] */
            if (iei == 0x15) {
                GSM_DBG_DTAP("%" PRIu64 ": CC Capabilities", numPackets);
                T2BUF_SKIP_TLV(t2buf);
            }
            break;
        }

        /* ----------------------------------------------------------------- */
        /* CC Call Information Phase messages                                */
        /* ----------------------------------------------------------------- */

        case 0x17: { // Modify
            GSM_DBG_DTAP("%" PRIu64 ": CC Call Information Phase message: Modify", numPackets);
            md->gsmFlowP->pstat |= GSM_STAT_UPLINK;
            /* Bearer Capability */
            T2BUF_SKIP_LV(t2buf);
            uint8_t iei;
            GSM_DTAP_PEEK_IEI(t2buf, &iei);
            /* 0x7c Low Layer Compatibility [O] */
            if (iei == 0x7c) {
                GSM_DBG_DTAP("%" PRIu64 ": Low Layer Compatibility", numPackets);
                T2BUF_SKIP_TLV(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x7d High Layer Compatibility [O] */
            if (iei == 0x7d) {
                GSM_DBG_DTAP("%" PRIu64 ": High Layer Compatibility", numPackets);
                T2BUF_SKIP_TLV(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0xa3 Reverse Call Setup Direction [O] */
            if (iei == 0xa3) {
                t2buf_skip_u8(t2buf); // iei
                GSM_DBG_DTAP("%" PRIu64 ": Reverse Call Setup Direction", numPackets);
                // Nothing to do
            }
            break;
        }

        case 0x1f: { // Modify Complete
            GSM_DBG_DTAP("%" PRIu64 ": CC Call Information Phase message: Modify Complete", numPackets);
            md->gsmFlowP->pstat |= GSM_STAT_UPLINK;
            /* Bearer Capability */
            T2BUF_SKIP_LV(t2buf);
            uint8_t iei;
            GSM_DTAP_PEEK_IEI(t2buf, &iei);
            /* 0x7c Low Layer Compatibility [O] */
            if (iei == 0x7c) {
                GSM_DBG_DTAP("%" PRIu64 ": Low Layer Compatibility", numPackets);
                T2BUF_SKIP_TLV(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x7d High Layer Compatibility [O] */
            if (iei == 0x7d) {
                GSM_DBG_DTAP("%" PRIu64 ": High Layer Compatibility", numPackets);
                T2BUF_SKIP_TLV(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0xa3 Reverse Call Setup Direction [O] */
            if (iei == 0xa3) {
                t2buf_skip_u8(t2buf); // iei
                GSM_DBG_DTAP("%" PRIu64 ": Reverse Call Setup Direction", numPackets);
                // Nothing to do
            }
            break;
        }

        case 0x13: { // Modify Reject
            md->gsmFlowP->pstat |= GSM_STAT_DOWNLINK;
            /* Bearer Capability */
            T2BUF_SKIP_LV(t2buf);
            /* Cause */
            uint8_t cause = t2buf_dissect_dtap_cause(t2buf);
            GSM_DBG_DTAP("%" PRIu64 ": CC Call Information Phase message: Modify Reject: Cause: %u (%s)", numPackets, cause, gsm48_cc_cause_name(cause));
            uint8_t iei;
            GSM_DTAP_PEEK_IEI(t2buf, &iei);
            /* 0x7c Low Layer Compatibility [O] */
            if (iei == 0x7c) {
                GSM_DBG_DTAP("%" PRIu64 ": Low Layer Compatibility", numPackets);
                T2BUF_SKIP_TLV(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x7d High Layer Compatibility [O] */
            if (iei == 0x7d) {
                GSM_DBG_DTAP("%" PRIu64 ": High Layer Compatibility", numPackets);
                T2BUF_SKIP_TLV(t2buf);
            }
            break;
        }

        case 0x10: { // User Information
            GSM_DBG_DTAP("%" PRIu64 ": CC Call Information Phase message: User Information", numPackets);
            md->gsmFlowP->pstat |= GSM_STAT_UPLINK;
            /* User-user */
            T2BUF_SKIP_LV(t2buf);
            uint8_t iei;
            GSM_DTAP_PEEK_IEI(t2buf, &iei);
            /* 0xa0 More Data [O] */
            if (iei == 0xa0) {
                t2buf_skip_u8(t2buf); // iei
                GSM_DBG_DTAP("%" PRIu64 ": More Data", numPackets);
                // Nothing to do
            }
            break;
        }

        /* ----------------------------------------------------------------- */
        /* Call clearing message                                             */
        /* ----------------------------------------------------------------- */

        case 0x25: { // Disconnect
            md->a_dtap.gsmCCMsgTypeStr = "Disconnect";
            md->gsmFlowP->pstat |= GSM_STAT_UPLINK;
            /* Cause */
            uint8_t cause1 = t2buf_dissect_dtap_cause(t2buf);
            md->a_dtap.cause = cause1;
            GSM_DBG_DTAP("%" PRIu64 ": CC Call Clearing message: Disconnect: Cause: %u (%s)", numPackets, cause1, gsm48_cc_cause_name(cause1));
            uint8_t iei;
            GSM_DTAP_PEEK_IEI(t2buf, &iei);
            /* 0x1c Facility [O] */
            if (iei == 0x1c) {
                GSM_DBG_DTAP("%" PRIu64 ": Facility", numPackets);
                md->gsmFlowP->pstat |= GSM_STAT_GSM_MAP;
                T2BUF_SKIP_TLV(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x1e Progress Indicator [O] */
            if (iei == 0x1e) {
                GSM_DBG_DTAP("%" PRIu64 ": Progress Indicator", numPackets);
                T2BUF_SKIP_TLV(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x7e User-user [O] */
            if (iei == 0x7e) {
                GSM_DBG_DTAP("%" PRIu64 ": User-user", numPackets);
                T2BUF_SKIP_TLV(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x7f SS version [O] */
            if (iei == 0x7f) {
                GSM_DBG_DTAP("%" PRIu64 ": SS Version", numPackets);
                T2BUF_SKIP_TLV(t2buf);
            }
            break;
        }

        case 0x2d: { // Release
            md->a_dtap.gsmCCMsgTypeStr = "Release";
            md->gsmFlowP->pstat |= GSM_STAT_UPLINK;
            GSM_DBG_DTAP("%" PRIu64 ": CC Call Clearing message: Release", numPackets);
            uint8_t iei;
            GSM_DTAP_PEEK_IEI(t2buf, &iei);
            /* 0x08 Cause [O] */
            if (iei == 0x08) {
                t2buf_skip_u8(t2buf); // iei
                uint8_t cause1 = t2buf_dissect_dtap_cause(t2buf);
                md->a_dtap.cause = cause1;
                GSM_DBG_DTAP("%" PRIu64 ": Cause: %u (%s)", numPackets, cause1, gsm48_cc_cause_name(cause1));
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
                /* 0x08 Second Cause [O] */
                if (iei == 0x08) {
                    t2buf_skip_u8(t2buf); // iei
                    uint8_t cause2 = t2buf_dissect_dtap_cause(t2buf);
                    GSM_DBG_DTAP("%" PRIu64 ": Second Cause: %u (%s)", numPackets, cause2, gsm48_cc_cause_name(cause2));
                    GSM_DTAP_PEEK_IEI(t2buf, &iei);
                }
            }
            /* 0x1c Facility [O] */
            if (iei == 0x1c) {
                GSM_DBG_DTAP("%" PRIu64 ": Facility", numPackets);
                md->gsmFlowP->pstat |= GSM_STAT_GSM_MAP;
                T2BUF_SKIP_TLV(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x7e User-user [O] */
            if (iei == 0x7e) {
                GSM_DBG_DTAP("%" PRIu64 ": User-user", numPackets);
                T2BUF_SKIP_TLV(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x7f SS version [O] */
            if (iei == 0x7f) {
                GSM_DBG_DTAP("%" PRIu64 ": SS Version", numPackets);
                T2BUF_SKIP_TLV(t2buf);
            }
            break;
        }

        case 0x2a: { // Release Complete
            md->a_dtap.gsmCCMsgTypeStr = "Release Complete";
            md->gsmFlowP->pstat |= GSM_STAT_DOWNLINK;
            GSM_DBG_DTAP("%" PRIu64 ": CC Call Clearing message: Release Complete", numPackets);
            uint8_t iei;
            GSM_DTAP_PEEK_IEI(t2buf, &iei);
            /* 0x08 Cause [O] */
            if (iei == 0x08) {
                t2buf_skip_u8(t2buf); // iei
                uint8_t cause1 = t2buf_dissect_dtap_cause(t2buf);
                md->a_dtap.cause = cause1;
                GSM_DBG_DTAP("%" PRIu64 ": Cause: %u (%s)", numPackets, cause1, gsm48_cc_cause_name(cause1));
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x1c Facility [O] */
            if (iei == 0x1c) {
                GSM_DBG_DTAP("%" PRIu64 ": Facility", numPackets);
                md->gsmFlowP->pstat |= GSM_STAT_GSM_MAP;
                T2BUF_SKIP_TLV(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x7e User-user [O] */
            if (iei == 0x7e) {
                GSM_DBG_DTAP("%" PRIu64 ": User-user", numPackets);
                T2BUF_SKIP_TLV(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x7f SS version [O] */
            if (iei == 0x7f) {
                GSM_DBG_DTAP("%" PRIu64 ": SS Version", numPackets);
                T2BUF_SKIP_TLV(t2buf);
            }
            break;
        }

        /* ----------------------------------------------------------------- */
        /* Messages for supplementary service control                        */
        /* ----------------------------------------------------------------- */

        case 0x3a: { // Facility
            GSM_DBG_DTAP("%" PRIu64 ": CC Miscellaneous message: Facility", numPackets);
            md->gsmFlowP->pstat |= GSM_STAT_UPLINK;
            /* Facility */
            T2BUF_SKIP_LV(t2buf);
            uint8_t iei;
            GSM_DTAP_PEEK_IEI(t2buf, &iei);
            /* 0x7f SS version [O] */
            if (iei == 0x7f) {
                GSM_DBG_DTAP("%" PRIu64 ": SS Version", numPackets);
                T2BUF_SKIP_TLV(t2buf);
            }
            break;
        }

        case 0x18: { // Hold
            md->a_dtap.gsmCCMsgTypeStr = "Hold";
            GSM_DBG_DTAP("%" PRIu64 ": CC Call Information Phase message: Hold", numPackets);
            break;
        }

        case 0x19: { // Hold Acknowledge
            md->a_dtap.gsmCCMsgTypeStr = "Hold Acknowledge";
            GSM_DBG_DTAP("%" PRIu64 ": CC Call Information Phase message: Hold Acknowledge", numPackets);
            break;
        }

        case 0x1a: { // Hold Reject
            md->a_dtap.gsmCCMsgTypeStr = "Hold Reject";
            md->gsmFlowP->pstat |= GSM_STAT_DOWNLINK;
            /* Cause */
            uint8_t cause1 = t2buf_dissect_dtap_cause(t2buf);
            md->a_dtap.cause = cause1;
            GSM_DBG_DTAP("%" PRIu64 ": CC Call Information Phase message: Hold Reject: Cause: %u (%s)", numPackets, cause1, gsm48_cc_cause_name(cause1));
            break;
        }

        case 0x1c: { // Retrieve
            GSM_DBG_DTAP("%" PRIu64 ": CC Call Information Phase message: Retrieve", numPackets);
            md->gsmFlowP->pstat |= GSM_STAT_DOWNLINK;
            break;
        }

        case 0x1d: { // Retrieve Acknowledge
            GSM_DBG_DTAP("%" PRIu64 ": CC Call Information Phase message: Retrieve Acknowledge", numPackets);
            break;
        }

        case 0x1e: { // Retrieve Reject
            /* Cause */
            uint8_t cause = t2buf_dissect_dtap_cause(t2buf);
            GSM_DBG_DTAP("%" PRIu64 ": CC Call Information Phase message: Retrieve Reject: Cause: %u (%s)", numPackets, cause, gsm48_cc_cause_name(cause));
            break;
        }

        /* ----------------------------------------------------------------- */
        /* Miscellaneous message                                             */
        /* ----------------------------------------------------------------- */

        case 0x39: { // Congestion Control
            md->gsmFlowP->pstat |= GSM_STAT_DOWNLINK;
            /* Congestion Level and Spare Half Octet */
            uint8_t octet;
            t2buf_read_u8(t2buf, &octet);
            const uint8_t level = ((octet & 0xf0) >> 4);
            GSM_DBG_DTAP("%" PRIu64 ": CC Miscellaneous message: Congestion Control: %s", numPackets,
                    ((level == 0x00) ? "Receiver Ready" :
                     (level == 0x0f) ? "Receiver Not Ready" : "Reserved"));
            uint8_t iei;
            GSM_DTAP_PEEK_IEI(t2buf, &iei);
            /* 0x08 Cause [O] */
            if (iei == 0x08) {
                t2buf_skip_u8(t2buf); // iei
                uint8_t cause = t2buf_dissect_dtap_cause(t2buf);
                GSM_DBG_DTAP("%" PRIu64 ": Cause: %u (%s)", numPackets, cause, gsm48_cc_cause_name(cause));
            }
            break;
        }

        case 0x3e: { // Notify
            md->gsmFlowP->pstat |= GSM_STAT_DOWNLINK;
            /* Notification Indicator */
            uint8_t octet;
            t2buf_read_u8(t2buf, &octet);
            const uint8_t notif = (octet & 0x7f);
            GSM_DBG_DTAP("%" PRIu64 ": CC Miscellaneous message: Notify: Notification Indicator=%s", numPackets,
                    ((notif == 0x00) ? "User Suspended" :
                     (notif == 0x01) ? "User Resumed" :
                     (notif == 0x02) ? "Bearer Change" : "Reserved"));
            break;
        }

        case 0x3d: { // Status
            md->gsmFlowP->pstat |= GSM_STAT_DOWNLINK;
            /* Cause */
            uint8_t cause = t2buf_dissect_dtap_cause(t2buf);
            /* Call State */
            uint8_t octet;
            t2buf_read_u8(t2buf, &octet);
            // const uint8_t coding_standard = ((octet & 0xc0) >> 6);
            const uint8_t call_state = (octet & 0x3f);
            GSM_DBG_DTAP("%" PRIu64 ": CC Miscellaneous message: Status: Cause: %u (%s), Call State=0x%02" B2T_PRIX8, numPackets, cause, gsm48_cc_cause_name(cause), call_state);
            uint8_t iei;
            GSM_DTAP_PEEK_IEI(t2buf, &iei);
            /* 0x24 Auxiliary State [O] */
            if (iei == 0x24) {
                GSM_DBG_DTAP("%" PRIu64 ": Auxiliary State", numPackets);
                T2BUF_SKIP_TLV(t2buf);
            }
            break;
        }

        case 0x34: { // Status Enquiry
            GSM_DBG_DTAP("%" PRIu64 ": CC Miscellaneous message: Status Enquiry", numPackets);
            break;
        }

        case 0x35: { // Start DTMF
            GSM_DBG_DTAP("%" PRIu64 ": CC Miscellaneous message: Start DTMF", numPackets);
            md->gsmFlowP->pstat |= GSM_STAT_UPLINK;
            uint8_t iei;
            GSM_DTAP_PEEK_IEI(t2buf, &iei);
            /* 0x2c Keypad Facility [O] */
            if (iei == 0x2c) {
                t2buf_skip_u8(t2buf); // iei
                GSM_DBG_DTAP("%" PRIu64 ": Keypad Facility", numPackets);
                t2buf_skip_u8(t2buf);
            }
            break;
        }

        case 0x31: { // Stop DTMF
            GSM_DBG_DTAP("%" PRIu64 ": CC Miscellaneous message: Stop DTMF", numPackets);
            uint8_t iei;
            GSM_DTAP_PEEK_IEI(t2buf, &iei);
            /* 0x2c Keypad Facility [O] */
            if (iei == 0x2c) {
                t2buf_skip_u8(t2buf); // iei
                GSM_DBG_DTAP("%" PRIu64 ": Keypad Facility", numPackets);
                t2buf_skip_u8(t2buf);
            }
            break;
        }

        case 0x32: { // Stop DTMF Acknowledge
            GSM_DBG_DTAP("%" PRIu64 ": CC Miscellaneous message: Stop DTMF Acknowledge", numPackets);
            md->gsmFlowP->pstat |= GSM_STAT_DOWNLINK;
            break;
        }

        case 0x36: { // Start DTMF Acknowledge
            GSM_DBG_DTAP("%" PRIu64 ": CC Miscellaneous message: Start DTMF Acknowledge", numPackets);
            md->gsmFlowP->pstat |= GSM_STAT_DOWNLINK;
            break;
        }

        case 0x37: { // Start DTMF Reject
            md->gsmFlowP->pstat |= GSM_STAT_DOWNLINK;
            /* Cause */
            uint8_t cause = t2buf_dissect_dtap_cause(t2buf);
            GSM_DBG_DTAP("%" PRIu64 ": CC Miscellaneous message: Start DTMF Reject: Cause: %u (%s)", numPackets, cause, gsm48_cc_cause_name(cause));
            break;
        }

        default:
#if GSM_DBG_DTAP_UNK == 1
            GSM_DBG_DTAP("%" PRIu64 ": Unknown CC message type: 0x%02" B2T_PRIX8, numPackets, msg_type);
#endif
            break;
    }

#if GSM_CALLFILE == 1
    if (md->a_dtap.gsmCCMsgTypeStr) {
        const time_t sec = md->flowP->lastSeen.tv_sec;
        const intmax_t usec = md->flowP->lastSeen.tv_usec;
        if (md->a_dtap.caller.number || md->a_dtap.callee.number) {
            t2_normalize_e164(&md->a_dtap.caller, &md->a_dtap.callee);
            t2_normalize_e164(&md->a_dtap.callee, &md->a_dtap.caller);
        }

        if (!md->rsl.channel.str) {
            md->rsl.channel.str = channel_to_str(&md->rsl.channel);
        }

        FILE * const callFp = file_manager_fp(t2_file_manager, callFile);
        fprintf(callFp,
                "%" PRIu64  /* pktNo            */ SEP_CHR
                "%" PRIu64  /* flowInd          */ SEP_CHR
                "%ld.%06jd" /* time             */ SEP_CHR
                "%" PRIu16  /* vlanID           */ SEP_CHR
                "%" PRIu8   /* lapdTEI          */ SEP_CHR
                "%s"        /* gsmMsgType       */ SEP_CHR
                "%s"        /* gsmCause         */ SEP_CHR
                "%" PRIu8   /* gsmRslTN         */ SEP_CHR
                "%" PRIu8   /* gsmRslSubCh      */ SEP_CHR
                "%s"        /* gsmRslChannel    */ SEP_CHR
                "%s"        /* gsmCaller        */ SEP_CHR
                "%s"        /* gsmCallerCountry */ SEP_CHR
                "%s"        /* gsmCallee        */ SEP_CHR
                "%s"        /* gsmCalleeCountry */ "\n"
                ,
                numPackets,
                md->flowP->findex,
                sec, usec,
                md->flowP->vlanId,
                md->gsmFlowP->tei,
                md->a_dtap.gsmCCMsgTypeStr,
                ((md->a_dtap.cause > 0) ? gsm48_cc_cause_name(md->a_dtap.cause) : ""),
                md->rsl.channel.tn,
                md->rsl.channel.subchannel,
                md->rsl.channel.str,
                md->a_dtap.caller.number  ? md->a_dtap.caller.number  : "",
                md->a_dtap.caller.country ? md->a_dtap.caller.country : "",
                md->a_dtap.callee.number  ? md->a_dtap.callee.number  : "",
                md->a_dtap.callee.country ? md->a_dtap.callee.country :
                    md->a_dtap.callee.type == 2 && md->a_dtap.caller.country ? md->a_dtap.caller.country : "");
    }
#endif

    return has_next_layer;
}


/* ========================================================================= */
/* Mobility Management messages (MM)                                         */
/* ========================================================================= */
static inline bool dissect_gsm_a_dtap_mm(t2buf_t *t2buf, uint8_t msg_type, gsm_metadata_t *md) {

    numGSMDTAPMM++;
    numDtapMM[msg_type]++;
    md->gsmFlowP->pstat |= GSM_STAT_DTAP_MM;

    bool has_next_layer = false;

    switch (msg_type) {

        /* ----------------------------------------------------------------- */
        /* MM Registration messages                                          */
        /* ----------------------------------------------------------------- */

        case 0x01: { // IMSI detach indication
            GSM_DBG_DTAP("%" PRIu64 ": MM Registration message: IMSI Detach Indication", numPackets);
            md->gsmFlowP->pstat |= GSM_STAT_UPLINK;
            /* Mobile Station Classmark 1 */
            t2buf_skip_u8(t2buf);
            /* Mobile Identity */
            gsmMobileIdentity_t id = t2buf_read_mobile_identity(t2buf, md);
            gsm_mobile_identity_free(&id);
            break;
        }

        case 0x02: { // Location Updating Accept
            md->gsmFlowP->pstat |= GSM_STAT_DOWNLINK;
            /* Location Area Identification (LAI) */
            md->a_dtap.lai = t2buf_dissect_dtap_lai(t2buf);
            uint8_t iei;
            GSM_DTAP_PEEK_IEI(t2buf, &iei);
            /* 0x17 Mobile Identity [O] */
            if (iei == 0x17) {
                t2buf_skip_u8(t2buf); // iei
                gsmMobileIdentity_t id = t2buf_read_mobile_identity(t2buf, md);
                gsm_mobile_identity_free(&id);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0xa1 Follow-on Proceed [O] */
            if (iei == 0xa1) {
                t2buf_skip_u8(t2buf); // iei
                GSM_DBG_DTAP("%" PRIu64 ": Follow-on Proceed", numPackets);
                // Nothing to do
            }
            break;
        }

        case 0x04: { // Location Updating Reject
            md->gsmFlowP->pstat |= GSM_STAT_DOWNLINK;
            /* Reject cause */
            uint8_t cause;
            t2buf_read_u8(t2buf, &cause);
            GSM_DBG_DTAP("%" PRIu64 ": MM Registration message: Location Updating Reject: Reject Cause=%u", numPackets, cause);
            break;
        }

        case 0x08: { // Location Updating Request
            md->gsmFlowP->pstat |= GSM_STAT_UPLINK;
            /* Location Updating Type and Ciphering Key Sequence */
            t2buf_skip_u8(t2buf);
            /* Location Area Identification (LAI) */
            md->a_dtap.lai = t2buf_dissect_dtap_lai(t2buf);
            /* Mobile Station Classmark 1 */
            t2buf_skip_u8(t2buf);
            /* Mobile Identity */
            gsmMobileIdentity_t id = t2buf_read_mobile_identity(t2buf, md);
            gsm_mobile_identity_free(&id);
            break;
        }

        /* ----------------------------------------------------------------- */
        /* MM Security messages                                              */
        /* ----------------------------------------------------------------- */

        case 0x11: { // Authentication Reject
            GSM_DBG_DTAP("%" PRIu64 ": MM Security message: Authentication Reject", numPackets);
            md->gsmFlowP->pstat |= GSM_STAT_UPLINK;
            break;
        }

        case 0x12: { // Authentication Request
            GSM_DBG_DTAP("%" PRIu64 ": MM Security message: Authentication Request", numPackets);
            md->gsmFlowP->pstat |= GSM_STAT_DOWNLINK;
            /* Ciphering Key Sequence Number and Spare Half Octet */
            t2buf_skip_u8(t2buf);
            /* Authentication Parameter RAND */
            t2buf_skip_n(t2buf, 16);
            break;
        }

        case 0x14: { // Authentication Response
            GSM_DBG_DTAP("%" PRIu64 ": MM Security message: Authentication Response", numPackets);
            md->gsmFlowP->pstat |= GSM_STAT_UPLINK;
            /* Authentication Parameter SRES */
            t2buf_skip_n(t2buf, 4);
            break;
        }

        case 0x18: { // Identity Request
            md->gsmFlowP->pstat |= GSM_STAT_DOWNLINK;
            /* Identity Type and Spare Half Octet */
            uint8_t octet;
            t2buf_read_u8(t2buf, &octet);
            const uint8_t id_type = (octet & 0x07);
            GSM_DBG_DTAP("%" PRIu64 ": MM Security message: Identity Request: %s", numPackets,
                    ((id_type == 0x01) ? "IMSI" :
                     (id_type == 0x02) ? "IMEI" :
                     (id_type == 0x03) ? "IMEISV" :
                     (id_type == 0x04) ? "TMSI" : "Reserved"));;
            break;
        }

        case 0x19: {  // Identity Response
            GSM_DBG_DTAP("%" PRIu64 ": MM Security message: Identity Response", numPackets);
            md->gsmFlowP->pstat |= GSM_STAT_UPLINK;
            /* Mobile Identity */
            gsmMobileIdentity_t id = t2buf_read_mobile_identity(t2buf, md);
            gsm_mobile_identity_free(&id);
            break;
        }

        case 0x1a: { // TMSI Reallocation Command
            GSM_DBG_DTAP("%" PRIu64 ": MM Security message: TMSI Reallocation Command", numPackets);
            md->gsmFlowP->pstat |= GSM_STAT_DOWNLINK;
            /* Location Area Identification (LAI) */
            md->a_dtap.lai = t2buf_dissect_dtap_lai(t2buf);
            /* Mobile Identity */
            gsmMobileIdentity_t id = t2buf_read_mobile_identity(t2buf, md);
            gsm_mobile_identity_free(&id);
            break;
        }

        case 0x1b: { // TMSI Reallocation Complete
            GSM_DBG_DTAP("%" PRIu64 ": MM Security message: TMSI Reallocation Complete", numPackets);
            break;
        }

        /* ----------------------------------------------------------------- */
        /* MM Connection Management messages                                 */
        /* ----------------------------------------------------------------- */

        case 0x21: { // CM Service Accept
            GSM_DBG_DTAP("%" PRIu64 ": MM Connection Management message: CM Service Accept", numPackets);
            break;
        }

        case 0x22: { // CM Service Reject
            md->gsmFlowP->pstat |= GSM_STAT_DOWNLINK;
            /* Reject cause */
            uint8_t cause;
            t2buf_read_u8(t2buf, &cause);
            GSM_DBG_DTAP("%" PRIu64 ": MM Connection Management message: CM Service Reject: Reject Cause=%u", numPackets, cause);
            break;
        }

        case 0x23: { // CM Service Abort
            GSM_DBG_DTAP("%" PRIu64 ": MM Connection Management message: CM Service Abort", numPackets);
            break;
        }

        case 0x24: { // CM Service Request
            GSM_DBG_DTAP("%" PRIu64 ": MM Connection Management message: CM Service Request", numPackets);
            md->gsmFlowP->pstat |= GSM_STAT_UPLINK;
            // CM Service Type and Ciphering Key Sequence Number */
            t2buf_skip_u8(t2buf);
            /* Mobile Station Classmark 2 */
            T2BUF_SKIP_LV(t2buf);
            /* Mobile Identity */
            gsmMobileIdentity_t id = t2buf_read_mobile_identity(t2buf, md);
            gsm_mobile_identity_free(&id);
            break;
        }

        case 0x28: { // CM Re-Establishment Request
            GSM_DBG_DTAP("%" PRIu64 ": MM Connection Management message: CM Re-Establishment Request", numPackets);
            md->gsmFlowP->pstat |= GSM_STAT_UPLINK;
            /* Ciphering Key Sequence Number and Spare Half Octet */
            t2buf_skip_u8(t2buf);
            /* Mobile Station Classmark 2 */
            T2BUF_SKIP_LV(t2buf);
            /* Mobile Identity */
            // Skip over Mobile Identity to load LAI first
            const uint8_t pos = t2buf_tell(t2buf);
            T2BUF_SKIP_LV(t2buf);
            uint8_t iei;
            GSM_DTAP_PEEK_IEI(t2buf, &iei);
            /* 0x13 Location Area Identification [C] */
            if (iei == 0x13) {
                t2buf_skip_u8(t2buf); // iei
                md->a_dtap.lai = t2buf_dissect_dtap_lai(t2buf);
            }
            // Go back to Mobile Identity
            t2buf_seek(t2buf, pos, SEEK_SET);
            /* Mobile Identity */
            gsmMobileIdentity_t id = t2buf_read_mobile_identity(t2buf, md);
            gsm_mobile_identity_free(&id);
            break;
        }

        case 0x29: { // Abort
            md->gsmFlowP->pstat |= GSM_STAT_DOWNLINK;
            /* Reject cause */
            uint8_t cause;
            t2buf_read_u8(t2buf, &cause);
            GSM_DBG_DTAP("%" PRIu64 ": MM Connection Management message: Abort: Reject Cause=%u", numPackets, cause);
            break;
        }

        /* ----------------------------------------------------------------- */
        /* MM Miscellaneous messages                                         */
        /* ----------------------------------------------------------------- */

        case 0x31: { // MM Status
            md->gsmFlowP->pstat |= GSM_STAT_UPLINK;
            /* Reject cause */
            uint8_t cause;
            t2buf_read_u8(t2buf, &cause);
            GSM_DBG_DTAP("%" PRIu64 ": MM Miscellaneous message: MM Status: Reject Cause=%u", numPackets, cause);
            break;
        }

        case 0x32: { // MM Information
            GSM_DBG_DTAP("%" PRIu64 ": MM Miscellaneous message: Information", numPackets);
            md->gsmFlowP->pstat |= GSM_STAT_UPLINK;
            uint8_t iei;
            GSM_DTAP_PEEK_IEI(t2buf, &iei);
            /* 0x43 Full Name for network [O]  */
            if (iei == 0x43) {
                t2buf_skip_u8(t2buf); // iei
                uint8_t len;
                t2buf_read_u8(t2buf, &len);
                if (len <= 1) {
                    md->gsmFlowP->pstat |= GSM_STAT_DTAP_MALFORMED;
                    return false;
                }
                uint8_t flags;
                t2buf_read_u8(t2buf, &flags);
                //const uint8_t extension = !((flags & 0xf0) >> 7); // 1: no extension
                const uint8_t coding_scheme = ((flags & 0x70) >> 4); // 1: UCS2
                //const uint8_t add_ci = ((flags & 0x08) >> 3);
                //const uint8_t spare_bits = (flags & 0x07);
                if (coding_scheme == 1) {
                    if (md->a_dtap.full_network_name) {
                        GSM_DBG_DTAP("%" PRIu64 ": DTAP full network name already exists: %s", numPackets, md->a_dtap.full_network_name);
                        free(md->a_dtap.full_network_name);
                    }
                    md->a_dtap.full_network_name = t2buf_read_ucs2_as_utf8(t2buf, len-1);
                    GSM_DBG_DTAP("%" PRIu64 ": Full Network Name: %s", numPackets, md->a_dtap.full_network_name);
                } else {
                    GSM_DBG_DTAP("%" PRIu64 ": Full Network Name: Not in UCS2: 0x%02" B2T_PRIX8, numPackets, coding_scheme);
                }
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x45 Short Name for network [O]  */
            if (iei == 0x45) {
                t2buf_skip_u8(t2buf); // iei
                uint8_t len;
                t2buf_read_u8(t2buf, &len);
                if (len <= 1) {
                    md->gsmFlowP->pstat |= GSM_STAT_DTAP_MALFORMED;
                    return false;
                }
                uint8_t flags;
                t2buf_read_u8(t2buf, &flags);
                //const uint8_t extension = !((flags & 0xf0) >> 7); // 1: no extension
                const uint8_t coding_scheme = ((flags & 0x70) >> 4); // 1: UCS2
                //const uint8_t add_ci = ((flags & 0x08) >> 3);
                //const uint8_t spare_bits = (flags & 0x07);
                if (coding_scheme == 1) {
                    if (md->a_dtap.short_network_name) {
                        GSM_DBG_DTAP("%" PRIu64 ": DTAP short network name already exists: %s", numPackets, md->a_dtap.short_network_name);
                        free(md->a_dtap.short_network_name);
                    }
                    md->a_dtap.short_network_name = t2buf_read_ucs2_as_utf8(t2buf, len-1);
                    GSM_DBG_DTAP("%" PRIu64 ": Short Network Name: %s", numPackets, md->a_dtap.short_network_name);
                } else {
                    GSM_DBG_DTAP("%" PRIu64 ": Short Network Name: Not in UCS2: 0x%02" B2T_PRIX8, numPackets, coding_scheme);
                }
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x46 Network Time Zone [O]  */
            if (iei == 0x46) {
                t2buf_skip_u8(t2buf); // iei
                uint8_t tz;
                t2buf_read_u8(t2buf, &tz);
                const uint8_t oct = (tz >> 4) + (tz & 0x07) * 10;
                if (md->a_dtap.network_time_zone) {
                    GSM_DBG_DTAP("%" PRIu64 ": DTAP network time zone already exists: %s", numPackets, md->a_dtap.network_time_zone);
                    free(md->a_dtap.network_time_zone);
                }
                md->a_dtap.network_time_zone = t2_strdup_printf("GMT %c%d:%d",
                    ((tz & 0x08) ? '-' : '+'),
                    oct / 4, (oct % 4) * 15);
                GSM_DBG_DTAP("%" PRIu64 ": Time Zone - Local: %s", numPackets, md->a_dtap.network_time_zone);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x47 Network Time and Time Zone [O]  */
            if (iei == 0x47) {
                t2buf_skip_u8(t2buf); // iei
                uint8_t year;
                t2buf_read_u8(t2buf, &year);
                uint8_t month;
                t2buf_read_u8(t2buf, &month);
                uint8_t day;
                t2buf_read_u8(t2buf, &day);
                uint8_t hour;
                t2buf_read_u8(t2buf, &hour);
                uint8_t minute;
                t2buf_read_u8(t2buf, &minute);
                uint8_t second;
                t2buf_read_u8(t2buf, &second);
                uint8_t tz;
                t2buf_read_u8(t2buf, &tz);
                if (md->a_dtap.network_time_and_time_zone) {
                    GSM_DBG_DTAP("%" PRIu64 ": DTAP network time and time zone already exists: %s", numPackets, md->a_dtap.network_time_and_time_zone);
                    free(md->a_dtap.network_time_and_time_zone);
                }
                md->a_dtap.network_time_and_time_zone = t2_strdup_printf(
                    "%02" B2T_PRIX8 "/%02" B2T_PRIX8 "/%02" B2T_PRIX8 " "
                    "%02" B2T_PRIX8 ":%02" B2T_PRIX8 ":%02" B2T_PRIX8 " "
                    "UTC%c%02u",
                    (uint8_t)((year   & 0x0f) << 4 | year   >> 4),
                    (uint8_t)((month  & 0x0f) << 4 | month  >> 4),
                    (uint8_t)((day    & 0x0f) << 4 | day    >> 4),
                    (uint8_t)((hour   & 0x0f) << 4 | hour   >> 4),
                    (uint8_t)((minute & 0x0f) << 4 | minute >> 4),
                    (uint8_t)((second & 0x0f) << 4 | second >> 4),
                    ((tz & 0x80) ? '-' : '+'),
                    ((tz & 0x0f) << 4 | (tz & 0x70) >> 4) / 4);
                GSM_DBG_DTAP("%" PRIu64 ": Network Time and Time Zone: %s", numPackets, md->a_dtap.network_time_and_time_zone);
            }
            break;
        }

        default:
#if GSM_DBG_DTAP_UNK == 1
            GSM_DBG_DTAP("%" PRIu64 ": Unknown MM message type: 0x%02" B2T_PRIX8, numPackets, msg_type);
#endif
            break;
    }

#if GSM_OPFILE == 1
    if (md->a_dtap.full_network_name || md->a_dtap.short_network_name) {
        const time_t sec = md->flowP->lastSeen.tv_sec;
        const intmax_t usec = md->flowP->lastSeen.tv_usec;
        if (!md->rsl.channel.str) {
            md->rsl.channel.str = channel_to_str(&md->rsl.channel);
        }

        FILE * const opFp = file_manager_fp(t2_file_manager, opFile);
        fprintf(opFp,
                "%" PRIu64  /* pktNo               */ SEP_CHR
                "%" PRIu64  /* flowInd             */ SEP_CHR
                "%ld.%06jd" /* time                */ SEP_CHR
                "%" PRIu16  /* vlanID              */ SEP_CHR
                "%" PRIu8   /* lapdTEI             */ SEP_CHR
                "%" PRIu8   /* gsmRslTN            */ SEP_CHR
                "%" PRIu8   /* gsmRslSubCh         */ SEP_CHR
                "%s"        /* gsmRslChannel       */ SEP_CHR
                "%s"        /* gsmFullNetworkName  */ SEP_CHR
                "%s"        /* gsmShortNetworkName */ SEP_CHR
                "%s"        /* gsmTimeZone         */ SEP_CHR
                "%s"        /* gsmTimeAndTimeZone  */ "\n"
                ,
                numPackets,
                md->flowP->findex,
                sec, usec,
                md->flowP->vlanId,
                md->gsmFlowP->tei,
                md->rsl.channel.tn,
                md->rsl.channel.subchannel,
                md->rsl.channel.str,
                md->a_dtap.full_network_name ? md->a_dtap.full_network_name : "",
                md->a_dtap.short_network_name ? md->a_dtap.short_network_name : "",
                md->a_dtap.network_time_zone ? md->a_dtap.network_time_zone : "",
                md->a_dtap.network_time_and_time_zone ? md->a_dtap.network_time_and_time_zone : "");
    }
#endif

    return has_next_layer;
}


/* ========================================================================= */
/* Radio Resources Management messages (RR)                                  */
/* ========================================================================= */
static inline bool dissect_gsm_a_dtap_rr(t2buf_t *t2buf, uint8_t msg_type, gsm_metadata_t *md) {

    numGSMDTAPRR++;
    numDtapRR[msg_type]++;
    md->gsmFlowP->pstat |= GSM_STAT_DTAP_RR;

    bool has_next_layer = false;

    switch (msg_type) {

        /* ----------------------------------------------------------------- */
        /* RR Channel Establishment messages                                 */
        /* ----------------------------------------------------------------- */

        case 0x3b: { // Additional Assignment
            GSM_DBG_DTAP("%" PRIu64 ": RR Channel Establishment message: Additional Assignment", numPackets);
            /* Channel Description */
            if (md->a_dtap.channel.channel) {
                GSM_DBG_DTAP("%" PRIu64 ": DTAP channel description already exists: %s", numPackets, md->a_dtap.channel.channel);
                gsm_channel_description_free(&md->a_dtap.channel);
            }
            md->a_dtap.channel = t2buf_read_channel_description(t2buf, md);
            GSM_DBG_DTAP("%" PRIu64 ": Channel Description: %s", numPackets, md->a_dtap.channel.channel);
            uint8_t iei;
            GSM_DTAP_PEEK_IEI(t2buf, &iei);
            /* 0x72 Mobile Allocation [C] */
            if (iei == 0x72) {
                GSM_DBG_DTAP("%" PRIu64 ": Mobile Allocation", numPackets);
                T2BUF_SKIP_TLV(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x7c Starting Time [O] */
            if (iei == 0x7c) {
                t2buf_skip_u8(t2buf); // iei
                GSM_DBG_DTAP("%" PRIu64 ": Starting Time", numPackets);
                t2buf_skip_u16(t2buf);
            }
            break;
        }

        case 0x3f: { // Immediate Assignment
            GSM_DBG_DTAP("%" PRIu64 ": RR Channel Establishment message: Immediate Assignment", numPackets);
            /* Page Mode and Spare Half Octet (or dedicated mode or TBF) */
            t2buf_skip_u8(t2buf);
            GSM_DBG_DTAP("%" PRIu64 ": Page Mode and dedicated mode or TBF", numPackets);
            /* (Packet) Channel Description */
            if (md->a_dtap.channel.channel) {
                GSM_DBG_DTAP("%" PRIu64 ": DTAP channel description already exists: %s", numPackets, md->a_dtap.channel.channel);
                gsm_channel_description_free(&md->a_dtap.channel);
            }
            md->a_dtap.channel = t2buf_read_channel_description(t2buf, md);
            GSM_DBG_DTAP("%" PRIu64 ": Channel description: %s", numPackets, md->a_dtap.channel.channel);
            /* Request Reference */
            t2buf_read_request_reference(t2buf, &md->a_dtap.req_ref);
            /* Timing Advance */
            t2buf_read_timing_advance(t2buf, &md->a_dtap.ta, &md->a_dtap.bts_dist);
            /* Mobile Allocation */
            T2BUF_SKIP_LV(t2buf);
            uint8_t iei;
            GSM_DTAP_PEEK_IEI(t2buf, &iei);
            /* 0x7c Starting Time [O] */
            if (iei == 0x7c) {
                t2buf_skip_u8(t2buf); // iei
                GSM_DBG_DTAP("%" PRIu64 ": Starting Time", numPackets);
                t2buf_skip_u16(t2buf);
            }
            // IA Rest Octets
            break;
        }

        case 0x39: { // Immediate Assignment Extended
            GSM_DBG_DTAP("%" PRIu64 ": RR Channel Establishment message: Immediate Assignment Extended", numPackets);
            /* Page Mode and Spare Half Octet (or feature indicator) */
            t2buf_skip_u8(t2buf);
            /* Channel Description 1 */
            if (md->a_dtap.channel.channel) {
                GSM_DBG_DTAP("%" PRIu64 ": DTAP channel description already exists: %s", numPackets, md->a_dtap.channel.channel);
                gsm_channel_description_free(&md->a_dtap.channel);
            }
            md->a_dtap.channel = t2buf_read_channel_description(t2buf, md);
            GSM_DBG_DTAP("%" PRIu64 ": Channel description 1: %s", numPackets, md->a_dtap.channel.channel);
            /* Request Reference 1 */
            gsm_request_reference_t ref1 = {};
            t2buf_read_request_reference(t2buf, &ref1);
            /* Timing Advance 1 */
            t2buf_read_timing_advance(t2buf, &md->a_dtap.ta, &md->a_dtap.bts_dist);
            /* Channel Description 2 */
            gsmChannelDescription_t channel = t2buf_read_channel_description(t2buf, md);
            GSM_DBG_DTAP("%" PRIu64 ": Channel description 2: %s", numPackets, channel.channel);
            gsm_channel_description_free(&channel);
            /* Request Reference 2 */
            gsm_request_reference_t ref2 = {};
            t2buf_read_request_reference(t2buf, &ref2);
            /* Timing Advance 2 */
            uint8_t ta2 = 0;
            uint16_t bts_dist2 = 0;
            t2buf_read_timing_advance(t2buf, &ta2, &bts_dist2);
            /* Mobile Allocation */
            T2BUF_SKIP_LV(t2buf);
            uint8_t iei;
            GSM_DTAP_PEEK_IEI(t2buf, &iei);
            /* 0x7c Starting Time [O] */
            if (iei == 0x7c) {
                t2buf_skip_u8(t2buf); // iei
                GSM_DBG_DTAP("%" PRIu64 ": Starting Time", numPackets);
                t2buf_skip_u16(t2buf);
            }
            // IAX Rest Octets
            break;
        }

        case 0x3a: { // Immediate Assignment Reject
            GSM_DBG_DTAP("%" PRIu64 ": RR Channel Establishment message: Immediate Assignment Reject", numPackets);
            /* Page Mode and Spare Half Octet (or feature indicator) */
            t2buf_skip_u8(t2buf);
            /* Request Reference 1 */
            t2buf_read_request_reference(t2buf, &md->a_dtap.req_ref);
            /* Wait Indication 1 */
            uint8_t wait;
            t2buf_read_u8(t2buf, &wait);
            GSM_DBG_DTAP("%" PRIu64 ": Wait Indication 1: %u", numPackets, wait);
            /* Request Reference 2 */
            gsm_request_reference_t ref2 = {};
            t2buf_read_request_reference(t2buf, &ref2);
            /* Wait Indication 2 */
            t2buf_read_u8(t2buf, &wait);
            GSM_DBG_DTAP("%" PRIu64 ": Wait Indication 2: %u", numPackets, wait);
            /* Request Reference 3 */
            gsm_request_reference_t ref3 = {};
            t2buf_read_request_reference(t2buf, &ref3);
            /* Wait Indication 3 */
            t2buf_read_u8(t2buf, &wait);
            GSM_DBG_DTAP("%" PRIu64 ": Wait Indication 3: %u", numPackets, wait);
            /* Request Reference 4 */
            gsm_request_reference_t ref4 = {};
            t2buf_read_request_reference(t2buf, &ref4);
            /* Wait Indication 4 */
            t2buf_read_u8(t2buf, &wait);
            GSM_DBG_DTAP("%" PRIu64 ": Wait Indication 4: %u", numPackets, wait);
            /* IAR Rest octets */
            t2buf_skip_n(t2buf, 3);
            break;
        }

        /* ----------------------------------------------------------------- */
        /* RR Ciphering messages                                             */
        /* ----------------------------------------------------------------- */

        case 0x35: { // Ciphering Mode Command
            /* Ciphering Mode Setting and Cipher Response */
            uint8_t octet;
            t2buf_read_u8(t2buf, &octet);
            const uint8_t mode = ((octet & 0x0e) >> 1);
            const uint8_t sc = (octet & 0x01);
            if (sc == 0) {
                GSM_DBG_DTAP("%" PRIu64 ": RR Ciphering message: Ciphering Mode Command: No Ciphering", numPackets);
            } else {
                switch (mode) {
                    case 0x00: memcpy(md->a_dtap.enc, "A5/1", sizeof(md->a_dtap.enc)); break;
                    case 0x01: memcpy(md->a_dtap.enc, "A5/1", sizeof(md->a_dtap.enc)); break;
                    case 0x02: memcpy(md->a_dtap.enc, "A5/1", sizeof(md->a_dtap.enc)); break;
                    case 0x03: memcpy(md->a_dtap.enc, "A5/1", sizeof(md->a_dtap.enc)); break;
                    case 0x04: memcpy(md->a_dtap.enc, "A5/1", sizeof(md->a_dtap.enc)); break;
                    case 0x05: memcpy(md->a_dtap.enc, "A5/1", sizeof(md->a_dtap.enc)); break;
                    case 0x06: memcpy(md->a_dtap.enc, "A5/1", sizeof(md->a_dtap.enc)); break;
                    default: memcpy(md->a_dtap.enc,   "RSVD", sizeof(md->a_dtap.enc)); break; // reserved
                }
                GSM_DBG_DTAP("%" PRIu64 ": RR Ciphering message: Ciphering Mode Command: Start Ciphering: %s%s", numPackets,
                        ((mode > 0x06) ? "Reserved" : "Cipher with Algorithm "), md->a_dtap.enc);
            }
            break;
        }

        case 0x32: { // Ciphering Mode Complete
            GSM_DBG_DTAP("%" PRIu64 ": RR Ciphering message: Ciphering Mode Complete", numPackets);
            uint8_t iei;
            GSM_DTAP_PEEK_IEI(t2buf, &iei);
            /* 0x17 Mobile Identity [O] */
            if (iei == 0x17) {
                t2buf_skip_u8(t2buf); // iei
                gsmMobileIdentity_t id = t2buf_read_mobile_identity(t2buf, md);
                gsm_mobile_identity_free(&id);
            }
            break;
        }

        /* ----------------------------------------------------------------- */
        /* RR Handover messages                                              */
        /* ----------------------------------------------------------------- */

        case 0x2e: { // Assignment Command
            GSM_DBG_DTAP("%" PRIu64 ": RR Handover message: Assignment Command", numPackets);
            /* Channel Description 2 */
            if (md->a_dtap.channel.channel) {
                GSM_DBG_DTAP("%" PRIu64 ": DTAP channel description already exists: %s", numPackets, md->a_dtap.channel.channel);
                gsm_channel_description_free(&md->a_dtap.channel);
            }
            md->a_dtap.channel = t2buf_dissect_dtap_channel_description_2(t2buf, md);
            GSM_DBG_DTAP("%" PRIu64 ": Description of the First Channel, after time: %s", numPackets, md->a_dtap.channel.channel);
            /* Power Command */
            uint8_t power;
            t2buf_read_u8(t2buf, &power);
            const uint8_t epc_mode = ((power & 0x40) >> 6);
            const uint8_t fpc_epc_mode = ((power & 0x20) >> 5);
            const uint8_t level = (power & 0x1f);
            if (level == 0) {
                GSM_DBG_DTAP("%" PRIu64 ": Power Command: Pn, Channel(s) %sin EPC mode, FPC %sin use/EPC %sin use for uplink power control", numPackets, (epc_mode ? "" : "not "), (fpc_epc_mode ? "" : "not "), (fpc_epc_mode ? "" : "not "));
            } else {
                GSM_DBG_DTAP("%" PRIu64 ": Power Command: Pn - %u dB, Channel(s) %sin EPC mode, FPC %sin use/EPC %sin use for uplink power control", numPackets, level, (epc_mode ? "" : "not "), (fpc_epc_mode ? "" : "not "), (fpc_epc_mode ? "" : "not "));
            }
            uint8_t iei;
            GSM_DTAP_PEEK_IEI(t2buf, &iei);
            /* 0x05 Frequency List, after time [C] */
            if (iei == 0x05) {
                GSM_DBG_DTAP("%" PRIu64 ": Frequency List, after time", numPackets);
                T2BUF_SKIP_TLV(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x62 Cell Channel Description [O] */
            if (iei == 0x62) {
                t2buf_dissect_dtap_ie_cell_channel_description(t2buf, md->gsmFlowP, false);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x10 Multislot Allocation */
            if (iei == 0x10) {
                GSM_DBG_DTAP("%" PRIu64 ": Description of the multislot configuration", numPackets);
                T2BUF_SKIP_TLV(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x63 Mode of the First Channel (Channel Set 1) [O] */
            if (iei == 0x63) {
                t2buf_skip_u8(t2buf); // iei
                GSM_DBG_DTAP("%" PRIu64 ": Mode of the First Channel (Channel Set 1)", numPackets);
                md->a_dtap.mode = t2buf_dissect_dtap_channel_mode(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x11 Channel Mode */
            if (iei == 0x11) {
                t2buf_skip_u8(t2buf); // iei
                GSM_DBG_DTAP("%" PRIu64 ": Mode of Channel Set 2", numPackets);
                /*const uint8_t mode = */t2buf_dissect_dtap_channel_mode(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x13 Channel Mode */
            if (iei == 0x13) {
                t2buf_skip_u8(t2buf); // iei
                GSM_DBG_DTAP("%" PRIu64 ": Mode of Channel Set 3", numPackets);
                /*const uint8_t mode = */t2buf_dissect_dtap_channel_mode(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x14 Channel Mode */
            if (iei == 0x14) {
                t2buf_skip_u8(t2buf); // iei
                GSM_DBG_DTAP("%" PRIu64 ": Mode of Channel Set 4", numPackets);
                /*const uint8_t mode = */t2buf_dissect_dtap_channel_mode(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x15 Channel Mode */
            if (iei == 0x15) {
                t2buf_skip_u8(t2buf); // iei
                GSM_DBG_DTAP("%" PRIu64 ": Mode of Channel Set 5", numPackets);
                /*const uint8_t mode = */t2buf_dissect_dtap_channel_mode(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x16 Channel Mode */
            if (iei == 0x16) {
                t2buf_skip_u8(t2buf); // iei
                GSM_DBG_DTAP("%" PRIu64 ": Mode of Channel Set 6", numPackets);
                /*const uint8_t mode = */t2buf_dissect_dtap_channel_mode(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x17 Channel Mode */
            if (iei == 0x17) {
                t2buf_skip_u8(t2buf); // iei
                GSM_DBG_DTAP("%" PRIu64 ": Mode of Channel Set 7", numPackets);
                /*const uint8_t mode = */t2buf_dissect_dtap_channel_mode(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x18 Channel Mode */
            if (iei == 0x18) {
                t2buf_skip_u8(t2buf); // iei
                GSM_DBG_DTAP("%" PRIu64 ": Mode of Channel Set 8", numPackets);
                /*const uint8_t mode = */t2buf_dissect_dtap_channel_mode(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x64 Description of the Second Channel, after time [O] */
            if (iei == 0x64) {
                t2buf_skip_u8(t2buf); // iei
                gsmChannelDescription_t channel = t2buf_read_channel_description(t2buf, md);
                GSM_DBG_DTAP("%" PRIu64 ": Description of the Second Channel, after time: %s", numPackets, channel.channel);
                gsm_channel_description_free(&channel);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x66 Mode of the Second Channel [O] */
            if (iei == 0x66) {
                t2buf_skip_u8(t2buf); // iei
                GSM_DBG_DTAP("%" PRIu64 ": Mode of the Second Channel", numPackets);
                /*const uint8_t mode = */t2buf_dissect_dtap_channel_mode(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x72 Mobile Allocation, after time [O] */
            if (iei == 0x72) {
                GSM_DBG_DTAP("%" PRIu64 ": Mobile Allocation, after time", numPackets);
                T2BUF_SKIP_TLV(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x7c Starting Time [O] */
            if (iei == 0x7c) {
                t2buf_skip_u8(t2buf); // iei
                GSM_DBG_DTAP("%" PRIu64 ": Starting Time", numPackets);
                t2buf_skip_u16(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x19 Frequency List, before time [O] */
            if (iei == 0x19) {
                GSM_DBG_DTAP("%" PRIu64 ": Frequency List, before time", numPackets);
                T2BUF_SKIP_TLV(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x1c Description of the First Channel, before time [O] */
            if (iei == 0x1c) {
                t2buf_skip_u8(t2buf); // iei
                gsmChannelDescription_t channel = t2buf_dissect_dtap_channel_description_2(t2buf, md);
                GSM_DBG_DTAP("%" PRIu64 ": Description of the First Channel, before time: %s", numPackets, channel.channel);
                free(channel.channel);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x1d Description of the Second Channel, before time [O] */
            if (iei == 0x1d) {
                t2buf_skip_u8(t2buf); // iei
                gsmChannelDescription_t channel = t2buf_read_channel_description(t2buf, md);
                GSM_DBG_DTAP("%" PRIu64 ": Description of the Second Channel, before time: %s", numPackets, channel.channel);
                gsm_channel_description_free(&channel);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x1e Frequency Channel Sequence, before time [O] */
            if (iei == 0x1e) {
                t2buf_skip_u8(t2buf); // iei
                GSM_DBG_DTAP("%" PRIu64 ": Frequency Channel Sequence, before time", numPackets);
                t2buf_skip_n(t2buf, 9);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x21 Mobile Allocation, before time [O] */
            if (iei == 0x21) {
                GSM_DBG_DTAP("%" PRIu64 ": Mobile Allocation, before time", numPackets);
                T2BUF_SKIP_TLV(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x9- Cipher Mode Setting [O] */
            if ((iei & 0xf0) == 0x90) {
                t2buf_skip_u8(t2buf); // iei
                GSM_DBG_DTAP("%" PRIu64 ": Cipher Mode Setting", numPackets);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x01 VGCS Target Mode Indication [O] */
            if (iei == 0x01) {
                GSM_DBG_DTAP("%" PRIu64 ": VGCS Target Mode Indication", numPackets);
                T2BUF_SKIP_TLV(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x03 Multi-Rate Configuration */
            if (iei == 0x03) {
                t2buf_skip_u8(t2buf); // iei
                md->a_dtap.amr_config = t2buf_read_multirate_configuration(t2buf, md);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x04 VGCS Ciphering Parameters [O] */
            if (iei == 0x04) {
                GSM_DBG_DTAP("%" PRIu64 ": VGCS Ciphering Parameters", numPackets);
                T2BUF_SKIP_TLV(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            break;
        }

        case 0x29: { // Assignment Complete
            /* RR Cause */
            uint8_t cause;
            t2buf_read_u8(t2buf, &cause);
            md->a_dtap.cause = cause;
            GSM_DBG_DTAP("%" PRIu64 ": RR Handover message: Assignment Complete: RR Cause: %u (%s)", numPackets, cause, rr_cause_name(cause));
            break;
        }

        case 0x2f: { // Assignment Failure
            /* RR Cause */
            uint8_t cause;
            t2buf_read_u8(t2buf, &cause);
            md->a_dtap.cause = cause;
            GSM_DBG_DTAP("%" PRIu64 ": RR Handover message: Assignment Failure: RR Cause: %u (%s)", numPackets, cause, rr_cause_name(cause));
            break;
        }

        case 0x2b: { // Handover Command
            GSM_DBG_DTAP("%" PRIu64 ": RR Handover message: Handover Command", numPackets);
            /* Cell Description */
            t2buf_skip_u16(t2buf);
            /* Channel Description 2 */
            if (md->a_dtap.channel.channel) {
                GSM_DBG_DTAP("%" PRIu64 ": DTAP channel description already exists: %s", numPackets, md->a_dtap.channel.channel);
                gsm_channel_description_free(&md->a_dtap.channel);
            }
            md->a_dtap.channel = t2buf_dissect_dtap_channel_description_2(t2buf, md);
            GSM_DBG_DTAP("%" PRIu64 ": Description of the first channel, after time: %s", numPackets, md->a_dtap.channel.channel);
            /* Handover Reference */
            uint8_t ref;
            t2buf_read_u8(t2buf, &ref);
            GSM_DBG_DTAP("%" PRIu64 ": Handover Reference: %u", numPackets, ref);
            /* Power Command and Access Type */
            t2buf_skip_u8(t2buf);
            uint8_t iei;
            GSM_DTAP_PEEK_IEI(t2buf, &iei);
            /* 0xd- Synchronization Indication [O] */
            if ((iei & 0xf0) == 0xd0) {
                t2buf_skip_u8(t2buf); // iei
                GSM_DBG_DTAP("%" PRIu64 ": Synchronization Indication", numPackets);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x02 Frequency Short List [C] */
            if (iei == 0x02) {
                t2buf_skip_u8(t2buf); // iei
                GSM_DBG_DTAP("%" PRIu64 ": Frequency Short List, after time", numPackets);
                t2buf_skip_n(t2buf, 9);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x05 Frequency List [C] */
            if (iei == 0x05) {
                GSM_DBG_DTAP("%" PRIu64 ": Frequency List, after time", numPackets);
                T2BUF_SKIP_TLV(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x62 Cell Channel Description [C] */
            if (iei == 0x62) {
                t2buf_dissect_dtap_ie_cell_channel_description(t2buf, md->gsmFlowP, false);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x10 Multislot Allocation */
            if (iei == 0x10) {
                GSM_DBG_DTAP("%" PRIu64 ": Multislot Allocation", numPackets);
                T2BUF_SKIP_TLV(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x63 Channel Mode [O] */
            if (iei == 0x63) {
                t2buf_skip_u8(t2buf); // iei
                GSM_DBG_DTAP("%" PRIu64 ": Mode of the First Channel (Channel Set 1)", numPackets);
                md->a_dtap.mode = t2buf_dissect_dtap_channel_mode(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x11 Channel Mode [O] */
            if (iei == 0x11) {
                t2buf_skip_u8(t2buf); // iei
                GSM_DBG_DTAP("%" PRIu64 ": Mode of Channel Set 2", numPackets);
                /*const uint8_t mode = */t2buf_dissect_dtap_channel_mode(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x13 Channel Mode [O] */
            if (iei == 0x13) {
                t2buf_skip_u8(t2buf); // iei
                GSM_DBG_DTAP("%" PRIu64 ": Mode of Channel Set 3", numPackets);
                /*const uint8_t mode = */t2buf_dissect_dtap_channel_mode(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x14 Channel Mode [O] */
            if (iei == 0x14) {
                t2buf_skip_u8(t2buf); // iei
                GSM_DBG_DTAP("%" PRIu64 ": Mode of Channel Set 4", numPackets);
                /*const uint8_t mode = */t2buf_dissect_dtap_channel_mode(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x15 Channel Mode [O] */
            if (iei == 0x15) {
                t2buf_skip_u8(t2buf); // iei
                GSM_DBG_DTAP("%" PRIu64 ": Mode of Channel Set 5", numPackets);
                /*const uint8_t mode = */t2buf_dissect_dtap_channel_mode(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x16 Channel Mode [O] */
            if (iei == 0x16) {
                t2buf_skip_u8(t2buf); // iei
                GSM_DBG_DTAP("%" PRIu64 ": Mode of Channel Set 6", numPackets);
                /*const uint8_t mode = */t2buf_dissect_dtap_channel_mode(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x17 Channel Mode [O] */
            if (iei == 0x17) {
                t2buf_skip_u8(t2buf); // iei
                GSM_DBG_DTAP("%" PRIu64 ": Mode of Channel Set 7", numPackets);
                /*const uint8_t mode = */t2buf_dissect_dtap_channel_mode(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x18 Channel Mode [O] */
            if (iei == 0x18) {
                t2buf_skip_u8(t2buf); // iei
                GSM_DBG_DTAP("%" PRIu64 ": Mode of Channel Set 8", numPackets);
                /*const uint8_t mode = */t2buf_dissect_dtap_channel_mode(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x64 Channel Description [O] */
            if (iei == 0x64) {
                t2buf_skip_u8(t2buf); // iei
                gsmChannelDescription_t channel = t2buf_read_channel_description(t2buf, md);
                GSM_DBG_DTAP("%" PRIu64 ": Description of the Second Channel, after time: %s", numPackets, channel.channel);
                gsm_channel_description_free(&channel);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x66 Channel Mode 2 [O] */
            if (iei == 0x66) {
                t2buf_skip_u8(t2buf); // iei
                GSM_DBG_DTAP("%" PRIu64 ": Mode of the Second Channel", numPackets);
                /*const uint8_t mode = */t2buf_dissect_dtap_channel_mode_2(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x69 Frequency Channel Sequence [C] */
            if (iei == 0x69) {
                t2buf_skip_u8(t2buf); // iei
                GSM_DBG_DTAP("%" PRIu64 ": Frequency Channel Sequence, after time", numPackets);
                t2buf_skip_n(t2buf, 9);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x72 Mobile Allocation [C] */
            if (iei == 0x72) {
                GSM_DBG_DTAP("%" PRIu64 ": Mobile Allocation after time", numPackets);
                T2BUF_SKIP_TLV(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x7c Starting Time [O] */
            if (iei == 0x7c) {
                t2buf_skip_u8(t2buf); // iei
                GSM_DBG_DTAP("%" PRIu64 ": Starting Time", numPackets);
                t2buf_skip_u16(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x7b Time Difference [C] */
            if (iei == 0x7b) {
                GSM_DBG_DTAP("%" PRIu64 ": Real Time Difference", numPackets);
                T2BUF_SKIP_TLV(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x7d Timing Advance [C] */
            if (iei == 0x7d) {
                t2buf_skip_u8(t2buf); // iei
                GSM_DBG_DTAP("%" PRIu64 ": Timing Advance", numPackets);
                t2buf_read_timing_advance(t2buf, &md->a_dtap.ta, &md->a_dtap.bts_dist);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x12 Frequency Short List [C] */
            if (iei == 0x12) {
                t2buf_skip_u8(t2buf); // iei
                GSM_DBG_DTAP("%" PRIu64 ": Frequency Short List, before time", numPackets);
                t2buf_skip_n(t2buf, 9);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x19 Frequency List [C] */
            if (iei == 0x19) {
                GSM_DBG_DTAP("%" PRIu64 ": Frequency List, before time", numPackets);
                T2BUF_SKIP_TLV(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x1c Channel Description [O] */
            if (iei == 0x1c) {
                t2buf_skip_u8(t2buf); // iei
                gsmChannelDescription_t channel = t2buf_dissect_dtap_channel_description_2(t2buf, md);
                GSM_DBG_DTAP("%" PRIu64 ": Description of the First Channel, before time: %s", numPackets, channel.channel);
                free(channel.channel);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x1d Channel Description [O] */
            if (iei == 0x1d) {
                t2buf_skip_u8(t2buf); // iei
                gsmChannelDescription_t channel = t2buf_read_channel_description(t2buf, md);
                GSM_DBG_DTAP("%" PRIu64 ": Description of the Second Channel, before time: %s", numPackets, channel.channel);
                gsm_channel_description_free(&channel);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x1e Frequency Channel Sequence [C] */
            if (iei == 0x1e) {
                t2buf_skip_u8(t2buf); // iei
                GSM_DBG_DTAP("%" PRIu64 ": Frequency Channel Sequence, before time", numPackets);
                t2buf_skip_n(t2buf, 9);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x21 Mobile Allocation [C] */
            if (iei == 0x21) {
                GSM_DBG_DTAP("%" PRIu64 ": Mobile Allocation, before time", numPackets);
                T2BUF_SKIP_TLV(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x9- Cipher Mode Setting [O] */
            if ((iei & 0xf0) == 0x90) {
                t2buf_skip_u8(t2buf); // iei
                GSM_DBG_DTAP("%" PRIu64 ": Cipher Mode Setting", numPackets);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x01 VGCS Target Mode Indication [O] */
            if (iei == 0x01) {
                GSM_DBG_DTAP("%" PRIu64 ": VGCS Target Mode Indication", numPackets);
                T2BUF_SKIP_TLV(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x76 Dynamic ARFCN Mapping */
            if (iei == 0x76) {
                t2buf_skip_u8(t2buf); // iei
                GSM_DBG_DTAP("%" PRIu64 ": Dynamic ARFCN Mapping", numPackets);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x03 Multi-Rate Configuration */
            if (iei == 0x03) {
                t2buf_skip_u8(t2buf); // iei
                md->a_dtap.amr_config = t2buf_read_multirate_configuration(t2buf, md);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x04 VGCS Ciphering Parameters [O] */
            if (iei == 0x04) {
                GSM_DBG_DTAP("%" PRIu64 ": VGCS Ciphering Parameters", numPackets);
                T2BUF_SKIP_TLV(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x51 Dedicated Service Information [O] */
            if (iei == 0x51) {
                t2buf_skip_u8(t2buf); // iei
                GSM_DBG_DTAP("%" PRIu64 ": Dedicated Service Information", numPackets);
                t2buf_skip_u16(t2buf);
            }
            break;
        }

        case 0x2c: { // Handover complete
            /* RR Cause */
            uint8_t cause;
            t2buf_read_u8(t2buf, &cause);
            md->a_dtap.cause = cause;
            GSM_DBG_DTAP("%" PRIu64 ": RR Handover message: Handover Complete: RR Cause: %u (%s)", numPackets, cause, rr_cause_name(cause));
            uint8_t iei;
            GSM_DTAP_PEEK_IEI(t2buf, &iei);
            /* 0x77 Mobile Observed Time Difference [O] */
            if (iei == 0x77) {
                t2buf_skip_u8(t2buf); // iei
                GSM_DBG_DTAP("%" PRIu64 ": Mobile Observed Time Difference", numPackets);
                t2buf_skip_n(t2buf, 4);
            }
            break;
        }

        case 0x28: { // Handover failure
            /* RR Cause */
            uint8_t cause;
            t2buf_read_u8(t2buf, &cause);
            md->a_dtap.cause = cause;
            GSM_DBG_DTAP("%" PRIu64 ": RR Handover message: Handover Failure: RR Cause: %u (%s)", numPackets, cause, rr_cause_name(cause));
            break;
        }

        case 0x2d: { // Physical information
            GSM_DBG_DTAP("%" PRIu64 ": RR Handover message: Physical Information", numPackets);
            /* Timing Advance */
            t2buf_read_timing_advance(t2buf, &md->a_dtap.ta, &md->a_dtap.bts_dist);
            break;
        }

        /* ----------------------------------------------------------------- */
        /* RR Channel Release messages                                       */
        /* ----------------------------------------------------------------- */

        case 0x0d: { // Channel release
            /* RR Cause */
            uint8_t cause;
            t2buf_read_u8(t2buf, &cause);
            md->a_dtap.cause = cause;
            GSM_DBG_DTAP("%" PRIu64 ": RR Channel Release message: Channel Release: RR Cause: %u (%s)", numPackets, cause, rr_cause_name(cause));
            uint8_t iei;
            GSM_DTAP_PEEK_IEI(t2buf, &iei);
            /* 0x73 BA Range [O] */
            if (iei == 0x73) {
                GSM_DBG_DTAP("%" PRIu64 ": BA Range", numPackets);
                T2BUF_SKIP_TLV(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x74 Group Channel Description [O] */
            //if (iei == 0x74) {
            //    GSM_DBG_DTAP("%" PRIu64 ": Group Channel Description", numPackets);
            //    T2BUF_SKIP_TLV(t2buf);
            //    GSM_DTAP_PEEK_IEI(t2buf, &iei);
            //}
            /* 0x8- Group Cipher Key Number [C] */
            //if ((iei & 0xf0) == 0x80) {
            //    t2buf_skip_u8(t2buf); // iei
            //    GSM_DBG_DTAP("%" PRIu64 ": Group Cipher Key Number", numPackets);
            //    GSM_DTAP_PEEK_IEI(t2buf, &iei);
            //}
            /* 0xc- GPRS Resumption [O] */
            if ((iei & 0xf0) == 0xc0) {
                t2buf_skip_u8(t2buf); // iei
                GSM_DBG_DTAP("%" PRIu64 ": GPRS Resumption", numPackets);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x75 BA List Pref */
            if (iei == 0x75) {
                GSM_DBG_DTAP("%" PRIu64 ": BA List Pref", numPackets);
                T2BUF_SKIP_TLV(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x76 UTRAN Freq List */
            if (iei == 0x76) {
                GSM_DBG_DTAP("%" PRIu64 ": UTRAN Freq List", numPackets);
                T2BUF_SKIP_TLV(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x62 Cell Channel Description */
            if (iei == 0x62) {
                t2buf_dissect_dtap_ie_cell_channel_description(t2buf, md->gsmFlowP, false);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x77 Cell Selection indicator after release of all TCH and SDCCH */
            if (iei == 0x77) {
                GSM_DBG_DTAP("%" PRIu64 ": Cell Selection indicator after release of all TCH and SDCCH", numPackets);
                T2BUF_SKIP_TLV(t2buf);
            }
            break;
        }

        case 0x0a: { // Partial release
            if (md->a_dtap.channel.channel) {
                GSM_DBG_DTAP("%" PRIu64 ": DTAP channel description already exists: %s", numPackets, md->a_dtap.channel.channel);
                gsm_channel_description_free(&md->a_dtap.channel);
            }
            md->a_dtap.channel = t2buf_read_channel_description(t2buf, md);
            GSM_DBG_DTAP("%" PRIu64 ": RR Channel Release message: Partial Release: %s", numPackets, md->a_dtap.channel.channel);
            break;
        }

        case 0x0f: { // Partial release complete
            GSM_DBG_DTAP("%" PRIu64 ": RR Channel Release message: Partial Release Complete", numPackets);
            break;
        }

        /* ----------------------------------------------------------------- */
        /* RR Paging messages                                                */
        /* ----------------------------------------------------------------- */

        case 0x21: { // Paging request type 1
            GSM_DBG_DTAP("%" PRIu64 ": RR Paging message: Paging Request Type 1", numPackets);
            /* Page Mode and Channel Needed */
            t2buf_skip_u8(t2buf);
            /* Mobile Identity */
            gsmMobileIdentity_t id = t2buf_read_mobile_identity(t2buf, md);
            gsm_mobile_identity_free(&id);
            uint8_t iei;
            GSM_DTAP_PEEK_IEI(t2buf, &iei);
            /* 0x17 Mobile Identity [O] */
            if (iei == 0x17) {
                t2buf_skip_u8(t2buf); // iei
                gsmMobileIdentity_t id = t2buf_read_mobile_identity(t2buf, md);
                gsm_mobile_identity_free(&id);
            }
            // P1 rest Octets
            break;
        }

        case 0x22: { // RR Paging request type 2
            GSM_DBG_DTAP("%" PRIu64 ": RR Paging message: Paging Request Type 1", numPackets);
            /* Page Mode and Channel Needed */
            t2buf_skip_u8(t2buf);
            /* Mobile Identity 1 (TMSI) */
            t2buf_dissect_dtap_tmsi(t2buf, md);
            /* Mobile Identity 2 (TMSI) */
            t2buf_dissect_dtap_tmsi(t2buf, md);
            uint8_t iei;
            GSM_DTAP_PEEK_IEI(t2buf, &iei);
            /* 0x17 Mobile Identity 3 [O] */
            if (iei == 0x17) {
                t2buf_skip_u8(t2buf); // iei
                gsmMobileIdentity_t id = t2buf_read_mobile_identity(t2buf, md);
                gsm_mobile_identity_free(&id);
            }
            // P2 rest Octets
            break;
        }

        case 0x24: { // RR Paging request type 3
            GSM_DBG_DTAP("%" PRIu64 ": RR Paging message: Paging Request Type 1", numPackets);
            /* Page Mode and Channel Needed */
            t2buf_skip_u8(t2buf);
            /* Mobile Identity 1 (TMSI) */
            t2buf_dissect_dtap_tmsi(t2buf, md);
            /* Mobile Identity 2 (TMSI) */
            t2buf_dissect_dtap_tmsi(t2buf, md);
            /* Mobile Identity 3 (TMSI) */
            t2buf_dissect_dtap_tmsi(t2buf, md);
            /* Mobile Identity 4 (TMSI) */
            t2buf_dissect_dtap_tmsi(t2buf, md);
            // P3 rest Octets
            break;
        }

        case 0x27: { // RR Paging response
            GSM_DBG_DTAP("%" PRIu64 ": RR Paging message: Paging Response", numPackets);
            /* Ciphering Key Sequence Number and Spare Half Octet */
            t2buf_skip_u8(t2buf);
            /* Mobile Station Classmark 2 */
            T2BUF_SKIP_LV(t2buf);
            /* Mobile Identity */
            gsmMobileIdentity_t id = t2buf_read_mobile_identity(t2buf, md);
            gsm_mobile_identity_free(&id);
            uint8_t iei;
            GSM_DTAP_PEEK_IEI(t2buf, &iei);
            /* 0xc- Additional Update Parameters */
            if ((iei & 0xf0) == 0xc0) {
                t2buf_skip_u8(t2buf); // iei
                GSM_DBG_DTAP("%" PRIu64 ": Additional Update Parameters", numPackets);
                t2buf_skip_u8(t2buf);
            }
            break;
        }

        /* ----------------------------------------------------------------- */
        /* RR System Information messages                                    */
        /* ----------------------------------------------------------------- */

        case 0x19: { // System information type 1
            GSM_DBG_DTAP("%" PRIu64 ": RR System Information message: System Information Type 1", numPackets);
            /* Cell Channel Description */
            t2buf_dissect_dtap_cell_channel_description(t2buf, md->gsmFlowP);
            /* RACH Control Parameters */
            t2buf_skip_n(t2buf, 3);
            // SI 1 Rest octets
            break;
        }

        case 0x1a: { // System information type 2
            GSM_DBG_DTAP("%" PRIu64 ": RR System Information message: System Information Type 2", numPackets);
            /* Neighbour Cell Description - BCCH Frequency List */
            t2buf_skip_n(t2buf, 16);
            /* NCC permitted */
            t2buf_skip_u8(t2buf);
            /* RACH Control Parameters */
            t2buf_skip_n(t2buf, 3);
            break;
        }

        case 0x02: { // System information type 2bis
            GSM_DBG_DTAP("%" PRIu64 ": RR System Information message: System Information Type 2bis", numPackets);
            /* Neighbour Cell Description  - Extended BCCH Frequency List */
            t2buf_skip_n(t2buf, 16);
            /* RACH Control Parameters */
            t2buf_skip_n(t2buf, 3);
            // SI 2bis Rest Octets
            break;
        }

        case 0x03: { // System information type 2ter
            GSM_DBG_DTAP("%" PRIu64 ": RR System Information message: System Information Type 2ter", numPackets);
            /* Neighbour Cell Description - Extended BCCH Frequency List */
            t2buf_skip_n(t2buf, 16);
            // SI 2ter Rest Octets
            break;
        }

        case 0x1b: { // System information type 3
            GSM_DBG_DTAP("%" PRIu64 ": RR System Information message: System Information Type 3", numPackets);
            /* Cell Identity */
            t2buf_read_u16(t2buf, &md->a_dtap.cell_id);
            /* Location Area Identification (LAI) */
            md->a_dtap.lai = t2buf_dissect_dtap_lai(t2buf);
            /* Control Channel Description */
            t2buf_skip_n(t2buf, 3);
            /* Cell Options (BCCH) */
            t2buf_skip_u8(t2buf);
            /* Cell Selection Parameters */
            t2buf_skip_u16(t2buf);
            /* RACH Control Parameters */
            t2buf_skip_n(t2buf, 3);
            // SI 3 rest octets
            break;
        }

        case 0x1c: { // System information type 4
            GSM_DBG_DTAP("%" PRIu64 ": RR System Information message: System Information Type 4", numPackets);
            /* Location Area Identification (LAI) */
            md->a_dtap.lai = t2buf_dissect_dtap_lai(t2buf);
            /* Cell Selection Parameters */
            t2buf_skip_u16(t2buf);
            /* RACH Control Parameters */
            t2buf_skip_n(t2buf, 3);
            uint8_t iei;
            GSM_DTAP_PEEK_IEI(t2buf, &iei);
            /* 0x64 CBCH Channel Description [O] */
            if (iei == 0x64) {
                t2buf_skip_u8(t2buf); // iei
                if (md->a_dtap.channel.channel) {
                    GSM_DBG_DTAP("%" PRIu64 ": DTAP channel description already exists: %s", numPackets, md->a_dtap.channel.channel);
                    gsm_channel_description_free(&md->a_dtap.channel);
                }
                md->a_dtap.channel = t2buf_read_channel_description(t2buf, md);
                GSM_DBG_DTAP("%" PRIu64 ": CBCH Channel description: %s", numPackets, md->a_dtap.channel.channel);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x72 CBCH Mobile Allocation [C] */
            if (iei == 0x72) {
                GSM_DBG_DTAP("%" PRIu64 ": CBCH Mobile Allocation", numPackets);
                T2BUF_SKIP_TLV(t2buf);
            }
            // SI 4 Rest Octets
            break;
        }

        case 0x1d: { // System information type 5
            GSM_DBG_DTAP("%" PRIu64 ": RR System Information message: System Information Type 5", numPackets);
            /* Neighbour Cell Description  - BCCH Frequency List */
            t2buf_skip_n(t2buf, 16);
            break;
        }

        case 0x05: { // System information type 5bis
            GSM_DBG_DTAP("%" PRIu64 ": RR System Information message: System Information Type 5bis", numPackets);
            /* Neighbour Cell Description - Extended BCCH Frequency List */
            t2buf_skip_n(t2buf, 16);
            break;
        }

        case 0x06: { // System information type 5ter
            GSM_DBG_DTAP("%" PRIu64 ": RR System Information message: System Information Type 5ter", numPackets);
            /* Neighbour Cell Description - Extended BCCH Frequency List */
            t2buf_skip_n(t2buf, 16);
            break;
        }

        case 0x1e: { // System information type 6
            GSM_DBG_DTAP("%" PRIu64 ": RR System Information message: System Information Type 6", numPackets);
            /* Cell Identity */
            t2buf_read_u16(t2buf, &md->a_dtap.cell_id);
            /* Location Area Identification (LAI) */
            md->a_dtap.lai = t2buf_dissect_dtap_lai(t2buf);
            /* Cell Options (SACCH) */
            t2buf_skip_u8(t2buf);
            /* NCC Permitted */
            t2buf_skip_u8(t2buf);
            // TODO
            // ?? call reference
            // ?? PCH Information Type 1
            // ?? PCH Information Type 1
            // ?? PCH Information Type 2
            // ?? PCH Information Type 2
            // SI6 Rest octets
            break;
        }

        case 0x1f: { // System information type 7
            GSM_DBG_DTAP("%" PRIu64 ": RR System Information message: System Information Type 7", numPackets);
            // SI 7 Rest octets
            break;
        }

        case 0x18: { // System information type 8
            GSM_DBG_DTAP("%" PRIu64 ": RR System Information message: System Information Type 8", numPackets);
            // SI 8 Rest octets
            break;
        }

        case 0x04: { // System information type 9
            GSM_DBG_DTAP("%" PRIu64 ": RR System Information message: System Information Type 9", numPackets);
            /* RACH Control Parameters */
            t2buf_skip_n(t2buf, 3);
            // SI 9 Rest octets
            break;
        }

        case 0x00: { // System information type 10
            GSM_DBG_DTAP("%" PRIu64 ": RR System Information message: System Information Type 10", numPackets);
            // TODO
            // ?? encoded neighbour cell BSIC description [O]
            // ?? cell description [O]
            // ?? cell description [O]
            // ?? cell description [O]
            // ?? cell description [O]
            // ?? cell description [O]
            // ?? call reference [O]
            // ?? call reference [O]
            // ?? PCH Information type 1 [O]
            // ?? PCH Information type 1 [O]
            // ?? PCH Information type 2 [O]
            // ?? PCH Information type 2 [O]
            break;
        }

        case 0x01: { // System information type 10bis
            GSM_DBG_DTAP("%" PRIu64 ": RR System Information message: System Information Type 10bis", numPackets);
            // TODO
            // ?? encoded neighbour cell BSIC description
            break;
        }

        case 0x07: { // System information type 11
            GSM_DBG_DTAP("%" PRIu64 ": RR System Information message: System Information Type 11", numPackets);
            /* Cell Description */
            t2buf_skip_u16(t2buf);
            // TODO
            // ?? Channel description [O]
            // ?? Frequency short list [C]
            // ?? Frequency short list 2 [C]
            // ?? Starting time [O]
            // ?? Frequency short list 2 [C]
            // ?? Channel description [O]
            // ?? NCH position [O]
            // ?? Cell description [O]
            // ?? Channel description [O]
            // ?? NCH position [O]
            // ?? Cell description [O]
            // ?? Channel description [O]
            // ?? NCH position [O]
            // ?? Cell description [O]
            // ?? Channel description [O]
            // ?? NCH position [O]
            // ?? Call reference [O]
            // ?? PCH Information type 1 [O]
            // ?? PCH Information type 1 [O]
            // ?? PCH Information type 2 [O]
            // ?? PCH Information type 2 [O]
            break;
        }

        case 0x08: { // System information type 12
            GSM_DBG_DTAP("%" PRIu64 ": RR System Information message: System Information Type 12", numPackets);
            /* 1. Cell Description */
            t2buf_skip_u16(t2buf);
            /* 1. Cell Reselection Parameters */
            t2buf_skip_n(t2buf, 4);
            // TODO
            // ?? 2nd Cell Description [O]
            // ?? 2nd Cell Reselection Parameters [C]
            break;
        }

        /* ----------------------------------------------------------------- */
        /* Specific messages for VBS/VGCS                                    */
        /* ----------------------------------------------------------------- */

        case 0x20: { // Notification/NCH type 1
            GSM_DBG_DTAP("%" PRIu64 ": RR Specific message for VBS/VGCS: Notification/NCH Type 1", numPackets);
            /* Call Reference */
            t2buf_skip_n(t2buf, 4);
            // TODO half an octet left to read...
            // ?? Group channel description [O]
            // ?? Call reference [O]
            // ?? Group channel description [O]
            // ?? Call reference [O]
            // ?? NT/N1 rest octets
            break;
        }

        case 0x23: { // Notification/NCH type 2
            GSM_DBG_DTAP("%" PRIu64 ": RR Specific message for VBS/VGCS: Notification/NCH Type 2", numPackets);
            /* Call Reference */
            t2buf_skip_n(t2buf, 4);
            // TODO half an octet left to read...
            /* Cell Description */
            t2buf_skip_u16(t2buf);
            // ?? Cell description [O]
            // ?? Call reference [O]
            // ?? Cell description [C]
            // ?? Cell description [O]
            // ?? NT/N2 Rest octets
            break;
        }

        case 0x25: { // Notification/FACCH
            GSM_DBG_DTAP("%" PRIu64 ": RR Specific message for VBS/VGCS: Notification/FACCH", numPackets);
            /* Call Reference */
            t2buf_skip_n(t2buf, 4);
            // TODO half an octet left to read...
            // ?? Channel description [O]
            // ?? Frequency short list 2 [C]
            // ?? Mobile allocation [C]
            // ?? Call reference [O]
            // ?? Call reference [O]
            // ?? PCH Information type 1 [O]
            // ?? PCH Information type 1 [O]
            // ?? PCH Information type 2 [O]
            // ?? PCH Information type 2 [O]
            // ?? Mobile identity [O]
            // ?? Mobile identity [O]
            break;
        }

        case 0x26: { // Notification/SACCH
            GSM_DBG_DTAP("%" PRIu64 ": RR Specific message for VBS/VGCS: Notification/SACCH", numPackets);
            /* Call Reference */
            t2buf_skip_n(t2buf, 4);
            // TODO half an octet left to read...
            // ?? Call reference [0]
            // ?? Call reference [0]
            // ?? PCH Information type 1 [0]
            // ?? PCH Information type 1 [0]
            // ?? PCH Information type 2 [0]
            // ?? PCH Information type 2 [0]
            // ?? Mobile identity [0]
            // ?? Mobile identity [0]
            break;
        }

        case 0x2a: { // Uplink busy
            GSM_DBG_DTAP("%" PRIu64 ": RR VGCS Uplink Control message: Uplink Busy", numPackets);
            break;
        }

        case 0x0c: { // Uplink free
            /* Uplink Identity Code (UIC) [C] */
            uint8_t octet;
            t2buf_read_u8(t2buf, &octet);
            const uint8_t uic = ((octet & 0xfc) >> 2);
            GSM_DBG_DTAP("%" PRIu64 ": RR VGCS Uplink Control message: Uplink Free: UIC=0x%02" B2T_PRIX8, numPackets, uic);
            // TODO
            // ?? call reference [O]
            // ?? call reference [O]
            // ?? uplink access request [O]
            // ?? PCH information type 1 [O]
            // ?? PCH information type 1 [O]
            // ?? PCH information type 2 [O]
            // ?? PCH information type 2 [O]
            // ?? mobile identity [O]
            // ?? mobile identity [O]
            break;
        }

        case 0x0e: { // Uplink release
            /* RR Cause */
            uint8_t cause;
            t2buf_read_u8(t2buf, &cause);
            md->a_dtap.cause = cause;
            GSM_DBG_DTAP("%" PRIu64 ": RR Specific message for VBS/VGCS: Uplink Release: RR Cause: %u (%s)", numPackets, cause, rr_cause_name(cause));
            break;
        }

        case 0x09: { // VGCS uplink grant
            GSM_DBG_DTAP("%" PRIu64 ": RR Specific message for VBS/VGCS: VGCS Uplink Grant", numPackets);
            /* Request Reference */
            gsm_request_reference_t ref = {};
            t2buf_read_request_reference(t2buf, &ref);
            /* Timing Advance */
            t2buf_read_timing_advance(t2buf, &md->a_dtap.ta, &md->a_dtap.bts_dist);
            break;
        }

        case 0x11: { // Talker indication
            GSM_DBG_DTAP("%" PRIu64 ": RR Specific message for VBS/VGCS: Talker Indication", numPackets);
            /* Mobile Station Classmark 2 */
            T2BUF_SKIP_LV(t2buf);
            /* Mobile identity */
            gsmMobileIdentity_t id = t2buf_read_mobile_identity(t2buf, md);
            gsm_mobile_identity_free(&id);
            uint8_t iei;
            GSM_DTAP_PEEK_IEI(t2buf, &iei);
            /* Ciphering Key Sequence Number */
            if ((iei & 0xf0) == 0xd0) {
                t2buf_skip_u8(t2buf); // iei
                GSM_DBG_DTAP("%" PRIu64 ": Ciphering Key Sequence Number", numPackets);
                t2buf_skip_u8(t2buf);
            }
            break;
        }

        case 0x0b: { // Notification response
            GSM_DBG_DTAP("%" PRIu64 ": RR Specific message for VBS/VGCS: Notification Response", numPackets);
            /* Mobile Station Classmark 2 */
            T2BUF_SKIP_LV(t2buf);
            /* Mobile Identity */
            gsmMobileIdentity_t id = t2buf_read_mobile_identity(t2buf, md);
            gsm_mobile_identity_free(&id);
            /* Call Reference */
            t2buf_skip_n(t2buf, 4);
            // TODO half an octet left to read...
            break;
        }

        /* ----------------------------------------------------------------- */
        /* RR Miscellaneous messages                                         */
        /* ----------------------------------------------------------------- */

        case 0x10: { // Channel mode modify
            GSM_DBG_DTAP("%" PRIu64 ": RR Miscellaneous message: Channel Mode Modify", numPackets);
            /* Channel description 2 */
            if (md->a_dtap.channel.channel) {
                GSM_DBG_DTAP("%" PRIu64 ": DTAP channel description already exists: %s", numPackets, md->a_dtap.channel.channel);
                gsm_channel_description_free(&md->a_dtap.channel);
            }
            md->a_dtap.channel = t2buf_dissect_dtap_channel_description_2(t2buf, md);
            GSM_DBG_DTAP("%" PRIu64 ": Channel description 2: %s", numPackets, md->a_dtap.channel.channel);
            /* Channel mode */
            md->a_dtap.mode = t2buf_dissect_dtap_channel_mode(t2buf);
            uint8_t iei;
            GSM_DTAP_PEEK_IEI(t2buf, &iei);
            /* 0x01 VGCS Target mode indication [O] */
            if (iei == 0x01) {
                GSM_DBG_DTAP("%" PRIu64 ": VGCS Target Mode Indication", numPackets);
                T2BUF_SKIP_TLV(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x03 Multi-Rate Configuration */
            if (iei == 0x03) {
                t2buf_skip_u8(t2buf); // iei
                md->a_dtap.amr_config = t2buf_read_multirate_configuration(t2buf, md);
            }
            break;
        }

        case 0x17: { // Channel mode modify acknowledge
            GSM_DBG_DTAP("%" PRIu64 ": RR Miscellaneous message: Channel Mode Modify Acknowledge", numPackets);
            /* Channel description */
            if (md->a_dtap.channel.channel) {
                GSM_DBG_DTAP("%" PRIu64 ": DTAP channel description already exists: %s", numPackets, md->a_dtap.channel.channel);
                gsm_channel_description_free(&md->a_dtap.channel);
            }
            md->a_dtap.channel = t2buf_dissect_dtap_channel_description_2(t2buf, md);
            GSM_DBG_DTAP("%" PRIu64 ": Channel description 2: %s", numPackets, md->a_dtap.channel.channel);
            /* Channel mode */
            md->a_dtap.mode = t2buf_dissect_dtap_channel_mode(t2buf);
            break;
        }

        case 0x16: { // Classmark change
            GSM_DBG_DTAP("%" PRIu64 ": RR Miscellaneous message: Classmark Change", numPackets);
            /* Mobile Station Classmark 2 */
            T2BUF_SKIP_LV(t2buf);
            uint8_t iei;
            GSM_DTAP_PEEK_IEI(t2buf, &iei);
            /* 0x20 Mobile Station Classmark 3 [C] */
            if (iei == 0x20) {
                GSM_DBG_DTAP("%" PRIu64 ": Mobile Station Classmark 3", numPackets);
                T2BUF_SKIP_TLV(t2buf);
            }
            break;
        }

        case 0x13: { // Classmark enquiry
            GSM_DBG_DTAP("%" PRIu64 ": RR Miscellaneous message: Classmark Enquiry", numPackets);
            uint8_t iei;
            GSM_DTAP_PEEK_IEI(t2buf, &iei);
            /* 0x10 Classmark Enquiry Mask */
            if (iei == 0x10) {
                GSM_DBG_DTAP("%" PRIu64 ": Classmark Enquiry Mask", numPackets);
                T2BUF_SKIP_TLV(t2buf);
            }
            break;
        }

        case 0x14: { // Frequency redefinition
            GSM_DBG_DTAP("%" PRIu64 ": RR Miscellaneous message: Frequency Redefinition", numPackets);
            /* Channel description */
            if (md->a_dtap.channel.channel) {
                GSM_DBG_DTAP("%" PRIu64 ": DTAP channel description already exists: %s", numPackets, md->a_dtap.channel.channel);
                gsm_channel_description_free(&md->a_dtap.channel);
            }
            md->a_dtap.channel = t2buf_read_channel_description(t2buf, md);
            GSM_DBG_DTAP("%" PRIu64 ": Channel description: %s", numPackets, md->a_dtap.channel.channel);
            /* Mobile Allocation */
            T2BUF_SKIP_LV(t2buf);
            /* Starting Time */
            t2buf_skip_u16(t2buf);
            uint8_t iei;
            GSM_DTAP_PEEK_IEI(t2buf, &iei);
            /* 0x62 Cell Channel Description [O] */
            if (iei == 0x62) {
                t2buf_dissect_dtap_ie_cell_channel_description(t2buf, md->gsmFlowP, false);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x9- Carrier Indication [O] */
            if ((iei & 0xf0) == 0x90) {
                t2buf_skip_u8(t2buf); // iei
                GSM_DBG_DTAP("%" PRIu64 ": Carrier Indication", numPackets);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x11 Mobile Allocation [O] */
            if (iei == 0x11) {
                GSM_DBG_DTAP("%" PRIu64 ": Mobile Allocation C2", numPackets);
                T2BUF_SKIP_TLV(t2buf);
                GSM_DTAP_PEEK_IEI(t2buf, &iei);
            }
            /* 0x12 Channel Description 3 [O] */
            if (iei == 0x12) {
                t2buf_skip_u8(t2buf); // iei
                t2buf_dissect_dtap_channel_description_3(t2buf, md);
                GSM_DBG_DTAP("%" PRIu64 ": Channel Description C2", numPackets);
            }
            break;
        }

        case 0x15: { // Measurement report
            GSM_DBG_DTAP("%" PRIu64 ": RR Miscellaneous message: Measurement Report", numPackets);
            /* Measurement results */
            t2buf_skip_n(t2buf, 16);
            break;
        }

        case 0x12: { // RR status
            /* RR Cause */
            uint8_t cause;
            t2buf_read_u8(t2buf, &cause);
            md->a_dtap.cause = cause;
            GSM_DBG_DTAP("%" PRIu64 ": RR Miscellaneous message: RR Status: RR Cause: %u (%s)", numPackets, cause, rr_cause_name(cause));
            break;
        }

        default:
#if GSM_DBG_DTAP_UNK == 1
            GSM_DBG_DTAP("%" PRIu64 ": Unknown RR message type 0x%02" B2T_PRIX8, numPackets, msg_type);
#endif
            break;
    }

#if GSM_IMMASSFILE == 1
    if (msg_type == 0x3f || msg_type == 0x3a || msg_type == 0x2e || msg_type == 0x29 || msg_type == 0x2f) {
        const time_t sec = md->flowP->lastSeen.tv_sec;
        const intmax_t usec = md->flowP->lastSeen.tv_usec;
        if (!md->rsl.channel.str) {
            md->rsl.channel.str = channel_to_str(&md->rsl.channel);
        }

        FILE * const immAssFp = file_manager_fp(t2_file_manager, immAssFile);
        fprintf(immAssFp,
                "%" PRIu64  /* pktNo         */ SEP_CHR
                "%" PRIu64  /* flowInd       */ SEP_CHR
                "%ld.%06jd" /* time          */ SEP_CHR
                "%" PRIu16  /* vlanID        */ SEP_CHR
                "%" PRIu8   /* lapdTEI       */ SEP_CHR
                "%s"        /* gsmMsgType    */ SEP_CHR
                "%s"        /* gsmCause      */ SEP_CHR
                "%" PRIu8   /* gsmRslTN      */ SEP_CHR
                "%" PRIu8   /* gsmRslSubCh   */ SEP_CHR
                "%s"        /* gsmRslChannel */ SEP_CHR
                ,
                numPackets,
                md->flowP->findex,
                sec, usec,
                md->flowP->vlanId,
                md->gsmFlowP->tei,
                gsm48_rr_msg_name(msg_type),
                ((md->a_dtap.cause > 0) ? rr_cause_name(md->a_dtap.cause) : ""),
                md->rsl.channel.tn,
                md->rsl.channel.subchannel,
                md->rsl.channel.str);

        if (msg_type == 0x3a || msg_type == 0x29 || msg_type == 0x2f) {
            fputs(/* gsmDtapTN         */ SEP_CHR
                  /* gsmDtapChannel    */ SEP_CHR
                  /* gsmTSC            */ SEP_CHR
                  /* gsmHoppingChannel */ SEP_CHR
                  /* gsmARFCN          */ SEP_CHR
                  /* gsmBand           */ SEP_CHR
                  /* gsmUpFreqMHz      */ SEP_CHR
                  /* gsmDownFreqMHz    */ SEP_CHR
                  /* gsmMAIO           */ SEP_CHR
                  /* gsmHoppingSeqNum  */ SEP_CHR
                  , immAssFp);
        } else {
            fprintf(immAssFp,
                    "%u" /* gsmDtapTN         */ SEP_CHR
                    "%s" /* gsmDtapChannel    */ SEP_CHR
                    "%u" /* gsmTSC            */ SEP_CHR
                    "%u" /* gsmHoppingChannel */ SEP_CHR
                    ,
                    md->a_dtap.channel.tn,
                    md->a_dtap.channel.channel,
                    md->a_dtap.channel.tsc,
                    md->a_dtap.channel.hopping);

            if (md->a_dtap.channel.hopping) {
                fprintf(immAssFp,
                             /* gsmARFCN         */ SEP_CHR
                             /* gsmBand          */ SEP_CHR
                             /* gsmUpFreqMHz     */ SEP_CHR
                             /* gsmDownFreqMHz   */ SEP_CHR
                        "%u" /* gsmMAIO          */ SEP_CHR
                        "%u" /* gsmHoppingSeqNum */ SEP_CHR
                        ,
                        md->a_dtap.channel.maio,
                        md->a_dtap.channel.hsn);
            } else {
                uint16_t freq10u = gsm_arfcn2freq10(md->a_dtap.channel.arfcn, 1);
                uint16_t freq10d = gsm_arfcn2freq10(md->a_dtap.channel.arfcn, 0);
                enum gsm_band band;
                gsm_arfcn2band_rc(md->a_dtap.channel.arfcn, &band);
                fprintf(immAssFp,
                        "%u"     /* gsmARFCN         */ SEP_CHR
                        "%s"     /* gsmBand          */ SEP_CHR
                        "%u.%1u" /* gsmUpFreqMHz     */ SEP_CHR
                        "%u.%1u" /* gsmDownFreqMHz   */ SEP_CHR
                                 /* gsmMAIO          */ SEP_CHR
                                 /* gsmHoppingSeqNum */ SEP_CHR
                        ,
                        md->a_dtap.channel.arfcn,
                        gsm_band_name(band),
                        freq10u / 10, freq10u % 10,
                        freq10d / 10, freq10d % 10);
            }
        }

        if (msg_type == 0x2e || msg_type == 0x29 || msg_type == 0x2f) {
            fputs(/* gsmRandomAccessInfo */ SEP_CHR
                  /* gsmRequestRefT1     */ SEP_CHR
                  /* gsmRequestRefT2     */ SEP_CHR
                  /* gsmRequestRefT3     */ SEP_CHR
                  /* gsmRequestRefRFN    */ SEP_CHR
                  , immAssFp);
        } else {
            fprintf(immAssFp,
                    "%u" /* gsmRandomAccessInfo */ SEP_CHR
                    "%u" /* gsmRequestRefT1     */ SEP_CHR
                    "%u" /* gsmRequestRefT2     */ SEP_CHR
                    "%u" /* gsmRequestRefT3     */ SEP_CHR
                    "%u" /* gsmRequestRefRFN    */ SEP_CHR
                    ,
                    md->a_dtap.req_ref.ra,
                    md->a_dtap.req_ref.t1,
                    md->a_dtap.req_ref.t2,
                    md->a_dtap.req_ref.t3,
                    md->a_dtap.req_ref.rfn);
        }

        if (msg_type == 0x3a || msg_type == 0x2e || msg_type == 0x29 || msg_type == 0x2f) {
            fputs(/* gsmTimingAdvance   */ SEP_CHR
                  /* gsmDistanceFromBTS */ SEP_CHR
                  , immAssFp);
        } else {
            fprintf(immAssFp,
                    "%u" /* gsmTimingAdvance   */ SEP_CHR
                    "%u" /* gsmDistanceFromBTS */ SEP_CHR
                    ,
                    md->a_dtap.ta,
                    md->a_dtap.bts_dist);
        }

        fprintf(immAssFp,
                "%s" /* gsmChannelMode     */ SEP_CHR
                "%s" /* gsmMultiRateConfig */ "\n"
                ,
                md->a_dtap.mode ? md->a_dtap.mode : "",
                md->a_dtap.amr_config ? md->a_dtap.amr_config : "");
    }
#endif

    return has_next_layer;
}


static inline uint8_t t2buf_dissect_dtap_cause(t2buf_t *t2buf) {
    uint8_t cause = UINT8_MAX;
    uint8_t len;
    t2buf_read_u8(t2buf, &len);
    if (len != 2) {
        t2buf_skip_n(t2buf, len);
    } else {
        t2buf_skip_u8(t2buf); // flags
        uint8_t c;
        t2buf_read_u8(t2buf, &c);
        cause = (c & 0x7f);
    }
    return cause;
}


// Returned value MUST be free'd with free()
static inline gsmChannelDescription_t t2buf_dissect_dtap_channel_description_2(t2buf_t *t2buf, gsm_metadata_t *md) {
    gsmChannelDescription_t d = {};

    uint8_t channel_type;
    t2buf_read_u8(t2buf, &channel_type);

    d.c_bits = ((channel_type & 0xf8));
    d.tn = (channel_type & 0x07);

    switch (d.c_bits) {
        case 0x00:
            d.channel = t2_strdup_printf("Ch:(TN:%u TCH/F + FACCH/F and SACCH/M)", d.tn);
            break;
        case 0x08:
            d.channel = t2_strdup_printf("Ch:(TN:%u TCH/F + FACCH/F and SACCH/F)", d.tn);
            break;
        case 0xf0:
            d.channel = t2_strdup_printf("Ch:(TN:%u TCH/F + FACCH/F and SACCH/M + bi- and unidirectional channels)", d.tn);
            break;
        default:
            if ((channel_type & 0xf0) == 0x10) {
                d.channel = t2_strdup_printf("Ch:(TN:%u SbCh:%u  CC:TCH/H + ACCHs)", d.tn, ((channel_type & 0x08) >> 3));
            } else if ((channel_type & 0xe0) == 0x20) {
                d.channel = t2_strdup_printf("Ch:(TN:%u SbCh:%u CC:SDCCH/4 + SACCH/C4 or CBCH (SDCCH/4))", d.tn, ((channel_type & 0x18) >> 3));
            } else if ((channel_type & 0xc0) == 0x40) {
                d.channel = t2_strdup_printf("Ch:(TN:%u SbCh:%u CC:SDCCH/8 + SACCH/C8 or CBCH (SDCCH/8))", d.tn, ((channel_type & 0x38) >> 3));
            } else if ((channel_type & 0xc0) == 0x80) {
                d.channel = t2_strdup_printf("Ch:(TN:%u SbCh:%u CC:TCH/F + FACCH/F and SACCH/M + bidirectional channels at timeslot", d.tn, ((channel_type & 0x38) >> 3));
            } else if ((channel_type & 0xe0) == 0xc0) {
                d.channel = t2_strdup_printf("Ch:(TN:%u SbCh:%u CC:TCH/F + FACCH/F and SACCH/M + unidirectional channels at timeslot", d.tn, ((channel_type & 0x38) >> 3));
            } else {
#if GSM_DBG_UNK == 1
                GSM_DBG("%" PRIu64 ": Unknown channel type 0x%02" B2T_PRIX8, numPackets, d.c_bits);
#endif
            }
            break;
    }

    uint8_t octet3;
    t2buf_read_u8(t2buf, &octet3);

    uint8_t octet4;
    t2buf_read_u8(t2buf, &octet4);

    // Training Sequence Code (TSC)
    d.tsc = ((octet3 & 0xe0) >> 5);
    d.hopping = ((octet3 & 0x10) >> 4); // 0: Single RF channel, 1: RF hopping channel

    GSM_DBG("%" PRIu64 ": Channel Description 2 IE: %s, Training Sequence Code (TSC): 0x%02" B2T_PRIX8 " (%s)", numPackets, d.channel, d.tsc, (d.hopping ? "RF hopping channel" : "Single RF Channel"));

    if (d.hopping) {
        // Mobile Allocation Index Offset (MAIO)
        const uint8_t maio_high = (octet3 & 0x0f);
        const uint8_t maio_low = ((octet4 & 0xc0) >> 6);
        d.maio = ((maio_high << 2) | maio_low);
        // Hopping sequence number (HSN)
        d.hsn = (octet4 & 0x1f);
        GSM_DBG("%" PRIu64 ": MAIO: %u, HSN: %u", numPackets, d.maio, d.hsn);
    } else {
        const uint8_t arfcn_high = (octet3 & 0x03);
        const uint8_t arfcn_low = octet4;
        d.arfcn = ((arfcn_high << 8) | arfcn_low);
        const uint16_t freq10u = gsm_arfcn2freq10(d.arfcn, 1);
        const uint16_t freq10d = gsm_arfcn2freq10(d.arfcn, 0);
        enum gsm_band band;
        gsm_arfcn2band_rc(d.arfcn, &band);
        GSM_DBG("%" PRIu64 ": ARFCN: %u (%s): Uplink %u.%1u MHz / Downlink %u.%1u MHz",
                numPackets, d.arfcn, gsm_band_name(band), freq10u / 10, freq10u % 10, freq10d / 10, freq10d % 10);
#if GSM_ARFCNFILE == 1
        const time_t sec = md->flowP->lastSeen.tv_sec;
        const intmax_t usec = md->flowP->lastSeen.tv_usec;
        if (!md->rsl.channel.str) {
            md->rsl.channel.str = channel_to_str(&md->rsl.channel);
        }

        FILE * const arfcnFp = file_manager_fp(t2_file_manager, arfcnFile);
        fprintf(arfcnFp,
                "%" PRIu64  /* pktNo          */ SEP_CHR
                "%" PRIu64  /* flowInd        */ SEP_CHR
                "%ld.%06jd" /* time           */ SEP_CHR
                "%" PRIu16  /* vlanID         */ SEP_CHR
                "%" PRIu8   /* lapdTEI        */ SEP_CHR
                "%" PRIu8   /* gsmRslTN       */ SEP_CHR
                "%" PRIu8   /* gsmRslSubCh    */ SEP_CHR
                "%s"        /* gsmRslChannel  */ SEP_CHR
                "%u"        /* gsmDtapTN      */ SEP_CHR
                "%s"        /* gsmDtapChannel */ SEP_CHR
                "%u"        /* gsmARFCN       */ SEP_CHR
                "%s"        /* gsmBand        */ SEP_CHR
                "%u.%1u"    /* gsmUpFreqMHz   */ SEP_CHR
                "%u.%1u"    /* gsmDownFreqMHz */ "\n"
                ,
                numPackets,
                md->flowP->findex,
                sec, usec,
                md->flowP->vlanId,
                md->gsmFlowP->tei,
                md->rsl.channel.tn,
                md->rsl.channel.subchannel,
                md->rsl.channel.str,
                d.tn,
                d.channel,
                d.arfcn,
                gsm_band_name(band),
                freq10u / 10, freq10u % 10,
                freq10d / 10, freq10d % 10);
#endif
    }

    return d;
}


static inline bool t2buf_dissect_dtap_channel_description_3(t2buf_t *t2buf, gsm_metadata_t *md) {

    uint8_t octet2;
    t2buf_read_u8(t2buf, &octet2);

    uint8_t octet3;
    t2buf_read_u8(t2buf, &octet3);

    // Training Sequence Code (TSC)
    const uint8_t tsc = ((octet2 & 0xe0) >> 5);
    const bool hopping = ((octet2 & 0x10) >> 4); // 0: Single RF channel, 1: RF hopping channel

    GSM_DBG("%" PRIu64 ": Channel Description 3 IE: Training Sequence (TSC): 0x%02" B2T_PRIX8 " (%s)",
            numPackets, tsc, (hopping ? "RF hopping channel" : "Single RF Channel"));

    if (hopping) {
        // Mobile Allocation Index Offset (MAIO)
        const uint8_t maio_high = (octet2 & 0x0f);
        const uint8_t maio_low = ((octet3 & 0xc0) >> 6);
        const uint16_t maio = ((maio_high << 2) | maio_low);
        // Hopping sequence number (HSN)
        const uint8_t hsn = (octet3 & 0x1f);
        GSM_DBG("%" PRIu64 ": MAIO: %u, HSN: %u", numPackets, maio, hsn);
    } else {
        const uint8_t arfcn_high = (octet2 & 0x03);
        const uint8_t arfcn_low = octet3;
        const uint16_t arfcn = ((arfcn_high << 8) | arfcn_low);
        const uint16_t freq10u = gsm_arfcn2freq10(arfcn, 1);
        const uint16_t freq10d = gsm_arfcn2freq10(arfcn, 0);
        enum gsm_band band;
        gsm_arfcn2band_rc(arfcn, &band);
        GSM_DBG("%" PRIu64 ": ARFCN: %u (%s): Uplink %u.%1u MHz / Downlink %u.%1u MHz",
                numPackets, arfcn, gsm_band_name(band), freq10u / 10, freq10u % 10, freq10d / 10, freq10d % 10);
#if GSM_ARFCNFILE == 1
        const time_t sec = md->flowP->lastSeen.tv_sec;
        const intmax_t usec = md->flowP->lastSeen.tv_usec;
        if (!md->rsl.channel.str) {
            md->rsl.channel.str = channel_to_str(&md->rsl.channel);
        }
        char *dtap_tn = (md->a_dtap.channel.channel ? t2_strdup_printf("%u", md->a_dtap.channel.tn) : NULL);

        FILE * const arfcnFp = file_manager_fp(t2_file_manager, arfcnFile);
        fprintf(arfcnFp,
                "%" PRIu64  /* pktNo          */ SEP_CHR
                "%" PRIu64  /* flowInd        */ SEP_CHR
                "%ld.%06jd" /* time           */ SEP_CHR
                "%" PRIu16  /* vlanID         */ SEP_CHR
                "%" PRIu8   /* lapdTEI        */ SEP_CHR
                "%" PRIu8   /* gsmRslTN       */ SEP_CHR
                "%" PRIu8   /* gsmRslSubCh    */ SEP_CHR
                "%s"        /* gsmRslChannel  */ SEP_CHR
                "%s"        /* gsmDtapTN      */ SEP_CHR
                "%s"        /* gsmDtapChannel */ SEP_CHR
                "%u"        /* gsmARFCN       */ SEP_CHR
                "%s"        /* gsmBand        */ SEP_CHR
                "%u.%1u"    /* gsmUpFreqMHz   */ SEP_CHR
                "%u.%1u"    /* gsmDownFreqMHz */ "\n"
                ,
                numPackets,
                md->flowP->findex,
                sec, usec,
                md->flowP->vlanId,
                md->gsmFlowP->tei,
                md->rsl.channel.tn,
                md->rsl.channel.subchannel,
                md->rsl.channel.str,
                dtap_tn ? dtap_tn : "",
                md->a_dtap.channel.channel ? md->a_dtap.channel.channel : "",
                arfcn,
                gsm_band_name(band),
                freq10u / 10, freq10u % 10,
                freq10d / 10, freq10d % 10);
        free(dtap_tn);
#endif
    }

    return true;
}


static inline uint32_t t2buf_dissect_dtap_tmsi(t2buf_t *t2buf, gsm_metadata_t *md) {
    uint32_t tmsi;
    t2buf_read_u32(t2buf, &tmsi);

#if GSM_TMSI_FORMAT == 1
    GSM_DBG("%" PRIu64 ": TMSI/P-TMSI: 0x%04" B2T_PRIX32, numPackets, tmsi);
#else
    GSM_DBG("%" PRIu64 ": TMSI/P-TMSI: %" PRIu32, numPackets, tmsi);
#endif

#if GSM_IMSIFILE == 1
    const time_t sec = md->flowP->lastSeen.tv_sec;
    const intmax_t usec = md->flowP->lastSeen.tv_usec;
    if (!md->rsl.channel.str) {
        md->rsl.channel.str = channel_to_str(&md->rsl.channel);
    }

    FILE * const imsiFp = file_manager_fp(t2_file_manager, imsiFile);
    fprintf(imsiFp,
            "%" PRIu64         /* pktNo                 */ SEP_CHR
            "%" PRIu64         /* flowInd               */ SEP_CHR
            "%ld.%06jd"        /* time                  */ SEP_CHR
            "%" PRIu16         /* vlanID                */ SEP_CHR
            "%" PRIu8          /* lapdTEI               */ SEP_CHR
            "%" PRIu8          /* gsmRslTN              */ SEP_CHR
            "%" PRIu8          /* gsmRslSubCh           */ SEP_CHR
            "%s"               /* gsmRslChannel         */ SEP_CHR
            "TMSI"             /* gsmMobileIdentityType */ SEP_CHR
#if GSM_TMSI_FORMAT == 1
            "0x%04" B2T_PRIX32 /* gsmIMSI               */ SEP_CHR
#else
            "%" PRIu32         /* gsmIMSI               */ SEP_CHR
#endif
                               /* gsmIMEITACManuf       */ SEP_CHR
                               /* gsmIMEITACModel       */ SEP_CHR
                               /* gsmIMSIMCC            */ SEP_CHR
                               /* gsmIMSIMCCCountry     */ SEP_CHR
                               /* gsmIMSIMNC            */ SEP_CHR
                               /* gsmIMSIMNCOperator    */ SEP_CHR
            , numPackets
            , md->flowP->findex
            , sec, usec
            , md->flowP->vlanId
            , md->gsmFlowP->tei
            , md->rsl.channel.tn
            , md->rsl.channel.subchannel
            , md->rsl.channel.str
            , tmsi);

    if (md->a_dtap.lai.valid == true) {
        fprintf(imsiFp,
                "%s"               /* gsmLAIMCC          */ SEP_CHR
                "%s"               /* gsmLAIMCCCountry   */ SEP_CHR
                "%s"               /* gsmLAIMNC          */ SEP_CHR
                "\"%s\""           /* gsmLAIMNCOperator  */ SEP_CHR
                "0x%04" B2T_PRIX16 /* gsmLAILAC          */ "\n"
                , md->a_dtap.lai.mcc
                , mcc_to_str(md->a_dtap.lai.mcc)
                , md->a_dtap.lai.mnc
                , mnc_to_str(md->a_dtap.lai.mcc, md->a_dtap.lai.mnc)
                , md->a_dtap.lai.lac);
    } else {
        fputs(/* gsmLAIMCC         */ SEP_CHR
              /* gsmLAIMCCCountry  */ SEP_CHR
              /* gsmLAIMNC         */ SEP_CHR
              /* gsmLAIMNCOperator */ SEP_CHR
              /* gsmLAILAC         */ "\n"
              , imsiFp);
    }
#endif // GSM_IMSIFILE == 1

    return tmsi;
}


static inline gsmLAI_t t2buf_dissect_dtap_lai(t2buf_t *t2buf) {
    /* Location Area Identification (LAI) */
    gsmLAI_t lai = { .valid = false };
    uint8_t digits[3];
    if (!t2buf_read_u8(t2buf, &digits[0]) || // MCC digit 2 and 1
        !t2buf_read_u8(t2buf, &digits[1]))   // 0xf, MCC digit 3
    {
        return lai;
    }

    lai.valid = true; // MCC is valid

    if (!t2buf_read_u8(t2buf, &digits[2])) {  // MNC digit 2 and 1
        return lai;
    }

    // Location Area Code
    if (!t2buf_read_u16(t2buf, &lai.lac)) return lai;

    mcc_mnc_aux(digits, lai.mcc, lai.mnc);

#if GSM_DEBUG == 1
    GSM_DBG("%" PRIu64 ": Location Area Identification (LAI): %s/%s/0x%04" B2T_PRIX16 " (%s/%s)",
            numPackets, lai.mcc, lai.mnc, lai.lac,
            mcc_to_str(lai.mcc), mnc_to_str(lai.mcc, lai.mnc));
#endif

    return lai;
}


static inline const char *t2buf_dissect_dtap_channel_mode(t2buf_t *t2buf) {
    uint8_t mode;
    t2buf_read_u8(t2buf, &mode);

    const char *mode_str = NULL;
    switch (mode) {
        case 0x00: mode_str = "Signalling Only"; break;
        case 0x01: mode_str = "Speech Full Rate or Half Rate Version 1 (GSM FR or GSM HR)"; break;
        case 0xc1: mode_str = "Speech Full Rate or Half Rate Version 1 (GSM FR or GSM HR) in VAMOS mode"; break;
        case 0x21: mode_str = "Speech Full Rate or Half Rate Version 2 (GSM EFR)"; break;
        case 0xc2: mode_str = "Speech Full Rate or Half Rate Version 2 (GSM EFR) in VAMOS mode"; break;
        case 0x41: mode_str = "Speech Full Rate or Half Rate Version 3 (FR AMR or HR AMR)"; break;
        case 0xc3: mode_str = "Speech Full Rate or Half Rate Version 3 (FR AMR or HR AMR) in VAMOS mode"; break;
        case 0x81: mode_str = "Speech Full Rate or Half Rate Version 4 (OFR AMR-WB or OHR AMR-WB)"; break;
        case 0x82: mode_str = "Speech Full Rate or Half Rate Version 5 (FR AMR-WB)"; break;
        case 0xc5: mode_str = "Speech Full Rate or Half Rate Version 5 (FR AMR-WB) in VAMOS mode"; break;
        case 0x83: mode_str = "Speech Full Rate or Half Rate Version 6 (OHR AMR)"; break;
        case 0x61: mode_str = "Data, 43.5 Kbit/s (downlink) + 14.5 kbps (Uplink)"; break;
        case 0x62: mode_str = "Data, 29.0 Kbit/s (downlink) + 14.5 kbps (Uplink)"; break;
        case 0x64: mode_str = "Data, 43.5 Kbit/s (downlink) + 29.0 kbps (Uplink)"; break;
        case 0x67: mode_str = "Data, 14.5 Kbit/s (downlink) + 43.5 kbps (Uplink)"; break;
        case 0x65: mode_str = "Data, 14.5 Kbit/s (downlink) + 29.0 kbps (Uplink)"; break;
        case 0x66: mode_str = "Data, 29.0 Kbit/s (downlink) + 43.5 kbps (Uplink)"; break;
        case 0x27: mode_str = "Data, 43.5 Kbit/s Radio Interface Rate"; break;
        case 0x63: mode_str = "Data, 32.0 Kbit/s Radio Interface Rate"; break;
        case 0x43: mode_str = "Data, 29.0 Kbit/s Radio Interface Rate"; break;
        case 0x0f: mode_str = "Data, 14.5 Kbit/s Radio Interface Rate"; break;
        case 0x03: mode_str = "Data, 12.0 Kbit/s Radio Interface Rate"; break;
        case 0x0b: mode_str = "Data, 6.0 Kbit/s Radio Interface Rate"; break;
        case 0x13: mode_str = "Data, 3.6 Kbit/s Radio Interface Rate"; break;
#if GSM_DBG_UNK == 1
        default:   GSM_DBG("%" PRIu64 ": Channel Mode: Reserved: 0x%02" B2T_PRIX8, numPackets, mode); break;
#endif
    }

    if (mode_str) {
        GSM_DBG("%" PRIu64 ": Channel Mode: %s", numPackets, mode_str);
    }

    return mode_str;
}


static inline const char *t2buf_dissect_dtap_channel_mode_2(t2buf_t *t2buf) {
    uint8_t mode;
    t2buf_read_u8(t2buf, &mode);

    const char *mode_str = NULL;
    switch (mode) {
        case 0x00: mode_str = "Signalling Only"; break;
        case 0x05: mode_str = "Speech Half Rate Version 1 (GSM HR)"; break;
        case 0x25: mode_str = "Speech Half Rate Version 2 (GSM EFR)"; break;
        case 0x45: mode_str = "Speech Half Rate Version 3 (HR AMR)"; break;
        case 0x85: mode_str = "Speech Half Rate Version 4 (OHR AMR-WB)"; break;
        case 0x06: mode_str = "Speech Half Rate Version 6 (OHR AMR)"; break;
        case 0x0f: mode_str = "Data, 6.0 Kbit/s Radio Interface Rate"; break;
        case 0x17: mode_str = "Data, 3.6 Kbit/s Radio Interface Rate"; break;
#if GSM_DBG_UNK == 1
        default:   GSM_DBG("%" PRIu64 ": Channel Mode 2: Reserved: 0x%02" B2T_PRIX8, numPackets, mode); break;
#endif
    }

    if (mode_str) {
        GSM_DBG("%" PRIu64 ": Channel Mode 2: %s", numPackets, mode_str);
    }

    return mode_str;
}


static inline bool t2buf_dissect_dtap_ie_cell_channel_description(t2buf_t *t2buf, gsmFlow_t *gsmFlowP, bool mandatory) {
    uint8_t ie;

    if (!mandatory) {
        if (!t2buf_peek_u8(t2buf, &ie) || ie != 0x62) return false;
    }

    t2buf_read_u8(t2buf, &ie);
    if (ie != 0x62) {
        GSM_DBG_DTAP("%" PRIu64 ": Cell Channel Description IE 0x62 expected, found 0x%02" B2T_PRIX8, numPackets, ie);
        gsmFlowP->pstat |= GSM_STAT_DTAP_MALFORMED;
    }

    return t2buf_dissect_dtap_cell_channel_description(t2buf, gsmFlowP);
}


static inline bool t2buf_dissect_dtap_cell_channel_description(t2buf_t *t2buf, gsmFlow_t *gsmFlowP) {
    uint8_t octet;
    t2buf_read_u8(t2buf, &octet);

    uint8_t left = 15;

    //const uint8_t format_identifier = (octet & 0xce)
    if ((octet & 0xc0) == 0x00) {
        // bit map 0
        GSM_DBG_DTAP("%" PRIu64 ": Cell Channel Description: bit map 0", numPackets);
    } else if ((octet & 0xc8) == 0x80) {
        // 1024 range
        GSM_DBG_DTAP("%" PRIu64 ": Cell Channel Description: 1024 range", numPackets);
    } else if ((octet & 0xce) == 0x88) {
        // 512 range
        GSM_DBG_DTAP("%" PRIu64 ": Cell Channel Description: 512 range", numPackets);
    } else if ((octet & 0xce) == 0x8a) {
        // 256 range
        GSM_DBG_DTAP("%" PRIu64 ": Cell Channel Description: 256 range", numPackets);
    } else if ((octet & 0xce) == 0x8c) {
        // 128 range
        GSM_DBG_DTAP("%" PRIu64 ": Cell Channel Description: 128 range", numPackets);
    } else if ((octet & 0xce) == 0x8e) {
        // variable bit map
        uint8_t octet2;
        t2buf_read_u8(t2buf, &octet2);
        left--;
        uint8_t octet3;
        t2buf_peek_u8(t2buf, &octet3);
        uint16_t arfcn = (((octet & 0x01) << 9) | (octet2 << 1) | ((octet3 & 0x80) >> 7));
        uint8_t bit = 7;
        char *str = t2_strdup_printf("%u", arfcn);
        for (uint_fast8_t i = 0; i <= 13; i++) {
            uint8_t oct;
            t2buf_read_u8(t2buf, &oct);
            left--;
            while (bit-- != 0) {
                arfcn++;
                if (((oct >> bit) & 0x01) == 0x01) {
                    char *tmp = str;
                    str = t2_strdup_printf("%s, %u", tmp, arfcn % 1024);
                    free(tmp);
                }
            }
            bit = 8;
        }
        GSM_DBG_DTAP("%" PRIu64 ": Cell Channel Description: variable bit map: List of ARFCNs: %s", numPackets, str);
        free(str);
    } else {
        GSM_DBG_DTAP("%" PRIu64 ": Cell Channel Description: unknown", numPackets);
        gsmFlowP->pstat |= GSM_STAT_DTAP_MALFORMED;
    }

    if (left > 0) {
        t2buf_skip_n(t2buf, left);
    }

    return true;
}
