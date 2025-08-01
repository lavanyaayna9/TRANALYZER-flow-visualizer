/*
 * gsm_sms.c
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

#include "gsm_sms.h"

#include "gsm_osmocore.h" // for gsm_get_octet_len
#include "gsm_utils.h"    // for channel_to_str, t2buf_read_bcd_number_with_len, t2_normalize_e164

//#include <osmocom/gsm/gsm_utils.h>  // for gsm_get_octet_len


// Returned value MUST be free'd with free()
static char *t2buf_dissect_sms_tstamp(t2buf_t *t2buf)
    __attribute__((__nonnull__(1)))
    __attribute__((__warn_unused_result__));


/* ========================================================================= */
/* GSM SMS TPDU                                                              */
/* GSM 03.40                                                                 */
/* ========================================================================= */
inline bool dissect_gsm_sms(t2buf_t *t2buf, gsm_metadata_t *md) {
    numGSMSMSTPDU++;
    md->gsmFlowP->pstat |= GSM_STAT_SMS;

    const char *msg_type_str = "";
    uint8_t tp_ud_len = 0;
    uint8_t tp_dcs = 0; // GSM-7bit

    uint8_t first_octet;
    t2buf_read_u8(t2buf, &first_octet);

    const bool tp_udhi = (first_octet & 0x40);

    switch (first_octet & 0x03) {

        case 0: { // SMS_DELIVER/SMS_DELIVER_REPORT
            if (md->a_rp.ms_sc) {
                msg_type_str = "SMS_DELIVER_REPORT"; // MS->SC
                GSM_DBG_SMS("%" PRIu64 ": %s", numPackets, msg_type_str);
                if (md->a_rp.msg_type == 0x04 || md->a_rp.msg_type == 0x05) { // RP-ERROR
                    /* TP-Failure-Cause */
                    t2buf_skip_u8(t2buf);
                }

                /* TP-Parameter-Indicator */
                uint8_t pi;
                if (t2buf_peek_u8(t2buf, &pi)) {
                    t2buf_skip_u8(t2buf); // pi
                    /* TP-Protocol-Identifier (TP-PID) */
                    if (pi & 0x01) {
                        uint8_t pid;
                        t2buf_read_u8(t2buf, &pid);
                        GSM_DBG_SMS("%" PRIu64 ": TP-Protocol-Identifier: 0x%02" B2T_PRIX8, numPackets, pid);
                    }
                    /* TP-Data-Coding-Scheme (TP-DCS) */
                    if (pi & 0x02) {
                        t2buf_read_u8(t2buf, &tp_dcs);
                    }
                    /* TP-User-Data-Length (TP-UDL) */
                    if (pi & 0x04) {
                        t2buf_read_u8(t2buf, &tp_ud_len);
                        GSM_DBG_SMS("%" PRIu64 ": TP-User-Data-Length: %" PRIu8, numPackets, tp_ud_len);
                    }
                }
            } else {
                msg_type_str = "SMS_DELIVER"; // SC->MS
                GSM_DBG_SMS("%" PRIu64 ": %s", numPackets, msg_type_str);

                //const bool tp_mms = (first_octet & 0x40); // TP-More-Messages-to-Send

                /* TP-Originating-Address (TP-OA) */
                uint8_t sender_len;
                t2buf_read_u8(t2buf, &sender_len);
                GSM_DBG_SMS("%" PRIu64 ": TP-Originating-Address Length: %" PRIu8 " digits (0x%02" B2T_PRIX8 ")",
                        numPackets, sender_len, sender_len);
                if (sender_len > 0) {
                    sender_len = ((sender_len + 1) / 2) + 1; // the +1 will be removed by t2buf_read_bcd_number_with_len() when reading the type
                    GSM_DBG_SMS("%" PRIu64 ": TP-Originating-Address Length: %" PRIu8 " bytes (0x%02" B2T_PRIX8 ")",
                            numPackets, sender_len, sender_len);
                    md->a_sms.tp_originating_addr = t2buf_read_bcd_number_with_len(t2buf, sender_len);
                }

                /* TP-Protocol-Identifier (TP-PID) */
                uint8_t tp_pid;
                t2buf_read_u8(t2buf, &tp_pid);

                /* TP-Data-Coding-Scheme (TP-DCS) */
                t2buf_read_u8(t2buf, &tp_dcs);
                if (tp_dcs == 0x00) {
                    //GSM_DBG_SMS("%" PRIu64 ": GSM 7 bit default alphabet", numPackets);
                } else if (tp_dcs == 0x04) {
                    //GSM_DBG_SMS("%" PRIu64 ": 8 bit data", numPackets);
                } else if (tp_dcs != 0x08) {
#if GSM_DBG_SMS_UNK == 1
                    GSM_DBG_SMS("%" PRIu64 ": unknown encoding: 0x%02" B2T_PRIX8, numPackets, tp_dcs);
#endif
                    md->gsmFlowP->pstat |= GSM_STAT_SMS_MALFORMED;
                    tp_dcs = 0x00;
                }

                /* TP-Service-Centre-Time-Stamp (TP-SCTS) */
                md->a_sms.sctstamp = t2buf_dissect_sms_tstamp(t2buf);

                /* TP-User-Data-Length (TP-UDL) */
                t2buf_read_u8(t2buf, &tp_ud_len);
            }
            break;
        }

        case 1: { // SMS_SUBMIT/SMS_SUBMIT_REPORT
            if (md->a_rp.ms_sc) {
                msg_type_str = "SMS_SUBMIT"; // MS->SC
                GSM_DBG_SMS("%" PRIu64 ": %s", numPackets, msg_type_str);
                //bool tp_rp = first_octet & 0x80;
                //bool srr = first_octet & 0x20;
                uint8_t vpf = (first_octet & 0x18);
                //bool tp_rd = first_octet & 0x04;
                /* TP-Message-Reference */
                uint8_t mr;
                t2buf_read_u8(t2buf, &mr);
                md->a_sms.msg_ref = mr;
                GSM_DBG_SMS("%" PRIu64 ": TP-Message-Reference: %" PRIu8, numPackets, mr);

                /* TP-Destination-Address */
                uint8_t sender_len;
                t2buf_read_u8(t2buf, &sender_len);
                if (sender_len > 0) {
                    sender_len = ((sender_len + 1) / 2) + 1; // the +1 will be removed by t2buf_read_bcd_number_with_len() when reading the type
                    md->a_sms.tp_destination_addr = t2buf_read_bcd_number_with_len(t2buf, sender_len);
                }

                /* TP-Protocol-Identifier (TP-PID) */
                uint8_t tp_pid;
                t2buf_read_u8(t2buf, &tp_pid);

                /* TP-Data-Coding-Scheme (TP-DCS) */
                t2buf_read_u8(t2buf, &tp_dcs);
                if (tp_dcs == 0x00) {
                    //GSM_DBG_SMS("%" PRIu64 ": GSM 7 bit default alphabet", numPackets);
                } else if (tp_dcs == 0x04) {
                    //GSM_DBG_SMS("%" PRIu64 ": 8 bit data", numPackets);
                } else if (tp_dcs != 0x08) {
#if GSM_DBG_SMS_UNK == 1
                    GSM_DBG_SMS("%" PRIu64 ": unknown encoding: 0x%02" B2T_PRIX8, numPackets, tp_dcs);
#endif
                    tp_dcs = 0x00;
                }

                /* TP-Validity-Period */
                if (vpf) {
                    uint8_t validity;
                    t2buf_read_u8(t2buf, &validity);
                }

                /* TP-User-Data-Length */
                t2buf_read_u8(t2buf, &tp_ud_len);
            } else {
                msg_type_str = "SMS_SUBMIT_REPORT"; // SC->MS
                GSM_DBG_SMS("%" PRIu64 ": %s", numPackets, msg_type_str);
                if (md->a_rp.msg_type == 0x04 || md->a_rp.msg_type == 0x05) { // RP-ERROR
                    /* TP-Failure-Cause */
                    t2buf_skip_u8(t2buf);
                }

                /* TP-Parameter-Indicator */
                uint8_t pi;
                if (t2buf_peek_u8(t2buf, &pi)) {
                    t2buf_skip_u8(t2buf); // pi
                    /* TP-Protocol-Identifier (TP-PID) */
                    if (pi & 0x01) {
                        uint8_t pid;
                        t2buf_read_u8(t2buf, &pid);
                        GSM_DBG_SMS("%" PRIu64 ": TP-Protocol-Identifier: 0x%02" B2T_PRIX8, numPackets, pid);
                    }
                    /* TP-Data-Coding-Scheme (TP-DCS) */
                    if (pi & 0x02) {
                        t2buf_read_u8(t2buf, &tp_dcs);
                    }
                    /* TP-User-Data-Length (TP-UDL) */
                    if (pi & 0x04) {
                        t2buf_read_u8(t2buf, &tp_ud_len);
                        GSM_DBG_SMS("%" PRIu64 ": TP-User-Data-Length: %" PRIu8, numPackets, tp_ud_len);
                    }
                }
            }
            break;
        }

        case 2: { // SMS_COMMAND/SMS_STATUS_REPORT
            if (md->a_rp.ms_sc) {
                msg_type_str = "SMS_COMMAND"; // MS->SC
                GSM_DBG_SMS("%" PRIu64 ": %s", numPackets, msg_type_str);
                //const bool srr = first_octet & 0x20;
                /* TP-Message-Reference (TP-MR) */
                uint8_t mr;
                t2buf_read_u8(t2buf, &mr);
                md->a_sms.msg_ref = mr;
                GSM_DBG_SMS("%" PRIu64 ": TP-Message-Reference: %" PRIu8, numPackets, mr);
                /* TP-Protocol-Identifier (TP-PID) */
                uint8_t pid;
                t2buf_read_u8(t2buf, &pid);
                GSM_DBG_SMS("%" PRIu64 ": TP-Protocol-Identifier: 0x%02" B2T_PRIX8, numPackets, pid);
                /* TP-Command-Type (TP-CT) */
                uint8_t ct;
                t2buf_read_u8(t2buf, &ct);
                GSM_DBG_SMS("%" PRIu64 ": TP-Command-Type: 0x%02" B2T_PRIX8, numPackets, ct);
                /* TP-Message-Number (TP-MN) */
                uint8_t mn;
                t2buf_read_u8(t2buf, &mn);
                //msg_ref = mr;
                GSM_DBG_SMS("%" PRIu64 ": TP-Message-Number: 0x%02" B2T_PRIX8, numPackets, mn);
                /* TP-Destination-Address (TP-DA) */
                uint8_t da_len;
                t2buf_read_u8(t2buf, &da_len);
                if (da_len > 0) {
                    da_len = ((da_len + 1) / 2) + 1; // the +1 will be removed by t2buf_read_bcd_number_with_len() when reading the type
                    GSM_DBG_SMS("%" PRIu64 ": TP-Destination-Address Length: %" PRIu8 " (0x%02" B2T_PRIX8 ")", numPackets, da_len, da_len);
                    md->a_sms.tp_destination_addr = t2buf_read_bcd_number_with_len(t2buf, da_len);
                }
                /* TP-Command-Data-Length (TP-CDL) */
                uint8_t cd_len;
                t2buf_read_u8(t2buf, &cd_len);
                GSM_DBG_SMS("%" PRIu64 ": TP-Command-Data-Length: %" PRIu8, numPackets, cd_len);
                /* TP-Command-Data (TP-CD) */
                t2buf_skip_n(t2buf, cd_len);
            } else {
                msg_type_str = "SMS_STATUS_REPORT"; // SC->MS
                GSM_DBG_SMS("%" PRIu64 ": %s", numPackets, msg_type_str);
                //const bool srq = first_octet & 0x20;
                //const bool lp = first_octet & 0x08;
                //const bool mms = first_octet & 0x04;

                /* TP-Message-Reference (TP-MR) */
                uint8_t mr;
                t2buf_read_u8(t2buf, &mr);
                md->a_sms.msg_ref = mr;
                GSM_DBG_SMS("%" PRIu64 ": TP-Message-Reference: %" PRIu8, numPackets, mr);

                /* TP-Recipient-Address (TP-RA) */
                uint8_t recipient_len;
                t2buf_read_u8(t2buf, &recipient_len);
                if (recipient_len > 0) {
                    recipient_len = ((recipient_len + 1) / 2) + 1; // the +1 will be removed by t2buf_read_bcd_number_with_len() when reading the type
                    md->a_sms.tp_recipient_addr = t2buf_read_bcd_number_with_len(t2buf, recipient_len);
                }

                /* TP-Service-Centre-Time-Stamp (TP-SCTS) */
                md->a_sms.sctstamp = t2buf_dissect_sms_tstamp(t2buf);

                /* TP-Discharge-Time (TP-DT) */
                char *dt = t2buf_dissect_sms_tstamp(t2buf);
                GSM_DBG_SMS("%" PRIu64 ": TP-Discharge-Time: %s", numPackets, dt);
                free(dt);

                /* TP-Status (TP-ST) */
                uint8_t status;
                t2buf_read_u8(t2buf, &status);
                //const bool def = ((status & 0x80) >> 7);
                //const uint8_t err = ((status & 0x60) >> 6);
                //const uint8_t reason = (status & 0x1f);

                /* TP-Parameter-Indicator */
                uint8_t pi;
                if (t2buf_peek_u8(t2buf, &pi)) {
                    t2buf_skip_u8(t2buf); // pi
                    /* TP-Protocol-Identifier (TP-PID) */
                    if (pi & 0x01) {
                        uint8_t pid;
                        t2buf_read_u8(t2buf, &pid);
                        GSM_DBG_SMS("%" PRIu64 ": TP-Protocol-Identifier: 0x%02" B2T_PRIX8, numPackets, pid);
                    }
                    /* TP-Data-Coding-Scheme (TP-DCS) */
                    if (pi & 0x02) {
                        t2buf_read_u8(t2buf, &tp_dcs);
                    }
                    /* TP-User-Data-Length (TP-UDL) */
                    if (pi & 0x04) {
                        t2buf_read_u8(t2buf, &tp_ud_len);
                        GSM_DBG_SMS("%" PRIu64 ": TP-User-Data-Length: %" PRIu8, numPackets, tp_ud_len);
                    }
                }
            }
            break;
        }

        default: {
#if GSM_DBG_SMS_UNK == 1
            GSM_DBG_SMS("%" PRIu64 ": Unknown GSM SMS message type 0x%02" B2T_PRIX8, numPackets, (uint8_t)(first_octet & 0x03));
#endif
            return false;
        }
    }

    /* TP-User-Data-Length */
    if (tp_ud_len > 0) {
        const uint8_t tp_ud_len_orig = tp_ud_len;
        const uint8_t tp_udh_start = t2buf_tell(t2buf);
        GSM_DBG_SMS("%" PRIu64 ": TP-User-Data-Length: %" PRIu8 " (0x%02" B2T_PRIX8 ")", numPackets, tp_ud_len, tp_ud_len);
        // !!! GSM 7 bit encodes the uncompressed length
        const uint8_t tp_ud_num_bytes = ((tp_dcs == 0) ? gsm_get_octet_len(tp_ud_len) : tp_ud_len);
        const uint16_t pktlen = md->packet->l7Len;
        if (tp_ud_num_bytes != pktlen - t2buf_tell(t2buf)) {
#if GSM_DBG_SMS_UNK == 1
            GSM_DBG_SMS("%" PRIu64 ": Byte %lu (TP-DATA) is not the PDU length: 0x%02" B2T_PRIX8 " (%" PRIu8 ") != %lu",
                    numPackets, t2buf_tell(t2buf), tp_ud_len, tp_ud_len, pktlen - t2buf_tell(t2buf));
#endif
            md->gsmFlowP->pstat |= GSM_STAT_SMS_MALFORMED;
            return false;
        }

        if (tp_udhi) {
            /* TP-User-Data-Header-Length (TP-UDHL) */
            uint8_t udh_len;
            t2buf_read_u8(t2buf, &udh_len);
            tp_ud_len -= (udh_len + 1);

            GSM_DBG_SMS("%" PRIu64 ": TP-UDH Length: %" PRIu8 " (0x%02" B2T_PRIX8 ") -> %" PRIu8 " bytes",
                    numPackets, udh_len, udh_len, tp_ud_num_bytes);

            /* TP-User-Data-Header (TP-UDH) */
            while (udh_len > 0) {
                uint8_t elem_ie;
                if (!t2buf_peek_u8(t2buf, &elem_ie)) break;
                t2buf_skip_u8(t2buf); // iei
                udh_len--;
                switch (elem_ie) {
                    case 0x00:   // Concatenated short messages, 8-bit reference number
                    case 0x08: { // Concatenated short messages, 16-bit reference number
                        uint8_t len;
                        t2buf_read_u8(t2buf, &len);
                        udh_len -= (len + 1); // len

                        if (elem_ie == 0x08) {
                            // 16-bit reference number
                            uint16_t id;
                            t2buf_read_u16(t2buf, &id);
                            md->a_sms.msg_id = id;
                        } else {
                            // 8-bit reference number
                            uint8_t id;
                            t2buf_read_u8(t2buf, &id);
                            md->a_sms.msg_id = id;
                        }

                        t2buf_read_u8(t2buf, &md->a_sms.msg_parts);
                        t2buf_read_u8(t2buf, &md->a_sms.msg_part);

                        GSM_DBG_SMS("%" PRIu64 ": SMS PART: ID: 0x%04" B2T_PRIX16 ", %" PRIu8 "/%" PRIu8,
                                numPackets, (uint16_t)md->a_sms.msg_id, md->a_sms.msg_part, md->a_sms.msg_parts);

                        md->gsmFlowP->msg_id = md->a_sms.msg_id;
                        break;
                    }
                    //case 0x05: // Application port addressing scheme, 16-bit address
                    default:
                        GSM_DBG_SMS("%" PRIu64 ": TP-UDH: Unhandled IEI 0x%02" B2T_PRIX8, numPackets, elem_ie);
                        t2buf_skip_n(t2buf, udh_len);
                        udh_len = 0;
                        break;
                }
            }
        }

        /* TP-User-Data */
        if (tp_ud_len > 0) {
            GSM_DBG_SMS("%" PRIu64 ": TP-UD Length: %" PRIu8 " (0x%02" B2T_PRIX8 ")", numPackets, tp_ud_len, tp_ud_len);
            if (tp_dcs == 0x04) {
                md->a_sms.msg = t2_calloc_fatal(2 * tp_ud_len + 1, sizeof(char)); // Every character may have to be duplicated... '\t' -> '\\', 't'
                for (uint_fast8_t i = 0; i < tp_ud_len; i++) {
                    t2buf_read_u8(t2buf, (uint8_t*)&md->a_sms.msg[i]);
                    switch (md->a_sms.msg[i]) {
                        case 0x09: // \t
                            md->a_sms.msg[i] = ' ';
                            //md->a_sms.msg[i++] = '\\';
                            //md->a_sms.msg[i] = 't';
                            //tp_ud_len++;
                            break;
                        case 0x0a: // \n
                            md->a_sms.msg[i] = ' ';
                            //md->a_sms.msg[i++] = '\\';
                            //md->a_sms.msg[i] = 'n';
                            //tp_ud_len++;
                            break;
                        case 0x0d: // \r
                            md->a_sms.msg[i] = ' ';
                            //md->a_sms.msg[i++] = '\\';
                            //md->a_sms.msg[i] = 'r';
                            //tp_ud_len++;
                            break;
                        case 0x22: // double quote (")
                            md->a_sms.msg[i++] = '\\';
                            md->a_sms.msg[i] = '"';
                            tp_ud_len++;
                            break;
                        //case 0x27: // single quote (')
                        //    md->a_sms.msg[i++] = '\\';
                        //    md->a_sms.msg[i] = '\'';
                        //    tp_ud_len++;
                        //    break;
                        case 0x5c: // backslash
                            md->a_sms.msg[i++] = '\\';
                            md->a_sms.msg[i] = '\\';
                            tp_ud_len++;
                            break;
                        default:
                            if (md->a_sms.msg[i] < 32 || md->a_sms.msg[i] > 126) {
                                md->a_sms.msg[i] = '.';
                            }
                            break;
                    }
                }
            } else if (tp_dcs == 0x08) {
                md->a_sms.msg = t2buf_read_ucs2_as_utf8(t2buf, tp_ud_len);
            } else { // tp_dcs == 0x00
                t2buf_seek(t2buf, tp_udh_start, SEEK_SET);
                uint8_t data[tp_ud_len_orig];
                for (uint_fast8_t i = 0; i < tp_ud_len_orig; i++) {
                    t2buf_read_u8(t2buf, &data[i]);
                }
                const size_t text_len = 2 * tp_ud_len_orig + 1; // assume every char may be doubled...
                md->a_sms.msg = t2_calloc_fatal(text_len, sizeof(char));
                gsm_7bit_decode_n_hdr(md->a_sms.msg, text_len, data, tp_ud_len_orig, tp_udhi);
            }

            GSM_DBG_SMS("%" PRIu64 ": SMS text (len=%" PRIu8 "): %s", numPackets, tp_ud_len, md->a_sms.msg);
        }
    }

#if GSM_SMSFILE == 1
    const time_t sec = md->flowP->lastSeen.tv_sec;
    const intmax_t usec = md->flowP->lastSeen.tv_usec;

    if (!md->rsl.channel.str) {
        md->rsl.channel.str = channel_to_str(&md->rsl.channel);
    }

    t2_normalize_e164(&md->a_sms.tp_originating_addr, &md->a_rp.originator_addr);
    t2_normalize_e164(&md->a_sms.tp_destination_addr, &md->a_rp.destination_addr);

    FILE * const smsFp = file_manager_fp(t2_file_manager, smsFile);
    fprintf(smsFp,
            "%" PRIu64  /* pktNo                    */ SEP_CHR
            "%" PRIu64  /* flowInd                  */ SEP_CHR
            "%ld.%06jd" /* time                     */ SEP_CHR
            "%" PRIu16  /* vlanID                   */ SEP_CHR
            "%" PRIu8   /* lapdTEI                  */ SEP_CHR
            "%s"        /* direction                */ SEP_CHR
            "%" PRIu8   /* gsmRslTN                 */ SEP_CHR
            "%" PRIu8   /* gsmRslSubCh              */ SEP_CHR
            "%s"        /* gsmRslChannel            */ SEP_CHR
            "%s"        /* smsMsgType               */ SEP_CHR
            "\"%s\""    /* serviceCenterTimeStamp   */ SEP_CHR
            "%s"        /* rpOriginatorAddr         */ SEP_CHR
            "%s"        /* rpOriginatorAddrCountry  */ SEP_CHR
            "%s"        /* rpDestinationAddr        */ SEP_CHR
            "%s"        /* rpDestinationAddrCountry */ SEP_CHR
            "%s"        /* tpOriginatingAddr        */ SEP_CHR
            "%s"        /* tpOriginatingAddrCountry */ SEP_CHR
            "%s"        /* tpDestinationAddr        */ SEP_CHR
            "%s"        /* tpDestinationAddrCountry */ SEP_CHR
            "%s"        /* tpRecipientAddr          */ SEP_CHR
            "%s"        /* tpRecipientAddrCountry   */ SEP_CHR
            ,
            numPackets,
            md->flowP->findex,
            sec, usec,
            md->flowP->vlanId,
            md->gsmFlowP->tei,
            md->a_rp.ms_sc ? "MS->SC" : "SC->MS",
            md->rsl.channel.tn,
            md->rsl.channel.subchannel,
            md->rsl.channel.str,
            msg_type_str,
            md->a_sms.sctstamp ? md->a_sms.sctstamp : "",
            md->a_rp.originator_addr.number  ? md->a_rp.originator_addr.number  : "\"\"",
            md->a_rp.originator_addr.country ? md->a_rp.originator_addr.country : "\"\"",
            md->a_rp.destination_addr.number  ? md->a_rp.destination_addr.number  : "\"\"",
            md->a_rp.destination_addr.country ? md->a_rp.destination_addr.country : "\"\"",
            md->a_sms.tp_originating_addr.number  ? md->a_sms.tp_originating_addr.number  : "\"\"",
            md->a_sms.tp_originating_addr.country ? md->a_sms.tp_originating_addr.country : "\"\"",
            md->a_sms.tp_destination_addr.number  ? md->a_sms.tp_destination_addr.number  : "\"\"",
            md->a_sms.tp_destination_addr.country ? md->a_sms.tp_destination_addr.country : "\"\"",
            md->a_sms.tp_recipient_addr.number  ? md->a_sms.tp_recipient_addr.number  : "\"\"",
            md->a_sms.tp_recipient_addr.country ? md->a_sms.tp_recipient_addr.country : "\"\"");

    /* smsMsgRef */
    if (md->a_sms.msg_ref > 0) {
        fprintf(smsFp, "%d" /* smsMsgRef */ SEP_CHR, md->a_sms.msg_ref);
    } else {
        fputs(/* smsMsgRef */ SEP_CHR, smsFp);
    }

    /* smsMsgId, smsMsgPart */
    if (md->a_sms.msg_parts > 0) {
        fprintf(smsFp,
                "%d"                 /* smsMsgId   */ SEP_CHR
                "%" PRIu8 "/%" PRIu8 /* smsMsgPart */ SEP_CHR
                ,
                md->a_sms.msg_id,
                md->a_sms.msg_part, md->a_sms.msg_parts);
    } else {
        fputs(/* smsMsgId   */ SEP_CHR
              /* smsMsgPart */ SEP_CHR
              , smsFp);
    }

    fprintf(smsFp, "\"%s\"" /* smsMsg */ "\n", md->a_sms.msg ? md->a_sms.msg : "");
#endif // GSM_SMSFILE

    if (md->a_sms.msg) {
        numGSMSMSMsg++;
    }

    return false;
}


// Returned value MUST be free'd with free()
static inline char *t2buf_dissect_sms_tstamp(t2buf_t *t2buf) {
    if (t2buf_left(t2buf) < 7) return strdup("");

    uint8_t ts[7];
    for (uint_fast8_t i = 0; i < 7; i++) {
        t2buf_read_u8(t2buf, &ts[i]);
    }

    return t2_strdup_printf(
            "%02" B2T_PRIX8 "/%02" B2T_PRIX8 "/%02" B2T_PRIX8 " "
            "%02" B2T_PRIX8 ":%02" B2T_PRIX8 ":%02" B2T_PRIX8 " UTC%c%02" PRIu8,
            (uint8_t)((ts[0] & 0x0f) << 4 | ts[0] >> 4),
            (uint8_t)((ts[1] & 0x0f) << 4 | ts[1] >> 4),
            (uint8_t)((ts[2] & 0x0f) << 4 | ts[2] >> 4),
            (uint8_t)((ts[3] & 0x0f) << 4 | ts[3] >> 4),
            (uint8_t)((ts[4] & 0x0f) << 4 | ts[4] >> 4),
            (uint8_t)((ts[5] & 0x0f) << 4 | ts[5] >> 4),
            ((ts[6] & 0x80) ? '-' : '+'),
            (uint8_t)(((ts[6] & 0x0f) << 4 | (ts[6] & 0x70) >> 4) / 4));
}
