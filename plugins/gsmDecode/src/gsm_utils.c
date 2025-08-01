/*
 * gsm_utils.c
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

#include "gsm_utils.h"

#include "e164_list.h"    // for e164_country, e164_country_code
#include "gsm_osmocore.h" // for gsm_7bit_decode_n_hdr, gsm_band_name, ...
#include "mcc_list.h"     // for mcc_to_str, mnc_to_str
#include "t2utils.h"      // for t2_calloc_fatal
#include "tac_list.h"     // for gsm_tac_t, gsm_tac_list_t, gsm_tac_list_lookup

//#include <osmocom/gsm/gsm_utils.h> // for gsm_get_octet_len

extern gsm_tac_list_t tac_list;

static uint8_t unichar_to_utf8(uint32_t c, char *outbuf) __attribute__((__nonnull__(2)));


const dgt_set_t Dgt0_9_bcd = {
    {
        /*  0   1   2   3   4   5   6   7   8   9   a   b   c   d   e  f */
           '0','1','2','3','4','5','6','7','8','9','?','?','?','?','?','?'
    }
};

const dgt_set_t Dgt_tbcd = {
    {
  /*  0   1   2   3   4   5   6   7   8   9   a   b   c   d   e   f */
     '0','1','2','3','4','5','6','7','8','9','?','B','C','*','#','?'
    }
};

const dgt_set_t Dgt_keypad_abc_tbcd = {
    {
  /*  0   1   2   3   4   5   6   7   8   9   a   b   c   d   e   f */
     '0','1','2','3','4','5','6','7','8','9','*','#','a','b','c','?'
    }
};


static const char * const identity_str[] = {
    "No Identity",
    "IMSI",
    "IMEI",
    "IMEISV",
    "TMSI", // TMSI/P-TMSI/M-TMSI/5G-TMSI
    "ID(5)",
    "ID(6)",
    "ID(7)"
};


static uint8_t unichar_to_utf8 (uint32_t c, char *outbuf) {
    uint8_t len = 0;

    if (c < 0x80) {
        switch (c) {
            case 0x09: // \t
                outbuf[len++] = ' ';
                //outbuf[len++] = '\\';
                //outbuf[len++] = 't';
                break;
            case 0x0a: // \n
                outbuf[len++] = ' ';
                //outbuf[len++] = '\\';
                //outbuf[len++] = 'n';
                break;
            case 0x0d: // \r
                outbuf[len++] = ' ';
                //outbuf[len++] = '\\';
                //outbuf[len++] = 'r';
                break;
            case 0x22: // double quote (")
                outbuf[len++] = '\\';
                outbuf[len++] = '"';
                break;
            //case 0x27: // single quote (')
            //    outbuf[len++] = '\\';
            //    outbuf[len++] = '\'';
            //    break;
            case 0x5c: // backslash
                outbuf[len++] = '\\';
                outbuf[len++] = '\\';
                break;
            default:
                outbuf[len++] = c;
                break;
        }
    } else {
        uint8_t first = 0;
        if (c < 0x800) {
            first = 0xc0;
            len = 2;
        } else if (c < 0x10000) {
            first = 0xe0;
            len = 3;
        } else if (c < 0x200000) {
            first = 0xf0;
            len = 4;
        } else if (c < 0x4000000) {
            first = 0xf8;
            len = 5;
        } else {
            first = 0xfc;
            len = 6;
        }

        for (uint_fast8_t i = len - 1; i > 0; --i) {
            outbuf[i] = (c & 0x3f) | 0x80;
            c >>= 6;
        }

        outbuf[0] = c | first;
    }

    return len;
}


#define IS_LEAD_SURROGATE(uchar2)    ((uchar2) >= 0xd800 && (uchar2) < 0xdc00)
#define IS_TRAIL_SURROGATE(uchar2)   ((uchar2) >= 0xdc00 && (uchar2) < 0xe000)
#define SURROGATE_VALUE(lead, trail) (((((lead) - 0xd800) << 10) | ((trail) - 0xdc00)) + 0x10000)


/* Returned value MUST be free'd */
char *t2buf_read_ucs2_as_utf8(t2buf_t *t2buf, uint8_t len) {
    // len = number of bytes
    char *out = t2_calloc_fatal(6 * len + 1, sizeof(char)); // 6: max length returned by unichar_to_utf8()
    char *out2 = out;
    uint16_t u16;
    int i;
    for (i = 0; i + 1 < len; i += 2) {
        t2buf_read_u16(t2buf, &u16);
        if (IS_LEAD_SURROGATE(u16)) {
            i += 2;
            if (i+1 >= len) {
                *out2++ = '.';
                break;
            }
            const uint16_t lead_surrogate = u16;
            t2buf_read_u16(t2buf, &u16);
            if (IS_TRAIL_SURROGATE(u16)) {
                const uint32_t u32 = SURROGATE_VALUE(lead_surrogate, u16);
                out2 += unichar_to_utf8(u32, out2);
            } else {
                *out2++ = '.';
            }
        } else if (IS_TRAIL_SURROGATE(u16)) {
            *out2++ = '.';
        } else {
            out2 += unichar_to_utf8(u16, out2);
        }
    }
    if (i < len) *out2++ = '.';
    *out2 = '\0';
    return out;
}


// Adapted from wireshark
inline void mcc_mnc_aux(uint8_t *octs, char *mcc, char *mnc) {
    dgt_set_t dgt = Dgt_tbcd;

    // MCC
    if ((octs[0] & 0x0f) <= 9) {
        mcc[0] = dgt.out[octs[0] & 0x0f];
    } else {
        mcc[0] = (octs[0] & 0x0f) + 55;
    }

    if (((octs[0] & 0xf0) >> 4) <= 9) {
        mcc[1] = dgt.out[(octs[0] & 0xf0) >> 4];
    } else {
        mcc[1] = ((octs[0] & 0xf0) >> 4) + 55;
    }

    if ((octs[1] & 0x0f) <= 9) {
        mcc[2] = dgt.out[octs[1] & 0x0f];
    } else {
        mcc[2] = (octs[1] & 0x0f) + 55;
    }

    mcc[3] = '\0';

    // MNC
    if (((octs[1] & 0xf0) >> 4) <= 9) {
        mnc[2] = dgt.out[(octs[1] & 0xf0) >> 4];
    } else {
        mnc[2] = ((octs[1] & 0xf0) >> 4) + 55;
    }

    if ((octs[2] & 0x0f) <= 9) {
        mnc[0] = dgt.out[octs[2] & 0x0f];
    } else {
        mnc[0] = (octs[2] & 0x0f) + 55;
    }

    if (((octs[2] & 0xf0) >> 4) <= 9) {
        mnc[1] = dgt.out[(octs[2] & 0xf0) >> 4];
    } else {
        mnc[1] = ((octs[2] & 0xf0) >> 4) + 55;
    }

    if (mnc[1] == 'F') {
        // only a 1 digit MNC (very old)
        mnc[1] = '\0';
    } else if (mnc[2] == 'F') {
        // only a 2 digit MNC
        mnc[2] = '\0';
    } else {
        mnc[3] = '\0';
    }
}


// channel description gsm 04.08
// Returned value MUST be free'd with gsm_channel_description_free()
inline gsmChannelDescription_t t2buf_read_channel_description(t2buf_t *t2buf, gsm_metadata_t *md) {
    gsmChannelDescription_t d = {};

    uint8_t channel_type;
    t2buf_read_u8(t2buf, &channel_type);

    d.c_bits = ((channel_type & 0xf8) >> 3);
    d.tn = (channel_type & 0x07);

    switch (d.c_bits) {
        case 0x01:
            d.channel = t2_strdup_printf("Ch:(TN:%u TCH/F + ACCHs)", d.tn);
            break;
        case 0x02:
        case 0x03:
            d.channel = t2_strdup_printf("Ch:(TN:%u SbCh: %u CC:TCH/H + ACCHs)", d.tn, (d.c_bits & 0x01));
            break;
        case 0x04:
        case 0x05:
        case 0x06:
        case 0x07:
            d.channel = t2_strdup_printf("Ch:(TN:%u SbCh:%u CC:SDCCH/4 + SACCH/C4 or CBCH (SDCCH/4))", d.tn, (d.c_bits & 0x3));
            break;
        case 0x08:
        case 0x09:
        case 0x0a:
        case 0x0b:
        case 0x0c:
        case 0x0d:
        case 0x0e:
        case 0x0f:
            d.channel = t2_strdup_printf("Ch:(TN:%u SbCh:%u CC:SDCCH/8 + SACCH/C8 or CBCH (SDCCH/8))", d.tn, (d.c_bits & 0x7));
            break;
        default:
#if GSM_DBG_UNK == 1
            GSM_DBG("%" PRIu64 ": Unknown channel type amd TDMA offset 0x%02" B2T_PRIX8, numPackets, d.c_bits);
#endif
            break;
    }

    uint8_t octet3;
    t2buf_read_u8(t2buf, &octet3);

    uint8_t octet4;
    t2buf_read_u8(t2buf, &octet4);

    // Training Sequence Code (TSC)
    d.tsc = ((octet3 & 0xe0) >> 5);
    d.hopping = ((octet3 & 0x10) >> 4); // 0: Single RF channel, 1: RF hopping channel

    GSM_DBG("%" PRIu64 ": Channel Description IE: %s, Training Sequence Code (TSC): 0x%02" B2T_PRIX8 " (%s)", numPackets, d.channel, d.tsc, (d.hopping ? "RF hopping channel" : "Single RF Channel"));

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
                numPackets,
                d.arfcn, gsm_band_name(band),
                freq10u / 10, freq10u % 10,
                freq10d / 10, freq10d % 10);
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


// Returned value MUST be free'd with gsm_mobile_identity_free()
inline gsmMobileIdentity_t t2buf_read_mobile_identity(t2buf_t *t2buf, gsm_metadata_t *md) {
    gsmMobileIdentity_t identity = {};

    // Mobile identity
    uint8_t len;
    if (!t2buf_read_u8(t2buf, &len) || len == 0) return identity;

    uint8_t flags;
    if (!t2buf_peek_u8(t2buf, &flags)) return identity;

    //const uint8_t odd_even = ((flags & 0x08) >> 3); // 1: odd number of identity digits
    const uint8_t id_type = (flags & 0x07);
    identity.type = id_type;

    switch (id_type) {

        case 0: // No Identity
            GSM_DBG("%" PRIu64 ": Mobile Identity: No Identity", numPackets);
            break;

        case 1:   // IMSI
        case 2:   // IMEI
        case 3: { // IMEISV
            bool skip_first = true;
            identity.str = t2_calloc_fatal(2 * len + 1, sizeof(char));
            dgt_set_t dgt = Dgt0_9_bcd;
            int i = 0;
            while (len > 0) {
                uint8_t octet;
                t2buf_read_u8(t2buf, &octet);

                if (skip_first) {
                    skip_first = false;
                } else {
                    identity.str[i++] = dgt.out[octet & 0x0f];
                }

                octet = (octet >> 4);

                if (len == 1 && octet == 0x0f) {
                    // TODO test odd_even instead?
                    /*
                     * This is the last octet, and the high-order
                     * nibble is 0xf, so we have an odd number of
                     * digits, and this is a filler digit. Ignore
                     * it.
                     */
                    break;
                }

                identity.str[i++] = dgt.out[octet & 0x0f];

                len--;
            };

            identity.str[i] = '\0';

            GSM_DBG("%" PRIu64 ": Mobile Identity: %s: %s", numPackets, identity_str[id_type], identity.str);
            break;
        }

        case 4: { // TMSI
            t2buf_skip_u8(t2buf); // flags
            t2buf_read_u32(t2buf, &identity.tmsi);
#if GSM_TMSI_FORMAT == 1
            GSM_DBG("%" PRIu64 ": Mobile Identity: TMSI: 0x%04" B2T_PRIX32, numPackets, identity.tmsi);
#else
            GSM_DBG("%" PRIu64 ": Mobile Identity: TMSI: %" PRIu32, numPackets, identity.tmsi);
#endif
            break;
        }

        default: // Reserved
#if GSM_DBG_UNK == 1
            GSM_DBG("%" PRIu64 ": Mobile Identity: Reserved: 0x%02" B2T_PRIX8, numPackets, id_type);
#endif
            break;
    }

#if GSM_IMSIFILE == 1
    if (id_type > 0 && id_type < 5) {

        const time_t sec = md->flowP->lastSeen.tv_sec;
        const intmax_t usec = md->flowP->lastSeen.tv_usec;
        if (!md->rsl.channel.str) {
            md->rsl.channel.str = channel_to_str(&md->rsl.channel);
        }

        FILE * const imsiFp = file_manager_fp(t2_file_manager, imsiFile);
        fprintf(imsiFp,
                "%" PRIu64  /* pktNo                 */ SEP_CHR
                "%" PRIu64  /* flowInd               */ SEP_CHR
                "%ld.%06jd" /* time                  */ SEP_CHR
                "%" PRIu16  /* vlanID                */ SEP_CHR
                "%" PRIu8   /* lapdTEI               */ SEP_CHR
                "%" PRIu8   /* gsmRslTN              */ SEP_CHR
                "%" PRIu8   /* gsmRslSubCh           */ SEP_CHR
                "%s"        /* gsmRslChannel         */ SEP_CHR
                "%s"        /* gsmMobileIdentityType */ SEP_CHR
                , numPackets
                , md->flowP->findex
                , sec, usec
                , md->flowP->vlanId
                , md->gsmFlowP->tei
                , md->rsl.channel.tn
                , md->rsl.channel.subchannel
                , md->rsl.channel.str
                , identity_str[id_type]);

        switch (id_type) {
            case 1: // IMSI
            case 2: // IMEI
            case 3: // IMEISV
                fprintf(imsiFp, "%s" /* gsmIMSI */, identity.str);
                break;
            case 4: // TMSI
#if GSM_TMSI_FORMAT == 1
                fprintf(imsiFp, "0x%04" B2T_PRIX32 /* gsmIMSI */, identity.tmsi);
#else
                fprintf(imsiFp, "%" PRIu32 /* gsmIMSI */, identity.tmsi);
#endif
                break;
            default:
                break;
        }

        const gsm_tac_t * tac = NULL;
        if (id_type == 2 || id_type == 3) { // IMEI/IMEISV
            char tac_str[9] = {
                identity.str[0],
                identity.str[1],
                identity.str[2],
                identity.str[3],
                identity.str[4],
                identity.str[5],
                identity.str[6],
                identity.str[7],
                '\0'
            };
            tac = gsm_tac_list_lookup(&tac_list, strtoul(tac_str, NULL, 0));
        }

        if (tac) {
            fprintf(imsiFp,
                             /* gsmIMSI         */ SEP_CHR
                    "\"%s\"" /* gsmIMEITACManuf */ SEP_CHR
                    "\"%s\"" /* gsmIMEITACModel */ SEP_CHR
                    , tac->manuf
                    , tac->model);
        } else {
            fputs(/* gsmIMSI         */ SEP_CHR
                  /* gsmIMEITACManuf */ SEP_CHR
                  /* gsmIMEITACModel */ SEP_CHR
                  , imsiFp);
        }

        if (id_type == 1) { // IMSI
            char mcc[4] = {
                identity.str[0],
                identity.str[1],
                identity.str[2],
                '\0'
            };
            char mnc[3] = {
                identity.str[3],
                identity.str[4],
                '\0'
            };
            fprintf(imsiFp,
                    "%s"     /* gsmIMSIMCC         */ SEP_CHR
                    "\"%s\"" /* gsmIMSIMCCCountry  */ SEP_CHR
                    "%s"     /* gsmIMSIMNC         */ SEP_CHR
                    "\"%s\"" /* gsmIMSIMNCOperator */ SEP_CHR
                    , mcc
                    , mcc_to_str(mcc)
                    , mnc
                    , mnc_to_str(mcc, mnc));
        } else {
            fputs(/* gsmIMSIMCC         */ SEP_CHR
                  /* gsmIMSIMCCCountry  */ SEP_CHR
                  /* gsmIMSIMNC         */ SEP_CHR
                  /* gsmIMSIMNCOperator */ SEP_CHR
                  , imsiFp);
        }

        if (md->a_dtap.lai.valid == true) {
            fprintf(imsiFp,
                    "%s"               /* gsmLAIMCC         */ SEP_CHR
                    "%s"               /* gsmLAIMCCCountry  */ SEP_CHR
                    "%s"               /* gsmLAIMNC         */ SEP_CHR
                    "\"%s\""           /* gsmLAIMNCOperator */ SEP_CHR
                    "0x%04" B2T_PRIX16 /* gsmLAILAC         */ "\n"
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
    }
#endif

    return identity;
}


// Returned value MUST be free'd with gsm_mobile_number_free()
inline gsmMobileNumber_t t2buf_read_bcd_number(t2buf_t *t2buf) {
    uint8_t len;
    if (!t2buf_read_u8(t2buf, &len)) len = 0;
    return t2buf_read_bcd_number_with_len(t2buf, len);
}


// Returned value MUST be free'd with gsm_mobile_number_free()
inline gsmMobileNumber_t t2buf_read_bcd_number_with_len(t2buf_t *t2buf, uint8_t len) {

    gsmMobileNumber_t number = {};

    if (len == 0) return number;

    uint8_t num_type;
    t2buf_read_u8(t2buf, &num_type); // num_type & 0x80: extension,
                                     // num_type & 0x70: type of number,
                                     // num_type & 0x0f: numbering plan identification
    len -= 1;

    const uint8_t type_of_num = ((num_type & 0x70) >> 4);
    const uint8_t numbering_plan = (num_type & 0x0f);

    number.type = type_of_num;
    number.numbering_plan = numbering_plan;

    GSM_DBG("%" PRIu64 ": Type of Number: 0x%02" B2T_PRIX8, numPackets, type_of_num);
    GSM_DBG("%" PRIu64 ": Numbering Plan: 0x%02" B2T_PRIX8, numPackets, numbering_plan);

    // Type of number:
    //    000: unknown
    //    001: international number
    //    010: national number
    //    011: network specific number
    //    100: dedicated access, short code
    //    101: alphanumeric (GSM 7-bit default alphabet)
    //    111: reserved for extension

    // Numbering plan identification
    //    0000: Unknown
    //    0001: ISDN/telephone numbering plan (Rec. E.164/E.163)
    //    0011: Data numbering plan (Recommendation X.121)
    //    0100: Telex numbering plan (Recommendation F.69)
    //    1000: National numbering plan
    //    1001: Private numbering plan
    //    1111: Reserved for extension
    //    All other values are reserved.

    /* Extension */
    if ((num_type & 0x80) == 0x00) {
        uint8_t ext;
        t2buf_read_u8(t2buf, &ext);
        if (len == 0) return number;
        len -= 1;
    }

    char *num_str;
    if (type_of_num == 0x05) { // Alphanumeric
        uint8_t data[len];
        for (uint_fast8_t i = 0; i < len; i++) {
            t2buf_read_u8(t2buf, &data[i]);
        }
        const size_t text_len = (2 * ((len * 8) / 7)) + 1; // XXX assume every char may be doubled...
        num_str = t2_calloc_fatal(text_len, sizeof(char));
        gsm_7bit_decode_n_hdr(num_str, text_len, data, (len * 8) / 7, 0);
    } else {
        const size_t num_len = 2 * len + 2; // in case we need to add a '+'
        num_str = t2_calloc_fatal(num_len, sizeof(char));
        int pos = 0;
        if (type_of_num == 1 && /*numbering_plan == 1 &&*/ len > 4) {
            pos = snprintf(num_str, num_len, "+");
        }
        uint8_t num[len];
        dgt_set_t dgt = Dgt_keypad_abc_tbcd;
        for (uint_fast8_t i = 0; i < len; i++) {
            t2buf_read_u8(t2buf, &num[i]);
            pos += snprintf(num_str + pos, num_len - pos, "%c", dgt.out[num[i] & 0x0f]);
            if (i < (len-1) || ((num[i] & 0xf0) != 0xf0)) {
                pos += snprintf(num_str + pos, num_len - pos, "%c", dgt.out[num[i] >> 4]);
            }
        }
    }

    GSM_DBG("%" PRIu64 ": BCD Number: %s", numPackets, num_str);

    number.number = num_str;
    if (type_of_num == 1 && /*numbering_plan == 1 &&*/ len > 4) {
        if (num_str[1] == '0' && num_str[2] == '0') {
            char *tmp = t2_strdup_printf("+%s", num_str+3);
            free(number.number);
            number.number = tmp;
            num_str = tmp;
        }
        char dgt3[] = { num_str[1], num_str[2], num_str[3] };
        number.country = e164_country(dgt3, 0);
    }

    return number;
}


inline bool t2buf_read_timing_advance(t2buf_t *t2buf, uint8_t *ta, uint16_t *bts_dist) {
    if (!t2buf_read_u8(t2buf, ta)) return false;

    // timing advance (& 0xc0: reserved)
    *ta = (*ta & 0x3f);
    if (*ta == 0) {
        *bts_dist = 300;
        GSM_DBG("%" PRIu64 ": Timing Advance: 0 (MS < 300m from BTS)", numPackets);
    } else {
        // BTS unreachable if distance > 35 km
        *bts_dist = (300 + *ta * 550) / 2;
        GSM_DBG("%" PRIu64 ": Timing Advance: %u (MS ~ %um from BTS)", numPackets, *ta, *bts_dist);
    }

    return true;
}


// Returned value MUST be free'd with free()
inline char *t2buf_read_multirate_configuration(t2buf_t *t2buf, gsm_metadata_t *md) {
    uint8_t len;
    t2buf_read_u8(t2buf, &len);

    uint8_t bf1;
    t2buf_read_u8(t2buf, &bf1);
    len--;

    const uint8_t multirate_speech_version = ((bf1 & 0xe0) >> 5);
    const uint8_t ncsb = ((bf1 & 0x10) >> 4); // Noise Suppression Control Bit
    const uint8_t icmi = ((bf1 & 0x08) >> 3); // Initial Codec Mode Indicator
    const uint8_t start_mode = (bf1 & 0x03);  // Start Mode

    if (ncsb) {
        GSM_DBG("%" PRIu64 ": MultiRate Configuration IE: Noise Suppression shall be turned off", numPackets);
    } else {
        GSM_DBG("%" PRIu64 ": MultiRate Configuration IE: Noise Suppression can be used (default)", numPackets);
    }

    char *start_mode_str;
    if (icmi) {
        start_mode_str = t2_strdup_printf(", Start Mode: %u", start_mode);
        GSM_DBG("%" PRIu64 ": MultiRate Configuration IE: The initial codec mode is defined by the Start Mode field (%u)", numPackets, start_mode);
    } else {
        start_mode_str = NULL;
        GSM_DBG("%" PRIu64 ": MultiRate Configuration IE: The initial codec mode is defined by the implicit rule provided in 3GPP TS 05.09", numPackets);
    }

    char *amr_config = NULL;
    switch (multirate_speech_version) {
        case 1: { // Adaptive MultiRate speech version 1
            uint8_t codec_modes;
            t2buf_read_u8(t2buf, &codec_modes);
            amr_config = t2_strdup_printf("AMR speech version 1%s%s%s%s%s%s%s%s%s%s",
                ((codec_modes & 0x80) ? ", 12.2 kbit/s" : ""),
                ((codec_modes & 0x40) ? ", 10.2 kbit/s" : ""),
                ((codec_modes & 0x20) ? ", 7.95 kbit/s" : ""),
                ((codec_modes & 0x10) ? ", 7.40 kbit/s" : ""),
                ((codec_modes & 0x08) ? ", 6.70 kbit/s" : ""),
                ((codec_modes & 0x04) ? ", 5.90 kbit/s" : ""),
                ((codec_modes & 0x02) ? ", 5.15 kbit/s" : ""),
                ((codec_modes & 0x01) ? ", 4.75 kbit/s" : ""),
                (ncsb ? "" : ", NCSB"),
                (start_mode_str ? start_mode_str : ""));
            GSM_DBG("%" PRIu64 ": MultiRate Configuration: %s", numPackets, amr_config);
            len--;
            break;
        }

        case 2: { // Adaptive MultiRate speech version 2
            uint8_t codec_modes;
            t2buf_read_u8(t2buf, &codec_modes);
            amr_config = t2_strdup_printf("AMR speech version 2%s%s%s%s%s%s%s",
                ((codec_modes & 0x10) ? ", 23.85 kbit/s" : ""),
                ((codec_modes & 0x08) ? ", 15.85 kbit/s" : ""),
                ((codec_modes & 0x04) ? ", 12.65 kbit/s" : ""),
                ((codec_modes & 0x02) ? ", 8.85 kbit/s" : ""),
                ((codec_modes & 0x01) ? ", 6.60 kbit/s" : ""),
                (ncsb ? "" : ", NCSB"),
                (start_mode_str ? start_mode_str : ""));
            GSM_DBG("%" PRIu64 ": MultiRate Configuration: %s", numPackets, amr_config);
            len--;
            break;
        }

        default:
            GSM_DBG("%" PRIu64 ": MultiRate Configuration IE: Unknown multirate speech version 0x%02" B2T_PRIX8, numPackets, multirate_speech_version);
            md->gsmFlowP->pstat |= GSM_STAT_MALFORMED;
            t2buf_skip_n(t2buf, len);
            return NULL;
    }

    if (len) {
        t2buf_skip_n(t2buf, len);
        // TODO AMR Threshold (6 bits), AMR Hysteresis (4 bits)
    }

    free(start_mode_str);

    return amr_config;
}


inline bool t2buf_read_request_reference(t2buf_t *t2buf, gsm_request_reference_t *ref) {
    if (!t2buf_read_u8(t2buf, &ref->ra)) return false; // random access information

    uint8_t octet2;
    if (!t2buf_read_u8(t2buf, &octet2)) return false;

    uint8_t octet3;
    if (!t2buf_read_u8(t2buf, &octet3)) return false;

    ref->t1 = ((octet2 & 0xf8) >> 3);
    const uint8_t t3_high = (octet2 & 0x07);
    const uint8_t t3_low = ((octet3 & 0xe0) >> 5);
    ref->t2 = (octet3 & 0x1f);
    ref->t3 = ((t3_high << 3) | t3_low);
    int16_t t = (ref->t3 - ref->t2) % 26;
    if (t < 0) t += 26;
    ref->rfn = 51 * t + ref->t3 + 51 * 26 * ref->t1;
    GSM_DBG("%" PRIu64 ": Request Reference: RA: %u, T1': %u, T2: %u, T3: %u => RFN: %u", numPackets, ref->ra, ref->t1, ref->t2, ref->t3, ref->rfn);

    return true;
}


inline void t2_normalize_e164(gsmMobileNumber_t *a, const gsmMobileNumber_t * const b) {
    if (!a->number || a->country || a->numbering_plan != 1 || strlen(a->number) < 4) return;

    if ((a->type == 2 || (a->type == 0 && a->number[0] == '0' && a->number[1] != '0'))) { // National/Unknown
        if (b->country) {
            a->country = b->country;
            const int cc = e164_country_code(a->country);
            if (cc > 0) {
                const size_t len = strlen(a->number) + 1 + 4;
                char *e164 = t2_calloc_fatal(len, sizeof(char));
                snprintf(e164, len, "+%d%s", cc, a->number + ((a->number[0] == '0') ? 1 : 0));
                free(a->number);
                a->number = e164;
            }
        } else if (a->number[0] != '0') {
            const size_t len = strlen(a->number) + 2;
            char *e164 = t2_calloc_fatal(len, sizeof(char));
            snprintf(e164, len, "0%s", a->number);
            free(a->number);
            a->number = e164;
        }
    } else if (a->type == 0) { // Unknown
        if (a->number[0] == '0' && a->number[1] == '0') {
            char dgt3[] = { a->number[2], a->number[3], a->number[4] };
            a->country = e164_country(dgt3, 0);
            const size_t len = strlen(a->number);
            char *e164 = t2_calloc_fatal(len, sizeof(char));
            snprintf(e164, len, "+%s", a->number + 2);
            free(a->number);
            a->number = e164;
        }
    }
}


// Returned value MUST be free'd with free()
inline char *channel_to_str(const gsmChannel_t * const channel) {
    switch (channel->type) {
        case 0x01: return t2_strdup_printf("Ch:(TN:%u CC:Bm + ACCH's)", channel->tn);
        case 0x02: return t2_strdup_printf("Ch:(TN:%u SbCh:%u CC:Lm + ACCH's)", channel->tn, channel->subchannel);
        case 0x04: return t2_strdup_printf("Ch:(TN:%u SbCh:%u CC:SDCCH/4 + ACCH)", channel->tn, channel->subchannel);
        case 0x08: return t2_strdup_printf("Ch:(TN:%u SbCh:%u CC:SDCCH/8 + ACCH)", channel->tn, channel->subchannel);
        case 0x10: return t2_strdup_printf("Ch:(TN:%u CC:BCCH)", channel->tn);
        case 0x11: return t2_strdup_printf("Ch:(TN:%u CC:Uplink CCCH (RACH))", channel->tn);
        case 0x12: return t2_strdup_printf("Ch:(TN:%u CC:Downlink CCCH (PCH + AGCH))", channel->tn);
        case 0x00:
            return strdup("");
        default:
            return t2_strdup_printf("Ch:(TN:%u CC:0x%02" B2T_PRIX8 ")", channel->tn, channel->c_bits);
    }
}


inline void gsm_channel_description_free(gsmChannelDescription_t *ch_desc) {
    GSM_FREE_AND_NULL(ch_desc->channel);
}


inline void gsm_channel_free(gsmChannel_t *channel) {
    GSM_FREE_AND_NULL(channel->str);
}


inline void gsm_metadata_free(gsm_metadata_t *md) {
    // md->rsl
    GSM_FREE_AND_NULL(md->rsl.amr_config);
    GSM_FREE_AND_NULL(md->rsl.channel_content);
    gsm_channel_free(&md->rsl.channel);
    // md->a_dtap
    gsm_channel_description_free(&md->a_dtap.channel);
    gsm_mobile_number_free(&md->a_dtap.caller);
    gsm_mobile_number_free(&md->a_dtap.callee);
    GSM_FREE_AND_NULL(md->a_dtap.full_network_name);
    GSM_FREE_AND_NULL(md->a_dtap.short_network_name);
    GSM_FREE_AND_NULL(md->a_dtap.network_time_zone);
    GSM_FREE_AND_NULL(md->a_dtap.network_time_and_time_zone);
    GSM_FREE_AND_NULL(md->a_dtap.amr_config);
    // md->a_rp
    gsm_mobile_number_free(&md->a_rp.originator_addr);
    gsm_mobile_number_free(&md->a_rp.destination_addr);
    GSM_FREE_AND_NULL(md->a_rp.destination);
    GSM_FREE_AND_NULL(md->a_rp.originator);
    // md->a_sms
    gsm_mobile_number_free(&md->a_sms.tp_originating_addr);
    gsm_mobile_number_free(&md->a_sms.tp_destination_addr);
    gsm_mobile_number_free(&md->a_sms.tp_recipient_addr);
    GSM_FREE_AND_NULL(md->a_sms.sender);
    GSM_FREE_AND_NULL(md->a_sms.sctstamp);
    GSM_FREE_AND_NULL(md->a_sms.msg);
}


inline void gsm_mobile_identity_free(gsmMobileIdentity_t *id) {
    switch (id->type) {
        case 1: // IMSI
        case 2: // IMEI
        case 3: // IMEISV
            GSM_FREE_AND_NULL(id->str);
            break;
        default:
            break;
    }
}


inline void gsm_mobile_number_free(gsmMobileNumber_t *number) {
    GSM_FREE_AND_NULL(number->number);
}
