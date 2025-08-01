/*
 * gsm_osmocore.c
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

#include "gsm_osmocore.h"

#include <stdio.h>


/* ======================================================================== */
/* libosmocore/src/codec/gsm690.c                                           */
/* ======================================================================== */


/* See also RFC 4867 §3.6, Table 1, Column "Total speech bits" */
/*static*/ const uint8_t amr_len_by_ft[16] = {
	12, 13, 15, 17, 19, 20, 26, 31, 5,  0,  0,  0,  0,  0,  0,  0
};

const struct value_string osmo_amr_type_names[] = {
	{ AMR_4_75,		"AMR 4,75 kbits/s" },
	{ AMR_5_15,		"AMR 5,15 kbit/s" },
	{ AMR_5_90,		"AMR 5,90 kbit/s" },
	{ AMR_6_70,		"AMR 6,70 kbit/s (PDC-EFR)" },
	{ AMR_7_40,		"AMR 7,40 kbit/s (TDMA-EFR)" },
	{ AMR_7_95,		"AMR 7,95 kbit/s" },
	{ AMR_10_2,		"AMR 10,2 kbit/s" },
	{ AMR_12_2,		"AMR 12,2 kbit/s (GSM-EFR)" },
	{ AMR_SID,		"AMR SID" },
	{ AMR_GSM_EFR_SID,	"GSM-EFR SID" },
	{ AMR_TDMA_EFR_SID,	"TDMA-EFR SID" },
	{ AMR_PDC_EFR_SID,	"PDC-EFR SID" },
	{ AMR_NO_DATA,		"No Data/NA" },
	{ 0,			NULL },
};


/* ======================================================================== */
/* libosmocore/src/utils.c                                                  */
/* ======================================================================== */


static __thread char namebuf[255];

/*! get human-readable string for given value
 *  \param[in] vs Array of value_string tuples
 *  \param[in] val Value to be converted
 *  \returns pointer to human-readable string
 *
 * If val is found in vs, the array's string entry is returned. Otherwise, an
 * "unknown" string containing the actual value is composed in a static buffer
 * that is reused across invocations.
 */
const char *get_value_string(const struct value_string *vs, uint32_t val)
{
	const char *str = get_value_string_or_null(vs, val);
	if (str)
		return str;

	snprintf(namebuf, sizeof(namebuf), "unknown 0x%"PRIx32, val);
	namebuf[sizeof(namebuf) - 1] = '\0';
	return namebuf;
}

/*! get human-readable string or NULL for given value
 *  \param[in] vs Array of value_string tuples
 *  \param[in] val Value to be converted
 *  \returns pointer to human-readable string or NULL if val is not found
 */
const char *get_value_string_or_null(const struct value_string *vs,
				     uint32_t val)
{
	int i;

	if (!vs)
		return NULL;

	for (i = 0;; i++) {
		if (vs[i].value == 0 && vs[i].str == NULL)
			break;
		if (vs[i].value == val)
			return vs[i].str;
	}

	return NULL;
}


/* ======================================================================== */
/* libosmocore/src/gsm/gsm_utils.c                                          */
/* ======================================================================== */


/* ETSI GSM 03.38 6.2.1 and 6.2.1.1 default alphabet
 * Greek symbols at hex positions 0x10 and 0x12-0x1a
 * left out as they can't be handled with a char and
 * since most phones don't display or write these
 * characters this would only needlessly make the code
 * more complex.
 *
 * Note that this table contains the latin1->7bit mapping _and_ has
 * been merged with the reverse mapping (7bit->latin1) for the
 * extended characters at offset 0x7f.
 */
/*static*/ unsigned char gsm_7bit_alphabet[] = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0a, 0xff, 0xff, 0x0d, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0x20, 0x21, 0x22, 0x23, 0x02, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c,
	0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
	0x3c, 0x3d, 0x3e, 0x3f, 0x00, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a,
	0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59,
	0x5a, 0x3c, 0x2f, 0x3e, 0x14, 0x11, 0xff, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
	0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
	0x78, 0x79, 0x7a, 0x28, 0x40, 0x29, 0x3d, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0x0c, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x5e, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x40, 0xff, 0x01, 0xff,
	0x03, 0xff, 0x7b, 0x7d, 0xff, 0xff, 0xff, 0xff, 0xff, 0x5c, 0xff, 0xff, 0xff, 0xff, 0xff,
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x5b, 0x7e, 0x5d, 0xff, 0x7c, 0xff, 0xff, 0xff,
	0xff, 0x5b, 0x0e, 0x1c, 0x09, 0xff, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x5d,
	0xff, 0xff, 0xff, 0xff, 0x5c, 0xff, 0x0b, 0xff, 0xff, 0xff, 0x5e, 0xff, 0xff, 0x1e, 0x7f,
	0xff, 0xff, 0xff, 0x7b, 0x0f, 0x1d, 0xff, 0x04, 0x05, 0xff, 0xff, 0x07, 0xff, 0xff, 0xff,
	0xff, 0x7d, 0x08, 0xff, 0xff, 0xff, 0x7c, 0xff, 0x0c, 0x06, 0xff, 0xff, 0x7e, 0xff, 0xff
};

/* GSM 03.38 6.2.1 Character lookup for decoding */
/*static*/ int gsm_septet_lookup(uint8_t ch)
{
	int i = 0;
	for (; i < (int)sizeof(gsm_7bit_alphabet); i++) {
		if (gsm_7bit_alphabet[i] == ch)
			return i;
	}
	return -1;
}

/*! Compute number of octets from number of septets.
 * For instance: 47 septets need 41,125 = 42 octets.
 * \param[in] sept_len Number of septets
 * \returns Number of octets required */
uint8_t gsm_get_octet_len(const uint8_t sept_len){
	int octet_len = (sept_len * 7) / 8;
	if ((sept_len * 7) % 8 != 0)
		octet_len++;

	return octet_len;
}

/*! TS 03.38 7-bit Character unpacking (6.2.1)
 *  \param[out] text Caller-provided output text buffer
 *  \param[in] n Length of \a text
 *  \param[in] user_data Input Data (septets)
 *  \param[in] septet_l Number of septets in \a user_data
 *  \param[in] ud_hdr_ind User Data Header present in data
 *  \returns number of bytes written to \a text */
int gsm_7bit_decode_n_hdr(char *text, size_t n, const uint8_t *user_data, uint8_t septet_l, uint8_t ud_hdr_ind)
{
	unsigned shift = 0;
	uint8_t c7, c8, next_is_ext = 0, lu, ru;
	const uint8_t maxlen = gsm_get_octet_len(septet_l);
	const char *text_buf_begin = text;
	const char *text_buf_end = text + n;

	OSMO_ASSERT (n > 0);

	/* skip the user data header */
	if (ud_hdr_ind) {
		/* get user data header length + 1 (for the 'user data header length'-field) */
		shift = ((user_data[0] + 1) * 8) / 7;
		if ((((user_data[0] + 1) * 8) % 7) != 0)
			shift++;
		septet_l = septet_l - shift;
	}

	unsigned i, l, r;
	for (i = 0; i < septet_l && text != text_buf_end - 1; i++) {

		l = ((i + shift) * 7 + 7) >> 3;
		r = ((i + shift) * 7) >> 3;

		/* the left side index is always >= right side index
		sometimes it even gets beyond array boundary
		check for that explicitly and force 0 instead
		 */
		if (l >= maxlen)
			lu = 0;
		else
			lu = user_data[l] << (7 - (((i + shift) * 7 + 7) & 7));

		ru = user_data[r] >> (((i + shift) * 7) & 7);

		c7 = (lu | ru) & 0x7f;

		if (next_is_ext) {
			/* this is an extension character */
			next_is_ext = 0;
			c8 = gsm_7bit_alphabet[0x7f + c7];
		} else if (c7 == 0x1b && i + 1 < septet_l) {
			next_is_ext = 1;
			continue;
		} else {
			c8 = gsm_septet_lookup(c7);
		}

		*(text++) = c8;

		////////////////////////////////////////////////////////////////////////
		// BEGIN T2 ADDITION                                                  //
		////////////////////////////////////////////////////////////////////////

		switch (*(text-1)) {
			case '\t': // \t
				*(text-1) = ' ';
				//*(text-1) = '\\';
				//*(text++) = 't';
				break;
			case '\n': // \n
				*(text-1) = ' ';
				//*(text-1) = '\\';
				//*(text++) = 'n';
				break;
			case '\r': // \r
				*(text-1) = ' ';
				//*(text-1) = '\\';
				//*(text++) = 'r';
				break;
			case '"': // double quote (")
				*(text-1) = '\\';
				*(text++) = '"';
				break;
			//case '\'': // single quote (')
			//	*(text-1) = '\\';
			//	*(text++) = '\\';
			//	break;
			case '\\': // backslash
				*(text-1) = '\\';
				*(text++) = '\\';
				break;
			default:
				break;
		}

		////////////////////////////////////////////////////////////////////////
		// END T2 ADDITION                                                    //
		////////////////////////////////////////////////////////////////////////
	}

	*text = '\0';

	return text - text_buf_begin;
}

/*! Return string name of a given GSM Band */
const char *gsm_band_name(enum gsm_band band)
{
	switch (band) {
	case GSM_BAND_450:
		return "GSM450";
	case GSM_BAND_480:
		return "GSM480";
	case GSM_BAND_750:
		return "GSM750";
	case GSM_BAND_810:
		return "GSM810";
	case GSM_BAND_850:
		return "GSM850";
	case GSM_BAND_900:
		return "GSM900";
	case GSM_BAND_1800:
		return "DCS1800";
	case GSM_BAND_1900:
		return "PCS1900";
	}
	return "invalid";
}

/*! Resolve GSM band from ARFCN.
 *  In Osmocom, we use the highest bit of the \a arfcn to indicate PCS
 *  \param[in] arfcn Osmocom ARFCN, highest bit determines PCS mode
 *  \param[out] band GSM Band containing \arfcn if arfcn is valid, undetermined otherwise
 *  \returns 0 if arfcn is valid and \a band was set, negative on error */
int gsm_arfcn2band_rc(uint16_t arfcn, enum gsm_band *band)
{
	int is_pcs = arfcn & ARFCN_PCS;

	arfcn &= ~ARFCN_FLAG_MASK;

	if (is_pcs) {
		*band = GSM_BAND_1900;
		return 0;
	} else if (arfcn <= 124) {
		*band = GSM_BAND_900;
		return 0;
	} else if (arfcn >= 955 && arfcn <= 1023) {
		*band = GSM_BAND_900;
		return 0;
	} else if (arfcn >= 128 && arfcn <= 251) {
		*band = GSM_BAND_850;
		return 0;
	} else if (arfcn >= 512 && arfcn <= 885) {
		*band = GSM_BAND_1800;
		return 0;
	} else if (arfcn >= 259 && arfcn <= 293) {
		*band = GSM_BAND_450;
		return 0;
	} else if (arfcn >= 306 && arfcn <= 340) {
		*band = GSM_BAND_480;
		return 0;
	} else if (arfcn >= 350 && arfcn <= 425) {
		*band = GSM_BAND_810;
		return 0;
	} else if (arfcn >= 438 && arfcn <= 511) {
		*band = GSM_BAND_750;
		return 0;
	}
	return -1;
}

struct gsm_freq_range {
	uint16_t arfcn_first;
	uint16_t arfcn_last;
	uint16_t freq_ul_first;
	uint16_t freq_dl_offset;
	uint16_t flags;
};

static struct gsm_freq_range gsm_ranges[] = {
	{ 512,  810, 18502, 800, ARFCN_PCS },	/* PCS 1900 */
	{   0,  124,  8900, 450, 0 },		/* P-GSM + E-GSM ARFCN 0 */
	{ 955, 1023,  8762, 450, 0 },		/* E-GSM + R-GSM */
	{ 128,  251,  8242, 450, 0 },		/* GSM 850  */
	{ 512,  885, 17102, 950, 0 },		/* DCS 1800 */
	{ 259,  293,  4506, 100, 0 },		/* GSM 450  */
	{ 306,  340,  4790, 100, 0 },		/* GSM 480  */
	{ 350,  425,  8060, 450, 0 },		/* GSM 810  */
	{ 438,  511,  7472, 300, 0 },		/* GSM 750  */
	{ /* Guard */ }
};

/*! Convert an ARFCN to the frequency in MHz * 10
 *  \param[in] arfcn GSM ARFCN to convert
 *  \param[in] uplink Uplink (1) or Downlink (0) frequency
 *  \returns Frequency in units of 1/10ths of MHz (100kHz) */
uint16_t gsm_arfcn2freq10(uint16_t arfcn, int uplink)
{
	struct gsm_freq_range *r;
	uint16_t flags = arfcn & ARFCN_FLAG_MASK;
	uint16_t freq10_ul = 0xffff;
	uint16_t freq10_dl = 0xffff;

	arfcn &= ~ARFCN_FLAG_MASK;

	for (r=gsm_ranges; r->freq_ul_first>0; r++) {
		if ((flags == r->flags) &&
		    (arfcn >= r->arfcn_first) &&
		    (arfcn <= r->arfcn_last))
		{
			freq10_ul = r->freq_ul_first + 2 * (arfcn - r->arfcn_first);
			freq10_dl = freq10_ul + r->freq_dl_offset;
			break;
		}
	}

	return uplink ? freq10_ul : freq10_dl;
}


/* ======================================================================== */
/* libosmocore/src/gsm/rsl.c                                                */
/* ======================================================================== */


static const struct value_string rsl_err_vals[] = {
	{ RSL_ERR_RADIO_IF_FAIL,	"Radio Interface Failure" },
	{ RSL_ERR_RADIO_LINK_FAIL,	"Radio Link Failure" },
	{ RSL_ERR_HANDOVER_ACC_FAIL,	"Handover Access Failure" },
	{ RSL_ERR_TALKER_ACC_FAIL,	"Talker Access Failure" },
	{ RSL_ERR_OM_INTERVENTION,	"O&M Intervention" },
	{ RSL_ERR_NORMAL_UNSPEC,	"Normal event, unspecified" },
	{ RSL_ERR_T_MSRFPCI_EXP,	"Siemens: T_MSRFPCI Expired" },
	{ RSL_ERR_EQUIPMENT_FAIL,	"Equipment Failure" },
	{ RSL_ERR_RR_UNAVAIL,		"Radio Resource not available" },
	{ RSL_ERR_TERR_CH_FAIL,		"Terrestrial Channel Failure" },
	{ RSL_ERR_CCCH_OVERLOAD,	"CCCH Overload" },
	{ RSL_ERR_ACCH_OVERLOAD,	"ACCH Overload" },
	{ RSL_ERR_PROCESSOR_OVERLOAD,	"Processor Overload" },
	{ RSL_ERR_BTS_NOT_EQUIPPED,     "BTS not equipped" },
	{ RSL_ERR_REMOTE_TRANSC_FAIL,   "Remote Transcoder Failure" },
	{ RSL_ERR_NOTIFICATION_OVERFL,  "Notification Overflow" },
	{ RSL_ERR_RES_UNAVAIL,		"Resource not available, unspecified" },
	{ RSL_ERR_TRANSC_UNAVAIL,	"Transcoding not available" },
	{ RSL_ERR_SERV_OPT_UNAVAIL,	"Service or Option not available" },
	{ RSL_ERR_ENCR_UNIMPL,		"Encryption algorithm not implemented" },
	{ RSL_ERR_SERV_OPT_UNIMPL,	"Service or Option not implemented" },
	{ RSL_ERR_RCH_ALR_ACTV_ALLOC,	"Radio channel already activated" },
	{ RSL_ERR_INVALID_MESSAGE,	"Invalid Message, unspecified" },
	{ RSL_ERR_MSG_DISCR,		"Message Discriminator Error" },
	{ RSL_ERR_MSG_TYPE,		"Message Type Error" },
	{ RSL_ERR_MSG_SEQ,		"Message Sequence Error" },
	{ RSL_ERR_IE_ERROR,		"General IE error" },
	{ RSL_ERR_MAND_IE_ERROR,	"Mandatory IE error" },
	{ RSL_ERR_OPT_IE_ERROR,		"Optional IE error" },
	{ RSL_ERR_IE_NONEXIST,		"IE non-existent" },
	{ RSL_ERR_IE_LENGTH,		"IE length error" },
	{ RSL_ERR_IE_CONTENT,		"IE content error" },
	{ RSL_ERR_PROTO,		"Protocol error, unspecified" },
	{ RSL_ERR_INTERWORKING,		"Interworking error, unspecified" },
	{ 0,				NULL }
};

/*! Get human-readable name for RSL Error */
const char *rsl_err_name(uint8_t err)
{
	return get_value_string(rsl_err_vals, err);
}

/* Names for Radio Link Layer Management */
static const struct value_string rsl_msgt_names[] = {
	{ RSL_MT_DATA_REQ,		"DATA_REQ" },
	{ RSL_MT_DATA_IND,		"DATA_IND" },
	{ RSL_MT_ERROR_IND,		"ERROR_IND" },
	{ RSL_MT_EST_REQ,		"EST_REQ" },
	{ RSL_MT_EST_CONF,		"EST_CONF" },
	{ RSL_MT_EST_IND,		"EST_IND" },
	{ RSL_MT_REL_REQ,		"REL_REQ" },
	{ RSL_MT_REL_CONF,		"REL_CONF" },
	{ RSL_MT_REL_IND,		"REL_IND" },
	{ RSL_MT_UNIT_DATA_REQ,		"UNIT_DATA_REQ" },
	{ RSL_MT_UNIT_DATA_IND,		"UNIT_DATA_IND" },
	{ RSL_MT_SUSP_REQ,		"SUSP_REQ" },
	{ RSL_MT_SUSP_CONF,		"SUSP_CONF" },
	{ RSL_MT_RES_REQ,		"RES_REQ" },
	{ RSL_MT_RECON_REQ,		"RECON_REQ" },

	{ RSL_MT_BCCH_INFO,		"BCCH_INFO" },
	{ RSL_MT_CCCH_LOAD_IND,		"CCCH_LOAD_IND" },
	{ RSL_MT_CHAN_RQD,		"CHAN_RQD" },
	{ RSL_MT_DELETE_IND,		"DELETE_IND" },
	{ RSL_MT_PAGING_CMD,		"PAGING_CMD" },
	{ RSL_MT_IMMEDIATE_ASSIGN_CMD,	"IMM_ASS_CMD" },
	{ RSL_MT_SMS_BC_REQ,		"SMS_BC_REQ" },
	{ RSL_MT_CHAN_CONF,		"CHAN_CONF" },

	{ RSL_MT_RF_RES_IND,		"RF_RES_IND" },
	{ RSL_MT_SACCH_FILL,		"SACCH_FILL" },
	{ RSL_MT_OVERLOAD,		"OVERLOAD" },
	{ RSL_MT_ERROR_REPORT,		"ERROR_REPORT" },
	{ RSL_MT_SMS_BC_CMD,		"SMS_BC_CMD" },
	{ RSL_MT_CBCH_LOAD_IND,		"CBCH_LOAD_IND" },
	{ RSL_MT_NOT_CMD,		"NOTIFY_CMD" },

	{ RSL_MT_CHAN_ACTIV,		"CHAN_ACTIV" },
	{ RSL_MT_CHAN_ACTIV_ACK,	"CHAN_ACTIV_ACK" },
	{ RSL_MT_CHAN_ACTIV_NACK,	"CHAN_ACTIV_NACK" },
	{ RSL_MT_CONN_FAIL,		"CONN_FAIL" },
	{ RSL_MT_DEACTIVATE_SACCH,	"DEACTIVATE_SACCH" },
	{ RSL_MT_ENCR_CMD,		"ENCR_CMD" },
	{ RSL_MT_HANDO_DET,		"HANDOVER_DETECT" },
	{ RSL_MT_MEAS_RES,		"MEAS_RES" },
	{ RSL_MT_MODE_MODIFY_REQ,	"MODE_MODIFY_REQ" },
	{ RSL_MT_MODE_MODIFY_ACK,	"MODE_MODIFY_ACK" },
	{ RSL_MT_MODE_MODIFY_NACK,	"MODE_MODIFY_NACK" },
	{ RSL_MT_PHY_CONTEXT_REQ,	"PHY_CONTEXT_REQ" },
	{ RSL_MT_PHY_CONTEXT_CONF,	"PHY_CONTEXT_CONF" },
	{ RSL_MT_RF_CHAN_REL,		"RF_CHAN_REL" },
	{ RSL_MT_MS_POWER_CONTROL,	"MS_POWER_CONTROL" },
	{ RSL_MT_BS_POWER_CONTROL,	"BS_POWER_CONTROL" },
	{ RSL_MT_PREPROC_CONFIG,	"PREPROC_CONFIG" },
	{ RSL_MT_PREPROC_MEAS_RES,	"PREPROC_MEAS_RES" },
	{ RSL_MT_RF_CHAN_REL_ACK,	"RF_CHAN_REL_ACK" },
	{ RSL_MT_SACCH_INFO_MODIFY,	"SACCH_INFO_MODIFY" },
	{ RSL_MT_TALKER_DET,		"TALKER_DETECT" },
	{ RSL_MT_LISTENER_DET,		"LISTENER_DETECT" },
	{ RSL_MT_REMOTE_CODEC_CONF_REP,	"REM_CODEC_CONF_REP" },
	{ RSL_MT_RTD_REP,		"RTD_REQ" },
	{ RSL_MT_PRE_HANDO_NOTIF,	"HANDO_NOTIF" },
	{ RSL_MT_MR_CODEC_MOD_REQ,	"CODEC_MOD_REQ" },
	{ RSL_MT_MR_CODEC_MOD_ACK,	"CODEC_MOD_ACK" },
	{ RSL_MT_MR_CODEC_MOD_NACK,	"CODEC_MOD_NACK" },
	{ RSL_MT_MR_CODEC_MOD_PER,	"CODEC_MODE_PER" },
	{ RSL_MT_TFO_REP,		"TFO_REP" },
	{ RSL_MT_TFO_MOD_REQ,		"TFO_MOD_REQ" },
	{ RSL_MT_LOCATION_INFO,		"LOCATION_INFO" },
	{ RSL_MT_OSMO_ETWS_CMD,		"OSMO_ETWS_CMD" },
	{ 0,				NULL }
};

/*! Get human-readable string for RSL Message Type */
const char *rsl_msg_name(uint8_t msg_type)
{
	return get_value_string(rsl_msgt_names, msg_type);
}


/* ======================================================================== */
/* libosmocore/src/gsm/gsm48.c                                              */
/* ======================================================================== */


static const struct value_string rr_cause_names[] = {
	{ GSM48_RR_CAUSE_NORMAL,		"Normal event" },
	{ GSM48_RR_CAUSE_ABNORMAL_UNSPEC,	"Abnormal release, unspecified" },
	{ GSM48_RR_CAUSE_ABNORMAL_UNACCT,	"Abnormal release, channel unacceptable" },
	{ GSM48_RR_CAUSE_ABNORMAL_TIMER,	"Abnormal release, timer expired" },
	{ GSM48_RR_CAUSE_ABNORMAL_NOACT,	"Abnormal release, no activity on radio path" },
	{ GSM48_RR_CAUSE_PREMPTIVE_REL,		"Preemptive release" },
	{ GSM48_RR_CAUSE_UTRAN_CFG_UNK,		"UTRAN configuration unknown" },
	{ GSM48_RR_CAUSE_HNDOVER_IMP,		"Handover impossible, timing advance out of range" },
	{ GSM48_RR_CAUSE_CHAN_MODE_UNACCT,	"Channel mode unacceptable" },
	{ GSM48_RR_CAUSE_FREQ_NOT_IMPL,		"Frequency not implemented" },
	{ GSM48_RR_CAUSE_LEAVE_GROUP_CA,	"Originator or talker leaving group call area" },
	{ GSM48_RR_CAUSE_LOW_LEVEL_FAIL,	"Lower layer failure" },
	{ GSM48_RR_CAUSE_CALL_CLEARED,		"Call already cleared" },
	{ GSM48_RR_CAUSE_SEMANT_INCORR,		"Semantically incorrect message" },
	{ GSM48_RR_CAUSE_INVALID_MAND_INF,	"Invalid mandatory information" },
	{ GSM48_RR_CAUSE_MSG_TYPE_N,		"Message type non-existent or not implemented" },
	{ GSM48_RR_CAUSE_MSG_TYPE_N_COMPAT,	"Message type not compatible with protocol state" },
	{ GSM48_RR_CAUSE_COND_IE_ERROR,		"Conditional IE error" },
	{ GSM48_RR_CAUSE_NO_CELL_ALLOC_A,	"No cell allocation available" },
	{ GSM48_RR_CAUSE_PROT_ERROR_UNSPC,	"Protocol error unspecified" },
	{ 0,					NULL },
};

/*! TS 04.08 RR Message Type names */
const struct value_string gsm48_rr_msgtype_names[] = {
	OSMO_VALUE_STRING(GSM48_MT_RR_INIT_REQ),
	OSMO_VALUE_STRING(GSM48_MT_RR_ADD_ASS),
	OSMO_VALUE_STRING(GSM48_MT_RR_IMM_ASS),
	OSMO_VALUE_STRING(GSM48_MT_RR_IMM_ASS_EXT),
	OSMO_VALUE_STRING(GSM48_MT_RR_IMM_ASS_REJ),
	OSMO_VALUE_STRING(GSM48_MT_RR_DTM_ASS_FAIL),
	OSMO_VALUE_STRING(GSM48_MT_RR_DTM_REJECT),
	OSMO_VALUE_STRING(GSM48_MT_RR_DTM_REQUEST),
	OSMO_VALUE_STRING(GSM48_MT_RR_PACKET_ASS),

	OSMO_VALUE_STRING(GSM48_MT_RR_CIPH_M_CMD),
	OSMO_VALUE_STRING(GSM48_MT_RR_CIPH_M_COMPL),

	OSMO_VALUE_STRING(GSM48_MT_RR_CFG_CHG_CMD),
	OSMO_VALUE_STRING(GSM48_MT_RR_CFG_CHG_ACK),
	OSMO_VALUE_STRING(GSM48_MT_RR_CFG_CHG_REJ),

	OSMO_VALUE_STRING(GSM48_MT_RR_ASS_CMD),
	OSMO_VALUE_STRING(GSM48_MT_RR_ASS_COMPL),
	OSMO_VALUE_STRING(GSM48_MT_RR_ASS_FAIL),
	OSMO_VALUE_STRING(GSM48_MT_RR_HANDO_CMD),
	OSMO_VALUE_STRING(GSM48_MT_RR_HANDO_COMPL),
	OSMO_VALUE_STRING(GSM48_MT_RR_HANDO_FAIL),
	OSMO_VALUE_STRING(GSM48_MT_RR_HANDO_INFO),
	OSMO_VALUE_STRING(GSM48_MT_RR_HANDO_INFO),
	OSMO_VALUE_STRING(GSM48_MT_RR_DTM_ASS_CMD),

	OSMO_VALUE_STRING(GSM48_MT_RR_CELL_CHG_ORDER),
	OSMO_VALUE_STRING(GSM48_MT_RR_PDCH_ASS_CMD),

	OSMO_VALUE_STRING(GSM48_MT_RR_CHAN_REL),
	OSMO_VALUE_STRING(GSM48_MT_RR_PART_REL),
	OSMO_VALUE_STRING(GSM48_MT_RR_PART_REL_COMP),

	OSMO_VALUE_STRING(GSM48_MT_RR_PAG_REQ_1),
	OSMO_VALUE_STRING(GSM48_MT_RR_PAG_REQ_2),
	OSMO_VALUE_STRING(GSM48_MT_RR_PAG_REQ_3),
	OSMO_VALUE_STRING(GSM48_MT_RR_PAG_RESP),
	OSMO_VALUE_STRING(GSM48_MT_RR_NOTIF_NCH),
	OSMO_VALUE_STRING(GSM48_MT_RR_NOTIF_FACCH),
	OSMO_VALUE_STRING(GSM48_MT_RR_NOTIF_RESP),
	OSMO_VALUE_STRING(GSM48_MT_RR_PACKET_NOTIF),
	OSMO_VALUE_STRING(GSM48_MT_RR_UTRAN_CLSM_CHG),
	OSMO_VALUE_STRING(GSM48_MT_RR_CDMA2K_CLSM_CHG),
	OSMO_VALUE_STRING(GSM48_MT_RR_IS_TO_UTRAN_HANDO),
	OSMO_VALUE_STRING(GSM48_MT_RR_IS_TO_CDMA2K_HANDO),

	OSMO_VALUE_STRING(GSM48_MT_RR_SYSINFO_8),
	OSMO_VALUE_STRING(GSM48_MT_RR_SYSINFO_1),
	OSMO_VALUE_STRING(GSM48_MT_RR_SYSINFO_2),
	OSMO_VALUE_STRING(GSM48_MT_RR_SYSINFO_3),
	OSMO_VALUE_STRING(GSM48_MT_RR_SYSINFO_4),
	OSMO_VALUE_STRING(GSM48_MT_RR_SYSINFO_5),
	OSMO_VALUE_STRING(GSM48_MT_RR_SYSINFO_6),
	OSMO_VALUE_STRING(GSM48_MT_RR_SYSINFO_7),

	OSMO_VALUE_STRING(GSM48_MT_RR_SYSINFO_2bis),
	OSMO_VALUE_STRING(GSM48_MT_RR_SYSINFO_2ter),
	OSMO_VALUE_STRING(GSM48_MT_RR_SYSINFO_2quater),
	OSMO_VALUE_STRING(GSM48_MT_RR_SYSINFO_5bis),
	OSMO_VALUE_STRING(GSM48_MT_RR_SYSINFO_5ter),
	OSMO_VALUE_STRING(GSM48_MT_RR_SYSINFO_9),
	OSMO_VALUE_STRING(GSM48_MT_RR_SYSINFO_13),

	OSMO_VALUE_STRING(GSM48_MT_RR_SYSINFO_16),
	OSMO_VALUE_STRING(GSM48_MT_RR_SYSINFO_17),

	OSMO_VALUE_STRING(GSM48_MT_RR_SYSINFO_18),
	OSMO_VALUE_STRING(GSM48_MT_RR_SYSINFO_19),
	OSMO_VALUE_STRING(GSM48_MT_RR_SYSINFO_20),

	OSMO_VALUE_STRING(GSM48_MT_RR_CHAN_MODE_MODIF),
	OSMO_VALUE_STRING(GSM48_MT_RR_STATUS),
	OSMO_VALUE_STRING(GSM48_MT_RR_CHAN_MODE_MODIF_ACK),
	OSMO_VALUE_STRING(GSM48_MT_RR_FREQ_REDEF),
	OSMO_VALUE_STRING(GSM48_MT_RR_MEAS_REP),
	OSMO_VALUE_STRING(GSM48_MT_RR_CLSM_CHG),
	OSMO_VALUE_STRING(GSM48_MT_RR_CLSM_ENQ),
	OSMO_VALUE_STRING(GSM48_MT_RR_EXT_MEAS_REP),
	OSMO_VALUE_STRING(GSM48_MT_RR_EXT_MEAS_REP_ORD),
	OSMO_VALUE_STRING(GSM48_MT_RR_GPRS_SUSP_REQ),
	OSMO_VALUE_STRING(GSM48_MT_RR_DTM_INFO),

	OSMO_VALUE_STRING(GSM48_MT_RR_VGCS_UPL_GRANT),
	OSMO_VALUE_STRING(GSM48_MT_RR_UPLINK_RELEASE),
	OSMO_VALUE_STRING(GSM48_MT_RR_UPLINK_FREE),
	OSMO_VALUE_STRING(GSM48_MT_RR_UPLINK_BUSY),
	OSMO_VALUE_STRING(GSM48_MT_RR_TALKER_IND),
	{ 0, NULL }
};

/*! TS 04.08 MM Message Type names */
const struct value_string gsm48_mm_msgtype_names[] = {
	OSMO_VALUE_STRING(GSM48_MT_MM_IMSI_DETACH_IND),
	OSMO_VALUE_STRING(GSM48_MT_MM_LOC_UPD_ACCEPT),
	OSMO_VALUE_STRING(GSM48_MT_MM_LOC_UPD_REJECT),
	OSMO_VALUE_STRING(GSM48_MT_MM_LOC_UPD_REQUEST),

	OSMO_VALUE_STRING(GSM48_MT_MM_AUTH_REJ),
	OSMO_VALUE_STRING(GSM48_MT_MM_AUTH_REQ),
	OSMO_VALUE_STRING(GSM48_MT_MM_AUTH_RESP),
	OSMO_VALUE_STRING(GSM48_MT_MM_AUTH_FAIL),
	OSMO_VALUE_STRING(GSM48_MT_MM_ID_REQ),
	OSMO_VALUE_STRING(GSM48_MT_MM_ID_RESP),
	OSMO_VALUE_STRING(GSM48_MT_MM_TMSI_REALL_CMD),
	OSMO_VALUE_STRING(GSM48_MT_MM_TMSI_REALL_COMPL),

	OSMO_VALUE_STRING(GSM48_MT_MM_CM_SERV_ACC),
	OSMO_VALUE_STRING(GSM48_MT_MM_CM_SERV_REJ),
	OSMO_VALUE_STRING(GSM48_MT_MM_CM_SERV_ABORT),
	OSMO_VALUE_STRING(GSM48_MT_MM_CM_SERV_REQ),
	OSMO_VALUE_STRING(GSM48_MT_MM_CM_SERV_PROMPT),
	OSMO_VALUE_STRING(GSM48_MT_MM_CM_REEST_REQ),
	OSMO_VALUE_STRING(GSM48_MT_MM_ABORT),

	OSMO_VALUE_STRING(GSM48_MT_MM_NULL),
	OSMO_VALUE_STRING(GSM48_MT_MM_STATUS),
	OSMO_VALUE_STRING(GSM48_MT_MM_INFO),
	{ 0, NULL }
};

/*! TS 04.08 CC Message Type names */
const struct value_string gsm48_cc_msgtype_names[] = {
	OSMO_VALUE_STRING(GSM48_MT_CC_ALERTING),
	OSMO_VALUE_STRING(GSM48_MT_CC_CALL_CONF),
	OSMO_VALUE_STRING(GSM48_MT_CC_CALL_PROC),
	OSMO_VALUE_STRING(GSM48_MT_CC_CONNECT),
	OSMO_VALUE_STRING(GSM48_MT_CC_CONNECT_ACK),
	OSMO_VALUE_STRING(GSM48_MT_CC_EMERG_SETUP),
	OSMO_VALUE_STRING(GSM48_MT_CC_PROGRESS),
	OSMO_VALUE_STRING(GSM48_MT_CC_ESTAB),
	OSMO_VALUE_STRING(GSM48_MT_CC_ESTAB_CONF),
	OSMO_VALUE_STRING(GSM48_MT_CC_RECALL),
	OSMO_VALUE_STRING(GSM48_MT_CC_START_CC),
	OSMO_VALUE_STRING(GSM48_MT_CC_SETUP),

	OSMO_VALUE_STRING(GSM48_MT_CC_MODIFY),
	OSMO_VALUE_STRING(GSM48_MT_CC_MODIFY_COMPL),
	OSMO_VALUE_STRING(GSM48_MT_CC_MODIFY_REJECT),
	OSMO_VALUE_STRING(GSM48_MT_CC_USER_INFO),
	OSMO_VALUE_STRING(GSM48_MT_CC_HOLD),
	OSMO_VALUE_STRING(GSM48_MT_CC_HOLD_ACK),
	OSMO_VALUE_STRING(GSM48_MT_CC_HOLD_REJ),
	OSMO_VALUE_STRING(GSM48_MT_CC_RETR),
	OSMO_VALUE_STRING(GSM48_MT_CC_RETR_ACK),
	OSMO_VALUE_STRING(GSM48_MT_CC_RETR_REJ),

	OSMO_VALUE_STRING(GSM48_MT_CC_DISCONNECT),
	OSMO_VALUE_STRING(GSM48_MT_CC_RELEASE),
	OSMO_VALUE_STRING(GSM48_MT_CC_RELEASE_COMPL),

	OSMO_VALUE_STRING(GSM48_MT_CC_CONG_CTRL),
	OSMO_VALUE_STRING(GSM48_MT_CC_NOTIFY),
	OSMO_VALUE_STRING(GSM48_MT_CC_STATUS),
	OSMO_VALUE_STRING(GSM48_MT_CC_STATUS_ENQ),
	OSMO_VALUE_STRING(GSM48_MT_CC_START_DTMF),
	OSMO_VALUE_STRING(GSM48_MT_CC_STOP_DTMF),
	OSMO_VALUE_STRING(GSM48_MT_CC_STOP_DTMF_ACK),
	OSMO_VALUE_STRING(GSM48_MT_CC_START_DTMF_ACK),
	OSMO_VALUE_STRING(GSM48_MT_CC_START_DTMF_REJ),
	OSMO_VALUE_STRING(GSM48_MT_CC_FACILITY),
	{ 0, NULL }
};

const struct value_string gsm48_cc_cause_names[] = {
	{ GSM48_CC_CAUSE_UNASSIGNED_NR,		"UNASSIGNED_NR" },
	{ GSM48_CC_CAUSE_NO_ROUTE,		"NO_ROUTE" },
	{ GSM48_CC_CAUSE_CHAN_UNACCEPT,		"CHAN_UNACCEPT" },
	{ GSM48_CC_CAUSE_OP_DET_BARRING,	"OP_DET_BARRING" },
	{ GSM48_CC_CAUSE_NORM_CALL_CLEAR,	"NORM_CALL_CLEAR" },
	{ GSM48_CC_CAUSE_USER_BUSY,		"USER_BUSY" },
	{ GSM48_CC_CAUSE_USER_NOTRESPOND,	"USER_NOTRESPOND" },
	{ GSM48_CC_CAUSE_USER_ALERTING_NA,	"USER_ALERTING_NA" },
	{ GSM48_CC_CAUSE_CALL_REJECTED,		"CALL_REJECTED" },
	{ GSM48_CC_CAUSE_NUMBER_CHANGED,	"NUMBER_CHANGED" },
	{ GSM48_CC_CAUSE_PRE_EMPTION,		"PRE_EMPTION" },
	{ GSM48_CC_CAUSE_NONSE_USER_CLR,	"NONSE_USER_CLR" },
	{ GSM48_CC_CAUSE_DEST_OOO,		"DEST_OOO" },
	{ GSM48_CC_CAUSE_INV_NR_FORMAT,		"INV_NR_FORMAT" },
	{ GSM48_CC_CAUSE_FACILITY_REJ,		"FACILITY_REJ" },
	{ GSM48_CC_CAUSE_RESP_STATUS_INQ,	"RESP_STATUS_INQ" },
	{ GSM48_CC_CAUSE_NORMAL_UNSPEC,		"NORMAL_UNSPEC" },
	{ GSM48_CC_CAUSE_NO_CIRCUIT_CHAN,	"NO_CIRCUIT_CHAN" },
	{ GSM48_CC_CAUSE_NETWORK_OOO,		"NETWORK_OOO" },
	{ GSM48_CC_CAUSE_TEMP_FAILURE,		"TEMP_FAILURE" },
	{ GSM48_CC_CAUSE_SWITCH_CONG,		"SWITCH_CONG" },
	{ GSM48_CC_CAUSE_ACC_INF_DISCARD,	"ACC_INF_DISCARD" },
	{ GSM48_CC_CAUSE_REQ_CHAN_UNAVAIL,	"REQ_CHAN_UNAVAIL" },
	{ GSM48_CC_CAUSE_RESOURCE_UNAVAIL,	"RESOURCE_UNAVAIL" },
	{ GSM48_CC_CAUSE_QOS_UNAVAIL,		"QOS_UNAVAIL" },
	{ GSM48_CC_CAUSE_REQ_FAC_NOT_SUBSC,	"REQ_FAC_NOT_SUBSC" },
	{ GSM48_CC_CAUSE_INC_BARRED_CUG,	"INC_BARRED_CUG" },
	{ GSM48_CC_CAUSE_BEARER_CAP_UNAUTH,	"BEARER_CAP_UNAUTH" },
	{ GSM48_CC_CAUSE_BEARER_CA_UNAVAIL,	"BEARER_CA_UNAVAIL" },
	{ GSM48_CC_CAUSE_SERV_OPT_UNAVAIL,	"SERV_OPT_UNAVAIL" },
	{ GSM48_CC_CAUSE_BEARERSERV_UNIMPL,	"BEARERSERV_UNIMPL" },
	{ GSM48_CC_CAUSE_ACM_GE_ACM_MAX,	"ACM_GE_ACM_MAX" },
	{ GSM48_CC_CAUSE_REQ_FAC_NOTIMPL,	"REQ_FAC_NOTIMPL" },
	{ GSM48_CC_CAUSE_RESTR_BCAP_AVAIL,	"RESTR_BCAP_AVAIL" },
	{ GSM48_CC_CAUSE_SERV_OPT_UNIMPL,	"SERV_OPT_UNIMPL" },
	{ GSM48_CC_CAUSE_INVAL_TRANS_ID,	"INVAL_TRANS_ID" },
	{ GSM48_CC_CAUSE_USER_NOT_IN_CUG,	"USER_NOT_IN_CUG" },
	{ GSM48_CC_CAUSE_INCOMPAT_DEST,		"INCOMPAT_DEST" },
	{ GSM48_CC_CAUSE_INVAL_TRANS_NET,	"INVAL_TRANS_NET" },
	{ GSM48_CC_CAUSE_SEMANTIC_INCORR,	"SEMANTIC_INCORR" },
	{ GSM48_CC_CAUSE_INVAL_MAND_INF,	"INVAL_MAND_INF" },
	{ GSM48_CC_CAUSE_MSGTYPE_NOTEXIST,	"MSGTYPE_NOTEXIST" },
	{ GSM48_CC_CAUSE_MSGTYPE_INCOMPAT,	"MSGTYPE_INCOMPAT" },
	{ GSM48_CC_CAUSE_IE_NOTEXIST,		"IE_NOTEXIST" },
	{ GSM48_CC_CAUSE_COND_IE_ERR,		"COND_IE_ERR" },
	{ GSM48_CC_CAUSE_MSG_INCOMP_STATE,	"MSG_INCOMP_STATE" },
	{ GSM48_CC_CAUSE_RECOVERY_TIMER,	"RECOVERY_TIMER" },
	{ GSM48_CC_CAUSE_PROTO_ERR,		"PROTO_ERR" },
	{ GSM48_CC_CAUSE_INTERWORKING,		"INTERWORKING" },
	{ 0 , NULL }
};

/*! return string representation of RR Cause value */
const char *rr_cause_name(uint8_t cause)
{
	return get_value_string(rr_cause_names, cause);
}

static const struct value_string cc_msg_names[] = {
	{ GSM48_MT_CC_ALERTING,		"ALERTING" },
	{ GSM48_MT_CC_CALL_PROC,	"CALL_PROC" },
	{ GSM48_MT_CC_PROGRESS,		"PROGRESS" },
	{ GSM48_MT_CC_ESTAB,		"ESTAB" },
	{ GSM48_MT_CC_SETUP,		"SETUP" },
	{ GSM48_MT_CC_ESTAB_CONF,	"ESTAB_CONF" },
	{ GSM48_MT_CC_CONNECT,		"CONNECT" },
	{ GSM48_MT_CC_CALL_CONF,	"CALL_CONF" },
	{ GSM48_MT_CC_START_CC,		"START_CC" },
	{ GSM48_MT_CC_RECALL,		"RECALL" },
	{ GSM48_MT_CC_EMERG_SETUP,	"EMERG_SETUP" },
	{ GSM48_MT_CC_CONNECT_ACK,	"CONNECT_ACK" },
	{ GSM48_MT_CC_USER_INFO,	"USER_INFO" },
	{ GSM48_MT_CC_MODIFY_REJECT,	"MODIFY_REJECT" },
	{ GSM48_MT_CC_MODIFY,		"MODIFY" },
	{ GSM48_MT_CC_HOLD,		"HOLD" },
	{ GSM48_MT_CC_HOLD_ACK,		"HOLD_ACK" },
	{ GSM48_MT_CC_HOLD_REJ,		"HOLD_REJ" },
	{ GSM48_MT_CC_RETR,		"RETR" },
	{ GSM48_MT_CC_RETR_ACK,		"RETR_ACK" },
	{ GSM48_MT_CC_RETR_REJ,		"RETR_REJ" },
	{ GSM48_MT_CC_MODIFY_COMPL,	"MODIFY_COMPL" },
	{ GSM48_MT_CC_DISCONNECT,	"DISCONNECT" },
	{ GSM48_MT_CC_RELEASE_COMPL,	"RELEASE_COMPL" },
	{ GSM48_MT_CC_RELEASE,		"RELEASE" },
	{ GSM48_MT_CC_STOP_DTMF,	"STOP_DTMF" },
	{ GSM48_MT_CC_STOP_DTMF_ACK,	"STOP_DTMF_ACK" },
	{ GSM48_MT_CC_STATUS_ENQ,	"STATUS_ENQ" },
	{ GSM48_MT_CC_START_DTMF,	"START_DTMF" },
	{ GSM48_MT_CC_START_DTMF_ACK,	"START_DTMF_ACK" },
	{ GSM48_MT_CC_START_DTMF_REJ,	"START_DTMF_REJ" },
	{ GSM48_MT_CC_CONG_CTRL,	"CONG_CTRL" },
	{ GSM48_MT_CC_FACILITY,		"FACILITY" },
	{ GSM48_MT_CC_STATUS,		"STATUS" },
	{ GSM48_MT_CC_NOTIFY,		"NOTFIY" },
	{ 0,				NULL }
};

/*! return string representation of CC Message Type */
const char *gsm48_cc_msg_name(uint8_t msgtype)
{
	return get_value_string(cc_msg_names, msgtype);
}

static const struct value_string rr_msg_names[] = {
	/* Channel establishment messages */
	{ GSM48_MT_RR_INIT_REQ,		"RR INITIALISATION REQUEST" },
	{ GSM48_MT_RR_ADD_ASS,		"ADDITIONAL ASSIGNMENT" },
	{ GSM48_MT_RR_IMM_ASS,		"IMMEDIATE ASSIGNMENT" },
	{ GSM48_MT_RR_IMM_ASS_EXT,	"MMEDIATE ASSIGNMENT EXTENDED" },
	{ GSM48_MT_RR_IMM_ASS_REJ,	"IMMEDIATE ASSIGNMENT REJECT" },
	{ GSM48_MT_RR_DTM_ASS_FAIL,	"DTM ASSIGNMENT FAILURE" },
	{ GSM48_MT_RR_DTM_REJECT,	"DTM REJECT" },
	{ GSM48_MT_RR_DTM_REQUEST,	"DTM REQUEST" },
	{ GSM48_MT_RR_PACKET_ASS,	"PACKET ASSIGNMENT" },

	/* Ciphering messages */
	{ GSM48_MT_RR_CIPH_M_CMD,	"CIPHERING MODE COMMAND" },
	{ GSM48_MT_RR_CIPH_M_COMPL,	"CIPHERING MODE COMPLETE" },

	/* Configuration change messages */
	{ GSM48_MT_RR_CFG_CHG_CMD,	"CONFIGURATION CHANGE COMMAND" },
	{ GSM48_MT_RR_CFG_CHG_ACK,	"CONFIGURATION CHANGE ACK" },
	{ GSM48_MT_RR_CFG_CHG_REJ,	"CONFIGURATION CHANGE REJECT" },

	/* Handover messages */
	{ GSM48_MT_RR_ASS_CMD,		"ASSIGNMENT COMMAND" },
	{ GSM48_MT_RR_ASS_COMPL,	"ASSIGNMENT COMPLETE" },
	{ GSM48_MT_RR_ASS_FAIL,		"ASSIGNMENT FAILURE" },
	{ GSM48_MT_RR_HANDO_CMD,	"HANDOVER COMMAND" },
	{ GSM48_MT_RR_HANDO_COMPL,	"HANDOVER COMPLETE" },
	{ GSM48_MT_RR_HANDO_FAIL,	"HANDOVER FAILURE" },
	{ GSM48_MT_RR_HANDO_INFO,	"PHYSICAL INFORMATION" },
	{ GSM48_MT_RR_DTM_ASS_CMD,	"DTM ASSIGNMENT COMMAND" },

	{ GSM48_MT_RR_CELL_CHG_ORDER,	"RR-CELL CHANGE ORDER" },
	{ GSM48_MT_RR_PDCH_ASS_CMD,	"PDCH ASSIGNMENT COMMAND" },

	/* Channel release messages */
	{ GSM48_MT_RR_CHAN_REL,		"CHANNEL RELEASE" },
	{ GSM48_MT_RR_PART_REL,		"PARTIAL RELEASE" },
	{ GSM48_MT_RR_PART_REL_COMP,	"PARTIAL RELEASE COMPLETE" },

	/* Paging and Notification messages */
	{ GSM48_MT_RR_PAG_REQ_1,		"PAGING REQUEST TYPE 1" },
	{ GSM48_MT_RR_PAG_REQ_2,		"PAGING REQUEST TYPE 2" },
	{ GSM48_MT_RR_PAG_REQ_3,		"PAGING REQUEST TYPE 3" },
	{ GSM48_MT_RR_PAG_RESP,			"PAGING RESPONSE" },
	{ GSM48_MT_RR_NOTIF_NCH,		"NOTIFICATION/NCH" },
	{ GSM48_MT_RR_NOTIF_FACCH,		"(Reserved)" },
	{ GSM48_MT_RR_NOTIF_RESP,		"NOTIFICATION/RESPONSE" },
	{ GSM48_MT_RR_PACKET_NOTIF,		"PACKET NOTIFICATION" },
	/* 3G Specific messages */
	{ GSM48_MT_RR_UTRAN_CLSM_CHG,		"UTRAN Classmark Change" },
	{ GSM48_MT_RR_CDMA2K_CLSM_CHG,		"cdma 2000 Classmark Change" },
	{ GSM48_MT_RR_IS_TO_UTRAN_HANDO,	"Inter System to UTRAN Handover Command" },
	{ GSM48_MT_RR_IS_TO_CDMA2K_HANDO,	"Inter System to cdma2000 Handover Command" },

	/* System information messages */
	{ GSM48_MT_RR_SYSINFO_8,	"SYSTEM INFORMATION TYPE 8" },
	{ GSM48_MT_RR_SYSINFO_1,	"SYSTEM INFORMATION TYPE 1" },
	{ GSM48_MT_RR_SYSINFO_2,	"SYSTEM INFORMATION TYPE 2" },
	{ GSM48_MT_RR_SYSINFO_3,	"SYSTEM INFORMATION TYPE 3" },
	{ GSM48_MT_RR_SYSINFO_4,	"SYSTEM INFORMATION TYPE 4" },
	{ GSM48_MT_RR_SYSINFO_5,	"SYSTEM INFORMATION TYPE 5" },
	{ GSM48_MT_RR_SYSINFO_6,	"SYSTEM INFORMATION TYPE 6" },
	{ GSM48_MT_RR_SYSINFO_7,	"SYSTEM INFORMATION TYPE 7" },
	{ GSM48_MT_RR_SYSINFO_2bis,	"SYSTEM INFORMATION TYPE 2bis" },
	{ GSM48_MT_RR_SYSINFO_2ter,	"SYSTEM INFORMATION TYPE 2ter" },
	{ GSM48_MT_RR_SYSINFO_2quater,	"SYSTEM INFORMATION TYPE 2quater" },
	{ GSM48_MT_RR_SYSINFO_5bis,	"SYSTEM INFORMATION TYPE 5bis" },
	{ GSM48_MT_RR_SYSINFO_5ter,	"SYSTEM INFORMATION TYPE 5ter" },
	{ GSM48_MT_RR_SYSINFO_9,	"SYSTEM INFORMATION TYPE 9" },
	{ GSM48_MT_RR_SYSINFO_13,	"SYSTEM INFORMATION TYPE 13" },
	{ GSM48_MT_RR_SYSINFO_16,	"SYSTEM INFORMATION TYPE 16" },
	{ GSM48_MT_RR_SYSINFO_17,	"SYSTEM INFORMATION TYPE 17" },
	{ GSM48_MT_RR_SYSINFO_18,	"SYSTEM INFORMATION TYPE 18" },
	{ GSM48_MT_RR_SYSINFO_19,	"SYSTEM INFORMATION TYPE 19" },
	{ GSM48_MT_RR_SYSINFO_20,	"SYSTEM INFORMATION TYPE 20" },

	/* Miscellaneous messages */
	{ GSM48_MT_RR_CHAN_MODE_MODIF,		"CHANNEL MODE MODIFY" },
	{ GSM48_MT_RR_STATUS,			"RR STATUS" },
	{ GSM48_MT_RR_CHAN_MODE_MODIF_ACK,	"CHANNEL MODE MODIFY ACKNOWLEDGE" },
	{ GSM48_MT_RR_FREQ_REDEF,		"FREQUENCY REDEFINITION" },
	{ GSM48_MT_RR_MEAS_REP,			"MEASUREMENT REPORT" },
	{ GSM48_MT_RR_CLSM_CHG,			"CLASSMARK CHANGE" },
	{ GSM48_MT_RR_CLSM_ENQ,			"CLASSMARK ENQUIRY" },
	{ GSM48_MT_RR_EXT_MEAS_REP,		"EXTENDED MEASUREMENT REPORT" },
	{ GSM48_MT_RR_EXT_MEAS_REP_ORD,		"EXTENDED MEASUREMENT ORDER" },
	{ GSM48_MT_RR_GPRS_SUSP_REQ,		"GPRS SUSPENSION REQUEST" },
	{ GSM48_MT_RR_DTM_INFO,			"DTM INFORMATION" },

	/* VGCS uplink control messages */
	{ GSM48_MT_RR_VGCS_UPL_GRANT,	"VGCS UPLINK GRANT" },
	{ GSM48_MT_RR_UPLINK_RELEASE,	"UPLINK RELEASE" },
	{ GSM48_MT_RR_UPLINK_FREE,	"0c" },
	{ GSM48_MT_RR_UPLINK_BUSY,	"UPLINK BUSY" },
	{ GSM48_MT_RR_TALKER_IND,	"TALKER INDICATION" },

	/* Application messages */
	{ GSM48_MT_RR_APP_INFO,		"Application Information" },
	{ 0,				NULL }
};

/*! return string representation of RR Message Type */
const char *gsm48_rr_msg_name(uint8_t msgtype)
{
	return get_value_string(rr_msg_names, msgtype);
}

////////////////////////////////////////////////////////////////////////
// BEGIN T2 ADDITION                                                  //
////////////////////////////////////////////////////////////////////////

/*! return string representation of MM Message Type */
const char *gsm48_mm_msg_name(uint8_t msgtype)
{
	return get_value_string(gsm48_mm_msgtype_names, msgtype);
}

////////////////////////////////////////////////////////////////////////
// END T2 ADDITION                                                    //
////////////////////////////////////////////////////////////////////////
