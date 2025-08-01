/*
 * gsm_osmocore.h
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

#ifndef T2_GSM_OSMOCORE_H_INCLUDED
#define T2_GSM_OSMOCORE_H_INCLUDED

// Global includes

#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

// No configuration flags available

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


#define OSMO_ASSERT assert


/* ========================================================================= */
/* libosmocore/include/osmocom/core/utils.h                                  */
/* ========================================================================= */

/*! Make a value_string entry from an enum value name */
#define OSMO_VALUE_STRING(x) { x, #x }

/*! A mapping between human-readable string and numeric value */
struct value_string {
	uint32_t value;		/*!< numeric value */
	const char *str;	/*!< human-readable string */
};

const char *get_value_string(const struct value_string *vs, uint32_t val);
const char *get_value_string_or_null(const struct value_string *vs,
				     uint32_t val);


/* ======================================================================== */
/* libosmocore/include/osmocom/codec/codec.h                                */
/* ======================================================================== */

extern const struct value_string osmo_amr_type_names[];

enum osmo_amr_type {
       AMR_4_75 = 0,
       AMR_5_15 = 1,
       AMR_5_90 = 2,
       AMR_6_70 = 3,
       AMR_7_40 = 4,
       AMR_7_95 = 5,
       AMR_10_2 = 6,
       AMR_12_2 = 7,
       AMR_SID = 8,
       AMR_GSM_EFR_SID = 9,
       AMR_TDMA_EFR_SID = 10,
       AMR_PDC_EFR_SID = 11,
       AMR_NO_DATA = 15,
};

static inline const char *osmo_amr_type_name(enum osmo_amr_type type)
{ return get_value_string(osmo_amr_type_names, type); }

enum osmo_amr_quality {
       AMR_BAD = 0,
       AMR_GOOD = 1
};

/*! Check if given AMR Frame Type is a speech frame
 *  \param[in] ft AMR Frame Type
 *  \returns true if AMR with given Frame Type contains voice, false otherwise
 */
static inline bool osmo_amr_is_speech(enum osmo_amr_type ft)
{
	switch (ft) {
	case AMR_4_75:
	case AMR_5_15:
	case AMR_5_90:
	case AMR_6_70:
	case AMR_7_40:
	case AMR_7_95:
	case AMR_10_2:
	case AMR_12_2:
		return true;
	default:
		return false;
	}
}


/* ========================================================================= */
/* libosmocore/include/osmocom/gsm/gsm_utils.h                               */
/* ========================================================================= */


enum gsm_band {
	GSM_BAND_850	= 1,
	GSM_BAND_900	= 2,
	GSM_BAND_1800	= 4,
	GSM_BAND_1900	= 8,
	GSM_BAND_450	= 0x10,
	GSM_BAND_480	= 0x20,
	GSM_BAND_750	= 0x40,
	GSM_BAND_810	= 0x80,
};

#define	ARFCN_PCS	0x8000
#define	ARFCN_FLAG_MASK	0xf000	/* Reserve the upper 5 bits for flags */


/* ========================================================================= */
/* libosmocore/include/osmocom/gsm/protocol/gsm_04_08.h                      */
/* ========================================================================= */


/* Section 10.4 */
#define GSM48_MT_RR_INIT_REQ		0x3c
#define GSM48_MT_RR_ADD_ASS		0x3b
#define GSM48_MT_RR_IMM_ASS		0x3f
#define GSM48_MT_RR_IMM_ASS_EXT		0x39
#define GSM48_MT_RR_IMM_ASS_REJ		0x3a
#define GSM48_MT_RR_DTM_ASS_FAIL	0x48
#define GSM48_MT_RR_DTM_REJECT		0x49
#define GSM48_MT_RR_DTM_REQUEST		0x4A
#define GSM48_MT_RR_PACKET_ASS		0x4B

#define GSM48_MT_RR_CIPH_M_CMD		0x35
#define GSM48_MT_RR_CIPH_M_COMPL	0x32

#define GSM48_MT_RR_CFG_CHG_CMD		0x30
#define GSM48_MT_RR_CFG_CHG_ACK		0x31
#define GSM48_MT_RR_CFG_CHG_REJ		0x33

#define GSM48_MT_RR_ASS_CMD		0x2e
#define GSM48_MT_RR_ASS_COMPL		0x29
#define GSM48_MT_RR_ASS_FAIL		0x2f
#define GSM48_MT_RR_HANDO_CMD		0x2b
#define GSM48_MT_RR_HANDO_COMPL		0x2c
#define GSM48_MT_RR_HANDO_FAIL		0x28
#define GSM48_MT_RR_HANDO_INFO		0x2d
#define GSM48_MT_RR_HANDO_INFO		0x2d
#define GSM48_MT_RR_DTM_ASS_CMD		0x4c

#define GSM48_MT_RR_CELL_CHG_ORDER	0x08
#define GSM48_MT_RR_PDCH_ASS_CMD	0x23

#define GSM48_MT_RR_CHAN_REL		0x0d
#define GSM48_MT_RR_PART_REL		0x0a
#define GSM48_MT_RR_PART_REL_COMP	0x0f

#define GSM48_MT_RR_PAG_REQ_1		0x21
#define GSM48_MT_RR_PAG_REQ_2		0x22
#define GSM48_MT_RR_PAG_REQ_3		0x24
#define GSM48_MT_RR_PAG_RESP		0x27
#define GSM48_MT_RR_NOTIF_NCH		0x20
#define GSM48_MT_RR_NOTIF_FACCH		0x25 /* (Reserved) */
#define GSM48_MT_RR_NOTIF_RESP		0x26
#define GSM48_MT_RR_PACKET_NOTIF	0x4e
#define GSM48_MT_RR_UTRAN_CLSM_CHG	0x60
#define GSM48_MT_RR_CDMA2K_CLSM_CHG	0x62
#define GSM48_MT_RR_IS_TO_UTRAN_HANDO	0x63
#define GSM48_MT_RR_IS_TO_CDMA2K_HANDO	0x64

#define GSM48_MT_RR_SYSINFO_8		0x18
#define GSM48_MT_RR_SYSINFO_1		0x19
#define GSM48_MT_RR_SYSINFO_2		0x1a
#define GSM48_MT_RR_SYSINFO_3		0x1b
#define GSM48_MT_RR_SYSINFO_4		0x1c
#define GSM48_MT_RR_SYSINFO_5		0x1d
#define GSM48_MT_RR_SYSINFO_6		0x1e
#define GSM48_MT_RR_SYSINFO_7		0x1f

#define GSM48_MT_RR_SYSINFO_2bis	0x02
#define GSM48_MT_RR_SYSINFO_2ter	0x03
#define GSM48_MT_RR_SYSINFO_2quater	0x07
#define GSM48_MT_RR_SYSINFO_5bis	0x05
#define GSM48_MT_RR_SYSINFO_5ter	0x06
#define GSM48_MT_RR_SYSINFO_9		0x04
#define GSM48_MT_RR_SYSINFO_13		0x00

#define GSM48_MT_RR_SYSINFO_16		0x3d
#define GSM48_MT_RR_SYSINFO_17		0x3e

#define GSM48_MT_RR_SYSINFO_18		0x40
#define GSM48_MT_RR_SYSINFO_19		0x41
#define GSM48_MT_RR_SYSINFO_20		0x42

#define GSM48_MT_RR_CHAN_MODE_MODIF	0x10
#define GSM48_MT_RR_STATUS		0x12
#define GSM48_MT_RR_CHAN_MODE_MODIF_ACK	0x17
#define GSM48_MT_RR_FREQ_REDEF		0x14
#define GSM48_MT_RR_MEAS_REP		0x15
#define GSM48_MT_RR_CLSM_CHG		0x16
#define GSM48_MT_RR_CLSM_ENQ		0x13
#define GSM48_MT_RR_EXT_MEAS_REP	0x36
#define GSM48_MT_RR_EXT_MEAS_REP_ORD	0x37
#define GSM48_MT_RR_GPRS_SUSP_REQ	0x34
#define GSM48_MT_RR_DTM_INFO		0x4d

#define GSM48_MT_RR_VGCS_UPL_GRANT	0x09
#define GSM48_MT_RR_UPLINK_RELEASE	0x0e
#define GSM48_MT_RR_UPLINK_FREE		0x0c
#define GSM48_MT_RR_UPLINK_BUSY		0x2a
#define GSM48_MT_RR_TALKER_IND		0x11

#define GSM48_MT_RR_APP_INFO		0x38

/* Table 10.2/3GPP TS 04.08 */
#define GSM48_MT_MM_IMSI_DETACH_IND	0x01
#define GSM48_MT_MM_LOC_UPD_ACCEPT	0x02
#define GSM48_MT_MM_LOC_UPD_REJECT	0x04
#define GSM48_MT_MM_LOC_UPD_REQUEST	0x08

#define GSM48_MT_MM_AUTH_REJ		0x11
#define GSM48_MT_MM_AUTH_REQ		0x12
#define GSM48_MT_MM_AUTH_RESP		0x14
#define GSM48_MT_MM_AUTH_FAIL		0x1c
#define GSM48_MT_MM_ID_REQ		0x18
#define GSM48_MT_MM_ID_RESP		0x19
#define GSM48_MT_MM_TMSI_REALL_CMD	0x1a
#define GSM48_MT_MM_TMSI_REALL_COMPL	0x1b

#define GSM48_MT_MM_CM_SERV_ACC		0x21
#define GSM48_MT_MM_CM_SERV_REJ		0x22
#define GSM48_MT_MM_CM_SERV_ABORT	0x23
#define GSM48_MT_MM_CM_SERV_REQ		0x24
#define GSM48_MT_MM_CM_SERV_PROMPT	0x25
#define GSM48_MT_MM_CM_REEST_REQ	0x28
#define GSM48_MT_MM_ABORT		0x29

#define GSM48_MT_MM_NULL		0x30
#define GSM48_MT_MM_STATUS		0x31
#define GSM48_MT_MM_INFO		0x32

/* Table 10.3/3GPP TS 04.08 */
#define GSM48_MT_CC_ALERTING		0x01
#define GSM48_MT_CC_CALL_CONF		0x08
#define GSM48_MT_CC_CALL_PROC		0x02
#define GSM48_MT_CC_CONNECT		0x07
#define GSM48_MT_CC_CONNECT_ACK		0x0f
#define GSM48_MT_CC_EMERG_SETUP		0x0e
#define GSM48_MT_CC_PROGRESS		0x03
#define GSM48_MT_CC_ESTAB		0x04
#define GSM48_MT_CC_ESTAB_CONF		0x06
#define GSM48_MT_CC_RECALL		0x0b
#define GSM48_MT_CC_START_CC		0x09
#define GSM48_MT_CC_SETUP		0x05

#define GSM48_MT_CC_MODIFY		0x17
#define GSM48_MT_CC_MODIFY_COMPL	0x1f
#define GSM48_MT_CC_MODIFY_REJECT	0x13
#define GSM48_MT_CC_USER_INFO		0x10
#define GSM48_MT_CC_HOLD		0x18
#define GSM48_MT_CC_HOLD_ACK		0x19
#define GSM48_MT_CC_HOLD_REJ		0x1a
#define GSM48_MT_CC_RETR		0x1c
#define GSM48_MT_CC_RETR_ACK		0x1d
#define GSM48_MT_CC_RETR_REJ		0x1e

#define GSM48_MT_CC_DISCONNECT		0x25
#define GSM48_MT_CC_RELEASE		0x2d
#define GSM48_MT_CC_RELEASE_COMPL	0x2a

#define GSM48_MT_CC_CONG_CTRL		0x39
#define GSM48_MT_CC_NOTIFY		0x3e
#define GSM48_MT_CC_STATUS		0x3d
#define GSM48_MT_CC_STATUS_ENQ		0x34
#define GSM48_MT_CC_START_DTMF		0x35
#define GSM48_MT_CC_STOP_DTMF		0x31
#define GSM48_MT_CC_STOP_DTMF_ACK	0x32
#define GSM48_MT_CC_START_DTMF_ACK	0x36
#define GSM48_MT_CC_START_DTMF_REJ	0x37
#define GSM48_MT_CC_FACILITY		0x3a

/* 3GPP TS 44.018 10.5.2.31 RR Cause / Table 10.5.70 */
enum gsm48_rr_cause {
	GSM48_RR_CAUSE_NORMAL		= 0x00,
	GSM48_RR_CAUSE_ABNORMAL_UNSPEC	= 0x01,
	GSM48_RR_CAUSE_ABNORMAL_UNACCT	= 0x02,
	GSM48_RR_CAUSE_ABNORMAL_TIMER	= 0x03,
	GSM48_RR_CAUSE_ABNORMAL_NOACT	= 0x04,
	GSM48_RR_CAUSE_PREMPTIVE_REL	= 0x05,
	GSM48_RR_CAUSE_UTRAN_CFG_UNK	= 0x06,
	GSM48_RR_CAUSE_HNDOVER_IMP	= 0x08,
	GSM48_RR_CAUSE_CHAN_MODE_UNACCT	= 0x09,
	GSM48_RR_CAUSE_FREQ_NOT_IMPL	= 0x0a,
	GSM48_RR_CAUSE_LEAVE_GROUP_CA	= 0x0b,
	GSM48_RR_CAUSE_LOW_LEVEL_FAIL	= 0x0c,
	GSM48_RR_CAUSE_CALL_CLEARED	= 0x41,
	GSM48_RR_CAUSE_SEMANT_INCORR	= 0x5f,
	GSM48_RR_CAUSE_INVALID_MAND_INF = 0x60,
	GSM48_RR_CAUSE_MSG_TYPE_N	= 0x61,
	GSM48_RR_CAUSE_MSG_TYPE_N_COMPAT= 0x62,
	GSM48_RR_CAUSE_COND_IE_ERROR	= 0x64,
	GSM48_RR_CAUSE_NO_CELL_ALLOC_A	= 0x65,
	GSM48_RR_CAUSE_PROT_ERROR_UNSPC = 0x6f,
};

/* Section 10.5.4.11 CC Cause / Table 10.5.123 */
enum gsm48_cc_cause {
	GSM48_CC_CAUSE_UNASSIGNED_NR	= 1,
	GSM48_CC_CAUSE_NO_ROUTE		= 3,
	GSM48_CC_CAUSE_CHAN_UNACCEPT	= 6,
	GSM48_CC_CAUSE_OP_DET_BARRING	= 8,
	GSM48_CC_CAUSE_NORM_CALL_CLEAR	= 16,
	GSM48_CC_CAUSE_USER_BUSY	= 17,
	GSM48_CC_CAUSE_USER_NOTRESPOND	= 18,
	GSM48_CC_CAUSE_USER_ALERTING_NA	= 19,
	GSM48_CC_CAUSE_CALL_REJECTED	= 21,
	GSM48_CC_CAUSE_NUMBER_CHANGED	= 22,
	GSM48_CC_CAUSE_PRE_EMPTION	= 25,
	GSM48_CC_CAUSE_NONSE_USER_CLR	= 26,
	GSM48_CC_CAUSE_DEST_OOO		= 27,
	GSM48_CC_CAUSE_INV_NR_FORMAT	= 28,
	GSM48_CC_CAUSE_FACILITY_REJ	= 29,
	GSM48_CC_CAUSE_RESP_STATUS_INQ	= 30,
	GSM48_CC_CAUSE_NORMAL_UNSPEC	= 31,
	GSM48_CC_CAUSE_NO_CIRCUIT_CHAN	= 34,
	GSM48_CC_CAUSE_NETWORK_OOO	= 38,
	GSM48_CC_CAUSE_TEMP_FAILURE	= 41,
	GSM48_CC_CAUSE_SWITCH_CONG	= 42,
	GSM48_CC_CAUSE_ACC_INF_DISCARD	= 43,
	GSM48_CC_CAUSE_REQ_CHAN_UNAVAIL	= 44,
	GSM48_CC_CAUSE_RESOURCE_UNAVAIL	= 47,
	GSM48_CC_CAUSE_QOS_UNAVAIL	= 49,
	GSM48_CC_CAUSE_REQ_FAC_NOT_SUBSC= 50,
	GSM48_CC_CAUSE_INC_BARRED_CUG	= 55,
	GSM48_CC_CAUSE_BEARER_CAP_UNAUTH= 57,
	GSM48_CC_CAUSE_BEARER_CA_UNAVAIL= 58,
	GSM48_CC_CAUSE_SERV_OPT_UNAVAIL	= 63,
	GSM48_CC_CAUSE_BEARERSERV_UNIMPL= 65,
	GSM48_CC_CAUSE_ACM_GE_ACM_MAX	= 68,
	GSM48_CC_CAUSE_REQ_FAC_NOTIMPL	= 69,
	GSM48_CC_CAUSE_RESTR_BCAP_AVAIL	= 70,
	GSM48_CC_CAUSE_SERV_OPT_UNIMPL	= 79,
	GSM48_CC_CAUSE_INVAL_TRANS_ID	= 81,
	GSM48_CC_CAUSE_USER_NOT_IN_CUG	= 87,
	GSM48_CC_CAUSE_INCOMPAT_DEST	= 88,
	GSM48_CC_CAUSE_INVAL_TRANS_NET	= 91,
	GSM48_CC_CAUSE_SEMANTIC_INCORR	= 95,
	GSM48_CC_CAUSE_INVAL_MAND_INF	= 96,
	GSM48_CC_CAUSE_MSGTYPE_NOTEXIST	= 97,
	GSM48_CC_CAUSE_MSGTYPE_INCOMPAT	= 98,
	GSM48_CC_CAUSE_IE_NOTEXIST	= 99,
	GSM48_CC_CAUSE_COND_IE_ERR	= 100,
	GSM48_CC_CAUSE_MSG_INCOMP_STATE	= 101,
	GSM48_CC_CAUSE_RECOVERY_TIMER	= 102,
	GSM48_CC_CAUSE_PROTO_ERR	= 111,
	GSM48_CC_CAUSE_INTERWORKING	= 127,
};

extern const struct value_string gsm48_cc_cause_names[];
static inline const char *gsm48_cc_cause_name(enum gsm48_cc_cause val)
{ return get_value_string(gsm48_cc_cause_names, val); }


/* ========================================================================= */
/* libosmocore/include/osmocom/gsm/protocol/gsm_08_58.h                      */
/* ========================================================================= */


/* RSL Message Type (Chapter 9.1) */
enum abis_rsl_msgtype {
	/* Radio Link Layer Management */
	RSL_MT_DATA_REQ			= 0x01,
	RSL_MT_DATA_IND,
	RSL_MT_ERROR_IND,
	RSL_MT_EST_REQ,
	RSL_MT_EST_CONF,
	RSL_MT_EST_IND,
	RSL_MT_REL_REQ,
	RSL_MT_REL_CONF,
	RSL_MT_REL_IND,
	RSL_MT_UNIT_DATA_REQ,
	RSL_MT_UNIT_DATA_IND,		/* 0x0b */
	RSL_MT_SUSP_REQ,		/* non-standard elements */
	RSL_MT_SUSP_CONF,
	RSL_MT_RES_REQ,
	RSL_MT_RECON_REQ,		/* 0x0f */

	/* Common Channel Management / TRX Management */
	RSL_MT_BCCH_INFO			= 0x11,
	RSL_MT_CCCH_LOAD_IND,
	RSL_MT_CHAN_RQD,
	RSL_MT_DELETE_IND,
	RSL_MT_PAGING_CMD,
	RSL_MT_IMMEDIATE_ASSIGN_CMD,
	RSL_MT_SMS_BC_REQ,
	RSL_MT_CHAN_CONF,		/* non-standard element */
	/* empty */
	RSL_MT_RF_RES_IND			= 0x19,
	RSL_MT_SACCH_FILL,
	RSL_MT_OVERLOAD,
	RSL_MT_ERROR_REPORT,
	RSL_MT_SMS_BC_CMD,
	RSL_MT_CBCH_LOAD_IND,
	RSL_MT_NOT_CMD,			/* 0x1f */

	/* Dedicate Channel Management */
	RSL_MT_CHAN_ACTIV			= 0x21,
	RSL_MT_CHAN_ACTIV_ACK,
	RSL_MT_CHAN_ACTIV_NACK,
	RSL_MT_CONN_FAIL,
	RSL_MT_DEACTIVATE_SACCH,
	RSL_MT_ENCR_CMD,
	RSL_MT_HANDO_DET,
	RSL_MT_MEAS_RES,
	RSL_MT_MODE_MODIFY_REQ,
	RSL_MT_MODE_MODIFY_ACK,
	RSL_MT_MODE_MODIFY_NACK,
	RSL_MT_PHY_CONTEXT_REQ,
	RSL_MT_PHY_CONTEXT_CONF,
	RSL_MT_RF_CHAN_REL,
	RSL_MT_MS_POWER_CONTROL,
	RSL_MT_BS_POWER_CONTROL,		/* 0x30 */
	RSL_MT_PREPROC_CONFIG,
	RSL_MT_PREPROC_MEAS_RES,
	RSL_MT_RF_CHAN_REL_ACK,
	RSL_MT_SACCH_INFO_MODIFY,
	RSL_MT_TALKER_DET,
	RSL_MT_LISTENER_DET,
	RSL_MT_REMOTE_CODEC_CONF_REP,
	RSL_MT_RTD_REP,
	RSL_MT_PRE_HANDO_NOTIF,
	RSL_MT_MR_CODEC_MOD_REQ,
	RSL_MT_MR_CODEC_MOD_ACK,
	RSL_MT_MR_CODEC_MOD_NACK,
	RSL_MT_MR_CODEC_MOD_PER,
	RSL_MT_TFO_REP,
	RSL_MT_TFO_MOD_REQ,		/* 0x3f */
	RSL_MT_LOCATION_INFO		= 0x41,

	/* ip.access specific RSL message types */
	RSL_MT_IPAC_DIR_RETR_ENQ	= 0x40,
	RSL_MT_IPAC_PDCH_ACT		= 0x48,
	RSL_MT_IPAC_PDCH_ACT_ACK,
	RSL_MT_IPAC_PDCH_ACT_NACK,
	RSL_MT_IPAC_PDCH_DEACT		= 0x4b,
	RSL_MT_IPAC_PDCH_DEACT_ACK,
	RSL_MT_IPAC_PDCH_DEACT_NACK,
	RSL_MT_IPAC_CONNECT_MUX		= 0x50,
	RSL_MT_IPAC_CONNECT_MUX_ACK,
	RSL_MT_IPAC_CONNECT_MUX_NACK,
	RSL_MT_IPAC_BIND_MUX		= 0x53,
	RSL_MT_IPAC_BIND_MUX_ACK,
	RSL_MT_IPAC_BIND_MUX_NACK,
	RSL_MT_IPAC_DISC_MUX		= 0x56,
	RSL_MT_IPAC_DISC_MUX_ACK,
	RSL_MT_IPAC_DISC_MUX_NACK,
	RSL_MT_IPAC_MEAS_PREPROC_DFT 	= 0x60,		/*Extented Common Channel Management */
	RSL_MT_IPAC_HO_CAN_ENQ 		= 0x61,
	RSL_MT_IPAC_HO_CAN_RES 		= 0x62,
	RSL_MT_IPAC_CRCX		= 0x70,		/* Bind to local BTS RTP port */
	RSL_MT_IPAC_CRCX_ACK,
	RSL_MT_IPAC_CRCX_NACK,
	RSL_MT_IPAC_MDCX		= 0x73,
	RSL_MT_IPAC_MDCX_ACK,
	RSL_MT_IPAC_MDCX_NACK,
	RSL_MT_IPAC_DLCX_IND		= 0x76,
	RSL_MT_IPAC_DLCX		= 0x77,
	RSL_MT_IPAC_DLCX_ACK,
	RSL_MT_IPAC_DLCX_NACK,

	RSL_MT_OSMO_ETWS_CMD		= 0x7f,
};

/* normal event */
#define RSL_ERR_RADIO_IF_FAIL		0x00
#define RSL_ERR_RADIO_LINK_FAIL		0x01
#define RSL_ERR_HANDOVER_ACC_FAIL	0x02
#define RSL_ERR_TALKER_ACC_FAIL		0x03
#define RSL_ERR_OM_INTERVENTION		0x07
#define RSL_ERR_NORMAL_UNSPEC		0x0f
#define RSL_ERR_T_MSRFPCI_EXP		0x18
/* resource unavailable */
#define RSL_ERR_EQUIPMENT_FAIL		0x20
#define RSL_ERR_RR_UNAVAIL		0x21
#define RSL_ERR_TERR_CH_FAIL		0x22
#define RSL_ERR_CCCH_OVERLOAD		0x23
#define RSL_ERR_ACCH_OVERLOAD		0x24
#define RSL_ERR_PROCESSOR_OVERLOAD	0x25
#define RSL_ERR_BTS_NOT_EQUIPPED	0x27
#define RSL_ERR_REMOTE_TRANSC_FAIL	0x28
#define RSL_ERR_NOTIFICATION_OVERFL	0x29
#define RSL_ERR_RES_UNAVAIL		0x2f
/* service or option not available */
#define RSL_ERR_TRANSC_UNAVAIL		0x30
#define RSL_ERR_SERV_OPT_UNAVAIL	0x3f
/* service or option not implemented */
#define RSL_ERR_ENCR_UNIMPL		0x40
#define RSL_ERR_SERV_OPT_UNIMPL		0x4f
/* invalid message */
#define RSL_ERR_RCH_ALR_ACTV_ALLOC	0x50
#define RSL_ERR_INVALID_MESSAGE		0x5f
/* protocol error */
#define RSL_ERR_MSG_DISCR		0x60
#define RSL_ERR_MSG_TYPE		0x61
#define RSL_ERR_MSG_SEQ			0x62
#define RSL_ERR_IE_ERROR		0x63
#define RSL_ERR_MAND_IE_ERROR		0x64
#define RSL_ERR_OPT_IE_ERROR		0x65
#define RSL_ERR_IE_NONEXIST		0x66
#define RSL_ERR_IE_LENGTH		0x67
#define RSL_ERR_IE_CONTENT		0x68
#define RSL_ERR_PROTO			0x6f
/* interworking */
#define RSL_ERR_INTERWORKING		0x7f


/* ======================================================================== */
/* libosmocore/src/codec/gsm690.c                                           */
/* ======================================================================== */

extern const uint8_t amr_len_by_ft[16];


/* ========================================================================= */
/* libosmocore/src/gsm/gsm_utils.c                                           */
/* ========================================================================= */


extern unsigned char gsm_7bit_alphabet[];

int gsm_septet_lookup(uint8_t ch);
uint8_t gsm_get_octet_len(const uint8_t sept_len);
int gsm_7bit_decode_n_hdr(char *text, size_t n, const uint8_t *user_data, uint8_t septet_l, uint8_t ud_hdr_ind);
const char *gsm_band_name(enum gsm_band band);
int gsm_arfcn2band_rc(uint16_t arfcn, enum gsm_band *band);
uint16_t gsm_arfcn2freq10(uint16_t arfcn, int uplink);


/* ========================================================================= */
/* libosmocore/src/gsm/rsl.c                                                 */
/* ========================================================================= */


const char *rsl_err_name(uint8_t err);
const char *rsl_msg_name(uint8_t msg_type);


/* ========================================================================= */
/* libosmocore/src/gsm/gsm48.c                                               */
/* ========================================================================= */


const char *rr_cause_name(uint8_t cause);
const char *gsm48_cc_msg_name(uint8_t msgtype);
const char *gsm48_rr_msg_name(uint8_t msgtype);
////////////////////////////////////////////////////////////////////////
// BEGIN T2 ADDITION                                                  //
////////////////////////////////////////////////////////////////////////
const char *gsm48_mm_msg_name(uint8_t msgtype);
////////////////////////////////////////////////////////////////////////
// END T2 ADDITION                                                    //
////////////////////////////////////////////////////////////////////////


#endif // T2_GSM_OSMOCORE_H_INCLUDED
