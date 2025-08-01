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

#include "sctpDecode.h"


// Global variables

sctpFlow_t *sctpFlow;


// Static variables

static uint16_t sctpTypeBF;
static uint8_t  sctpCFlags;
static uint8_t  sctpStat;

#if SCTP_CHNKVAL == 2
static const char *sctpChunkTypeStr[] = {
    /*   0 */ "DATA",              // Payload data
    /*   1 */ "INIT",              // Initiation
    /*   2 */ "INIT-ACK",          // Initiation acknowledgement
    /*   3 */ "SACK",              // Selective acknowledgement
    /*   4 */ "HEARTBEAT",         // Heartbeat request
    /*   5 */ "HEARTBEAT-ACK",     // Heartbeat acknowledgement
    /*   6 */ "ABORT",             // Abort
    /*   7 */ "SHUTDOWN",          // Shutdown
    /*   8 */ "SHUTDOWN-ACK",      // Shutdown acknowledgement
    /*   9 */ "ERROR",             // Operation error
    /*  10 */ "COOKIE-ECHO",       // State cookie
    /*  11 */ "COOKIE-ACK",        // Cookie acknowledgement
    /*  12 */ "ECNE",              // Explicit congestion notification echo (reserved)
    /*  13 */ "CWR",               // Congestion window reduced (reserved)
    /*  14 */ "SHTDWN-CMPLT",      // Shutdown complete
    /*  15 */ "AUTH",              // Authentication chunk
    /*  16 */ "N/A",               // Reserved by IETF
    /*  17 */ "N/A",               // Reserved by IETF
    /*  18 */ "N/A",               // Reserved by IETF
    /*  19 */ "N/A",               // Reserved by IETF
    /*  20 */ "N/A",               // Reserved by IETF
    /*  21 */ "N/A",               // Reserved by IETF
    /*  22 */ "N/A",               // Reserved by IETF
    /*  23 */ "N/A",               // Reserved by IETF
    /*  24 */ "N/A",               // Reserved by IETF
    /*  25 */ "N/A",               // Reserved by IETF
    /*  26 */ "N/A",               // Reserved by IETF
    /*  27 */ "N/A",               // Reserved by IETF
    /*  28 */ "N/A",               // Reserved by IETF
    /*  29 */ "N/A",               // Reserved by IETF
    /*  30 */ "N/A",               // Reserved by IETF
    /*  31 */ "N/A",               // Reserved by IETF
    /*  32 */ "N/A",               // Reserved by IETF
    /*  33 */ "N/A",               // Reserved by IETF
    /*  34 */ "N/A",               // Reserved by IETF
    /*  35 */ "N/A",               // Reserved by IETF
    /*  36 */ "N/A",               // Reserved by IETF
    /*  37 */ "N/A",               // Reserved by IETF
    /*  38 */ "N/A",               // Reserved by IETF
    /*  39 */ "N/A",               // Reserved by IETF
    /*  40 */ "N/A",               // Reserved by IETF
    /*  41 */ "N/A",               // Reserved by IETF
    /*  42 */ "N/A",               // Reserved by IETF
    /*  43 */ "N/A",               // Reserved by IETF
    /*  44 */ "N/A",               // Reserved by IETF
    /*  45 */ "N/A",               // Reserved by IETF
    /*  46 */ "N/A",               // Reserved by IETF
    /*  47 */ "N/A",               // Reserved by IETF
    /*  48 */ "N/A",               // Reserved by IETF
    /*  49 */ "N/A",               // Reserved by IETF
    /*  50 */ "N/A",               // Reserved by IETF
    /*  51 */ "N/A",               // Reserved by IETF
    /*  52 */ "N/A",               // Reserved by IETF
    /*  53 */ "N/A",               // Reserved by IETF
    /*  54 */ "N/A",               // Reserved by IETF
    /*  55 */ "N/A",               // Reserved by IETF
    /*  56 */ "N/A",               // Reserved by IETF
    /*  57 */ "N/A",               // Reserved by IETF
    /*  58 */ "N/A",               // Reserved by IETF
    /*  59 */ "N/A",               // Reserved by IETF
    /*  60 */ "N/A",               // Reserved by IETF
    /*  61 */ "N/A",               // Reserved by IETF
    /*  62 */ "N/A",               // Reserved by IETF
    /*  63 */ "N/A",               // Reserved by IETF
    /*  64 */ "I-DATA",            // Payload data supporting packet interleaving
    /*  65 */ "N/A",               // Reserved by IETF
    /*  66 */ "N/A",               // Reserved by IETF
    /*  67 */ "N/A",               // Reserved by IETF
    /*  68 */ "N/A",               // Reserved by IETF
    /*  69 */ "N/A",               // Reserved by IETF
    /*  70 */ "N/A",               // Reserved by IETF
    /*  71 */ "N/A",               // Reserved by IETF
    /*  72 */ "N/A",               // Reserved by IETF
    /*  73 */ "N/A",               // Reserved by IETF
    /*  74 */ "N/A",               // Reserved by IETF
    /*  75 */ "N/A",               // Reserved by IETF
    /*  76 */ "N/A",               // Reserved by IETF
    /*  77 */ "N/A",               // Reserved by IETF
    /*  78 */ "N/A",               // Reserved by IETF
    /*  79 */ "N/A",               // Reserved by IETF
    /*  80 */ "N/A",               // Reserved by IETF
    /*  81 */ "N/A",               // Reserved by IETF
    /*  82 */ "N/A",               // Reserved by IETF
    /*  83 */ "N/A",               // Reserved by IETF
    /*  84 */ "N/A",               // Reserved by IETF
    /*  85 */ "N/A",               // Reserved by IETF
    /*  86 */ "N/A",               // Reserved by IETF
    /*  87 */ "N/A",               // Reserved by IETF
    /*  88 */ "N/A",               // Reserved by IETF
    /*  89 */ "N/A",               // Reserved by IETF
    /*  90 */ "N/A",               // Reserved by IETF
    /*  91 */ "N/A",               // Reserved by IETF
    /*  92 */ "N/A",               // Reserved by IETF
    /*  93 */ "N/A",               // Reserved by IETF
    /*  94 */ "N/A",               // Reserved by IETF
    /*  95 */ "N/A",               // Reserved by IETF
    /*  96 */ "N/A",               // Reserved by IETF
    /*  97 */ "N/A",               // Reserved by IETF
    /*  98 */ "N/A",               // Reserved by IETF
    /*  99 */ "N/A",               // Reserved by IETF
    /* 100 */ "N/A",               // Reserved by IETF
    /* 101 */ "N/A",               // Reserved by IETF
    /* 102 */ "N/A",               // Reserved by IETF
    /* 103 */ "N/A",               // Reserved by IETF
    /* 104 */ "N/A",               // Reserved by IETF
    /* 105 */ "N/A",               // Reserved by IETF
    /* 106 */ "N/A",               // Reserved by IETF
    /* 107 */ "N/A",               // Reserved by IETF
    /* 108 */ "N/A",               // Reserved by IETF
    /* 109 */ "N/A",               // Reserved by IETF
    /* 110 */ "N/A",               // Reserved by IETF
    /* 111 */ "N/A",               // Reserved by IETF
    /* 112 */ "N/A",               // Reserved by IETF
    /* 113 */ "N/A",               // Reserved by IETF
    /* 114 */ "N/A",               // Reserved by IETF
    /* 115 */ "N/A",               // Reserved by IETF
    /* 116 */ "N/A",               // Reserved by IETF
    /* 117 */ "N/A",               // Reserved by IETF
    /* 118 */ "N/A",               // Reserved by IETF
    /* 119 */ "N/A",               // Reserved by IETF
    /* 120 */ "N/A",               // Reserved by IETF
    /* 121 */ "N/A",               // Reserved by IETF
    /* 122 */ "N/A",               // Reserved by IETF
    /* 123 */ "N/A",               // Reserved by IETF
    /* 124 */ "N/A",               // Reserved by IETF
    /* 125 */ "N/A",               // Reserved by IETF
    /* 126 */ "N/A",               // Reserved by IETF
    /* 127 */ "N/A",               // Reserved by IETF
    /* 128 */ "ASCONF-ACK",         // Address configuration change acknowledgement
    /* 129 */ "N/A",               // Reserved by IETF
    /* 130 */ "RE-CONFIG",         // Stream reconfiguration
    /* 131 */ "N/A",               // Reserved by IETF
    /* 132 */ "PAD",               // Packet padding
    /* 133 */ "N/A",               // Reserved by IETF
    /* 134 */ "N/A",               // Reserved by IETF
    /* 135 */ "N/A",               // Reserved by IETF
    /* 136 */ "N/A",               // Reserved by IETF
    /* 137 */ "N/A",               // Reserved by IETF
    /* 138 */ "N/A",               // Reserved by IETF
    /* 139 */ "N/A",               // Reserved by IETF
    /* 140 */ "N/A",               // Reserved by IETF
    /* 141 */ "N/A",               // Reserved by IETF
    /* 142 */ "N/A",               // Reserved by IETF
    /* 143 */ "N/A",               // Reserved by IETF
    /* 144 */ "N/A",               // Reserved by IETF
    /* 145 */ "N/A",               // Reserved by IETF
    /* 146 */ "N/A",               // Reserved by IETF
    /* 147 */ "N/A",               // Reserved by IETF
    /* 148 */ "N/A",               // Reserved by IETF
    /* 149 */ "N/A",               // Reserved by IETF
    /* 150 */ "N/A",               // Reserved by IETF
    /* 151 */ "N/A",               // Reserved by IETF
    /* 152 */ "N/A",               // Reserved by IETF
    /* 153 */ "N/A",               // Reserved by IETF
    /* 154 */ "N/A",               // Reserved by IETF
    /* 155 */ "N/A",               // Reserved by IETF
    /* 156 */ "N/A",               // Reserved by IETF
    /* 157 */ "N/A",               // Reserved by IETF
    /* 158 */ "N/A",               // Reserved by IETF
    /* 159 */ "N/A",               // Reserved by IETF
    /* 160 */ "N/A",               // Reserved by IETF
    /* 161 */ "N/A",               // Reserved by IETF
    /* 162 */ "N/A",               // Reserved by IETF
    /* 163 */ "N/A",               // Reserved by IETF
    /* 164 */ "N/A",               // Reserved by IETF
    /* 165 */ "N/A",               // Reserved by IETF
    /* 166 */ "N/A",               // Reserved by IETF
    /* 167 */ "N/A",               // Reserved by IETF
    /* 168 */ "N/A",               // Reserved by IETF
    /* 169 */ "N/A",               // Reserved by IETF
    /* 170 */ "N/A",               // Reserved by IETF
    /* 171 */ "N/A",               // Reserved by IETF
    /* 172 */ "N/A",               // Reserved by IETF
    /* 173 */ "N/A",               // Reserved by IETF
    /* 174 */ "N/A",               // Reserved by IETF
    /* 175 */ "N/A",               // Reserved by IETF
    /* 176 */ "N/A",               // Reserved by IETF
    /* 177 */ "N/A",               // Reserved by IETF
    /* 178 */ "N/A",               // Reserved by IETF
    /* 179 */ "N/A",               // Reserved by IETF
    /* 180 */ "N/A",               // Reserved by IETF
    /* 181 */ "N/A",               // Reserved by IETF
    /* 182 */ "N/A",               // Reserved by IETF
    /* 183 */ "N/A",               // Reserved by IETF
    /* 184 */ "N/A",               // Reserved by IETF
    /* 185 */ "N/A",               // Reserved by IETF
    /* 186 */ "N/A",               // Reserved by IETF
    /* 187 */ "N/A",               // Reserved by IETF
    /* 188 */ "N/A",               // Reserved by IETF
    /* 189 */ "N/A",               // Reserved by IETF
    /* 190 */ "N/A",               // Reserved by IETF
    /* 191 */ "N/A",               // ETF-defined chunk extensions
    /* 192 */ "FORWARD-TSN",       // Increment expected TSN
    /* 193 */ "ASCONF",            // Address configuration change
    /* 194 */ "I-FORWARD-TSN",     // Increment expected TSN, supporting packet interleaving
};
#endif // SCTP_CHNKVAL == 2


#define SCTP_SPKTMD_PRI_NONE() \
    if (sPktFile) { \
        if (SCTP_CRCADL32CHK > 0) { \
            fputs(/* sctpCalCRCChkSum/sctpCalADLChkSum */ SEP_CHR, sPktFile); \
        } \
        fputs(       /* sctpVTag                                        */ SEP_CHR \
                     /* sctpChkSum                                      */ SEP_CHR \
                     /* sctpCalCRCChkSum/sctpCalADLChkSum -> see above  */         \
                     /* sctpChunkType_sid_flags_cflags_numDPkts_len_pid */ SEP_CHR \
              "0"    /* sctpNChunks                                     */ SEP_CHR \
                     /* sctpCCBF                                        */ SEP_CHR \
                     /* sctpARW                                         */ SEP_CHR \
                     /* sctpPID                                         */ SEP_CHR \
              "0x00" /* sctpStat                                        */ SEP_CHR \
                     /* sctpTSN/sctpRelTSN                              */ SEP_CHR \
                     /* sctpTSNAck/sctpRelTSNAck                        */ SEP_CHR \
                     /* sctpASIP4                                       */ SEP_CHR \
                     /* sctpASIP6                                       */ SEP_CHR \
              , sPktFile); \
    }


// Tranalyzer functions

T2_PLUGIN_INIT("sctpDecode", "0.9.3", 0, 9);


void t2Init() {
    T2_PLUGIN_STRUCT_NEW(sctpFlow);

#if SCTP_CRCADL32CHK == 1
    //crc32_init();
#endif // SCTP_CRCADL32CHK == 1

    if (sPktFile) {
        fputs("sctpVTag"                                        SEP_CHR
              "sctpChkSum"                                      SEP_CHR
#if SCTP_CRCADL32CHK == 1
              "sctpCalCRCChkSum"                                SEP_CHR
#elif SCTP_CRCADL32CHK == 2
              "sctpCalADLChkSum"                                SEP_CHR
#endif // SCTP_CRCADL32CHK
              "sctpChunkType_sid_flags_cflags_numDPkts_len_pid" SEP_CHR
              "sctpNChunks"                                     SEP_CHR
              "sctpCCBF"                                        SEP_CHR
              "sctpARW"                                         SEP_CHR
              "sctpPID"                                         SEP_CHR
              "sctpStat"                                        SEP_CHR
#if SCTP_TSNREL == 1
              "sctpRelTSN"                                      SEP_CHR
              "sctpRelTSNAck"                                   SEP_CHR
#else // SCTP_TSNREL == 0
              "sctpTSN"                                         SEP_CHR
              "sctpTSNAck"                                      SEP_CHR
#endif // SCTP_TSNREL == 1
              "sctpASIP4"                                       SEP_CHR
              "sctpASIP6"                                       SEP_CHR
              , sPktFile);
    }
}


binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;

    BV_APPEND_H8(bv, "sctpStat", "SCTP status");

#if SCTP_ACTIVATE > 0
    BV_APPEND_U16(bv, "sctpDSNum", "SCTP data stream number");
#else // SCTP_ACTIVATE == 0
    BV_APPEND_U16(bv, "sctpMaxDSNum", "SCTP max number of data streams");
#endif // SCTP_ACTIVATE

    BV_APPEND_U32(bv, "sctpPID" , "SCTP Payload ID");
    BV_APPEND_H32(bv, "sctpVTag", "SCTP verification tag");

#if SCTP_CHNKVAL == 2
    BV_APPEND_STRC_R(bv, "sctpTypeN" , "SCTP unique types name");
#elif SCTP_CHNKVAL == 1
    BV_APPEND_U8_R(bv  , "sctpType"  , "SCTP unique types values");
#else // SCTP_CHNKVAL == 0
    BV_APPEND_H16(bv   , "sctpTypeBF", "SCTP aggregated type bit field");
#endif // SCTP_CHNKVAL == 0

    BV_APPEND(       bv, "sctpCntD_I_A", "SCTP DATA, INIT and ABORT count", 3, bt_uint_16, bt_uint_16, bt_uint_16);
    BV_APPEND_H8(    bv, "sctpCFlags"  , "SCTP aggregated chunk flags");
    BV_APPEND_H16(   bv, "sctpCCBF"    , "SCTP aggregated error cause code bit field");
    BV_APPEND_STRC_R(bv, "sctpASIP4"   , "SCTP ASCONF IPv4");
    BV_APPEND_STRC_R(bv, "sctpASIP6"   , "SCTP ASCONF IPv6");
    BV_APPEND_U16(   bv, "sctpIS"      , "SCTP inbound streams");
    BV_APPEND_U16(   bv, "sctpOS"      , "SCTP outbound streams");
    BV_APPEND_U32(   bv, "sctpIARW"    , "SCTP Initial Advertised Receiver Window");
    BV_APPEND_U32(   bv, "sctpIARWMin" , "SCTP Initial Advertised Receiver Window Minimum");
    BV_APPEND_U32(   bv, "sctpIARWMax" , "SCTP Initial Advertised Receiver Window Maximum");
    BV_APPEND_FLT(   bv, "sctpARW"     , "SCTP Advertised Receiver Window");

    return bv;
}


void t2OnNewFlow(packet_t* packet UNUSED, unsigned long flowIndex) {
    sctpFlow_t *sctpFlowP = &sctpFlow[flowIndex];
    memset(sctpFlowP, '\0', sizeof(sctpFlow_t));
    sctpFlowP->ct3_arwcMin = UINT32_MAX;
}


#if ETH_ACTIVATE > 0
void t2OnLayer2(packet_t *packet UNUSED, unsigned long flowIndex) {
    if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;
    SCTP_SPKTMD_PRI_NONE();
}
#endif // ETH_ACTIVATE > 0


void t2OnLayer4(packet_t* packet, unsigned long flowIndex) {
    if (packet->l4Proto != L3_SCTP) {
        SCTP_SPKTMD_PRI_NONE();
        return;
    }

    // only 1. frag packet will be processed 4 now
    if (!t2_is_first_fragment(packet)) {
        SCTP_SPKTMD_PRI_NONE();
        return;
    }

    uint_fast16_t l3Len;
    if (PACKET_IS_IPV6(packet)) {
        //const ip6Header_t * const ip6HdrP = IPV6_HEADER(packet);
        //l3Len = ntohs(ip6HdrP->payload_len) + 40; // FIXME TSO case
        l3Len = packet->l3Len;
    } else {
        //const ipHeader_t * const ipHdrP = IPV4_HEADER(packet);
        //l3Len = ntohs(ipHdrP->ip_len); // FIXME TSO case
        l3Len = packet->l3Len;
    }

    sctpFlow_t * const sctpFlowP = &sctpFlow[flowIndex];
    flow_t *flowP = &flows[flowIndex];
    sctpFlow_t *sctpFlowPO;
    if (FLOW_HAS_OPPOSITE(flowP)) {
        sctpFlowPO = &sctpFlow[flowP->oppositeFlowIndex];
    } else {
        sctpFlowPO = NULL;
    }

    const sctpHeader_t * const sctpHdrP = SCTP_HEADER(packet);
    sctpChunk_t *sctpChunkP = NULL;
    uint32_t j = 0;
    uint32_t sctpWin = 0;
    uint8_t sctpStat = 0, nChnks = 0;
    uint32_t tsn = 0, tsnAck = 0;
    uint32_t sacnt = 0, sa6cnt = 0;

#if SCTP_ACTIVATE > 0
    uint8_t *sctpL7P = (uint8_t*)packet->l7SctpHdrP;
    int32_t sctpL7Len = packet->snapSctpL7Len;
    if (sctpL7Len > packet->snapL7Len) {
        sctpL7Len = packet->snapL7Len;
        sctpStat = sctpFlowP->stat |= SCTP_C_TRNC;
    }
#else // SCTP_ACTIVATE == 0
    uint8_t *sctpL7P = (uint8_t*)packet->l7HdrP;
    int32_t sctpL7Len = packet->snapL7Len;
#endif // SCTP_ACTIVATE

    sctpFlowP->verTag = ntohl(sctpHdrP->verTag);

    if (sctpL7Len < 4) {
        SCTP_SPKTMD_PRI_NONE();
        return;
    }

    if (packet->snapL3Len < l3Len) {
        sctpStat |= (SCTP_C_CRCERR | SCTP_C_ADLERR);
    } else {
#if SCTP_CRCADL32CHK == 1
        j = sctp_crc32c((uint8_t*)packet->l4HdrP, packet->snapL4Len);
        if (sctpHdrP->chkSum != j) sctpStat |= SCTP_C_CRCERR;
#elif SCTP_CRCADL32CHK == 2
        j = sctp_adler32((uint8_t*)packet->l4HdrP, packet->snapL4Len);
        if (sctpHdrP->chkSum != j) sctpiStat |= SCTP_C_ADLERR;
#endif // SCTP_CRCADL32CHK
    }

    // sctpVTag, sctpChkSum, sctpCalCRCChkSum/sctpCalADLChkSum
    if (sPktFile) {
        fprintf(sPktFile,
                "0x%08" B2T_PRIX32 /* sctpVTag                          */ SEP_CHR
                "0x%08" B2T_PRIX32 /* sctpChkSum                        */ SEP_CHR
#if SCTP_CRCADL32CHK > 0
                "0x%08" B2T_PRIX32 /* sctpCalCRCChkSum/sctpCalADLChkSum */ SEP_CHR
#endif // SCTP_CRCADL32CHK
                , sctpFlowP->verTag, ntohl(sctpHdrP->chkSum)
#if SCTP_CRCADL32CHK > 0
                , ntohl(j)
#endif // SCTP_CRCADL32CHK
        );
    }

    int32_t sctpChnkLen, sctpChnkPLen;
    uint32_t ppi = 0, retCnt = 0;
    uint16_t sid;
    uint8_t chnkType;
    uint32_t ipAddr[SCTP_MXADDR];
    ipAddr_t ip6Addr[SCTP_MXADDR];
    sctpWin = 0;
    while (sctpL7Len > 3) {
        nChnks++;
        sctpChunkP = (sctpChunk_t*)sctpL7P;
        sctpChnkPLen = ntohs(sctpChunkP->len);
        sctpChnkLen = sctpChnkPLen;
        if (sctpChnkLen == 0) break;
        if (sctpL7Len < sctpChnkPLen) {
            sctpChnkPLen = sctpL7Len;
            sctpStat |= SCTP_C_TRNC;
        }
        chnkType = sctpChunkP->type;
#if SCTP_CHNKVAL == 0
        sctpFlowP->typeBF |= (1 << (chnkType & SCTP_C_TYPE));
#else // SCTP_CHNKVAL > 0
        if (sctpFlowP->numTypeS < SCTP_MAXCTYPE) {
//#if SCTP_CHNKAGGR == 1
            for (j = 0; j < sctpFlowP->numTypeS; j++) {
                if (sctpFlowP->cTypeS[j] == chnkType) goto chktfnd;
            }
//#endif // SCTP_CHNKAGGR == 1
            sctpFlowP->cTypeS[sctpFlowP->numTypeS++] = chnkType;
        } else sctpStat |= SCTP_C_TPVFL;
chktfnd:
#endif // SCTP_CHNKVAL > 0
        sctpStat |= chnkType & SCTP_C_TACT;
        sctpFlowP->cflags |= sctpChunkP->flags;
        sid = 0;
        tsn = 0;
        tsnAck = 0;
        int iax = 1; // whatever value bigger than 0 to enter the while loop where it will be overwritten
        int32_t sctpIALen;
        char *iaP;
        //if (!sctpFlowP->ct0_dataCnt) sctpFlowP->tsnInit = tsn;
        switch (chnkType) {
            case SCTP_CT_DATA: {
                tsn = ntohl(sctpChunkP->tsn_it_cta);
                if (!sctpFlowP->ct0_dataCnt) sctpFlowP->tsnInit = tsn;
                else if (tsn - sctpFlowP->tsnLst != 1) sctpFlowP->cflags |= SCTP_TSN_ERR;
                sctpFlowP->ct0_dataCnt++;
                ppi = ntohl(sctpChunkP->ppi);
                sctpFlowP->ct0_ppi = ppi;
                sid = ntohs(sctpChunkP->sis);
                if (sid > sctpFlowP->ct0_sid) sctpFlowP->ct0_sid = sid;
                const int32_t pad = 4 - sctpChnkLen % 4;
                if (pad < 4) {
                    sctpChnkPLen += pad;
                    sctpStat |= SCTP_C_PAD;
                }
                tsnAck = sctpFlowP->tsnAckLst;
                //sctpFlowP->tsnLst = tsn;
                break;
            }

            case SCTP_CT_INIT:
                sctpFlowP->ct1_initCnt++;
                /* FALLTHRU */
            case SCTP_CT_INIT_ACK:
                tsn = ntohl(sctpChunkP->itsn);
                if (sctpFlowPO) {
                    sctpFlowP->tsnAckInit = sctpFlowPO->tsnInit;
                    sctpFlowPO->tsnAckInit = tsn;
                }
                sctpFlowP->tsnInit = tsn;
                ppi = ntohl(sctpChunkP->ppi);
                sctpFlowP->ct1_2_nos_nis = ppi;
                sctpWin = ntohl(sctpChunkP->arwc);
                sctpFlowP->ct1_2_3_arwc = sctpWin;
                sctpFlowP->ct1_2_3_arwcI = sctpFlowP->ct1_2_3_arwc;
                sctpFlowP->ct3_arwcMin = MIN(sctpFlowP->ct3_arwcMin, sctpWin);
                sctpFlowP->ct3_arwcMax = MAX(sctpFlowP->ct3_arwcMax, sctpWin);
                sctpIALen = sctpChnkPLen - 20;
                if (sctpIALen < 4) break;
                iaP = (char*)&sctpChunkP->data;
                goto sctpia;

            case SCTP_CT_ASCONF:
                tsn = ntohl(sctpChunkP->tsn_it_cta);
                sctpIALen = sctpChnkPLen - 8;
                iaP = (char*)&sctpChunkP->sis;
sctpia:
                while (sctpIALen > 3 && iax > 0) {
                    sctpAddr4_t *sctpAddrP = (sctpAddr4_t*)iaP;
                    iax = ntohs(sctpAddrP->aLen);
                    if (sctpAddrP->aType == PT_ADDIPADD || sctpAddrP->aType == PT_SETPADD || sctpAddrP->aType == PT_DELIPADD) {
                        iax = 8;
                        goto sctpasc;
                    } else if (sctpAddrP->aType == PT_IPV4) {
                        if (sPktFile && sacnt < SCTP_MXADDR) ipAddr[sacnt++] = sctpAddrP->aAddr;
                        if (sctpFlowP->numasIP < SCTP_ASMX) {
                            for (j = 0; j < sctpFlowP->numasIP; j++) {
                                if (sctpFlowP->asIP[j] == sctpAddrP->aAddr) goto sctpasc;
                            }
                            sctpFlowP->asIP[j] = sctpAddrP->aAddr;
                            sctpFlowP->numasIP++;
                        }
                    } else if (sctpAddrP->aType == PT_IPV6) {
                        sctpAddr6_t *sctpAddr6P = (sctpAddr6_t*)iaP;
                        if (sPktFile && sa6cnt < SCTP_MXADDR) ip6Addr[sa6cnt++] = sctpAddr6P->aAddr;
                        if (sctpFlowP->numasIP6 < SCTP_ASMX) {
                            for (j = 0; j < sctpFlowP->numasIP6; j++) {
                                if (sctpFlowP->asIP6[j].IPv6L[0] == sctpAddr6P->aAddr.IPv6L[0] &&
                                    sctpFlowP->asIP6[j].IPv6L[1] == sctpAddr6P->aAddr.IPv6L[1])
                                {
                                    goto sctpasc;
                                }
                            }
                            sctpFlowP->asIP6[j] = sctpAddr6P->aAddr;
                            sctpFlowP->numasIP6++;
                        }
                    }
sctpasc:
                    iaP += iax;
                    sctpIALen -= iax;
                }
                break;

            case SCTP_CT_SACK:
                tsnAck = ntohl(sctpChunkP->tsn_it_cta);
                if (tsnAck < sctpFlowP->tsnAckLst) sctpFlowP->cflags |= SCTP_ASN_ERR;
                else if (tsnAck == sctpFlowP->tsnAckLst) retCnt++;
                sctpWin = ntohl(sctpChunkP->arwc);
                sctpFlowP->ct1_2_3_arwc = 0.7 * sctpFlowP->ct1_2_3_arwc + 0.3 * (float)sctpWin;
                sctpFlowP->ct3_arwcMin = MIN(sctpFlowP->ct3_arwcMin, sctpWin);
                sctpFlowP->ct3_arwcMax = MAX(sctpFlowP->ct3_arwcMax, sctpWin);
                sctpFlowP->tsnAckLst = tsnAck;
                tsn = sctpFlowP->tsnLst;
                break;

            case SCTP_CT_ABORT:
                sctpFlowP->ct6_abrtCnt++;
                break;

            case SCTP_CT_ERROR: {
                const uint16_t cc = ntohs(sctpChunkP->cc);
                if (cc < 15) sctpFlowP->ct9_cc = cc;
                else sctpFlowP->ct9_cc = 15;
                break;
            }

            case SCTP_CT_HEARTBEAT:
                sctpStat |= SCTP_C_HRTBT;
                break;

            case SCTP_CT_HEARTBEAT_ACK:
                sctpStat |= SCTP_C_HRTBTACK;
                break;

            case SCTP_CT_SHUTDOWN:
                tsnAck = ntohl(sctpChunkP->tsn_it_cta);
                break;

            case SCTP_CT_SHUTDOWN_ACK:
                tsnAck = sctpFlowP->tsnAckLst;
                break;

            case SCTP_CT_COOKIE_ECHO:
                /* FALLTHRU */
            case SCTP_CT_COOKIE_ACK:
                /* FALLTHRU */
            case SCTP_CT_SHTDWN_CMPLT:
                /* FALLTHRU */
            case SCTP_CT_AUTH:
                ppi = 0;
                tsn = sctpFlowP->tsnLst;
                break;

            case SCTP_CT_IDATA:
                tsn = ntohl(sctpChunkP->tsn_it_cta);
                break;

            case SCTP_CT_ASCONF_ACK:
                tsnAck = ntohl(sctpChunkP->tsn_it_cta);
                break;

            case SCTP_CT_RECONFIG:
                ppi = 0;
                break;

            case SCTP_CT_PAD:
                break;

            case SCTP_CT_FORWARD_TSN:
                /* FALLTHRU */
            case SCTP_CT_IFORWARD_TSN:
                tsn = ntohl(sctpChunkP->tsn_it_cta);
                break;

            default:
                break;
        }

        if (tsn) sctpFlowP->tsnLst = tsn;
        //if (tsnAck && chnkType != SCTP_CT_ASCONF_ACK) sctpFlowP->tsnAckLst = tsnAck;

        sctpL7P += sctpChnkPLen;
        sctpL7Len -= sctpChnkPLen;

        // sctpChunkType_sid_flags_numDPkts_len_tsn_pid
        if (sPktFile) {
            if (nChnks > 1) fputc(';', sPktFile);
#if SCTP_CHNKVAL == 2
            if (chnkType < 195) fputs(sctpChunkTypeStr[chnkType], sPktFile);
            else
#endif // SCTP_CHNKVAL == 2
                fprintf(sPktFile, "%" PRIu8, chnkType);

            fprintf(sPktFile, "_%" PRIu16 "_0x%02" B2T_PRIX8 "_0x%02" B2T_PRIX8 "_%" PRIu16 "_%" PRId32 "_%" PRIu32,
                    sid, sctpChunkP->flags, sctpFlowP->cflags, sctpFlowP->ct0_dataCnt, sctpChnkLen, ppi);
        }

        if (retCnt > 2) {
            sctpStat |= SCTP_C_3ACK;
            retCnt = 0;
        }
    }

    sctpFlowP->stat |= sctpStat;

    if (sPktFile) {
        // sctpNChunks, sctpCCBF
        fprintf(sPktFile,
                               /* sctpChunkType_sid_flags_cflags_numDPkts_len_pid */ SEP_CHR
                "%"     PRIu8  /* sctpNChunks                                     */ SEP_CHR
                "0x%04" PRIx16 /* sctpCCBF                                        */ SEP_CHR
                , nChnks, sctpFlowP->ct9_cc);

        // sctpARW
        if (sctpWin) fprintf(sPktFile, "%" PRIu32 /* sctpARW */ SEP_CHR, sctpWin);
        else fputs(/* sctpARW */ SEP_CHR, sPktFile);

        // sctpPID, sctpStat
        fprintf(sPktFile,
                "%"     PRIu32    /* sctpPID  */ SEP_CHR
                "0x%02" B2T_PRIX8 /* sctpStat */ SEP_CHR
                , sctpFlowP->ct0_ppi, sctpStat);

        // sctpRelTSN/sctpRelTSNAck
#if SCTP_TSNREL == 1
        // sctpRelTSN
        if (tsn) fprintf(sPktFile, "%" PRIu32 /* sctpRelTSN */ SEP_CHR, tsn-sctpFlowP->tsnInit);
        else fputs(/* sctpRelTSN */ SEP_CHR, sPktFile);

        // sctpRelTSNAck
        if (tsnAck) fprintf(sPktFile, "%" PRIu32 /* sctpRelTSNAck */ SEP_CHR, tsnAck-sctpFlowP->tsnAckInit);
        else fputs(/* sctpRelTSNAck */ SEP_CHR, sPktFile);
#else // SCTP_TSNREL == 0
        // sctpTSN
        if (tsn) fprintf(sPktFile, "%" PRIu32 /* sctpTSN */ SEP_CHR, tsn);
        else fputs(/* sctpTSN */ SEP_CHR, sPktFile);

        // sctpTSNAck
        if (tsnAck) fprintf(sPktFile, "%" PRIu32 /* sctpTSNAck */ SEP_CHR, tsnAck);
        else fputs(/* sctpTSNAck */ SEP_CHR, sPktFile);
#endif // SCTP_TSNREL == 1

        /*if (tsn) fprintf(sPktFile, "%" PRIu32 SEP_CHR, sctpFlowP->tsnLst);
        else fputs(SEP_CHR, sPktFile);

        if (sctpFlowP->tsnAckLst) fprintf(sPktFile, "%" PRIu32 SEP_CHR, sctpFlowP->tsnAckLst);
        else fputs(SEP_CHR, sPktFile);*/

        // sctpASIP4
        char asAddr[INET6_ADDRSTRLEN] = {};
        for (uint32_t i = 0; i < sacnt; i++) {
            const ipAddr_t ip = { .IPv4x[0] = ipAddr[i] };
            inet_ntop(AF_INET, &ip, asAddr, INET6_ADDRSTRLEN);
            if (i) fputc(';', sPktFile);
            fprintf(sPktFile, "%s", asAddr);
        }
        fputs(/* sctpASIP4 */ SEP_CHR, sPktFile);

        // sctpASIP6
        for (uint32_t i = 0; i < sa6cnt; i++) {
            inet_ntop(AF_INET6, &ip6Addr[i], asAddr, INET6_ADDRSTRLEN);
            if (i) fputc(';', sPktFile);
            fprintf(sPktFile, "%s", asAddr);
        }
        fputs(/* sctpASIP6 */ SEP_CHR, sPktFile);
    }
}


void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {
    const sctpFlow_t * const sctpFlowP = &sctpFlow[flowIndex];

    sctpStat   |= sctpFlowP->stat;
    sctpTypeBF |= sctpFlowP->typeBF;
    sctpCFlags |= sctpFlowP->cflags;

    uint32_t j;

    OUTBUF_APPEND_U8(buf , sctpFlowP->stat);     // sctpStat
    OUTBUF_APPEND_U16(buf, sctpFlowP->ct0_sid);  // sctpDSNum/sctpMaxDSNum
    OUTBUF_APPEND_U32(buf, sctpFlowP->ct0_ppi);  // sctpPID
    OUTBUF_APPEND_U32(buf, sctpFlowP->verTag);   // sctpVTag

    // sctpTypeN/sctpType/sctpTypeBF
#if SCTP_CHNKVAL == 0
    OUTBUF_APPEND_U16(buf, sctpFlowP->typeBF); // sctpTypeBF
#else // SCTP_CHNKVAL > 0
    // sctpTypeN/sctpType
    j = sctpFlowP->numTypeS;
    OUTBUF_APPEND_NUMREP(buf, j);
    for (uint_fast32_t i = 0; i < j; i++) {
#if SCTP_CHNKVAL == 2
        // sctpType
        const char *str;
        if (sctpFlowP->cTypeS[i] < 195) str = sctpChunkTypeStr[sctpFlowP->cTypeS[i]];
        else str = "N/A";
        OUTBUF_APPEND_STR(buf, str);
#else // SCTP_CHNKVAL == 1
        OUTBUF_APPEND_U8(buf, sctpFlowP->cTypeS[i]); // sctpTypeN
#endif // SCTP_CHNKVAL == 1
    }
#endif // SCTP_CHNKTVAL > 0

    // sctpCntD_I_A
    OUTBUF_APPEND_U16(buf, sctpFlowP->ct0_dataCnt);
    OUTBUF_APPEND_U16(buf, sctpFlowP->ct1_initCnt);
    OUTBUF_APPEND_U16(buf, sctpFlowP->ct6_abrtCnt);

    OUTBUF_APPEND_U8(buf, sctpFlowP->cflags);  // sctpCFlags
    OUTBUF_APPEND_U16(buf, sctpFlowP->ct9_cc); // sctpCCBF

    // sctpASIP4
    j = sctpFlowP->numasIP;
    OUTBUF_APPEND_NUMREP(buf, j);
    for (uint_fast32_t i = 0; i < j; i++) {
        char asAddr[INET6_ADDRSTRLEN] = {};
        if (sctpFlowP->asIP[i]) {
            const ipAddr_t ip = { .IPv4x[0] = sctpFlowP->asIP[i] };
            inet_ntop(AF_INET, &ip, asAddr, INET6_ADDRSTRLEN);
        }
        OUTBUF_APPEND_STR(buf, asAddr);
    }

    // sctpASIP6
    j = sctpFlowP->numasIP6;
    OUTBUF_APPEND_NUMREP(buf, j);
    for (uint_fast32_t i = 0; i < j; i++) {
        char asAddr[INET6_ADDRSTRLEN] = {};
        if (sctpFlowP->asIP6[i].IPv6L[0] || sctpFlowP->asIP6[i].IPv6L[1]) {
            inet_ntop(AF_INET6, &sctpFlowP->asIP6[i], asAddr, INET6_ADDRSTRLEN);
        }
        OUTBUF_APPEND_STR(buf, asAddr);
    }

    OUTBUF_APPEND_U16(buf, sctpFlowP->ct1_2_nis);      // sctpIS
    OUTBUF_APPEND_U16(buf, sctpFlowP->ct1_2_nos);      // sctpOS
    OUTBUF_APPEND_U32(buf, sctpFlowP->ct1_2_3_arwcI);  // sctpIARW
    OUTBUF_APPEND_U32(buf, sctpFlowP->ct3_arwcMin);    // sctpIARWMin
    OUTBUF_APPEND_U32(buf, sctpFlowP->ct3_arwcMax);    // sctpIARWMax
    OUTBUF_APPEND_FLT(buf, sctpFlowP->ct1_2_3_arwc);   // sctpARW
}


void t2PluginReport(FILE *stream) {
    T2_FPLOG_AGGR_HEX(stream, plugin_name, sctpStat);
    T2_FPLOG_AGGR_HEX(stream, plugin_name, sctpCFlags);
    T2_FPLOG_AGGR_HEX(stream, plugin_name, sctpTypeBF);
}


void t2Finalize() {
    free(sctpFlow);
}
