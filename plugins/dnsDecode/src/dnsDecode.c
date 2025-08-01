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

#include "dnsDecode.h"


// Global includes

#include <ctype.h>  // for isprint


// Local includes

#include "dnsType.h"

#if DNS_MAL_TEST > 0
#include "malsite.h"
#endif // DNS_MAL_TEST > 0


// Global plugin variables

dnsFlow_t *dnsFlow;


// Static variables

#if DNS_MAL_TEST > 0
static malsitetable_t *malsite_table;
static uint64_t dnsAlarms, dnsAlarmFlows;
#endif // DNS_MAL_TEST > 0

static uint64_t totalDnsPktCnt, totalDnsPktCnt0;
static uint64_t totalDnsQPktCnt, totalDnsQPktCnt0;
static uint64_t totalDnsRPktCnt, totalDnsRPktCnt0;
static uint16_t dnsStat;
static uint16_t dnsOpC;
static uint16_t dnsRetC;
static uint8_t  dnsHFlg;


#if DNS_HDRMD > 1

// DNS op and ret codes

static const char *opcoded[] = {
    "QUERY" , "IQUERY", "STATUS", "", "NOTIFY",
    "UPDATE", ""      , ""      , "", ""      ,
    ""      , ""      , ""      , "", ""      , ""
};
static const char *rcoded[] = {
    "NOERR"  , "FORMERR ", "SERVFAIL", "NXDOMAIN", "NOTIMP" ,
    "REFUSED", "YXDOMAIN", "XRRSET"  , "NOTAUTH" , "NOTZONE",
    ""       , ""        , ""        , ""        , ""       , ""
};

// NetBIOS
static const char *opcoden[] = {
    "Query"   , ""       , ""    , ""       , "",
    "Register", "Release", "WACK", "Refresh", "",
    ""        , ""       , ""    , ""       , "", ""
};
static const char *rcoden[] = {
    "NOERR"  , "FMT_ERR", "SRV_ERR", "", "",
    "RFS_ERR", "ACT_ERR", ""       , "", "",
    "",         ""      , ""       , "", "", ""
};
#endif // DNS_HDRMD > 1


// Macros

#define NBNS_DECODE(dst, dstlen, src) do { \
    uint_fast32_t j = 0; \
    for (uint_fast32_t i = 0; i < 32 && j < dstlen; i += 2) { \
        dst[j] = ((src[i] - 0x41) << 4) + ((src[i+1] - 0x41) & 0x0f); \
        /* exclude padding, but keep suffix */ \
        if (i == 30 || !isprint(dst[j])) { \
            j += snprintf(&dst[j], dstlen - j, "<%02" B2T_PRIX8 ">", dst[j]); \
        } else if (i < 30 && dst[j] == ' ') { \
            dst[j] = '\0'; \
        } else { \
            j++; \
        } \
    } \
    dst[MIN(j, dstlen-1)] = '\0'; \
} while (0)

#define OUTBUF_APPEND_NBNS_STR(buf, s) do { \
    char tmp[DNS_HNLMAX+1] = {}; \
    NBNS_DECODE(tmp, sizeof(tmp), s); \
    OUTBUF_APPEND_STR(buf, tmp); \
} while (0)


// Function prototypes

#if DNS_MODE > 0
static inline uint16_t dns_parse(char *dnsName, uint16_t len, uint16_t l, uint16_t *kp, const uint8_t *dnsPayloadB, uint16_t lb, const uint16_t *nLenp);
#endif // DNS_MODE > 0


// Tranalyzer functions

T2_PLUGIN_INIT("dnsDecode", "0.9.3", 0, 9);


void t2Init() {
    T2_PLUGIN_STRUCT_NEW(dnsFlow);

#if DNS_MAL_TEST > 0
    if (UNLIKELY(!(malsite_table = malsite_init()))) {
        free(dnsFlow);
        exit(EXIT_FAILURE);
    }
#endif // DNS_MAL_TEST > 0

    // Packet mode
    if (sPktFile) {
        fputs(
#if DNS_WHO == 0
              "dnsIPs"               SEP_CHR
#else // DNS_WHO == 0
              "dnsIPs_cntry_org"     SEP_CHR
#endif // DNS_WHO
              "dnsStat"              SEP_CHR
#if DNS_HDRMD == 0
              "dnsHdr"               SEP_CHR
#elif DNS_HDRMD == 1
              "dnsHFlg_OpC_RetC"     SEP_CHR
#else // DNS_HDRMD > 1
              "dnsHFlg_OpN_RetN"     SEP_CHR
#endif // DNS_HDRMD
              "dnsCntQu_Asw_Aux_Add" SEP_CHR
              , sPktFile);
    }
}


binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;

    BV_APPEND_H16(bv, "dnsStat", "DNS status, warnings and errors");
    BV_APPEND_H16(bv, "dnsHdrOPField", "DNS last header field");

#if DNS_HDRMD == 0
    BV_APPEND(bv, "dnsHFlg_OpC_RetC", "DNS aggregated header flags, operational and return code", 3, bt_hex_8, bt_hex_16, bt_hex_16);
#else // DNS_HDRMD > 0
    BV_APPEND_H8(bv, "dnsHFlg", "DNS aggregated header flags");
#if DNS_HDRMD == 1
    BV_APPEND_U8_R(bv, "dnsOpC", "DNS operational code");
    BV_APPEND_U8_R(bv, "dnsRetC", "DNS return code");
#else // DNS_HDRMD > 1
    BV_APPEND_STRC_R(bv, "dnsOpN", "DNS operational string");
    BV_APPEND_STRC_R(bv, "dnsRetN", "DNS return string");
#endif // DNS_HDRMD > 1
#endif // DNS_HDRMD > 0

    BV_APPEND(bv    , "dnsCntQu_Asw_Aux_Add", "DNS number of question, answer, auxiliary and additional records", 4, bt_uint_16, bt_uint_16, bt_uint_16, bt_uint_16);
    BV_APPEND_FLT(bv, "dnsAAAqF"            , "DNS DDOS AAA / query factor");

#if DNS_MODE > 0
    // TODO rename
#if DNS_HEXON == 1
    BV_APPEND(bv, "dnsTypeBF3_BF2_BF1_BF0", "DNS type bitfields", 4, bt_hex_8, bt_hex_16, bt_hex_16, bt_hex_64);
#endif // DNS_HEXON == 1

    BV_APPEND_STR_R(bv, "dnsQname", "DNS query name");

#if (DNS_MAL_TEST > 0 && DNS_MAL_DOMAIN == 1)
    BV_APPEND_U32(bv  , "dnsMalCnt" , "DNS domain malware count");
#if DNS_MAL_TYPE == 1
    BV_APPEND_STR_R(bv, "dnsMalType", "DNS domain malware type");
#else // DNS_MAL_TYPE == 0
    BV_APPEND_U32_R(bv, "dnsMalCode", "DNS domain malware code");
#endif // DNS_MAL_TYPE
#endif // (DNS_MAL_TEST > 0 && DNS_MAL_DOMAIN == 1)

    BV_APPEND_STR_R(bv, "dnsAname"    , "DNS answer name record");
    BV_APPEND_STR_R(bv, "dnsAPname"   , "DNS name CNAME entries");
    BV_APPEND_IP4_R(bv, "dns4Aaddress", "DNS address entries IPv4");
#if DNS_WHO == 1
    BV_APPEND_R(bv    , "dns4CC_Org"  , "DNS IPv4 country and organization", 2, bt_string_class, bt_string);
#endif // DNS_WHO == 1
    BV_APPEND_IP6_R(bv, "dns6Aaddress", "DNS address entries IPv6");
#if DNS_WHO == 1
    BV_APPEND_R(bv    , "dns6CC_Org"  , "DNS IPv6 country and organization", 2, bt_string_class, bt_string);
#endif // DNS_WHO == 1

#if (DNS_MAL_TEST > 0 && DNS_MAL_DOMAIN == 0)
    BV_APPEND_H32_R(bv, "dnsIPMalCode", "DNS IP malware code");
#endif // (DNS_MAL_TEST > 0 && DNS_MAL_DOMAIN == 0)

#if DNS_TYPE == 1
    BV_APPEND_STRC_R(bv, "dnsQTypeN"    , "DNS query record type names");
#else // DNS_TYPE == 0
    BV_APPEND_U16_R(bv,  "dnsQType"     , "DNS query record type entries");
#endif // DNS_TYPE
    BV_APPEND_U16_R(bv,  "dnsQClass"    , "DNS query record class entries");
#if DNS_TYPE == 1
    BV_APPEND_STRC_R(bv, "dnsATypeN"    , "DNS answer record type names");
#else // DNS_TYPE == 0
    BV_APPEND_U16_R(bv,  "dnsAType"     , "DNS answer record type entries");
#endif // DNS_TYPE
    BV_APPEND_U16_R(bv,  "dnsAClass"    , "DNS answer record class entries");
    BV_APPEND_U32_R(bv,  "dnsATTL"      , "DNS answer record TTL entries");
    BV_APPEND_U16_R(bv,  "dnsMXpref"    , "DNS MX record preference entries");
    BV_APPEND_U16_R(bv,  "dnsSRVprio"   , "DNS SRV record priority entries");
    BV_APPEND_U16_R(bv,  "dnsSRVwgt"    , "DNS SRV record weight entries");
    BV_APPEND_U16_R(bv,  "dnsSRVprt"    , "DNS SRV record port entries");
    BV_APPEND_H32_R(bv,  "dnsOptStat"   , "DNS option status");
#endif // DNS_MODE > 0

    return bv;
}


void t2OnNewFlow(packet_t *packet, unsigned long flowIndex) {
    dnsFlow_t *dnsFlowP = &dnsFlow[flowIndex];
    memset(dnsFlowP, '\0', sizeof(dnsFlow_t));

    flow_t * const flowP = &flows[flowIndex];
    const uint_fast16_t sp = flowP->srcPort;
    const uint_fast16_t dp = flowP->dstPort;

    if (sp == DNSNPORT || dp == DNSNPORT) {
        dnsFlowP->stat = DNS_NBIOS;
    }

    if (sp == DNSPORT || sp == DNSPORTM || sp == DNSPORTB ||
        dp == DNSPORT || dp == DNSPORTM || dp == DNSPORTB ||
        dnsFlowP->stat == DNS_NBIOS)
    {
        dnsFlowP->stat |= DNS_PRTDT;
        const uint_fast8_t l4Proto = flowP->l4Proto;
        const uint16_t *dnsPayload = (uint16_t*)packet->l7HdrP;
        if (l4Proto == L3_UDP) {
            if (packet->snapL7Len < 2) return;
            dnsPayload++;
            if (!FLOW_HAS_OPPOSITE(flowP)) {
                if (sp == dp) {
                    if (*dnsPayload & DNS_QRN) flowP->status |= L3FLOWINVERT;
                    else flowP->status &= ~L3FLOWINVERT;
                }
            }
        } else if (l4Proto == L3_TCP) {
            const uint8_t tcpFlags = *((uint8_t*)packet->l4HdrP + 13);
            if ((tcpFlags & TH_SYN_FIN_RST) != TH_SYN) {
                // if there is no SYN then corrupt
                dnsFlowP->stat |= DNS_ERRCRPT;
            }

            const tcpHeader_t * const tcpHdrP = TCP_HEADER(packet);
            dnsFlowP->seqT = ntohl(tcpHdrP->seq);
        }
    }
}


#if ETH_ACTIVATE > 0
void t2OnLayer2(packet_t *packet UNUSED, unsigned long flowIndex) {
    if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;

    if (sPktFile) {
        fputs(          /* dnsIPs                                   */ SEP_CHR
              "0x0000"  /* dnsStat                                  */ SEP_CHR
                        /* dnsHdr/dnsHFlg_OpC_RetC/dnsHFlg_OpN_RetN */ SEP_CHR
              "0_0_0_0" /* dnsCntQu_Asw_Aux_Add                     */ SEP_CHR
              , sPktFile);
    }
}
#endif // ETH_ACTIVATE > 0


void t2OnLayer4(packet_t *packet, unsigned long flowIndex) {
    dnsFlow_t * const dnsFlowP = &dnsFlow[flowIndex];

    uint16_t stat = dnsFlowP->stat;
    uint16_t u = 0;
    uint16_t qnCnt = 0, anCnt = 0, nsCnt = 0, arCnt = 0;
    uint16_t opCode = 0, rCode = 0;
    uint8_t  dnsFlags = 0;

    if (!(stat & DNS_PRTDT) || (stat & DNS_ERRCRPT)) {
        // Not DNS or DNS TCP starts in the middle somewhere
        goto early;
    }

    // only 1. frag packet will be processed
    if (!t2_is_first_fragment(packet)) goto early;

    uint16_t *dnsPayload = (uint16_t*)packet->l7HdrP;
    const uint16_t sL7Len = packet->snapL7Len;
    const uint_fast8_t l4Proto = packet->l4Proto;

    uint16_t dnsLen;

    if (l4Proto == L3_UDP) {
        dnsLen = sL7Len;
        if (dnsLen < DNS_MINDNSLEN) {
            dnsFlowP->stat |= (DNS_ERRCRPT | DNS_WRNMLN);
            goto early; // No DNS payload
        }
        if (dnsLen > 548) stat |= DNS_WRNULN;
    } else if (l4Proto == L3_TCP) { // TCP: length in DNS header
        const tcpHeader_t * const tcpHdrP = TCP_HEADER(packet);
        const uint32_t seq = ntohl(tcpHdrP->seq);
        if (sL7Len < 6) {
            dnsFlowP->seqT = seq;
            goto early;
        }

        if (dnsFlowP->seqT != seq) { // are packets missing?
            dnsFlowP->stat |= DNS_ERRCRPT;  // packets corrupt, stop processing
            goto early;
        }

        dnsFlowP->seqT = seq + packet->l7Len; // only if payload

        if (dnsFlowP->stat & DNS_FRAGS) {
            dnsLen = dnsFlowP->tLen;
        } else {
            dnsLen = ntohs(*dnsPayload);
            dnsFlowP->tLen = dnsLen;
        }

        if (dnsLen <= sL7Len) {
            stat &= ~DNS_FRAGS; // last fragment, reset frag state
        } else {
            dnsLen = sL7Len;
            dnsFlowP->tLen -= dnsLen;
            stat |= (DNS_FRAGS | DNS_FRAGA); // set frag state
        }

        dnsPayload++;
    } else { // Not TCP nor UDP
        goto early;
    }

    if (dnsLen < DNS_LEN_REJECT) {
        dnsFlowP->stat |= DNS_WRNMLN;
        goto early; // No DNS payload
    }

    if (dnsFlowP->stat & DNS_FRAGS) {
        if (dnsFlowP->hdrOPField & DNS_QR) totalDnsRPktCnt++;
        else totalDnsQPktCnt++;
        qnCnt = dnsFlowP->qnCnt;
        anCnt = dnsFlowP->anCnt;
        nsCnt = dnsFlowP->nsCnt;
        arCnt = dnsFlowP->arCnt;
    } else {
        totalDnsPktCnt++; // count only IP unfragmented DNS packets

        dnsPayload++;
        u = ntohs(*dnsPayload);
        dnsFlowP->hdrOPField = u;
        dnsFlags = ((u & 0x07f0) >> 4) | ((u & DNS_QR) >> 8);
        opCode = ((u & 0x7800) >> 11);
        rCode = (u & 0x000f);

        dnsFlowP->hFlagsBF |= dnsFlags;
        dnsFlowP->opCodeBF |= (1 << opCode);
        dnsFlowP->rCodeBF  |= (1 << rCode);

#if DNS_HDRMD > 0
        uint_fast32_t i;
        for (i = 0; i < dnsFlowP->opCodeCnt; i++) {
            if (dnsFlowP->opCode[i] == opCode) break;
        }

        if (i == dnsFlowP->opCodeCnt && i < DNS_QRECMXI) {
            dnsFlowP->opCode[dnsFlowP->opCodeCnt++] = opCode;
        }

        for (i = 0; i < dnsFlowP->rCodeCnt; i++) {
            if (dnsFlowP->rCode[i] == rCode) break;
        }

        if (i == dnsFlowP->rCodeCnt && i < DNS_QRECMXI) {
            dnsFlowP->rCode[dnsFlowP->rCodeCnt++] = rCode;
        }
#endif // DNS_HDRMD > 0

        if (u & DNS_QR) {
            totalDnsRPktCnt++;
            dnsFlowP->aaLen += dnsLen;
        } else {
            totalDnsQPktCnt++;
        }

        if (dnsLen < DNS_MINDNSLEN) goto early; // no DNS payload

        qnCnt = ntohs(*(++dnsPayload));
        anCnt = ntohs(*(++dnsPayload));
        nsCnt = ntohs(*(++dnsPayload));
        arCnt = ntohs(*(++dnsPayload));
        dnsFlowP->qnCnt = qnCnt;
        dnsFlowP->anCnt = anCnt;
        dnsFlowP->nsCnt = nsCnt;
        dnsFlowP->arCnt = arCnt;
        dnsFlowP->qnaCnt += qnCnt;
        dnsFlowP->anaCnt += anCnt;
        dnsFlowP->nsaCnt += nsCnt;
        dnsFlowP->araCnt += arCnt;

        if ((u & 0x4040) ||
            (dnsFlowP->opCodeBF & 0xff00) ||
            (dnsFlowP->rCodeBF  & 0xf800) ||
            (qnCnt * 5 + 13 * (anCnt + nsCnt + arCnt) - 16) > dnsLen)
        {
            stat |= DNS_ERRCRPT;
            dnsFlowP->stat = stat;
            goto early;
        }
    }

    dnsFlowP->stat = stat;

#if DNS_MODE > 0
#if DNS_AGGR == 1
    uint32_t m;
#endif // DNS_AGGR == 1

    uint32_t j = 0, n;
    uint16_t k, nLen;
#if DNS_MODE > 1
    char ips[INET6_ADDRSTRLEN];
#endif // DNS_MODE > 1
    char tnBuf[DNS_HNLMAX+1];

    dnsPayload -= 5; // reset uint16_t ptr to beginning of DNS payload
    const uint8_t * const dnsPayloadB = (uint8_t*)dnsPayload; // set byte ptr

#if DNS_AGGR == 1
    j = dnsFlowP->qrnCnt;
    if (j >= DNS_QRECMXI) {
        j = DNS_QRECMXI;
        dnsFlowP->qrnCnt = DNS_QRECMXI;
        dnsFlowP->stat |= DNS_WRNDEX;
    }
#endif // DNS_AGGR == 1

    uint_fast32_t i;
    uint16_t l = DNS_RSTART;
    for (i = 0; i < qnCnt; i++) {
        k = 0;
        nLen = 0;

#if DNS_AGGR == 1
        j = dnsFlowP->qrnaCnt;
#endif // DNS_AGGR == 1

        if (!dnsPayloadB[l]) {
#if DNS_AGGR == 1
            m = j;
#endif // DNS_AGGR == 1
            l++;
        } else {
            l = dns_parse(tnBuf, dnsLen, l, &k, dnsPayloadB, l, &nLen);
            if ((l4Proto == L3_UDP && l > sL7Len) ||
                (l4Proto == L3_TCP && l > sL7Len))
            {
                goto errl;
            }
            n = strlen(tnBuf);
#if DNS_AGGR == 1
            for (m = 0; m < j; m++) {
                if (!memcmp(dnsFlowP->qName[m], tnBuf, n)) break;
            }
            if (m == j && m < DNS_QRECMXI) {
                dnsFlowP->qrnaCnt++;
#endif // DNS_AGGR == 1
                T2_REALLOC(dnsFlowP->qName[j], n+1);
                memcpy(dnsFlowP->qName[j], tnBuf, n);
                dnsFlowP->qName[j][n] = '\0';
#if (DNS_MAL_TEST > 1 && DNS_MAL_DOMAIN == 1)
                dnsFlowP->malcode[j] = maldomain_test(malsite_table, dnsFlowP->qName[j]);
                if (dnsFlowP->malcode[j]) {
                    dnsFlowP->numAF++;
                    T2_SET_STATUS(&flows[flowIndex], FL_ALARM);
                }
#endif // (DNS_MAL_TEST > 1 && DNS_MAL_DOMAIN == 1)
#if DNS_AGGR == 1
            }
#endif // DNS_AGGR == 1
        }

        dnsPayload = (uint16_t*)(dnsPayloadB + l);

#if DNS_AGGR == 1
        if (m == j && m < DNS_QRECMXI) {
#endif // DNS_AGGR == 1
            const uint16_t qtype = ntohs(*dnsPayload++);
            dnsFlowP->qType[j] = qtype;

            if (qtype < DNS_BF0) dnsFlowP->typeBF0 |= ((uint64_t)1 << qtype);

#if DNS_HEXON == 1
            if (qtype >= DNS_BF1) dnsFlowP->typeBF1 |= (1 << (qtype - DNS_BF1));
            if (qtype >= DNS_BF2) dnsFlowP->typeBF2 |= (1 << (qtype - DNS_BF2));
            if (qtype >= DNS_BF3) dnsFlowP->typeBF3 |= (1 << (qtype - DNS_BF3));
#endif // DNS_HEXON == 1

                 if (qtype == DNS_AXFR)    dnsFlowP->stat |= DNS_ZTRANS;
            else if (qtype == DNS_IXFR)    dnsFlowP->stat |= DNS_IZTRANS;
            else if (qtype == DNS_ZONEALL) dnsFlowP->stat |= DNS_ANY;

            dnsFlowP->qClass[j] = ntohs(*dnsPayload);
#if DNS_AGGR == 1
        }
#endif // DNS_AGGR == 1

        l += 4; // advance byte ptr to unit16_t ptr

#if DNS_AGGR == 0
        if (j < DNS_QRECMXI) {
            j++;
        } else {
            dnsFlowP->stat |= DNS_WRNDEX;
            break;
        }
#endif // DNS_AGGR == 0
    }

    dnsFlowP->qrnCnt = j;
    if (u & 0x8000) dnsFlowP->qaLen += l;
#endif // DNS_MODE > 0

#if DNS_MODE > 1
    uint16_t recLen;

#if DNS_AGGR == 0
    j = dnsFlowP->arnCnt;
    if (j >= DNS_ARECMXI) {
        j = DNS_ARECMXI;
        dnsFlowP->arnCnt = DNS_ARECMXI;
        dnsFlowP->stat |= DNS_WRNAEX;
    }
#endif // DNS_AGGR == 0

    for (i = 0; i < anCnt && l+5 < dnsLen; i++) {
        k = 0;
        nLen = 0;

        if (!dnsPayloadB[l]) {
            l++;
        } else {
            l = dns_parse(tnBuf, dnsLen, l, &k, dnsPayloadB, l, &nLen);
            if (l > sL7Len) goto errl;
            n = strlen(tnBuf);

#if DNS_AGGR == 1
            for (m = 0; m < dnsFlowP->arnaCnt; m++) {
                if (!memcmp(dnsFlowP->aName[m], tnBuf, n)) break;
            }

            if (m == dnsFlowP->arnaCnt && m < DNS_ARECMXI) {
                dnsFlowP->arnaCnt++;
                T2_REALLOC(dnsFlowP->aName[m], n+1);
                memcpy(dnsFlowP->aName[m], tnBuf, n);
                dnsFlowP->aName[m][n] = '\0';
            }
#else // DNS_AGGR == 0
            T2_REALLOC(dnsFlowP->aName[j], n+1);
            memcpy(dnsFlowP->aName[j], tnBuf, n);
            dnsFlowP->aName[j][n] = '\0';
#endif // DNS_AGGR
        }

        dnsPayload = (uint16_t*)(dnsPayloadB + l);

        const uint16_t atype = ntohs(*dnsPayload++);

        if (atype < DNS_BF0) dnsFlowP->typeBF0 |= ((uint64_t)1 << atype);

#if DNS_HEXON == 1
        if (atype >= DNS_BF1) dnsFlowP->typeBF1 |= (1 << (atype - DNS_BF1));
        if (atype >= DNS_BF2) dnsFlowP->typeBF2 |= (1 << (atype - DNS_BF2));
        if (atype >= DNS_BF3) dnsFlowP->typeBF3 |= (1 << (atype - DNS_BF3));
#endif // DNS_HEXON == 1

             if (atype == DNS_AXFR)    dnsFlowP->stat |= DNS_ZTRANS;
        else if (atype == DNS_IXFR)    dnsFlowP->stat |= DNS_IZTRANS;
        else if (atype == DNS_ZONEALL) dnsFlowP->stat |= DNS_ANY;

#if DNS_AGGR == 1
        for (m = 0; m < dnsFlowP->arnatCnt; m++) {
            if (dnsFlowP->aType[m] == atype) break;
        }

        if (m == dnsFlowP->arnatCnt && m < DNS_ARECMXI) {
            dnsFlowP->arnatCnt++;
            dnsFlowP->aType[m] = atype;
        }
#else // DNS_AGGR == 0
        dnsFlowP->aType[j] = atype;
#endif // DNS_AGGR

        if (atype != DNS_OPT) {
            const uint16_t aClass = ntohs(*dnsPayload++);
            const uint16_t aTTL = ntohl(*(uint32_t*)dnsPayload++);
#if DNS_AGGR == 1
            for (m = 0; m < dnsFlowP->arnacCnt; m++) {
                if (dnsFlowP->aClass[m] == aClass) break;
            }

            if (m == dnsFlowP->arnacCnt && m < DNS_ARECMXI) {
                dnsFlowP->arnacCnt++;
                dnsFlowP->aClass[m] = aClass;
            }

            for (m = 0; m < dnsFlowP->arnaaCnt; m++) {
                if (dnsFlowP->aTTL[m] == aTTL) break;
            }

            if (m == dnsFlowP->arnaaCnt && m < DNS_ARECMXI) {
                dnsFlowP->arnaaCnt++;
                dnsFlowP->aTTL[m] = aTTL;
            }
#else // DNS_AGGR == 0
            dnsFlowP->aClass[j] = aClass;
            dnsFlowP->aTTL[j] = aTTL;
#endif // DNS_AGGR
            l += 10; // advance byte ptr to unit16_t ptr
        }

        if (l + 4 > dnsLen) {
#if DNS_AGGR == 0
            if (j < DNS_ARECMXI) j++;
#endif // DNS_AGGR == 0
            break;
        }

        dnsPayload++;
        recLen = ntohs(*dnsPayload++);

        switch (atype) {
            case DNS_A: {
                const uint32_t aAddr4 = *(uint32_t*)(dnsPayload);
#if DNS_AGGR == 1
                for (m = 0; m < dnsFlowP->aAddr4Cnt; m++) {
                    if (dnsFlowP->aAddr4[m] == aAddr4) break;
                }

                if (m == dnsFlowP->aAddr4Cnt && m < DNS_ARECMXI) {
                    dnsFlowP->aAddr4Cnt++;
                    dnsFlowP->aAddr4[m] = aAddr4;
                }
#else // DNS_AGGR == 0
                dnsFlowP->aAddr[j].IPv4x[0] = aAddr4;
#endif // DNS_AGGR

                if (sPktFile) {
                    inet_ntop(AF_INET, &aAddr4, ips, INET_ADDRSTRLEN);
#if DNS_WHO == 0
                    fprintf(sPktFile,"%s;", ips);
#else // DNS_WHO == 1
#if (PV6_ACTIVATE == 2 || IPV6_ACTIVATE == 0)
                    const uint32_t netNum = subnet_testHL4((subnettable4_t*)subnetTableP[0], aAddr4);
                    const subnet4_t * const loP = &(((subnettable4_t*)subnetTableP[0])->subnets[netNum]);
                    fprintf(sPktFile,"%s_%s_%s;", ips, loP->loc, loP->org);
#else // PV6_ACTIVATE == 1
                    fprintf(sPktFile,"%s_-_-;", ips);
#endif // (PV6_ACTIVATE == 2 || IPV6_ACTIVATE == 0)
#endif // DNS_WHO
                }

                l += 4;
                break;
            }

            case DNS_NS:
            case DNS_CNAME:
            case DNS_PTR: {
                k = 0;
                nLen = 0;
                l = dns_parse(tnBuf, dnsLen, l, &k, dnsPayloadB, l, &nLen);
                n = strlen(tnBuf);
#if DNS_AGGR == 1
                for (m = 0; m < dnsFlowP->pCnt; m++) {
                    if (!memcmp(dnsFlowP->pName[m], tnBuf, n)) break;
                }

                if (m == dnsFlowP->pCnt && m < DNS_ARECMXI) {
                    dnsFlowP->pCnt++;
                    T2_REALLOC(dnsFlowP->pName[m], n+1);
                    memcpy(dnsFlowP->pName[m], tnBuf, n);
                    dnsFlowP->pName[m][n] = '\0';
                }
#else // DNS_AGGR == 0
                T2_REALLOC(dnsFlowP->pName[j], n+1);
                memcpy(dnsFlowP->pName[j], tnBuf, n);
                dnsFlowP->pName[j][n] = '\0';
#endif // DNS_AGGR
                if (l > sL7Len) goto errl;
                break;
            }

            case DNS_SOA: {
                k = 0;
                nLen = 0;
                l = dns_parse(tnBuf, dnsLen, l, &k, dnsPayloadB, l, &nLen);
                n = strlen(tnBuf);
#if DNS_AGGR == 1
                for (m = 0; m < dnsFlowP->pCnt; m++) {
                    if (!memcmp(dnsFlowP->pName[m], tnBuf, n)) break;
                }

                if (m == dnsFlowP->pCnt && m < DNS_ARECMXI) {
                    dnsFlowP->pCnt++;
                    T2_REALLOC(dnsFlowP->pName[m], n+1);
                    memcpy(dnsFlowP->pName[m], tnBuf, n);
                    dnsFlowP->pName[m][n] = '\0';
                }
#else // DNS_AGGR == 0
                T2_REALLOC(dnsFlowP->pName[j], n+1);
                memcpy(dnsFlowP->pName[j], tnBuf, n);
                dnsFlowP->pName[j][n] = '\0';
#endif // DNS_AGGR
                if (l > sL7Len) goto errl;

                k = 0;
                nLen = 0;
                l = dns_parse(tnBuf, dnsLen, l, &k, dnsPayloadB, l, &nLen);
                n = strlen(tnBuf);
#if DNS_AGGR == 1
                for (m = 0; m < dnsFlowP->pCnt; m++) {
                    if (!memcmp(dnsFlowP->pName[m], tnBuf, n)) break;
                }

                if (m == dnsFlowP->pCnt && m < DNS_ARECMXI) {
                    dnsFlowP->pCnt++;
                    T2_REALLOC(dnsFlowP->pName[m], n+1);
                    memcpy(dnsFlowP->pName[m], tnBuf, n);
                    dnsFlowP->pName[m][n] = '\0';
                }
#else // DNS_AGGR == 0
                if (j < DNS_ARECMXI) j++;
                T2_REALLOC(dnsFlowP->pName[j], n+1);
                memcpy(dnsFlowP->pName[j], tnBuf, n);
                dnsFlowP->pName[j][n] = '\0';
#endif // DNS_AGGR

                l += 16;
                if (l > sL7Len) goto errl;

#if DNS_AGGR == 1
                const uint32_t aTTL = ntohl(*(uint32_t*)(dnsPayloadB+l));
                for (m = 0; m < dnsFlowP->arnaaCnt; m++) {
                    if (dnsFlowP->aTTL[m] == aTTL) break;
                }

                if (m == dnsFlowP->arnaaCnt && m < DNS_ARECMXI) {
                    dnsFlowP->arnaaCnt++;
                    dnsFlowP->aTTL[m] = aTTL;
                }
#else // DNS_AGGR == 0
                dnsFlowP->aTTL[j] = ntohl(*(uint32_t*)(dnsPayloadB+l));
#endif // DNS_AGGR
                l += 4;
                break;
            }

            case DNS_MX: {
                k = 0;
                nLen = 0;
#if DNS_AGGR == 1
                const uint16_t dnsMXP = ntohs(*dnsPayload);
                for (m = 0; m < dnsFlowP->mxpCnt; m++) {
                    if (dnsFlowP->aAddr4[m] == dnsMXP) break;
                }

                if (m == dnsFlowP->mxpCnt && m < DNS_ARECMXI) {
                    dnsFlowP->mxpCnt++;
                    dnsFlowP->mxPref[m] = dnsMXP;
                }
#else // DNS_AGGR == 0
                dnsFlowP->mxPref[j] = ntohs(*dnsPayload);
#endif // DNS_AGGR
                l += 2;
                l = dns_parse(tnBuf, dnsLen, l, &k, dnsPayloadB, l, &nLen);
                if (l > sL7Len) goto errl;

                n = strlen(tnBuf);
#if DNS_AGGR == 1
                for (m = 0; m < dnsFlowP->pCnt; m++) {
                    if (!memcmp(dnsFlowP->pName[m], tnBuf, n)) break;
                }

                if (m == dnsFlowP->pCnt && m < DNS_ARECMXI) {
                    dnsFlowP->pCnt++;
                    T2_REALLOC(dnsFlowP->pName[m], n+1);
                    memcpy(dnsFlowP->pName[m], tnBuf, n);
                    dnsFlowP->pName[m][n] = '\0';
                }
#else // DNS_AGGR == 0
                T2_REALLOC(dnsFlowP->pName[j], n+1);
                memcpy(dnsFlowP->pName[j], tnBuf, n);
                dnsFlowP->pName[j][n] = '\0';
#endif // DNS_AGGR
                break;
            }

            case DNS_TXT: {
                k = dnsPayloadB[l];
                if (recLen == k+1) l++;
                else k = recLen;
                if (l >= sL7Len) goto errl;
                const uint16_t tocopy = MIN(k, sL7Len - l);
#if DNS_AGGR == 1
                for (m = 0; m < dnsFlowP->pCnt; m++) {
                    if (!memcmp(dnsFlowP->pName[m], dnsPayloadB + l, k)) break;
                }

                if (m == dnsFlowP->pCnt && m < DNS_ARECMXI) {
                    dnsFlowP->pCnt++;
                    T2_REALLOC(dnsFlowP->pName[m], tocopy+1);
                    memcpy(dnsFlowP->pName[m], dnsPayloadB + l, tocopy);
                    dnsFlowP->pName[m][tocopy] = '\0';
                }
#else // DNS_AGGR == 0
                T2_REALLOC(dnsFlowP->pName[j], tocopy+1);
                memcpy(dnsFlowP->pName[j], dnsPayloadB + l, tocopy);
                dnsFlowP->pName[j][tocopy] = '\0';
#endif // DNS_AGGR == 1
                l += k;
                if (l > sL7Len) goto errl;
                break;
            }

            case DNS_AAAA: {
                const ipAddr_t aAddr6 = *(ipAddr_t*)(dnsPayload);
#if DNS_AGGR == 1
                for (m = 0; m < dnsFlowP->aAddr6Cnt; m++) {
                    if (dnsFlowP->aAddr6[m].IPv6L[0] == aAddr6.IPv6L[0] &&
                        dnsFlowP->aAddr6[m].IPv6L[1] == aAddr6.IPv6L[1])
                    {
                        break;
                    }
                }

                if (m == dnsFlowP->aAddr6Cnt && m < DNS_ARECMXI) {
                    dnsFlowP->aAddr6Cnt++;
                    dnsFlowP->aAddr6[m] = aAddr6;
                }
#else // DNS_AGGR == 0
                dnsFlowP->aAddr[j] = aAddr6;
#endif // DNS_AGGR == 1

                if (sPktFile) {
                    t2_ipv6_to_str(aAddr6.IPv6, ips, INET6_ADDRSTRLEN);
#if DNS_WHO == 0
                    fprintf(sPktFile,"%s;", ips);
#else // DNS_WHO == 1
#if IPV6_ACTIVATE > 0
                    const uint32_t netNum = subnet_testHL6((subnettable6_t*)subnetTableP[1], aAddr6);
                    const subnet6_t * const loP = &(((subnettable6_t*)subnetTableP[1])->subnets[netNum]);
                    fprintf(sPktFile,"%s_%s_%s;", ips, loP->loc, loP->org);
#else // IPV6_ACTIVATE == 0
                    fprintf(sPktFile,"%s_-_-;", ips);
#endif // IPV6_ACTIVATE
#endif // DNS_WHO
                }

                l += 16;
                break;
            }

            case DNS_SRV: {
                k = 0;
                nLen = 0;

#if DNS_AGGR == 1
                const uint16_t prio = ntohs(*(dnsPayload++));
                for (m = 0; m < dnsFlowP->pwpCnt; m++) {
                    if (dnsFlowP->srvPrio[m] == prio) break;
                }

                if (m == dnsFlowP->pwpCnt && m < DNS_ARECMXI) {
                    dnsFlowP->pwpCnt++;
                    dnsFlowP->srvPrio[m] = prio;
                    dnsFlowP->srvWeight[m] = ntohs(*(dnsPayload++));
                    dnsFlowP->srvPort[m] = ntohs(*(dnsPayload));
                }
#else // DNS_AGGR == 0
                dnsFlowP->srvPrio[j] = ntohs(*(dnsPayload++));
                dnsFlowP->srvWeight[j] = ntohs(*(dnsPayload++));
                dnsFlowP->srvPort[j] = ntohs(*(dnsPayload));
#endif // DNS_AGGR == 1

                l += 6;
                l = dns_parse(tnBuf, dnsLen, l, &k, dnsPayloadB, l, &nLen);
                n = strlen(tnBuf);

#if DNS_AGGR == 1
                for (m = 0; m < dnsFlowP->pCnt; m++) {
                    if (!memcmp(dnsFlowP->pName[m], tnBuf, n)) break;
                }

                if (m == dnsFlowP->pCnt && m < DNS_ARECMXI) {
                    dnsFlowP->pCnt++;
                    T2_REALLOC(dnsFlowP->pName[m], n+1);
                    memcpy(dnsFlowP->pName[m], tnBuf, n);
                    dnsFlowP->pName[m][n] = '\0';
                }
#else // DNS_AGGR == 0
                T2_REALLOC(dnsFlowP->pName[j], n+1);
                memcpy(dnsFlowP->pName[j], tnBuf, n);
                dnsFlowP->pName[j][n] = '\0';
#endif // DNS_AGGR
                if (l > sL7Len) goto errl;
                break;
            }

            case DNS_OPT: {
#if DNS_AGGR == 1
                const uint16_t dnsOPT = ntohl(*(uint32_t*)(dnsPayload-1));
                for (m = 0; m < dnsFlowP->optCnt; m++) {
                    if (dnsFlowP->optStat[m] == dnsOPT) break;
                }

                if (m == dnsFlowP->optCnt && m < DNS_ARECMXI) {
                    dnsFlowP->optCnt++;
                    dnsFlowP->optStat[m] = dnsOPT;
                    //dnsFlowP->aClass[m] = 0;
                    //dnsFlowP->aTTL[m] = 0;
                }
#else // DNS_AGGR == 0
                dnsFlowP->optStat[j] = ntohl(*(uint32_t*)(dnsPayload-1));
                dnsFlowP->aClass[j] = 0;
                dnsFlowP->aTTL[j] = 0;
#endif // DNS_AGGR

                /*n = ntohs(*dnsPayload);
                //T2_REALLOC(dnsFlowP->dnsOpt[dnsNRACnt], n+1);
                //memcpy(dnsFlowP->pName[dnsNRACnt], dnsPayloadB+l+4, n);
                dnsFlowP->pName[dnsNRACnt][n] = '\0';*/
                l += recLen;
                break;
            }

            case DNS_RRSIG:
            case NB:
                l += recLen;
                break;

            default:
                dnsFlowP->stat |= DNS_WRNIGN;
                l += recLen;

        /*      if (arnCnt < DNS_ARECMXI) arnCnt++;
                dnsFlowP->arnCnt = arnCnt;
                dnsFlowP->anCnt -= (i+1);
                goto early;
        */
                break;
        }
#if DNS_AGGR == 0
        if (j < DNS_ARECMXI) j++;
    }

    if (j < DNS_ARECMXI) dnsFlowP->arnCnt = j;
    else dnsFlowP->arnCnt = DNS_ARECMXI;
#else // DNS_AGGR == 1
    }
#endif // DNS_AGGR
#endif // DNS_MODE > 1

#if DNS_MODE > 2
#if DNS_AGGR == 0
    j = dnsFlowP->arnCnt;
    if (j >= DNS_ARECMXI) {
        j = DNS_ARECMXI;
        dnsFlowP->arnCnt = DNS_ARECMXI;
        dnsFlowP->stat |= DNS_WRNAEX;
    }
#endif // DNS_AGGR == 0

    for (i = 0; i < nsCnt && l+5 < dnsLen; i++) {
        k = 0;
        nLen = 0;

        if (!dnsPayloadB[l]) {
            l++;
        } else {
            l = dns_parse(tnBuf, dnsLen, l, &k, dnsPayloadB, l, &nLen);
            if (l > sL7Len) goto errl;
            n = strlen(tnBuf);
#if DNS_AGGR == 1
            for (m = 0; m < dnsFlowP->arnaCnt; m++) {
                if (!memcmp(dnsFlowP->aName[m], tnBuf, n)) break;
            }

            if (m == dnsFlowP->arnaCnt && m < DNS_ARECMXI) {
                dnsFlowP->arnaCnt++;
                T2_REALLOC(dnsFlowP->aName[m], n+1);
                memcpy(dnsFlowP->aName[m], tnBuf, n);
                dnsFlowP->aName[m][n] = '\0';
            }
#else // DNS_AGGR == 0
            T2_REALLOC(dnsFlowP->aName[j], n+1);
            memcpy(dnsFlowP->aName[j], tnBuf, n);
            dnsFlowP->aName[j][n] = '\0';
#endif // DNS_AGGR
        }

        dnsPayload = (uint16_t*)(dnsPayloadB + l);

        const uint16_t atype = ntohs(*dnsPayload++);

        if (atype < DNS_BF0) dnsFlowP->typeBF0 |= ((uint64_t)1 << atype);

#if DNS_HEXON == 1
        if (atype >= DNS_BF1) dnsFlowP->typeBF1 |= (1 << (atype - DNS_BF1));
        if (atype >= DNS_BF2) dnsFlowP->typeBF2 |= (1 << (atype - DNS_BF2));
        if (atype >= DNS_BF3) dnsFlowP->typeBF3 |= (1 << (atype - DNS_BF3));
#endif // DNS_HEXON == 1

             if (atype == DNS_AXFR)    dnsFlowP->stat |= DNS_ZTRANS;
        else if (atype == DNS_IXFR)    dnsFlowP->stat |= DNS_IZTRANS;
        else if (atype == DNS_ZONEALL) dnsFlowP->stat |= DNS_ANY;

#if DNS_AGGR == 1
        for (m = 0; m < dnsFlowP->arnatCnt; m++) {
            if (dnsFlowP->aType[m] == atype) break;
        }

        if (m == dnsFlowP->arnatCnt && m < DNS_ARECMXI) {
            dnsFlowP->arnatCnt++;
            dnsFlowP->aType[m] = atype;
        }
#else // DNS_AGGR == 0
        dnsFlowP->aType[j] = atype;
#endif // DNS_AGGR

        if (atype != DNS_OPT) {
            const uint16_t aClass = ntohs(*dnsPayload++);
            const uint16_t aTTL = ntohl(*(uint32_t*)dnsPayload++);

#if DNS_AGGR == 1
            for (m = 0; m < dnsFlowP->arnacCnt; m++) {
                if (dnsFlowP->aClass[m] == aClass) break;
            }

            if (m == dnsFlowP->arnacCnt && m < DNS_ARECMXI) {
                dnsFlowP->arnacCnt++;
                dnsFlowP->aClass[m] = aClass;
            }

            for (m = 0; m < dnsFlowP->arnaaCnt; m++) {
                if (dnsFlowP->aTTL[m] == aTTL) break;
            }

            if (m == dnsFlowP->arnaaCnt && m < DNS_ARECMXI) {
                dnsFlowP->arnaaCnt++;
                dnsFlowP->aTTL[m] = aTTL;
            }
#else // DNS_AGGR == 0
            dnsFlowP->aClass[j] = aClass;
            dnsFlowP->aTTL[j] = aTTL;
#endif // DNS_AGGR
            l += 10; // advance byte ptr to unit16_t ptr
        }

        if (l + 4 > dnsLen) {
#if DNS_AGGR == 0
            if (j < DNS_ARECMXI) j++;
#endif // DNS_AGGR == 0
            break;
        }

        dnsPayload++;
        recLen = ntohs(*dnsPayload++);

        switch (atype) {
            case DNS_A: {
                const uint32_t aAddr4 = *(uint32_t*)(dnsPayload);
#if DNS_AGGR == 1
                for (m = 0; m < dnsFlowP->aAddr4Cnt; m++) {
                    if (dnsFlowP->aAddr4[m] == aAddr4) break;
                }

                if (m == dnsFlowP->aAddr4Cnt && m < DNS_ARECMXI) {
                    dnsFlowP->aAddr4Cnt++;
                    dnsFlowP->aAddr4[m] = aAddr4;
                }
#else // DNS_AGGR == 0
                dnsFlowP->aAddr[j].IPv4x[0] = aAddr4;
#endif // DNS_AGGR == 1

                if (sPktFile) {
                    inet_ntop(AF_INET, &aAddr4, ips, INET_ADDRSTRLEN);
#if DNS_WHO == 0
                    fprintf(sPktFile,"%s;", ips);
#else // DNS_WHO == 1
#if (PV6_ACTIVATE == 2 || IPV6_ACTIVATE == 0)
                    const uint32_t netNum = subnet_testHL4((subnettable4_t*)subnetTableP[0], aAddr4);
                    const subnet4_t * const loP = &(((subnettable4_t*)subnetTableP[0])->subnets[netNum]);
                    fprintf(sPktFile,"%s_%s_%s;", ips, loP->loc, loP->org);
#else // PV6_ACTIVATE == 1
                    fprintf(sPktFile,"%s_-_-;", ips);
#endif // (PV6_ACTIVATE == 2 || IPV6_ACTIVATE == 0)
#endif // DNS_WHO
                }

                l += 4;
                break;
            }

            case DNS_NS:
            case DNS_CNAME:
            case DNS_PTR: {
                k = 0;
                nLen = 0;
                l = dns_parse(tnBuf, dnsLen, l, &k, dnsPayloadB, l, &nLen);
                n = strlen(tnBuf);
#if DNS_AGGR == 1
                for (m = 0; m < dnsFlowP->pCnt; m++) {
                    if (!memcmp(dnsFlowP->pName[m], tnBuf, n)) break;
                }

                if (m == dnsFlowP->pCnt && m < DNS_ARECMXI) {
                    dnsFlowP->pCnt++;
                    T2_REALLOC(dnsFlowP->pName[m], n+1);
                    memcpy(dnsFlowP->pName[m], tnBuf, n);
                    dnsFlowP->pName[m][n] = '\0';
                }
#else // DNS_AGGR == 0
                T2_REALLOC(dnsFlowP->pName[j], n+1);
                memcpy(dnsFlowP->pName[j], tnBuf, n);
                dnsFlowP->pName[j][n] = '\0';
#endif // DNS_AGGR
                if (l > sL7Len) goto errl;
                break;
            }

            case DNS_SOA: {
                k = 0;
                nLen = 0;
                l = dns_parse(tnBuf, dnsLen, l, &k, dnsPayloadB, l, &nLen);
                n = strlen(tnBuf);

#if DNS_AGGR == 1
                for (m = 0; m < dnsFlowP->pCnt; m++) {
                    if (!memcmp(dnsFlowP->pName[m], tnBuf, n)) break;
                }

                if (m == dnsFlowP->pCnt && m < DNS_ARECMXI) {
                    dnsFlowP->pCnt++;
                    T2_REALLOC(dnsFlowP->pName[m], n+1);
                    memcpy(dnsFlowP->pName[m], tnBuf, n);
                    dnsFlowP->pName[m][n] = '\0';
                }
#else // DNS_AGGR == 0
                T2_REALLOC(dnsFlowP->pName[j], n+1);
                memcpy(dnsFlowP->pName[j], tnBuf, n);
                dnsFlowP->pName[j][n] = '\0';
#endif // DNS_AGGR

                if (l > sL7Len) goto errl;

                k = 0;
                nLen = 0;
                l = dns_parse(tnBuf, dnsLen, l, &k, dnsPayloadB, l, &nLen);
                n = strlen(tnBuf);

#if DNS_AGGR == 1
                for (m = 0; m < dnsFlowP->pCnt; m++) {
                    if (!memcmp(dnsFlowP->pName[m], tnBuf, n)) break;
                }

                if (m == dnsFlowP->pCnt && m < DNS_ARECMXI) {
                    dnsFlowP->pCnt++;
                    T2_REALLOC(dnsFlowP->pName[m], n+1);
                    memcpy(dnsFlowP->pName[m], tnBuf, n);
                    dnsFlowP->pName[m][n] = '\0';
                }
#else // DNS_AGGR == 0
                if (j < DNS_ARECMXI) j++;
                T2_REALLOC(dnsFlowP->pName[j], n+1);
                memcpy(dnsFlowP->pName[j], tnBuf, n);
                dnsFlowP->pName[j][n] = '\0';
#endif // DNS_AGGR

                l += 16;
                if (l > sL7Len) goto errl;

#if DNS_AGGR == 1
                const uint32_t aTTL = ntohl(*(uint32_t*)(dnsPayloadB+l));
                for (m = 0; m < dnsFlowP->arnaaCnt; m++) {
                    if (dnsFlowP->aTTL[m] == aTTL) break;
                }

                if (m == dnsFlowP->arnaaCnt && m < DNS_ARECMXI) {
                    dnsFlowP->arnaaCnt++;
                    dnsFlowP->aTTL[m] = aTTL;
                }
#else // DNS_AGGR == 0
                dnsFlowP->aTTL[j] = ntohl(*(uint32_t*)(dnsPayloadB+l));
#endif // DNS_AGGR

                l += 4;
                break;
            }

            case DNS_MX: {
                k = 0;
                nLen = 0;

#if DNS_AGGR == 1
                const uint16_t dnsMXP = ntohs(*dnsPayload);
                for (m = 0; m < dnsFlowP->mxpCnt; m++) {
                    if (dnsFlowP->aAddr4[m] == dnsMXP) break;
                }

                if (m == dnsFlowP->mxpCnt && m < DNS_ARECMXI) {
                    dnsFlowP->mxpCnt++;
                    dnsFlowP->mxPref[m] = dnsMXP;
                }
#else // DNS_AGGR == 0
                dnsFlowP->mxPref[j] = ntohs(*dnsPayload);
#endif // DNS_AGGR

                l += 2;
                l = dns_parse(tnBuf, dnsLen, l, &k, dnsPayloadB, l, &nLen);
                n = strlen(tnBuf);

#if DNS_AGGR == 1
                for (m = 0; m < dnsFlowP->pCnt; m++) {
                    if (!memcmp(dnsFlowP->pName[m], tnBuf, n)) break;
                }

                if (m == dnsFlowP->pCnt && m < DNS_ARECMXI) {
                    dnsFlowP->pCnt++;
                    T2_REALLOC(dnsFlowP->pName[m], n+1);
                    memcpy(dnsFlowP->pName[m], tnBuf, n);
                    dnsFlowP->pName[m][n] = '\0';
                }
#else // DNS_AGGR == 0
                T2_REALLOC(dnsFlowP->pName[j], n+1);
                memcpy(dnsFlowP->pName[j], tnBuf, n);
                dnsFlowP->pName[j][n] = '\0';
#endif // DNS_AGGR == 1

                if (l > sL7Len) goto errl;
                break;
            }

            case DNS_TXT: {
                k = dnsPayloadB[l];
                if (recLen == k+1) l++;
                else k = recLen;
                if (l >= sL7Len) goto errl;
                const uint16_t tocopy = MIN(k, sL7Len - l);

#if DNS_AGGR == 1
                for (m = 0; m < dnsFlowP->pCnt; m++) {
                    if (!memcmp(dnsFlowP->pName[m], dnsPayloadB + l, k)) break;
                }

                if (m == dnsFlowP->pCnt && m < DNS_ARECMXI) {
                    dnsFlowP->pCnt++;
                    T2_REALLOC(dnsFlowP->pName[m], tocopy+1);
                    memcpy(dnsFlowP->pName[m], dnsPayloadB + l, tocopy);
                    dnsFlowP->pName[m][tocopy] = '\0';
                }
#else // DNS_AGGR == 0
                T2_REALLOC(dnsFlowP->pName[j], tocopy+1);
                memcpy(dnsFlowP->pName[j], dnsPayloadB + l, tocopy);
                dnsFlowP->pName[j][tocopy] = '\0';
#endif // DNS_AGGR == 1

                l += k;
                if (l > sL7Len) goto errl;
                break;
            }

            case DNS_AAAA: {
                const ipAddr_t aAddr6 = *(ipAddr_t*)(dnsPayload);
#if DNS_AGGR == 1
                for (m = 0; m < dnsFlowP->aAddr6Cnt; m++) {
                    if (dnsFlowP->aAddr6[m].IPv6L[0] == aAddr6.IPv6L[0] &&
                        dnsFlowP->aAddr6[m].IPv6L[1] == aAddr6.IPv6L[1])
                    {
                        break;
                    }
                }

                if (m == dnsFlowP->aAddr6Cnt && m < DNS_ARECMXI) {
                    dnsFlowP->aAddr6Cnt++;
                    dnsFlowP->aAddr6[m] = aAddr6;
                }
#else // DNS_AGGR == 0
                dnsFlowP->aAddr[j] = aAddr6;
#endif // DNS_AGGR == 1

                if (sPktFile) {
                    t2_ipv6_to_str(aAddr6.IPv6, ips, INET6_ADDRSTRLEN);
#if DNS_WHO == 0
                    fprintf(sPktFile,"%s;", ips);
#else // DNS_WHO == 1
#if IPV6_ACTIVATE > 0
                    const uint32_t netNum = subnet_testHL6((subnettable6_t*)subnetTableP[1], aAddr6);
                    const subnet6_t * const loP = &(((subnettable6_t*)subnetTableP[1])->subnets[netNum]);
                    fprintf(sPktFile,"%s_%s_%s;", ips, loP->loc, loP->org);
#else // IPV6_ACTIVATE == 0
                    fprintf(sPktFile,"%s_-_-;", ips);
#endif // IPV6_ACTIVATE
#endif // DNS_WHO
                }

                l += 16;
                break;
            }

            case DNS_SRV: {
                k = 0;
                nLen = 0;

#if DNS_AGGR == 1
                const uint16_t prio = ntohs(*(dnsPayload++));
                for (m = 0; m < dnsFlowP->pwpCnt; m++) {
                    if (dnsFlowP->srvPrio[m] == prio) break;
                }

                if (m == dnsFlowP->pwpCnt && m < DNS_ARECMXI) {
                    dnsFlowP->pwpCnt++;
                    dnsFlowP->srvPrio[m] = prio;
                    dnsFlowP->srvWeight[m] = ntohs(*(dnsPayload++));
                    dnsFlowP->srvPort[m] = ntohs(*(dnsPayload));
                }
#else // DNS_AGGR == 0
                dnsFlowP->srvPrio[j] = ntohs(*(dnsPayload++));
                dnsFlowP->srvWeight[j] = ntohs(*(dnsPayload++));
                dnsFlowP->srvPort[j] = ntohs(*(dnsPayload));
#endif // DNS_AGGR == 1

                l += 6;
                l = dns_parse(tnBuf, dnsLen, l, &k, dnsPayloadB, l, &nLen);
                n = strlen(tnBuf);

#if DNS_AGGR == 1
                for (m = 0; m < dnsFlowP->pCnt; m++) {
                    if (!memcmp(dnsFlowP->pName[m], tnBuf, n)) break;
                }

                if (m == dnsFlowP->pCnt && m < DNS_ARECMXI) {
                    dnsFlowP->pCnt++;
                    T2_REALLOC(dnsFlowP->pName[m], n+1);
                    memcpy(dnsFlowP->pName[m], tnBuf, n);
                    dnsFlowP->pName[m][n] = '\0';
                }
#else // DNS_AGGR == 0
                T2_REALLOC(dnsFlowP->pName[j], n+1);
                memcpy(dnsFlowP->pName[j], tnBuf, n);
                dnsFlowP->pName[j][n] = '\0';
#endif // DNS_AGGR

                if (l > sL7Len) goto errl;
                break;
            }

            case DNS_OPT: {
#if DNS_AGGR == 1
                const uint16_t dnsOPT = ntohl(*(uint32_t*)(dnsPayload-1));
                for (m = 0; m < dnsFlowP->optCnt; m++) {
                    if (dnsFlowP->optStat[m] == dnsOPT) break;
                }

                if (m == dnsFlowP->optCnt && m < DNS_ARECMXI) {
                    dnsFlowP->optCnt++;
                    dnsFlowP->optStat[m] = dnsOPT;
                    //dnsFlowP->aClass[m] = 0;
                    //dnsFlowP->aTTL[m] = 0;
                }
#else // DNS_AGGR == 0
                dnsFlowP->optStat[j] = ntohl(*(uint32_t*)(dnsPayload-1));
                dnsFlowP->aClass[j] = 0;
                dnsFlowP->aTTL[j] = 0;
#endif // DNS_AGGR

                /*n = ntohs(*dnsPayload);
                //T2_REALLOC(dnsFlowP->dnsOpt[dnsNRACnt], n+1);
                //memcpy(dnsFlowP->pName[dnsNRACnt], dnsPayloadB+l+4, n);
                dnsFlowP->pName[dnsNRACnt][n] = '\0';*/
                l += recLen;
                break;
            }

            case DNS_RRSIG:
            case NB:
                l += recLen;
                break;

            default:
                dnsFlowP->stat |= DNS_WRNIGN;
                l += recLen;

            /*  if (dnsNRACnt < DNS_ARECMXI) dnsNRACnt++;
                dnsFlowP->arnCnt = dnsNRACnt;
                dnsFlowP->nsCnt -= (i+1);
                goto early;
            */
                break;
        }
#if DNS_AGGR == 0
        if (j < DNS_ARECMXI) j++;
    }

    if (j < DNS_ARECMXI) dnsFlowP->arnCnt = j;
    else dnsFlowP->arnCnt = DNS_ARECMXI;
#else // DNS_AGGR == 1
    }
#endif // DNS_AGGR

#endif // DNS_MODE > 2

#if DNS_MODE > 3
#if DNS_AGGR== 0
    j = dnsFlowP->arnCnt;
    if (j > DNS_ARECMXI) {
        j = DNS_ARECMXI;
        dnsFlowP->arnCnt = DNS_ARECMXI;
        dnsFlowP->stat |= DNS_WRNAEX;
    }
#endif // DNS_AGGR == 0

    for (i = 0; i < arCnt && l+5 < dnsLen; i++) {
        k = 0;
        nLen = 0;

        if (!dnsPayloadB[l]) {
            l++;
        } else {
            l = dns_parse(tnBuf, dnsLen, l, &k, dnsPayloadB, l, &nLen);
            if (l > sL7Len) goto errl;
            n = strlen(tnBuf);

#if DNS_AGGR == 1
            for (m = 0; m < dnsFlowP->arnaCnt; m++) {
                if (!memcmp(dnsFlowP->aName[m], tnBuf, n)) break;
            }

            if (m == dnsFlowP->arnaCnt && m < DNS_ARECMXI) {
                dnsFlowP->arnaCnt++;
                T2_REALLOC(dnsFlowP->aName[m], n+1);
                memcpy(dnsFlowP->aName[m], tnBuf, n);
                dnsFlowP->aName[m][n] = '\0';
            }
#else // DNS_AGGR == 0
            T2_REALLOC(dnsFlowP->aName[j], n+1);
            memcpy(dnsFlowP->aName[j], tnBuf, n);
            dnsFlowP->aName[j][n] = '\0';
#endif // DNS_AGGR
        }

        dnsPayload = (uint16_t*)(dnsPayloadB + l);
        const uint16_t atype = ntohs(*dnsPayload++);

        if (atype < DNS_BF0) dnsFlowP->typeBF0 |= ((uint64_t)1 << atype);

#if DNS_HEXON == 1
        if (atype >= DNS_BF1) dnsFlowP->typeBF1 |= (1 << (atype - DNS_BF1));
        if (atype >= DNS_BF2) dnsFlowP->typeBF2 |= (1 << (atype - DNS_BF2));
        if (atype >= DNS_BF3) dnsFlowP->typeBF3 |= (1 << (atype - DNS_BF3));
#endif // DNS_HEXON == 1

             if (atype == DNS_AXFR)    dnsFlowP->stat |= DNS_ZTRANS;
        else if (atype == DNS_IXFR)    dnsFlowP->stat |= DNS_IZTRANS;
        else if (atype == DNS_ZONEALL) dnsFlowP->stat |= DNS_ANY;

#if DNS_AGGR == 1
        for (m = 0; m < dnsFlowP->arnatCnt; m++) {
            if (dnsFlowP->aType[m] == atype) break;
        }

        if (m == dnsFlowP->arnatCnt && m < DNS_ARECMXI) {
            dnsFlowP->arnatCnt++;
            dnsFlowP->aType[m] = atype;
        }
#else // DNS_AGGR == 0
        dnsFlowP->aType[j] = atype;
#endif // DNS_AGGR

        if (atype != DNS_OPT) {
            const uint16_t aClass = ntohs(*dnsPayload++);
            const uint16_t aTTL = ntohl(*(uint32_t*)dnsPayload++);

#if DNS_AGGR == 1
            for (m = 0; m < dnsFlowP->arnacCnt; m++) {
                if (dnsFlowP->aClass[m] == aClass) break;
            }

            if (m == dnsFlowP->arnacCnt && m < DNS_ARECMXI) {
                dnsFlowP->arnacCnt++;
                dnsFlowP->aClass[m] = aClass;
            }

            for (m = 0; m < dnsFlowP->arnaaCnt; m++) {
                if (dnsFlowP->aTTL[m] == aTTL) break;
            }

            if (m == dnsFlowP->arnaaCnt && m < DNS_ARECMXI) {
                dnsFlowP->arnaaCnt++;
                dnsFlowP->aTTL[m] = aTTL;
            }
#else // DNS_AGGR == 0
            dnsFlowP->aClass[j] = aClass;
            dnsFlowP->aTTL[j] = aTTL;
#endif // DNS_AGGR

            l += 10; // advance byte ptr to unit16_t ptr
        }

        if (l + 4 > dnsLen) {
#if DNS_AGGR == 0
            if (j < DNS_ARECMXI) j++;
#endif // DNS_AGGR == 0
            break;
        }

        dnsPayload++;
        recLen = ntohs(*dnsPayload++);

        switch (atype) {
            case DNS_A: {
                const uint32_t aAddr4 = *(uint32_t*)(dnsPayload);

#if DNS_AGGR == 1
                for (m = 0; m < dnsFlowP->aAddr4Cnt; m++) {
                    if (dnsFlowP->aAddr4[m] == aAddr4) break;
                }

                if (m == dnsFlowP->aAddr4Cnt && m < DNS_ARECMXI) {
                    dnsFlowP->aAddr4Cnt++;
                    dnsFlowP->aAddr4[m] = aAddr4;
                }
#else // DNS_AGGR == 0
                dnsFlowP->aAddr[j].IPv4x[0] = aAddr4;
#endif // DNS_AGGR == 1

                if (sPktFile) {
                    inet_ntop(AF_INET, &aAddr4, ips, INET_ADDRSTRLEN);
#if DNS_WHO == 0
                    fprintf(sPktFile,"%s;", ips);
#else // DNS_WHO == 1
#if (PV6_ACTIVATE == 2 || IPV6_ACTIVATE == 0)
                    const uint32_t netNum = subnet_testHL4((subnettable4_t*)subnetTableP[0], aAddr4);
                    const subnet4_t * const loP = &(((subnettable4_t*)subnetTableP[0])->subnets[netNum]);
                    fprintf(sPktFile,"%s_%s_%s;", ips, loP->loc, loP->org);
#else // IPV6_ACTIVATE == 1
                    fprintf(sPktFile,"%s_-_-;", ips);
#endif // (PV6_ACTIVATE == 2 || IPV6_ACTIVATE == 0)
#endif // DNS_WHO
                }

                l += 4;
                break;
            }

            case DNS_NS:
            case DNS_CNAME:
            case DNS_PTR: {
                k = 0;
                nLen = 0;
                l = dns_parse(tnBuf, dnsLen, l, &k, dnsPayloadB, l, &nLen);
                n = strlen(tnBuf);

#if DNS_AGGR == 1
                for (m = 0; m < dnsFlowP->pCnt; m++) {
                    if (!memcmp(dnsFlowP->pName[m], tnBuf, n)) break;
                }

                if (m == dnsFlowP->pCnt && m < DNS_ARECMXI) {
                    dnsFlowP->pCnt++;
                    T2_REALLOC(dnsFlowP->pName[m], n+1);
                    memcpy(dnsFlowP->pName[m], tnBuf, n);
                    dnsFlowP->pName[m][n] = '\0';
                }
#else // DNS_AGGR == 0
                T2_REALLOC(dnsFlowP->pName[j], n+1);
                memcpy(dnsFlowP->pName[j], tnBuf, n);
                dnsFlowP->pName[j][n] = '\0';
#endif // DNS_AGGR

                if (l > sL7Len) goto errl;
                break;
            }

            case DNS_SOA: {
                k = 0;
                nLen = 0;
                l = dns_parse(tnBuf, dnsLen, l, &k, dnsPayloadB, l, &nLen);
                n = strlen(tnBuf);

#if DNS_AGGR == 1
                for (m = 0; m < dnsFlowP->pCnt; m++) {
                    if (!memcmp(dnsFlowP->pName[m], tnBuf, n)) break;
                }

                if (m == dnsFlowP->pCnt && m < DNS_ARECMXI) {
                    dnsFlowP->pCnt++;
                    T2_REALLOC(dnsFlowP->pName[m], n+1);
                    memcpy(dnsFlowP->pName[m], tnBuf, n);
                    dnsFlowP->pName[m][n] = '\0';
                }
#else // DNS_AGGR == 0
                T2_REALLOC(dnsFlowP->pName[j], n+1);
                memcpy(dnsFlowP->pName[j], tnBuf, n);
                dnsFlowP->pName[j][n] = '\0';
#endif // DNS_AGGR

                if (l > sL7Len) goto errl;

                k = 0;
                nLen = 0;
                l = dns_parse(tnBuf, dnsLen, l, &k, dnsPayloadB, l, &nLen);
                n = strlen(tnBuf);

#if DNS_AGGR == 1
                for (m = 0; m < dnsFlowP->pCnt; m++) {
                    if (!memcmp(dnsFlowP->pName[m], tnBuf, n)) break;
                }

                if (m == dnsFlowP->pCnt && m < DNS_ARECMXI) {
                    dnsFlowP->pCnt++;
                    T2_REALLOC(dnsFlowP->pName[m], n+1);
                    memcpy(dnsFlowP->pName[m], tnBuf, n);
                    dnsFlowP->pName[m][n] = '\0';
                    //if (sPktFile) fprintf(sPktFile,"%s;", dnsFlowP->pName[m]);
                }
#else // DNS_AGGR == 0
                if (j < DNS_ARECMXI) j++;
                T2_REALLOC(dnsFlowP->pName[j], n+1);
                memcpy(dnsFlowP->pName[j], tnBuf, n);
                dnsFlowP->pName[j][n] = '\0';
#endif // DNS_AGGR

                l += 16;
                if (l > sL7Len) goto errl;

#if DNS_AGGR == 1
                const uint32_t aTTL = ntohl(*(uint32_t*)(dnsPayloadB+l));
                for (m = 0; m < dnsFlowP->arnaaCnt; m++) {
                    if (dnsFlowP->aTTL[m] == aTTL) break;
                }

                if (m == dnsFlowP->arnaaCnt && m < DNS_ARECMXI) {
                    dnsFlowP->arnaaCnt++;
                    dnsFlowP->aTTL[m] = aTTL;
                }
#else // DNS_AGGR == 0
                dnsFlowP->aTTL[j] = ntohl(*(uint32_t*)(dnsPayloadB+l));
#endif // DNS_AGGR

                l += 4;
                break;
            }

            case DNS_MX: {
                k = 0;
                nLen = 0;

#if DNS_AGGR == 1
                const uint16_t dnsMXP = ntohs(*dnsPayload);
                for (m = 0; m < dnsFlowP->mxpCnt; m++) {
                    if (dnsFlowP->aAddr4[m] == dnsMXP) break;
                }

                if (m == dnsFlowP->mxpCnt && m < DNS_ARECMXI) {
                    dnsFlowP->mxpCnt++;
                    dnsFlowP->mxPref[m] = dnsMXP;
                }
#else // DNS_AGGR == 0
                dnsFlowP->mxPref[j] = ntohs(*dnsPayload);
#endif // DNS_AGGR
                l += 2;
                l = dns_parse(tnBuf, dnsLen, l, &k, dnsPayloadB, l, &nLen);
                n = strlen(tnBuf);

#if DNS_AGGR == 1
                for (m = 0; m < dnsFlowP->pCnt; m++) {
                    if (!memcmp(dnsFlowP->pName[m], tnBuf, n)) break;
                }

                if (m == dnsFlowP->pCnt && m < DNS_ARECMXI) {
                    dnsFlowP->pCnt++;
                    T2_REALLOC(dnsFlowP->pName[m], n+1);
                    memcpy(dnsFlowP->pName[m], tnBuf, n);
                    dnsFlowP->pName[m][n] = '\0';
                }
#else // DNS_AGGR == 0
                T2_REALLOC(dnsFlowP->pName[j], n+1);
                memcpy(dnsFlowP->pName[j], tnBuf, n);
                dnsFlowP->pName[j][n] = '\0';
#endif // DNS_AGGR == 1

                if (l > sL7Len) goto errl;
                break;
            }

            case DNS_TXT: {
                k = dnsPayloadB[l];
                if (recLen == k+1) l++;
                else k = recLen;
                if (l >= sL7Len) goto errl;
                const uint16_t tocopy = MIN(k, sL7Len - l);

#if DNS_AGGR == 1
                for (m = 0; m < dnsFlowP->pCnt; m++) {
                    if (!memcmp(dnsFlowP->pName[m], dnsPayloadB + l, k)) break;
                }

                if (m == dnsFlowP->pCnt && m < DNS_ARECMXI) {
                    dnsFlowP->pCnt++;
                    T2_REALLOC(dnsFlowP->pName[m], tocopy+1);
                    memcpy(dnsFlowP->pName[m], dnsPayloadB + l, tocopy);
                    dnsFlowP->pName[m][tocopy] = '\0';
                }
#else // DNS_AGGR == 0
                T2_REALLOC(dnsFlowP->pName[j], tocopy+1);
                memcpy(dnsFlowP->pName[j], dnsPayloadB + l, tocopy);
                dnsFlowP->pName[j][tocopy] = '\0';
#endif // DNS_AGGR == 1

                l += k;
                if (l > sL7Len) goto errl;
                break;
            }

            case DNS_AAAA: {
                const ipAddr_t aAddr6 = *(ipAddr_t*)(dnsPayload);
#if DNS_AGGR == 1
                for (m = 0; m < dnsFlowP->aAddr6Cnt; m++) {
                    if (dnsFlowP->aAddr6[m].IPv6L[0] == aAddr6.IPv6L[0] &&
                        dnsFlowP->aAddr6[m].IPv6L[1] == aAddr6.IPv6L[1])
                    {
                        break;
                    }
                }

                if (m == dnsFlowP->aAddr6Cnt && m < DNS_ARECMXI) {
                    dnsFlowP->aAddr6Cnt++;
                    dnsFlowP->aAddr6[m] = aAddr6;
                }
#else // DNS_AGGR == 0
                dnsFlowP->aAddr[j] = aAddr6;
#endif // DNS_AGGR == 1

                if (sPktFile) {
                    t2_ipv6_to_str(aAddr6.IPv6, ips, INET6_ADDRSTRLEN);
#if DNS_WHO == 0
                    fprintf(sPktFile,"%s;", ips);
#else // DNS_WHO == 1
#if IPV6_ACTIVATE > 0
                    const uint32_t netNum = subnet_testHL6((subnettable6_t*)subnetTableP[1], aAddr6);
                    const subnet6_t * const loP = &(((subnettable6_t*)subnetTableP[1])->subnets[netNum]);
                    fprintf(sPktFile,"%s_%s_%s;", ips, loP->loc, loP->org);
#else // IPV6_ACTIVATE == 0
                    fprintf(sPktFile,"%s_-_-;", ips);
#endif // IPV6_ACTIVATE
#endif // DNS_WHO
                }

                l += 16;
                break;
            }

            case DNS_SRV: {
                k = 0;
                nLen = 0;

#if DNS_AGGR == 1
                const uint16_t prio = ntohs(*(dnsPayload++));
                for (m = 0; m < dnsFlowP->pwpCnt; m++) {
                    if (dnsFlowP->srvPrio[m] == prio) break;
                }

                if (m == dnsFlowP->pwpCnt && m < DNS_ARECMXI) {
                    dnsFlowP->pwpCnt++;
                    dnsFlowP->srvPrio[m] = prio;
                    dnsFlowP->srvWeight[m] = ntohs(*(dnsPayload++));
                    dnsFlowP->srvPort[m] = ntohs(*(dnsPayload));
                }
#else // DNS_AGGR == 0
                dnsFlowP->srvPrio[j] = ntohs(*(dnsPayload++));
                dnsFlowP->srvWeight[j] = ntohs(*(dnsPayload++));
                dnsFlowP->srvPort[j] = ntohs(*(dnsPayload));
#endif // DNS_AGGR == 1

                l += 6;
                l = dns_parse(tnBuf, dnsLen, l, &k, dnsPayloadB, l, &nLen);
                n = strlen(tnBuf);

#if DNS_AGGR == 1
                for (m = 0; m < dnsFlowP->pCnt; m++) {
                    if (!memcmp(dnsFlowP->pName[m], tnBuf, n)) break;
                }

                if (m == dnsFlowP->pCnt && m < DNS_ARECMXI) {
                    dnsFlowP->pCnt++;
                    T2_REALLOC(dnsFlowP->pName[m], n+1);
                    memcpy(dnsFlowP->pName[m], tnBuf, n);
                    dnsFlowP->pName[m][n] = '\0';
                }
#else // DNS_AGGR == 0
                T2_REALLOC(dnsFlowP->pName[j], n+1);
                memcpy(dnsFlowP->pName[j], tnBuf, n);
                dnsFlowP->pName[j][n] = '\0';
#endif // DNS_AGGR

                if (l > sL7Len) goto errl;
                break;
            }

            case DNS_OPT: {
#if DNS_AGGR == 1
                const uint16_t dnsOPT = ntohl(*(uint32_t*)(dnsPayload-1));
                for (m = 0; m < dnsFlowP->optCnt; m++) {
                    if (dnsFlowP->optStat[m] == dnsOPT) break;
                }

                if (m == dnsFlowP->optCnt && m < DNS_ARECMXI) {
                    dnsFlowP->optCnt++;
                    dnsFlowP->optStat[m] = dnsOPT;
                    //dnsFlowP->aClass[m] = 0;
                    //dnsFlowP->aTTL[m] = 0;
                }
#else // DNS_AGGR == 0
                dnsFlowP->optStat[j] = ntohl(*(uint32_t*)(dnsPayload-1));
                dnsFlowP->aClass[j] = 0;
                dnsFlowP->aTTL[j] = 0;
#endif // DNS_AGGR

                /*n = ntohs(*dnsPayload);
                //T2_REALLOC(dnsFlowP->dnsOpt[dnsNRACnt], n+1);
                //memcpy(dnsFlowP->pName[dnsNRACnt], dnsPayloadB+l+4, n);
                dnsFlowP->pName[dnsNRACnt][n] = '\0';*/
                l += recLen;
                break;
            }

            case DNS_RRSIG:
            case NB:
                l += recLen;
                break;

            default:
                dnsFlowP->stat |= DNS_WRNIGN;
                l += recLen;

            /*  if (araCnt < DNS_ARECMXI) araCnt++;
                dnsFlowP->arnCnt = araCnt;
                dnsFlowP->arCnt -= (i+1);
                goto early;
            */
                break;
        }
#if DNS_AGGR == 0
        if (j < DNS_ARECMXI) j++;
    }

    if (j < DNS_ARECMXI) dnsFlowP->arnCnt = j;
    else dnsFlowP->arnCnt = DNS_ARECMXI;
#else // DNS_AGGR == 1
    }
#endif // DNS_AGGR

#endif // DNS_MODE > 3

#if FORCE_MODE == 1
    if (dnsFlowP->stat & (DNS_WRNDEX | DNS_WRNAEX)) {
        flow_t * const flowP = &flows[flowIndex];
        T2_RM_FLOW(flowP);
    }
#endif // FORCE_MODE == 1

    goto early;

#if DNS_MODE > 0
// Error Handling
errl:
    dnsFlowP->stat |= DNS_ERRLEN;

    //if (l == 65531) dnsFlowP->stat |= DNS_ERRLEN;
    if (l == 65532) dnsFlowP->stat |= DNS_ERRPTR;
#endif // DNS_MODE > 0

early: // Packet mode
    if (sPktFile) {
        if (dnsFlowP->stat & DNS_PRTDT) {
            fprintf(sPktFile,
                                                                   /* dnsIPs               */ SEP_CHR
                    "0x%04" B2T_PRIX16                             /* dnsStat              */ SEP_CHR
#if DNS_HDRMD == 0
                    "0x%04" B2T_PRIX16                             /* dnsHdr               */ SEP_CHR
#elif DNS_HDRMD == 1
                    "0x%02" B2T_PRIX8 "_%" PRIu16 "_%" PRIu16      /* dnsHFlg_OpC_RetC     */ SEP_CHR
#else // DNS_HDRMD > 1
                    "0x%02" B2T_PRIX8 "_%s_%s"                     /* dnsHFlg_OpN_RetN     */ SEP_CHR
#endif // DNS_HDRMD
                    "%" PRIu16 "_%" PRIu16 "_%" PRIu16 "_%" PRIu16 /* dnsCntQu_Asw_Aux_Add */ SEP_CHR
                    , dnsFlowP->stat,
#if DNS_HDRMD == 0
                      u,
#elif DNS_HDRMD == 1
                      dnsFlags, opCode, rCode,
#else // DNS_HDRMD > 1
                      dnsFlags,
                      (dnsFlowP->stat & DNS_NBIOS) ? opcoden[opCode] : opcoded[opCode],
                      (dnsFlowP->stat & DNS_NBIOS) ? rcoded[rCode]   : rcoden[rCode],
#endif // DNS_HDRMD
                      qnCnt, anCnt, nsCnt, arCnt);
        } else {
            fputs(          /* dnsIPs                                   */ SEP_CHR
                  "0x0000"  /* dnsStat                                  */ SEP_CHR
                            /* dnsHdr/dnsHFlg_OpC_RetC/dnsHFlg_OpN_RetN */ SEP_CHR
                  "0_0_0_0" /* dnsCntQu_Asw_Aux_Add                     */ SEP_CHR
                  , sPktFile);
        }
    }
}


void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {
#if (DNS_HDRMD > 0 || DNS_MODE > 0 || DNS_MAL_TEST == 1)
    uint_fast32_t i;
    uint32_t j;
#endif // (DNS_HDRMD > 0 || DNS_MODE > 0 || DNS_MAL_TEST == 1)

    dnsFlow_t * const dnsFlowP = &dnsFlow[flowIndex];

    dnsStat |= dnsFlowP->stat;
    dnsOpC  |= dnsFlowP->opCodeBF;
    dnsRetC |= dnsFlowP->rCodeBF;
    dnsHFlg |= dnsFlowP->hFlagsBF;

#if DNS_MAL_TEST == 1
    uint32_t numAF = 0;
#if DNS_MAL_DOMAIN == 1
    uint32_t malcode[DNS_QRECMAX] = {};
#if DNS_AGGR == 1
    j = dnsFlowP->qrnaCnt;
#else // DNS_AGGR == 0
    j = dnsFlowP->qrnCnt;
#endif // DNS_AGGR
    if (j >= DNS_QRECMXI) j = DNS_QRECMAX;
#else // DNS_MAL_DOMAIN == 0
    uint32_t malcode[DNS_ARECMAX] = {};
#if DNS_AGGR == 1
    j = dnsFlowP->arnaCnt;
#else // DNS_AGGR == 0
    j = dnsFlowP->arnCnt;
#endif // DNS_AGGR
    if (j >= DNS_ARECMXI) j = DNS_ARECMAX;
#endif // DNS_MAL_DOMAIN

    for (i = 0; i < j; i++) {
#if DNS_MAL_DOMAIN == 1
        malcode[i] = maldomain_test(malsite_table, dnsFlowP->qName[i]);
#elif DNS_AGGR == 0 // && DNS_MAL_DOMAIN == 0
        malcode[i] = malip_test(malsite_table, dnsFlowP->aAddr[i]);
#endif // DNS_MAL_DOMAIN
        if (malcode[i]) numAF++;
    }

    if (numAF) {
        dnsAlarms += numAF;
        dnsAlarmFlows++;
        T2_SET_STATUS(&flows[flowIndex], FL_ALARM);
        T2_REPORT_ALARMS(numAF);
    }

#elif DNS_MAL_TEST > 1
    if (dnsFlowP->numAF) {
        dnsAlarms += dnsFlowP->numAF;
        dnsAlarmFlows++;
        T2_REPORT_ALARMS(dnsFlowP->numAF);
    }
#endif // DNS_MAL_TEST

    OUTBUF_APPEND_U16(buf, dnsFlowP->stat);       // dnsStat
    OUTBUF_APPEND_U16(buf, dnsFlowP->hdrOPField); // dnsHdrOPField

    // dnsHFlg_OpC_RetC / dnsHFlg, dnsOpC / dnsOpN, dnsRetC / dnsRetN
    OUTBUF_APPEND_U8(buf , dnsFlowP->hFlagsBF); // dnsHFlg

#if DNS_HDRMD == 0
    // dnsHFlg_OpC_RetC
    OUTBUF_APPEND_U16(buf, dnsFlowP->opCodeBF); // dnsOpC
    OUTBUF_APPEND_U16(buf, dnsFlowP->rCodeBF);  // dnsRetC
#else // DNS_HDRMD > 0
    j = dnsFlowP->opCodeCnt;
    OUTBUF_APPEND_NUMREP(buf, j);
    for (i = 0; i < j; i++) {
#if DNS_HDRMD == 1
        OUTBUF_APPEND_U8(buf , dnsFlowP->opCode[i]);  // dnsOpC
#else // DNS_HDRMD > 1
        // dnsOpN
        if (dnsFlowP->stat & DNS_NBIOS) {
            OUTBUF_APPEND_STR(buf, opcoden[dnsFlowP->opCode[i]]); // dnsOpN
        } else {
            OUTBUF_APPEND_STR(buf, opcoded[dnsFlowP->opCode[i]]); // dnsOpN
        }
#endif // DNS_HDRMD > 1
    }

    j = dnsFlowP->rCodeCnt;
    OUTBUF_APPEND_NUMREP(buf, j);
    for (i = 0; i < j; i++) {
#if DNS_HDRMD == 1
        OUTBUF_APPEND_U8(buf , dnsFlowP->rCode[i]); // dnsRetC
#else // DNS_HDRMD > 1
        // dnsRetN
        if (dnsFlowP->stat & DNS_NBIOS) {
            OUTBUF_APPEND_STR(buf, rcoden[dnsFlowP->rCode[i]]); // dnsRetN
        } else {
            OUTBUF_APPEND_STR(buf, rcoded[dnsFlowP->rCode[i]]); // dnsRetN
        }
#endif // DNS_HDRMD > 1
    }
#endif // DNS_HDRMD > 0

    // dnsCntQu_Asw_Aux_Add
    OUTBUF_APPEND_U16(buf, dnsFlowP->qnaCnt);
    OUTBUF_APPEND_U16(buf, dnsFlowP->anaCnt);
    OUTBUF_APPEND_U16(buf, dnsFlowP->nsaCnt);
    OUTBUF_APPEND_U16(buf, dnsFlowP->araCnt);

    // dnsAAAqF
    const float f = (dnsFlowP->qaLen != 0) ? dnsFlowP->aaLen / (float)dnsFlowP->qaLen : 0.0f;
    OUTBUF_APPEND_FLT(buf, f);

#if DNS_MODE > 0
    char *p;

#if DNS_HEXON == 1
    // dnsTypeBF3_BF2_BF1_BF0
    OUTBUF_APPEND_U8(buf , dnsFlowP->typeBF3);
    OUTBUF_APPEND_U16(buf, dnsFlowP->typeBF2);
    OUTBUF_APPEND_U16(buf, dnsFlowP->typeBF1);
    OUTBUF_APPEND_U64(buf, dnsFlowP->typeBF0);
#endif // DNS_HEXON == 1

#if DNS_AGGR== 1
    j = dnsFlowP->qrnaCnt;
#else // DNS_AGGR== 0
    j = dnsFlowP->qrnCnt;
#endif // DNS_AGGR
    if (j >= DNS_QRECMXI) j = DNS_QRECMAX;

    // dnsQname
    OUTBUF_APPEND_NUMREP(buf, j);
    for (i = 0; i < j; i++) {
        p = dnsFlowP->qName[i];
        if (p) {
            if (dnsFlowP->stat & DNS_NBIOS) {
                OUTBUF_APPEND_NBNS_STR(buf, p);
            } else {
                OUTBUF_APPEND_STR(buf, p);
            }
            free(p);
        } else { // !p
            OUTBUF_APPEND_STR_EMPTY(buf);
        }
    }

#if (DNS_MAL_TEST > 0 && DNS_MAL_DOMAIN == 1)
    malsite_t *malsiteP = malsite_table->malsites;

    // dnsMalCnt
#if DNS_MAL_TEST == 1
    OUTBUF_APPEND_U32(buf, numAF);
#else // DNS_MAL_TEST > 1
    OUTBUF_APPEND_U32(buf, dnsFlowP->numAF);
#endif // DNS_MAL_TEST

    // dnsMalType/dnsMalCode
    OUTBUF_APPEND_NUMREP(buf, j);
    for (i = 0; i < j; i++) {
#if DNS_MAL_TYPE == 1
        // dnsMalType
#if DNS_MAL_TEST == 1
        OUTBUF_APPEND_STR(buf, malsiteP[malcode[i]].malTyp);
#else // DNS_MAL_TEST > 1
        OUTBUF_APPEND_STR(buf, malsiteP[dnsFlowP->malcode[i]].malTyp);
#endif // DNS_MAL_TEST
#else // DNS_MAL_TYPE == 0
        // dnsMalCode
#if DNS_MAL_TEST == 1
        OUTBUF_APPEND_U32(buf, malsiteP[malcode[i]].malId);
#else // DNS_MAL_TEST > 1
        OUTBUF_APPEND_U32(buf, malsiteP[dnsFlowP->malcode[i]].malId);
#endif // DNS_MAL_TEST
#endif // DNS_MAL_TYPE
    }

#endif // (DNS_MAL_TEST > 0 && DNS_MAL_DOMAIN == 1)

#if DNS_AGGR == 0
    j = dnsFlowP->arnCnt;
#elif DNS_AGGR== 1
    j = dnsFlowP->arnaCnt;
#endif // DNS_AGGR == 1
    if (j >= DNS_ARECMXI) j = DNS_ARECMAX;

    // dnsAname
    OUTBUF_APPEND_NUMREP(buf, j);
    for (i = 0; i < j; i++) {
        p = dnsFlowP->aName[i];
        if (p) {
            if (dnsFlowP->stat & DNS_NBIOS) {
                OUTBUF_APPEND_NBNS_STR(buf, p);
            } else {
                OUTBUF_APPEND_STR(buf, p);
            }
            free(p);
        } else { // !p
            OUTBUF_APPEND_STR_EMPTY(buf);
        }
    }

#if DNS_AGGR == 1
    j = dnsFlowP->pCnt;
    if (j >= DNS_ARECMXI) j = DNS_ARECMAX;
#endif // DNS_AGGR == 1

    // dnsAPname
    OUTBUF_APPEND_NUMREP(buf, j);
    for (i = 0; i < j; i++) {
        p = dnsFlowP->pName[i];
        if (p) {
            OUTBUF_APPEND_STR(buf, p);
            free(p);
        } else { // !p
            OUTBUF_APPEND_STR_EMPTY(buf);
        }
    }

    if (dnsFlowP->typeBF0 & DNS_HOST_B) {
#if DNS_AGGR == 1
        j = dnsFlowP->aAddr4Cnt;
        if (j >= DNS_ARECMXI) j = DNS_ARECMAX;
#endif // DNS_AGGR == 1
    } else { // !(dnsFlowP->typeBF0 & DNS_HOST_B)
        j = 0;
    }

    // dns4Aaddress
    OUTBUF_APPEND_NUMREP(buf, j);
    for (i = 0; i < j; i++) {
#if DNS_AGGR == 1
        OUTBUF_APPEND_U32(buf, dnsFlowP->aAddr4[i]);
#else // DNS_AGGR == 0
        if (dnsFlowP->aType[i] == DNS_A) {
            OUTBUF_APPEND_U32(buf, dnsFlowP->aAddr[i].IPv4x[0]);
        } else {
            OUTBUF_APPEND_U32_ZERO(buf);
        }
#endif // DNS_AGGR
    }

#if DNS_WHO == 1
    uint32_t netNum;
    char *loc, *org;

    // dns4CC_Org
    OUTBUF_APPEND_NUMREP(buf, j);
    for (i = 0; i < j; i++) {
#if DNS_AGGR == 1
#if IPV6_ACTIVATE != 1
            netNum = subnet_testHL4((subnettable4_t*)subnetTableP[0], dnsFlowP->aAddr4[i]);
#else // IPV6_ACTIVATE == 1
            netNum = 0;
#endif // IPV6_ACTIVATE
#else // DNS_AGGR == 0
        if (dnsFlowP->aType[i] == DNS_A) {
            SUBNET_TEST_IP4(netNum, dnsFlowP->aAddr[i]); // subnet test on dnsAddress
#endif // DNS_AGGR
            SUBNET_LOC(loc, 4, netNum);  // get country for IP
            SUBNET_ORG(org, 4, netNum);  // get organization for IP
            OUTBUF_APPEND_STR(buf, loc);
            OUTBUF_APPEND_STR(buf, org);
#if DNS_AGGR == 0
        } else { // dnsFlowP->aType[i] != DNS_A
            OUTBUF_APPEND_STR_EMPTY(buf);
            OUTBUF_APPEND_STR_EMPTY(buf);
        }
#endif // DNS_AGGR
    }
#endif // DNS_WHO == 1

    if (dnsFlowP->typeBF0 & DNS_AAAA_B) {
#if DNS_AGGR == 1
        j = dnsFlowP->aAddr6Cnt;
        if (j >= DNS_ARECMXI) j = DNS_ARECMAX;
#endif // DNS_AGGR == 1
    } else { // !(dnsFlowP->typeBF0 & DNS_AAAA_B)
        j = 0;
    }

    // dns6Aaddress
#if DNS_AGGR == 0
#endif // DNS_AGGR
    OUTBUF_APPEND_NUMREP(buf, j);
    for (i = 0; i < j; i++) {
#if DNS_AGGR == 1
        OUTBUF_APPEND_IP6(buf, dnsFlowP->aAddr6[i]);
#else // DNS_AGGR == 0
        if (dnsFlowP->aType[i] == DNS_AAAA) {
            OUTBUF_APPEND_IP6(buf, dnsFlowP->aAddr[i]);
        } else {
            OUTBUF_APPEND_IP6_ZERO(buf);
        }
#endif // DNS_AGGR
    }

#if DNS_WHO == 1
    // dns6CC_Org
    OUTBUF_APPEND_NUMREP(buf, j);
    for (i = 0; i < j; i++) {
#if DNS_AGGR == 1
        SUBNET_TEST_IP6(netNum, dnsFlowP->aAddr6[i]); // subnet test on dnsAddress
#else // DNS_AGGR == 0
        if (dnsFlowP->aType[i] == DNS_AAAA) {
            SUBNET_TEST_IP6(netNum, dnsFlowP->aAddr[i]); // subnet test on dnsAddress
#endif // DNS_AGGR
            SUBNET_LOC(loc, 6, netNum);  // get country for IP
            SUBNET_ORG(org, 6, netNum);  // get organization for IP
            OUTBUF_APPEND_STR(buf, loc);
            OUTBUF_APPEND_STR(buf, org);
#if DNS_AGGR == 0
        } else { // dnsFlowP->aType[i] != DNS_AAAA
            OUTBUF_APPEND_STR_EMPTY(buf);
            OUTBUF_APPEND_STR_EMPTY(buf);
        }
#endif // DNS_AGGR == 0
    }
#endif // DNS_WHO == 1

    // dnsIPMalCode
#if (DNS_MAL_TEST > 0 && DNS_MAL_DOMAIN == 0)
#if DNS_MAL_TEST == 1
    OUTBUF_APPEND_ARRAY_U32(buf, malcode, j);
#else // DNS_MAL_TEST > 1
    OUTBUF_APPEND_ARRAY_U32(buf, dnsFlowP->malcode, j);
#endif // DNS_MAL_TEST
#endif // (DNS_MAL_TEST > 0 && DNS_MAL_DOMAIN == 0)

#if DNS_AGGR== 1
    j = dnsFlowP->qrnaCnt;
#else // DNS_AGGR== 0
    j = dnsFlowP->qrnCnt;
#endif // DNS_AGGR
    if (j >= DNS_QRECMXI) j = DNS_QRECMAX;

#if DNS_TYPE == 1
    const char *tp;
    const char * const n = "NIL";
    OUTBUF_APPEND_NUMREP(buf, j);
    for (i = 0; i < j; i++) {
        const uint16_t k = dnsFlowP->qType[i];
             if (k <= DNS_CSYNC)                  tp = (char*)dnsTypeN[k];
        else if (k >= DNS_SPF  && k <= DNS_EUI64) tp = (char*)dnsTypeN63[k-DNS_SPF];
        else if (k >= DNS_TKEY && k <= DNS_CAA)   tp = (char*)dnsTypeNF9[k-DNS_TKEY];
        else if (k >= DNS_TA   && k <= DNS_DLV)   tp = (char*)dnsTypeN8000[k-DNS_TA];
        else                                      tp = n;
        OUTBUF_APPEND_STR(buf, tp); // dnsQTypeN
    }
#else // DNS_TYPE == 0
    OUTBUF_APPEND_ARRAY_U16(buf, dnsFlowP->qType, j); // dnsQType
#endif // DNS_TYPE

    // dnsQClass
    OUTBUF_APPEND_NUMREP(buf, j);
    for (i = 0; i < j; i++) {
        const uint16_t cls = (dnsFlowP->qClass[i] & 0x7fff);
        OUTBUF_APPEND_U16(buf, cls);
    }

#if DNS_AGGR == 0
    j = dnsFlowP->arnCnt;
#elif DNS_AGGR == 1
    j = dnsFlowP->arnatCnt;
#endif // DNS_AGGR == 1
    if (j >= DNS_ARECMXI) j = DNS_ARECMAX;

#if DNS_TYPE == 1
    OUTBUF_APPEND_NUMREP(buf, j);
    for (i = 0; i < j; i++) {
        const uint16_t k = dnsFlowP->aType[i];
             if (k <= DNS_CSYNC)                  tp = (char*)dnsTypeN[k];
        else if (k >= DNS_SPF  && k <= DNS_EUI64) tp = (char*)dnsTypeN63[k-DNS_SPF];
        else if (k >= DNS_TKEY && k <= DNS_CAA)   tp = (char*)dnsTypeNF9[k-DNS_TKEY];
        else if (k >= DNS_TA   && k <= DNS_DLV)   tp = (char*)dnsTypeN8000[k-DNS_TA];
        else                                      tp = n;
        OUTBUF_APPEND_STR(buf, tp); // dnsATypeN
    }
#else // DNS_TYPE == 0
    OUTBUF_APPEND_ARRAY_U16(buf, dnsFlowP->aType, j); // dnsAType
#endif // DNS_TYPE

#if DNS_AGGR == 1
    j = dnsFlowP->arnacCnt;
    if (j >= DNS_ARECMXI) j = DNS_ARECMAX;
#endif // DNS_AGGR == 1

    // dnsAClass
    OUTBUF_APPEND_NUMREP(buf, j);
    for (i = 0; i < j; i++) {
        const uint16_t cls = (dnsFlowP->aClass[i] & 0x7fff);
        OUTBUF_APPEND_U16(buf, cls);
    }

#if DNS_AGGR == 1
    j = dnsFlowP->arnaaCnt;
    if (j >= DNS_ARECMXI) j = DNS_ARECMAX;
#endif // DNS_AGGR == 1
    OUTBUF_APPEND_ARRAY_U32(buf, dnsFlowP->aTTL, j); // dnsATTL

#if DNS_AGGR == 1
    j = dnsFlowP->mxpCnt;
    if (j >= DNS_ARECMXI) j = DNS_ARECMAX;
#endif // DNS_AGGR == 1
    OUTBUF_APPEND_ARRAY_U16(buf, dnsFlowP->mxPref, j); // dnsMXPref

#if DNS_AGGR == 1
    j = dnsFlowP->pwpCnt;
    if (j >= DNS_ARECMXI) j = DNS_ARECMAX;
#endif // DNS_AGGR == 1

    OUTBUF_APPEND_ARRAY_U16(buf, dnsFlowP->srvPrio  , j); // dnsSRVprio
    OUTBUF_APPEND_ARRAY_U16(buf, dnsFlowP->srvWeight, j); // dnsSRVwgt
    OUTBUF_APPEND_ARRAY_U16(buf, dnsFlowP->srvPort  , j); // dnsSRVprt

#if DNS_AGGR == 1
    j = dnsFlowP->optCnt;
    if (j >= DNS_ARECMXI) j = DNS_ARECMAX;
#endif // DNS_AGGR == 1
    OUTBUF_APPEND_ARRAY_U32(buf, dnsFlowP->optStat, j); // dnsOptStat
#endif // DNS_MODE > 0
}


static inline void dns_pluginReport(FILE *stream) {
    if (dnsStat) {
        T2_FPLOG_AGGR_HEX0(stream, plugin_name, dnsStat);
        T2_FPLOG_AGGR_HEX(stream, plugin_name, dnsHFlg);
        T2_FPLOG_AGGR_HEX(stream, plugin_name, dnsOpC);
        T2_FPLOG_AGGR_HEX(stream, plugin_name, dnsRetC);
        T2_FPLOG_DIFFNUMP0(stream, plugin_name, "Number of DNS packets", totalDnsPktCnt, numPackets);
        T2_FPLOG_DIFFNUMP(stream, plugin_name, "Number of DNS Q packets", totalDnsQPktCnt, totalDnsPktCnt);
        T2_FPLOG_DIFFNUMP(stream, plugin_name, "Number of DNS R packets", totalDnsRPktCnt, totalDnsPktCnt);
#if DNS_MAL_TEST > 0
        if (dnsAlarms) {
            char hrnum1[64], hrnum2[64];
            T2_CONV_NUM(dnsAlarms, hrnum1);
            T2_CONV_NUM(dnsAlarmFlows, hrnum2);
            T2_FPWRN_NP(stream, plugin_name, "%" PRIu64 "%s alarms in %" PRIu64 "%s flows [%.2f%%]", dnsAlarms, hrnum1, dnsAlarmFlows, hrnum2, 100.0 * (dnsAlarmFlows / totalFlows));
        }
#endif // DNS_MAL_TEST > 0
    }
}


void t2PluginReport(FILE *stream) {
#if DIFF_REPORT == 1
    totalDnsPktCnt0 = 0;
    totalDnsQPktCnt0 = 0;
    totalDnsRPktCnt0 = 0;
#endif // DIFF_REPORT == 1
    dns_pluginReport(stream);
}


void t2Monitoring(FILE *stream, uint8_t state) {

    switch (state) {

        case T2_MON_PRI_HDR:
            fputs("dnsPkts"  SEP_CHR
                  "dnsQPkts" SEP_CHR
                  "dnsRPkts" SEP_CHR
                  , stream);
            return;

        case T2_MON_PRI_VAL:
            fprintf(stream,
                    "%" PRIu64 /* dsnPkts  */ SEP_CHR
                    "%" PRIu64 /* dsnQPkts */ SEP_CHR
                    "%" PRIu64 /* dsnRPkts */ SEP_CHR
                    , totalDnsPktCnt  - totalDnsPktCnt0
                    , totalDnsQPktCnt - totalDnsQPktCnt0
                    , totalDnsRPktCnt - totalDnsRPktCnt0);
            break;

        case T2_MON_PRI_REPORT:
            dns_pluginReport(stream);
            break;

        // Invalid state, do nothing
        default:
            return;
    }

#if DIFF_REPORT == 1
    totalDnsPktCnt0 = totalDnsPktCnt;
    totalDnsQPktCnt0 = totalDnsQPktCnt;
    totalDnsRPktCnt0 = totalDnsRPktCnt;
#endif // DIFF_REPORT == 1
}


void t2Finalize() {
#if DNS_MAL_TEST == 1
    malsite_destroy(malsite_table);
#endif // DNS_MAL_TEST == 1

    free(dnsFlow);
}


#if DNS_MODE > 0
static inline uint16_t dns_parse(char *dnsName, uint16_t len, uint16_t l, uint16_t *kp, const uint8_t *dnsPayloadB, uint16_t lb, const uint16_t *nLenp) {
    int mxlen, n;
    uint16_t j, u;
    uint8_t sw = 1;

    if (l+1 > len) return 65531;

    uint16_t k = *kp;

    if (!dnsPayloadB[l]) {
        if (k > 0 && dnsName[k - 1] == '.') {
            dnsName[k - 1] = '\0';
        } else {
            dnsName[k] = '\0';
        }
        return ++l;
    }

    uint16_t nLen = *nLenp;

    while (1) {
        if (l + 1 >= len || l < DNS_RSTART) {
            l = 65530; // ++l -> 65531
            break;
        }
        j = *(uint16_t*)(dnsPayloadB+l);
        if (j & DNS_PTRN) {
            if ((j & DNS_PTRN) == DNS_PTRN) {
                u = ntohs(j & DNS_PTRVN);
                if (u >= l || u > len) goto ptrerr;
                dns_parse(dnsName, len, u, &k, dnsPayloadB, l, &nLen);
                *kp = k;
                return l + 2;
            } else {
ptrerr:
                l = 65531; // ++l -> 65532
                break;
            }
        } else {
            mxlen = l + dnsPayloadB[l];
            nLen += dnsPayloadB[l];
            if (nLen > DNS_MXNAME || mxlen + 1 == lb) sw = 0;

            n = k + dnsPayloadB[l] - DNS_HNLMAX;
            if (n > 0) mxlen -= (n+1);

            if (mxlen > len) {
                mxlen = len;
                sw = 0;
            }

            for (j = l + 1; j <= mxlen; j++) {
                dnsName[k++] = dnsPayloadB[j];
            }

            if (sw) {
                l += dnsPayloadB[l] + 1;
            } else {
                l = 65530; // ++l -> 65531
                break;
            }

            if (dnsPayloadB[l] == '\0' || l >= len) break;

            if (n <= 0) dnsName[k++] = '.';
        }
    }

    dnsName[k] = '\0';
    *kp = k;

    return ++l;
}
#endif // DNS_MODE > 0
