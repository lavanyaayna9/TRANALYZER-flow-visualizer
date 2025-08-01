/*
 * tp0f.c
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

#include "tp0f.h"

#include <stdio.h>      // for FILE
#include <stdlib.h>     // for free, exit, NULL
#include <string.h>     // for strlen, memcmp, memset

#include "t2Plugin.h"
#include "tp0flist.h"   // for tp0flist_table_t, tp0flist_table_create, tp0flist_table_free, TCPOPTMAX


// plugin variables

tp0fFlow_t *tp0fFlows;


// Static variables

#if TP0FRULES == 1
static uint64_t numFgpIP;
static tp0flist_table_t *tp0flist_table;
#if TP0FHSH == 1
static hashMap_t *ipP0fHashMap;
static uint32_t *ipP0fClass;
static uint8_t tp0fAStat;
#endif // TP0FHSH == 1
#endif // TP0FRULES == 1
static uint8_t tp0fStat;

static const char * const osCl[] = {
    "!", "win", "unix", "other"
};

static const char * const progCl[] = {
    "unknown", "Windows", "Linux", "OpenBSD", "FreeBSD",
    "Solaris", "MacOSX" , "HP-UX", "OpenVMS", "iOS",
    "BaiduSpider", "Blackberry", "NeXTSTEP", "Nintendo",
    "NMap", "tp0f", "Tru64"
};

static const char * const verCl[] = {
    "unknown", "NT", "XP", "7", "8", "10",
    "10.9 or newer (sometimes iPhone or iPad)",
    "10.x", "11.x", "2.0", "2.2.x", "2.2.x-3.x",
    "2.2.x-3.x (barebone)", "2.2.x-3.x (no timestamps)",
    "2.2.x (loopback)", "2.4-2.6", "2.4.x", "2.4.x-2.6.x",
    "2.4.x (loopback)", "2.6.x", "2.6.x (Google crawler)",
    "2.6.x (loopback)", "3.11 and newer", "3.1-3.10", "3DS",
    "3.x", "3.x (loopback)", "4.x", "4.x-5.x", "5.x", "6",
    "7 or 8", "7 (Websense crawler)", "7.x", "8", "8.x",
    "8.x-9.x", "9.x", "9.x or newer", "(Android)",
    "iPhone or iPad", "NT kernel", "NT kernel 5.x",
    "NT kernel 6.x", "OS detection", "sendsyn utility",
    "SYN scan", "Wii", "Arch 5.0+", "Kali 5.0+", "Ubuntu 22.04+"
};


// Tranalyzer functions

T2_PLUGIN_INIT("tp0f", "0.9.3", 0, 9);


void t2Init() {
    T2_PLUGIN_STRUCT_NEW(tp0fFlows);

#if TP0FRULES == 1
    t2_env_t env[ENV_TP0F_N] = {};
#if ENVCNTRL > 0
    t2_get_env(PLUGIN_SRCH, ENV_TP0F_N, env);
#else // ENVCNTRL == 0
    T2_SET_ENV_STR(TP0F_L34FILE);
#endif // ENVCNTRL

    char filename[MAX_FILENAME_LEN];
    t2_build_filename(filename, sizeof(filename), pluginFolder, T2_ENV_VAL(TP0F_L34FILE), NULL);
    if (UNLIKELY(!(tp0flist_table = tp0flist_table_create(filename)))) {
        free(tp0fFlows);
        exit(EXIT_FAILURE);
    }

#if TP0FHSH == 1
#if IPV6_ACTIVATE == 2
    ipP0fHashMap = hashTable_init(1.0f, sizeof(ipVAddr_t), plugin_name);
#elif IPV6_ACTIVATE == 1
    ipP0fHashMap = hashTable_init(1.0f, sizeof(ipAddr_t), plugin_name);
#else // IPV6_ACTIVATE == 0
    ipP0fHashMap = hashTable_init(1.0f, sizeof(uint32_t), plugin_name);
#endif // IPV6_ACTIVATE

    ipP0fClass = t2_calloc_fatal(ipP0fHashMap->hashChainTableSize, sizeof(uint32_t));
#endif // TP0FHSH == 1

#if ENVCNTRL > 0
    t2_free_env(ENV_TP0F_N, env);
#endif // ENVCNTRL > 0
#endif // TP0FRULES == 1

    if (sPktFile) fputs("tp0fStat"    SEP_CHR
                        "tp0fDis"     SEP_CHR
                        //"tp0fClName" SEP_CHR
                        "tp0fPrName"  SEP_CHR
                        "tp0fVerName" SEP_CHR
                        , sPktFile);
}


binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;

    BV_APPEND_H8(bv  , "tp0fStat"   , "tp0f status");
    BV_APPEND_U8(bv  , "tp0fDis"    , "tp0f TTL distance");

#if TP0FRC == 1
    BV_APPEND_U16(bv , "tp0fRN"     , "tp0f rule number");
    BV_APPEND_U8(bv  , "tp0fClass"  , "tp0f class");
    BV_APPEND_U8(bv  , "tp0fProg"   , "tp0f program");
    BV_APPEND_U8(bv  , "tp0fVer"    , "tp0f version");
#endif // TP0FRC == 1

    BV_APPEND_STRC(bv, "tp0fClName" , "tp0f OS class name");
    BV_APPEND_STRC(bv, "tp0fPrName" , "tp0f OS/program name");
    BV_APPEND_STRC(bv, "tp0fVerName", "tp0f OS/program version name");

    return bv;
}


void t2OnNewFlow(packet_t* packet, unsigned long flowIndex) {
    tp0fFlow_t * const tp0fFlowP = &tp0fFlows[flowIndex];
    memset(tp0fFlowP, '\0', sizeof(tp0fFlow_t));

    const flow_t * const flowP = &flows[flowIndex];
    if (flowP->status & L2_FLOW) return; // Layer 2 flow. No L3/4 pointers, so return

    uint_fast8_t ttl/*, ipID*/;

#if TP0FRULES == 1
    uint_fast8_t ipDF;
    int l3Len;
#endif // TP0FRULES == 1

    if (PACKET_IS_IPV6(packet)) {
        const ip6Header_t * const ip6HdrP = IPV6_HEADER(packet);
        ttl = ip6HdrP->ip_ttl;
        //ipID = 1;
#if TP0FRULES == 1
        ipDF = IPF_DF;
        //l3Len = ntohs(ip6HdrP->payload_len) + 40; // FIXME TSO case use l3Len
        l3Len = packet->l3Len;
#endif // TP0FRULES == 1
    } else { // IPv4
        const ipHeader_t * const ipHdrP = IPV4_HEADER(packet);
        ttl = ipHdrP->ip_ttl;
        //ipID = ntohs(ipHdrP->ip_id);
#if TP0FRULES == 1
        ipDF = *((uint8_t*)ipHdrP + 6) & IPF_DF;
        //l3Len = ntohs(ipHdrP->ip_len); // FIXME TSO case use l3Len
        l3Len = packet->l3Len;
#endif // TP0FRULES == 1
    }

    const uint_fast8_t l4Proto = L4_PROTO(packet);

    tp0fFlowP->clss = 3;
    if (ttl > 128) {
        tp0fFlowP->dist = 255 - ttl;
        ttl = 255;
        tp0fFlowP->clss = 2;
        if (l4Proto == 1) tp0fFlowP->prog = 4;
        else tp0fFlowP->prog = 5;
    } else if (ttl > 64) {
        tp0fFlowP->dist = 128 - ttl;
        ttl = 128;
        tp0fFlowP->clss = 1;
        tp0fFlowP->prog = 1;
    } else if (ttl > 32) {
        tp0fFlowP->dist = 64 - ttl;
        ttl = 64;
        tp0fFlowP->clss = 2;
        tp0fFlowP->prog = 2;
    } else if (ttl > 16) {
        tp0fFlowP->dist = 32 - ttl;
        ttl = 32;
        tp0fFlowP->clss = 1;
        tp0fFlowP->prog = 1;
    } else if (ttl > 8) {
        tp0fFlowP->dist = 16 - ttl;
        ttl = 16;
    }
    if (tp0fFlowP->dist > TP0F_MXTTLD) tp0fFlowP->stat |= TP0F_TTLNS;

    if (l4Proto != L3_TCP) {
        // TODO check whether IP was already classified in ipP0fHashMap
        return;
    }

    const tcpHeader_t * const tcpHdrP = TCP_HEADER(packet);
    const uint8_t tcpFlags = (unsigned char) *((char*)tcpHdrP + 13);
    if (!((tcpFlags & 0x07) == TH_SYN)) return;

    uint32_t tcpWin = ntohs(tcpHdrP->window);
    if (ttl == 255) {
        if (tcpWin == 4128) {
            tp0fFlowP->prog = 9;
        }
    } else if (ttl == 128) {
        if (tcpWin == 65535) tp0fFlowP->ver = 2;
        else if (tcpWin == 8192) tp0fFlowP->ver = 3;
    } else if (ttl == 64) {
        if (tcpWin == 65535) {
            tp0fFlowP->prog = 4;
        }
    }

#if TP0FRULES == 1
    const tp0flist_t * const tp0fLc = tp0flist_table->tp0flists, *tp0fLci;
    uint_fast32_t i;

#if TP0FHSH == 1
#if IPV6_ACTIVATE == 2
    const ipVAddr_t srcIP = {
        .ver = PACKET_IPVER(packet),
        .addr = flowP->srcIP
    };
#elif IPV6_ACTIVATE == 1
    const ipAddr_t srcIP = flowP->srcIP;
#else // IPV6_ACTIVATE == 0
    const uint32_t srcIP = (uint32_t)flowP->srcIP.IPv4.s_addr;
#endif // IPV6_ACTIVATE == 0
    unsigned long ipP0fIndex = hashTable_lookup(ipP0fHashMap, (char*)&srcIP);
    if (ipP0fIndex != HASHTABLE_ENTRY_NOT_FOUND) {
        tp0fFlowP->stat = (ipP0fClass[ipP0fIndex] & 0x00ff) | TP0F_ASN;
        i = ipP0fClass[ipP0fIndex] >> 8;
        tp0fFlowP->rID = tp0fLc[i-1].id;
        tp0fFlowP->clss = tp0fLc[i].nclass;
        tp0fFlowP->prog = tp0fLc[i].nprog;
        tp0fFlowP->ver = tp0fLc[i].nver;
        return;
    }
#endif // TP0FHSH == 1

    int tcpOptCnt = 0, j = 0;
    uint32_t tWS, tcpW;
    uint16_t tcpMss = 0;
    uint8_t tcpWS = 0;
    uint8_t tcpOpt[TCPOPTMAX];
    const uint16_t l4HDLen = packet->l4HdrLen;
    const uint_fast32_t tOptLen = l4HDLen - 20;
    const uint_fast16_t l3HDLen = packet->l3HdrLen;
    const int l4Len = l3Len - l3HDLen;
    const uint8_t * const tOpt = ((uint8_t*)tcpHdrP + 20);
    const uint8_t l7LenSW = (packet->snapL7Len) ? 1 : 0;
    uint8_t tcpF;

    if (l4HDLen - 20 > 0) { // consider all tcpOptions and set flag bits
        if (packet->snapL3Len >= (l3HDLen + l4HDLen) && l4Len >= l4HDLen) { // option field exists or crafted packet?
            for (i = 0; i < tOptLen && tOpt[i] > 0; i += (tOpt[i] > 1) ? tOpt[i+1] : 1) {
                tcpOpt[j++] = tOpt[i] & 0x1F;
                if (tcpOptCnt < TCPOPTMAX) {
                    if (tOpt[i] == 2) tcpMss = (tOpt[i+2] << 8) + tOpt[i+3]; // save the last MSS
                    else if ((tOpt[i] == 3) && (tcpFlags & TH_SYN)) tcpWS = tOpt[i+2]; // save the Window Scale
                }
                tcpOptCnt++;
                if (tOpt[i+1] == 0) break;
            }
        } else {
            tp0fFlowP->stat |= TP0F_L4OPTBAD; // warning: crafted packet or option field not acquired
            return;
        }
    }

    j = MIN(tcpOptCnt, TCPOPTMAX);

    tcpF = tcpFlags & 0x17;
    if (tcpF == TH_SYN) {
        for (i = 0; i < tp0flist_table->count; i++) {
            tp0fLci = &tp0fLc[i];
            tcpF = tp0fLci->tcpF & TH_SYN_ACK;
            if (tcpF != TH_SYN) continue;
            if (tcpOptCnt != tp0fLci->ntcpopt || ttl != tp0fLci->ttl) continue;
            tcpW = tp0fLci->wsize;
            if (tp0fLci->clst & CLST_MSS_DC) {
                if (tp0fLci->clst & CLST_MSS) tcpW = tp0fLci->ws * tcpMss;
                if (tp0fLci->clst & CLST_MTU) tcpW = tp0fLci->ws * (tcpMss + 40);
            } else {
                if (tp0fLci->mss != tcpMss) continue;
            }
            if (tcpWin != tcpW) continue;
            if (!(tp0fLci->clst & CLST_WS_DC) && tp0fLci->ws != tcpWS) continue;
//            if ((tp0fLci->clst & CLST_PLD) == 0) {
//                if (tp0fLci->pldl != l7LenSW) continue;
//            }
            if ((tp0fLci->ipF & IPF_DF) == ipDF) {
                if (memcmp(tcpOpt, tp0fLci->tcpopt, j)) continue;
                tp0fFlowP->rID = tp0fLc[i].id;
                tp0fFlowP->stat |= TP0F_TSSIG;
                break;
            }
        }
    } else if (tcpF == TH_SYN_ACK) {
        for (i = 0; i < tp0flist_table->count; i++) {
            tp0fLci = &tp0fLc[i];
            tcpF = tp0fLci->tcpF & TH_SYN_ACK;
            if (tcpF != TH_SYN_ACK) continue;
            if (tcpOptCnt != tp0fLci->ntcpopt || ttl != tp0fLci->ttl) continue;
            tcpW = tp0fLci->wsize;
            if (tp0fLci->clst & CLST_MSS_DC) {
                if (tp0fLci->clst & CLST_WS_DC) tWS = 1 << tcpWS;
                else tWS = 1 << tp0fLci->ws;
                if (tp0fLci->clst & CLST_MSS) tcpW = tWS * tp0fLci->wsize * tcpMss;
                if (tp0fLci->clst & CLST_MTU) tcpW = tWS * tp0fLci->wsize * (tcpMss + 40);
            } else {
                if (tp0fLci->mss != tcpMss) continue;
            }
            if (tcpWin != tcpW) continue;
            if ((tp0fLci->clst & CLST_PLD) == 0) {
                if (tp0fLci->pldl != l7LenSW) continue;
            }
            if ((tp0fLci->ipF & IPF_DF) == ipDF) {
                if (memcmp(tcpOpt, tp0fLci->tcpopt, j)) continue;
                tp0fFlowP->rID = tp0fLc[i].id;
                tp0fFlowP->stat |= TP0F_TSASIG;
                break;
            }
        }
    }

#if TP0FHSH == 1
    if (tp0fFlowP->stat & (TP0F_TSSIG | TP0F_TSASIG)) {
        ipP0fIndex = hashTable_insert(ipP0fHashMap, (char*)&srcIP);
        if (ipP0fIndex == HASHTABLE_ENTRY_NOT_FOUND) {
            if (!tp0fAStat) {
                tp0fAStat = 1;
                T2_PWRN(plugin_name, "%s HashMap full", ipP0fHashMap->name);
            }
            return;
        } else {
            if (tp0fAStat) {
                T2_PWRN(plugin_name, "%s HashMap free", ipP0fHashMap->name);
                tp0fAStat = 0;
            }
        }
        ipP0fClass[ipP0fIndex] = (tp0fFlowP->rID << 8) | tp0fFlowP->stat;
    }
#endif // TP0FHSH == 1
#endif // TP0FRULES == 1
}


#if ETH_ACTIVATE > 0
void t2OnLayer2(packet_t *packet UNUSED, unsigned long flowIndex) {
        if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;

        // This packet does not have a layer 4.
        // Print tabs to keep the packet file aligned
        if (sPktFile) fputs("0x00" /* tp0fStat    */ SEP_CHR
                                   /* tp0fDis     */ SEP_CHR
                                   ///* tp0fClName  */ SEP_CHR
                                   /* tp0fPrName  */ SEP_CHR
                                   /* tp0fVerName */ SEP_CHR
                            , sPktFile);
}
#endif // ETH_ACTIVATE > 0


void t2OnLayer4(packet_t* packet UNUSED, unsigned long flowIndex) {
    tp0fFlow_t * const tp0fFlowP = &tp0fFlows[flowIndex];
    const flow_t * const flowP = &flows[flowIndex];
    if (flowP->status & L2_FLOW) return; // Layer 2 flow. No L3/4 pointers, so return
    if (sPktFile) {
#if TP0FRULES == 1
        if (tp0fFlowP->rID) {
            const uint_fast8_t i = tp0fFlowP->rID - 1;
            const tp0flist_t * const tp0fLc = tp0flist_table->tp0flists;
            tp0fFlowP->clss = tp0fLc[i].nclass;
            tp0fFlowP->prog = tp0fLc[i].nprog;
            tp0fFlowP->ver = tp0fLc[i].nver;
        }
#endif // TP0FRULES == 1
        fprintf(sPktFile, "0x%02" B2T_PRIX8 /* tp0fStat    */ SEP_CHR
                          "%" PRIu8         /* tp0fDis     */ SEP_CHR
                          //"%s"              /* tp0fClName  */ SEP_CHR
                          "%s"              /* tp0fPrName  */ SEP_CHR
                          "%s"              /* tp0fVerName */ SEP_CHR
                          , tp0fFlowP->stat
                          , tp0fFlowP->dist
                          //, osCl[tp0fFlowP->clss]
                          , progCl[tp0fFlowP->prog]
                          , verCl[tp0fFlowP->ver]);
    }
}


void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {
    tp0fFlow_t * const tp0fFlowP = &tp0fFlows[flowIndex];
    tp0fStat |= tp0fFlowP->stat;

#if TP0FRULES == 1
    const tp0flist_t * const tp0fLc = tp0flist_table->tp0flists;
    if (tp0fFlowP->rID) {
        const int i = tp0fFlowP->rID - 1;
        tp0fFlowP->clss = tp0fLc[i].nclass;
        tp0fFlowP->prog = tp0fLc[i].nprog;
        tp0fFlowP->ver = tp0fLc[i].nver;
        numFgpIP++;
    }
#endif // TP0FRULES == 1

    OUTBUF_APPEND_U8(buf, tp0fFlowP->stat);
    OUTBUF_APPEND_U8(buf, tp0fFlowP->dist);

#if TP0FRC == 1
    OUTBUF_APPEND_U16(buf, tp0fFlowP->rID);
    OUTBUF_APPEND_U8(buf, tp0fFlowP->clss);
    OUTBUF_APPEND_U8(buf, tp0fFlowP->prog);
    OUTBUF_APPEND_U8(buf, tp0fFlowP->ver);
#endif // TP0FRC == 1

    OUTBUF_APPEND_STR(buf, osCl[tp0fFlowP->clss]);
    OUTBUF_APPEND_STR(buf, progCl[tp0fFlowP->prog]);
    OUTBUF_APPEND_STR(buf, verCl[tp0fFlowP->ver]);
}


void t2PluginReport(FILE *stream) {
    T2_FPLOG_AGGR_HEX(stream, plugin_name, tp0fStat);
#if TP0FRULES == 1
    T2_FPLOG_NUMP(stream, plugin_name, "Number of p0f rule matches", numFgpIP, totalFlows)
#endif // TP0FRULES == 1
}


void t2Finalize() {
    free(tp0fFlows);

#if TP0FRULES == 1
    tp0flist_table_free(tp0flist_table);
#if TP0FHSH== 1
    hashTable_destroy(ipP0fHashMap);
    free(ipP0fClass);
#endif // TP0FHSH == 1
#endif // TP0FRULES == 1
}
