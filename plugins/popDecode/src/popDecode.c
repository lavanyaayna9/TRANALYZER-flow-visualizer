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

#include "popDecode.h"

#include <errno.h>  // for errno


// Global variables

popFlow_t *popFlows;


// Static variables

static uint64_t numPopPkts;
static uint16_t popStat;

#if ENVCNTRL > 0
static t2_env_t env[ENV_POP_N];
#endif // ENVCNTRL
#if POP_SAVE == 1
static uint64_t totPopSaved;
#if ENVCNTRL > 0
static const char *popPath;
static const char *popNoName;
#else // ENVCNTRL == 0
static const char * const popPath = POP_F_PATH;
static const char * const popNoName = POP_NONAME;
#endif // ENVCNTRL
#endif // POP_SAVE == 1

static const uint32_t popErrC[2] = {
    0x204b4f2b,  // +OK
    0x5252452d   // -ERR
};

static const char popCom[17][5] = {
    "APOP", "AUTH", "CAPA", "DELE",
    "LIST", "NOOP", "PASS", "QUIT",
    "RETR", "RSET", "STAT", "STLS",
    "TOP ", "UIDL", "USER", "XTND",
    "-"
};


#define POP_SPKTMD_PRI_NONE() if (sPktFile) fputs("0x0000" SEP_CHR, sPktFile);


// Tranalyzer functions

T2_PLUGIN_INIT("popDecode", "0.9.3", 0, 9);


void t2Init() {
    T2_PLUGIN_STRUCT_NEW(popFlows);

#if POP_SAVE == 1
#if ENVCNTRL > 0
    t2_get_env(PLUGIN_SRCH, ENV_POP_N, env);
    const uint8_t rmdir = T2_ENV_VAL_UINT(POP_RMDIR);
    popPath = T2_ENV_VAL(POP_F_PATH);
    popNoName = T2_ENV_VAL(POP_NONAME);
#else // ENVCNTRL == 0
    const uint8_t rmdir = POP_RMDIR;
#endif // ENVCNTRL

    T2_MKPATH(popPath, rmdir);
#endif // POP_SAVE == 1

    if (sPktFile) fputs("popStat" SEP_CHR, sPktFile);
}


binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;
    BV_APPEND_H16(bv,    "popStat"  , "POP status");
#if POP_BTFLD == 1
    BV_APPEND_H16(bv,    "popCBF"   , "POP command codes bitfield");
#endif // POP_BTFLD == 1
    BV_APPEND_STRC_R(bv, "popCC"    , "POP command codes");
    BV_APPEND_U16_R(bv,  "popRM"    , "POP response #mail");
    BV_APPEND_U8(bv,     "popUsrNum", "POP number of users");
    BV_APPEND_STR_R(bv,  "popUsr"   , "POP users");
    BV_APPEND_U8(bv,     "popPwNum" , "POP number of passwords");
    BV_APPEND_STR_R(bv,  "popPw"    , "POP passwords");
    BV_APPEND_U8(bv,     "popCNum"  , "POP number of parameters");
    BV_APPEND_STR_R(bv,  "popC"     , "POP content");
    return bv;
}


void t2OnNewFlow(packet_t *packet UNUSED, unsigned long flowIndex) {
    popFlow_t * const popFlowP = &popFlows[flowIndex];
    memset(popFlowP, '\0', sizeof(*popFlowP));

    const flow_t * const flowP = &flows[flowIndex];
    if (flowP->l4Proto != L3_TCP) return;

    const uint_fast16_t srcPort = flowP->srcPort;
    const uint_fast16_t dstPort = flowP->dstPort;

    if (dstPort == POP3_PORT || srcPort == POP3_PORT) popFlowP->stat = POP3_INIT;
    else if (dstPort == POP2_PORT || srcPort == POP2_PORT) popFlowP->stat = POP2_INIT;
}


#if ETH_ACTIVATE > 0
void t2OnLayer2(packet_t *packet UNUSED, unsigned long flowIndex) {
    if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;

    // This packet does not have a layer 4.
    // Print tabs to keep the packet file aligned
    if (sPktFile) POP_SPKTMD_PRI_NONE();
}
#endif // ETH_ACTIVATE > 0


void t2OnLayer4(packet_t *packet, unsigned long flowIndex) {
    const flow_t * const flowP = &flows[flowIndex];

    popFlow_t * const popFlowP = &popFlows[flowIndex];
    if (!popFlowP->stat) {
        POP_SPKTMD_PRI_NONE();
        return;
    }

#if POP_SAVE == 1
    const tcpHeader_t * const tcpHdrP = TCP_HEADER(packet);
    const uint32_t tcpSeq = ntohl(tcpHdrP->seq); // absolute / relative TCP sequence number
#endif // POP_SAVE == 1

    uint32_t l7Hdr32;
    int32_t i, j;
    int32_t l7Len = packet->snapL7Len;
    char *l7HdrP = (char*)packet->l7HdrP, *s;
    uint8_t sC = 0;

    if (l7Len < 4) goto popPkt;

    numPopPkts++;

    l7Hdr32 = *(uint32_t*)l7HdrP;
    if (l7HdrP[0] > 0x60) l7Hdr32 -= 0x20202020;

//#if POP_SAVE == 1
    popFlow_t *popFlowPO = (FLOW_HAS_OPPOSITE(flowP) ? &popFlows[flowP->oppositeFlowIndex] : NULL);
//#endif // POP_SAVE == 1

    if (FLOW_IS_B(flowP)) {
        if (popFlowP->rCCnt >= POP_MXCNM) {
            popFlowP->stat |= POP_OVFL;
            goto popPkt;
        }

        if (memmem(l7HdrP, 3, "+OK", 3)) {
            popFlowP->stat |= POP_ROK;
#if POP_SAVE == 1
            if (popFlowPO && (popFlowPO->stat & POP_DTP) && !popFlowP->fd) {
                char imfname[MAX_FILENAME_LEN] = {};
                if (popFlowPO->nameUCnt > 0) s = popFlowPO->nameU[popFlowPO->nameUCnt-1];
                else s = (char*)popNoName;
                j = strlen(s);
                for (i = 0; i < j; i++) {
                    if (s[i] == '/') s[i] = '_';
                }
                snprintf(imfname, sizeof(imfname), "%s%s_%c_%" PRIu64,
                        popPath, s, FLOW_DIR_C(flowP), flowP->findex);

                popFlowP->fd = file_manager_open(t2_file_manager, imfname, "w+b");
                if (!popFlowP->fd) {
                    T2_PERR(plugin_name, "Failed to open file '%s': %s", imfname, strerror(errno));
                    popFlowP->stat |= POP_RERR;
                    goto popPkt;
                }

                popFlowP->seqInit = tcpSeq + l7Len;
                popFlowPO->stat |= POP_DWF;

                totPopSaved++;
            }
#endif // POP_SAVE == 1
            j = 4;
        } else if (l7Hdr32 == popErrC[1]) {
            popFlowP->stat |= POP_RERR;
            j = 5;
#if POP_SAVE == 1
            if (popFlowP->fd) {
                file_manager_close(t2_file_manager, popFlowP->fd);
                popFlowP->fd = NULL;
                if (popFlowPO) popFlowPO->stat &= ~POP_DTP;
            }
#endif // POP_SAVE == 1
        } else {
            popFlowP->stat |= POP_RNVL;
            if (popFlowP->stat & POP_RPATH) {
                if (memmem(l7HdrP, 14, "Return-Path: <", 14)) {
                    if ((s = memchr(l7HdrP, '>', l7Len)) != NULL) {
                        i = s - l7HdrP - 14;
                        if (i > POP_MXNMLN) i = POP_MXNMLN;
                        memcpy(popFlowP->nameU[popFlowP->nameUCnt++], l7HdrP+14, i);
                    }
                }
                popFlowP->stat &= ~POP_RPATH;
            }
#if POP_SAVE == 1
            if (popFlowPO && popFlowPO->stat & POP_DTP) {
                if (popFlowP->fd) {
                    FILE * const fp = file_manager_fp(t2_file_manager, popFlowP->fd);
                    i = tcpSeq - popFlowP->seqInit;
                    fseek(fp, i, SEEK_SET);
                    fwrite(l7HdrP, 1, l7Len , fp);
                } else popFlowP->stat &= ~POP_DTP;
            } else if (popFlowP->fd) {
                file_manager_close(t2_file_manager, popFlowP->fd);
                popFlowP->fd = NULL;
                if (popFlowPO) popFlowPO->stat &= ~POP_DTP;
            }
#endif // POP_SAVE == 1
            goto popPkt;
        }

        if (popFlowP->nameCCnt >= POP_MXPNM) {
            popFlowP->stat |= POP_OVFL;
            goto popaa;
        }

        l7HdrP += j;
        l7Len -= j;
        if ((s = memchr(l7HdrP, '\r', l7Len)) != NULL) {
            i = s - l7HdrP;
            if (i > POP_MXNMLN) i = POP_MXNMLN;
            memcpy(popFlowP->nameC[popFlowP->nameCCnt++], l7HdrP, i);
        }

popaa:
        j = atoi(l7HdrP);
        if (!j) goto popPkt;
        for (i = 0; i < popFlowP->rCCnt; i++) {
            if (popFlowP->recCode[i] == j) goto popPkt;
        }
        popFlowP->recCode[popFlowP->rCCnt++] = j;

    } else {
        switch (l7Hdr32) {
            case APOP:
                sC = 0;
                popFlowP->tCodeBF |= POP_APOP;
                break;

            case AUTH:
                sC = 1;
                popFlowP->tCodeBF |= POP_AUTH;
                if (memmem(l7HdrP, 10, "PLAIN", 5)) popFlowP->stat |= POP_PAUT;
                break;

            case CAPA:
                sC = 2;
                popFlowP->tCodeBF |= POP_CAPA;
                break;

            case DELE:
                sC = 3;
                popFlowP->tCodeBF |= POP_DELE;
                break;

            case LIST:
                sC = 4;
                popFlowP->tCodeBF |= POP_LIST;
                break;

            case NOOP:
                sC = 5;
                popFlowP->tCodeBF |= POP_NOOP;
                break;

            case PASS:
                sC = 6;
                if (popFlowP->namePCnt >= POP_MXPNM) {
                    popFlowP->stat |= POP_OVFL;
                    break;
                }
                popFlowP->tCodeBF |= POP_PASS;
                if (l7Len < 7) break;
                l7HdrP += 5;
                l7Len -= 5;
                if ((s = memchr(l7HdrP, '\r', l7Len)) != NULL) {
                    i = s - l7HdrP;
                    if (i > POP_MXNMLN) i = POP_MXNMLN;
                    memcpy(popFlowP->nameP[popFlowP->namePCnt++], l7HdrP, i);
                }
                break;

            case QUIT:
                sC = 7;
                popFlowP->tCodeBF |= POP_QUIT;
#if POP_SAVE == 1
                if (popFlowP->fd) {
                    file_manager_close(t2_file_manager, popFlowP->fd);
                    popFlowP->fd = NULL;
                    popFlowP->stat &= ~POP_DTP;
                }
#endif // POP_SAVE == 1
                break;

            case RETR:
                sC = 8;
                if (popFlowP->nameCCnt >= POP_MXPNM) {
                    popFlowP->stat |= POP_OVFL;
                    break;
                }
                popFlowP->tCodeBF |= POP_RETR;
#if POP_SAVE == 1
                popFlowP->stat |= POP_DTP;
#endif // POP_SAVE == 1
                if (l7Len < 7) break;
                l7HdrP += 5;
                l7Len -= 5;
                if ((s = memchr(l7HdrP, '\r', l7Len)) != NULL) {
                    i = s - l7HdrP;
                    if (i > POP_MXNMLN) i = POP_MXNMLN;
                    memcpy(popFlowP->nameC[popFlowP->nameCCnt++], l7HdrP, i);
                }
                break;

            case RSET:
                sC = 9;
                popFlowP->tCodeBF |= POP_RSET;
                break;

            case STAT:
                sC = 10;
                popFlowP->tCodeBF |= POP_STAT;
                break;

            case STLS:
                sC = 11;
                popFlowP->tCodeBF |= POP_STLS;
                break;

            case TOP:
                sC = 12;
                popFlowP->tCodeBF |= POP_TOP;
                break;

            case UIDL:
                sC = 13;
                popFlowP->tCodeBF |= POP_UIDL;
                break;

            case USER:
                sC = 14;
                if (popFlowP->nameUCnt >= POP_MXUNM) {
                    popFlowP->stat |= POP_OVFL;
                    break;
                }
                popFlowP->tCodeBF |= POP_USER;
                if (l7Len < 7) break;
                l7HdrP += 5;
                l7Len -= 5;
                if ((s = memchr(l7HdrP, '\r', l7Len)) != NULL) {
                    i = s - l7HdrP;
                    if (i > POP_MXNMLN) i = POP_MXNMLN;
                    memcpy(popFlowP->nameU[popFlowP->nameUCnt++], l7HdrP, i);
                }
                break;

            case XTND:
                sC = 15;
                popFlowP->tCodeBF |= POP_XTND;
                break;

            default:
                if (popFlowP->stat & POP_PAUT) {
                    if ((s = memchr(l7HdrP, '\r', l7Len)) != NULL) {
                        i = (int) (s - l7HdrP);
                        if (i > POP_MXNMLN) i = POP_MXNMLN;
                        memcpy(popFlowP->nameP[popFlowP->namePCnt++], l7HdrP, i);
                        popFlowP->stat &= ~POP_PAUT;
                        if (popFlowPO) popFlowPO->stat |= POP_RPATH;
                    }
                }
                goto popPkt;
        }

        if (popFlowP->tCCnt >= POP_MXCNM) {
            popFlowP->stat |= POP_OVFL;
            goto popPkt;
        }

        for (j = 0; j < popFlowP->tCCnt; j++) {
            if (popFlowP->tCode[j] == sC) goto popPkt;
        }

        popFlowP->tCode[popFlowP->tCCnt++] = sC;
        popFlowP->tCodeBF |= (1 << sC);

    }

popPkt:
    if (sPktFile) {
        fprintf(sPktFile, "0x%04" B2T_PRIX16 SEP_CHR, popFlowP->stat);
    }
}


void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {
    popFlow_t * const popFlowP = &popFlows[flowIndex];

    popStat |= popFlowP->stat;

#if POP_SAVE == 1
    if (popFlowP->fd) {
        file_manager_close(t2_file_manager, popFlowP->fd);
        popFlowP->fd = NULL;
    }
#endif // POP_SAVE == 1

    OUTBUF_APPEND_U16(buf, popFlowP->stat);    // popStat
#if POP_BTFLD == 1
    OUTBUF_APPEND_U16(buf, popFlowP->tCodeBF); // popCBF
#endif // POP_BTFLD == 1

    uint32_t j;

    // popCC
    j = popFlowP->tCCnt;
    OUTBUF_APPEND_NUMREP(buf, j);
    for (uint_fast32_t i = 0; i < j; i++) {
        uint8_t code = popFlowP->tCode[i];
        if (code > 17) code = 17;
        OUTBUF_APPEND_STR(buf, popCom[code]);
    }

    OUTBUF_APPEND_ARRAY_U16(buf, popFlowP->recCode, popFlowP->rCCnt);   // popRM
    OUTBUF_APPEND_U8(buf, popFlowP->nameUCnt);                          // popUsrNum
    OUTBUF_APPEND_ARRAY_STR(buf, popFlowP->nameU, popFlowP->nameUCnt);  // popUsr
    OUTBUF_APPEND_U8(buf, popFlowP->namePCnt);                          // popPwNum
    OUTBUF_APPEND_ARRAY_STR(buf, popFlowP->nameP, popFlowP->namePCnt);  // popPw
    OUTBUF_APPEND_U8(buf, popFlowP->nameCCnt);                          // popCNum
    OUTBUF_APPEND_ARRAY_STR(buf, popFlowP->nameC, popFlowP->nameCCnt);  // popC
}


void t2PluginReport(FILE *stream) {
    if (popStat) {
        T2_FPLOG_AGGR_HEX0(stream, plugin_name, popStat);
        T2_FPLOG_NUMP(stream, plugin_name, "Number of POP packets", numPopPkts, numPackets);
#if POP_SAVE == 1
        T2_FPLOG_NUM(stream, plugin_name, "Number of files extracted", totPopSaved);
#endif // POP_SAVE == 1
    }
}


void t2Finalize() {
#if ENVCNTRL > 0
    t2_free_env(ENV_POP_N, env);
#endif // ENVCNTRL > 0

    free(popFlows);
}
