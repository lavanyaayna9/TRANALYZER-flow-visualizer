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

#include "smtpDecode.h"

#include <errno.h>  // for errno


// Global variables

smtpFlow_t *smtpFlow;


// Static variables

#if SMTP_SAVE == 1
#if ENVCNTRL > 0
static t2_env_t env[ENV_SMTP_N];
static const char *smtpFPth;
static const char *smtpNoName;
#else // ENVCNTRL == 0
const char * const smtpFPth = SMTP_F_PATH;
const char * const smtpNoName = SMTP_NONAME;
#endif // ENVCNTRL
#endif // SMTP_SAVE == 1

static uint64_t totsmtpPktCnt;
static uint32_t smtpFileCnt;
static uint8_t smtpStat;

// send commands
static const char smtpCom[17][5] = {
    "HELO", "EHLO", "MAIL", "RCPT", "DATA", "RSET",
    "SEND", "SOML", "SAML", "VRFY", "EXPN", "HELP",
    "NOOP", "QUIT", "TURN", "AUTH", "STLS"
};


// Tranalyzer functions

T2_PLUGIN_INIT("smtpDecode", "0.9.3", 0, 9);


void t2Init() {
    T2_PLUGIN_STRUCT_NEW(smtpFlow);

#if SMTP_SAVE == 1
#if ENVCNTRL > 0
    t2_get_env(PLUGIN_SRCH, ENV_SMTP_N, env);
    const uint8_t rmdir = T2_ENV_VAL_UINT(SMTP_RMDIR);
    smtpFPth = T2_ENV_VAL(SMTP_F_PATH);
    smtpNoName = T2_ENV_VAL(SMTP_NONAME);
#else // ENVCNTRL == 0
    const uint8_t rmdir = SMTP_RMDIR;
#endif // ENVCNTRL

    T2_MKPATH(smtpFPth, rmdir);
#endif // SMTP_SAVE == 1

    if (sPktFile) fputs("smtpStat" SEP_CHR, sPktFile);
}


binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;
    BV_APPEND_H8(bv,     "smtpStat"  , "SMTP status");
#if SMTP_BTFLD == 1
    BV_APPEND_H16(bv,    "smtpCBF"   , "SMTP command codes bitfield");
    //BV_APPEND_H32(bv,    "smtpRBF"   , "SMTP response codes bitfield");
#endif // SMTP_BTFLD == 1
    BV_APPEND_STRC_R(bv, "smtpCC"    , "SMTP command codes");
    BV_APPEND_U16_R(bv,  "smtpRC"    , "SMTP response codes");
    BV_APPEND_STR_R(bv,  "smtpUsr"   , "SMTP users");
    BV_APPEND_STR_R(bv,  "smtpPW"    , "SMTP passwords");
    BV_APPEND_U8(bv,     "smtpSANum" , "SMTP number of server addresses");
    BV_APPEND_U8(bv,     "smtpESANum", "SMTP number of email sender addresses");
    BV_APPEND_U8(bv,     "smtpERANum", "SMTP number of email receiver addresses");
    BV_APPEND_STR_R(bv,  "smtpSA"    , "SMTP server send addresses");
    BV_APPEND_STR_R(bv,  "smtpESA"   , "SMTP email send addresses");
    BV_APPEND_STR_R(bv,  "smtpERA"   , "SMTP email receive addresses");
    return bv;
}


void t2OnNewFlow(packet_t* packet UNUSED, unsigned long flowIndex) {
    smtpFlow_t *smtpFlowP = &smtpFlow[flowIndex];
    memset(smtpFlowP, '\0', sizeof(smtpFlow_t));

    const flow_t * const flowP = &flows[flowIndex];

    const uint_fast16_t srcPort = flowP->srcPort;
    const uint_fast16_t dstPort = flowP->dstPort;

    if (flowP->l4Proto != L3_TCP) return;

    if (dstPort == 25 || dstPort == 465 || dstPort == 587 || dstPort == 2525 ||
        srcPort == 25 || srcPort == 465 || srcPort == 587 || srcPort == 2525)
    {
        smtpFlowP->smtpStat = SMTP_INIT;
    }
}


#if ETH_ACTIVATE > 0
void t2OnLayer2(packet_t *packet UNUSED, unsigned long flowIndex) {
    if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;

    // This packet does not have a layer 4.
    // Print tabs to keep the packet file aligned
    if (sPktFile) fputs("0x00" SEP_CHR, sPktFile);
}
#endif // ETH_ACTIVATE > 0


void t2OnLayer4(packet_t* packet, unsigned long flowIndex) {
    smtpFlow_t *smtpFlowP = &smtpFlow[flowIndex];
    if (!smtpFlowP->smtpStat) goto smtppkt;

#if SMTP_SAVE == 1
    const tcpHeader_t * const tcpHdrP = TCP_HEADER(packet);
    const uint32_t tcpSeq = ntohl(tcpHdrP->seq);
#endif // SMTP_SAVE == 1

    uint32_t *l7Hdr32;
    uint32_t i, j;
    int pshft = 5;
    int32_t l7Len = packet->snapL7Len;
    char *l7HdrP = (char*)packet->l7HdrP, *s;
    uint8_t sC = 0;

    totsmtpPktCnt++;

    if (l7Len < 4) goto smtppkt;

    const flow_t * const flowP = &flows[flowIndex];
    if (FLOW_IS_B(flowP)) {
#if SMTP_RCTXT == 1
        int32_t nameSLen = 0, k;
        char *t = smtpFlowP->nameS[smtpFlowP->nameSCnt];
smtpsnxt:
#endif // SMTP_RCTXT == 1
        l7Hdr32 = (uint32_t*)l7HdrP;
        if (smtpFlowP->rCCnt >= SMTP_MAXCNM) {
            smtpFlowP->smtpStat |= 0x80;
            goto smtppkt;
        }
        i = *l7Hdr32 & 0xffffff;
        j = atoi((char*)&i);
        if (!j) goto smtppkt;
        for (i = 0; i < smtpFlowP->rCCnt; i++) {
            if (smtpFlowP->recCode[i] == j)
#if SMTP_RCTXT == 1
                goto smtpsinfo;
#else // SMTP_RCTXT == 0
                goto smtppkt;
#endif // SMTP_RCTXT
        }
        smtpFlowP->recCode[smtpFlowP->rCCnt++] = j;
        //smtpFlowP->recCode |= (1 << i);
#if SMTP_RCTXT == 1
smtpsinfo:
        if (j) {
            if (smtpFlowP->nameSCnt >= SMTP_MAXSNM) {
                smtpFlowP->smtpStat |= SMTP_OVFL;
                goto smtppkt;
            }

            if ((s = memchr(l7HdrP, '\r', l7Len)) != NULL) {
                pshft = s - l7HdrP;
                nameSLen += pshft;
                if (nameSLen > SMTP_MXNMLN) pshft = nameSLen - SMTP_MXNMLN;
                memcpy(t, l7HdrP, pshft);
                k = l7Len - pshft - 7;
                if (k > 0 && nameSLen < SMTP_MXNMLN-7) {
                    t += pshft;
                    *t = '_';
                    t++;
                    pshft += 2;
                    l7HdrP += pshft;
                    l7Len -= pshft;
                    goto smtpsnxt;
                } else {
                    smtpFlowP->nameSCnt++;
                    goto smtppkt;
                }
            }
        }
#endif // SMTP_RCTXT == 1
    } else {
        if (smtpFlowP->smtpStat & SMTP_AUTP) {
            if (smtpFlowP->namePCnt >= SMTP_MAXPNM) {
                smtpFlowP->smtpStat |= SMTP_OVFL;
                goto smtppkt;
            }

            s = memchr(l7HdrP, '\r', l7Len);
            if (s) {
                j = s - l7HdrP;
            } else {
                smtpFlowP->smtpStat &= ~(SMTP_PWP | SMTP_AUTP);
                goto smtppkt;
            }

            if (smtpFlowP->smtpStat & SMTP_PWP) {
                if (j > SMTP_MXPNMLN) j = SMTP_MXPNMLN;
                s = smtpFlowP->nameP[smtpFlowP->namePCnt++];
                smtpFlowP->smtpStat &= ~(SMTP_PWP | SMTP_AUTP);
            } else {
                if (j > SMTP_MXUNMLN) j = SMTP_MXUNMLN;
                s = smtpFlowP->nameU[smtpFlowP->nameUCnt++];
                smtpFlowP->smtpStat |= SMTP_PWP;
            }

            memcpy(s, l7HdrP, j);
            //s[j] = 0x0;
            goto smtppkt;
#if SMTP_SAVE == 1
        } else if (smtpFlowP->smtpStat & SMTP_DTP) {
            FILE * const fp = file_manager_fp(t2_file_manager, smtpFlowP->fd);
            i = tcpSeq - smtpFlowP->seqInit;
            fseek(fp, i, SEEK_SET);
            fwrite(l7HdrP, 1, l7Len , fp);
#endif // SMTP_SAVE == 1
        }

        l7Hdr32 = (uint32_t*)l7HdrP;
        // case insensitive check of first 4 letters of SMTP command
        switch (l7HdrP[0] > 0x60 ? *l7Hdr32 - 0x20202020 : *l7Hdr32) {
            case HELO:
                sC = 0;
                smtpFlowP->sendCode |= SMTP_HELO;
                smtpFlowP->smtpStat &= ~(SMTP_PWP | SMTP_AUTP);
                if (smtpFlowP->nameSCnt >= SMTP_MAXSNM) {
                    smtpFlowP->smtpStat |= SMTP_OVFL;
                    break;
                }
                goto smtpcc;
            case EHLO:
                sC = 1;
                smtpFlowP->sendCode |= SMTP_EHLO;
                smtpFlowP->smtpStat &= ~(SMTP_PWP | SMTP_AUTP);
                if (smtpFlowP->nameSCnt >= SMTP_MAXSNM) {
                    smtpFlowP->smtpStat |= SMTP_OVFL;
                    break;
                }
smtpcc:
                if (l7Len <= 7) break;
                l7HdrP += 5;
                l7Len -= 5;
                if ((s = memchr(l7HdrP, '\r', l7Len)) != NULL) {
                    pshft = s - l7HdrP;
                    if (pshft > SMTP_MXNMLN) pshft = SMTP_MXNMLN;
                    memcpy(smtpFlowP->nameS[smtpFlowP->nameSCnt++], l7HdrP, pshft);
                }
                break;
            case MAIL:
                sC = 2;
                smtpFlowP->sendCode |= SMTP_MAIL;
                smtpFlowP->smtpStat &= ~(SMTP_PWP | SMTP_AUTP);
                if (smtpFlowP->nameTCnt >= SMTP_MAXTNM) {
                    smtpFlowP->smtpStat |= SMTP_OVFL;
                    break;
                }
                if (l7Len <= 13) break;
                l7HdrP += 10;
                l7Len -= 10;
                if ((s = memchr(l7HdrP, '<', l7Len)) != NULL) {
                    l7HdrP = s + 1;
                    l7Len--;
                    if ((s = memchr(l7HdrP, '>', l7Len)) != NULL) pshft = s - l7HdrP;
                    else pshft = l7Len;
                    if (pshft > SMTP_MXNMLN) pshft = SMTP_MXNMLN;
                    memcpy(smtpFlowP->nameT[smtpFlowP->nameTCnt++], l7HdrP, pshft);
                }
                break;
            case RCPT:
                sC = 3;
                smtpFlowP->sendCode |= SMTP_RCPT;
                smtpFlowP->smtpStat &= ~(SMTP_PWP | SMTP_AUTP);
                if (smtpFlowP->nameRCnt >= SMTP_MAXRNM) {
                    smtpFlowP->smtpStat |= SMTP_OVFL;
                    break;
                }
                if (l7Len <= 11) break;
                l7HdrP += 8;
                l7Len -= 8;
                s = memchr(l7HdrP, '<', l7Len);
                if (s != NULL) {
                    l7HdrP = s + 1;
                    l7Len--;
                    if ((s = memchr(l7HdrP, '>', l7Len)) != NULL) pshft = s - l7HdrP;
                    else pshft = l7Len;
                    if (pshft > SMTP_MXNMLN) pshft = SMTP_MXNMLN;
                    memcpy(smtpFlowP->nameR[smtpFlowP->nameRCnt++], l7HdrP, pshft);
                }
                break;
            case DATA:
                sC = 4;
                smtpFlowP->sendCode |= SMTP_DATA;
#if SMTP_SAVE == 1
                if (!smtpFlowP->fd) {
                    char imfname[MAX_FILENAME_LEN] = {};
                    if (smtpFlowP->nameTCnt > 0) s = smtpFlowP->nameT[smtpFlowP->nameTCnt-1];
                    else s = (char*)smtpNoName;
                    j = strlen(s);
                    for (i = 0; i < j; i++) {
                        if (s[i] == '/') s[i] = '_';
                    }
                    snprintf(imfname, sizeof(imfname), "%s%s_%c_%" PRIu64,
                            smtpFPth, s, FLOW_DIR_C(flowP), flowP->findex);

                    smtpFlowP->fd = file_manager_open(t2_file_manager, imfname, "w+b");
                    if (!smtpFlowP->fd) {
                        T2_PERR(plugin_name, "Failed to open file '%s': %s", imfname, strerror(errno));
                        smtpFlowP->smtpStat |= SMTP_FERR;
                        goto smtppkt;
                    }

                    smtpFlowP->seqInit = tcpSeq + 6;
                    smtpFlowP->smtpStat |= SMTP_DTP;
                }
#endif // SMTP_SAVE == 1
                break;
            case RSET:
                sC = 5;
                smtpFlowP->sendCode |= SMTP_RSET;
                smtpFlowP->smtpStat &= ~(SMTP_PWP | SMTP_AUTP);
                break;
            case SEND:
                sC = 6;
                smtpFlowP->sendCode |= SMTP_SEND;
                break;
            case SOML:
                sC = 7;
                smtpFlowP->sendCode |= SMTP_SOML;
                break;
            case SAML:
                sC = 8;
                smtpFlowP->sendCode |= SMTP_SAML;
                break;
            case VRFY:
                sC = 9;
                smtpFlowP->sendCode |= SMTP_VRFY;
                break;
            case EXPN:
                sC = 10;
                smtpFlowP->sendCode |= SMTP_EXPN;
                break;
            case HELP:
                sC = 11;
                smtpFlowP->sendCode |= SMTP_HELP;
                break;
            case NOOP:
                sC = 12;
                smtpFlowP->sendCode |= SMTP_NOOP;
                break;
            case QUIT:
                sC = 13;
                smtpFlowP->sendCode |= SMTP_QUIT;
                smtpFlowP->smtpStat &= ~(SMTP_PWP | SMTP_AUTP);
#if SMTP_SAVE == 1
                if (smtpFlowP->fd) {
                    file_manager_close(t2_file_manager, smtpFlowP->fd);
                    smtpFlowP->fd = NULL;
                    smtpFlowP->smtpStat &= ~SMTP_DTP;
                    smtpFlowP->smtpStat |= SMTP_PWF;
                }
#endif // SMTP_SAVE == 1
                break;
            case TURN:
                sC = 14;
                smtpFlowP->sendCode |= SMTP_TURN;
                break;
            case AUTH:
                sC = 15;
                smtpFlowP->sendCode |= SMTP_AUTH;
                smtpFlowP->smtpStat |= SMTP_AUTP;
                break;
            default:
                goto smtppkt;
        }

        if (smtpFlowP->tCCnt >= SMTP_MAXCNM) {
            smtpFlowP->smtpStat |= SMTP_OVFL;
            goto smtppkt;
        }

        for (j = 0; j < smtpFlowP->tCCnt; j++) {
            //if (smtpFlowP->tCode[i] == *l7Hdr32) return;
            if (smtpFlowP->tCode[j] == sC) goto smtppkt;
        }
        //smtpFlowP->tCode[smtpFlowP->tCCnt++] = *l7Hdr32;
        smtpFlowP->tCode[smtpFlowP->tCCnt++] = sC;
    }

smtppkt:
    if (sPktFile) {
        fprintf(sPktFile, "0x%02" B2T_PRIX8 SEP_CHR, smtpFlowP->smtpStat);
    }
}


void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {
    smtpFlow_t *smtpFlowP = &smtpFlow[flowIndex];

    smtpStat |= smtpFlowP->smtpStat;
    smtpFileCnt += smtpFlowP->nameTCnt;

#if SMTP_SAVE == 1
    if (smtpFlowP->fd) {
        file_manager_close(t2_file_manager, smtpFlowP->fd);
        smtpFlowP->fd = NULL;
    }
#endif // SMTP_SAVE == 1

    OUTBUF_APPEND_U8(buf, smtpFlowP->smtpStat); // smtpStat

#if SMTP_BTFLD == 1
    OUTBUF_APPEND_U16(buf, smtpFlowP->sendCode);  // smtpCBF
    //OUTBUF_APPEND_U32(buf, smtpFlowP->recCode);   // smtpRBF
#endif // SMTP_BTFLD == 1

    // smtpCC
    const uint32_t tCCnt = smtpFlowP->tCCnt;
    OUTBUF_APPEND_NUMREP(buf, tCCnt);
    for (uint_fast32_t i = 0; i < tCCnt; i++) {
        OUTBUF_APPEND_STR(buf, smtpCom[smtpFlowP->tCode[i]]);
    }

    OUTBUF_APPEND_ARRAY_U16(buf, smtpFlowP->recCode, smtpFlowP->rCCnt);   // smtpRC
    OUTBUF_APPEND_ARRAY_STR(buf, smtpFlowP->nameU, smtpFlowP->nameUCnt);  // smtpUsr
    OUTBUF_APPEND_ARRAY_STR(buf, smtpFlowP->nameP, smtpFlowP->namePCnt);  // smtpPW

    OUTBUF_APPEND_U8(buf, smtpFlowP->nameSCnt);                           // smtpSANum
    OUTBUF_APPEND_U8(buf, smtpFlowP->nameTCnt);                           // smtpESANum
    OUTBUF_APPEND_U8(buf, smtpFlowP->nameRCnt);                           // smtpERANum

    OUTBUF_APPEND_ARRAY_STR(buf, smtpFlowP->nameS, smtpFlowP->nameSCnt);  // smtpSA
    OUTBUF_APPEND_ARRAY_STR(buf, smtpFlowP->nameT, smtpFlowP->nameTCnt);  // smtpESA
    OUTBUF_APPEND_ARRAY_STR(buf, smtpFlowP->nameR, smtpFlowP->nameRCnt);  // smtpERA
}


void t2PluginReport(FILE *stream) {
    if (smtpStat) {
        T2_FPLOG_AGGR_HEX0(stream, plugin_name, smtpStat);
        T2_FPLOG_NUMP(stream, plugin_name, "Number of SMTP packets", totsmtpPktCnt, numPackets);
        T2_FPLOG_NUM(stream, plugin_name, "Number of SMTP files", smtpFileCnt);
    }
}


void t2Finalize() {
#if (ENVCNTRL > 0 && SMTP_SAVE == 1)
    t2_free_env(ENV_SMTP_N, env);
#endif // (ENVCNTRL > 0 && SMTP_SAVE == 1)

    free(smtpFlow);
}
