/*
 * telnetDecode.c
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

#include "telnetDecode.h"
#include "telnet_utils.h"

#include <errno.h>  // for errno


// Global variables

telFlow_t *telFlows;


// Static variables

static uint64_t totTelPktCnt;
static uint16_t telStat;

#if TEL_SAVE == 1
static uint64_t totTelSaved;
#if ENVCNTRL > 0
static const char *telFPath;
#else // ENVCNTRL == 0
static const char * const telFPath = TEL_F_PATH;
#endif // ENVCNTRL
#endif // TEL_SAVE == 1


#define TEL_SPKTMD_PRI_NONE() \
    if (sPktFile) { \
        fputs("0x00" /* telStat         */ SEP_CHR \
                     /* telCmdS/telCmdC */ SEP_CHR \
                     /* telOptS/telOptC */ SEP_CHR \
              , sPktFile); \
    }


// Tranalyzer functions

T2_PLUGIN_INIT("telnetDecode", "0.9.3", 0, 9);


void t2Init() {
    T2_PLUGIN_STRUCT_NEW(telFlows);

#if TEL_SAVE == 1
#if ENVCNTRL > 0
    t2_env_t env[ENV_TEL_N];
    t2_get_env(PLUGIN_SRCH, ENV_TEL_N, env);
    const uint8_t rmdir = T2_ENV_VAL_UINT(TEL_RMDIR);
    telFPath = T2_STEAL_ENV_VAL(TEL_F_PATH);
#else // ENVCNTRL == 0
    const uint8_t rmdir = TEL_RMDIR;
#endif // ENVCNTRL

    T2_MKPATH(telFPath, rmdir);

#if ENVCNTRL > 0
    t2_free_env(ENV_TEL_N, env);
#endif // ENVCNTRL > 0
#endif // TEL_SAVE == 1

    if (sPktFile) {
        fputs("telStat" SEP_CHR
#if TEL_CMDOPTS == 1
              "telCmdS" SEP_CHR
              "telOptS" SEP_CHR
#else // TEL_CMDOPTS == 0
              "telCmdC" SEP_CHR
              "telOptC" SEP_CHR
#endif // TEL_CMDOPTS
              , sPktFile);
    }
}


binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;

    BV_APPEND_H8(bv,    "telStat" , "Telnet status");
#if TEL_BTFLD == 1
    BV_APPEND_H16(bv,   "telCmdBF", "Telnet commands");
    BV_APPEND_H32(bv,   "telOptBF", "Telnet options");
#endif // TEL_BTFLD == 1

    BV_APPEND_STRC(bv,  "telUsr"  , "Telnet user");
    BV_APPEND_STRC(bv,  "telPW"   , "Telnet password");

    BV_APPEND_U16(bv,   "telCCnt" , "Telnet command count");
#if TEL_CMDOPTS == 1
    BV_APPEND_STR_R(bv, "telCmdS" , "Telnet command names");
#else // TEL_CMDOPTS == 0
    BV_APPEND_U8_R(bv,  "telCmdC" , "Telnet command codes");
#endif // TEL_CMDOPTS
    BV_APPEND_U16(bv,   "telOCnt" , "Telnet option count");
#if TEL_CMDOPTS == 1
    BV_APPEND_STR_R(bv, "telOptS" , "Telnet option names");
#else // TEL_CMDOPTS == 0
    BV_APPEND_U8_R(bv,  "telOptC" , "Telnet option codes");
#endif // TEL_CMDOPTS

    return bv;
}


void t2OnNewFlow(packet_t* packet, unsigned long flowIndex) {
    telFlow_t *telFlowP = &telFlows[flowIndex];
    memset(telFlowP, '\0', sizeof(*telFlowP));

    const uint_fast8_t proto = packet->l4Proto;
    // check also whether a passive telnet connection matches a port 23 connection using hash
    if (proto == L3_TCP || proto == L3_SCTP) {
        const flow_t * const flowP = &flows[flowIndex];
        if (flowP->dstPort == TLNTPRT || flowP->srcPort == TLNTPRT) {
            telFlowP->stat |= TEL_INIT;
#if TEL_SAVE == 1
#if TEL_SAVE_SPLIT == 0
            if (FLOW_HAS_OPPOSITE(flowP)) {
                telFlowP->fd = telFlows[flowP->oppositeFlowIndex].fd;
            } else {
#endif // TEL_SAVE_SPLIT == 0
                char filepath[MAX_FILENAME_LEN];
#if TEL_SAVE_SPLIT == 0
                const char * const dir = "AB";
#else // TEL_SAVE_SPLIT == 1
                const char * const dir = FLOW_DIR_S(flowP);
#endif // TEL_SAVE_SPLIT == 1
                const size_t len = snprintf(filepath, sizeof(filepath), "%stelnet_flow_%" PRIu64 "_%s",
                        telFPath, flowP->findex, dir);
                if (len >= sizeof(filepath)) {
                    T2_PERR(plugin_name, "Failed to open file '%s...': filename too long", filepath);
                    telFlowP->stat |= TEL_OFERR;
                    return;
                }

                telFlowP->fd = file_manager_open(t2_file_manager, filepath, "w+b");
                if (UNLIKELY(!telFlowP->fd)) {
                    T2_PERR(plugin_name, "Failed to open file '%s': %s", filepath, strerror(errno));
                    telFlowP->stat |= TEL_OFERR;
                    return;
                }

                telFlowP->stat |= TEL_FWRT;
                totTelSaved++;
#if TEL_SAVE_SPLIT == 0
            }
#endif // TEL_SAVE_SPLIT == 0

            const tcpHeader_t * const tcpHdrP = TCP_HEADER(packet);
            const uint32_t tcpSeq = ((proto == L3_TCP) ? ntohl(tcpHdrP->seq) : 0);
            telFlowP->seqInit = tcpSeq;
#endif // TEL_SAVE == 1
        }
    }
}


#if ETH_ACTIVATE > 0
void t2OnLayer2(packet_t *packet UNUSED, unsigned long flowIndex) {
    if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;

    // This packet does not have a layer 4.
    // Print tabs to keep the packet file aligned
    if (sPktFile) TEL_SPKTMD_PRI_NONE();
}
#endif // ETH_ACTIVATE > 0


void t2OnLayer4(packet_t *packet, unsigned long flowIndex) {
    telFlow_t *telFlowP = &telFlows[flowIndex];
    if (!telFlowP->stat) {
        TEL_SPKTMD_PRI_NONE();
        return;
    }

    totTelPktCnt++;

    int32_t l7Len = packet->snapL7Len;

    if (l7Len < MINTELLEN) {
        TEL_SPKTMD_PRI_NONE();
        return;
    }

    const uint8_t *l7Hdru = (uint8_t*)packet->l7HdrP;
    uint8_t cmd = 0, subcmd = 0;

    if (*l7Hdru == TELCMD) {
        while (*l7Hdru == TELCMD && l7Len >= 2) {
            cmd = *(++l7Hdru) & 0x0f;
            subcmd = *(++l7Hdru);
            l7Len -= 2;
            if (telFlowP->cmdCnt >= TELCMDN) {
                telFlowP->stat |= TEL_CMD_OVFL;
            } else {
#if TEL_CMD_AGGR == 1
                for (uint_fast32_t i = 0; i < telFlowP->cmdCnt; i++) {
                    if (telFlowP->cmdCode[i] == cmd) goto cmdkn;
                }

#endif // TEL_CMD_AGGR == 1
                telFlowP->cmdCode[telFlowP->cmdCnt++] = cmd;
            }
#if TEL_CMD_AGGR == 1
cmdkn:
#endif // TEL_CMD_AGGR == 1
#if TEL_BTFLD == 1
            telFlowP->cmdBF |= (1 << cmd);
            telFlowP->optBF |= (1 << subcmd);
#endif // TEL_BTFLD == 1

            switch (cmd) {
                case SE:
                case NOP:
                case DM:
                case BRK:
                case IP:
                case AO:
                case AYT:
                case EC:
                case EL:
                case GA:
                case SB:
                    while (*l7Hdru != SE && l7Len > 0) {
                        l7Hdru++;
                        l7Len--;
                    }
                    break;
                case WILL:
                case WONT:
                case DO:
                case DONT:
                    if (telFlowP->optCnt >= TELOPTN) {
                        telFlowP->stat |= TEL_OPT_OVFL;
                    } else {
                        const uint8_t opt = *l7Hdru;
#if TEL_OPT_AGGR == 1
                        for (uint_fast32_t i = 0; i < telFlowP->optCnt; i++) {
                            if (telFlowP->optCode[i] == opt) goto optkn;
                        }
#endif // TEL_OPT_AGGR == 1
                        telFlowP->optCode[telFlowP->optCnt++] = opt;
                    }
#if TEL_OPT_AGGR == 1
optkn:
#endif // TEL_OPT_AGGR == 1
                    l7Hdru++;
                    l7Len--;
                    break;
                default:
                    break;
            } // end switch
        } // end while
    } else {
        if (memmem(l7Hdru, 6, "login:", 6)) {
            const unsigned long long oindex = flows[flowIndex].oppositeFlowIndex;
            if (oindex != HASHTABLE_ENTRY_NOT_FOUND) telFlows[oindex].stat |= TEL_USR;
        }
        if (memmem(l7Hdru, 9, "Password:", 9)) {
            const unsigned long long oindex = flows[flowIndex].oppositeFlowIndex;
            if (oindex != HASHTABLE_ENTRY_NOT_FOUND) telFlows[oindex].stat |= TEL_PWD;
        }

        if (telFlowP->stat & TEL_USR) {
            if (*l7Hdru == '\r') {
                telFlowP->user[telFlowP->idx] = '\0';
                telFlowP->stat &= ~TEL_USR;
                telFlowP->idx = 0;
            } else {
                if (l7Len == 1) {
                    if (telFlowP->idx < TELUPLN) telFlowP->user[telFlowP->idx++] = *l7Hdru;
                    else telFlowP->idx = TELUPLN;
                } else {
                    const uint8_t * const s = memchr(l7Hdru, '\r', l7Len);
                    int i = (s) ? (int)(s - l7Hdru) : l7Len;
                    if (i > TELUPLN) i = TELUPLN;
                    memcpy(telFlowP->user, l7Hdru, i);
                    telFlowP->user[i] = '\0';
                    telFlowP->stat &= ~TEL_USR;
                }
            }
        }

        if (telFlowP->stat & TEL_PWD) {
            if (*l7Hdru == '\r') {
                telFlowP->passwd[telFlowP->idx] = '\0';
                telFlowP->stat &= ~TEL_PWD;
                telFlowP->idx = 0;
            } else {
                if (l7Len == 1) {
                    if (telFlowP->idx < TELUPLN) telFlowP->passwd[telFlowP->idx++] = *l7Hdru;
                    else telFlowP->idx = TELUPLN;
                } else {
                    const uint8_t * const s = memchr(l7Hdru, '\r', l7Len);
                    int i = (s) ? (int)(s - l7Hdru) : l7Len;
                    if (i >= TELUPLN) i = TELUPLN;
                    memcpy(telFlowP->passwd, l7Hdru, i);
                    telFlowP->passwd[i] = '\0';
                    telFlowP->stat &= ~TEL_PWD;
                }
            }
        }

#if TEL_SAVE == 1
        if (!(telFlowP->stat & TEL_OFERR)) {
            FILE * const fp = file_manager_fp(t2_file_manager, telFlowP->fd);
#if TEL_SEQPOS == 1
            const tcpHeader_t * const tcpHdrP = TCP_HEADER(packet);
            if (packet->l4Proto == L3_TCP) {
                const long seqDiff = ntohl(tcpHdrP->seq) - telFlowP->seqInit;
                fseek(fp, seqDiff, SEEK_SET);
            }
#endif // TEL_SEQPOS == 1
            fwrite(packet->l7HdrP, 1, l7Len , fp);
        }
#endif // TEL_SAVE == 1
    }

    if (sPktFile) {
#if TEL_CMDOPTS == 1
        fprintf(sPktFile,
                "0x%02" B2T_PRIX8 /* telStat */ SEP_CHR
                "%s"              /* telCmdS */ SEP_CHR
                "%s"              /* telOptS */ SEP_CHR
                , telFlowP->stat
                , telCmdS[cmd]
                , telOpt[subcmd]);
#else // TEL_CMDOPTS == 0
        fprintf(sPktFile,
                "0x%02" B2T_PRIX8 /* telStat */ SEP_CHR
                "%"     PRIu8     /* telCmdC */ SEP_CHR
                "%"     PRIu8     /* telOptC */ SEP_CHR
                , telFlowP->stat
                , cmd
                , subcmd);
#endif // TEL_CMDOPTS
    }
}


void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {
    telFlow_t *telFlowP = &telFlows[flowIndex];

    telStat |= telFlowP->stat;

#if TEL_SAVE == 1
    if (telFlowP->fd) {
        file_manager_close(t2_file_manager, telFlowP->fd);
        telFlowP->fd = NULL;
#if TEL_SAVE_SPLIT == 0
        const flow_t * const flowP = &flows[flowIndex];
        if (FLOW_HAS_OPPOSITE(flowP)) telFlows[flowP->oppositeFlowIndex].fd = NULL;
#endif // TEL_SAVE_SPLIT == 0
    }
#endif // TEL_SAVE == 1

    OUTBUF_APPEND_U8(buf,  telFlowP->stat);     // telStat
#if TEL_BTFLD == 1
    OUTBUF_APPEND_U16(buf, telFlowP->cmdBF);    // telCmdBF
    OUTBUF_APPEND_U32(buf, telFlowP->optBF);    // telOptBF
#endif // TEL_BTFLD == 1

    OUTBUF_APPEND_STR(buf, telFlowP->user);     // telUsr
    OUTBUF_APPEND_STR(buf, telFlowP->passwd);   // telPW

    OUTBUF_APPEND_U16(buf, telFlowP->cmdCnt);   // telCCnt

    // telCmdS/telCmdC
    uint32_t cnt = telFlowP->cmdCnt;
    OUTBUF_APPEND_NUMREP(buf, cnt);
    for (uint_fast32_t i = 0; i < cnt; i++) {
#if TEL_CMDOPTS == 1
        OUTBUF_APPEND_STR(buf, telCmdS[telFlowP->cmdCode[i]]); // telCmdS
#else // TEL_CMDOPTS == 0
        OUTBUF_APPEND_U8(buf, telFlowP->cmdCode[i]);           // telCmdC
#endif // TEL_CMDOPTS
    }

    OUTBUF_APPEND_U16(buf, telFlowP->optCnt);                  // telOCnt

    // telOptS/telOptC
    cnt = telFlowP->optCnt;
    OUTBUF_APPEND_NUMREP(buf, cnt);
    for (uint_fast32_t i = 0; i < cnt; i++) {
#if TEL_CMDOPTS == 1
        OUTBUF_APPEND_STR(buf, telOpt[telFlowP->optCode[i]]);  // telOptS
#else // TEL_CMDOPTS == 0
        OUTBUF_APPEND_U8(buf, telFlowP->optCode[i]);           // telOptC
#endif // TEL_CMDOPTS
    }
}


void t2PluginReport(FILE *stream) {
    if (telStat) {
        T2_FPLOG_AGGR_HEX0(stream, plugin_name, telStat);
        T2_FPLOG_NUMP(stream, plugin_name, "Number of Telnet packets", totTelPktCnt, numPackets);
#if TEL_SAVE == 1
        T2_FPLOG_NUM(stream, plugin_name, "Number of files extracted", totTelSaved);
#endif // TEL_SAVE == 1
    }
}


void t2Finalize() {
#if (TEL_SAVE == 1 && ENVCNTRL > 0)
    free((char*)telFPath);
#endif // (TEL_SAVE == 1 && ENVCNTRL > 0)

    free(telFlows);
}
