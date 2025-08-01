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

#include "tftpDecode.h"

#include <errno.h>  // for errno


// Global variables

tftpFlow_t *tftpFlows;


// Static variables

static uint16_t tftpStat;
static uint64_t totTftpPktCnt;

#if TFTP_SAVE == 1
static uint64_t totTftpSaved;
#endif // TFTP_SAVE == 1

#if TFTP_SAVE == 1
#if ENVCNTRL > 0
static t2_env_t env[ENV_TFTP_N];
static const char *tftpFPath;
#else // ENVCNTRL == 0
static const char * const tftpFPath = TFTP_F_PATH;
#endif // ENVCNTRL
#endif // TFTP_SAVE == 1

static const char tftpCom[7][4] = {
    "---", "RRQ", "WRQ", "DTA", "ACK", "ERR", "OAK"
};

#define TFTP_SPKTMD_PRI_NONE(stat) \
    if (sPktFile) { \
        fprintf(sPktFile, \
                "0x%04" B2T_PRIX16 /* tftpStat   */ SEP_CHR \
                                   /* tftpOpcode */ SEP_CHR \
                , (uint16_t)(stat)); \
    }


// Tranalyzer functions

T2_PLUGIN_INIT("tftpDecode", "0.9.3", 0, 9);


void t2Init() {
    T2_PLUGIN_STRUCT_NEW(tftpFlows);

#if TFTP_SAVE == 1
#if ENVCNTRL > 0
    t2_get_env(PLUGIN_SRCH, ENV_TFTP_N, env);
    const uint8_t rmdir = T2_ENV_VAL_UINT(TFTP_RMDIR);
    tftpFPath = T2_ENV_VAL(TFTP_F_PATH);
#else // ENVCNTRL == 0
    const uint8_t rmdir = TFTP_RMDIR;
#endif // ENVCNTRL
    T2_MKPATH(tftpFPath, rmdir);
#endif // TFTP_SAVE == 1

    if (sPktFile) {
        fputs("tftpStat"   SEP_CHR
              "tftpOpcode" SEP_CHR
              , sPktFile);
    }
}


binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;
    BV_APPEND_H16(bv   , "tftpStat"     , "TFTP status");
    BV_APPEND_U64(bv   , "tftpPFlow"    , "TFTP parent flow");
#if TFTP_BTFLD == 1
    BV_APPEND_H8(bv    , "tftpOpCBF"    , "TFTP opcode bitfield");
    BV_APPEND_H8(bv    , "tftpErrCBF"   , "TFTP error Code bitfield");
#endif // TFTP_BTFLD == 1
    BV_APPEND_U8(bv    , "tftpNumOpcode", "TFTP number of opcodes");
#if TFTP_MAXCNM > 0
    BV_APPEND_STRC_R(bv, "tftpOpcode"   , "TFTP opcodes");
#endif // TFTP_MAXCNM > 0
    BV_APPEND_U8(bv    , "tftpNumParam" , "TFTP number of parameters");
#if TFTP_MAXCNM > 0
    BV_APPEND_STR_R(bv , "tftpParam"    , "TFTP parameters");
#endif // TFTP_MAXCNM > 0
    BV_APPEND_U8(bv    , "tftpNumErr"   , "TFTP number of errors");
#if TFTP_MAXCNM > 0
    BV_APPEND_U16_R(bv , "tftpErrC"     , "TFTP error codes");
#endif // TFTP_MAXCNM > 0
    return bv;
}


void t2OnNewFlow(packet_t* packet UNUSED, unsigned long flowIndex) {
    tftpFlow_t *tftpFlowP = &tftpFlows[flowIndex];
    memset(tftpFlowP, '\0', sizeof(*tftpFlowP));

    const flow_t * const flowP = &flows[flowIndex];
    const uint8_t proto = flowP->l4Proto;
    if (proto != L3_UDP) return;

    if ((flowP->srcPort == TFTP_PORT && flowP->dstPort > 1024) ||
         flowP->dstPort == TFTP_PORT || flowP->dstPort == TFTP_MCAST_PORT)
    {
        tftpFlowP->stat = (TFTPS_INIT | TFTPS_ACT);
        return;
    }

    const unsigned long oFlowIndex = flowP->oppositeFlowIndex;
    if (oFlowIndex != HASHTABLE_ENTRY_NOT_FOUND) {
        const tftpFlow_t * const otftpFlowP = &tftpFlows[oFlowIndex];
        if (otftpFlowP->stat & TFTPS_INIT) {
            tftpFlowP->pfi = otftpFlowP->pfi;
            tftpFlowP->stat = otftpFlowP->stat;
            tftpFlowP->sndBlk = 1;
            tftpFlowP->lstBlk = 1;
            return;
        }
    }

    flow_t parent = {
#if ETH_ACTIVATE == 2
        .ethDS = flowP->ethDS,
#endif // ETH_ACTIVATE == 2
#if IPV6_ACTIVATE == 2 || ETH_ACTIVATE > 0
        .ethType = flowP->ethType,
#endif // IPV6_ACTIVATE == 2 || ETH_ACTIVATE > 0
#if SCTP_ACTIVATE & 1
        .sctpStrm = flowP->sctpStrm,
#endif // SCTP_ACTIVATE & 1
#if SCTP_ACTIVATE & 2
        .sctpVtag = flowP->sctpVtag,
#endif // SCTP_ACTIVATE & 2
        .l4Proto = proto,
        .vlanId = flowP->vlanId,
        .srcIP = flowP->dstIP,
        .dstIP = flowP->srcIP,
        .srcPort = flowP->dstPort,
        .dstPort = TFTP_PORT,
    };

    const char * const pa = (char*)&parent.srcIP;
    unsigned long pIndex = hashTable_lookup(mainHashMap, pa);
    if (pIndex == HASHTABLE_ENTRY_NOT_FOUND) {
        parent.dstPort = TFTP_MCAST_PORT;
        pIndex = hashTable_lookup(mainHashMap, pa);
        if (pIndex == HASHTABLE_ENTRY_NOT_FOUND) return;
    }

    tftpFlows[pIndex].pfi = flowP->findex;
    tftpFlowP->pfi = flows[pIndex].findex;
    tftpFlowP->stat = (TFTPS_INIT | TFTPS_PSV);
    tftpFlows[pIndex].stat = (TFTPS_INIT | TFTPS_PSV);
    tftpFlowP->sndBlk = 1;
    tftpFlowP->lstBlk = 1;
}


#if ETH_ACTIVATE > 0
void t2OnLayer2(packet_t *packet UNUSED, unsigned long flowIndex) {
    if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;

    // This packet does not have a layer 4.
    // Print tabs to keep the packet file aligned
    TFTP_SPKTMD_PRI_NONE(0x0000);
}
#endif // ETH_ACTIVATE > 0


void t2OnLayer4(packet_t* packet, unsigned long flowIndex) {
    tftpFlow_t *tftpFlowP = &tftpFlows[flowIndex];
    if (!tftpFlowP->stat) {
        TFTP_SPKTMD_PRI_NONE(0x0000);
        return;
    }

    int32_t l7Len = packet->snapL7Len;
    char *l7HdrP = (char*)packet->l7HdrP;

    if (*l7HdrP || l7Len < 4) {
        TFTP_SPKTMD_PRI_NONE(tftpFlowP->stat);
        return;
    }

    totTftpPktCnt++;

    const uint16_t * const l7Hdr16 = (uint16_t*)l7HdrP;
#if TFTP_MAXCNM > 0
    if (tftpFlowP->opCnt >= TFTP_MAXCNM) {
        tftpFlowP->stat |= TFTPS_OVFL;
        TFTP_SPKTMD_PRI_NONE(tftpFlowP->stat);
        return;
    }
#endif // TFTP_MAXCNM > 0

    uint16_t j;
    uint32_t i;

#if TFTP_SAVE == 1
    flow_t *flowP = &flows[flowIndex];
#endif // TFTP_SAVE == 1

    const uint16_t opcode = ntohs(*l7Hdr16);
#if TFTP_MAXCNM > 0
#if TFTP_CMD_AGGR == 1
    for (i = 0; i < tftpFlowP->opCnt; i++) {
        if (tftpFlowP->opCode[i] == opcode) break;
    }
    if (i == tftpFlowP->opCnt)
#endif // TFTP_CMD_AGGR == 1
        tftpFlowP->opCode[tftpFlowP->opCnt++] = opcode;
#endif // TFTP_MAXCNM > 0

#if TFTP_BTFLD == 1
    if (opcode) tftpFlowP->opCodeBF |= (1 << (opcode-1));
#endif // TFTP_BTFLD == 1


    switch (opcode) {
        case RRQ: /* FALLTHRU */
        case WRQ: {
#if TFTP_MAXCNM == 0
            tftpFlowP->pCnt++; // TODO check for overflow
#else // TFTP_MAXCNM > 0
            if (tftpFlowP->pCnt >= TFTP_MAXCNM) {
                tftpFlowP->stat |= TFTPS_OVFL;
                break;
            }
#endif // TFTP_MAXCNM > 0

            // skip opcode
            l7HdrP += 2;
            l7Len -= 2;

            // filename
            j = i = strlen(l7HdrP);
            if (i == 0 || l7Len < 1) {
                tftpFlowP->stat |= TFTPS_RW_PLNERR;
                break;
            }

#if TFTP_MAXCNM == 0 && TFTP_SAVE == 1
            const char * const filename = l7HdrP;
#elif TFTP_MAXCNM > 0
            if (i > TFTP_MXNMLN) {
                tftpFlowP->stat |= TFTPS_TRUNC;
                i = TFTP_MXNMLN;
            }
            if ((int32_t)i > l7Len) i = l7Len - 1;
            memcpy(tftpFlowP->nameC[tftpFlowP->pCnt++], l7HdrP, i);
#endif // TFTP_MAXCNM > 0

            // skip filename
            l7HdrP += j+1;
            l7Len -= j+1;

            // mode (netascii, octet, mail)
            i = strlen(l7HdrP);
            if (i == 0 || l7Len < 1) {
                tftpFlowP->stat |= TFTPS_RW_PLNERR;
                break;
            }

#if TFTP_MAXCNM > 0
            if (i > TFTP_MXNMLN) {
                tftpFlowP->stat |= TFTPS_TRUNC;
                i = TFTP_MXNMLN;
            }
            if ((int32_t)i > l7Len) i = l7Len - 1;
            memcpy(tftpFlowP->nameC[tftpFlowP->pCnt++], l7HdrP, i);
            //for (i = 0; i < 3; i++) if (*tftpMode[i] == *l7HdrP) tftpFlowP->mode |= (1<<(i+1));
#endif // TFTP_MAXCNM > 0

#if TFTP_SAVE == 1
            char filepath[MAX_FILENAME_LEN] = {};
#if TFTP_MAXCNM > 0
            char *filename = tftpFlowP->nameC[tftpFlowP->pCnt-2];
            const size_t flen = strlen(filename);
            for (i = 0; i < flen; i++) if (filename[i] == '/') filename[i] = '_';
#endif // TFTP_MAXCNM > 0
            const size_t len = snprintf(filepath, sizeof(filepath), "%s%s_%" PRIu64 "_%c",
                    tftpFPath, filename, flowP->findex, FLOW_DIR_C(flowP));
            if (len >= sizeof(filepath)) {
                // filename was truncated...
                tftpFlowP->stat |= TFTPS_OVFL;
            }

            tftpFlowP->fd = file_manager_open(t2_file_manager, filepath, "w+b");
            if (!tftpFlowP->fd) {
                T2_PERR(plugin_name, "Failed to open file '%s': %s", filepath, strerror(errno));
                tftpFlowP->stat |= TFTPS_FERR;
                break;
            }

            totTftpSaved++;
#endif // TFTP_SAVE == 1
            break;
        }

        case DATA: {
            // Block number
            const uint16_t blockN = ntohs(*(l7Hdr16+1));
            if (blockN != tftpFlowP->sndBlk) tftpFlowP->stat |= TFTPS_BSERR;
            tftpFlowP->sndBlk = blockN + 1;
#if TFTP_SAVE == 1
            tftpFlow_t *tftpFlowPO = NULL;
            if (tftpFlowP->stat & TFTPS_ACT) {
                if (FLOW_HAS_OPPOSITE(flowP)) tftpFlowPO = &tftpFlows[flowP->oppositeFlowIndex];
            } else {
                tftpFlowPO = &tftpFlows[tftpFlowP->pfi - 1];
            }
            if (tftpFlowPO && tftpFlowPO->fd) {
                FILE * const fp = file_manager_fp(t2_file_manager, tftpFlowPO->fd);
                fseek(fp, (blockN-1)*512, SEEK_SET);
                i = l7Len - 4;
                fwrite(l7HdrP+4, 1, i, fp);
                if (i < 512) {
                    file_manager_close(t2_file_manager, tftpFlowPO->fd);
                    tftpFlowPO->fd = NULL;
                }
            }
#endif // TFTP_SAVE == 1
            break;
        }

        case ACK: {
            // Block number
            const uint16_t blockN = ntohs(*(l7Hdr16+1));
            if (blockN) {
                if (blockN != tftpFlowP->lstBlk) tftpFlowP->stat |= TFTPS_BSAERR;
                tftpFlowP->lstBlk = blockN + 1;
            }
            break;
        }

        case ERR: {
#if TFTP_SAVE == 1
            if (tftpFlowP->fd) {
                file_manager_close(t2_file_manager, tftpFlowP->fd);
                tftpFlowP->fd = NULL;
            }
#endif // TFTP_SAVE == 1

            // Error code
#if TFTP_BTFLD == 1 || TFTP_MAXCNM > 0
            const uint16_t errCode = ntohs(*(l7Hdr16+1)) - 1;
#endif // TFTP_BTFLD == 1 || TFTP_MAXCNM > 0

#if TFTP_BTFLD == 1
            tftpFlowP->errCodeBF |= (1 << errCode);
#endif // TFTP_BTFLD == 1

#if TFTP_MAXCNM == 0
            tftpFlowP->errCnt++; // TODO check for overflow?
#else // TFTP_MAXCNM > 0
            if (tftpFlowP->errCnt >= TFTP_MAXCNM) {
                tftpFlowP->stat |= TFTPS_OVFL;
                break;
            }

#if TFTP_CMD_AGGR == 1
            for (i = 0; i < tftpFlowP->errCnt; i++) {
                if (tftpFlowP->errCode[i] == errCode) break;
            }
            if (i == tftpFlowP->errCnt)
#endif // TFTP_CMD_AGGR == 1
                tftpFlowP->errCode[tftpFlowP->errCnt++] = errCode;
#endif // TFTP_MAXCNM > 0

            // Error message (null terminated)
            break;
        }

        case OACK:
            break;

        default:
            tftpFlowP->stat |= TFTPS_PERR;
            break;
    }

    if (sPktFile) {
        fprintf(sPktFile,
                "0x%04" B2T_PRIX16 /* tftpStat   */ SEP_CHR
                "%s"               /* tftpOpcode */ SEP_CHR
                , tftpFlowP->stat, tftpCom[((opcode < 7) ? opcode : 0)]);
    }
}


void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {
    tftpFlow_t *tftpFlowP = &tftpFlows[flowIndex];

    tftpStat |= tftpFlowP->stat;

#if TFTP_SAVE == 1
    if (tftpFlowP->fd) {
        file_manager_close(t2_file_manager, tftpFlowP->fd);
        tftpFlowP->fd = NULL;
    }
#endif

    OUTBUF_APPEND_U16(buf, tftpFlowP->stat);      // tftpStat
    OUTBUF_APPEND_U64(buf, tftpFlowP->pfi);       // tftpPFlw

#if TFTP_BTFLD == 1
    OUTBUF_APPEND_U8(buf, tftpFlowP->opCodeBF);   // tftpOpCBF
    OUTBUF_APPEND_U8(buf, tftpFlowP->errCodeBF);  // tftpErrCBF
#endif // TFTP_BTFLD == 1

    OUTBUF_APPEND_U8(buf, tftpFlowP->opCnt);      // tftpNumOpcode

#if TFTP_MAXCNM > 0
    // tftpOpcode
    const uint32_t cnt = tftpFlowP->opCnt;
    OUTBUF_APPEND_NUMREP(buf, cnt);
    for (uint_fast32_t i = 0; i < cnt; i++) {
        uint8_t opcode = tftpFlowP->opCode[i];
        if (opcode >= 7) opcode = 0;
        OUTBUF_APPEND_STR(buf, tftpCom[opcode]);
    }
#endif // TFTP_MAXCNM > 0

    OUTBUF_APPEND_U8(buf, tftpFlowP->pCnt);                              // tftpNumParam

#if TFTP_MAXCNM > 0
    OUTBUF_APPEND_ARRAY_STR(buf, tftpFlowP->nameC, tftpFlowP->pCnt);     // tftpParam
#endif // TFTP_MAXCNM > 0

    OUTBUF_APPEND_U8(buf, tftpFlowP->errCnt);                            // tftpNumErr

#if TFTP_MAXCNM > 0
    OUTBUF_APPEND_ARRAY_U16(buf, tftpFlowP->errCode, tftpFlowP->errCnt); // tftpErrC
#endif // TFTP_MAXCNM > 0
}


void t2PluginReport(FILE *stream) {
    if (tftpStat) {
        T2_FPLOG_AGGR_HEX0(stream, plugin_name, tftpStat);
        T2_FPLOG_NUMP(stream, plugin_name, "Number of TFTP packets", totTftpPktCnt, numPackets);
#if TFTP_SAVE == 1
        T2_FPLOG_NUM(stream, plugin_name, "Number of files extracted", totTftpSaved);
#endif
    }
}


void t2Finalize() {
#if (ENVCNTRL > 0 && TFTP_SAVE == 1)
    t2_free_env(ENV_TFTP_N, env);
#endif // (ENVCNTRL > 0 && TFTP_SAVE == 1)

    free(tftpFlows);
}
