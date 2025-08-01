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

#include "ftpDecode.h"

#include <errno.h>  // for errno


// Global variables

ftpFlow_t *ftpFlows;


// Static variables

static hashMap_t *ftpHashMap;
static uint64_t *ftpFindex;
static uint64_t totFtpPktCnt, totFtpPktCnt0;
static uint64_t totFtpDPktCnt, totFtpDPktCnt0;
static uint64_t totFtpDByteCnt, totFtpDByteCnt0;
static uint8_t ftpStat;

#if FTP_SAVE == 1
static uint64_t totFtpSaved;
#endif // FTP_SAVE == 1

#if ENVCNTRL > 0
static t2_env_t env[ENV_FTP_N];
#if FTP_SAVE == 1
static const char *ftpFPath;
#endif // FTP_SAVE == 1
static const char *ftpNoName;
#else // ENVCNTRL == 0
#if FTP_SAVE == 1
static const char * const ftpFPath = FTP_F_PATH;
#endif // FTP_SAVE == 1
static const char * const ftpNoName = FTP_NONAME;
#endif // ENVCNTRL

static const char ftpCom[61][5] = {
    "ABOR", "ACCT", "ADAT", "ALLO", "APPE", "AUTH",
    "CCC" , "CDUP", "CONF", "CWD" , "DELE", "ENC" ,
    "EPRT", "EPSV", "FEAT", "HELP", "LANG", "LIST",
    "LPRT", "LPSV", "MDTM", "MIC" , "MKD" , "MLSD",
    "MLST", "MODE", "NLST", "NOOP", "OPTS", "PASS",
    "PASV", "PBSZ", "PORT", "PROT", "PWD" , "QUIT",
    "REIN", "REST", "RETR", "RMD" , "RNFR", "RNTO",
    "SITE", "SIZE", "SMNT", "STAT", "STOR", "STOU",
    "STRU", "SYST", "TYPE", "USER", "XCUP", "XMKD",
    "XPWD", "XRCP", "XRMD", "XRSQ", "XSEM", "XSEN",
    "CLNT"
};


// Tranalyzer functions

T2_PLUGIN_INIT("ftpDecode", "0.9.3", 0, 9);


void t2Init() {
    T2_PLUGIN_STRUCT_NEW(ftpFlows);

#if ENVCNTRL > 0
    t2_get_env(PLUGIN_SRCH, ENV_FTP_N, env);
#if FTP_SAVE == 1
    const uint8_t rmdir = T2_ENV_VAL_UINT(FTP_RMDIR);
    ftpFPath = T2_ENV_VAL(FTP_F_PATH);
#endif // FTP_SAVE == 1
    ftpNoName = T2_ENV_VAL(FTP_NONAME);
#else // ENVCNTRL == 0
#if FTP_SAVE == 1
    const uint8_t rmdir = FTP_RMDIR;
#endif // FTP_SAVE == 1
#endif // ENVCNTRL

#if FTP_SAVE == 1
    T2_MKPATH(ftpFPath, rmdir);
#endif // FTP_SAVE == 1

    flow_t fF;

    // initialize FTP data pair hash and the counter arrays
    ftpHashMap = hashTable_init(1.0f, ((char*) &fF.l4Proto - (char*) &fF.srcIP + sizeof(fF.l4Proto)), "ftp");
    ftpFindex = t2_calloc_fatal(ftpHashMap->hashChainTableSize, sizeof(uint64_t));

    if (sPktFile) fputs("ftpStat" SEP_CHR, sPktFile);
}


binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;
    BV_APPEND_H8(bv    , "ftpStat"    , "FTP status");
    BV_APPEND_U64_R(bv , "ftpCDFindex", "FTP command/data findex link");
#if FTP_BTFLD == 1
    BV_APPEND_H64(bv   , "ftpCBF"     , "FTP command bitfield");
    //BV_APPEND_H32(bv   , "ftpRBF"     , "FTP response bitfield");
#endif // FTP_BTFLD == 1
    BV_APPEND_STRC_R(bv, "ftpCC"     , "FTP command codes");
    BV_APPEND_U16_R(bv , "ftpRC"     , "FTP response codes");
    BV_APPEND_U8(bv    , "ftpNumUser", "FTP number of users");
    BV_APPEND_STR_R(bv , "ftpUser"   , "FTP users");
    BV_APPEND_U8(bv    , "ftpNumPass", "FTP number of passwords");
    BV_APPEND_STR_R(bv , "ftpPass"   , "FTP passwords");
    BV_APPEND_U8(bv    , "ftpNumCP"  , "FTP number of command parameters");
    BV_APPEND_STR_R(bv , "ftpCP"     , "FTP command parameters");
    BV_APPEND_U32(bv   , "ftpPLen"   , "FTP passive file length");
    return bv;
}


void t2OnNewFlow(packet_t* packet UNUSED, unsigned long flowIndex) {
    ftpFlow_t *ftpFlowP = &ftpFlows[flowIndex];
    memset(ftpFlowP, '\0', sizeof(*ftpFlowP));

    const flow_t * const flowP = &flows[flowIndex];
    const uint_fast8_t proto = flowP->l4Proto;
    if (proto != L3_TCP && proto != L3_SCTP) return;

    // check also whether a passive FTP connection matches a port 21 connection using hash
    const uint_fast16_t sport = flowP->srcPort;
    const uint_fast16_t dport = flowP->dstPort;
    if (dport == FTP_CTRL_PORT || sport == FTP_CTRL_PORT) {
        ftpFlowP->stat = FTP_INIT;
    } else if (dport == FTP_DATA_PORT || dport > 1024 ||
               sport == FTP_DATA_PORT || sport > 1024)
    {
        const flow_t client = {
            .vlanId = flowP->vlanId,
#if IPV6_ACTIVATE == 2 || ETH_ACTIVATE > 0
            .ethType = flowP->ethType,
#endif // IPV6_ACTIVATE == 2 || ETH_ACTIVATE > 0
#if SCTP_ACTIVATE & 1
            .sctpStrm = flowP->sctpStrm,
#endif // SCTP_ACTIVATE & 1
#if SCTP_ACTIVATE & 2
            .sctpVtag = flowP->verTag;
#endif // SCTP_ACTIVATE & 2
            .l4Proto = flowP->l4Proto,
            .srcIP = flowP->srcIP,
            .dstIP = flowP->dstIP,
            .dstPort = (FLOW_HAS_OPPOSITE(flowP) ? sport : dport),
        };

        uint64_t pFindex = hashTable_lookup(ftpHashMap, (char*)&client.srcIP);
        if (pFindex != HASHTABLE_ENTRY_NOT_FOUND) return;

        pFindex = hashTable_insert(ftpHashMap, (char*)&client.srcIP);
        if (pFindex == HASHTABLE_ENTRY_NOT_FOUND) {
            if (!(ftpStat & FTP_HSHMFLL)) {
                ftpStat |= FTP_HSHMFLL;
                T2_PWRN(plugin_name, "%s HashMap full", ftpHashMap->name);
            }
            return;
        }

        if (ftpStat & FTP_HSHMFLL) {
            T2_PWRN(plugin_name, "%s HashMap free", ftpHashMap->name);
            ftpStat &= ~FTP_HSHMFLL;
        }

        ftpFindex[pFindex] = flowP->flowIndex;
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
    ftpFlow_t *ftpFlowP = &ftpFlows[flowIndex];
    if (!ftpFlowP->stat) goto ftppkt;
/*
#if FTP_SAVE == 1
    if (ftpFlowP->stat & FTP_PPWF) {
        totFtpDPktCnt++;
        goto ftppkt;
    }
#endif // FTP_SAVE == 1
*/

    int32_t l7Len = packet->snapL7Len;
    char *l7HdrP = (char*)packet->l7HdrP, *s, *t;

    const flow_t * const flowP = &flows[flowIndex];
    if (ftpFlowP->stat & FTP_INIT) {
        totFtpPktCnt++;
    } else {
        totFtpDPktCnt++;
    }

    if (l7Len < 4) goto ftppkt;

#if FTP_SAVE == 1
    const tcpHeader_t * const tcpHdrP = TCP_HEADER(packet);
    const uint32_t tcpSeq = (PROTO_IS_TCP(packet) ? ntohl(tcpHdrP->seq) : 0);
#endif // FTP_SAVE == 1

    if (ftpFlowP->stat & FTP_PPRNT) {
#if FTP_SAVE == 1
        if (!ftpFlowP->fd) {
            char *filename;
            if (UNLIKELY(ftpFlowP->nameCCnt == 0)) {
                filename = (char*)ftpNoName; // should not happen
            } else {
                filename = ftpFlowP->nameC[ftpFlowP->nameCCnt-1];
                const size_t fLen = strlen(filename);
                for (size_t i = 0; i < fLen; i++) if (filename[i] == '/') filename[i] = '_';
            }

            char filepath[MAX_FILENAME_LEN] = {};
            const size_t len = snprintf(filepath, sizeof(filepath), "%s%s_%" PRIu64 "_%c",
                    ftpFPath, filename, flowP->findex, FLOW_DIR_C(flowP));
            if (len >= sizeof(filepath)) {
                // filename was truncated...
                ftpFlowP->stat |= FTP_OVFL;
            }

            ftpFlowP->fd = file_manager_open(t2_file_manager, filepath, "w+b");
            if (!ftpFlowP->fd) {
                T2_PERR(plugin_name, "Failed to open file '%s': %s", filepath, strerror(errno));
                ftpFlowP->stat |= FTP_PPWFERR;
                goto ftppkt;
            }

            //if (ftpFlowP->cLen) ftpFlowP->dwLen = ftpFlowP->cLen;
            //else ftpFlowP->dwLen = l7Len;
            ftpFlowP->seqInit = tcpSeq;

            totFtpSaved++;
        }

        //if (ftpFlowP->dwLen > 0) {
            FILE * const fp = file_manager_fp(t2_file_manager, ftpFlowP->fd);
            if (packet->l4Proto == L3_TCP) {
                const long seqDiff = tcpSeq - ftpFlowP->seqInit;
                fseek(fp, seqDiff, SEEK_SET);
            }
            fwrite(l7HdrP, 1, l7Len, fp);
            ftpFlowP->dwLen += l7Len;
            if (ftpFlowP->dwLen > ftpFlowP->cLen) ftpFlowP->stat |= FTP_PPWF;
        //}

    /*    if (ftpFlowP->dwLen == 0) {
            file_manager_close(t2_file_manager, ftpFlowP->fd);
            ftpFlowP->fd = NULL;
            ftpFlowP->stat |= FTP_PPWF;
        }*/
#endif // FTP_SAVE == 1
        goto ftppkt;
#if FTP_SAVE == 1
    } else {
        if (!ftpFlowP->fd) {
            char filepath[MAX_FILENAME_LEN] = {};
            const size_t len = snprintf(filepath, sizeof(filepath), "%sftp_flow_%" PRIu64 "_%c.txt",
                    ftpFPath, flowP->findex, FLOW_DIR_C(flowP));
            if (len >= sizeof(filepath)) {
                // filename was truncated...
                ftpFlowP->stat |= FTP_OVFL;
            }

            ftpFlowP->fd = file_manager_open(t2_file_manager, filepath, "w+");
            if (!ftpFlowP->fd) {
                T2_PERR(plugin_name, "Failed to open file '%s': %s", filepath, strerror(errno));
                ftpFlowP->stat |= FTP_PPWFERR;
                goto ftppkt;
            }

            ftpFlowP->seqInit = tcpSeq;
        }

        FILE * const fp = file_manager_fp(t2_file_manager, ftpFlowP->fd);
        const long seqDiff = tcpSeq - ftpFlowP->seqInit;
        fseek(fp, seqDiff, SEEK_SET);
        fwrite(l7HdrP, 1, l7Len , fp);
        ftpFlowP->dwLen += l7Len;
        if (ftpFlowP->dwLen > ftpFlowP->cLen) ftpFlowP->stat |= FTP_PPWF;
#endif // FTP_SAVE == 1
    }

    uint32_t i, j;
    uint32_t l7Hdr32 = *(uint32_t*)l7HdrP;
    if (FLOW_IS_B(flowP)) {
        i = l7Hdr32 & 0xffffff;
        const uint32_t recCode = strtoul((char*)&i, NULL, 0);

        if (ftpFlowP->rCCnt >= FTP_MAXCNM) {
            ftpFlowP->stat |= FTP_OVFL;
        } else {
#if FTP_CMD_AGGR == 1
            for (i = 0; i < ftpFlowP->rCCnt; i++) {
                if (ftpFlowP->recCode[i] == recCode) break;
            }
            if (i == ftpFlowP->rCCnt)
#endif // FTP_CMD_AGGR == 1
                ftpFlowP->recCode[ftpFlowP->rCCnt++] = recCode;
        }

        switch (recCode) {
            case 213: // File Status
                if (memchr(l7HdrP, '\r', l7Len) != NULL) {
                    ftpFlowP->cLen = atoll(l7HdrP+4);
                }
                break;
            case 215: // NAME system type
                if (ftpFlowP->nameCCnt >= FTP_MAXCNM) {
                    ftpFlowP->stat |= FTP_OVFL;
                } else if ((s = memchr(l7HdrP, '\r', l7Len)) != NULL) {
                    const size_t len = s - l7HdrP;
                    memcpy(ftpFlowP->nameC[ftpFlowP->nameCCnt++], l7HdrP, MIN(len, FTP_MXNMLN));
                }
                break;
            case 227: { // Entering Passive mode (h1,h2,h3,h4,p1,p2)
                if (memchr(l7HdrP, '\r', l7Len) != NULL) {
                    if (!(s = memchr(l7HdrP, ',', l7Len))) break;
                    s++; // skip the comma
                    const uint8_t h1 = strtoul(l7HdrP + 5, NULL, 0);
                    const uint8_t h2 = strtoul(s, NULL, 0);
                    if (!(s = memchr(s, ',', l7Len - (s - l7HdrP)))) break;
                    s++; // skip the comma
                    const uint8_t h3 = strtoul(s, NULL, 0);
                    if (!(s = memchr(s, ',', l7Len - (s - l7HdrP)))) break;
                    s++; // skip the comma
                    const uint8_t h4 = strtoul(s, NULL, 0);
                    ftpFlowP->pslAddr = (h1 << 24 | h2 << 16 | h3 << 8 | h4);
                    if (!(s = memchr(s, ',', l7Len - (s - l7HdrP)))) break;
                    s++; // skip the comma
                    const uint8_t p1 = strtoul(s, NULL, 0);
                    if (!(s = memchr(s, ',', l7Len - (s - l7HdrP)))) break;
                    s++; // skip the comma
                    const uint8_t p2 = strtoul(s, NULL, 0);
                    const uint16_t port = (p1 << 8) + p2;
                    ftpFlowP->pcrPort = port;
                    ftpFlowP->stat |= FTP_APRNT;
                    ftpFlow_t * const ftpFlowPO = (FLOW_HAS_OPPOSITE(flowP) ? &ftpFlows[flowP->oppositeFlowIndex] : NULL);
                    if (ftpFlowPO) {
                        ftpFlowPO->pcrPort = port;
                        ftpFlowPO->stat |= FTP_APRNT;
                    }
                }
                break;
            }
            case 125: // Data connection already open; transfer starting
            case 150: // File status okay; about to open data connection
                if ((t = memmem(l7HdrP, l7Len, "for", 3))) {
                    t += 4;
                } else {
                    t = l7HdrP;
                    ftpFlowP->stat |= FTP_NDFLW;
                }

                if ((s = memrchr(l7HdrP, '(', l7Len)) != NULL) {
                    ftpFlowP->cLen = atoll(s+1);
                    s--;
                } else {
                    if (!(s = memchr(l7HdrP, '\r', l7Len))) s = l7HdrP + l7Len;
                    //ftpFlowP->cLen = 0; //check why
                }

                const flow_t client = {
                    .vlanId = flowP->vlanId,
#if IPV6_ACTIVATE == 2 || ETH_ACTIVATE > 0
                    .ethType = flowP->ethType,
#endif // IPV6_ACTIVATE == 2 || ETH_ACTIVATE > 0
#if SCTP_ACTIVATE & 1
                    .sctpStrm = flowP->sctpStrm,
#endif // SCTP_ACTIVATE & 1
#if SCTP_ACTIVATE & 2
                    .sctpVtag = flowP->sctpVtag,
#endif // SCTP_ACTIVATE & 2
                    .l4Proto = flowP->l4Proto,
                    .srcIP = flowP->dstIP,
                    .dstIP = flowP->srcIP,
                    .dstPort = (ftpFlowP->pcrPort) ? ftpFlowP->pcrPort : flowP->dstPort + 1,
                };

                const uint64_t pFindex = hashTable_lookup(ftpHashMap, (char*)&client.srcIP);
                if (pFindex == HASHTABLE_ENTRY_NOT_FOUND) {
                    ftpFlowP->stat |= FTP_NDFLW;
                    break;
                } else ftpFlowP->stat &= ~FTP_NDFLW;

                uint64_t find = ftpFindex[pFindex];
                if (ftpFlowP->pfiCnt > FTP_MAXCPFI) ftpFlowP->pfiCnt = FTP_MAXCPFI;
                ftpFlowP->pfi[ftpFlowP->pfiCnt++] = flows[find].findex;

                ftpFlow_t *ftpDataFlowP = &ftpFlows[find];
                if (ftpDataFlowP->pfiCnt > FTP_MAXCPFI) ftpDataFlowP->pfiCnt = FTP_MAXCPFI;
                ftpDataFlowP->pfi[ftpDataFlowP->pfiCnt++] = flowP->findex;

                ftpFlow_t * const ftpFlowPO = (FLOW_HAS_OPPOSITE(flowP) ? &ftpFlows[flowP->oppositeFlowIndex] : NULL);

                j = (uint32_t)(s - t);
                if (j > FTP_MXNMLN) j = FTP_MXNMLN;

                size_t flen;
                const char *filename;
                if ((ftpFlowPO && ftpFlowPO->nameCCnt > 0 && ftpFlowPO->nameCCnt < FTP_MAXCNM)) {
                    filename = ftpFlowPO->nameC[ftpFlowPO->nameCCnt-1];
                    flen = j;
                } else {
                    filename = ftpNoName;
                    flen = strlen(ftpNoName);
                }

                find = flows[find].oppositeFlowIndex;

                if (find != HASHTABLE_ENTRY_NOT_FOUND) {
                    ftpFlow_t *ftpDataFlowPO = &ftpFlows[find];
                    ftpDataFlowPO->stat |= FTP_PPRNT;
                    ftpDataFlowPO->cLen = ftpFlowP->cLen;

                    if (ftpDataFlowPO->nameCCnt >= FTP_MAXCNM) {
                        ftpDataFlowPO->stat |= FTP_OVFL;
                        break;
                    }

                    memcpy(ftpDataFlowPO->nameC[ftpDataFlowPO->nameCCnt++], filename, flen);
                }

                if (ftpFlowP->nameCCnt >= FTP_MAXPNM) {
                    ftpFlowP->stat |= FTP_OVFL;
                    break;
                }

                memcpy(ftpFlowP->nameC[ftpFlowP->nameCCnt++], t, j);
                memcpy(ftpDataFlowP->nameC[ftpDataFlowP->nameCCnt++], filename, flen);

                ftpDataFlowP->cLen = ftpFlowP->cLen;
                ftpDataFlowP->stat |= FTP_PPRNT;
                //ftpFlowP->stat |= FTP_APRNT;
                break;
            case 226: // Closing data connection. Requested file action successful
#if FTP_SAVE == 1
                if (ftpFlowP->fd) {
                    file_manager_close(t2_file_manager, ftpFlowP->fd);
                    ftpFlowP->fd = NULL;
                }
#endif // FTP_SAVE == 1
                break;
            default:
                break;
        }
    } else { // request
        uint8_t sC = 0;
        int pshft = 5;
        if (l7HdrP[0] > 0x60) l7Hdr32 -= 0x20202020;
        switch (l7Hdr32) {
            case ABOR:
                sC = 0;
                ftpFlowP->sendCode |= FTP_ABOR;
                break;
            case ACCT:
                sC = 1;
                ftpFlowP->sendCode |= FTP_ACCT;
                break;
            case ADAT:
                sC = 2;
                ftpFlowP->sendCode |= FTP_ADAT;
                break;
            case ALLO:
                sC = 3;
                ftpFlowP->sendCode |= FTP_ALLO;
                break;
            case APPE:
                sC = 4;
                ftpFlowP->sendCode |= FTP_APPE;
                break;
            case AUTH:
                sC = 5;
                ftpFlowP->sendCode |= FTP_AUTH;
                break;
            case CCC:
                sC = 6;
                ftpFlowP->sendCode |= FTP_CCC;
                break;
            case CDUP:
                sC = 7;
                ftpFlowP->sendCode |= FTP_CDUP;
                break;
            case CONF:
                sC = 8;
                ftpFlowP->sendCode |= FTP_CONF;
                break;
            case CWD:
                sC = 9;
                ftpFlowP->sendCode |= FTP_CWD;
                pshft = 4;
                goto ftpcc;
            case DELE:
                sC = 10;
                ftpFlowP->sendCode |= FTP_DELE;
                goto ftpcc;
            case ENC:
                sC = 11;
                ftpFlowP->sendCode |= FTP_ENC;
                break;
            case EPRT:
                sC = 12;
                ftpFlowP->sendCode |= FTP_EPRT;
                break;
            case EPSV:
                sC = 13;
                ftpFlowP->sendCode |= FTP_EPSV;
                break;
            case FEAT:
                sC = 14;
                ftpFlowP->sendCode |= FTP_FEAT;
                goto ftpcc;
            case HELP:
                sC = 15;
                ftpFlowP->sendCode |= FTP_HELP;
                break;
            case LANG:
                sC = 16;
                ftpFlowP->sendCode |= FTP_LANG;
                break;
            case LIST:
                sC = 17;
                ftpFlowP->sendCode |= FTP_LIST;
                break;
            case LPRT:
                sC = 18;
                ftpFlowP->sendCode |= FTP_LPRT;
                break;
            case LPSV:
                sC = 19;
                ftpFlowP->sendCode |= FTP_LPSV;
                break;
            case MDTM:
                sC = 20;
                ftpFlowP->sendCode |= FTP_MDTM;
                break;
            case MIC:
                sC = 21;
                ftpFlowP->sendCode |= FTP_MIC;
                break;
            case MKD:
                sC = 22;
                ftpFlowP->sendCode |= FTP_MKD;
                break;
            case MLSD:
                sC = 23;
                ftpFlowP->sendCode |= FTP_MLSD;
                break;
            case MLST:
                sC = 24;
                ftpFlowP->sendCode |= FTP_MLST;
                break;
            case MODE:
                sC = 25;
                ftpFlowP->sendCode |= FTP_MODE;
                break;
            case NLST:
                sC = 26;
                ftpFlowP->sendCode |= FTP_NLST;
                break;
            case NOOP:
                sC = 27;
                ftpFlowP->sendCode |= FTP_NOOP;
                break;
            case OPTS:
                sC = 28;
                ftpFlowP->sendCode |= FTP_OPTS;
                break;
            case PASS:
                sC = 29;
                if (ftpFlowP->namePCnt >= FTP_MAXPNM) {
                    ftpFlowP->stat |= FTP_OVFL;
                    break;
                }
                ftpFlowP->sendCode |= FTP_PASS;
                if (l7Len <= 7) break;
                l7HdrP += 5;
                l7Len -= 5;
                if ((s = memchr(l7HdrP, '\r', l7Len)) != NULL) {
                    const size_t len = s - l7HdrP;
                    memcpy(ftpFlowP->nameP[ftpFlowP->namePCnt++], l7HdrP, MIN(len, FTP_PXNMLN));
                }
                break;
            case PASV:
                sC = 30;
                ftpFlowP->sendCode |= FTP_PASV;
                break;
            case PBSZ:
                sC = 31;
                ftpFlowP->sendCode |= FTP_PBSZ;
                break;
            case PORT: { // PORT h1,h2,h3,h4,p1,p2
                sC = 32;
                ftpFlowP->sendCode |= FTP_PORT;
                if ((s = memchr(l7HdrP, '\r', l7Len)) != NULL) {
                    if (!(s = memchr(l7HdrP, ',', l7Len))) break;
                    s++; // skip the comma
                    const uint8_t h1 = strtoul(l7HdrP + 5, NULL, 0);
                    const uint8_t h2 = strtoul(s, NULL, 0);
                    if (!(s = memchr(s, ',', l7Len - (s - l7HdrP)))) break;
                    s++; // skip the comma
                    const uint8_t h3 = strtoul(s, NULL, 0);
                    if (!(s = memchr(s, ',', l7Len - (s - l7HdrP)))) break;
                    s++; // skip the comma
                    const uint8_t h4 = strtoul(s, NULL, 0);
                    ftpFlowP->pslAddr = (h1 << 24 | h2 << 16 | h3 << 8 | h4);
                    if (!(s = memchr(s, ',', l7Len - (s - l7HdrP)))) break;
                    s++; // skip the comma
                    const uint8_t p1 = strtoul(s, NULL, 0);
                    if (!(s = memchr(s, ',', l7Len - (s - l7HdrP)))) break;
                    s++; // skip the comma
                    const uint8_t p2 = strtoul(s, NULL, 0);
                    const uint16_t port = (p1 << 8) + p2;
                    ftpFlowP->pcrPort = port;
                    ftpFlowP->stat |= FTP_APRNT;
                    ftpFlow_t * const ftpFlowPO = (FLOW_HAS_OPPOSITE(flowP) ? &ftpFlows[flowP->oppositeFlowIndex] : NULL);
                    if (ftpFlowPO) {
                        ftpFlowPO->pcrPort = port;
                        ftpFlowPO->stat |= FTP_APRNT;
                    }
                }
                goto ftpcc;
            }
            case PROT:
                sC = 33;
                ftpFlowP->sendCode |= FTP_PROT;
                break;
            case PWD:
                sC = 34;
                ftpFlowP->sendCode |= FTP_PWD;
                pshft = 4;
                goto ftpcc;
            case QUIT:
                sC = 35;
                ftpFlowP->sendCode |= FTP_QUIT;
                break;
            case REIN:
                sC = 36;
                ftpFlowP->sendCode |= FTP_REIN;
                break;
            case REST:
                sC = 37;
                ftpFlowP->sendCode |= FTP_REST;
                break;
            case RETR:
                sC = 38;
                ftpFlowP->sendCode |= FTP_RETR;
                goto ftpcc;
            case RMD:
                sC = 39;
                ftpFlowP->sendCode |= FTP_RMD;
                pshft = 4;
                goto ftpcc;
            case RNFR:
                sC = 40;
                ftpFlowP->sendCode |= FTP_RNFR;
ftpcc:
                if (ftpFlowP->nameCCnt >= FTP_MAXCNM) {
                    ftpFlowP->stat |= FTP_OVFL;
                    break;
                }

                if (l7Len <= pshft+2) break;

                l7HdrP += pshft;
                l7Len -= pshft;
                if ((s = memchr(l7HdrP, '\r', l7Len)) != NULL) {
                    i = s - l7HdrP;
                    if (i > FTP_MXNMLN) i = FTP_MXNMLN;
                    for (j = 0; j < ftpFlowP->nameCCnt; j++) {
                        if (!memcmp(ftpFlowP->nameC[j], l7HdrP, i)) goto strcd;
                    }
                    memcpy(ftpFlowP->nameC[j], l7HdrP, i);
                    ftpFlowP->nameCCnt++;
                }
                break;
            case RNTO:
                sC = 41;
                ftpFlowP->sendCode |= FTP_RNTO;
                goto ftpcc;
            case SITE:
                sC = 42;
                ftpFlowP->sendCode |= FTP_SITE;
                break;
            case SIZE:
                sC = 43;
                ftpFlowP->sendCode |= FTP_SIZE;
                goto ftpcc;
            case SMNT:
                sC = 44;
                ftpFlowP->sendCode |= FTP_SMNT;
                break;
            case STAT:
                sC = 45;
                ftpFlowP->sendCode |= FTP_STAT;
                break;
            case STOR:
                sC = 46;
                ftpFlowP->sendCode |= FTP_STOR;
                goto ftpcc;
            case STOU:
                sC = 47;
                ftpFlowP->sendCode |= FTP_STOU;
                break;
            case STRU:
                sC = 48;
                ftpFlowP->sendCode |= FTP_STRU;
                break;
            case SYST:
                sC = 49;
                ftpFlowP->sendCode |= FTP_SYST;
                break;
            case TYPE:
                sC = 50;
                ftpFlowP->sendCode |= FTP_TYPE;
                goto ftpcc;
            case USER:
                sC = 51;
                if (ftpFlowP->nameUCnt >= FTP_MAXUNM) {
                    ftpFlowP->stat |= FTP_OVFL;
                    break;
                }
                ftpFlowP->sendCode |= FTP_USER;
                if (l7Len <= 7) break;
                l7HdrP += 5;
                l7Len -= 5;
                if ((s = memchr(l7HdrP, '\r', l7Len)) != NULL) {
                    const size_t len = s - l7HdrP;
                    memcpy(ftpFlowP->nameU[ftpFlowP->nameUCnt++], l7HdrP, MIN(len, FTP_UXNMLN));
                }
                break;
            case XCUP:
                sC = 52;
                ftpFlowP->sendCode |= FTP_XCUP;
                break;
            case XMKD:
                sC = 53;
                ftpFlowP->sendCode |= FTP_XMKD;
                break;
            case XPWD:
                sC = 54;
                ftpFlowP->sendCode |= FTP_XPWD;
                break;
            case XRCP:
                sC = 55;
                ftpFlowP->sendCode |= FTP_XRCP;
                break;
            case XRMD:
                sC = 56;
                ftpFlowP->sendCode |= FTP_XRMD;
                break;
            case XRSQ:
                sC = 57;
                ftpFlowP->sendCode |= FTP_XRSQ;
                break;
            case XSEM:
                sC = 58;
                ftpFlowP->sendCode |= FTP_XSEM;
                break;
            case XSEN:
                sC = 59;
                ftpFlowP->sendCode |= FTP_XSEN;
                break;
            case CLNT:
                sC = 60;
                ftpFlowP->sendCode |= FTP_CLNT;
                break;
            default:
                goto ftppkt;
        }

strcd:
        if (ftpFlowP->tCCnt >= FTP_MAXCNM) {
            ftpFlowP->stat |= FTP_OVFL;
            goto ftppkt;
        }

#if FTP_CMD_AGGR == 1
        for (j = 0; j < ftpFlowP->tCCnt; j++) {
            if (ftpFlowP->tCode[j] == sC) goto ftppkt ;
        }
#endif // FTP_CMD_AGGR

        ftpFlowP->tCode[ftpFlowP->tCCnt++] = sC;
    }

ftppkt:
    if (sPktFile) fprintf(sPktFile, "0x%02" B2T_PRIX8 SEP_CHR, ftpFlowP->stat);
}


void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {
    const flow_t * const flowP = &flows[flowIndex];

    flow_t client = {
        .vlanId = flowP->vlanId,
#if IPV6_ACTIVATE == 2 || ETH_ACTIVATE > 0
        .ethType = flowP->ethType,
#endif // IPV6_ACTIVATE == 2 || ETH_ACTIVATE > 0
#if SCTP_ACTIVATE & 1
        .sctpStrm = flowP->sctpStrm,
#endif // SCTP_ACTIVATE & 1
#if SCTP_ACTIVATE & 2
        .sctpVtag = flowP->verTag;
#endif // SCTP_ACTIVATE & 2
        .l4Proto = flowP->l4Proto,
        .srcIP = flowP->srcIP,
        .dstIP = flowP->dstIP,
        .dstPort = flowP->dstPort,
    };

    hashTable_remove(ftpHashMap, (char*)&client.srcIP);

    client.dstPort = flowP->srcPort;
    hashTable_remove(ftpHashMap, (char*)&client.srcIP);

    ftpFlow_t * const ftpFlowP = &ftpFlows[flowIndex];

    ftpStat |= ftpFlowP->stat;

#if FTP_SAVE == 1
    if (ftpFlowP->fd) {
        file_manager_close(t2_file_manager, ftpFlowP->fd);
        ftpFlowP->fd = NULL;
        totFtpDByteCnt += ftpFlowP->dwLen;
    }
#endif // FTP_SAVE == 1

    const ftpFlow_t * const ftpFlowPO = (FLOW_HAS_OPPOSITE(flowP) ? &ftpFlows[flowP->oppositeFlowIndex] : NULL);
    if (ftpFlowPO && (ftpFlowPO->stat & FTP_PPRNT)) ftpFlowP->stat |= FTP_PPRNT;

    OUTBUF_APPEND_U8(buf, ftpFlowP->stat);  // ftpStat

    // ftpCDFindex
    uint32_t cnt = ftpFlowP->pfiCnt;
    if (cnt) {
        OUTBUF_APPEND_ARRAY_U64(buf, ftpFlowP->pfi, cnt);
    } else {
        cnt = ftpFlowPO ? ftpFlowPO->pfiCnt : 0;
        OUTBUF_APPEND_ARRAY_U64(buf, ftpFlowPO->pfi, cnt);
    }

#if FTP_BTFLD == 1
    OUTBUF_APPEND_U64(buf, ftpFlowP->sendCode);  // ftpCBF
    //OUTBUF_APPEND_U32(buf, ftpFlowP->recCode);   // ftpRBF
#endif // FTP_BTFLD == 1

    // ftpCC
    cnt = ftpFlowP->tCCnt;
    OUTBUF_APPEND_NUMREP(buf, cnt);
    for (uint_fast32_t i = 0; i < cnt; i++) {
        OUTBUF_APPEND_STR(buf, ftpCom[ftpFlowP->tCode[i]]);
    }

    // ftpRC
    OUTBUF_APPEND_ARRAY_U16(buf, ftpFlowP->recCode, ftpFlowP->rCCnt);

    // ftpNumUser
    OUTBUF_APPEND_U8(buf, ftpFlowP->nameUCnt);

    // ftpUser
    OUTBUF_APPEND_ARRAY_STR(buf, ftpFlowP->nameU, ftpFlowP->nameUCnt);

    // ftpNumPass
    OUTBUF_APPEND_U8(buf, ftpFlowP->namePCnt);

    // ftpPass
    OUTBUF_APPEND_ARRAY_STR(buf, ftpFlowP->nameP, ftpFlowP->namePCnt);

    // ftpNumCP
    OUTBUF_APPEND_U8(buf, ftpFlowP->nameCCnt);

    // ftpCP
    OUTBUF_APPEND_ARRAY_STR(buf, ftpFlowP->nameC, ftpFlowP->nameCCnt);

    OUTBUF_APPEND_U32(buf, ftpFlowP->cLen);
}


void t2PluginReport(FILE *stream) {
    if (ftpStat) {
        T2_FPLOG_AGGR_HEX0(stream, plugin_name, ftpStat);
        T2_FPLOG_NUMP(stream, plugin_name, "Number of FTP control packets", totFtpPktCnt, numPackets);
        T2_FPLOG_NUMP(stream, plugin_name, "Number of FTP-DATA packets", totFtpDPktCnt, numPackets);
        T2_FPLOG_NUMP(stream, plugin_name, "Number of FTP-DATA bytes", totFtpDByteCnt, bytesProcessed);
#if FTP_SAVE == 1
        T2_FPLOG_NUM(stream, plugin_name, "Number of files extracted", totFtpSaved);
#endif // FTP_SAVE == 1
    }
}


void t2Monitoring(FILE *stream, uint8_t state) {

    switch (state) {

        case T2_MON_PRI_HDR:
            fputs("ftpPkts"     SEP_CHR
                  "ftpDataPkts" SEP_CHR
                  , stream);
            return;

        case T2_MON_PRI_VAL:
            fprintf(stream,
                    "%" PRIu64 /* ftpPkts     */ SEP_CHR
                    "%" PRIu64 /* ftpDataPkts */ SEP_CHR
                    "%" PRIu64 /* ftpDataBytes */ SEP_CHR
                    , totFtpPktCnt  - totFtpPktCnt0
                    , totFtpDPktCnt - totFtpDPktCnt0
                    , totFtpDByteCnt - totFtpDByteCnt0);
            break;

        case T2_MON_PRI_REPORT:
            T2_PLOG_DIFFNUMP(stream, plugin_name, "Number of FTP control packets", totFtpPktCnt, numPackets);
            T2_PLOG_DIFFNUMP(stream, plugin_name, "Number of FTP-DATA packets", totFtpDPktCnt, numPackets);
            T2_PLOG_DIFFNUMP(stream, plugin_name, "Number of FTP-DATA bytes", totFtpDByteCnt, bytesProcessed);
            break;

        // Invalid state, do nothing
        default:
            return;
    }

#if DIFF_REPORT == 1
    totFtpPktCnt0 = totFtpPktCnt;
    totFtpDPktCnt0 = totFtpDPktCnt;
    totFtpDByteCnt0 = totFtpDByteCnt;
#endif // DIFF_REPORT == 1
}


void t2Finalize() {
#if (ENVCNTRL > 0 && FTP_SAVE == 1)
    t2_free_env(ENV_FTP_N, env);
#endif // (ENVCNTRL > 0 && FTP_SAVE == 1)

    hashTable_destroy(ftpHashMap);
    free(ftpFindex);

    free(ftpFlows);
}
