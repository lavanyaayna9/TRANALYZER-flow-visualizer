/*
 * smbDecode.c
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

#include "smbDecode.h"

#include <errno.h>  // for errno


#define SMB_WIN_TICK         10000000.0 // 100ns
#define SMB_WIN_UNIX_DIFF 11644473600LL // number of secs between windows and unix first epoch
#define SMB_WIN_TIME_TO_UNIX(t) ((t) / SMB_WIN_TICK - SMB_WIN_UNIX_DIFF);


// Global variables

smb_flow_t *smb_flows;


// Static variables

static uint64_t num_smb[3];
static uint64_t numSMBPackets;

#if SMB_SAVE_DATA == 1 || SMB_SAVE_AUTH == 1

#if ENVCNTRL > 0
static t2_env_t env[ENV_SMB_N];
#if SMB_SAVE_DATA == 1
static const char *saveDir;
static const char *fileID;
#endif // SMB_SAVE_DATA == 1
#else // ENVCNTRL == 0
#if SMB_SAVE_DATA == 1
static const char * const saveDir = SMB_SAVE_DIR;
static const char * const fileID = SMB_FILE_ID;
#endif // SMB_SAVE_DATA == 1
#endif // ENVCNTRL

#if SMB_SAVE_DATA == 1
static FILE *guidMapF;
#endif // SMB_SAVE_DATA == 1

#if SMB_SAVE_AUTH == 1
static uint32_t smbNumAuth;
static FILE *smbAuthFile;
#endif // SMB_SAVE_AUTH == 1

#endif // SMB_SAVE_DATA == 1 || SMB_SAVE_AUTH == 1

#if SMB_SECBLOB == 1
static const char *ntlmssp = "NTLMSSP";
#endif // SMB_SECBLOB == 1

static uint16_t smbStat;

//#if SMB_USE_FILTER > 0
//static const char *smb_fmt[] = { SMB_SAVE_FMT , NULL };
//static inline int str_has_suffix(const char *str, const char *suffix);
//#endif // SMB_USE_FILTER


// Tranalyzer functions

T2_PLUGIN_INIT("smbDecode", "0.9.3", 0, 9);


void t2Init() {
    T2_PLUGIN_STRUCT_NEW(smb_flows);

#if SMB_SAVE_DATA == 1 || SMB_SAVE_AUTH == 1
#if ENVCNTRL > 0
    t2_get_env(PLUGIN_SRCH, ENV_SMB_N, env);
#if SMB_SAVE_DATA == 1
    const uint8_t rmdir = T2_ENV_VAL_UINT(SMB_RM_DATADIR);
    const char * const mapFile = T2_ENV_VAL(SMB_MAP_FILE);
    saveDir = T2_ENV_VAL(SMB_SAVE_DIR);
    fileID = T2_ENV_VAL(SMB_FILE_ID);
#endif // §SMB_SAVE_DATA == 1
#if SMB_SAVE_AUTH == 1
    const char * const authFile = T2_ENV_VAL(SMB_AUTH_FILE);
#endif // SMB_SAVE_AUTH == 1
#else // ENVCNTRL == 0
#if SMB_SAVE_DATA == 1
    const uint8_t rmdir = SMB_RM_DATADIR;
    const char * const mapFile = SMB_MAP_FILE;
#endif
#if SMB_SAVE_AUTH == 1
    const char * const authFile = SMB_AUTH_FILE;
#endif // SMB_SAVE_AUTH == 1
#endif // ENVCNTRL
#endif // SMB_SAVE_DATA == 1 || SMB_SAVE_AUTH == 1

#if SMB_SAVE_DATA == 1
    T2_MKPATH(saveDir, rmdir);

    guidMapF = t2_fopen_in_dir(saveDir, mapFile, "w");
    if (UNLIKELY(!guidMapF)) exit(EXIT_FAILURE);
#endif // SMB_SAVE_DATA

#if SMB_SAVE_AUTH == 1
    smbAuthFile = t2_fopen_with_suffix(baseFileName, authFile, "w");
    if (UNLIKELY(!smbAuthFile)) exit(EXIT_FAILURE);
#endif // SMB_SAVE_AUTH == 1
}


binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;
    BV_APPEND_H16(bv, "smbStat", "SMB status");
#if SMB1_NUM_DIALECT > 0
    BV_APPEND_U32(bv,   "smb1NDialects", "SMB1 number of requested dialects");
    BV_APPEND_STR_R(bv, "smb1Dialects" , "SMB1 requested dialects");
#endif // SMB1_NUM_DIALECT > 0
#if SMB2_NUM_DIALECT > 0
    BV_APPEND_U32(bv,   "smb2NDialects", "SMB2 number of dialects");
    BV_APPEND_H16_R(bv, "smb2Dialects" , "SMB2 dialect revision");
#endif // SMB2_NUM_DIALECT > 0
#if SMB2_NUM_STAT > 0
    BV_APPEND_U32(bv,   "smbNHdrStat", "SMB2 number of unique SMB2 header status values");
    BV_APPEND_H32_R(bv, "smbHdrStat" , "SMB2 list of unique header status");
#endif // SMB2_NUM_STAT > 0
    BV_APPEND_H32(bv, "smbOpcodes" , "SMB opcodes");
    BV_APPEND(bv,     "smbNOpcodes", "SMB number of opcodes", SMB2_OP_N,
        bt_uint_32, bt_uint_32, bt_uint_32, bt_uint_32, bt_uint_32,
        bt_uint_32, bt_uint_32, bt_uint_32, bt_uint_32, bt_uint_32,
        bt_uint_32, bt_uint_32, bt_uint_32, bt_uint_32, bt_uint_32,
        bt_uint_32, bt_uint_32, bt_uint_32, bt_uint_32);
    BV_APPEND_H64(bv, "smbPrevSessId"       , "SMB previous session ID");
    BV_APPEND_STR(bv, "smbNativeOS"         , "SMB native OS");
    BV_APPEND_STR(bv, "smbNativeLanMan"     , "SMB native LAN Manager");
    BV_APPEND_STR(bv, "smbPrimDom"          , "SMB primary domain");
    BV_APPEND_STR(bv, "smbTargName"         , "SMB target name");
    BV_APPEND_STR(bv, "smbDomName"          , "SMB domain name");
    BV_APPEND_STR(bv, "smbUserName"         , "SMB user name");
    BV_APPEND_STR(bv, "smbHostName"         , "SMB host name");
    BV_APPEND_STR(bv, "smbNTLMServChallenge", "SMB NTLM server challenge");
    BV_APPEND_STR(bv, "smbNTProofStr"       , "SMB NT proof string");
#if SMB_SAVE_AUTH == 1
    //BV_APPEND_STR(bv, "smbNTLMCliChallenge", "SMB NTLM client challenge");
#endif // SMB_SAVE_AUTH == 1
    BV_APPEND_STR(bv,       "smbSessionKey"      , "SMB session key");
    BV_APPEND_STR(bv,       "smbGUID"            , "SMB client/server GUID");
    BV_APPEND(bv,           "smbSFlags_secM_caps", "SMB session flags, security mode and capabilities", 3, bt_hex_16, bt_hex_8, bt_hex_32);
    BV_APPEND_TIMESTAMP(bv, "smbBootT"           , "SMB server start time");
    BV_APPEND(bv,           "smbMaxSizeT_R_W"    , "SMB max transaction/read/write size", 3, bt_uint_32, bt_uint_32, bt_uint_32);
    BV_APPEND_STR(bv,       "smbPath"            , "SMB full share path name");
    BV_APPEND_H8(bv,        "smbShareT"          , "SMB type of share being accessed");
    BV_APPEND(bv,           "smbShareF_caps_acc" , "SMB share flags, capabilities and access mask", 3, bt_hex_32, bt_hex_32, bt_hex_32);
    BV_APPEND_U32(bv,       "smbNFiles"          , "SMB number of accessed files");
    BV_APPEND_STR_R(bv,     "smbFiles"           , "SMB accessed files");
    return bv;
}


void t2OnNewFlow(packet_t* packet, unsigned long flowIndex) {
    smb_flow_t * const smbFlowP = &smb_flows[flowIndex];
    memset(smbFlowP, '\0', sizeof(*smbFlowP));
    const flow_t * const flowP = &flows[flowIndex];
    const uint_fast8_t proto = packet->l4Proto;
    const uint_fast16_t sp = flowP->srcPort;
    const uint_fast16_t dp = flowP->dstPort;
    if (proto == L3_TCP &&
            (sp == NB_SESSION_PORT || sp == SMB_DIRECT_PORT ||
             dp == NB_SESSION_PORT || dp == SMB_DIRECT_PORT))
    {
        smbFlowP->stat |= SMB_STAT_SMB;
    }
}


void t2OnLayer4(packet_t* packet, unsigned long flowIndex) {

    const flow_t * const flowP = &flows[flowIndex];

    smb_flow_t * const smbFlowP = &smb_flows[flowIndex];
    if (!smbFlowP->stat) return;
numSMBPackets++;
    // only 1. frag packet will be processed
    if (!t2_is_first_fragment(packet)) return;

    //smbFlowP->numPkts++;

    const uint32_t tcpSeq = ntohl(TCP_HEADER(packet)->seq);
    if (smbFlowP->hdrstat > 0 && tcpSeq > smbFlowP->tcpSeq) {
        // packet out of order, reset state
        //printf("MISSING SEGMENT: findex: %ld, pkt: %" PRIu32 ", %" PRIu32 " > %" PRIu32 " = %" PRIu32 "\n",
        //      flowP->findex, smbFlowP->numPkts, tcpSeq, smbFlowP->tcpSeq, tcpSeq - smbFlowP->tcpSeq);
        smbFlowP->hdrstat = 0;
    }
    smbFlowP->tcpSeq = tcpSeq + packet->l7Len;

    uint32_t version;
    uint32_t tmp;

#if SMB1_DECODE == 1
    smb1_header_t *smb1 = NULL;
#endif // SMB1_DECODE == 1
    smb2_header_t *smb2 = NULL;
    uint32_t remaining = packet->snapL7Len;
    uint8_t *ptr = (uint8_t*)packet->l7HdrP;

//#if SMB_SECBLOB == 1
    const uint8_t * const l7end = ptr + remaining;
//#endif // SMB_SECBLOB == 1

    while (remaining && l7end - ptr) {

#if SMB1_SAVE_DATA == 1
        if (smbFlowP->hdrstat == SMB1_HDRSTAT_DATA) {
            goto smb1_write_data;
        } else if (smbFlowP->hdrstat == SMB1_HDRSTAT_WRITE) {
            goto smb1_write_hdr;
        } else
#endif // SMB1_SAVE_DATA == 1
#if SMB1_DECODE == 1
        if (smbFlowP->hdrstat == SMB1_HDRSTAT_SMB1) {
            tmp = sizeof(smb1_header_t) - smbFlowP->hdroff;
            if (remaining < tmp) {
                smbFlowP->hdrstat = 0;
                smbFlowP->hdroff = 0;
                return;
            }
            memcpy(smbFlowP->hdr + smbFlowP->hdroff, ptr, tmp);
            ptr += tmp;
            remaining -= tmp;
            smb1 = (smb1_header_t*)smbFlowP->hdr;
            version = smb1->proto_id;
            goto smb_version;
        } else
#endif // SMB1_DECODE == 1
#if SMB2_SAVE_DATA == 1
        if (smbFlowP->hdrstat == SMB2_HDRSTAT_DATA) {
            goto write_data;
        } else if (smbFlowP->hdrstat == SMB2_HDRSTAT_RDATA) {
            smbFlowP->hdrstat = 0;
            goto smb2_read;
        } else if (smbFlowP->hdrstat == SMB2_HDRSTAT_WRITE) {
            goto write_hdr;
        } else if (smbFlowP->hdrstat == SMB2_HDRSTAT_READ) {
            goto read_hdr;
        } else
#endif // SMB2_SAVE_DATA == 1
        if (smbFlowP->hdrstat == SMB2_HDRSTAT_SMB2) {
            tmp = sizeof(smb2_header_t) - smbFlowP->hdroff;
            if (remaining < tmp) {
                smbFlowP->hdrstat = 0;
                smbFlowP->hdroff = 0;
                return;
            }
            memcpy(smbFlowP->hdr + smbFlowP->hdroff, ptr, tmp);
            ptr += tmp;
            remaining -= tmp;
            smb2 = (smb2_header_t*)smbFlowP->hdr;
            version = smb2->proto_id;
            goto smb_version;
        } else if (smbFlowP->hdrstat == SMB_HDRSTAT_SMB) {
            tmp = sizeof(smb1_header_t) - smbFlowP->hdroff;
            if (remaining < tmp) {
                smbFlowP->hdrstat = 0;
                smbFlowP->hdroff = 0;
                return;
            }
            memcpy(smbFlowP->hdr + smbFlowP->hdroff, ptr, tmp);
            ptr += tmp;
            remaining -= tmp;
            version = ((smbFlowP->hdr[0] << 24) | (smbFlowP->hdr[1] << 16) |
                       (smbFlowP->hdr[2] << 8)  | (smbFlowP->hdr[3]));
            switch (version) {
                case SMB1_MAGIC_HDR:
#if SMB1_DECODE == 1
                    smbFlowP->hdrstat = SMB1_HDRSTAT_SMB1;
                    smb1 = (smb1_header_t*)smbFlowP->hdr;
#endif // SMB1_DECODE == 1
                    break;
                case SMB2_MAGIC_HDR:
                    smbFlowP->hdrstat = SMB2_HDRSTAT_SMB2;
                    smb2 = (smb2_header_t*)smbFlowP->hdr;
                    break;
                case SMB3_MAGIC_HDR:
                    // TODO not implemented yet
                default:
                    smbFlowP->hdrstat = 0;
                    smbFlowP->hdroff = 0;
                    return;
            }
            goto smb_version;
        }

        // Netbios Session Header
        if (remaining <= NB_SS_HDR_LEN) {
            if (flowP->status & SNAPLENGTH) return;
            if (remaining >= 1 && *ptr != 0) return;
            smbFlowP->hdrstat = SMB_HDRSTAT_NB;
            smbFlowP->hdroff = remaining;
            return;
        }

        if (smbFlowP->hdrstat == SMB_HDRSTAT_NB && smbFlowP->hdroff != 0) {
            smbFlowP->hdrstat = 0;
            tmp = NB_SS_HDR_LEN - smbFlowP->hdroff;
            if (remaining < tmp) {
                smbFlowP->hdroff = 0;
                return;
            }
            //printf("rebuilding NB header %d %d\n", tmp, remaining);
            ptr += tmp;
            remaining -= tmp;
            smbFlowP->hdroff = 0;
        } else {
            // zero(8),smb message length(24)
            if (*ptr != 0) return;

            ptr += NB_SS_HDR_LEN;
            remaining -= NB_SS_HDR_LEN;
        }

        if (remaining < sizeof(uint32_t)) {
            if (flowP->status & SNAPLENGTH) return;
            //printf("remaining < uint32_t(version)\n");
            smbFlowP->hdrstat = SMB_HDRSTAT_SMB; // SMB, version unknown
            if (remaining) {
                memcpy(smbFlowP->hdr, ptr, remaining);
                smbFlowP->hdroff = remaining;
            }
            return;
        }

        version = *(uint32_t*)ptr;

smb_version:
        switch (version) { // SMB protocol id

            case SMB1_MAGIC_HDR: {
                num_smb[0]++;
#if SMB1_DECODE == 1
                if (smbFlowP->hdrstat != SMB1_HDRSTAT_SMB1) {
                    // SMB1 header
                    if (remaining < sizeof(smb1_header_t)) {
                        if (flowP->status & SNAPLENGTH) return;
                        smbFlowP->hdrstat = SMB1_HDRSTAT_SMB1;
                        if (remaining) {
                            memcpy(smbFlowP->hdr, ptr, remaining);
                            smbFlowP->hdroff = remaining;
                        }
                        return;
                    }

                    smb1 = (smb1_header_t*) ptr;
                    if (smbFlowP->hdrstat == SMB1_HDRSTAT_DATA) {
                        smbFlowP->hdrstat = 0;
                    }

                    ptr += sizeof(smb1_header_t);
                    remaining -= sizeof(smb1_header_t);
                } else {
                    smbFlowP->hdrstat = 0;
                    smbFlowP->hdroff = 0;
                }

                if (smb1->cmd == SMB1_CMD_CREATE_ANDX) {
                    if ((smb1->flags & SMB1_FLAGS_REPLY) == 0) { // REQUEST
                        const smb1_create_andx_req_t * const c = (smb1_create_andx_req_t*)ptr;
                        if (remaining <= sizeof(*c)) return;
                        ptr += sizeof(*c);
                        remaining -= sizeof(*c);
                        uint8_t *x = ptr;
                        uint16_t i, len;
                        if ((smb1->flags2 & SMB1_FLAGS2_UNICODE) == 0) {
                            // TODO SMB_STAT_NAMETRUNC?
                            t2_strcpy(smbFlowP->fname, (char*)x, sizeof(smbFlowP->fname), SMB_STRCPY_BEHAVIOR);
                        } else {
                            len = MIN(c->NameLength / 2, SMB_FNAME_LEN);
                            if (remaining < 2*len) return;
                            if (len < c->NameLength / 2) smbFlowP->stat |= SMB_STAT_NAMETRUNC;
                            uint16_t tmp;
                            for (i = 0; i < len; i++) {
                                tmp = *(uint16_t*)x;
                                if (tmp < 128 && *x != '\\') {
                                    smbFlowP->fname[i] = *x;
                                } else {
                                    smbFlowP->fname[i] = '_';
                                }
                                x += 2;
                            }
                            smbFlowP->fname[i] = '\0';
                        }
                        if (remaining < c->NameLength) return;
                        ptr += c->NameLength;
                        remaining -= c->NameLength;
                        len = strlen(smbFlowP->fname);
                        if (len == 0 || remaining < len) return;
                        const uint_fast32_t numSFile = MIN(smbFlowP->numSFile, SMB_NUM_FNAME);
                        for (i = 0; i < numSFile; i++) {
                            if (memcmp(smbFlowP->sname[i], smbFlowP->fname, len) == 0) return;
                        }
                        if (smbFlowP->numSFile < SMB_NUM_FNAME) {
                            memcpy(smbFlowP->sname[smbFlowP->numSFile], smbFlowP->fname, len);
                        } else {
                            smbFlowP->stat |= SMB_STAT_FNAMEL;
                        }
                        smbFlowP->numSFile++;
                    } else { // RESPONSE
#if SMB1_SAVE_DATA == 1
                        const smb1_create_andx_resp_t * const c = (smb1_create_andx_resp_t*)ptr;
                        if (remaining <= sizeof(*c)) return;
                        ptr += sizeof(*c);
                        remaining -= sizeof(*c);
                        const unsigned long ofidx = flowP->oppositeFlowIndex;
                        if (ofidx != HASHTABLE_ENTRY_NOT_FOUND) {
                            const smb_flow_t * const smbRevFlowP = &smb_flows[ofidx];
                            if (smbRevFlowP && strlen(smbRevFlowP->fname) > 0) {
                                fprintf(guidMapF, "%s%04x_%" PRIu64 "\t%s\n",
                                    fileID, c->fid, flowP->findex, smbRevFlowP->fname);
                            }
                        }
#endif // SMB1_SAVE_DATA == 1
                    }
                } else
#if SMB1_SAVE_DATA == 1
                if (smb1->cmd == SMB1_CMD_WRITE_ANDX) {
                    if ((smb1->flags & SMB1_FLAGS_REPLY) == 0) { // REQUEST
                        smbFlowP->stat |= SMB_STAT_WFSMB1;
                        smb1_write_andx_req_t *w = (smb1_write_andx_req_t*)ptr;
                        if (smbFlowP->hdrstat == SMB1_HDRSTAT_WRITE) {
smb1_write_hdr:
                            memcpy(smbFlowP->hdr + smbFlowP->hdroff, ptr, sizeof(*w) - smbFlowP->hdroff);
                            if (remaining < (sizeof(*w) - smbFlowP->hdroff)) return;
                            ptr += sizeof(*w) - smbFlowP->hdroff;
                            remaining -= (sizeof(*w) - smbFlowP->hdroff);
                            w = (smb1_write_andx_req_t*)smbFlowP->hdr;
                            smbFlowP->hdrstat = 0;
                        } else {
                            ptr += sizeof(*w);
                            if (remaining <= sizeof(*w)) {
                                smbFlowP->hdrstat = SMB1_HDRSTAT_WRITE;
                                if (remaining) {
                                    memcpy(smbFlowP->hdr, ptr, remaining);
                                    smbFlowP->hdroff = remaining;
                                }
                                return;
                            }
                            remaining -= sizeof(*w);
                        }
                        // skip named pipes
                        if (w->bc == 0 || w->wmode & SMB1_WM_MSG_START) return;
                        smbFlowP->left = w->bc - 1;
                        smbFlowP->off = 0;
                        //printf("%#04x: off: %d, rem: %d, len: %d, bc: %d\n", w->fid, w->offset, w->remaining, w->dlen, w->bc);
                        snprintf(smbFlowP->fname, 7, "%04x", w->fid);

smb1_write_data:;
                        char name[MAX_FILENAME_LEN];
                        size_t fnamelen = strlen(saveDir) + strlen(fileID) + strlen(smbFlowP->fname) + 21;
                        if (fnamelen >= sizeof(name)) {
                            smbFlowP->stat |= SMB_STAT_NAMETRUNC;
                            fnamelen = SMB_FNAME_LEN;
                        }
                        snprintf(name, fnamelen, "%s%s%s_%" PRIu64, saveDir, fileID, smbFlowP->fname, flowP->findex);
                        const size_t len = remaining;
                        if (len == 0) return;
                        FILE *f = fopen(name, "a");
                        if (f) fclose(f);
                        f = fopen(name, "r+");
                        if (UNLIKELY(!f)) return;
                        fseek(f, smbFlowP->off, SEEK_SET);
                        fwrite(ptr, 1, len, f);
                        fclose(f);
                        smbFlowP->left -= len;
                        smbFlowP->off += len;
                        if (smbFlowP->left > 0) {
                            smbFlowP->hdrstat = SMB1_HDRSTAT_DATA;
                        } else {
                            smbFlowP->hdrstat = 0;
                            smbFlowP->off = 0;
                        }
                    } else {
                        // TODO response
                    }
                    return;
                } else
#endif // SMB1_SAVE_DATA
                if (smb1->cmd == SMB1_CMD_SESSION_SETUP_ANDX) {
                    if ((smb1->flags & SMB1_FLAGS_REPLY) == 0) { // REQUEST
                        const smb1_session_setup_andx_req12_t * const s = (smb1_session_setup_andx_req12_t*) ptr;
                        if (s->wc != 12) return; // TODO s->wc==13
                        if (sizeof(*s)+s->secbloblen >= remaining) return;
                        remaining -= (sizeof(*s) + s->secbloblen);
                        ptr += sizeof(*s) + s->secbloblen;
                        if ((smb1->flags2 & SMB1_FLAGS2_UNICODE) == 0) {
                            uint16_t bc = s->bc - s->secbloblen;
                            size_t tmp = t2_strcpy(smbFlowP->nativeos, (char*)ptr, sizeof(smbFlowP->nativeos), SMB_STRCPY_BEHAVIOR);
                            if (tmp > bc || remaining < tmp) return;
                            ptr += tmp;
                            bc -= tmp;
                            tmp = t2_strcpy(smbFlowP->nativelanman, (char*)ptr, sizeof(smbFlowP->nativelanman), SMB_STRCPY_BEHAVIOR);
                            if (tmp > bc || remaining < tmp) return;
                            ptr += tmp;
                            bc -= tmp;
                            if (bc > 0) {
                                tmp = t2_strcpy(smbFlowP->primarydomain, (char*)ptr, sizeof(smbFlowP->primarydomain), SMB_STRCPY_BEHAVIOR);
                                if (tmp > bc || remaining < tmp) return;
                                ptr += tmp;
                                bc -= tmp;
                            }
                        } else {
                            if (remaining && ((sizeof(*s)+s->secbloblen) & 0x1) != 0) ptr++; // padding
                            uint32_t i = 0;
                            uint16_t tmp;
                            uint16_t bc = s->bc - s->secbloblen;
                            while (remaining > 1 && bc > 1 && i < SMB_NATIVE_NAME_LEN && *(uint16_t*)ptr != 0) {
                                tmp = *(uint16_t*)ptr;
                                if (tmp < 128) smbFlowP->nativeos[i] = *ptr;
                                else smbFlowP->nativeos[i] = '_';
                                ptr += 2;
                                bc -= 2;
                                i++;
                            }
                            smbFlowP->nativeos[i] = '\0';
                            if (bc < 2 || remaining < 2) return;
                            ptr += 2;
                            bc -= 2;
                            i = 0;
                            while (remaining > 1 && bc > 1 && i < SMB_NATIVE_NAME_LEN && *(uint16_t*)ptr != 0) {
                                tmp = *(uint16_t*)ptr;
                                if (tmp < 128) smbFlowP->nativelanman[i] = *ptr;
                                else smbFlowP->nativelanman[i] = '_';
                                ptr += 2;
                                bc -= 2;
                                i++;
                            }
                            smbFlowP->nativelanman[i] = '\0';
                            if (bc < 2 || remaining < 2) return;
                            ptr += 2;
                            bc -= 2;
                            i = 0;
                            while (remaining > 1 && bc > 1 && i < SMB_NATIVE_NAME_LEN && *(uint16_t*)ptr != 0) {
                                tmp = *(uint16_t*)ptr;
                                if (tmp < 128) smbFlowP->primarydomain[i] = *ptr;
                                else smbFlowP->primarydomain[i] = '_';
                                ptr += 2;
                                bc -= 2;
                                i++;
                            }
                            smbFlowP->primarydomain[i] = '\0';
                        }
#if SMB_SECBLOB == 1
                        if (s->secbloblen > 0) {
                            ptr = (uint8_t*)s + sizeof(*s);
                            if (l7end - ptr <= 0) return;
                            const void * const vtmp = memmem(ptr, /*s->secbloblen*/l7end - ptr, ntlmssp, NTLMSSP_LEN);
                            if (!vtmp) return;
                            ptr += ((uint8_t*)vtmp - ptr);
                            remaining -= ((uint8_t*)vtmp - ptr);

                            const ntlmssp_auth_t * const a = (ntlmssp_auth_t*)ptr;
                            if (remaining < sizeof(*a)) return;
                            if (a->type != NTLMSSP_MT_AUTH) return;

                            uint32_t i, off;
                            uint8_t *tmp;

                            if (a->nt_resp_len >= 16) {
                                // NTProofStr
                                off = 0;
                                tmp = ptr + a->nt_resp_off;
                                if (remaining < sizeof(*a) + a->nt_resp_off + 16) return;
                                for (i = 0; i < 16; i++) {
                                    snprintf(&(smbFlowP->ntproof[off]), 3, "%02" B2T_PRIX8, *tmp);
                                    off += 2;
                                    tmp++;
                                }
                                smbFlowP->ntproof[off] = '\0';

                                // NTLMv2 response *TODO: check length
                                off = 0;
                                const uint16_t len = a->nt_resp_len - 16;
                                if (remaining < sizeof(*a) + a->nt_resp_off + 16 + len) return;
                                for (i = 0; i < len; i++) {
                                    snprintf(&(smbFlowP->ntlmclientchallenge[off]), 3, "%02" B2T_PRIX8, *tmp);
                                    off += 2;
                                    tmp++;
                                }
                                smbFlowP->ntlmclientchallenge[off] = '\0';
                            }

                            tmp = ptr + a->dom_off;
                            if (remaining < sizeof(*a) + a->dom_off + a->dom_len) return;
                            //SMB_READ_U16_STR(smbFlowP->host_name, tmp, a->host_len/2);
                            for (i = 0; i < a->dom_len/2; i++) {
                                smbFlowP->domain_name[i] = *tmp;
                                tmp += 2;
                            }
                            tmp = ptr + a->user_off;
                            //SMB_READ_U16_STR(smbFlowP->user_name, tmp, a->user_len/2);
                            if (remaining < sizeof(*a) + a->user_off + a->user_len) return;
                            for (i = 0; i < a->user_len/2; i++) {
                                smbFlowP->user_name[i] = *tmp;
                                tmp += 2;
                            }
                            tmp = ptr + a->host_off;
                            //SMB_READ_U16_STR(smbFlowP->host_name, tmp, a->host_len/2);
                            if (remaining < sizeof(*a) + a->host_off + a->host_len) return;
                            for (i = 0; i < a->host_len/2; i++) {
                                smbFlowP->host_name[i] = *tmp;
                                tmp += 2;
                            }
                            tmp = ptr + a->session_off;
                            off = 0;
                            if (remaining < sizeof(*a) + a->session_off + a->session_len) return;
                            for (i = 0; i < a->session_len; i++) {
                                snprintf(&(smbFlowP->sessionkey[off]), 3, "%02" B2T_PRIX8, *tmp);
                                off += 2;
                                tmp++;
                            }
                            smbFlowP->sessionkey[off] = '\0';
                            // TODO Version
                        }
#endif // SMB_SECBLOB == 1
                    } else { // RESPONSE
                        const smb1_session_setup_andx_resp_t * const s = (smb1_session_setup_andx_resp_t*) ptr;
                        if (s->wc == 0) return;
                        uint16_t bc = s->bc;
                        ptr += sizeof(*s);
                        if (s->wc == 4) {
#if SMB_SECBLOB == 1
                            if (l7end - ptr <= 0) return;
                            const void * const tmp = memmem(ptr, /*s->bc*/l7end - ptr, ntlmssp, NTLMSSP_LEN);
                            if (!tmp) return;
                            const ntlmssp_challenge_t * const c = (ntlmssp_challenge_t*)tmp;
                            if (c->type != NTLMSSP_MT_CHALLENGE) return;

                            // NTLM Server challenge
                            uint32_t i, off = 0;
                            for (i = 0; i < 8; i++) {
                                snprintf(&(smbFlowP->ntlmserverchallenge[off]), 3, "%02" B2T_PRIX8, c->nonce[i]);
                                off += 2;
                            }
                            smbFlowP->ntlmserverchallenge[off] = '\0';
#endif // SMB_SECBLOB == 1
                            bc = *(uint16_t*)ptr;
                            if (remaining < (uint32_t)(2 + s->bc)) return;
                            ptr += 2 + s->bc; // skip security blob
                            remaining -= (2 + s->bc);
                        }
                        if (remaining < sizeof(*s)) return;
                        remaining -= sizeof(*s);
                        if ((smb1->flags2 & SMB1_FLAGS2_UNICODE) == 0) {
                            size_t tmp = t2_strcpy(smbFlowP->nativeos, (char*)ptr, sizeof(smbFlowP->nativeos), SMB_STRCPY_BEHAVIOR);
                            if (tmp >= bc || remaining < tmp) return;
                            ptr += tmp;
                            remaining -= tmp;
                            bc -= tmp;
                            tmp = t2_strcpy(smbFlowP->nativelanman, (char*)ptr, sizeof(smbFlowP->nativelanman), SMB_STRCPY_BEHAVIOR);
                            if (tmp >= bc || remaining < tmp) return;
                            ptr += tmp;
                            remaining -= tmp;
                            bc -= tmp;
                            if (bc > 1 && remaining > 1) {
                                tmp = t2_strcpy(smbFlowP->primarydomain, (char*)ptr, sizeof(smbFlowP->primarydomain), SMB_STRCPY_BEHAVIOR);
                                if (remaining < tmp) return;
                                ptr += tmp;
                                remaining -= tmp;
                            }
                        } else {
                            if (((sizeof(*s)+((s->wc==4) ? (2+s->bc) : 0)) & 0x1) != 0) {
                                if (bc < 1 || remaining < 1) return;
                                ptr++; // padding
                                remaining--;
                                bc--;
                            }
                            uint32_t i = 0;
                            uint16_t tmp;
                            while (remaining > 1 && bc > 1 && i < SMB_NATIVE_NAME_LEN && *(uint16_t*)ptr != 0) {
                                tmp = *(uint16_t*)ptr;
                                if (tmp < 128) smbFlowP->nativeos[i] = *ptr;
                                else smbFlowP->nativeos[i] = '_';
                                ptr += 2;
                                remaining -= 2;
                                bc -= 2;
                                i++;
                            }
                            smbFlowP->nativeos[i] = '\0';
                            if (bc < 2 || remaining < 2) return;
                            bc -= 2;
                            ptr += 2;
                            remaining -= 2;
                            i = 0;
                            while (remaining > 1 && bc > 1 && i < SMB_NATIVE_NAME_LEN && *(uint16_t*)ptr != 0) {
                                tmp = *(uint16_t*)ptr;
                                if (tmp < 128) smbFlowP->nativelanman[i] = *ptr;
                                else smbFlowP->nativelanman[i] = '_';
                                ptr += 2;
                                remaining -= 2;
                                bc -= 2;
                                i++;
                            }
                            smbFlowP->nativelanman[i] = '\0';
                            if (bc < 2 || remaining < 2) return;
                            bc -= 2;
                            ptr += 2;
                            remaining -= 2;
                            if (bc > 2) {
                                i = 0;
                                while (remaining > 1 && bc > 1 && i < SMB_NATIVE_NAME_LEN && (l7end - ptr) != 0 && *(uint16_t*)ptr != 0) {
                                    tmp = *(uint16_t*)ptr;
                                    if (tmp < 128) smbFlowP->primarydomain[i] = *ptr;
                                    else smbFlowP->primarydomain[i] = '_';
                                    ptr += 2;
                                    remaining -= 2;
                                    bc -= 2;
                                    i++;
                                }
                                smbFlowP->primarydomain[i] = '\0';
                            }
                        }
                    }
                }
#endif // SMB1_DECODE
#if SMB1_NUM_DIALECT > 0
                if (smb1->cmd != SMB1_CMD_NEGOTIATE) return;
                if ((smb1->flags & SMB1_FLAGS_REPLY) == 0) { // REQUEST
                    const smb1_negotiate_req_t * const n = (smb1_negotiate_req_t*)ptr;
                    if (remaining < sizeof(*n)) return;
                    remaining -= sizeof(*n);
                    ptr += sizeof(*n);
                    size_t len, maxlen;
                    uint32_t ndialect1 = 0;
                    const uint8_t diff = (smbFlowP->ndialect1 == 0) ? 0 : 1;
                    while (remaining > 1) {
                        ptr++; // skip buffer format
                        len = strlen((char*)ptr);
                        maxlen = MIN(len, sizeof(smbFlowP->dialect1[0]));
                        if (remaining < maxlen) return;
                        if (maxlen < len) smbFlowP->stat |= SMB_STAT_DIALNAME;
                        if (diff == 0) {
                            if (smbFlowP->ndialect1 < SMB1_NUM_DIALECT) {
                                t2_strcpy(smbFlowP->dialect1[smbFlowP->ndialect1], (char*)ptr, sizeof(smbFlowP->dialect1[smbFlowP->ndialect1]), SMB_STRCPY_BEHAVIOR);
                            } else {
                                smbFlowP->stat |= SMB_STAT_DIAL1L;
                            }
                            smbFlowP->ndialect1++;
                        } else {
                            if (strncmp(smbFlowP->dialect1[ndialect1], (char*)ptr, maxlen) != 0) smbFlowP->stat |= SMB_STAT_MALFORMED;
                            ndialect1++;
                        }
                        len++; // include '\0'
                        if (len+1 <= remaining) remaining -= (len + 1); // skip buffer format and dialect
                        else remaining = 0;
                        ptr += len;
                    }

                } else { // RESPONSE
                    const unsigned long ofidx = flowP->oppositeFlowIndex;
                    if (ofidx != HASHTABLE_ENTRY_NOT_FOUND) {
                        const smb1_negotiate_resp_t * const n = (smb1_negotiate_resp_t*)ptr;
                        if (remaining < sizeof(*n)) return;
                        const smb_flow_t * const smbRevFlowP = &smb_flows[ofidx];
                        const uint16_t sdi = n->sdi;
                        if (n->wc > 0 && sdi < smbRevFlowP->ndialect1) {
                            if (sdi < SMB1_NUM_DIALECT) {
                                smbFlowP->ndialect1 = 1;
                                t2_strcpy(smbFlowP->dialect1[0], smbRevFlowP->dialect1[sdi], sizeof(smbFlowP->dialect1[0]), SMB_STRCPY_BEHAVIOR);
                            } else {
                                smbFlowP->stat |= SMB_STAT_DIAL_OOB;
                            }
                        } else {
                            smbFlowP->stat |= SMB_STAT_INV_DIAL;
                        }
                    }
                }
#endif // SMB1_NUM_DIALECT > 0
                return;
            }

            case SMB2_MAGIC_HDR: {
                num_smb[1]++;
                if (smbFlowP->hdrstat != SMB2_HDRSTAT_SMB2) {
                    // SMB2 header
                    if (remaining < sizeof(smb2_header_t)) {
                        if (flowP->status & SNAPLENGTH) return;
                        smbFlowP->hdrstat = SMB2_HDRSTAT_SMB2;
                        if (remaining) {
                            memcpy(smbFlowP->hdr, ptr, remaining);
                            smbFlowP->hdroff = remaining;
                        }
                        return;
                    }

                    smb2 = (smb2_header_t*) ptr;
                    if (smbFlowP->hdrstat == SMB2_HDRSTAT_DATA) {
                        smbFlowP->hdrstat = 0;
                    }

                    ptr += sizeof(smb2_header_t);
                    remaining -= sizeof(smb2_header_t);
                } else {
                    smbFlowP->hdrstat = 0;
                    smbFlowP->hdroff = 0;
                }
                smbFlowP->msg_id = smb2->msg_id;
                break;
            }

            // Ignore SMB3 for now...
            case SMB3_MAGIC_HDR: num_smb[2]++; return;
            default:                           return;
        }

        // length
        if (smb2->len != SMB2_HDR_LEN) {
            smbFlowP->stat |= SMB_STAT_MALFORMED;
            return;
        }

#if SMB2_NUM_STAT > 0
        // status
        if (!SMB2_IS_REQUEST(smb2)) { // RESPONSE
            uint32_t i, found = 0;
            uint32_t imax = MIN(smbFlowP->numstat, SMB2_NUM_STAT);
            for (i = 0; i < imax && !found; i++) {
                if (smbFlowP->smbstat[i] == smb2->status) found = 1;
            }
            if (!found) {
                if (smbFlowP->numstat < SMB2_NUM_STAT)
                    smbFlowP->smbstat[smbFlowP->numstat] = smb2->status;
                else {
                    smbFlowP->stat |= SMB_STAT_SMB2STAT;
                }
                smbFlowP->numstat++;
            }
        }
#endif // SMB2_NUM_STAT > 0

        // opcode
        if (smb2->opcode >= SMB2_OP_N) {
            smbFlowP->stat |= SMB_STAT_MALFORMED;
            return;
        }
        smbFlowP->opcodes |= (1 << smb2->opcode);
        smbFlowP->nopcode[smb2->opcode]++;

        switch (smb2->opcode) {

            case SMB2_OP_CREATE: {
                if (SMB2_IS_REQUEST(smb2)) {
                    const smb2_create_req_t * const c = (smb2_create_req_t*) ptr;
                    uint8_t *x = ((uint8_t*)smb2 + c->fnameoff);
                    remaining -= sizeof(*c);
                    //T2_INF("%d\n", remaining);
                    if (remaining == 0) return;
                    const uint16_t len = MIN(c->fnamelen / 2, SMB_FNAME_LEN);
                    if (len < c->fnamelen / 2) smbFlowP->stat |= SMB_STAT_NAMETRUNC;
                    uint16_t i, tmp;
                    for (i = 0; i < len; i++) {
                        tmp = *(uint16_t*)x;
                        if (tmp < 128 && *x != '\\') {
                            smbFlowP->fname[i] = *x;
                        } else {
                            smbFlowP->fname[i] = '_';
                        }
                        x += 2;
                    }
                    smbFlowP->fname[i] = '\0';
                    const uint_fast32_t numSFile = MIN(smbFlowP->numSFile, SMB_NUM_FNAME);
                    for (i = 0; i < numSFile; i++) {
                        if (memcmp(smbFlowP->sname[i], smbFlowP->fname, len) == 0) return;
                    }
                    if (smbFlowP->numSFile < SMB_NUM_FNAME) {
                        memcpy(smbFlowP->sname[smbFlowP->numSFile], smbFlowP->fname, len);
                        smbFlowP->sname[smbFlowP->numSFile][len] = '\0';
                    } else {
                        smbFlowP->stat |= SMB_STAT_FNAMEL;
                    }
                    smbFlowP->numSFile++;
                } else { // SMB2 RESPONSE
#if SMB2_SAVE_DATA == 1
                    const smb2_create_resp_t * const c = (smb2_create_resp_t*) ptr;
                    const unsigned long ofidx = flowP->oppositeFlowIndex;
                    if (ofidx != HASHTABLE_ENTRY_NOT_FOUND) {
                        const smb_flow_t * const smbRevFlowP = &smb_flows[ofidx];
                        if (smbRevFlowP && strlen(smbRevFlowP->fname) > 0) {
                            fprintf(guidMapF, "File_Id_%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x_%" PRIu64 "\t%s\n",
                                c->fid.d1, c->fid.d2, c->fid.d3,
                                c->fid.d4[0], c->fid.d4[1], c->fid.d4[2], c->fid.d4[3],
                                c->fid.d4[4], c->fid.d4[5], c->fid.d4[6], c->fid.d4[7],
                                flowP->findex, smbRevFlowP->fname);
                        }
                    }
#endif // SMB2_SAVE_DATA
                }
                return;
            }

            case SMB2_OP_CLOSE: {
                if (SMB2_IS_REQUEST(smb2)) {
                    //smb2_close_req_t *c = (smb2_close_req_t*) ptr;
                } else { // RESPONSE
                    //smb2_close_resp_t *c = (smb2_close_resp_t*) ptr;
                }
                return;
            }

#if SMB2_SAVE_DATA == 1
            case SMB2_OP_WRITE: {
                if (SMB2_IS_REQUEST(smb2)) {
                    smbFlowP->stat |= SMB_STAT_WFSMB2;
                    smb2_write_t *w = (smb2_write_t*) ptr;
                    static const uint16_t wsize = 48;
                    if (smbFlowP->hdrstat == SMB2_HDRSTAT_WRITE) {
write_hdr:
                        memcpy(smbFlowP->hdr + smbFlowP->hdroff, ptr, wsize - smbFlowP->hdroff);
                        ptr += wsize - smbFlowP->hdroff;
                        w = (smb2_write_t*)smbFlowP->hdr;
                    }
                    if (remaining < wsize) {
                        smbFlowP->hdrstat = SMB2_HDRSTAT_WRITE;
                        if (remaining) {
                            memcpy(smbFlowP->hdr, ptr, remaining);
                            smbFlowP->hdroff = remaining;
                        }
                        return;
                    }
                    smbFlowP->left = w->datalen;
                    smbFlowP->off = w->fileoff;
                    remaining -= wsize;
                    if (smbFlowP->hdrstat == SMB2_HDRSTAT_WRITE) {
                        smbFlowP->hdrstat = 0;
                        remaining += smbFlowP->hdroff;
                        smbFlowP->hdroff = 0;
                    }
                    ptr += (w->dataoff - sizeof(smb2_header_t));

                    // use file id as name
                    snprintf(smbFlowP->fname, 37,
                        "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                        w->fid.d1, w->fid.d2, w->fid.d3,
                        w->fid.d4[0], w->fid.d4[1], w->fid.d4[2], w->fid.d4[3],
                        w->fid.d4[4], w->fid.d4[5], w->fid.d4[6], w->fid.d4[7]);

write_data:;
                    const uint32_t len = smbFlowP->left < remaining ? smbFlowP->left : remaining;
                    //T2_PDBG(plugin_name, "%s:%d:writing %d at %ld finishing at %ld", smbFlowP->fname, smbFlowP->numPkts, len, smbFlowP->off, smbFlowP->off + len);

//#if SMB_USE_FILTER > 0
//#if SMB_USE_FILTER == 1
//                    uint8_t found = 0;
//#endif // SMB_USE_FILTER == 1
//                    int i;
//                    for (i = 0; smb_fmt[i]; i++) {
//                        if (str_has_suffix(smbFlowP->fname, smb_fmt[i])) {
//#if SMB_USE_FILTER == 1
//                            found = 1;
//                            break;
//#elif SMB_USE_FILTER == 2
//                            return;
//#endif // SMB_USE_FILTER
//                        }
//                    }
//#if SMB_USE_FILTER == 1
//                    if (!found) return;
//#endif // SMB_USE_FILTER == 1
//#endif // SMB_USE_FILTER

                    char name[MAX_FILENAME_LEN];
                    size_t fnamelen = strlen(saveDir) + strlen(fileID) + strlen(smbFlowP->fname) + 21;
                    if (fnamelen >= sizeof(name)) {
                        smbFlowP->stat |= SMB_STAT_NAMETRUNC;
                        fnamelen = SMB_FNAME_LEN;
                    }
                    snprintf(name, fnamelen, "%s%s%s_%" PRIu64, saveDir, fileID, smbFlowP->fname, flowP->findex);
                    FILE *f = fopen(name, "a");
                    if (f) fclose(f);
                    f = fopen(name, "r+");
                    if (UNLIKELY(!f)) return;
                    fseek(f, smbFlowP->off, SEEK_SET);
                    fwrite(ptr, 1, len, f);
                    fclose(f);

                    smbFlowP->off += len;
                    if (smbFlowP->left <= remaining) {
                        ptr += smbFlowP->left;
                        smbFlowP->left = remaining - smbFlowP->left;
                        smbFlowP->hdrstat = 0;
                    } else {
                        smbFlowP->left -= len;
                        if (smbFlowP->left > 0) smbFlowP->hdrstat = SMB2_HDRSTAT_DATA;
                        else smbFlowP->hdrstat = 0;
                    }
                    remaining -= len;
                } else { // SMB2 RESPONSE
                    // TODO
                    return;
                }
                break;
            }
#endif // SMB2_SAVE_DATA == 1

#if SMB2_SAVE_DATA == 1
            case SMB2_OP_READ: {
                if (SMB2_IS_REQUEST(smb2)) {
                    const smb2_read_req_t * const r = (smb2_read_req_t*) ptr;
                    snprintf(smbFlowP->rname, sizeof(smbFlowP->rname),
                        "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                        r->fid.d1, r->fid.d2, r->fid.d3,
                        r->fid.d4[0], r->fid.d4[1], r->fid.d4[2], r->fid.d4[3],
                        r->fid.d4[4], r->fid.d4[5], r->fid.d4[6], r->fid.d4[7]);
                    smbFlowP->roff = r->off;
                } else { // SMB2 RESPONSE
                    // TODO not all read records are counted...
                    smb2_read_resp_t *r = (smb2_read_resp_t*) ptr;
                    if (smbFlowP->hdrstat == SMB2_HDRSTAT_READ) {
read_hdr:
                        memcpy(smbFlowP->hdr + smbFlowP->hdroff, ptr, 17 - smbFlowP->hdroff);
                        ptr += 17 - smbFlowP->hdroff;
                        r = (smb2_read_resp_t*)smbFlowP->hdr;
                    }
                    // TODO check SMB header status if not success, abort
                    if (r->dlen == 0) return;
                    if (remaining < sizeof(*r)) {
                        smbFlowP->hdrstat = SMB2_HDRSTAT_READ;
                        if (remaining) {
                            memcpy(smbFlowP->hdr, ptr, remaining);
                            smbFlowP->hdroff = remaining;
                        }
                        return;
                    }
                    if (smbFlowP->hdrstat == SMB2_HDRSTAT_READ) {
                        smbFlowP->hdrstat = 0;
                        remaining -= (17 - smbFlowP->hdroff);
                        smbFlowP->hdroff = 0;
                    } else {
                        ptr += sizeof(*r);
                        remaining -= sizeof(*r);
                    }
smb2_read:;
                    const unsigned long ofidx = flowP->oppositeFlowIndex;
                    if (ofidx == HASHTABLE_ENTRY_NOT_FOUND) return; // request not seen
                    const smb_flow_t * const smbRevFlowP = &smb_flows[ofidx];
                    if (smbRevFlowP->msg_id != smbFlowP->msg_id) return; // msg id do not match

                    const uint32_t len = remaining;
                    if (smbFlowP->rleft == 0) {
                        smbFlowP->rleft = r->dlen; // TODO fix warning
                        smbFlowP->roff = smbRevFlowP->roff;
                    }
                    if (smbFlowP->rleft > len) smbFlowP->hdrstat = SMB2_HDRSTAT_RDATA;
                    smbFlowP->rleft -= len;
                    char name[SMB_FNAME_LEN];
                    size_t fnamelen = strlen(saveDir) + strlen(fileID) + strlen(smbRevFlowP->rname) + 21;
                    if (fnamelen >= SMB_FNAME_LEN) {
                        smbFlowP->stat |= SMB_STAT_NAMETRUNC;
                        fnamelen = SMB_FNAME_LEN;
                    }
                    snprintf(name, fnamelen, "%s%s%s_%" PRIu64, saveDir, fileID, smbRevFlowP->rname, flowP->findex); // TODO try without findex
                    FILE *f = fopen(name, "a");
                    if (f) fclose(f);
                    f = fopen(name, "r+");
                    if (UNLIKELY(!f)) return;
                    fseek(f, smbFlowP->roff, SEEK_SET);
                    fwrite(ptr, 1, len, f);
                    fclose(f);
                    if (smbFlowP->hdrstat == SMB2_HDRSTAT_RDATA) {
                        smbFlowP->roff += len;
                        return;
                    }
                    if (smbFlowP->rleft == 0) {
                        smbFlowP->roff = 0;
                    }
                }
                return;
            }
#endif // SMB2_SAVE_DATA == 1

            case SMB2_OP_QUERY_INFO: {
                if (SMB2_IS_REQUEST(smb2)) {

                } else { // SMB2 RESPONSE
                    // TODO get info about file
                }
                return;
            }

            case SMB2_OP_QUERY_DIR: {
                // TODO [MS-FSCC], section 2.4
                if (SMB2_IS_REQUEST(smb2)) {

                } else { // SMB2 RESPONSE
                    // TODO get directory listing
                }
                return;
            }

            case SMB2_OP_TREE_CONNECT: {
                if (SMB2_IS_REQUEST(smb2)) {
                    const smb2_tree_connect_req_t * const t = (smb2_tree_connect_req_t*) ptr;
                    uint8_t *x = ((uint8_t*)smb2 + t->pathoff);
                    const uint16_t len = MIN(t->pathlen / 2, SMB_FNAME_LEN);
                    if (len < t->pathlen / 2) smbFlowP->stat |= SMB_STAT_NAMETRUNC;
                    uint16_t i, tmp;
                    for (i = 0; i < len; i++) {
                        tmp = *(uint16_t*)x;
                        if (tmp < 128) {
                            smbFlowP->path[i] = *x;
                        } else {
                            smbFlowP->path[i] = '_';
                        }
                        x += 2;
                    }
                    smbFlowP->path[i] = '\0';
                } else { // SMB2 RESPONSE
                    const smb2_tree_connect_resp_t * const t = (smb2_tree_connect_resp_t*) ptr;
                    smbFlowP->sharetype = t->sharetype;
                    smbFlowP->shareflags = t->shareflags;
                    smbFlowP->sharecaps = t->caps;
                    smbFlowP->shareaccess = t->maxacc;
                }
                return;
            }

            case SMB2_OP_NEGOTIATE: {
                if (SMB2_IS_REQUEST(smb2)) {
                    const smb2_negotiate_req_t * const n = (smb2_negotiate_req_t*) ptr;
                    smbFlowP->caps = n->caps;
                    smbFlowP->secmod = n->secmod;
#if SMB2_NUM_DIALECT > 0
                    smbFlowP->ndialect = (remaining - 36) / sizeof(uint16_t);
                    const uint8_t imax = MIN(smbFlowP->ndialect, SMB2_NUM_DIALECT);
                    if (imax < smbFlowP->ndialect) smbFlowP->stat |= SMB_STAT_DIAL2L;
                    uint16_t *tmp = (uint16_t*)(ptr+36);
                    for (uint_fast8_t i = 0; i < imax; i++) {
                        smbFlowP->dialect[i] = *tmp;
                        tmp++;
                    }
#endif // SMB2_NUM_DIALECT > 0
                    snprintf(smbFlowP->guid, sizeof(smbFlowP->guid),
                        "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                        n->guid.d1, n->guid.d2, n->guid.d3,
                        n->guid.d4[0], n->guid.d4[1], n->guid.d4[2], n->guid.d4[3],
                        n->guid.d4[4], n->guid.d4[5], n->guid.d4[6], n->guid.d4[7]);
                } else { // SMB2 RESPONSE
                    const smb2_negotiate_resp_t * const n = (smb2_negotiate_resp_t*) ptr;
#if SMB2_NUM_DIALECT > 0
                    smbFlowP->ndialect = 1;
                    smbFlowP->dialect[0] = n->drev;
#endif // SMB2_NUM_DIALECT > 0
                    smbFlowP->secmod = n->secmod;
                    smbFlowP->caps = n->caps;
                    smbFlowP->maxTSize = n->maxTSize;
                    smbFlowP->maxRSize = n->maxRSize;
                    smbFlowP->maxWSize = n->maxWSize;
                    smbFlowP->bootTime = SMB_WIN_TIME_TO_UNIX(n->srvStartT);
                    snprintf(smbFlowP->guid, sizeof(smbFlowP->guid),
                        "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                        n->guid.d1, n->guid.d2, n->guid.d3,
                        n->guid.d4[0], n->guid.d4[1], n->guid.d4[2], n->guid.d4[3],
                        n->guid.d4[4], n->guid.d4[5], n->guid.d4[6], n->guid.d4[7]);
#if SMB_SECBLOB == 1
                    if (n->secbuflen > 0) {
                        ptr += (n->secbufoff - SMB2_HDR_LEN);
                        const gssapi_t * const gss = (gssapi_t*)ptr;
                        ptr += sizeof(*gss);
                        if (gss->atag != 0x60) return;
                        if (gss->otag == 0x06) {
                            switch (*(uint64_t*)(ptr-2)) {
                                case SPNEGO_OID:
                                    // TODO list supported
                                    break;
                                default:
                                    //T2_PDBG(plugin_name, "Unhandled OID");
                                    break;
                            }
                        }
                    }
#endif // SMB_SECBLOB == 1
                }
                return;
            }

            case SMB2_OP_SESSION_SETUP: {
                if (SMB2_IS_REQUEST(smb2)) {
                    const smb2_session_setup_req_t * const s = (smb2_session_setup_req_t*) ptr;
                    smbFlowP->prevsessid = s->prevsessid;
#if SMB_SECBLOB == 1
                    if (s->secbuflen > 0) {
                        ptr += (s->secbufoff - SMB2_HDR_LEN);
                        if (l7end - ptr <= 0) return;
                        const void * const vtmp = memmem(ptr, /*s->secbuflen*/l7end - ptr, ntlmssp, NTLMSSP_LEN);
                        if (!vtmp) return;
                        ptr += ((uint8_t*)vtmp - ptr);
                        remaining -= ((uint8_t*)vtmp - ptr);
                        ntlmssp_auth_t *a = (ntlmssp_auth_t*)ptr;
                        if (remaining < sizeof(*a)) return;
                        if (a->type != NTLMSSP_MT_AUTH) return;
                        uint32_t i;
                        uint8_t *tmp = ptr + a->dom_off;
                        //SMB_READ_U16_STR(smbFlowP->domain_name, tmp, a->dom_len/2);
                        if (remaining < sizeof(*a) + a->dom_off + a->dom_len) return;
                        for (i = 0; i < a->dom_len/2; i++) {
                            smbFlowP->domain_name[i] = *tmp;
                            tmp += 2;
                        }
                        tmp = ptr + a->user_off;
                        //SMB_READ_U16_STR(smbFlowP->user_name, tmp, a->user_len/2);
                        if (remaining < sizeof(*a) + a->user_off + a->user_len) return;
                        for (i = 0; i < a->user_len/2; i++) {
                            smbFlowP->user_name[i] = *tmp;
                            tmp += 2;
                        }
                        tmp = ptr + a->host_off;
                        //SMB_READ_U16_STR(smbFlowP->host_name, tmp, a->host_len/2);
                        if (remaining < sizeof(*a) + a->host_off + a->host_len) return;
                        for (i = 0; i < a->host_len/2; i++) {
                            smbFlowP->host_name[i] = *tmp;
                            tmp += 2;
                        }
                        tmp = ptr + a->session_off;
                        uint32_t off = 0;
                        if (remaining < sizeof(*a) + a->session_off + a->session_len) return;
                        for (i = 0; i < a->session_len; i++) {
                            snprintf(&(smbFlowP->sessionkey[off]), 3, "%02" B2T_PRIX8, *tmp);
                            off += 2;
                            tmp++;
                        }
                        smbFlowP->sessionkey[off] = '\0';
                        // TODO Version
                    }
#endif // SMB_SECBLOB == 1
                    ptr += sizeof(*s);
                } else { // SMB2 RESPONSE
                    const smb2_session_setup_resp_t * const s = (smb2_session_setup_resp_t*) ptr;
                    smbFlowP->sflags = s->sflags;
#if SMB_SECBLOB == 1
                    if (s->secbuflen > 0) {
                        if (s->secbufoff < SMB2_HDR_LEN) return;
                        if (remaining < (uint32_t)(s->secbufoff-SMB2_HDR_LEN)) return; // TODO fix warning
                        remaining -= (s->secbufoff-SMB2_HDR_LEN);
                        ptr += (s->secbufoff - SMB2_HDR_LEN);
                        if (l7end - ptr <= 0) return;
                        const void * const vtmp = memmem(ptr, /*s->secbuflen*/l7end - ptr, ntlmssp, NTLMSSP_LEN);
                        if (!vtmp) return;
                        ptr += ((uint8_t*)vtmp - ptr);
                        remaining -= ((uint8_t*)vtmp - ptr);
                        const ntlmssp_challenge_t * const c = (ntlmssp_challenge_t*)ptr;
                        if (remaining < sizeof(*c)) return;
                        if (c->type != NTLMSSP_MT_CHALLENGE) return;
                        uint8_t *tmp = ptr + c->domoff;
                        uint32_t i;
                        //SMB_READ_U16_STR(smbFlowP->target_name, ptr, c->domlen/2);
                        if (remaining < sizeof(*c) + c->domoff + c->domlen) return;
                        for (i = 0; i < c->domlen/2; i++) {
                            smbFlowP->target_name[i] = *tmp;
                            tmp += 2;
                        }
                        smbFlowP->target_name[i] = '\0';

                        // NTLM Server challenge
                        if (remaining < sizeof(*c) + 16) return;
                        uint32_t off = 0;
                        for (i = 0; i < 8; i++) {
                            snprintf(&(smbFlowP->ntlmserverchallenge[off]), 3, "%02" B2T_PRIX8, c->nonce[i]);
                            off += 2;
                        }
                        smbFlowP->ntlmserverchallenge[off] = '\0';
                        // TODO list supported
                    }
#endif // SMB_SECBLOB == 1
                }
                return;
            }

            default:
                T2_PDBG(plugin_name, "Unhandled SMB2 opcode %#02x", smb2->opcode);
                return;
        }
    }
}


void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {
    smb_flow_t * const smbFlowP = &smb_flows[flowIndex];

    smbStat |= smbFlowP->stat;

    uint32_t imax;

    OUTBUF_APPEND_U16(buf, smbFlowP->stat); // smbStat

#if SMB1_NUM_DIALECT > 0
    // smb1NDialects
    OUTBUF_APPEND_U32(buf, smbFlowP->ndialect1);

    // smb1Dialects
    imax = MIN(smbFlowP->ndialect1, SMB1_NUM_DIALECT);
    OUTBUF_APPEND_ARRAY_STR(buf, smbFlowP->dialect1, imax);
#endif // SMB1_NUM_DIALECT > 0

#if SMB2_NUM_DIALECT > 0
    // smb2NDialects
    OUTBUF_APPEND_U32(buf, smbFlowP->ndialect);

    // smb2Dialects
    imax = MIN(smbFlowP->ndialect, SMB2_NUM_DIALECT);
    OUTBUF_APPEND_ARRAY_U16(buf, smbFlowP->dialect, imax);
#endif // SMB2_NUM_DIALECT > 0

#if SMB2_NUM_STAT > 0
    // smbNHdrStat
    OUTBUF_APPEND_U32(buf, smbFlowP->numstat);

    // smbHdrStat
    imax = MIN(smbFlowP->numstat, SMB2_NUM_STAT);
    OUTBUF_APPEND_ARRAY_U32(buf, smbFlowP->smbstat, imax);
#endif // SMB2_NUM_STAT > 0

    // smbOpcodes
    OUTBUF_APPEND_U32(buf, smbFlowP->opcodes);

    // smbNOpcodes
    for (uint_fast32_t i = 0; i < SMB2_OP_N; i++) {
        OUTBUF_APPEND_U32(buf, smbFlowP->nopcode[i]);
    }

    OUTBUF_APPEND_U64(buf, smbFlowP->prevsessid);          // smbPrevSessId
    OUTBUF_APPEND_STR(buf, smbFlowP->nativeos);            // smbNativeOS
    OUTBUF_APPEND_STR(buf, smbFlowP->nativelanman);        // smbNativeLanMan
    OUTBUF_APPEND_STR(buf, smbFlowP->primarydomain);       // smbPrimDom
    OUTBUF_APPEND_STR(buf, smbFlowP->target_name);         // smbTargName
    OUTBUF_APPEND_STR(buf, smbFlowP->domain_name);         // smbDomName
    OUTBUF_APPEND_STR(buf, smbFlowP->user_name);           // smbUserName
    OUTBUF_APPEND_STR(buf, smbFlowP->host_name);           // smbHostName
    OUTBUF_APPEND_STR(buf, smbFlowP->ntlmserverchallenge); // smbNTLMServChallenge
    OUTBUF_APPEND_STR(buf, smbFlowP->ntproof);             // smbNTProofStr

#if SMB_SAVE_AUTH == 1
    //OUTBUF_APPEND_STR(buf, smbFlowP->ntlmclientchallenge); // smbNTLMCliChallenge
#endif // SMB_SAVE_AUTH == 1

    OUTBUF_APPEND_STR(buf, smbFlowP->sessionkey); // smbSessionKey
    OUTBUF_APPEND_STR(buf, smbFlowP->guid);       // smbGUID

    // smbSFlags_secM_caps
    OUTBUF_APPEND_U16(buf, smbFlowP->sflags);
    OUTBUF_APPEND_U8(buf , smbFlowP->secmod);
    OUTBUF_APPEND_U32(buf, smbFlowP->caps);

    OUTBUF_APPEND_TIME_SEC(buf, smbFlowP->bootTime); // smbBootT

    // smbMaxSizeT_R_W
    OUTBUF_APPEND_U32(buf, smbFlowP->maxTSize);
    OUTBUF_APPEND_U32(buf, smbFlowP->maxRSize);
    OUTBUF_APPEND_U32(buf, smbFlowP->maxWSize);

    OUTBUF_APPEND_STR(buf, smbFlowP->path);      // smbPath
    OUTBUF_APPEND_U8(buf, smbFlowP->sharetype);  // smbShareT

    // smbShareF_caps_acc
    OUTBUF_APPEND_U32(buf, smbFlowP->shareflags);
    OUTBUF_APPEND_U32(buf, smbFlowP->sharecaps);
    OUTBUF_APPEND_U32(buf, smbFlowP->shareaccess);

    OUTBUF_APPEND_U32(buf, smbFlowP->numSFile);  // smbNFiles

    // smbFiles
    imax = MIN(smbFlowP->numSFile, SMB_NUM_FNAME);
    OUTBUF_APPEND_ARRAY_STR(buf, smbFlowP->sname, imax);

#if SMB_SAVE_AUTH == 1
    const flow_t * const flowP = &flows[flowIndex];
    if (FLOW_IS_A(flowP) && FLOW_HAS_OPPOSITE(flowP)) {
        const unsigned long reverseFlowIndex = flowP->oppositeFlowIndex;
        smb_flow_t * const reverseFlow = &smb_flows[reverseFlowIndex];
        if (strlen(smbFlowP->user_name) && strlen(smbFlowP->domain_name) &&
            strlen(reverseFlow->ntlmserverchallenge) && strlen(smbFlowP->ntproof) &&
            strlen(smbFlowP->ntlmclientchallenge))
        {
            smbNumAuth++;
            smbFlowP->stat |= SMB_STAT_AUTH;
            reverseFlow->stat |= SMB_STAT_AUTH;
            fprintf(smbAuthFile, "# %" PRIu64 "\n%s::%s:%s:%s:%s\n", flowP->findex,
                    smbFlowP->user_name, smbFlowP->domain_name,
                    reverseFlow->ntlmserverchallenge, smbFlowP->ntproof,
                    smbFlowP->ntlmclientchallenge);
        }
    }
#endif // SMB_SAVE_AUTH == 1
}


void t2PluginReport(FILE *stream) {
    if (smbStat) {
        T2_FPLOG_AGGR_HEX0(stream, plugin_name, smbStat);
        T2_FPLOG_NUMP(stream, plugin_name, "Number of SMB packets", numSMBPackets, numPackets);
        T2_FPLOG_NUM(stream, plugin_name, "Number of SMBv1 records", num_smb[0]);
        T2_FPLOG_NUM(stream, plugin_name, "Number of SMBv2 records", num_smb[1]);
        T2_FPLOG_NUM(stream, plugin_name, "Number of SMBv3 records", num_smb[2]);
    }

#if SMB_SAVE_AUTH == 1
    T2_FPLOG_NUM(stream, plugin_name, "Number of NetNTLMv2 hashes extracted", smbNumAuth);
#endif // SMB_SAVE_AUTH == 1
}


void t2Finalize() {
#if SMB_SAVE_DATA == 1
    if (guidMapF) fclose(guidMapF);
#endif /// SMB_SAVE_DATA

#if SMB_SAVE_AUTH == 1
    if (smbAuthFile) fclose(smbAuthFile);
#endif /// SMB_SAVE_AUTH

    free(smb_flows);

#if (ENVCNTRL > 0 && (SMB_SAVE_DATA == 1 || SMB_SAVE_AUTH == 1))
    t2_free_env(ENV_SMB_N, env);
#endif // (SMB_SAVE_DATA == 1 && ENVCNTRL > 0)
}


//#if SMB_USE_FILTER > 0
//static inline int str_has_suffix(const char *str, const char *suffix) {
//    if (!str || !suffix) return 0;
//    const size_t str_len = strlen(str);
//    const size_t suffix_len = strlen(suffix);
//    if (str_len < suffix_len) return 0;
//    return (strcmp(str + str_len - suffix_len, suffix) == 0);
//}
//#endif // SMB_USE_FILTER
