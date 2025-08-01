/*
 * bitForensic.c
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

#include "bitForensic.h"
#include <errno.h>


// Global variables

bitForFlow_t *bitForFlows;


// Static variables

static uint32_t bfCnt;
static uint8_t bfStat;

#if BF_SAVE_BCH == 1
static uint32_t bfFdCnt, bfFdCntMax;

#if ENVCNTRL > 0
static const char *bfVPath;
static const char *bfFName;
#else // ENVCNTRL == 0
static const char * const bfVPath = BF_V_PATH;
static const char * const bfFName = BF_FNAME;
#endif // ENVCNTRL

#endif // BF_SAVE_BCH == 1


// Tranalyzer functions

T2_PLUGIN_INIT("bitForensic", "0.9.3", 0, 9);


void t2Init() {
    T2_PLUGIN_STRUCT_NEW(bitForFlows);

#if BF_SAVE_BCH == 1

#if ENVCNTRL > 0
    t2_env_t env[ENV_BF_N] = {};
    t2_get_env(PLUGIN_SRCH, ENV_BF_N, env);
    bfVPath = T2_STEAL_ENV_VAL(BF_V_PATH);
    bfFName = T2_STEAL_ENV_VAL(BF_FNAME);
    const uint8_t rmdir = T2_ENV_VAL_UINT(BF_RMDIR);
    t2_free_env(ENV_BF_N, env);
#else // ENVCNTRL == 0
    const uint8_t rmdir = BF_RMDIR;
    //T2_SET_ENV_NUM(BF_RMDIR);
    //T2_SET_ENV_STR(BF_V_PATH);
    //T2_SET_ENV_STR(BF_FNAME);
#endif // ENVCNTRL

    T2_MKPATH(bfVPath, rmdir);
#endif // BF_SAVE_BCH == 1

    // Packet mode
    if (sPktFile) {
        fputs("bfStat"  SEP_CHR
              "bfPDPos" SEP_CHR
              , sPktFile);
    }
}


binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;

    BV_APPEND_H8(bv, "bfStat", "bitForensic status");
    BV_APPEND_U16_R(bv, "bfPDPos", "bitForensic Pattern Detect Position");

    return bv;
}


void t2OnNewFlow(packet_t *packet UNUSED, unsigned long flowIndex) {
    bitForFlow_t * const bfFlowP = &bitForFlows[flowIndex];
    memset(bfFlowP, '\0', sizeof(*bfFlowP));
}


static inline void bitFCmp(packet_t *packet, unsigned long flowIndex) {
    bitForFlow_t * const bfFlowP = &bitForFlows[flowIndex];

#if BF_PWDTH > 1
    typedef union {
#if BF_PWDTH == 4
        uint64_t *b;
#elif BF_PWDTH == 3
        uint32_t *b;
#elif BF_PWDTH == 2
        uint16_t *b;
#endif // BF_PWDTH > 1
        uint8_t *c;
    } u8_t;
    u8_t z;
#else // BW_PWDTH <= 1
    uint8_t *c;
#endif // BF_PWDTH

#if SPKTMD_PCNTL == 4

#if BF_PWDTH > 1
    z.c = (uint8_t*)packet->l7HdrP;
#else // BW_PWDTH <= 1
    c = (uint8_t*)packet->l7HdrP;
#endif // BF_PWDTH

    const uint16_t len = packet->snapL7Len;

#elif SPKTMD_PCNTL == 3

#if BF_PWDTH > 1
    z.c = (uint8_t*)packet->l4HdrP;
#else // BW_PWDTH <= 1
    c = (uint8_t*)packet->l4HdrP;
#endif // BF_PWDTH

    const uint16_t len = packet->snapL4Len;

#elif SPKTMD_PCNTL == 2

#if BF_PWDTH > 1
    z.c = (uint8_t*)packet->l3HdrP;
#else // BW_PWDTH <= 1
    c = (uint8_t*)packet->l3HdrP;
#endif // BF_PWDTH

    const uint16_t len = packet->snapL3Len;

#elif SPKTMD_PCNTL == 1

#if BF_PWDTH > 1
    z.c = (uint8_t*)packet->l2HdrP;
#else // BW_PWDTH <= 1
    c = (uint8_t*)packet->l2HdrP;
#endif // BF_PWDTH

    const uint16_t len = packet->snapL2Len;

#elif SPKTMD_PCNTL == 0

#if BF_PWDTH > 1
    z.c = (uint8_t*)packet->raw_packet;
#else // BW_PWDTH <= 1
    c = (uint8_t*)packet->raw_packet;
#endif // BF_PWDTH

    const uint16_t len = packet->snapLen;

#endif // SPKTMD_PCNTL

#if BF_PLEN == 1
    uint16_t lenh = packet->len - BF_EXLEN;
#endif // BF_PLEN == 1

    uint8_t stat = 0x00;
    for (uint_fast32_t i = 0; i < len; i++) {
#if BF_PLEN == 1

#if BF_PWDTH == 4
        if (*z.b && (*z.b & MSK) ==
#if BF_NETODR == 1
                htobe64(lenh)) {
#else // BF_NETODR == 0
                lenh) {
#endif // BF_NETODR
#elif BF_PWDTH == 3
        if (*z.b && ((*z.b & MSK) ==
#if BF_NETODR == 1
                ntohl(lenh)) {
#else // BF_NETODR == 0
                lenh) {
#endif // BF_NETODR
#elif BF_PWDTH == 2
        if (*z.b && (*z.b & MSK) ==
#if BF_NETODR == 1
                ntohs(lenh)) {
#else // BF_NETODR == 0
                lenh) {
#endif // BF_NETODR
#else // BF_PWDTH <= 1
        if (*c && (*c & MSK) == (uint8_t)(lenh)) {
#endif // BF_PWDTH
            stat |= BF_PHLEN;

#else // BF_PLEN == 0

#if BF_PWDTH > 1
        if ((*z.b & MSK) == PAT) {
#else // BF_PWDTH <= 1
        if ((*c & MSK) == PAT) {
#endif // BF_PWDTH

#endif // BF_PLEN
            if (!(stat & BF_DET)) {
                stat |= (BF_DET | BF_PWDTH << 4);
                if (sPktFile) fprintf(sPktFile, "0x%02" B2T_PRIX8 /* bfStat */ SEP_CHR, stat);
            }

            if (sPktFile) fprintf(sPktFile, "%" PRIuFAST32 ";", i); // bfPDPos

            bfCnt++;
            if (bfFlowP->cnt < BF_DNUM) {
                for (uint32_t j = 0; j < bfFlowP->cnt; j++) {
                    if (bfFlowP->bPDPos[j] == i) goto bfexist;
                }
                bfFlowP->bPDPos[bfFlowP->cnt++] = i;
            }
        }

bfexist:;
#if BF_PWDTH > 1
        z.c++;
#else // BF_PWDTH <= 1
        c++;
#endif // BF_PWDTH

#if (BF_PLEN == 1 && BF_TOTLEN == 0)
        lenh--;
#endif // (BF_PLEN == 1 && BF_TOTLEN == 0)
    }

#if BF_SAVE_BCH == 1
// if (bchannel start) {
    if (bfFlowP->fd == NULL) {
        flow_t * const flowP = &flows[flowIndex];
        snprintf(bfFlowP->bfname, sizeof(bfFlowP->bfname),
                "%s%s_%" PRIu64 "_%c.raw",
                bfVPath, bfFName, flowP->findex, FLOW_DIR_C(flowP));

        bfFlowP->fd = file_manager_open(t2_file_manager, bfFlowP->bfname, "w+b");
        if (!bfFlowP->fd) {
            T2_PERR(plugin_name, "failed to open file '%s' for writing: %s", bfFlowP->bfname, strerror(errno));
            goto bfpout;
        }

        stat |= BF_WROP;
        if (++bfFdCnt > bfFdCntMax) bfFdCntMax = bfFdCnt;
    }

    const size_t alen = len - BF_BSHIFT;
    if (alen > 0) {
        FILE * const fp = file_manager_fp(t2_file_manager, bfFlowP->fd);
#if BF_PWDTH > 1
        fwrite(z.b + BF_BSHIFT, alen, 1, fp);
#else // BF_PWDTH <= 1
        fwrite(c + BF_BSHIFT, alen, 1, fp);
#endif // BF_PWDTH
    }
//}

bfpout:
#endif // BF_SAVE_BCH == 1
    if (sPktFile) {
        if (stat) {
            fputs(/* bfStat */ SEP_CHR, sPktFile);
        } else {
            fputs("0x00" /* bfStat */ SEP_CHR /* bfPDPos */ SEP_CHR, sPktFile);
        }
    }

    bfFlowP->stat |= stat;
}


#if ETH_ACTIVATE > 0
void t2OnLayer2(packet_t *packet, unsigned long flowIndex) {
    if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;

    bitFCmp(packet, flowIndex);
}
#endif // ETH_ACTIVATE > 0


void t2OnLayer4(packet_t *packet, unsigned long flowIndex) {
    bitFCmp(packet, flowIndex);
}


void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {
    bitForFlow_t * const bfFlowP = &bitForFlows[flowIndex];

#if BF_SAVE_BCH == 1
    if (bfFlowP->fd) {
        file_manager_close(t2_file_manager, bfFlowP->fd);
        bfFlowP->fd = NULL;
        bfFdCnt--;
        if (!(bfFlowP->stat & BF_WROP)) remove(bfFlowP->bfname);
    }
#endif // BF_SAVE_BCH == 1

    bfStat |= bfFlowP->stat;

    // bfStat
    OUTBUF_APPEND_U8(buf, bfFlowP->stat);

    // bfPDPos
    OUTBUF_APPEND_ARRAY_U16(buf, bfFlowP->bPDPos, bfFlowP->cnt);
}


void t2PluginReport(FILE *stream) {
    T2_FPLOG_AGGR_HEX(stream, plugin_name, bfStat);
    T2_FPLOG_NUM(stream, plugin_name, "Number of bit patterns", bfCnt);
#if BF_SAVE_BCH == 1
    T2_FPLOG_NUM(stream, plugin_name, "Max number of file handles", bfFdCntMax);
#endif // BF_SAVE_BCH == 1
}


void t2Finalize() {
#if BF_SAVE_BCH == 1 && ENVCNTRL > 0
    free((char*)bfVPath);
    free((char*)bfFName);
#endif // BF_SAVE_BCH == 1 && ENVCNTRL > 0

    free(bitForFlows);
}
