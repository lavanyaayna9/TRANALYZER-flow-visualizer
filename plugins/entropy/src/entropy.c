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

#include "entropy.h"

#include <math.h>


// Global variables

entropyFlow_t *entropyFlow;


// Static variables

static float entropyGMin = ENT_NBITS, entropyGMax;
static float entAve = -1.0;
static uint32_t eStat;

#if ENVCNTRL > 0
static int32_t enthtn;
static uint16_t enthpktig;
static uint16_t enthead;
static uint16_t enttail;
static uint16_t entthresl;
static uint16_t entthresh;
#else // ENVCNTRL == 0
static const int32_t enthtn = ENT_TAIL - ENT_HEAD;
static const uint16_t enthpktig = ENT_HPKTIG;
static const uint16_t enthead = ENT_HEAD;
static const uint16_t enttail = ENT_TAIL;
static const uint16_t entthresl = ENT_THRESL;
static const uint16_t entthresh = ENT_THRESH;
#endif // ENVCNTRL


// Tranalyzer Plugin functions

T2_PLUGIN_INIT("entropy", "0.9.3", 0, 9);


void t2Init() {
    T2_PLUGIN_STRUCT_NEW(entropyFlow);

#if ENVCNTRL > 0
    t2_env_t env[ENV_ENT_N] = {};
    t2_get_env(PLUGIN_SRCH, ENV_ENT_N, env);
    enthpktig = T2_ENV_VAL_UINT(ENT_HPKTIG);
    enthead = T2_ENV_VAL_UINT(ENT_HEAD);
    enttail = T2_ENV_VAL_UINT(ENT_TAIL);
    entthresl = T2_ENV_VAL_UINT(ENT_THRESL);
    entthresh = T2_ENV_VAL_UINT(ENT_THRESH);
    enthtn = (int32_t)(enttail - enthead);
    t2_free_env(ENV_ENT_N, env);
#endif // ENVCNTRL

    if (UNLIKELY(enthtn <= 0)) {
        T2_PFATAL(plugin_name, "ENT_TAIL (%" PRIu16 ") - ENT_HEAD (%" PRIu16 ") MUST be > 0", enttail, enthead);
    }
}


binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;

    BV_APPEND_FLT(bv  , "PyldEntropy" , "Payload entropy");
    BV_APPEND_FLT(bv  , "PyldChRatio" , "Payload character ratio");
    BV_APPEND_FLT(bv  , "PyldBinRatio", "Payload binary ratio");

#if ENT_ALPHAD == 1
    BV_APPEND_U32(bv  , "NumBin0"     , "Number of 0 count bins");
    BV_APPEND_FLT(bv  , "Corr"        , "Entropy correction");
    BV_APPEND_U32(bv  , "PyldLen"     , "Payload length");
    BV_APPEND_U32_R(bv, "PyldHisto"   , "Payload histogram");
#endif // ENT_ALPHAD == 1

    return bv;
}


void t2OnNewFlow(packet_t* packet UNUSED, unsigned long flowIndex) {
    entropyFlow_t * const entropyFlowP = &entropyFlow[flowIndex];
    memset(entropyFlowP, '\0', sizeof(entropyFlow_t));
}


static inline void ent_claimInfo(packet_t* packet, unsigned long flowIndex) {
    entropyFlow_t * const entropyFlowP = &entropyFlow[flowIndex];

    if (entropyFlowP->numPktIgn < enthpktig) {
        entropyFlowP->numPktIgn++;
        return;
    } else if (entropyFlowP->numWrds >= entthresh) {
        return;
    }

    int_fast32_t snapL7Len = packet->snapL7Len - enthead;
    if (snapL7Len < 0) return;

    if (packet->snapL7Len > enttail) snapL7Len = enthtn;
    if (snapL7Len + entropyFlowP->numWrds > entthresh) snapL7Len = entthresh - entropyFlowP->numWrds;

    const uint8_t * const pld = packet->l7HdrP + enthead;

#if ENT_NBITS < 8
    uint8_t w, j;
#endif // ENT_NBITS < 8

    for (int_fast32_t i = 0; i < snapL7Len; i++) {
#if (ENT_NBITS >= 8 || ENT_NBITS <= 0)
        entropyFlowP->binCnt[pld[i]]++;
#else // ENT_NBITS < 8
        w = pld[i];
        j = ENT_NSHFT;
        while (j--) {
            entropyFlowP->binCnt[(w & ENT_MSK)]++;
            w >>= (ENT_NBITS);
        }
#endif // ENT_NBITS
    }

    entropyFlowP->numWrds += snapL7Len; // only the true snapped payload
}


#if ETH_ACTIVATE > 0
void t2OnLayer2(packet_t *packet, unsigned long flowIndex) {
    if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;
    ent_claimInfo(packet, flowIndex);
}
#endif // ETH_ACTIVATE > 0


void t2OnLayer4(packet_t* packet, unsigned long flowIndex) {
    ent_claimInfo(packet, flowIndex);
}


void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {
    float crp, brp, entropy = 0.0f;

    entropyFlow_t * const entropyFlowP = &entropyFlow[flowIndex];
    const float numWrds = entropyFlowP->numWrds * ENT_NSHFT;
    uint32_t numBin0 = 0;

    if (numWrds > entthresl) {
        uint32_t pBin = 0, pChar = 0;
        for (uint_fast32_t i = 0; i < ENT_MAXPBIN; i++) {
            const uint32_t count = entropyFlowP->binCnt[i];
            if (count) {
                const float p = count / numWrds;
                entropy += p * log(p);
#if ENT_NBITS == 8
                if (i == 10 || i == 13 || (i >= 32 && i <= 127)) pChar += count;
                else if (i < 10) pBin += count;
#endif // ENT_NBITS == 8
            } else numBin0++;
        }

        entropy /= -log(ENT_NORMMB);

        crp = pChar / numWrds;
        brp = pBin / numWrds;
    } else {
        entropy = -1.0f;
        crp = -1.0f;
        brp = -1.0f;
    }

    if (entropy <= 0) {
        eStat++;
    } else {
        entropyGMin = MIN(entropyGMin, entropy);
        entropyGMax = MAX(entropyGMax, entropy);
        if (entAve != -1.0) entAve = 0.7 * entAve + 0.3 * entropy;
        else entAve = entropy;
    }

    OUTBUF_APPEND_FLT(buf, entropy); // PyldEntropy
    OUTBUF_APPEND_FLT(buf, crp);     // PyldChRatio
    OUTBUF_APPEND_FLT(buf, brp);     // PyldBinRatio

#if ENT_ALPHAD == 1
    float corr = 0.0;
    if (numWrds > 0 && numBin0) corr = (float)(numBin0 - 1) / (2 * numWrds);
    OUTBUF_APPEND_U32(buf, numBin0);
    OUTBUF_APPEND_FLT(buf, corr);
    numBin0 = numWrds;
    OUTBUF_APPEND_U32(buf, numBin0);
    OUTBUF_APPEND_ARRAY_U32(buf, entropyFlowP->binCnt, ENT_MAXPBIN); // PyldHisto
#endif // ENT_ALPHAD == 1
}


void t2PluginReport(FILE *stream) {
    if (entropyGMax) {
        T2_FPLOG(stream, plugin_name, "NValFlows, min, ave, max: %d, %f, %f, %f", eStat, entropyGMin, entAve, entropyGMax);
    }
}


void t2Finalize() {
    free(entropyFlow);
}
