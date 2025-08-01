/*
 * dfft.c
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

#include "dfft.h"

#include <complex.h>

#include "nFrstPkts.h"
#include "t2asm.h"


// Plugin variables

dfftFlow_t *dfftFlows;


// Variables from dependencies

extern nFrstPkts_t *nFrstPkts __attribute__((weak));


// Static variables

//float complex e[N2];
static uint8_t dfftStat;


// Static functions prototypes

static inline void dfft_pluginReport(FILE *stream);


// Tranalyzer functions

T2_PLUGIN_INIT_WITH_DEPS("dfft", "0.9.3", 0, 9, "nFrstPkts");


void t2Init() {
    T2_PLUGIN_STRUCT_NEW(dfftFlows);

#if DFFT_F == 1
    if (NB != (uint32_t)NB) {
        T2_PFATAL(plugin_name, "For FFT, only 2^N is allowed: change DFFT_N from %d to %d\n", DFFT_N, 1 << ((uint32_t)NB + 1));
    }
#endif // DFFT_F == 1

    /*
    const float w = PI2 / DFFT_N;

    uint_fast32_t i;
    float f;

    float complex e[N2];
    for (i = 0, f = 0.0; i < N2; i++, f += w) {
        e[i] = cos(f) - I * sin(f);
    }

#if DFFT_F == 1
    // bit inversion of index
    complex float s[DFFT_N];
    for (i = 0; i < N2; i++) {
        const uint_fast32_t u = i;
        BINV_32(u);
        s[i] = LGIBP32(u, DFFT_N);
    }
#endif // DFFT_F == 1
    */
}


binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;

    BV_APPEND_H8(bv, "dfftStat", "dfft status");
    BV_APPEND_R(bv, "dfftFR_FI", "DFT Real_Imag", 2, bt_float, bt_float);

    return bv;
}


void t2OnNewFlow(packet_t *packet UNUSED, unsigned long flowIndex) {
    dfftFlow_t * const dfftFlowP = &dfftFlows[flowIndex];
    memset(dfftFlowP, '\0', sizeof(*dfftFlowP));
}


void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {
    dfftFlow_t * const dfftFlowP = &dfftFlows[flowIndex];

    nFrstPkts_t *nFrstPktsP = &nFrstPkts[flowIndex];
    if (UNLIKELY(!nFrstPktsP)) {
        T2_PFATAL(plugin_name, "nFrstPkts dependency pointer is NULL");
    }

    float complex F[DFFT_N] = {};
    if (nFrstPktsP->pktCnt < DFFT_N) {
        T2_PDBG(plugin_name, "Flow with id: %lu, not enough packets..", flowIndex);
        dfftFlowP->stat |= DFFT_S_NF;
        goto pf;
    } else if (nFrstPktsP->pktCnt > DFFT_N) {
        dfftFlowP->stat |= DFFT_S_CLP;
    }

    const float w = PI2 / DFFT_N;

    uint_fast32_t i, j;
    float f;

    float complex e[N2];
    for (i = 0, f = 0.0; i < N2; i++, f += w) {
        e[i] = cos(f) - I * sin(f);
    }

    float complex c[DFFT_N];
    for (i = 0; i < DFFT_N; i++) {
        c[i] = nFrstPktsP->pkt[i].pktLen + I * 0.0;
    }

#if DFFT_F == 1
    // 1 point FFT
    uint_fast32_t z;
    for (i = 0; i < DFFT_N; i++) {
        z = i;
        BINV_32(z);
        z = LGIBP32(z, DFFT_N);
        if (z > i) {
            const float complex t = c[i];
            c[i] = c[z];
            c[z] = t;
        }
    }

    // N point FFT Butterfly
    uint_fast32_t n = 1;
    uint_fast32_t a = N2;
    for (i = 0; i < NB; i++) {
        for (j = 0; j < DFFT_N; j++) {
            if (!(j & n)) {
                const uint_fast32_t k = j + n;
                const float complex b0 = c[j];
                const float complex b1 = e[(j * a) & (N2 - 1)] * c[k];
                //const float complex b1 = e[(j * a) % (n * a)] * c[k];
                //printf("%d %d %d %d %d\n", j,n,j+n, (n * a), N2-1);
                c[j] = b0 + b1;
                c[k] = b0 - b1;
            }
        }
        n <<= 1;
        a >>= 1;
    }

    // Norm
    for (i = 0; i < DFFT_N; i++) {
        F[i] = c[i] / DFFT_N;
    }
#else // DFFT_F == 1
    for (i = 0; i < DFFT_N; i++) {
        F[i] = 0.0 + I * 0.0;
        for (j = 0; j < DFFT_N; j++) {
            F[i] += c[j] * e[(j * i) % DFFT_N];
        }
        F[i] /= DFFT_N;
    }
#endif // DFFT_F

    dfftFlowP->stat |= DFFT_S_S;

pf:
    dfftStat |= dfftFlowP->stat;

    OUTBUF_APPEND_U8(buf, dfftFlowP->stat);  // dfftStat

    // dfftFR_FI
    if (dfftFlowP->stat & DFFT_S_S) {
        OUTBUF_APPEND_NUMREP(buf, DFFT_N);
        for (i = 0; i < DFFT_N; i++) {
            f = creal(F[i]);
            OUTBUF_APPEND_FLT(buf, f);
            f = cimag(F[i]);
            OUTBUF_APPEND_FLT(buf, f);
        }
    } else {
        OUTBUF_APPEND_NUMREP_ZERO(buf);
    }
}


static inline void dfft_pluginReport(FILE *stream) {
    T2_FPLOG_AGGR_HEX(stream, plugin_name, dfftStat);
}


void t2Monitoring(FILE *stream, uint8_t state) {

    switch (state) {

        case T2_MON_PRI_HDR:
            fputs("dfftStat" SEP_CHR
                  , stream);
            return;

        case T2_MON_PRI_VAL:
            fprintf(stream,
                    "0x%02" B2T_PRIX8 /* dfftStat */ SEP_CHR
                    , dfftStat);
            break;

        case T2_MON_PRI_REPORT:
            dfft_pluginReport(stream);
            break;

        // Invalid state, do nothing
        default:
            return;
    }
}


void t2PluginReport(FILE *stream) {
    dfft_pluginReport(stream);
}


void t2Finalize() {
    free(dfftFlows);
}
