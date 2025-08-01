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

#include "dwt.h"
#include "wavelet.h"


// global variables

wavelet_t *waveletP;


// Tranalyzer functions

T2_PLUGIN_INIT("wavelet", "0.9.3", 0, 9);


void t2Init() {
    T2_PLUGIN_STRUCT_NEW(waveletP);
}


binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;

    BV_APPEND_U16(bv, "waveNumPnts", "Wavelet number of points");

#if WAVELET_SIG == 1
    BV_APPEND_TYPE_R(bv, "waveSig", "Wavelet signal", BTWPREC);
#endif // WAVELET_SIG == 1

    BV_APPEND_U32(bv, "waveNumLvl", "Number of wavelet levels");

    binary_value_t *act_bv;

    act_bv = bv_new_bv(WAVELET_DETAIL, "Wavelet detail coefficients", 1, 1, 0);
    act_bv = bv_add_sv_to_bv(act_bv, 0, 1, 1, BTWPREC);
    bv = bv_append_bv(bv, act_bv);

    act_bv = bv_new_bv(WAVELET_APPROX, "Wavelet approximation coefficients", 1, 1, 0);
    act_bv = bv_add_sv_to_bv(act_bv, 0, 1, 1, BTWPREC);
    bv = bv_append_bv(bv, act_bv);

    return bv;
}


void t2OnNewFlow(packet_t *packet UNUSED, unsigned long flowIndex) {
    wavelet_t * const waveP = &waveletP[flowIndex];
    memset(waveP, '\0', sizeof(*waveP));

    //waveP->numSig = WAVELET_TYPE * 2;
#if WAVELET_IAT > 0
    waveP->lstPktTm = packet->pcapHdrP->ts;
#endif // WAVELET_IAT > 0
}


#if ETH_ACTIVATE > 0
void t2OnLayer2(packet_t *packet, unsigned long flowIndex) {
    if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND || (packet->status & L2_FLOW) == 0) return;

    wavelet_t * const waveP = &waveletP[flowIndex];

    if (waveP->numSig < WAVELET_MAX_PKT) {
#if WAVELET_IAT == 0
        waveP->sig[waveP->numSig++] = packet->len;
#else // WAVELET_IAT > 0
        struct timeval iat;
        T2_TIMERSUB(&packet->pcapHdrP->ts, &waveP->lstPktTm, &iat);
        waveP->sig[waveP->numSig++] = (WPREC)iat.tv_sec + (WPREC)iat.tv_usec / TSTAMPFAC;
        waveP->lstPktTm = packet->pcapHdrP->ts;
#endif // WAVELET_IAT
    }
}
#endif // ETH_ACTIVATE > 0


void t2OnLayer4(packet_t *packet, unsigned long flowIndex) {
    wavelet_t * const waveP = &waveletP[flowIndex];

    if (waveP->numSig < WAVELET_MAX_PKT) {
#if WAVELET_IAT == 0
        waveP->sig[waveP->numSig++] = packet->len;
#else // WAVELET_IAT > 0
        struct timeval iat;
        T2_TIMERSUB(&packet->pcapHdrP->ts, &waveP->lstPktTm, &iat);
        waveP->sig[waveP->numSig++] = (WPREC)iat.tv_sec + (WPREC)iat.tv_usec / TSTAMPFAC;
        waveP->lstPktTm = packet->pcapHdrP->ts;
#endif // WAVELET_IAT
    }
}


void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {
    wavelet_t * const waveP = &waveletP[flowIndex];

    uint_fast32_t i;
    const uint32_t numSig = waveP->numSig;

    // waveNumPnts
    OUTBUF_APPEND_U16(buf, waveP->numSig);

#if WAVELET_SIG == 1
    // waveSig
    OUTBUF_APPEND_NUMREP(buf, numSig);
    for (i = 0; i < numSig; i++) {
        OUTBUF_APPEND(buf, waveP->sig[i], sizeof(WPREC));
    }
#endif // WAVELET_SIG == 1

    if (numSig < WAVELET_THRES) {
        OUTBUF_APPEND_U32_ZERO(buf);     // waveNumLvl
        OUTBUF_APPEND_NUMREP_ZERO(buf);  // waveCoefDetail
        OUTBUF_APPEND_NUMREP_ZERO(buf);  // waveCoefApprox
    } else {
        // discrete wavelet transform
        dwt1D(waveP, WAVELET_TYPE, WAVELET_LEVEL, WAVELET_EXTMODE);

        // waveNumLvl
        const uint32_t level = WAVELET_LEVEL;
        OUTBUF_APPEND_U32(buf, level);

        const WPREC *detail = waveP->wtDetail;

        // waveCoefDetail
        OUTBUF_APPEND_NUMREP(buf, level);
        for (i = 0; i < level; i++) {
            const uint32_t cnt = waveP->wtlvl_len[i];
            OUTBUF_APPEND_U32(buf, cnt);
            OUTBUF_APPEND(buf, detail[0], cnt * sizeof(WPREC));
            detail += cnt;
        }

        // waveCoefApprox
        const WPREC *approx = waveP->wtApprox;
        OUTBUF_APPEND_NUMREP(buf, level);
        for (i = 0; i < level; i++) {
            const uint32_t cnt = waveP->wtlvl_len[i];
            OUTBUF_APPEND_U32(buf, cnt);
            OUTBUF_APPEND(buf, approx[0], cnt * sizeof(WPREC));
            approx += cnt;
        }
    }
}


void t2Finalize() {
    free(waveletP);
}
