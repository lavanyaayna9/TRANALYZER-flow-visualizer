#ifndef _DWT_H
#define _DWT_H

#include <stdint.h>         // for uint16_t

#include "define_global.h"  // for wavelet_t

void dwt1D(wavelet_t *waveP, uint16_t wave_type, uint16_t wave_level, uint16_t wave_ext);

#endif // _DWT_H
