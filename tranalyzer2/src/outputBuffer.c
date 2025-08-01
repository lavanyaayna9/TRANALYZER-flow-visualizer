/*
 * outputBuffer.c
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

#include "outputBuffer.h"

#include <stdlib.h>   // for free
#include <string.h>   // for memcpy

#include "t2log.h"    // for T2_ERR, T2_INF
#include "t2utils.h"  // for t2_[cm]alloc, LIKELY, UNLIKELY, T2_FATAL


const uint32_t ZERO = 0;
const uint32_t ONE  = 1;


#if OUTBUF_AUTOPILOT == 1
// Double the buffer size
#define OUTPUTBUFFER_DOUBLE_CAPACITY(buffer) do { \
    buffer->size <<= 1; \
    buffer->buffer -= BUFFER_DATAP; \
    T2_REALLOC(buffer->buffer, buffer->size); \
    buffer->buffer += BUFFER_DATAP; \
} while (0)
#endif // OUTBUF_AUTOPILOT == 1


outputBuffer_t *outputBuffer_initialize(size_t size) {
    outputBuffer_t* buffer = t2_malloc_fatal(sizeof(*buffer));
    buffer->buffer = t2_calloc_fatal(size + 1, sizeof(char));
    buffer->buffer += BUFFER_DATAP;
    buffer->size = size - BUFFER_DATAP;
    buffer->pos = 0;
    return buffer;
}


#if BLOCK_BUF == 1
inline void outputBuffer_append(outputBuffer_t *buffer UNUSED, const char *output UNUSED, size_t size UNUSED) {}
#else // BLOCK_BUF == 0
inline void outputBuffer_append(outputBuffer_t *buffer, const char *output, size_t size) {
#if DEBUG > 0
    if (UNLIKELY(size == 0)) {
        T2_FATAL("Invalid parameters passed to outputBuffer_append: size MUST be > 0");
    }
#endif // DEBUG > 0

    if (UNLIKELY(buffer->pos + size >= buffer->size)) {
#if OUTBUF_AUTOPILOT == 1
        if (2 * buffer->size < OUTBUF_MAXSIZE_F * MAIN_OUTBUF_SIZE) {
            T2_INF("output buffer full, doubling its capacity");
            OUTPUTBUFFER_DOUBLE_CAPACITY(buffer);
            return outputBuffer_append(buffer, output, size);
        }
#endif // OUTBUF_AUTOPILOT == 1

        // appending was NOT successful
        T2_FATAL("Buffer overflow in outputBuffer");
    }

    memcpy(&(buffer->buffer[buffer->pos]), output, size);
    buffer->pos += size;
    //buffer->buffer[buffer->pos] = '\0'; // terminate string
}
#endif // BLOCK_BUF == 0


inline void outputBuffer_append_numrep(outputBuffer_t *outbuf, uint32_t reps) {
    OUTBUF_APPEND_U32(outbuf, reps);
}


inline void outputBuffer_reset(outputBuffer_t *buffer) {
    buffer->buffer[BUFFER_DATAP] = '\0';
    buffer->pos = 0;
}


void outputBuffer_destroy(outputBuffer_t *buffer) {
    if (UNLIKELY(!buffer)) return;

    if (LIKELY(buffer->buffer != NULL)) {
        buffer->buffer -= BUFFER_DATAP;
        free(buffer->buffer);
    }

    free(buffer);
}
