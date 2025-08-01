/*
 * ioBuffer.h
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

 /*
 * Inspired by http://msmvps.com/blogs/vandooren/archive/2007/01/05/creating-a-thread-safe-producer-consumer-queue-in-c-without-using-locks.aspx
 */

#ifndef T2_IOBUFFER_H_INCLUDED
#define T2_IOBUFFER_H_INCLUDED

/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

// Input Buffering
// useful in live sniffing if there is a (short) packet burst

#define IO_BUFFERING 0 // enable buffering of the packets in a queue

#if IO_BUFFERING != 0

#define IO_BUFFER_FULL_WAIT_MS  200 // number of ms to wait if queue is full
#define IO_BUFFER_SIZE         8192 // max number of packets to store in the buffer (power of two is faster)
#define IO_BUFFER_MAX_MTU      2048 // max size of a packet (divisible by 4)

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// Includes

#include <inttypes.h>  // for uint8_t


// functions

void ioBufferInitialize();
void mainLoop();


// variables

extern volatile uint8_t gBufStat;

#endif // IO_BUFFERING != 0

#endif // T2_IOBUFFER_H_INCLUDED
