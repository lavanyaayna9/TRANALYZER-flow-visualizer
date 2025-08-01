/*
 * lapd.h
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

#ifndef T2_LAPD_H_INCLUDED
#define T2_LAPD_H_INCLUDED

#include <stdint.h>  // for uint8_t, uint16_t


// -----------------------------------------------------------------------------
// Link Access Procedure, Channel D (LAPD)
// -----------------------------------------------------------------------------

// Address Flags / Masks

#define LAPD_AF_SAPI 0xfc // Service Access Point Identifier (SAPI)
#define LAPD_AF_CR   0x02 // Command/Response bit
#define LAPD_AF_EA1  0x01 // First Address Extension bit
#define LAPD_AF_TEI  0xfe // Terminal Endpoint Identifier (TEI)
#define LAPD_AF_EA2  0x01 // Second Address Extension bit

#define LAPD_AF_CR_16 (LAPD_AF_CR << 8)

// Control Flags / Masks

#define LAPD_CF_CMD  0xfc
#define LAPD_CF_FT   0x03
#define LAPDETHTYP   0xf000
#define LAPDETHCFFT  (LAPDETHTYP | LAPD_CF_CMD)

#define LAPD_I_FN    0xfe00 // Information Frame Numbers
#define LAPD_I_ACK   0x00fe // Information Acknowledgments
#define LAPD_RR      0x0100 // Receive Ready
#define LAPD_RNR     0x0500 // Receive Not Ready
#define LAPD_REJ     0x0900 // Reject
#define LAPD_SABME   0x6f   // Set Asynchronous Balance Mode Extended
#define LAPD_DM      0x0f   // Disconnect Mode
#define LAPD_UI      0x03   // Unnumbered Information
#define LAPD_DISC    0x43   // Disconnect
#define LAPD_UA      0x63   // Unnumbered ACK
#define LAPD_FRMR    0x87   // Frame Reject
#define LAPD_XID     0xaf   // Exchange ID

// GSM Service Access Point Identifier (SAPI)
#define LAPD_SAPI_RSL  0 // Radio signaling (radio signaling link or RSL)
#define LAPD_SAPI_OML 62 // O&M messages (O&M link or OML)
#define LAPD_SAPI_L2M 63 // Layer 2 management


typedef struct {
    union {
       uint8_t sapi;
       struct {
          uint8_t ea1:1;    // bit  0   : Extension Address Field (= 0)
          uint8_t cr:1;     // bit  1   : Command/response (C/R)
          uint8_t mdsapi:6; // bits 2-7 : Service Access Point Identifier (SAPI)
       };
    };
    union {
       uint8_t tei;
       struct {
          uint8_t ea2:1;   // bit  0   : Extension Address Field
          uint8_t atei:7;  // bits 1-7 : Terminal Endpoint Identifier (TEI)
       };
    };
    union {
       struct {
          uint8_t cf1;
          uint8_t cf2;
       };
       uint16_t cf;    // Control Field
    };
    uint8_t data;
} __attribute__ ((__packed__)) lapdHdr_t;

#endif // T2_LAPD_H_INCLUDED
