/*
 * l2tp.h
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

#ifndef T2_L2TP_H_INCLUDED
#define T2_L2TP_H_INCLUDED

#include <stdbool.h>  // for bool
#include <stdint.h>   // for uint8_t, uint16_t, uint32_t

#include "packet.h"   // for packet_t


// L2TP - Layer 2 Tunneling Protocol

#define L2TP_PORT   1701
#define L2TP_PORT_N 0xa506 // 1701

#define L2TP_VERSION 0x0f00

#define L2TP_V2  0x0200
#define L2TP_V3  0x0300

#define L2TP_RES 0xf000 // Reserved, MUST be 0
#define L2TP_VER 0X0f00 // Version
#define L2TP_FLG 0X00ff // Flags

#define L2TP_PRI  0x0001 // Priority present
#define L2TP_OFF  0x0002 // Offset present
#define L2TP_SQN  0x0008 // Sequence present
#define L2TP_LEN  0x0040 // Length present
#define L2TP_TYPE 0x0080 // Message type: data (0) or control (1) message

#define L2TPv3_PROTO_ETH         0
#define L2TPv3_PROTO_CHDLC       1
#define L2TPv3_PROTO_FR          2
#define L2TPv3_PROTO_PPP         3
#define L2TPv3_PROTO_IP          4
#define L2TPv3_PROTO_MPLS        5
#define L2TPv3_PROTO_AAL5        6
#define L2TPv3_PROTO_LAPD        7
#define L2TPv3_PROTO_DOCSIS_DMPT 8
#define L2TPv3_PROTO_ERICSSON    9

typedef struct {
    uint16_t res3:4;  // reserved
    uint16_t ver:4;   // L2TP version
    uint16_t type:1;  // message type (0: Data, 1: Control)
    uint16_t len:1;   // message length present
    uint16_t res:2;   // reserved
    uint16_t seq:1;   // sequence numbers present
    uint16_t res2:1;  // reserved
    uint16_t off:1;   // offset number present
    uint16_t prio:1;  // priority (zero on Control messages)
    uint16_t length;  // length
    union {
        struct {
            uint16_t tID;  // tunnel ID, L2TPv2
            uint16_t sID;  // session ID, L2TPv2
        };
        uint32_t ccID;     // Control Connection ID, L2TPv3
    };
    uint16_t sN;      // sequence number
    uint16_t sNExp;   // sequence number expected
    union {
        // L2TPv2
        struct {
            uint16_t offSize; // offset size
            uint16_t offPad;  // offset pad
        };
        // L2TPv3
        uint8_t data[4];
    };
} __attribute__((packed)) l2tpHeader_t;

bool     t2_is_l2tp      (uint16_t sport, uint16_t dport)    __attribute__((__const__));
uint8_t *t2_process_l2tp (uint8_t *pktptr, packet_t *packet) __attribute__((__nonnull__(1, 2)));

#endif // T2_L2TP_H_INCLUDED
