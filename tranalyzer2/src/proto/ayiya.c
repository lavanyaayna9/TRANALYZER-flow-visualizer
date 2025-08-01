/*
 * ayiya.c
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

#include "ayiya.h"
#include "tranalyzer.h"      // for AYIYA, DEBUG

#if AYIYA == 1

#include <stddef.h>          // for NULL, size_t

#include "flow.h"            // for L3_AYIYA, STPDSCT
#include "hdrDesc.h"         // for T2_PKTDESC_ADD_HDR
#include "main.h"            // for T2_SET_STATUS
#include "networkHeaders.h"  // for IPV6_ACTIVATE, L3_IPIP4, L3_...
#include "packetCapture.h"   // for dissembleIPv4Packet, dissembleIPv6Packet
#include "t2log.h"           // for T2_ERR


inline bool t2_is_ayiya(uint16_t sport, uint16_t dport) {
    return (sport == AYIYA_PORT && dport > 1024) ||
           (dport == AYIYA_PORT && sport > 1024);
}


// AYIYA can be transported over IPv4, IPv6, TCP, UDP or SCTP
// This function assumes pktptr points to the ayiya header, i.e.,
// the caller MUST check that the source or destination ports is AYIYA (5072)
// Returns a pointer to the beginning of the next header or
// Returns NULL if no more processing is required
inline uint8_t *t2_process_ayiya(uint8_t *pktptr, packet_t *packet) {
    const ayiyaHeader_t * const ayiya = (ayiyaHeader_t*)pktptr;

    // skip ayiya header
    const size_t skip = sizeof(*ayiya) + (1 << ayiya->id_len) + (ayiya->sig_len << 2);
    if (pktptr + skip >= packet->end_packet) {
        return pktptr;
    }
    pktptr += skip;

    switch (ayiya->next_header) {
        case L3_IPIP6:
            if ((*pktptr & 0xf0) == 0x60) {
                T2_PKTDESC_ADD_HDR(packet, ":ayiya");
                T2_SET_STATUS(packet, L3_AYIYA);
#if IPV6_ACTIVATE > 0
                packet->l3HdrP = pktptr;
                dissembleIPv6Packet(packet);
                return NULL; // finished processing
#else // IPV6_ACTIVATE == 0
                T2_PKTDESC_ADD_HDR(packet, ":ipv6");
                T2_PKTDESC_ADD_PROTO(packet, ((ip6Header_t*)pktptr)->next_header);
                T2_SET_STATUS(packet, (FS_IPV6_PKT | STPDSCT));
#endif // IPV6_ACTIVATE == 0
            }
            break;

        case L3_IPIP4:
            if ((*pktptr & 0xf0) == 0x40) {
                T2_PKTDESC_ADD_HDR(packet, ":ayiya");
                T2_SET_STATUS(packet, L3_AYIYA);
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
                packet->l3HdrP = pktptr;
                dissembleIPv4Packet(packet);
                return NULL; // finished processing
#else // IPV6_ACTIVATE == 1
                T2_PKTDESC_ADD_HDR(packet, ":ipv4");
                T2_PKTDESC_ADD_PROTO(packet, ((ipHeader_t*)pktptr)->ip_p);
                T2_SET_STATUS(packet, (FS_IPV4_PKT | STPDSCT));
#endif // IPV6_ACTIVATE == 1
            }
            break;

        case L3_NXTH6:
            T2_PKTDESC_ADD_HDR(packet, ":ayiya");
            T2_SET_STATUS(packet, (L3_AYIYA | STPDSCT));
            break;

        default:
#if DEBUG > 0
            T2_ERR("Unhandled AYIYA next header: 0x%02x", ayiya->next_header);
#endif // DEBUG > 0
            //T2_PKTDESC_ADD_HDR(packet, ":ayiya");
            //T2_PKTDESC_ADD_PROTO(packet, ayiya->next_header);
            T2_SET_STATUS(packet, STPDSCT);
            break;
    }

    // AYIYA could not be processed.
    // Revert the packet pointer to the ayiya header
    return pktptr - skip;
}

#endif // AYIYA == 1
