/*
 * teredo.c
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

#include "teredo.h"

#include <stddef.h>          // for NULL

#include "flow.h"            // for L3_TRDO
#include "hdrDesc.h"         // for T2_PKTDESC_ADD_HDR
#include "main.h"            // for T2_SET_STATUS
#include "networkHeaders.h"  // for ip6Header_t, ipAddr_t, IPV6_ACTIVATE
#include "packetCapture.h"   // for dissembleIPv6Packet


inline bool t2_is_teredo(uint16_t sport, uint16_t dport) {
    return (sport > 1024 && dport > 1024);
}


inline uint8_t *t2_process_teredo(uint8_t *pktptr, packet_t *packet) {

    uint16_t marker = *(uint16_t*)pktptr;
    if (*pktptr != 0x60 && marker != 0x0100 && marker != 0x000) return pktptr;

    // Teredo Authentication Header
    uint8_t *trdoAHdrP = NULL;
    if (marker == 0x0100) {
        trdoAHdrP = pktptr;
        const uint_fast8_t client_id_len  = *(pktptr + 2);
        const uint_fast8_t auth_value_len = *(pktptr + 3);
        pktptr += sizeof(teredo_authentication_header_t) + client_id_len + auth_value_len;
        marker = *(uint16_t*)pktptr;
    }

    // Teredo Origin Indication Header
    uint8_t *trdoOIHdrP = NULL;
    if (marker == 0x0000) {
        trdoOIHdrP = pktptr;
        pktptr += sizeof(teredo_origin_indication_header_t);
    }

    // IPv6 header?
    if ((*pktptr & 0xf0) != 0x60) return pktptr;

    const ip6Header_t * const ipv6_header = (ip6Header_t*)pktptr;
    const uint32_t srcIP0 = ipv6_header->ip_src.IPv4x[0];
    const uint32_t dstIP0 = ipv6_header->ip_dst.IPv4x[0];
    if (packet->srcPort != TEREDO_PORT && srcIP0 != TEREDO_IPV6_PREFIX_N &&
        packet->dstPort != TEREDO_PORT && dstIP0 != TEREDO_IPV6_PREFIX_N)
    {
        return pktptr;
    }

    T2_PKTDESC_ADD_HDR(packet, ":teredo");
    T2_SET_STATUS(packet, L3_TRDO);

    if (trdoAHdrP) packet->trdoAHdrP = trdoAHdrP;
    if (trdoOIHdrP) packet->trdoOIHdrP = trdoOIHdrP;

#if IPV6_ACTIVATE > 0
    packet->l3HdrP = pktptr;
    dissembleIPv6Packet(packet);
    return NULL;
#else // IPV6_ACTIVATE == 0
    T2_PKTDESC_ADD_HDR(packet, ":ipv6");
    T2_PKTDESC_ADD_PROTO(packet, ipv6_header->next_header);
    T2_SET_STATUS(packet, (FS_IPV6_PKT | STPDSCT));
    return pktptr;
#endif // IPV6_ACTIVATE == 0
}
