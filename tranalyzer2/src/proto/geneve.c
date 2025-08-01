/*
 * geneve.c
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

#include "geneve.h"
#include "tranalyzer.h"      // for DEBUG, GENEVE

#if GENEVE == 1

#include <stddef.h>          // for NULL

#include "ethertype.h"       // for ETHERTYPE_IPV6n, ETHERTYPE_IPn, ETHERTYP...
#include "flow.h"            // for L2_PPPoE_D, L2_PPPoE_S, L3_GENEVE, STPDSCT
#include "hdrDesc.h"         // for T2_PKTDESC_ADD_HDR, T2_PKTDESC_ADD_ETHPROTO
#include "main.h"            // for T2_SET_STATUS
#include "networkHeaders.h"  // for IPV6_ACTIVATE, pppoEH_t, ...
#include "packetCapture.h"   // for dissembleIPv4Packet, dissembleIPv6Packet
#include "t2log.h"           // for T2_ERR
#include "vlan.h"            // for _8021Q_t, t2_process_vlans


inline bool t2_is_geneve(uint16_t sport, uint16_t dport) {
    return (sport == GENEVE_PORT && dport > 1024) ||
           (dport == GENEVE_PORT && sport > 1024);
}


// This function assumes pktptr points to the GENEVE header, i.e.,
// the caller MUST check that the source or destination port is GENEVE
// Returns a pointer to the beginning of the next header or
// Returns NULL if no more processing is required
inline uint8_t *t2_process_geneve(uint8_t *pktptr, packet_t *packet) {
    uint8_t * const start = pktptr;
    const uint8_t * const oldL2Hdr = packet->l2HdrP;
    const uint8_t * const oldL3Hdr = packet->l3HdrP;
    const uint32_t oldSnapL2Len = packet->snapL2Len;

    geneve_header_t *geneve = (geneve_header_t*)pktptr;
    pktptr += sizeof(geneve_header_t) + (geneve->optlen << 2);
    if (pktptr >= packet->end_packet) return start;

    const uint16_t skip = (uint16_t)(pktptr - (uint8_t*)packet->l2HdrP);

    if (geneve->reserved1 != 0 || geneve->reserved2 != 0) {
        // reserved MUST be 0
        return start;
    }

    switch (geneve->proto) {
        case ETHERTYPE_TEBn:
            T2_SET_STATUS(packet, L3_GENEVE);
            T2_PKTDESC_ADD_HDR(packet, ":geneve");
            break;
        default:
#if DEBUG > 0
            T2_ERR("Unhandled GENEVE protocol 0x%02x", geneve->proto);
#endif // DEBUG > 0
            //T2_SET_STATUS(packet, L3_GENEVE);
            //T2_PKTDESC_ADD_HDR(packet, ":geneve");
            //T2_PKTDESC_ADD_ETHPROTO(packet, geneve->proto);
            goto geneve_reset;
    }

    T2_PKTDESC_ADD_HDR(packet, ":eth");

    packet->snapL2Len -= skip;
    packet->l2HdrP = pktptr;

    pktptr += 12; // jump to ethertype

    // check for 802.1Q/ad signature (VLANs)
    _8021Q_t *shape = (_8021Q_t*)pktptr;
    if (packet->snapL2Len >= sizeof(_8021Q_t)) {
        shape = t2_process_vlans(shape, packet);
    }
    if (pktptr != (uint8_t*)shape) pktptr = (uint8_t*)shape;
    else pktptr += 2; // skip ethertype

    switch (shape->identifier) {
        case ETHERTYPE_IPn:
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
            packet->l3HdrP = pktptr;
            dissembleIPv4Packet(packet);
            return NULL;
#else // IPV6_ACTIVATE == 1
            T2_PKTDESC_ADD_HDR(packet, ":ipv4");
            T2_PKTDESC_ADD_PROTO(packet, ((ipHeader_t*)pktptr)->ip_p);
            T2_SET_STATUS(packet, (FS_IPV4_PKT | STPDSCT));
            break;
#endif // IPV6_ACTIVATE == 1
        case ETHERTYPE_IPV6n:
#if IPV6_ACTIVATE > 0
            packet->l3HdrP = pktptr;
            dissembleIPv6Packet(packet);
            return NULL;
#else // IPV6_ACTIVATE == 0
            T2_PKTDESC_ADD_HDR(packet, ":ipv6");
            T2_PKTDESC_ADD_PROTO(packet, ((ip6Header_t*)pktptr)->next_header);
            T2_SET_STATUS(packet, (FS_IPV6_PKT | STPDSCT));
            break;
#endif // IPV6_ACTIVATE == 0
        case ETHERTYPE_PPPoE_Dn:
            T2_PKTDESC_ADD_HDR(packet, ":pppoed");
            T2_SET_STATUS(packet, L2_PPPoE_D);
            packet->pppoeHdrP = (pppoEH_t*)&shape->vlanId;
            break;
        case ETHERTYPE_PPPoE_Sn:
            T2_PKTDESC_ADD_HDR(packet, ":pppoes");
            T2_SET_STATUS(packet, L2_PPPoE_S);
            packet->pppoeHdrP = (pppoEH_t*)&shape->vlanId;
            packet->pppHdrP = (pppHu_t*)(packet->pppoeHdrP + 1);
            T2_PKTDESC_ADD_HDR(packet, ":ppp");
            if (packet->pppoeHdrP->pppProt == PPP_IP4n) {
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
                packet->l3HdrP = (uint8_t*)packet->pppHdrP;
                dissembleIPv4Packet(packet);
                return NULL;
#else // IPV6_ACTIVATE == 1
                T2_PKTDESC_ADD_HDR(packet, ":ipv4");
                T2_PKTDESC_ADD_PROTO(packet, ((ipHeader_t*)packet->pppHdrP)->ip_p);
                T2_SET_STATUS(packet, (FS_IPV4_PKT | STPDSCT));
#endif // IPV6_ACTIVATE == 1
            } else if (packet->pppoeHdrP->pppProt == PPP_IP6n) {
#if IPV6_ACTIVATE > 0
                packet->l3HdrP = (uint8_t*)packet->pppHdrP;
                dissembleIPv6Packet(packet);
                return NULL;
#else // IPV6_ACTIVATE == 0
                T2_PKTDESC_ADD_HDR(packet, ":ipv6");
                T2_PKTDESC_ADD_PROTO(packet, ((ip6Header_t*)packet->pppHdrP)->next_header);
                T2_SET_STATUS(packet, (FS_IPV6_PKT | STPDSCT));
#endif // IPV6_ACTIVATE == 0
            } else {
                T2_PKTDESC_ADD_PPPPROTO(packet, packet->pppoeHdrP->pppProt);
            }
            break;
        default:
            T2_PKTDESC_ADD_ETHPROTO(packet, shape->identifier);
            break;
    }

geneve_reset:
    // GENEVE could not be processed... revert changes
    // XXX status, globalWarn and hdrDesc are NOT reverted
    packet->snapL2Len = oldSnapL2Len;
    packet->l2HdrP = oldL2Hdr;
    packet->l3HdrP = oldL3Hdr;
    T2_SET_STATUS(packet, STPDSCT);

    return start;
}

#endif // GENEVE == 1
