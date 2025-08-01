/*
 * capwap.c
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

#include "capwap.h"
#include "tranalyzer.h"      // for CAPWAP

#if CAPWAP == 1

#include <arpa/inet.h>       // for ntohs
#include <stddef.h>          // for NULL
#include <sys/types.h>       // for u_char

#include "ethertype.h"       // for ETHERTYPE_EAPOLn, ETHERTYPE_IPV6n, ETHER...
#include "flow.h"            // for STPDSCT, L3_CAPWAP
#include "hdrDesc.h"         // for T2_PKTDESC_ADD_HDR, T2_PKTDESC_ADD_ETHPROTO
#include "ieee80211.h"       // for t2_process_ieee80211
#include "main.h"            // for T2_SET_STATUS
#include "networkHeaders.h"  // for IPV6_ACTIVATE
#include "packetCapture.h"   // for dissembleIPv4Packet, dissembleIPv6Packet
#include "vlan.h"            // for _8021Q_t, t2_process_vlans


inline bool t2_is_capwap(uint16_t sport, uint16_t dport) {
    return ((sport == CAPWAP_DATA_PORT || sport == CAPWAP_CTRL_PORT) && dport > 1024) ||
           ((dport == CAPWAP_DATA_PORT || dport == CAPWAP_CTRL_PORT) && sport > 1024);
}


// This function assumes pktptr points to the CAPWAP header, i.e.,
// the caller MUST check that the source or destination port is CAPWAP_DATA
// Returns a pointer to the beginning of the next header or
// Returns NULL if no more processing is required
inline uint8_t *t2_process_capwap(uint8_t *pktptr, packet_t *packet) {
    uint8_t * const start = pktptr;
    const uint8_t * const oldL2Hdr = packet->l2HdrP;
    const uint8_t * const oldL3Hdr = packet->l3HdrP;
    const uint32_t oldSnapL2Len = packet->snapL2Len;

    if (pktptr + sizeof(capwap_header_t) > packet->end_packet) {
        return start;
    }

    capwap_header_t *capwap = (capwap_header_t*)pktptr;
    if (capwap->type == 0) {
        pktptr += (capwap->hlen << 2);
        if (pktptr >= packet->end_packet) return start;
    }

    const uint16_t skip = (uint16_t)(pktptr - (uint8_t*)packet->l2HdrP);
    const uint16_t frag_off = ntohs(capwap->frag_off);

    if ( capwap->flags_res != 0 || (frag_off & 0x3) != 0 || // reserved MUST be 0
         capwap->version   != 0 ||                          // version MUST be 0
        (capwap->flags_t   == 1 && capwap->wbid     != 1))  // IEEE 802.3 / IEEE 802.11 only
    {
        return start;
    }

    bool control;
    if (packet->srcPort == CAPWAP_DATA_PORT ||
        packet->dstPort == CAPWAP_DATA_PORT)
    {
        control = false;
        T2_PKTDESC_ADD_HDR(packet, ":capwap.data");
    } else {
        control = true;
        T2_PKTDESC_ADD_HDR(packet, ":capwap");
    }

    T2_SET_STATUS(packet, L3_CAPWAP);

    if (capwap->type == 1) { // DTLS (encrypted)
        T2_PKTDESC_ADD_HDR(packet, ":dtls");
        T2_SET_STATUS(packet, (STPDSCT|L7_DTLS));
        return start;
    }

    if ( capwap->flags_k == 1 || control ||                        // Keep-Alive or Control
        (capwap->flags_f == 1 && ((frag_off & 0xfff8) >> 3) != 0)) // Fragments
    {
        T2_SET_STATUS(packet, STPDSCT);
        return start;
    }

    if (capwap->flags_t == 0) { // IEEE 802.3 (TODO not tested)
        T2_PKTDESC_ADD_HDR(packet, ":eth");
        packet->snapL2Len -= skip;
        packet->l2HdrP = pktptr;
        pktptr += 12; // jump to ethertype
    } else {
        // IEEE 802.11
        pktptr = t2_process_ieee80211(pktptr, CAPWAP_SWAP_FC, packet);
        if (!pktptr) goto capwap_reset;
    }

    // check for 802.1Q/ad signature (VLANs)
    _8021Q_t *shape = (_8021Q_t*)pktptr;
    if (oldSnapL2Len - skip >= sizeof(_8021Q_t)) {
        shape = t2_process_vlans(shape, packet);
    }

    if (pktptr == (uint8_t*)shape) {
        // No VLAN, skip ethertype
        pktptr += 2;
    } else {
        pktptr = (uint8_t*)shape;
        const uint16_t shapeid = ntohs(shape->identifier);
        if (shapeid <= LLC_LEN || shapeid == ETHERTYPE_JUMBO_LLC) {
            T2_PKTDESC_ADD_HDR(packet, ":llc");
            packet->etherLLC = (etherLLCHeader_t*)pktptr;
            pktptr = ((u_char*)packet->etherLLC + 8); // jump to ether type
            shape = (_8021Q_t*)pktptr;
        }
    }

    if (shape->identifier == ETHERTYPE_IPn) {
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
        packet->l3HdrP = pktptr;
        dissembleIPv4Packet(packet);
        return NULL;
#else // IPV6_ACTIVATE == 1
        T2_PKTDESC_ADD_HDR(packet, ":ipv4");
        T2_PKTDESC_ADD_PROTO(packet, ((ipHeader_t*)pktptr)->ip_p);
        T2_SET_STATUS(packet, (FS_IPV4_PKT | STPDSCT));
#endif // IPV6_ACTIVATE == 1
    } else if (shape->identifier == ETHERTYPE_IPV6n) {
#if IPV6_ACTIVATE > 0
        packet->l3HdrP = pktptr;
        dissembleIPv6Packet(packet);
        return NULL;
#else // IPV6_ACTIVATE == 0
        T2_PKTDESC_ADD_HDR(packet, ":ipv6");
        T2_PKTDESC_ADD_PROTO(packet, ((ip6Header_t*)pktptr)->next_header);
        T2_SET_STATUS(packet, (FS_IPV6_PKT | STPDSCT));
#endif // IPV6_ACTIVATE == 0
    } else if (shape->identifier == ETHERTYPE_EAPOLn) {
        T2_PKTDESC_ADD_HDR(packet, ":eapol");
        // TODO there may be some TLS further down
    } else {
        // Seen: ARP, EAPOL, LLDP, CDP, WLCCP, TDLS
        T2_PKTDESC_ADD_ETHPROTO(packet, shape->identifier);
        // TODO t2_dispatch_l2_packet(packet);
    }

capwap_reset:
    // CAPWAP could not be processed... revert changes
    // XXX status, globalWarn and hdrDesc are NOT reverted
    packet->snapL2Len = oldSnapL2Len;
    packet->l2HdrP = oldL2Hdr;
    packet->l3HdrP = oldL3Hdr;
    T2_SET_STATUS(packet, STPDSCT);

    return start;
}

#endif // CAPWAP == 1
