/*
 * l2tp.c
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

#include "l2tp.h"

#include <arpa/inet.h>       // for ntohs
#include <stddef.h>          // for NULL

#include "flow.h"            // for STPDSCT, L2_L2TP, L2_PPP
#include "hdrDesc.h"         // for T2_PKTDESC_ADD_HDR, T2_PKTDESC_ADD_PPPPROTO
#include "main.h"            // for T2_SET_STATUS
#include "networkHeaders.h"  // for PPP_IP4n, PPP_IP6n, PPP_MPn
#include "packetCapture.h"   // for dissembleIPv4Packet, dissembleIPv6Packet


inline bool t2_is_l2tp(uint16_t sport, uint16_t dport) {
    return (sport == L2TP_PORT || dport == L2TP_PORT);
}


// L2TP is transported over UDP
// L2TPv3 can be transported over IP
//
// This function assumes pktptr points to the L2TP header, i.e.,
// the caller MUST check that the source or destination ports is L2TP (1701)
//
// Return NULL if no more processing is required
inline uint8_t *t2_process_l2tp(uint8_t *pktptr, packet_t *packet) {

    const uint16_t flags = *(uint16_t*)pktptr;
    if (flags & L2TP_RES) {
        // Reserved bits are not zero (probably not L2TP)
        return pktptr;
    }

    const uint_fast8_t version = (*(pktptr + 1) & 0x0f);
    switch (version) {
        case 2:
            packet->l3Proto = L2TP_V2;
            break;
        case 3:
            packet->l3Proto = L2TP_V3;
            break;
        default:
            // Unknown version (probably not L2TP)
            return pktptr;
    }

    T2_PKTDESC_ADD_HDR(packet, ":l2tp");
    T2_SET_STATUS(packet, L2_L2TP);
    packet->l2tpHdrP = (uint16_t*)pktptr;
    packet->l2tpL3HdrP = packet->l3HdrP;

    if (flags & L2TP_TYPE) {
        // Control message, finished processing
        T2_SET_STATUS(packet, STPDSCT);
        return pktptr;
    }

    pktptr += sizeof(uint16_t); // skip flags

    if (version == 3) {
        // Skip control connection ID
        pktptr += sizeof(uint32_t);
    } else { // version == 2
        // Skip length
        if (flags & L2TP_LEN) {
            pktptr += sizeof(uint16_t);
        }

        // Skip tunnel ID and session ID
        pktptr += sizeof(uint32_t);

        // Skip sequence number
        if (flags & L2TP_SQN) {
            pktptr += sizeof(uint32_t);
        }

        // Skip offset
        if (flags & L2TP_OFF) {
            pktptr += ntohs(*(uint16_t*)pktptr) + sizeof(uint16_t);
        }
    }

    // Make sure we did not read past the end of the packet
    if (pktptr >= packet->end_packet) {
        T2_SET_STATUS(packet, STPDSCT);
        return pktptr;
    }

    // PPP-in-HDLC-like-framing
    if (*pktptr == 0x0f || *pktptr == 0x8f) {
        T2_PKTDESC_ADD_HDR(packet, ":chdlc");
    } else /*if (*(uint16_t*)pktptr == 0x03ff)*/ {
        T2_PKTDESC_ADD_HDR(packet, ":ppp");
    //} else {
    //    T2_PKTDESC_ADD_HDR(packet, ":ppp");
    }

    T2_SET_STATUS(packet, L2_PPP);
    packet->pppHdrP = (pppHu_t*)pktptr; // save PPP header
    pktptr += 2; // Skip PPP address and control

    if (*(uint16_t*)pktptr == PPP_MPn) { // PPP multilink protocol
        T2_PKTDESC_ADD_HDR(packet, ":mp");
        pktptr += 6; // skip protocol and multilink header
    }

    const uint16_t ppp_proto = *(uint16_t*)pktptr;

    // Skip PPP protocol
    pktptr += sizeof(uint16_t);
    if (pktptr >= packet->end_packet) {
        T2_SET_STATUS(packet, STPDSCT);
        return pktptr;
    }

    switch (ppp_proto) {
        case PPP_IP4n:
            packet->l3HdrP = pktptr;
            dissembleIPv4Packet(packet);
            return NULL;
        case PPP_IP6n:
            packet->l3HdrP = pktptr;
            dissembleIPv6Packet(packet);
            return NULL;
        //case PPP_MPLS_UCASTn:
        //case PPP_MPLS_MCASTn:
        //    t2_process_mpls(packet);
        //    break;
        default:
            T2_PKTDESC_ADD_PPPPROTO(packet, ppp_proto);
            T2_SET_STATUS(packet, STPDSCT);
            return pktptr;
    }

    return pktptr;
}
