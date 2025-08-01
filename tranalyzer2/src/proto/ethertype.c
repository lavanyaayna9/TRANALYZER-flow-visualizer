/*
 * ethertype.c
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

#include "ethertype.h"

#include <arpa/inet.h>       // for ntohs
#include <stddef.h>          // for NULL
#include <sys/types.h>       // for u_char

#include "flow.h"            // for L2_ARP, L3_IPVX, L2_ERSPAN, L2_LLDP, L2_...
#include "hdrDesc.h"         // for T2_PKTDESC_ADD_HDR, T2_PKTDESC_ADD_ETHPROTO
#include "main.h"            // for T2_SET_STATUS, mplsHdrCntMx, numVxPackets
#include "networkHeaders.h"  // for pppoEH_t, BTM_MP...
#include "packetCapture.h"   // for dissembleIPv4Packet, dissembleIPv6Packet
#include "t2stats.h"         // for numVxPackets
#include "t2utils.h"         // for MAX
#include "tranalyzer.h"      // for IPVX_INTERPRET
#include "vlan.h"            // for _8021Q_t, t2_process_vlans


inline uint8_t *t2_process_ethertype(uint8_t *pktptr, packet_t *packet) {
    _8021Q_t *shape = (_8021Q_t*)pktptr;

    const uint16_t shape_id = shape->identifier;
    packet->ethType = ntohs(shape_id);

    switch (shape_id) {

        case ETHERTYPE_IPn:
            packet->l3HdrP = (pktptr + 2);
            if ((*(pktptr + 2) & 0xf0) != 0x40) { // non IPv4 packets
                numVxPackets++;
#if IPVX_INTERPRET == 0
                T2_PKTDESC_ADD_HDR(packet, ":ipvx");
                T2_SET_STATUS(packet, L3_IPVX);
                break;
#endif
            }
            dissembleIPv4Packet(packet);
            return NULL;

        case ETHERTYPE_IPV6n:
            packet->l3HdrP = (pktptr + 2);
            if ((*(pktptr + 2) & 0xf0) != 0x60) { // non IPv6 packets
                numVxPackets++;
#if IPVX_INTERPRET == 0
                T2_PKTDESC_ADD_HDR(packet, ":ipvx");
                T2_SET_STATUS(packet, L3_IPVX);
                break;
#endif
            }
            dissembleIPv6Packet(packet);
            return NULL;

        case ETHERTYPE_AARPn:
            T2_PKTDESC_ADD_HDR(packet, ":aarp");
            T2_SET_STATUS(packet, L2_ARP);
            break;

        case ETHERTYPE_ARPn:
            T2_PKTDESC_ADD_HDR(packet, ":arp");
            T2_SET_STATUS(packet, L2_ARP);
            break;

        case ETHERTYPE_RARPn:
            T2_PKTDESC_ADD_HDR(packet, ":rarp");
            T2_SET_STATUS(packet, L2_RARP);
            break;

        case ETHERTYPE_MPLS_MULTICASTn:
        case ETHERTYPE_MPLS_UNICASTn: {
            if (shape_id == ETHERTYPE_MPLS_MULTICASTn) {
                T2_SET_STATUS(packet, L2_MPLS_MCAST);
            } else {
                T2_SET_STATUS(packet, L2_MPLS_UCAST);
            }
            shape = (_8021Q_t*)&shape->vlanId;
            packet->mplsHdrP = (uint32_t*)shape;
            const uint8_t * const endPkt = packet->end_packet - 4;
            uint8_t count = 1;
            while (!(shape->vlanId & BTM_MPLS_STKn16) && (uint8_t*)shape <= endPkt) {
                shape++; // test MPLS end of stack bit
                count++;
            }

            shape++; // advance 4 bytes to IP Header

            packet->mplsHdrCnt += count;
            T2_PKTDESC_ADD_REPHDR(packet, ":mpls", count);
            mplsHdrCntMx = MAX(mplsHdrCntMx, packet->mplsHdrCnt);

            const uint_fast8_t ipver = (shape->identifier & 0xf0);
            switch (ipver) {
                case 0x40:
                    packet->l3HdrP = (uint8_t*)shape;
                    dissembleIPv4Packet(packet);
                    return NULL;
                case 0x60:
                    packet->l3HdrP = (uint8_t*)shape;
                    dissembleIPv6Packet(packet);
                    return NULL;
                default:
#if PW_ETH_CW == 1
                    if (ipver == 0) {  // TODO test whether MAC addresses look legit...
                        // There may be a Pseudowire (PW) Ethernet Control Word (RFC 4448)...
                        T2_PKTDESC_ADD_HDR(packet, ":pwethcw");
                        shape++; // Skip PW Ethernet Control Word
                    }
#endif
                    T2_PKTDESC_ADD_HDR(packet, ":eth");
                    packet->l2HdrP = (uint8_t*)shape;
                    shape += 3; // Skip Ethernet Addresses (12 bytes)
                    shape = t2_process_vlans(shape, packet);
                    return t2_process_ethertype((uint8_t*)shape, packet);
            }
            break;
        }

        case ETHERTYPE_ERSPANn:
            T2_SET_STATUS(packet, L2_ERSPAN);
            T2_PKTDESC_ADD_HDR(packet, ":erspan");
            T2_PKTDESC_ADD_HDR(packet, ":eth");
            // skip ERSPAN header (8 bytes) and ethertype (2 bytes)
            pktptr += 10;
            packet->l2HdrP = pktptr;
            // skip ethernet addresses
            pktptr += 12;
            return t2_process_ethertype(pktptr, packet);

        case ETHERTYPE_PPPoE_Dn: // discovery stage
            T2_PKTDESC_ADD_HDR(packet, ":pppoed");
            T2_SET_STATUS(packet, L2_PPPoE_D);
            packet->pppoeHdrP = (pppoEH_t*)&shape->vlanId;
            break;

        case ETHERTYPE_PPPoE_Sn: { // session stage
            T2_PKTDESC_ADD_HDR(packet, ":pppoes");
            T2_SET_STATUS(packet, L2_PPPoE_S);
            packet->pppoeHdrP = (pppoEH_t*)&shape->vlanId;
            packet->pppHdrP = (pppHu_t*)(packet->pppoeHdrP + 1);
            T2_PKTDESC_ADD_HDR(packet, ":ppp");
            const uint16_t pppProto = packet->pppoeHdrP->pppProt;
            switch (pppProto) {
                case PPP_IP4n:
                    packet->l3HdrP = (uint8_t*)packet->pppHdrP;
                    dissembleIPv4Packet(packet);
                    return NULL;
                case PPP_IP6n:
                    packet->l3HdrP = (uint8_t*)packet->pppHdrP;
                    dissembleIPv6Packet(packet);
                    return NULL;
                default:
                    T2_PKTDESC_ADD_PPPPROTO(packet, pppProto);
                    break;
            }
            break;
        }

        case ETHERTYPE_LLDPn:
            T2_PKTDESC_ADD_HDR(packet, ":lldp");
            T2_SET_STATUS(packet, L2_LLDP);
            break;

        //case ETHERTYPE_EAPOLn:
        //  T2_PKTDESC_ADD_HDR(packet, ":eapol");
        //  // TODO there may be some TLS further down...
        //  break;

#if T2_PRI_HDRDESC == 1
        case ETHERTYPE_SLOWn:
            T2_PKTDESC_ADD_HDR(packet, ":slow");
            switch (*(pktptr + 3)) {
                case  1: T2_PKTDESC_ADD_HDR(packet, ":lacp");   break; // Link Aggregation Control Protocol
                case  2: T2_PKTDESC_ADD_HDR(packet, ":marker"); break; // Link Aggregation - Marker Protocol
                case  3: T2_PKTDESC_ADD_HDR(packet, ":oampdu"); break; // Operations, Administration, and Maintenance
                case 10: T2_PKTDESC_ADD_HDR(packet, ":ossp");   break; // Organization Specific Slow Protocol
                default: break;
            }
            break;
#endif

        default:
            T2_PKTDESC_ADD_ETHPROTO(packet, shape_id);
            break;
    }

    return pktptr;
}
