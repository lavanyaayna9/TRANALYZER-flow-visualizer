/*
 * linktype.c
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

#include "linktype.h"

#include <inttypes.h>       // for PRIu32, PRIu8
#include <arpa/inet.h>      // for ntohl, ntohs
#include <pcap/pcap.h>      // for pcap_datalink, DLT_EN10MB, pcap_datalink_val_to_desc...
#include <stdbool.h>        // for false
#include <stdlib.h>         // for exit, EXIT_FAILURE
#include <string.h>         // for NULL, memcmp
#include <sys/socket.h>     // for PF_INET

#include "bin2txt.h"        // for B2T_PRIX16
#include "ethertype.h"      // for ETHERTYPE_IPV6n, ETHERTYPE_IPn, ETHERTYP...
#include "flow.h"           // for L2SNAPLENGTH, L2_NO_ETH, L2_PPP
#include "hdrDesc.h"        // for T2_PKTDESC_ADD_HDR, T2_PKTDESC_ADD_PPPPROTO
#include "ieee80211.h"      // for t2_process_ieee80211
#include "main.h"           // for T2_SET_STATUS, globalWarn, captureDescriptor
#include "packetCapture.h"  // for dissembleIPv4Packet, dissembleIPv6Packet
#include "networkHeaders.h" // for pppHdr_t, ethern...
#include "t2log.h"          // for T2_WRN, T2_ERR
#include "t2utils.h"        // for UNLIKELY
#include "vlan.h"           // for _8021Q_t


#define T2_CHECK_SNAP_L2(packet, l2size, action_if_fail) \
    if (UNLIKELY((packet)->snapL2Len < (uint32_t)(l2size))) { \
        (packet)->status |= L2SNAPLENGTH; \
        if (!(globalWarn & L2SNAPLENGTH)) { \
            globalWarn |= L2SNAPLENGTH; \
        } \
        action_if_fail; \
    }


inline uint8_t *t2_process_linktype(uint8_t *pktptr, packet_t *packet) {
#if DPDK_MP == 0
    int linkType = pcap_datalink(captureDescriptor);

    // Per-Packet Information (PPI)
    if (linkType == DLT_PPI) {
        T2_PKTDESC_ADD_HDR(packet, "ppi:");
        const ppi_hdr_t * const ppi = (ppi_hdr_t*)pktptr;
        T2_CHECK_SNAP_L2(packet, ppi->len + 1, return NULL);
        pktptr += ppi->len; // skip PPI header
        packet->snapL2Len -= ppi->len;
        linkType = ppi->dlt;
    }

    switch (linkType) {
        // IEEE 802.3 Ethernet
        case DLT_EN10MB: {
#endif // DPDK_MP == 0
            // In DPDK mode: only support Ethernet
            T2_CHECK_SNAP_L2(packet, sizeof(ethernetHeader_t), return NULL);
            packet->l2HdrP = pktptr;
            const uint8_t * const dMac = ETH_HEADER(packet)->ethDS.ether_dhost;
            static const uint8_t isl1[5] = { 0x01, 0x00, 0x0c, 0x00, 0x00 };
            static const uint8_t isl2[5] = { 0x03, 0x00, 0x0c, 0x00, 0x00 };
            if (memcmp(dMac, isl1, 5) == 0 || memcmp(dMac, isl2, 5) == 0) {
                T2_PKTDESC_ADD_HDR(packet, "isl:");
                // Jump over the ISL header
                T2_CHECK_SNAP_L2(packet, sizeof(ethernetHeader_t)+ISL_HEADER_LEN, return NULL);
                pktptr += ISL_HEADER_LEN;
                packet->l2HdrP = pktptr;
            }
            T2_PKTDESC_ADD_HDR(packet, "eth");
            return (pktptr + 12); // advance 12 bytes to ether type
#if DPDK_MP == 0
        }

        case DLT_ETHERNET_MPACKET:
            pktptr += 8; // Preamble (7 octets), Start mPacket Delimiter (SMD) (1 octet) or
                         // Preamble (6 octets), Start mPacket Delimiter (SMD) (1 octet) and frag count (1 octet)
            // TODO there is a 4 octets trailing CRC
            T2_PKTDESC_ADD_HDR(packet, "fpp:");
            T2_CHECK_SNAP_L2(packet, sizeof(ethernetHeader_t), return NULL);
            packet->l2HdrP = pktptr;
            T2_PKTDESC_ADD_HDR(packet, "eth");
            return (pktptr + 12); // advance 12 bytes to ether type

        // BSD Loopback encapsulation
        case DLT_NULL: {
            T2_PKTDESC_ADD_HDR(packet, "null");
            T2_CHECK_SNAP_L2(packet, 4, return NULL); // Family (Null/Loopback header)
            packet->l2HdrP = pktptr;
            packet->l3HdrP = (pktptr + 4);
            // Family encoding depends on the machine on which the traffic was captured...
            uint32_t family = *(uint32_t*)pktptr;
            if (family > 30) family = ntohl(family);
            T2_SET_STATUS(packet, L2_NO_ETH);
            switch (family) {
                case PF_INET: // 2
                    dissembleIPv4Packet(packet);
                    break;
                case 10: // Linux
                case 23: // WinSock
                case 24: // BSD
                case 26: // Solaris
                case 28: // FreeBSD
                case 30: // Darwin
                    dissembleIPv6Packet(packet);
                    break;
                default:
                    T2_WRN("Null/Loopback header: unhandled family %" PRIu32, family);
                    break;
            }
            return NULL;
        }

        // Raw IP
        case DLT_RAW:
            T2_PKTDESC_ADD_HDR(packet, "raw");
            packet->l2HdrP = pktptr;
            packet->l3HdrP = pktptr;
            T2_SET_STATUS(packet, L2_NO_ETH);
            if ((*pktptr & 0xf0) == 0x40) {
                dissembleIPv4Packet(packet);
            } else if ((*pktptr & 0xf0) == 0x60) {
                dissembleIPv6Packet(packet);
            } else {
                T2_WRN("Unknown IP protocol %" PRIu8 " in raw pcap", (uint8_t)((*pktptr & 0xf0) >> 4));
            }
            return NULL;

        // Raw IPv4
        case DLT_IPV4:
            packet->l2HdrP = pktptr;
            packet->l3HdrP = pktptr;
            T2_SET_STATUS(packet, L2_NO_ETH);
            dissembleIPv4Packet(packet);
            return NULL;

        // Raw IPv6
        case DLT_IPV6:
            packet->l2HdrP = pktptr;
            packet->l3HdrP = pktptr;
            T2_SET_STATUS(packet, L2_NO_ETH);
            dissembleIPv6Packet(packet);
            return NULL;

        // Linux cooked capture
        case DLT_LINUX_SLL:
            T2_PKTDESC_ADD_HDR(packet, "sll");
            T2_CHECK_SNAP_L2(packet, sizeof(linux_cooked_t), return NULL);
            packet->l2HdrP = pktptr;
            return (pktptr + 14); // advance to ether type

        // Point-to-Point Protocol
        case DLT_PPP_WITH_DIR: // PPP with direction
            pktptr++;
            /* FALLTHRU */
        case DLT_PPP_SERIAL:
        case DLT_PPP: {
            T2_PKTDESC_ADD_HDR(packet, "ppp");
            T2_SET_STATUS(packet, L2_NO_ETH|L2_PPP);
            packet->pppHdrP = (pppHu_t*)pktptr;
            if (linkType != DLT_PPP_WITH_DIR) {
                packet->l2HdrP = pktptr;
            } else {
                packet->l2HdrP = (pktptr - 1);
            }
            // FIXME PPP header may be one byte only...?!?
            pppHdr_t *ppp = (pppHdr_t*)pktptr;
            if (ppp->addctl == 0x000f || ppp->addctl == 0x008f) { // Cisco HDLC
                T2_PKTDESC_ADD_HDR(packet, ":chdlc");
                return (pktptr + 2);
            } else {
                uint16_t pppProto;
                if (ppp->addctl == PPP_ADD_CTLn) {
                    pppProto = ppp->prot;
                    pktptr += 4;
                } else {
                    pppProto = ppp->addctl;
                    pktptr += 2;
                }
                switch (pppProto) {
                    case PPP_IP4n:
                        packet->l3HdrP = pktptr;
                        dissembleIPv4Packet(packet);
                        return NULL;
                    case PPP_IP6n:
                        packet->l3HdrP = pktptr;
                        dissembleIPv6Packet(packet);
                        return NULL;
                    case PPP_MPLS_UCASTn: {
                        _8021Q_t *shape = (_8021Q_t*)pktptr;
                        shape->identifier = ETHERTYPE_MPLS_UNICASTn;
                        return (uint8_t*)shape;
                    }
                    case PPP_MPLS_MCASTn: {
                        _8021Q_t *shape = (_8021Q_t*)pktptr;
                        shape->identifier = ETHERTYPE_MPLS_MULTICASTn;
                        return (uint8_t*)shape;
                    }
                    default:
                        // TODO
                        T2_PKTDESC_ADD_PPPPROTO(packet, pppProto);
                        return NULL;
                }
            }
            break;
        }

        // Cisco PPP with HDLC framing / Frame Relay
        case DLT_C_HDLC_WITH_DIR: // CISCO HDLC with direction
        case DLT_FRELAY_WITH_DIR: // Frame Relay with direction
            pktptr += 1; // direction
            /* FALLTHRU */
        case DLT_FRELAY: // Frame Relay
        case DLT_C_HDLC: // CISCO HDLC
            if (linkType == DLT_FRELAY_WITH_DIR || linkType == DLT_FRELAY) {
                T2_PKTDESC_ADD_HDR(packet, "fr");
            } else if (linkType == DLT_C_HDLC_WITH_DIR || linkType == DLT_C_HDLC) {
                T2_PKTDESC_ADD_HDR(packet, "chdlc");
            }
            if (linkType == DLT_C_HDLC_WITH_DIR || linkType == DLT_FRELAY_WITH_DIR) {
                packet->l2HdrP = (pktptr - 1);
            } else {
                packet->l2HdrP = pktptr;
            }
            T2_SET_STATUS(packet, L2_NO_ETH);
            return (pktptr + 2);

#if LINKTYPE_JUNIPER == 1
        // Juniper (Experimental)
        case DLT_JUNIPER_ATM1:
        case DLT_JUNIPER_ETHER:
        case DLT_JUNIPER_PPPOE: {
            // TODO
            //T2_CHECK_SNAP_L2(packet, sizeof(???), return NULL);
            T2_PKTDESC_ADD_HDR(packet, "juniper");
            const juniper_eth_hdr_t * const juniper = (juniper_eth_hdr_t*)pktptr;
            if (juniper->magic != JUNIPER_PCAP_MAGIC_N) {
                T2_WRN("Juniper magic cookie not found");
                return NULL;
            }
            if ((juniper->flags & JUNIPER_FLAG_EXT) == JUNIPER_FLAG_EXT) {
                pktptr += 6 + ntohs(juniper->ext_len); // magic, flags and extlen
            } else {
                pktptr += 4; // magic and flags
            }
            if ((juniper->flags & JUNIPER_FLAG_NOL2) == JUNIPER_FLAG_NOL2) {
                const uint32_t proto = *(uint32_t*)pktptr;
                pktptr += 4;
                switch (proto) {
                    case 2: // IP
                        T2_SET_STATUS(packet, L2_NO_ETH);
                        packet->l2HdrP = (uint8_t*)juniper;
                        packet->l3HdrP = pktptr;
                        dissembleIPv4Packet(packet);
                        return NULL;
                    //case 3: // MPLS_IP
                    //case 4: // IP_MPLS
                    //case 5: // MPLS
                    case 6: // IP6
                        T2_SET_STATUS(packet, L2_NO_ETH);
                        packet->l2HdrP = (uint8_t*)juniper;
                        packet->l3HdrP = pktptr;
                        dissembleIPv6Packet(packet);
                        return NULL;
                    //case 7:   // MPLS_IP6
                    //case 8:   // IP6_MPLS
                    //case 10:  // CLNP
                    //case 32:  // CLNP_MPLS
                    //case 33:  // MPLS_CLNP
                    //case 200: // PPP
                    //case 201: // ISO
                    //case 202: // LLC
                    //case 203: // LLC_SNAP
                    case 204: // ETHER
                        T2_PKTDESC_ADD_HDR(packet, ":eth");
                        packet->l2HdrP = pktptr;
                        return (pktptr + 12); // advance 12 bytes to ether type
                    //case 205: // OAM
                    //case 206: // Q933
                    //case 207: // FRELAY
                    //case 208: // CHDLC
                    //case 0: // Unknown
                    default:
                        T2_WRN("Unhandled Juniper protocol %" PRIu32, proto);
                        return NULL;
                }
            } else {
                if (linkType == DLT_JUNIPER_ATM1) pktptr += 4; // cookie
                packet->l3HdrP = pktptr;
                if ((*pktptr & 0xf0) == 0x40) {
                    packet->l2HdrP = (uint8_t*)juniper;
                    T2_SET_STATUS(packet, L2_NO_ETH);
                    dissembleIPv4Packet(packet);
                    return NULL;
                } else if ((*pktptr & 0xf0) == 0x60) {
                    packet->l2HdrP = (uint8_t*)juniper;
                    T2_SET_STATUS(packet, L2_NO_ETH);
                    dissembleIPv6Packet(packet);
                    return NULL;
                } else {
                    T2_PKTDESC_ADD_HDR(packet, ":eth");
                    packet->l2HdrP = pktptr;
                    return (pktptr + 12); // advance 12 bytes to ether type
                }
            }
            break;
        }
#endif // LINKTYPE_JUNIPER == 1

        // Symantec Enterprise Firewall
        case DLT_SYMANTEC_FIREWALL: {
            T2_PKTDESC_ADD_HDR(packet, "symantec");
            const symantec_fw_v2_hdr_t * const v2 = (symantec_fw_v2_hdr_t*)pktptr;
            const symantec_fw_v3_hdr_t * const v3 = (symantec_fw_v3_hdr_t*)pktptr;
            if (UNLIKELY(v2->type == 0 && v3->type == 0)) return NULL;
            uint16_t ethType;
            if (v2->type != 0) {
                T2_CHECK_SNAP_L2(packet, sizeof(*v2), return NULL);
                ethType = v2->type;
                pktptr += sizeof(*v2);
            } else {
                T2_CHECK_SNAP_L2(packet, sizeof(*v3), return NULL);
                ethType = v3->type;
                pktptr += sizeof(*v3);
            }
            packet->l2HdrP = (uint8_t*)v2;
            packet->l3HdrP = pktptr;
            T2_SET_STATUS(packet, L2_NO_ETH);
            if (ethType == ETHERTYPE_IPn) {
                dissembleIPv4Packet(packet);
            } else if (ethType == ETHERTYPE_IPV6n) {
                dissembleIPv6Packet(packet);
            } else {
                T2_WRN("Unhandled Ethertype 0x%04" B2T_PRIX16 " for Symantec Enterprise Firewall", ethType);
            }
            return NULL;
        }

        case DLT_PRISM_HEADER: {
            T2_PKTDESC_ADD_HDR(packet, "prism");
            const prism_hdr_t * const prism = (prism_hdr_t*)pktptr;
            if (UNLIKELY(prism->msglen != PRISM_HDR_LEN)) {
                T2_WRN("Prism message length %" PRIu32 " different from default value %u", prism->msglen, PRISM_HDR_LEN);
            }
            pktptr += PRISM_HDR_LEN; // skip prism header
            packet->l2HdrP = pktptr;
            return t2_process_ieee80211(pktptr, false, packet);
        }

        case DLT_IEEE802_11_RADIO: {
            T2_PKTDESC_ADD_HDR(packet, "radiotap");
            const radiotap_hdr_t * const radio = (radiotap_hdr_t*)pktptr;
            pktptr += radio->len; // skip radiotap header
            packet->l2HdrP = pktptr;
            return t2_process_ieee80211(pktptr, false, packet);
        }

        // IEEE 802.11 wireless LAN
        case DLT_IEEE802_11:
            packet->l2HdrP = pktptr;
            return t2_process_ieee80211(pktptr, false, packet);

        case DLT_LINUX_LAPD:
            pktptr += sizeof(linux_cooked_t);
            /* FALLTHRU */
        case DLT_LAPD: {
#if LAPD_ACTIVATE == 1
            packet->l2HdrP = pktptr;
            pktptr += 2; // skip address field
            // Skip control field
            if ((*pktptr & 0x03) == 0x03) {  // Unnumbered frame
                pktptr++;
            } else {  // Information or Supervisory frame
                pktptr += 2;
            }
            packet->l3HdrP = pktptr;
            packet->l7HdrP = pktptr;
            T2_PKTDESC_ADD_HDR(packet, "lapd");
            t2_dispatch_lapd_packet(packet);
            return NULL;
#else // LDAP_ACTIVATE == 0
            T2_ERR("Support for LAPD flows currently disabled");
            T2_INF("Activate it as follows: t2conf -D LAPD_ACTIVATE=1 tranalyzer2 && t2build -R -r");
            exit(EXIT_FAILURE);
#endif // LDAP_ACTIVATE
        }

        default: {
            static const char * const prefix = "Unsupported link-layer type:";
            const char * const name = pcap_datalink_val_to_name(linkType);
            const char * const desc = pcap_datalink_val_to_description(linkType);
            // Only continue if linkType is PPI (Per-Packet Information)
            if (linkType == pcap_datalink(captureDescriptor)) {
                T2_ERR("%s %s [%s/%d]", prefix, desc, name, linkType);
                exit(EXIT_FAILURE);
            }
            T2_WRN("%s %s [%s/%d]", prefix, desc, name, linkType);
            return NULL;
        }
    }

    return NULL;
#endif // DPDK_MP == 0
}
