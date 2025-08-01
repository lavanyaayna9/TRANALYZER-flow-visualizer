/*
 * hdrDesc.h
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

#ifndef T2_HDRDESC_H_INCLUDED
#define T2_HDRDESC_H_INCLUDED

#include "networkHeaders.h"  // for T2_PRI_HDRDESC


#if T2_PRI_HDRDESC == 0

// Nothing to do
#define T2_PKTDESC_ADD_HDR(   pkt, desc)       { (void)(pkt); (void)(desc); }
#define T2_PKTDESC_ADD_REPHDR(pkt, desc, reps) { (void)(pkt); (void)(desc); (void)(reps); }

#define T2_PKTDESC_ADD_PROTO(   pkt, proto) { (void)(pkt); (void)(proto); }
#define T2_PKTDESC_ADD_LLCPROTO(pkt, proto) { (void)(pkt); (void)(proto); }
#define T2_PKTDESC_ADD_ETHPROTO(pkt, proto) { (void)(pkt); (void)(proto); }
#define T2_PKTDESC_ADD_PPPPROTO(pkt, proto) { (void)(pkt); (void)(proto); }

#else // T2_PRI_HDRDESC == 1

#include <stdint.h>  // for uint16_t, uint8_t, uint_fast8_t

#include "packet.h"  // for packet_t


#define T2_PKTDESC_ADD_HDR(   pkt, desc)       t2_pktdesc_add_hdr(   (pkt), (desc))
#define T2_PKTDESC_ADD_REPHDR(pkt, desc, reps) t2_pktdesc_add_rephdr((pkt), (desc), (reps))

#define T2_PKTDESC_ADD_PROTO(   pkt, proto) t2_pktdesc_add_proto(   (pkt), (proto))
#define T2_PKTDESC_ADD_LLCPROTO(pkt, proto) t2_pktdesc_add_llcproto((pkt), (proto))
#define T2_PKTDESC_ADD_ETHPROTO(pkt, proto) t2_pktdesc_add_ethproto((pkt), (proto))
#define T2_PKTDESC_ADD_PPPPROTO(pkt, proto) t2_pktdesc_add_pppproto((pkt), (proto))

void t2_pktdesc_add_hdr(packet_t *pkt, const char *desc) __attribute__((__nonnull__(1, 2)));
void t2_pktdesc_add_rephdr(packet_t *pkt, const char *desc, uint_fast8_t reps) __attribute__((__nonnull__(1, 2)));

void t2_pktdesc_add_proto(packet_t *pkt, uint8_t proto) __attribute__((__nonnull__(1)));
void t2_pktdesc_add_llcproto(packet_t *pkt, uint8_t proto) __attribute__((__nonnull__(1)));
void t2_pktdesc_add_ethproto(packet_t *pkt, uint16_t proto) __attribute__((__nonnull__(1)));
void t2_pktdesc_add_pppproto(packet_t *pkt, uint16_t proto) __attribute__((__nonnull__(1)));

#endif // T2_PRI_HDRDESC == 1

#endif // T2_HDRDESC_H_INCLUDED
