/*
 * vlan.c
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

#include "vlan.h"

#include <arpa/inet.h>   // for ntohs
#include <sys/types.h>   // for u_char

#include "ethertype.h"   // for ETHERTYPEn_IS_VLAN
#include "flow.h"        // for FS_VLAN0, L2_VLAN
#include "hdrDesc.h"     // for T2_PKTDESC_ADD_REPHDR
#include "main.h"        // for vlanHdrCntMx, T2_SET_STATUS
#include "t2stats.h"     // for vlanHdrCntMx
#include "t2utils.h"     // for MAX
#include "tranalyzer.h"  // for AGGREGATIONFLAG, VLANID


// Scroll all VLAN headers
inline _8021Q_t *t2_process_vlans(_8021Q_t *shape, packet_t *packet) {
    if (!ETHERTYPEn_IS_VLAN(shape->identifier)) {
        // No VLAN
        return shape;
    }

    T2_SET_STATUS(packet, L2_VLAN);

#if (AGGREGATIONFLAG & VLANID) == 0
    packet->vlanHdrP = (uint32_t*)((uint8_t*)shape+2);
#endif // (AGGREGATIONFLAG & VLANID) == 0

    uint8_t count = 0;
    const uint8_t * const endPkt = packet->end_packet - 4;
    while (ETHERTYPEn_IS_VLAN(shape->identifier) &&
           (uint8_t*)shape <= endPkt)
    {
        if ((shape->vlanId & VLANID_MASK16n) == 0) {
            T2_SET_STATUS(packet, FS_VLAN0);
        }
        shape++;
        count++;
    }

    packet->vlanHdrCnt += count;

    T2_PKTDESC_ADD_REPHDR(packet, ":vlan", count);
    vlanHdrCntMx = MAX(vlanHdrCntMx, packet->vlanHdrCnt);

#if (AGGREGATIONFLAG & VLANID) == 0
    packet->vlanId = ntohs((shape-1)->vlanId) & VLANID_MASK16;
#endif // (AGGREGATIONFLAG & VLANID) == 0

    return shape;
}
