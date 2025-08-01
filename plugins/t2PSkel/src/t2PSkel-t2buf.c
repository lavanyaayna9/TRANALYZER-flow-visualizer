/*
 * t2PSkel.c
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

#include "t2PSkel.h"

#include "t2buf.h"


/*
 * Plugin variables that may be used by other plugins MUST be declared in
 * the header file as 'extern t2PSkelFlow_t *t2PSkelFlows;'
 */
t2PSkelFlow_t *t2PSkelFlows;


/*
 * Static variables are only visible in this file
 */

static uint64_t numT2PSkelPkts;
static uint8_t t2PSkelStat;


/*
 * Static functions prototypes
 */


// Tranalyzer functions

/*
 * This describes the plugin name, version, major and minor version of
 * Tranalyzer required and dependencies
 */
T2_PLUGIN_INIT("t2PSkel", "0.9.3", 0, 9);


/*
 * This function is called before processing any packet.
 */
void t2Init() {
    // allocate struct for all flows and initialize to 0
    T2_PLUGIN_STRUCT_NEW(t2PSkelFlows);
}


/*
 * This function is used to describe the columns output by the plugin
 */
binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;
    BV_APPEND_H8(bv, "t2PSkelStat", "t2PSkel status");
    return bv;
}


/*
 * This function is called every time a new flow is created.
 */
void t2OnNewFlow(packet_t *packet, unsigned long flowIndex) {
    // Reset the structure for this flow
    t2PSkelFlow_t * const t2PSkelFlowP = &t2PSkelFlows[flowIndex];
    memset(t2PSkelFlowP, '\0', sizeof(*t2PSkelFlowP));
}


#if ETH_ACTIVATE > 0
/*
 * This function is called for every packet with a layer 2.
 * If flowIndex is HASHTABLE_ENTRY_NOT_FOUND, this means the packet also
 * has a layer 4 and thus a call to t2OnLayer4() will follow.
 */
void t2OnLayer2(packet_t *packet, unsigned long flowIndex) {
    if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;

    t2PSkelFlow_t * const t2PSkelFlowP = &t2PSkelFlows[flowIndex];

    const uint16_t snaplen = packet->snapL7Len;
    const uint8_t * const l7HdrP = packet->l7HdrP;

    t2buf_t t2buf = t2buf_create(l7HdrP, snaplen);
    while (t2buf_left(&t2buf) > 0) {
        uint8_t byte;
        if (!t2buf_read_u8(&t2buf, &byte)) return;
        switch (byte) {
            case 0: t2buf_skip_u8(&t2buf);  break;
            case 1: t2buf_skip_u16(&t2buf); break;
            case 2: t2buf_skip_u32(&t2buf); break;
            case 3: t2buf_skip_u64(&t2buf); break;
            case 4: {
                char *str[byte+1];
                t2buf_readstr(&t2buf, (uint8_t*)str, sizeof(str), T2BUF_UTF8, true);
                break;
            }
            default: t2buf_skip_n(&t2buf, byte); break;
        }
    }
}
#endif // ETH_ACTIVATE > 0


/*
 * This function is called once a flow is terminated.
 * Output all the statistics for the flow here.
 */
void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {
    const t2PSkelFlow_t * const t2PSkelFlowP = &t2PSkelFlows[flowIndex];

    t2PSkelStat |= t2PSkelFlowP->stat;

    OUTBUF_APPEND_U8(buf, t2PSkelFlowP->stat);
}


/*
 * This function is used to report information regarding the plugin.
 * This will appear in the final report.
 */
void t2PluginReport(FILE *stream) {
    T2_FPLOG_AGGR_HEX(stream, plugin_name, t2PSkelStat);
    T2_FPLOG_NUMP(stream, plugin_name, "Number of t2PSkel packets", numT2PSkelPkts, numPackets);
}


/*
 * This function is called once all the packets have been processed.
 * Cleanup all used memory here.
 */
void t2Finalize() {
    free(t2PSkelFlows);
}
