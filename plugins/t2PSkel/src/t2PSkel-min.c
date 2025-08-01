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


/*
 * This function is called for every packet with a layer 4.
 */
void t2OnLayer4(packet_t *packet, unsigned long flowIndex) {
    t2PSkelFlow_t * const t2PSkelFlowP = &t2PSkelFlows[flowIndex];

    // only 1. frag packet will be processed
    if (!t2_is_first_fragment(packet)) return;

    t2PSkelFlowP->stat |= T2PSKEL_STAT_MYPROT;
    numT2PSkelPkts++;
}


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
