/*
 * macRecorder.c
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

#include "macRecorder.h"
#include "t2Plugin.h"

#if MR_MACLBL > 0
#include "macLbl.h"
#endif


// Plugin variables

macRecorder_t *macArray;        // the big struct for all flows


// Static variables

static macList_t *macList;      // the big struct with all list entries
static macList_t *macListFree;  // pointer to the first free entry

#if MR_MACLBL > 0
static maclbltable_t *maclbltable;
#endif // MR_MACLBL > 0

static uint32_t minMac = UINT32_MAX, maxMac;
static float aveMac;
static uint8_t macStat;


#if MR_MAC_FMT != 1
#define MR_READ_U48(p) (be64toh(*(uint64_t*)(p)) >> 16)
#endif

#if MR_MACLBL > 0
#define MR_MAC_UINT64(mac) ((*(uint64_t*)&mac) & 0x0000ffffffffffff)
#endif


// Tranalyzer Plugin functions

T2_PLUGIN_INIT("macRecorder", "0.9.3", 0, 9);


void t2Init() {
    macArray = t2_calloc_fatal(mainHashMap->hashChainTableSize, sizeof(*macArray));
    macList = t2_calloc_fatal(2 * mainHashMap->hashChainTableSize, sizeof(*macList));

    // connect free entries with each other
    for (unsigned int i = 0; i < 2 * mainHashMap->hashChainTableSize - 1; i++) {
        macList[i].next = &(macList[i+1]);
    }

    // set freeList pointer on first entry
    macListFree = &(macList[0]);

#if MR_MACLBL > 0
    if (UNLIKELY(!(maclbltable = maclbl_init(pluginFolder, MACLBLFILE)))) {
        exit(EXIT_FAILURE);
    }

    if (sPktFile) {
        fputs("srcMacLbl" SEP_CHR
              "dstMacLbl" SEP_CHR
              , sPktFile);
    }
#endif // MR_MACLBL > 0
}


binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;
    BV_APPEND_H8(bv, "macStat", "macRecorder status");
#if MR_NPAIRS == 1
    BV_APPEND_U32(bv, "macPairs", "Number of distinct source/destination MAC addresses pairs");
#endif // MR_NPAIRS == 1
    BV_APPEND_R(bv, "srcMac_dstMac_numP", "Source/destination MAC address, number of packets of MAC address combination", 3, MR_MAC_TYPE, MR_MAC_TYPE, bt_uint_64);
#if MR_MACLBL > 0
    BV_APPEND_R(bv, "srcMacLbl_dstMacLbl", "Source/destination MAC label", 2, MR_LBL_TYPE, MR_LBL_TYPE);
#endif // MR_MACLBL > 0
    return bv;
}


void t2OnNewFlow(packet_t *packet UNUSED, unsigned long flowIndex) {
    // first put all attached macList entries back into the free list
    macList_t *temp, *list = macArray[flowIndex].macList;
    while (list) {
        temp = list->next;
        list->next = macListFree;
        macListFree = list;
        list = temp;
    }

    // reset array entry
    macRecorder_t * const macRecorderP = &macArray[flowIndex];
    memset(macRecorderP, '\0', sizeof(*macRecorderP));
    macRecorderP->ethType = packet->ethType;
}


static inline void claimInfo(packet_t *packet, unsigned long flowIndex) {
    const ethernetHeader_t * const l2HdrP = (ethernetHeader_t*)packet->l2HdrP;
    flow_t * const flowP = &flows[flowIndex];

    macRecorder_t * const macListP = &macArray[flowIndex];

#if MR_MACLBL > 0
    if (sPktFile) {
        if (!l2HdrP || (flowP->status & (L2_NO_ETH | LAPD_FLOW))) {
            fputs(/* srcMacLbl */ SEP_CHR
                  /* dstMacLbl */ SEP_CHR
                  , sPktFile);
        } else {
            const uint64_t srcMac64 = MR_MAC_UINT64(l2HdrP->ethDS.ether_shost);
            const uint64_t dstMac64 = MR_MAC_UINT64(l2HdrP->ethDS.ether_dhost);
            const uint32_t srcIdx = maclbl_test(maclbltable, srcMac64, macListP->ethType);
            const uint32_t dstIdx = maclbl_test(maclbltable, dstMac64, macListP->ethType);
#if MR_MACLBL == 1
            fprintf(sPktFile,
                    "%" MR_LBL_PRI /* srcMacLbl */ SEP_CHR
                    "%" MR_LBL_PRI /* dstMacLbl */ SEP_CHR,
                    srcIdx, dstIdx);
#else // MR_MACLBL > 1
            const maclbl_t * const maclP = maclbltable->maclbls;
            fprintf(sPktFile,
                    "%s" /* srcMacLbl */ SEP_CHR
                    "%s" /* dstMacLbl */ SEP_CHR
                    , maclP[srcIdx].org, maclP[dstIdx].org);
#endif // MR_MACLBL == 3
        }
    }
#endif // MR_MACLBL > 0

    if (flowP->status & (L2_NO_ETH | LAPD_FLOW)) return;

    macList_t *list = macListP->macList;
    macList_t *temp = list;

    if (macListP->num_entries >= MR_MAX_MAC) {
        macArray[flowIndex].stat |= MR_F_OVRN;
        return;
    }

    while (list) {
        if (memcmp(list->ethHdr.ether_dhost, l2HdrP->ethDS.ether_dhost, 12) == 0) {
            list->numPkts++;
            return;
        }
        temp = list;
        list = list->next;
    }

    // the macList entry wasn't found
    // take a list entry out of the free list
    if (macListP->macList == NULL) {
        macListP->macList = macListFree; // point to first entry in free list
        temp = macListP->macList;        // move temp pointer to entry
    } else {
        temp->next = macListFree; // point to first entry in free list
        temp = temp->next;        // move temp pointer to entry
    }

    macListFree = macListFree->next; // move free list pointer
    temp->next = NULL;               // disconnect entry from free list

    // fill with the right values
    memcpy(&(temp->ethHdr), l2HdrP, sizeof(ethernetHeader_t));
    temp->numPkts = 1;

    // increment the number of mac combos
    macArray[flowIndex].num_entries++;
}


#if ETH_ACTIVATE > 0
void t2OnLayer2(packet_t *packet, unsigned long flowIndex) {
    if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;
    claimInfo(packet, flowIndex);
}
#endif // ETH_ACTIVATE > 0


void t2OnLayer4(packet_t *packet, unsigned long flowIndex) {
    claimInfo(packet, flowIndex);
}


void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {
    const macRecorder_t * const macListP = &macArray[flowIndex];

    const uint32_t num_entries = macListP->num_entries;
    if (num_entries < minMac) minMac = num_entries;
    if (num_entries > maxMac) maxMac = num_entries;

    if (aveMac) aveMac = 0.7 * aveMac + 0.3 * (float)num_entries;
    else aveMac = (float)(minMac + maxMac) / 2.0;

    macStat |= macListP->stat;

    OUTBUF_APPEND_U8(buf, macListP->stat); // macStat

#if MR_NPAIRS == 1
    OUTBUF_APPEND_U32(buf, num_entries); // macPairs
#endif // MR_NPAIRS == 1

    // srcMac_dstMac_numP
    OUTBUF_APPEND_NUMREP(buf, num_entries);

#if MR_MAC_FMT != 1
    uint64_t mac;
#endif // MR_MAC_FMT != 1

    // point to actual entry
    macList_t *list = macListP->macList;
    while (list) {
        // print source and dest mac
#if MR_MAC_FMT == 1
        OUTBUF_APPEND_MAC(buf, list->ethHdr.ether_shost);
        OUTBUF_APPEND_MAC(buf, list->ethHdr.ether_dhost);
#else // MR_MAC_FMT != 1
        mac = MR_READ_U48(&list->ethHdr.ether_shost);
        OUTBUF_APPEND_U64(buf, mac);
        mac = MR_READ_U48(&list->ethHdr.ether_dhost);
        OUTBUF_APPEND_U64(buf, mac);
#endif // MR_MAC_FMT != 1

        // print number of packets with this src/dst combo
        OUTBUF_APPEND_U64(buf, list->numPkts);

        // goto next entry
        list = list->next;
    }

// Optimization: no need to call maclbl_test() if we don't create output
#if BLOCK_BUF == 0
    // srcMacLbl_dstMacLbl
#if MR_MACLBL > 0
    // MAC label
    int32_t i;
    list = macListP->macList;
#if MR_MACLBL > 1
    maclbl_t *maclP = maclbltable->maclbls;
#endif // MR_MACLBL > 1
    OUTBUF_APPEND_NUMREP(buf, num_entries);
    while (list) {
        i = maclbl_test(maclbltable, MR_MAC_UINT64(list->ethHdr.ether_shost), macListP->ethType);
#if MR_MACLBL == 1
        OUTBUF_APPEND_U32(buf, i);
#else // MR_MACLBL > 1
        OUTBUF_APPEND_STR(buf, maclP[i].org);
#endif // MR_MACLBL
        i = maclbl_test(maclbltable, MR_MAC_UINT64(list->ethHdr.ether_dhost), macListP->ethType);
#if MR_MACLBL == 1
        OUTBUF_APPEND_U32(buf, i);
#else // MR_MACLBL > 1
        OUTBUF_APPEND_STR(buf, maclP[i].org);
#endif // MR_MACLBL
        list = list->next;
    }
#endif // MR_MACLBL > 0
#endif // BLOCK_BUF == 0
}


void t2PluginReport(FILE *stream) {
    T2_FPLOG_AGGR_HEX(stream, plugin_name, macStat);
    if (maxMac > 1) {
        T2_FPLOG(stream, plugin_name,
                "MAC pairs per flow: min: %" PRIu32 ", max: %" PRIu32 ", average: %.2f",
                minMac, maxMac, aveMac);
    }
}


void t2Finalize() {
    free(macArray);
    free(macList);
}
