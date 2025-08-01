/*
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

// local includes
#include "pktSIATHisto.h"


// Global variables

rbTreeNodePool_t *pktSIAT_treeNodePool;
pktSIAT_t        *pktSIAT_trees;
psiat_val_t      *psiat_vals;


// Static variables

#if ENVCNTRL > 0
static uint32_t psiatNdplf;
#else // ENVCNTRL == 0
static const uint32_t psiatNdplf = PSIAT_NDPLF;
#endif // ENVCNTRL

#if PRINT_HISTO == 1 && BLOCK_BUF == 0
static outputBuffer_t *psiat_buffer;
#endif // PRINT_HISTO == 1 && BLOCK_BUF == 0

#if BLOCK_BUF == 0 && PRINT_HISTO == 1
static uint32_t psiat_counter;
#endif // BLOCK_BUF == 0 && PRINT_HISTO == 1

// definition of bin count fields
#if IATSECMAX == 1
static const uint32_t IATBinBu[] = { 0, IATBINBu1 };
static const uint32_t IATBinNu[] = { 0, IATBINNu1 };
static const uint32_t IATBinWu[] = { IATBINWu1 };
#elif IATSECMAX == 2
static const uint32_t IATBinBu[] = { 0, IATBINBu1, IATBINBu2 };
static const uint32_t IATBinNu[] = { 0, IATBINNu1, IATBINNu2 };
static const uint32_t IATBinWu[] = { IATBINWu1, IATBINWu2 };
#elif IATSECMAX == 3
static const uint32_t IATBinBu[] = { 0, IATBINBu1, IATBINBu2, IATBINBu3 };
static const uint32_t IATBinNu[] = { 0, IATBINNu1, IATBINNu2, IATBINNu3 };
static const uint32_t IATBinWu[] = { IATBINWu1, IATBINWu2, IATBINWu3 };
#elif IATSECMAX == 4
static const uint32_t IATBinBu[] = { 0, IATBINBu1, IATBINBu2, IATBINBu3, IATBINBu4 };
static const uint32_t IATBinNu[] = { 0, IATBINNu1, IATBINNu2, IATBINNu3, IATBINNu4 };
static const uint32_t IATBinWu[] = { IATBINWu1, IATBINWu2, IATBINWu3, IATBINWu4 };
#elif IATSECMAX == 5
static const uint32_t IATBinBu[] = { 0, IATBINBu1, IATBINBu2, IATBINBu3, IATBINBu4, IATBINBu5 };
static const uint32_t IATBinNu[] = { 0, IATBINNu1, IATBINNu2, IATBINNu3, IATBINNu4, IATBINNu5 };
static const uint32_t IATBinWu[] = { IATBINWu1, IATBINWu2, IATBINWu3, IATBINWu4, IATBINWu5 };
#else // IATSECMAX > 5
static const uint32_t IATBinBu[] = { 0, IATBINBu1, IATBINBu2, IATBINBu3, IATBINBu4, IATBINBu5, IATBINBu6 };
static const uint32_t IATBinNu[] = { 0, IATBINNu1, IATBINNu2, IATBINNu3, IATBINNu4, IATBINNu5, IATBINNu6 };
static const uint32_t IATBinWu[] = { IATBINWu1, IATBINWu2, IATBINWu3, IATBINWu4, IATBINWu5, IATBINWu6 };
#endif // IATSECMAX 1-6

//static uint32_t IATBinNu[IATSECMAX+1];

//static const float IATBinBf[] = { 0.0f, IATBINBF1, IATBINBF2, IATBINBF3 };
//static const float IATBinWf[] = { IATBINWF1, IATBINWF2, IATBINWF3 };
//static const float IATBinWif[] = { IATBINWIF1, IATBINWIF2, IATBINWIF3 };
//static const uint32_t IATBinNfu[] = { 0, IATBINF1, IATBINF2, IATBINF3 };


static void recursiveDestroyIATTree(rbNode_t *node, rbTreeNodePool_t *treeNodePool);
#if (HISTO_DEBUG != 0 && DEBUG > 3)
static void printTree_inOrder(rbNode_t *tree);
#endif


// Tranalyzer Plugin Functions

T2_PLUGIN_INIT("pktSIATHisto", "0.9.3", 0, 9);


// new flexible float bin definition

//uint32_t iat2binf(float iat) {
//  int32_t i;
//  float f;
//  for (i = 0; i < IATSECMAX; i++) {
//      f = iat - IATBinBf[i];
//      if (f > 0.0f) return f * IATBinWif[i] + IATBinNfu[i];
//  }
//  return IATSECMAX;
//}


//float bin2iatf(uint32_t bin) {
//  int32_t i;
//  for (i = 0; i < IATSECMAX; i++) {
//      if (bin < IATBinNu[i+1]) return (bin - IATBinBf[i]) * IATBinWf[i] + IATBinBf[i];
//  }
//  return IATBinNu[IATSECMAX];
//}


// flexible uint bins

static uint32_t iat2bin(struct timeval iat) {
    const uint32_t k = (uint32_t)iat.tv_sec * IATNORM + iat.tv_usec / IATNORM;
    for (uint_fast32_t i = 0; i < IATSECMAX; i++) {
        if (k < IATBinBu[i+1]) {
            return (k - IATBinBu[i]) / IATBinWu[i] + IATBinNu[i];
        }
    }
    return IATBinNu[IATSECMAX];
}


int32_t bin2iat(uint32_t bin) {
    for (uint_fast32_t i = 0; i < IATSECMAX; i++) {
        if (bin < IATBinNu[i+1]) {
            return (bin - IATBinNu[i]) * IATBinWu[i] + IATBinBu[i];
        }
    }
    return IATBinBu[IATSECMAX];
}


void t2Init() {

#if PRINT_HISTO == 1 && BLOCK_BUF == 0
    psiat_buffer = outputBuffer_initialize(MAIN_OUTBUF_SIZE);
#endif // PRINT_HISTO == 1 && BLOCK_BUF == 0

#if ENVCNTRL > 0
    t2_env_t env[ENV_PSIAT_N] = {};
    t2_get_env(PLUGIN_SRCH, ENV_PSIAT_N, env);
    psiatNdplf = T2_ENV_VAL_UINT(PSIAT_NDPLF);
    t2_free_env(ENV_PSIAT_N, env);
#endif // ENVCNTRL > 0

    pktSIAT_treeNodePool = rbTree_initTreeNodePool(mainHashMap->hashChainTableSize * psiatNdplf);

    pktSIAT_trees = t2_calloc_fatal(mainHashMap->hashChainTableSize, sizeof(pktSIAT_t));
    psiat_vals = t2_calloc_fatal(pktSIAT_treeNodePool->size, sizeof(psiat_val_t));

    //IATBinNu[0] = 0;
    //for (i = 1; i <= IATSECMAX; i++) {
    //  IATBinNu[i] = (IATBinBu[i] - IATBinBu[i-1]) / IATBinWu[i-1] + IATBinNu[i-1];
    //}
}


#if HISTO_EARLY_CLEANUP == 0
void t2OnNewFlow(packet_t *packet UNUSED, unsigned long flowIndex) {
    pktSIAT_t * const pSIAT = &pktSIAT_trees[flowIndex];
    // cleanup
    if (pSIAT->packetTree) {
        recursiveDestroyIATTree(pSIAT->packetTree, pktSIAT_treeNodePool);
        rbTree_destroy(pSIAT->packetTree, pktSIAT_treeNodePool);
        memset(pSIAT, '\0', sizeof(pktSIAT_t));
    }
}
#endif // HISTO_EARLY_CLEANUP


#if PRINT_HISTO == 1
binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;

    BV_APPEND_U32(bv, "tCnt", "Number of tree entries");

#if HISTO_PRINT_BIN == 1
    BV_APPEND_R(bv, "Ps_IatBin_Cnt_PsCnt_IatCnt", "Packet size (PS) and inter-arrival time (IAT) of bin histogram", 5, bt_uint_16, bt_uint_32, bt_uint_32, bt_uint_32, bt_uint_32);
#else // HISTO_PRINT_BIN == 0
    BV_APPEND_R(bv, "Ps_Iat_Cnt_PsCnt_IatCnt", "Packet size (PS) and min inter-arrival time (IAT) of bin histogram", 5, bt_uint_16, bt_uint_32, bt_uint_32, bt_uint_32, bt_uint_32);
#endif // HISTO_PRINT_BIN

    return bv;
}
#endif // PRINT_HISTO == 1


static inline void claimInfo(packet_t *packet, unsigned long flowIndex) {
#if PSI_XCLD == 1 && PSI_XMIN > 0
    if (packet->len < PSI_XMIN) return;
#endif // PSI_XCLD == 1 && PSI_XMIN > 0
#if PSI_MOD > 1
    int32_t const pLen = packet->len % PSI_MOD;
#else // PSI_MOD == 0
    int32_t const pLen = packet->len;
#endif // PSI_MOD

    pktSIAT_t * const pSIAT = &pktSIAT_trees[flowIndex];

    bool entryExists;
    rbNode_t * const currentPacketNode = rbTree_search_insert(pSIAT->packetTree, pktSIAT_treeNodePool, pLen, true, &entryExists);
    if (UNLIKELY(!currentPacketNode)) {
        T2_PFATAL(plugin_name, "Failed to insert new tree node. Increase PSIAT_NDPLF in pktSIATHisto.h and recompile the plugin");
    }

    pSIAT->numPackets++;

    const unsigned long currPacketTreeBucket = currentPacketNode - &pktSIAT_treeNodePool->nodePool[0];
    if (!currentPacketNode->parent) {
        pSIAT->packetTree = currentPacketNode;
    }
#if RBT_ROTATION == 1
    else {
        // if the tree was rotated at its root, we have to change the information in the current pktSIAT tree
        while (pSIAT->packetTree->parent) {
            pSIAT->packetTree = pSIAT->packetTree->parent;
        }
    }
#endif // RBT_ROTATION == 1

    if (entryExists) {
        psiat_vals[currPacketTreeBucket].numPackets++;
    } else {
        memset(&psiat_vals[currPacketTreeBucket], '\0', sizeof(psiat_val_t));
        psiat_vals[currPacketTreeBucket].numPackets = 1;
    }

    // get IAT
    struct timeval currentIAT;
    if (pSIAT->lastPacketTime.tv_sec) { // marker for flow start
        T2_TIMERSUB(&packet->pcapHdrP->ts, &pSIAT->lastPacketTime, &currentIAT);
    } else {
        currentIAT.tv_sec = 0;
        currentIAT.tv_usec = 0;
    }

    // update last packet seen time
    pSIAT->lastPacketTime = packet->pcapHdrP->ts;

    // store iat
    const uint32_t i = iat2bin(currentIAT);
    pSIAT->numPacketsInTimeBin[i]++;

    rbNode_t * const currentIATNode = rbTree_search_insert(psiat_vals[currPacketTreeBucket].iat_tree, pktSIAT_treeNodePool, i, true, &entryExists);
    if (UNLIKELY(!currentIATNode)) {
        T2_PFATAL(plugin_name, "Failed to insert new tree node. Increase PSIAT_NDPLF in pktSIATHisto.h and recompile the plugin");
    }

    const unsigned long currIATTreeBucket = currentIATNode - &pktSIAT_treeNodePool->nodePool[0];
    if (!currentIATNode->parent) {
        psiat_vals[currPacketTreeBucket].iat_tree = currentIATNode;
    }
#if RBT_ROTATION == 1
    else {
        // if the tree was rotated at its root, we have to change the information in the current packet tree
        while (psiat_vals[currPacketTreeBucket].iat_tree->parent) {
            psiat_vals[currPacketTreeBucket].iat_tree = psiat_vals[currPacketTreeBucket].iat_tree->parent;
        }
    }
#endif // RBT_ROTATION == 1

    if (entryExists) {
        psiat_vals[currIATTreeBucket].numPackets++;
    } else {
        memset(&psiat_vals[currIATTreeBucket], '\0', sizeof(psiat_val_t));
        psiat_vals[currIATTreeBucket].numPackets = 1;
    }
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


#if (BLOCK_BUF == 0 && PRINT_HISTO == 1)
static void recursivePrintIAT_binary(rbNode_t *node, int32_t packetSize, uint32_t numPacketsPS, pktSIAT_t *tree, outputBuffer_t *buf) {
    if (node->left) recursivePrintIAT_binary(node->left, packetSize, numPacketsPS, tree, buf);

    const unsigned long currIATTreeBucket = node - &pktSIAT_treeNodePool->nodePool[0];

    psiat_counter++;

    // Ps
    OUTBUF_APPEND_U16(buf, packetSize);

    // IatBin/Iat
#if HISTO_PRINT_BIN == 1
    OUTBUF_APPEND_U32(buf, node->value);
#else // HISTO_PRINT_BIN == 0
    const uint32_t tempVar = bin2iat(node->value);
    OUTBUF_APPEND_U32(buf, tempVar);
#endif // HISTO_PRINT_BIN

    OUTBUF_APPEND_U32(buf, psiat_vals[currIATTreeBucket].numPackets);
    OUTBUF_APPEND_U32(buf, numPacketsPS);
    OUTBUF_APPEND_U32(buf, tree->numPacketsInTimeBin[node->value]);

    if (node->right) recursivePrintIAT_binary(node->right, packetSize, numPacketsPS, tree, buf);
}
#endif // (BLOCK_BUF == 0 && PRINT_HISTO == 1)


#if (BLOCK_BUF == 0 && PRINT_HISTO == 1)
static void recursivePrintPacketSize_binary(rbNode_t *node, pktSIAT_t *tree, outputBuffer_t *buf) {
    if (node->left) recursivePrintPacketSize_binary(node->left, tree, buf);

    const unsigned long currPacketTreeBucket = node - pktSIAT_treeNodePool->nodePool;
    recursivePrintIAT_binary(psiat_vals[currPacketTreeBucket].iat_tree, node->value, psiat_vals[currPacketTreeBucket].numPackets, tree, buf);

    if (node->right) recursivePrintPacketSize_binary(node->right, tree, buf);
}
#endif // (BLOCK_BUF == 0 && PRINT_HISTO == 1)


static void recursiveDestroyIATTree(rbNode_t *node, rbTreeNodePool_t *treeNodePool) {
    if (UNLIKELY(!node)) return;

    if (node->left)  recursiveDestroyIATTree(node->left , treeNodePool);
    if (node->right) recursiveDestroyIATTree(node->right, treeNodePool);

    const unsigned long currPacketTreeBucket = node - pktSIAT_treeNodePool->nodePool;
    rbTree_destroy(psiat_vals[currPacketTreeBucket].iat_tree, treeNodePool);
}


#if PSI_XCLD == 0 || HISTO_EARLY_CLEANUP == 1 || (HISTO_DEBUG != 0 && DEBUG > 3) || (BLOCK_BUF == 0 && PRINT_HISTO == 1)
void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf
#if BLOCK_BUF == 1 || PRINT_HISTO == 0
    UNUSED
#endif
) {
    pktSIAT_t * const pSIAT = &pktSIAT_trees[flowIndex];

#if PSI_XCLD == 0
    if (UNLIKELY(!pSIAT->packetTree)) {
        T2_PWRN(plugin_name, "Flow with number %lu has no tree", flowIndex);
        // TODO exit?
        return;
    }
#endif // PSI_XCLD == 0

#if HISTO_DEBUG != 0 && DEBUG > 3
    rbTree_print(pSIAT->packetTree, 5);
    printTree_inOrder(pSIAT->packetTree);
    fputs("\n\n", stdout);
#endif // HISTO_DEBUG != 0 && DEBUG > 3

#if BLOCK_BUF == 0
#if PRINT_HISTO == 1
    // reset the psiat_buffer
    outputBuffer_reset(psiat_buffer);
    psiat_counter = 0;

    // print in buffer
#if PSI_XCLD != 0
    if (pSIAT->packetTree)
#endif // PSI_XCLD != 0
        recursivePrintPacketSize_binary(pSIAT->packetTree, &pktSIAT_trees[flowIndex], psiat_buffer);

    OUTBUF_APPEND_U32(buf, psiat_counter); // tCnt

    // Ps_Iat_Cnt_PsCnt_IatCnt/Ps_IatBin_Cnt_PsCnt_IatCnt
    OUTBUF_APPEND_NUMREP(buf, psiat_counter);
    outputBuffer_append(buf, psiat_buffer->buffer, psiat_buffer->pos);
#endif // PRINT_HISTO == 1
#endif // BLOCK_BUF == 0

#if HISTO_EARLY_CLEANUP == 1
    // cleanup
    if (pSIAT->packetTree) {
        recursiveDestroyIATTree(pSIAT->packetTree, pktSIAT_treeNodePool);
        rbTree_destroy(pSIAT->packetTree, pktSIAT_treeNodePool);
    }
    memset(pSIAT, '\0', sizeof(pktSIAT_t));
#endif // HISTO_EARLY_CLEANUP == 1
}
#endif // PSI_XCLD == 0 || HISTO_EARLY_CLEANUP == 1 || (HISTO_DEBUG != 0 && DEBUG > 3) || (BLOCK_BUF == 0 && PRINT_HISTO == 1)


void t2Finalize() {
    if (pktSIAT_treeNodePool) {
        free(pktSIAT_treeNodePool->nodePool);
        free(pktSIAT_treeNodePool);
    }

    free(pktSIAT_trees);
    free(psiat_vals);

#if PRINT_HISTO == 1 && BLOCK_BUF == 0
    outputBuffer_destroy(psiat_buffer);
#endif
}


#if (HISTO_DEBUG != 0 && DEBUG > 3)
static void printTree_inOrder(rbNode_t *tree) {
    if (tree->left) printTree_inOrder(tree->left);
    printf("[%" PRId32 ":%" PRIu32 "]\t", tree->value, psiat_vals[tree - &pktSIAT_treeNodePool->nodePool[0]].numPackets);
    if (tree->right) printTree_inOrder(tree->right);
}
#endif // (HISTO_DEBUG != 0 && DEBUG > 3)
