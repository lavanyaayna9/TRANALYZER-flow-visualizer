/*
 * centrality.c
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

/*
 * Counts every directed connection from srcIP to dstIP,
 * stores them in a Matrix and calculates the eigenvector-Centrality
 * for each IP.
 *
 * Current Version: Write srcIP, dstIP and number of connections to
 * "baseFileName_centrality.txt"
 */

#include "centrality.h"
#include "t2Plugin.h"
#include "cs.h"

#if CENTRALITY_MATRIXENTRIES >= 2
#include "../basicStats/src/basicStats.h"


extern bSFlow_t *bSFlow __attribute__((weak));
#endif // CENTRALITY_MATRIXENTRIES >= 2


// static variables

#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2

#if CENTRALITY_TIME_CALC != 0
static unsigned long lastCalcTime;
#endif // CENTRALITY_TIME_CALC != 0

#if CENTRALITY_TRAVIZ == 1
static uint64_t cent_num_rows;
#endif // CENTRALITY_TRAVIZ == 1

static uint8_t centAStat;

// hashMaps
static hashMap_t *connectionHashMap;   // srcIP, dstIP and #connections
static hashMap_t *centralityIpHashMap; // list of unique IPs (for matrix generation)

/* We have to know which IP is on which row in the adjacency-matrix.
 * Therefore we need an indexed array with all unique IPs */
static in_addr_t *centralityIps;
static ipPairsConnections_t *centralityIpPairs; // Struct for _ALL_ flow srcIP and dstIP

static unsigned long maxIpIndex;     // Max IP index (size of matrix)
static unsigned long maxIpPairIndex; // Max IP pair index (needed for matrix construction)
//static uint64_t cent_calc_times = 1;

static FILE *centralityFile;

#if CENTRALITY_MATRIXFILE == 1
static FILE *matrixFile;
#endif


// local function prototypes

static void calculateEigenvectorCentrality(unsigned long maxIpIndex, unsigned long maxIpPairIndex, ipPairsConnections_t *ipPairs);
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2


// Tranalyzer plugin functions

T2_PLUGIN_INIT_WITH_DEPS("centrality", "0.9.3", 0, 9,
#if CENTRALITY_MATRIXENTRIES >= 2
    "basicStats"
#else // CENTRALITY_MATRIXENTRIES < 2
    ""
#endif // CENTRALITY_MATRIXENTRIES < 2

);


void t2Init() {
#if IPV6_ACTIVATE == 1
    T2_PERR(plugin_name, "IPv6 not supported");
#else // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
#if IPV6_ACTIVATE == 2
    T2_PWRN(plugin_name, "IPv6 not supported: results only apply to IPv4");
#endif // IPV6_ACTIVATE == 2

    centralityFile = t2_fopen_with_suffix(baseFileName, CENTRALITY_SUFFIX, "w");
    if (UNLIKELY(!centralityFile)) exit(EXIT_FAILURE);

#if CENTRALITY_TRAVIZ == 1
    fprintf(centralityFile, "%50s\n", "");  // placeholder for header (% numRows time IP centrality)
#endif // CENTRALITY_TRAVIZ == 1

#if CENTRALITY_MATRIXFILE == 1
    matrixFile = t2_fopen_with_suffix(baseFileName, MATRIX_SUFFIX, "w");
    if (UNLIKELY(!matrixFile)) {
        fclose(centralityFile);
        exit(EXIT_FAILURE);
    }
#endif // CENTRALITY_MATRIXFILE == 1

    // initialize HashTables
    connectionHashMap = hashTable_init(1.0f, sizeof(ipPairs_t), "conn");
    centralityIpHashMap = hashTable_init(1.0f, sizeof(in_addr_t), "cent");

    if (UNLIKELY(!connectionHashMap || !centralityIpHashMap)) {
        T2_PERR(plugin_name, "failed to initialize hash tables");
        fclose(centralityFile);
#if CENTRALITY_MATRIXFILE == 1
        fclose(matrixFile);
#endif // CENTRALITY_MATRIXFILE
        hashTable_destroy(connectionHashMap);
        hashTable_destroy(centralityIpHashMap);
        exit(EXIT_FAILURE);
    }

    // Storage for srcIPs, dstIPs and number of directed connections between them
    centralityIpPairs = t2_calloc(connectionHashMap->hashChainTableSize, sizeof(*centralityIpPairs));
    // Unique IP Array
    centralityIps = t2_calloc(centralityIpHashMap->hashChainTableSize, sizeof(*centralityIps));

    if (UNLIKELY(!centralityIpPairs || !centralityIps)) {
        T2_PERR(plugin_name, "failed to allocate memory for centralityIps or centralityIpPairs");
        fclose(centralityFile);
#if CENTRALITY_MATRIXFILE == 1
        fclose(matrixFile);
#endif // CENTRALITY_MATRIXFILE
        hashTable_destroy(connectionHashMap);
        hashTable_destroy(centralityIpHashMap);
        exit(EXIT_FAILURE);
    }
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
}


#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
static void calculateEigenvectorCentrality(unsigned long maxIpIndex, unsigned long maxIpPairIndex, ipPairsConnections_t *ipPairs) {

    // Matrix/Vector init
    cs *graph = cs_spalloc(maxIpIndex+2, maxIpIndex+2, maxIpPairIndex, 1, 1);

    // Add values to adjacency-matrix
    unsigned long k;
    for (k = 0; k <= maxIpIndex+1; k++) {
        cs_entry(graph, 0, k, 1);
        cs_entry(graph, k, 0, 1);
    }

    ipPairsConnections_t ipPair;
    for (k = 0; k <= maxIpPairIndex; k++) {
        ipPair = ipPairs[k];
        if (ipPair.numberOfConnections != 0) {
#if CENTRALITY_MATRIXENTRIES == 0
            cs_entry(graph, ipPair.srcIP_ID+1, ipPair.dstIP_ID+1, ipPair.numberOfConnections ? 1 : 0);
            //cs_entry(graph, ipPair.dstIP_ID+1, ipPair.srcIP_ID+1, ipPair.numberOfConnections ? 1 : 0);
#elif CENTRALITY_MATRIXENTRIES == 1
            cs_entry(graph, ipPair.srcIP_ID+1, ipPair.dstIP_ID+1, ipPair.numberOfConnections);
#elif CENTRALITY_MATRIXENTRIES == 2
            cs_entry(graph, ipPair.srcIP_ID+1, ipPair.dstIP_ID+1, ipPair.sentBytes);
#elif CENTRALITY_MATRIXENTRIES == 3
            cs_entry(graph, ipPair.srcIP_ID+1, ipPair.dstIP_ID+1, ipPair.byteAsym/ipPair.numberOfConnections);
#elif CENTRALITY_MATRIXENTRIES == 4
            cs_entry(graph, ipPair.srcIP_ID+1, ipPair.dstIP_ID+1, ipPair.sentPkts);
#elif CENTRALITY_MATRIXENTRIES == 5
            cs_entry(graph, ipPair.srcIP_ID+1, ipPair.dstIP_ID+1, ipPair.pktAsym/ipPair.numberOfConnections);
#endif // CENTRALITY_MATRIXENTRIES

#if CENTRALITY_TIME_CALC != 0
            // subtract all connections that have been closed in the last time-window
            ipPair.numberOfConnections -= ipPair.subConnections;
            ipPair.subConnections = 0;
#if CENTRALITY_MATRIXENTRIES == 2
            ipPair.sentBytes = 0;
#elif CENTRALITY_MATRIXENTRIES == 3
            ipPair.byteAsym = 0;
#elif CENTRALITY_MATRIXENTRIES == 4
            ipPair.sentPkts = 0;
#elif CENTRALITY_MATRIXENTRIES == 5
            ipPair.pktAsym = 0;
#endif // CENTRALITY_MATRIXENTRIES == 5
#endif // CENTRALITY_TIME_CALC != 0
        }
    }

#if CENTRALITY_MATRIXFILE == 1
    cs_print(graph, 1, matrixFile);
#endif // CENTRALITY_MATRIXFILE == 1

    graph = cs_compress(graph); // Convert graph-storage format

    cs *vec = cs_spalloc(maxIpIndex+1, 1, maxIpIndex+1, 1, 1);
    // use ones(maxIpIndex) as start-vector for the power iteration
    for (k = 0; k <= maxIpIndex+1; k++) {
        cs_entry(vec, k, 0, 1);
    }

    vec = cs_compress(vec); // Convert vector-storage format

    double diff;
    int times = 0;
    cs *tmp, *tmp2, *oldvec;
    // Power Iteration
    do {
        times++;
        oldvec = cs_add(vec, vec, 0, 1);
        vec = cs_multiply(graph, vec);
        tmp2 = vec;
        vec = cs_add(vec, vec, 0, 1.0/cs_norm(vec));
        tmp = cs_add(oldvec, vec, 1, -1);
        diff = cs_norm(tmp);
        cs_spfree(oldvec);
        cs_spfree(tmp2);
        cs_spfree(tmp);
    } while (diff > 0.01 * log1p(maxIpIndex) && times < 1000);

    //T2_PINF(plugin_name, "sec = %ld, n = %ld, times: %d", cent_calc_times * CENTRALITY_TIME_CALC, maxIpIndex+1, times);

    // Output to centrality-file
    // - Assignments
    const csi * const vecP = vec->p;
    const csi * const vecI = vec->i;
    const double * const vecX = vec->x;
    const double maxcent = vecX[vecP[0]];

    // - Output
    for (csi p = vecP[0]+1; p < vecP[1]; p++) {
#if CENTRALITY_TRAVIZ == 1
        cent_num_rows++;
        fprintf(centralityFile, "%ld" SEP_CHR, actTime.tv_sec);
#endif // CENTRALITY_TRAVIZ == 1
        const uint32_t ip = ntohl(centralityIps[vecI[p]-1]);
        const double val = vecX[p] / maxcent;
#if CENTRALITY_IP_FORMAT == 0
        fprintf(centralityFile, "%u" SEP_CHR "%2.10f" SEP_CHR, ip, val);
#elif CENTRALITY_IP_FORMAT == 1
        fprintf(centralityFile, "0x%08" B2T_PRIX32 SEP_CHR "%2.10f" SEP_CHR, ip, val);
#elif CENTRALITY_IP_FORMAT == 2
        fprintf(centralityFile, "%d.%d.%d.%d" SEP_CHR "%2.10f" SEP_CHR,
            (ip & 0xff000000) >> 24,
            (ip & 0x00ff0000) >> 16,
            (ip & 0x0000ff00) >>  8,
            (ip & 0x000000ff),
            val);
#endif // CENTRALITY_IP_FORMAT
#if CENTRALITY_TRAVIZ == 1
        fputc('\n', centralityFile);
#endif // CENTRALITY_TRAVIZ == 1
    }

    fputc('\n', centralityFile);

    fflush(centralityFile);

    // Free Matrices
    cs_spfree(vec);
    cs_spfree(graph);
}


void t2OnNewFlow(packet_t* packet UNUSED, unsigned long flowIndex) {
    const flow_t * const flowP = &flows[flowIndex];
    if (flowP->status & (L2_FLOW|L2_IPV6)) return;

    const ipPairs_t currFlowIps = {
        .srcIP = flowP->srcIP.IPv4.s_addr,
        .dstIP = flowP->dstIP.IPv4.s_addr
    };

    // Index of current connection
    unsigned long ipPairIndex = hashTable_lookup(connectionHashMap, (char*)&currFlowIps);
    if (ipPairIndex != HASHTABLE_ENTRY_NOT_FOUND) {
        // There is already an index, so increment the number of connections
        centralityIpPairs[ipPairIndex].numberOfConnections++;
        return;
    }

    // There was no Index found, so this is the first directed connection from srcIP to dstIP
    // Make a new HashMap entry and store the information in the Array for usage on application termination
    ipPairIndex = hashTable_insert(connectionHashMap, (char*)&currFlowIps);

    if (ipPairIndex == HASHTABLE_ENTRY_NOT_FOUND) {
        if (!(centAStat & CIPP_HFLL)) {
            T2_PWRN(plugin_name, "%s HashMap full", connectionHashMap->name);
            centAStat = CIPP_HFLL;
        }
        return;
    }

    if (centAStat & CIPP_HFLL) {
        T2_PWRN(plugin_name, "%s HashMap free", connectionHashMap->name);
        centAStat &= ~CIPP_HFLL;
    }

    if (ipPairIndex > maxIpPairIndex) maxIpPairIndex = ipPairIndex;

    /*----------- IP HASHTABLE LOOKUP-------------- */

    // Check srcIP
    unsigned long ipIndex = hashTable_lookup(centralityIpHashMap, (char*)&currFlowIps.srcIP);
    if (ipIndex == HASHTABLE_ENTRY_NOT_FOUND) {
        // The current _srcIP_ appears for the first time
        // => 1. Add it to the HashTable
        ipIndex = hashTable_insert(centralityIpHashMap, (char*)&currFlowIps.srcIP);
        if (ipIndex == HASHTABLE_ENTRY_NOT_FOUND) {
            if (!(centAStat & CIP_HFLL)) {
                T2_PWRN(plugin_name, "%s HashMap full", centralityIpHashMap->name);
                centAStat = CIP_HFLL;
            }
            return;
        }

        if (centAStat & CIP_HFLL) {
            T2_PWRN(plugin_name, "%s HashMap free", centralityIpHashMap->name);
            centAStat = ~CIP_HFLL;
        }

        // => 2. Add it to the IPlist
        centralityIps[ipIndex] = currFlowIps.srcIP;
    }

    // => Add srcIpIndex to storage-array
    centralityIpPairs[ipPairIndex].srcIP_ID = ipIndex;
    if (ipIndex > maxIpIndex) maxIpIndex = ipIndex;

    // Check dstIP
    if ((ipIndex = hashTable_lookup(centralityIpHashMap, (char*)&currFlowIps.dstIP)) == HASHTABLE_ENTRY_NOT_FOUND) {
        // The current _dstIP_ appears for the first time
        // => 1. Add it to the HashTable
        ipIndex = hashTable_insert(centralityIpHashMap, (char*)&currFlowIps.dstIP);
        if (ipIndex == HASHTABLE_ENTRY_NOT_FOUND) {
            if (!(centAStat & CIP_HFLL)) {
                T2_PWRN(plugin_name, "%s HashMap full", centralityIpHashMap->name);
                centAStat = CIP_HFLL;
            }
            return;
        }

        if (centAStat & CIP_HFLL) {
            T2_PWRN(plugin_name, "%s HashMap free", centralityIpHashMap->name);
            centAStat = ~CIP_HFLL;
        }

        // => 2. Add it to the IPlist
        centralityIps[ipIndex] = currFlowIps.dstIP;
    }

    // => Add dstIpIndex to storage-array
    centralityIpPairs[ipPairIndex].dstIP_ID = ipIndex;
    if (ipIndex > maxIpIndex) maxIpIndex = ipIndex;

    /*------------/IP HASHTABLE LOOKUP--------------*/

    centralityIpPairs[ipPairIndex].numberOfConnections = 1;
#if CENTRALITY_TIME_CALC != 0
    centralityIpPairs[ipPairIndex].subConnections = 0;
#endif // CENTRALITY_TIME_CALC != 0
#if CENTRALITY_MATRIXENTRIES == 2
    centralityIpPairs[ipPairIndex].sentBytes = 0;
#elif CENTRALITY_MATRIXENTRIES == 3
    centralityIpPairs[ipPairIndex].byteAsym = 0;
#elif CENTRALITY_MATRIXENTRIES == 4
    centralityIpPairs[ipPairIndex].sentPkts = 0;
#elif CENTRALITY_MATRIXENTRIES == 5
    centralityIpPairs[ipPairIndex].pktAsym = 0;
#endif // CENTRALITY_MATRIXENTRIES
}


void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf UNUSED) {
    const flow_t * const flowP = &flows[flowIndex];
    if (flowP->status & (L2_FLOW|L2_IPV6)) return;

    const ipPairs_t currFlowIps = {
        .srcIP = flowP->srcIP.IPv4.s_addr,
        .dstIP = flowP->dstIP.IPv4.s_addr
    };

    // Check if there was a beginning of this flow...
    const unsigned long ipPairIndex = hashTable_lookup(connectionHashMap, (char*)&currFlowIps);
    if (ipPairIndex == HASHTABLE_ENTRY_NOT_FOUND) {
        if (!centAStat) T2_PWRN(plugin_name, "Flow %lu has no IP pair index in connectionHashMap", flowIndex);
    } else {
        ipPairsConnections_t *ciP = &centralityIpPairs[ipPairIndex];
        if (ciP->numberOfConnections == ciP->subConnections) {
            if (UNLIKELY(hashTable_remove(connectionHashMap, (char*) &currFlowIps) == HASHTABLE_ENTRY_NOT_FOUND)) {
                T2_PERR(plugin_name, "failed to remove data from connectionHashMap");
                exit(EXIT_FAILURE);
            }
#if CENTRALITY_TIME_CALC != 0
            goto e;
#else // CENTRALITY_TIME_CALC == 0
            return;
#endif // CENTRALITY_TIME_CALC
        }

        // Increment connections to subtract by 1
        ciP->subConnections++;

        // Check if there are more flows terminated than started...
        if (ciP->numberOfConnections < ciP->subConnections) {
            char srcIP[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(flowP->srcIP), srcIP, INET_ADDRSTRLEN);
            char dstIP[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(flowP->dstIP), dstIP, INET_ADDRSTRLEN);
            T2_PWRN(plugin_name, "Connection %lu between %s and %s has no beginning (not passed t2OnNewFlow()), flowInd=%ld, findex=%" PRIu64,
                    ipPairIndex, srcIP, dstIP, flowIndex, flowP->findex);
        }

#if CENTRALITY_MATRIXENTRIES >= 2
        const bSFlow_t * const bSFlowP = &bSFlow[flowIndex]; // Get basicStats info
#endif // CENTRALITY_MATRIXENTRIES >= 2

#if CENTRALITY_MATRIXENTRIES == 2
        // Add the bytes sent information to the host
        ciP->sentBytes += bSFlowP->numTBytes;
#elif CENTRALITY_MATRIXENTRIES == 3
        // store the num of bytes of the opposite flow
        const int64_t numTBytesO = (FLOW_HAS_OPPOSITE(flowP) ? bSFlow[flowP->oppositeFlowIndex].numTBytes : 0);
        // Add the byte asymmetry sent information to the host
        const float byteAsym = (numTBytesO > 0) ? (bSFlowP->numTBytes - numTBytesO) / (float) (bSFlowP->numTBytes + numTBytesO) : 0;
        ciP->byteAsym += byteAsym+1;
#elif CENTRALITY_MATRIXENTRIES == 4
        ciP->sentPkts += bSFlowP->numTPkts;
#elif CENTRALITY_MATRIXENTRIES == 5
        // store the num of packets of the opposite flow
        const int64_t numTPktsO = (FLOW_HAS_OPPOSITE(flowP) ? bSFlow[flowP->oppositeFlowIndex].numTPkts : 0);
        // Add the packets asymmetry sent information to the host
        const float pktAsym = (numTPktsO > 0) ? (bSFlowP->numTPkts - numTPktsO) / (float) (bSFlowP->numTPkts + numTPktsO) : 0;
        ciP->pktAsym += pktAsym+1;
#endif // CENTRALITY_MATRIXENTRIES
    }

#if CENTRALITY_TIME_CALC != 0
e:
    // Check if already CENTRALITY_TIME_CALC seconds passed (in dump-time)
    //T2_PINF(plugin_name, "actTime: %lu, lastCalcTime: %lu, diff: %lu", actTime.tv_sec, lastCalcTime, actTime.tv_sec - lastCalcTime);
    if (actTime.tv_sec - lastCalcTime >= CENTRALITY_TIME_CALC) {
        //T2_PINF(plugin_name, "yup diff = %lu, times = %lu", actTime.tv_sec - lastCalcTime, cent_calc_times);
        lastCalcTime = actTime.tv_sec;
        // Increment the counter for output and the check above
        //cent_calc_times++;
        // Calculate the centrality with the values until CENTRALITY_TIME_CALC * cent_calc_times seconds in dump-time
        calculateEigenvectorCentrality(maxIpIndex, maxIpPairIndex, centralityIpPairs);
    }
#endif // CENTRALITY_TIME_CALC
}


void t2PluginReport(FILE *stream) {
    if (centAStat) {
        T2_FPLOG(stream, plugin_name, "Anomaly flags: 0x%02" B2T_PRIX8, centAStat);
    }
}


void t2Finalize() {
    // Increment Counter (for later use in MATLAB / Gnuplot -> no zero values as index)
    //cent_calc_times++;

    // if CENTRALITY_TIME_CALC == 0: Calculate the Centrality over the whole dump
    // if CENTRALITY_TIME_CALC > 0: Calculate the Centrality over (dump-end-time)-1*CENTRALITY_TIME_CALC seconds
    calculateEigenvectorCentrality(maxIpIndex, maxIpPairIndex, centralityIpPairs);

    /* --------------- Free Memory ----------------*/
    if (LIKELY(centralityFile != NULL)) {
#if CENTRALITY_TRAVIZ == 1
        fseek(centralityFile, 0, SEEK_SET);
        fprintf(centralityFile, "%s %" PRIu64 " time IP centrality", HDR_CHR, cent_num_rows);
#endif // CENTRALITY_TRAVIZ == 1
        fclose(centralityFile);
    }

#if CENTRALITY_MATRIXFILE == 1
    if (LIKELY(matrixFile != NULL)) fclose(matrixFile);
#endif // CENTRALITY_MATRIXFILE

    // Free HashTables
    hashTable_destroy(connectionHashMap);
    hashTable_destroy(centralityIpHashMap);

    // Free arrays
    free(centralityIpPairs);
    free(centralityIps);
}
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
