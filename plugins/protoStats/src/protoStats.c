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

#include "protoStats.h"
#include <errno.h>      // for errno


// Structs

typedef struct {
    uint64_t pkts;
    uint64_t bytes;
} port_usage_t;


// Static variables

static port_usage_t tcpPortUsage[L4PORTMAX+1];
static port_usage_t udpPortUsage[L4PORTMAX+1];

#if PST_UDPLITE_STAT == 1
static port_usage_t udplitePortUsage[L4PORTMAX+1];
#endif // PST_UDPLITE_STAT == 1

#if PST_SCTP_STAT == 1
static port_usage_t sctpPortUsage[L4PORTMAX+1];
#endif // PST_SCTP_STAT == 1

#if PST_ETH_STAT == 1
static char l2_ethname[L2ETHTYPEMAX+1][L2ETHMAXLEN+1];
#endif // PST_ETH_STAT == 1

static char tcp_portname[L4PORTMAX+1][L4PORTMAXLEN+1];
static char udp_portname[L4PORTMAX+1][L4PORTMAXLEN+1];


// Macros

#define PS_PRINT_L4PROTO(file, name, proto, portUsage, portName) { \
    T2_CONV_NUM(numPacketsL3[proto], str); \
    fprintf(file, "\n\n# Total %s packets: %" PRIu64 "%s [%.02f%%]\n", name, \
            numPacketsL3[proto], str, 100.0 * numPacketsL3[proto] / (double)numPackets); \
    T2_CONV_NUM(numBytesL3[proto], str); \
    fprintf(file, "# Total %s bytes: %" PRIu64 "%s [%.02f%%]\n", name, \
            numBytesL3[proto], str, 100.0 * numBytesL3[proto] / (double)bytesProcessed); \
    if (numPacketsL3[proto] > 0) { \
        const double percent_pkts = 100.0f / (double) numPacketsL3[proto]; \
        const double percent_bytes = 100.0f / (double) numBytesL3[proto]; \
        fprintf(file, "# %s Port\t%30s\t%30s\tDescription\n", name, "Packets", "Bytes"); \
        for (i = 0; i <= L4PORTMAX; i++) { \
            if (portUsage[i].pkts > 0) { \
                fprintf(file, "%5" PRIuFAST32 "\t" \
                        "%20" PRIu64 " [%6.02f%%]\t" /* packets */ \
                        "%20" PRIu64 " [%6.02f%%]\t" /* bytes   */ \
                        "%s\n", i, \
                        portUsage[i].pkts, portUsage[i].pkts * percent_pkts, \
                        portUsage[i].bytes, portUsage[i].bytes * percent_bytes, \
                        portName[i]); \
            } \
        } \
    } \
}


// Tranalyzer Plugin functions

T2_PLUGIN_INIT("protoStats", "0.9.3", 0, 9);


//void t2Init() {
//  // Nothing to do
//}


void t2OnLayer4(packet_t *packet, unsigned long flowIndex) {
    const flow_t * const flowP = &flows[flowIndex];
    const uint_fast16_t dport = FLOW_IS_B(flowP) ? flowP->srcPort : flowP->dstPort;

    // check for encapsulated packet
    switch (packet->l4Proto) {

        case L3_TCP:
            tcpPortUsage[dport].pkts++;
            tcpPortUsage[dport].bytes += packet->snapLen;
            break;

        case L3_UDP:
            udpPortUsage[dport].pkts++;
            udpPortUsage[dport].bytes += packet->snapLen;
            break;

#if PST_UDPLITE_STAT == 1
        case L3_UDPLITE:
            udplitePortUsage[dport].pkts++;
            udplitePortUsage[dport].bytes += packet->snapLen;
            return;
#endif // PST_UDPLITE_STAT == 1

#if PST_SCTP_STAT == 1
        case L3_SCTP:
            sctpPortUsage[dport].pkts++;
            sctpPortUsage[dport].bytes += packet->snapLen;
            break;
#endif // PST_SCTP_STAT == 1

        default:
            return; // no ports
    }
}


void t2Finalize() {
    FILE *file;
    uint_fast32_t i;
    char s[L4PORTMAXLEN+1];

    t2_env_t env[ENV_PST_N] = {};
#if ENVCNTRL > 0
    t2_get_env(PLUGIN_SRCH, ENV_PST_N, env);
#else // ENVCNTRL == 0
    T2_SET_ENV_STR(PST_SUFFIX);
    T2_SET_ENV_STR(PST_L2ETHFILE);
    T2_SET_ENV_STR(PST_PORTFILE);
    T2_SET_ENV_STR(PST_PROTOFILE);
#endif // ENVCNTRL

#if PST_ETH_STAT == 1
    // Read ethernet type decoder file
    file = t2_fopen_in_dir(pluginFolder, T2_ENV_VAL(PST_L2ETHFILE), "r");
    if (LIKELY(file != NULL)) {
        uint32_t num1, num2;
        char ss[L2ETHMAXLEN+1];
        while (fgets(s, L2ETHMAXLEN, file)) {
            const char *p = strchr(s, '-');
            if (p && p - s < 8) {
                sscanf(s, "0x%04x-0x%04x\t%" STR(L2ETHMAXLEN) "[^\n\t]", &num1, &num2, ss);
                for (i = num1; i <= num2; i++) {
                    memcpy(l2_ethname[i], ss, strlen(ss)+1);
                }
            } else {
                sscanf(s, "0x%04x\t%" STR(L2ETHMAXLEN) "[^\n\t]", &num1, ss);
                memcpy(l2_ethname[num1], ss, strlen(ss)+1);
            }
        }
        fclose(file);
    }
#endif // PST_ETH_STAT == 1

    int z;
    char ip_protname[IPPROTMAX+1][IPPROTMAXLEN+1] = {};

    // Read proto decoder file
    file = t2_fopen_in_dir(pluginFolder, T2_ENV_VAL(PST_PROTOFILE), "r");
    if (LIKELY(file != NULL)) {
        uint32_t num;
        for (i = 0; i <= IPPROTMAX; i++) {
            z = fscanf(file, "%" SCNu32 "\t%*" STR(L4PORTMAXLEN) "[^\n\t]\t%" STR(IPPROTMAXLEN) "[^\n\t]", &num, ip_protname[i]);
            if (UNLIKELY(z != 2)) {
                T2_PWRN(plugin_name, "Failed to read line %" PRIuFAST32 " of file '%s': %s", i, T2_ENV_VAL(PST_PROTOFILE), strerror(errno));
                continue;
            }
        }
        fclose(file);
    }

    // Read port decoder file
    file = t2_fopen_in_dir(pluginFolder, T2_ENV_VAL(PST_PORTFILE), "r");
    if (LIKELY(file != NULL)) {
        char l4P[4];
        while (1) {
            z = fscanf(file, "%" SCNuFAST32 "\t%3[^\n\t]\t%*" STR(L4PORTMAXLEN) "[^\n\t]\t%" STR(L4PORTMAXLEN) "[^\n\t]", &i, l4P, s);
            if (z <= 0) break;
            if (strncmp("udp", l4P, 3) == 0) t2_strcpy(udp_portname[i], s, sizeof(udp_portname[i]), T2_STRCPY_TRUNC);
            else if (strncmp("tcp", l4P, 3) == 0) t2_strcpy(tcp_portname[i], s, sizeof(tcp_portname[i]), T2_STRCPY_TRUNC);
        }
        fclose(file);
    }

    // open protocol statistics file
    file = t2_fopen_with_suffix(baseFileName, T2_ENV_VAL(PST_SUFFIX), "w");
    if (UNLIKELY(!file)) exit(EXIT_FAILURE);

    char str[64];
    const uint64_t numBytes = bytesProcessed;
    const double percent_pkts  = 100.0f / (double)numPackets;
    const double percent_bytes = 100.0f / (double)numBytes;

#if PST_ETH_STAT == 1
    T2_CONV_NUM(numPackets, str);
    fprintf(file, "# Total packets: %" PRIu64 "%s\n", numPackets, str);
    T2_CONV_NUM(numBytes, str);
    fprintf(file, "# Total bytes: %" PRIu64 "%s\n", numBytes, str);
    fprintf(file, "# L2/3 Protocol\t%30s\t%30s\tDescription\n", "Packets", "Bytes");

    // print protocol usage
    for (i = 0; i <= L2ETHTYPEMAX; i++) {
        if (numPacketsL2[i] > 0) {
            fprintf(file, "0x%04" B2T_PRIXFAST32 "\t"
                    "%20" PRIu64 " [%6.02f%%]\t"    // packets
                    "%20" PRIu64 " [%6.02f%%]\t"    // bytes
                    "%s\n", i,
                    numPacketsL2[i], numPacketsL2[i] * percent_pkts,
                    numBytesL2[i], numBytesL2[i] * percent_bytes,
                    l2_ethname[i]);
        }
    }
    fprintf(file, "\n\n");
#endif // PST_ETH_STAT == 1

#if (IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2)
    T2_CONV_NUM(numV4Packets, str);
    fprintf(file, "# Total IPv4 packets: %" PRIu64 "%s [%.02f%%]\n", numV4Packets, str, numV4Packets * percent_pkts);
#endif // (IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2)

#if IPV6_ACTIVATE > 0
    T2_CONV_NUM(numV6Packets, str);
    fprintf(file, "# Total IPv6 packets: %" PRIu64 "%s [%.02f%%]\n", numV6Packets, str, numV6Packets * percent_pkts);
#endif // IPV6_ACTIVATE > 0

    // print protocol usage
    fprintf(file, "# L4 Protocol\t%30s\t%30s\tDescription\n", "Packets", "Bytes");
    for (i = 0; i <= IPPROTMAX; i++) {
        if (numPacketsL3[i] > 0) {
            fprintf(file, "%3" PRIuFAST32 "\t"
                    "%20" PRIu64 " [%6.02f%%]\t"    // packets
                    "%20" PRIu64 " [%6.02f%%]\t"    // bytes
                    "%s\n", i,
                    numPacketsL3[i], numPacketsL3[i] * percent_pkts,
                    numBytesL3[i], numBytesL3[i] * percent_bytes,
                    ip_protname[i]);
        }
    }

    // print port usage
    PS_PRINT_L4PROTO(file, "TCP", L3_TCP, tcpPortUsage, tcp_portname);
    PS_PRINT_L4PROTO(file, "UDP", L3_UDP, udpPortUsage, udp_portname);

#if PST_UDPLITE_STAT == 1
    PS_PRINT_L4PROTO(file, "UDP-Lite", L3_UDPLITE, udplitePortUsage, udp_portname);
#endif // PST_UDPLITE_STAT == 1

#if PST_SCTP_STAT == 1
    PS_PRINT_L4PROTO(file, "SCTP", L3_SCTP, sctpPortUsage, tcp_portname);
#endif // PST_SCTP_STAT == 1

    fclose(file);

#if ENVCNTRL > 0
    t2_free_env(ENV_PST_N, env);
#endif // ENVCNTRL > 0
}
