/*
 * main.h
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

#ifndef T2_MAIN_H_INCLUDED
#define T2_MAIN_H_INCLUDED

#include <pcap/pcap.h>              // for bpf_program, pcap_compile, pcap_geterr, pcap_setfilter, pcap_t
#include <signal.h>                 // for sigset_t, sig_atomic_t
#include <stdbool.h>                // for bool
#include <stdint.h>                 // for uint16_t, uint32_t, uint64_t, uint8_t
#include <stdlib.h>                 // for exit, EXIT_FAILURE
#include <string.h>                 // for strlen

#include "binaryValue.h"            // for binary_value_t
#include "flow.h"                   // for flow_t
#include "fsutils.h"                // for file_manager_t
#include "hashTable.h"              // for hashMap_t
#include "loadPlugins.h"            // for t2_plugin_array_t
#include "networkHeaders.h"         // for IPV6_ACTIVATE, L3_GRE, L3_ICMP
#include "outputBuffer.h"           // for outputBuffer_t
#include "proto/ethertype.h"        // for ETHERTYPE_ARP, ETHERTYPE_IP, ETHE...
#include "t2log.h"                  // for T2_ERR
#include "tranalyzer.h"             // for BPF_OPTIMIZE, SUBNET_INIT, DIFF_R...

#if SUBNET_INIT
#include "subnetHL4.h"  // for subnettable4_t
#include "subnetHL6.h"  // for subnettable6_t
#endif // SUBNET_INIT


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

// Packet mode (-s option)
#define SPKTMD_PKTNO    1 // Print the packet number
#define SPKTMD_PCNTC    1 // Print payload as characters
#define SPKTMD_PCNTH    0 // Print payload as hex

#define SPKTMD_PCNTL    4 // 0: Print the full payload of the packet
                          // 1: Print payload from L2
                          // 2: Print payload from L3
                          // 3: Print payload from L4
                          // 4: Print payload from L7

#define SPKTMD_BOPS  0x00 // Operations on content (requires SPKTMD_PCNTH == 1):
                          //    0x00: MSB (default)
                          //    0x01: LSB, Bit inverse
                          //    0x02: Nibble SWAP, MSB
                          //    0x03: Nibble SWAP, LSB
                          //    0x10: Shift right
                          //    0x20: shift from last byte into extra byte if 0x10

//#define SPKTMD_BSHFT_PA  5 // Bitshift byte pos End
//#define SPKTMD_BSHFT_PE 35 // Bitshift byte pos End
#define SPKTMD_BSHFT_POS 5 // Shift SPKTMD_BSHFT_POS-1 at 8-SPKTMD_BSHFT into following bytes
#define SPKTMD_BSHFT     2 // Bitshift requires (SPKTMD_BOPS & 0x10)

// Monitoring mode
#define MONINTTHRD     1   // Monitoring: Threaded interrupt handling.
#define MONINTBLK      0   // Monitoring: Block interrupts in main loop during packet processing, disables MONINTTHRD.
#define MONINTPSYNC    1   // Monitoring: 1: pcap main loop synchronized printing. 0: Interrupt printing.
#define MONINTTMPCP    0   // Monitoring: 1: pcap time base, 0: real time base.
#define MONINTTMPCP_ON 0   // Monitoring: Startup monitoring 1: on 0: off; if (MONINTTMPCP == 0)
#define MONINTV        1.0 // Monitoring: GI_ALRM: MONINTV >= 1.0 sec interval of monitoring output.
#define POLLENV        0   // Monitoring: change monitoring interval via env var $T2MTIME

// Monitoring mode protocol stat
#define MONPROTMD 1 // Monitoring: 0: Protocol numbers; 1: Protocol names (L3 only)
#define MONPROTL2 ETHERTYPE_ARP,ETHERTYPE_RARP
#define MONPROTL3 L3_TCP,L3_UDP,L3_ICMP,L3_ICMP6,L3_SCTP
#define MONPROTFL "proto.txt"

#define DPDK_MP   0 // Use DPDK multi-process mode instead of libpcap

// statistics summary min max
#define MIN_MAX_ESTIMATE 0   // min max bandwidth statistics
#define MMXLAGTMS        0.1 // Min Max interval [s]
#define MMXNO0           0   // 1: Suppress 0 in MIN estimation

/* +++++++++++++++++++++ ENV / RUNTIME - conf Variables +++++++++++++++++++++ */

// Configure packet mode as hex
#define SPKTMD_PCNTH_PREF "0x" // Prefix to add to every byte ("" -> ab cd instead of 0xab 0xcd)
#define SPKTMD_PCNTH_SEP  " "  // Byte separator ("," -> 0xab,0xcd instead of 0xab 0xcd)

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


#define T2_APPNAME      "Tranalyzer"
#define T2_PACKAGE      "tranalyzer"
#define T2_VERSION      "0.9.3"
#define T2_CODENAME     "Anteater"
#define T2_RELEASE      "Cobra"
#define T2_APPSTRING    T2_APPNAME " " T2_VERSION

#if DIFF_REPORT == 1
#define REPTYPE 'D'
#else // DIFF_REPORT == 0
#define REPTYPE 'A'
#endif // DIFF_REPORT

#define REPORT_SECTION_L2 'B'
#define REPORT_SECTION_L3 'C'
#define REPORT_SECTION_PL 'P'

#define REPORT_HIST_HDR \
    "%repTyp\tstartTime\ttotFIndex\tnumFlows\tnumAFlows\t" \
    "numBFlows\tnumPkts\tnumAPkts\tnumBPkts\tnumV4Pkts\t" \
    "numV6Pkts\tnumVxPkts\tnumBytes\tnumABytes\tnumBBytes\t" \
    "numFrgV4Pkts\tnumFrgV6Pkts\tnumAlarms\tbytesOnWire\trawBytesOnWire\t" \
    "padBytesOnWire\tcorrReplFlows\ttotalRmFlows\tllcPkts\tgrePkts\t" \
    "teredoPkts\tayiyaPkts\tglobalWarn\n"

// Convenience macro to improve readability of configuration flags
#define T2_YES 1
#define T2_NO  0

// global core defines

// globalInt
#define GI_DIE  0x0000
#define GI_EXIT 0x0001
#define GI_RUN  0x000f
#define GI_RPRT 0x0010
#define GI_USR1 0x0100
#define GI_USR2 0x0200
#define GI_ALRM 0x0400

#define GI_USR (GI_USR1 | GI_USR2)

#define GI_TERM_THRES (GI_EXIT + 2) // after n-times CTRL+C keystroke hit or remote SIGINT, kill the process
#define GI_INIT (GI_TERM_THRES & GI_RUN)

// internal pcap

#define PCAP_MAGIC_L    0xa1b2c3d4
#define PCAP_MAGIC_B    0xd4c3b2a1
#define PCAP_MAGIC_NS_L 0xa1b23c4d // Nanoseconds
#define PCAP_MAGIC_NS_B 0x4d3cb2a1 // Nanoseconds
#define PCAPNG          0x0a0d0d0a
#define PCAPNG_MAGIC_L  0x1a2b3c4d
#define PCAPNG_MAGIC_B  0x4d3c2b1a

// capture types 16 Bit
#define IFACE       0x0001 // -i option
#define CAPFILE     0x0002 // -r option
#define LISTFILE    0x0004 // -R option
#define DIRFILE     0x0008 // -D option
#define OFILELN     0x0010 // -W option
#define PKTFILE     0x0020 // -s option
#define LOGFILE     0x0040 // -l option
#define FILECNFLCT  0x0080 // Error: more than one input source provided
#define WSTDOUT     0x0100 // indicates that -w/-W option was '-' (stdout)
#define WFINDEX     0x1000 // -W option
#define MONFILE     0x2000 // -m option

// One of IFACE, CAPFILE, LISTFILE or DIRFILE is required
#define CAPTYPE_REQUIRED 0x000f

// Only one of IFACE, CAPFILE, LISTFILE or DIRFILE is allowed
#define CAPTYPE_ERROR(c, v) (((c) & CAPTYPE_REQUIRED) > (v))

// Macros

// 's' can be a pointer to the packet or flow structure
#define T2_SET_STATUS(s, flag) { \
    (s)->status |= (flag); \
    globalWarn |= (flag); \
}

#define BPFSET(captureDescriptor, bpfCommand) { \
    if (bpfCommand && strlen(bpfCommand) > 0) { \
        struct bpf_program bpfProgram; \
        if (pcap_compile(captureDescriptor, &bpfProgram, bpfCommand, BPF_OPTIMIZE, 0) == -1) { \
            T2_ERR("pcap_compile failed: '%s' is not a valid BPF: %s", bpfCommand, pcap_geterr(captureDescriptor)); \
            if (capType & DIRFILE) T2_ERR("-D option requires \"\" for regex, RTFM"); \
            exit(EXIT_FAILURE); \
        } \
        if (pcap_setfilter(captureDescriptor, &bpfProgram) == -1) { \
            T2_ERR("pcap_setfilter failed: %s", pcap_geterr(captureDescriptor)); \
            exit(EXIT_FAILURE); \
        } \
    } \
}

// bit shift constants
#define SPKTMD_BSHFT_MSK  (0xff << (8-SPKTMD_BSHFT))
#define SPKTMD_BSHFT_AMSK (0xff << SPKTMD_BSHFT)

// global thread variables
#if MONINTTHRD == 1
extern volatile sig_atomic_t globalInt; // global main/thread interrupt register
#else // MONINTTHRD == 0
extern volatile uint32_t globalInt;     // global interrupt register
#endif // MONINTTHRD

//extern uint32_t globalProt; // global status and warning register
extern uint64_t globalWarn; // global status and warning register

#if ALARM_MODE == 1
extern unsigned char supOut; // suppress output
#endif // ALARM_MODE == 1

#if (FORCE_MODE == 1 || FDURLIMIT > 0)
extern unsigned long num_rm_flows;
//extern flow_t *rm_flows[HASHCHAINTABLE_BASE_SIZE];
extern flow_t *rm_flows[10];
#endif // (FORCE_MODE == 1 || FDURLIMIT > 0)

extern flow_t lruHead, lruTail; // front and tail lru flows. Are unused and don't contain values
#if DPDK_MP == 0
extern pcap_t *captureDescriptor; // pcap handler
#else // DPDK_MP != 0
extern int dpdk_num_procs; // number of processes in multi-process DPDK mode
extern int dpdk_proc_id;   // process ID in multi-process DPDK mode
#endif // DPDK_MP == 0

extern t2_plugin_array_t *t2_plugins;

extern binary_value_t *main_header_bv;
extern flow_t *flows;
extern hashMap_t *mainHashMap;
extern outputBuffer_t *main_output_buffer;
extern file_manager_t *t2_file_manager;

extern struct timeval actTime;
extern char *last_err;

extern char *fileNumP, fileNumB[21];
extern uint32_t fileNum;      // -D option, incremental file ID
extern uint32_t fileNumE;     // -D option, final file ID
extern uint8_t numType;       // -D option, trailing 0?
extern int fNumLen, fNumLen0; // -D option, Number length
extern char *pDot;            // -D option, postion of '.'
extern char *globFName;       // -D

#if USE_PLLIST > 0
extern char *pluginList;    // -b option: plugin loading list
#endif // USE_PLLIST > 0
extern FILE *dooF;          // -l option: end report file
extern char *pluginFolder;  // -p option
extern FILE *sPktFile;      // -s option: packet file
extern uint32_t sensorID;   // -x option
extern double oFragFsz;     // -W option
extern uint64_t oFileNumB;  // -W option
extern char *capName;       // -D, -i, -r and -R option
extern uint16_t capType;    // -D, -i, -l, -r, -s and -W options
extern char *baseFileName;  // base file name for all generated files
extern char *esomFileName;  // for pcapd

extern char *cmdline;       // command line buffer

extern size_t baseFileName_len;
extern size_t pluginFolder_len;

extern uint64_t captureFileSize;

#if SUBNET_INIT != 0
extern void *subnetTableP[2];
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
extern subnettable4_t *subnetTable4P;
#endif
#if IPV6_ACTIVATE > 0
extern subnettable6_t *subnetTable6P;
#endif
#endif // SUBNET_INIT != 0

#if FRAGMENTATION >= 1
extern hashMap_t *fragPendMap;
extern unsigned long *fragPend;
#endif // FRAGMENTATION >= 1

extern char *bpfCommand; // BPF filter command
extern uint32_t hashFactor;

typedef struct timeout_s {
    float timeout; // the timeout value in seconds
    flow_t flow;   // a sentinel flow
    struct timeout_s *next;
} timeout_t;

void cycleLRULists();

// Adds a new timeout handler to the main timeout manager
void timeout_handler_add(float timeout);

// -R option

typedef struct caplist_elem_s {
    uint64_t size;
    char *name;
    struct caplist_elem_s *next;
} caplist_elem_t;

typedef struct {
    uint64_t size;
    uint32_t num_files;
    caplist_elem_t *file_list;
} caplist_t;

extern caplist_t *caplist;
extern caplist_elem_t *caplist_elem;
extern uint32_t caplist_index;

bool ckpcaphdr(const char * const pcapname);
void printGStats();

#if HASH_AUTOPILOT == 1
void lruRmLstFlow();
#endif

#if FDURLIMIT > 0
flow_t *removeFlow(flow_t *aFlow);
void lruPrintFlow(const flow_t * const flowP) __attribute__((__nonnull__(1)));
#endif // FDURLIMIT > 0

sigset_t t2_get_sigset();
void terminate() __attribute__((__noreturn__));

#endif // T2_MAIN_H_INCLUDED
