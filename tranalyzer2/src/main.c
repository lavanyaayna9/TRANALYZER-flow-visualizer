/*
 * main.c
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

#include "main.h"

//#include <bsd/string.h>         // for strnstr
#include <ctype.h>              // for isascii
#include <errno.h>              // for errno
#include <float.h>              // for FLT_MIN
#include <getopt.h>             // for getopt_long, struct option, ...
#include <inttypes.h>           // for PRIu32, PRIu64, PRIu16, PRIu8
#include <math.h>               // for log, pow, INFINITY
#include <netinet/in.h>         // for INET6_ADDRSTRLEN
#include <pthread.h>            // for pthread_create, pthread_self
#include <pwd.h>                // for getpwnam
#include <sched.h>              // for sched_getcpu, cpu_set_t, CPU_SET
#include <stdio.h>              // for printf, fclose, fflush, fputs
#include <string.h>             // for strlen, strerror, strcmp, strcat, ...
#include <sys/resource.h>       // for getrusage, RUSAGE_SELF, getpriority
#include <sys/stat.h>           // for stat, S_IRWXU, S_ISDIR
#include <sys/time.h>           // for timeval, gettimeofday
#include <unistd.h>             // for optarg, getopt, optopt, optind
#include <wordexp.h>            // for wordexp, wordexp_t, wordfree

#if DPDK_MP != 0
#include <rte_common.h>
#include <rte_eal.h>
#include <rte_dev.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#endif // DPDK_MP != 0

#include "bin2txt.h"            // for B2T_PRIX16, B2T_PRIX64, HDR_CHR
#include "binaryValue.h"        // for binary_value_t, bv_append_bv
#include "fsutils.h"            // for mkpath, file_manager_t, file_manager_new, file_manager_destroy
#include "ioBuffer.h"           // for IO_BUFFERING
#include "loadPlugins.h"        // for t2_plugin_t, FOREACH_PLUGIN_DO
#include "memdebug.h"           // for memdebug_check_leak
#include "outputBuffer.h"       // for outputBuffer_append, outputBuf...
#include "packetCapture.h"      // for perPacketCallback
#include "subnetHL.h"           // for SUBNET_CNT, SUBNET_REV, SUBNET...
#include "t2log.h"              // for T2_ERR, T2_FINF, T2_FWRN, T2_WRN...
#include "t2utils.h"            // for t2_[cm]alloc, UNLIKELY, T2_CONV_NUM, t2_open...

#include "missing/missing.h"    // for strnstr


#define T2_PRINT_BANNER(file) \
    fputs("\n" \
          "                                    @      @                                    \n"  \
          "                                     |    |                                     \n"  \
          "===============================vVv==(a    a)==vVv===============================\n"  \
          "=====================================\\    /=====================================\n" \
          "======================================\\  /======================================\n" \
          "                                       oo                                       \n", \
          (file))

#define T2_CONF_REPORT(file) \
    T2_FINF(file, "Creating flows for %s%s%s%s%s%s", \
        (ETH_ACTIVATE > 0) ? "L2, " : "", \
        (LAPD_ACTIVATE == 1) ? "LAPD, " : "", \
        (IPV6_ACTIVATE == 2) ? "IPv4, IPv6" : \
            (IPV6_ACTIVATE == 1) ? "IPv6" : "IPv4", \
        (SCTP_ACTIVATE > 0) ? ", SCTP" : "", \
        (ALARM_MODE == 1) ? " [ALARM]" : "", \
        (FORCE_MODE == 1) ? " [FORCE]" : "")

#define T2_PRINT_GLOBALWARN(file) \
    if (globalWarn & L2SNAPLENGTH) T2_FWRN(file, "L2 header snapped"); \
    if (globalWarn & L3SNAPLENGTH) T2_FWRN(file, "L3 SnapLength < Length in IP header"); \
    if (globalWarn & L3HDRSHRTLEN) T2_FWRN(file, "L3 header snapped"); \
    if (globalWarn & L4HDRSHRTLEN) T2_FWRN(file, "L4 header snapped"); \
    if (globalWarn & LANDATTACK)   T2_FWRN(file, "Land attack"); \
    if (globalWarn & TIMEJUMP)     T2_FWRN(file, "Timestamp jump, probably due to multi-path packet delay or NTP operation"); \
    if (globalWarn & DUPIPID)      T2_FWRN(file, "Consecutive duplicate IP ID"); \
    if (globalWarn & PCAPSNPD)     T2_FWRN(file, "PCAP packet length > IO_BUFFER_MAX_MTU, caplen reduced"); \
    if (globalWarn & HDOVRN)       T2_FWRN(file, "Header description overrun"); \
    if (globalWarn & L3_IPVX)      T2_FWRN(file, "IPvX L3 header bogus packets"); \
    if (globalWarn & IPV4_HL_TOO_SHORT) { \
        T2_FWRN(file, "IPv4 header length < 20 bytes"); \
    } \
    if (globalWarn & IP_PL_MSMTCH) { \
        T2_FWRN(file, "IPv4/6 payload length > framing length"); \
    } \
    if (globalWarn & IPV4_FRAG_HDSEQ_ERR) { \
        T2_FWRN(file, "IPv4/6 fragmentation header packet missing%s", FRAG_HLST_CRFT ? "" : ", trailing packets ignored"); \
    } \
    if (globalWarn & IPV4_FRAG_PENDING) { \
        T2_FWRN(file, "IPv4/6 packet fragmentation sequence not finished"); \
    } \
    if (globalWarn & STPDSCT)      T2_FINF(file, "Stop dissecting: Clipped packet, unhandled protocol or subsequent fragment");\
    if (globalWarn & L2_FLOW)      T2_FINF(file, "Layer 2 flows"); \
    if (globalWarn & LAPD_FLOW)    T2_FINF(file, "LAPD flows"); \
    if (globalWarn & (L2_IPV4 | FS_IPV4_PKT)) { \
        T2_FINF(file, "IPv4%s", IPV6_ACTIVATE == 1 ? "" : " flows"); \
    } \
    if (globalWarn & (L2_IPV6 | FS_IPV6_PKT)) { \
        T2_FINF(file, "IPv6%s", IPV6_ACTIVATE == 0 ? "" : " flows"); \
    } \
    if (globalWarn & L4_SCTP) { \
        T2_FINF(file, "SCTP%s", SCTP_ACTIVATE == 0 ? "" : " flows"); \
    } \
    if (globalWarn & L2_NO_ETH)    T2_FINF(file, "No Ethernet header"); \
    if (globalWarn & L2_ARP)       T2_FINF(file, "ARP"); \
    if (globalWarn & L2_RARP)      T2_FINF(file, "RARP"); \
    if (globalWarn & L2_LLDP)      T2_FINF(file, "LLDP"); \
    if (globalWarn & L3_ETHIPF)    T2_FINF(file, "EtherIP"); \
    if (globalWarn & L2_VLAN)      T2_FINF(file, "VLAN encapsulation"); \
    if (globalWarn & FS_VLAN0)     T2_FINF(file, "VLAN ID 0 (priority tag)"); \
    if (globalWarn & IPV4_FRAG)    T2_FINF(file, "IPv4/6 fragmentation"); \
    if (globalWarn & L3_IPIP)      T2_FINF(file, "IPv4/6 in IPv4/6"); \
    if (globalWarn & L3_VXLAN)     T2_FINF(file, "VXLAN encapsulation"); \
    if (globalWarn & L3_GENEVE)    T2_FINF(file, "GENEVE encapsulation"); \
    if (globalWarn & L2_MPLS)      T2_FINF(file, "MPLS encapsulation"); \
    if (globalWarn & L2_L2TP)      T2_FINF(file, "L2TP encapsulation"); \
    if (globalWarn & L2_PPP)       T2_FINF(file, "PPP/HDLC encapsulation"); \
    if (globalWarn & L2_GRE)       T2_FINF(file, "GRE encapsulation"); \
    if (globalWarn & L2_ERSPAN)    T2_FINF(file, "ERSPAN encapsulation"); \
    if (globalWarn & L2_WCCP)      T2_FINF(file, "WCCP encapsulation"); \
    if (globalWarn & L3_AYIYA)     T2_FINF(file, "AYIYA tunnel"); \
    if (globalWarn & L3_GTP)       T2_FINF(file, "GTP tunnel"); \
    if (globalWarn & L3_TRDO)      T2_FINF(file, "Teredo tunnel"); \
    if (globalWarn & L3_CAPWAP)    T2_FINF(file, "CAPWAP/LWAPP tunnel"); \
    if (globalWarn & L3_IPSEC_AH)  T2_FINF(file, "IPsec AH"); \
    if (globalWarn & L3_IPSEC_ESP) T2_FINF(file, "IPsec ESP"); \
    if (globalWarn & L4_UPNP)      T2_FINF(file, "SSDP/UPnP"); \
    if (globalWarn & L7_SIPRTP)    T2_FINF(file, "SIP/RTP"); \
    if (globalWarn & L7_DTLS)      T2_FINF(file, "DTLS"); \
    if (globalWarn & TORADD)       T2_FINF(file, "Tor addresses"); \
    if (globalWarn & FL_ALARM)     T2_FINF(file, "IPAlarm");

#define T2_LOG_LINK_LAYER_TYPE(stream, captureDescriptor) { \
    const int linkType = ((DPDK_MP == 0) ? pcap_datalink(captureDescriptor) : 1 /* DLT_EN10MB */); \
    const char *dl_descr = pcap_datalink_val_to_description(linkType); \
    const char *dl_name = pcap_datalink_val_to_name(linkType); \
    if (LAPD_ACTIVATE == 1) { \
        /* libpcap does not have any name/description for DLT_LAPD... */ \
        if (linkType == DLT_LAPD) { \
            if (!dl_descr) dl_descr = "LAPD"; \
            if (!dl_name) dl_name = "LAPD"; \
        } \
    } \
    T2_FLOG(stream, "Link layer type: %s [%s/%d]", dl_descr, dl_name, linkType); \
}

// 24 = size of global pcap header,
// 16 = pcap header of every capture packet.
// (see http://wiki.wireshark.org/Development/LibpcapFileFormat)
#define T2_LOG_PERCENT(stream, nfiles, fsize) \
    fprintf(stream, "Percentage completed: %.2f%%\n", \
            100.0f * ((24 * (nfiles)) + bytesProcessed + (16 * numPackets)) / (double)fsize)


// global main/thread interrupt
#if MONINTTHRD == 1
volatile sig_atomic_t globalInt = GI_INIT;
#else // MONINTTHRD == 0
volatile uint32_t globalInt = GI_INIT;
#endif // MONINTTHRD == 0

uint64_t globalWarn;       // global warning & status register

#if DPDK_MP == 0
pcap_t *captureDescriptor; // pcap handler
#else // DPDK_MP != 0
int dpdk_num_procs = -1;
int dpdk_proc_id = -1;
static uint16_t dpdk_port_id;
static uint8_t reassembled[16 * 1024];
// timestamp values
//static int tsc_dynfield_offset = -1;
static uint64_t tsc_hz = 0;
static uint64_t tsc_init_value = 0;
#endif // DPDK_MP == 0

#if ALARM_MODE == 1
unsigned char supOut;      // suppress output
#endif // ALARM_MODE == 1

#if (FORCE_MODE == 1 || FDURLIMIT > 0)
unsigned long num_rm_flows;
flow_t *rm_flows[10];
#endif // (FORCE_MODE == 1 || FDURLIMIT > 0)

binary_value_t *main_header_bv;
file_manager_t *t2_file_manager;
flow_t *flows;
hashMap_t *mainHashMap;
outputBuffer_t *main_output_buffer;
t2_plugin_array_t *t2_plugins;

#if FRAGMENTATION == 1
hashMap_t *fragPendMap;
unsigned long *fragPend;
#endif // FRAGMENTATION == 1

uint64_t captureFileSize;
uint64_t hshFSize0;
uint64_t memmax0;
uint64_t totalfIndex; //, totalfIndex0;

// counter and monitoring statistics absolute/diff mode

uint64_t bytesOnWire, bytesOnWire0;
uint64_t bytesProcessed, bytesProcessed0;
uint64_t corrReplFlws, corrReplFlws0;
uint64_t maxNumFlows; //, maxNumFlows0;
uint64_t maxNumFlowsPeak; //, maxNumFlowsPeak0;
uint64_t numABytes, numABytes0;
uint64_t numAlarmFlows, numAlarmFlows0;
uint64_t numAlarms, numAlarms0;
uint64_t numAPackets, numAPackets0;
uint64_t numAYIYAPackets, numAYIYAPackets0;
uint64_t numBBytes, numBBytes0;
uint64_t numBPackets, numBPackets0;
#if FORCE_MODE == 1
uint64_t numForced, numForced0;
#endif // FORCE_MODE == 1
uint64_t numFragV4Packets, numFragV4Packets0;
uint64_t numFragV6Packets, numFragV6Packets0;
uint64_t numGREPackets, numGREPackets0;
uint64_t numLAPDPackets, numLAPDPackets0;
uint64_t numLLCPackets, numLLCPackets0;
uint64_t numPackets, numPackets0;
uint64_t numTeredoPackets, numTeredoPackets0;
uint64_t numL2Packets, numL2Packets0;
uint64_t numV4Packets, numV4Packets0;
uint64_t numV6Packets, numV6Packets0;
uint64_t numVxPackets, numVxPackets0;
uint64_t padBytesOnWire, padBytesOnWire0;
uint64_t rawBytesOnWire, rawBytesOnWire0;
uint64_t totalAFlows, totalAFlows0;
uint64_t totalBFlows, totalBFlows0;
uint64_t totalFlows, totalFlows0;
uint64_t totalIPv4Flows, totalIPv4Flows0;
uint64_t totalIPv6Flows, totalIPv6Flows0;
uint64_t totalL2Flows, totalL2Flows0;
#if DTLS == 1
uint64_t numDTLSPackets, numDTLSPackets0;
#endif // DTLS == 1

// global L2 protocols
uint64_t numBytesL2[65536], numBytes0L2[65536];
uint64_t numPacketsL2[65536], numPackets0L2[65536];

// global L3 protocols
uint64_t numBytesL3[256], numBytes0L3[256];
uint64_t numPacketsL3[256], numPackets0L3[256];

uint16_t maxHdrDesc, minHdrDesc = UINT16_MAX;
float avgHdrDesc;

#if PKT_CB_STATS == 1
double minCpuTime = FLT_MAX, maxCpuTime, avgCpuTime, varCpuTime;
#endif // PKT_CB_STATS == 1

// endreport max min bandwidth info
#if MIN_MAX_ESTIMATE > 0
double lagTm, bave, bvar;
uint64_t maxBytesPs, rawBytesW0;
uint64_t minBytesPs = UINT64_MAX;
uint64_t numSpl;
uint64_t numAPkts0, numBPkts0;
uint64_t numAByts0, numBByts0;
#endif // MIN_MAX_ESTIMATE > 0

// Min/Max A/B packet load
double pktALdMax = 0.0, pktALdMin = DBL_MAX;
double pktBLdMax = 0.0, pktBLdMin = DBL_MAX;

// VLAN, MPLS cnts
uint8_t mplsHdrCntMx;
uint8_t vlanHdrCntMx;

struct timeval actTime, startTime;
struct timeval startTStamp, startTStamp0;

// timer def interval and off
static struct itimerval ivalon = {
    .it_value.tv_sec  = (uint32_t)MONINTV,
    .it_value.tv_usec = (MONINTV - (uint32_t)MONINTV) * 1000000
};
static struct itimerval ivaloff;

char *last_err;

// parsing parameters
char *cmdline;                          // command line
char *capName;                          // -D, -i, -r and -R options
uint16_t capType;
char *pluginFolder;                     // -p option
#if USE_PLLIST > 0
char *pluginList;                       // -b option
#endif // USE_PLLIST > 0
char *baseFileName;                     // -w/-W options, prefix for all generated files
char *esomFileName;                     // -e option, for pcapd
FILE *dooF;                             // -l option, end report file
FILE *sPktFile;                         // -s option, packet file
uint32_t sensorID = T2_SENSORID;        // Sensor ID from central host or user
char *fileNumP, fileNumB[21];           // -D option
uint32_t fileNum;                       // -D option, incremental file ID
uint32_t fileNumE = UINT32_MAX;         // -D option, final file ID
uint8_t numType;                        // -D option, trailing 0?
int fNumLen, fNumLen0;                  // -D option, Number length
char *pDot, *pLn;                       // -D option, position of '.','_'
char *globFName;                        // -D option
double oFragFsz;                        // -W option
uint64_t oFileNumB;                     // -W option
char *bpfCommand;                       // bpf filter command
caplist_t *caplist;                     // -R option
caplist_elem_t *caplist_elem;           // -R option
uint32_t caplist_index;                 // -R option

static int32_t snapLen = SNAPLEN;       // -S option, snaplength
static int32_t liveBufSz = LIVEBUFSIZE; // -B option, live RX buffer size
static float monIntV = MONINTV;         // -M option, monitoring timout
static FILE *monFile;                   // -m option, monitoring report file

// Avoid multiple calls to strlen()
// (set in t2_set_baseFileName() and t2_set_pluginFolder())
size_t baseFileName_len;
size_t pluginFolder_len;


// static variables

#if MACHINE_REPORT == 1 || DIFF_REPORT == 1 || REPORT_HIST == 1
static const uint16_t monProtL2[] = { MONPROTL2 }; // Monitoring L2 proto array
static const uint8_t  monProtL3[] = { MONPROTL3 }; // Monitoring L3 proto array

#define NUMMONPL2 (sizeof(monProtL2) >> 1)
#define NUMMONPL3  sizeof(monProtL3)

#endif // MACHINE_REPORT == 1 || DIFF_REPORT == 1 || REPORT_HIST == 1

#if MACHINE_REPORT == 1 && MONPROTMD == 1
static char ipProtSn[256][16];
#endif

#if REPSUP == 1
static uint64_t numLstPackets; // for alive mode
#endif // REPSUP == 1

static timeout_t *timeout_list;

#if HASH_AUTOPILOT == 1 || DIFF_REPORT == 1 || REPORT_HIST == 1
static uint64_t totalRmFlows;
#endif

#if DIFF_REPORT == 1 || (HASH_AUTOPILOT == 1 && (VERBOSE > 0 || MACHINE_REPORT == 0))
static uint64_t totalRmFlows0;
#endif

#if SUBNET_INIT != 0
void *subnetTableP[2];
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
subnettable4_t *subnetTable4P;
#endif
#if IPV6_ACTIVATE > 0
subnettable6_t *subnetTable6P;
#endif
#endif // SUBNET_INIT != 0

#ifndef __APPLE__
static int cpu = -1;
#endif


// Static inline functions prototypes

static inline FILE *t2_create_pktfile();
static inline FILE *t2_open_logFile();
static inline FILE *t2_open_monFile();

static inline void t2_set_baseFileName();
static inline void t2_set_pluginFolder();

static inline void t2_setup_sigaction();

#if BLOCK_BUF == 0
static inline binary_value_t *buildHeaders();
#endif // BLOCK_BUF == 0

static inline void cycleLRUList(timeout_t *th);
static inline void printFlow(unsigned long flowIndex, uint8_t dir);
#if FDURLIMIT == 0
static inline void lruPrintFlow(const flow_t * const flowP) __attribute__((__nonnull__(1)));
static inline flow_t *removeFlow(flow_t *aFlow);
#endif // FDURLIMIT

#if VERBOSE > 0 || MACHINE_REPORT == 0
static inline void t2_print_report(FILE *stream, bool monitoring);
#endif

#if MACHINE_REPORT == 1
static inline void t2_machine_report_header(FILE *stream);
static inline void t2_machine_report(FILE *stream);
#endif // MACHINE_REPORT == 1

#if DIFF_REPORT == 1 && VERBOSE > 0
static inline void resetGStats0();
#endif

#if DIFF_REPORT == 1
static inline void updateGStats0();
#endif // DIFF_REPORT == 1

#if PID_FNM_ACT == 1
static inline void t2_create_pid_file();
static inline void t2_destroy_pid_file();
#endif // PID_FNM_ACT == 1

#if (MACHINE_REPORT == 1 && MONPROTMD == 1)
static inline void t2_load_proto_file();
#endif

#ifndef __APPLE__
static inline void t2_set_cpu(int cpu);
#endif // __APPLE__


// Static functions prototypes

static __attribute__((noreturn)) void t2_abort_with_help();
static void t2_usage();
static void t2_version();
static void t2_cleanup();
static char *copy_argv(char **argv);
static bool t2_validate_captype(uint16_t capType);
#if DPDK_MP == 0
static caplist_t *read_caplist(const char *filename) __attribute__((__nonnull__(1), __warn_unused_result__, __returns_nonnull__));
#if IO_BUFFERING == 0
static void mainLoop();
#endif // IO_BUFFERING == 0
#else // DPDK_MP != 0
static int lcore_main(void *arg __rte_unused);
#endif // DPDK_MP == 0
static void prepareSniffing();
static char *read_bpffile(const char *fname);

#if (MONINTTHRD == 1 && MONINTBLK == 0)
static void *intThreadHandler(void *arg);
#endif
static void sigHandler(int scode);

#if REPORT_HIST == 1
static void t2_restore_state();
static void t2_save_state();
#endif // REPORT_HIST == 1


static void t2_parse_options(int argc, char **argv) {

    if (UNLIKELY(argc == 1)) {
        t2_usage();
        exit(EXIT_FAILURE);
    }

    cmdline = copy_argv(&argv[0]);

    static const struct option t2_options[] = {

        /* Input arguments */

#if DPDK_MP == 0
#define T2_INPUT_OPTS "D:i:r:R:"

        { "input-regex", required_argument, 0, 'D' },
        { "interface"  , required_argument, 0, 'i' },
        { "pcap"       , required_argument, 0, 'r' },
        { "pcap-list"  , required_argument, 0, 'R' },

#define T2_DPDK_OPTS ""
#else // DPDK_MP != 0
#define T2_INPUT_OPTS "i:"

        { "interface"  , required_argument, 0, 'i' },

#define T2_DPDK_OPTS "N:I:"

        { "num-procs"  , required_argument, 0, 'N' },
        { "proc-id"    , required_argument, 0, 'I' },
#endif // DPDK_MP == 0

        /* Output arguments */

#define T2_OUTPUT_OPTS "lmsw:W:"

        { "logfile"      , no_argument      , 0, 'l' },
        { "monfile"      , no_argument      , 0, 'm' },
        { "packets"      , no_argument      , 0, 's' },
        { "output-prefix", required_argument, 0, 'w' },
        { "output-regex" , required_argument, 0, 'W' },

        /* Optional arguments */

#define T2_OPT_OPTS "b:c:e:f:F:p:x:S:B:P:M:"

#if USE_PLLIST > 0
        { "plugin-list"  , required_argument, 0, 'b' },
#endif
#ifndef __APPLE__
        { "cpu"          , required_argument, 0, 'c' },
#endif
        { "pcapd"        , required_argument, 0, 'e' },
        { "hash-factor"  , required_argument, 0, 'f' },
        { "bpf-file"     , required_argument, 0, 'F' },
        { "plugin-folder", required_argument, 0, 'p' },
        { "sensor-id"    , required_argument, 0, 'x' },
        { "snaplen"      , required_argument, 0, 'S' },
        { "priority"     , required_argument, 0, 'P' },
        { "rx-bufsize"   , required_argument, 0, 'B' },
        { "mon-interval" , required_argument, 0, 'M' },

        /* Help and documentation arguments */

#define T2_HELP_OPTS "Vh"

        { "version", no_argument, 0, 'V' },
        { "help"   , no_argument, 0, 'h' },

        { 0, 0, 0, 0 }
    };

#define T2_OPTS ":" T2_INPUT_OPTS T2_DPDK_OPTS T2_OUTPUT_OPTS T2_OPT_OPTS T2_HELP_OPTS "?"

#ifndef __APPLE__
    int cpu_opt = -1;
#endif

    int t2optind = -1;

    int opt;
    while ((opt = getopt_long(argc, argv, T2_OPTS, t2_options, &t2optind)) != -1) {
        switch (opt) {

            /* Input arguments */

#if DPDK_MP == 0
            case 'D': {
                capType |= DIRFILE;
                if (CAPTYPE_ERROR(capType, DIRFILE)) {
                    capType |= FILECNFLCT;
                    break;
                }

                size_t len = strlen(optarg);
                capName = t2_calloc_fatal(len + 21, sizeof(*capName));
                memcpy(capName, optarg, len);
                fileNumP = memrchr(capName, ',', len);
                if (fileNumP) {
                    len = (fileNumP - capName);
                    *fileNumP++ = 0;
                    if (*fileNumP == '-') goto frmerr;
                    fileNumE = strtoul(fileNumP, NULL, 0);
                }

                char *oBP = memrchr(capName, ':', len);
                int olen = 1;
                if (!oBP) fileNumP = memrchr(capName, SCHR, len);
                else {
                    char schr[4] = {};
                    if (fileNumP) olen = fileNumP - oBP - 2;
                    memcpy(schr, oBP + 1, olen);
                    len = (oBP - capName);
                    *oBP = '\0';
                    if (olen > 1) fileNumP = strnstr(capName, schr, len);
                    else fileNumP = memrchr(capName, schr[0], len);
                }

                if (fileNumP) {
                    fileNumP += olen;
                    len -= (fileNumP - capName);
                    pDot = memchr(fileNumP, '.', len);
                    pLn = memchr(fileNumP, '_', len);
                    if (pLn) len -= strlen(pLn);
                    else if (pDot) len -= strlen(pDot);
                    if (*fileNumP == '0') {
                        fNumLen = len;
                        numType = 1;
                        if (fileNumE == UINT32_MAX) {
                            fileNumE = pow(10, fNumLen) - 1;
                        }
                    }
                    fileNum = strtoul(fileNumP, NULL, 0);
                    memcpy(fileNumB, fileNumP, len);
                    fNumLen0 = len + 1;
                    break;
                }
frmerr:
                free(capName);
                free(cmdline);
                T2_ERR("Option '-D': Invalid format, expected 'expr[:schr][,stop]'");
                t2_abort_with_help();
            }
#endif // DPDK_MP == 0

            case 'i':
                capType |= IFACE;
                if (CAPTYPE_ERROR(capType, IFACE)) capType |= FILECNFLCT;
                capName = optarg;
                break;

#if DPDK_MP == 0
            case 'r':
                capType |= CAPFILE;
                if (CAPTYPE_ERROR(capType, CAPFILE)) capType |= FILECNFLCT;
                capName = optarg;
                break;

            case 'R':
                capType |= LISTFILE;
                if (CAPTYPE_ERROR(capType, LISTFILE)) capType |= FILECNFLCT;
                capName = optarg;
                break;

#else // DPDK_MP != 0
            /* DPDK arguments */

            case 'N':
                dpdk_num_procs = atoi(optarg);
                break;

            case 'I':
                dpdk_proc_id = atoi(optarg);
                break;

#endif // DPDK_MP == 0

            /* Output arguments */

            case 'l':
                capType |= LOGFILE;
                break;

            case 'm':
                capType |= MONFILE;
                break;

            case 's':
                capType |= PKTFILE;
                break;

            case 'w':
                baseFileName = optarg;
                break;

            case 'W': {  // PREFIX[:SIZE][,START]
                capType |= OFILELN;
                const size_t len = strlen(optarg);
                // Start index (default to 0)
                char *oBP1 = memrchr(optarg, ',', len);
                if (oBP1) {
                    oFileNumB = strtoull(oBP1 + 1, NULL, 0);
                    *oBP1 = '\0';
                }
                // Size
                char *oBP = memrchr(optarg, ':', len);
                if (!oBP) {
                    oFragFsz = OFRWFILELN;
                } else {
                    oFragFsz = atof(oBP + 1);
                    if (oBP1) oBP1--;
                    else oBP1 = optarg + len - 1;
                    if (*oBP1 == 'f') {
                        capType |= WFINDEX;
                        oBP1--;
                    }
                    if (*oBP1 == 'K') oFragFsz *= 1000.0;
                    else if (*oBP1 == 'M') oFragFsz *= 1000000.0;
                    else if (*oBP1 == 'G') oFragFsz *= 1000000000.0;
                    *oBP = '\0';
                }
                baseFileName = optarg;
                break;
            }

            /* Optional arguments */

#if USE_PLLIST > 0
            case 'b':
                pluginList = optarg;
                break;
#endif

            case 'c': {
#ifndef __APPLE__
                cpu_opt = atoi(optarg);
#else
                T2_ERR("Option '-c' is not supported on macOS");
                t2_abort_with_help();
#endif
                break;
            }

            case 'e':
                esomFileName = optarg;
                break;

            case 'f':
                hashFactor = strtoul(optarg, NULL, 0);
                if (hashFactor == 0) {
                    T2_ERR("Option '-f': Hash factor must be greater than 0");
                    t2_abort_with_help();
                }
                break;

            case 'F':
                bpfCommand = read_bpffile(optarg);
                break;

            case 'p':
                pluginFolder = optarg;
                break;

            case 'x':
                sensorID = strtoul(optarg, NULL, 0);
                break;

            case 'P': {
                const int prio = strtol(optarg, NULL, 0);
                if (getuid() == 0) {
                    if (prio < -20 || prio > 20) {
                        T2_ERR("Priority MUST be between -20 and 20 (highest to lowest)");
                        t2_abort_with_help();
                    }
                } else if (prio < 0) {
                    T2_ERR("Only root can assign priority < 0");
                    t2_abort_with_help();
                } else if (prio > 20) {
                    T2_ERR("Priority MUST be between 0 and 20 (highest to lowest)");
                    t2_abort_with_help();
                }

                const pid_t pid = getpid();
                if (setpriority(PRIO_PROCESS, pid, prio) != 0) {
                    T2_FATAL("Failed to set priority to %d: %s", prio, strerror(errno));
                }
                break;
            }

            case 'M':
                monIntV = atof(optarg);
                if (monIntV < 0) {
                    T2_ERR("Option '-M': Monitoring interval must be greater than 0.0");
                    t2_abort_with_help();
                }
                ivalon.it_value.tv_sec  = (uint32_t)monIntV;
                ivalon.it_value.tv_usec = (monIntV - (uint32_t)monIntV) * 1000000;
                break;

            /* Interface capture arguments */

            case 'B':
                liveBufSz = strtol(optarg, NULL, 0);
                if (liveBufSz < 0) {
                    T2_ERR("Option '-B': Buffer size must be greater than 0");
                    t2_abort_with_help();
                }
                break;

            case 'S':
                snapLen = strtol(optarg, NULL, 0);
                if (snapLen < 0) {
                    T2_ERR("Option '-S': Snapshot length must be greater than 0");
                    t2_abort_with_help();
                }
                break;

            /* Help and documentation arguments */

            case 'h':
                t2_usage();
                exit(EXIT_SUCCESS);

            case 'V':
                t2_version();
                exit(EXIT_SUCCESS);

            /* Missing arguments */

            case ':':
                T2_ERR("Option '-%c' requires an argument", optopt);
                t2_abort_with_help();

            /* Unknown options */

            default:
                T2_ERR("Unknown option '-%c'", optopt);
                t2_abort_with_help();
        }

        t2optind = -1;
    }

#if DPDK_MP != 0
    if (UNLIKELY(dpdk_proc_id < 0)) {
        T2_FATAL("Missing mandatory proc-id parameter");
    }

    if (UNLIKELY(rte_eal_process_type() == RTE_PROC_PRIMARY && dpdk_num_procs <= 0)) {
        T2_FATAL("Missing or invalid mandatory num-procs parameter");
    }
#endif // DPDK_MP != 0

    if (UNLIKELY(!t2_validate_captype(capType))) {
        t2_abort_with_help();
    }

    // all remaining parameters belong to the BPF string
    // (except if '-F' option was used)
    if (!bpfCommand) bpfCommand = copy_argv(&argv[optind]);

    t2_set_baseFileName();

    dooF = t2_open_logFile();
    monFile = t2_open_monFile();

    if (getuid() == 0 && !(capType & IFACE)) {
        T2_WRN("Running Tranalyzer as root on a pcap is not recommended");
        sleep(1);
    }

    t2_set_pluginFolder();

#if PID_FNM_ACT == 1
    t2_create_pid_file();
#endif

#ifndef __APPLE__
    if (cpu_opt != -1) t2_set_cpu(cpu_opt);
#endif
}


// main Tranalyzer2

int main(int argc, char *argv[]) {
#if DPDK_MP != 0
    // initialise the EAL
    // EAL and t2 arguments should be separated by a --
    const int ret = rte_eal_init(argc, argv);
    if (UNLIKELY(ret < 0)) {
        T2_FATAL("Cannot init EAL");
    }

    argc -= ret;
    argv += ret;
#endif // DPDK_MP != 0

    t2_parse_options(argc, argv);

#if VERBOSE > 0
    T2_LOG("================================================================================"); // 80 chars
    char cpu_str[32] = {};
#ifndef __APPLE__
    if (cpu != -1) snprintf(cpu_str, sizeof(cpu_str), ", CPU: %d", cpu);
#endif
    const pid_t pid = getpid();
    T2_LOG("%s %s (%s), %s. PID: %d, Prio: %d, SID: %d%s"
#if DPDK_MP == 1
            ", DPDK process: %d/%d"
#endif // DPDK_MP == 1
            , T2_APPNAME, T2_VERSION, T2_CODENAME, T2_RELEASE
            , pid, getpriority(PRIO_PROCESS, pid), sensorID, cpu_str
#if DPDK_MP == 1
            , dpdk_proc_id, dpdk_num_procs
#endif // DPDK_MP == 1
    );
    T2_LOG("================================================================================"); // 80 chars

    struct timeval t;
    gettimeofday(&t, NULL);
    t2_log_date(dooF, "Date: ", t, TSTAMP_R_UTC);

    T2_CONF_REPORT(dooF);
#endif // VERBOSE > 0

    // block all relevant interrupts to be shifted to the thread
    t2_setup_sigaction();

#if MONINTBLK == 0
    sigset_t mask = t2_get_sigset();

#if MONINTTHRD == 0
    sigprocmask(SIG_UNBLOCK, &mask, NULL);
#else // MONINTTHRD == 1
    sigprocmask(SIG_BLOCK, &mask, NULL);
    pthread_t thread;
    pthread_create(&thread, NULL, intThreadHandler, NULL);
#endif // MONINTTHRD == 1
#endif // MONINTBLK == 0

    prepareSniffing();

#if (MONINTTMPCP == 0 && MONINTTMPCP_ON == 1)
    globalInt |= GI_ALRM;
    //alarm(MONINTV);
    ivalon.it_interval = ivalon.it_value;
    setitimer(ITIMER_REAL, &ivalon, NULL);
#endif // (MONINTTMPCP == 0 && MONINTTMPCP_ON == 1)

#if DPDK_MP == 0
    mainLoop();
#else // DPDK_MP != 0
    rte_eal_mp_remote_launch(lcore_main, NULL, CALL_MAIN);
#endif // DPDK_MP == 0

    terminate();

    // Never called...
    return EXIT_SUCCESS;
}


#if DPDK_MP != 0
static int dpdk_port_init(uint16_t port, struct rte_mempool *mbuf_pool, uint16_t num_queues) {
    #define RX_RING_SIZE 1024

    struct rte_eth_conf port_conf = {
        .rxmode = {
            .mq_mode  = RTE_ETH_MQ_RX_RSS,
            .offloads = RTE_ETH_RX_OFFLOAD_CHECKSUM,
        },
        .rx_adv_conf = {
            .rss_conf = {
                .rss_key = NULL,
                .rss_hf = RTE_ETH_RSS_IP,
            },
        }
    };
    const uint16_t rx_rings = num_queues;
    struct rte_eth_dev_info info;
    struct rte_eth_rxconf rxq_conf;
    int retval;
    uint16_t nb_rxd = RX_RING_SIZE;
    uint64_t rss_hf_tmp;

    if (UNLIKELY(!rte_eth_dev_is_valid_port(port)))
        return -1;

    retval = rte_eth_dev_info_get(port, &info);
    if (UNLIKELY(retval != 0)) {
        T2_ERR("Error during getting device (port %u) info: %s", port, strerror(-retval));
        return -1;
    }

    info.default_rxconf.rx_drop_en = 1;

    rss_hf_tmp = port_conf.rx_adv_conf.rss_conf.rss_hf;
    port_conf.rx_adv_conf.rss_conf.rss_hf &= info.flow_type_rss_offloads;
    if (port_conf.rx_adv_conf.rss_conf.rss_hf != rss_hf_tmp) {
        T2_INF("Port %u modified RSS hash function based on hardware support,"
                "requested: %#" PRIx64 ", configured: %#" PRIx64,
                port, rss_hf_tmp, port_conf.rx_adv_conf.rss_conf.rss_hf);
    }

    retval = rte_eth_dev_configure(port, rx_rings, 0, &port_conf);
    if (retval == -EINVAL) {
        T2_WRN("Port %u configuration failed. Re-attempting with HW checksum disabled.", port);
        port_conf.rxmode.offloads &= ~(RTE_ETH_RX_OFFLOAD_CHECKSUM);
        retval = rte_eth_dev_configure(port, rx_rings, 0, &port_conf);
    }

    if (retval == -ENOTSUP) {
        T2_WRN("Port %u configuration failed. Re-attempting with HW RSS disabled.", port);
        port_conf.rxmode.mq_mode &= ~(RTE_ETH_MQ_RX_RSS);
        retval = rte_eth_dev_configure(port, rx_rings, 0, &port_conf);
    }

    if (UNLIKELY(retval < 0))
        return retval;

    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, NULL);
    if (UNLIKELY(retval < 0))
        return retval;

    rxq_conf = info.default_rxconf;
    rxq_conf.offloads = port_conf.rxmode.offloads;
    for (uint16_t q = 0; q < rx_rings; q ++) {
        retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
                rte_eth_dev_socket_id(port),
                &rxq_conf,
                mbuf_pool);
        if (UNLIKELY(retval < 0))
            return retval;
    }

    retval = rte_eth_promiscuous_enable(port);
    if (UNLIKELY(retval != 0))
        return -1;

    retval = rte_eth_dev_start(port);
    if (UNLIKELY(retval < 0))
        return retval;

    return 0;
}
#endif // DPDK_MP != 0


static void prepareSniffing() {
#if DPDK_MP == 0
    struct stat fileStats;
    char errbuf[PCAP_ERRBUF_SIZE];

    // prepare data source
    if (capType & CAPFILE) { // -r option
        if (UNLIKELY(!ckpcaphdr(capName))) exit(EXIT_FAILURE); // check file type

        // open pcap
#if TSTAMP_PREC == 1
        if (UNLIKELY(!(captureDescriptor = pcap_open_offline_with_tstamp_precision(capName, PTSPREC, errbuf)))) {
#else // TSTAMP_PREC == 0 (for backward compatibility reasons)
        if (UNLIKELY(!(captureDescriptor = pcap_open_offline(capName, errbuf)))) {
#endif // TSTAMP_PREC
            T2_FATAL("pcap_open_offline failed for '%s': %s", capName, errbuf);
        }

        // pcap_get_tstamp_precision(pcap_t captureDescriptor);

        // read number of bytes residing in dump file
        if (stat(capName, &fileStats) == 0) {
            captureFileSize += fileStats.st_size;
        } else {
            if (*capName != '-') T2_WRN("Cannot get stats for file '%s': %s", capName, strerror(errno));
            //captureFileSize = 0;
        }
    } else if (capType & IFACE) { // -i option
        // open in promisc mode with custom buffer size
        if (UNLIKELY((captureDescriptor = pcap_create(capName, errbuf)) == NULL)) {
            T2_ERR("pcap_create failed for '%s': %s", capName, errbuf);
            T2_INF2("Try using the 'st2' command to run Tranalyzer as root");
            exit(EXIT_FAILURE);
        }

        if (UNLIKELY(pcap_set_snaplen(captureDescriptor, snapLen) != 0)) {
            T2_FATAL("Failed to set snaplen to %" PRId32 " for capture interface '%s'", snapLen, capName);
        }

        if (UNLIKELY(pcap_set_promisc(captureDescriptor, 1) != 0)) {
            T2_FATAL("Failed to set capture interface '%s' to promiscuous mode", capName);
        }

        if (UNLIKELY(pcap_set_timeout(captureDescriptor, CAPTURE_TIMEOUT) != 0)) {
            T2_FATAL("Failed to set timeout to %d for capture interface '%s'", CAPTURE_TIMEOUT, capName);
        }

        // Set timestamp precision (non-fatal)
        if (pcap_set_tstamp_precision(captureDescriptor, PTSPREC) != 0) {
            const char * const prec = ((PTSPREC == 1) ? "nanoseconds" : "microseconds");
            T2_WRN("Failed to set timestamp precision to %s for capture interface '%s'", prec, capName);
        }

        if (UNLIKELY(pcap_set_buffer_size(captureDescriptor, liveBufSz) != 0)) {
            T2_FATAL("Failed to set buffer size to %" PRId32 " for capture interface '%s'", liveBufSz, capName);
        }

        // Activate the capture handle
        if (UNLIKELY(pcap_activate(captureDescriptor) != 0)) {
            const char * const pcap_err = pcap_geterr(captureDescriptor);
            if (pcap_err) {
                T2_FATAL("Failed to activate capture interface '%s': %s", capName, pcap_err);
            } else {
                T2_FATAL("Failed to activate capture interface '%s'", capName);
            }
        }

        if (UNLIKELY(pcap_setnonblock(captureDescriptor, NON_BLOCKING_MODE, errbuf) == -1)) {
            T2_FATAL("Could not set blocking mode %d on interface '%s': %s", NON_BLOCKING_MODE, capName, errbuf);
        }
    } else if (capType & DIRFILE) { // -D option
        wordexp_t globName;
        wordexp(capName, &globName, 0);
        size_t len = strlen(globName.we_wordv[0]);
        globFName = t2_calloc_fatal(len + 64, sizeof(*globFName));
        memcpy(globFName, globName.we_wordv[0], len + 1);
        wordfree(&globName);

        //if (UNLIKELY(!ckpcaphdr(globFName))) exit(EXIT_FAILURE); // check file type

        // open 1. capture file
        while ((captureDescriptor = pcap_open_offline(globFName, errbuf)) == NULL) {
#if VERBOSE > 1
            if ((capType & LOGFILE) == 0) fputc('.', dooF);
#endif // VERBOSE > 1
            fflush(NULL); // commit all changes in all buffers
            sleep(POLLTM);
            if (UNLIKELY(globalInt == GI_EXIT)) exit(EXIT_FAILURE);

            wordexp(capName, &globName, 0);
            len = strlen(globName.we_wordv[0]);
            T2_REALLOC(globFName, len + 64);
            memcpy(globFName, globName.we_wordv[0], len + 1);
            wordfree(&globName);
        }

        // acquire filelength
        if (stat(globFName, &fileStats) == 0) {
            captureFileSize += fileStats.st_size;
        } else {
#if VERBOSE > 0
            T2_WRN("Cannot get stats for file '%s': %s", globFName, strerror(errno));
            T2_INF("Waiting for file number %" PRIu32, fileNum);
#endif // VERBOSE > 0
            //captureFileSize = 0;
        }
    } else if (capType & LISTFILE) { // -R option
        // open file with list of pcap dump files in it
        caplist = read_caplist(capName);

        // start with the first file in list
        caplist_elem = caplist->file_list;
        caplist_index = 0;
        if (UNLIKELY(!(captureDescriptor = pcap_open_offline(caplist_elem->name, errbuf)))) {
            T2_FATAL("pcap_open_offline failed for '%s': %s", caplist_elem->name, errbuf);
        }
    }

    // setup the bpf filter
    BPFSET(captureDescriptor, bpfCommand);

#else // DPDK_MP != 0

    #define MBUF_POOL_NAME "T2_MBUF_POOL"
    #define NB_MBUFS ((1 << 16) - 1) // following doc advice: n = 2^q-1
    #define MBUF_CACHE_SIZE 257      // following doc advice: n % cache_size == 0

    if (UNLIKELY(rte_eth_dev_get_port_by_name(capName, &dpdk_port_id) != 0)) {
        T2_FATAL("Failed to find a DPDK network interface named %s", capName);
    }

    enum rte_proc_type_t proc_type = rte_eal_process_type();
    struct rte_mempool *mp = (proc_type == RTE_PROC_SECONDARY) ?
        rte_mempool_lookup(MBUF_POOL_NAME) :
        rte_pktmbuf_pool_create(MBUF_POOL_NAME, NB_MBUFS,
                MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
                rte_socket_id());

    if (UNLIKELY(!mp)) {
        T2_FATAL("Cannot get memory pool for buffers");
    }

    if (proc_type == RTE_PROC_PRIMARY) {
        rte_eth_stats_reset(dpdk_port_id);
        if (UNLIKELY(dpdk_port_init(dpdk_port_id, mp, (uint16_t)dpdk_num_procs) < 0)) {
            T2_FATAL("Failed to init DPDK port (%u) %s", dpdk_port_id, capName);
        }
    }

    // TODO: check if BPF string can be converted to eBPF instructions and used with
    //       rte_bpf_load + rte_bpf_exec_burst => pcap_compile + rte_bpf_convert?
#endif // DPDK_MP == 0

    // reset lru list
    lruHead.lruNextFlow = &lruTail;
    lruHead.lruPrevFlow = NULL;
    lruTail.lruNextFlow = NULL;
    lruTail.lruPrevFlow = &lruHead;

    // initialize timeout manager with default timeout handler
    timeout_handler_add(FLOW_TIMEOUT);

    // initialize main buffer
    main_output_buffer = outputBuffer_initialize(MAIN_OUTBUF_SIZE);

    t2_plugins = t2_load_plugins(pluginFolder);

#if (MACHINE_REPORT == 1 && MONPROTMD == 1)
    t2_load_proto_file();
#endif

    const size_t hash_size = (char*) &lruHead.l4Proto - (char*) &lruHead.srcIP + sizeof(lruHead.l4Proto);
    mainHashMap = hashTable_init(1.0f, hash_size, "main");

    // initialize flow array
    flows = t2_calloc_fatal(mainHashMap->hashChainTableSize, sizeof(*flows));

    // initialize T2 global file manager. max concurrently opened files allowed
    // depend on kernel limit (value can be checked with: ulimit -Hn)
    t2_file_manager = file_manager_new(SIZE_MAX);

#if FRAGMENTATION == 1
    // initialize fragPendMap and fragPend array
    fragPendMap = hashTable_init(1.0f, hash_size, "frag");
    fragPend = t2_calloc_fatal(fragPendMap->hashChainTableSize, sizeof(*fragPend));
#endif // FRAGMENTATION == 1

#if BLOCK_BUF == 0
    main_header_bv = buildHeaders();
#endif

    if (capType & PKTFILE) sPktFile = t2_create_pktfile();

#if SUBNET_INIT != 0
#if VERBOSE > 1
    char hrnum[64];
#endif // VERBOSE > 1
#if (IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2)
    subnetTable4P = subnet_init4(pluginFolder, SUBNETFILE4);
    subnetTableP[0] = subnetTable4P;
#if VERBOSE > 1
    T2_CONV_NUM(SUBNET_CNT(subnetTable4P), hrnum);
    T2_INF("IPv4 Ver: %" PRIu32 ", Rev: %08" PRIu32 ", Range Mode: %d, subnet ranges loaded: %" PRIu32 "%s",
            SUBNET_VER(subnetTable4P), SUBNET_REV(subnetTable4P),
            SUBNET_RNG(subnetTable4P), SUBNET_CNT(subnetTable4P), hrnum);
#endif // VERBOSE > 1
#endif // (IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2)
#if IPV6_ACTIVATE > 0
    subnetTable6P = subnet_init6(pluginFolder, SUBNETFILE6);
    subnetTableP[1] = subnetTable6P;
#if VERBOSE > 1
    T2_CONV_NUM(subnetTable6P->count >> 1, hrnum);
    T2_INF("IPv6 Ver: %" PRIu32 ", Rev: %08" PRIu32 ", Range Mode: %d, subnet ranges loaded: %" PRIu32 "%s",
            SUBNET_VER(subnetTable6P), SUBNET_REV(subnetTable6P),
            SUBNET_RNG(subnetTable6P), SUBNET_CNT(subnetTable6P), hrnum);
#endif // VERBOSE > 1
#endif // IPV6_ACTIVATE > 0
#endif // SUBNET_INIT != 0

    FOREACH_PLUGIN_DO(init);

    if (sPktFile) {

        // Macro to simplify column name creation
#define SPKTMD_PRI_CONTENT_NAME(sPktFile, prefix) { \
    if (prefix) fputs((prefix), (sPktFile)); \
    if (SPKTMD_BOPS & 0x01) { \
        if (prefix) fputs("Lsb", sPktFile); \
        else fputs("lsb", sPktFile); \
    } \
    if (SPKTMD_BOPS & 0x02) { \
        if (SPKTMD_BOPS & 0x01 || prefix) fputs("Ns", sPktFile); \
        else fputs("ns", sPktFile); \
    } \
    if ((SPKTMD_BOPS & 0x03) != 0 || prefix) fputs("Content" SEP_CHR, sPktFile); \
    else fputs("content" SEP_CHR, sPktFile); \
}

#if SPKTMD_PCNTL == 0
        // hex[Lsb][Ns]Content
        if (SPKTMD_PCNTH == 1) SPKTMD_PRI_CONTENT_NAME(sPktFile, "hex");
        // [lsb][[Nn]s][Cc]ontent
        if (SPKTMD_PCNTC == 1) SPKTMD_PRI_CONTENT_NAME(sPktFile, NULL);
#elif SPKTMD_PCNTL == 1 // l2
        // l2Hex[Lsb][Ns]Content
        if (SPKTMD_PCNTH == 1) SPKTMD_PRI_CONTENT_NAME(sPktFile, "l2Hex");
        // l2[Lsb][Ns]Content
        if (SPKTMD_PCNTC == 1) SPKTMD_PRI_CONTENT_NAME(sPktFile, "l2");
#elif SPKTMD_PCNTL == 2 // l3
        // l3Hex[Lsb][Ns]Content
        if (SPKTMD_PCNTH == 1) SPKTMD_PRI_CONTENT_NAME(sPktFile, "l3Hex");
        // l3[Lsb][Ns]Content
        if (SPKTMD_PCNTC == 1) SPKTMD_PRI_CONTENT_NAME(sPktFile, "l3");
#elif SPKTMD_PCNTL == 3 // l4
        // l4Hex[Lsb][Ns]Content
        if (SPKTMD_PCNTH == 1) SPKTMD_PRI_CONTENT_NAME(sPktFile, "l4Hex");
        // l4[Lsb][Ns]Content
        if (SPKTMD_PCNTC == 1) SPKTMD_PRI_CONTENT_NAME(sPktFile, "l4");
#else // SPKTMD_PCNTL == 4 // l7
        // l7Hex[Lsb][Ns]Content
        if (SPKTMD_PCNTH == 1) SPKTMD_PRI_CONTENT_NAME(sPktFile, "l7Hex");
        // l7[Lsb][Ns]Content
        if (SPKTMD_PCNTC == 1) SPKTMD_PRI_CONTENT_NAME(sPktFile, "l7");
#endif // SPKTMD_PCNTL == 4

#undef SPKTMD_PRI_CONTENT_NAME

        t2_discard_trailing_chars(sPktFile, SEP_CHR, sizeof(SEP_CHR) - 1);
        fputc('\n', sPktFile);
    }

#if IO_BUFFERING != 0
    ioBufferInitialize();
#endif

#if REPORT_HIST == 1
    t2_restore_state();
#endif

#if VERBOSE > 1
         if (capType & CAPFILE)  T2_LOG("Processing file: %s", capName);
    else if (capType & LISTFILE) T2_LOG("Processing list file: %s", capName);
    else if (capType & DIRFILE)  T2_LOG("Processing file: %s", globFName);
    else if (capType & IFACE)    T2_LOG("Live capture on interface: %s", capName);

    if (bpfCommand) T2_INF("BPF: %s", bpfCommand);

    if (capType & LISTFILE) {
        T2_LOG("Processing file no. %" PRIu32 " of %" PRIu32 ": %s",
                caplist_index + 1, caplist->num_files, caplist_elem->name);
    }

    T2_LOG_LINK_LAYER_TYPE(dooF, captureDescriptor);

#if DPDK_MP == 0
    const int snaplen = pcap_snapshot(captureDescriptor);
#else // DPDK_MP != 0
    const int snaplen = 65535; // TODO: base snaplength on device max_mtu?
#endif // DPDK_MP == 0
    T2_LOG_NUM0("Snapshot length", snaplen);

    if (capType & IFACE) T2_LOG_NUM0("Rx buffer length", liveBufSz);

    fflush(dooF);
#endif // VERBOSE > 1

#if MACHINE_REPORT == 1
    t2_machine_report_header(monFile);
#endif

    // begin counting ticks
#if TSTAMP_PREC == 1
    struct timespec tmns;
    clock_gettime(CLOCK_REALTIME, &tmns);
    startTime.tv_sec = (time_t)tmns.tv_sec;
    startTime.tv_usec = tmns.tv_nsec;
#else // TSTAMP_PREC == 0
    gettimeofday(&startTime, NULL);
#endif // TSTAMP_PREC

#if DPDK_MP != 0
    tsc_hz = rte_get_tsc_hz();
    tsc_init_value = rte_rdtsc();
#endif // DPDK_MP != 0

#if MONINTTMPCP == 0
    startTStamp = startTime;
    startTStamp0 = startTStamp;
#endif // MONINTTMPCP == 0
}


static inline void t2_setup_sigaction() {
    struct sigaction sa;
    sigfillset(&sa.sa_mask);
    sa.sa_handler = sigHandler;
    sa.sa_flags = SA_RESTART; // Restart system call, if possible
    //sa.sa_flags = (SA_RESTART | SA_SIGINFO); // Restart system call, if possible and enable process info
    if (UNLIKELY(sigaction(SIGINT,  &sa, NULL) == -1)) perror("Error: cannot handle SIGINT");
    if (UNLIKELY(sigaction(SIGTERM, &sa, NULL) == -1)) perror("Error: cannot handle SIGTERM");
    if (UNLIKELY(sigaction(SIGUSR1, &sa, NULL) == -1)) perror("Error: cannot handle SIGUSR1");
    if (UNLIKELY(sigaction(SIGUSR2, &sa, NULL) == -1)) perror("Error: cannot handle SIGUSR2");
    if (UNLIKELY(sigaction(SIGALRM, &sa, NULL) == -1)) perror("Error: cannot handle SIGALRM");
    if (UNLIKELY(sigaction(SIGSYS,  &sa, NULL) == -1)) perror("Error: cannot handle SIGSYS");
}


inline sigset_t t2_get_sigset() {
    sigset_t sigset;
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGINT);
    sigaddset(&sigset, SIGTERM);
    sigaddset(&sigset, SIGUSR1);
    sigaddset(&sigset, SIGUSR2);
    sigaddset(&sigset, SIGALRM);
#if REPSUP == 1
    sigaddset(&sigset, SIGSYS);
#endif // REPSUP == 1
    return sigset;
}


#if DPDK_MP == 0

#if IO_BUFFERING == 0
static void mainLoop() {

#if MONINTBLK == 1
    sigset_t mask = t2_get_sigset();
#endif // MONINTBLK == 1

    char errbuf[PCAP_ERRBUF_SIZE];

#if ZPKTITMUPD == 1
    int zcnt = 0;
#endif // ZPKTITMUPD == 1

    while (LIKELY((globalInt & GI_RUN) > GI_EXIT)) {
#if MONINTBLK == 1
        sigprocmask (SIG_BLOCK, &mask, NULL);
#endif

        const int pcap_ret = pcap_dispatch(captureDescriptor, PACKETS_PER_BURST, perPacketCallback, NULL);

#if MONINTBLK == 1
        sigpending(&mask);
        sigprocmask(SIG_UNBLOCK, &mask, NULL);
#endif

        if (UNLIKELY(pcap_ret == PCAP_ERROR)) {
            const char * const err = pcap_geterr(captureDescriptor);
            if (!last_err || strcmp(err, last_err) != 0) {
                T2_WRN("pcap_dispatch failed: %s", err);
                free(last_err);
                last_err = strdup(err);
            }
            //globalInt = GI_EXIT;
        } else if (pcap_ret == 0) {
            // Terminate if we are reading from a file rather than live-sniffing
            if (capType & CAPFILE) globalInt = GI_EXIT;
            else if (capType & DIRFILE) {
#if RROP == 0
                if (fileNum >= fileNumE) {
                    globalInt = GI_EXIT;
                    return;
                }
#endif // RROP == 0

                pcap_close(captureDescriptor);

#if MFPTMOUT > 0
                time_t sec0;
nxtnum:             sec0 = time(NULL);
#endif // MFPTMOUT > 0
                fileNum++;
                if (numType) {
#if RROP == 1
                    if (fileNum > fileNumE) fileNum = strtoul(fileNumB, NULL, 0);
#endif
                    snprintf(fileNumP, fNumLen + 1, "%0*" PRIu32, fNumLen, fileNum);
                } else {
                    fNumLen = log(fileNum) / log(10.0) + 2;
#if RROP == 1
                    if (fileNum > fileNumE) {
                        if (*fileNumB) {
                            fileNum = strtoul(fileNumB, NULL, 0);
                            fNumLen = log(fileNum) / log(10.0) + 2;
                        } else {
                            fileNum = 0;
                            *fileNumP = 0;
                            fNumLen0 = fNumLen = 0;
                        }
                    }
#endif // RROP == 1
                    if (pDot && fNumLen > fNumLen0) {
                        size_t len = strlen(pDot) + 1;
                        do {
                            pDot[len] = pDot[len - 1];
                        } while (--len);
                        pDot++;
                        fNumLen0 = fNumLen;
                    }
                    snprintf(fileNumP, fNumLen, "%" PRIu32, fileNum);
                }
                if (pDot) *pDot = '.';
                if (pLn) *pLn = '_';

                wordexp_t globName;
                wordexp(capName, &globName, 0);
                memcpy(globFName, globName.we_wordv[0], strlen(globName.we_wordv[0]) + 1);
                wordfree(&globName);

                if (UNLIKELY(!ckpcaphdr(globFName))) exit(EXIT_FAILURE); // check file type

                // capture from next dump file
                while ((captureDescriptor = pcap_open_offline(globFName, errbuf)) == NULL) {
#if (MONINTPSYNC == 1 || MONINTTMPCP == 1)
                    if (globalInt & GI_RPRT) {
                        printGStats();
                        globalInt &= ~GI_RPRT;
                    }
#endif // (MONINTPSYNC == 1 || MONINTTMPCP == 1)
#if VERBOSE > 1
                    if ((capType & LOGFILE) == 0) fputc('.', dooF);
#endif
                    fflush(NULL); // commit all changes in all buffers
                    sleep(POLLTM);
                    if (UNLIKELY(globalInt == GI_EXIT)) return;
                    wordexp(capName, &globName, 0);
                    memcpy(globFName, globName.we_wordv[0], strlen(globName.we_wordv[0]) + 1);
                    wordfree(&globName);
#if MFPTMOUT > 0
                    if (time(NULL) - sec0 >= MFPTMOUT) goto nxtnum;
#endif // MFPTMOUT > 0
                }

                // get filesize info
                struct stat fileStats;
                if (stat(globFName, &fileStats) == 0) {
                    captureFileSize += fileStats.st_size;
                } else {
#if VERBOSE > 0
                    T2_WRN("Failed to get stats of file '%s': %s", globFName, strerror(errno));
#endif
                    //captureFileSize = 0;
                }

                BPFSET(captureDescriptor, bpfCommand);
#if VERBOSE > 1
                T2_LOG("Processing file: %s", globFName);
                T2_LOG_LINK_LAYER_TYPE(dooF, captureDescriptor);
                T2_LOG_NUM0("Snapshot length", pcap_snapshot(captureDescriptor));
                fflush(dooF);
#endif
            } else if (capType & LISTFILE) {
                if (!caplist_elem->next) {
                    // there is no next file -> terminate
                    globalInt = GI_EXIT;
                } else {
                    pcap_close(captureDescriptor);

                    // set descriptor to next file
                    caplist_elem = caplist_elem->next;
                    caplist_index++;

                    if (UNLIKELY(!(captureDescriptor = pcap_open_offline(caplist_elem->name, errbuf)))) {
                        T2_ERR("pcap_open_offline failed for '%s': %s", caplist_elem->name, errbuf);
                        globalInt = GI_EXIT;
                        break;
                    }

                    BPFSET(captureDescriptor, bpfCommand);

#if VERBOSE > 1
                    T2_LOG("Processing file no. %" PRIu32 " of %" PRIu32 ": %s",
                            caplist_index + 1, caplist->num_files, caplist_elem->name);
                    T2_LOG_LINK_LAYER_TYPE(dooF, captureDescriptor);
                    T2_LOG_NUM0("Snapshot length", pcap_snapshot(captureDescriptor));
                    fflush(dooF);
#endif // VERBOSE > 1
                }
            } else {
                // reading from live-interface. As we're using non-blocking mode,
                // pcap_dispatch returns zero immediately if no packets are to
                // be read at the moment. if no packets are to be read at the
                // moment then either actTime needs to be updated, or we just
                // wait a bit in order to avoid CPU loop load.
#if ZPKTITMUPD == 1
                if (++zcnt > ZPKTTMO) {
                    zcnt = 0;
                    gettimeofday(&actTime, NULL);
                    cycleLRULists();
                    fflush(NULL);
                } else
#endif // ZPKTITMUPD == 1
                    usleep(NO_PKTS_DELAY_US);
            }
        }

#if (MONINTPSYNC == 1 || MONINTTMPCP == 1)
        if (globalInt & GI_RPRT) {
            printGStats();
            globalInt &= ~GI_RPRT;
        }
#endif // (MONINTPSYNC == 1 || MONINTTMPCP == 1)

#if MIN_MAX_ESTIMATE > 0
        const double tl = actTime.tv_sec + actTime.tv_usec / TSTAMPFAC;
        const double ttlg = tl - lagTm;
        if (ttlg >= MMXLAGTMS) {
            lagTm = tl;
            const uint64_t rawBytesWDiff = rawBytesOnWire - rawBytesW0;
            if (maxBytesPs < rawBytesWDiff) maxBytesPs = rawBytesWDiff;
            if (rawBytesWDiff && minBytesPs > rawBytesWDiff) minBytesPs = rawBytesWDiff;
            const double div = (double)(++numSpl);
            const double db = rawBytesWDiff - bave;
            bave += db / div;
            bvar += (db * db - bvar) / div;

            rawBytesW0 = rawBytesOnWire;

            const double numABytesDiff = numABytes   - numAByts0;
            const double numBBytesDiff = numBBytes   - numBByts0;
            const double numAPktsDiff  = numAPackets - numAPkts0;
            const double numBPktsDiff  = numBPackets - numBPkts0;

            double pktLd = numAPktsDiff ? (numABytesDiff / numAPktsDiff) : 0.0;
            if (pktLd > pktALdMax) pktALdMax = pktLd;
            if (
#if MMXNO0 == 1
                pktLd > 0.0 &&
#endif // MMXNO0 == 1
                pktLd < pktALdMin
            )
            {
                pktALdMin = pktLd;
            }

            pktLd = numBPktsDiff ? (numBBytesDiff / numBPktsDiff) : 0.0;
            if (pktLd > pktBLdMax) pktBLdMax = pktLd;
            if (
#if MMXNO0 == 1
                pktLd > 0.0 &&
#endif // MMXNO0 == 1
                pktLd < pktBLdMin
            )
            {
                pktBLdMin = pktLd;
            }

            numAPkts0 = numAPackets;
            numBPkts0 = numBPackets;
            numAByts0 = numABytes;
            numBByts0 = numBBytes;
        }
#endif // MIN_MAX_ESTIMATE > 0
    }
}
#endif // IO_BUFFERING == 0

#else // DPDK_MP != 0

static inline struct timeval current_time() {
    static const long int ts_precision = (long int)TSTAMPFAC;
    const uint64_t ticks = rte_rdtsc() - tsc_init_value;
    struct timeval now = {
        .tv_sec = startTime.tv_sec + (ticks / tsc_hz),
        .tv_usec = startTime.tv_usec + ((ticks % tsc_hz) * ts_precision) / tsc_hz,
    };
    if (now.tv_usec >= ts_precision) {
        now.tv_usec -= ts_precision;
        now.tv_sec += 1;
    }
    return now;
}


static int lcore_main(void *arg __rte_unused) {
    #define PKT_BURST 32
    const uint16_t q_id = (uint16_t)dpdk_proc_id;
    struct rte_mbuf *buf[PKT_BURST];
    struct rte_mbuf *m;

    while (LIKELY((globalInt & GI_RUN) > GI_EXIT)) {
        const uint16_t rx_c = rte_eth_rx_burst(dpdk_port_id, q_id, buf, PKT_BURST);
        for (uint16_t i = 0; i < rx_c; ++i) {
            m = buf[i];
            const uint32_t pkt_len = m->pkt_len;
            const struct pcap_pkthdr pkt_hdr = {
                .ts = current_time(),
                .caplen = pkt_len,
                .len = pkt_len,
            };
            rte_prefetch0(rte_pktmbuf_mtod(m, void *));
            if (m->nb_segs == 1) {
                perPacketCallback(NULL, &pkt_hdr, rte_pktmbuf_mtod(m, void *));
            } else if (pkt_len <= sizeof(reassembled)) {
                // handle packets scattered in several segments
                uint32_t len = 0;
                while (m && (len + m->data_len < sizeof(reassembled))) {
                    rte_memcpy(reassembled + len, rte_pktmbuf_mtod(m, void *), m->data_len);
                    len += m->data_len;
                    m = m->next;
                }
                if (len == pkt_len) {
                    perPacketCallback(NULL, &pkt_hdr, reassembled);
                } else {
                    T2_WRN("Invalid sum of segments lengths: %u != %u", len, pkt_len);
                }
            } else {
                T2_WRN("Packet too large for reassembly buffer: %u", pkt_len);
            }
            rte_pktmbuf_free(m);
        }

#if (MONINTPSYNC == 1 || MONINTTMPCP == 1)
        if (globalInt & GI_RPRT) {
            printGStats();
            globalInt &= ~GI_RPRT;
        }
#endif // (MONINTPSYNC == 1 || MONINTTMPCP == 1)

#if MIN_MAX_ESTIMATE > 0
        const double tl = actTime.tv_sec + actTime.tv_usec / TSTAMPFAC;
        const double ttlg = tl - lagTm;
        if (ttlg >= MMXLAGTMS) {
            lagTm = tl;
            const uint64_t rawBytesWDiff = rawBytesOnWire - rawBytesW0;
            if (maxBytesPs < rawBytesWDiff) maxBytesPs = rawBytesWDiff;
            if (rawBytesWDiff && minBytesPs > rawBytesWDiff) minBytesPs = rawBytesWDiff;
            const double div = (double)(++numSpl);
            const double db = rawBytesWDiff - bave;
            bave += db / div;
            bvar += (db * db - bvar) / div;

            rawBytesW0 = rawBytesOnWire;

            const double numABytesDiff = numABytes   - numAByts0;
            const double numBBytesDiff = numBBytes   - numBByts0;
            const double numAPktsDiff  = numAPackets - numAPkts0;
            const double numBPktsDiff  = numBPackets - numBPkts0;

            double pktLd = numAPktsDiff ? (numABytesDiff / numAPktsDiff) : 0.0;
            if (pktLd > pktALdMax) pktALdMax = pktLd;
            if (
#if MMXNO0 == 1
                pktLd > 0.0 &&
#endif // MMXNO0 == 1
                pktLd < pktALdMin
            )
            {
                pktALdMin = pktLd;
            }
            pktLd = numBPktsDiff ? (numBBytesDiff / numBPktsDiff) : 0.0;
            if (pktLd > pktBLdMax) pktBLdMax = pktLd;
            if (
#if MMXNO0 == 1
                pktLd > 0.0 &&
#endif // MMXNO0 == 1
                pktLd < pktBLdMin
            )
            {
                pktBLdMin = pktLd;
            }
            numAPkts0 = numAPackets;
            numBPkts0 = numBPackets;
            numAByts0 = numABytes;
            numBByts0 = numBBytes;
        }
#endif // MIN_MAX_ESTIMATE > 0
    }
    return 0;
}

#endif // DPDK_MP != 0


/*
 * Returning 'prev' is necessary because the flow and its opposite could be
 * two following flows. When this is the case, then the pointer used outside
 * of this function would be invalid.
 */
#if FDURLIMIT > 0
inline flow_t *removeFlow(flow_t *aFlow) {
#else // FDURLIMIT == 0
static inline flow_t *removeFlow(flow_t *aFlow) {
#endif // FDURLIMIT
    if (UNLIKELY(!aFlow)) return NULL;

    flow_t *remove[] = { aFlow, NULL };

    // Remove the reverse flow as well if it exists
    const unsigned long reverseFlowIndex = aFlow->oppositeFlowIndex;
    if (reverseFlowIndex != HASHTABLE_ENTRY_NOT_FOUND) {
        remove[1] = &flows[reverseFlowIndex];
    }

    flow_t *flowP;
    flow_t *prev = aFlow->lruPrevFlow;
    for (uint_fast8_t i = 0; i < 2; i++) {

        if (!(flowP = remove[i])) return prev;

        if (UNLIKELY((hashTable_remove(mainHashMap, (char*)&flowP->srcIP) == HASHTABLE_ENTRY_NOT_FOUND))) {
#if VERBOSE > 0
            const uint_fast8_t ipver = FLOW_IPVER(flowP);
            char srcAddr[INET6_ADDRSTRLEN] = {};
            char dstAddr[INET6_ADDRSTRLEN] = {};
            if (ipver != 0) {
                T2_IP_TO_STR(flowP->srcIP, ipver, srcAddr, sizeof(srcAddr));
                T2_IP_TO_STR(flowP->dstIP, ipver, dstAddr, sizeof(dstAddr));
                T2_WRN("Failed to remove flow with flowIndex %lu from mainHashMap: %s:%u -> %s:%u proto %u, vlan %u, findex %" PRIu64
#if SCTP_ACTIVATE & 1
                        ", sctpStrmID %" PRIu16
#endif // SCTP_ACTIVATE & 1
#if SCTP_ACTIVATE & 2
                        ", sctpVerTag 0x%" PRIx32
#endif // SCTP_ACTIVATE & 2
                        , flowP->flowIndex, srcAddr, flowP->srcPort, dstAddr, flowP->dstPort
                        , flowP->l4Proto, flowP->vlanId, flowP->findex
#if SCTP_ACTIVATE & 1
                        , ntohs(flowP->sctpStrm)
#endif // SCTP_ACTIVATE & 1
#if SCTP_ACTIVATE & 2
                        , ntohl(flowP->sctpVtag)
#endif // SCTP_ACTIVATE & 2
                );

            } else { // Layer 2 or LAPD flow
#if ETH_ACTIVATE > 0
                t2_mac_to_str(flowP->ethDS.ether_shost, srcAddr, sizeof(srcAddr));
                t2_mac_to_str(flowP->ethDS.ether_dhost, dstAddr, sizeof(dstAddr));
#endif // ETH_ACTIVATE > 0
#if (IPV6_ACTIVATE == 2 || ETH_ACTIVATE > 0 || LAPD_ACTIVATE == 1)
                const uint16_t ethType = flowP->ethType;
#else // !(IPV6_ACTIVATE == 2 || ETH_ACTIVATE > 0 || LAPD_ACTIVATE == 1)
                const uint16_t ethType = 0;
#endif // !(IPV6_ACTIVATE == 2 || ETH_ACTIVATE > 0 || LAPD_ACTIVATE == 1)
                T2_WRN("Failed to remove flow with flowIndex %lu from mainHashMap: %s -> %s ethertype 0x%02" B2T_PRIX16 ", vlan %u, findex %" PRIu64,
                        flowP->flowIndex, srcAddr, dstAddr, ethType, flowP->vlanId, flowP->findex);
            }
#endif // VERBOSE > 0
            continue;
        }

#if FRAGMENTATION == 1
        if (flowP->status & IPV4_FRAG_PENDING) {
            flowP->fragID = flowP->lastFragIPID;
            hashTable_remove(fragPendMap, (char*)&flowP->srcIP);
            globalWarn |= IPV4_FRAG_PENDING;
        }
#endif // FRAGMENTATION == 1

        flowP->lruNextFlow->lruPrevFlow = flowP->lruPrevFlow;
        flowP->lruPrevFlow->lruNextFlow = flowP->lruNextFlow;

        // handle cases where the A and B flows follow each other
        if (prev == flowP) prev = flowP->lruPrevFlow;

        --maxNumFlows;
    }

    return prev;
}


inline void cycleLRULists() {
#if FORCE_MODE == 1
    flow_t *lruFlowP;
    while (num_rm_flows) {
        lruFlowP = rm_flows[--num_rm_flows];
        lruPrintFlow(lruFlowP);
        removeFlow(lruFlowP);
    }
#endif // FORCE_MODE == 1

    timeout_t *t = timeout_list;
    while (t) {
        cycleLRUList(t);
        t = t->next;
    }
}


static inline void cycleLRUList(timeout_t *th) {
    float timeDiff;
    flow_t *revFlowP, *tmpFlowP;

    // from the timeout handler work backwards (commit and remove flows) until we
    // hit a flow which is younger than the timeout value of the timeout handler
    flow_t *lruFlowP = th->flow.lruPrevFlow;
    while (lruFlowP != &lruHead) {
        // if flow is a sentinel skip it
        if (FLOW_IS_SENTINEL(lruFlowP)) {
            lruFlowP = lruFlowP->lruPrevFlow;
            continue;
        }

        // check if flow would be too young and could not have timed-out
        timeDiff = actTime.tv_sec - lruFlowP->lastSeen.tv_sec;
        timeDiff += ((actTime.tv_usec - lruFlowP->lastSeen.tv_usec) / TSTAMPFAC);

        if (timeDiff < th->timeout) break; // flow too young

        tmpFlowP = lruFlowP->lruPrevFlow;

        if (timeDiff >= lruFlowP->timeout) {
            // only remove flow if the opposite flow has timed-out too
            if (!FLOW_HAS_OPPOSITE(lruFlowP)) {
                lruPrintFlow(lruFlowP);
                tmpFlowP = removeFlow(lruFlowP);
            } else {
                revFlowP = &flows[lruFlowP->oppositeFlowIndex];

                timeDiff = actTime.tv_sec - revFlowP->lastSeen.tv_sec;
                timeDiff += ((actTime.tv_usec - revFlowP->lastSeen.tv_usec) / TSTAMPFAC);

                if (timeDiff >= revFlowP->timeout) {
                    lruPrintFlow(lruFlowP);
                    tmpFlowP = removeFlow(lruFlowP);
                }
            }
        }

        lruFlowP = tmpFlowP;
    }

    if (lruFlowP != th->flow.lruPrevFlow) {
        // move timeout handler sentinel flow behind last inspected flow (behind lruFlowP)
        th->flow.lruNextFlow->lruPrevFlow = th->flow.lruPrevFlow; // take out, step 1
        th->flow.lruPrevFlow->lruNextFlow = th->flow.lruNextFlow; // take out, step 2

        th->flow.lruNextFlow = lruFlowP->lruNextFlow;             // place in, step 1
        th->flow.lruPrevFlow = lruFlowP;                          // place in, step 2

        lruFlowP->lruNextFlow->lruPrevFlow = &(th->flow); // connect, step 1
        lruFlowP->lruNextFlow = &(th->flow);              // connect, step 2
    }

    // if the LRU list is empty and we want to stop the application from creating new flows, terminate
    if (UNLIKELY(mainHashMap->freeListSize == mainHashMap->hashChainTableSize && (globalInt & GI_RUN) < GI_TERM_THRES)) {
        terminate();
    }
}


#if HASH_AUTOPILOT == 1
inline void lruRmLstFlow() {
    flow_t *lruFlowP = lruTail.lruPrevFlow;
    int n = NUMFLWRM;
    totalRmFlows += NUMFLWRM;
    while (lruFlowP != &lruHead && n > 0) {
        // skip sentinels
        if (FLOW_IS_SENTINEL(lruFlowP)) {
            lruFlowP = lruFlowP->lruPrevFlow;
            continue;
        }
        T2_SET_STATUS(lruFlowP, RMFLOW_HFULL);
        lruPrintFlow(lruFlowP);
        lruFlowP = removeFlow(lruFlowP);
        n--;
    }
}
#endif // HASH_AUTOPILOT == 1


// Print 'A' and 'B' flows (if present)
#if FDURLIMIT > 0
inline void lruPrintFlow(const flow_t * const flowP) {
#else // FDURLIMIT == 0
static inline void lruPrintFlow(const flow_t * const flowP) {
#endif // FDURLIMIT
    if (!FLOW_HAS_OPPOSITE(flowP)) {
        // flow does not have a reverse flow
        if (flowP->status & L3FLOWINVERT) corrReplFlws++;
        printFlow(flowP->flowIndex, 0);
    } else if (flowP->status & L3FLOWINVERT) {
        // flow is a 'B' flow
        printFlow(flowP->oppositeFlowIndex, 0);
        printFlow(flowP->flowIndex, 1);
    } else {
        // flow is an 'A' flow
        printFlow(flowP->flowIndex, 0);
        printFlow(flowP->oppositeFlowIndex, 1);
    }
}


#if BLOCK_BUF == 1
static inline void printFlow(unsigned long flowIndex, uint8_t dir UNUSED) {
#else
static inline void printFlow(unsigned long flowIndex, uint8_t dir) {
#endif
    if (UNLIKELY(flowIndex == HASHTABLE_ENTRY_NOT_FOUND)) return;

    flow_t * const flowP = &flows[flowIndex];

    // Compute the duration of the flow (local variables are required as the
    // flow_t structure is packed (see clang -Waddress-of-packed-member option)
    const struct timeval firstSeen = flowP->firstSeen;
    const struct timeval lastSeen = flowP->lastSeen;
    struct timeval duration;
    T2_TIMERSUB(&lastSeen, &firstSeen, &duration);
    flowP->duration = duration;

#if ALARM_MODE == 1
    supOut = 1;
#endif

#if BLOCK_BUF == 0
    OUTBUF_APPEND_U8(main_output_buffer, dir);
    OUTBUF_APPEND_U64(main_output_buffer, flowP->findex);
#endif

    FOREACH_PLUGIN_DO(onFlowTerm, flowIndex, main_output_buffer);

#if ALARM_MODE == 1
    if (supOut) {
#if BLOCK_BUF == 0
        outputBuffer_reset(main_output_buffer);
#endif
        return;
    }
#endif // ALARM_MODE

#if BLOCK_BUF == 0
    FOREACH_PLUGIN_DO(bufToSink, main_output_buffer, main_header_bv);
    outputBuffer_reset(main_output_buffer);
#endif
}


// Copy a 2D array (like argv) into a flat string
// Return a pointer to the flat string (MUST be free'd)
// Adapted from tcpdump
static char *copy_argv(char **argv) {
    char **p = argv;
    if (*p == 0) return 0;

    unsigned int len = 0;
    while (*p) len += strlen(*p++) + 1;

    if (len <= 1) return 0;

    char *buf = t2_malloc_fatal(len);
    char *dst = buf;

    p = argv;

    char *src;
    while ((src = *p++) != NULL) {
        while ((*dst++ = *src++) != '\0');
        dst[-1] = ' ';
    }

    dst[-1] = '\0';

    return buf;
}


static void t2_usage() {
    printf("%s - High performance flow based network traffic analyzer\n\n", T2_APPSTRING);

    printf("Usage:\n");
    printf("    tranalyzer [OPTION...] <INPUT>\n");

    printf("\nInput arguments:\n");
#if DPDK_MP == 0
    printf("    -i IFACE     Listen on interface IFACE\n");
    printf("    -r PCAP      Read packets from PCAP file or from stdin if PCAP is \"-\"\n");
    printf("    -R FILE      Process every PCAP file listed in FILE\n");
    printf("    -D EXPR[:SCHR][,STOP]\n");
    printf("                 Process every PCAP file whose name matches EXPR, up to an\n");
    printf("                 optional last index STOP. If STOP is omitted, then Tranalyzer\n");
    printf("                 never stops. EXPR can be a filename, e.g., file.pcap0, or an\n");
    printf("                 expression, such as \"dump*.pcap00\", where the star matches\n");
    printf("                 anything (note the quotes to prevent the shell from\n");
    printf("                 interpreting the expression). SCHR can be used to specify\n");
    printf("                 the last character before the index (default: '%c')\n", SCHR);
#else // DPDK_MP != 0
    printf("    -i PCIDEV    Listen on interface with PCI device ID PICDEV\n");
    printf("                 PCIDEV example: 0000:37:00.1\n");
    printf("                 Most cards need to have been bound to a DPDK compatible driver\n");
    printf("                 with dpdk-devbind.py. Except for Mellanox cards using the\n");
    printf("                 mlx5_core kernel driver.\n");
#endif // DPDK_MP != 0

    printf("\nOutput arguments:\n");
    printf("    -w PREFIX    Append PREFIX to any output file produced. If the option is\n");
    printf("                 omitted, derive PREFIX from the input. Use '-w -' to output\n");
    printf("                 the flow file to stdout (other files will be saved as if the\n");
    printf("                 '-w' option had been omitted and the '-l' and '-m' options used)\n");
    printf("    -W PREFIX[:SIZE][,START]\n");
    printf("                 Like -w, but fragment flow files according to SIZE, producing\n");
    printf("                 files starting with index START. SIZE can be specified in bytes\n");
    printf("                 (default), KB ('K'), MB ('M') or GB ('G'). Scientific notation,\n");
    printf("                 i.e., 1e5 or 1E5 (=100000), can be used as well. If a 'f' is\n");
    printf("                 appended, e.g., 10Kf, then SIZE denotes the number of flows.\n");
    printf("    -l           Print end report in PREFIX_log.txt instead of stdout\n");
    printf("    -m           Print monitoring output in PREFIX_monitoring.txt instead of stdout\n");
    printf("    -s           Packet forensics mode\n");

#if DPDK_MP != 0
    printf("\nDPDK arguments:\n");
    printf("    -N NUM       Set the number of processes to NUM\n");
    printf("    -I PID       Set the process ID to PID\n");
#endif // DPDK_MP != 0

    printf("\nInterface capture arguments:\n");
    printf("    -S SNAPLEN   Set the snapshot length (used with -i option)\n");
    printf("    -B BUFSIZE   Set the live Rx buffer size (used with -i option)\n");

    printf("\nOptional arguments:\n");
    printf("    -p PATH      Load plugins from PATH instead of ~/.tranalyzer/plugins\n");
#if USE_PLLIST > 0
    printf("    -b FILE      Use plugin list FILE instead of plugin_folder/plugins.txt\n");
#endif
    printf("    -e FILE      Create a PCAP file by extracting all packets belonging to\n");
    printf("                 flow indexes listed in FILE (require pcapd plugin)\n");
    printf("    -f FACTOR    Set hash multiplication factor\n");
    printf("    -x ID        Sensor ID\n");
#ifndef __APPLE__
    printf("    -c CPU       Bind tranalyzer to one core. If CPU is 0 then OS selects the\n");
    printf("                 core to bind\n");
#endif
    printf("    -P PRIO      Set tranalyzer priority to PRIO (int) instead of 0\n");
    printf("                 (PRIO [highest, lowest]: [-20, 20] (root), [0, 20] (user))\n");
    printf("    -M FLT       Set monitoring interval to FLT seconds\n");
    printf("    -F FILE      Read BPF filter from FILE\n");

    printf("\nHelp and documentation arguments:\n");
    printf("    -V           Show the version of the program and exit\n");
    printf("    -h           Show help options and exit\n");

    printf("\nRemaining arguments:\n");
    printf("    BPF          Berkeley Packet Filter command, as in tcpdump\n\n");
}


static void t2_version() {
    printf("%s (%s) [%s]\n", T2_APPSTRING, T2_CODENAME, T2_RELEASE);
}


static bool t2_validate_captype(uint16_t capType) {
    // check that at least one input source was specified
    if (UNLIKELY(!(capType & CAPTYPE_REQUIRED))) {
        T2_ERR("One of '-r', '-R', '-D' or '-i' option is required");
        return false;
    }

    // check that only one input source was specified
    if (UNLIKELY(capType & FILECNFLCT)) {
        T2_ERR("'-r', '-R', '-D' and '-i' options can only be used exclusively");
        return false;
    }

    return true;
}


static inline void terminateFlows() {
    if (LIKELY(totalFlows > 0)) {
        flow_t *lruFlowP = lruTail.lruPrevFlow;
        while (lruFlowP != &lruHead && LIKELY(globalInt)) {
            // Skip sentinels
            if (FLOW_IS_SENTINEL(lruFlowP)) {
                lruFlowP = lruFlowP->lruPrevFlow;
                continue;
            }

            lruPrintFlow(lruFlowP);
            lruFlowP = removeFlow(lruFlowP);
        }
    }
}


__attribute__((noreturn)) void terminate() {
    totalFlows = totalAFlows + totalBFlows;

    // commit all changes in all buffers
    fflush(NULL);

#if VERBOSE > 0
    t2_log_date(dooF, "Dump stop : ", actTime, TSTAMP_UTC);

    struct timeval duration;
    T2_TIMERSUB(&actTime, &startTStamp, &duration);
    t2_log_time(dooF, "Total dump duration: ", duration);

    struct timeval elapsed, endTime;
#if TSTAMP_PREC == 1
    struct timespec tmns;
    clock_gettime(CLOCK_REALTIME, &tmns);
    endTime.tv_sec = (time_t)tmns.tv_sec;
    endTime.tv_usec = tmns.tv_nsec;
#else // TSTAMP_PREC == 0
    gettimeofday(&endTime, NULL);
#endif // TSTAMP_PREC == 1
    T2_TIMERSUB(&endTime, &startTime, &elapsed);
    t2_log_time(dooF, "Finished processing. Elapsed time: ", elapsed);
#endif // VERBOSE > 0

    terminateFlows();

#if VERBOSE > 0
#if DIFF_REPORT == 1
    resetGStats0();
#endif // DIFF_REPORT == 1
    t2_print_report(dooF, false);
#endif // VERBOSE > 0

#if REPORT_HIST == 1
    t2_save_state();
#endif // REPORT_HIST == 1

    t2_cleanup();

    exit(EXIT_SUCCESS);
}


void printGStats() {
    totalFlows = totalAFlows + totalBFlows;

#if MACHINE_REPORT == 0
    t2_print_report(monFile, true);
#else // MACHINE_REPORT == 1
    t2_machine_report(monFile);
#endif // MACHINE_REPORT == 1

#if DIFF_REPORT == 1
    updateGStats0();
#endif // DIFF_REPORT == 1
}


#if VERBOSE > 0 || MACHINE_REPORT == 0
static inline void t2_print_report(FILE *stream, bool monitoring) {
    struct timeval duration;
    T2_TIMERSUB(&actTime, monitoring ? &startTStamp0 : &startTStamp, &duration);

    struct timeval endTime;
#if TSTAMP_PREC == 1
    struct timespec tmns;
    clock_gettime(CLOCK_REALTIME, &tmns);
    endTime.tv_sec = (time_t)tmns.tv_sec;
    endTime.tv_usec = tmns.tv_nsec;
#else // TSTAMP_PREC == 0
    gettimeofday(&endTime, NULL);
#endif // TSTAMP_PREC == 1

    struct timeval elapsed;
    T2_TIMERSUB(&endTime, &startTime, &elapsed);

    if (!monitoring) {
        t2_log_time(stream, "Finished unloading flow memory. Time: ", elapsed);
    } else {
        T2_PRINT_BANNER(stream);
        T2_FLOG(stream, "USR1 %c type report: %s %s (%s), %s. PID: %d",
                REPTYPE, T2_APPNAME, T2_VERSION, T2_CODENAME, T2_RELEASE, getpid());
        if (!(capType & IFACE)) {
            t2_log_date(stream, "PCAP time: ", actTime, TSTAMP_UTC);
            t2_log_time(stream, "PCAP duration: ", duration);
        }
        t2_log_date(stream, "Time: ", endTime, TSTAMP_R_UTC);
        t2_log_time(stream, "Elapsed time: ", elapsed);
    }

#if DPDK_MP == 0
    if ((capType & CAPFILE) && captureFileSize) {
        if (monitoring) {
            T2_FLOG(stream, "Processing file: %s", capName);
            T2_LOG_LINK_LAYER_TYPE(stream, captureDescriptor);
            T2_FLOG_NUM0(stream, "Snapshot length", pcap_snapshot(captureDescriptor));
            T2_FLOG_NUM0(stream, "Total bytes to process", captureFileSize);
        }
        T2_LOG_PERCENT(stream, 1, captureFileSize);
    } else if ((capType & LISTFILE) && caplist->size) {
        if (monitoring) {
            T2_FLOG(stream, "Processing list file: %s", capName);
            T2_FLOG(stream, "Processing file no. %" PRIu32 " of %" PRIu32 ": %s",
                    caplist_index + 1, caplist->num_files, caplist_elem->name);
            T2_LOG_LINK_LAYER_TYPE(stream, captureDescriptor);
            T2_FLOG_NUM0(stream, "Snapshot length", pcap_snapshot(captureDescriptor));
            T2_FLOG_NUM0(stream, "Total bytes to process", caplist->size);
            T2_FLOG_NUM0(stream, "Current file size in bytes", caplist_elem->size);
        }
        T2_LOG_PERCENT(stream, caplist->num_files, caplist->size);
    } else if (capType & DIRFILE) {
        if (monitoring) {
            T2_FLOG(stream, "Current file: %s", globFName);
            T2_LOG_LINK_LAYER_TYPE(stream, captureDescriptor);
            T2_FLOG_NUM0(stream, "Snapshot length", pcap_snapshot(captureDescriptor));
        }
        T2_LOG_PERCENT(stream, 1, captureFileSize);
    } else if ((capType & IFACE) && captureDescriptor) {
        if (monitoring) {
            T2_FLOG(stream, "Live capture on interface: %s", capName);
            T2_LOG_LINK_LAYER_TYPE(stream, captureDescriptor);
            T2_FLOG_NUM0(stream, "Snapshot length", pcap_snapshot(captureDescriptor));
        }
        struct pcap_stat ps;
        pcap_stats(captureDescriptor, &ps);
        const uint64_t ps_tot = (ps.ps_recv + ps.ps_drop + ps.ps_ifdrop);
        T2_FLOG_NUMP(stream, "Number of packets received", ps.ps_recv, ps_tot);
        T2_FLOG_NUMP(stream, "Number of packets dropped by the kernel", ps.ps_drop, ps_tot);
        T2_FLOG_NUMP(stream, "Number of packets dropped by the interface", ps.ps_ifdrop, ps_tot);
    }
#else // DPDK_MP == 1
    // Get stats for port
    if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
        struct rte_eth_stats stats;
        if (rte_eth_stats_get(dpdk_port_id, &stats) != 0) {
            T2_WRN("Failed to get statistics for port %" PRIu16 " from DPDK", dpdk_port_id);
        } else {
            const uint64_t ps_tot = stats.ipackets + stats.imissed + stats.ierrors;
            T2_FLOG_NUMP(stream, "Number of packets received", stats.ipackets, ps_tot);
            T2_FLOG_NUMP(stream, "Number of packets dropped by the HW", stats.imissed, ps_tot);
            T2_FLOG_NUMP(stream, "Number of erroneous received packets", stats.ierrors, ps_tot);
            T2_FLOG_NUM(stream, "Number of bytes received", stats.ibytes);
        }
    }
#endif // DPDK_MP == 0

    if (monitoring) {
        // 24 = size of global pcap header,
        // 16 = pcap header of every capture packet.
        // (see http://wiki.wireshark.org/Development/LibpcapFileFormat)
        float pb;
        if ((capType & CAPFILE) && captureFileSize) {
            pb = 24 + bytesProcessed + (numPackets * 16);
            T2_FLOG_NUM(stream, "Total bytes processed so far", pb);
            pb /= (double)captureFileSize;
        } else if ((capType & LISTFILE) && caplist->size) {
            pb = ((24 * caplist->num_files) + bytesProcessed + (numPackets * 16)) / (double)caplist->size;
        } else {
            pb = 1.0;
        }

        if (!(capType & IFACE) && pb > 0.0) {
            const double u = (elapsed.tv_sec + elapsed.tv_usec/TSTAMPFAC);
            const double c = (1.0 - pb) / pb;
            const double d = u * c;
            const uint64_t a = (uint64_t)d;
            elapsed.tv_sec = a;
            elapsed.tv_usec = (d - a) * TSTAMPFAC;
            t2_log_time(stream, "Remaining time: ", elapsed);
            struct timeval etfTime;
            T2_TIMERADD(&endTime, &elapsed, &etfTime);
            t2_log_date(stream, "ETF: ", etfTime, TSTAMP_R_UTC);
        }
    }

    T2_LOG_DIFFNUM(stream, "Number of processed packets", numPackets);
    T2_LOG_DIFFNUM(stream, "Number of processed bytes", bytesProcessed);
    T2_LOG_DIFFNUM(stream, "Number of raw bytes", rawBytesOnWire);
    T2_LOG_DIFFNUM(stream, "Number of pad bytes", padBytesOnWire);
    if (!monitoring && !(capType & IFACE)) {
        T2_FLOG_NUM(stream, "Number of pcap bytes", captureFileSize);
    }

    T2_LOG_DIFFNUMP(stream, "Number of L2 packets", numL2Packets, numPackets);
    T2_LOG_DIFFNUMP(stream, "Number of IPv4 packets", numV4Packets, numPackets);
    T2_LOG_DIFFNUMP(stream, "Number of IPv6 packets", numV6Packets, numPackets);
    T2_LOG_DIFFNUMP(stream, "Number of IPvX packets", numVxPackets, numPackets);

    const double numABBytes       = numABytes      + numBBytes;
    const double numABBytes0      = numABytes0     + numBBytes0;
    const double numABPackets     = numAPackets    + numBPackets;
    const double numABPackets0    = numAPackets0   + numBPackets0;
    const double numABytesDiff    = numABytes      - numABytes0;
    const double numBBytesDiff    = numBBytes      - numBBytes0;
    const double numBytesDiff     = bytesProcessed - bytesProcessed0;
    const double numPacketsDiff   = numPackets     - numPackets0;
    const double numAPacketsDiff  = numAPackets    - numAPackets0;
    const double numBPacketsDiff  = numBPackets    - numBPackets0;
    const double numABPacketsDiff = numABPackets   - numABPackets0;

    if (numPacketsDiff != numABPacketsDiff && numABPacketsDiff > 0) {
        T2_FLOG_NUMP(stream, "Number of packets without flow",
                (numPacketsDiff - numABPacketsDiff), numPacketsDiff);
    }

    T2_LOG_DIFFNUMP(stream, "Number of A packets", numAPackets, numABPackets);
    T2_LOG_DIFFNUMP(stream, "Number of B packets", numBPackets, numABPackets);

    T2_LOG_DIFFNUMP(stream, "Number of A bytes", numABytes, numABBytes);
    T2_LOG_DIFFNUMP(stream, "Number of B bytes", numBBytes, numABBytes);

    double pktLd = numAPacketsDiff ? (numABytesDiff / numAPacketsDiff) : 0.0;
    //if (pktLd > pktALdMax) pktALdMax = pktLd;
    //if (pktLd && pktLd < pktALdMin) pktALdMin = pktLd;
    char hrnum[64];
    T2_CONV_NUM(pktLd, hrnum);
    T2_FLOG(stream, "<A packet load>: %.2f%s", pktLd, hrnum);
#if MIN_MAX_ESTIMATE > 0
    T2_CONV_NUM(pktALdMax, hrnum);
    T2_FLOG(stream, "Max A packet load: %.2f%s", pktALdMax, hrnum);
    T2_CONV_NUM(pktALdMin, hrnum);
    T2_FLOG(stream, "Min A packet load: %.2f%s", pktALdMin, hrnum);
#endif // MIN_MAX_ESTIMATE > 0

    pktLd = numBPacketsDiff ? (numBBytesDiff / numBPacketsDiff) : 0.0;
    //if (pktLd > pktBLdMax) pktBLdMax = pktLd;
    //if (pktLd && pktLd < pktBLdMin) pktBLdMin = pktLd;
    T2_CONV_NUM(pktLd, hrnum);
    T2_FLOG(stream, "<B packet load>: %.2f%s", pktLd, hrnum);
#if MIN_MAX_ESTIMATE > 0
    T2_CONV_NUM(pktBLdMax, hrnum);
    T2_FLOG(stream, "Max B packet load: %.2f%s", pktBLdMax, hrnum);
    T2_CONV_NUM(pktBLdMin, hrnum);
    T2_FLOG(stream, "Min B packet load: %.2f%s", pktBLdMin, hrnum);
#endif // MIN_MAX_ESTIMATE > 0

#if PLUGIN_REPORT > 0
    fputs("--------------------------------------------------------------------------------\n", stream);
    if (monitoring) {
        FOREACH_PLUGIN_DO(monitoring, stream, T2_MON_PRI_REPORT);
    } else {
        FOREACH_PLUGIN_DO(report, stream);
    }
#endif // PLUGIN_REPORT > 0

    fputs("--------------------------------------------------------------------------------\n", stream);

#if T2_PRI_HDRDESC == 1
    T2_FLOG(stream, "Headers count: min: %" PRIu16 ", max: %" PRIu16 ", avg: %.2f",
            minHdrDesc, maxHdrDesc, avgHdrDesc);
#endif // T2_PRI_HDRDESC == 1

    if (globalWarn & L2_VLAN) T2_FLOG(stream, "Max VLAN header count: %" PRIu8, vlanHdrCntMx);
    if (globalWarn & L2_MPLS) T2_FLOG(stream, "Max MPLS header count: %" PRIu8, mplsHdrCntMx);

    T2_LOG_DIFFNUMP(stream, "Number of LLC packets"   , numLLCPackets, numPackets);
    T2_FLOG_NUMP(stream   , "Number of ARP packets"   , (numPacketsL2[ETHERTYPE_ARP]  - numPackets0L2[ETHERTYPE_ARP] ), numPacketsDiff);
    T2_FLOG_NUMP(stream   , "Number of RARP packets"  , (numPacketsL2[ETHERTYPE_RARP] - numPackets0L2[ETHERTYPE_RARP]), numPacketsDiff);
    T2_LOG_DIFFNUMP(stream, "Number of GRE packets"   , numGREPackets   , numPackets);
    T2_LOG_DIFFNUMP(stream, "Number of LAPD packets"  , numLAPDPackets  , numPackets);
    T2_LOG_DIFFNUMP(stream, "Number of Teredo packets", numTeredoPackets, numPackets);
    T2_LOG_DIFFNUMP(stream, "Number of AYIYA packets" , numAYIYAPackets , numPackets);
    T2_FLOG_NUMP(stream   , "Number of IGMP packets"  , (numPacketsL3[L3_IGMP]  - numPackets0L3[L3_IGMP] ), numPacketsDiff);
    T2_FLOG_NUMP(stream   , "Number of ICMP packets"  , (numPacketsL3[L3_ICMP]  - numPackets0L3[L3_ICMP] ), numPacketsDiff);
    T2_FLOG_NUMP(stream   , "Number of ICMPv6 packets", (numPacketsL3[L3_ICMP6] - numPackets0L3[L3_ICMP6]), numPacketsDiff);
    T2_FLOG_NUMP(stream   , "Number of TCP packets"   , (numPacketsL3[L3_TCP]   - numPackets0L3[L3_TCP]  ), numPacketsDiff);
    T2_FLOG_NUMP(stream   , "Number of TCP bytes"     , (numBytesL3[L3_TCP]     - numBytes0L3[L3_TCP]    ), numBytesDiff);
    T2_FLOG_NUMP(stream   , "Number of UDP packets"   , (numPacketsL3[L3_UDP]   - numPackets0L3[L3_UDP]  ), numPacketsDiff);
    T2_FLOG_NUMP(stream   , "Number of UDP bytes"     , (numBytesL3[L3_UDP]     - numBytes0L3[L3_UDP]    ), numBytesDiff);
    if (globalWarn & L4_SCTP) {
        T2_FLOG_NUMP(stream, "Number of SCTP packets", (numPacketsL3[L3_SCTP] - numPackets0L3[L3_SCTP]), numPacketsDiff);
        T2_FLOG_NUMP(stream, "Number of SCTP bytes"  , (numBytesL3[L3_SCTP]   - numBytes0L3[L3_SCTP]  ), numBytesDiff);
    }
#if DTLS == 1
    T2_LOG_DIFFNUMP(stream, "Number of DTLS packets" , numDTLSPackets , numPackets);
#endif // DTLS == 1

#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
    T2_LOG_DIFFNUMP(stream, "Number of IPv4 fragmented packets", numFragV4Packets, numV4Packets);
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2

#if IPV6_ACTIVATE > 0
    T2_LOG_DIFFNUMP(stream, "Number of IPv6 fragmented packets", numFragV6Packets, numV6Packets);
#endif // IPV6_ACTIVATE > 0

    fputs("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n", stream);

    const double totalFlowsDiff = totalFlows - totalFlows0;
    if (totalFlowsDiff > 0) {
        const double totalAFlowsDiff    = totalAFlows     - totalAFlows0;
        const double totalBFlowsDiff    = totalBFlows     - totalBFlows0;
        const double totalIPv4FlowsDiff = totalIPv4Flows  - totalIPv4Flows0;
        const double totalIPv6FlowsDiff = totalIPv6Flows  - totalIPv6Flows0;
        const double totalL2FlowsDiff   = totalL2Flows    - totalL2Flows0;
        const double corrReplFlwsDiff   = corrReplFlws    - corrReplFlws0;
        const double aflwcorrDiff       = totalAFlowsDiff - corrReplFlwsDiff;
        const double bflwcorrDiff       = totalBFlowsDiff + corrReplFlwsDiff;

        T2_LOG_DIFFNUM0(stream, "Number of processed      flows", totalFlows);
        T2_FLOG_NUMP(stream,    "Number of processed L2   flows", totalL2FlowsDiff  , totalFlowsDiff);
        T2_FLOG_NUMP(stream,    "Number of processed IPv4 flows", totalIPv4FlowsDiff, totalFlowsDiff);
        T2_FLOG_NUMP(stream,    "Number of processed IPv6 flows", totalIPv6FlowsDiff, totalFlowsDiff);
        T2_FLOG_NUMP(stream,    "Number of processed A    flows", totalAFlowsDiff   , totalFlowsDiff);
        T2_FLOG_NUMP(stream,    "Number of processed B    flows", totalBFlowsDiff   , totalFlowsDiff);
        T2_FLOG_NUMP(stream,    "Number of request        flows", aflwcorrDiff      , totalFlowsDiff);
        T2_FLOG_NUMP(stream,    "Number of reply          flows", bflwcorrDiff      , totalFlowsDiff);

        T2_FLOG(stream, "Total   A/B    flow asymmetry: %.2f", (totalAFlowsDiff - totalBFlowsDiff) / totalFlowsDiff);
        T2_FLOG(stream, "Total req/rply flow asymmetry: %.2f", (aflwcorrDiff - bflwcorrDiff) / totalFlowsDiff);

        if (numABPacketsDiff > 0) {
            const double tmp = numABPacketsDiff / totalFlowsDiff;
            T2_CONV_NUM(tmp, hrnum);
            T2_FLOG(stream, "Number of processed A+B packets/A+B flows: %.2f%s", tmp, hrnum);
        }

        if (totalAFlowsDiff > 0) {
            const double tmp = numAPacketsDiff / totalAFlowsDiff;
            T2_CONV_NUM(tmp, hrnum);
            T2_FLOG(stream, "Number of processed A   packets/A   flows: %.2f%s", tmp, hrnum);
        }

        if (totalBFlowsDiff > 0) {
            const double tmp = numBPacketsDiff / totalBFlowsDiff;
            T2_CONV_NUM(tmp, hrnum);
            T2_FLOG(stream, "Number of processed   B packets/  B flows: %.2f%s", tmp, hrnum);
        }
    }

    const double f = duration.tv_sec + duration.tv_usec / TSTAMPFAC;
    if (f > 0) {
        const double tmp = numPacketsDiff / f;
        T2_CONV_NUM(tmp, hrnum);
        T2_FLOG(stream, "Number of processed total packets/s: %.2f%s", tmp, hrnum);

        if (numABPacketsDiff > 0) {
            const double tmp = numABPacketsDiff / f;
            T2_CONV_NUM(tmp, hrnum);
            T2_FLOG(stream, "Number of processed A+B   packets/s: %.2f%s", tmp, hrnum);

            if (numAPacketsDiff > 0) {
                const double tmp = numAPacketsDiff / f;
                T2_CONV_NUM(tmp, hrnum);
                T2_FLOG(stream, "Number of processed A     packets/s: %.2f%s", tmp, hrnum);
            }

            if (numBPacketsDiff > 0) {
                const double tmp = numBPacketsDiff / f;
                T2_CONV_NUM(tmp, hrnum);
                T2_FLOG(stream, "Number of processed   B   packets/s: %.2f%s", tmp, hrnum);
            }
        }
    }

    fputs("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n", stream);

    if (f > 0) {
        const double tmp = totalFlowsDiff / f;
        T2_CONV_NUM(tmp, hrnum);
        T2_FLOG(stream, "<Number of processed flows/s>: %.2f%s", tmp, hrnum);

        T2_LOG_SPEED(stream, "<Bandwidth>", (bytesOnWire - bytesOnWire0) / f);
        if (globalWarn & SNAPLENGTH) {
            T2_LOG_SPEED(stream, "<Snapped bandwidth>", (bytesProcessed - bytesProcessed0) / f);
        }
        T2_LOG_SPEED(stream, "<Raw bandwidth>", (rawBytesOnWire - rawBytesOnWire0) / f);

#if MIN_MAX_ESTIMATE > 0
        T2_LOG_SPEED(stream, "<IIR raw bandwidth>", bave / MMXLAGTMS);
        T2_LOG_SPEED(stream, "Stddev IIR raw bandwidth", sqrt(bvar) / MMXLAGTMS);
        T2_LOG_SPEED(stream, "Max raw bandwidth", maxBytesPs / MMXLAGTMS);
        T2_LOG_SPEED(stream, "Min raw bandwidth", minBytesPs / MMXLAGTMS);
#endif // MIN_MAX_ESTIMATE > 0
    }

    if (mainHashMap) {
        if (monitoring) {
            const uint64_t fillSize = mainHashMap->hashChainTableSize - mainHashMap->freeListSize;
            T2_FLOG(stream, "Fill size of main hash map: %" PRIu64 " [%.2f%%]",
                    fillSize, 100.0f * fillSize / (double) (mainHashMap->hashChainTableSize));
        }
        T2_FLOG_NUMP(stream, "Max number of flows in memory", maxNumFlowsPeak, mainHashMap->hashChainTableSize);
    }

#if HASH_AUTOPILOT == 1
    T2_LOG_DIFFNUMP(stream, "Number of flows terminated by autopilot", totalRmFlows, totalFlows);
#endif // HASH_AUTOPILOT == 1

    struct rusage r_usage;
    getrusage(RUSAGE_SELF, &r_usage);

    const double memtotal = ((double)sysconf(_SC_PHYS_PAGES) * (double)sysconf(_SC_PAGESIZE));
    double maxrss = r_usage.ru_maxrss;
#ifdef __APPLE__
    maxrss /= 1000; // ru_maxrss is in KB on Linux, but in bytes on macOS
#endif // __APPLE__
    T2_FLOG(stream, "Memory usage: %.2f GB [%.2f%%]", maxrss / 1000000.0, 100.0f * (maxrss * 1000.0) / memtotal);

    T2_FLOG(stream, "Aggregated flowStat=0x%016" B2T_PRIX64, globalWarn);

    if (numAlarms) {
        char str[64], str1[64];
        const uint64_t numAlarmsDiff = numAlarms - numAlarms0;
        const uint64_t numAlarmFlowsDiff = numAlarmFlows - numAlarmFlows0;
        T2_CONV_NUM(numAlarmsDiff, str1);
        T2_CONV_NUM(numAlarmFlowsDiff, str);
        T2_FWRN(stream, "%" PRIu64 "%s alarms in %" PRIu64 "%s flows [%.2f%%]",
                numAlarmsDiff, str1, numAlarmFlowsDiff, str, 100.0 * numAlarmFlowsDiff / totalFlowsDiff);
    }

#if FORCE_MODE == 1
    if (numForced) {
        char str[64];
        const uint64_t numForcedDiff = numForced - numForced0;
        T2_CONV_NUM(numForcedDiff, str);
        T2_FWRN(stream, "Number of flows terminated by force mode: %" PRIu64 "%s [%.2f%%]",
                numForcedDiff, str, 100.0 * numForcedDiff / totalFlowsDiff);
    }
#endif // FORCE_MODE == 1

#if PKT_CB_STATS == 1
    T2_FLOG(stream, "Per packet CPU time: min: %.9f, max: %.9f, avg: %.9f, std: %.9f",
            minCpuTime, maxCpuTime, avgCpuTime, sqrt(varCpuTime));
    //T2_FLOG(stream, "Per packet CPU time: min: %.9g, max: %.9g, avg: %.9g, std: %.9g", minCpuTime, maxCpuTime, avgCpuTime, sqrt(varCpuTime));
#endif // PKT_CB_STATS == 1

    T2_PRINT_GLOBALWARN(stream);

    if (monitoring) fputs("================================================================================\n\n", stream);

    fflush(stream);
}
#endif // VERBOSE > 0 || MACHINE_REPORT == 0


#if MACHINE_REPORT == 1
inline void t2_machine_report_header(FILE *stream) {
    fputs(HDR_CHR
          "repType"  SEP_CHR
          "sensorID" SEP_CHR
#if DPDK_MP == 1
          "procID"   SEP_CHR
#endif // DPDK_MP == 1
          "time"     SEP_CHR
          "duration" SEP_CHR
          , stream);

    if (capType & IFACE) {
#if DPDK_MP == 1
        // Only report global stats for port in primary process
        if (rte_eal_process_type() == RTE_PROC_PRIMARY)
#endif // DPDK_MP == 1
            fputs("pktsRec"   SEP_CHR
                  "pktsDrp"   SEP_CHR
#if DPDK_MP == 1
                  "pktsErr"   SEP_CHR
                  "bytesRec"  SEP_CHR
#else // DPDK_MP == 0
                  "ifDrp"     SEP_CHR
#endif // DPDK_MP == 0
                  , stream);
    }

    fputs("memUsageKB"    SEP_CHR
          "fillSzHashMap" SEP_CHR
          "numFlows"      SEP_CHR
          "numAFlows"     SEP_CHR
          "numBFlows"     SEP_CHR
          "numPkts"       SEP_CHR
          "numAPkts"      SEP_CHR
          "numBPkts"      SEP_CHR
          "numL2Pkts"     SEP_CHR
          "numV4Pkts"     SEP_CHR
          "numV6Pkts"     SEP_CHR
          "numVxPkts"     SEP_CHR
          "numBytes"      SEP_CHR
          "numABytes"     SEP_CHR
          "numBBytes"     SEP_CHR
          "numFrgV4Pkts"  SEP_CHR
          "numFrgV6Pkts"  SEP_CHR
          "numAlarms"     SEP_CHR
          "rawBandwidth"  SEP_CHR
          "globalWarn"    SEP_CHR
          , stream);

    uint_fast32_t i;

    for (i = 0; i < NUMMONPL2; i++) {
        fprintf(stream,
                "0x%04" B2T_PRIX16 "Pkts"  SEP_CHR
                "0x%04" B2T_PRIX16 "Bytes" SEP_CHR
                , monProtL2[i], monProtL2[i]);
    }

    for (i = 0; i < NUMMONPL3; i++) {
#if MONPROTMD == 1
        fprintf(stream,
                "%sPkts"  SEP_CHR
                "%sBytes" SEP_CHR
                , ipProtSn[monProtL3[i]], ipProtSn[monProtL3[i]]);
#else // MONPROTMD == 0
        fprintf(stream,
                "%" PRIu8 "Pkts"  SEP_CHR
                "%" PRIu8 "Bytes" SEP_CHR
                , monProtL3[i], monProtL3[i]);
#endif // MONPROTMD == 0
    }

    FOREACH_PLUGIN_DO(monitoring, stream, T2_MON_PRI_HDR);

    t2_discard_trailing_chars(stream, SEP_CHR, sizeof(SEP_CHR) - 1);
    fputc('\n', stream);

    fflush(stream);
}
#endif // MACHINE_REPORT == 1


#if MACHINE_REPORT == 1
inline void t2_machine_report(FILE *stream) {
    struct timeval duration;
    T2_TIMERSUB(&actTime, &startTStamp0, &duration);

    const time_t time_sec = actTime.tv_sec;
    const intmax_t time_usec = actTime.tv_usec;
    const time_t dur_sec = duration.tv_sec;
    const intmax_t dur_usec = duration.tv_usec;

    fprintf(stream,
            "USR1MR_%c" /* repType  */ SEP_CHR
            "%" PRIu32  /* sensorID */ SEP_CHR
#if DPDK_MP == 1
            "%d"        /* procID   */ SEP_CHR
#endif // DPDK_MP == 1
            "%" PRIu32 ".%" T2_PRI_USEC /* time     */ SEP_CHR
            "%" PRIu32 ".%" T2_PRI_USEC /* duration */ SEP_CHR
            , REPTYPE
            , sensorID
#if DPDK_MP == 1
           , dpdk_proc_id
#endif // DPDK_MP == 1
            , (uint32_t)time_sec, time_usec
            , (uint32_t)dur_sec, dur_usec);

    if (capType & IFACE) {
#if DPDK_MP == 1
        // Get stats for port
        if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
            struct rte_eth_stats stats = {};
            if (rte_eth_stats_get(dpdk_port_id, &stats) != 0) {
                T2_WRN("Failed to get statistics for port %" PRIu16 " from DPDK", dpdk_port_id);
            }
            fprintf(stream,
                    "%" PRIu64 /* pktsRec  */ SEP_CHR
                    "%" PRIu64 /* pktsDrp  */ SEP_CHR
                    "%" PRIu64 /* pktsErr  */ SEP_CHR
                    "%" PRIu64 /* bytesRec */ SEP_CHR
                    , stats.ipackets
                    , stats.imissed
                    , stats.ierrors
                    , stats.ibytes);
        }
#else // DPDK_MP == 0
        struct pcap_stat ps;
        pcap_stats(captureDescriptor, &ps);
        fprintf(stream,
                "%u" /* pktsRec */ SEP_CHR
                "%u" /* pktsDrp */ SEP_CHR
                "%u" /* ifDrp   */ SEP_CHR
                , ps.ps_recv, ps.ps_drop, ps.ps_ifdrop);
#endif // DPDK_MP == 0
    }

    struct rusage r_usage;
    getrusage(RUSAGE_SELF, &r_usage);

    uint64_t memmax = r_usage.ru_maxrss;
#ifdef __APPLE__
    memmax /= 1000; // ru_maxrss is in KB on Linux, but in bytes on macOS
#endif // __APPLE__

    const int64_t fillSz = ((mainHashMap) ? (mainHashMap->hashChainTableSize - mainHashMap->freeListSize - hshFSize0) : 0);

    const float f = duration.tv_sec + duration.tv_usec / TSTAMPFAC;

    fprintf(stream,
            "%"      PRId64     /* memUsageKB    */ SEP_CHR
            "%"      PRId64     /* fillSzHashMap */ SEP_CHR
            "%"      PRIu64     /* numFlows      */ SEP_CHR
            "%"      PRIu64     /* numAFlows     */ SEP_CHR
            "%"      PRIu64     /* numBFlows     */ SEP_CHR
            "%"      PRIu64     /* numPkts       */ SEP_CHR
            "%"      PRIu64     /* numAPkts      */ SEP_CHR
            "%"      PRIu64     /* numBPkts      */ SEP_CHR
            "%"      PRIu64     /* numL2Pkts     */ SEP_CHR
            "%"      PRIu64     /* numV4Pkts     */ SEP_CHR
            "%"      PRIu64     /* numV6Pkts     */ SEP_CHR
            "%"      PRIu64     /* numVxPkts     */ SEP_CHR
            "%"      PRIu64     /* numBytes      */ SEP_CHR
            "%"      PRIu64     /* numABytes     */ SEP_CHR
            "%"      PRIu64     /* numBBytes     */ SEP_CHR
            "%"      PRIu64     /* numFrgV4Pkts  */ SEP_CHR
            "%"      PRIu64     /* numFrgV6Pkts  */ SEP_CHR
            "%"      PRIu64     /* numAlarms     */ SEP_CHR
            "%.3f"              /* rawBandwidth  */ SEP_CHR
            "0x%016" B2T_PRIX64 /* globalWarn    */ SEP_CHR
            , (int64_t)(memmax - memmax0)
            , fillSz
            , totalFlows - totalFlows0
            , totalAFlows - totalAFlows0
            , totalBFlows - totalBFlows0
            , numPackets - numPackets0
            , numAPackets - numAPackets0
            , numBPackets - numBPackets0
            , numL2Packets - numL2Packets0
            , numV4Packets - numV4Packets0
            , numV6Packets - numV6Packets0
            , numVxPackets - numVxPackets0
            , bytesProcessed - bytesProcessed0
            , numABytes - numABytes0
            , numBBytes - numBBytes0
            , numFragV4Packets - numFragV4Packets0
            , numFragV6Packets - numFragV6Packets0
            , numAlarms - numAlarms0
            , ((f == 0.0f) ? 0.0f : ((rawBytesOnWire - rawBytesOnWire0) * 8 / f))
            , globalWarn);

    uint_fast32_t i;
    for (i = 0; i < NUMMONPL2; i++) {
        fprintf(stream,
                "%" PRIu64 "" SEP_CHR
                "%" PRIu64 "" SEP_CHR
                , numPacketsL2[monProtL2[i]] - numPackets0L2[monProtL2[i]]
                , numBytesL2[monProtL2[i]] - numBytes0L2[monProtL2[i]]);
    }

    for (i = 0; i < NUMMONPL3; i++) {
        fprintf(stream,
                "%" PRIu64 "" SEP_CHR
                "%" PRIu64 "" SEP_CHR
                , numPacketsL3[monProtL3[i]] - numPackets0L3[monProtL3[i]]
                , numBytesL3[monProtL3[i]] - numBytes0L3[monProtL3[i]]);
    }

    FOREACH_PLUGIN_DO(monitoring, stream, T2_MON_PRI_VAL);

    t2_discard_trailing_chars(stream, SEP_CHR, sizeof(SEP_CHR) - 1);
    fputc('\n', stream);

    fflush(stream);
}
#endif // MACHINE_REPORT == 1


static void t2_cleanup() {
    t2_unload_plugins(t2_plugins);

    // commit all changes in all buffers
    fflush(NULL);

    // terminate timeout handlers
    timeout_t *tcurr = timeout_list;
    timeout_t *tnext;
    while (tcurr) {
        tnext = tcurr->next;
        free(tcurr);
        tcurr = tnext;
    }

#if DPDK_MP == 0
    if (captureDescriptor) pcap_close(captureDescriptor);
#else // DPDK_MP != 0
    rte_eal_cleanup();
#endif // DPDK_MP == 0

    if (sPktFile) fclose(sPktFile);

#if VERBOSE > 0
    if (dooF != stdout) fclose(dooF);
#endif

    if (monFile != stdout) {
        fclose(monFile);
        // Delete the monitoring file if empty
        char filename[MAX_FILENAME_LEN] = {};
        t2_strcat(filename, sizeof(filename), baseFileName, MON_SUFFIX, NULL);
        struct stat stats;
        if (stat(filename, &stats) == 0 && stats.st_size == 0) {
            remove(filename);
        }
    }

#if PID_FNM_ACT == 1
    t2_destroy_pid_file();
#endif // PID_FNM_ACT == 1

    // free memory
    free(baseFileName);
    free(bpfCommand);
    free(cmdline);
    free(flows);
    free(pluginFolder);
    free(last_err);

    hashTable_destroy(mainHashMap);

#if FRAGMENTATION == 1
    hashTable_destroy(fragPendMap);
    free(fragPend);
#endif // FRAGMENTATION == 1

#if SUBNET_INIT != 0
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
    subnettable4_destroy(subnetTable4P);
#endif
#if IPV6_ACTIVATE > 0
    subnettable6_destroy(subnetTable6P);
#endif
#endif // SUBNET_INIT != 0

    outputBuffer_destroy(main_output_buffer);
    bv_header_destroy(main_header_bv);

    if (capType & DIRFILE) {
        free(capName);
        free(globFName);
    } else if (capType & LISTFILE) {
        caplist_elem = caplist->file_list;
        while (caplist_elem) {
            caplist_elem_t *next = caplist_elem->next;
            free(caplist_elem->name);
            free(caplist_elem);
            caplist_elem = next;
        }
        free(caplist);
    }

    // destroy T2 file manager
    file_manager_destroy(t2_file_manager);

    // verify any possible memory leaks (if MEMORY_DEBUG == 1)
    memdebug_check_leak();
}


static inline void sigHandler(int scode) {
#if USE_T2BUS == 1
    // XXX FIXME temporary code to illustrate t2BusCallback usage
    for (uint_fast32_t i = 0; i < t2_plugins->num_plugins; i++) {
        if (t2_plugins->plugin[i].t2BusCb.cb) {
            const uint16_t plugin_number = t2_plugins->plugin[i].t2BusCb.pl_num;
            t2_plugins->plugin[i].t2BusCb.cb(plugin_number);
        }
    }
#endif // USE_T2BUS == 1

    switch (scode) {
        case SIGINT:
            if (globalInt && (--globalInt & GI_RUN)) {
#if VERBOSE > 0
                if ((globalInt & GI_RUN) == GI_EXIT + 1) {
                    T2_INF("SIGINT: Stop flow creation, when all pending flows timeout (%ds): exit", FLOW_TIMEOUT);
                } else if ((globalInt & GI_RUN) == GI_EXIT) {
                    T2_INF("SIGINT: Remove all flows and exit");
                }
#endif // VERBOSE > 0
                break;
            }
#if VERBOSE > 0
            T2_INF("SIGINT: Terminate, terminate.");
#endif // VERBOSE > 0
            break;

        case SIGTERM:
            if (globalInt == GI_EXIT) exit(EXIT_FAILURE);
#if VERBOSE > 0
            T2_INF("SIGTERM: Terminate, terminate. Remove all flows and exit");
#endif // VERBOSE > 0
            globalInt = GI_EXIT;
            //globalInt = GI_DIE;
            break;

        case SIGUSR1: {
#if MONINTPSYNC == 1
            globalInt |= GI_RPRT;
#else // MONINTPSYNC == 0
            printGStats();
#endif // MONINTPSYNC == 0
#if POLLENV == 1
            const char * const t2mtime = getenv("T2MTIME");
            if (t2mtime) {
                const float mtime = atof(t2mtime);
                if (monIntV != mtime) {
                    monIntV = mtime;
#if VERBOSE > 0
                    T2_INF("Monitoring interval changed via T2MTIME environment variable: %f", monIntV);
#endif // VERBOSE > 0
                    ivalon.it_value.tv_sec  = (uint32_t)monIntV;
                    ivalon.it_value.tv_usec = (monIntV - (uint32_t)monIntV) * 1000000;
                    setitimer(ITIMER_REAL, &ivalon, NULL);
                }
            }
#endif // POLLENV == 1
            break;
        }

        case SIGUSR2:
            globalInt ^= GI_ALRM;
            //if (globalInt & GI_ALRM) alarm(MONINTV);
            if (globalInt & GI_ALRM) {
                ivalon.it_interval = ivalon.it_value;
                setitimer(ITIMER_REAL, &ivalon, NULL);
            } else {
                setitimer(ITIMER_REAL, &ivaloff, NULL);
            }

            break;

        case SIGALRM:
            if (globalInt & GI_ALRM) {
#if MONINTPSYNC == 1
                globalInt |= GI_RPRT;
#else // MONINTPSYNC == 0
                printGStats();
#endif // MONINTPSYNC == 0
                //alarm(MONINTV);
            }
            break;

#if REPSUP == 1
        case SIGSYS: {
            // TODO do something with system() return value...
            int ret UNUSED; // Silence -Wunused-result compiler warning
            if (numPackets != numLstPackets) ret = system(REPCMDAW);
            else ret = system(REPCMDAS);
            numLstPackets = numPackets;
            break;
        }
#endif // REPSUP == 1

        default:
            break;
    }
}


#if (MONINTTHRD == 1 && MONINTBLK == 0)
static void* intThreadHandler(void *arg UNUSED) {
    t2_setup_sigaction();
    sigset_t mask = t2_get_sigset();
    sigprocmask(SIG_UNBLOCK, &mask, NULL);

#ifndef __APPLE__
    int scode;
    while (globalInt & GI_RUN) {
        sigwait(&mask, &scode);
        sigHandler(scode);
    }
#endif // __APPLE__

    return NULL;
}
#endif // (MONINTTHRD == 1 && MONINTBLK == 0)


#if DIFF_REPORT == 1 && VERBOSE > 0
static inline void resetGStats0() {
    memmax0 = 0;
    hshFSize0 = 0;
    numPackets0 = 0;
    numAPackets0 = 0;
    numBPackets0 = 0;
    numABytes0 = 0;
    numBBytes0 = 0;
    bytesProcessed0 = 0;
    bytesOnWire0 = 0;
    rawBytesOnWire0 = 0;
    padBytesOnWire0 = 0;
    numAlarms0 = 0;
#if FORCE_MODE == 1
    numForced0 = 0;
#endif
    numV4Packets0 = 0;
    numV6Packets0 = 0;
    numVxPackets0 = 0;
    numFragV4Packets0 = 0;
    numFragV6Packets0 = 0;
    numLLCPackets0 = 0;
    numGREPackets0 = 0;
    numLAPDPackets0 = 0;
    numTeredoPackets0 = 0;
    numAYIYAPackets0 = 0;
    totalFlows0 = 0;
    totalAFlows0 = 0;
    totalBFlows0 = 0;
    totalIPv4Flows0 = 0;
    totalIPv6Flows0 = 0;
    totalL2Flows0 = 0;
    corrReplFlws0 = 0;
    totalRmFlows0 = 0;
#if DTLS == 1
    numDTLSPackets0 = 0;
#endif // DTLS == 1

    uint_fast32_t i;
    for (i = 0; i < NUMMONPL2; i++) {
        numPackets0L2[monProtL2[i]] = 0;
        numBytes0L2[monProtL2[i]] = 0;
    }

    for (i = 0; i < NUMMONPL3; i++) {
        numPackets0L3[monProtL3[i]] = 0;
        numBytes0L3[monProtL3[i]] = 0;
    }

    //FOREACH_PLUGIN_DO(monitoring, NULL, T2_MON_RESET_VAL);
}
#endif // DIFF_REPORT == 1 && VERBOSE > 0


#if DIFF_REPORT == 1
static inline void updateGStats0() {
    struct rusage r_usage;
    getrusage(RUSAGE_SELF, &r_usage);
    memmax0 = r_usage.ru_maxrss;
#ifdef __APPLE__
    memmax0 /= 1000; // ru_maxrss is in KB on Linux, but in bytes on macOS
#endif // __APPLE__
    if (mainHashMap) {
        hshFSize0 = (mainHashMap->hashChainTableSize - mainHashMap->freeListSize);
    }
    startTStamp0 = actTime;
    numPackets0 = numPackets;
    numAPackets0 = numAPackets;
    numBPackets0 = numBPackets;
    numABytes0 = numABytes;
    numBBytes0 = numBBytes;
    bytesProcessed0 = bytesProcessed;
    bytesOnWire0 = bytesOnWire;
    rawBytesOnWire0 = rawBytesOnWire;
    padBytesOnWire0 = padBytesOnWire;
    numAlarms0 = numAlarms;
#if FORCE_MODE == 1
    numForced0 = numForced;
#endif
    numL2Packets0 = numL2Packets;
    numV4Packets0 = numV4Packets;
    numV6Packets0 = numV6Packets;
    numVxPackets0 = numVxPackets;
    numFragV4Packets0 = numFragV4Packets;
    numFragV6Packets0 = numFragV6Packets;
    numLLCPackets0 = numLLCPackets;
    numGREPackets0 = numGREPackets;
    numLAPDPackets0 = numLAPDPackets;
    numTeredoPackets0 = numTeredoPackets;
    numAYIYAPackets0 = numAYIYAPackets;
    totalFlows0 = totalFlows;
    totalAFlows0 = totalAFlows;
    totalBFlows0 = totalBFlows;
    totalIPv4Flows0 = totalIPv4Flows;
    totalIPv6Flows0 = totalIPv6Flows;
    totalL2Flows0 = totalL2Flows;
    corrReplFlws0 = corrReplFlws;
    totalRmFlows0 = totalRmFlows;
#if DTLS == 1
    numDTLSPackets0 = numDTLSPackets;
#endif // DTLS == 1

    uint_fast32_t i;
    for (i = 0; i < NUMMONPL2; i++) {
        numPackets0L2[monProtL2[i]] = numPacketsL2[monProtL2[i]];
        numBytes0L2[monProtL2[i]] = numBytesL2[monProtL2[i]];
    }

    for (i = 0; i < NUMMONPL3; i++) {
        numPackets0L3[monProtL3[i]] = numPacketsL3[monProtL3[i]];
        numBytes0L3[monProtL3[i]] = numBytesL3[monProtL3[i]];
    }

    //FOREACH_PLUGIN_DO(monitoring, NULL, T2_MON_UPDATE_VAL);
}
#endif // DIFF_REPORT == 1


#if BLOCK_BUF == 0
static inline binary_value_t *buildHeaders() {
    binary_value_t *bv = bv_new_bv("dir", "Flow direction", 0, 1, bt_flow_direction);
    BV_APPEND_U64(bv, "flowInd", "Flow index");
    // get binary values from plugins
    for (uint_fast32_t i = 0; i < t2_plugins->num_plugins; i++) {
        if (t2_plugins->plugin[i].priHdr) {
            bv = bv_append_bv(bv, t2_plugins->plugin[i].priHdr());
        }
    }
    return bv;
}
#endif // BLOCK_BUF == 0


void timeout_handler_add(float timeout) {
    // first check if there is already a timeout_handler in the list
    timeout_t *t = timeout_list;
    while (t) {
        if (t->timeout == timeout) return; // timeout already in list
        t = t->next;
    }

    // timeout value not in list -> build new timeout handler
    timeout_t *tnew = t2_malloc_fatal(sizeof(*tnew));
    tnew->timeout = timeout;
    tnew->flow.timeout = INFINITY;  // a sentinel never times out
    tnew->flow.lastSeen.tv_sec = 0; // An impossible timestamp of zero seconds marks it as a sentinel
    tnew->next = NULL;

    // place it in front of lru_tail
    tnew->flow.lruPrevFlow = lruTail.lruPrevFlow;
    tnew->flow.lruNextFlow = &lruTail;

    lruTail.lruPrevFlow->lruNextFlow = &(tnew->flow);
    lruTail.lruPrevFlow = &(tnew->flow);

    if (!timeout_list) {
        // the new timeout handler is the only one in the list,
        // so place it at the list's head
        timeout_list = tnew;
        return;
    }

    // add it at the right position in the timeout handler list
    // timeout handler with biggest timeout first
    timeout_t *tprev = timeout_list;

    t = tprev;
    while (t) {
        if (tnew->timeout > t->timeout) {
            // add new timeout handler in front of the list
            tnew->next = t;
            if (tprev != t) {
                tprev->next = tnew;
            } else {
                // The new timeout is at the top of the list
                // -> set entry point to new timeout handler
                timeout_list = tnew;
            }

            return;
        }

        if (tprev != t) tprev = tprev->next;
        t = t->next;
    }

    // new timeout is at the end of the list
    tprev->next = tnew;
}


#if DPDK_MP == 0
static caplist_t* read_caplist(const char *filename) {
#if VERBOSE > 1
    T2_LOG("Checking list file");
#endif // VERBOSE > 1

    FILE *file = t2_fopen(filename, "r");
    if (UNLIKELY(!file)) exit(EXIT_FAILURE);

    caplist_t *list = t2_calloc_fatal(1, sizeof(*list));

    struct stat fileStats;

    caplist_elem_t *elem = list->file_list;

    ssize_t read;
    size_t len = 0;
    char *line = NULL;
    while ((read = getline(&line, &len, file)) != -1) {
        // skip comments
        if (line[0] == '#') continue;

        // cut off newline char
        if (read > 0 && line[read - 1] == '\n') line[--read] = '\0';
        if (read > 0 && line[read - 1] == '\r') line[--read] = '\0';

        if (UNLIKELY(access(line, F_OK) != 0)) {
            // file does not exist
            if (read < 2 || !isascii(line[read - 1]) || !isascii(line[read - 2])) {
                // probably a binary file...
                T2_FATAL("'%s' is not a valid list of PCAP files", filename);
            }
        }

#if VERBOSE > 1
        T2_LOG("    checking file '%s'", line);
#endif // VERBOSE > 1

        // Test if valid pcap file
        if (!ckpcaphdr(line)) continue;

        if (stat(line, &fileStats) != 0) {
            T2_WRN("Cannot get complete file stats for '%s': %s", line, strerror(errno));
            continue;
        }

        captureFileSize += fileStats.st_size;

        // file is valid, add it to list
        caplist_elem_t *new_elem = t2_calloc_fatal(1, sizeof(*new_elem));
        new_elem->name = t2_malloc_fatal(read + 1);
        memcpy(new_elem->name, line, read + 1);

        if (!elem) {
            list->file_list = new_elem;
            elem = new_elem;
        } else {
            elem->next = new_elem;
            elem = elem->next;
        }

        new_elem->size = fileStats.st_size;
        list->size += new_elem->size;
        list->num_files++;
    }

    fclose(file);
    free(line);

    // no valid files were found
    if (UNLIKELY(list->num_files == 0)) {
        T2_FATAL("No valid files found in %s", capName);
    }

    return list;
}
#endif // DPDK_MP == 0


bool ckpcaphdr(const char * const pcapname) {
    if (!pcapname || *pcapname == '-' || (capType & DIRFILE)) return true;

    FILE *fp;
    if (UNLIKELY(!(fp = fopen(pcapname, "r")))) {
#if VERBOSE > 1
        T2_ERR("Failed to open file '%s' for reading: %s", pcapname, strerror(errno));
#endif // VERBOSE > 1
        return false;
    }

    struct stat stats;
    if (UNLIKELY(stat(pcapname, &stats) < 0)) {
#if VERBOSE > 1
        T2_ERR("Failed to get stats of file '%s': %s", pcapname, strerror(errno));
#endif // VERBOSE > 1
        fclose(fp);
        return false;
    }

    if (UNLIKELY(stats.st_size == 0)) {
#if VERBOSE > 1
        T2_ERR("PCAP file '%s' is empty", pcapname);
#endif // VERBOSE > 1
        fclose(fp);
        return false;
    }

    uint32_t rbuf[3];
    if (UNLIKELY(fread(rbuf, 4, 3, fp) == 0)) {
#if VERBOSE > 1
        T2_ERR("Failed to read data from file '%s'", pcapname);
#endif // VERBOSE > 1
        fclose(fp);
        return false;
    }

    fclose(fp);

    bool valid = false;
    if (rbuf[0] == PCAPNG) {
#if VERBOSE > 1
        T2_WRN("PCAP-NG, so *percentage completed* in end report might be less than 100%%, will be fixed in a later version");
#endif // VERBOSE > 1
        if (rbuf[2] == PCAPNG_MAGIC_B || rbuf[2] == PCAPNG_MAGIC_L) {
            valid = true;
        }
    } else if (rbuf[0] == PCAP_MAGIC_B || rbuf[0] == PCAP_MAGIC_L) {
        valid = true;
    } else if (rbuf[0] == PCAP_MAGIC_NS_B || rbuf[0] == PCAP_MAGIC_NS_L) {
#if TSTAMP_PREC != 1
        T2_WRN("PCAP nanosecond-resolution: for improved precision, run 't2conf tranalyzer2 -D TSTAMP_PREC=1 && t2build -R'");
#endif
        valid = true;
    }

#if VERBOSE > 1
    if (!valid) T2_ERR("File '%s' is not a valid PCAP/PCAP-NG file", pcapname);
#endif // VERBOSE > 1

    return valid;
}


static __attribute__((noreturn)) void t2_abort_with_help() {
    printf("Try '%s -h' for more information.\n", T2_PACKAGE);
    exit(EXIT_FAILURE);
}


#if PID_FNM_ACT == 1
// TODO
//  - test if PID file exists before creating it
//  - if it exists, warn the user and ask whether to continue
//  - delete the file in t2_cleanup()
static inline void t2_create_pid_file() {
    //if (t2_file_exists(pluginFolder, PID_FNM)) {
    //  T2_WRN("A PID file '%s%s' already exists... another instance of Tranalyzer is probably running", pluginFolder, PID_FNM);
    //  //printf("Proceed anyway (Y/n)? ");
    //}
    FILE * const file = t2_fopen_in_dir(pluginFolder, PID_FNM, "w");
    if (LIKELY(file != NULL)) {
        fprintf(file, "%d\n", getpid());
        fclose(file);
    }
}
#endif // PID_FNM_ACT == 1


#if PID_FNM_ACT == 1
static inline void t2_destroy_pid_file() {
    char filename[len];
    t2_build_filename(filename, sizeof(filename), pluginFolder, PID_FNM, NULL);

    if (UNLIKELY(unlink(filename) != 0)) {
        T2_WRN("Failed to delete file '%s': %s", filename, strerror(errno));
    }
}
#endif // PID_FNM_ACT == 1


#if (MACHINE_REPORT == 1 && MONPROTMD == 1)
static inline void t2_load_proto_file() {
    FILE * const file = t2_fopen_in_dir(pluginFolder, MONPROTFL, "r");
    if (UNLIKELY(!file)) exit(EXIT_FAILURE);

    for (uint_fast16_t i = 0; i < 256; i++) {
        const int n = fscanf(file, "%*" SCNu32 "\t%15[^\n\t]\t%*99[^\n\t]", ipProtSn[i]);
        if (UNLIKELY(n != 1)) {
            T2_FATAL("Failed to read line %" PRIuFAST16 " of file '%s': %s",
                    i, MONPROTFL, strerror(errno));
        }
    }

    fclose(file);
}
#endif // (MACHINE_REPORT == 1 && MONPROTMD == 1)


static inline FILE *t2_open_logFile() {
    FILE *file;
    if (!(capType & LOGFILE)) {
#if VERBOSE == 0
        file = t2_fopen("/dev/null", "w");
        if (UNLIKELY(!file)) exit(EXIT_FAILURE);
#else // VERBOSE > 0
        file = stdout;
#endif // VERBOSE > 0
    } else {
        file = t2_fopen_with_suffix(baseFileName, LOG_SUFFIX, "w");
        if (UNLIKELY(!file)) exit(EXIT_FAILURE);
    }
    return file;
}


static inline FILE *t2_open_monFile() {
    FILE *file;
    if (!(capType & MONFILE)) {
        file = stdout;
    } else {
        file = t2_fopen_with_suffix(baseFileName, MON_SUFFIX, "w");
        if (UNLIKELY(!file)) exit(EXIT_FAILURE);
    }
    return file;
}


static inline FILE *t2_create_pktfile() {
    FILE *file = t2_fopen_with_suffix(baseFileName, PACKETS_SUFFIX, "w");
    if (UNLIKELY(!file)) exit(EXIT_FAILURE);

    fputs(HDR_CHR
#if SPKTMD_PKTNO == 1
          "pktNo"   SEP_CHR
#endif // SPKTMD_PKTNO == 0
          "flowInd" SEP_CHR
          , file);

    return file;
}


// baseFileName MUST be free'd
static inline void t2_set_baseFileName() {
    if (baseFileName && strcmp(baseFileName, "-") == 0) {
        baseFileName = NULL;
        // Force -l and -m options when writing to stdout
        capType |= (WSTDOUT | LOGFILE | MONFILE);
    }

    if (!baseFileName) {
        // Derive the output prefix from the input (file, interface, ...)
        char * const dot = strrchr(capName, '.');
        if (strcmp(capName, "-") == 0) {
            baseFileName = strdup("stdin");
        } else if (!dot || (capType & IFACE)) {
            baseFileName = strdup(capName);
        } else {
            *dot = '\0';
            baseFileName = strdup(capName);
            *dot = '.';
        }
    } else {
        // If baseFileName contains directories, create them
        char *slash = strrchr(baseFileName, '/');
        // Do not create a directory if we cannot know whether baseFileName is
        // a prefix or a directory, e.g., /data instead of /data/
        if (slash && slash != baseFileName) {
            *slash = '\0';
            if (UNLIKELY(!mkpath(baseFileName, S_IRWXU))) {
                T2_FATAL("Failed to create directory '%s': %s", baseFileName, strerror(errno));
            }
            *slash = '/';
        }

        // If baseFileName is not a directory, use it as such
        struct stat st;
        if (stat(baseFileName, &st) == -1 || !S_ISDIR(st.st_mode)) {
            baseFileName = strdup(baseFileName);
        } else {
            // use the directory from baseFileName (-w/-W option)
            const char * const dir = baseFileName;
            const size_t dlen = strlen(dir);
            // and derive the prefix from the input file
            slash = strrchr(capName, '/');
            const char * const prefix = (
                    slash ? slash + 1 :
                    strcmp(capName, "-") == 0 ? "stdin" :
                    capName
            );
            char * const dot = strrchr(prefix, '.');
            if (dot && !(capType & IFACE)) *dot = '\0';
            const size_t slen = ((dir[dlen - 1] == '/') ? 0 : 1);
            baseFileName = t2_strdup_printf("%s%s%s", dir, (slen ? "/" : ""), prefix);
            if (dot) *dot = '.';
        }
    }

#if DPDK_MP != 0
    // suffix the baseFileName with the DPDK process ID in multi-process mode
    char *tmp = t2_strdup_printf("%s_%03d", baseFileName, dpdk_proc_id);
    free(baseFileName);
    baseFileName = tmp;
#endif // DPDK_MP != 0

    baseFileName_len = strlen(baseFileName);
}


#ifndef __APPLE__
// Binds Tranalyzer to CPU core number 'cpu_n'.
// If 'cpu_n' is 0, then binds tranalyzer to the current core number.
static inline void t2_set_cpu(int cpu_n) {
    if (UNLIKELY(cpu_n < 0)) {
        T2_FATAL("CPU number must be >= 0");
    }

    const int old_cpu = sched_getcpu() + 1;
    if (cpu_n == 0) cpu_n = old_cpu;

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu_n - 1, &cpuset);

    if (pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset) < 0) {
#if VERBOSE > 0
        T2_WRN("Failed to move %s from CPU %d to CPU %d", T2_APPNAME, old_cpu, cpu_n);
#endif // VERBOSE > 0
    } else {
        const int new_cpu = sched_getcpu() + 1;
        cpu = new_cpu; // update global variable
#if VERBOSE > 0
        if (new_cpu != old_cpu) {
            T2_INF("%s successfully moved from CPU %d to CPU %d", T2_APPNAME, old_cpu, new_cpu);
        } else {
            T2_INF("%s successfully bound to CPU %d", T2_APPNAME, new_cpu);
        }
#endif // VERBOSE > 0
    }
}
#endif // __APPLE__


// Make sure pluginFolder is set and ends with a slash
// pluginFolder MUST be free'd
static inline void t2_set_pluginFolder() {
    // absolute path
    if (!pluginFolder && PLUGIN_FOLDER[0] == '/') pluginFolder = PLUGIN_FOLDER;

    if (pluginFolder) { // -p option
        const size_t len = strlen(pluginFolder);
        if (pluginFolder[len - 1] == '/') {
            pluginFolder = strdup(pluginFolder);
            pluginFolder_len = len;
        } else {
            pluginFolder = t2_strdup_printf("%s/", pluginFolder);
            pluginFolder_len = len + 1;
        }
    } else { // relative path (to home)
        const char * const home = getenv("HOME");
        if (UNLIKELY(!home)) T2_FATAL("Could not get HOME environment variable");
        pluginFolder = t2_strdup_printf("%s/%s", home, PLUGIN_FOLDER);
        pluginFolder_len = strlen(pluginFolder);
    }

    struct stat st;
    if ((stat(pluginFolder, &st) != 0 || !S_ISDIR(st.st_mode))) {
        const char * const sudo_user = getenv("SUDO_USER");
        if (sudo_user) {
            // pluginFolder does not exist and command was run with sudo
            T2_WRN("Plugin folder '%s' does not exist...", pluginFolder);
            free(pluginFolder);
            const struct passwd * const pwd = getpwnam(sudo_user);
            pluginFolder = t2_strdup_printf("%s/%s", pwd->pw_dir, PLUGIN_FOLDER);
            pluginFolder_len = strlen(pluginFolder);
            T2_INF("Trying with plugin_folder '%s'...", pluginFolder);
        }
    }
}


// adapted from tcpdump
// returned value must be free'd
static char *read_bpffile(const char *fname) {
    FILE *file;
    if (UNLIKELY(!(file = fopen(fname, "r")))) {
        T2_FATAL("Failed to open file '%s' for reading: %s", fname, strerror(errno));
    }

    struct stat stats;
    if (UNLIKELY(stat(fname, &stats) < 0)) {
        T2_FATAL("Failed to get stats of file '%s': %s", fname, strerror(errno));
    }

    if (UNLIKELY(stats.st_size == 0)) {
        T2_FATAL("BPF file '%s' is empty", fname);
    }

    char *buf = t2_malloc_fatal(stats.st_size + 1);

    size_t read = fread(buf, 1, stats.st_size, file);
    if (UNLIKELY(read == 0)) {
        T2_FATAL("Failed to read data from file '%s'", fname);
    }

    fclose(file);

    if (UNLIKELY((int64_t)read != stats.st_size)) {
        T2_FATAL("Failed to read all the data from file '%s': read %zu, file size %jd",
                fname, read, (intmax_t)stats.st_size);
    }

    // replace comments with spaces
    for (uint_fast64_t i = 0; i < read; i++) {
        if (buf[i] == '#') {
            while (i < read && buf[i] != '\n') buf[i++] = ' ';
        }
    }

    // remove trailing spaces and newlines
    while (read > 0 && (buf[read - 1] == ' ' || buf[read - 1] == '\n')) read--;

    buf[read] = '\0';

    return buf;
}


#if REPORT_HIST == 1
static void t2_restore_state() {

    if (!t2_file_exists(pluginFolder, REPORT_HIST_FILE)) {
#if VERBOSE > 2
        T2_INF("No previous state to restore");
#endif
        return;
    }

    FILE *file = t2_fopen_in_dir(pluginFolder, REPORT_HIST_FILE, "r");
    if (UNLIKELY(!file)) return;

    ssize_t read;
    size_t len = 0;
    char *line = NULL;
    while ((read = getline(&line, &len, file)) != -1) {
        // Skip comments and empty lines
        if (read == 0 || line[0] == '#' || isspace(line[0])) continue;
        switch (line[0]) {
            case '%':
                if (UNLIKELY(
                    read + 1 != sizeof(REPORT_HIST_HDR) ||
                    strncmp(line, REPORT_HIST_HDR, read) != 0
                )) {
                    T2_FATAL("Cannot restore Tranalyzer state: expected '%s', found '%s'",
                            REPORT_HIST_HDR, line);
                }
                break;

            case REPTYPE: {
                time_t sec;
                intmax_t usec;
                sscanf(line,
                       "%*c"            /* (REPTYPE)        */ "\t"
                       "%ld.%06jd"      /* startTStamp      */ "\t"
                       "%" SCNu64       /* totalfIndex      */ "\t"
                       "%" SCNu64       /* totalFlows       */ "\t"
                       "%" SCNu64       /* totalAFlows      */ "\t"
                       "%" SCNu64       /* totalBFlows      */ "\t"
                       "%" SCNu64       /* numPackets       */ "\t"
                       "%" SCNu64       /* numAPackets      */ "\t"
                       "%" SCNu64       /* numBPackets      */ "\t"
                       "%" SCNu64       /* numL2Packets     */ "\t"
                       "%" SCNu64       /* numV4Packets     */ "\t"
                       "%" SCNu64       /* numV6Packets     */ "\t"
                       "%" SCNu64       /* numVxPackets     */ "\t"
                       "%" SCNu64       /* bytesProcessed   */ "\t"
                       "%" SCNu64       /* numABytes        */ "\t"
                       "%" SCNu64       /* numBBytes        */ "\t"
                       "%" SCNu64       /* numFragV4Packets */ "\t"
                       "%" SCNu64       /* numFragV6Packets */ "\t"
                       "%" SCNu64       /* numAlarms        */ "\t"
                       "%" SCNu64       /* bytesOnWire      */ "\t"
                       "%" SCNu64       /* rawBytesOnWire   */ "\t"
                       "%" SCNu64       /* padBytesOnWire   */ "\t"
                       "%" SCNu64       /* captureFileSize  */ "\t"
                       "%" SCNu64       /* corrReplFlws     */ "\t"
                       "%" SCNu64       /* totalRmFlows     */ "\t"
                       "%" SCNu64       /* numLLCPackets    */ "\t"
                       "%" SCNu64       /* numGREPackets    */ "\t"
                       "%" SCNu64       /* numLAPDPackets   */ "\t"
                       "%" SCNu64       /* numTeredoPackets */ "\t"
                       "%" SCNu64       /* numAYIYAPackets  */ "\t"
                       "0x016%" SCNx64  /* globalWarn       */ "\n"
                       /* , REPTYPE */
                       , &sec, &usec,
                       , &totalfIndex
                       , &totalFlows
                       , &totalAFlows
                       , &totalBFlows
                       , &numPackets
                       , &numAPackets
                       , &numBPackets
                       , &numL2Packets
                       , &numV4Packets
                       , &numV6Packets
                       , &numVxPackets
                       , &bytesProcessed
                       , &numABytes
                       , &numBBytes
                       , &numFragV4Packets
                       , &numFragV6Packets
                       , &numAlarms
                       , &bytesOnWire
                       , &rawBytesOnWire
                       , &padBytesOnWire
                       , &captureFileSize
                       , &corrReplFlws
                       , &totalRmFlows
                       , &numLLCPackets
                       , &numGREPackets
                       , &numLAPDPackets
                       , &numTeredoPackets
                       , &numAYIYAPackets
                       , &globalWarn);
                startTStamp.tv_sec = sec;
                startTStamp.tv_usec = usec;
                break;
            }

            case REPORT_SECTION_L2: {
                uint16_t l2proto;
                uint64_t numPkts;
                uint64_t numBytes;
                sscanf(line, "%*c\t0x%04" SCNx16 "\t%" SCNu64 "\t%" SCNu64 "\n",
                        &l2proto, &numPkts, &numBytes);
                numPacketsL2[l2proto] = numPkts;
                numBytesL2[l2proto] = numBytes;
                break;
            }

            case REPORT_SECTION_L3: {
                uint8_t l3proto;
                uint64_t numPkts;
                uint64_t numBytes;
                sscanf(line, "%*c\t0x%02" SCNx8 "\t%" SCNu64 "\t%" SCNu64 "\n",
                        &l3proto, &numPkts, &numBytes);
                numPacketsL3[l3proto] = numPkts;
                numBytesL3[l3proto] = numBytes;
                break;
            }

            case REPORT_SECTION_PL: {
                uint_fast16_t pluginNumber;
                sscanf(line, "%*c\t%03" SCNuFAST16 "\t", &pluginNumber);
                for (uint_fast32_t i = 0; i < t2_plugins->num_plugins; i++) {
                    t2_plugin_t plugin = t2_plugins->plugin[i];
                    if (plugin.number == pluginNumber && plugin.restoreState) {
                        // Skip P <tab> pluginNumber <tab> and send the line to the plugin
                        plugin.restoreState(line + 5);
                    }
                }
                break;
            }

            default:
                break;
        }
    }

#if DIFF_REPORT == 1
    updateGStats0();
    startTStamp0 = startTStamp;
#endif

    free(line);
    fclose(file);

    T2_INF("Tranalyzer state restored from '%s%s'", pluginFolder, REPORT_HIST_FILE);
}
#endif // REPORT_HIST == 1


#if REPORT_HIST == 1
static void t2_save_state() {
    FILE *file = t2_fopen_in_dir(pluginFolder, REPORT_HIST_FILE, "w");
    if (UNLIKELY(!file)) return;

    struct timeval t;
#if TSTAMP_PREC == 1
    struct timespec tmns;
    clock_gettime(CLOCK_REALTIME, &tmns);
    t.tv_sec = (time_t)tmns.tv_sec;
    t.tv_usec = tmns.tv_nsec;
#else // TSTAMP_PREC == 0
    gettimeofday(&t, NULL);
#endif // TSTAMP_PREC

    t2_log_date(file, "# Date: ", t, TSTAMP_R_UTC);
    fprintf(file, "# %s %s (%s), %s.\n", T2_APPNAME, T2_VERSION, T2_CODENAME, T2_RELEASE);
    fprintf(file, "# Command line: %s\n", cmdline);

    fputs("# Plugins loaded:\n", file);
    for (uint_fast32_t i = 0; i < t2_plugins->num_plugins; i++) {
        fprintf(file, "#   %02" PRIuFAST32 ": %s, version %s\n",
                i + 1, t2_plugins->plugin[i].name, t2_plugins->plugin[i].version);
    }

    fputs("\n" REPORT_HIST_HDR, file);

    const time_t sec = startTStamp.tv_sec;
    const intmax_t usec = startTStamp.tv_usec;
    fprintf(file,
            "%c"             /* REPTYPE          */ "\t"
            "%ld.%06jd"      /* startTStamp      */ "\t"
            "%" PRIu64       /* totalfIndex      */ "\t"
            "%" PRIu64       /* totalFlows       */ "\t"
            "%" PRIu64       /* totalAFlows      */ "\t"
            "%" PRIu64       /* totalBFlows      */ "\t"
            "%" PRIu64       /* numPackets       */ "\t"
            "%" PRIu64       /* numAPackets      */ "\t"
            "%" PRIu64       /* numBPackets      */ "\t"
            "%" PRIu64       /* numL2Packets     */ "\t"
            "%" PRIu64       /* numV4Packets     */ "\t"
            "%" PRIu64       /* numV6Packets     */ "\t"
            "%" PRIu64       /* numVxPackets     */ "\t"
            "%" PRIu64       /* bytesProcessed   */ "\t"
            "%" PRIu64       /* numABytes        */ "\t"
            "%" PRIu64       /* numBBytes        */ "\t"
            "%" PRIu64       /* numFragV4Packets */ "\t"
            "%" PRIu64       /* numFragV6Packets */ "\t"
            "%" PRIu64       /* numAlarms        */ "\t"
            "%" PRIu64       /* bytesOnWire      */ "\t"
            "%" PRIu64       /* rawBytesOnWire   */ "\t"
            "%" PRIu64       /* padBytesOnWire   */ "\t"
            "%" PRIu64       /* captureFileSize  */ "\t"
            "%" PRIu64       /* corrReplFlws     */ "\t"
            "%" PRIu64       /* totalRmFlows     */ "\t"
            "%" PRIu64       /* numLLCPackets    */ "\t"
            "%" PRIu64       /* numGREPackets    */ "\t"
            "%" PRIu64       /* numLAPDPackets   */ "\t"
            "%" PRIu64       /* numTeredoPackets */ "\t"
            "%" PRIu64       /* numAYIYAPackets  */ "\t"
            "0x016%" PRIx64  /* globalWarn       */ "\n\n"
            , REPTYPE
            , sec, usec,
            , totalfIndex
            , totalFlows
            , totalAFlows
            , totalBFlows
            , numPackets
            , numAPackets
            , numBPackets
            , numL2Packets
            , numV4Packets
            , numV6Packets
            , numVxPackets
            , bytesProcessed
            , numABytes
            , numBBytes
            , numFragV4Packets
            , numFragV6Packets
            , numAlarms
            , bytesOnWire
            , rawBytesOnWire
            , padBytesOnWire
            , captureFileSize
            , corrReplFlws
            , totalRmFlows
            , numLLCPackets
            , numGREPackets
            , numLAPDPackets
            , numTeredoPackets
            , numAYIYAPackets
            , globalWarn);

    uint_fast32_t i;
    for (i = 0; i < NUMMONPL2; i++) {
        fprintf(file, "%c\t0x%04" PRIx16 "\t%" PRIu64 "\t%" PRIu64 "\n",
                REPORT_SECTION_L2, monProtL2[i], numPacketsL2[monProtL2[i]], numBytesL2[monProtL2[i]]);
    }

    fputc('\n', file);

    for (i = 0; i < NUMMONPL3; i++) {
        fprintf(file, "%c\t0x%02" PRIx8 "\t%" PRIu64 "\t%" PRIu64 "\n",
                REPORT_SECTION_L3, monProtL3[i], numPacketsL3[monProtL3[i]], numBytesL3[monProtL3[i]]);
    }

    fputc('\n', file);

    for (i = 0; i < t2_plugins->num_plugins; i++) {
        t2_plugin_t plugin = t2_plugins->plugin[i];
        if (plugin.saveState) {
            fprintf(file, "%c\t%03u\t", REPORT_SECTION_PL, plugin.number);
            plugin.saveState(file);
            fprintf(file, " # %s (%s)\n", plugin.name, plugin.version);
        }
    }

    fclose(file);

    T2_INF("Tranalyzer state saved in '%s%s'", pluginFolder, REPORT_HIST_FILE);
}
#endif // REPORT_HIST == 1
