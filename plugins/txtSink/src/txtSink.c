/*
 * txtSink.c
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

#include "txtSink.h"
#include "t2Plugin.h"

#if TFS_GZ_COMPRESS == 1
#include "gz2txt.h"
#endif // TFS_GZ_COMPRESS == 0

#include <errno.h>          // for errno
#include <ifaddrs.h>        // for getifaddrs, freeifaddrs, ifaddrs
#include <netdb.h>          // for getnameinfo
#include <string.h>         // for strerror, strtok
#include <sys/resource.h>   // for getpriority
#include <sys/utsname.h>    // for uname, utsname
#include <unistd.h>         // for getpid

#ifdef __APPLE__
#include <net/if_dl.h>
#else
#include <netpacket/packet.h>
#endif //__APPLE__


#if BLOCK_BUF == 0

// Static variables
static b2t_func_t funcs;

#if TFS_GZ_COMPRESS == 1
static gzFile txt_file;
#else // TFS_GZ_COMPRESS == 0
static FILE *txt_file;
#endif // TFS_GZ_COMPRESS == 1

static char txt_filename[MAX_FILENAME_LEN+1]; // filename of the flow file

#if TFS_SPLIT == 1
// -W option
static uint64_t oFileNum, oFileLn;
static uint64_t txtfIndex;
static char *oFileNumP;
#endif // TFS_SPLIT == 1

#endif // BLOCK_BUF == 0


// Function prototypes

#if TFS_HDR_FILE == 1
static void print_hdr_file(binary_value_t *bv, const char * const suffix);
static int query_iface_info(char *buf, size_t buflen);
#endif // TFS_HDR_FILE


// Tranalyzer plugin functions

T2_PLUGIN_INIT("txtSink", "0.9.3", 0, 9);


void t2Init() {
#if ENVCNTRL > 0
    t2_env_t env[ENV_TFS_N] = {};
    t2_get_env(PLUGIN_SRCH, ENV_TFS_N, env);
#if BLOCK_BUF == 0
    const char * const txtSfx = T2_ENV_VAL(TFS_FLOWS_TXT_SUFFIX);
#endif // BLOCK_BUF == 0
#if TFS_HDR_FILE == 1
    const char * const hdrSfx = T2_ENV_VAL(TFS_HEADER_SUFFIX);
#endif // TFS_HDR_FILE == 1
#else // ENVCNTRL == 0
#if BLOCK_BUF == 0
    const char * const txtSfx = TFS_FLOWS_TXT_SUFFIX;
#endif // BLOCK_BUF == 0
#if TFS_HDR_FILE == 1
    const char * const hdrSfx = TFS_HEADER_SUFFIX;
#endif // TFS_HDR_FILE == 1
#endif // ENVCNTRL

#if BLOCK_BUF == 1
    T2_PWRN(plugin_name, "BLOCK_BUF is set in 'tranalyzer.h', no flow file will be produced");
#else // BLOCK_BUF == 0

#if TFS_GZ_COMPRESS == 1
    funcs = b2t_funcs_gz;
#else // TFS_GZ_COMPRESS == 0
    funcs = b2t_funcs;
#endif // TFS_GZ_COMPRESS == 1

    // setup output file names
    if (capType & WSTDOUT) {
#if TFS_GZ_COMPRESS == 1
        if (UNLIKELY((txt_file = gzdopen(fileno(stdout), "w")) == NULL)) {
            T2_PFATAL(plugin_name, "Could not create compressed stream: %s", strerror(errno));
        }
#else // TFS_GZ_COMPRESS == 0
        txt_file = stdout;
#endif // TFS_GZ_COMPRESS == 0
    } else {
        const size_t blen = baseFileName_len;
        const size_t slen = strlen(txtSfx);
        size_t len = blen + slen + 1;
#if TFS_GZ_COMPRESS == 1
        len += sizeof(GZ_SUFFIX) - 1;
#endif
        if (UNLIKELY(len > sizeof(txt_filename))) {
            T2_PFATAL(plugin_name, "filename too long");
        }

        memcpy(txt_filename, baseFileName, blen);
        memcpy(txt_filename + blen, txtSfx, slen+1);
#if TFS_GZ_COMPRESS == 1
        memcpy(txt_filename + blen + slen, GZ_SUFFIX, sizeof(GZ_SUFFIX));
#endif

#if TFS_SPLIT == 1
        if (capType & OFILELN) {
            txtfIndex = 0;
            oFileLn = (uint64_t)oFragFsz;
            oFileNumP = txt_filename + strlen(txt_filename);
            oFileNum = oFileNumB;
            sprintf(oFileNumP, "%" PRIu64, oFileNum);
        }
#endif // TFS_SPLIT == 1

        // open flow output file
        if (UNLIKELY(!((txt_file = funcs.fopen(txt_filename, "w"))))) {
            T2_PFATAL(plugin_name, "Failed to open file '%s' for writing: %s", txt_filename, strerror(errno));
        }
    }

#if TFS_PRI_HDR == 1
    // write header in flow file
    parse_binary_header2text(main_header_bv, txt_file, funcs);
#endif // TFS_PRI_HDR == 1

#endif // BLOCK_BUF == 0

#if TFS_HDR_FILE == 1
    print_hdr_file(main_header_bv, hdrSfx);
#endif // TFS_HDR_FILE == 1

#if ENVCNTRL > 0
    t2_free_env(ENV_TFS_N, env);
#endif // ENVCNTRL > 0
}


#if BLOCK_BUF == 0
void t2BufferToSink(outputBuffer_t *buf, binary_value_t *bv) {

    if (UNLIKELY(!parse_buffer_bin2txt(buf, bv, txt_file, funcs))) {
        exit(EXIT_FAILURE);
    }

#if TFS_SPLIT == 1
    if (capType & OFILELN) {
        const uint64_t offset = ((capType & WFINDEX) ? ++txtfIndex : (uint64_t)funcs.ftell(txt_file));
        if (offset >= oFileLn) {
            funcs.fclose(txt_file);

            oFileNum++;
            sprintf(oFileNumP, "%" PRIu64, oFileNum);

            if (UNLIKELY(!((txt_file = funcs.fopen(txt_filename, "w"))))) {
                T2_PFATAL(plugin_name, "Failed to open file '%s' for writing: %s", txt_filename, strerror(errno));
            }
#if (TFS_PRI_HDR == 1 && TFS_PRI_HDR_FW == 1)
            parse_binary_header2text(bv, txt_file, funcs);
#endif // (TFS_PRI_HDR == 1 && TFS_PRI_HDR_FW == 1)
            txtfIndex = 0;
        }
    }
#endif // TFS_SPLIT == 1
}
#endif // BLOCK_BUF == 0


#if BLOCK_BUF == 0
void t2Finalize() {
    if (LIKELY(txt_file != NULL)) {
#if (TFS_PRI_HDR == 1 && TFS_EXTENDED_HEADER == 1)
        funcs.fseek(txt_file, 0, SEEK_SET);
        funcs.fprintf(txt_file, "%s %lu", HDR_CHR, totalFlows);
#endif // (TFS_PRI_HDR == 1 && TFS_EXTENDED_HEADER == 1)
        funcs.fclose(txt_file);
    }
}
#endif // BLOCK_BUF == 0


// TODO compress header file?
#if TFS_HDR_FILE == 1
static void print_hdr_file(binary_value_t *bv
#if BLOCK_BUF > 0
    UNUSED
#endif
    , const char * const suffix
) {
    // open header output file
    FILE *file = t2_fopen_with_suffix(baseFileName, suffix, "w");
    if (UNLIKELY(!file)) exit(EXIT_FAILURE);

    // calc time
    struct timeval t;
    gettimeofday(&t, NULL);

    // get name and information about current kernel
    struct utsname sysinfo;
    uname(&sysinfo);

    // get PID
    const pid_t pid = getpid();

    // write headers
    t2_log_date(file, "# Date: ", t, TSTAMP_R_UTC);
    fprintf(file, "# %s %s (%s), %s\n", T2_APPNAME, T2_VERSION, T2_CODENAME, T2_RELEASE);
    fprintf(file, "# Core configuration: %s%s%s%s%s%s\n",
            (ETH_ACTIVATE > 0) ? "L2, " : "",
            (LAPD_ACTIVATE == 1) ? "LAPD, " : "",
            (IPV6_ACTIVATE == 2) ? "IPv4, IPv6" :
                (IPV6_ACTIVATE == 1) ? "IPv6" : "IPv4",
            (SCTP_ACTIVATE > 0) ? ", SCTP" : "",
            (ALARM_MODE == 1) ? " [ALARM]" : "",
            (FORCE_MODE == 1) ? " [FORCE]" : "");
    fprintf(file, "# SensorID: %" PRIu32 "\n", sensorID);
    fprintf(file, "# PID: %d\n", pid);
    fprintf(file, "# Priority: %d\n", getpriority(PRIO_PROCESS, pid));
#if DPDK_MP == 1
    fprintf(file, "# DPDK process: %d/%d\n", dpdk_proc_id, dpdk_num_procs);
#endif // DPDK_MP == 1
    fprintf(file, "# Command line: %s\n", cmdline);
    fprintf(file, "# HW info: %s;%s;%s;%s;%s\n", sysinfo.nodename,
            sysinfo.sysname, sysinfo.release,
            sysinfo.version, sysinfo.machine);
    fprintf(file, "# SW info: %s\n#\n", pcap_lib_version());

    if (capType & IFACE) {
        fprintf(file, "# Live captured from interface: %s\n", capName);

        char iface_info[1024] = {};
        query_iface_info(iface_info, sizeof(iface_info));
        fprintf(file, "%s#\n", &iface_info[0]);
    }

    fputs("# Plugins loaded:\n", file);
    for (uint_fast8_t i = 0; i < t2_plugins->num_plugins; i++) {
        const t2_plugin_t plugin = t2_plugins->plugin[i];
        fprintf(file, "#   %02u: %s, version %s\n", i+1, plugin.name, plugin.version);
    }

#if BLOCK_BUF == 0
    fputs("#\n", file);
    print_values_description(bv, file, b2t_funcs);
#endif

    fclose(file);
}
#endif // TFS_HDR_FILE == 1


#if TFS_HDR_FILE == 1
static int query_iface_info(char *buf, size_t buflen) {
    struct ifaddrs *ifaddr;
    if (UNLIKELY(getifaddrs(&ifaddr) == -1)) {
        T2_PERR(plugin_name, "Failed to list network interfaces: %s", strerror(errno));
        *buf = '\0';
        return 0;
    }

    char *h = buf;

    h += snprintf(h, buflen - (h - buf), "# Interfaces:\n");

    char hbuf[NI_MAXHOST];

    for (struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;

        h += snprintf(h, buflen - (h - buf), "#   %s\t", ifa->ifa_name);

        switch (ifa->ifa_addr->sa_family) {
            case AF_INET: {
                uint_fast32_t l = 0;
                const uint32_t ip = *(uint32_t*)&((struct sockaddr_in*)ifa->ifa_netmask)->sin_addr;
                for (uint_fast32_t k = ~ntohl(ip); k & 1; k >>= 1, l++);
                if (getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), hbuf, sizeof(hbuf), NULL, 0, NI_NUMERICHOST) == 0) {
                    h += snprintf(h, buflen - (h - buf), "%s/%" PRIuFAST32, hbuf, 32-l);
                }
                break;
            }

            case AF_INET6: {
                uint_fast32_t l = 0;
                const uint64_t * const ip6 = (uint64_t*)&((struct sockaddr_in6*)ifa->ifa_netmask)->sin6_addr;
                for (uint_fast64_t k = ~ip6[0]; k & 1; k >>= 1, l++);
                for (uint_fast64_t k = ~ip6[1]; k & 1; k >>= 1, l++);
                if (getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in6), hbuf, sizeof(hbuf), NULL, 0, NI_NUMERICHOST) == 0) {
                    h += snprintf(h, buflen - (h - buf), "%s/%" PRIuFAST32, strtok(hbuf, "%"), 128-l);
                }
                break;
            }

#ifdef __APPLE__
            case AF_LINK: {
                const uint8_t * const mac = (unsigned char*)LLADDR((struct sockaddr_dl*)(ifa)->ifa_addr);
#else // !__APPLE__
            case AF_PACKET: {
                const uint8_t * const mac = ((struct sockaddr_ll*)ifa->ifa_addr)->sll_addr;
#endif // !__APPLE__
                h += t2_mac_to_str(mac, h, buflen - (h - buf));
                break;
            }

            default:
                break;
        }

        h += snprintf(h, buflen - (h - buf), "\n");
    }

    freeifaddrs(ifaddr);

    return (h - buf);
}
#endif // TFS_HDR_FILE == 1
