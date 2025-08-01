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

#include "socketSink.h"

#include <errno.h>          // for errno
#include <ifaddrs.h>        // for getifaddrs, struct ifaddrs, freeifaddrs
#include <netdb.h>          // for gethostbyname
#include <sys/types.h>      // for ssize_t
#include <sys/utsname.h>    // for uname, struct utsname
#include <unistd.h>         // for close

#if SKS_HOST_INFO == 1 && SKS_CONTENT_TYPE == 0
#ifdef __APPLE__
#include <net/if_dl.h>        // for LLADDR
#else // ! __APPLE__
#include <netpacket/packet.h> // for struct sockaddr_ll
#endif // __APPLE__
#endif // SKS_HOST_INFO == 1 && SKS_CONTENT_TYPE == 0

#if SKS_GZ_COMPRESS == 1
#include "gz2txt.h"
#endif // SKS_GZ_COMPRESS == 0


#if BLOCK_BUF == 0

// Static variables

#if SKS_GZ_COMPRESS == 1
static gzFile gzfd;
#endif

static int sfd;
#if SKS_SOCKTYPE == 0
static struct sockaddr_in server;
#endif // SKS_SOCKTYPE == 0
static char *bH;

#if SKS_CONTENT_TYPE > 0
static FILE *sBuf;
static size_t sBufSize;
#endif


// Function prototypes

static void cleanup();
static inline void sendbuf(const char *buf, ssize_t buflen);
#if SKS_HOST_INFO == 1 && SKS_CONTENT_TYPE == 0
static int gethostinfo(char *buf, size_t buflen);
#endif

#endif // BLOCK_BUF == 0


// Tranalyzer functions

T2_PLUGIN_INIT("socketSink", "0.9.3", 0, 9);


void t2Init() {

#if BLOCK_BUF == 1
    T2_PWRN(plugin_name, "BLOCK_BUF is set in 'tranalyzer.h', no output will be produced");
#else // BLOCK_BUF == 0

#if ENVCNTRL > 0
    t2_env_t env[ENV_SKS_N] = {};
    t2_get_env(PLUGIN_SRCH, ENV_SKS_N, env);
    const char * const addr = T2_ENV_VAL(SKS_SERVADD);
    const uint16_t port = T2_ENV_VAL_UINT(SKS_DPORT);
#else // ENVCNTRL == 0
    const char * const addr = SKS_SERVADD;
    const uint16_t port = SKS_DPORT;
#endif // ENVCNTRL

#if SKS_SOCKTYPE == 1
    sfd = t2_tcp_socket_connect(plugin_name, addr, port, false);
#else // SKS_SOCKTYPE == 0
    sfd = t2_udp_socket_init(plugin_name, addr, port, &server);
#endif // SKS_SOCKTYPE

#if SKS_GZ_COMPRESS == 1
    if (UNLIKELY(!(gzfd = gzdopen(sfd, "w")))) {
        T2_PERR(plugin_name, "Could not create compressed stream: %s", strerror(errno));
        cleanup();
        exit(EXIT_FAILURE);
    }
#endif // SKS_GZ_COMPRESS == 1

#if SKS_CONTENT_TYPE > 0
    sBuf = open_memstream(&bH, &sBufSize);
    if (UNLIKELY(!sBuf)) {
        T2_PERR(plugin_name, "open_memstream failed: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

#if SKS_CONTENT_TYPE == 1
    parse_binary_header2text(main_header_bv, sBuf, b2t_funcs);
    fflush(sBuf);
    sendbuf(bH, sBufSize);
#endif // SKS_CONTENT_TYPE == 1

#else // SKS_CONTENT_TYPE == 0
    uint32_t buflen, *wP;

    // build first packet info about host and sent it to the appropriate socket
#if SKS_HOST_INFO == 1
    bH = t2_calloc_fatal(MAXBHBUF+1, sizeof(*bH));
    wP = (uint32_t*)bH;
    buflen = gethostinfo(bH + SOCK_BUFSHFT, MAXBHBUF - SOCK_BUFSHFT) + SOCK_BUFSHFT;
    buflen = (buflen + 3) & ~3; // pad the buffer to a multiple of 4 (uint32_t aligned)
    // TODO make sure buflen <= MAXBHBUF?
#if BUF_DATA_SHFT > 0
    wP[0] = buflen;
#if BUF_DATA_SHFT > 1
    wP[1] = 0;
    wP[1] = Checksum32(wP, buflen);
#endif
#endif // BUF_DATA_SHFT > 0
    sendbuf((char*)wP, buflen);
#endif // SKS_HOST_INFO == 1

    // build binary header and sent it to the appropriate socket
    binary_header_t * const header = build_header(main_header_bv);

    wP = header->header;
    buflen = header->length << 2;

#if BUF_DATA_SHFT > 0
    wP[0] = buflen;
#if BUF_DATA_SHFT > 1
    wP[1] = 0;
    wP[1] = Checksum32(wP, buflen-4);
#endif // BUF_DATA_SHFT > 1
#endif // BUF_DATA_SHFT > 0

    sendbuf((char*)wP, buflen);

    free(header->header);
    free(header);
#endif // SKS_CONTENT_TYPE == 0

#if ENVCNTRL > 0
    t2_free_env(ENV_SKS_N, env);
#endif // ENVCNTRL > 0

#endif // BLOCK_BUF == 0
}


// If BLOCK_BUF == 1, the plugin does not produce any output.
// All the code below is therefore not activated.


#if BLOCK_BUF == 0


void t2BufferToSink(outputBuffer_t *buf, binary_value_t *bv
#if SKS_CONTENT_TYPE == 0
    UNUSED
#endif
) {

#if SKS_CONTENT_TYPE > 0
    fseek(sBuf, 0, SEEK_SET);

#if SKS_CONTENT_TYPE == 2
    if (UNLIKELY(!parse_buffer_bin2json(buf, bv, sBuf, b2t_funcs))) {
#else // SKS_CONTENT_TYPE == 1
    if (UNLIKELY(!parse_buffer_bin2txt(buf, bv, sBuf, b2t_funcs))) {
#endif // SKS_CONTENT_TYPE == 1
        // ignore this flow
        return;
    }

    fflush(sBuf);
    sendbuf(bH, sBufSize);
#else // SKS_CONTENT_TYPE == 0
    char * const sbuf = buf->buffer - SOCK_BUFSHFT;
    const uint32_t buflen = buf->pos + SOCK_BUFSHFT;

#if BUF_DATA_SHFT > 0
    uint32_t * const buf32 = (uint32_t*)sbuf;
    buf32[0] = buf->pos;
#if BUF_DATA_SHFT > 1
    buf32[1] = 0;
    buf32[1] = Checksum32(buf32, buflen);
#endif
#endif // BUF_DATA_SHFT > 0

    sendbuf(sbuf, buflen);
#endif // SKS_CONTENT_TYPE == 0
}


static void cleanup() {
#if SKS_GZ_COMPRESS == 1
    gzclose(gzfd);
#endif

    if (LIKELY(sfd)) close(sfd);

#if SKS_CONTENT_TYPE > 0
    if (LIKELY(sBuf != NULL)) fclose(sBuf);
#endif

    free(bH);
}


void t2Finalize() {
    cleanup();
}


#if SKS_HOST_INFO == 1 && SKS_CONTENT_TYPE == 0
static int gethostinfo(char *ht, size_t buflen) {

    struct ifaddrs *ifaddr;
    if (UNLIKELY(getifaddrs(&ifaddr) == -1)) {
        T2_PERR(plugin_name, "Failed to list network interfaces: %s", strerror(errno));
        cleanup();
        exit(EXIT_FAILURE);
    }

    struct timeval t;
    gettimeofday(&t, NULL);

    *ht = 0x0;
    uint32_t * const p = (uint32_t*)ht;
    uint64_t * const m = (uint64_t*)(p+1);

    p[0] = T2_SENSORID;
    m[0] = (uint64_t)t.tv_sec;
    p[3] = (uint32_t)t.tv_usec;

    char *h = ht + 16;

    struct utsname buf;
    uname(&buf);

    h += snprintf(h, buflen - (h - ht), "%s;%s;%s;%s;%s;", buf.nodename, buf.sysname, buf.release, buf.version, buf.machine);

    for (struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) continue;

        h += snprintf(h, buflen - (h - ht), "%s(", ifa->ifa_name);

        switch (ifa->ifa_addr->sa_family) {
            case AF_INET: {
                uint_fast32_t l = 0;
                const uint32_t ip = *(uint32_t*)&((struct sockaddr_in*)ifa->ifa_netmask)->sin_addr;
                for (uint_fast32_t k = ~ntohl(ip); k & 1; k >>= 1, l++);
                char hbuf[NI_MAXHOST];
                if (getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), hbuf, sizeof(hbuf), NULL, 0, NI_NUMERICHOST) == 0) {
                    h += snprintf(h, buflen - (h - ht), "%s/%" PRIuFAST32, hbuf, 32-l);
                }
                break;
            }

            case AF_INET6: {
                uint_fast32_t l = 0;
                const uint64_t * const ip6 = (uint64_t*)&((struct sockaddr_in6*)ifa->ifa_netmask)->sin6_addr;
                for (uint_fast64_t k = ~ip6[0]; k & 1; k >>= 1, l++);
                for (uint_fast64_t k = ~ip6[1]; k & 1; k >>= 1, l++);
                char hbuf[NI_MAXHOST];
                if (getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in6), hbuf, sizeof(hbuf), NULL, 0, NI_NUMERICHOST) == 0) {
                    h += snprintf(h, buflen - (h - ht), "%s/%" PRIuFAST32, strtok(hbuf, "%"), 128-l);
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
                h += t2_mac_to_str(mac, h, buflen - (h - ht));
                break;
            }

            default:
                break;
        }

        h += snprintf(h, buflen - (h - ht), ");");
    }

    freeifaddrs(ifaddr);

    return (h - ht);
}
#endif // SKS_HOST_INFO == 1 && SKS_CONTENT_TYPE == 0


static inline void sendbuf(const char *buf, ssize_t buflen) {
    ssize_t bytes;
    ssize_t written = 0;
    while (written < buflen) {
#if SKS_GZ_COMPRESS == 1
        bytes = gzwrite(gzfd, buf + written, buflen - written);
#elif SKS_SOCKTYPE == 1 // && SKS_GZ_COMPRESS == 0
        bytes = write(sfd, buf + written, buflen - written);
#else // SKS_SOCKTYPE == 0 && SKS_GZ_COMPRESS == 0
        bytes = sendto(sfd, buf + written, buflen - written, 0, (struct sockaddr*)&server, sizeof(server));
#endif // SKS_SOCKTYPE == 0 && SKS_GZ_COMPRESS == 0
        if (UNLIKELY(bytes <= 0)) {
            T2_PERR(plugin_name, "Could not send message to socket: %s", strerror(errno));
            cleanup();
            exit(EXIT_FAILURE);
        }
        written += bytes;
    }
}

#endif // BLOCK_BUF == 0
