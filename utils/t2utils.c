/*
 * t2utils.c
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

#include "t2utils.h"

#include <arpa/inet.h>                  // for inet_ntop, ntohs, ntohl
#include <assert.h>                     // for assert
#include <errno.h>                      // for errno
#include <fcntl.h>                      // for fcntl, F_GETFL, F_SETFL, O_NONBLOCK
#include <inttypes.h>                   // for PRIu8, PRIu32
#include <math.h>                       // for ilogb
#include <netdb.h>                      // for gethostbyname
#include <netinet/in.h>                 // for in_addr, in6_addr...
#include <stdarg.h>                     // for va_end, va_list, va_start
#include <stdint.h>                     // for uint_fast8_t, uint8_t, uint16_t
#include <string.h>                     // for memcpy, strlen, strcpy, strdup
#include <sys/socket.h>                 // for socket, connect, AF_INET, AF_INET6
#include <sys/stat.h>                   // for stat, off_t
#include <unistd.h>                     // for close

#include "bin2txt.h"                    // for B2T_PRIX8, B2T_PRIX16, MAC_SEP
#include "t2log.h"                      // for T2_ERR, T2_PERR, T2_PFATAL
#include "tranalyzer.h"                 // for MAX_FILENAME_LEN, DEBUG, VERBOSE


static inline size_t t2_build_filenamev(char *dest, size_t dsize, const char * const first_elem, va_list args)
    __attribute__((__nonnull__(1)));

static inline size_t t2_strcatv(char *dest, size_t dsize, const char * const first_elem, va_list args)
    __attribute__((__nonnull__(1, 3)));


inline void *t2_malloc_fatal(size_t size) {
    void *data = t2_malloc(size);
    if (UNLIKELY(!data)) {
        T2_PFATAL("t2_malloc_fatal", "Failed to allocate memory");
    }
    return data;
}


inline void *t2_calloc_fatal(size_t nmemb, size_t size) {
    void *data = t2_calloc(nmemb, size);
    if (UNLIKELY(!data)) {
        T2_PFATAL("t2_calloc_fatal", "Failed to allocate memory");
    }
    return data;
}


inline char *t2_alloc_filename(const char * const first_elem, ...) {
    va_list args;
    va_start(args, first_elem);

    char path[MAX_FILENAME_LEN];
    t2_build_filenamev(path, sizeof(path), first_elem, args);

    va_end(args);

    char *filename = strdup(path);
    if (UNLIKELY(!filename)) {
        T2_PFATAL("t2_alloc_filename", "Failed to allocate memory");
    }

    return filename;
}


inline char *t2_strdup_printf(const char * const format, ...) {
    va_list args;
    va_start(args, format);

    char *buf = NULL;
    const int printed = vasprintf(&buf, format, args);
    if (UNLIKELY(printed < 0)) {
        T2_PFATAL("t2_strdup_printf", "Failed to allocate memory");
    }

    va_end(args);

    return buf;
}


inline char *t2_alloc_strcat(const char * const first_elem, ...) {
    va_list args;
    va_start(args, first_elem);

    char str[MAX_FILENAME_LEN];
    t2_strcatv(str, sizeof(str), first_elem, args);

    va_end(args);

    char *ret = strdup(str);
    if (UNLIKELY(!ret)) {
        T2_PFATAL("t2_alloc_strcat", "Failed to allocate memory");
    }

    return ret;
}


static inline size_t t2_strcatv(char *dest, size_t dsize, const char * const first_elem, va_list args) {
    size_t len = t2_strcpy(dest, first_elem, dsize, T2_STRCPY_EXIT);

    const char *elem;
    while ((elem = va_arg(args, char *))) {
        len += t2_strcpy(dest + len, elem, dsize - len, T2_STRCPY_EXIT);
    }

    return len;
}


inline size_t t2_strcat(char *dest, size_t dsize, const char * const first_elem, ...) {
#if DEBUG > 0
    if (UNLIKELY(dsize == 0 || dsize > MAX_FILENAME_LEN)) {
        // Programming error
        T2_PFATAL("t2_strcat", "0 < dsize <= MAX_FILENAME_LEN is required");
    }
#endif

    va_list args;
    va_start(args, first_elem);

    const size_t len = t2_strcatv(dest, dsize, first_elem, args);

    va_end(args);

    return len;
}


static inline size_t t2_build_filenamev(char *dest, size_t dsize, const char * const first_elem, va_list args) {
    size_t len = 0;

    if (first_elem) {
        len += t2_strcpy(dest, first_elem, dsize, T2_STRCPY_EXIT);
    }

    const char *elem;
    while ((elem = va_arg(args, char *))) {
        if (len > 0) {
            if (dest[len - 1] != '/' && elem[0] != '/') dest[len++] = '/';
            else if (dest[len - 1] == '/' && elem[0] == '/') len -= 1;
        }
        len += t2_strcpy(dest + len, elem, dsize - len, T2_STRCPY_EXIT);
    }

    return len;
}


inline size_t t2_build_filename(char *dest, size_t dsize, const char * const first_elem, ...) {
#if DEBUG > 0
    if (UNLIKELY(dsize == 0 || dsize > MAX_FILENAME_LEN)) {
        // Programming error
        T2_PFATAL("t2_build_filename", "0 < dsize <= MAX_FILENAME_LEN is required");
    }
#endif

    va_list args;
    va_start(args, first_elem);

    const size_t len = t2_build_filenamev(dest, dsize, first_elem, args);

    va_end(args);

    return len;
}


inline size_t t2_strncpy(char *dest, const char * const src, size_t src_size, size_t dest_size, t2_strcpy_t behavior) {
#if DEBUG > 0
    if (UNLIKELY(dest_size == 0)) {
        // Programming error
        T2_PFATAL("t2_strncpy", "dest_size > 0 is required");
    }
#endif

    size_t len = MIN(src_size, dest_size);

    if (LIKELY(len < dest_size)) {
        memcpy(dest, src, len + 1);
        dest[len] = '\0';
        return len;
    }

    // Destination buffer too short

    if (behavior == T2_STRCPY_EXIT) {
        T2_PFATAL("t2_strncpy", "Failed to copy '%s': destination buffer too short", src);
    } else if (LIKELY(dest_size > 0)) {
        if (behavior == T2_STRCPY_TRUNC) {
            len = dest_size - 1;
            memcpy(dest, src, len);
            dest[len] = '\0';
#if DEBUG > 0
            T2_WRN2("Truncating string '%s' to '%s'", src, dest);
#endif
        } else if (behavior == T2_STRCPY_ELLIPSIS) {
            len = dest_size - 1;
            memcpy(dest, src, dest_size - 4);
            memcpy(dest + dest_size - 4, "...", 3);
            dest[len] = '\0';
#if DEBUG > 0
            T2_WRN2("Truncating string '%s' to '%s'", src, dest);
#endif
        } else { // behavior == T2_STRCPY_EMPTY
            len = 0;
            dest[0] = '\0';
#if DEBUG > 0
            T2_WRN2("Truncating string '%s' to '%s'", src, dest);
#endif
        }
    }

    return len;
}


inline size_t t2_strcpy(char *dest, const char * const src, size_t dest_size, t2_strcpy_t behavior) {
#if DEBUG > 0
    if (UNLIKELY(dest_size == 0)) {
        // Programming error
        T2_PFATAL("t2_strcpy", "dest_size > 0 is required");
    }
#endif

    const size_t len = strnlen(src, dest_size);
    return t2_strncpy(dest, src, len, dest_size, behavior);
}


inline size_t t2_strncpy_escape(char *dest, const char * const src, size_t src_size, size_t dest_size, t2_strcpy_t behavior) {
#if DEBUG > 0
    if (UNLIKELY(dest_size == 0)) {
        // Programming error
        T2_PFATAL("t2_strncpy_escape", "dest_size > 0 is required");
    }
#endif

    const int_fast32_t imax = MIN(src_size, dest_size);

    bool too_short = false;
    unsigned long len = 0;
    for (int_fast32_t i = 0; i < imax && len < dest_size && !too_short; i++, len++) {
        switch (src[i]) {
            case '\n':
                if (len + 1 >= dest_size) {
                    too_short = true;
                    break;
                }
                dest[len++] = '\\';
                dest[len] = 'n';
                break;
            case '\r':
                if (len + 1 >= dest_size) {
                    too_short = true;
                    break;
                }
                dest[len++] = '\\';
                dest[len] = 'r';
                break;
            case '\t':
                if (len + 1 >= dest_size) {
                    too_short = true;
                    break;
                }
                dest[len++] = '\\';
                dest[len] = 't';
                break;
            case '"':
            case '\\':
                if (len + 1 >= dest_size) {
                    too_short = true;
                    break;
                }
                dest[len++] = '\\';
                /* FALLTHRU */
            default:
                dest[len] = src[i];
                break;
        }
    }

    if (len >= dest_size || too_short) {    // Destination buffer too short
        if (behavior == T2_STRCPY_EXIT) {
            T2_PFATAL("t2_strncpy_escape", "Failed to copy '%s': destination buffer too short", src);
        } else if (LIKELY(dest_size > 0)) {
            if (behavior == T2_STRCPY_TRUNC) {
                len -= 1;
#if DEBUG > 0
                T2_WRN2("Truncating string '%s' to '%s'", src, dest);
#endif
            } else if (behavior == T2_STRCPY_ELLIPSIS && dest_size >= 4) {
                dest[len - 4] = '.';
                dest[len - 3] = '.';
                dest[len - 2] = '.';
                len -= 1;
#if DEBUG > 0
                T2_WRN2("Truncating string '%s' to '%s'", src, dest);
#endif
            } else { // behavior == T2_STRCPY_EMPTY
                len = 0;
#if DEBUG > 0
                T2_WRN2("Truncating string '%s' to '%s'", src, dest);
#endif
            }
        }
    }

    dest[len] = '\0';

    return len;
}


inline size_t t2_strcpy_escape(char *dest, const char * const src, size_t dest_size, t2_strcpy_t behavior) {
#if DEBUG > 0
    if (UNLIKELY(dest_size == 0)) {
        // Programming error
        T2_PFATAL("t2_strcpy_escape", "dest_size > 0 is required");
    }
#endif

    const size_t len = strnlen(src, dest_size);
    return t2_strncpy_escape(dest, src, len, dest_size, behavior);
}


inline bool t2_str_has_prefix(const char *str, const char *prefix) {
    const size_t str_len = strlen(str);
    const size_t prefix_len = strlen(prefix);
    if (str_len < prefix_len) return 0;
    return (memcmp(str, prefix, prefix_len) == 0);
}


inline bool t2_str_has_suffix(const char *str, const char *suffix) {
    const size_t str_len = strlen(str);
    const size_t suffix_len = strlen(suffix);
    if (str_len < suffix_len) return 0;
    return (memcmp(str + str_len - suffix_len, suffix, suffix_len) == 0);
}


inline bool t2_file_exists(const char * const dir, const char * const file) {
    char path[MAX_FILENAME_LEN];
    t2_build_filename(path, sizeof(path), dir, file, NULL);

    struct stat buf;
    return (stat(path, &buf) == 0);
}


inline FILE *t2_fopen(const char * const filename, const char * const mode) {
    FILE *file;
    if (UNLIKELY(!(file = fopen(filename, mode)))) {
        T2_ERR("Failed to open file '%s': %s", filename, strerror(errno));
        return NULL;
    }

    return file;
}


inline FILE *t2_fopen_in_dir(const char * const dir, const char * const file, const char * const mode) {
    char path[MAX_FILENAME_LEN];
    t2_build_filename(path, sizeof(path), dir, file, NULL);
    return t2_fopen(path, mode);
}


inline FILE *t2_fopen_with_suffix(const char * const prefix, const char * const suffix, const char * const mode) {
    char path[MAX_FILENAME_LEN];
    t2_strcat(path, sizeof(path), prefix, suffix, NULL);
    return t2_fopen(path, mode);
}


inline int t2_conv_readable_num(uint64_t num, char *numstr, size_t size, const char * const suffix) {
    if (num < 1024) {
        numstr[0] = '\0';
        return 0;
    }

    const uint_fast8_t i = MIN(ilogb(num) / 10, 8);
    if (i == 0) {
        numstr[0] = '\0';
        return 0;
    }

    const char *units = ".KMGTPEZY"; // 8 max
    const double factors[] = { 1, 1e3, 1e6, 1e9, 1e12, 1e15, 1e18, 1e21, 1e24 };
    return snprintf(&(numstr[0]), size, " (%.2f %c%s)", num / factors[i], units[i], suffix ? suffix : "");
}


// Return true if packet is a fragment with offset 0 and the more bit set
inline bool t2_is_fragmented_first_fragment(const packet_t * const packet) {
#if IPV6_ACTIVATE == 2
    if (PACKET_IS_IPV6(packet)) {
#endif // IPV6_ACTIVATE == 2
#if IPV6_ACTIVATE > 0
        const ip6FragHdr_t * const ip6FragHdrP = packet->ip6FragHdrP;
        if (ip6FragHdrP && (ip6FragHdrP->frag_off & FRAG6IDM_N) == MORE_FRAG6_N) {
            return false;
        }
#endif // IPV6_ACTIVATE > 0
#if IPV6_ACTIVATE == 2
    } else { // IPv4
#endif // IPV6_ACTIVATE == 2
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
        const ipHeader_t * const ipHeaderP = (ipHeader_t*)packet->l3HdrP;
        if (ipHeaderP && (ipHeaderP->ip_off & FRAGIDM_N) == MORE_FRAG_N) {
            return false;
        }
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
#if IPV6_ACTIVATE == 2
    }
#endif // IPV6_ACTIVATE == 2

    return true;
}


// Return true if packet is a first fragment, i.e., the fragment offset is 0
inline bool t2_is_first_fragment(const packet_t * const packet) {
#if IPV6_ACTIVATE == 2
    if (PACKET_IS_IPV6(packet)) {
#endif // IPV6_ACTIVATE == 2
#if IPV6_ACTIVATE > 0
        const ip6FragHdr_t * const ip6FragHdrP = packet->ip6FragHdrP;
        if (ip6FragHdrP && (ip6FragHdrP->frag_off & FRAG6ID_N)) {
            return false;
        }
#endif // IPV6_ACTIVATE > 0
#if IPV6_ACTIVATE == 2
    } else { // IPv4
#endif // IPV6_ACTIVATE == 2
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
        const ipHeader_t * const ipHeaderP = (ipHeader_t*)packet->l3HdrP;
        if (ipHeaderP && (ipHeaderP->ip_off & FRAGID_N)) {
            return false;
        }
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
#if IPV6_ACTIVATE == 2
    }
#endif // IPV6_ACTIVATE == 2

    return true;
}


// Return true if packet is the last fragment, i.e., the more bit is not set
inline bool t2_is_last_fragment(const packet_t * const packet) {
#if IPV6_ACTIVATE == 2
    if (PACKET_IS_IPV6(packet)) {
#endif // IPV6_ACTIVATE == 2
#if IPV6_ACTIVATE > 0
        const ip6FragHdr_t * const ip6FragHdrP = packet->ip6FragHdrP;
        if (ip6FragHdrP && (ip6FragHdrP->frag_off & MORE_FRAG6_N)) {
            return false;
        }
#endif // IPV6_ACTIVATE > 0
#if IPV6_ACTIVATE == 2
    } else { // IPv4
#endif // IPV6_ACTIVATE == 2
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
        const ipHeader_t * const ipHeaderP = (ipHeader_t*)packet->l3HdrP;
        if (ipHeaderP && (ipHeaderP->ip_off & MORE_FRAG_N)) {
            return false;
        }
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
#if IPV6_ACTIVATE == 2
    }
#endif // IPV6_ACTIVATE == 2

    return true;
}


inline void t2_ipv4_to_str(struct in_addr ip, char *dest, size_t dsize) {
#if IP4_FORMAT == 1
    t2_ipv4_to_uncompressed(ip, dest, dsize);
#elif IP4_FORMAT == 2
    t2_ipv4_to_hex(ip, dest, dsize);
#elif IP4_FORMAT == 3
    t2_ipv4_to_uint(ip, dest, dsize);
#else // IP4_FORMAT == 0
    t2_ipv4_to_compressed(ip, dest, dsize);
#endif // IP4_FORMAT == 0
}


inline void t2_ipv4_to_compressed(struct in_addr ip, char *dest, size_t dsize) {
    inet_ntop(AF_INET, &ip, dest, dsize);
}


inline void t2_ipv4_to_hex(struct in_addr ip, char *dest, size_t dsize) {
    snprintf(dest, dsize, "0x%08" B2T_PRIX32, ntohl(ip.s_addr));
}


inline void t2_ipv4_to_uint(struct in_addr ip, char *dest, size_t dsize) {
    snprintf(dest, dsize, "%" PRIu32, ntohl(ip.s_addr));
}


inline void t2_ipv4_to_uncompressed(struct in_addr ip, char *dest, size_t dsize) {
    const uint8_t addr[] = {
        (ip.s_addr & 0x000000ff),
        (ip.s_addr & 0x0000ff00) >>  8,
        (ip.s_addr & 0x00ff0000) >> 16,
        (ip.s_addr & 0xff000000) >> 24,
    };
    snprintf(dest, dsize, "%03" PRIu8 ".%03" PRIu8 ".%03" PRIu8 ".%03" PRIu8,
            addr[0], addr[1], addr[2], addr[3]);
}


inline void t2_ipv6_to_str(struct in6_addr ip, char *dest, size_t dsize) {
#if IP6_FORMAT == 1 // uncompressed
    t2_ipv6_to_uncompressed(ip, dest, dsize);
#elif IP6_FORMAT == 2 // hex128
    t2_ipv6_to_hex128(ip, dest, dsize);
#elif IP6_FORMAT == 3 // hex64_hex64
    t2_ipv6_to_hex64_hex64(ip, dest, dsize);
#else // IP6_FORMAT == 0
    t2_ipv6_to_compressed(ip, dest, dsize);
#endif // IP6_FORMAT == 0
}


inline void t2_ipv6_to_compressed(struct in6_addr ip, char *dest, size_t dsize) {
    inet_ntop(AF_INET6, &ip, dest, dsize);
}


inline void t2_ipv6_to_uncompressed(struct in6_addr ip, char *dest, size_t dsize) {
#if defined(s6_addr16)
    const uint16_t * const val16 = ip.s6_addr16;
#elif defined(__APPLE__)
    const uint16_t * const val16 = ip.__u6_addr.__u6_addr16;
#else
    const uint16_t * const val16 = ip.__in6_u.__u6_addr16;
#endif
    snprintf(dest, dsize,
            "%04" B2T_PRIX16 ":%04" B2T_PRIX16 ":%04" B2T_PRIX16 ":%04" B2T_PRIX16 ":"
            "%04" B2T_PRIX16 ":%04" B2T_PRIX16 ":%04" B2T_PRIX16 ":%04" B2T_PRIX16,
            ntohs(val16[0]), ntohs(val16[1]), ntohs(val16[2]), ntohs(val16[3]),
            ntohs(val16[4]), ntohs(val16[5]), ntohs(val16[6]), ntohs(val16[7]));
}


inline void t2_ipv6_to_hex128(struct in6_addr ip, char *dest, size_t dsize) {
#if defined(s6_addr)
    const uint8_t * const val8 = ip.s6_addr;
#elif defined(__APPLE__)
    const uint8_t * const val8 = ip.__u6_addr.__u6_addr8;
#else
    const uint8_t * const val8 = ip.__in6_u.__u6_addr8;
#endif
    snprintf(dest, dsize,
            "0x%02" B2T_PRIX8 "%02" B2T_PRIX8 "%02" B2T_PRIX8 "%02" B2T_PRIX8
              "%02" B2T_PRIX8 "%02" B2T_PRIX8 "%02" B2T_PRIX8 "%02" B2T_PRIX8
              "%02" B2T_PRIX8 "%02" B2T_PRIX8 "%02" B2T_PRIX8 "%02" B2T_PRIX8
              "%02" B2T_PRIX8 "%02" B2T_PRIX8 "%02" B2T_PRIX8 "%02" B2T_PRIX8,
            val8[0], val8[1], val8[2], val8[3], val8[4], val8[5], val8[6], val8[7],
            val8[8], val8[9], val8[10], val8[11], val8[12], val8[13], val8[14], val8[15]);
}


inline void t2_ipv6_to_hex64_hex64(struct in6_addr ip, char *dest, size_t dsize) {
#if defined(s6_addr)
    const uint8_t * const val8 = ip.s6_addr;
#elif defined(__APPLE__)
    const uint8_t * const val8 = ip.__u6_addr.__u6_addr8;
#else
    const uint8_t * const val8 = ip.__in6_u.__u6_addr8;
#endif
    snprintf(dest, dsize,
            "0x%02" B2T_PRIX8 "%02" B2T_PRIX8 "%02" B2T_PRIX8 "%02" B2T_PRIX8
              "%02" B2T_PRIX8 "%02" B2T_PRIX8 "%02" B2T_PRIX8 "%02" B2T_PRIX8 "_"
            "0x%02" B2T_PRIX8 "%02" B2T_PRIX8 "%02" B2T_PRIX8 "%02" B2T_PRIX8
              "%02" B2T_PRIX8 "%02" B2T_PRIX8 "%02" B2T_PRIX8 "%02" B2T_PRIX8,
            val8[0], val8[1], val8[2], val8[3], val8[4], val8[5], val8[6], val8[7],
            val8[8], val8[9], val8[10], val8[11], val8[12], val8[13], val8[14], val8[15]);
}


inline void t2_swap_mac(ethDS_t *ethDS) {
    uint8_t dhost[ETH_ALEN] = {};
    memcpy(dhost, ethDS->ether_dhost, ETH_ALEN);
    memcpy(ethDS->ether_dhost, ethDS->ether_shost, ETH_ALEN);
    memcpy(ethDS->ether_shost, dhost, ETH_ALEN);
}


inline int t2_mac_to_str(const uint8_t mac[ETH_ALEN], char *dest, size_t dsize) {
#if MAC_FORMAT == 1
    return t2_mac_to_hex(mac, dest, dsize);
#elif MAC_FORMAT == 2
    return t2_mac_to_uint(mac, dest, dsize);
#else // MAC_FORMAT == 0
    return t2_mac_to_mac(mac, dest, dsize);
#endif // MAC_FORMAT == 0
}


inline int t2_mac_to_mac(const uint8_t mac[ETH_ALEN], char *dest, size_t dsize) {
    return snprintf(dest, dsize,
            "%02" B2T_PRIX8 "%s%02" B2T_PRIX8 "%s%02" B2T_PRIX8 "%s"
            "%02" B2T_PRIX8 "%s%02" B2T_PRIX8 "%s%02" B2T_PRIX8,
            mac[0], MAC_SEP, mac[1], MAC_SEP, mac[2], MAC_SEP,
            mac[3], MAC_SEP, mac[4], MAC_SEP, mac[5]);
}


inline int t2_mac_to_hex(const uint8_t mac[ETH_ALEN], char *dest, size_t dsize) {
    return snprintf(dest, dsize, "0x%016" B2T_PRIX64,
            ((uint64_t)mac[0] << 40) | ((uint64_t)mac[1] << 32) |
            ((uint64_t)mac[2] << 24) | ((uint64_t)mac[3] << 16) |
            ((uint64_t)mac[4] <<  8) |  (uint64_t)mac[5]);
}


inline int t2_mac_to_uint(const uint8_t mac[ETH_ALEN], char *dest, size_t dsize) {
    return snprintf(dest, dsize, "%" PRIu64, t2_mac_to_uint64(mac));
}


inline uint64_t t2_mac_to_uint64(const uint8_t mac[ETH_ALEN]) {
    uint64_t mac64 = mac[0];
    for (uint_fast8_t i = 1; i < ETH_ALEN; i++) {
        mac64 = (mac64 << 8) | mac[i];
    }
    return mac64;
}


inline void t2_uint64_to_mac(uint64_t mac, uint8_t *dest) {
    for (uint_fast8_t i = 0; i < ETH_ALEN; i++) {
        dest[i] = (mac >> 8 * (ETH_ALEN - 1 - i)) & 0xff;
    }
}


inline void t2_discard_trailing_char(FILE *stream, int c) {
    const off_t offset = ftello(stream);
    if (LIKELY(offset > 0)) {
        fseek(stream, -1, SEEK_CUR);
        const int last = fgetc(stream);
        if (last == c) {
            fseek(stream, -1, SEEK_CUR);
            fputc('\0', stream);
        }
    }
}


inline void t2_discard_trailing_chars(FILE *stream, char *chars, ssize_t size) {
    const off_t offset = ftello(stream);
    if (LIKELY(offset > size)) {
        fseek(stream, -size, SEEK_CUR);
        char last[size + 1];
        if (UNLIKELY(!fgets(last, size + 1, stream))) return;
        if (memcmp(last, chars, size) == 0) {
            fseek(stream, -size, SEEK_CUR);
            for (ssize_t i = 0; i < size; i++) {
                fputc('\0', stream);
            }
            fseek(stream, -size, SEEK_CUR);
        }
    }
}


inline int t2_tcp_socket_connect(const char *plugin_name, const char *addr, uint16_t port, bool non_blocking) {
    const struct hostent * const host = gethostbyname(addr);
    if (UNLIKELY(!host)) {
        T2_PERR(plugin_name, "gethostbyname() failed for '%s'", addr);
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in server = {};
    server.sin_addr = *(struct in_addr*)host->h_addr;
    server.sin_family = AF_INET;
    server.sin_port = htons(port);

    return t2_tcp_socket_connect_to_server(plugin_name, &server, non_blocking);
}


inline int t2_tcp_socket_connect_to_server(const char *plugin_name, struct sockaddr_in *server, bool non_blocking) {
    int sfd;
    if (UNLIKELY((sfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)) {
        T2_PFATAL(plugin_name, "Could not create TCP socket: %s", strerror(errno));
    }

    if (UNLIKELY(connect(sfd, (struct sockaddr*)server, sizeof(*server)) < 0)) {
        T2_PERR(plugin_name, "Could not connect to TCP socket at %s:%" PRIu16 ": %s",
                inet_ntoa(server->sin_addr), ntohs(server->sin_port), strerror(errno));
        close(sfd);
        exit(EXIT_FAILURE);
    }

    if (non_blocking) {
        int flags = fcntl(sfd, F_GETFL, 0);
        flags |= O_NONBLOCK;
        fcntl(sfd, F_SETFL, flags);
    }

    return sfd;
}


inline int t2_udp_socket_init(const char *plugin_name, const char *addr, uint16_t port, struct sockaddr_in *server) {
    int sfd;
    if (UNLIKELY((sfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)) {
        T2_PFATAL(plugin_name, "Could not create UDP socket: %s", strerror(errno));
    }

    const struct hostent * const host = gethostbyname(addr);
    if (UNLIKELY(!host)) {
        T2_PERR(plugin_name, "gethostbyname() failed for '%s'", addr);
        close(sfd);
        exit(EXIT_FAILURE);
    }

    server->sin_addr = *(struct in_addr*)host->h_addr;
    server->sin_family = AF_INET;
    server->sin_port = htons(port);

    return sfd;
}


#if ENVCNTRL > 0

// Extract plugin name from filename (.../plugins/PLUGIN_NAME/src/...)
// Returned value MUST be free'd with free()
static char *extract_plugin_name_from_filename(const char *filename) {
    char *plugin;

    char *tmp_name = strdup(filename);

    const char *start = strstr(tmp_name, "/plugins/");
    if (start) start += 9;
    else start = tmp_name;

    char *end = strstr(start, "/src/");
    if (end) {
        *end = '\0';
        plugin = strdup(start);
        *end = '/';
    } else {
        plugin = strdup(start);
    }

    free(tmp_name);

    return plugin;
}


void t2_get_env(const char *hname, int num_env, t2_env_t env[]) {
#define ENVDEF "#define"
#define ENVBGN "/* +++++++++++++++++++++ ENV / RUNTIME - conf Variables +"
#define ENVEND "/* ------------------------- DO NOT EDIT BELOW HERE -"

    FILE *cf = t2_fopen(hname, "r");
    if (UNLIKELY(!cf)) exit(EXIT_FAILURE);

    int i = 0;
    char *s, *e, *f;

    size_t len = 0;
    ssize_t read;
    char *line = NULL;

    int cnt = 0;
    int flg = 0;
    while ((read = getline(&line, &len, cf)) != -1 && cnt < num_env) {
        if (memcmp(line, ENVBGN, sizeof(ENVBGN) - 1) == 0) {
            flg = 1;
            continue;
        } else if (memcmp(line, ENVEND, sizeof(ENVEND) - 1) == 0) {
            flg = 0;
            break;
        } else if (!flg || memcmp(line, ENVDEF, sizeof(ENVDEF) - 1) != 0) {
            continue;
        }

        s = line + sizeof(ENVDEF);
        while (*s == ' ') s++;

        i = (int)(s - line);
        e = memchr(s, ' ', len - i);
        i = (int)(e - s);

        if (i <= 0) continue;

        env[cnt].key = t2_malloc_fatal(i + 1);
        memcpy(env[cnt].key, s, i);
        env[cnt].key[i] = '\0';

        s += ++i;
        while (*s == ' ') s++;

        i = strlen(s);
        e = strchr(s + 1, '\"');
        if (e) {
            s++;
        } else {
            e = memchr(s, ' ', i);
            f = memchr(s, '/', i);
            if (e > f) e = f;
        }

        if (e) i = (int)(e - s);
        else i--;

        if (i < 0) i = 0;

        env[cnt].val = t2_malloc_fatal(i + 1);
        memcpy(env[cnt].val, s, i);
        env[cnt].val[i] = '\0';

        cnt++;
    }

    free(line);
    fclose(cf);

    if (cnt != num_env) {
        char * const plugin = extract_plugin_name_from_filename(hname);
        T2_PERR(plugin, "Number of 'env' parameters differ: found %d, expected %d", cnt, num_env);
        free(plugin);
        exit(EXIT_FAILURE);
    }

#if ENVCNTRL == 2
#if VERBOSE > 2
    int not_defined = 0;
#endif
    for (i = 0; i < num_env; i++) {
        s = getenv(env[i].key);
        if (s) {
            free(env[i].val);
            env[i].val = strdup(s);
#if VERBOSE > 2
        } else {
            if (++not_defined > 1) {
                fprintf(dooF, ", %s", env[i].key);
            } else {
                char *plugin = extract_plugin_name_from_filename(hname);
                fprintf(dooF, YELLOW_BOLD "[WRN] %s: " NOCOLOR YELLOW "%s", plugin, env[i].key);
                free(plugin);
            }
#endif // VERBOSE > 2
        }
    }

#if VERBOSE > 2
    if (not_defined > 0) {
        fprintf(dooF, " parameter%s not defined in 'env'. Using default from header file." NOCOLOR "\n",
                ((not_defined == 1) ? "" : "s"));
    }
#endif // VERBOSE > 2

#endif // ENVCNTRL == 2

#undef ENVDEF
#undef ENVBGN
#undef ENVEND
}


void t2_free_env(int num_env, t2_env_t env[]) {
    for (int i = 0; i < num_env; i++) {
        free(env[i].key);
        if (!env[i].stolen) {
            free(env[i].val);
        }
    }
}

#endif // ENVCNTRL > 0
