/*
 * t2utils.h
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

#ifndef T2_T2UTILS_H_INCLUDED
#define T2_T2UTILS_H_INCLUDED

#include <arpa/inet.h>       // for INET_ADDRSTRLEN, INET6_ADDRSTRLEN, struct in_addr, struct in6_addr
#include <stdarg.h>          // for ...
#include <stdbool.h>         // for bool, false
#include <stddef.h>          // for size_t
#include <stdint.h>          // for uint8_t, uint64_t
#include <stdio.h>           // for FILE
#include <stdlib.h>          // for exit, EXIT_FAILURE, calloc, malloc

#include "bin2txt.h"         // for MAC_FORMAT, MAC_SEP
#include "flow.h"            // for L2_FLOW, L2_IPV4, L2_IPV6
#include "networkHeaders.h"  // for ETH_ALEN, IPV6_ACTIVATE, ETH_ACTIVATE
#include "packet.h"          // for packet_t
#include "t2log.h"           // for T2_ERR
#include "tranalyzer.h"      // for TSTAMP_PREC, TSTAMPFAC


// Forward declarations

struct in6_addr;
struct in_addr;


// Hints the compiler that the expression is likely to evaluate to a true value
#define LIKELY(x) __builtin_expect ((x), 1)

// Hints the compiler that the expression is unlikely to evaluate to a true value
#define UNLIKELY(x) __builtin_expect ((x), 0)

#define UNUSED __attribute__((__unused__))

// Exit with an error message and status 1
#define T2_FATAL(format, args...) { \
    T2_ERR(format, ##args); \
    exit(EXIT_FAILURE); \
}

#define T2_PFATAL(plugin_name, format, args...) { \
    T2_PERR(plugin_name, format, ##args); \
    exit(EXIT_FAILURE); \
}

// Min/Max for two and three values
#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif // MIN

#ifndef MIN3
#define MIN3(a, b, c) ((a) < (b) ? MIN((a), (c)) : MIN((b), (c)))
#endif // MIN3

#ifndef MAX
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif // MAX

#ifndef MAX3
#define MAX3(a, b, c) ((a) > (b) ? MAX((a), (c)) : MAX((b), (c)))
#endif // MAX3


// Stringify macros
#define XSTR(s) #s
#define STR(s) XSTR(s)


#if ETH_ACTIVATE > 0
#define FLOW_IS_L2(f) (((f)->status & L2_FLOW) != 0)
#else // ETH_ACTIVATE == 0
#define FLOW_IS_L2(f) false
#endif

#if LAPD_ACTIVATE == 1
#define FLOW_IS_LAPD(f) (((f)->status & LAPD_FLOW) != 0)
#else // LAPD_ACTIVATE == 0
#define FLOW_IS_LAPD(f) false
#endif

#if IPV6_ACTIVATE == 2 || ETH_ACTIVATE > 0
#define FLOW_IS_IPV4(f)   (((f)->status & L2_IPV4) != 0)
#define FLOW_IS_IPV6(f)   (((f)->status & L2_IPV6) != 0)
#define PACKET_IS_IPV4(p) (((p)->status & L2_IPV4) != 0)
#define PACKET_IS_IPV6(p) (((p)->status & L2_IPV6) != 0)
#else // IPV6_ACTIVATE != 2 && ETH_ACTIVATE == 0
#define FLOW_IS_IPV4(f)   (IPV6_ACTIVATE == 0)
#define FLOW_IS_IPV6(f)   (IPV6_ACTIVATE == 1)
#define PACKET_IS_IPV4(p) (IPV6_ACTIVATE == 0)
#define PACKET_IS_IPV6(p) (IPV6_ACTIVATE == 1)
#endif // IPV6_ACTIVATE != 2 && ETH_ACTIVATE == 0

#define FLOW_IS_IP(f) (FLOW_IS_IPV4(f) || FLOW_IS_IPV6(f))
#define PACKET_IS_IP(p) (PACKET_IS_IPV4(p) || PACKET_IS_IPV6(p))

#define FLOW_IPVER(f)   (FLOW_IS_IPV6(f)   ? 6 : (FLOW_IS_IPV4(f)   ? 4 : 0))
#define PACKET_IPVER(p) (PACKET_IS_IPV6(p) ? 6 : (PACKET_IS_IPV4(p) ? 4 : 0))

// Layer 2
#define L2_PROTO(p)    ((p)->ethType)

#define ETH_HEADER(p)  ((ethernetHeader_t*) L2_HEADER(p))
#define LAPD_HEADER(p) ((lapdHdr_t*)        L2_HEADER(p))

// Layer 3
#define IPV4_HEADER(p) ((ipHeader_t*)  L3_HEADER(p))
#define IPV6_HEADER(p) ((ip6Header_t*) L3_HEADER(p))

#define PROTO_IS_IPV4(p) (PACKET_IS_IPV4(p))
#define PROTO_IS_IPV6(p) (PACKET_IS_IPV6(p))

// Layer 4
#define L4_PROTO(p)       ((p)->l4Proto)

#define PROTO_IS_ICMP4(p) (L4_PROTO(p) == L3_ICMP)
#define PROTO_IS_ICMP6(p) (L4_PROTO(p) == L3_ICMP6)
#define PROTO_IS_IGMP(p)  (L4_PROTO(p) == L3_IGMP)
#define PROTO_IS_SCTP(p)  (L4_PROTO(p) == L3_SCTP)
#define PROTO_IS_TCP(p)   (L4_PROTO(p) == L3_TCP)
#define PROTO_IS_UDP(p)   (L4_PROTO(p) == L3_UDP)

#define ICMP_HEADER(p) ((icmpHeader_t*) L4_HEADER(p))
#define IGMP_HEADER(p) ((igmpHeader_t*) L4_HEADER(p))
#define PIM_HEADER(p)  ((pimHeader_t*)  L4_HEADER(p))
#define SCTP_HEADER(p) ((sctpHeader_t*) L4_HEADER(p))
#define TCP_HEADER(p)  ((tcpHeader_t*)  L4_HEADER(p))
#define UDP_HEADER(p)  ((udpHeader_t*)  L4_HEADER(p))

#define DTLS12_HEADER(p) ((dtls12Header_t*) L7_HEADER(p))


// Return true if both IPv4 addresses 'ipA' and 'ipB' of type ipAddr_t are
// equal, false otherwise
#define T2_CMP_IP4(ipA, ipB) \
    ((ipA).IPv4.s_addr == (ipB).IPv4.s_addr)


// Return true if both IPv6 addresses 'ipA' and 'ipB' of type ipAddr_t are
// equal, false otherwise
#define T2_CMP_IP6(ipA, ipB) \
    ((ipA).IPv6L[0] == (ipB).IPv6L[0] && \
     (ipA).IPv6L[1] == (ipB).IPv6L[1])


// Return true if both IP addresses (with the same version 'ipver')
// 'ipA' and 'ipB' of type ipAddr_t are equal, false otherwise
#define T2_CMP_IP(ipA, ipB, ipver) \
    (((ipver) == 6) ? T2_CMP_IP6((ipA), (ipB)) : \
        (((ipver) == 4) ? T2_CMP_IP4((ipA), (ipB)) : false))

// Return true if 'ipA' and 'ipB' are equal, false otherwise
// If IPV6_ACTIVATE > 0, this is the same as T2_CMP_IP
// If IPV6_ACTIVATE = 0, this only returns true if 'ipver' = 4 and 'ipA' == 'ipB'
#if IPV6_ACTIVATE > 0
#define T2_CMP_FLOW_IP(ipA, ipB, ipver) T2_CMP_IP(ipA, ipB, ipver)
#else // IPV6_ACTIVATE == 0
#define T2_CMP_FLOW_IP(ipA, ipB, ipver) \
    (((ipver) == 4) ? ((ipA).IPv4.s_addr == (ipB).IPv4.s_addr) : false)
#endif // IPV6_ACTIVATE == 0


// Call t2_ipv6_to_str(ip.IPv6, ...) or t2_ipv4_to_str(ip.IPv4, ...)
#define T2_IPV4_TO_STR(ip, dest, dsize) t2_ipv4_to_str(ip.IPv4, dest, dsize)
#define T2_IPV6_TO_STR(ip, dest, dsize) t2_ipv6_to_str(ip.IPv6, dest, dsize)

// Call T2_IPV4_TO_STR(...) or T2_IPV6_TO_STR(...) depending on the value of 'version'
#if IPV6_ACTIVATE == 0
#define T2_IP_TO_STR(ip, version, dest, dsize) { \
    if (version == 4) { \
        T2_IPV4_TO_STR(ip, dest, dsize); \
    } else { \
        *dest = '\0'; \
    } \
}
#else //  IPV6_ACTIVATE != 0
#define T2_IP_TO_STR(ip, version, dest, dsize) \
    if (version == 6) { \
        T2_IPV6_TO_STR(ip, dest, dsize); \
    } else if (version == 4) { \
        T2_IPV4_TO_STR(ip, dest, dsize); \
    } else { \
        *dest = '\0'; \
    }
#endif // IPV6_ACTIVATE != 0


#define T2_CONV_NUM_SFX(num, str, sfx) \
    t2_conv_readable_num((num), (str), sizeof(str), (sfx));
#define T2_CONV_NUM(num, str) T2_CONV_NUM_SFX((num), (str), "")


#define t2_calloc  calloc
#define t2_free    free
#define t2_malloc  malloc
#define t2_memcpy  memcpy
#define t2_realloc realloc

#define T2_REALLOC(dst, size) { \
    void *tmp; \
    if (UNLIKELY(!(tmp = t2_realloc(dst, size)))) { \
        free(dst); \
        T2_FATAL("Failed to reallocate memory for " STR(dst)); \
    } \
    dst = tmp; \
}


#define T2_FREE_CONST(s) free((char*)s)


// timer functions for us and ns

#define T2_TIMERADD(a, b, result) { \
    (result)->tv_sec = (a)->tv_sec + (b)->tv_sec; \
    (result)->tv_usec = (a)->tv_usec + (b)->tv_usec; \
    if ((result)->tv_usec >= TSTAMPFAC) { \
        ++(result)->tv_sec; \
        (result)->tv_usec -= TSTAMPFAC; \
    } \
}

#define T2_TIMERSUB(a, b, result) { \
    (result)->tv_sec = (a)->tv_sec - (b)->tv_sec; \
    (result)->tv_usec = (a)->tv_usec - (b)->tv_usec; \
    if ((result)->tv_usec < 0) { \
        --(result)->tv_sec; \
        (result)->tv_usec += TSTAMPFAC; \
    } \
}


// Functions

// Returned value MUST be free'd with free().
void *t2_malloc_fatal(size_t size)
    __attribute__((__malloc__))
    __attribute__((__alloc_size__(1)))
    __attribute__((__returns_nonnull__))
    __attribute__((__warn_unused_result__));

// Returned value MUST be free'd with free().
void *t2_calloc_fatal(size_t nmemb, size_t size)
    __attribute__((__malloc__))
    __attribute__((__alloc_size__(1, 2)))
    __attribute__((__returns_nonnull__))
    __attribute__((__warn_unused_result__));

// Returned value MUST be free'd with free().
char *t2_strdup_printf(const char * const format, ...)
    __attribute__((__malloc__))
    __attribute__((__format__(printf, 1, 2)))
    __attribute__((__nonnull__(1)))
    __attribute__((__returns_nonnull__))
    __attribute__((__warn_unused_result__));

// Build the filename consisting of the concatenation of all elements
// (interspersed with slashes).
// The list of elements MUST be followed by a sentinel of value NULL.
// 'first_elem' may be NULL and will then be simply ignored.
//
// Return:
//    A newly allocated buffer with the filename (MUST be free'd with free()).
//
// Usage:
//    char *dest = t2_alloc_filename("/tmp", "file_flows.txt", NULL);
//    // -> /tmp/file_flows.txt
//    free(dest);
//    dest = t2_alloc_filename("/home/user/", "Documents", "file.txt", NULL);
//    // -> /home/user/Documents/file.txt
//    free(dest);
char* t2_alloc_filename(const char * const first_elem, ...)
    __attribute__((__malloc__))
    __attribute__((__sentinel__))
    __attribute__((__returns_nonnull__))
    __attribute__((__warn_unused_result__));

// Build the filename consisting of the concatenation of all elements
// (interspersed with slashes).
// The list of elements MUST be followed by a sentinel of value NULL.
// The filename is stored in 'dest' of size 'dsize' (including trailing '\0').
// 'first_elem' may be NULL and will then be simply ignored.
//
// Return:
//    The length of the string copied into 'dest' (not including the trailing '\0').
//
// Usage:
//    char dest[64];
//    t2_build_filename(dest, sizeof(dest), "/tmp", "file_flows.txt", NULL);
//    // -> /tmp/file_flows.txt
//    t2_build_filename(dest, sizeof(dest), "/home/user/", "Documents", "file.txt", NULL);
//    // -> /home/user/Documents/file.txt
//    t2_build_filename(dest, sizeof(dest), NULL, "user", "Documents", "file.txt", NULL);
//    // -> user/Documents/file.txt
size_t t2_build_filename(char *dest, size_t dsize, const char * const first_elem, ...)
    __attribute__((__nonnull__(1)))
    __attribute__((__sentinel__));

// Return true if 'filename' exists, false otherwise.
// 'filename' is the concatenation of 'dir', a slash and 'file'.
// If 'dir' is NULL, 'filename' is set to 'file' (must not be NULL).
//
// Usage:
//    if (t2_file_exists("/tmp", "file.txt")) { ... }
bool t2_file_exists(const char * const dir, const char * const file)
    __attribute__((__nonnull__(2)))
    __attribute__((__warn_unused_result__));

// Open 'filename' in mode 'mode' ('r', 'w', ...).
// Returned value must be closed with fclose().
//
// Usage:
//    FILE *f = t2_fopen("/tmp/file.txt", "w");
//    fclose(f);
FILE* t2_fopen(const char * const filename, const char * const mode)
    __attribute__((__nonnull__(1, 2)))
    __attribute__((__warn_unused_result__));

// Open 'filename' in mode 'mode' ('r', 'w', ...).
// 'filename' is the concatenation of 'dir', a slash and 'file'.
// If 'dir' is NULL, 'filename' is set to 'file' (must not be NULL).
// (In this case, the function is equivalent to t2_fopen(file, mode).)
// Returned value must be closed with fclose().
//
// Usage:
//    FILE *f = t2_fopen_in_dir("/tmp", "file.txt", "w");
//    fclose(f);
FILE* t2_fopen_in_dir(const char * const dir, const char * const file, const char * const mode)
    __attribute__((__nonnull__(2, 3)))
    __attribute__((__warn_unused_result__));

// Open 'filename' in mode 'mode' ('r', 'w', ...).
// 'filename' is the concatenation of 'prefix' and 'suffix'.
// Returned value must be closed with fclose().
//
// Usage:
//    FILE *f = t2_fopen_with_suffix("/tmp/file", "_flows.txt", "r");
//    fclose(f);
FILE* t2_fopen_with_suffix(const char * const prefix, const char * const suffix, const char * const mode)
    __attribute__((__nonnull__(1, 2, 3)))
    __attribute__((__warn_unused_result__));

// Convert 'num' to human readable format, e.g., 1577658 -> " (1.58 M)".
// Formatted output is stored in 'numstr' (of size 'size').
// An extra 'suffix' can be provided, e.g., 'b/s' -> " (1.58 Mb/s)".
//
// Return:
//    The length of 'numstr' and guarantee that 'numstr' is NULL terminated.
//
// Usage:
//    char hrnum[64];
//    t2_conv_readable_num(10052345, hrnum, sizeof(hrnum), "");
int t2_conv_readable_num(uint64_t num, char *numstr, size_t size, const char * const suffix)
    __attribute__((__nonnull__(2)));


// Behavior of t2_strcpy function in case of overflow
typedef enum {
    T2_STRCPY_EXIT,     // exit
    T2_STRCPY_EMPTY,    // return an empty buffer                ("abcdefg" -> "")
    T2_STRCPY_TRUNC,    // truncate destination                  ("abcdefg" -> "abcdef")
    T2_STRCPY_ELLIPSIS, // truncate destination with an ellipsis ("abcdefg" -> "abc...")
} t2_strcpy_t;

// Copy 'src_size' characters from 'src' into 'dest'.
// 'src' and 'dest' MUST NOT be NULL.
//
// Return:
//    The length of the string copied into 'dest' (not including the trailing '\0').
//
// Usage:
//    char dest[64];
//    t2_strncpy(dest, "/tmp/file.txt", 4, sizeof(dest), T2_STRCPY_EXIT);
size_t t2_strncpy(char *dest, const char * const src, size_t src_size, size_t dest_size, t2_strcpy_t behavior)
    __attribute__((__nonnull__(1, 2)));

// Copy the string 'src' into 'dest'.
// 'src' and 'dest' MUST NOT be NULL.
//
// Return:
//    The length of the string copied into 'dest' (not including the trailing '\0').
//
// Usage:
//    char dest[64];
//    t2_strcpy(dest, "/tmp/file.txt", sizeof(dest), T2_STRCPY_EXIT);
size_t t2_strcpy(char *dest, const char * const src, size_t dest_size, t2_strcpy_t behavior)
    __attribute__((__nonnull__(1, 2)));

// Copy 'src_size' characters from 'src' into 'dest'.
// 'src' and 'dest' MUST NOT be NULL.
//
// Escape the following characters:
//    \n => backslash + n
//    \r => backslash + r
//    \t => backslash + t
//    "  => backslash + double quote
//    \  => backslash + backslash
//
// Return:
//    The length of the escaped string copied into 'dest' (not including the trailing '\0').
//
// Usage:
//    char dest[64];
//    t2_strncpy_escape(dest, "\"Hello\\World\"", 4, sizeof(dest), T2_STRCPY_EXIT);
size_t t2_strncpy_escape(char *dest, const char * const src, size_t src_size, size_t dest_size, t2_strcpy_t behavior)
    __attribute__((__nonnull__(1, 2)));

// Copy the string 'src' into 'dest'.
// 'src' and 'dest' MUST NOT be NULL.
//
// Escape the following characters:
//    \n => backslash + n
//    \r => backslash + r
//    \t => backslash + t
//    "  => backslash + double quote
//    \  => backslash + backslash
//
// Return:
//    The length of the escaped string copied into 'dest' (not including the trailing '\0').
//
// Usage:
//    char dest[64];
//    t2_strcpy_escape(dest, "\"Hello\\World\"", sizeof(dest), T2_STRCPY_EXIT);
size_t t2_strcpy_escape(char *dest, const char * const src, size_t dest_size, t2_strcpy_t behavior)
    __attribute__((__nonnull__(1, 2)));

// Concatenate a list of string 'first_elem' and '...' into 'dest'.
// The list MUST be followed by a sentinel of value NULL.
//
// Return:
//    A newly allocated buffer (MUST be free'd with free()).
//
// Usage:
//    char *dest = t2_alloc_strcat("/tmp", "/", "file.txt", NULL);
//    // -> /tmp/file.txt
//    free(dest);
//    dest = t2_alloc_strcat("/tmp/file", "_flows.txt", NULL);
//    // -> /tmp/file_flows.txt
//    free(dest)
char *t2_alloc_strcat(const char * const first_elem, ...)
    __attribute__((__malloc__))
    __attribute__((__nonnull__(1)))
    __attribute__((__sentinel__))
    __attribute__((__returns_nonnull__))
    __attribute__((__warn_unused_result__));

// Concatenate a list of string 'first_elem' and '...' into 'dest'.
// The list MUST be followed by a sentinel of value NULL.
//
// Return:
//    The length of the string copied into 'dest' (not including the trailing '\0').
//
// Usage:
//    char dest[64];
//    t2_strcat(dest, sizeof(dest), "/tmp", "/", "file.txt", NULL);
//    // -> /tmp/file.txt
//    t2_strcat(dest, sizeof(dest), "/tmp/file", "_flows.txt", NULL);
//    // -> /tmp/file_flows.txt
size_t t2_strcat(char *dest, size_t dsize, const char * const first_elem, ...)
    __attribute__((__nonnull__(1, 3)))
    __attribute__((__sentinel__));

// Check whether a string starts with a given prefix.
// 'str' and 'prefix' MUST NOT be NULL.
//
// Return:
//    TRUE if the prefix was found, FALSE otherwise.
//
// Usage:
//    if (t2_str_has_prefix("Andy", "And")) { ... }
bool t2_str_has_prefix(const char *str, const char *prefix)
    __attribute__((__nonnull__(1, 2)));

// Check whether a string ends with a given suffix.
// 'str' and 'suffix' MUST NOT be NULL.
//
// Return:
//    TRUE if the suffix was found, FALSE otherwise.
//
// Usage:
//    if (t2_str_has_suffix("Andy", "dy")) { ... }
bool t2_str_has_suffix(const char *str, const char *suffix)
    __attribute__((__nonnull__(1, 2)));


/******************************************************************************
 * IPv4 addresses conversion                                                  *
 ******************************************************************************/

// Return the string representation of the IPv4 address 'ip'
// (dependent on IP4_FORMAT)
//
// Usage:
//    char ipStr[INET_ADDRSTRLEN];
//    struct in_addr ip = {};
//    t2_ipv4_to_str(ip, ipStr, sizeof(ipStr));
void t2_ipv4_to_str(struct in_addr ip, char *dest, size_t dsize)
    __attribute__((__nonnull__(2)));

// Return the IPv4 compressed string representation of the IPv4 address 'ip',
// e.g., 1.2.3.4
void t2_ipv4_to_compressed(struct in_addr ip, char *dest, size_t dsize)
    __attribute__((__nonnull__(2)));

// Return the IPv4 uncompressed string representation of the IPv4 address 'ip',
// e.g., 001.002.003.004
void t2_ipv4_to_uncompressed(struct in_addr ip, char *dest, size_t dsize)
    __attribute__((__nonnull__(2)));

// Return the hexadecimal string representation of the IPv4 address 'ip',
// e.g., 0x01020304
void t2_ipv4_to_hex(struct in_addr ip, char *dest, size_t dsize)
    __attribute__((__nonnull__(2)));

// Return the unsigned int string representation of the IPv4 address 'ip',
// e.g., 16909060
void t2_ipv4_to_uint(struct in_addr ip, char *dest, size_t dsize)
    __attribute__((__nonnull__(2)));


/******************************************************************************
 * IPv6 addresses conversion                                                  *
 ******************************************************************************/

// Return the string representation of the IPv6 address 'ip'
// (dependent on IP6_FORMAT)
//
// Usage:
//    char ipStr[INET6_ADDRSTRLEN];
//    struct in6_addr ip6 = {};
//    t2_ipv6_to_str(ip6, ipStr, sizeof(ipStr));
void t2_ipv6_to_str(struct in6_addr ip, char *dest, size_t dsize)
    __attribute__((__nonnull__(2)));

// Return the IPv6 compressed string representation of the IPv6 address 'ip',
// e.g, 1111::1111
void t2_ipv6_to_compressed(struct in6_addr ip, char *dest, size_t dsize)
    __attribute__((__nonnull__(2)));

// Return the IPv6 uncompressed string representation of the IPv6 address 'ip',
// e.g, 1111:0000:0000:0000:0000:0000:0000:1111
void t2_ipv6_to_uncompressed(struct in6_addr ip, char *dest, size_t dsize)
    __attribute__((__nonnull__(2)));

// Return the hexadecimal string representation of the IPv6 address 'ip',
// e.g, 0x11110000000000000000000000001111
void t2_ipv6_to_hex128(struct in6_addr ip, char *dest, size_t dsize)
    __attribute__((__nonnull__(2)));

// Return the hexadecimal string representation of the IPv6 address 'ip' as
// two 64-bits hex numbers separated by underscore,
// e.g, 0x1111000000000000_0x0000000000001111
void t2_ipv6_to_hex64_hex64(struct in6_addr ip, char *dest, size_t dsize)
    __attribute__((__nonnull__(2)));


/******************************************************************************
 * MAC addresses                                                              *
 ******************************************************************************/

// Length of the string representation of a MAC address (without the terminating '\0')
#define T2_MAC_STRLEN (MAX(20, 12 + 5 * sizeof(MAC_SEP)))

// Swap source and destination addresses from an ethDS_t structure
//
// Usage:
//    ethDS_t ethDS = {
//        .ether_shost = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 },
//        .ether_dhost = { 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc },
//    };
//    t2_swap_mac(&ethDS);
void t2_swap_mac(ethDS_t *ethDS)
    __attribute__((__nonnull__(1)));

// Fill 'dest' with the string representation of the MAC address 'mac'
// (dependent on MAC_FORMAT and MAC_SEP)
//
// Return the length of 'dest'
//
// Usage:
//    char macStr[T2_MAC_STRLEN+1];
//    ethernetHeader_t eth = {};
//    t2_mac_to_str(eth.ethDS.ether_shost, macStr, sizeof(macStr));
int t2_mac_to_str(const uint8_t mac[ETH_ALEN], char *dest, size_t dsize)
    __attribute__((__nonnull__(2)));

// Fill 'dest' with the string representation of the MAC address 'mac',
// e.g., 00:11:22:33:44:55
// (dependent on MAC_SEP)
//
// Return the length of 'dest'
int t2_mac_to_mac(const uint8_t mac[ETH_ALEN], char *dest, size_t dsize)
    __attribute__((__nonnull__(2)));

// Fill 'dest' with the hexadecimal string representation of the MAC address 'mac',
// e.g., 0x001122334455
// Return the length of 'dest'
int t2_mac_to_hex(const uint8_t mac[ETH_ALEN], char *dest, size_t dsize)
    __attribute__((__nonnull__(2)));

// Fill 'dest' with the uint64 string representation of the MAC address 'mac',
// e.g., 18838586676582
// Return the length of 'dest'
int t2_mac_to_uint(const uint8_t mac[ETH_ALEN], char *dest, size_t dsize)
    __attribute__((__nonnull__(2)));

// Convert a MAC address 'mac' (array of uint8_t) to an uint64_t
// e.g, 73588229205
uint64_t t2_mac_to_uint64(const uint8_t mac[ETH_ALEN])
    __attribute__((__warn_unused_result__));

// Convert a MAC address 'mac' (uint64_t) as an array of uint8_t,
// e.g., { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 }
// (Make sure 'dest' can store at least ETH_ALEN (=6) bytes)
void t2_uint64_to_mac(uint64_t mac, uint8_t *dest)
    __attribute__((__nonnull__(2)));


/******************************************************************************
 * Miscellaneous                                                              *
 ******************************************************************************/

// Return true if 'packet' is a fragment with offset 0 and the more bit set
bool t2_is_fragmented_first_fragment(const packet_t * const packet)
    __attribute__((__nonnull__(1)));

// Return true if 'packet' is a first fragment, i.e., the fragment offset is 0
bool t2_is_first_fragment(const packet_t * const packet)
    __attribute__((__nonnull__(1)));

// Return true if 'packet' is the last fragment, i.e., the more bit is not set
bool t2_is_last_fragment(const packet_t * const packet)
    __attribute__((__nonnull__(1)));

// Remove the trailing character 'c' from 'stream'
void t2_discard_trailing_char(FILE *stream, int c)
    __attribute__((__nonnull__(1)));

// Remove the 'size' trailing characters 'chars' from 'stream'
void t2_discard_trailing_chars(FILE *stream, char *chars, ssize_t size)
    __attribute__((__nonnull__(1, 2)));

// Open a TCP socket connected to 'addr' and 'port'.
// Return the socket handle.
// (Returned value MUST be closed with close())
int t2_tcp_socket_connect(const char *plugin_name, const char *addr, uint16_t port, bool non_blocking)
    __attribute__((__nonnull__(1, 2)))
    __attribute__((__warn_unused_result__));

// Open a TCP socket connected to 'server'.
// Return the socket handle.
// (Returned value MUST be closed with close())
int t2_tcp_socket_connect_to_server(const char *plugin_name, struct sockaddr_in *server, bool non_blocking)
    __attribute__((__nonnull__(1, 2)))
    __attribute__((__warn_unused_result__));

// Initialize a UDP socket.
// Return the socket handle and the filled in 'server' struct.
// (Returned value MUST be closed with close())
int t2_udp_socket_init(const char *plugin_name, const char *addr, uint16_t port, struct sockaddr_in *server)
    __attribute__((__nonnull__(1, 2, 4)))
    __attribute__((__warn_unused_result__));

/******************************************************************************
 * Environment constant control                                               *
 ******************************************************************************/

typedef struct {
    char *key;
    char *val;
    bool  stolen;
} t2_env_t;

#define T2_ENV_KEY(name) env[ENV_ ## name].key
// Return the value of an environment variable as a string
#define T2_ENV_VAL(name) env[ENV_ ## name].val
// Return the value of an environment variable as an unsigned long long integer
#define T2_ENV_VAL_UINT(name) strtoull(env[ENV_ ## name].val, NULL, 0)
// Return the value of an environment variable as a long long integer (signed)
#define T2_ENV_VAL_INT(name) strtoll(env[ENV_ ## name].val, NULL, 0)
// Return a copy of an environment variable (MUST be free'd with free())
#define T2_DUP_ENV_VAL(name) strdup(env[ENV_ ## name].val)
// Take ownership of the value of an environment variable (MUST be free'd with free())
#define T2_STEAL_ENV_VAL(name) \
    env[ENV_ ## name].val; \
    env[ENV_ ## name].stolen = true

#define T2_SET_ENV_NUM(name) \
    env[ENV_ ## name].key = #name; \
    env[ENV_ ## name].val = STR(name);

#define T2_SET_ENV_STR(name) \
    env[ENV_ ## name].key = #name; \
    env[ENV_ ## name].val = name;

void t2_get_env(const char * const hname, int num_env, t2_env_t env[])
    __attribute__((__nonnull__(1, 3)));

void t2_free_env(int num_env, t2_env_t env[])
    __attribute__((__nonnull__(2)));

#endif // T2_T2UTILS_H_INCLUDED
