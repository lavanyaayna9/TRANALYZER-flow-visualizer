/*
 * subnetHL.h
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

#ifndef T2_SUBNETHL_H_INCLUDED
#define T2_SUBNETHL_H_INCLUDED

#include <stdint.h>         // for uint8_t, uint32_t

#include "networkHeaders.h" // for ipAddr_t, IPV6_ACTIVATE


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define SUBRNG       0 // IP range definition: 0: CIDR only, 1: Begin-End
#define CNTYCTY      0 // 1: add county, city
#define WHOADDR      0 // 1: add whois address info
#define SUB_MAP      1 // 1: mmap subnet, 0: normal read

#define CNTYLEN     14 // length of County record
#define CTYLEN      14 // length of City record
#define WHOLEN      30 // length of Organization record
#define ADDRLEN     30 // length of Address record

/* +++++++++++++++++++++ ENV / RUNTIME - conf Variables +++++++++++++++++++++ */

#define SUBNET_UNK "-" // Representation of unknown locations

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// subnet defines
#define SUBVER 5 // Version of the subnet file

#define VERMSK 0x7fff           // Version mask
#define SMLINE (1024 + CNTYLEN + CTYLEN + WHOLEN)  // line length of subnetfile

#define MASK64 0xffffffffffffffffL

#define SINGLE4 0x20 // Range mode /32 bit IPv4 marker
#define SINGLE6 0x80 // Range mode /128 bit IPv6 marker

#define SUBNET_POS_UNKNOWN 666.0f
#define SUBNET_POS_IS_UNKNOWN(lat, lng) ((lat) == SUBNET_POS_UNKNOWN && (lng) == SUBNET_POS_UNKNOWN)

// Macros to facilitate access to fields in subnets table

#define SUBNET_VER(table) ((table)->ver & VERMSK)
#define SUBNET_RNG(table) ((table)->ver >> 31)
#define SUBNET_REV(table) ((table)->rev)
#define SUBNET_CNT(table) ((table)->count >> 1)

#define SUBNET_TEST_IP4(dest, ip) \
    if (IPV6_ACTIVATE != 1) { \
        dest = subnet_testHL4((subnettable4_t*)subnetTableP[0], (ip).IPv4.s_addr); \
    } else { \
        dest = 0; \
    }

#define SUBNET_TEST_IP6(dest, ip) \
    if (IPV6_ACTIVATE > 0) { \
        dest = subnet_testHL6((subnettable6_t*)subnetTableP[1], ip); \
    } else { \
        dest = 0; \
    }

#define SUBNET_TEST_IP(dest, ip, ipver) \
    if ((ipver) == 6) { \
        SUBNET_TEST_IP6(dest, ip); \
    } else if ((ipver) == 4) { \
        SUBNET_TEST_IP4(dest, ip); \
    } else { \
        dest = 0; \
    }

#define SUBNET_WRAPPER(dest, ipver, num, field, not_found) \
    if (IPV6_ACTIVATE > 0 && (ipver) == 6) { \
        dest = ((subnettable6_t*)subnetTableP[1])->subnets[num].field; \
    } else if (IPV6_ACTIVATE != 1 && (ipver) == 4) { \
        dest = ((subnettable4_t*)subnetTableP[0])->subnets[num].field; \
    } else { \
        dest = (not_found); \
    }

#define SUBNET_ASN(  dest, ipver, num) SUBNET_WRAPPER(dest, ipver, num, asn  , 0)
#define SUBNET_CNTY( dest, ipver, num) SUBNET_WRAPPER(dest, ipver, num, cnty , SUBNET_UNK)
#define SUBNET_CTY(  dest, ipver, num) SUBNET_WRAPPER(dest, ipver, num, cty  , SUBNET_UNK)
#define SUBNET_NETID(dest, ipver, num) SUBNET_WRAPPER(dest, ipver, num, netID, 0)
#define SUBNET_LAT(  dest, ipver, num) SUBNET_WRAPPER(dest, ipver, num, lat  , 0.0f)
#define SUBNET_LNG(  dest, ipver, num) SUBNET_WRAPPER(dest, ipver, num, lng  , 0.0f)
#define SUBNET_LOC(  dest, ipver, num) SUBNET_WRAPPER(dest, ipver, num, loc  , SUBNET_UNK)
#define SUBNET_PREC( dest, ipver, num) SUBNET_WRAPPER(dest, ipver, num, oP   , 0.0f)
#define SUBNET_ORG(  dest, ipver, num) SUBNET_WRAPPER(dest, ipver, num, org  , SUBNET_UNK)

// Same macros but specific to IPv4/IPv6 (no version required)

#define SUBNET4_ASN(  dest, num) SUBNET_ASN(  dest, 4, num)
#define SUBNET4_CNTY( dest, num) SUBNET_CNTY( dest, 4, num)
#define SUBNET4_CTY(  dest, num) SUBNET_CTY(  dest, 4, num)
#define SUBNET4_NETID(dest, num) SUBNET_NETID(dest, 4, num)
#define SUBNET4_LAT(  dest, num) SUBNET_LAT(  dest, 4, num)
#define SUBNET4_LNG(  dest, num) SUBNET_LNG(  dest, 4, num)
#define SUBNET4_LOC(  dest, num) SUBNET_LOC(  dest, 4, num)
#define SUBNET4_PREC( dest, num) SUBNET_PREC( dest, 4, num)
#define SUBNET4_ORG(  dest, num) SUBNET_ORG(  dest, 4, num)

#define SUBNET6_ASN(  dest, num) SUBNET_ASN(  dest, 6, num)
#define SUBNET6_CNTY( dest, num) SUBNET_CNTY( dest, 6, num)
#define SUBNET6_CTY(  dest, num) SUBNET_CTY(  dest, 6, num)
#define SUBNET6_NETID(dest, num) SUBNET_NETID(dest, 6, num)
#define SUBNET6_LAT(  dest, num) SUBNET_LAT(  dest, 6, num)
#define SUBNET6_LNG(  dest, num) SUBNET_LNG(  dest, 6, num)
#define SUBNET6_LOC(  dest, num) SUBNET_LOC(  dest, 6, num)
#define SUBNET6_PREC( dest, num) SUBNET_PREC( dest, 6, num)
#define SUBNET6_ORG(  dest, num) SUBNET_ORG(  dest, 6, num)


// Structs

typedef struct {
    uint32_t net; // in Host Order !
    uint32_t netVec;
    uint32_t netID;
#if SUBRNG == 0
    uint32_t mask;
#endif
    uint32_t asn;
    float lat, lng, oP;
    char loc[4];
#if CNTYCTY == 1
    char cnty[CNTYLEN+1];
    char cty[CTYLEN+1];
#endif // CNTYCTY == 1
    char org[WHOLEN+1];
#if WHOADDR == 1
    char addr[ADDRLEN+1];
#endif // WHOADDR == 1
#if SUBRNG == 1
    uint8_t beF;
#endif
} subnet4_t;

typedef struct {
    ipAddr_t net; // in Host Order !
#if SUBRNG == 0
    ipAddr_t mask;
#endif
    uint32_t netVec;
    uint32_t netID;
    uint32_t asn;
    float lat, lng, oP;
    char loc[4];
#if CNTYCTY == 1
    char cnty[CNTYLEN+1];
    char cty[CTYLEN+1];
#endif // CNTYCTY == 1
    char org[WHOLEN+1];
#if WHOADDR == 1
    char addr[ADDRLEN+1];
#endif // WHOADDR == 1
#if SUBRNG == 1
    uint8_t beF;
#endif
} subnet6_t;

#endif // T2_SUBNETHL_H_INCLUDED
