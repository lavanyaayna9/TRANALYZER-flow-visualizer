/*
 * geoip.h
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
 * This product includes GeoLite/GeoLite2 data created by MaxMind,
 *     available from http://www.maxmind.com
 */

#ifndef __GEOIP_H__
#define __GEOIP_H__

#include "t2Plugin.h"


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define GEOIP_LIB           2 // Library to use:
                              //   0: GeoLite  / geoip (legacy)
                              //   1: GeoLite2 / libmaxmind
                              //   2: GeoLite2 / Internal libmaxmind (faster)

#define GEOIP_SRC           1 // Display geo info for the source IP
#define GEOIP_DST           1 // Display geo info for the destination IP

#define GEOIP_CONTINENT     2 // 0: no continent,
                              // 1: name (GeoLite2),
                              // 2: two letters code
#define GEOIP_COUNTRY       2 // 0: no country,
                              // 1: name,
                              // 2: two letters code,
                              // 3: three letters code (Legacy)
#define GEOIP_CITY          1 // Display the city of the IP
#define GEOIP_POSTCODE      1 // Display the postal code of the IP
#define GEOIP_POSITION      1 // Display the position (latitude, longitude) of the IP
#define GEOIP_METRO_CODE    0 // Display the metro (dma) code of the IP (US only)

#if GEOIP_LIB != 0
#define GEOIP_ACCURACY      1 // Display the accuracy (GeoLite2)
#define GEOIP_TIMEZONE      1 // Display the time zone (GeoLite2)

// GeoLite2 Enterprise databases only
#define GEOIP_ORG           0 // Display the organization
#define GEOIP_ISP           0 // Display the ISP name
#define GEOIP_ASN           0 // Display the autonomous systems number
#define GEOIP_ASNAME        0 // Display the autonomous systems name
#define GEOIP_CONNT         0 // Display the connection type
#define GEOIP_USRT          0 // Display the user type
// End GeoLite2 Enterprise

#define GEOIP_LANG       "en" // Output language: en, de, fr, es, ja, pt-BR, ru, zh-CN, ...
#define GEOIP_BUFSIZE      64 // Buffer size
#else // GEOIP_LIB == 0
#define GEOIP_REGION        1 // 0: no region,
                              // 1: name,
                              // 2: code
#define GEOIP_AREA_CODE     0 // Display the telephone area code of the IP
#define GEOIP_NETMASK       1 // 0: no netmask,
                              // 1: netmask as int (cidr),
                              // 2: netmask as hex (IPv4 only),
                              // 3: netmask as IP (IPv4 only)

#define GEOIP_DB_CACHE      2 // 0: read DB from file system (slower, least memory)
                              // 1: index cache (cache frequently used index only)
                              // 2: memory cache (faster, more memory)
#endif // GEOIP_LIB == 0

/* +++++++++++++++++++++ ENV / RUNTIME - conf Variables +++++++++++++++++++++ */

#define GEOIP_UNKNOWN    "--" // Representation of unknown locations (GeoIP's default)

// Name of the database(s) to use
#define GEOIP_DB_FILE  "GeoLite2-City.mmdb" // Combined IPv4 and IPv6 database (require GEOIP_LIB > 0)
#define GEOIP_DB_FILE4 "GeoLiteCity.dat"    // IPv4 database (require GEOIP_LIB == 0)
#define GEOIP_DB_FILE6 "GeoLiteCityv6.dat"  // IPv6 database (require GEOIP_LIB == 0)

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// Environment var vector
// The elements in the enum below MUST be in the same order as above
enum {
    ENV_GEOIP_UNKNOWN,
    ENV_GEOIP_DB_FILE,
    ENV_GEOIP_DB_FILE4,
    ENV_GEOIP_DB_FILE6,
    ENV_GEOIP_N
};


// plugin defines

// geoStat status variable
#define GEOIP_STAT_TRUNC    0x01 // name was truncated... increase GEOIP_BUFSIZE
#define GEOIP_STAT_SRC_FAIL 0x02 // Source IP lookup failed
#define GEOIP_STAT_DST_FAIL 0x04 // Destination IP lookup failed

// Silence -Wundef warnings
#if GEOIP_LIB != 0
#define GEOIP_REGION    0
#define GEOIP_AREA_CODE 0
#define GEOIP_NETMASK   0
#else // GEOIP_LIB == 0
#define GEOIP_ACCURACY  0
#define GEOIP_TIMEZONE  0
#define GEOIP_ORG       0
#define GEOIP_ISP       0
#define GEOIP_ASN       0
#define GEOIP_ASNAME    0
#define GEOIP_CONNT     0
#define GEOIP_USRT      0
#endif // GEOIP_LIB == 0

// Country type
#if GEOIP_COUNTRY == 1
#define GEOIP_COUNTRY_TYPE bt_string
#elif (GEOIP_COUNTRY == 2 || GEOIP_COUNTRY == 3)
#define GEOIP_COUNTRY_TYPE bt_string_class
#endif // (GEOIP_COUNTRY == 2 || GEOIP_COUNTRY == 3)

// Region type
#if GEOIP_REGION == 1
#define GEOIP_REGION_TYPE bt_string
#elif GEOIP_REGION == 2
#define GEOIP_REGION_TYPE bt_string_class
#endif // GEOIP_REGION == 2

// Continent type
#if GEOIP_CONTINENT == 1
#define GEOIP_CONTINENT_TYPE bt_string
#elif GEOIP_CONTINENT == 2
#define GEOIP_CONTINENT_TYPE bt_string_class
#endif // GEOIP_CONTINENT == 2

// Position and metro code type
#if GEOIP_LIB != 0
#define GEOIP_POS_TYPE bt_double
#define GEOIP_DMA_TYPE bt_uint_16
#else // GEOIP_LIB == 0
#define GEOIP_POS_TYPE bt_float
#define GEOIP_DMA_TYPE bt_int_32
#endif // GEOIP_LIB == 0

#if GEOIP_LIB == 0

// TODO For now, netmask for IPv6 can only be represented as int
#if IPV6_ACTIVATE > 0 && GEOIP_NETMASK > 1
#error "Netmask for IPv6 can only be represented as int (GEOIP_NETMASK=1)"
#endif // IPV6_ACTIVATE > 0 && GEOIP_NETMASK > 0

// Netmask type
#if GEOIP_NETMASK == 1
#define GEOIP_NETMASK_TYPE bt_uint_32
#elif GEOIP_NETMASK == 2
#define GEOIP_NETMASK_TYPE bt_hex_32
#elif GEOIP_NETMASK == 3
#define GEOIP_NETMASK_TYPE bt_ip4_addr
#endif // GEOIP_NETMASK == 3

#define GEOIP_CIDR_TO_HEX(m) ((0xffffffff >> (32 - (m))) << (32 - (m)))
#define GEOIP_CIDR_TO_IP(m) ntohl(GEOIP_CIDR_TO_HEX((m)))

// DB cache
#if GEOIP_DB_CACHE == 0
#define GEOIP_DB_CACHE_FLAG GEOIP_STANDARD
#elif GEOIP_DB_CACHE == 1
#define GEOIP_DB_CACHE_FLAG GEOIP_INDEX_CACHE
#else // GEOIP_DB_CACHE == 2
#define GEOIP_DB_CACHE_FLAG GEOIP_MEMORY_CACHE
#endif // GEOIP_DB_CACHE == 2
#endif // GEOIP_LIB == 0

#endif // __GEOIP_H__
