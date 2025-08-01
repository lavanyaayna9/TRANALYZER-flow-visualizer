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

/*
 * This product includes GeoLite/GeoLite2 data created by MaxMind,
 *     available from http://www.maxmind.com
 */

#ifndef __T2MMDB_H__
#define __T2MMDB_H__

// local includes
#include "geoip.h"
#include "t2utils.h"


#if GEOIP_LIB != 1 && GEOIP_LIB != 2
#error "Unsupported configuration in geoip: set GEOIP_LIB to 1 or 2"
#endif


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define T2MMDB_SUBNET     1 // 0: IP results,
                            // 1: Create IP range T2 subnet format

#define T2MMDB_CONTINENT  1 // 0: no continent,
                            // 1: name (GeoLite2),
                            // 2: two letters code
#define T2MMDB_COUNTRY    2 // 0: no country,
                            // 1: name,
                            // 2: two letters code,
                            // 3: three letters code (Legacy)
#define T2MMDB_CITY       1 // Display the city of the IP
#define T2MMDB_POSTCODE   1 // Display the postal code of the IP
#define T2MMDB_POSITION   1 // Display the position (latitude, longitude) of the IP
#define T2MMDB_METRO_CODE 1 // Display the metro (dma) code of the IP (US only)

#define T2MMDB_ACCURACY   1 // Display the accuracy (GeoLite2)
#define T2MMDB_TIMEZONE   1 // Display the time zone (GeoLite2)

// GeoLite2 Enterprise databases only
#define T2MMDB_ORG        1 // Display the organization
#define T2MMDB_ISP        1 // Display the ISP name
#define T2MMDB_DOMAIN     1 // Display the domain name
#define T2MMDB_ASNAME     1 // Display the autonomous systems name
#define T2MMDB_USRT       1 // Display the user type
// End GeoLite2 Enterprise

#define T2MMDB_LANG       "en" // Output language: en, de, fr, es, ja, pt-BR, ru, zh-CN, ...
#define T2MMDB_BUFSIZE    64   // buffer size

#define T2MMDB_UNKNOWN    "-" // Representation of unknown locations (GeoIP's default)

// DB to be loaded
#define T2MMDB_DB_FILE    "GeoLite2-City.mmdb"

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


#define MASK32 0xffffffff
#define MASK64 0xffffffffffffffffL

// T2 Subnet mode
#if T2MMDB_SUBNET == 1
#undef  T2MMDB_CONTINENT
#define T2MMDB_CONTINENT 0
#undef  T2MMDB_POSTCODE
#define T2MMDB_POSTCODE 0
#undef  T2MMDB_METRO_CODE
#define T2MMDB_METRO_CODE 0
#undef  T2MMDB_DOMAIN
#define T2MMDB_DOMAIN 0
#undef  T2MMDB_TIMEZONE
#define T2MMDB_TIMEZONE 0
#endif // T2MMDB_SUBNET == 1

#endif // __T2MMDB_H__
