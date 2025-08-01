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

#include "geoip.h"

#include <arpa/inet.h>  // for inet_ntop

#if GEOIP_LIB == 0
#include <GeoIPCity.h>
#elif GEOIP_LIB == 1
#include <maxminddb.h>
#else // GEOIP_LIB == 2
#include "MMDB/maxminddb.h"
#endif // GEOIP_LIB == 2


// Static variables
#if BLOCK_BUF == 0 && ( \
    GEOIP_LIB > 0 || \
    (GEOIP_LIB == 0 && (GEOIP_CONTINENT > 0 || GEOIP_COUNTRY > 0 || GEOIP_REGION > 0 || GEOIP_CITY == 1 || GEOIP_POSTCODE == 1)))
#define GEOIP_NEED_UNK
#endif

#ifdef GEOIP_NEED_UNK
#if ENVCNTRL > 0
static const char *geoip_unk;
#else // ENVCNTRL == 0
static const char * const geoip_unk = GEOIP_UNKNOWN;
#endif // ENVCNTRL
#endif // GEOIP_NEED_UNK

#if GEOIP_LIB == 0
#if (GEOIP_SRC > 0 || GEOIP_DST > 0)
static GeoIP *geoip_db;
#if IPV6_ACTIVATE > 0
static GeoIP *geoip_db6;
#endif // IPV6_ACTIVATE > 0
#endif // (GEOIP_SRC > 0 || GEOIP_DST > 0)
#else // GEOIP_LIB != 0
#if (GEOIP_SRC > 0 || GEOIP_DST > 0)
static MMDB_s geoip_db;
#endif // (GEOIP_SRC > 0 || GEOIP_DST > 0)

#if BLOCK_BUF == 0
static const uint8_t geoip_type[] = {
#if GEOIP_CONTINENT > 0
    MMDB_DATA_TYPE_UTF8_STRING, // srcIpContinent, dstIpContinent
#endif // GEOIP_CONTINENT > 0
#if GEOIP_COUNTRY > 0
    MMDB_DATA_TYPE_UTF8_STRING, // srcIpCountry, dstIpCountry
#endif // GEOIP_COUNTRY > 0
#if GEOIP_CITY == 1
    MMDB_DATA_TYPE_UTF8_STRING, // srcIpCity, dstIpCity
#endif // GEOIP_CITY == 1
#if GEOIP_POSTCODE == 1
    MMDB_DATA_TYPE_UTF8_STRING, // srcIpPostcode, dstIpPostcode
#endif // GEOIP_POSTCODE == 1
#if GEOIP_ACCURACY == 1
    MMDB_DATA_TYPE_UINT16,      // srcIpAccuracy, dstIpAccuracy
#endif // GEOIP_ACCURACY == 1
#if GEOIP_POSITION == 1
    MMDB_DATA_TYPE_DOUBLE,      // srcIpLat, dstIpLat
    MMDB_DATA_TYPE_DOUBLE,      // srcIpLong, dstIpLong
#endif // GEOIP_POSITION == 1
#if GEOIP_METRO_CODE == 1
    MMDB_DATA_TYPE_UINT16,      // srcIpMetroCode, dstIpMetroCode
#endif // GEOIP_METRO_CODE == 1
#if GEOIP_TIMEZONE == 1
    MMDB_DATA_TYPE_UTF8_STRING, // srcIpTimeZone, dstIpTimeZone
#endif // GEOIP_TIMEZONE == 1
#if GEOIP_ORG == 1
    MMDB_DATA_TYPE_UTF8_STRING, // srcIpOrg, dstIpOrg
#endif // GEOIP_ORG == 1
#if GEOIP_ISP == 1
    MMDB_DATA_TYPE_UTF8_STRING, // srcIpISP, dstIpISP
#endif // GEOIP_ISP == 1
#if GEOIP_ASN == 1
    MMDB_DATA_TYPE_UINT32,      // srcIpASN, dstIpASN
#endif // GEOIP_ASN == 1
#if GEOIP_ASNAME == 1
    MMDB_DATA_TYPE_UTF8_STRING, // srcIpASName, dstIpASName
#endif // GEOIP_ASNAME == 1
#if GEOIP_CONNT == 1
    MMDB_DATA_TYPE_UTF8_STRING, // srcIpConnT, dstIpConnT
#endif // GEOIP_CONNT == 1
#if GEOIP_USRT == 1
    MMDB_DATA_TYPE_UTF8_STRING, // srcIpUsrT, dstIpUsrT
#endif // GEOIP_USRT == 1
    UINT8_MAX                   // silence -Warray-bounds warnings when no field is being output...
};

static const char *geoip_path[][4] = {
    // srcIpContinent, dstIpContinent
#if GEOIP_CONTINENT == 1
    { "continent", "names", GEOIP_LANG, NULL },
#elif GEOIP_CONTINENT == 2
    { "continent", "code", NULL, NULL },
#endif // GEOIP_CONTINENT == 2
    // srcIpCountry, dstIpCountry
#if GEOIP_COUNTRY == 1
    { "country", "names", GEOIP_LANG, NULL },
#elif GEOIP_COUNTRY == 2
    { "country", "iso_code", NULL, NULL },
#endif // GEOIP_COUNTRY == 2
#if GEOIP_CITY == 1
    { "city", "names", GEOIP_LANG, NULL },                      // srcIpCity, dstIpCity
#endif // GEOIP_CITY == 1
#if GEOIP_POSTCODE == 1
    { "postal", "code", NULL, NULL },                           // srcIpPostcode, dstIpPostcode
#endif // GEOIP_POSTCODE == 1
#if GEOIP_ACCURACY == 1
    { "location", "accuracy_radius", NULL, NULL },              // srcIpAccuracy, dstIpAccuracy
#endif // GEOIP_ACCURACY == 1
#if GEOIP_POSITION == 1
    { "location", "latitude", NULL, NULL },                     // srcIpLat, dstIpLat
    { "location", "longitude", NULL, NULL },                    // srcIpLong, dstIpLong
#endif // GEOIP_POSITION == 1
#if GEOIP_METRO_CODE == 1
    { "location", "metro_code", NULL, NULL },                   // srcIpMetroCode, dstIpMetroCode
#endif // GEOIP_METRO_CODE == 1
#if GEOIP_TIMEZONE == 1
    { "location", "time_zone", NULL, NULL },                    // srcIpTimeZone, dstIpTimeZone
#endif // GEOIP_TIMEZONE == 1
#if GEOIP_ORG == 1
    { "traits", "organization", NULL, NULL },                   // srcIpOrg, dstIpOrg
#endif // GEOIP_ORG == 1
#if GEOIP_ISP == 1
    { "traits", "isp", NULL, NULL },                            // srcIpISP, dstIpISP
#endif // GEOIP_ISP == 1
#if GEOIP_ASN == 1
    { "traits", "autonomous_system_number", NULL, NULL },       // srcIpASN, dstIpASN
#endif // GEOIP_ASN == 1
#if GEOIP_ASNAME == 1
    { "traits", "autonomous_system_organization", NULL, NULL }, // srcIpASName, dstIpASName
#endif // GEOIP_ASNAME == 1
#if GEOIP_CONNT == 1
    { "traits", "connection_type", NULL, NULL },                // srcIpConnT, dstIpConnT
#endif // GEOIP_CONNT == 1
#if GEOIP_USRT == 1
    { "traits", "user_type", NULL, NULL },                      // srcIpUsrT, dstIpUsrT
#endif // GEOIP_USRT == 1
    { NULL, NULL, NULL, NULL }
};
#endif // BLOCK_BUF == 0

#endif // GEOIP_LIB != 0


// Tranalyzer functions

T2_PLUGIN_INIT("geoip", "0.9.3", 0, 9);


void t2Init() {
#if (GEOIP_SRC > 0 || GEOIP_DST > 0)
    t2_env_t env[ENV_GEOIP_N] = {};

#if ENVCNTRL > 0
    t2_get_env(PLUGIN_SRCH, ENV_GEOIP_N, env);
#ifdef GEOIP_NEED_UNK
    geoip_unk = T2_STEAL_ENV_VAL(GEOIP_UNKNOWN);
#endif // GEOIP_NEED_UNK
#else // ENVCNTRL == 0
    T2_SET_ENV_STR(GEOIP_DB_FILE);
    T2_SET_ENV_STR(GEOIP_DB_FILE4);
    T2_SET_ENV_STR(GEOIP_DB_FILE6);
#endif // ENVCNTRL

    char dbname[MAX_FILENAME_LEN] = {};

#if GEOIP_LIB != 0
    t2_build_filename(dbname, sizeof(dbname), pluginFolder, T2_ENV_VAL(GEOIP_DB_FILE), NULL);
    if (UNLIKELY(MMDB_open(dbname, MMDB_MODE_MMAP, &geoip_db) != MMDB_SUCCESS)) {
        T2_PFATAL(plugin_name, "failed to open GeoIP database '%s'", dbname);
    }
#else // GEOIP_LIB == 0

#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
    t2_build_filename(dbname, sizeof(dbname), pluginFolder, T2_ENV_VAL(GEOIP_DB_FILE4), NULL);
    geoip_db = GeoIP_open(dbname, GEOIP_DB_CACHE_FLAG);
    if (UNLIKELY(geoip_db == NULL)) {
        T2_PFATAL(plugin_name, "failed to open GeoIP database '%s'", dbname);
    }
    GeoIP_set_charset(geoip_db, GEOIP_CHARSET_UTF8);
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2

#if IPV6_ACTIVATE > 0
    t2_build_filename(dbname, sizeof(dbname), pluginFolder, T2_ENV_VAL(GEOIP_DB_FILE6), NULL);
    geoip_db6 = GeoIP_open(dbname, GEOIP_DB_CACHE_FLAG);
    if (UNLIKELY(geoip_db6 == NULL)) {
        T2_PFATAL(plugin_name, "failed to open GeoIP database '%s'", dbname);
    }
    GeoIP_set_charset(geoip_db6, GEOIP_CHARSET_UTF8);
#endif // IPV6_ACTIVATE > 0
#endif // GEOIP_LIB == 0

#if ENVCNTRL > 0
    t2_free_env(ENV_GEOIP_N, env);
#endif
#endif // (GEOIP_SRC > 0 || GEOIP_DST > 0)
}


binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;

#if GEOIP_SRC == 1
#if GEOIP_CONTINENT > 0
    BV_APPEND(bv, "srcIpContinent", "IP source continent", 1, GEOIP_CONTINENT_TYPE);
#endif // GEOIP_CONTINENT > 0
#if GEOIP_COUNTRY > 0
    BV_APPEND(bv, "srcIpCountry", "IP source country", 1, GEOIP_COUNTRY_TYPE);
#endif // GEOIP_COUNTRY > 0
#if GEOIP_REGION > 0
    BV_APPEND(bv, "srcIpRegion", "IP source region", 1, GEOIP_REGION_TYPE);
#endif // GEOIP_REGION > 0
#if GEOIP_CITY == 1
    BV_APPEND_STR(bv, "srcIpCity", "IP source city");
#endif // GEOIP_CITY == 1
#if GEOIP_POSTCODE == 1
    BV_APPEND_STRC(bv, "srcIpPostcode", "IP source postcode");
#endif // GEOIP_POSTCODE == 1
#if GEOIP_ACCURACY == 1
    BV_APPEND_U16(bv, "srcIpAccuracy", "IP source accuracy");
#endif // GEOIP_ACCURACY == 1
#if GEOIP_POSITION == 1
    BV_APPEND(bv, "srcIpLat" , "IP source latitude" , 1, GEOIP_POS_TYPE);
    BV_APPEND(bv, "srcIpLong", "IP source longitude", 1, GEOIP_POS_TYPE);
#endif // GEOIP_POSITION == 1
#if GEOIP_METRO_CODE == 1
    BV_APPEND(bv, "srcIpMetroCode", "IP source metro (dma) code", 1, GEOIP_DMA_TYPE);
#endif // GEOIP_METRO_CODE == 1
#if GEOIP_AREA_CODE == 1
    BV_APPEND_I32(bv, "srcIpAreaCode", "IP source area code");
#endif // GEOIP_AREA_CODE == 1
#if GEOIP_NETMASK > 0
    BV_APPEND(bv, "srcIpNetmask", "IP source netmask", 1, GEOIP_NETMASK_TYPE);
#endif // GEOIP_NETMASK > 0
#if GEOIP_TIMEZONE == 1
    BV_APPEND_STR(bv, "srcIpTimeZone", "IP source time zone");
#endif // GEOIP_TIMEZONE == 1
#if GEOIP_ORG == 1
    BV_APPEND_STR(bv, "srcIpOrg", "IP source organization");
#endif // GEOIP_ORG == 1
#if GEOIP_ISP == 1
    BV_APPEND_STR(bv, "srcIpISP", "IP source ISP");
#endif // GEOIP_ISP == 1
#if GEOIP_ASN == 1
    BV_APPEND_U32(bv, "srcIpASN", "IP source AS number");
#endif // GEOIP_ASN == 1
#if GEOIP_ASNAME == 1
    BV_APPEND_STR(bv, "srcIpASName", "IP source AS name");
#endif // GEOIP_ASNAME == 1
#if GEOIP_CONNT == 1
    BV_APPEND_STR(bv, "srcIpConnT", "IP source connection type");
#endif // GEOIP_CONNT == 1
#if GEOIP_USRT == 1
    BV_APPEND_STR(bv, "srcIpUsrT", "IP source user type");
#endif // GEOIP_USRT == 1
#endif // GEOIP_SRC == 1

#if GEOIP_DST == 1
#if GEOIP_CONTINENT > 0
    BV_APPEND(bv, "dstIpContinent", "IP destination continent", 1, GEOIP_CONTINENT_TYPE);
#endif // GEOIP_CONTINENT > 0
#if GEOIP_COUNTRY > 0
    BV_APPEND(bv, "dstIpCountry", "IP destination country", 1, GEOIP_COUNTRY_TYPE);
#endif // GEOIP_COUNTRY > 0
#if GEOIP_REGION > 0
    BV_APPEND(bv, "dstIpRegion", "IP destination region", 1, GEOIP_REGION_TYPE);
#endif // GEOIP_REGION > 0
#if GEOIP_CITY == 1
    BV_APPEND_STR(bv, "dstIpCity", "IP destination city");
#endif // GEOIP_CITY == 1
#if GEOIP_POSTCODE == 1
    BV_APPEND_STRC(bv, "dstIpPostcode", "IP destination postcode");
#endif // GEOIP_POSTCODE == 1
#if GEOIP_ACCURACY == 1
    BV_APPEND_U16(bv, "dstIpAccuracy", "IP destination accuracy");
#endif // GEOIP_ACCURACY == 1
#if GEOIP_POSITION == 1
    BV_APPEND(bv, "dstIpLat" , "IP destination latitude" , 1, GEOIP_POS_TYPE);
    BV_APPEND(bv, "dstIpLong", "IP destination longitude", 1, GEOIP_POS_TYPE);
#endif // GEOIP_POSITION == 1
#if GEOIP_METRO_CODE == 1
    BV_APPEND(bv, "dstIpMetroCode", "IP destination metro (dma) code", 1, GEOIP_DMA_TYPE);
#endif // GEOIP_METRO_CODE == 1
#if GEOIP_AREA_CODE == 1
    BV_APPEND_I32(bv, "dstIpAreaCode", "IP destination area code");
#endif // GEOIP_AREA_CODE == 1
#if GEOIP_NETMASK > 0
    BV_APPEND(bv, "dstIpNetmask", "IP destination netmask", 1, GEOIP_NETMASK_TYPE);
#endif // GEOIP_NETMASK > 0
#if GEOIP_TIMEZONE == 1
    BV_APPEND_STR(bv, "dstIpTimeZone", "IP destination time zone");
#endif // GEOIP_TIMEZONE == 1
#if GEOIP_ORG == 1
    BV_APPEND_STR(bv, "dstIpOrg", "IP destination organization");
#endif // GEOIP_ORG == 1
#if GEOIP_ISP == 1
    BV_APPEND_STR(bv, "dstIpISP", "IP destination ISP");
#endif // GEOIP_ISP == 1
#if GEOIP_ASN == 1
    BV_APPEND_U32(bv, "dstIpASN", "IP destination AS number");
#endif // GEOIP_ASN == 1
#if GEOIP_ASNAME == 1
    BV_APPEND_STR(bv, "dstIpASName", "IP destination AS name");
#endif // GEOIP_ASNAME == 1
#if GEOIP_CONNT == 1
    BV_APPEND_STR(bv, "dstIpConnT", "IP destination connection type");
#endif // GEOIP_CONNT == 1
#if GEOIP_USRT == 1
    BV_APPEND_STR(bv, "dstIpUsrT", "IP destination user type");
#endif // GEOIP_USRT == 1
#endif // GEOIP_DST == 1

    BV_APPEND_H8(bv, "geoStat", "GeoIP status");

    return bv;
}


#if BLOCK_BUF == 0
void t2OnFlowTerminate(unsigned long flowIndex
#if GEOIP_SRC == 0 && GEOIP_DST == 0
        UNUSED
#endif
        , outputBuffer_t *buf
) {
#if (GEOIP_SRC == 1 || GEOIP_DST == 1 || (GEOIP_LIB == 0 && GEOIP_NETMASK > 0 && (IPV6_ACTIVATE == 2 || ETH_ACTIVATE > 0)))
    const flow_t * const flowP = &flows[flowIndex];
#endif

    uint8_t status = 0;

#if GEOIP_LIB != 0
#if GEOIP_LIB == 1
    int iperr, dberr;
    MMDB_lookup_result_s res[GEOIP_SRC+GEOIP_DST];
#else // GEOIP_LIB == 2
    int dberr;
    MMDB_lookup_result_s res[GEOIP_SRC+GEOIP_DST] = {
#if GEOIP_SRC == 1
       { .found_entry = false, .netmask = 0, .entry = { .mmdb = &geoip_db, .offset = 0 } },
#endif // GEOIP_SRC == 1
#if GEOIP_DST == 1
       { .found_entry = false, .netmask = 0, .entry = { .mmdb = &geoip_db, .offset = 0 } }
#endif // GEOIP_DST == 1
    };
#endif // GEOIP_LIB == 2

    uint8_t r = 0;

#if GEOIP_SRC == 1
    char srcIP[INET6_ADDRSTRLEN];
    if (FLOW_IS_IPV6(flowP)) {
#if GEOIP_LIB == 1
        inet_ntop(AF_INET6, &flowP->srcIP, srcIP, INET6_ADDRSTRLEN);
        res[r++] = MMDB_lookup_string(&geoip_db, srcIP, &iperr, &dberr);
#else // GEOIP_LIB == 2
        dberr = MMDB_find_address_in_search_tree(&geoip_db, (uint8_t*)&flowP->srcIP, AF_INET6, &res[r++]);
#endif // GEOIP_LIB == 2
    } else { // IPv4
#if GEOIP_LIB == 1
        inet_ntop(AF_INET, &flowP->srcIP.IPv4, srcIP, INET_ADDRSTRLEN);
        res[r++] = MMDB_lookup_string(&geoip_db, srcIP, &iperr, &dberr);
#else // GEOIP_LIB == 2
        ipAddr_t sIP = { .IPv4x[3] = flowP->srcIP.IPv4x[0] };
        dberr = MMDB_find_address_in_search_tree(&geoip_db, (uint8_t*)&sIP, AF_INET, &res[r++]);
#endif // GEOIP_LIB == 2
    }
#if GEOIP_LIB == 1
    if (iperr != 0 || dberr != MMDB_SUCCESS) {
#else // GEOIP_LIB == 2
    if (dberr != MMDB_SUCCESS) {
        if (FLOW_IS_IPV6(flowP)) {
            inet_ntop(AF_INET6, &flowP->srcIP, srcIP, INET6_ADDRSTRLEN);
        } else { // IPv4
            inet_ntop(AF_INET, &flowP->srcIP.IPv4, srcIP, INET_ADDRSTRLEN);
        }
#endif // GEOIP_LIB == 2
        T2_PERR(plugin_name, "Failed to lookup IP address '%s' in database", srcIP);
        status |= GEOIP_STAT_SRC_FAIL;
    }
#endif // GEOIP_SRC == 1

#if GEOIP_DST == 1
    char dstIP[INET6_ADDRSTRLEN];
    if (FLOW_IS_IPV6(flowP)) {
#if GEOIP_LIB == 1
        inet_ntop(AF_INET6, &flowP->dstIP, dstIP, INET6_ADDRSTRLEN);
        res[r++] = MMDB_lookup_string(&geoip_db, dstIP, &iperr, &dberr);
#else // GEOIP_LIB == 2
        dberr = MMDB_find_address_in_search_tree(&geoip_db, (uint8_t*)&flowP->dstIP, AF_INET6, &res[r++]);
#endif // GEOIP_LIB == 2
    } else { // IPv4
#if GEOIP_LIB == 1
        inet_ntop(AF_INET, &flowP->dstIP.IPv4, dstIP, INET_ADDRSTRLEN);
        res[r++] = MMDB_lookup_string(&geoip_db, dstIP, &iperr, &dberr);
#else // GEOIP_LIB == 2
        ipAddr_t dIP = { .IPv4x[3] = flowP->dstIP.IPv4x[0] };
        dberr = MMDB_find_address_in_search_tree(&geoip_db, (uint8_t*)&dIP, AF_INET, &res[r++]);
#endif // GEOIP_LIB == 2
    }
#if GEOIP_LIB == 1
    if (iperr != 0 || dberr != MMDB_SUCCESS) {
#else // GEOIP_LIB == 2
    if (dberr != MMDB_SUCCESS) {
        if (FLOW_IS_IPV6(flowP)) {
            inet_ntop(AF_INET6, &flowP->dstIP, dstIP, INET6_ADDRSTRLEN);
        } else { // IPv4
            inet_ntop(AF_INET, &flowP->dstIP.IPv4, dstIP, INET_ADDRSTRLEN);
        }
#endif // GEOIP_LIB == 2
        T2_PERR(plugin_name, "Failed to lookup IP address '%s' in database", dstIP);
        status |= GEOIP_STAT_DST_FAIL;
    }
#endif // GEOIP_DST == 1

    for (uint_fast8_t j = 0; j < r; j++) { // for src/dst IP address
        if (res[j].found_entry) {
            for (uint_fast8_t i = 0; geoip_path[i][0]; i++) {
                MMDB_entry_data_s entry;
                MMDB_aget_value(&res[j].entry, &entry, geoip_path[i]);
                switch (geoip_type[i]) {
                    case MMDB_DATA_TYPE_UTF8_STRING:
                        if (entry.has_data) {
                            const uint32_t slen = MIN(entry.data_size, GEOIP_BUFSIZE);
                            if (slen < entry.data_size) status |= GEOIP_STAT_TRUNC;
                            char sbuf[GEOIP_BUFSIZE] = {};
                            memcpy(sbuf, entry.utf8_string, slen);
                            sbuf[slen] = '\0';
                            OUTBUF_APPEND_STR(buf, sbuf);
                        } else {
                            OUTBUF_APPEND_STR(buf, geoip_unk);
                        }
                        break;
                    case MMDB_DATA_TYPE_DOUBLE: {
                        const double d = ((entry.has_data) ? entry.double_value : 0.0);
                        OUTBUF_APPEND_DBL(buf, d);
                        break;
                    }
                    case MMDB_DATA_TYPE_UINT16: {
                        const uint16_t u16 = ((entry.has_data) ? entry.uint16 : 0);
                        OUTBUF_APPEND_U16(buf, u16);
                        break;
                    }
                    case MMDB_DATA_TYPE_UINT32: {
                        const uint32_t u32 = ((entry.has_data) ? entry.uint32 : 0);
                        OUTBUF_APPEND_U32(buf, u32);
                        break;
                    }
                    default:
                        T2_PWRN(plugin_name, "Unhandled type %d", entry.type);
                        break;
                }
            }
        } else { // entry not found
#if GEOIP_CONTINENT > 0
            OUTBUF_APPEND_STR(buf, geoip_unk); // continent
#endif // GEOIP_CONTINENT > 0
#if GEOIP_COUNTRY > 0
            OUTBUF_APPEND_STR(buf, geoip_unk); // country
#endif // GEOIP_COUNTRY > 0
#if GEOIP_CITY == 1
            OUTBUF_APPEND_STR(buf, geoip_unk); // city
#endif // GEOIP_CITY == 1
#if GEOIP_POSTCODE == 1
            OUTBUF_APPEND_STR(buf, geoip_unk); // postcode
#endif // GEOIP_POSTCODE == 1
#if GEOIP_POSITION == 1
            OUTBUF_APPEND_DBL_ZERO(buf);       // longitude
            OUTBUF_APPEND_DBL_ZERO(buf);       // latitude
#endif // GEOIP_POSITION == 1
#if GEOIP_METRO_CODE == 1
            OUTBUF_APPEND_U16_ZERO(buf);       // metro code
#endif // GEOIP_METRO_CODE == 1
#if GEOIP_TIMEZONE == 1
            OUTBUF_APPEND_STR(buf, geoip_unk); // time zone
#endif // GEOIP_TIMEZONE == 1
#if GEOIP_ORG == 1
            OUTBUF_APPEND_STR(buf, geoip_unk); // organization
#endif // GEOIP_ORG == 1
#if GEOIP_ISP == 1
            OUTBUF_APPEND_STR(buf, geoip_unk); // isp
#endif // GEOIP_ISP == 1
#if GEOIP_ASN == 1
            OUTBUF_APPEND_U32_ZERO(buf);       // AS number
#endif // GEOIP_ASN == 1
#if GEOIP_ASNAME == 1
            OUTBUF_APPEND_STR(buf, geoip_unk); // AS name
#endif // GEOIP_ASNAME == 1
#if GEOIP_CONNT == 1
            OUTBUF_APPEND_STR(buf, geoip_unk); // connection type
#endif // GEOIP_CONNT == 1
#if GEOIP_USRT == 1
            OUTBUF_APPEND_STR(buf, geoip_unk); // user type
#endif // GEOIP_USRT == 1
        }
    }

#else // GEOIP_LIB == 0

    uint8_t r = 0;
    GeoIPRecord *rec[GEOIP_SRC+GEOIP_DST] = {};
#if GEOIP_SRC == 1
    if (FLOW_IS_IPV6(flowP)) {
#if IPV6_ACTIVATE > 0
        rec[r++] = GeoIP_record_by_ipnum_v6(geoip_db6, flowP->srcIP.IPv6);
#endif // IPV6_ACTIVATE > 0
    } else { // IPv4
        const struct in_addr sip = flowP->srcIP.IPv4;
        rec[r++] = GeoIP_record_by_ipnum(geoip_db, ntohl(*(uint32_t*)&sip));
    }
    if (!rec[r-1]) status |= GEOIP_STAT_SRC_FAIL;
#endif // GEOIP_SRC == 1

#if GEOIP_DST == 1
    if (FLOW_IS_IPV6(flowP)) {
#if IPV6_ACTIVATE > 0
        rec[r++] = GeoIP_record_by_ipnum_v6(geoip_db6, flowP->dstIP.IPv6);
#endif // IPV6_ACTIVATE > 0
    } else { // IPv4
        const struct in_addr dip = flowP->dstIP.IPv4;
        rec[r++] = GeoIP_record_by_ipnum(geoip_db, ntohl(*(uint32_t*)&dip));
    }
    if (!rec[r-1]) status |= GEOIP_STAT_DST_FAIL;
#endif // GEOIP_DST == 1

#if (GEOIP_CONTINENT > 0 || GEOIP_COUNTRY > 0 || GEOIP_REGION > 0 || GEOIP_CITY > 0 || GEOIP_POSTCODE > 0)
    const char *str;
#endif

    for (uint_fast8_t j = 0; j < r; j++) {
#if GEOIP_CONTINENT > 0
        str = (rec[j] ? rec[j]->continent_code : geoip_unk);
        if (!str) str = geoip_unk;
        OUTBUF_APPEND_STR(buf, str);
#endif // GEOIP_CONTINENT > 0

#if GEOIP_COUNTRY > 0
#if GEOIP_COUNTRY == 1
        str = rec[j] ? rec[j]->country_name : geoip_unk;
#elif GEOIP_COUNTRY == 2
        str = rec[j] ? rec[j]->country_code : geoip_unk;
#elif GEOIP_COUNTRY == 3
        str = rec[j] ? rec[j]->country_code3 : geoip_unk;
#endif // GEOIP_COUNTRY == 3
        if (!str) str = geoip_unk;
        OUTBUF_APPEND_STR(buf, str);
#endif // GEOIP_COUNTRY > 0

#if GEOIP_REGION > 0
        if (rec[j]) {
#if GEOIP_REGION == 1
            str = GeoIP_region_name_by_code(rec[j]->country_code, rec[j]->region);
#else // GEOIP_REGION != 1
            str = rec[j]->region;
#endif // GEOIP_REGION != 1
        }
        if (!str) str = geoip_unk;
        OUTBUF_APPEND_STR(buf, str);
#endif // GEOIP_REGION > 0

#if GEOIP_CITY == 1
        str = rec[j] ? rec[j]->city : geoip_unk;
        if (!str) str = geoip_unk;
        OUTBUF_APPEND_STR(buf, str);
#endif // GEOIP_CITY == 1

#if GEOIP_POSTCODE == 1
        str = rec[j] ? rec[j]->postal_code : geoip_unk;
        if (!str) str = geoip_unk;
        OUTBUF_APPEND_STR(buf, str);
#endif // GEOIP_POSTCODE == 1

#if GEOIP_POSITION == 1
        const float lat = (rec[j] ? rec[j]->latitude  : 0.0);
        const float lng = (rec[j] ? rec[j]->longitude : 0.0);
        OUTBUF_APPEND_FLT(buf, lat);
        OUTBUF_APPEND_FLT(buf, lng);
#endif // GEOIP_POSITION == 1

#if GEOIP_METRO_CODE == 1
        const int32_t dma = (rec[j] ? rec[j]->metro_code : 0);
        OUTBUF_APPEND_I32(buf, dma);
#endif // GEOIP_METRO_CODE == 1

#if GEOIP_AREA_CODE == 1
        const int32_t area = (rec[j] ? rec[j]->area_code : 0);
        OUTBUF_APPEND_I32(buf, area);
#endif // GEOIP_AREA_CODE == 1

#if GEOIP_NETMASK > 0
        uint32_t mask = (uint32_t) (rec[j] ? rec[j]->netmask : 0);
        if (FLOW_IS_IPV6(flowP)) {
#if GEOIP_NETMASK == 2
            // TODO
#elif GEOIP_NETMASK == 3
            // TODO
#endif // GEOIP_NETMASK == 3
        } else { // IPv4
#if GEOIP_NETMASK == 2
            mask = GEOIP_CIDR_TO_HEX(mask);
#elif GEOIP_NETMASK == 3
            mask = GEOIP_CIDR_TO_IP(mask);
#endif // GEOIP_NETMASK == 3
        }
        OUTBUF_APPEND_U32(buf, mask);
#endif // GEOIP_NETMASK > 0

        if (rec[j]) {
            GeoIPRecord_delete(rec[j]);
            rec[j] = NULL;
        }
    }
#endif // GEOIP_LIB == 0

    OUTBUF_APPEND_U8(buf, status); // geoStat
}
#endif // BLOCK_BUF == 0


void t2Finalize() {
#if defined(GEOIP_NEED_UNK) && ENVCNTRL > 0
    free((char*)geoip_unk);
#endif // defined(GEOIP_NEED_UNK) && ENVCNTRL > 0

#if (GEOIP_SRC > 0 || GEOIP_DST > 0)
#if GEOIP_LIB != 0
    MMDB_close(&geoip_db);
#else // GEOIP_LIB == 0
#if IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
    if (LIKELY(geoip_db != NULL)) {
        GeoIP_delete(geoip_db);
    }
#endif // IPV6_ACTIVATE == 0 || IPV6_ACTIVATE == 2
#if IPV6_ACTIVATE > 0
    if (LIKELY(geoip_db6 != NULL)) {
        GeoIP_delete(geoip_db6);
    }
#endif // IPV6_ACTIVATE > 0
#endif // GEOIP_LIB == 0
#endif // (GEOIP_SRC > 0 || GEOIP_DST > 0)
}
