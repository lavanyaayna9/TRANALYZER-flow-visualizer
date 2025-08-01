/*
 * This product includes GeoLite/GeoLite2 data created by MaxMind,
 *     available from http://www.maxmind.com
 */

#include "t2mmdb.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef __APPLE__
#include "missing/missing.h"
#endif

#if GEOIP_LIB == 2
#include "../../../src/MMDB/maxminddb.h"
#elif GEOIP_LIB == 1
#include <maxminddb.h>
#endif


// Static variables

static MMDB_s mmdb;

static const uint8_t geoip_type[] = {
#if T2MMDB_METRO_CODE == 1
    MMDB_DATA_TYPE_UINT16,
#endif // T2MMDB_METRO_CODE == 1
#if T2MMDB_TIMEZONE == 1
    MMDB_DATA_TYPE_UTF8_STRING,
#endif // T2MMDB_TIMEZONE == 1
#if T2MMDB_CONTINENT > 0
    MMDB_DATA_TYPE_UTF8_STRING,
#endif // T2MMDB_CONTINENT > 0
#if T2MMDB_POSTCODE == 1
    MMDB_DATA_TYPE_UTF8_STRING,
#endif // T2MMDB_POSTCODE == 1
    MMDB_DATA_TYPE_UINT32,
#if T2MMDB_ACCURACY == 1
    MMDB_DATA_TYPE_UINT16,
#endif // T2MMDB_ACCURACY == 1
#if T2MMDB_POSITION == 1
    MMDB_DATA_TYPE_DOUBLE,
    MMDB_DATA_TYPE_DOUBLE,
#endif // T2MMDB_POSITION == 1
#if T2MMDB_COUNTRY > 0
    MMDB_DATA_TYPE_UTF8_STRING,
#endif // T2MMDB_COUNTRY > 0
#if T2MMDB_CITY == 1
    MMDB_DATA_TYPE_UTF8_STRING,
#endif // T2MMDB_CITY == 1
#if T2MMDB_ORG == 1
    MMDB_DATA_TYPE_UTF8_STRING,
#endif // T2MMDB_ORG == 1
#if T2MMDB_ISP == 1
    MMDB_DATA_TYPE_UTF8_STRING,
#endif // T2MMDB_ISP == 1
#if T2MMDB_ASNAME == 1
    MMDB_DATA_TYPE_UTF8_STRING,
#endif // T2MMDB_ASNAME == 1
#if T2MMDB_DOMAIN == 1
    MMDB_DATA_TYPE_UTF8_STRING,
#endif // T2MMDB_DOMAIN == 1
#if T2MMDB_USRT == 1
    MMDB_DATA_TYPE_UTF8_STRING,
#endif // T2MMDB_USRT == 1
};

static const char *geoip_path[][4] = {
#if T2MMDB_METRO_CODE == 1
    { "location", "metro_code", NULL, NULL },
#endif // T2MMDB_METRO_CODE == 1
#if T2MMDB_TIMEZONE == 1
    { "location", "time_zone", NULL, NULL },
#endif // T2MMDB_TIMEZONE == 1
#if T2MMDB_CONTINENT == 1
    { "continent", "names", T2MMDB_LANG, NULL },
#elif T2MMDB_CONTINENT == 2
    { "continent", "code", NULL, NULL },
#endif // T2MMDB_CONTINENT == 2
#if T2MMDB_POSTCODE == 1
    { "postal", "code", NULL, NULL },
#endif // T2MMDB_POSTCODE == 1
    { "traits", "autonomous_system_number", NULL, NULL },
#if T2MMDB_ACCURACY == 1
    { "location", "accuracy_radius", NULL, NULL },
#endif // T2MMDB_ACCURACY == 1
#if T2MMDB_POSITION == 1
    { "location", "latitude", NULL, NULL },
    { "location", "longitude", NULL, NULL },
#endif // T2MMDB_POSITION == 1
#if T2MMDB_COUNTRY == 1
    { "country", "names", T2MMDB_LANG, NULL },
#elif T2MMDB_COUNTRY == 2
    { "country", "iso_code", NULL, NULL },
#endif // T2MMDB_COUNTRY == 2
#if T2MMDB_CITY == 1
    { "city", "names", T2MMDB_LANG, NULL },
#endif // T2MMDB_CITY == 1
#if T2MMDB_ORG == 1
    { "traits", "organization", NULL, NULL },
#endif // T2MMDB_ORG == 1
#if T2MMDB_ISP == 1
    { "traits", "isp", NULL, NULL },
#endif // T2MMDB_ISP == 1
#if T2MMDB_ASNAME == 1
    { "traits", "autonomous_system_organization", NULL, NULL },
#endif // T2MMDB_ASNAME == 1
#if T2MMDB_DOMAIN == 1
    { "traits", "domain", NULL, NULL },
#endif // T2MMDB_DOMAIN == 1
#if T2MMDB_USRT == 1
    { "traits", "user_type", NULL, NULL },
#endif // T2MMDB_USRT == 1
    { NULL, NULL, NULL, NULL }
};

// Required to use t2utils.c
FILE *dooF;


static void usage() {
    printf("Usage:\n");
    printf("    t2mmdb [OPTION...] [INPUT...]\n");
    printf("\nInput:\n");
    printf("    -               If no input is provided, read from stdin\n");
    printf("    -i file         Read IP address(es) from 'file'\n");
    printf("\nOptional arguments:\n");
    printf("    -x              Do not display the header\n");
    printf("    -f file         Database to use (default: '%s' in the plugin folder)\n", T2MMDB_DB_FILE);
    printf("    -h              Show help options and exit\n");
}


static __attribute__((noreturn)) void abort_with_help() {
    printf("Try 't2mmdb -h' for more information.\n");
    exit(EXIT_FAILURE);
}


static inline bool process_ip(const char *line) {
    int dberr;

#if GEOIP_LIB == 1
    int iperr;
    MMDB_lookup_result_s res;
#elif GEOIP_LIB == 2
    MMDB_lookup_result_s res = {
        .found_entry = false,
        .netmask = 0,
        .entry = {
            .mmdb = &mmdb,
            .offset = 0
        }
    };
#endif

    MMDB_entry_data_s entry;

    ipAddr_t ip6;
    double d;
    uint32_t u32, slen, cidr;
    uint16_t u16;
    char buf[T2MMDB_BUFSIZE] = {};

#if T2MMDB_SUBNET == 1
    int sw;
    char netA[INET6_ADDRSTRLEN], netE[INET6_ADDRSTRLEN];
#endif // T2MMDB_SUBNET

    char *newline = strchr(line, '\n');
    if (newline) *newline = '\0';

    const char * const s4 = strchr(line, '.');
    const char * const s6 = strchr(line, ':');
    if (!(s4 || s6)) {
        T2_FWRN(stderr, "'%s' is not a valid IP address", line);
        return false;
    }

#if GEOIP_LIB == 1
    res = MMDB_lookup_string(&mmdb, line, &iperr, &dberr);
    if (iperr != 0 || dberr != MMDB_SUCCESS) {
#elif GEOIP_LIB == 2
    if (s6) {
        inet_pton(AF_INET6, line, &ip6);
        dberr = MMDB_find_address_in_search_tree(&mmdb, (uint8_t*)&ip6, AF_INET6, &res);
    } else {
        uint32_t ip;
        inet_pton(AF_INET, line, &ip);
        ip6.IPv6L[0] = 0; ip6.IPv4x[3] = ip; ip6.IPv4x[2] = 0;
        dberr = MMDB_find_address_in_search_tree(&mmdb, (uint8_t*)&ip6, AF_INET, &res);
    }

    if (dberr != MMDB_SUCCESS) {
#endif
        T2_FWRN(stderr, "Failed to lookup IP address '%s' in database", line);
        return false;
    }

    if (!res.found_entry) {
        T2_FWRN(stderr, "No entry found in database for IP address '%s'", line);
        return false;
    }

#if T2MMDB_SUBNET == 1
    if (s6) {
        cidr = res.netmask;
        inet_pton(AF_INET6, line, &ip6);

        uint64_t msk0, msk1;
        if (cidr > 64) {
            msk0 = MASK64;
            msk1 = htobe64(MASK64 << (128-cidr));
        } else {
            msk0 = htobe64(MASK64 << (64-cidr));
            msk1 = 0;
        }

        ip6.IPv6L[0] &= msk0;
        ip6.IPv6L[1] &= msk1;
        inet_ntop(AF_INET6, (char*)&ip6, netA, INET6_ADDRSTRLEN);

        ip6.IPv6L[0] |= ~msk0;
        ip6.IPv6L[1] |= ~msk1;
        inet_ntop(AF_INET6, (char*)&ip6, netE, INET6_ADDRSTRLEN);

        printf("%s/%" PRIu32 "\t%s-%s\t0x00000000\t", netA, cidr, netA, netE);
    } else {
        cidr = res.netmask - mmdb.ipv4_start_node.netmask;
        inet_pton(AF_INET, line, &u32);
        const uint32_t m = ntohl(MASK32 << (32-cidr));
        const uint32_t a = u32 & m;
        const uint32_t e = u32 | ~m;
        sprintf(netA, "%" PRIu32 ".%" PRIu32 ".%" PRIu32 ".%" PRIu32, a & 0x000000ff, (a & 0x0000ff00) >> 8, (a & 0x00ff0000) >> 16, (a & 0xff000000) >> 24);
        printf("%s/%" PRIu32 "\t%s-%" PRIu32 ".%" PRIu32 ".%" PRIu32 ".%" PRIu32 "\t0x00000000\t", netA, cidr, netA, e & 0x000000ff, (e & 0x0000ff00) >> 8, (e & 0x00ff0000) >> 16, (e & 0xff000000) >> 24);
    }
    sw = 0;
#else // T2MMDB_SUBNET == 0
    if (s6) cidr = res.netmask;
    else cidr = res.netmask - mmdb.ipv4_start_node.netmask;
    printf("%s\t%d\t", line, cidr);
#endif // T2MMDB_SUBNET

    for (uint_fast32_t i = 0; geoip_path[i][0]; i++) {
        MMDB_aget_value(&res.entry, &entry, geoip_path[i]);
        switch (geoip_type[i]) {
            case MMDB_DATA_TYPE_UTF8_STRING:
                if (entry.has_data) {
                    slen = MIN(entry.data_size, sizeof(buf));
                    memcpy(buf, entry.utf8_string, slen);
                    buf[slen] = '\0';
#if T2MMDB_SUBNET  == 1
                    if (!memcmp(geoip_path[i][1], "iso_", 4)) {
                        buf[0] = tolower(buf[0]);
                        buf[1] = tolower(buf[1]);
                    }
#endif // T2MMDB_SUBNET == 1
                    printf("%s\t", buf);
#if T2MMDB_SUBNET  == 1
                    if (sw || !memcmp(geoip_path[i][1], "orga", 4)) goto end;
#endif // T2MMDB_SUBNET == 1
                } else {
#if T2MMDB_SUBNET  == 1
                    if (!memcmp(geoip_path[i][1], "orga", 4))      { sw = 1; break; }
                    else if (!memcmp(geoip_path[i][1], "isp", 3))  { sw = 1; break; }
                    else if (!memcmp(geoip_path[i][1], "user", 3)) { putchar('-'); goto end; }
                    else if (!sw)
#endif // T2MMDB_SUBNET == 1
                    printf("-\t");
                }
#if T2MMDB_SUBNET  == 1
                if (!memcmp(geoip_path[i][0], "country", 7)) printf("-\t");
#endif // T2MMDB_SUBNET == 1
                break;
            case MMDB_DATA_TYPE_DOUBLE:
                d = (entry.has_data) ? entry.double_value : 0.0;
                printf("%f\t", d);
                break;
            case MMDB_DATA_TYPE_UINT32:
                u32 = (entry.has_data) ? entry.uint32 : 0;
                printf("%" PRIu32 "\t", u32);
                break;
            case MMDB_DATA_TYPE_UINT16:
                u16 = (entry.has_data) ? entry.uint16 : 0;
                printf("%" PRIu16 "\t", u16);
                break;
            default:
                printf("-\t");
                break;
        }
    }

#if T2MMDB_SUBNET == 1
end:
#endif // T2MMDB_SUBNET == 1

    putchar('\n');

    return true;
}


int main(int argc, char *argv[]) {
    char *dbname = NULL;
    char *ipFile = NULL;
    FILE *file = stdin;
    int op;
    bool header = true;

    while ((op = getopt(argc, argv, ":xhf:i:")) != EOF) {
        switch (op) {
            case 'f':
                dbname = strdup(optarg);
                break;
            case 'i':
                ipFile = optarg;
                break;
            case 'x':
                header = false;
                break;
            case 'h':
                usage();
                exit(0);
            case ':':
                T2_ERR("Option '-%c' requires an argument", optopt);
                abort_with_help();
            default:
                T2_ERR("Unknown option '-%c'", optopt);
                abort_with_help();
        }
    }

    argc -= optind;
    argv += optind;

    if (!dbname) {
        const char * const home = getenv("HOME");
        dbname = t2_alloc_filename(home, PLUGIN_FOLDER, T2MMDB_DB_FILE, NULL);
    }

    if (MMDB_open(dbname, MMDB_MODE_MMAP, &mmdb) != MMDB_SUCCESS) {
        T2_ERR("Failed to open GeoIP database '%s'", dbname);
        free(dbname);
        exit(EXIT_FAILURE);
    }

    free(dbname);

    if (ipFile && !(file = fopen(ipFile, "r"))) {
        T2_ERR("Failed to open file '%s' for reading: %s", ipFile, strerror(errno));
        exit(EXIT_FAILURE);
    }

    if (header) {
#if T2MMDB_SUBNET == 1
        printf("#\t5\t01032020\n");
        printf("# IPCIDR\tIPrange\tCtryWhoCode\tASN\tAccuracy\tLatitude\tLongitude\tCountry\tCounty\tCity\tOrg\n");
#else // T2MMDB_SUBNET == 0
        printf("# IP\tMask\tMetroCode\tTimeZone\tContCode\tPostalCode\tASN\tAccuracy\tLatitude\tLongitude\tCountry\tCity\tOrg\tISP\tASNname\tUserType\tDomain\n");
#endif // T2MMDB_SUBNET
    }

    for (int_fast32_t i = 0; i < argc; i++) {
        process_ip(argv[i]);
    }

    if (argc == 0 || ipFile) {
        size_t len = 0;
        char *line = NULL;
        while (getline(&line, &len, file) != -1) {
            if (line[0] == '\n' || line[0] == '#' || line[0] == ' ' || line[0] == '\t') continue;
            process_ip(line);
        }
    }

    MMDB_close(&mmdb);

    return EXIT_SUCCESS;
}
