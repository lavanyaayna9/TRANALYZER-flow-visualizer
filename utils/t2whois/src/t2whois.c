#include "t2whois.h"

#include "t2whois-prompt.h"   // for prompt_init, run_prompt
#include "t2whois-server.h"   // for T2WHOIS_SERVER_IP, T2WHOIS_SERVER_PORT
#include "t2whois-utils.h"    // for print_func_t

#if !defined(__APPLE__) && T2WHOIS_RANDOM == 1
#include <bsd/stdlib.h>       // for arc4random
#endif

#include <arpa/inet.h>        // for htonl, inet_ntop, inet_pton
#include <ctype.h>            // for isspace
#include <errno.h>            // for errno
#include <getopt.h>           // for getopt
#include <signal.h>           // for signal
#include <stdio.h>            // for fclose, sscanf, strcasecmp, strerror, ...
#include <stdlib.h>           // for EXIT_FAILURE, EXIT_SUCCESS
#include <string.h>           // for memcpy, strchr
#include <unistd.h>           // for isatty

#include "bin2txt.h"          // for B2T_PRIX32
#include "iputils.h"          // for ipv[46]_to_mask, mask_to_ipv[46]
#include "missing/missing.h"  // for htobe64
#include "subnetHL4.h"        // for subnet_init4, subnettable4_destroy
#include "subnetHL6.h"        // for subnet_init6, subnettable6_destroy
#include "t2log.h"            // for T2_ERR, T2_INF, T2_WRN


static ofield_t ofields_default[] = {
    { "ip"     , "IP"          , OFIELD_IP     , true  },
    { "netmask", "Network/Mask", OFIELD_NETMASK, (SUBRNG == 1 ? false : true) },
    { "net"    , "Network"     , OFIELD_NET    , false },
    { "mask"   , "Mask"        , OFIELD_MASK   , false },
    { "range"  , "Range"       , OFIELD_RANGE  , true  },
    { "org"    , "Organization", OFIELD_ORG    , true  },
    { "country", "Country"     , OFIELD_COUNTRY, true  },
    { "county" , "County"      , OFIELD_CNTY   , (CNTYCTY == 0 ? false : true) },
    { "city"   , "City"        , OFIELD_CITY   , (CNTYCTY == 0 ? false : true) },
    { "asn"    , "ASN"         , OFIELD_ASN    , true  },
    { "lat"    , "Latitude"    , OFIELD_LAT    , true  },
    { "lng"    , "Longitude"   , OFIELD_LNG    , true  },
    { "prec"   , "Precision"   , OFIELD_PREC   , true  },
    { "netid"  , "NetID"       , OFIELD_NETID  , true  },
    { NULL     , NULL          , OFIELD_NUM    , true  },
};
static ofield_t ofields[OFIELD_NUM+1];
static print_func_t print_func;


#if CNTYCTY == 1
#define T2W_SUBNET_CITY(subnet) (subnet).cty
#define T2W_SUBNET_CNTY(subnet) (subnet).cnty
#else // CNTYCTY == 0
#define T2W_SUBNET_CITY(subnet) SUBNET_UNK
#define T2W_SUBNET_CNTY(subnet) SUBNET_UNK
#endif // CNTYCTY == 0


#define PRINT_ERR(file, format, args...) \
    print_func(file, RED_BOLD "[ERR] " RED format NOCOLOR "\n", ##args)


#define PRINT_FIELD(file, ipstr, netstr, mask, ipfirst, iplast, subnet, field, quote) { \
    switch (field) { \
        case OFIELD_IP:      print_func(file, "%s", ipstr);                                     break; \
        case OFIELD_ORG:     print_func(file, "%s%s%s", quote, (subnet).org, quote);            break; \
        case OFIELD_NET:     print_func(file, "%s", netstr);                                    break; \
        case OFIELD_COUNTRY: print_func(file, "%s", (subnet).loc);                              break; \
        case OFIELD_CITY:    print_func(file, "%s%s%s", quote, T2W_SUBNET_CITY(subnet), quote); break; \
        case OFIELD_CNTY:    print_func(file, "%s%s%s", quote, T2W_SUBNET_CNTY(subnet), quote); break; \
        case OFIELD_LAT:     print_func(file, "%f", (subnet).lat);                              break; \
        case OFIELD_LNG:     print_func(file, "%f", (subnet).lng);                              break; \
        case OFIELD_PREC:    print_func(file, "%f", (subnet).oP);                               break; \
        case OFIELD_ASN:     print_func(file, "%" PRIu32, (subnet).asn);                        break; \
        case OFIELD_MASK:    print_func(file, "%" PRIu32, mask);                                break; \
        case OFIELD_NETMASK: print_func(file, "%s/%" PRIu8, netstr, mask);                      break; \
        case OFIELD_RANGE:   print_func(file, "%s%s - %s%s", quote, ipfirst, iplast, quote);    break; \
        case OFIELD_NETID:   print_func(file, "0x%08" B2T_PRIX32, (subnet).netID);              break; \
        default: \
            PRINT_ERR(file, "Field %u not implemented", field); \
            break; \
    } \
}


#define PRINT_GEOINFO(file, ipstr, netstr, mask, ipfirst, iplast, subnet) \
    if (oneline) { \
        PRINT_GEOINFO_ONELINE(file, ipstr, netstr, mask, ipfirst, iplast, subnet); \
    } else if (kml_file) { \
        if (!SUBNET_POS_IS_UNKNOWN((subnet).lng, (subnet).lat)) { \
            PRINT_GEOINFO_KML(kml_file, ipstr, netstr, mask, ipfirst, iplast, subnet); \
        } \
    } else { \
        PRINT_GEOINFO_BLOCK(file, ipstr, netstr, mask, ipfirst, iplast, subnet); \
    }


#define PRINT_GEOINFO_NOT_FOUND(file, ipstr) \
    if (oneline) { \
        print_geoinfo_oneline_empty(file, ipstr); \
    } else { \
        print_func(file, YELLOW_BOLD "[WRN] " YELLOW "No entry found for '%s'" NOCOLOR "%s\n", ipstr, prompt ? "" : "\n"); \
    }


#define PRINT_GEOINFO_ONELINE(file, ipstr, netstr, mask, ipfirst, iplast, subnet) { \
    for (uint_fast32_t i = 0; ofields[i].name; i++) { \
        if (ofields[i].active) { \
            PRINT_FIELD(file, ipstr, netstr, mask, ipfirst, iplast, subnet, ofields[i].field, T2WHOIS_QUOTE); \
            print_func(file, "%s", (ofields[i+1].name ? sep : "")); \
        } \
    } \
    print_func(file, "\n"); \
}


#define PRINT_GEOINFO_BLOCK(file, ipstr, netstr, mask, ipfirst, iplast, subnet) { \
    for (uint_fast32_t i = 0; ofields[i].name; i++) { \
        if (ofields[i].active) { \
            print_func(file, BOLD "%-10s" NOCOLOR "%s", ofields[i].descr, sep); \
            PRINT_FIELD(file, ipstr, netstr, mask, ipfirst, iplast, subnet, ofields[i].field, T2WHOIS_NOQUOTE); \
            print_func(file, "\n"); \
        } \
    } \
    print_func(file, "\n"); \
}


#define PRINT_GEOINFO_KML(file, ipstr, netstr, mask, ipfirst, iplast, subnet) { \
    print_func(file, "    <Placemark>"); \
    print_func(file, "<styleUrl>#ipv%u</styleUrl>", strchr(ipstr, ':') ? 6 : 4); \
    print_func(file, "<name>%s</name>", ipstr); \
    print_func(file, "<description><![CDATA[<table><tr>"); \
    for (uint_fast32_t i = 0; ofields[i].name; i++) { \
        if (ofields[i].active) { \
            print_func(file, "<td><b>%s:</b</td><td>", ofields[i].descr); \
            PRINT_FIELD(file, ipstr, netstr, mask, ipfirst, iplast, subnet, ofields[i].field, T2WHOIS_NOQUOTE); \
            print_func(file, "</td></tr>"); \
        } \
    } \
    print_func(file, "</tr></table>]]></description>"); \
    print_func(file, "<Point>"); \
    print_func(file, "<coordinates>%f,%f</coordinates>", (subnet).lng, (subnet).lat); \
    print_func(file, "</Point>"); \
    print_func(file, "</Placemark>\n"); \
}


static subnettable4_t *subnet_table4;
static subnettable6_t *subnet_table6;

FILE *dooF;
FILE *kml_file;
bool prompt = true;
bool oneline = false;
bool print_header = true;
const char *sep = SEP_CHR;
const char *hsep = HDR_CHR;

static char *pluginFolder;
static const char *dbpath4, *dbpath6;
static const char *subnetfile4;
static const char *subnetfile6;


static const char *sep_to_str(const char * const sep) {
    const size_t seplen = strlen(sep);
    if (seplen != 1) return sep;
    switch (*sep) {
        case '\n': return "\\n";
        case '\r': return "\\r";
        case '\t': return "\\t";
        case '\\': return "\\\\";
        default: return sep;
    }
}


static void usage() {
    printf("Usage:\n");
    printf("    %s [OPTION...] [INPUT...]\n", T2WHOIS);
    printf("\nInput:\n");
    printf("    -               If no input is provided, read from stdin\n");
    printf("    ip              Read IP address(es) directly from the command line\n");
    printf("    -r file         Read IP address(es) from 'file'\n");
#if T2WHOIS_RANDOM == 1
    printf("    -R [046]        Test a random IPv4 or IPv6\n");
#endif
    printf("\nOptional arguments:\n");
    printf("    -D              Run as a server/daemon on %s:%u\n", T2WHOIS_SERVER_IP, T2WHOIS_SERVER_PORT);
    printf("    -a              Server address\n");
    printf("    -p              Server port\n");
    printf("\n");
    printf("    -d file         Binary subnet file to use for IPv4\n");
    printf("    -e file         Binary subnet file to use for IPv6\n");
    printf("\n");
    printf("    -o field(s)     Field(s) to output (in order). Many fields can be selected\n");
    printf("                    by using multiple '-o' options or by separating the fields\n");
    printf("                    with a comma, e.g., -o field1,field2. Valid field names are\n");
    printf("                    all, default, ");
    for (uint_fast32_t i = 0; ofields_default[i].name; i++) {
        printf("%s", ofields_default[i].name);
        if (i+1 == OFIELD_NUM) {
            printf("\n");
        } else if (i == 6) {
            printf(",\n                    ");
        } else {
            printf(", ");
        }
    }
    printf("\n");
    printf("    -q              Do not display an interactive prompt when reading from stdin\n");
    printf("\n");
    printf("    -k file         Generate a KML 'file'\n");
    printf("\n");
    printf("    -l              Output one line per IP\n");
    printf("    -H              Do not output the header with -l option\n");
    printf("    -t char         Start character(s) for column header (-l option) [\"%s\"]\n", hsep);
    printf("\n");
    printf("    -s char         Column separator for output [\"%s\"]\n", sep_to_str(sep));
    printf("\nHelp and documentation arguments:\n");
    printf("    -L              Describe the available fields and exit\n");
    printf("    -V              Show info about the database (version, ...) and exit\n");
    printf("    -h              Show help options and exit\n");
}


static __attribute__((noreturn)) void abort_with_help() {
    printf("Try '%s -h' for more information.\n", T2WHOIS);
    exit(EXIT_FAILURE);
}


static void init_subnet_table4(const char *dir, const char *filename) {
    if (UNLIKELY(!(subnet_table4 = subnet_init4(dir, filename)))) {
        exit(EXIT_FAILURE);
    }
}


static void init_subnet_table6(const char *dir, const char *filename) {
    if (UNLIKELY(!(subnet_table6 = subnet_init6(dir, filename)))) {
        exit(EXIT_FAILURE);
    }
}


static void cleanup() {
    subnettable4_destroy(subnet_table4);
    subnettable6_destroy(subnet_table6);
    if (kml_file) fclose(kml_file);
    free(pluginFolder);
}


static __attribute__((noreturn)) void cleanup_and_exit(int status) {
    cleanup();
    exit(status);
}


static __attribute__((noreturn)) void int_handler(int sig UNUSED) {
    cleanup_and_exit(EXIT_FAILURE);
}


// Returned value MUST be free'd
static char *get_pluginFolder() {
    const char *home = getenv("HOME");
    const size_t len = strlen(home);
    char *fname = t2_malloc_fatal(len + sizeof(PLUGIN_FOLDER) + 2);
    strcpy(fname, home);
    strcat(fname, "/" PLUGIN_FOLDER);
    return fname;
}


static void print_kml_header(FILE *file) {
    print_func(file, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    print_func(file, "<kml xmlns=\"http://www.opengis.net/kml/2.2\">\n");
    print_func(file, "  <Document>\n");
    print_func(file, "    <name>Tranalyzer</name>\n");
    print_func(file, "    <description>Geolocation</description>\n");
    print_func(file, "    <Style id=\"ipv4\">\n");
    print_func(file, "      <IconStyle>\n");
    print_func(file, "        <color>ff0000ff</color>\n");
    print_func(file, "      </IconStyle>\n");
    print_func(file, "    </Style>\n");
    print_func(file, "    <Style id=\"ipv6\">\n");
    print_func(file, "      <IconStyle>\n");
    print_func(file, "        <color>ff00ff00</color>\n");
    print_func(file, "      </IconStyle>\n");
    print_func(file, "    </Style>\n");
}


static void print_kml_footer(FILE *file) {
    print_func(file, "  </Document>\n");
    print_func(file, "</kml>\n");
}


void print_fields() {
    printf("The fields available are:\n");
    for (uint_fast32_t i = 0; ofields_default[i].name; i++) {
        printf("\t" BOLD "%-11s\t" NOCOLOR "%s\n", ofields_default[i].name, ofields_default[i].descr);
    }
}


// Extract and print version information from binary file
static void print_db_info(const char *dir, const char *filename) {
    FILE *file = t2_fopen_in_dir(dir, filename, "r");
    if (UNLIKELY(!file)) exit(EXIT_FAILURE);

    subnet4_t srec;
    if (fread(&srec, sizeof(srec), 1, file) == 0) {
        T2_FATAL("Failed to read record in file '%s'", filename);
    }

    fclose(file);

    char hrnum[64];
    const uint32_t num_subnets = srec.net/2;
    T2_CONV_NUM(num_subnets, hrnum);

    putchar('\n');
    printf(BOLD "%-11s" NOCOLOR "%s%s%s\n", "Database", sep, dir ? dir : "", filename);
    printf(BOLD "%-11s" NOCOLOR "%s%" PRIu32 "\n", "Version", sep, (srec.netVec & VERMSK));
    printf(BOLD "%-11s" NOCOLOR "%s%08" PRIu32 "\n", "Revision", sep, srec.netID);
    printf(BOLD "%-11s" NOCOLOR "%s%lu\n", "Range Mode", sep, (unsigned long)(srec.netVec & ~VERMSK) >> 31);
    printf(BOLD "%-11s" NOCOLOR "%s%" PRIu32 "%s\n", "Num Subnets", sep, num_subnets, hrnum);
    putchar('\n');
}


void print_dbs_info() {
    print_db_info(dbpath4, subnetfile4);
    print_db_info(dbpath6, subnetfile6);
}


void print_geoinfo_oneline_hdr(FILE *file) {
    print_func(file, "%s", hsep);
    for (uint_fast32_t i = 0; ofields[i].name; i++) {
        if (ofields[i].active) {
            print_func(file, "%s%s", ofields[i].descr, (ofields[i+1].name ? sep : ""));
        }
    }
    print_func(file, "\n");
}


static void print_geoinfo_oneline_empty(FILE *file, const char * const ipstr) {
    for (uint_fast32_t i = 0; ofields[i].name; i++) {
        if (ofields[i].active) {
            print_func(file, "%s%s", ofields[i].field == OFIELD_IP ? ipstr : "", (ofields[i+1].name ? sep : ""));
        }
    }
    print_func(file, "\n");
}


static void process_ipv4(FILE *file, const char *ipstr) {
    // Discard network mask
    char * const slash = strchr(ipstr, '/');
    if (slash) *slash = '\0';

    char addr[INET_ADDRSTRLEN];

    // Convert the IP
    struct in_addr ip;
    if (strncmp(ipstr, "0x", 2) == 0) {
        uint32_t hex32;
        sscanf(ipstr, "0x%08" SCNx32, &hex32);
        ip.s_addr = htonl(hex32);
        inet_ntop(AF_INET, &ip, addr, INET_ADDRSTRLEN);
        ipstr = addr;
    } else {
        struct in_addr ipa;
        if (inet_pton(AF_INET, ipstr, &ipa) != 1) {
            if (slash) *slash = '/'; // Restore the network mask
            PRINT_ERR(file, "Failed to convert IP '%s'", ipstr);
            return;
        }
        ip = ipa;
    }

    // Lookup the IP
    const uint32_t subnet_id = subnet_testHL4(subnet_table4, ip.s_addr);
    if (slash) *slash = '/'; // Restore the network mask
    if (subnet_id == 0) {
        PRINT_GEOINFO_NOT_FOUND(file, ipstr);
        return;
    }

    char ipfirst[INET_ADDRSTRLEN];
    char iplast[INET_ADDRSTRLEN];

    const subnet4_t subnet = subnet_table4->subnets[subnet_id];

    uint32_t net = subnet.net;

    // Get the mask and mask the net
#if SUBRNG == 1
    const uint8_t mask = subnet.beF;
    net &= mask_to_ipv4(mask);
#else // SUBRNG == 0
    const uint8_t mask = ipv4_to_mask(subnet.mask);
    net &= subnet.mask;
#endif // SUBRNG == 0

    // Convert the net to string
    char netstr[INET_ADDRSTRLEN];
    net = htonl(net);
    t2_ipv4_to_str(*(struct in_addr*)&net, netstr, sizeof(netstr));

    // Get ipfirst and iplast to display the range
    if ((mask & SINGLE4) == SINGLE4) { // => mask = 32
        const size_t iplen = strlen(ipstr) + 1;
        memcpy(ipfirst, ipstr, iplen);
        memcpy(iplast, ipstr, iplen);
    } else {
#if SUBRNG == 1
        struct in_addr temp;
        if (subnet.beF == 1) {
            temp.s_addr = htonl(subnet_table4->subnets[subnet_id-1].net),
            t2_ipv4_to_str(temp, ipfirst, sizeof(ipfirst));
            temp.s_addr = htonl(subnet.net);
            t2_ipv4_to_str(temp, iplast, sizeof(iplast));
        } else {
            temp.s_addr = htonl(subnet.net);
            t2_ipv4_to_str(temp, ipfirst, sizeof(ipfirst));
            temp.s_addr = htonl(subnet_table4->subnets[subnet_id+1].net);
            t2_ipv4_to_str(temp, iplast, sizeof(iplast));
        }
#else // SUBRNG == 0
        memcpy(ipfirst, netstr, strlen(netstr)+1);
        const uint32_t temp = net | ~htonl(subnet.mask);
        t2_ipv4_to_str(*(struct in_addr*)&temp, iplast, sizeof(iplast));
#endif // SUBRNG == 0
    }

    PRINT_GEOINFO(file, ipstr, netstr, mask, ipfirst, iplast, subnet);
}


static void process_ipv6(FILE *file, const char *ipstr) {
    // Discard network mask
    char * const slash = strchr(ipstr, '/');
    if (slash) *slash = '\0';

    // Convert the IP
    ipAddr_t ip = {};
    if (inet_pton(AF_INET6, ipstr, &ip) != 1) {
        if (slash) *slash = '/'; // Restore the network mask
        PRINT_ERR(file, "Failed to convert IP '%s'", ipstr);
        return;
    }

    // Lookup the IP
    const uint32_t subnet_id = subnet_testHL6(subnet_table6, ip);
    if (slash) *slash = '/'; // Restore the network mask
    if (subnet_id == 0) {
        PRINT_GEOINFO_NOT_FOUND(file, ipstr);
        return;
    }

    char ipfirst[INET6_ADDRSTRLEN];
    char iplast[INET6_ADDRSTRLEN];

    const subnet6_t subnet = subnet_table6->subnets[subnet_id];

    ipAddr_t net = {
        .IPv6L[0] = htobe64(subnet.net.IPv6L[0]),
        .IPv6L[1] = htobe64(subnet.net.IPv6L[1]),
    };

    // Get the mask and mask the net
#if SUBRNG == 1
    const uint8_t mask = subnet.beF;
    ipAddr_t ipmask = mask_to_ipv6(mask);
    const ipAddr_t orig_net = net;
    net.IPv6L[0] &= ipmask.IPv6L[0];
    net.IPv6L[1] &= ipmask.IPv6L[1];
#else // SUBRNG == 0
    const uint8_t mask = ipv6_to_mask(subnet.mask);
    net.IPv6L[0] &= htobe64(subnet.mask.IPv6L[0]);
    net.IPv6L[1] &= htobe64(subnet.mask.IPv6L[1]);
#endif // SUBRNG == 0

    // Convert the net to string
    char netstr[INET6_ADDRSTRLEN];
    t2_ipv6_to_str(*(struct in6_addr*)&net, netstr, sizeof(netstr));

    // Get ipfirst and iplast to display the range
    if ((mask & SINGLE6) == SINGLE6) { // => mask = 128
        const size_t iplen = strlen(ipstr) + 1;
        memcpy(ipfirst, ipstr, iplen);
        memcpy(iplast, ipstr, iplen);
    } else {
#if SUBRNG == 1
        if (subnet.beF == 1) {
            ipAddr_t prev = subnet_table6->subnets[subnet_id-1].net;
            prev.IPv6L[0] = htobe64(prev.IPv6L[0]);
            prev.IPv6L[1] = htobe64(prev.IPv6L[1]);
            t2_ipv6_to_str(*(struct in6_addr*)&prev, ipfirst, sizeof(ipfirst));
            t2_ipv6_to_str(*(struct in6_addr*)&orig_net, iplast, sizeof(iplast));
        } else {
            t2_ipv6_to_str(*(struct in6_addr*)&orig_net, ipfirst, sizeof(ipfirst));
            ipAddr_t next = subnet_table6->subnets[subnet_id+1].net;
            next.IPv6L[0] = htobe64(next.IPv6L[0]);
            next.IPv6L[1] = htobe64(next.IPv6L[1]);
            t2_ipv6_to_str(*(struct in6_addr*)&next, iplast, sizeof(iplast));
        }
#else // SUBRNG == 0
        memcpy(ipfirst, netstr, strlen(netstr)+1);
        const ipAddr_t temp = {
            .IPv6L[0] = net.IPv6L[0] | ~htobe64(subnet.mask.IPv6L[0]),
            .IPv6L[1] = net.IPv6L[1] | ~htobe64(subnet.mask.IPv6L[1]),
        };
        t2_ipv6_to_str(*(struct in6_addr*)&temp, iplast, sizeof(iplast));
#endif // SUBRNG == 0
    }

    PRINT_GEOINFO(file, ipstr, netstr, mask, ipfirst, iplast, subnet);
}


void process_ip(FILE *file, const char *ipstr) {

    if (!oneline && !kml_file && !prompt) print_func(file, "\n");

    if (strchr(ipstr, ':')) {
        process_ipv6(file, ipstr);
    } else {
        process_ipv4(file, ipstr);
    }
}


static void process_file(FILE *file) {
    size_t len = 0;
    char *line = NULL;
    ssize_t linelen;
    while ((linelen = getline(&line, &len, file)) != -1) {
        if (*line == '#' || isspace(*line)) continue;
        line[linelen-1] = '\0'; // discard trailing '\n'
        process_ip(stdout, line);
    }
    free(line);
}


#if T2WHOIS_RANDOM == 1

void test_random_ipv4() {
    struct in_addr ip;
    ip.s_addr = arc4random();
    char addr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip, addr, INET_ADDRSTRLEN);
    process_ip(stdout, addr);
}


void test_random_ipv6() {
    ipAddr_t ip = {
        .IPv4x[0] = arc4random(),
        .IPv4x[1] = arc4random(),
        .IPv4x[2] = arc4random(),
        .IPv4x[3] = arc4random(),
    };

    char addr[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &ip, addr, INET6_ADDRSTRLEN);
    process_ip(stdout, addr);
}


void test_random_ip() {
    if (arc4random() & 1) {
        test_random_ipv6();
    } else {
        test_random_ipv4();
    }
}

#endif // T2WHOIS_RANDOM == 1


static void process_o_option(char *str) {
    static uint_fast32_t ofields_idx = 0;

    char *field, *last;
    for (field = strtok_r(str, ",", &last);
         field;
         field = strtok_r(NULL, ",", &last))
    {
        const bool o_all = (strcasecmp(field, "all") == 0);
        const bool o_default = (strcasecmp(field, "default") == 0);

        bool found = false;
        for (uint_fast32_t i = 0; ofields_default[i].name; i++) {
            if (o_all) {
                ofields[ofields_idx] = ofields_default[i];
                ofields[ofields_idx++].active = true;
            } else if (o_default) {
                ofields[ofields_idx++] = ofields_default[i];
            } else if (strcasecmp(field, ofields_default[i].name) == 0) {
#if CNTYCTY == 0
                if (ofields_default[i].field == OFIELD_CNTY ||
                    ofields_default[i].field == OFIELD_CITY)
                {
                    T2_ERR("The databases were not built with the County and City information");
                    T2_INF("Run 't2conf tranalyzer2 -D CNTYCTY=1 && t2build -f tranalyzer2'");
                    exit(EXIT_FAILURE);
                }
#endif
                if (ofields_idx == OFIELD_NUM) {
                    T2_FATAL("The same output field was specified multiple times");
                }

                ofields[ofields_idx] = ofields_default[i];
                ofields[ofields_idx++].active = true;
                found = true;
                break;
            }
        }

        if (o_all || o_default) return;

        if (!found) {
            fprintf(stderr, RED_BOLD "[ERR] " RED "Invalid argument for '-o' option: expected one of ");
            for (uint_fast32_t i = 0; ofields_default[i].name; i++) {
                fprintf(stderr, "'%s', ", ofields_default[i].name);
            }
            fprintf(stderr, "found '%s'" NOCOLOR "\n", field);
            exit(EXIT_FAILURE);
        }
    }
}


int main(int argc, char *argv[]) {
    dooF = stdout;
    bool list_fields = false;
    bool dbinfo = false;
    bool daemon = false;
    uint16_t server_port = T2WHOIS_SERVER_PORT;
    const char *server_addr = T2WHOIS_SERVER_IP;
    const char *ipfile = NULL;
    const char *kml_name = NULL;
#if T2WHOIS_RANDOM == 1
    uint8_t rand = 0;
#endif

    int op;
    while ((op = getopt(argc, argv, ":r:s:t:d:e:o:k:R:a:p:DqlHLVh")) != EOF) {
        switch (op) {

            case 'q':
                prompt = false;
                break;

            case 'd':
                subnetfile4 = optarg;
                break;

            case 'e':
                subnetfile6 = optarg;
                break;

            case 'o':
                process_o_option(optarg);
                break;

            case 'a':
                server_addr = optarg;
                break;

            case 'p':
                server_port = atoi(optarg);
                break;

            case 'D':
                daemon = true;
                break;

            case 'l':
                oneline = true;
                break;

            case 'k':
                kml_name = optarg;
                break;

            case 'H':
                print_header = false;
                break;

            case 's':
                sep = optarg;
                break;

            case 't':
                hsep = optarg;
                break;

            case 'r':
                if (*optarg != '-' || strlen(optarg) > 1) {
                    ipfile = optarg;
                }
                break;

            case 'R':
#if T2WHOIS_RANDOM == 0
                T2_ERR("Option '-%c' not available", optopt);
                T2_INF("Set T2WHOIS_RANDOM to 1 in src/t2whois.h and recompile t2whois");
                exit(EXIT_FAILURE);
#else // T2WHOIS_RANDOM == 1
                switch (*optarg) {
                    case '4': rand |= 0x02; break;
                    case '6': rand |= 0x04; break;
                    default : rand |= 0x01; break;
                }
#endif // T2WHOIS_RANDOM == 0
                break;

            case 'L':
                list_fields = true;
                break;

            case 'V':
                dbinfo = true;
                break;

            case 'h':
                usage();
                exit(EXIT_SUCCESS);
                break;

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

    // We know that argv[0] does not start with a '-' as getopt did not process it
    for (int_fast32_t i = 1; i < argc; i++) {
        if (*argv[i] == '-') {
            T2_WRN("Options following '%s' will be ignored. IPs MUST be specified last.", argv[i-1]);
            break;
        }
    }

    if (oneline && kml_name) {
        T2_ERR("Cannot use '-l' and '-k' options at the same time");
        abort_with_help();
    }

    if (list_fields) {
        print_fields();
        cleanup_and_exit(EXIT_SUCCESS);
    }

    if (!ofields[0].name) {
        for (uint_fast32_t i = 0; ofields_default[i].name; i++) {
            ofields[i] = ofields_default[i];
        }
    }

    signal(SIGINT, int_handler);

    // Get the default filename for subnet files
    if (!subnetfile4 || !subnetfile6) {
        pluginFolder = get_pluginFolder();

        if (!subnetfile4) {
            dbpath4 = pluginFolder;
            subnetfile4 = SUBNETFILE4;
        }

        if (!subnetfile6) {
            dbpath6 = pluginFolder;
            subnetfile6 = SUBNETFILE6;
        }
    }

    if (dbinfo) {
        print_dbs_info();
        cleanup_and_exit(EXIT_SUCCESS);
    }

    init_subnet_table4(dbpath4, subnetfile4);
    init_subnet_table6(dbpath4, subnetfile6);

    if (daemon) {
        print_func = fprintf_socket;
        run_server(server_addr, server_port);
        cleanup_and_exit(EXIT_SUCCESS);
    }

    print_func = fprintf;

    // Disable the prompt if stdin is not a tty, i.e., data was passed via stdin
    if (argc == 0) {
        if (!isatty(fileno(stdin))) {
            prompt = false;
        } else if (!ipfile && !isatty(fileno(stdout))) {
            T2_ERR("No input provided, nothing to redirect");
            cleanup();
            abort_with_help();
        }
    }

    if (oneline && print_header && (ipfile || argc > 0 || !prompt)) {
        print_geoinfo_oneline_hdr(stdout);
    } else if (kml_name) {
        kml_file = fopen(kml_name, "w");
        if (!kml_file) {
            T2_ERR("Failed to open file '%s' for writing: %s", kml_name, strerror(errno));
            cleanup_and_exit(EXIT_FAILURE);
        }
        print_kml_header(kml_file);
    }

#if T2WHOIS_RANDOM == 1
    if (rand & 0x01) test_random_ip();
    if (rand & 0x02) test_random_ipv4();
    if (rand & 0x04) test_random_ipv6();
#endif

    for (int_fast32_t i = 0; i < argc; i++) {
        process_ip(stdout, argv[i]);
    }

    if (ipfile) {
        FILE *file = fopen(ipfile, "r");
        if (!file) {
            T2_ERR("Failed to open file '%s' for reading: %s", ipfile, strerror(errno));
            cleanup_and_exit(EXIT_FAILURE);
        }
        prompt = false;
        process_file(file);
        fclose(file);
    } else if (argc == 0
#if T2WHOIS_RANDOM == 1
        && !rand
#endif
    ) {
        if (!prompt) {
            process_file(stdin);
        } else {
            prompt_init();
            T2_INF("Enter an IPv4/6 address, 'help' or 'quit' to exit\n");
            if (kml_file) {
                T2_WRN("All results will be redirected to '%s'\n", kml_name);
            }
            run_prompt(prompt);
        }
    }

    if (kml_file) {
        print_kml_footer(kml_file);
    }

    cleanup();

    return EXIT_SUCCESS;
}
