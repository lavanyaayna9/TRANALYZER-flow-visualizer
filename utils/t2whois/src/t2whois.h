#ifndef T2WHOIS_H_INCLUDED
#define T2WHOIS_H_INCLUDED

#include <stdbool.h>  // for bool
#include <stdint.h>   // for uint16_t
#include <stdio.h>    // for FILE

#define T2WHOIS "t2whois"

#define T2WHOIS_RANDOM 0 // Add support for testing random IP addresses
                         // (and drop the dependency to libbsd)

#define T2WHOIS_QUOTE   "\""
#define T2WHOIS_NOQUOTE ""

enum {
    OFIELD_IP,
    OFIELD_NETMASK,
    OFIELD_NET,
    OFIELD_MASK,
    OFIELD_RANGE,
    OFIELD_ORG,
    OFIELD_COUNTRY,
    OFIELD_CITY,
    OFIELD_CNTY,
    OFIELD_ASN,
    OFIELD_LAT,
    OFIELD_LNG,
    OFIELD_PREC,
    OFIELD_NETID,
    OFIELD_NUM // Marker
};

typedef struct {
    const char *name;
    const char *descr;
    uint16_t field;
    bool active;
} ofield_t;


extern bool oneline;
extern bool print_header;

void print_dbs_info();
void print_fields();
void print_geoinfo_oneline_hdr(FILE *file);
void process_ip(FILE *file, const char *ipstr);

#if T2WHOIS_RANDOM == 1
void test_random_ip();
void test_random_ipv4();
void test_random_ipv6();
#endif

#endif // T2WHOIS_H_INCLUDED
