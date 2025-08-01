/*
 * covertChannels.c
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

// global includes
#include <ctype.h>
#include <math.h>
#include <stdio.h>

// local includes
#include "covertChannels.h"
#include "t2Plugin.h"
#include "memdebug.h"


// Macros

#define CC_DEBUG (DEBUG | CC_DEBUG_MESSAGES)

#if CC_DEBUG != 0
/** if DEBUG is enabled, print file name, line and function + message*/
#define debug_print(format, args...) T2_PWRN(plugin_name, format, ##args)
#else // CC_DEBUG == 0
/** on DEBUG disabled, just ignore */
#define debug_print(format, args...)
#endif // CC_DEBUG != 0


// Global variables

cc_flow_t *cc_flows;


// Static variables

static size_t cc_count;
static uint16_t covertChannels;


// Tranalyzer functions

T2_PLUGIN_INIT("covertChannels", "0.9.3", 0, 9);


// Helper functions

#if (CC_DETECT_DNS | CC_DETECT_ICMP_WL) != 0
/**
 * @brief Removes the line return at the end of a line.
 *
 * @param  str   the string to strip.
 * @param  size  size of the string to strip.
 */
static void stripln(char *start, ssize_t *size) {
    char *end = start + *size - 1;
    while (*size > 0 && (*end == '\r' || *end == '\n')) {
        *end-- = '\0';
        --(*size);
    }
}
#endif // (CC_DETECT_DNS | CC_DETECT_ICMP_WL) != 0

#if CC_DETECT_DNS == 1
// DNS whitelist
static char **dns_whitelist;
static size_t dns_whitelist_len = 0;

// type of sections in DNS packet
typedef enum {
    DNS_QUESTION,
    DNS_ANSWER_RR,
    DNS_AUTHORITY_RR,
    DNS_ADDITIONAL_RR,
} dns_section;

// type of characters in domain names
typedef enum {
    TYPE_NONE,
    CONSONANT,
    VOWEL,
    DIGIT,
    SPECIAL,
} char_type;

// array used to get the character type of any byte in O(1)
static const char_type alphabet[] = {
    SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL,
    SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL,
    SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL,
    SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL,
    SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, DIGIT, DIGIT, DIGIT,
    DIGIT, DIGIT, DIGIT, DIGIT, DIGIT, DIGIT, DIGIT, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL,
    SPECIAL, SPECIAL, VOWEL, CONSONANT, CONSONANT, CONSONANT, VOWEL, CONSONANT, CONSONANT, CONSONANT,
    VOWEL, CONSONANT, CONSONANT, CONSONANT, CONSONANT, CONSONANT, VOWEL, CONSONANT, CONSONANT,
    CONSONANT, CONSONANT, CONSONANT, VOWEL, CONSONANT, CONSONANT, CONSONANT, VOWEL, CONSONANT,
    SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, VOWEL, CONSONANT, CONSONANT, CONSONANT,
    VOWEL, CONSONANT, CONSONANT, CONSONANT, VOWEL, CONSONANT, CONSONANT, CONSONANT, CONSONANT,
    CONSONANT, VOWEL, CONSONANT, CONSONANT, CONSONANT, CONSONANT, CONSONANT, VOWEL, CONSONANT,
    CONSONANT, CONSONANT, VOWEL, CONSONANT, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL,
    SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL,
    SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL,
    SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL,
    SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL,
    SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL,
    SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL,
    SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL,
    SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL,
    SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL,
    SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL,
    SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL,
    SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL,
    SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL, SPECIAL
};

/**
 * @brief Extract domain name from DNS packet.
 *
 * This function transforms the domain name representation from a DNS packet to a dot separated
 * string. DNS pointers are followed so the complete domain is extracted.
 * This function assumes that the destination buffer is at least DNS_MAX_DOMAIN_LEN + 1 bytes long.
 * The return value is used to determine where the next entry is located.
 *
 * @param  dns      pointer to the DNS header
 * @param  pos      position in the DNS packet where the domain to extract starts
 * @param  dns_len  length of the DNS payload (including the DNS header)
 * @param  buffer   buffer to store the extracted domain name (DNS_MAX_DOMAIN_LEN + 1 bytes long)
 * @return          number of bytes used in the DNS payload to encode the extracted domain
 * @retval -1       invalid domain name
 * @retval -2       snapped domain name
 */
static int parse_domain(const uint8_t *dns, uint16_t pos, uint16_t dns_len, char *buffer) {
    int ret = 0;
    bool followed_ptr = false;
    size_t write_pos = 0;

    while (pos < dns_len && dns[pos] != 0) {
        // if there is only one byte left and it's not 0 => domain is snapped
        if (pos == dns_len - 1) {
            return -2;
        }
        // check for DNS pointer (DNS packet compression)
        const uint16_t ptr = ntohs(*(uint16_t*)(dns + pos));
        if (ptr & DNS_POINTER_MASK) {
            // if label start with 0b01 or 0b10, it is neither a valid label, nor a valid pointer
            if ((ptr & DNS_POINTER_MASK) != DNS_POINTER_MASK) {
                debug_print("DNS: invalid label start byte");
                return -1;
            }
            const uint16_t ptr_pos = ptr & ~DNS_POINTER_MASK;
            // DNS pointer must point to a prior occurrence (to avoid infinite loop)
            if (ptr_pos >= pos) {
                debug_print("DNS: invalid forward pointer");
                return -1;
            }
            // follow DNS pointer
            pos = ptr_pos;
            followed_ptr = true;
            ret += 2;
            continue;
        }
        const uint8_t label_len = dns[pos];
        // check that label length is valid
        if (label_len > DNS_MAX_LABEL_LEN) {
            debug_print("DNS: label too long");
            return -1;
        }
        // check if label is snapped
        if (pos + label_len >= dns_len) {
            return -2;
        }
        // check that the total domain name length is valid
        if (write_pos + label_len > DNS_MAX_DOMAIN_LEN) {
            debug_print("DNS: domain name too long");
            return -1;
        }
        // copy the label while checking it doesn't contain '\0' characters
        pos++;
        for (uint8_t i = 0; i < label_len; ++i) {
            if (dns[pos] == 0) {
                debug_print("DNS: null byte in domain name");
                return -1;
            }
            buffer[write_pos++] = dns[pos++];
        }
        buffer[write_pos++] = '.';
        if (!followed_ptr) {
            ret += label_len + 1;
        }
    }
    if (pos >= dns_len) {
        return -2;
    }
    // skip the end null byte
    if (!followed_ptr) {
        ret++;
    }
    // null terminate the output string
    if (write_pos > 0) {
        buffer[write_pos-1] = '\0';
    } else {
        buffer[0] = '\0';
    }
    return ret;
}

/**
 * This function checks if a domain name is a covert channel.
 *
 * @param domain  the buffer containing the null terminated domain name
 * @return        is domain name a covert channel
 */
static bool is_dns_cc(const char *domain) {
    int anomalies = 0;
    size_t len = strlen(domain);
    // check for total domain name length
    if (len > CC_DNS_MAX_QUERY_LEN) {
        anomalies++;
    }
    int count = 0;
    int label_len = 0;
    int label_count = 1;
    char_type t = TYPE_NONE;
    for (size_t i = 0; i < len; ++i) {
        const uint8_t c = domain[i];
        // reinitialize everything on next label
        if (c == '.') {
            count = 0;
            t = TYPE_NONE;
            label_len = 0;
            label_count++;
            // check the number of labels
            if (label_count > CC_DNS_MAX_LABEL_COUNT) {
                anomalies++;
                // reset label_count to 1 to avoid incrementing anomalies on each subsequent label
                label_count = 1;
            }
            continue;
        }
        // check label size
        label_len++;
        if (label_len > CC_DNS_MAX_LABEL_LEN) {
            anomalies++;
            // reset label_len to 0 to avoid incrementing anomalies on each subsequent character
            label_len = 0;
        }
        // check if too many consecutive characters of same type
        if ((t == VOWEL && count > CC_DNS_MAX_VOWELS) ||
                (t == CONSONANT && count > CC_DNS_MAX_CONSONANTS) ||
                (t == DIGIT     && count > CC_DNS_MAX_DIGITS) ||
                (t == SPECIAL   && count > CC_DNS_MAX_SPECIALS)) {
            anomalies++;
            count = 0;
            t = TYPE_NONE;
        }
        // count consecutive characters of same type
        if (alphabet[c] == t) {
            count++;
        } else {
            count = 0;
            t = alphabet[c];
        }
    }
    return anomalies >= CC_DNS_ANOMALY_THRESHOLD;
}

/**
 * This function checks if a domain is in the whitelist. If this is the case, this domain
 * won't be detected as a covert channel even though it should.
 *
 * @param domain  the domain to check against the whitelist
 * @return        is the domain in the whitelist
 */
static bool is_in_dns_whitelist(const char *domain) {
    // nothing is whitelisted if there is no whitelist
    if (dns_whitelist == NULL || dns_whitelist_len == 0) {
        return false;
    }
    const size_t len = strlen(domain);
    // check domain against each entry in the whitelist
    for (size_t i = 0; i < dns_whitelist_len; ++i) {
        const char* const entry = dns_whitelist[i];
        const size_t entry_len = strlen(entry);
        if (entry_len > len) {
            continue;
        }
        // only compare the end of the domain
        if (strcasecmp(domain + len - entry_len, entry) == 0 &&
                (entry_len == len || domain[len-entry_len-1] == '.')) {
            return true;
        }
    }
    return false;
}

/**
 * @brief Load DNS whitelist from a file.
 *
 * @param  filename  path to the file containing the whitelist.
 * @return true if the whitelist could correctly be loaded; false otherwise.
 */
static bool load_dns_whitelist(const char *filename) {
    FILE *fp = fopen(filename, "r");
    if (fp == NULL) {
        T2_PERR(plugin_name, "couldn't open DNS whitelist file: %s", filename);
        return false;
    }

    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    size_t allocated = 8;
    if (!(dns_whitelist = t2_calloc(allocated, sizeof(*dns_whitelist)))) {
        T2_PERR(plugin_name, "failed to allocate memory for DNS whitelist");
        fclose(fp);
        return false;
    }

    while ((read = getline(&line, &len, fp)) != -1) {
        stripln(line, &read);
        if (read == 0 || line[0] == '%') {
            continue;
        }
        if (read > DNS_MAX_DOMAIN_LEN) {
            T2_PERR(plugin_name, "domain name in whitelist is longer than %d", DNS_MAX_DOMAIN_LEN);
            return false;
        }
        if (dns_whitelist_len >= allocated) {
            allocated *= 2;
            char **tmp;
            if (!(tmp = realloc(dns_whitelist, allocated * sizeof(*dns_whitelist)))) {
                T2_PERR(plugin_name, "failed to reallocate memory for DNS whitelist");
                free(dns_whitelist);
                free(line);
                fclose(fp);
                return false;
            }
            dns_whitelist = tmp;
        }
        dns_whitelist[dns_whitelist_len++] = strdup(line);
    }

    free(line);
    fclose(fp);
    return true;
}
#endif // CC_DETECT_DNS

#if CC_DETECT_ICMP_WL == 1
// ICMP whitelist
typedef struct {
    uint8_t *pattern;
    size_t length;
} ping_pattern;

static ping_pattern *ping_whitelist;
static size_t ping_whitelist_len = 0;

/**
 * @brief This function decodes an hex-encoded string.
 *
 * It assumes that the output buffer is at least length(input) / 2 bytes long.
 *
 * @param input    NULL terminated hex-encoded string
 * @param output   buffer to store the decoded bytes
 * @return         true on successful decoding, false on invalid hex-encoded input
 */
static bool hex_decode(const char *input, uint8_t *output) {
    size_t len = strlen(input);
    if (len % 2) {
        return false; // cannot decode half a byte
    }
    // parse the input two hex characters at a time
    for (size_t i = 0; i < len; i += 2) {
        if (sscanf(&input[i], "%02hhx", output++) != 1) {
            return false; // invalid hex characters
        }
    }
    return true;
}

#if CC_DEBUG != 0
/**
 * @brief This function encodes bytes to an hex string.
 *
 * It assumes that the output buffer is at least length(input) * 2 + 1 bytes long.
 *
 * @param input      bytes to hex-encode
 * @param input_len  number of bytes to hex-encode
 * @param output     buffer to store the encoded hex characters
 */
static void hex_encode(const uint8_t *input, size_t input_len, char *output) {
    // parse the input one byte at a time
    for (size_t i = 0; i < input_len; ++i) {
        sprintf(output, "%02" B2T_PRIX8, input[i]);
        output += 2;
    }
}
#endif // CC_DEBUG != 0

/**
 * This function checks if a PING pattern is in the whitelist.
 *
 * @param payload      the PING payload to check against the whitelist
 * @param payload_len  the length of the PING payload
 * @return             is the payload in the whitelist
 */
static bool is_in_ping_whitelist(const uint8_t *payload, size_t payload_len) {
    // nothing is whitelisted if there is no whitelist
    if (ping_whitelist == NULL || ping_whitelist_len == 0) {
        return false;
    }
    // check pattern against each entry in the whitelist
    for (size_t i = 0; i < ping_whitelist_len; ++i) {
        const ping_pattern * const pattern = &ping_whitelist[i];
        // min(payload_len, pattern->length)
        const size_t len = MIN(pattern->length, payload_len);
        // compare payload with pattern
        if (memcmp(payload, pattern->pattern, len) == 0) {
            return true;
        }
    }
    return false;
}

/**
 * @brief Load PING whitelist from a file.
 *
 * @param  filename  path to the file containing the whitelist.
 * @return true if the whitelist could correctly be loaded; false otherwise.
 */
static bool load_ping_whitelist(const char* filename) {
    FILE *fp = fopen(filename, "r");
    if (fp == NULL) {
        T2_PERR(plugin_name, "couldn't open PING whitelist file: %s", filename);
        return false;
    }

    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    size_t allocated = 8;
    if (!(ping_whitelist = t2_calloc(allocated, sizeof(*ping_whitelist)))) {
        T2_PERR(plugin_name, "failed to allocate memory for PING whitelist");
        fclose(fp);
        return false;
    }

    // read whitelist file line by line
    while ((read = getline(&line, &len, fp)) != -1) {
        stripln(line, &read);
        // skip comments and empty lines
        if (read == 0 || line[0] == '%') {
            continue;
        }
        // decode hex-encoded pattern
        uint8_t *pattern;
        if (!(pattern = t2_malloc(read / 2))) {
            T2_PERR(plugin_name, "failed to allocate buffer for hex decoding PING pattern");
            return false;
        }
        if (!hex_decode(line, pattern)) {
            T2_PERR(plugin_name, "invalid PING whitelist entry: %s", line);
            free(pattern);
            return false;
        }
        // reallocate whitelist if it is full
        if (ping_whitelist_len >= allocated) {
            allocated *= 2;
            ping_pattern *tmp;
            if (!(tmp = realloc(ping_whitelist, allocated * sizeof(*ping_whitelist)))) {
                T2_PERR(plugin_name, "failed to reallocate memory for PING whitelist");
                free(ping_whitelist);
                free(line);
                fclose(fp);
                return false;
            }
            ping_whitelist = tmp;
        }
        // store new pattern in whitelist
        ping_whitelist[ping_whitelist_len].pattern = pattern;
        ping_whitelist[ping_whitelist_len].length = read / 2;
        ping_whitelist_len++;
    }

    free(line);
    fclose(fp);
    return true;
}
#endif // CC_DETECT_ICMP_WL

#if CC_DETECT_IPID == 1
static float entropy(uint16_t* ipIds, uint64_t numPackets) {
    float sum = 0.0f;
    for (int i = 0; i < IP_ID_BUCKET_COUNT; i++) {
        float x = ((float) ipIds[i]) / numPackets;
        if (x) {
           sum += x * log2(x);
        }
    }
    return -sum / log2(IP_ID_BUCKET_COUNT);
}

#if IPV6_ACTIVATE != 1
static bool is_unicast(uint32_t ip) {
    // try to detect broadcast by checking that IP ends with .255
    // far from ideal, should be replaced if better method is found.
    if ((ip & 0x000000ff) == 0x000000ff) {
        return false;
    }
    // check for multicast addresses
    if ((ip & 0xf0000000) == 0xe0000000) { // 224.0.0.0/4
        return false;
    }
    return true;
}
#endif // IPV6_ACTIVATE != 1
#endif // CC_DETECT_IPID

#if CC_DETECT_RTP_TS == 1
/**
 * Apply linear regression and return RMSE
 */
static float rmse(uint64_t n, double sx, double sy, double sxx, double sxy, double syy) {
    double beta = (n * sxy - sx * sy) / (n * sx - sx * sx);
    //double alpha = (sy / n) - (sx * beta / n);
    return (n*syy - sy*sy - beta*beta * (n*sxx - sx*sx)) / (n*(n-2));
}
#endif // CC_DETECT_RTP_TS

#if CC_DETECT_HCOVERT == 1
/**
 * Determines the percentage of URL-encoded characters in an URL.
 *
 * @param url  the URL to analyze
 * @return     percentage of URL-encoded characters in URL
 * @retval -1  invalid URL-encoding
 */
static float url_encoded_ratio(const char *url) {
    size_t len = strlen(url);
    int encoded = 0;
    for (size_t i = 0; i < len; ++i) {
        // is character URL-encoded
        if (url[i] == '%') {
            // first check that there are enough characters left (long URLs can be truncated)
            if (i >= len - 2) {
                len = i + 1;
                break;
            }
            // valid URL-encoded characters are % followed by two hex digits
            if (isxdigit(url[i+1]) && isxdigit(url[i+2])) {
                encoded++;
                i += 2;
            } else {
                return -1;
            }
        }
    }
    return (float)encoded / (len - 2 * encoded);
}
#endif // CC_DETECT_HCOVERT


// Tranalyzer functions


void t2Init() {
    // allocate memory for all flows structs
    T2_PLUGIN_STRUCT_NEW(cc_flows);

#if (CC_DETECT_DNS | CC_DETECT_ICMP_WL) != 0
    // get the length of the plugin folder
    const size_t plen = pluginFolder_len;
#endif // (CC_DETECT_DNS | CC_DETECT_ICMP_WL) != 0
#if CC_DETECT_DNS == 1
    // get the path to the DNS whitelist
    const size_t dns_len = plen + sizeof(CC_DNS_WHITELIST_NAME);
    if (dns_len > MAX_FILENAME_LEN) {
        T2_PFATAL(plugin_name, "DNS whitelist path too long");
    }

    char dns_whitelist_path[dns_len];
    memcpy(dns_whitelist_path, pluginFolder, plen);
    memcpy(dns_whitelist_path + plen, CC_DNS_WHITELIST_NAME, sizeof(CC_DNS_WHITELIST_NAME));

    // load DNS whitelist
    if (!load_dns_whitelist(dns_whitelist_path)) {
        T2_PFATAL(plugin_name, "failed loading DNS whitelist %s", dns_whitelist_path);
    }
#endif // CC_DETECT_DNS == 1
#if CC_DETECT_ICMP_WL == 1
    // get the path to the DNS whitelist
    const size_t ping_len = plen + sizeof(CC_PING_WHITELIST_NAME);
    if (ping_len > MAX_FILENAME_LEN) {
        T2_PFATAL(plugin_name, "ping whitelist path too long");
    }

    char ping_whitelist_path[ping_len];
    memcpy(ping_whitelist_path, pluginFolder, plen);
    memcpy(ping_whitelist_path + plen, CC_PING_WHITELIST_NAME, sizeof(CC_PING_WHITELIST_NAME));

    // load ping whitelist
    if (!load_ping_whitelist(ping_whitelist_path)) {
        T2_PFATAL(plugin_name, "failed loading ping whitelist %s", ping_whitelist_path);
    }
#endif // CC_DETECT_ICMP_WL == 1
}


binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;
    BV_APPEND_H16(bv, "covertChannels", "Detected covert channels");
    return bv;
}


void t2OnNewFlow(packet_t* packet UNUSED, unsigned long flowIndex) {
    cc_flow_t * const cc_flow = &cc_flows[flowIndex];
    memset(cc_flow, 0, sizeof(*cc_flow)); // set everything to 0
}


void t2OnLayer4(packet_t* packet, unsigned long flowIndex) {
#if CC_DETECT_DNS    != 0 || CC_DETECT_ICMP    != 0 || \
    CC_DETECT_DEVCC  != 0 || CC_DETECT_HCOVERT != 0 || \
    CC_DETECT_RTP_TS != 0 || CC_DETECT_SKYDE   != 0 || \
    (CC_DETECT_IPID  != 0 && IPV6_ACTIVATE != 1)
    cc_flow_t *cc_flow = &cc_flows[flowIndex];
#else
    // Silence -Wundef warnings
    (void)packet;
    (void)flowIndex;
#endif

#if CC_DETECT_DNS != 0 || (CC_DETECT_IPID != 0 && IPV6_ACTIVATE != 1) || \
    (CC_DEBUG != 0 && (CC_DETECT_HCOVERT != 0 || CC_DETECT_ICMP_WL != 0))
    const flow_t * const flowP = &flows[flowIndex];
#endif

#if (CC_DETECT_DNS | CC_DETECT_HCOVERT) != 0 || (CC_DETECT_ICMP_WL == 1 && CC_DEBUG != 0)
    // temporary buffer to store the DNS name / http URL / hex-encoded ping payload
    char buffer[BUFFER_LEN];
#endif // (CC_DETECT_DNS | CC_DETECT_HCOVERT) != 0 || (CC_DETECT_ICMP_WL == 1 && CC_DEBUG != 0)

#if CC_DETECT_DNS == 1
    // check DNS packets. Description of DNS packet format:
    // https://tools.ietf.org/html/rfc1035
    // http://www.ccs.neu.edu/home/amislove/teaching/cs4700/fall09/handouts/project1-primer.pdf
    if (!(cc_flow->detected_cc & CC_BITMASK(CC_DNS)) &&
            (flowP->dstPort == 53 || flowP->srcPort == 53) && packet->snapL7Len > 22) {
        const uint16_t *dns_header = (uint16_t*)packet->l7HdrP;
        uint16_t dns_len = packet->snapL7Len;
        // DNS over TCP is prefixed by a two bytes length
        if (packet->l4Proto == L3_TCP) {
            dns_header++;
            dns_len -= 2;
        }
        uint16_t offset = 12; // skip header
        bool parse = true; // used to stop parsing DNS (break out of both loop)
        // for now we just decode domains in QUERY and IQUERY messages
        const uint16_t opcode = (ntohs(dns_header[1]) & DNS_OPCODE_MASK) >> 11;
        if (opcode != DNS_TYPE_QUERY && opcode != DNS_TYPE_IQUERY) {
            parse = false;
            // detect non DNS traffic on port 53
            const uint16_t qdcount = ntohs(dns_header[DNS_QUESTION+2]);
            const uint16_t ancount = ntohs(dns_header[DNS_ANSWER_RR+2]);
            if (qdcount > 10 || (ancount > 0 && qdcount > ancount)) {
                debug_print("Flow %" PRIu64 ": non DNS traffic on port 53", flowP->findex);
                cc_flow->detected_cc |= CC_BITMASK(CC_DNS);
            }
        }
        // for each section
        for (dns_section section = DNS_QUESTION; section <= DNS_ADDITIONAL_RR && parse && offset < dns_len; section++) {
            // for each query / answer in this section
            for (int i = 0; i < ntohs(dns_header[section+2]) && offset < dns_len; ++i) {
                int len = parse_domain((const uint8_t*)dns_header, offset, dns_len, buffer);
                if (len < 0) {
                    if (len == -1) {
                        debug_print("Flow %" PRIu64 ": invalid DNS packet", flowP->findex);
                        cc_flow->detected_cc |= CC_BITMASK(CC_DNS);
                #if CC_DEBUG != 0
                    } else if (len == -2) {
                        debug_print("Flow %" PRIu64 ": snapped DNS packet", flowP->findex);
                #endif // CC_DEBUG != 0
                    }
                    parse = false; // invalid or snapped DNS packet => stop parsing
                    break;
                }
                // skip the domain name
                offset += len;
                // check if domain name is a covert channel
                if (is_dns_cc(buffer) && !is_in_dns_whitelist(buffer)) {
                    debug_print("Flow %" PRIu64 ": CC domain: %s", flowP->findex, buffer);
                    cc_flow->detected_cc |= CC_BITMASK(CC_DNS);
                    parse = false;
                    break;
                }
                // skip the other fields after the domain name
                if (section == DNS_QUESTION) {
                    offset += 4;
                } else {
                    // skip the RDATA field of RDLENGTH bytes
                    if (offset + 10 <= dns_len) {
                        const uint16_t rd_len = *(uint16_t*)((uint8_t*)dns_header + offset + 8);
                        offset += rd_len + 10;
                    } else {
                        parse = false; // DNS payload is snapped
                        break;
                    }
                }
            }
        }
    }
#endif // CC_DETECT_DNS == 1

#if CC_DETECT_ICMP != 0
    if (packet->l4Proto == L3_ICMP && packet->snapL4Len >= 2) {
        const icmpHeader_t *icmp_header = ICMP_HEADER(packet);
        // is it a PING packet?
        if (icmp_header->code == 0 && (icmp_header->type == ICMP_ECHO || icmp_header->type == ICMP_ECHOREPLY)) {
        #if CC_DETECT_ICMP_ASYM == 1
            // byte counter used to determine flow asymmetry (from layer 4)
            cc_flow->icmp_count += packet->l2Len - packet->l2HdrLen - packet->l3HdrLen;
        #endif // CC_DETECT_ICMP_ASYM == 1
        #if CC_DETECT_ICMP_WL == 1
            // PING whitelist needs at least 28 bytes: skip first 24 ones and compare next 4 ones or more
            if (packet->snapL4Len >= 28 && !(cc_flow->detected_cc & CC_BITMASK(CC_ICMP_WL))) {
                const uint8_t* const ping_payload = (uint8_t*)packet->l4HdrP + 24;
                // check this pattern against the PING whitelist
                size_t payload_len = packet->snapL4Len - 24;
                if (!is_in_ping_whitelist(ping_payload, payload_len)) {
                #if CC_DEBUG != 0
                    payload_len = MIN(payload_len, (BUFFER_LEN - 1) / 2);
                    hex_encode(ping_payload, payload_len, buffer);
                    debug_print("Flow %" PRIu64 ": invalid PING pattern: %s", flowP->findex, buffer);
                #endif // CC_DEBUG != 0
                    cc_flow->detected_cc |= CC_BITMASK(CC_ICMP_WL);
                }
            }
        #endif // CC_DETECT_ICMP_WL == 1
        } else {
        #if CC_DETECT_ICMP_NP == 1
            // only PING flows should have multiple ICMP packets
            cc_flow->non_ping_count++;
        #endif // CC_DETECT_ICMP_NP == 1
        }
    }
#endif // CC_DETECT_ICMP != 0

#if IPV6_ACTIVATE != 1 && CC_DETECT_IPID == 1
    if (PACKET_IS_IPV4(packet) && !cc_flow->ignore_ipid) {
        // ignore broadcast and multicast flows
        if (!FLOW_HAS_OPPOSITE(flowP)) {
            const uint32_t dst_ip = ntohl(flowP->dstIP.IPv4.s_addr);
            if (!is_unicast(dst_ip)) {
                cc_flow->ignore_ipid = true;
            }
        }
        const ipHeader_t * const ipHeaderP = IPV4_HEADER(packet);
        if (packet->snapL3Len >= 8  && (ipHeaderP->ip_id || !(ntohs(ipHeaderP->ip_off) & IP_DF))) {
            const uint16_t currentIpId = ntohs(ipHeaderP->ip_id);
            const uint16_t currentCount = cc_flow->ipIds[currentIpId % IP_ID_BUCKET_COUNT];
            // to avoid IP ID count rollover
            cc_flow->ipIds[currentIpId % IP_ID_BUCKET_COUNT] = MAX(currentCount, currentCount+1);
            if (ipHeaderP->ip_id == 0) // ntohs(0) == 0
                cc_flow->nullIpIds++;
            cc_flow->ipIdCount++;
        }
    }
#endif // IPV6_ACTIVATE != 1 && CC_DETECT_IPID == 1


#if CC_DETECT_DEVCC == 1
    if (packet->l4Proto == L3_TCP && packet->snapL4Len > 20) { // if L4 is TCP
        int tcpOptLen = packet->l4HdrLen - 20;
        if (tcpOptLen > 0) {
            uint8_t* tcpOpt = (uint8_t*)packet->l4HdrP + 20;
            for (int i = 0; i < tcpOptLen && tcpOpt[i] > 0; i += MAX(tcpOpt[i], 1)) {
                if (tcpOpt[i] == 8) {
                    if (tcpOpt[i+5] & 0x1) cc_flow->timestamp1++;
                    else cc_flow->timestamp0++;
                }

                if (tcpOpt[i+1] == 0) break;
            }
        }
    }
#endif // CC_DETECT_DEVCC

#if CC_DETECT_HCOVERT == 1
    // detect hcovert (data URL-encoded in HTTP GET request)
    // 16 bytes is the size of "GET / HTTP/1.1\r\n"
    if (packet->l4Proto == L3_TCP && !(cc_flow->detected_cc & CC_BITMASK(CC_HCOVERT)) &&
            packet->snapL7Len >= CC_HC_MIN_URL_LEN + 16) {
        const char *http_header = (const char*)packet->l7HdrP;
        // check that the packet start with "GET " == 0x47455420
        if (ntohl(*(uint32_t*)http_header) == 0x47455420) {
            // copy URL in buffer
            size_t i = 0;
            while (i + 4 < packet->snapL7Len && i < BUFFER_LEN - 1 &&
                    http_header[i + 4] != ' ' && http_header[i + 4] != '\0')
            {
                buffer[i] = http_header[i + 4];
                i++;
            }
            buffer[i] = '\0';
            // compute the ratio of URL-encoded characters in the URL
            const float ratio = url_encoded_ratio(buffer);
            if (ratio < 0) {
                debug_print("Flow %" PRIu64 ": invalid URL-encoding: %s", flowP->findex, buffer);
            } else if (ratio > CC_HC_MAX_RATIO) {
                debug_print("Flow %" PRIu64 ": URL-encoded ratio: %.02f; URL: %s", flowP->findex,
                        ratio, buffer);
                cc_flow->detected_cc |= CC_BITMASK(CC_HCOVERT);
            }
        }
    }
#endif // CC_DETECT_HCOVERT

#if (CC_DETECT_RTP_TS | CC_DETECT_SKYDE) != 0
    struct timeval pcapTs = packet->pcapHdrP->ts;
    double pktTime = pcapTs.tv_sec + pcapTs.tv_usec / 1000000.0;
#endif // (CC_DETECT_RTP_TS | CC_DETECT_SKYDE) != 0

#if CC_DETECT_RTP_TS == 1
    if (packet->l4Proto == L3_UDP) {
        const udpHeader_t * const udpHeaderP = UDP_HEADER(packet);
        // TODO: find better way to identify RTP streams
        if (ntohs(udpHeaderP->dest) == 4000) {
            uint32_t ts = ntohl(*((uint32_t*) (packet->l7HdrP + 4)));
            if (cc_flow->rtpCount == 0) {
                cc_flow->xShift = pktTime;
                cc_flow->yShift = ts;
            }
            pktTime -= cc_flow->xShift;
            ts -= cc_flow->yShift;
            // https://en.wikipedia.org/wiki/Simple_linear_regression#Numerical_example
            cc_flow->sx += pktTime;
            cc_flow->sy += ts;
            cc_flow->sxx += pktTime * pktTime;
            cc_flow->sxy += pktTime * ts;
            cc_flow->syy += ts * ts;
            cc_flow->rtpCount++;
        }
    }
#endif // CC_DETECT_RTP_TS

#if CC_DETECT_SKYDE == 1
    if (packet->l4Proto == L3_UDP && packet->snapL7Len > 12 && (packet->l7HdrP[2] & 0x8f) == 0x0d) {
        //if (!cc_flow->initialized) {
            //cc_flow->silentPkts = list2_new(SKYDE_W * SKYDE_MAX_PACKET_RATE);
            //cc_flow->initialize = 1;
            const double deltaT = pktTime - cc_flow->lastPkt;
            if (deltaT > 0.0 && cc_flow->lastPkt != 0.0) {
                cc_flow->ipdAvg += (deltaT - cc_flow->ipdAvg) / ++cc_flow->skypeCount;
                debug_print("deltaT = %f ; new average = %f", deltaT, cc_flow->ipdAvg);

            }
            cc_flow->lastPkt = pktTime;
        //}
    }
#endif // CC_DETECT_SKYDE
}


void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {
    cc_flow_t * const cc_flow = &cc_flows[flowIndex];

#if CC_DETECT_ICMP_NP != 0 || CC_DETECT_ICMP_ASYM != 0 || CC_DETECT_SKYDE != 0 || \
    (CC_DEBUG != 0 && (CC_DETECT_DEVCC != 0 || CC_DETECT_IPID != 0 || CC_DETECT_RTP_TS != 0))
    const flow_t * const flowP = &flows[flowIndex];
#endif

#if (CC_DETECT_ICMP_NP | CC_DETECT_ICMP_ASYM) != 0
    // check if ICMP flow and there exist an opposite flow
    if (flowP->l4Proto == L3_ICMP && FLOW_HAS_OPPOSITE(flowP)) {
        cc_flow_t *cc_opposite_flow = &cc_flows[flowP->oppositeFlowIndex];
    #if CC_DETECT_ICMP_ASYM == 1
        const uint64_t total = cc_flow->icmp_count + cc_opposite_flow->icmp_count;
        const double ratio = ((double) cc_flow->icmp_count) / total;
        if (total > CC_ICMP_ASYM_MIN_BYTES && fabs(ratio - 0.5) > CC_ICMP_ASYM_MAX_DEV) {
            debug_print("Flow %" PRIu64 ": ICMP ratio: %.02f", flowP->findex, ratio);
            cc_flow->detected_cc |= CC_BITMASK(CC_ICMP_ASYM);
        }
    #endif // CC_DETECT_ICMP_ASYM == 1
    #if CC_DETECT_ICMP_NP == 1
        // also check for bidirectional non-ping flows
        if (cc_flow->non_ping_count > 0 && cc_opposite_flow->non_ping_count > 0) {
            debug_print("Flow %" PRIu64 ": bidirectional non-PING ICMP flow", flowP->findex);
            cc_flow->detected_cc |= CC_BITMASK(CC_ICMP_NP);
        }
    #endif // CC_DETECT_ICMP_NP == 1
    }
#endif // (CC_DETECT_ICMP_NP | CC_DETECT_ICMP_ASYM) != 0

#if CC_DETECT_DEVCC == 1
    const uint64_t total = cc_flow->timestamp0 + cc_flow->timestamp1;
    if (total > CC_DEVCC_MIN_PACKETS) {
        const double ratio = ((double) cc_flow->timestamp1) / total;
        if (fabs(ratio - 0.5) > CC_DEVCC_MAX_DEV) {
            debug_print("Flow %" PRIu64 ": TCP timestamp ratio: %.02f with %" PRIu64 " packets",
                    flowP->findex, ratio, total);
            cc_flow->detected_cc |= CC_BITMASK(CC_DEVCC);
        }
    }
#endif // CC_DETECT_DEVCC

#if CC_DETECT_IPID == 1
    // last condition avoids false positives with Dropbox Lan Sync
    // and some P2P applications which set all IPIDs to 0
    if (!cc_flow->ignore_ipid && cc_flow->ipIdCount > IP_ID_BUCKET_COUNT &&
        cc_flow->nullIpIds != cc_flow->ipIdCount) {
        const float e = entropy(cc_flow->ipIds, cc_flow->ipIdCount);
        // detects if IPIDs are too unevenly distributed
        if (e < 0.6 || (cc_flow->ipIdCount > 2*IP_ID_BUCKET_COUNT && e < 0.8)) {
            debug_print("Flow %" PRIu64 ": IPID entropy = %f", flowP->findex, e);
            cc_flow->detected_cc |= CC_BITMASK(CC_IPID);
        }
    }
#endif // CC_DETECT_IPID

#if CC_DETECT_RTP_TS == 1
    const double rtpRmse = rmse(cc_flow->rtpCount, cc_flow->sx, cc_flow->sy, cc_flow->sxx, cc_flow->sxy, cc_flow->syy);
    // TODO: find a threshold which minimizes false positives
    if (rtpRmse > 0.0) {
        debug_print("Flow %" PRIu64 ": RTP RMSE = %f", flowP->findex, rtpRmse);
        cc_flow->detected_cc |= CC_BITMASK(CC_RTP_TS);
    }
#endif // CC_DETECT_RTP_TS

#if CC_DETECT_SKYDE == 1
    if (flowP->l4Proto == L3_UDP && FLOW_HAS_OPPOSITE(flowP) && cc_flow->skypeCount > 1000) {
        const double otherIpdAvg = cc_flows[flowP->oppositeFlowIndex].ipdAvg;
        const double avgDelta = fabs(otherIpdAvg - cc_flow->ipdAvg);
        // TODO: find threshold -> this method does NOT work!
        if (avgDelta > 0.0f) {
            debug_print("Flow %" PRIu64 ": Skype delta IPD = %f", flowP->findex, avgDelta);
            cc_flow->detected_cc |= CC_BITMASK(CC_SKYDE);
        }
    }
#endif // CC_DETECT_SKYDE

    covertChannels |= cc_flow->detected_cc;

    // output covertChannels column
    OUTBUF_APPEND_U16(buf, cc_flow->detected_cc);

    // https://graphics.stanford.edu/~seander/bithacks.html#CountBitsSetKernighan
    uint16_t copy = cc_flow->detected_cc;
    while (copy) {
        ++cc_count;
        copy &= copy - 1; // clear the least significant bit set
    }
}


void t2PluginReport(FILE *stream) {
    if (cc_count) {
        T2_FPLOG_AGGR_HEX(stream, plugin_name, covertChannels);
        T2_FPLOG_NUM(stream, plugin_name, "Number of covert channels", cc_count);
    }
}


void t2Finalize() {
    // free flow structs
    free(cc_flows);
    cc_flows = NULL;

#if CC_DETECT_DNS == 1
    // free DNS whitelist
    for (size_t i = 0; i < dns_whitelist_len; ++i) {
        free(dns_whitelist[i]);
    }
    free(dns_whitelist);
#endif // CC_DETECT_DNS == 1

#if CC_DETECT_ICMP_WL == 1
    // free ping whitelist
    for (size_t i = 0; i < ping_whitelist_len; ++i) {
        free(ping_whitelist[i].pattern);
    }
    free(ping_whitelist);
#endif // CC_DETECT_ICMP_WL == 1
}
