/*
 * torDetector.c
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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE // for strptime
#endif // _GNU_SOURCE

#include "torDetector.h"

#include "t2Plugin.h"
#include "memdebug.h"
#include "t2buf.h"

#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <regex.h>

#if TOR_DETECT_OBFUSCATION == 1
#include <math.h>
#include "tcpFlags.h"
#endif // TOR_DETECT_OBFUSCATION


#define TOR_DEBUG (DEBUG | TOR_DEBUG_MESSAGES)


// macros to print messages only in message debug mode
#if TOR_DEBUG != 0
#define debug_print(format, args...) T2_PINF(plugin_name, format, ##args)
#else // TOR_DEBUG == 0
#define debug_print(format, args...)
#endif // TOR_DEBUG != 0


// static variables
static uint32_t torCount;
static regex_t subject_re;
static regex_t issuer_re;
static regex_t sni_re;
#define BASE32_CHARS "abcdefghijklmnopqrstuvwxyz234567"
static const char * const subject_re_str = "^www\\.[" BASE32_CHARS "]{8,20}\\.net$";
static const char * const issuer_re_str  = "^www\\.[" BASE32_CHARS "]{8,20}\\.(net|com)$";
static const char * const sni_re_str = "^www\\.[" BASE32_CHARS "]{4,25}\\.com$";

#if TOR_SPLIT_BITFIELD == 0
static uint8_t torStat;
#endif


// variable from tcpFlags plugin
#if TOR_DETECT_OBFUSCATION == 1
extern tcpFlagsFlow_t *tcpFlagsFlows __attribute__((weak));
#endif // TOR_DETECT_OBFUSCATION


// plugin variables
torFlow_t *torFlows;


// helper functions


#if TOR_DETECT_OBFUSCATION == 1
static double entropy(uint8_t buckets[256], size_t elem_count) {
    double sum = 0.0f;
    for (int i = 0; i < 256; ++i) {
        double x = ((double) buckets[i]) / elem_count;
        if (x) {
           sum += x * log2(x);
        }
    }
    return -sum / 8.0;
}
#endif // TOR_DETECT_OBFUSCATION


/**
 * Converts a certificate ASN1 date to a tm struct
 */
static bool asn1_time_convert(ASN1_TIME *time, struct tm *tm) {
    if (time->type == V_ASN1_UTCTIME && time->length == 13 && time->data[12] == 'Z') {
        if (!strptime((const char *)time->data, "%y%m%d%H%M%SZ", tm)) {
            return false;
        }
    } else if (time->type == V_ASN1_GENERALIZEDTIME && time->length == 15 && time->data[14] == 'Z') {
        if (!strptime((const char *)time->data, "%Y%m%d%H%M%SZ", tm)) {
            return false;
        }
    } else {
        /* Invalid ASN.1 time */
        return false;
    }
    return true;
}


/**
 * Detect if server -> client flow is using Tor (based on certificate content)
 */
static bool is_tor(sslCert_t *cert, uint32_t cert_len) {
    // Tor sometimes sends multiple certificates, but always short ones
    if (cert_len > TOR_MAX_CERT_LEN) {
        return false;
    }
    // Tor certificate are RSA 1024 bits (switched to RSA 2048 bits in 2017/2018)
    if ((cert->pkey_size != 1024 && cert->pkey_size != 2048) || strcmp(cert->pkey_type, "RSA") != 0) {
        return false;
    }
    // check the validity period
    uint64_t validity_start = timegm(&cert->cert_not_before);
    uint64_t validity_end = timegm(&cert->cert_not_after);
    // validity must start at midnight (since ~ 2013)
    // validity must be exactly one year (until ~ 2013)
    if (validity_start % (24 * 3600) != 0 && (validity_end - validity_start) != (365 * 24 * 60 * 60)) {
        return false;
    }
    // check that cert is not self signed
    if (strcmp(cert->sCommon, cert->iCommon) == 0) {
        return false;
    }
    // check the format of the subject and the issuer
    if (strlen(cert->sOrg) != 0 || strlen(cert->iOrg) != 0 || strlen(cert->sCountry) != 0 ||
            strlen(cert->iCountry) != 0 || regexec(&subject_re, cert->sCommon, 0, NULL, 0) ||
            regexec(&issuer_re, cert->iCommon, 0, NULL, 0)) {
        return false;
    }
    // if all checks pass, this is probably a Tor flow
    return true;
}


// Tranalyzer functions

T2_PLUGIN_INIT_WITH_DEPS("torDetector", "0.9.3", 0, 9,
#if TOR_DETECT_OBFUSCATION == 1
    "tcpFlags"  // in order to detect dropped packets
#else // TOR_DETECT_OBFUSCATION == 0
    ""
#endif // TOR_DETECT_OBFUSCATION == 0
);


void t2Init() {
    T2_PLUGIN_STRUCT_NEW(torFlows);

    if (UNLIKELY(regcomp(&subject_re, subject_re_str, REG_EXTENDED|REG_NOSUB) != 0)) {
        T2_PERR(plugin_name, "Failed to compile subject regex");
        free(torFlows);
        exit(EXIT_FAILURE);
    }

    if (UNLIKELY(regcomp(&issuer_re, issuer_re_str, REG_EXTENDED|REG_NOSUB) != 0)) {
        T2_PERR(plugin_name, "Failed to compile issuer regex");
        free(torFlows);
        exit(EXIT_FAILURE);
    }

    if (UNLIKELY(regcomp(&sni_re, sni_re_str, REG_EXTENDED|REG_NOSUB) != 0)) {
        T2_PERR(plugin_name, "Failed to compile request regex");
        free(torFlows);
        exit(EXIT_FAILURE);
    }

    if (sPktFile) fputs("torStat" SEP_CHR, sPktFile);
}


binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;
    BV_APPEND_H8(bv, "torStat", "Tor status");
    return bv;
}


void t2OnNewFlow(packet_t* packet UNUSED, unsigned long flowIndex) {
    torFlow_t *torFlowP = &torFlows[flowIndex];
    memset(torFlowP, 0, sizeof(torFlow_t));
#if TOR_PKTL == 1
    torFlowP->minL3PktSz = UINT16_MAX;
#endif // TOR_PKTL == 1
    if (flows[flowIndex].status & TORADD) torFlowP->stat |= TOR_STAT_ADDR;
}


#if ETH_ACTIVATE > 0
void t2OnLayer2(packet_t *packet UNUSED, unsigned long flowIndex UNUSED) {
    if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;
    if (sPktFile) fputs("0x00" /* torStat */ SEP_CHR, sPktFile);
}
#endif // ETH_ACTIVATE > 0


void t2OnLayer4(packet_t* packet, unsigned long flowIndex) {
    flow_t *flowP = &flows[flowIndex];

    torFlow_t *torFlowP = &torFlows[flowIndex];
    const uint_fast8_t proto = flowP->l4Proto;
    if (proto != L3_TCP && proto != L3_UDP && proto != L3_SCTP) goto nxtpkt;

#if TOR_DETECT_OBFUSCATION == 1
    if (!(torFlowP->stat & TOR_STAT_OBFCHK)) {
        // only try to detect obfuscation in TCP flows where we have the first packets
        if (!(torFlowP->stat & TOR_STAT_SYN)) {
            if (proto != L3_TCP || !(TCP_HEADER(packet)->flags & TH_SYN)) torFlowP->stat |= TOR_STAT_OBFCHK;
            else torFlowP->stat |= TOR_STAT_SYN;
        }
        // stop detection if packets where dropped during the first bytes
        tcpFlagsFlow_t *tcpFlow = &tcpFlagsFlows[flowIndex];
        if (tcpFlow->tcpAnomaly & TCP_SEQ_PLSSMS) torFlowP->stat |= TOR_STAT_OBFCHK;
    }
#endif // TOR_DETECT_OBFUSCATION

    const size_t remaining = packet->snapL7Len;
    if (remaining == 0) goto nxtpkt; // No payload

    // only 1. frag packet will be processed
    if (!t2_is_first_fragment(packet)) goto nxtpkt;

    uint8_t* const rp = (uint8_t* const)packet->l7HdrP;

    // build t2buf_t
    t2buf_t t2buf = t2buf_create(rp, remaining);

#if TOR_DETECT_OBFUSCATION == 1
    // TODO: stop obfuscation if packet are dropped, currently this creates false positives
    // when we have syn -> dropped certificate packets ->
    if (!(torFlowP->stat & TOR_STAT_OBFCHK)) {
        for (size_t i = 0; i < remaining; ++i) {
            uint8_t byte = rp[i];
            if (torFlowP->byte_count + i > TOR_OBFUSC_BYTES || torFlowP->bytes[byte] == UINT8_MAX) {
                double e = entropy(torFlowP->bytes, torFlowP->byte_count + i);
                if (e > TOR_OBFUSC_THRESHOLD) {
                    debug_print("Flow %" PRIu64 ": entropy: %f", flowP->findex, e);
                    torFlowP->stat |= TOR_STAT_OBFUSC;
                }
                torFlowP->stat |= TOR_STAT_OBFCHK;
                break;
            }
            torFlowP->bytes[byte]++;
        }
        torFlowP->byte_count += remaining;
    }
#endif // TOR_DETECT_OBFUSCATION

#if TOR_PKTL == 1
    if (flowP->srcPort == 443 || flowP->dstPort == 443) {
        const uint16_t ipLength = packet->len % 8;
        if (ipLength) {
            torFlowP->minL3PktSz = MIN(ipLength, torFlowP->minL3PktSz);
            torFlowP->maxL3PktSz = MAX(ipLength, torFlowP->maxL3PktSz);
        }
    }
#endif // TOR_PKTL == 1

    const unsigned long oppositeFlowIndex = flowP->oppositeFlowIndex;

    while (t2buf_left(&t2buf) > 0) {
        if (t2buf_left(&t2buf) < SSL_RT_HDR_LEN) goto nxtpkt;

        // record header:
        //   type(8), version(16: major(8), minor(8))
        //   if type==DTLS: epoch(16), seqnum(48)
        //   len(16)

        // SSL Record
        sslRecordHeader_t rec;

        TOR_READ_U8(&t2buf, &rec.type);
        // stop if invalid record type
        if (!SSL_RT_IS_VALID(rec.type)) goto nxtpkt;

        // check version
        TOR_READ_U16(&t2buf, &rec.version);
        if (SSL_V_IS_DTLS(rec.version)) {
            TOR_SKIP_U16(&t2buf); // epoch
            TOR_SKIP_U48(&t2buf); // seqnum
        } else if (!SSL_V_IS_SSL(rec.version)) {
            // invalid version... probably not ssl
            goto nxtpkt;
        } else if (proto == L3_UDP || proto == L3_SCTP) {
            goto nxtpkt;
        }

        // record length
        TOR_READ_U16(&t2buf, &rec.len);

        // invalid length
        if (rec.len > SSL_RT_MAX_LEN) goto nxtpkt;

        int64_t leftAtRecordStart = t2buf_left(&t2buf); // backup of bytes left at start of record

        switch (rec.type) {

            case SSL_RT_HANDSHAKE: {
                sslHandshake_t handshake;
                TOR_READ_U8(&t2buf, &handshake.type);
                TOR_READ_U24(&t2buf, &handshake.len);

                if (SSL_V_IS_DTLS(rec.version)) {
                    TOR_SKIP_U16(&t2buf); // message_seq
                    TOR_SKIP_U24(&t2buf); // fragment_offset
                    TOR_SKIP_U24(&t2buf); // fragment_length
                }

                bool client_hello = true;

                switch (handshake.type) {

                    case SSL_HT_SERVER_HELLO:
                        client_hello = false;
                        /* FALLTHRU */
                    case SSL_HT_CLIENT_HELLO: {
                        bool cipher_empty_renegotiation = false;
                        bool non_tor_ext = false;
                        char server_name[SSL_SNI_MAX_LEN+1];
                        memset(&server_name, 0, SSL_SNI_MAX_LEN+1);

                        uint16_t version;
                        TOR_READ_U16(&t2buf, &version);
                        if (!SSL_V_IS_VALID(version)) {
                            // invalid version... message probably encrypted
                            TOR_SKIP_N(&t2buf, handshake.len);
                            break;
                        }
                        TOR_SKIP_N(&t2buf, SSL_HELLO_RANDOM_LEN); // skip random
                        uint8_t session_len;
                        TOR_READ_U8(&t2buf, &session_len);
                        TOR_SKIP_N(&t2buf, session_len); // skip session_id
                        if (client_hello) {
                            if (SSL_V_IS_DTLS(rec.version)) {
                                // TODO cookie MUST be 0 if message is not a reply to a hello_verify_request
                                TOR_SKIP_U32(&t2buf); // cookie
                            }
                            uint16_t cipher_len;
                            TOR_READ_U16(&t2buf, &cipher_len);
                            // Tor cipherlist (extracted from Firefox source code) has between 15 and 18
                            // ciphers for any recent version. Old versions (2015-2016) had up to 24 ciphers.
                            // Use a +- 3 margin for older / newer versions.
                            cipher_len /= sizeof(uint16_t);  // number of ciphers
                            if (cipher_len < 12 || cipher_len > 27) {
                                break;
                            }
                            // Tor client always sets TLS_EMPTY_RENEGOTIATION_INFO_SCSV as the last cipher
                            // in the list
                            TOR_SKIP_N(&t2buf, (cipher_len - 1) * sizeof(uint16_t));
                            uint16_t cipher;
                            TOR_READ_U16(&t2buf, &cipher);
                            if (cipher == TLS_EMPTY_RENEGOTIATION_INFO_SCSV) {
                                cipher_empty_renegotiation = true;
                            }
                        } else {
                            TOR_SKIP_U16(&t2buf); // skip chosen cipher suite
                        }
                        // skip compression info
                        uint8_t comp_len;
                        TOR_READ_U8(&t2buf, &comp_len);
                        TOR_SKIP_N(&t2buf, comp_len);

                        // Hello extensions?
                        if (rec.len - (leftAtRecordStart - t2buf_left(&t2buf)) <= 0) {
                            break; // no extension(s)
                        }

                        TOR_SKIP_U16(&t2buf); // ignore size of extensions

                        while (handshake.len - (leftAtRecordStart - t2buf_left(&t2buf)) > 0) {
                            uint16_t ext_type, ext_len;
                            TOR_READ_U16(&t2buf, &ext_type);
                            TOR_READ_U16(&t2buf, &ext_len);
                            switch (ext_type) {
                                case SSL_HT_HELLO_EXT_SERVER_NAME: {
                                    if (ext_len == 0) {
                                        break;
                                    }
                                    // skip server name list length
                                    TOR_SKIP_U16(&t2buf);
                                    uint8_t hostname;
                                    TOR_READ_U8(&t2buf, &hostname);
                                    if (hostname) { // skip type (only HOST_NAME (0) is valid)
                                        break;
                                    }
                                    uint16_t sNameLen;
                                    TOR_READ_U16(&t2buf, &sNameLen);
                                    TOR_READ_N(&t2buf, (uint8_t *)server_name, MIN(sNameLen, SSL_SNI_MAX_LEN));
                                    break;
                                }
                                // RENEG_INFO can only be set in server hello
                                case SSL_HT_HELLO_EXT_RENEG_INFO:
                                    if (client_hello) {
                                        non_tor_ext = true;
                                    }
                                    TOR_SKIP_N(&t2buf, ext_len);
                                    break;
                                // ALPN/NPN extensions are never set in Tor
                                case SSL_HT_HELLO_EXT_ALPN:
                                case SSL_HT_HELLO_EXT_NPN:
                                    non_tor_ext = true;
                                     /* FALLTHRU */
                                default:
                                    TOR_SKIP_N(&t2buf, ext_len);
                                    break;
                            }
                        }

                        if (client_hello && cipher_empty_renegotiation && !non_tor_ext &&
                                regexec(&sni_re, server_name, 0, NULL, 0) == 0) {
                            torFlowP->stat |= TOR_STAT_TOR;
                            debug_print("Flow %" PRIu64 ": client Tor flow detected!", flowP->findex);
                        } else if (!client_hello && non_tor_ext && oppositeFlowIndex != HASHTABLE_ENTRY_NOT_FOUND) {
                            // server hello with non-tor extensions -> make sure opposite flow is not marked as Tor
                            torFlows[oppositeFlowIndex].stat &= ~TOR_STAT_TOR;
                        }

                        break;
                    }

                    case SSL_HT_CERTIFICATE: {
                        TOR_SKIP_U24(&t2buf); // skip the length of all certificates

                        uint32_t cert_len;
                        TOR_READ_U24(&t2buf, &cert_len);  // read the length of first certificate

                        // decode certificate
                        uint8_t const *crt_start = t2buf.buffer + t2buf.pos;
                        uint8_t const * const crt_start_backup = crt_start;
                        X509 *x509Cert = d2i_X509(NULL, (const unsigned char**)&crt_start, MIN(cert_len, t2buf_left(&t2buf)));
                        // skip in t2buf bytes which were read by d2i_X509
                        TOR_SKIP_N(&t2buf, crt_start - crt_start_backup);
                        if (!x509Cert) {
                            debug_print("Flow %" PRIu64 ": truncated or invalid certificate", flowP->findex);
                            break;
                        }
                        // plugin specific certificate structure
                        sslCert_t cert;
                        memset(&cert, 0, sizeof(cert));

                        // certificate subject
                        X509_NAME *cert_name = X509_get_subject_name(x509Cert);
                        X509_NAME_get_text_by_NID(cert_name, NID_commonName, cert.sCommon, SSL_CERT_NAME_MAXLEN + 1);
                        X509_NAME_get_text_by_NID(cert_name, NID_organizationName, cert.sOrg, SSL_CERT_NAME_MAXLEN + 1);
                        X509_NAME_get_text_by_NID(cert_name, NID_countryName, cert.sCountry, SSL_CERT_COUNTRY_LEN + 1);

                        // certificate issuer
                        cert_name = X509_get_issuer_name(x509Cert);
                        X509_NAME_get_text_by_NID(cert_name, NID_commonName, cert.iCommon, SSL_CERT_NAME_MAXLEN + 1);
                        X509_NAME_get_text_by_NID(cert_name, NID_organizationName, cert.iOrg, SSL_CERT_NAME_MAXLEN + 1);
                        X509_NAME_get_text_by_NID(cert_name, NID_countryName, cert.iCountry, SSL_CERT_COUNTRY_LEN + 1);

                        // public key
                        EVP_PKEY *key = X509_get_pubkey(x509Cert);
                        if (key) {
                            cert.pkey_size = EVP_PKEY_bits(key);
                            switch (EVP_PKEY_base_id(key)) {
                                case EVP_PKEY_RSA : memcpy(cert.pkey_type, "RSA",   sizeof("RSA"));   break;
                                case EVP_PKEY_DSA : memcpy(cert.pkey_type, "DSA",   sizeof("DSA"));   break;
                                case EVP_PKEY_EC  : memcpy(cert.pkey_type, "ECDSA", sizeof("ECDSA")); break;
                                default: /*Unkown*/ memcpy(cert.pkey_type, "UNDEF", sizeof("UNDEF")); break;
                            }
                            EVP_PKEY_free(key);
                        }

                        // certificate validity
                        ASN1_TIME *not_before = X509_get_notBefore(x509Cert);
                        ASN1_TIME *not_after = X509_get_notAfter(x509Cert);

                        if (!asn1_time_convert(not_before, &cert.cert_not_before) ||
                                !asn1_time_convert(not_after, &cert.cert_not_after)) {
                            break;
                        }

                        X509_free(x509Cert);

                        // make sure opposite flow was not marked as Tor if certificate does not match
                        // the format used by the Tor client
                        if (!is_tor(&cert, cert_len) && oppositeFlowIndex != HASHTABLE_ENTRY_NOT_FOUND) {
                            torFlows[oppositeFlowIndex].stat &= ~TOR_STAT_TOR;
                        }
                    }

                    default:
                        break; // ignore other handshake types
                }
                break;
            }

            default:
                break; // ignore other record types
        }

        // move record pointer to end of record if its not already the case (certificate for instance)
        const int64_t shift = rec.len - (leftAtRecordStart - t2buf_left(&t2buf));
        if (shift > 0) TOR_SKIP_N(&t2buf, shift);
    }

nxtpkt:
    if (sPktFile) fprintf(sPktFile, "0x%02" B2T_PRIX8 /* torStat */ SEP_CHR, torFlowP->stat);
}


void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {
    torFlow_t *torFlowP = &torFlows[flowIndex];

#if TOR_PKTL == 1
    if (torFlowP->minL3PktSz == 2 && (torFlowP->maxL3PktSz == 6 || torFlowP->maxL3PktSz == 7)) torFlowP->stat |= TOR_STAT_PKTL;
#endif // TOR_PKTL == 1

    const unsigned long oppositeFlowIndex = flows[flowIndex].oppositeFlowIndex;
    if (oppositeFlowIndex != HASHTABLE_ENTRY_NOT_FOUND) {
#if TOR_DETECT_OBFUSCATION == 1
        // only flag as obfuscated Tor if first packets entropy is high in both directions
        if ((torFlowP->stat & TOR_STAT_OBFUSC) && !(torFlows[oppositeFlowIndex].stat & TOR_STAT_OBFUSC)) {
            torFlowP->stat &= ~TOR_STAT_OBFUSC;
        }
#endif // TOR_DETECT_OBFUSCATION == 1

        // flag both direction as Tor when one is detected
        if (torFlows[oppositeFlowIndex].stat & TOR_STAT_TOR) {
            torFlowP->stat |= TOR_STAT_TOR;
        }
    }

    if (torFlowP->stat & 0x0f) torCount++;

    torStat |= torFlowP->stat;

    OUTBUF_APPEND_U8(buf, torFlowP->stat);
}


void t2PluginReport(FILE *stream) {
    T2_FPLOG_AGGR_HEX(stream, plugin_name, torStat);
    T2_FPLOG_NUMP(stream, plugin_name, "Number of Tor flows", torCount, totalFlows);
}


void t2Finalize() {
    free(torFlows);

    regfree(&subject_re);
    regfree(&issuer_re);
    regfree(&sni_re);
}
