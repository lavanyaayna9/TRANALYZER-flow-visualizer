/*
 * sslDecode.c
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

#include "sslCipher.h"
#include "sslDecode.h"
#include "proto/capwap.h"
#include "t2buf.h"

#if SSL_ANALYZE_QUIC != 0
#include "quicDecode.h"
#if QUIC_DECODE_TLS == 0
#error "Cannot analyze QUIC TLS record if they are not decrypted: QUIC_DECODE_TLS == 0"
#endif
#endif // SSL_ANALYZE_QUIC != 0

#include <errno.h>  // for errno
#include <unistd.h> // for access, F_OK

#if SSL_ANALYZE_CERT == 1
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#endif

#if SSL_SAVE_CERT == 1
#include <openssl/pem.h>
#endif

#if SSL_DETECT_TOR == 1
#include <regex.h>
#include <stdbool.h>
#endif

#if SSL_BLIST == 1 || SSL_JA3 == 1 || SSL_JA4 == 1
#include "sslBlist.h"
#else
#include "t2Plugin.h"
#endif

#if SSL_BLIST == 1
static ssl_blist_t *sslbl;
static uint32_t numBlistCerts;
#endif

#if SSL_JA3 == 1
static ssl_blist_t *sslja3;
static uint32_t numJA3;
#endif

#if SSL_JA4 == 1
static ssl_blist_t *sslja4;
static ssl_blist_t *sslja4s;
static uint32_t numJA4;
static uint32_t numJA4S;
#endif

#if SSL_DETECT_TOR == 1
static uint32_t numTor;
static regex_t subject_re;
static regex_t issuer_re;
static regex_t request_re;
#define BASE32_CHARS "abcdefghijklmnopqrstuvwxyz234567"
#if SSL_CERT_SUBJECT == 1 && SSL_CERT_ISSUER == 1
static const char *subject_re_str = "^\\/CN=www\\.[" BASE32_CHARS "]{8,20}\\.net$";
static const char *issuer_re_str = "^\\/CN=www\\.[" BASE32_CHARS "]{8,20}\\.(net|com)$";
#elif SSL_CERT_SUBJECT == 2 && SSL_CERT_ISSUER == 2
static const char *subject_re_str = "^www\\.[" BASE32_CHARS "]{8,20}\\.net$";
static const char *issuer_re_str = "^www\\.[" BASE32_CHARS "]{8,20}\\.(net|com)$";
#endif // SSL_CERT_SUBJECT && SSL_CERT_ISSUER
static const char *request_re_str = "^www\\.[" BASE32_CHARS "]{4,25}\\.com$";
#endif // SSL_DETECT_TOR


// Variables from dependencies
#if SSL_ANALYZE_QUIC != 0
extern quic_flow_t *quic_flows __attribute__((weak));
#endif


// plugin variables
sslFlow_t *sslFlow;

#if SSL_ANALYZE_OVPN == 1
static uint32_t numOVPN;
#endif // SSL_ANALYZE_OVPN == 1
static uint32_t numSSL2;
static uint32_t numSSL3[5];
static uint32_t numTLS13D[15];  // TLS 1.3 drafts
static uint32_t numTLS13FBD[2]; // TLS 1.3 Facebook drafts
static uint32_t numDTLS[4];

#if SSL_SAVE_CERT == 1
#if ENVCNTRL > 0
static t2_env_t env[ENV_SSL_N];
static const char *certPath;
static const char *certExt;
#else // ENVCNTRL == 0
static const char * const certPath = SSL_CERT_PATH;
static const char * const certExt = SSL_CERT_EXT;
#endif // ENVCNTRL

static uint32_t numSavedCerts;
#endif // SSL_SAVE_CERT == 1

static uint32_t sslProto;
static uint32_t sslStat;


// Static inline functions prototypes

#if SSL_ANALYZE_OVPN == 1
static inline bool ssl_is_openvpn(t2buf_t *t2buf, packet_t *packet, sslFlow_t *sslFlowP);
static inline bool ssl_process_openvpn(t2buf_t *t2buf, sslFlow_t *sslFlowP);
#endif
static inline void ssl_process_sslv2(t2buf_t *t2buf, sslFlow_t *sslFlowP);
static inline bool ssl_process_alpn(t2buf_t *t2buf, uint16_t ext_len, sslFlow_t *sslFlowP, uint16_t ext_type);
static inline bool ssl_process_hello_extension(t2buf_t *t2buf, sslFlow_t *sslFlowP
#if SSL_SUPP_VER == 1
        , uint8_t handshake_type
#endif // SSL_SUPP_VER == 1
#if SSL_DETECT_TOR == 1
        , bool *non_tor_ext
#endif // SSL_DETECT_TOR == 1
);
static inline bool ssl_read_tls_record_header(t2buf_t *t2buf, sslFlow_t *sslFlowP, sslRecordHeader_t *rec);
#if SSL_ANALYZE_CERT == 1
#if SSL_CERT_VALIDITY == 1
static inline bool ssl_asn1_convert(const ASN1_TIME *t, struct tm *dst);
#endif
static inline bool ssl_process_ht_cert(t2buf_t *t2buf, sslFlow_t *sslFlowP
#if SSL_SAVE_CERT == 1 && SSL_CERT_NAME_FINDEX == 1
        , const flow_t * const flowP
#endif
#if SSL_DETECT_TOR == 1
        , bool *single_cert
#endif // SSL_DETECT_TOR == 1
);
#endif // SSL_ANALYZE_CERT == 1

#if SSL_JA3 == 1
static inline void ssl_compute_ja3(uint8_t handshake_type, sslFlow_t *sslFlowP);
#endif

#if SSL_COMPUTE_JA4
static inline void ssl_compute_ja4(uint8_t handshake_type, sslFlow_t *sslFlowP, const flow_t * const flowP);
#endif

// Tranalyzer functions

T2_PLUGIN_INIT_WITH_DEPS("sslDecode", "0.9.3", 0, 9,
#if SSL_ANALYZE_QUIC != 0
        "quicDecode"
#else // SSL_ANALYZE_QUIC == 0
        ""
#endif // SSL_ANALYZE_QUIC == 0
);


// helper functions


#if SSL_CERT_VALIDITY == 1
static inline bool ssl_asn1_convert(const ASN1_TIME *t, struct tm *dst) {
    if (t->type == V_ASN1_UTCTIME && t->length == 13 && t->data[12] == 'Z') {
        if (!strptime((const char *)t->data, "%y%m%d%H%M%SZ", dst)) {
            return false;
        }
    } else if (t->type == V_ASN1_GENERALIZEDTIME && t->length == 15 && t->data[14] == 'Z') {
        if (!strptime((const char *)t->data, "%Y%m%d%H%M%SZ", dst)) {
            return false;
        }
    } else {
        /* Invalid ASN.1 time */
        return false;
    }
    return true;
}
#endif // SSL_CERT_VALIDITY


#if SSL_ANALYZE_QUIC != 0
static inline bool quic_read_tls_record_header(t2buf_t *t2buf, sslFlow_t *sslFlowP UNUSED, sslRecordHeader_t *rec) {
    uint8_t frame_type;
    if (!t2buf_peek_u8(t2buf, &frame_type)) {
        //sslFlowP->stat |= SSL_STAT_SNAP;
        return false;
    }

    while (frame_type != QUIC_FT_CRYPTO) {
        // Skip the current frame and peek into next frame's type
        if (!t2buf_skip_quic_frame(t2buf) ||
            !t2buf_peek_u8(t2buf, &frame_type))
        {
            //sslFlowP->stat |= SSL_STAT_SNAP;
            return false;
        }
    }

    t2buf_skip_u8(t2buf); // frame_type

    uint64_t offset, length;
    if (!t2buf_read_quic_int(t2buf, &offset) ||
        !t2buf_read_quic_int(t2buf, &length) ||
        length > (uint64_t)t2buf_left(t2buf))
    {
        //sslFlowP->stat |= SSL_STAT_SNAP;
        return false;
    }

    rec->type = SSL_RT_HANDSHAKE;
    rec->version = TLSv13;
    rec->len = (uint16_t)length;

    return true;
}
#endif // SSL_ANALYZE_QUIC != 0


static inline bool ssl_read_tls_record_header(t2buf_t *t2buf, sslFlow_t *sslFlowP, sslRecordHeader_t *rec) {

    // record header:
    //   type(8), version(16: major(8), minor(8))
    //   if type==DTLS: epoch(16), seqnum(48)
    //   len(16)

    // Record Type
    if (!t2buf_read_u8(t2buf, &rec->type)) {
        sslFlowP->stat |= SSL_STAT_SNAP;
        return false;
    }

    if (!SSL_RT_IS_VALID(rec->type)) {
        // If type is invalid, it could still be SSLv2...
        t2buf->pos--; // Unread the record type
        ssl_process_sslv2(t2buf, sslFlowP);
        return false;
    }

    // Record Version
    if (!t2buf_read_u16(t2buf, &rec->version)) {
        sslFlowP->stat |= SSL_STAT_SNAP;
        return false;
    }

    if (rec->version == SSLv3) {
        sslFlowP->vuln |= SSL_VULN_BEAST;
        sslFlowP->vuln |= SSL_VULN_POODLE;
        sslFlowP->stat |= SSL_STAT_WEAK_PROTO;
    } else if (SSL_V_IS_DTLS(rec->version)) {
        t2buf_skip_u16(t2buf); // epoch
        t2buf_skip_u48(t2buf); // seqnum
    } else if (!SSL_V_IS_SSL(rec->version)) {
        // invalid version... probably not ssl
        return false;
    }

    if (rec->type != SSL_HT_CLIENT_HELLO && sslFlowP->version != 0 && sslFlowP->version != rec->version) {
        sslFlowP->flags |= SSL_FLAG_VER;
        // TODO check that version matches between A and B flow
        sslFlowP->stat |= SSL_STAT_VERSION_MISMATCH;
    }

    // Record Length
    if (!t2buf_read_u16(t2buf, &rec->len)) {
        sslFlowP->stat |= SSL_STAT_SNAP;
        return false;
    }

    return true;
}


#if SSL_DETECT_TOR == 1
/**
 * Detect if server -> client flow is using Tor based on certificate content
 */
static bool is_tor(sslFlow_t *sslFlowP, uint32_t cert_len, bool single_cert) {
    // Tor only sends a single small certificate
    if (!single_cert || cert_len > TOR_MAX_CERT_LEN) {
        return false;
    }
    // Tor certificate are RSA 1024 bits
    if (sslFlowP->pkey_type != EVP_PKEY_RSA || sslFlowP->pkey_size != 1024) {
        return false;
    }
    // check the validity period
    uint64_t validity_start = timegm(&sslFlowP->cert_not_before);
    uint64_t validity_end = timegm(&sslFlowP->cert_not_after);
    // validity must start at midnight (since ~ 2013)
    // validity must be exactly one year (until ~ 2013)
    if (validity_start % (24 * 3600) != 0 &&
        (validity_end - validity_start) != (365 * 24 * 60 * 60))
    {
        return false;
    }
    // check that cert is not self signed
#if SSL_CERT_SUBJECT == 1 && SSL_CERT_ISSUER == 1
    if (strlen(sslFlowP->cert_subject) == 0 ||
        strlen(sslFlowP->cert_issuer)  == 0 ||
        strcmp(sslFlowP->cert_subject, sslFlowP->cert_issuer) == 0)
    {
        return false;
    }
#elif SSL_CERT_SUBJECT == 2 && SSL_CERT_ISSUER == 2
    if (strlen(sslFlowP->cert_sCommon) == 0 ||
        strlen(sslFlowP->cert_iCommon) == 0 ||
        strcmp(sslFlowP->cert_sCommon, sslFlowP->cert_iCommon) == 0)
    {
        return false;
    }
#endif // SSL_CERT_SUBJECT && SSL_CERT_ISSUER
    // check the format of the subject and the issuer
#if SSL_CERT_SUBJECT == 1 && SSL_CERT_ISSUER == 1
    if (regexec(&subject_re, sslFlowP->cert_subject, 0, NULL, 0) ||
        regexec(&issuer_re, sslFlowP->cert_issuer, 0, NULL, 0))
    {
        return false;
    }
#elif SSL_CERT_SUBJECT == 2 && SSL_CERT_ISSUER == 2
    if (strlen(sslFlowP->cert_sOrg) != 0 ||
        strlen(sslFlowP->cert_iOrg) != 0 ||
        regexec(&subject_re, sslFlowP->cert_sCommon, 0, NULL, 0) ||
        regexec(&issuer_re, sslFlowP->cert_iCommon, 0, NULL, 0))
    {
        return false;
    }
#endif // SSL_CERT_SUBJECT && SSL_CERT_ISSUER
    // if all checks pass, this is probably a Tor flow
    return true;
}
#endif // SSL_DETECT_TOR


// Tranalyzer functions


void t2Init() {
#if SSL_SAVE_CERT == 1
#if ENVCNTRL > 0
    t2_get_env(PLUGIN_SRCH, ENV_SSL_N, env);
    const uint8_t rmdir = T2_ENV_VAL_UINT(SSL_RM_CERTDIR);
    certPath = T2_ENV_VAL(SSL_CERT_PATH);
    certExt = T2_ENV_VAL(SSL_CERT_EXT);
#else // ENVCNTRL == 0
    const uint8_t rmdir = SSL_RM_CERTDIR;
#endif // ENVCNTRL
    T2_MKPATH(certPath, rmdir);
#endif // SSL_SAVE_CERT

#if SSL_DETECT_TOR == 1
#if SSL_CERT_SUBJECT > 0 && SSL_CERT_ISSUER > 0
    if (UNLIKELY(regcomp(&subject_re, subject_re_str, REG_EXTENDED|REG_NOSUB) != 0)) {
        T2_PFATAL(plugin_name, "Failed to compile subject regex");
    }

    if (UNLIKELY(regcomp(&issuer_re, issuer_re_str, REG_EXTENDED|REG_NOSUB) != 0)) {
        T2_PFATAL(plugin_name, "Failed to compile issuer regex");
    }
#endif // SSL_CERT_SUBJECT && SSL_CERT_ISSUER

    if (UNLIKELY(regcomp(&request_re, request_re_str, REG_EXTENDED|REG_NOSUB) != 0)) {
        T2_PFATAL(plugin_name, "Failed to compile request regex");
    }
#endif // SSL_DETECT_TOR

#if SSL_BLIST == 1 || SSL_JA3 == 1 || SSL_JA4 == 1
    const size_t plen = pluginFolder_len;
    char filename[pluginFolder_len +
        MAX(
            MAX(sizeof(SSL_BLIST_NAME), sizeof(SSL_JA3_NAME)),
            MAX(sizeof(SSL_JA4_NAME), sizeof(SSL_JA4S_NAME))
        )
    ];
    memcpy(filename, pluginFolder, plen);

#if SSL_BLIST == 1
    memcpy(filename + plen, SSL_BLIST_NAME, sizeof(SSL_BLIST_NAME));
    sslbl = ssl_blist_load(plugin_name, filename, 40, SSL_BLIST_LEN);
#if VERBOSE > 0
    T2_PINF(plugin_name, "%" PRIu32 " blacklisted certificates fingerprints", sslbl->count);
#endif
#endif // SSL_BLIST == 1

#if SSL_JA3 == 1
    memcpy(filename + plen, SSL_JA3_NAME, sizeof(SSL_JA3_NAME));
    sslja3 = ssl_blist_load(plugin_name, filename, 32, SSL_JA3_DLEN);
#if VERBOSE > 0
    T2_PINF(plugin_name, "%" PRIu32 " JA3 fingerprints loaded", sslja3->count);
#endif
#endif // SSL_JA3 == 1

#if SSL_JA4 == 1
    memcpy(filename + plen, SSL_JA4_NAME, sizeof(SSL_JA4_NAME));
    sslja4 = ssl_blist_load(plugin_name, filename, 36, SSL_JA4_DLEN);
#if VERBOSE > 0
    T2_PINF(plugin_name, "%" PRIu32 " JA4 fingerprints loaded", sslja4->count);
#endif
    memcpy(filename + plen, SSL_JA4S_NAME, sizeof(SSL_JA4S_NAME));
    sslja4s = ssl_blist_load(plugin_name, filename, 25, SSL_JA4_DLEN);
#if VERBOSE > 0
    T2_PINF(plugin_name, "%" PRIu32 " JA4S fingerprints loaded", sslja4s->count);
#endif
#endif // SSL_JA4 == 1
#endif // SSL_BLIST == 1 || SSL_JA3 == 1

    T2_PLUGIN_STRUCT_NEW(sslFlow);
}


binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;

    BV_APPEND_H32(bv, "sslStat" , "SSL status");
    BV_APPEND_H32(bv, "sslProto", "SSL proto");

#if SSL_ANALYZE_OVPN == 1
    BV_APPEND_H16(bv, "ovpnType"     , "OpenVPN message types");
    BV_APPEND_U64(bv, "ovpnSessionID", "OpenVPN session ID");
#endif

    BV_APPEND_H8( bv, "sslFlags"  , "SSL flags");
    BV_APPEND_H16(bv, "sslVersion", "SSL version");

#if SSL_REC_VER == 1
    BV_APPEND_U16(  bv, "sslNumRecVer", "SSL number of record versions");
    BV_APPEND_H16_R(bv, "sslRecVer"   , "SSL record version");
#endif

#if SSL_HAND_VER == 1
    BV_APPEND_U16(  bv, "sslNumHandVer", "SSL number of handshake versions");
    BV_APPEND_H16_R(bv, "sslHandVer"   , "SSL handshake version");
#endif

    BV_APPEND_H8( bv, "sslVuln"  , "SSL vulnerabilities");
    BV_APPEND_H64(bv, "sslAlert" , "SSL alert");
    BV_APPEND_H16(bv, "sslCipher", "SSL preferred (Client) / negotiated (Server) cipher");

#if SSL_EXT_LIST == 1
    BV_APPEND_U16(  bv, "sslNumExt" , "SSL number of extensions");
    BV_APPEND_H16_R(bv, "sslExtList", "SSL list of extensions");
#endif

#if SSL_SUPP_VER == 1
    BV_APPEND_U16(  bv, "sslNumSuppVer", "SSL number of supported versions");
    BV_APPEND_H16_R(bv, "sslSuppVer"   , "SSL list of supported versions (client), negotiated version (server)");
#endif

#if SSL_SIG_ALG == 1
    BV_APPEND_U16(  bv, "sslNumSigAlg", "SSL number of signature algorithms");
    BV_APPEND_H16_R(bv, "sslSigAlg"   , "SSL list of signature algorithms");
#endif

#if SSL_EC == 1
    BV_APPEND_U16(  bv, "sslNumECPt", "SSL number of EC points");
    BV_APPEND_H16_R(bv, "sslECPt"   , "SSL list of EC points");
#endif

#if SSL_EC_FORMATS == 1
    BV_APPEND_U8(  bv, "sslNumECFormats", "SSL number of EC point formats");
    BV_APPEND_H8_R(bv, "sslECFormats"   , "SSL list of EC point formats");
#endif

#if SSL_ALPN_LIST == 1
    BV_APPEND_U16(  bv, "sslNumALPN" , "SSL number of protocols (ALPN)");
    BV_APPEND_STR_R(bv, "sslALPNList", "SSL list of protocols (ALPN)");
#endif

#if SSL_ALPS_LIST == 1
    BV_APPEND_U16(  bv, "sslNumALPS" , "SSL number of protocols (ALPS)");
    BV_APPEND_STR_R(bv, "sslALPSList", "SSL list of protocols (ALPS)");
#endif

#if SSL_NPN_LIST == 1
    BV_APPEND_U16(  bv, "sslNumNPN" , "SSL number of protocols (NPN)");
    BV_APPEND_STR_R(bv, "sslNPNList", "SSL list of protocols (NPN)");
#endif

#if SSL_CIPHER_LIST == 1
    BV_APPEND_U16(  bv, "sslNumCipher" , "SSL number of supported ciphers");
    BV_APPEND_H16_R(bv, "sslCipherList", "SSL list of supported cipher");
#endif

    BV_APPEND(bv, "sslNumCC_A_H_AD_HB",
            "SSL number of change_cipher, alert, handshake, application data, heartbeat records",
            5, bt_uint_16, bt_uint_16, bt_uint_16, bt_uint_64, bt_uint_64);
    BV_APPEND_U8(bv, "sslSessIdLen", "SSL Session ID length");
    BV_APPEND_TIMESTAMP_R(bv, "sslGMTTime", "SSL GMT Unix Time");
    BV_APPEND_STR_R(bv, "sslServerName", "SSL server name");

#if SSL_ANALYZE_CERT == 1
    BV_APPEND_U8_R(bv, "sslCertVersion", "SSL certificate version");

#if SSL_CERT_SERIAL == 1
    BV_APPEND_STRC_R(bv, "sslCertSerial", "SSL certificate serial number");
#endif

#if SSL_CERT_FINGPRINT == 2
    BV_APPEND_STRC_R(bv, "sslCertMd5FP", "SSL certificate MD5 fingerprint");
#elif SSL_CERT_FINGPRINT == 1
    BV_APPEND_STRC_R(bv, "sslCertSha1FP", "SSL certificate SHA1 fingerprint");
#endif

#if SSL_CERT_VALIDITY == 1
    BV_APPEND_R(bv, "sslCNotValidBefore_after_lifetime",
            "SSL certificate validity period (not valid before/after, lifetime (seconds))",
            3, bt_timestamp, bt_timestamp, bt_uint_64);
#endif

#if SSL_CERT_SIG_ALG == 1
    BV_APPEND_STR_R(bv, "sslCSigAlg", "SSL certificate signature algorithm");
#endif

#if SSL_CERT_PUBKEY_ALG == 1
    BV_APPEND_STR_R(bv, "sslCKeyAlg", "SSL certificate public key algorithm");
#endif

#if SSL_CERT_PUBKEY_TS == 1
    BV_APPEND_R(bv, "sslCPKeyType_Size", "SSL certificate public key type, size (bits)",
            2, bt_string_class, bt_uint_16);
#endif

    // Certificate Subject
#if SSL_CERT_SUBJECT == 1
    BV_APPEND_STR_R(bv, "sslCSubject", "SSL certificate subject");
#elif SSL_CERT_SUBJECT == 2
#if SSL_CERT_COMMON_NAME == 1
    BV_APPEND_STR_R(bv, "sslCSubjectCommonName", "SSL certificate subject common name");
#endif
#if SSL_CERT_ORGANIZATION == 1
    BV_APPEND_STR_R(bv, "sslCSubjectOrgName", "SSL certificate subject organization name");
#endif
#if SSL_CERT_ORG_UNIT == 1
    BV_APPEND_STR_R(bv, "sslCSubjectOrgUnit", "SSL certificate subject organizational unit name");
#endif
#if SSL_CERT_LOCALITY == 1
    BV_APPEND_STR_R(bv, "sslCSubjectLocality", "SSL certificate subject locality name");
#endif
#if SSL_CERT_STATE == 1
    BV_APPEND_STR_R(bv, "sslCSubjectState", "SSL certificate subject state or province name");
#endif
#if SSL_CERT_COUNTRY == 1
    BV_APPEND_STRC_R(bv, "sslCSubjectCountry", "SSL certificate subject country name");
#endif
#endif // SSL_CERT_SUBJECT

    // Certificate Issuer
#if SSL_CERT_ISSUER == 1
    BV_APPEND_STR_R(bv, "sslCIssuer", "SSL certificate issuer");
#elif SSL_CERT_ISSUER == 2
#if SSL_CERT_COMMON_NAME == 1
    BV_APPEND_STR_R(bv, "sslCIssuerCommonName", "SSL certificate issuer common name");
#endif
#if SSL_CERT_ORGANIZATION == 1
    BV_APPEND_STR_R(bv, "sslCIssuerOrgName", "SSL certificate issuer organization name");
#endif
#if SSL_CERT_ORG_UNIT == 1
    BV_APPEND_STR_R(bv, "sslCIssuerOrgUnit", "SSL certificate issuer organizational unit name");
#endif
#if SSL_CERT_LOCALITY == 1
    BV_APPEND_STR_R(bv, "sslCIssuerLocality", "SSL certificate issuer locality name");
#endif
#if SSL_CERT_STATE == 1
    BV_APPEND_STR_R(bv, "sslCIssuerState", "SSL certificate issuer state or province name");
#endif
#if SSL_CERT_COUNTRY == 1
    BV_APPEND_STRC_R(bv, "sslCIssuerCountry", "SSL certificate issuer country name");
#endif
#endif // SSL_CERT_ISSUER

#if SSL_BLIST == 1
    BV_APPEND_STR_R(bv, "sslBlistCat", "SSL blacklisted certificate category");
#endif

#if SSL_JA3 == 1
    BV_APPEND_STRC_R(bv, "sslJA3Hash", "SSL JA3 fingerprint");
    BV_APPEND_STR_R( bv, "sslJA3Desc", "SSL JA3 description");
#if SSL_JA3_STR == 1
    BV_APPEND_STR_R( bv, "sslJA3Str" , "SSL JA3 string");
#endif
#endif // SSL_JA3 == 1

#if SSL_JA4 == 1
    BV_APPEND_STRC_R(bv, "sslJA4"    , "SSL JA4/JA4S fingerprint");
    BV_APPEND_STR_R( bv, "sslJA4Desc", "SSL JA4/JA4S description");
#endif

#if SSL_JA4_O == 1
    BV_APPEND_STRC_R(bv, "sslJA4O" , "SSL JA4_o fingerprint (original order)");
#endif

#if SSL_JA4_R == 1
    BV_APPEND_STRC_R(bv, "sslJA4R" , "SSL JA4_r fingerprint (raw)");
#endif

#if SSL_JA4_RO == 1
    BV_APPEND_STRC_R(bv, "sslJA4RO", "SSL JA4_o fingerprint (raw, original order)");
#endif

#if SSL_DETECT_TOR == 1
    BV_APPEND_U8(bv, "sslTorFlow", "SSL Tor flow");
#endif

#endif // SSL_ANALYZE_CERT

    return bv;
}


void t2OnNewFlow(packet_t* packet UNUSED, unsigned long flowIndex) {
    sslFlow_t * const sslFlowP = &sslFlow[flowIndex];
    memset(sslFlowP, '\0', sizeof(sslFlow_t));
}


void t2OnLayer4(packet_t* packet, unsigned long flowIndex) {
#if SSL_ANALYZE_QUIC != 0
    uint16_t snaplen = packet->snapL7Len;
    const uint8_t *ptr = packet->l7HdrP;
#else // SSL_ANALYZE_QUIC == 0
    const uint16_t snaplen = packet->snapL7Len;
    const uint8_t * const ptr = packet->l7HdrP;
#endif // SSL_ANALYZE_QUIC

    if (snaplen == 0) return; // No payload

    const flow_t * const flowP = &flows[flowIndex];
    const uint8_t proto = flowP->l4Proto;
    if (proto != L3_TCP && proto != L3_UDP && proto != L3_SCTP) return;

    // only 1. frag packet will be processed
    if (!t2_is_first_fragment(packet)) return;

#if SSL_ANALYZE_QUIC != 0
    quic_flow_t *quic_flow = &quic_flows[flowIndex];
    if ((quic_flow->stat & QUIC_STAT_QUIC)) {
        if (!quic_flow->decrypted_payload) {
            return; // this is a QUIC flow but payload was not decryptable
        }
        ptr = (uint8_t *)quic_flow->decrypted_payload;
        snaplen = quic_flow->decrypted_payload_len;
    }
#endif // SSL_ANALYZE_QUIC != 0

    t2buf_t t2buf = t2buf_create(ptr, snaplen);

    sslFlow_t *sslFlowP = &sslFlow[flowIndex];

#if SSL_ANALYZE_OVPN == 1
    if (ssl_is_openvpn(&t2buf, packet, sslFlowP)) {
        if (!ssl_process_openvpn(&t2buf, sslFlowP)) {
            return;
        }
    }
#endif

    if (packet->status & L3_CAPWAP) {
        // FIXME only works if CAPWAP was the last header...
        // TODO if (!t2buf_peek_u48(t2buf, &type) || type != 1) return;
        capwap_header_t *capwap = (capwap_header_t*)(t2buf.buffer + t2buf.pos);
        if (capwap->type != 1) return;
        t2buf_skip_u32(&t2buf); // CAPWAP header
        // DTLS
    }

    while (t2buf_left(&t2buf) >= SSL_RT_HDR_LEN) {

        // SSL Record
        sslRecordHeader_t rec;

    #if SSL_ANALYZE_QUIC != 0
        if (quic_flow->stat & QUIC_STAT_QUIC) {
            if (!quic_read_tls_record_header(&t2buf, sslFlowP, &rec)) return;
        } else
    #endif // SSL_ANALYZE_QUIC != 0
            if (!ssl_read_tls_record_header(&t2buf, sslFlowP, &rec)) return;

        if (rec.len > SSL_RT_MAX_LEN) {
            // invalid length
            sslFlowP->stat |= SSL_STAT_REC_TOO_LONG;
            return;
        }

        sslFlowP->version = rec.version;

#if SSL_REC_VER == 1
        bool found = false;
        for (uint_fast32_t i = 0; i < sslFlowP->num_rec_ver; i++) {
            if (sslFlowP->rec_ver[i] == rec.version) {
                // record version already in the list
                found = true;
                break;
            }
        }

        if (!found) {
            if (sslFlowP->num_rec_ver < SSL_MAX_REC_VER) {
                sslFlowP->rec_ver[sslFlowP->num_rec_ver] = rec.version;
            } else {
                sslFlowP->stat |= SSL_STAT_REC_VER_TRUNC;
            }
            sslFlowP->num_rec_ver++;
        }
#endif // SSL_REC_VER == 1

        const long recStart = t2buf_tell(&t2buf);

        switch (rec.type) {

            case SSL_RT_APPLICATION_DATA:  // encrypted
                sslFlowP->num_app_data++;
                break;

            case SSL_RT_CHANGE_CIPHER_SPEC: {
                // message consists of a single byte of value 1
                uint8_t one;
                if (!t2buf_read_u8(&t2buf, &one)) {
                    sslFlowP->stat |= SSL_STAT_SNAP;
                    return;
                }
                if (one != 1) sslFlowP->stat |= SSL_STAT_MALFORMED;
                sslFlowP->num_change_cipher++;
                break;
            }

            case SSL_RT_ALERT: {
                sslFlowP->num_alert++;

                uint8_t level, descr;
                if (!t2buf_read_u8(&t2buf, &level) ||
                    !t2buf_read_u8(&t2buf, &descr))
                {
                    sslFlowP->stat |= SSL_STAT_SNAP;
                    return;
                }

                if (level != SSL_AL_WARN && level != SSL_AL_FATAL) {
                    // encrypted or malformed
                    break;
                }

                if (level == SSL_AL_FATAL) {
                    sslFlowP->stat |= SSL_STAT_AL_FATAL;
                }

                SSL_SET_AD_BF(sslFlowP, descr);
                break;
            }

            case SSL_RT_HANDSHAKE: {
                sslFlowP->num_handshake++;
                if (!rec.len) break;

                // there can be multiple handshake messages
                while (t2buf_left(&t2buf) != 0 && rec.len > (t2buf_tell(&t2buf) - recStart)) {
                    const long hsStart = t2buf_tell(&t2buf);

                    uint8_t handshake_type;
                    uint32_t handshake_len;
                    if (!t2buf_read_u8(&t2buf, &handshake_type) ||
                        !t2buf_read_u24(&t2buf, &handshake_len))
                    {
                        sslFlowP->stat |= SSL_STAT_SNAP;
                        return;
                    }

                    if (SSL_V_IS_DTLS(sslFlowP->version)) {
                        t2buf_skip_u16(&t2buf); // message_seq
                        t2buf_skip_u24(&t2buf); // fragment_offset
                        t2buf_skip_u24(&t2buf); // fragment_length
                    }

#if SSL_DETECT_TOR == 1
                    bool cipher_empty_renegotiation = false;
                    bool non_tor_ext = false;
                    bool single_cert = false;
                    const unsigned long oppositeFlowIndex = flowP->oppositeFlowIndex;
#endif

                    switch (handshake_type) {

                        case SSL_HT_HELLO_REQUEST:
                            sslFlowP->num_hello_req++;
                            break;

                        case SSL_HT_SERVER_HELLO:
                            /* FALLTHRU */
                        case SSL_HT_CLIENT_HELLO: {
                            uint16_t hand_ver;
                            if (!t2buf_read_u16(&t2buf, &hand_ver)) {
                                sslFlowP->stat |= SSL_STAT_SNAP;
                                return;
                            }

                            if (!SSL_V_IS_VALID(hand_ver)) {
                                // invalid version... message probably encrypted
                                t2buf_skip_n(&t2buf, handshake_len);
                                break;
                            }

                            sslFlowP->version = hand_ver;

#if SSL_HAND_VER == 1
                            bool found = false;
                            for (uint_fast32_t i = 0; i < sslFlowP->num_hand_ver; i++) {
                                if (sslFlowP->hand_ver[i] == hand_ver) {
                                    // handshake version already in the list
                                    found = true;
                                    break;
                                }
                            }

                            if (!found) {
                                if (sslFlowP->num_hand_ver < SSL_MAX_HAND_VER) {
                                    sslFlowP->hand_ver[sslFlowP->num_hand_ver] = hand_ver;
                                } else {
                                    sslFlowP->stat |= SSL_STAT_HAND_VER_TRUNC;
                                }
                                sslFlowP->num_hand_ver++;
                            }
#endif // SSL_HAND_VER == 1

                            // GMT time is part of Random
                            uint32_t gmt;
                            if (!t2buf_peek_u32(&t2buf, &gmt)) {
                                sslFlowP->stat |= SSL_STAT_SNAP;
                                return;
                            }
                            sslFlowP->gmt_time = gmt;

                            if (sslFlowP->gmt_time < SSL_TS_1YEAR) {
                                sslFlowP->flags |= SSL_FLAG_STIME;
                            } else if (sslFlowP->gmt_time > ((uint32_t)packet->pcapHdrP->ts.tv_sec + SSL_TS_5YEARS)) {
                                sslFlowP->flags |= SSL_FLAG_RTIME;
                            }

                            // peek into Random...
                            uint64_t rp1, rp2, rp3;
                            uint32_t rp4;
                            if (!t2buf_peek_u64(&t2buf, &rp1) ||
                                !t2buf_peek_u64(&t2buf, &rp2) ||
                                !t2buf_peek_u64(&t2buf, &rp3) ||
                                !t2buf_peek_u32(&t2buf, &rp4))
                            {
                                sslFlowP->stat |= SSL_STAT_SNAP;
                                return;
                            }

                            // make sure Random is random...
                            if ((rp1 == 0 && rp2 == 0 && rp3 == 0 && rp4 == 0) ||
                                (rp1 == UINT64_MAX && rp2 == UINT64_MAX &&
                                 rp3 == UINT64_MAX && rp4 == UINT32_MAX))
                            {
                                // Only 0s or only 1s
                                sslFlowP->flags |= SSL_FLAG_RAND;
                            }

                            // Skip Random
                            t2buf_skip_n(&t2buf, SSL_HELLO_RANDOM_LEN);

                            if (!t2buf_read_u8(&t2buf, &sslFlowP->session_len)) {
                                sslFlowP->stat |= SSL_STAT_SNAP;
                                return;
                            }

                            t2buf_skip_n(&t2buf, sslFlowP->session_len); // skip session_id
                            // if (id == 0) session not resumable
                            // else if (id != client_id) new session
                            // else resumed session

                            if (handshake_type == SSL_HT_CLIENT_HELLO) {
                                // TODO do we also have this on the ServerHello?
                                if (sslFlowP->session_len != 0) {
                                    sslFlowP->stat |= SSL_STAT_RENEGOTIATION;
                                }

                                // TODO do we also have this on the ServerHello?
                                if (SSL_V_IS_DTLS(sslFlowP->version)) {
                                    // TODO cookie MUST be 0 if message is not a reply to a hello_verify_request
                                    uint8_t cookie_len;
                                    if (!t2buf_read_u8(&t2buf, &cookie_len)) { // cookie length
                                        sslFlowP->stat |= SSL_STAT_SNAP;
                                        return;
                                    }
                                    t2buf_skip_n(&t2buf, cookie_len); // cookie
                                }
                            }

                            uint16_t num_cipher;
                            if (handshake_type == SSL_HT_SERVER_HELLO) {
                                num_cipher = 1;
                            } else {
                                uint16_t cipher_len;
                                if (!t2buf_read_u16(&t2buf, &cipher_len)) {
                                    sslFlowP->stat |= SSL_STAT_SNAP;
                                    return;
                                }

                                if (cipher_len & 1) {
                                    // cipher_len not divisible by two
                                    sslFlowP->stat |= SSL_STAT_MALFORMED;
                                }

                                num_cipher = cipher_len / sizeof(uint16_t);
                            }

#if SSL_CIPHER_LIST == 1 || SSL_JA3 == 1
                            sslFlowP->num_cipher = num_cipher;
#endif

                            uint16_t cipher;
                            for (uint_fast16_t i = 0; i < num_cipher; i++) {
                                if (!t2buf_read_u16(&t2buf, &cipher)) {
                                    sslFlowP->stat |= SSL_STAT_SNAP;
                                    return;
                                }

                                SSL_FLAG_WEAK_CIPHER(sslFlowP, cipher);

                                if (i == 0) {
                                    // Preferred/Selected cipher
                                    sslFlowP->cipher = cipher;
                                }
#if SSL_CIPHER_LIST == 1 || SSL_JA3 == 1
                                if (i < SSL_MAX_CIPHER) {
                                    sslFlowP->cipher_list[i] = cipher;
                                } else {
                                    sslFlowP->stat |= SSL_STAT_CIPHERL_TRUNC;
                                }
#endif
#if SSL_DETECT_TOR == 1
                                if (cipher == TLS_EMPTY_RENEGOTIATION_INFO_SCSV) {
                                    cipher_empty_renegotiation = true;
                                }
#endif
                            }

                            uint8_t comp_len;
                            if (handshake_type == SSL_HT_SERVER_HELLO) {
                                comp_len = 1;
                            } else {
                                if (!t2buf_read_u8(&t2buf, &comp_len)) {
                                    sslFlowP->stat |= SSL_STAT_SNAP;
                                    return;
                                }
                            }

                            // Compression methods
                            for (uint_fast8_t i = 0; i < comp_len; i++) {
                                uint8_t compr;
                                if (!t2buf_read_u8(&t2buf, &compr)) {
                                    sslFlowP->stat |= SSL_STAT_SNAP;
                                    return;
                                }

                                if (compr == SSL_COMPRESSION_DEFLATE) {
                                    sslFlowP->flags |= SSL_FLAG_COMPR;
                                    sslFlowP->vuln |= SSL_VULN_BREACH;
                                    sslFlowP->vuln |= SSL_VULN_CRIME;
                                }
                            }

                            // Hello extensions (optional for TLS < 1.3)
                            const long pos = t2buf_tell(&t2buf);
                            if (rec.len       > (pos - recStart) &&  // Record not fully parsed yet
                                handshake_len > (pos - hsStart))     // Handshake not fully parsed yet (XXX redundant?)
                            {
                                // Ignore size of extensions
                                t2buf_skip_u16(&t2buf);

                                while (handshake_len > (t2buf_tell(&t2buf) - hsStart)) { /// XXX rec.len > (pos - recStart)?
                                    if (!ssl_process_hello_extension(&t2buf, sslFlowP
#if SSL_SUPP_VER == 1
                                            , handshake_type
#endif // SSL_SUPP_VER == 1
#if SSL_DETECT_TOR == 1
                                            , &non_tor_ext
#endif // SSL_DETECT_TOR == 1
                                    )) {
#if SSL_COMPUTE_JA4
                                        ssl_compute_ja4(handshake_type, sslFlowP, flowP);
#endif // SSL_COMPUTE_JA4
                                        return;
                                    }
                                }
                            }
#if SSL_JA3 == 1
                            ssl_compute_ja3(handshake_type, sslFlowP);
#endif // SSL_JA3
#if SSL_COMPUTE_JA4
                            ssl_compute_ja4(handshake_type, sslFlowP, flowP);
#endif // SSL_COMPUTE_JA4
                            break;
                        }

                        case SSL_HT_HELLO_VERIFY_REQUEST:
                            if (!t2buf_read_u16(&t2buf, &sslFlowP->version)) {
                                sslFlowP->stat |= SSL_STAT_SNAP;
                                return;
                            }

                            if (!SSL_V_IS_VALID(sslFlowP->version)) {
                                // invalid version... message probably encrypted
                                sslFlowP->version = rec.version;
                                t2buf_skip_n(&t2buf, handshake_len);
                                break;
                            }

                            t2buf_skip_u32(&t2buf); // cookie
                            break;

                        case SSL_HT_CERTIFICATE:
#if SSL_ANALYZE_CERT == 1
                            // only process first certificate
                            if (sslFlowP->cert_version != 0) {
#endif
                                t2buf_skip_n(&t2buf, rec.len - (t2buf_tell(&t2buf) - recStart));
#if SSL_ANALYZE_CERT == 1
                            } else if (!ssl_process_ht_cert(&t2buf, sslFlowP
#if SSL_SAVE_CERT == 1 && SSL_CERT_NAME_FINDEX == 1
                                    , flowP
#endif
#if SSL_DETECT_TOR == 1
                                    , &single_cert
#endif // SSL_DETECT_TOR == 1
                            )) {
                                return;
                            }
#if SSL_DETECT_TOR == 1
                            // also mark opposite flow as Tor
                            if (sslFlowP->is_tor && oppositeFlowIndex != HASHTABLE_ENTRY_NOT_FOUND) {
                                sslFlow[oppositeFlowIndex].is_tor = 1;
                            }
#endif // SSL_DETECT_TOR == 1
#endif // SSL_ANALYZE_CERT == 1
                            break;

                        case SSL_HT_SERVER_HELLO_DONE:
                            // no payload
                            sslFlowP->num_server_hello_done++;
                            break;

                        case SSL_HT_CLIENT_KEY_EXCHANGE:
                        case SSL_HT_SERVER_KEY_EXCHANGE:
                        case SSL_HT_CERTIFICATE_REQUEST:
                        case SSL_HT_CERTIFICATE_VERIFY:
                        case SSL_HT_FINISHED:
                            if (handshake_len <= rec.len) t2buf_skip_n(&t2buf, handshake_len);
                            // XXX else ???
                            break;

                        default:
                            // unknown handshake type... encrypted or not ssl
                            //if (handshake_len <= rec.len) t2buf_skip_n(&t2buf, handshake_len);
                            t2buf_skip_n(&t2buf, rec.len - (t2buf_tell(&t2buf) - recStart));
                            break;
                    } // switch handshake_type

                    //if (handshake_len <= rec.len) t2buf_skip_n(&t2buf, handshake_len);

#if SSL_DETECT_TOR == 1
                    // Detect Tor: only use the client hello request if there is no server -> client flow
                    // because using the certificate is way more reliable
                    if (oppositeFlowIndex == HASHTABLE_ENTRY_NOT_FOUND &&
                        cipher_empty_renegotiation && !non_tor_ext &&
                        regexec(&request_re, sslFlowP->server_name, 0, NULL, 0) == 0)
                    {
                        sslFlowP->is_tor = 1;
                    }
#endif // SSL_DETECT_TOR == 1

                    if (rec.len == (t2buf_tell(&t2buf) - recStart)) break; // end of record
                    //if (rec.len - handshake_len - 4 == 0) break;

                    const size_t shift = handshake_len - (t2buf_tell(&t2buf) - hsStart) + 4;
                    if (shift > 0) /*handshake_len <= rec.len && shift)*/ t2buf_skip_n(&t2buf, shift);
                }
                break;
            }

            case SSL_RT_HEARTBEAT: {
                sslFlowP->num_heartbeat++;

                uint8_t type;
                uint16_t len;
                if (!t2buf_read_u8(&t2buf, &type) ||
                    !t2buf_read_u16(&t2buf, &len))
                {
                    sslFlowP->stat |= SSL_STAT_SNAP;
                    return;
                }

                if (type != SSL_HB_REQ && type != SSL_HB_RESP) {
                    sslFlowP->stat |= SSL_STAT_MALFORMED;
                }

                if (len > rec.len) {
                    sslFlowP->vuln |= SSL_VULN_HEART;
                    return;
                }

                t2buf_skip_n(&t2buf, len); // skip payload

                const uint16_t padding = (rec.len - len - SIZEOF_SSL_HEARTBEAT);
                if (padding < SSL_HB_MIN_PAD_LEN) {
                    sslFlowP->stat |= SSL_STAT_MALFORMED;
                }

                t2buf_skip_n(&t2buf, padding); // skip padding

                break;
            }

            default:
                // unknown record type... encrypted or not ssl
                break;
        }

        // next record?
        const size_t shift = rec.len - (t2buf_tell(&t2buf) - recStart);
        if (shift) t2buf_skip_n(&t2buf, shift);
    }
}


#if SSL_ANALYZE_OVPN == 1
static inline bool ssl_is_openvpn(t2buf_t *t2buf, packet_t *packet, sslFlow_t *sslFlowP) {
    uint16_t length;
    return sslFlowP->proto & SSL_STAT_PROTO_OVPN || (
                t2buf_left(t2buf) >= 16          &&
                t2buf_peek_u16(t2buf, &length)   &&
                length == packet->l7Len - 2);
}
#endif


#if SSL_ANALYZE_OVPN == 1
static inline bool ssl_process_openvpn(t2buf_t *t2buf, sslFlow_t *sslFlowP) {
    t2buf_skip_u16(t2buf);  // skip packet length

    // opcode(5)/key_id(3)
    uint8_t opcode;
    if (!t2buf_read_u8(t2buf, &opcode)) {
        sslFlowP->stat |= SSL_STAT_SNAP;
        return false;
    }

    opcode = (opcode & 0xf8) >> 3;
    if (!SSL_OVPN_OPCODE_IS_VALID(opcode)) {
        // Invalid opcode
        return false;
    }
    sslFlowP->ovpnType |= (1 << opcode);

    if (!(sslFlowP->proto & SSL_STAT_PROTO_OVPN)) {
        sslFlowP->proto |= SSL_STAT_PROTO_OVPN;
        numOVPN++;
    }

    if (opcode == SSL_OVPN_DATA_V1 || opcode == SSL_OVPN_DATA_V2) {
        // No more processing required
        return false;
    }

    if (sslFlowP->ovpnSessID == 0) {
        if (!t2buf_read_u64(t2buf, &sslFlowP->ovpnSessID)) {
            sslFlowP->stat |= SSL_STAT_SNAP;
            return false;
        }
    } else {
        // TODO test whether the session IDs match
        t2buf_skip_u64(t2buf);
    }

    // TODO only if tls_auth is used (heuristic)
//#if SSL_OVPN_TLS_AUTH == 1
//    // HMAC
//    t2buf_skip_n(t2buf, hmac_size);
//    if (t2buf_left(t2buf) >= 8) {
//        // PID
//        t2buf_skip_u32(t2buf);
//        // Net Time
//        t2buf_skip_u32(t2buf);
//    }
//#endif // SSL_OVPN_TLS_AUTH == 1

    if (opcode != SSL_OVPN_CTRL_V1) {
        // No more processing required
        return false;
    }

    // Message Packet-ID Array Length
    uint8_t len;
    if (!t2buf_read_u8(t2buf, &len)) {
        sslFlowP->stat |= SSL_STAT_SNAP;
        return false;
    }

    // Message Packet-ID Array
    if (len > 0) {
        t2buf_skip_n(t2buf, len * sizeof(uint32_t));
    }

    // Remote Session ID
    // Not present in first message
    // TODO check it matches opposite flow session id
    uint16_t rsid;
    if (!t2buf_peek_u16(t2buf, &rsid)) {
        sslFlowP->stat |= SSL_STAT_SNAP;
        return false;
    }

    if (rsid != 0) {
        t2buf_skip_u64(t2buf);
    }

    // Message Packet-ID
    t2buf_skip_u32(t2buf);

    // XXX do we really have to continue?
    return true;
}
#endif


static inline void ssl_process_sslv2(t2buf_t *t2buf, sslFlow_t *sslFlowP) {
    if (t2buf_left(t2buf) < SIZEOF_SSLV2) return;

    uint16_t len;
    uint8_t type;
    uint8_t v_major, v_minor;
    if (!t2buf_read_u16(t2buf, &len)    ||
        !t2buf_read_u8(t2buf, &type)    ||
        !t2buf_read_u8(t2buf, &v_major) ||
        !t2buf_read_u8(t2buf, &v_minor))
    {
        sslFlowP->stat |= SSL_STAT_SNAP;
        return;
    }

    if (!SSL2_MT_IS_VALID(type)) return;  // Invalid message type, probably not SSL

    if (len & 0x8000) {
        // no padding, record header is 2 bytes
        len = (len & 0x7fff) + 2;
    } else {
        // padding, record header is 3 bytes
        len = (len & 0x3fff) + 3;
    }

    if (len - SIZEOF_SSLV2 > t2buf_left(t2buf)) {
        return; // Not enough data available... snapped or not SSL
    }

    const uint16_t version = v_major << 8 | v_minor;
    if (sslFlowP->version != SSLv2 && (version == SSLv2 || !SSL_V_IS_SSL(version))) {
        return; // ... probably not SSL
    }

    sslFlowP->version = version; // can be SSLv3 or TLSv1*
    if (version == SSLv2) {
        sslFlowP->stat |= SSL_STAT_WEAK_PROTO;
        sslFlowP->flags |= SSL_FLAG_V2;
    }

    // TODO keep on decoding...
}


static inline bool ssl_process_alpn(t2buf_t *t2buf, uint16_t ext_len, sslFlow_t *sslFlowP, uint16_t ext_type) {
    uint8_t proto_len;
    while (ext_len != 0) {
        if (!t2buf_read_u8(t2buf, &proto_len) ||
            proto_len > t2buf_left(t2buf))
        {
            sslFlowP->stat |= SSL_STAT_SNAP;
            return false;
        }

        if (proto_len == 0) break;

        uint16_t proto16 = 0;

        if (proto_len >= sizeof(uint16_t)) {
            // If t2buf_peek_u16 fails, proto16 will still be 0
            t2buf_peek_u16(t2buf, &proto16);
            //if (!t2buf_peek_u16(t2buf, &proto16)) {
            //    sslFlowP->stat |= SSL_STAT_SNAP;
            //    return false;
            //}
        }

        if (SSL_IS_GREASE(proto16)) {
            sslFlowP->proto |= SSL_STAT_PROTO_GREASE;
            break;
        }

        switch (proto16) {
            // TODO flag h2c separately?
            case SSL_PROTO_HTTP2: sslFlowP->proto |= SSL_STAT_PROTO_HTTP2; break;
            case SSL_PROTO_HTTP3: sslFlowP->proto |= SSL_STAT_PROTO_HTTP3; break;
            case SSL_PROTO_QUIC:  sslFlowP->proto |= SSL_STAT_PROTO_HTTP3; break;
            default: {
                uint32_t proto32 = 0;
                if (proto_len >= sizeof(uint32_t)) {
                    // If t2buf_peek_u32 fails, proto32 will still be 0
                    t2buf_peek_u32(t2buf, &proto32);
                    //if (!t2buf_peek_u32(t2buf, &proto32)) {
                    //    sslFlowP->stat |= SSL_STAT_SNAP;
                    //    return false;
                    //}
                }
                switch (proto32) {
                    case SSL_PROTO_ACME: sslFlowP->proto |= SSL_STAT_PROTO_ACME; break;
                    case SSL_PROTO_APNS: sslFlowP->proto |= SSL_STAT_PROTO_APNS; break;
                    case SSL_PROTO_COAP: sslFlowP->proto |= SSL_STAT_PROTO_COAP; break;
                    case SSL_PROTO_DICO: sslFlowP->proto |= SSL_STAT_PROTO_DICO; break;
                    // TODO flag http/0.9, http/1.0 and http/1.1 separately?
                    case SSL_PROTO_HTTP: sslFlowP->proto |= SSL_STAT_PROTO_HTTP; break;
                    case SSL_PROTO_IMAP: sslFlowP->proto |= SSL_STAT_PROTO_IMAP; break;
                    case SSL_PROTO_MQTT: sslFlowP->proto |= SSL_STAT_PROTO_MQTT; break;
                    case SSL_PROTO_NNSP: sslFlowP->proto |= SSL_STAT_PROTO_NNTP; break;
                    case SSL_PROTO_NNTP: sslFlowP->proto |= SSL_STAT_PROTO_NNTP; break;
                    case SSL_PROTO_POP3: sslFlowP->proto |= SSL_STAT_PROTO_POP3; break;
                    case SSL_PROTO_SIP2: sslFlowP->proto |= SSL_STAT_PROTO_SIP2; break;
                    // TODO flag spdy/1, spdy/2 and spdy/3 separately?
                    case SSL_PROTO_SPDY: sslFlowP->proto |= SSL_STAT_PROTO_SPDY; break;
                    case SSL_PROTO_STUN: sslFlowP->proto |= SSL_STAT_PROTO_STUN; break;
                    case SSL_PROTO_TDS8: sslFlowP->proto |= SSL_STAT_PROTO_TDS8; break;
                    case SSL_PROTO_XMPP: sslFlowP->proto |= SSL_STAT_PROTO_XMPP; break;
                    default: {
                        uint32_t proto24 = 0;
                        if (proto_len >= 3) {
                            // If t2buf_peek_u24 fails, proto24 will still be 0
                            t2buf_peek_u24(t2buf, &proto24);
                            //if (!t2buf_peek_u24(t2buf, &proto24)) {
                            //    sslFlowP->stat |= SSL_STAT_SNAP;
                            //    return false;
                            //}
                        }
                        switch (proto24) {
                            case SSL_PROTO_DOQ: sslFlowP->proto |= SSL_STAT_PROTO_DOQ; break;
                            case SSL_PROTO_DOT: sslFlowP->proto |= SSL_STAT_PROTO_DOT; break;
                            case SSL_PROTO_FTP: sslFlowP->proto |= SSL_STAT_PROTO_FTP; break;
                            case SSL_PROTO_IRC: sslFlowP->proto |= SSL_STAT_PROTO_IRC; break;
                            case SSL_PROTO_SMB: sslFlowP->proto |= SSL_STAT_PROTO_SMB; break;
                            default: {
                                uint64_t proto48 = 0;
                                if (proto_len >= 6) {
                                    // If t2buf_peek_u48 fails, proto24 will still be 0
                                    t2buf_peek_u48(t2buf, &proto48);
                                    //if (!t2buf_peek_u48(t2buf, &proto48)) {
                                    //    sslFlowP->stat |= SSL_STAT_SNAP;
                                    //    return false;
                                    //}
                                }
                                switch (proto48) {
                                    case SSL_PROTO_NTSKE: sslFlowP->proto |= SSL_STAT_PROTO_NTSKE; break;
                                    case SSL_PROTO_SUNRPC: sslFlowP->proto |= SSL_STAT_PROTO_SUNRPC; break;
                                    case SSL_PROTO_WEBRTC: sslFlowP->proto |= SSL_STAT_PROTO_WEBRTC; break;
                                    default: {
                                        uint64_t proto64 = 0;
                                        if (proto_len >= 8) {
                                            // If t2buf_peek_u64 fails, proto64 will still be 0
                                            t2buf_peek_u64(t2buf, &proto64);
                                            //if (!t2buf_peek_u64(t2buf, &proto64)) {
                                            //    sslFlowP->stat |= SSL_STAT_SNAP;
                                            //    return false;
                                            //}
                                        }
                                        switch (proto64) {
                                            case SSL_PROTO_CWEBRTC: sslFlowP->proto |= SSL_STAT_PROTO_WEBRTC; break;
                                            default: {
                                                if (proto_len >= sizeof(SSL_PROTO_MANSIEVE) &&
                                                    strnstr((char*)(t2buf->buffer + t2buf->pos), SSL_PROTO_MANSIEVE, proto_len))
                                                {
                                                    sslFlowP->proto |= SSL_STAT_PROTO_MANSIEVE;
                                                } else {
                                                    sslFlowP->proto |= SSL_STAT_PROTO_UNKNOWN;
                                                }
                                                break;
                                            }
                                        }
                                        break;
                                    }
                                }
                                break;
                            }
                        }
                        break;
                    }
                }
                break;
            }
        }

        switch (ext_type) {
#if SSL_ALPN_LIST == 1
            case SSL_HT_HELLO_EXT_ALPN: {
                const uint8_t idx = sslFlowP->num_alpn;
                if (idx >= SSL_MAX_PROTO) {
                    sslFlowP->stat |= SSL_STAT_PROTOL_TRUNC;
                } else {
                    const uint8_t plen = MIN(SSL_PROTO_LEN, proto_len);
                    if (plen < proto_len) sslFlowP->stat |= SSL_STAT_PROTON_TRUNC;
                    memcpy(sslFlowP->alpn_list[idx], t2buf->buffer + t2buf->pos, plen);
                    sslFlowP->alpn_list[idx][plen] = '\0';
                }
                sslFlowP->num_alpn++;
                break;
            }
#endif // SSL_ALPN_LIST == 1

#if SSL_ALPS_LIST == 1
            case SSL_HT_HELLO_EXT_ALPS: {
                const uint8_t idx = sslFlowP->num_alps;
                if (idx >= SSL_MAX_PROTO) {
                    sslFlowP->stat |= SSL_STAT_PROTOL_TRUNC;
                } else {
                    const uint8_t plen = MIN(SSL_PROTO_LEN, proto_len);
                    if (plen < proto_len) sslFlowP->stat |= SSL_STAT_PROTON_TRUNC;
                    memcpy(sslFlowP->alps_list[idx], t2buf->buffer + t2buf->pos, plen);
                    sslFlowP->alps_list[idx][plen] = '\0';
                }
                sslFlowP->num_alps++;
                break;
            }
#endif // SSL_ALPS_LIST == 1

#if SSL_NPN_LIST == 1
            case SSL_HT_HELLO_EXT_NPN: {
                const uint8_t idx = sslFlowP->num_npn;
                if (idx >= SSL_MAX_PROTO) {
                    sslFlowP->stat |= SSL_STAT_PROTOL_TRUNC;
                } else {
                    const uint8_t plen = MIN(SSL_PROTO_LEN, proto_len);
                    if (plen < proto_len) sslFlowP->stat |= SSL_STAT_PROTON_TRUNC;
                    memcpy(sslFlowP->npn_list[idx], t2buf->buffer + t2buf->pos, plen);
                    sslFlowP->npn_list[idx][plen] = '\0';
                }
                sslFlowP->num_npn++;
                break;
            }
#endif // SSL_NPN_LIST == 1

            default:
                // Should not happen
                break;
        }

        t2buf_skip_n(t2buf, proto_len);
        ext_len -= (proto_len + 1);
    }

    return true;
}


static inline bool ssl_process_hello_extension(t2buf_t *t2buf, sslFlow_t *sslFlowP
#if SSL_SUPP_VER == 1
        , uint8_t handshake_type
#endif // SSL_SUPP_VER == 1
#if SSL_DETECT_TOR == 1
        , bool *non_tor_ext
#endif // SSL_DETECT_TOR == 1
) {
    uint16_t ext_len, ext_type;
    if (!t2buf_read_u16(t2buf, &ext_type) ||
        !t2buf_read_u16(t2buf, &ext_len))
    {
        sslFlowP->stat |= SSL_STAT_SNAP;
        return false;
    }

#if SSL_EXT_LIST == 1 || SSL_JA3 == 1
    if (sslFlowP->num_ext < SSL_MAX_EXT) {
        sslFlowP->ext_list[sslFlowP->num_ext] = ext_type;
    } else {
        sslFlowP->stat |= SSL_STAT_EXTL_TRUNC;
    }
    sslFlowP->num_ext++;
#endif

    switch (ext_type) {

        case SSL_HT_HELLO_EXT_SERVER_NAME: {
            if (ext_len == 0) break;

            t2buf_skip_u16(t2buf); // skip server name list length

            uint8_t type;
            if (!t2buf_read_u8(t2buf, &type)) {
                sslFlowP->stat |= SSL_STAT_SNAP;
                return false;
            }

            if (type) { // skip type (only HOST_NAME (0) is valid)
                sslFlowP->stat |= SSL_STAT_MALFORMED;
                break;
            }

            uint16_t sNameLen;
            if (!t2buf_read_u16(t2buf, &sNameLen)) {
                sslFlowP->stat |= SSL_STAT_SNAP;
                return false;
            }

            // TODO t2buf_peek_str
            //long ret = t2buf_read_str(t2buf, sslFlowP->server_name, SSL_SNI_MAX_LEN, T2BUF_UTF8, true);
            //if (ret == T2BUF_DST_FULL) {
            //    t2buf_skip_n(t2buf, sNameLen - SSL_SNI_MAX_LEN);
            //} else if (ret == T2BUF_EMPTY) {
            //    // XXX TODO FIXME add a return code, for no more data to read
            //    sslFlowP->stat |= SSL_STAT_SNAP;
            //    return false;
            //}
            memcpy(sslFlowP->server_name, t2buf->buffer + t2buf->pos, MIN(sNameLen, SSL_SNI_MAX_LEN));
            t2buf_skip_n(t2buf, sNameLen);
            break;
        }

#if SSL_SIG_ALG == 1
        case SSL_HT_HELLO_EXT_SIG_HASH_ALGS: {
            if (ext_len == 0) break;
            int32_t left = ext_len;
            t2buf_skip_u16(t2buf); // skip signature hash algorithms length
            left -= 2; // skip signature hash algorithms length
            while (left >= 2) {
                if (sslFlowP->num_sig_alg < SSL_MAX_SIG_ALG) {
                    if (!t2buf_read_u16(t2buf, &sslFlowP->sig_alg[sslFlowP->num_sig_alg])) {
                        sslFlowP->stat |= SSL_STAT_SNAP;
                        return false;
                    }
                } else {
                    t2buf_skip_u16(t2buf);
                    sslFlowP->stat |= SSL_STAT_SIG_ALG_TRUNC;
                }
                sslFlowP->num_sig_alg++;
                left -= 2;
            }
            break;
        }
#endif // SSL_SIG_ALG == 1

        case SSL_HT_HELLO_EXT_USE_SRTP:
            sslFlowP->proto |= SSL_STAT_PROTO_RTP;
            t2buf_skip_n(t2buf, ext_len);
            break;

        case SSL_HT_HELLO_EXT_HEARTBEAT: {
            uint8_t flag;
            if (!t2buf_peek_u8(t2buf, &flag)) {
                sslFlowP->stat |= SSL_STAT_SNAP;
                return false;
            }

            if (flag == SSL_HB_EXT_NOT_ALLOWED) {
                sslFlowP->stat |= SSL_STAT_NO_HEARTBEAT;
            } else if (flag != SSL_HB_EXT_ALLOWED) {
                sslFlowP->stat |= SSL_STAT_MALFORMED;
            }

            t2buf_skip_n(t2buf, ext_len);
            break;
        }

        // ALPN/NPN/ALPS
        case SSL_HT_HELLO_EXT_ALPN:
        case SSL_HT_HELLO_EXT_ALPS:
            if (!t2buf_read_u16(t2buf, &ext_len)) {  // ALPN/ALPS extension length
                sslFlowP->stat |= SSL_STAT_SNAP;
                return false;
            }
            /* FALLTHRU */
        case SSL_HT_HELLO_EXT_NPN:
#if SSL_DETECT_TOR == 1
            *non_tor_ext = true;
#endif
            if (!ssl_process_alpn(t2buf, ext_len, sslFlowP, ext_type)) return false;
            break;

#if SSL_SUPP_VER == 1
        case SSL_HT_HELLO_EXT_SUPPORTED_VERSION: {
            if (ext_len == 0) break;
            if (handshake_type == SSL_HT_SERVER_HELLO) {
                if (!t2buf_read_u16(t2buf, &sslFlowP->supp_ver[0])) {
                    sslFlowP->stat |= SSL_STAT_SNAP;
                    return false;
                }
                sslFlowP->num_supp_ver++;
                // JA3 uses the record version...
                // Set the A/B negotiated version in t2OnFlowTerminate()
            } else {
                int32_t left = ext_len;
                t2buf_skip_u8(t2buf); // skip supported versions length
                left--; // skip supported versions length
                while (left > 0) {
                    if (sslFlowP->num_supp_ver < SSL_MAX_SUPP_VER) {
                        if (!t2buf_read_u16(t2buf, &sslFlowP->supp_ver[sslFlowP->num_supp_ver])) {
                            sslFlowP->stat |= SSL_STAT_SNAP;
                            return false;
                        }
                    } else {
                        t2buf_skip_u16(t2buf);
                        sslFlowP->stat |= SSL_STAT_SUPP_VER_TRUNC;
                    }
                    sslFlowP->num_supp_ver++;
                    left -= 2;
                }
            }
            break;
        }
#endif // SSL_SUPP_VER == 1

        case SSL_HT_HELLO_EXT_RENEG_INFO:
            sslFlowP->stat |= SSL_STAT_RENEGOTIATION;
#if SSL_DETECT_TOR == 1
            *non_tor_ext = true;
#endif
            t2buf_skip_n(t2buf, ext_len);
            break;

#if SSL_EC == 1 || SSL_JA3 == 1
        case SSL_HT_HELLO_EXT_ELLIPTIC_CURVES: {
            if (ext_len == 0) break;
            int32_t left = ext_len;
            t2buf_skip_u16(t2buf); // skip EC points length
            left -= 2; // skip EC points length
            while (left > 0) {
                if (sslFlowP->num_ec < SSL_MAX_EC) {
                    if (!t2buf_read_u16(t2buf, &sslFlowP->ec[sslFlowP->num_ec])) {
                        sslFlowP->stat |= SSL_STAT_SNAP;
                        return false;
                    }
                } else {
                    t2buf_skip_u16(t2buf);
                    sslFlowP->stat |= SSL_STAT_EC_TRUNC;
                }
                sslFlowP->num_ec++;
                left -= 2;
            }
            break;
        }
#endif // SSL_EC == 1 || SSL_JA3 == 1

#if SSL_EC_FORMATS == 1 || SSL_JA3 == 1
        case SSL_HT_HELLO_EXT_EC_POINT_FORMATS: {
            if (ext_len == 0) break;
            int32_t left = ext_len;
            t2buf_skip_u8(t2buf); // skip EC point formats length
            left--; // skip EC point formats length
            while (left > 0) {
                if (sslFlowP->num_ec_formats < SSL_MAX_EC_FORMATS) {
                    if (!t2buf_read_u8(t2buf, &sslFlowP->ec_formats[sslFlowP->num_ec_formats])) {
                        sslFlowP->stat |= SSL_STAT_SNAP;
                        return false;
                    }
                } else {
                    t2buf_skip_u8(t2buf);
                    sslFlowP->stat |= SSL_STAT_EC_TRUNC;
                }
                sslFlowP->num_ec_formats++;
                left--;
            }
            break;
        }
#endif // SSL_EC_FORMATS == 1 || SSL_JA3 == 1

        default:
            t2buf_skip_n(t2buf, ext_len);
            break;
    } // switch ext_type

    return true;
}


#if SSL_ANALYZE_CERT == 1
static inline bool ssl_process_ht_cert(t2buf_t *t2buf, sslFlow_t *sslFlowP
#if SSL_SAVE_CERT == 1 && SSL_CERT_NAME_FINDEX == 1
        , const flow_t * const flowP
#endif
#if SSL_DETECT_TOR == 1
        , bool *single_cert
#endif // SSL_DETECT_TOR == 1
) {

#if (SSL_CERT_SUBJECT > 0 || SSL_CERT_ISSUER > 0)
    X509_NAME *cert_name;
#endif

    // read the length of all certificates
    uint32_t total_cert_len;
    if (!t2buf_read_u24(t2buf, &total_cert_len)) {
        sslFlowP->stat |= SSL_STAT_SNAP;
        return false;
    }

    if (total_cert_len == 0) return true;

    uint32_t cert_len;
    if (!t2buf_read_u24(t2buf, &cert_len)) {
        sslFlowP->stat |= SSL_STAT_SNAP;
        return false;
    }

    if (cert_len == 0) return true;

    const uint8_t *rp = t2buf->buffer + t2buf->pos;
    X509 * const cert = d2i_X509(NULL, (const unsigned char**)&rp, MIN(cert_len, t2buf_left(t2buf)));
    t2buf_skip_n(t2buf, cert_len);
    if (!cert) {
        //sslFlowP->stat |= SSL_STAT_CERT;
        return true;
    }

#if SSL_DETECT_TOR == 1
    if (total_cert_len == cert_len + 3) {
        *single_cert = true;
    }
#endif

    sslFlowP->cert_version = ((uint8_t) X509_get_version(cert)) + 1;

#if SSL_CERT_SUBJECT > 0
    cert_name = X509_get_subject_name(cert);
#endif

    // Certificate Subject
#if SSL_CERT_SUBJECT == 1
    // TODO replaced function with X509_NAME_print_ex() and XN_FLAG_ONELINE & ~ASN1_STRFLGS_ESC_MSB
    sslFlowP->cert_subject = X509_NAME_oneline(cert_name, NULL, 0);
#elif SSL_CERT_SUBJECT == 2
#if SSL_CERT_COMMON_NAME == 1
    X509_NAME_get_text_by_NID(cert_name, NID_commonName, sslFlowP->cert_sCommon, SSL_CERT_NAME_MAXLEN+1);
#endif
#if SSL_CERT_ORGANIZATION == 1
    X509_NAME_get_text_by_NID(cert_name, NID_organizationName, sslFlowP->cert_sOrg, SSL_CERT_NAME_MAXLEN+1);
#endif
#if SSL_CERT_ORG_UNIT == 1
    X509_NAME_get_text_by_NID(cert_name, NID_organizationalUnitName, sslFlowP->cert_sOrgUnit, SSL_CERT_NAME_MAXLEN+1);
#endif
#if SSL_CERT_LOCALITY == 1
    X509_NAME_get_text_by_NID(cert_name, NID_localityName, sslFlowP->cert_sLoc, SSL_CERT_LOC_MAXLEN+1);
#endif
#if SSL_CERT_STATE == 1
    X509_NAME_get_text_by_NID(cert_name, NID_stateOrProvinceName, sslFlowP->cert_sState, SSL_CERT_LOC_MAXLEN+1);
#endif
#if SSL_CERT_COUNTRY == 1
    X509_NAME_get_text_by_NID(cert_name, NID_countryName, sslFlowP->cert_sCountry, SSL_CERT_COUNTRY_LEN+1);
#endif
#endif // SSL_CERT_SUBJECT

    // Certificate Issuer
#if SSL_CERT_ISSUER > 0
    cert_name = X509_get_issuer_name(cert);
#endif
#if SSL_CERT_ISSUER == 1
    sslFlowP->cert_issuer  = X509_NAME_oneline(cert_name, NULL, 0);
#elif SSL_CERT_ISSUER == 2
#if SSL_CERT_COMMON_NAME == 1
    X509_NAME_get_text_by_NID(cert_name, NID_commonName, sslFlowP->cert_iCommon, SSL_CERT_NAME_MAXLEN+1);
#endif
#if SSL_CERT_ORGANIZATION == 1
    X509_NAME_get_text_by_NID(cert_name, NID_organizationName, sslFlowP->cert_iOrg, SSL_CERT_NAME_MAXLEN+1);
#endif
#if SSL_CERT_ORG_UNIT == 1
    X509_NAME_get_text_by_NID(cert_name, NID_organizationalUnitName, sslFlowP->cert_iOrgUnit, SSL_CERT_NAME_MAXLEN+1);
#endif
#if SSL_CERT_LOCALITY == 1
    X509_NAME_get_text_by_NID(cert_name, NID_localityName, sslFlowP->cert_iLoc, SSL_CERT_LOC_MAXLEN+1);
#endif
#if SSL_CERT_STATE == 1
    X509_NAME_get_text_by_NID(cert_name, NID_stateOrProvinceName, sslFlowP->cert_iState, SSL_CERT_LOC_MAXLEN+1);
#endif
#if SSL_CERT_COUNTRY == 1
    X509_NAME_get_text_by_NID(cert_name, NID_countryName, sslFlowP->cert_iCountry, SSL_CERT_COUNTRY_LEN+1);
#endif
#endif // SSL_CERT_ISSUER

#if SSL_CERT_SIG_ALG == 1
    // signature algorithm
    sslFlowP->sig_type = X509_get_signature_nid(cert);
#endif // SSL_CERT_SIG_ALG

    // Public Key
    EVP_PKEY * const key = X509_get_pubkey(cert);
    if (key) {
        sslFlowP->pkey_size = EVP_PKEY_bits(key);
        if (sslFlowP->pkey_size > 0 && sslFlowP->pkey_size < 1024) {
            sslFlowP->stat |= SSL_STAT_WEAK_KEY;
        }

#if SSL_CERT_PUBKEY_TS == 1 || SSL_CERT_PUBKEY_ALG == 1
        sslFlowP->pkey_type = EVP_PKEY_base_id(key);
#endif

        EVP_PKEY_free(key);
    }

#if SSL_CERT_SERIAL == 1
    const ASN1_INTEGER * const  serial = X509_get_serialNumber(cert);
    if (serial) {
        BIGNUM *bnserial = ASN1_INTEGER_to_BN(serial, NULL);
        if (bnserial) {
            sslFlowP->cert_serial = BN_bn2hex(bnserial);
            BN_free(bnserial);
        }
    }
#endif

#if SSL_CERT_VALIDITY == 1
    const ASN1_TIME * const not_before = X509_get_notBefore(cert);
    const ASN1_TIME * const not_after = X509_get_notAfter(cert);

    if (!ssl_asn1_convert(not_before, &sslFlowP->cert_not_before) ||
        !ssl_asn1_convert(not_after, &sslFlowP->cert_not_after))
    {
        // XXX what to do if conversion failed?
    }

    // TODO check certificate validity
    //sslFlowP->stat |= SSL_STAT_CERT_EXPIRED;
#endif

#if SSL_DETECT_TOR == 1
    // check if this flow is likely a Tor flow (using certificate)
    if (is_tor(sslFlowP, cert_len, single_cert)) {
        sslFlowP->is_tor = 1;
    }
#endif

    // TODO to save 'all' certificates, we need to reassemble packets...
#if (SSL_SAVE_CERT == 1 || SSL_CERT_FINGPRINT > 0)
    const EVP_MD *digest;
#if SSL_CERT_FINGPRINT == 2
    digest = EVP_md5();
#else
    digest = EVP_sha1();
#endif

    unsigned int n;
    unsigned char hash[SSL_CERT_SHA1_LEN];
    if (!X509_digest(cert, digest, hash, &n)) {
        X509_free(cert);
        return true;
    }

    for (unsigned int j = 0; j < n; j++) {
        sprintf(&sslFlowP->cert_fingerprint[2*j], "%02" B2T_PRIX8, hash[j]);
    }

#if SSL_BLIST == 1
    const char *blist_cat;
    if ((blist_cat = ssl_blist_lookup(sslbl, sslFlowP->cert_fingerprint))) {
        const size_t blen = strlen(blist_cat)+1;
        memcpy(sslFlowP->blist_cat, blist_cat, MIN(blen, SSL_BLIST_LEN));
        sslFlowP->stat |= SSL_STAT_BLIST;
        numBlistCerts++;
    }
#endif

#if SSL_SAVE_CERT == 1
    const size_t pathLen = strlen(certPath);
    const size_t fingerprintLen = strlen(sslFlowP->cert_fingerprint);
    const size_t extLen = strlen(certExt);
    size_t name_len = pathLen + fingerprintLen + extLen + 1;
#if SSL_CERT_NAME_FINDEX == 1
    name_len += 26 /* UINT64 */ + 1 /* _ */;
#endif // SSL_CERT_NAME_FINDEX == 1
    char name[name_len];
    memcpy(name, certPath, pathLen+1);
    size_t pos = pathLen;
#if SSL_CERT_NAME_FINDEX == 1
    pos += snprintf(&name[pos], 28, "%" PRIu64 "_", flowP->findex);
#endif // SSL_CERT_NAME_FINDEX == 1
    memcpy(name + pos, sslFlowP->cert_fingerprint, fingerprintLen+1);
    memcpy(name + pos + fingerprintLen, certExt, extLen+1);

    // only save/count certificates once
    if (access(name, F_OK) != 0) {
        FILE *f = fopen(name, "wb");
        if (UNLIKELY(!f)) {
            T2_PERR(plugin_name, "failed to open file '%s': %s", name, strerror(errno));
            X509_free(cert);
            return true;
        }
        PEM_write_X509(f, cert);
        fclose(f);
        numSavedCerts++;
    }
#endif // SSL_SAVE_CERT == 1
#endif // SSL_SAVE_CERT == 1 || SSL_CERT_FINGPRINT > 0

    X509_free(cert);

    return true;
}
#endif // SSL_ANALYZE_CERT == 1


#if SSL_JA3 == 1
/*
 * Fingerprints
 * ============
 *
 * ja3 = SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat
 *     md5(769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-24-25,0)
 *     md5(769,4-5-10-9-100-98-3-6-19-18-99,,,)
 *
 * ja3s = SSLVersion,Cipher,SSLExtension
 *     md5(769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11)
 *     md5(769,4-5-10-9-100-98-3-6-19-18-99,)
 */
static inline void ssl_compute_ja3(uint8_t handshake_type, sslFlow_t *sslFlowP) {
    if (strlen(sslFlowP->ja3_hash) != 0) {
        // Only fingerprint the first Client/Server Hello
        return;
    }

    if ((sslFlowP->stat & SSL_STAT_JA3_TRUNC) != 0) {
        // Do not try to fingerprint truncated entries
        sslFlowP->stat |= SSL_STAT_JA3_FAIL;
        return;
    }

    size_t pos = 0;
    char fingerprint[SSL_JA3_STR_LEN];

    // SSLVersion
    pos += snprintf(&fingerprint[pos], SSL_JA3_STR_LEN - pos, "%" PRIu16 ",", sslFlowP->version);
    if (pos >= SSL_JA3_STR_LEN) {
        sslFlowP->stat |= SSL_STAT_JA3_FAIL;
        return;
    }

    // Cipher
    if (handshake_type == SSL_HT_SERVER_HELLO) {
        pos += snprintf(&fingerprint[pos], SSL_JA3_STR_LEN - pos, "%" PRIu16, sslFlowP->cipher);
        if (pos >= SSL_JA3_STR_LEN) {
            sslFlowP->stat |= SSL_STAT_JA3_FAIL;
            return;
        }
#if SSL_CIPHER_LIST == 1
    } else {
        const uint_fast32_t num_cipher = sslFlowP->num_cipher;
        for (uint_fast32_t i = 0; i < num_cipher; i++) {
            if (SSL_IS_GREASE(sslFlowP->cipher_list[i])) continue;
            pos += snprintf(&fingerprint[pos], SSL_JA3_STR_LEN - pos, "%" PRIu16 "%s",
                            sslFlowP->cipher_list[i], i < num_cipher - 1 ? "-" : "");
            if (pos >= SSL_JA3_STR_LEN) {
                sslFlowP->stat |= SSL_STAT_JA3_FAIL;
                return;
            }
        }

        if (fingerprint[pos - 1] == '-') pos--;
#endif
    }

    pos += snprintf(&fingerprint[pos], SSL_JA3_STR_LEN - pos, ",");
    if (pos >= SSL_JA3_STR_LEN) {
        sslFlowP->stat |= SSL_STAT_JA3_FAIL;
        return;
    }

#if SSL_EXT_LIST == 1
    // SSLExtension
    const uint_fast32_t num_ext = sslFlowP->num_ext;
    for (uint_fast32_t i = 0; i < num_ext; i++) {
        if (SSL_IS_GREASE(sslFlowP->ext_list[i])) continue;
        pos += snprintf(&fingerprint[pos], SSL_JA3_STR_LEN - pos, "%" PRIu16 "%s",
                        sslFlowP->ext_list[i], i < num_ext - 1 ? "-" : "");
        if (pos >= SSL_JA3_STR_LEN) {
            sslFlowP->stat |= SSL_STAT_JA3_FAIL;
            return;
        }
    }

    if (fingerprint[pos - 1] == '-') pos--;
#endif

    if (handshake_type == SSL_HT_CLIENT_HELLO) {
        pos += snprintf(&fingerprint[pos], SSL_JA3_STR_LEN - pos, ",");
        if (pos >= SSL_JA3_STR_LEN) {
            sslFlowP->stat |= SSL_STAT_JA3_FAIL;
            return;
        }

#if SSL_EC == 1
        // EllipticCurve
        const uint_fast32_t num_ec = sslFlowP->num_ec;
        for (uint_fast32_t i = 0; i < num_ec; i++) {
            if (SSL_IS_GREASE(sslFlowP->ec[i])) continue;
            pos += snprintf(&fingerprint[pos], SSL_JA3_STR_LEN - pos, "%" PRIu16 "%s",
                            sslFlowP->ec[i], i < num_ec - 1 ? "-" : "");
            if (pos >= SSL_JA3_STR_LEN) {
                sslFlowP->stat |= SSL_STAT_JA3_FAIL;
                return;
            }
        }

        if (fingerprint[pos - 1] == '-') pos--;
#endif

        pos += snprintf(&fingerprint[pos], SSL_JA3_STR_LEN - pos, ",");
        if (pos >= SSL_JA3_STR_LEN) {
            sslFlowP->stat |= SSL_STAT_JA3_FAIL;
            return;
        }

#if SSL_EC_FORMATS == 1
        // EllipticCurvePointFormat
        const uint_fast32_t num_ec_formats = sslFlowP->num_ec_formats;
        for (uint_fast32_t i = 0; i < num_ec_formats; i++) {
            pos += snprintf(&fingerprint[pos], SSL_JA3_STR_LEN - pos, "%" PRIu8 "%s",
                            sslFlowP->ec_formats[i], i < num_ec_formats - 1 ? "-" : "");
            if (pos >= SSL_JA3_STR_LEN) {
                sslFlowP->stat |= SSL_STAT_JA3_FAIL;
                return;
            }
        }
#endif
    }

#if SSL_JA3_STR == 1
    memcpy(sslFlowP->ja3_str, fingerprint, strlen(fingerprint) + 1);
#endif

    t2_md5(fingerprint, strlen(fingerprint), sslFlowP->ja3_hash, sizeof(sslFlowP->ja3_hash), 0);

    const char *ja3_desc;
    if ((ja3_desc = ssl_blist_lookup(sslja3, sslFlowP->ja3_hash))) {
        numJA3++;
        const size_t dlen = strlen(ja3_desc) + 1;
        memcpy(sslFlowP->ja3_desc, ja3_desc, MIN(dlen, SSL_JA3_DLEN));
    }
}
#endif // SSL_JA3 == 1


#if SSL_COMPUTE_JA4

#if SSL_JA4 == 1 || SSL_JA4_R == 1
static inline int cmp_u16(const void *a, const void *b) {
    const uint16_t ua = *(uint16_t*)a;
    const uint16_t ub = *(uint16_t*)b;
    return (ua < ub) ? -1 : (ua > ub) ? 1 : 0;
}
#endif // SSL_JA4 == 1 || SSL_JA4_R == 1


static inline void ssl_compute_ja4(uint8_t handshake_type, sslFlow_t *sslFlowP, const flow_t * const flowP) {
    if (
#if SSL_JA4 == 1
        strlen(sslFlowP->ja4) != 0
#elif SSL_JA4_O == 1
        strlen(sslFlowP->ja4_o) != 0
#elif SSL_JA4_R == 1
        strlen(sslFlowP->ja4_r) != 0
#else // SSL_JA4_RO == 1
        strlen(sslFlowP->ja4_ro) != 0
#endif // SSL_JA4_RO
    ) {
        // Only fingerprint the first Client/Server Hello
        return;
    }

    if (sslFlowP->stat & (SSL_STAT_CIPHERL_TRUNC | SSL_STAT_EXTL_TRUNC)) {
        return;
    }

    if (handshake_type == SSL_HT_CLIENT_HELLO && (sslFlowP->stat & SSL_STAT_SIG_ALG_TRUNC)) {
        return;
    }

    size_t pos = 0;
    char ja4_a[11]; // JA4_a = 10 characters, JA4S_a = 7 characters

    // Protocol (TCP: t, QUIC: q)
    const uint8_t proto = flowP->l4Proto;
    if (proto == L3_TCP) {
        pos += snprintf(&ja4_a[pos], sizeof(ja4_a) - pos, "t");
    } else if (proto == L3_UDP) {
        pos += snprintf(&ja4_a[pos], sizeof(ja4_a) - pos, "q");
    } else {
        sslFlowP->stat |= SSL_STAT_JA4_FAIL;
        return;
    }

    // TLS version
    uint16_t version = sslFlowP->version;
    const uint_fast32_t num_supp_ver = MIN(sslFlowP->num_supp_ver, SSL_MAX_SUPP_VER);
    if (num_supp_ver > 0) {
        uint_fast32_t i;
        for (i = 0; i < num_supp_ver; i++) {
            if (SSL_IS_GREASE(sslFlowP->supp_ver[i])) continue;
            version = sslFlowP->supp_ver[i];
            break;
        }

        if (i == num_supp_ver) {
            // TLS version not found
            sslFlowP->stat |= SSL_STAT_JA4_FAIL;
            return;
        }
    }

    char *version_str;
    if (SSL_V_IS_TLS13(version)) {
        version_str = "13";
    } else if (version == TLSv12) {
        version_str = "12";
    } else if (version == TLSv11) {
        version_str = "11";
    } else if (version == TLSv10) {
        version_str = "10";
    } else if (version == SSLv3) {
        version_str = "s3";
    } else if (version == SSLv2) {
        version_str = "s2";
    } else if (version == SSLv1) {
        version_str = "s1";
    } else {
        // Should not happen
        sslFlowP->stat |= SSL_STAT_JA4_FAIL;
        return;
    }

    pos += snprintf(&ja4_a[pos], sizeof(ja4_a) - pos, "%s", version_str);
    if (pos >= sizeof(ja4_a)) {
        sslFlowP->stat |= SSL_STAT_JA4_FAIL;
        return;
    }

    if (handshake_type == SSL_HT_CLIENT_HELLO) {
        // SNI='d' or no SNI='i'
        bool has_sni = (sslFlowP->server_name[0] != '\0');
        if (!has_sni) {
            for (uint_fast8_t i = 0; i < sslFlowP->num_ext; i++) {
                if (sslFlowP->ext_list[i] == 0) {
                    has_sni = true;
                    break;
                }
            }
        }
        pos += snprintf(&ja4_a[pos], sizeof(ja4_a) - pos, "%c", (has_sni ? 'd' : 'i'));
        if (pos >= sizeof(ja4_a)) {
            sslFlowP->stat |= SSL_STAT_JA4_FAIL;
            return;
        }
    }

    // Number of cipher suites

    const uint_fast32_t num_cipher = sslFlowP->num_cipher;

    // Ignore GREASE values
    uint_fast32_t num_cipher_wo_grease = num_cipher;
    for (uint_fast32_t i = 0; i < num_cipher; i++) {
        if (SSL_IS_GREASE(sslFlowP->cipher_list[i])) num_cipher_wo_grease--;
    }

    if (handshake_type == SSL_HT_CLIENT_HELLO) {
        // Number of cipher suites
        pos += snprintf(&ja4_a[pos], sizeof(ja4_a) - pos, "%02" PRIuFAST32, num_cipher_wo_grease);
        if (pos >= sizeof(ja4_a)) {
            sslFlowP->stat |= SSL_STAT_JA4_FAIL;
            return;
        }
    }

    // Number of extensions

    const uint_fast32_t num_ext = sslFlowP->num_ext;

    // Ignore GREASE values
    uint_fast32_t num_ext_wo_grease = num_ext;
    for (uint_fast32_t i = 0; i < num_ext; i++) {
        if (SSL_IS_GREASE(sslFlowP->ext_list[i])) num_ext_wo_grease--;
    }

    pos += snprintf(&ja4_a[pos], sizeof(ja4_a) - pos, "%02" PRIuFAST32, num_ext_wo_grease);
    if (pos >= sizeof(ja4_a)) {
        sslFlowP->stat |= SSL_STAT_JA4_FAIL;
        return;
    }

    // First ALPN value (00 if no ALPN)
    char alpn[3] = { '0', '0' };
    const uint_fast32_t num_alpn = MIN(sslFlowP->num_alpn, SSL_MAX_PROTO);
    if (num_alpn > 0) {
        uint_fast32_t i;
        for (i = 0; i < num_alpn; i++) {
            // Ignore GREASE values
            if (t2_str_has_prefix(sslFlowP->alpn_list[i], "ignore/")) continue;
            // Ignore invalid (?) entries
            if (strlen(sslFlowP->alpn_list[i]) < 2) continue;
            alpn[0] = sslFlowP->alpn_list[i][0];
            alpn[1] = sslFlowP->alpn_list[i][strlen(sslFlowP->alpn_list[0]) - 1];
            break;
        }

        if (i == num_alpn) {
            sslFlowP->stat |= SSL_STAT_JA4_FAIL;
            return;
        }
    }

    pos += snprintf(&ja4_a[pos], sizeof(ja4_a) - pos, "%s", alpn);
    if (pos >= sizeof(ja4_a)) {
        sslFlowP->stat |= SSL_STAT_JA4_FAIL;
        return;
    }

    sslFlowP->stat |= SSL_STAT_JA4_A_OK;

    if (handshake_type == SSL_HT_SERVER_HELLO) {
        // Selected cipher (JA4S_b)
        char ja4s_b[5] = {};
        snprintf(ja4s_b, sizeof(ja4s_b), "%04x", sslFlowP->cipher);
        sslFlowP->stat |= SSL_STAT_JA4_B_OK;

        // List of extensions in the order they appear (JA4S_c)
        char ja4s_c[SSL_JA4_STR_LEN] = {};
        size_t ja4s_c_pos = 0;
        char *sep = "";
        for (uint_fast32_t i = 0; i < num_ext; i++) {
            if (SSL_IS_GREASE(sslFlowP->ext_list[i])) continue;
            ja4s_c_pos += snprintf(&ja4s_c[ja4s_c_pos], sizeof(ja4s_c) - ja4s_c_pos,
                                   "%s%04x", sep, sslFlowP->ext_list[i]);
            sep = ",";
            if (ja4s_c_pos >= sizeof(ja4s_c)) {
                sslFlowP->stat |= (SSL_STAT_JA4_TRUNC | SSL_STAT_JA4_FAIL);
                break;
            }
        }

#if SSL_JA4 == 1 || SSL_JA4_O == 1
        char ja4s_c_hash[T2_SHA256_STRLEN + 1] = {};
#endif // SSL_JA4 == 1 || SSL_JA4_O == 1

        if (!(sslFlowP->stat & SSL_STAT_JA4_FAIL)) {
#if SSL_JA4 == 1 || SSL_JA4_O == 1
            // compute and truncate sha256
            t2_sha256(ja4s_c, strlen(ja4s_c), ja4s_c_hash, sizeof(ja4s_c_hash), 0);
            ja4s_c_hash[SSL_JA4_TRUNC_HASH_LEN] = '\0';
#endif // SSL_JA4 == 1 || SSL_JA4_O == 1

            sslFlowP->stat |= SSL_STAT_JA4_C_OK;
#if SSL_JA4_R == 1 || SSL_JA4_RO == 1
        } else {
            // Failed to compute JA4S_c...
            ja4s_c[0] = '\0';
#endif // SSL_JA4_R == 1 || SSL_JA4_RO == 1
        }

        // build the fingerprint
#if SSL_JA4 == 1
        t2_strcat(sslFlowP->ja4, sizeof(sslFlowP->ja4), ja4_a, "_", ja4s_b, "_", ja4s_c_hash, NULL);

        const char *ja4s_desc;
        if ((ja4s_desc = ssl_blist_lookup(sslja4s, sslFlowP->ja4))) {
            numJA4S++;
            const size_t dlen = strlen(ja4s_desc) + 1;
            memcpy(sslFlowP->ja4_desc, ja4s_desc, MIN(dlen, SSL_JA4_DLEN));
        }
#endif
#if SSL_JA4_O == 1
        t2_strcat(sslFlowP->ja4_o, sizeof(sslFlowP->ja4_o), ja4_a, "_", ja4s_b, "_", ja4s_c_hash, NULL);
#endif
#if SSL_JA4_R == 1
        t2_strcat(sslFlowP->ja4_r, sizeof(sslFlowP->ja4_r), ja4_a, "_", ja4s_b, "_", ja4s_c, NULL);
#endif
#if SSL_JA4_RO == 1
        t2_strcat(sslFlowP->ja4_ro, sizeof(sslFlowP->ja4_ro), ja4_a, "_", ja4s_b, "_", ja4s_c, NULL);
#endif

    } else { // handshake_type == SSL_HT_CLIENT_HELLO

#if SSL_JA4 == 1 || SSL_JA4_R == 1
        // cipher suites sorted (JA4_b)
        uint16_t sorted_cipher[num_cipher_wo_grease];
        for (uint_fast32_t i = 0, j = 0; i < num_cipher; i++) {
            if (SSL_IS_GREASE(sslFlowP->cipher_list[i])) continue;
            sorted_cipher[j++] = sslFlowP->cipher_list[i];
        }
        qsort(sorted_cipher, num_cipher_wo_grease, sizeof(sorted_cipher[0]), cmp_u16);
#endif // SSL_JA4 == 1 || SSL_JA4_R == 1

#if SSL_JA4 == 1 || SSL_JA4_R == 1
        char ja4_r_b[SSL_JA4_STR_LEN] = {};
        size_t ja4_r_b_pos = 0;
#endif // SSL_JA4 == 1 || SSL_JA4_R == 1
#if SSL_JA4_O == 1 || SSL_JA4_RO == 1
        char ja4_o_b[SSL_JA4_STR_LEN] = {};
        size_t ja4_o_b_pos = 0;
#endif // SSL_JA4_O == 1 || SSL_JA4_RO == 1
        char *sep = "";
        for (uint_fast32_t i = 0; i < num_cipher_wo_grease; i++) {
#if SSL_JA4 == 1 || SSL_JA4_R == 1
            ja4_r_b_pos += snprintf(&ja4_r_b[ja4_r_b_pos], sizeof(ja4_r_b) - ja4_r_b_pos,
                                    "%s%04x", sep, sorted_cipher[i]);
            if (ja4_r_b_pos >= sizeof(ja4_r_b)) {
                sslFlowP->stat |= (SSL_STAT_JA4_TRUNC | SSL_STAT_JA4_FAIL);
                break;
            }
#endif // SSL_JA4 == 1 || SSL_JA4_R == 1
#if SSL_JA4_O == 1 || SSL_JA4_RO == 1
            ja4_o_b_pos += snprintf(&ja4_o_b[ja4_o_b_pos], sizeof(ja4_o_b) - ja4_o_b_pos, "%s%04x", sep, sslFlowP->cipher_list[i]);
            if (ja4_o_b_pos >= sizeof(ja4_o_b)) {
                sslFlowP->stat |= (SSL_STAT_JA4_TRUNC | SSL_STAT_JA4_FAIL);
                break;
            }
#endif // SSL_JA4_O == 1 || SSL_JA4_RO == 1
            sep = ",";
        }

#if SSL_JA4 == 1
        // compute and truncate sha256
        char ja4_b_hash[T2_SHA256_STRLEN + 1] = {};
        if (!(sslFlowP->stat & SSL_STAT_JA4_FAIL)) {
            t2_sha256(ja4_r_b, strlen(ja4_r_b), ja4_b_hash, sizeof(ja4_b_hash), 0);
            ja4_b_hash[SSL_JA4_TRUNC_HASH_LEN] = '\0';
        }
#endif // SSL_JA4 == 1

#if SSL_JA4_O == 1
        // compute and truncate sha256 (original order)
        char ja4_o_b_hash[T2_SHA256_STRLEN + 1] = {};
        if (!(sslFlowP->stat & SSL_STAT_JA4_FAIL)) {
            t2_sha256(ja4_o_b, strlen(ja4_o_b), ja4_o_b_hash, sizeof(ja4_o_b_hash), 0);
            ja4_o_b_hash[SSL_JA4_TRUNC_HASH_LEN] = '\0';
        }
#endif // SSL_JA4_O == 1

        if (!(sslFlowP->stat & SSL_STAT_JA4_FAIL)) {
            sslFlowP->stat |= SSL_STAT_JA4_B_OK;
        } else {
            // Failed to compute JA4_b...
#if SSL_JA4_R == 1
            ja4_r_b[0] = '\0';
#endif // SSL_JA4_R == 1
#if SSL_JA4_RO == 1
            ja4_o_b[0] = '\0';
#endif // SSL_JA4_RO == 1
        }

        // extensions sorted + signature algorithms in the order they appear (JA4_c)

        // extensions sorted
#if SSL_JA4 == 1 || SSL_JA4_R == 1
        uint16_t num_ext_wo_grease_sni_alpn = num_ext_wo_grease;
        uint16_t sorted_ext[num_ext_wo_grease_sni_alpn];
#endif // SSL_JA4 == 1 || SSL_JA4_R == 1
#if SSL_JA4_O == 1 || SSL_JA4_RO == 1
        char ja4_o_c[SSL_JA4_STR_LEN] = {};
        size_t ja4_o_c_pos = 0;
        sep = "";
#endif // SSL_JA4_O == 1 || SSL_JA4_RO == 1
        for (uint_fast32_t i = 0, j = 0; i < num_ext; i++) {
            if (SSL_IS_GREASE(sslFlowP->ext_list[i])) continue;
#if SSL_JA4_O == 1 || SSL_JA4_RO == 1
            ja4_o_c_pos += snprintf(&ja4_o_c[ja4_o_c_pos], sizeof(ja4_o_c) - ja4_o_c_pos, "%s%04x", sep, sslFlowP->ext_list[i]);
            sep = ",";
            if (ja4_o_c_pos >= sizeof(ja4_o_c)) {
                sslFlowP->stat |= (SSL_STAT_JA4_TRUNC | SSL_STAT_JA4_FAIL);
                break;
            }
#endif // SSL_JA4_O == 1 || SSL_JA4_RO == 1
#if !(SSL_JA4 == 1 || SSL_JA4_R == 1)
            (void)j; // silence warning
#else // SSL_JA4 == 1 || SSL_JA4_R == 1
            if (sslFlowP->ext_list[i] == 0x0000 || sslFlowP->ext_list[i] == 0x0010) {
                // Ignore SNI and ALPN extensions
                num_ext_wo_grease_sni_alpn--;
                continue;
            }
            sorted_ext[j++] = sslFlowP->ext_list[i];
#endif // SSL_JA4 == 1 || SSL_JA4_R == 1
        }
#if SSL_JA4 == 1 || SSL_JA4_R == 1
        qsort(sorted_ext, num_ext_wo_grease_sni_alpn, sizeof(sorted_ext[0]), cmp_u16);
#endif // SSL_JA4 == 1 || SSL_JA4_R == 1

        const uint_fast32_t num_sig_alg = sslFlowP->num_sig_alg;

#if SSL_JA4_O == 1 || SSL_JA4_RO == 1
        if (num_sig_alg > 0) {
            ja4_o_c_pos += snprintf(&ja4_o_c[ja4_o_c_pos], sizeof(ja4_o_c) - ja4_o_c_pos, "_");
            if (ja4_o_c_pos >= sizeof(ja4_o_c)) {
                sslFlowP->stat |= (SSL_STAT_JA4_TRUNC | SSL_STAT_JA4_FAIL);
            }
        }
#endif // SSL_JA4_O == 1 || SSL_JA4_RO == 1

#if SSL_JA4 == 1 || SSL_JA4_R == 1
        char ja4_r_c[SSL_JA4_STR_LEN] = {};
        size_t ja4_r_c_pos = 0;
        sep = "";
        for (uint_fast32_t i = 0; i < num_ext_wo_grease_sni_alpn; i++) {
            ja4_r_c_pos += snprintf(&ja4_r_c[ja4_r_c_pos], sizeof(ja4_r_c) - ja4_r_c_pos, "%s%04x", sep, sorted_ext[i]);
            sep = ",";
            if (ja4_r_c_pos >= sizeof(ja4_r_c)) {
                sslFlowP->stat |= (SSL_STAT_JA4_TRUNC | SSL_STAT_JA4_FAIL);
                break;
            }
        }

        if (num_sig_alg > 0) {
            ja4_r_c_pos += snprintf(&ja4_r_c[ja4_r_c_pos], sizeof(ja4_r_c) - ja4_r_c_pos, "_");
            if (ja4_r_c_pos >= sizeof(ja4_r_c)) {
                sslFlowP->stat |= (SSL_STAT_JA4_TRUNC | SSL_STAT_JA4_FAIL);
            }
        }
#endif // SSL_JA4 == 1 || SSL_JA4_R == 1

        sep = "";
        for (uint_fast32_t i = 0; i < num_sig_alg; i++) {
            if (SSL_IS_GREASE(sslFlowP->sig_alg[i])) continue;
#if SSL_JA4 == 1 || SSL_JA4_R == 1
            ja4_r_c_pos += snprintf(&ja4_r_c[ja4_r_c_pos], sizeof(ja4_r_c) - ja4_r_c_pos,
                                    "%s%04x", sep, sslFlowP->sig_alg[i]);
            if (ja4_r_c_pos >= sizeof(ja4_r_c)) {
                sslFlowP->stat |= (SSL_STAT_JA4_TRUNC | SSL_STAT_JA4_FAIL);
                break;
            }
#endif // SSL_JA4 == 1 || SSL_JA4_R == 1
#if SSL_JA4_O == 1 || SSL_JA4_RO == 1
            ja4_o_c_pos += snprintf(&ja4_o_c[ja4_o_c_pos], sizeof(ja4_o_c) - ja4_o_c_pos, "%s%04x", sep, sslFlowP->sig_alg[i]);
            if (ja4_o_c_pos >= sizeof(ja4_o_c)) {
                sslFlowP->stat |= (SSL_STAT_JA4_TRUNC | SSL_STAT_JA4_FAIL);
                break;
            }
#endif // SSL_JA4_O == 1 || SSL_JA4_RO == 1
            sep = ",";
        }

#if SSL_JA4 == 1
        // compute and truncate sha256
        char ja4_c_hash[T2_SHA256_STRLEN + 1] = {};
        if (!(sslFlowP->stat & SSL_STAT_JA4_FAIL)) {
            t2_sha256(ja4_r_c, strlen(ja4_r_c), ja4_c_hash, sizeof(ja4_c_hash), 0);
            ja4_c_hash[SSL_JA4_TRUNC_HASH_LEN] = '\0';
        }
#endif // SSL_JA4 == 1

#if SSL_JA4_O == 1
        // compute and truncate sha256 (original order)
        char ja4_o_c_hash[T2_SHA256_STRLEN + 1] = {};
        if (!(sslFlowP->stat & SSL_STAT_JA4_FAIL)) {
            t2_sha256(ja4_o_c, strlen(ja4_o_c), ja4_o_c_hash, sizeof(ja4_o_c_hash), 0);
            ja4_o_c_hash[SSL_JA4_TRUNC_HASH_LEN] = '\0';
        }
#endif // SSL_JA4_O

        if (!(sslFlowP->stat & SSL_STAT_JA4_FAIL)) {
            sslFlowP->stat |= SSL_STAT_JA4_C_OK;
        } else {
            // Failed to compute JA4_c...
#if SSL_JA4_R == 1
            ja4_r_c[0] = '\0';
#endif // SSL_JA4_R == 1
#if SSL_JA4_RO == 1
            ja4_o_c[0] = '\0';
#endif // SSL_JA4_RO == 1
        }

        // build the fingerprints
#if SSL_JA4 == 1
        t2_strcat(sslFlowP->ja4, sizeof(sslFlowP->ja4), ja4_a, "_", ja4_b_hash, "_", ja4_c_hash, NULL);

        const char *ja4_desc;
        if ((ja4_desc = ssl_blist_lookup(sslja4, sslFlowP->ja4))) {
            numJA4++;
            const size_t dlen = strlen(ja4_desc) + 1;
            memcpy(sslFlowP->ja4_desc, ja4_desc, MIN(dlen, SSL_JA4_DLEN));
        }
#endif
#if SSL_JA4_O == 1
        t2_strcat(sslFlowP->ja4_o, sizeof(sslFlowP->ja4_o), ja4_a, "_", ja4_o_b_hash, "_", ja4_o_c_hash, NULL);
#endif
#if SSL_JA4_R == 1
        t2_strcat(sslFlowP->ja4_r, sizeof(sslFlowP->ja4_r), ja4_a, "_", ja4_r_b, "_", ja4_r_c, NULL);
#endif
#if SSL_JA4_RO == 1
        t2_strcat(sslFlowP->ja4_ro, sizeof(sslFlowP->ja4_ro), ja4_a, "_", ja4_o_b, "_", ja4_o_c, NULL);
#endif
    }
}

#endif // SSL_COMPUTE_JA4


void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {
    sslFlow_t *sslFlowP = &sslFlow[flowIndex];

    const bool ssl_v_is_valid = (sslFlowP->version != 0);

    if (ssl_v_is_valid) {
#if SSL_SUPP_VER == 1
        bool version_updated = false;
        const flow_t * const flowP = &flows[flowIndex];

        // Extract negotiated version from B flow if available
        if (FLOW_IS_A(flowP) && FLOW_HAS_OPPOSITE(flowP)) {
            sslFlow_t *revFlowP = &sslFlow[flowP->oppositeFlowIndex];
            for (uint_fast32_t i = 0; i < revFlowP->num_supp_ver; i++) {
                if (SSL_IS_GREASE(revFlowP->supp_ver[i])) continue;
                sslFlowP->version = revFlowP->supp_ver[i];
                version_updated = true;
                break;
            }
        }

        // Use the first non-GREASE supported version
        if (!version_updated) {
            for (uint_fast32_t i = 0; i < sslFlowP->num_supp_ver; i++) {
                if (SSL_IS_GREASE(sslFlowP->supp_ver[i])) continue;
                sslFlowP->version = sslFlowP->supp_ver[i];
                break;
            }
        }
#endif // SSL_SUPP_VER == 1

        const uint16_t version = sslFlowP->version;
        if (SSL_V_IS_TLS13_FBD(version)) {
            if (version == TLSv13_FBD26) numTLS13FBD[1]++;
            else if (version == TLSv13_FBD23) numTLS13FBD[0]++;
        } else if (SSL_V_IS_TLS13_D(version)) {
            numTLS13D[version - TLSv13_D14]++;
        } else if (SSL_V_IS_SSL(version)) {
            numSSL3[SSL_V_MINOR(version)]++;
        } else if (SSL_V_IS_DTLS(version)) {
            numDTLS[(version == DTLSv10 ? 0 :
                     version == DTLSv12 ? 1 :
                     version == DTLSv13 ? 2 : 3)]++;
        }
    } else {
        // fix erroneous early detection
        if (!sslFlowP->proto) sslFlowP->stat = 0;
        sslFlowP->vuln = 0;
        sslFlowP->num_change_cipher = 0;
        sslFlowP->num_alert = 0;
        sslFlowP->num_handshake = 0;
        sslFlowP->num_app_data = 0;
        sslFlowP->num_heartbeat = 0;
    }

    sslStat  |= sslFlowP->stat;
    sslProto |= sslFlowP->proto;

#if SSL_DETECT_TOR == 1
    if (sslFlowP->is_tor) numTor++;
#endif // SSL_DETECT_TOR == 1

#if SSL_REC_VER     == 1 || SSL_HAND_VER == 1 || SSL_EXT_LIST   == 1 || \
    SSL_SUPP_VER    == 1 || SSL_SIG_ALG  == 1 || SSL_ALPN_LIST  == 1 || \
    SSL_CIPHER_LIST == 1 || SSL_EC       == 1 || SSL_EC_FORMATS == 1 || \
    SSL_ALPS_LIST   == 1 || SSL_NPN_LIST == 1
    uint32_t imax;
#endif

    OUTBUF_APPEND_U32(buf, sslFlowP->stat);       // sslStat
    OUTBUF_APPEND_U32(buf, sslFlowP->proto);      // sslProto

#if SSL_ANALYZE_OVPN == 1
    OUTBUF_APPEND_U16(buf, sslFlowP->ovpnType);   // ovpnType
    OUTBUF_APPEND_U64(buf, sslFlowP->ovpnSessID); // ovpnSessionID
#endif

    OUTBUF_APPEND_U8(buf , sslFlowP->flags);      // sslFlags
    OUTBUF_APPEND_U16(buf, sslFlowP->version);    // sslVersion

#if SSL_REC_VER == 1
    OUTBUF_APPEND_U16(buf, sslFlowP->num_rec_ver);           // sslNumRecVer
    imax = MIN(sslFlowP->num_rec_ver, SSL_MAX_REC_VER);
    OUTBUF_APPEND_ARRAY_U16(buf, sslFlowP->rec_ver, imax);   // sslRecVer
#endif

#if SSL_HAND_VER == 1
    OUTBUF_APPEND_U16(buf, sslFlowP->num_hand_ver);          // sslNumHandVer
    imax = MIN(sslFlowP->num_hand_ver, SSL_MAX_HAND_VER);
    OUTBUF_APPEND_ARRAY_U16(buf, sslFlowP->hand_ver, imax);  // sslHandVer
#endif

    OUTBUF_APPEND_U8(buf , sslFlowP->vuln);       // sslVuln
    OUTBUF_APPEND_U64(buf, sslFlowP->alert);      // sslAlert
    OUTBUF_APPEND_U16(buf, sslFlowP->cipher);     // sslCipher

#if SSL_EXT_LIST == 1
    OUTBUF_APPEND_U16(buf, sslFlowP->num_ext);                 // sslNumExt
    imax = MIN(sslFlowP->num_ext, SSL_MAX_EXT);
    OUTBUF_APPEND_ARRAY_U16(buf, sslFlowP->ext_list, imax);    // sslExtList
#endif

#if SSL_SUPP_VER == 1
    OUTBUF_APPEND_U16(buf, sslFlowP->num_supp_ver);            // sslNumSuppVer
    imax = MIN(sslFlowP->num_supp_ver, SSL_MAX_SUPP_VER);
    OUTBUF_APPEND_ARRAY_U16(buf, sslFlowP->supp_ver, imax);    // sslSuppVer
#endif

#if SSL_SIG_ALG == 1
    OUTBUF_APPEND_U16(buf, sslFlowP->num_sig_alg);             // sslNumSigAlg
    imax = MIN(sslFlowP->num_sig_alg, SSL_MAX_SIG_ALG);
    OUTBUF_APPEND_ARRAY_U16(buf, sslFlowP->sig_alg, imax);     // sslSigAlg
#endif

#if SSL_EC == 1
    OUTBUF_APPEND_U16(buf, sslFlowP->num_ec);                  // sslNumECPt
    imax = MIN(sslFlowP->num_ec, SSL_MAX_EC);
    OUTBUF_APPEND_ARRAY_U16(buf, sslFlowP->ec, imax);          // sslECPt
#endif

#if SSL_EC_FORMATS == 1
    OUTBUF_APPEND_U8(buf, sslFlowP->num_ec_formats);           // sslNumECFormats
    imax = MIN(sslFlowP->num_ec_formats, SSL_MAX_EC_FORMATS);
    OUTBUF_APPEND_ARRAY_U8(buf, sslFlowP->ec_formats, imax);   // sslECFormats
#endif

#if SSL_ALPN_LIST == 1
    OUTBUF_APPEND_U16(buf, sslFlowP->num_alpn);                // sslNumALPN
    imax = MIN(sslFlowP->num_alpn, SSL_MAX_PROTO);
    OUTBUF_APPEND_ARRAY_STR(buf, sslFlowP->alpn_list, imax);   // sslALPNList
#endif

#if SSL_ALPS_LIST == 1
    OUTBUF_APPEND_U16(buf, sslFlowP->num_alps);                // sslNumALPS
    imax = MIN(sslFlowP->num_alps, SSL_MAX_PROTO);
    OUTBUF_APPEND_ARRAY_STR(buf, sslFlowP->alps_list, imax);   // sslALPSList
#endif

#if SSL_NPN_LIST == 1
    OUTBUF_APPEND_U16(buf, sslFlowP->num_npn);                 // sslNumNPN
    imax = MIN(sslFlowP->num_npn, SSL_MAX_PROTO);
    OUTBUF_APPEND_ARRAY_STR(buf, sslFlowP->npn_list, imax);    // sslNPNList
#endif

#if SSL_CIPHER_LIST == 1
    OUTBUF_APPEND_U16(buf, sslFlowP->num_cipher);              // sslNumCipher
    imax = MIN(sslFlowP->num_cipher, SSL_MAX_CIPHER);
    OUTBUF_APPEND_ARRAY_U16(buf, sslFlowP->cipher_list, imax); // sslCipherList
#endif

    // sslNumCC_A_H_AD_HB
    OUTBUF_APPEND_U16(buf, sslFlowP->num_change_cipher);
    OUTBUF_APPEND_U16(buf, sslFlowP->num_alert);
    OUTBUF_APPEND_U16(buf, sslFlowP->num_handshake);
    OUTBUF_APPEND_U64(buf, sslFlowP->num_app_data);
    OUTBUF_APPEND_U64(buf, sslFlowP->num_heartbeat);

    OUTBUF_APPEND_U8(buf , sslFlowP->session_len);  // sslSessIdLen

    if (!ssl_v_is_valid) {
        OUTBUF_APPEND_NUMREP_ZERO(buf); // sslGMTTime
        OUTBUF_APPEND_NUMREP_ZERO(buf); // sslServerName

#if SSL_ANALYZE_CERT == 1
        OUTBUF_APPEND_NUMREP_ZERO(buf); // sslCertVersion

#if SSL_CERT_SERIAL == 1
        OUTBUF_APPEND_NUMREP_ZERO(buf); // sslCertSerial
#endif

#if SSL_CERT_FINGPRINT > 0
        OUTBUF_APPEND_NUMREP_ZERO(buf); // sslCertMd5FP/sslCertSha1FP
#endif

#if SSL_CERT_VALIDITY == 1
        OUTBUF_APPEND_NUMREP_ZERO(buf); // sslCNotValidBefore_after_lifetime
#endif

#if SSL_CERT_SIG_ALG == 1
        OUTBUF_APPEND_NUMREP_ZERO(buf); // sslCSigAlg
#endif

#if SSL_CERT_PUBKEY_ALG == 1
        OUTBUF_APPEND_NUMREP_ZERO(buf); // sslCKeyAlg
#endif

#if SSL_CERT_PUBKEY_TS == 1
        OUTBUF_APPEND_NUMREP_ZERO(buf); // sslCPKeyType_Size
#endif

        // Cert subject
#if SSL_CERT_SUBJECT == 1
        OUTBUF_APPEND_NUMREP_ZERO(buf); // sslCSubject
#elif SSL_CERT_SUBJECT == 2
#if SSL_CERT_COMMON_NAME == 1
        OUTBUF_APPEND_NUMREP_ZERO(buf); // sslCSubjectCommonName
#endif
#if SSL_CERT_ORGANIZATION == 1
        OUTBUF_APPEND_NUMREP_ZERO(buf); // sslCSubjectOrgName
#endif
#if SSL_CERT_ORG_UNIT == 1
        OUTBUF_APPEND_NUMREP_ZERO(buf); // sslCSubjectOrgUnit
#endif
#if SSL_CERT_LOCALITY == 1
        OUTBUF_APPEND_NUMREP_ZERO(buf); // sslCSubjectLocality
#endif
#if SSL_CERT_STATE == 1
        OUTBUF_APPEND_NUMREP_ZERO(buf); // sslCSubjectState
#endif
#if SSL_CERT_COUNTRY == 1
        OUTBUF_APPEND_NUMREP_ZERO(buf); // sslCSubjectCountry
#endif
#endif // SSL_CERT_SUBJECT

        // Cert issuer
#if SSL_CERT_ISSUER == 1
        OUTBUF_APPEND_NUMREP_ZERO(buf); // sslCIssuer
#elif SSL_CERT_ISSUER == 2
#if SSL_CERT_COMMON_NAME == 1
        OUTBUF_APPEND_NUMREP_ZERO(buf); // sslCIssuerCommonName
#endif
#if SSL_CERT_ORGANIZATION == 1
        OUTBUF_APPEND_NUMREP_ZERO(buf); // sslCIssuerOrgName
#endif
#if SSL_CERT_ORG_UNIT == 1
        OUTBUF_APPEND_NUMREP_ZERO(buf); // sslCIssuerOrgUnit
#endif
#if SSL_CERT_LOCALITY == 1
        OUTBUF_APPEND_NUMREP_ZERO(buf); // sslCIssuerLocality
#endif
#if SSL_CERT_STATE == 1
        OUTBUF_APPEND_NUMREP_ZERO(buf); // sslCIssuerState
#endif
#if SSL_CERT_COUNTRY == 1
        OUTBUF_APPEND_NUMREP_ZERO(buf); // sslCIssuerCountry
#endif
#endif // SSL_CERT_ISSUER

#endif // SSL_ANALYZE_CERT == 1
    } else { // ssl_v_is_valid

        // sslGMTTime
        if (sslFlowP->gmt_time == 0) {
            OUTBUF_APPEND_NUMREP_ZERO(buf);
        } else {
            OUTBUF_APPEND_NUMREP_ONE(buf);
            OUTBUF_APPEND_TIME_SEC(buf, sslFlowP->gmt_time);
        }

        // sslServerName
        if (sslFlowP->server_name[0] == '\0' && FLOW_HAS_OPPOSITE(&(flows[flowIndex]))) {
            OUTBUF_APPEND_OPT_STR(buf, sslFlow[flows[flowIndex].oppositeFlowIndex].server_name);
        } else {
            OUTBUF_APPEND_OPT_STR(buf, sslFlowP->server_name);
        }

#if SSL_ANALYZE_CERT == 1

        // sslCertVersion
        if (sslFlowP->cert_version == 0) {
            OUTBUF_APPEND_NUMREP_ZERO(buf);
        } else {
            OUTBUF_APPEND_NUMREP_ONE(buf);
            OUTBUF_APPEND_U8(buf, sslFlowP->cert_version);
        }

#if SSL_CERT_SERIAL == 1
        // sslCertSerial
        OUTBUF_APPEND_OPT_STR(buf, sslFlowP->cert_serial);
        OPENSSL_free(sslFlowP->cert_serial);
#endif

#if SSL_CERT_FINGPRINT > 0
        // sslCertMd5FP/sslCertSha1FP
        OUTBUF_APPEND_OPT_STR(buf, sslFlowP->cert_fingerprint);
#endif

#if SSL_CERT_VALIDITY == 1
        // sslCNotValidBefore_after_lifetime
        if (sslFlowP->cert_not_before.tm_mday == 0 || sslFlowP->cert_not_after.tm_mday == 0) { // mday starts at one
            OUTBUF_APPEND_NUMREP_ZERO(buf);
        } else {
            // time was given as UTC. Ignore daylight saving time.
            sslFlowP->cert_not_before.tm_isdst = -1;
            sslFlowP->cert_not_after.tm_isdst = -1;
            OUTBUF_APPEND_NUMREP_ONE(buf);
            const uint64_t t1 = mktime(&sslFlowP->cert_not_before);
            OUTBUF_APPEND_TIME_SEC(buf, t1);
            const uint64_t t2 = mktime(&sslFlowP->cert_not_after);
            OUTBUF_APPEND_TIME_SEC(buf, t2);
            const uint64_t d = t2 - t1;
            OUTBUF_APPEND_U64(buf, d);
        }
#endif

#if SSL_CERT_SIG_ALG == 1
        // sslCSigAlg
        if (sslFlowP->cert_version == 0) {
            OUTBUF_APPEND_NUMREP_ZERO(buf);
        } else {
#if SSL_CERT_ALG_NAME_LONG == 0
            const char *sig_alg = OBJ_nid2sn(sslFlowP->sig_type);
#else // SSL_CERT_ALG_NAME_LONG == 1
            const char *sig_alg = OBJ_nid2ln(sslFlowP->sig_type);
#endif // SSL_CERT_ALG_NAME_LONG
            OUTBUF_APPEND_OPT_STR(buf, sig_alg);
        }
#endif // SSL_CERT_SIG_ALG == 1

#if SSL_CERT_PUBKEY_ALG == 1
        // sslCKeyAlg
        if (sslFlowP->cert_version == 0) {
            OUTBUF_APPEND_NUMREP_ZERO(buf);
        } else {
#if SSL_CERT_ALG_NAME_LONG == 0
            const char *pkey_alg = OBJ_nid2sn(sslFlowP->pkey_type);
#else // SSL_CERT_ALG_NAME_LONG == 1
            const char *pkey_alg = OBJ_nid2ln(sslFlowP->pkey_type);
#endif // SSL_CERT_ALG_NAME_LONG
            OUTBUF_APPEND_OPT_STR(buf, pkey_alg);
        }
#endif // SSL_CERT_PUBKEY_ALG == 1

#if SSL_CERT_PUBKEY_TS == 1
        // sslCPKeyType_Size
        if (sslFlowP->pkey_type == 0 && sslFlowP->pkey_size == 0) {
            OUTBUF_APPEND_NUMREP_ZERO(buf);
        } else {
            OUTBUF_APPEND_NUMREP_ONE(buf);
            char *pkey_type;
            switch (sslFlowP->pkey_type) {
                case EVP_PKEY_RSA  : pkey_type = "RSA"  ; break;
                case EVP_PKEY_DSA  : pkey_type = "DSA"  ; break;
                case EVP_PKEY_EC   : pkey_type = "ECDSA"; break;
                default: /*Unknown*/ pkey_type = "UNDEF"; break;
            }
            OUTBUF_APPEND_STR(buf, pkey_type);
            OUTBUF_APPEND_U16(buf, sslFlowP->pkey_size);
        }
#endif

        // Certificate Subject
#if SSL_CERT_SUBJECT == 1
        OUTBUF_APPEND_OPT_STR(buf, sslFlowP->cert_subject);  // sslCSubject
        OPENSSL_free(sslFlowP->cert_subject);
#elif SSL_CERT_SUBJECT == 2
#if SSL_CERT_COMMON_NAME == 1
        OUTBUF_APPEND_OPT_STR(buf, sslFlowP->cert_sCommon);  // sslCSubjectCommonName
#endif
#if SSL_CERT_ORGANIZATION == 1
        OUTBUF_APPEND_OPT_STR(buf, sslFlowP->cert_sOrg);     // sslCSubjectOrgName
#endif
#if SSL_CERT_ORG_UNIT == 1
        OUTBUF_APPEND_OPT_STR(buf, sslFlowP->cert_sOrgUnit); // sslCSubjectOrgUnit
#endif
#if SSL_CERT_LOCALITY == 1
        OUTBUF_APPEND_OPT_STR(buf, sslFlowP->cert_sLoc);     // sslCSubjectLocality
#endif
#if SSL_CERT_STATE == 1
        OUTBUF_APPEND_OPT_STR(buf, sslFlowP->cert_sState);   // sslCSubjectState
#endif
#if SSL_CERT_COUNTRY == 1
        OUTBUF_APPEND_OPT_STR(buf, sslFlowP->cert_sCountry); // sslCSubjectCountry
#endif
#endif // SSL_CERT_SUBJECT

        // Certificate Issuer
#if SSL_CERT_ISSUER == 1
        OUTBUF_APPEND_OPT_STR(buf, sslFlowP->cert_issuer);   // sslCIssuer
        OPENSSL_free(sslFlowP->cert_issuer);
#elif SSL_CERT_ISSUER == 2
#if SSL_CERT_COMMON_NAME == 1
        OUTBUF_APPEND_OPT_STR(buf, sslFlowP->cert_iCommon);  // sslCIssuerCommonName
#endif
#if SSL_CERT_ORGANIZATION == 1
        OUTBUF_APPEND_OPT_STR(buf, sslFlowP->cert_iOrg);     // sslCIssuerOrgName
#endif
#if SSL_CERT_ORG_UNIT == 1
        OUTBUF_APPEND_OPT_STR(buf, sslFlowP->cert_iOrgUnit); // sslCIssuerOrgUnit
#endif
#if SSL_CERT_LOCALITY == 1
        OUTBUF_APPEND_OPT_STR(buf, sslFlowP->cert_iLoc);     // sslCIssuerLocality
#endif
#if SSL_CERT_STATE == 1
        OUTBUF_APPEND_OPT_STR(buf, sslFlowP->cert_iState);   // sslCIssuerState
#endif
#if SSL_CERT_COUNTRY == 1
        OUTBUF_APPEND_OPT_STR(buf, sslFlowP->cert_iCountry); // sslCIssuerCountry
#endif
#endif // SSL_CERT_ISSUER

#endif // SSL_ANALYZE_CERT
    }

#if SSL_BLIST == 1
    OUTBUF_APPEND_OPT_STR(buf, sslFlowP->blist_cat);    // sslBlistCat
#endif

#if SSL_JA3 == 1
    OUTBUF_APPEND_OPT_STR(buf, sslFlowP->ja3_hash);     // sslJA3Hash
    OUTBUF_APPEND_OPT_STR(buf, sslFlowP->ja3_desc);     // sslJA3Desc
#if SSL_JA3_STR == 1
    OUTBUF_APPEND_OPT_STR(buf, sslFlowP->ja3_str);      // sslJA3Str
#endif
#endif // SSL_JA3 == 1

#if SSL_JA4 == 1
    OUTBUF_APPEND_OPT_STR(buf, sslFlowP->ja4);          // sslJA4
    OUTBUF_APPEND_OPT_STR(buf, sslFlowP->ja4_desc);     // sslJA4Desc
#endif

#if SSL_JA4_O == 1
    OUTBUF_APPEND_OPT_STR(buf, sslFlowP->ja4_o);        // sslJA4O
#endif

#if SSL_JA4_R == 1
    OUTBUF_APPEND_OPT_STR(buf, sslFlowP->ja4_r);        // sslJA4R
#endif

#if SSL_JA4_RO == 1
    OUTBUF_APPEND_OPT_STR(buf, sslFlowP->ja4_ro);       // sslJA4RO
#endif

#if SSL_DETECT_TOR == 1
    OUTBUF_APPEND_U8(buf, sslFlowP->is_tor);            // sslTorFlow
#endif // SSL_DETECT_TOR == 1
}


void t2PluginReport(FILE *stream) {
    T2_FPLOG_AGGR_HEX(stream, plugin_name, sslStat);

#if SSL_ANALYZE_OVPN == 1
    T2_FPLOG_NUMP(stream, plugin_name, "Number of OpenVPN flows", numOVPN, totalFlows);
#endif

#if SSL_DETECT_TOR == 1
    T2_FPLOG_NUMP(stream, plugin_name, "Number of Tor flows", numTor, totalFlows);
#endif

    T2_FPLOG_NUMP(stream, plugin_name, "Number of SSL 2.0 flows", numSSL2, totalFlows);
    T2_FPLOG_NUMP(stream, plugin_name, "Number of SSL 3.0 flows", numSSL3[0], totalFlows);
    T2_FPLOG_NUMP(stream, plugin_name, "Number of TLS 1.0 flows", numSSL3[1], totalFlows);
    T2_FPLOG_NUMP(stream, plugin_name, "Number of TLS 1.1 flows", numSSL3[2], totalFlows);
    T2_FPLOG_NUMP(stream, plugin_name, "Number of TLS 1.2 flows", numSSL3[3], totalFlows);
    T2_FPLOG_NUMP(stream, plugin_name, "Number of TLS 1.3 flows", numSSL3[4], totalFlows);
    T2_FPLOG_NUMP(stream, plugin_name, "Number of TLS 1.3 (draft 14) flows", numTLS13D[0], totalFlows);
    T2_FPLOG_NUMP(stream, plugin_name, "Number of TLS 1.3 (draft 15) flows", numTLS13D[1], totalFlows);
    T2_FPLOG_NUMP(stream, plugin_name, "Number of TLS 1.3 (draft 16) flows", numTLS13D[2], totalFlows);
    T2_FPLOG_NUMP(stream, plugin_name, "Number of TLS 1.3 (draft 17) flows", numTLS13D[3], totalFlows);
    T2_FPLOG_NUMP(stream, plugin_name, "Number of TLS 1.3 (draft 18) flows", numTLS13D[4], totalFlows);
    T2_FPLOG_NUMP(stream, plugin_name, "Number of TLS 1.3 (draft 19) flows", numTLS13D[5], totalFlows);
    T2_FPLOG_NUMP(stream, plugin_name, "Number of TLS 1.3 (draft 20) flows", numTLS13D[6], totalFlows);
    T2_FPLOG_NUMP(stream, plugin_name, "Number of TLS 1.3 (draft 21) flows", numTLS13D[7], totalFlows);
    T2_FPLOG_NUMP(stream, plugin_name, "Number of TLS 1.3 (draft 22) flows", numTLS13D[8], totalFlows);
    T2_FPLOG_NUMP(stream, plugin_name, "Number of TLS 1.3 (draft 23) flows", numTLS13D[9], totalFlows);
    T2_FPLOG_NUMP(stream, plugin_name, "Number of TLS 1.3 (draft 24) flows", numTLS13D[10], totalFlows);
    T2_FPLOG_NUMP(stream, plugin_name, "Number of TLS 1.3 (draft 25) flows", numTLS13D[11], totalFlows);
    T2_FPLOG_NUMP(stream, plugin_name, "Number of TLS 1.3 (draft 26) flows", numTLS13D[12], totalFlows);
    T2_FPLOG_NUMP(stream, plugin_name, "Number of TLS 1.3 (draft 27) flows", numTLS13D[13], totalFlows);
    T2_FPLOG_NUMP(stream, plugin_name, "Number of TLS 1.3 (draft 28) flows", numTLS13D[14], totalFlows);
    T2_FPLOG_NUMP(stream, plugin_name, "Number of TLS 1.3 (Facebook draft 23) flows", numTLS13FBD[0], totalFlows);
    T2_FPLOG_NUMP(stream, plugin_name, "Number of TLS 1.3 (Facebook draft 26) flows", numTLS13FBD[1], totalFlows);
    T2_FPLOG_NUMP(stream, plugin_name, "Number of DTLS 1.0 (OpenSSL pre 0.9.8f) flows", numDTLS[3], totalFlows);
    T2_FPLOG_NUMP(stream, plugin_name, "Number of DTLS 1.0 flows", numDTLS[0], totalFlows);
    T2_FPLOG_NUMP(stream, plugin_name, "Number of DTLS 1.2 flows", numDTLS[1], totalFlows);
    T2_FPLOG_NUMP(stream, plugin_name, "Number of DTLS 1.3 flows", numDTLS[2], totalFlows);
    T2_FPLOG_AGGR_HEX(stream, plugin_name, sslProto);

#if SSL_SAVE_CERT == 1
    T2_FPLOG_NUM(stream, plugin_name, "Number of certificates saved", numSavedCerts);
#endif

#if SSL_BLIST == 1
    T2_FPWRN_NUM_NP(stream, plugin_name, "Number of blacklisted certificates", numBlistCerts);
#endif

#if SSL_JA3 == 1
    T2_FPLOG_NUM(stream, plugin_name, "Number of JA3 signatures matched", numJA3);
#endif

#if SSL_JA4 == 1
    T2_FPLOG_NUM(stream, plugin_name, "Number of JA4 signatures matched", numJA4);
    T2_FPLOG_NUM(stream, plugin_name, "Number of JA4S signatures matched", numJA4S);
#endif
}


void t2Finalize() {
    free(sslFlow);

#if SSL_SAVE_CERT == 1 && ENVCNTRL > 0
    t2_free_env(ENV_SSL_N, env);
#endif // SSL_SAVE_CERT == 1 && ENVCNTRL > 0

#if SSL_BLIST == 1
    ssl_blist_free(sslbl);
#endif

#if SSL_JA3 == 1
    ssl_blist_free(sslja3);
#endif

#if SSL_JA4 == 1
    ssl_blist_free(sslja4);
    ssl_blist_free(sslja4s);
#endif

#if SSL_DETECT_TOR == 1
    // free regexes
    regfree(&subject_re);
    regfree(&issuer_re);
    regfree(&request_re);
#endif
}
