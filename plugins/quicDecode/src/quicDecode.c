/*
 * quicDecode.c
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

#include "quicDecode.h"
#include "t2Plugin.h"

#include <ctype.h> // for isalnum

#if QUIC_DECODE_TLS != 0
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include "sslcompat.h"
#endif // QUIC_DECODE_TLS != 0


// Global variables

quic_flow_t *quic_flows;


// Static variables

#if QUIC_DECODE_TLS != 0
static uint8_t decrypt_buffer[QUIC_MAX_INITIAL_PKT_LEN];
#endif

static uint8_t quicStat;
static uint64_t num_quic_pkts;
static uint64_t num_quic[QUIC_NUM_PKT_TYPE];


// Defines

#define QUIC_SPKTMD_PRI_NONE() \
    if (sPktFile) { \
        quic_spkt_t spkt = {}; \
        quic_spkt_print(&spkt); \
    }

#define QUIC_SPKT_ADD_VAL(spkt, field) \
    if (sPktFile) { \
        (spkt)->field = field; \
        (spkt)->print |= QUIC_SPKT_ ## field; \
    }

#define QUIC_SPKT_ADD_CID(spkt, field) \
    if (sPktFile) { \
        (spkt)->field.len = field ## _len; \
        memcpy((spkt)->field.cid, field, field ## _len); \
        (spkt)->print |= QUIC_SPKT_ ## field; \
    }

#if QUIC_DEBUG == 1
#define QUIC_DBG(format, args...) printf(format, ##args)
#else
#define QUIC_DBG(format, args...)
#endif


// Function prototypes

static inline bool t2_quic_dissect_short(t2buf_t *t2buf, uint8_t flags, quic_flow_t *quicFlowP, quic_spkt_t *spkt);
static inline bool t2_quic_dissect_long(t2buf_t *t2buf, uint8_t flags, quic_flow_t *quicFlowP, quic_spkt_t *spkt, bool client);
static inline bool t2_quic_dissect_retry(t2buf_t *t2buf, quic_flow_t *quicFlowP, quic_spkt_t *spkt);

static inline void quic_spkt_print_header();
static inline void quic_spkt_print(quic_spkt_t *spkt);


// Tranalyzer functions

T2_PLUGIN_INIT("quicDecode", "0.9.3", 0, 9);


void t2Init() {
    T2_PLUGIN_STRUCT_NEW(quic_flows);

    quic_spkt_print_header();
}


binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;
    BV_APPEND_H8(bv  , "quicStat"    , "QUIC Status");
    BV_APPEND_H32(bv , "quicVersion" , "QUIC Version");
    BV_APPEND_H8(bv  , "quicFlags"   , "QUIC Flags");
    BV_APPEND_H8(bv  , "quicPktTypes", "QUIC Packet Types");
    BV_APPEND_STRC(bv, "quicDCID"    , "QUIC Destination Connection ID");
    BV_APPEND_STRC(bv, "quicSCID"    , "QUIC Source Connection ID");
    BV_APPEND_STRC(bv, "quicODCID"   , "QUIC Original Destination Connection ID (Retry)");
    return bv;
}


void t2OnNewFlow(packet_t *packet UNUSED, uint64_t flowIndex) {
    quic_flow_t * const quicFlowP = &quic_flows[flowIndex];
    memset(quicFlowP, '\0', sizeof(*quicFlowP));

    const flow_t * const flowP = &flows[flowIndex];
    if (flowP->status & L2_FLOW) return;

    if (flowP->l4Proto != L3_UDP) return;

    if (flowP->firstSeen.tv_sec < QUIC_TSTAMP_2015) return;

    const uint_fast16_t sport = flowP->srcPort;
    const uint_fast16_t dport = flowP->dstPort;

    if (sport == QUIC_PORT_1 || dport == QUIC_PORT_1 ||
        sport == QUIC_PORT_2 || dport == QUIC_PORT_2)
    {
        quicFlowP->stat |= QUIC_STAT_QUIC;
    }
}


#if ETH_ACTIVATE > 0
void t2OnLayer2(packet_t *packet UNUSED, unsigned long flowIndex) {
    if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;
    QUIC_SPKTMD_PRI_NONE();
}
#endif


void t2OnLayer4(packet_t *packet, unsigned long flowIndex) {
    // only 1. frag packet will be processed
    if (!t2_is_first_fragment(packet)) {
        QUIC_SPKTMD_PRI_NONE();
        return;
    }

    quic_flow_t * const quicFlowP = &quic_flows[flowIndex];
    if (!quicFlowP->stat) { // not a QUIC packet
        QUIC_SPKTMD_PRI_NONE();
        return;
    }

    num_quic_pkts++;

    const bool client = (flows[flowIndex].status & L3FLOWINVERT) == 0;
#if QUIC_DECODE_TLS != 0
    // if server flow: copy 1st destination connection ID from client
    if (!client && quicFlowP->first_dst_cid.len == 0) {
        const unsigned long oppositeFlowIndex = flows[flowIndex].oppositeFlowIndex;
        if (oppositeFlowIndex != HASHTABLE_ENTRY_NOT_FOUND) {
            const quic_flow_t * const opp_quic_flow = &quic_flows[oppositeFlowIndex];
            memcpy(&quicFlowP->first_dst_cid, &opp_quic_flow->first_dst_cid,
                    sizeof(quicFlowP->first_dst_cid));
#if QUIC_DEBUG == 1
        } else {
            T2_PWRN(plugin_name, "Server flow without opposite flow: should never happened");
#endif // QUIC_DEBUG == 1
        }
    }
    // reset pointer to decrypted payload
    quicFlowP->decrypted_payload = NULL;
    quicFlowP->decrypted_payload_len = 0;
#endif // QUIC_DECODE_TLS != 0

#if DTLS == 1
    uint16_t dHOff = 0;
    if (packet->status & L7_DTLS) dHOff = sizeof(dtls12Header_t);
    const uint16_t snaplen = packet->snapL7Len - dHOff;
    const uint8_t * const l7HdrP = packet->l7HdrP + dHOff;
#else // DTLS == 0
    const uint16_t snaplen = packet->snapL7Len;
    const uint8_t * const l7HdrP = packet->l7HdrP;
#endif // DTLS

    t2buf_t t2buf = t2buf_create(l7HdrP, snaplen);
    // There can be more than one record in a single packet...
    // How to handle that for the packet mode?
    //while (t2buf_left(&t2buf) > 0) {
        // Flags:
        //
        //  [Short header]
        //  0xxx xxxx  Header Form: 0 (Short Header), 1 (Long header)
        //  x1xx xxxx  Fixed Bit: 0 (false), 1 (true)
        //  xx1x xxxx  Spin Bit: 0 (false), 1 (true) [Short header]
        //
        //  [Long header]
        //  1xxx xxxx  Header Form: 0 (Short Header), 1 (Long header)
        //  x1xx xxxx  Fixed Bit: 0 (false), 1 (true)
        //  xx11 xxxx  Packet Type: 0 (Initial), 1 (0-RTT), 2 (Handshake), 3 (Retry)
        //  xxxx 11xx  Reserved
        //  xxxx xx11  Packet Number Length: 0 (1 bytes)

        uint8_t flags;
        if (UNLIKELY(!t2buf_read_u8(&t2buf, &flags))) {
            quicFlowP->stat |= QUIC_STAT_SNAPPED;
            QUIC_SPKTMD_PRI_NONE();
            return;
        }
        quicFlowP->flags |= flags;

        quic_spkt_t spkt = {};
        QUIC_SPKT_ADD_VAL(&spkt, flags);
        spkt.stat = quicFlowP->stat;

        QUIC_DBG("Pkt %" PRIu64 ", Flags: 0x%02x\n", numPackets, flags);
        QUIC_DBG("    %s Header\n", QUIC_FLAGS_HDR_FORM(flags) ? "Long" : "Short");
        QUIC_DBG("    Fixed Bit: %s\n", QUIC_FLAGS_FIXED_BIT(flags) ? "true" : "false");

        if (QUIC_HAS_SHORT_HEADER(flags)) {
            t2_quic_dissect_short(&t2buf, flags, quicFlowP, &spkt);
        } else { // Long Header
            t2_quic_dissect_long(&t2buf, flags, quicFlowP, &spkt, client);
        }
    //}

    quic_spkt_print(&spkt);

    QUIC_DBG("================================================================================\n");
}


#if QUIC_DECODE_TLS != 0

#define INITIAL_SECRET_LEN 32  // 256-bit (SHA-256)
#define INITIAL_SALT_LEN   20  // length of static salt defined in RFC

/**
 * HKDF-Extract key derivation function
 *
 * https://tools.ietf.org/html/rfc5869#section-2.2
 */
bool t2_tls13_hkdf_extract(const uint8_t salt[INITIAL_SALT_LEN], const uint8_t *ikm, size_t ikm_len,
        uint8_t dst[INITIAL_SECRET_LEN]) {
    unsigned int md_len = INITIAL_SECRET_LEN;
    return HMAC(EVP_sha256(), salt, INITIAL_SALT_LEN, ikm, ikm_len, dst, &md_len) != NULL;
}


/**
 * TLS 1.3 HKDF-Expand-Label key derivation function
 *
 * HKDF-Expand-Label: https://tools.ietf.org/html/rfc8446#section-7.1
 * HKDF-Expand: https://tools.ietf.org/html/rfc5869#section-2.3
 */
bool t2_tls13_hkdf_expand_label(const uint8_t secret[INITIAL_SECRET_LEN], const char *label,
        uint8_t *output, size_t output_len) {

    #define PREFIX "tls13 "
    #define PREFIX_LEN 6

    // construct HkdfLabel structure: https://tools.ietf.org/html/rfc8446#section-7.1
    uint8_t hkdf_label[265];
    const size_t label_len = strlen(label);
    if (label_len + PREFIX_LEN > 255) {
        return false;
    }
    hkdf_label[0] = output_len >> 8;
    hkdf_label[1] = output_len & 0xff;
    hkdf_label[2] = label_len + PREFIX_LEN;
    memcpy(&hkdf_label[3], PREFIX, PREFIX_LEN);
    memcpy(&hkdf_label[3 + PREFIX_LEN], label, label_len);
    hkdf_label[3 + PREFIX_LEN + label_len] = 0;
    const size_t hkdf_label_len = 4 + PREFIX_LEN + label_len;

    // expand secret with label structure using concatenated HMACs:
    // https://tools.ietf.org/html/rfc5869#section-2.3
    uint8_t last_hmac[INITIAL_SECRET_LEN];
    size_t written = 0;
    uint8_t count = 1;
    while (written < output_len) {
        HMAC_CTX *ctx = HMAC_CTX_new();
        if (!ctx) {
            return false;
        }
        unsigned int md_len = INITIAL_SECRET_LEN;
        bool ret = HMAC_Init_ex(ctx, secret, INITIAL_SECRET_LEN, EVP_sha256(), NULL) != 1 ||
                   (written > 0 ? HMAC_Update(ctx, last_hmac, INITIAL_SECRET_LEN) != 1 : false) ||
                   HMAC_Update(ctx, hkdf_label, hkdf_label_len) != 1 ||
                   HMAC_Update(ctx, &count, 1) != 1 ||
                   HMAC_Final(ctx, last_hmac, &md_len) != 1;
        HMAC_CTX_free(ctx);
        if (ret) {
            return false;
        }
        const size_t copy_len = MIN(output_len - written, INITIAL_SECRET_LEN);
        memcpy(&output[written], last_hmac, copy_len);
        written += copy_len;
        ++count;
    }
    return true;
}


/**
 * Derive the initial secret from the Destination Connection ID field
 *
 * https://tools.ietf.org/html/draft-ietf-quic-tls-20#section-5.2
 */
static bool t2_quic_initial_secret(const quic_cid_t * const dst_conn,
        uint8_t secret[INITIAL_SECRET_LEN], bool client, uint32_t version) {
    // NOTE: salt value will change in final version and should be changed here accordingly
    const uint8_t *initial_salt;
    switch (version) {
        case QUIC_VERSION_DRAFT_20: {
            // defined in QUIC TLS RFC draft 20: 0xef4fb0abb47470c41befcf8031334fae485e09a0
            static const uint8_t initial_salt_20[INITIAL_SALT_LEN] = {
                0xef, 0x4f, 0xb0, 0xab, 0xb4, 0x74, 0x70, 0xc4, 0x1b, 0xef,
                0xcf, 0x80, 0x31, 0x33, 0x4f, 0xae, 0x48, 0x5e, 0x09, 0xa0
            };
            initial_salt = initial_salt_20;
            break;
        }
        case QUIC_VERSION_DRAFT_21:
        case QUIC_VERSION_DRAFT_22: {
            // defined in QUIC TLS RFC draft 21-22: 0x7fbcdb0e7c66bbe9193a96cd21519ebd7a02644a
            static const uint8_t initial_salt_21[INITIAL_SALT_LEN] = {
                0x7f, 0xbc, 0xdb, 0x0e, 0x7c, 0x66, 0xbb, 0xe9, 0x19, 0x3a,
                0x96, 0xcd, 0x21, 0x51, 0x9e, 0xbd, 0x7a, 0x02, 0x64, 0x4a
            };
            initial_salt = initial_salt_21;
            break;
        }
        case QUIC_VERSION_DRAFT_23:
        case QUIC_VERSION_DRAFT_24:
        case QUIC_VERSION_DRAFT_25:
        case QUIC_VERSION_DRAFT_26:
        case QUIC_VERSION_DRAFT_27:
        case QUIC_VERSION_DRAFT_28: {
            // defined in QUIC TLS RFC draft 23-28: 0xc3eef712c72ebb5a11a7d2432bb46365bef9f502
            static const uint8_t initial_salt_23[INITIAL_SALT_LEN] = {
                0xc3, 0xee, 0xf7, 0x12, 0xc7, 0x2e, 0xbb, 0x5a, 0x11, 0xa7,
                0xd2, 0x43, 0x2b, 0xb4, 0x63, 0x65, 0xbe, 0xf9, 0xf5, 0x02
            };
            initial_salt = initial_salt_23;
            break;
        }
        case QUIC_VERSION_DRAFT_29:
        case QUIC_VERSION_DRAFT_30:
        case QUIC_VERSION_DRAFT_31:
        case QUIC_VERSION_DRAFT_32: {
            // defined in QUIC TLS RFC draft 29: 0xafbfec289993d24c9e9786f19c6111e04390a899
            static const uint8_t initial_salt_29[INITIAL_SALT_LEN] = {
                0xaf, 0xbf, 0xec, 0x28, 0x99, 0x93, 0xd2, 0x4c, 0x9e, 0x97,
                0x86, 0xf1, 0x9c, 0x61, 0x11, 0xe0, 0x43, 0x90, 0xa8, 0x99
            };
            initial_salt = initial_salt_29;
            break;
        }
        case QUIC_VERSION_DRAFT_33:
        case QUIC_VERSION_DRAFT_34: {
            // defined in QUIC TLS RFC draft 33: 0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a
            static const uint8_t initial_salt_33[INITIAL_SALT_LEN] = {
                0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
                0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a
            };
            initial_salt = initial_salt_33;
            break;
        }
        case QUIC_VERSION_2: {
            // defined in QUIC Version 2 RFC: 0x0dede3def700a6db819381be6e269dcbf9bd2ed9
            static const uint8_t initial_salt_v2[INITIAL_SALT_LEN] = {
                0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
                0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9
            };
            initial_salt = initial_salt_v2;
            break;
        }
        default:
            // Unsupported QUIC version
            return false;
    }

    // HKDF-Extract(initial_salt, client_dst_connection_id)
    uint8_t initial_secret[INITIAL_SECRET_LEN];
    if (!t2_tls13_hkdf_extract(initial_salt, dst_conn->cid, dst_conn->len, initial_secret)) {
        return false;
    }

    // HKDF-Expand-Label(initial_secret, "server/client in", "", Hash.length)
    const char *label = client ? "client in" : "server in";
    return t2_tls13_hkdf_expand_label(initial_secret, label, secret, INITIAL_SECRET_LEN);
}


/**
 * Decrypt the 5 bytes mask used to protect the packet number in the QUIC header.
 *
 * https://tools.ietf.org/html/draft-ietf-quic-tls-20#section-5.4.1
 * https://tools.ietf.org/html/draft-ietf-quic-tls-20#section-5.4.3
 *
 * For now just implement it for AEAD_AES_128_GCM which is used prior to TLS selecting a
 * ciphersuite, we cannot decrypt the following packets without the session key.
 */
#define AES_BLOCK_SIZE  16 // 128-bit
#define QUIC_MASK_SIZE   5
#define AES_KEY_SIZE    16 // 128-bit (AEAD_AES_128_GCM)
static bool t2_quic_header_protection(const uint8_t data[AES_BLOCK_SIZE],
        const uint8_t secret[INITIAL_SECRET_LEN],
        uint8_t mask[QUIC_MASK_SIZE]) {
    // derive secret "hp" value from initial secret
    uint8_t key_data[AES_KEY_SIZE];
    if (!t2_tls13_hkdf_expand_label(secret, "quic hp", key_data, AES_KEY_SIZE)) {
        return false;
    }

    // decrypt AES block
    AES_KEY key;
    uint8_t tmp[AES_BLOCK_SIZE];
    if (AES_set_encrypt_key(key_data, AES_KEY_SIZE * 8, &key) != 0) {
        return false;
    }
    AES_encrypt(data, tmp, &key);
    memcpy(mask, tmp, QUIC_MASK_SIZE);
    return true;
}


/**
 * Decrypt the AEAD_AES_128_GCM encrypted Initial packet payload.
 *
 * The key and IV are derived from the initial secret using TLS 1.3 HKDF
 *
 * @return  the length of the decrypted payload on success, -1 on error
 */
#define AES_GCM_IV_SIZE  12
static int t2_quic_decrypt_payload(const uint8_t secret[INITIAL_SECRET_LEN],
        const uint8_t *input, size_t input_len, uint8_t *output, uint64_t pktnum,
        const uint8_t *aad, size_t aad_len) {
    // derive key and IV from initial secret
    uint8_t key[AES_KEY_SIZE];
    uint8_t iv[AES_GCM_IV_SIZE];
    if (!t2_tls13_hkdf_expand_label(secret, "quic key", key, AES_KEY_SIZE) ||
        !t2_tls13_hkdf_expand_label(secret, "quic iv", iv, AES_GCM_IV_SIZE)) {
        return -1;
    }
    // https://tools.ietf.org/html/draft-ietf-quic-tls-20#section-5.3
    for (int i = AES_GCM_IV_SIZE-1; pktnum > 0; --i, pktnum >>= 8) {
        iv[i] ^= pktnum & 0xff;
    }

    // AES decrypt input data
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return -1;
    }
    int output_len1;
    int output_len2;
    // split ciphertext and GCM tag
    input_len -= AES_BLOCK_SIZE;
    uint8_t *tag = (uint8_t *)(&input[input_len]);
    // decrypt and verify GCM tag
    bool ret = EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, key, iv) != 1 ||
               EVP_DecryptUpdate(ctx, NULL, &output_len1, aad, aad_len) != 1 ||
               EVP_DecryptUpdate(ctx, output, &output_len1, input, input_len) != 1 ||
               EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_BLOCK_SIZE, tag) != 1 ||
               EVP_DecryptFinal_ex(ctx, output + output_len1, &output_len2) != 1;
    EVP_CIPHER_CTX_free(ctx);
    return ret ? -1 : output_len1 + output_len2;
}

#endif // QUIC_DECODE_TLS != 0


static inline bool t2_quic_dissect_short(t2buf_t *t2buf, uint8_t flags UNUSED, quic_flow_t *quicFlowP, quic_spkt_t *spkt) {
    QUIC_DBG("    Spin Bit: %s\n", QUIC_FLAGS_SPIN_BIT(flags) ? "true" : "false");

    if (quicFlowP->dstCID.len == 0) {
#if QUIC_DEBUG == 1
        T2_PWRN(plugin_name, "First QUIC packet has short header, cannot guess dstCID length");
#endif // QUIC_DEBUG == 1
        return false;
    }

    // Destination Connection ID
    uint8_t dstCID_len = quicFlowP->dstCID.len;
    uint8_t dstCID[dstCID_len];
    if (UNLIKELY(!t2buf_read_n(t2buf, dstCID, dstCID_len))) {
        quicFlowP->stat |= QUIC_STAT_SNAPPED;
        return false;
    }

    if ((quicFlowP->dstCID.len != 0 && quicFlowP->dstCID.len != dstCID_len) ||
        (*(uint64_t*)quicFlowP->dstCID.cid != 0 && memcmp(quicFlowP->dstCID.cid, dstCID, dstCID_len) != 0))
    {
        quicFlowP->stat |= QUIC_STAT_DCID_CHANGE;
#if QUIC_DEBUG == 1
        char cid1[QUIC_CID_STRLEN_MAX+1];
        quic_cid_to_str(quicFlowP->dstCID.cid, quicFlowP->dstCID.len, cid1);
        char cid2[QUIC_CID_STRLEN_MAX+1];
        quic_cid_to_str(dstCID, dstCID_len, cid2);
        T2_PWRN(plugin_name, "dstCID changed: %s / %s", cid1, cid2);
#endif
    }

    quicFlowP->dstCID.len = dstCID_len;
    memcpy(quicFlowP->dstCID.cid, dstCID, dstCID_len);
    QUIC_SPKT_ADD_CID(spkt, dstCID);

    return true;
}


static inline bool t2_quic_dissect_long(t2buf_t *t2buf, uint8_t flags, quic_flow_t *quicFlowP, quic_spkt_t *spkt, bool client
#if QUIC_DECODE_TLS == 0
    UNUSED
#endif
) {

    const uint8_t pktType = QUIC_FLAGS_PKT_TYPE(flags);

    if (pktType == QUIC_PKT_TYPE_HANDSHAKE) {
        quicFlowP->stat |= QUIC_STAT_HANDSHAKE;
    }

    quicFlowP->pktType |= (1 << pktType);
    num_quic[pktType]++;

    QUIC_SPKT_ADD_VAL(spkt, pktType);

    QUIC_DBG("    Packet Type: %s\n", quic_pkt_type_str[pktType]);
    QUIC_DBG("    Encrypted Reserved: %u\n", QUIC_FLAGS_RESERVED(flags));
    QUIC_DBG("    Encrypted Packet number length: %u\n", QUIC_FLAGS_PKTNUMLEN(flags));

    // Version
    uint32_t version;
    if (UNLIKELY(!t2buf_read_u32(t2buf, &version))) {
        quicFlowP->stat |= QUIC_STAT_SNAPPED;
        return false;
    }
    if (version == 0) {
        quicFlowP->stat |= QUIC_STAT_VERSION_NEGO;
    } else if (quicFlowP->version != 0 && quicFlowP->version != version) {
        quicFlowP->stat |= QUIC_STAT_VERSION_CHANGE;
    }
    quicFlowP->version = version;
    QUIC_SPKT_ADD_VAL(spkt, version);
    QUIC_DBG("Version: 0x%08x\n", version);

    // Destination/Source Connection ID Length
    uint8_t cid_len;
    if (UNLIKELY(!t2buf_read_u8(t2buf, &cid_len))) {
        quicFlowP->stat |= QUIC_STAT_SNAPPED;
        return false;
    }

    if (version == QUIC_V1) {
        const uint8_t dstCID_len = (cid_len <= QUIC_CID_BYTES_MAX) ? cid_len : QUIC_CID_BYTES_MAX;
        uint8_t dstCID[dstCID_len];
        if (UNLIKELY(!t2buf_read_n(t2buf, dstCID, dstCID_len))) {
            quicFlowP->stat |= QUIC_STAT_SNAPPED;
            return false;
        }
        quicFlowP->dstCID.len = dstCID_len;
        if (dstCID_len) memcpy(quicFlowP->dstCID.cid, dstCID, dstCID_len);
        if (UNLIKELY(!t2buf_read_u8(t2buf, &cid_len))) {
            quicFlowP->stat |= QUIC_STAT_SNAPPED;
            return false;
        }
        const uint8_t srcCID_len = (cid_len <= QUIC_CID_BYTES_MAX) ? cid_len : QUIC_CID_BYTES_MAX;
        uint8_t srcCID[srcCID_len];
        if (UNLIKELY(!t2buf_read_n(t2buf, srcCID, srcCID_len))) {
            quicFlowP->stat |= QUIC_STAT_SNAPPED;
            return false;
        }
        quicFlowP->srcCID.len = srcCID_len;
        if (srcCID_len) memcpy(quicFlowP->srcCID.cid, srcCID, srcCID_len);
        uint8_t i;
        t2buf_peek_u8(t2buf, &i);
        if (!(i & 0x40)) t2buf_read_u8(t2buf, &i);

        uint16_t pktnum;
        if (UNLIKELY(!t2buf_read_u16(t2buf, &pktnum))) {
            quicFlowP->stat |= QUIC_STAT_SNAPPED;
            return false;
        }
        pktnum &= 0x3fff;
        QUIC_SPKT_ADD_CID(spkt, dstCID);
        QUIC_SPKT_ADD_CID(spkt, srcCID);
        QUIC_SPKT_ADD_VAL(spkt, pktnum);
        return true;
    } else {
        uint8_t dstCID_len = 3 + (cid_len >> 4);
        uint8_t srcCID_len = 3 + (cid_len & 0x0f);

        if (dstCID_len > 3) {
            uint8_t dstCID[dstCID_len];
            // Destination Connection ID
            if (UNLIKELY(!t2buf_read_n(t2buf, dstCID, dstCID_len))) {
                quicFlowP->stat |= QUIC_STAT_SNAPPED;
                return false;
            }

            if ((quicFlowP->dstCID.len != 0 && quicFlowP->dstCID.len != dstCID_len) ||
                (*(uint64_t*)quicFlowP->dstCID.cid != 0 && memcmp(quicFlowP->dstCID.cid, dstCID, dstCID_len) != 0))
            {
                quicFlowP->stat |= QUIC_STAT_DCID_CHANGE;
#if QUIC_DEBUG == 1
                char cid1[QUIC_CID_STRLEN_MAX+1];
                quic_cid_to_str(quicFlowP->dstCID.cid, quicFlowP->dstCID.len, cid1);
                char cid2[QUIC_CID_STRLEN_MAX+1];
                quic_cid_to_str(dstCID, dstCID_len, cid2);
                T2_PWRN(plugin_name, "dstCID changed: %s / %s", cid1, cid2);
#endif
            }

            quicFlowP->dstCID.len = dstCID_len;
            memcpy(quicFlowP->dstCID.cid, dstCID, dstCID_len);
            QUIC_SPKT_ADD_CID(spkt, dstCID);

#if QUIC_DECODE_TLS != 0
            if (client && quicFlowP->first_dst_cid.len == 0) {
                quicFlowP->first_dst_cid.len = dstCID_len;
                memcpy(quicFlowP->first_dst_cid.cid, dstCID, dstCID_len);
            }
#endif
        }

        if (srcCID_len > 3) {
            uint8_t srcCID[srcCID_len];
            // Source Connection ID
            if (UNLIKELY(!t2buf_read_n(t2buf, srcCID, srcCID_len))) {
                quicFlowP->stat |= QUIC_STAT_SNAPPED;
                return false;
            }

            if ((quicFlowP->srcCID.len != 0 && quicFlowP->srcCID.len != srcCID_len) ||
                (*(uint64_t*)quicFlowP->srcCID.cid != 0 && memcmp(quicFlowP->srcCID.cid, srcCID, srcCID_len) != 0))
            {
                quicFlowP->stat |= QUIC_STAT_DCID_CHANGE;
#if QUIC_DEBUG == 1
                char cid1[QUIC_CID_STRLEN_MAX+1];
                quic_cid_to_str(quicFlowP->srcCID.cid, quicFlowP->srcCID.len, cid1);
                char cid2[QUIC_CID_STRLEN_MAX+1];
                quic_cid_to_str(srcCID, srcCID_len, cid2);
                T2_PWRN(plugin_name, "srcCID changed: %s / %s", cid1, cid2);
#endif
            }

            quicFlowP->srcCID.len = srcCID_len;
            memcpy(quicFlowP->srcCID.cid, srcCID, srcCID_len);
            QUIC_SPKT_ADD_CID(spkt, srcCID);
        }
    }

    if (version == 0) { // Version negotiation
        uint32_t supported;
        if (UNLIKELY(!t2buf_read_u32(t2buf, &supported))) {
            quicFlowP->stat |= QUIC_STAT_SNAPPED;
            return false;
        }
        QUIC_DBG("SupportedVersion: 0x%08" B2T_PRIX32 "\n", supported);
    } else if (pktType == QUIC_PKT_TYPE_RETRY) {
        return t2_quic_dissect_retry(t2buf, quicFlowP, spkt);
    } else if (pktType == QUIC_PKT_TYPE_INITIAL) {
        // Token Length
        uint64_t toklen;
        if (UNLIKELY(!t2buf_read_quic_int(t2buf, &toklen))) {
            quicFlowP->stat |= QUIC_STAT_SNAPPED;
            return false;
        }
        QUIC_DBG("Toklen: %" PRIu64 "\n", toklen);
        // skip token value
        if (UNLIKELY(!t2buf_skip_n(t2buf, toklen))) {
            quicFlowP->stat |= QUIC_STAT_SNAPPED;
            return false;
        }

        uint64_t len; // Length of packet
        if (UNLIKELY(!t2buf_read_quic_int(t2buf, &len))) {
            quicFlowP->stat |= QUIC_STAT_SNAPPED;
            return false;
        }
        QUIC_DBG("Len: %" PRIu64 "\n", len);

#if QUIC_DECODE_TLS != 0
        // The packet number and payload can only be decrypted in Initial packets
        // NOTE: it could also be decrypted in Handshake from client -> server if needed
        uint8_t secret[INITIAL_SECRET_LEN];
        if (client && quicFlowP->first_dst_cid.len > 0) {
            if (!t2_quic_initial_secret(&quicFlowP->first_dst_cid, secret, true, version)) {
#if QUIC_DEBUG == 1
                T2_PWRN(plugin_name, "Failed to compute Initial Secret");
#endif // QUIC_DEBUG == 1
                return false;
            }
        } else if (!client && quicFlowP->first_dst_cid.len > 0) {
            if (!t2_quic_initial_secret(&quicFlowP->first_dst_cid, secret, false, version)) {
#if QUIC_DEBUG == 1
                T2_PWRN(plugin_name, "Failed to compute Initial Secret");
#endif // QUIC_DEBUG == 1
                return false;
            }
        } else {
#if QUIC_DEBUG == 1
            T2_PWRN(plugin_name, "Missing 1st destination connection ID: cannot decrypt");
#endif // QUIC_DEBUG == 1
            return false;
        }

        // copy of header for AES-GCM associated data
        const long hdr_size = t2buf_tell(t2buf);
        uint8_t quic_hdr[hdr_size+4];
        t2buf_seek(t2buf, 0, SEEK_SET);
        t2buf_read_n(t2buf, quic_hdr, hdr_size);

        // Don't handle coalesced packets for now...
        const int64_t left = t2buf_left(t2buf);
        if (left <= 0 || len > (uint64_t)left) {
            quicFlowP->stat |= QUIC_STAT_SNAPPED;
            return false;
        }

        // read payload
        uint8_t * const payload = t2_malloc(len);
        if (UNLIKELY(!payload)) {
#if QUIC_DEBUG == 1
            T2_PWRN("quicDecode", "failed to allocate memory for QUIC payload");
#endif // QUIC_DEBUG == 1
            return false;
        }

        if (len < AES_BLOCK_SIZE + 4 || !t2buf_read_n(t2buf, payload, len)) {
            quicFlowP->stat |= QUIC_STAT_SNAPPED;
            free(payload);
            return false;
        }

        // decrypt protected header fields
        uint8_t mask[QUIC_MASK_SIZE];
        if (!t2_quic_header_protection(payload + 4, secret, mask)) {
#if QUIC_DEBUG == 1
            T2_PWRN(plugin_name, "Failed to decode QUIC header protection");
#endif // QUIC_DEBUG == 1
            free(payload);
            return false;
        }

        flags ^= mask[0] & 0x0f;
        quic_hdr[0] ^= mask[0] & 0x0f;

        const uint8_t pkt_num_len = QUIC_FLAGS_PKTNUMLEN(flags) + 1;
        QUIC_DBG("    Decrypted Reserved: %u\n", QUIC_FLAGS_RESERVED(flags));
        QUIC_DBG("    Decrypted Packet number length: %" PRIu8 "\n", pkt_num_len);

        // decrypt packet number
        uint32_t pktnum = 0;
        for (int i = 0; i < pkt_num_len; ++i) {
            pktnum = (pktnum << 8) | (payload[i] ^ mask[i+1]);
            quic_hdr[hdr_size+i] = payload[i] ^ mask[i+1];
        }
        QUIC_DBG("Pktnum: %" PRIu32 "\n", pktnum);
        QUIC_SPKT_ADD_VAL(spkt, pktnum);

        // decrypt payload
        len -= pkt_num_len;
        if (UNLIKELY(len > QUIC_MAX_INITIAL_PKT_LEN)) {
#if QUIC_DEBUG == 1
            T2_PWRN(plugin_name, "Initial packet too large for decryption buffer: %" PRIu64, len);
#endif // QUIC_DEBUG == 1
            free(payload);
            return false;
        }

        const int output_len = t2_quic_decrypt_payload(secret, payload+pkt_num_len, len, decrypt_buffer,
                pktnum, quic_hdr, hdr_size+pkt_num_len);
        if (output_len < 0) {
#if QUIC_DEBUG == 1
            T2_PWRN(plugin_name, "Failed to decrypt Initial packet payload");
#endif // QUIC_DEBUG == 1
            free(payload);
            return false;
        }

#if QUIC_DEBUG == 1
        QUIC_DBG("Decrypted payload length: %d\n", output_len);
        QUIC_DBG("Decrypted payload: 0x");
        for (uint_fast32_t i = 0; i < MIN(20, (uint32_t)output_len); i++) {
            QUIC_DBG("%02x", decrypt_buffer[i]);
        }
        QUIC_DBG("\n");
#endif

        // set pointer to decrypted payload for sslDecode plugin
        quicFlowP->decrypted_payload = decrypt_buffer;
        quicFlowP->decrypted_payload_len = output_len;

        // TODO
        //t2_quic_dissect_frame_type(quicFlowP);

        free(payload);
#else // QUIC_DECODE_TLS == 0
        // skip encrypted packet number and payload
        if (UNLIKELY(!t2buf_skip_n(t2buf, len))) {
            quicFlowP->stat |= QUIC_STAT_SNAPPED;
            return false;
        }
#endif // QUIC_DECODE_TLS != 0
    }
    return true;
}


static inline bool t2_quic_dissect_retry(t2buf_t *t2buf, quic_flow_t *quicFlowP, quic_spkt_t *spkt) {

    // Original Destination Connection ID Length
    uint8_t cid_len;
    if (UNLIKELY(!t2buf_read_u8(t2buf, &cid_len))) {
        quicFlowP->stat |= QUIC_STAT_SNAPPED;
        return false;
    }
    uint8_t origCID_len = 3 + (cid_len & 0x0f);
    QUIC_DBG("origCID Len: %u\n", origCID_len);

    uint8_t origCID[origCID_len];
    if (UNLIKELY(!t2buf_read_n(t2buf, origCID, origCID_len))) {
        quicFlowP->stat |= QUIC_STAT_SNAPPED;
        return false;
    }

    if ((quicFlowP->origCID.len != 0 && quicFlowP->origCID.len != origCID_len) ||
        (*(uint64_t*)quicFlowP->origCID.cid != 0 && memcmp(quicFlowP->origCID.cid, origCID, origCID_len) != 0))
    {
        quicFlowP->stat |= QUIC_STAT_DCID_CHANGE;
#if QUIC_DEBUG == 1
        char cid1[QUIC_CID_STRLEN_MAX+1];
        quic_cid_to_str(quicFlowP->origCID.cid, quicFlowP->origCID.len, cid1);
        char cid2[QUIC_CID_STRLEN_MAX+1];
        quic_cid_to_str(origCID, origCID_len, cid2);
        T2_PWRN(plugin_name, "origCID changed: %s / %s\n", cid1, cid2);
#endif // QUIC_DEBUG == 1
    }

    quicFlowP->origCID.len = origCID_len;
    memcpy(quicFlowP->origCID.cid, origCID, origCID_len);
    QUIC_SPKT_ADD_CID(spkt, origCID);

    // Retry Token
    const uint8_t rtoklen = 20;
    uint8_t rtok[rtoklen];
    if (UNLIKELY(!t2buf_read_n(t2buf, rtok, rtoklen))) {
        quicFlowP->stat |= QUIC_STAT_SNAPPED;
        return false;
    }
#if QUIC_DEBUG == 1
    QUIC_DBG("RetryToken: 0x");
    for (uint_fast32_t i = 0; i < rtoklen; i++) {
        QUIC_DBG("%02x", rtok[i]);
    }
    QUIC_DBG("\n");
#endif

    return true;
}


static inline void quic_spkt_print_header() {
    if (!sPktFile) return;

    fputs("quicStat"    SEP_CHR
          "quicFlags"   SEP_CHR
          "quicPktType" SEP_CHR
          "quicVersion" SEP_CHR
          "quicDCID"    SEP_CHR
          "quicSCID"    SEP_CHR
          "quicODCID"   SEP_CHR
          "quicPktNum"  SEP_CHR
          , sPktFile);
}


static inline void quic_spkt_print(quic_spkt_t *spkt) {
    if (!sPktFile) return;

    fprintf(sPktFile, "0x%02" B2T_PRIX8 /* quicFlags */ SEP_CHR, spkt->stat);

    if (!(spkt->print & QUIC_SPKT_flags)) {
        fputs(/* quicFlags */ SEP_CHR, sPktFile);
    } else {
        fprintf(sPktFile, "0x%02" B2T_PRIX8 /* quicFlags */ SEP_CHR, spkt->flags);
    }

    if (!(spkt->print & QUIC_SPKT_pktType)) {
        fputs(/* quicPktType */ SEP_CHR, sPktFile);
    } else {
#if QUIC_SPKT_TYPE_STR == 1
        fprintf(sPktFile, "%s" /* quicPktType */ SEP_CHR, quic_pkt_type_str[spkt->pktType]);
#else
        fprintf(sPktFile, "%" PRIu8 /* quicPktType */ SEP_CHR, spkt->pktType);
#endif
    }

    if (!(spkt->print & QUIC_SPKT_version)) {
        fputs(/* quicVersion */ SEP_CHR, sPktFile);
    } else {
        fprintf(sPktFile, "0x%08" B2T_PRIX32 /* quicVersion */ SEP_CHR, spkt->version);
    }

    char cid[QUIC_CID_STRLEN_MAX+1];

    if (!(spkt->print & QUIC_SPKT_dstCID)) {
        fputs(/* quicDCID */ SEP_CHR, sPktFile);
    } else {
        quic_cid_to_str(spkt->dstCID.cid, spkt->dstCID.len, cid);
        fprintf(sPktFile, "%s" /* quicDCID */ SEP_CHR, cid);
    }

    if (!(spkt->print & QUIC_SPKT_srcCID)) {
        fputs(/* quicSCID */ SEP_CHR, sPktFile);
    } else {
        quic_cid_to_str(spkt->srcCID.cid, spkt->srcCID.len, cid);
        fprintf(sPktFile, "%s" /* quicSCID */ SEP_CHR, cid);
    }

    if (!(spkt->print & QUIC_SPKT_origCID)) {
        fputs(/* quicODCID */ SEP_CHR, sPktFile);
    } else {
        quic_cid_to_str(spkt->origCID.cid, spkt->origCID.len, cid);
        fprintf(sPktFile, "%s" /* quicODCID */ SEP_CHR, cid);
    }

    if (!(spkt->print & QUIC_SPKT_pktnum)) {
        fputs(/* quicPktNum */ SEP_CHR, sPktFile);
    } else {
        fprintf(sPktFile, "%" PRIu32 /* quicPktNum */ SEP_CHR, spkt->pktnum);
    }
}


void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {
    const quic_flow_t * const quicFlowP = &quic_flows[flowIndex];

    quicStat |= quicFlowP->stat;

    OUTBUF_APPEND_U8(buf, quicFlowP->stat);
    OUTBUF_APPEND_U32(buf, quicFlowP->version);
    OUTBUF_APPEND_U8(buf, quicFlowP->flags);
    OUTBUF_APPEND_U8(buf, quicFlowP->pktType);

#if BLOCK_BUF == 0
    char cid[QUIC_CID_STRLEN_MAX+1];

    quic_cid_to_str(quicFlowP->dstCID.cid, quicFlowP->dstCID.len, cid);
    OUTBUF_APPEND_STR(buf, cid);

    quic_cid_to_str(quicFlowP->srcCID.cid, quicFlowP->srcCID.len, cid);
    OUTBUF_APPEND_STR(buf, cid);

    quic_cid_to_str(quicFlowP->origCID.cid, quicFlowP->origCID.len, cid);
    OUTBUF_APPEND_STR(buf, cid);
#endif // BLOCK_BUF == 0
}


void t2PluginReport(FILE *stream) {
    if (num_quic_pkts) {
        T2_FPLOG_AGGR_HEX(stream, plugin_name, quicStat);
        // TODO report number of records (there may be several QUIC records per packet...)
        T2_FPLOG_NUMP0(stream, plugin_name, "Number of QUIC packets", num_quic_pkts, numPackets);

        char hrnum[64];
        const double percent = 100.0 / (double) num_quic_pkts;
        for (uint_fast8_t i = 0; i < QUIC_NUM_PKT_TYPE; i++) {
            if (num_quic[i] == 0) continue;
            T2_CONV_NUM(num_quic[i], hrnum);
            T2_FPLOG(stream, plugin_name, "Number of QUIC %s packets: %" PRIu64 "%s [%.2f%%]",
                    quic_pkt_type_str[i], num_quic[i], hrnum, num_quic[i] * percent);
        }
    }
}


void t2Finalize() {
    free(quic_flows);
}
