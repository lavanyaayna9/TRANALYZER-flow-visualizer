/*
 * sshDecode.c
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

#include "sshDecode.h"
#include "t2buf.h"

#if (SSH_DECODE == 2 && SSH_FINGERPRINT > 0) || (SSH_HASSH == 1)
#include "t2crypto.h"
#endif

#if SSH_HASSH == 1
#include "sslBlist.h"
#endif

#if SSH_DEBUG == 1
#define SSH_DBG(format, args...) printf("%s: pkt %" PRIu64 ": " format "\n", plugin_name, numPackets, ##args)
#else // SSH_DEBUG == 0
#define SSH_DBG(format, args...)
#endif // SSH_DEBUG == 0


// plugin variables

sshFlow_t *sshFlows;


// Static variables

#if (SSH_DECODE == 2 && SSH_FINGERPRINT > 0)
// Message digest: md5 or sha1
static const EVP_MD *md;
#endif

static uint64_t numSSH, numSSH0;
static uint16_t sshStat;

#if SSH_HASSH == 1
static ssl_blist_t *ssh_hassh;
static uint64_t numHassh, numHassh0;
#endif


// Tranalyzer functions

T2_PLUGIN_INIT("sshDecode", "0.9.3", 0, 9);


void t2Init() {
    T2_PLUGIN_STRUCT_NEW(sshFlows);

#if (SSH_DECODE == 2 && SSH_FINGERPRINT > 0)
#if SSH_FINGERPRINT == 1
    md = EVP_md5();
#else // SSH_FINGERPRINT == 2
    md = EVP_sha256();
#endif // SSH_FINGERPRINT == 2
#endif // (SSH_DECODE == 2 && SSH_FINGERPRINT > 0)

#if SSH_HASSH == 1
#if ENVCNTRL > 0
    t2_env_t env[ENV_SSH_N] = {};
    t2_get_env(PLUGIN_SRCH, ENV_SSH_N, env);
    const char * const hasshName = T2_ENV_VAL(SSH_HASSH_NAME);
#else // ENVCNTRL == 0
    const char * const hasshName = SSH_HASSH_NAME;
#endif // ENVCNTRL
    const size_t plen = pluginFolder_len;
    const size_t hlen = strlen(hasshName) + 1;
    char filename[plen + hlen];
    memcpy(filename, pluginFolder, plen);
    memcpy(filename + plen, hasshName, hlen);
    ssh_hassh = ssl_blist_load(plugin_name, filename, 32, SSH_HASSH_DLEN);
#if VERBOSE > 0
    T2_PINF(plugin_name, "%" PRIu32 " HASSH fingerprints loaded", ssh_hassh->count);
#endif // VERBOSE > 0

#if ENVCNTRL > 0
    t2_free_env(ENV_SSH_N, env);
#endif // ENVCNTRL > 0
#endif // SSH_HASSH == 1

    if (sPktFile) fputs("sshStat" SEP_CHR, sPktFile);
}


binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;

    BV_APPEND_H16(bv, "sshStat", "SSH status");
    BV_APPEND_STR_R(bv, "sshVersion", "SSH version and software");

#if SSH_DECODE == 2
    BV_APPEND_STRC_R(bv, "sshHostKeyType", "SSH host key type");
#if SSH_FINGERPRINT > 0
    BV_APPEND_STRC_R(bv, "sshFingerprint", "SSH public key fingerprint");
#endif
#endif // SSH_DECODE == 2

#if SSH_DECODE > 0
    BV_APPEND_STRC_R(bv, "sshCookie", "SSH cookie");

#if SSH_ALGO == 1
    BV_APPEND_STRC_R(bv, "sshKEX", "SSH chosen KEX algorithm");
    BV_APPEND_STRC_R(bv, "sshSrvHKeyAlgo", "SSH chosen server host key algorithm");
    BV_APPEND_STRC_R(bv, "sshEncCS", "SSH chosen encryption algorithm client to server");
    BV_APPEND_STRC_R(bv, "sshEncSC", "SSH chosen encryption algorithm server to client");
    BV_APPEND_STRC_R(bv, "sshMacCS", "SSH chosen MAC algorithm client to server");
    BV_APPEND_STRC_R(bv, "sshMacSC", "SSH chosen MAC algorithm server to client");
    BV_APPEND_STRC_R(bv, "sshCompCS", "SSH chosen compression algorithm client to server");
    BV_APPEND_STRC_R(bv, "sshCompSC", "SSH chosen compression algorithm server to client");
    BV_APPEND_STRC_R(bv, "sshLangCS", "SSH chosen language client to server");
    BV_APPEND_STRC_R(bv, "sshLangSC", "SSH chosen language server to client");
#endif

#if SSH_LISTS == 1
    BV_APPEND_STR_R(bv, "sshKEXList", "SSH KEX algorithms");
    BV_APPEND_STR_R(bv, "sshSrvHKeyAlgoList", "SSH server host key algorithms");
    BV_APPEND_STR_R(bv, "sshEncCSList", "SSH encryption algorithms client to server");
    BV_APPEND_STR_R(bv, "sshEncSCList", "SSH encryption algorithms server to client");
    BV_APPEND_STR_R(bv, "sshMacCSList", "SSH MAC algorithms client to server");
    BV_APPEND_STR_R(bv, "sshMacSCList", "SSH MAC algorithms server to client");
    BV_APPEND_STR_R(bv, "sshCompCSList", "SSH compression algorithms client to server");
    BV_APPEND_STR_R(bv, "sshCompSCList", "SSH compression algorithms server to client");
    BV_APPEND_STR_R(bv, "sshLangCSList", "SSH languages client to server");
    BV_APPEND_STR_R(bv, "sshLangSCList", "SSH languages server to client");
#endif

#endif // SSH_DECODE > 0

#if SSH_HASSH == 1
    BV_APPEND_STRC_R(bv, "sshHassh", "SSH HASSH fingerprint");
    BV_APPEND_STR_R(bv, "sshHasshDesc", "SSH HASSH description");
#if SSH_HASSH_STR == 1
    BV_APPEND_STR_R(bv, "sshHasshStr", "SSH HASSH string");
#endif
#endif // SSH_HASSH == 1

    return bv;
}


void t2OnNewFlow(packet_t* packet UNUSED, unsigned long flowIndex) {
    sshFlow_t * const sshFlowP = &sshFlows[flowIndex];
    memset(sshFlowP, '\0', sizeof(sshFlow_t));
#if SSH_USE_PORT == 1
    const flow_t * const flowP = &flows[flowIndex];
    if (flowP->dstPort == SSH_PORT || flowP->srcPort == SSH_PORT) {
        sshFlowP->stat |= SSH_STAT_SSH;
    }
#endif
}


#if SSH_DECODE > 0 || SSH_HASSH == 1
// Find the first common element between two lists
// Returned value MUST be free'd with free()
static char *find_first_common_elem(const char *list1, const char *list2) {
    if (strlen(list1) == 0 || strlen(list2) == 0) return NULL;

    const char * const sep = ",";
    bool found = false;
    char *common = NULL;
    char *elem1, *last1;
    char *elem2, *last2;
    char * const l1 = strdup(list1);
    char * const l2 = strdup(list2);
    for (elem1 = strtok_r(l1, sep, &last1);
         elem1 && !found;
         elem1 = strtok_r(NULL, sep, &last1))
    {
        for (elem2 = strtok_r(l2, sep, &last2);
             elem2;
             elem2 = strtok_r(NULL, sep, &last2))
        {
            if (strcmp(elem1, elem2) == 0) {
                SSH_DBG("Highest common element is %s", elem1);
                common = strdup(elem1);
                found = true;
                break;
            }
        }
    }

    free(l1);
    free(l2);

    return common;
}
#endif // SSH_DECODE > 0 || SSH_HASSH == 1


#if SSH_ALGO == 1 && (SSH_DECODE > 0 || SSH_HASSH == 1)
static inline bool has_implicit_mac(const char *enc) {
    return strcmp(enc, "aes128-gcm@openssh.com")        == 0 ||
           strcmp(enc, "aes256-gcm@openssh.com")        == 0 ||
           strcmp(enc, "chacha20-poly1305@openssh.com") == 0;
}
#endif // SSH_ALGO == 1 && (SSH_DECODE > 0 || SSH_HASSH == 1)


#if SSH_ALGO == 1 && (SSH_DECODE > 0 || SSH_HASSH == 1)
static void find_first_common_algo(sshFlow_t *sshFlowP, sshFlow_t *revFlowP) {
    bool trunc = false;
    char *common;

    // server host key algorithms
    if ((common = find_first_common_elem(revFlowP->srv_hkey_algo, sshFlowP->srv_hkey_algo))) {
        const size_t len = t2_strcpy(revFlowP->srv_hkey, common, sizeof(revFlowP->srv_hkey), T2_STRCPY_TRUNC);
        if (len >= sizeof(revFlowP->srv_hkey)) trunc = true;
        free(common);
    }

    // encryption algorithm client to server
    if ((common = find_first_common_elem(revFlowP->enc_cs, sshFlowP->enc_cs))) {
        const size_t len = t2_strcpy(revFlowP->enc_cs1, common, sizeof(revFlowP->enc_cs1), T2_STRCPY_TRUNC);
        if (len >= sizeof(revFlowP->enc_cs1)) trunc = true;
        free(common);
    }

    // encryption algorithm server to client
    if ((common = find_first_common_elem(revFlowP->enc_sc, sshFlowP->enc_sc))) {
        const size_t len = t2_strcpy(revFlowP->enc_sc1, common, sizeof(revFlowP->enc_sc1), T2_STRCPY_TRUNC);
        if (len >= sizeof(revFlowP->enc_sc1)) trunc = true;
        free(common);
    }

    // mac algorithm client to server
    if (has_implicit_mac(sshFlowP->enc_cs1)) {
        const size_t len = t2_strcpy(revFlowP->mac_cs1, SSH_IMPLICIT, sizeof(revFlowP->mac_cs1), T2_STRCPY_TRUNC);
        if (len >= sizeof(revFlowP->mac_cs1)) trunc = true;
    } else if ((common = find_first_common_elem(revFlowP->mac_cs, sshFlowP->mac_cs))) {
        const size_t len = t2_strcpy(revFlowP->mac_cs1, common, sizeof(revFlowP->mac_cs1), T2_STRCPY_TRUNC);
        if (len >= sizeof(revFlowP->mac_cs1)) trunc = true;
        free(common);
    }

    // mac algorithm server to client
    if (has_implicit_mac(sshFlowP->enc_sc1)) {
        t2_strcpy(sshFlowP->mac_sc1, SSH_IMPLICIT, sizeof(sshFlowP->mac_sc1), T2_STRCPY_TRUNC);
        const size_t len = t2_strcpy(revFlowP->mac_sc1, SSH_IMPLICIT, sizeof(revFlowP->mac_sc1), T2_STRCPY_TRUNC);
        if (len >= sizeof(revFlowP->mac_sc1)) trunc = true;
    } else if ((common = find_first_common_elem(revFlowP->mac_sc, sshFlowP->mac_sc))) {
        t2_strcpy(sshFlowP->mac_sc1, common, sizeof(sshFlowP->mac_sc1), T2_STRCPY_TRUNC);
        const size_t len = t2_strcpy(revFlowP->mac_sc1, common, sizeof(revFlowP->mac_sc1), T2_STRCPY_TRUNC);
        if (len >= sizeof(revFlowP->mac_sc1)) trunc = true;
        free(common);
    }

    // compression algorithm client to server
    if ((common = find_first_common_elem(revFlowP->comp_cs, sshFlowP->comp_cs))) {
        t2_strcpy(sshFlowP->comp_cs1, common, sizeof(sshFlowP->comp_cs1), T2_STRCPY_TRUNC);
        const size_t len = t2_strcpy(revFlowP->comp_cs1, common, sizeof(revFlowP->comp_cs1), T2_STRCPY_TRUNC);
        if (len >= sizeof(revFlowP->comp_cs1)) trunc = true;
        free(common);
    }

    // compression algorithm server to client
    if ((common = find_first_common_elem(revFlowP->comp_sc, sshFlowP->comp_sc))) {
        const size_t len = t2_strcpy(revFlowP->comp_sc1, common, sizeof(revFlowP->comp_sc1), T2_STRCPY_TRUNC);
        if (len >= sizeof(revFlowP->comp_sc1)) trunc = true;
        free(common);
    }

    // languages client to server
    if ((common = find_first_common_elem(revFlowP->lang_cs, sshFlowP->lang_cs))) {
        const size_t len = t2_strcpy(revFlowP->lang_cs1, common, sizeof(revFlowP->lang_cs1), T2_STRCPY_TRUNC);
        if (len >= sizeof(revFlowP->lang_cs1)) trunc = true;
        free(common);
    }

    // languages server to client
    if ((common = find_first_common_elem(revFlowP->lang_sc, sshFlowP->lang_sc))) {
        const size_t len = t2_strcpy(revFlowP->lang_sc1, common, sizeof(revFlowP->lang_sc1), T2_STRCPY_TRUNC);
        if (len >= sizeof(revFlowP->lang_sc1)) trunc = true;
        free(common);
    }

    if (trunc) {
        sshFlowP->stat |= SSH_STAT_HKT_TRUNC;
        revFlowP->stat |= SSH_STAT_HKT_TRUNC;
    }
}
#endif // SSH_ALGO == 1 && (SSH_DECODE > 0 || SSH_HASSH == 1)


#if SSH_DECODE > 0 || SSH_HASSH == 1
static inline bool ssh_read_str(sshFlow_t *sshFlowP, t2buf_t *t2buf, char *dst, uint32_t dst_len, const char *dbg
#if SSH_DEBUG == 0
        UNUSED
#endif
    )
{
    uint32_t len;
    if (!t2buf_read_u32(t2buf, &len)) return false;

    const long start = t2buf_tell(t2buf);
    if (t2buf_readnstr(t2buf, (uint8_t*)dst, dst_len, len, T2BUF_UTF8, true) == T2BUF_DST_FULL) {
        SSH_DBG("%s (len=%" PRIu32 "): %s [truncated]", dbg, len, dst);
        sshFlowP->stat |= SSH_STAT_STR_TRUNC;
        t2buf_seek(t2buf, start, SEEK_SET);
        if (!t2buf_skip_n(t2buf, len)) {
            sshFlowP->stat |= SSH_STAT_MALFORMED;
            return false;
        }
    }

    SSH_DBG("%s (len=%" PRIu32 "): %s", dbg, len, dst);
    return true;
}
#endif // SSH_DECODE > 0 || SSH_HASSH == 1


#if SSH_DECODE > 0 && SSH_ALGO == 0 && SSH_LISTS == 0 && SSH_HASSH == 0
static inline bool ssh_skip_str(t2buf_t *t2buf) {
    uint32_t len;
    if (!t2buf_read_u32(t2buf, &len)) return false;
    if (!t2buf_skip_n(t2buf, len)) {
        //sshFlowP->stat |= SSH_STAT_MALFORMED;
        return false;
    }
    return true;
}
#endif


#if SSH_DECODE > 0 || SSH_HASSH == 1
static inline bool ssh_read_hexstr(t2buf_t *t2buf, char *dst, uint32_t dlen, const char *dbg
#if SSH_DEBUG == 0
        UNUSED
#endif
    )
{
    if (t2buf_hexdecode(t2buf, dlen, dst, 0) != dlen) {
        SSH_DBG("%s: %s [truncated]", dbg, dst);
        //sshFlowP->stat |= SSH_STAT_MALFORMED;
        return false;
    }

    SSH_DBG("%s: %s", dbg, dst);
    return true;
}
#endif // SSH_DECODE > 0 || SSH_HASSH == 1


#if SSH_DECODE == 2
static inline bool ssh_read_mpint(t2buf_t *t2buf, const char *dbg
#if SSH_DEBUG == 0
        UNUSED
#endif
    )
{
    uint32_t len;
    if (!t2buf_read_u32(t2buf, &len)) return false;

    const size_t dlen = MIN(len, SSH_BUF_SIZE);

    char dst[2*dlen+1];
    return ssh_read_hexstr(t2buf, dst, dlen, dbg);
}
#endif // SSH_DECODE == 2


#if SSH_HASSH == 1
static inline void ssh_compute_hassh(sshFlow_t *sshFlowP, bool server) {
    if ((sshFlowP->stat & SSH_STAT_STR_TRUNC) != 0 ||
        strlen(sshFlowP->hassh) != 0)
    {
        // Do not try to fingerprint truncated entries
        // Only fingerprint the first Client/Server Hello
        return;
    }

    size_t pos = 0;
    char fingerprint[SSH_HASSH_STR_LEN];

    char *enc, *mac, *comp;
    if (server) {
        enc = sshFlowP->enc_sc;
        mac = sshFlowP->mac_sc;
        comp = sshFlowP->comp_sc;
    } else {
        enc = sshFlowP->enc_cs;
        mac = sshFlowP->mac_cs;
        comp = sshFlowP->comp_cs;
    }

    // Key Exchange methods
    pos += snprintf(&fingerprint[pos], SSH_HASSH_STR_LEN-pos, "%s;", sshFlowP->kex_algo);
    if (pos >= SSH_HASSH_STR_LEN) {
        //sshFlowP->stat |= SSH_STAT_HASSH_FAIL;
        return;
    }

    // Encryption
    pos += snprintf(&fingerprint[pos], SSH_HASSH_STR_LEN-pos, "%s;", enc);
    if (pos >= SSH_HASSH_STR_LEN) {
        //sshFlowP->stat |= SSH_STAT_HASSH_FAIL;
        return;
    }

    // Message Authentication
    pos += snprintf(&fingerprint[pos], SSH_HASSH_STR_LEN-pos, "%s;", mac);
    if (pos >= SSH_HASSH_STR_LEN) {
        //sshFlowP->stat |= SSH_STAT_HASSH_FAIL;
        return;
    }

    // Compression
    pos += snprintf(&fingerprint[pos], SSH_HASSH_STR_LEN-pos, "%s", comp);
    if (pos >= SSH_HASSH_STR_LEN) {
        //sshFlowP->stat |= SSH_STAT_HASSH_FAIL;
        return;
    }

    t2_md5(fingerprint, strlen(fingerprint), sshFlowP->hassh, sizeof(sshFlowP->hassh), 0);

    const char *hassh_desc;
    if ((hassh_desc = ssl_blist_lookup(ssh_hassh, sshFlowP->hassh))) {
        numHassh++;
        const size_t dlen = strlen(hassh_desc)+1;
        memcpy(sshFlowP->hassh_desc, hassh_desc, MIN(dlen, SSH_HASSH_DLEN));
    }
}
#endif // SSH_HASSH == 1


#if ETH_ACTIVATE > 0
void t2OnLayer2(packet_t *packet UNUSED, unsigned long flowIndex) {
    if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;

    if (sPktFile) fputs("0x0000" SEP_CHR, sPktFile);
}
#endif // ETH_ACTIVATE > 0


void t2OnLayer4(packet_t* packet, unsigned long flowIndex) {
    const flow_t * const flowP = &flows[flowIndex];
    sshFlow_t * const sshFlowP = &sshFlows[flowIndex];

    const uint8_t proto = flowP->l4Proto;
    if (proto != L3_TCP) goto sshpkt;

    // Only first frag packet will be processed
    if (!t2_is_first_fragment(packet)) goto sshpkt;

    const uint32_t remaining = packet->snapL7Len;
    if (remaining == 0) goto sshpkt; // No payload

    const uint8_t * const ptr = packet->l7HdrP;
    t2buf_t t2buf = t2buf_create(ptr, remaining);

    const unsigned long oFlowInd = flowP->oppositeFlowIndex;
#if SSH_DECODE > 0 || SSH_HASSH == 1
    sshFlow_t * const revFlowP = (oFlowInd != HASHTABLE_ENTRY_NOT_FOUND) ? &sshFlows[oFlowInd] : NULL;
#endif

    // SSH protocol version exchange
    uint32_t magic;
    if (t2buf_peek_u32(&t2buf, &magic) && magic == SSH_MAGIC) {
        if (oFlowInd == HASHTABLE_ENTRY_NOT_FOUND ||
            !(sshFlows[oFlowInd].stat & SSH_STAT_VER_FIRST))
        {
            // keep track of who sent the ssh version first
            sshFlowP->stat |= SSH_STAT_VER_FIRST;
        }
        sshFlowP->stat |= SSH_STAT_SSH;

        long len = t2buf_readline(&t2buf, (uint8_t *)sshFlowP->version, SSH_BUF_SIZE, false);
        if (len > 0) { // len is at least 4 bytes because peek_u32 succeeded
            if (sshFlowP->version[len-2] == '\r') len--;
            else sshFlowP->stat |= SSH_STAT_BANNER; // backward compatibility
            sshFlowP->version[len-1] = '\0';
        } else if (len == T2BUF_DST_FULL) {
            SSH_DBG("version is truncated");
            sshFlowP->stat |= SSH_STAT_STR_TRUNC;
            sshFlowP->version[SSH_BUF_SIZE] = '\0';
        } else if (len == T2BUF_NULL) {
            sshFlowP->stat |= SSH_STAT_BANNER; // NULL byte in banner
        }
        goto sshpkt;
    }

    if (!sshFlowP->stat) goto sshpkt;

#if SSH_DECODE > 0 || SSH_HASSH == 1
    while (t2buf_left(&t2buf) > 5) {
        /* Packet length (min: 12, max: 32768) */
        uint32_t pkt_len;
        if (!t2buf_read_u32(&t2buf, &pkt_len)) goto sshpkt;
        if (pkt_len < 12 || pkt_len > 32768) goto sshpkt;

        if (sshFlowP->stat & SSH_STAT_NEWKEYS) {
            SSH_DBG("New encrypted record (len: %u)", pkt_len);
            t2buf_skip_n(&t2buf, pkt_len);
            continue;
        }

        /* Padding length (min: 4, max: 255) */
        uint8_t padlen;
        if (!t2buf_read_u8(&t2buf, &padlen)) goto sshpkt;
        if (padlen < 4) goto sshpkt;

        if (padlen >= pkt_len-1 || ((pkt_len + 4) % 8) != 0) {
            // Encrypted packet, TCP segment or snapped
            SSH_DBG("New encrypted or snapped record or TCP segment (len: %u, padding: %u)", pkt_len, padlen);
            goto sshpkt;
        }

        /* Message code */
        uint8_t msg_type;
        if (!t2buf_read_u8(&t2buf, &msg_type)) goto sshpkt;

        SSH_DBG("New Record (type: %u, len: %u, padding: %u)", msg_type, pkt_len, padlen);

        switch (msg_type) {
            case SSH_MSG_KEXINIT:
                SSH_DBG("Key Exchange Init");
                // Only one KEXINIT message per flow (avoid wrongly decoding encrypted packets)
                if (sshFlowP->stat & SSH_STAT_KEXINIT) {
                    SSH_DBG("Second SSH_MSG_KEXINIT for flow %" PRIu64, flowP->findex);
                    sshFlowP->stat |= SSH_STAT_MALFORMED;
                    goto sshpkt;
                }
                sshFlowP->stat |= SSH_STAT_KEXINIT;
                // cookie
                ssh_read_hexstr(&t2buf, sshFlowP->cookie, SSH_COOKIE_SIZE, "cookie");
                // kex algorithms
                ssh_read_str(sshFlowP, &t2buf, sshFlowP->kex_algo, SSH_BUF_SIZE, "kex_algo");
                // Find the first common element between both lists in order to figure out
                // whether to use diffie-hellman or elliptic curves
                if (revFlowP && strlen(revFlowP->kex_algo) > 0 && strlen(revFlowP->kex) == 0) {
                    char * const algo = find_first_common_elem(revFlowP->kex_algo, sshFlowP->kex_algo);
                    if (algo) {
                        SSH_DBG("Highest matching KEX algorithm is %s", algo);
                        const size_t len = t2_strcpy(revFlowP->kex, algo, sizeof(revFlowP->kex), T2_STRCPY_TRUNC);
                        if (len >= sizeof(revFlowP->kex)) {
                            sshFlowP->stat |= SSH_STAT_HKT_TRUNC;
                            revFlowP->stat |= SSH_STAT_HKT_TRUNC;
                        }
                    }
                    free(algo);
                }
#if SSH_ALGO == 0 && SSH_LISTS == 0 && SSH_HASSH == 0
                ssh_skip_str(&t2buf); // server host key algorithms
                ssh_skip_str(&t2buf); // encryption algorithm client to server
                ssh_skip_str(&t2buf); // encryption algorithm server to client
                ssh_skip_str(&t2buf); // mac algorithm client to server
                ssh_skip_str(&t2buf); // mac algorithm server to client
                ssh_skip_str(&t2buf); // compression algorithm client to server
                ssh_skip_str(&t2buf); // compression algorithm server to client
                ssh_skip_str(&t2buf); // languages client to server
                ssh_skip_str(&t2buf); // languages server to client
#else // SSH_ALGO == 1 || SSH_LISTS == 1 || SSH_HASSH == 1
                // server host key algorithms
                ssh_read_str(sshFlowP, &t2buf, sshFlowP->srv_hkey_algo, SSH_BUF_SIZE, "srv_hkey_algo");
                // encryption algorithm client to server
                ssh_read_str(sshFlowP, &t2buf, sshFlowP->enc_cs, SSH_BUF_SIZE, "enc_cs");
                // encryption algorithm server to client
                ssh_read_str(sshFlowP, &t2buf, sshFlowP->enc_sc, SSH_BUF_SIZE, "enc_sc");
                // mac algorithm client to server
                ssh_read_str(sshFlowP, &t2buf, sshFlowP->mac_cs, SSH_BUF_SIZE, "mac_cs");
                // mac algorithm server to client
                ssh_read_str(sshFlowP, &t2buf, sshFlowP->mac_sc, SSH_BUF_SIZE, "mac_sc");
                // compression algorithm client to server
                ssh_read_str(sshFlowP, &t2buf, sshFlowP->comp_cs, SSH_BUF_SIZE, "comp_cs");
                // compression algorithm server to client
                ssh_read_str(sshFlowP, &t2buf, sshFlowP->comp_sc, SSH_BUF_SIZE, "comp_sc");
                // languages client to server
                ssh_read_str(sshFlowP, &t2buf, sshFlowP->lang_cs, SSH_BUF_SIZE, "lang_cs");
                // languages server to client
                ssh_read_str(sshFlowP, &t2buf, sshFlowP->lang_sc, SSH_BUF_SIZE, "lang_sc");
#if SSH_ALGO == 1
                if (revFlowP && (revFlowP->stat & SSH_STAT_KEXINIT)) {
                    find_first_common_algo(sshFlowP, revFlowP);
                }
#endif
#endif // SSH_ALGO == 1 || SSH_LISTS == 1 || SSH_HASSH == 1

                // KEX first packet follows
                t2buf_skip_u8(&t2buf);
                // reserved
                t2buf_skip_u32(&t2buf);
#if SSH_HASSH == 1
                ssh_compute_hassh(sshFlowP, (flowP->status & L3FLOWINVERT));
#endif
                break;

            case SSH_MSG_NEWKEYS:
                SSH_DBG("New Keys");
                sshFlowP->stat |= SSH_STAT_NEWKEYS;
                break;

#if SSH_DECODE == 2
            case 30: /* Diffie-Hellman Key Exchange Init or
                        Elliptic Curve Diffie-Hellman Key Exchange Init */
                SSH_DBG("Diffie-Hellman Key Exchange Init");
                if (strncmp(sshFlowP->kex, "curve", 4) == 0) {
                    sshFlowP->stat |= SSH_STAT_ECDH_KEXINIT;
                    // ECDH client's ephemeral public key length
                    uint32_t qclen;
                    if (!t2buf_read_u32(&t2buf, &qclen)) goto sshpkt;
                    // ECDH client's ephemeral public key (Q_C)
                    if (!t2buf_skip_n(&t2buf, qclen)) goto sshpkt;
                    //char dst[255];
                    //ssh_read_hexstr(&t2buf, dst, qclen, "ecdh-q-c");
                } else {
                    sshFlowP->stat |= SSH_STAT_DH_KEXINIT;
                    // DH client e
                    ssh_read_mpint(&t2buf, "dh-client-e");
                }
                break;

            case 31: { /* Diffie-Hellman Key Exchange Reply or
                          Diffie-Hellman Group Exchange Group or
                          Elliptic Curve Diffie-Hellman Key Exchange Reply */
                const bool dhkexinit = (((revFlowP ? revFlowP->stat : 0) | sshFlowP->stat) & (SSH_STAT_DH_KEXINIT | SSH_STAT_ECDH_KEXINIT));
                if (dhkexinit) {
                    SSH_DBG("Diffie-Hellman Key Exchange Reply");
                    // Only one DH_KEXREPLY message per flow (avoid wrongly decoding encrypted packets)
                    if (sshFlowP->stat & (SSH_STAT_DH_KEXREPLY | SSH_STAT_ECDH_KEXREPLY)) {
                        SSH_DBG("Second (EC)DH_KEXREPLY for flow %" PRIu64, flowP->findex);
                        sshFlowP->stat |= SSH_STAT_MALFORMED;
                        goto sshpkt;
                    }
                    if (strncmp(sshFlowP->kex, "curve", 4) == 0) {
                        sshFlowP->stat |= SSH_STAT_ECDH_KEXREPLY;
                    } else {
                        sshFlowP->stat |= SSH_STAT_DH_KEXREPLY;
                    }
                    // host key length
                    uint32_t hklen;
                    if (!t2buf_read_u32(&t2buf, &hklen)) goto sshpkt;
                    const long start = t2buf_tell(&t2buf);
                    // host key type length
                    uint32_t hktlen;
                    if (!t2buf_read_u32(&t2buf, &hktlen)) goto sshpkt;
                    // host key type
                    if (t2buf_readnstr(&t2buf, (uint8_t*)sshFlowP->host_key_type, sizeof(sshFlowP->host_key_type), hktlen, T2BUF_UTF8, true) != T2BUF_DST_FULL) {
                        SSH_DBG("Host key type (len=%" PRIu32 "): %s", hktlen, sshFlowP->host_key_type);
                    } else {
                        SSH_DBG("Host key type (len=%" PRIu32 "): %s [truncated]", hktlen, sshFlowP->host_key_type);
                        sshFlowP->stat |= SSH_STAT_HKT_TRUNC;
                        t2buf_seek(&t2buf, start+4, SEEK_SET);
                        if (!t2buf_skip_n(&t2buf, hktlen)) {
                            sshFlowP->stat |= SSH_STAT_MALFORMED;
                            goto sshpkt;
                        }
                    }
                    if (memcmp(sshFlowP->host_key_type, "ssh-rsa", 7) == 0) {
                        // host key
                        // rsa public exponent
                        ssh_read_mpint(&t2buf, "rsa-public-exponent");
                        // rsa modulus (N)
                        ssh_read_mpint(&t2buf, "rsa-modulus-n");
                    } else if (memcmp(sshFlowP->host_key_type, "ssh-dss", 7) == 0) {
                        // dsa p
                        ssh_read_mpint(&t2buf, "dsa-p");
                        // dsa q
                        ssh_read_mpint(&t2buf, "dsa-q");
                        // dsa g
                        ssh_read_mpint(&t2buf, "dsa-g");
                        // dsa y
                        ssh_read_mpint(&t2buf, "dsa-y");
                    //    // TODO
                    //} else if (memcmp(sshFlowP->host_key_type, "ecdsa", 5) == 0) {
                    //    // ECDSA elliptic curve identifier
                    //    char dst[255];
                    //    ssh_read_str(sshFlowP, &t2buf, dst, SSH_BUF_SIZE, "ecdsa-curve-id");
                    //    // ECDSA public key length
                    //    uint32_t qlen;
                    //    if (!t2buf_read_u32(&t2buf, &qlen)) goto sshpkt;
                    //    // ECDSA public key (Q)
                    //    if (!t2buf_skip_n(&t2buf, qlen)) goto sshpkt;
                    //    //ssh_read_hexstr(&t2buf, dst, qlen, "ecdsa-q");
                    } else {
                        SSH_DBG("Unhandled host key type '%s'", sshFlowP->host_key_type);
                        if (!t2buf_skip_n(&t2buf, hklen)) goto sshpkt;
                        //goto sshpkt;
                    }
#if SSH_FINGERPRINT > 0
                    if (hklen) {
                        if (strlen(sshFlowP->fingerprint) != 0) {
                            SSH_DBG("Fingerprint already computed for flow %" PRIu64, flowP->findex);
                            sshFlowP->stat |= SSH_STAT_MALFORMED;
                        } else {
                            // Compute the fingerprint
                            const long end = t2buf_tell(&t2buf);
                            t2buf_seek(&t2buf, start, SEEK_SET);
                            t2_hash((char*)(t2buf.buffer + t2buf_tell(&t2buf)), hklen, sshFlowP->fingerprint, sizeof(sshFlowP->fingerprint), ':', md);
                            t2buf_seek(&t2buf, end, SEEK_SET);
                            SSH_DBG("Fingerprint: '%s'", sshFlowP->fingerprint);
                        }
                    }
#endif
                    if (sshFlowP->stat & SSH_STAT_ECDH_KEXREPLY) {
                        // ECDH server's ephemeral public key length
                        uint32_t qslen;
                        if (!t2buf_read_u32(&t2buf, &qslen)) goto sshpkt;
                        // ECDH server's ephemeral public key
                        if (!t2buf_skip_n(&t2buf, qslen)) goto sshpkt;
                        //char dst[255];
                        //ssh_read_hexstr(&t2buf, dst, qslen, "ecdh-q-s");
                    } else {
                        // DH server f
                        ssh_read_mpint(&t2buf, "dh-server-f");
                    }
                    // KEX DH H signature
                    uint32_t hlen;
                    if (!t2buf_read_u32(&t2buf, &hlen)) goto sshpkt;
                    if (!t2buf_skip_n(&t2buf, hlen)) goto sshpkt;
                    //hlen = MIN(hlen, SSH_BUF_SIZE);
                    //char dst[2*hlen+1];
                    //ssh_read_hexstr(&t2buf, dst, hlen, "kex_dh_h_sig");
                } else {
                    /* diffie-hellman group exchange group */
                    SSH_DBG("Diffie-Hellman Group Exchange Group");
                    sshFlowP->stat |= SSH_STAT_DH_GEX_GROUP;
                    // DH modulus (P)
                    ssh_read_mpint(&t2buf, "dh-modulus-p");
                    // DH base (G)
                    ssh_read_mpint(&t2buf, "dh-base-g");
                }
                break;
            }

            case 32: /* diffie-hellman group exchange init */
                SSH_DBG("Diffie-Hellman Group Exchange Init");
                sshFlowP->stat |= SSH_STAT_DH_GEX_INIT;
                // DH client e
                ssh_read_mpint(&t2buf, "dhclient-e");
                break;

            case 33: { /* diffie-hellman group exchange reply */
                SSH_DBG("Diffie-Hellman Group Exchange Reply");
                sshFlowP->stat |= SSH_STAT_DH_GEX_REP;
                // KEX DH Host key
                uint32_t hklen;
                if (!t2buf_read_u32(&t2buf, &hklen)) goto sshpkt;
#if SSH_FINGERPRINT > 0
                const long start = t2buf_tell(&t2buf);
#endif
                if (!t2buf_skip_n(&t2buf, hklen)) goto sshpkt;
                //hklen = MIN(hklen, SSH_BUF_SIZE);
                //char dst[2*hklen+1];
                //ssh_read_hexstr(&t2buf, dst, hklen, "kex_dh_h_sig");
#if SSH_FINGERPRINT > 0
                if (hklen) {
                    if (strlen(sshFlowP->fingerprint) != 0) {
                        SSH_DBG("Fingerprint already computed for flow %" PRIu64, flowP->findex);
                        sshFlowP->stat |= SSH_STAT_MALFORMED;
                    } else {
                        // Compute the fingerprint
                        const long end = t2buf_tell(&t2buf);
                        t2buf_seek(&t2buf, start, SEEK_SET);
                        t2_hash((char*)(t2buf.buffer + t2buf_tell(&t2buf)), hklen, sshFlowP->fingerprint, sizeof(sshFlowP->fingerprint), ':', md);
                        t2buf_seek(&t2buf, end, SEEK_SET);
                        SSH_DBG("Fingerprint: '%s'", sshFlowP->fingerprint);
                    }
                }
#endif
                // DH server f
                ssh_read_mpint(&t2buf, "dh-server-f");
                // KEX DH signature
                if (!t2buf_read_u32(&t2buf, &hklen)) goto sshpkt;
                if (!t2buf_skip_n(&t2buf, hklen)) goto sshpkt;
                //hklen = MIN(hklen, SSH_BUF_SIZE);
                //char sig[2*hklen+1];
                //ssh_read_hexstr(&t2buf, sig, hklen, "kex-dh-h-sig");
                break;
            }

            case 34: /* diffie-hellman group exchange request */
                SSH_DBG("Diffie-Hellman Group Exchange Request");
                sshFlowP->stat |= SSH_STAT_DH_GEX_REQ;
                // DH GEX Min
                t2buf_skip_u32(&t2buf);
                // DH GEX Number of Bits
                t2buf_skip_u32(&t2buf);
                // DH GEX Max
                t2buf_skip_u32(&t2buf);
                break;
#endif // SSH_DECODE == 2

            default:
#if SSH_DEBUG == 1
                T2_PERR(plugin_name, "pkt %" PRIu64 ": Unhandled message type %" PRIu8, numPackets, msg_type);
#endif
                goto sshpkt;
        }

        /* Padding */
        t2buf_skip_n(&t2buf, padlen);

        // TODO mac length?
    }
#endif // SSH_DECODE > 0 || SSH_HASSH == 1

sshpkt:
    if (sPktFile) fprintf(sPktFile, "0x%04" B2T_PRIX16 SEP_CHR, sshFlowP->stat);
}


void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {
    const sshFlow_t * const sshFlowP = &sshFlows[flowIndex];

    sshStat |= sshFlowP->stat;

    // Count the number of SSH flows
    if (sshFlowP->stat & SSH_STAT_SSH) numSSH++;

    // SSH status
    OUTBUF_APPEND_U16(buf, sshFlowP->stat);

    // SSH version
    OUTBUF_APPEND_OPT_STR(buf, sshFlowP->version);

#if SSH_DECODE == 2
    // SSH Host Key Type
    OUTBUF_APPEND_OPT_STR(buf, sshFlowP->host_key_type);

#if SSH_FINGERPRINT > 0
    // SSH public key fingerprint
    OUTBUF_APPEND_OPT_STR(buf, sshFlowP->fingerprint);
#endif
#endif // SSH_DECODE == 2

#if SSH_DECODE > 0
    // SSH cookie
    OUTBUF_APPEND_OPT_STR(buf, sshFlowP->cookie);

#if SSH_ALGO == 1
    // SSH KEX algorithm
    OUTBUF_APPEND_OPT_STR(buf, sshFlowP->kex);

    // SSH Server Host Key algorithm
    OUTBUF_APPEND_OPT_STR(buf, sshFlowP->srv_hkey);

    // SSH encryption algorithm client to server
    OUTBUF_APPEND_OPT_STR(buf, sshFlowP->enc_cs1);

    // SSH encryption algorithm server to client
    OUTBUF_APPEND_OPT_STR(buf, sshFlowP->enc_sc1);

    // SSH MAC algorithm client to server
    OUTBUF_APPEND_OPT_STR(buf, sshFlowP->mac_cs1);

    // SSH MAC algorithm server to client
    OUTBUF_APPEND_OPT_STR(buf, sshFlowP->mac_sc1);

    // SSH compression algorithm client to server
    OUTBUF_APPEND_OPT_STR(buf, sshFlowP->comp_cs1);

    // SSH compression algorithm server to client
    OUTBUF_APPEND_OPT_STR(buf, sshFlowP->comp_sc1);

    // SSH language client to server
    OUTBUF_APPEND_OPT_STR(buf, sshFlowP->lang_cs1);

    // SSH language server to client
    OUTBUF_APPEND_OPT_STR(buf, sshFlowP->lang_sc1);
#endif

#if SSH_LISTS == 1
    // SSH KEX algorithms
    OUTBUF_APPEND_OPT_STR(buf, sshFlowP->kex_algo);

    // SSH Server Host Key algorithms
    OUTBUF_APPEND_OPT_STR(buf, sshFlowP->srv_hkey_algo);

    // SSH encryption algorithms client to server
    OUTBUF_APPEND_OPT_STR(buf, sshFlowP->enc_cs);

    // SSH encryption algorithms server to client
    OUTBUF_APPEND_OPT_STR(buf, sshFlowP->enc_sc);

    // SSH MAC algorithms client to server
    OUTBUF_APPEND_OPT_STR(buf, sshFlowP->mac_cs);

    // SSH MAC algorithms server to client
    OUTBUF_APPEND_OPT_STR(buf, sshFlowP->mac_sc);

    // SSH compression algorithms client to server
    OUTBUF_APPEND_OPT_STR(buf, sshFlowP->comp_cs);

    // SSH compression algorithms server to client
    OUTBUF_APPEND_OPT_STR(buf, sshFlowP->comp_sc);

    // SSH languages client to server
    OUTBUF_APPEND_OPT_STR(buf, sshFlowP->lang_cs);

    // SSH languages server to client
    OUTBUF_APPEND_OPT_STR(buf, sshFlowP->lang_sc);
#endif

#endif // SSH_DECODE > 0

#if SSH_HASSH == 1
    // SSH HASSH fingerprint
    OUTBUF_APPEND_OPT_STR(buf, sshFlowP->hassh);

    // SSH HASSH description
    OUTBUF_APPEND_OPT_STR(buf, sshFlowP->hassh_desc);

#if SSH_HASSH_STR == 1
    // SSH HASSH string
    OUTBUF_APPEND_OPT_STR(buf, sshFlowP->hassh_str);
#endif
#endif // SSH_HASSH == 1
}


static inline void ssh_pluginReport(FILE *stream) {
    if (sshStat) {
        T2_FPLOG_AGGR_HEX0(stream, plugin_name, sshStat);
        T2_FPLOG_DIFFNUMP(stream, plugin_name, "Number of SSH flows", numSSH, totalFlows);
#if SSH_HASSH == 1
        T2_FPLOG_NUM(stream, plugin_name, "Number of HASSH signatures matched", numHassh-numHassh0);
#endif
    }
}


void t2Monitoring(FILE *stream, uint8_t state) {

    switch (state) {

        // Print the name of the variables that will be output
        case T2_MON_PRI_HDR:
            fputs("sshNFlows" SEP_CHR
                  "sshStat"   SEP_CHR
                  , stream);
            return;

        // Print the variables to monitor
        case T2_MON_PRI_VAL:
            fprintf(stream,
                    "%"     PRIu64     /* sshNFlows */ SEP_CHR
                    "0x%04" B2T_PRIX16 /* sshStat   */ SEP_CHR
                    , numSSH - numSSH0
                    , sshStat);
            break;

        // Print a report similar to t2PluginReport()
        case T2_MON_PRI_REPORT:
            ssh_pluginReport(stream);
            break;

        // Invalid state, do nothing
        default:
            return;
    }

#if DIFF_REPORT == 1
    numSSH0 = numSSH;
#if SSH_HASSH == 1
    numHassh0 = numHassh;
#endif
#endif // DIFF_REPORT == 1
}


void t2PluginReport(FILE *stream) {
#if DIFF_REPORT == 1
    numSSH0 = 0;
#if SSH_HASSH == 1
    numHassh0 = 0;
#endif
#endif // DIFF_REPORT == 1

    ssh_pluginReport(stream);
}


void t2Finalize() {
    free(sshFlows);

#if SSH_HASSH == 1
    ssl_blist_free(ssh_hassh);
#endif
}
