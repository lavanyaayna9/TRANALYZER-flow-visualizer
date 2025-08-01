/*
 * ntlmsspDecode.c
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

#include "ntlmsspDecode.h"
#include "t2buf.h"
#include <errno.h>


/*
 * Plugin variables that may be used by other plugins (MUST be declared in
 * the header file as 'extern ntlmsspFlow_t *ntlmsspFlows;'
 */
ntlmsspFlow_t *ntlmsspFlows;


/*
 * Static variables
 */

static uint64_t numNTLMSSPPkts;
static uint8_t ntlmsspStat;

#if NTLMSSP_SAVE_AUTH_V1 == 1
static FILE *ntlmsspAuthV1File;
static uint32_t ntlmsspNumAuthV1;
#endif // NTLMSSP_SAVE_AUTH_V1 == 1

#if NTLMSSP_SAVE_AUTH_V2 == 1
static FILE *ntlmsspAuthV2File;
static uint32_t ntlmsspNumAuthV2;
#endif // NTLMSSP_SAVE_AUTH_V2 == 1


/*
 * Static function prototypes
 */

static inline void ntlmssp_negotiate(t2buf_t *t2buf, uint64_t flowIndex);
static inline void ntlmssp_challenge(t2buf_t *t2buf, uint64_t flowIndex);
static inline void ntlmssp_authenticate(t2buf_t *t2buf, uint64_t flowIndex);


/*
 * Macros
 */

#define NTLMSSP_WIN_TICK         10000000.0 // 100ns
#define NTLMSSP_WIN_UNIX_DIFF 11644473600LL // number of secs between windows and unix first epoch
#define NTLMSSP_WIN_TIME_TO_UNIX(t) ((t) / NTLMSSP_WIN_TICK - NTLMSSP_WIN_UNIX_DIFF);

// NTLMSSP_READ_*

#define NTLMSSP_READ_U8(t2buf, val) do { \
    if (!t2buf_read_u8(t2buf, val)) return; \
} while(0)
#define NTLMSSP_READ_U16(t2buf, val) do { \
    if (!t2buf_read_le_u16(t2buf, val)) return; \
} while (0)
#define NTLMSSP_READ_U32(t2buf, val) do { \
    if (!t2buf_read_le_u32(t2buf, val)) return; \
} while (0)
#define NTLMSSP_READ_U64(t2buf, val) do { \
    if (!t2buf_read_le_u64(t2buf, val)) return; \
} while (0)
#define NTLMSSP_READNSTR(t2buf, dest, len) do { \
    switch (t2buf_readnstr(t2buf, (uint8_t*)dest, MIN(len, sizeof(dest)-1), len, T2BUF_UTF16_LE, true)) { \
       case T2BUF_EMPTY: \
          NTLMSSP_SKIP_U16(t2buf); \
          break; \
       case T2BUF_DST_FULL: \
           ntlmsspFlowP->status |= NTLMSSP_STAT_TRUNC; \
           break; \
       default: \
            break; \
    } \
    if (len >= sizeof(dest)) { \
        ntlmsspFlowP->status |= NTLMSSP_STAT_TRUNC; \
        NTLMSSP_SKIP_N(t2buf, len - sizeof(dest) - 1); \
    } \
} while (0)

// NTLMSSP_SKIP_*

#define NTLMSSP_SKIP_U8(t2buf) do { \
    if (!t2buf_skip_u8(t2buf)) return; \
} while(0)
#define NTLMSSP_SKIP_U16(t2buf) do { \
    if (!t2buf_skip_u16(t2buf)) return; \
} while (0)
#define NTLMSSP_SKIP_U32(t2buf) do { \
    if (!t2buf_skip_u32(t2buf)) return; \
} while (0)
#define NTLMSSP_SKIP_U64(t2buf) do { \
    if (!t2buf_skip_u64(t2buf)) return; \
} while (0)
#define NTLMSSP_SKIP_N(t2buf, n) do { \
    if (!t2buf_skip_n(t2buf, (n))) return; \
} while (0)


// Tranalyzer functions

T2_PLUGIN_INIT("ntlmsspDecode", "0.9.3", 0, 9);


void t2Init() {
    T2_PLUGIN_STRUCT_NEW(ntlmsspFlows);

#if NTLMSSP_SAVE_AUTH
    t2_env_t env[ENV_NTLMSSP_N] = {};

#if ENVCNTRL > 0
    t2_get_env(PLUGIN_SRCH, ENV_NTLMSSP_N, env);
#else // ENVCNTRL == 0
#if NTLMSSP_SAVE_AUTH_V1 == 1
    T2_SET_ENV_STR(NTLMSSP_AUTH_V1_FILE);
#endif // NTLMSSP_SAVE_AUTH_V1 == 1
#if NTLMSSP_SAVE_AUTH_V2 == 1
    T2_SET_ENV_STR(NTLMSSP_AUTH_V2_FILE);
#endif // NTLMSSP_SAVE_AUTH_V2 == 1
#endif // ENVCNTRL == 0

#if NTLMSSP_SAVE_AUTH_V1 == 1
    ntlmsspAuthV1File = t2_fopen_with_suffix(baseFileName, T2_ENV_VAL(NTLMSSP_AUTH_V1_FILE), "w");
    if (UNLIKELY(!ntlmsspAuthV1File)) exit(EXIT_FAILURE);
#endif // NTLMSSP_SAVE_AUTH_V1 == 1

#if NTLMSSP_SAVE_AUTH_V2 == 1
    ntlmsspAuthV2File = t2_fopen_with_suffix(baseFileName, T2_ENV_VAL(NTLMSSP_AUTH_V2_FILE), "w");
    if (UNLIKELY(!ntlmsspAuthV2File)) exit(EXIT_FAILURE);
#endif // NTLMSSP_SAVE_AUTH_V2 == 1

#if ENVCNTRL > 0
    t2_free_env(ENV_NTLMSSP_N, env);
#endif // ENVCNTRL > 0

#endif // NTLMSSP_SAVE_AUTH
}


binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;

    BV_APPEND_H8(bv  , "ntlmsspStat"          , "NTLMSSP status");
    BV_APPEND_STRC(bv, "ntlmsspTarget"        , "NTLMSSP target name");
    BV_APPEND_STRC(bv, "ntlmsspDomain"        , "NTLMSSP domain name");
    BV_APPEND_STRC(bv, "ntlmsspUser"          , "NTLMSSP username");
    BV_APPEND_STRC(bv, "ntlmsspHost"          , "NTLMSSP host/workstation");
    BV_APPEND_H32(bv , "ntlmsspNegotiateFlags", "NTLMSSP Negotiate Flags");
    BV_APPEND_STRC(bv, "ntlmsspSessKey"       , "NTLMSSP session key");
    BV_APPEND_STRC(bv, "ntlmsspNTProofStr"    , "NTLMSSP NT proof string");
    BV_APPEND_STRC(bv, "ntlmsspServChallenge" , "NTLMSSP server challenge");

#if NTLMSSP_CLI_CHALL == 1
    BV_APPEND_STRC(bv, "ntlmsspCliChallenge"  , "NTLMSSP client challenge");
#endif

#if NTLMSSP_VERSION == 1
    BV_APPEND_STR(bv , "ntlmsspVersion"       , "NTLMSSP version");
#elif NTLMSSP_VERSION == 2
    BV_APPEND(bv, "ntlmsspVersionMajor_Minor_Build_Rev", "NTLMSSP version (Major Version, Minor Version, Build Number and NTLM Current Revision)", 4, bt_uint_8, bt_uint_8, bt_uint_16, bt_uint_8);
#endif // NTLMSSP_VERSION == 2

#if NTLMSSP_NETBIOS == 1
    BV_APPEND_STRC(bv, "ntlmsspNbComputer"    , "NTLMSSP NetBIOS computer name");
    BV_APPEND_STRC(bv, "ntlmsspNbDomain"      , "NTLMSSP NetBIOS domain name");
#endif

#if NTLMSSP_DNS == 1
    BV_APPEND_STRC(bv, "ntlmsspDnsComputer"   , "NTLMSSP DNS computer name");
    BV_APPEND_STRC(bv, "ntlmsspDnsDomain"     , "NTLMSSP DNS domain name");
    BV_APPEND_STRC(bv, "ntlmsspDnsTree"       , "NTLMSSP DNS tree name");
#endif

    BV_APPEND_STRC(bv, "ntlmsspAttrTarget"    , "NTLMSSP Attribute Target Name");
    BV_APPEND_TIMESTAMP(bv, "ntlmsspTimestamp", "NTLMSSP timestamp");

    return bv;
}


static void ntlmssp_read_av_pairs(t2buf_t *t2buf, uint16_t len, uint64_t flowIndex UNUSED) {

    ntlmsspFlow_t * const ntlmsspFlowP = &ntlmsspFlows[flowIndex];
    uint16_t avid = UINT16_MAX;

    while (len >= 4 && t2buf_left(t2buf) >= 4 && avid != 0) {
        /* AvId */
        NTLMSSP_READ_U16(t2buf, &avid);

        /* AvLen */
        uint16_t avlen;
        NTLMSSP_READ_U16(t2buf, &avlen);

        if (len >= (4 + avlen)) len -= (4 + avlen);
        else len = 0;

        switch (avid) {
            case 0x0000: /* AvEOL: End of list */
                break;

            case 0x0001: /* AvNbComputerName */
                NTLMSSP_READNSTR(t2buf, ntlmsspFlowP->nbComputer, avlen);
                break;

            case 0x0002: /* AvNbDomainName */
                NTLMSSP_READNSTR(t2buf, ntlmsspFlowP->nbDomain, avlen);
                break;

            case 0x0003: /* AvDnsComputerName */
                NTLMSSP_READNSTR(t2buf, ntlmsspFlowP->dnsComputer, avlen);
                break;

            case 0x0004: /* AvDnsDomainName */
                NTLMSSP_READNSTR(t2buf, ntlmsspFlowP->dnsDomain, avlen);
                break;

            case 0x0005: /* AvDnsTreeName */
                NTLMSSP_READNSTR(t2buf, ntlmsspFlowP->dnsTree, avlen);
                break;

            case 0x0006: /* AvFlags */
                NTLMSSP_SKIP_U32(t2buf);
                break;

            case 0x0007: { /* AvTimestamp */
                uint64_t ts;
                NTLMSSP_READ_U64(t2buf, &ts);
                ntlmsspFlowP->timestamp = NTLMSSP_WIN_TIME_TO_UNIX(ts);
                break;
            }

            case 0x0008: { /* AvSingleHost */
                /* Size */
                NTLMSSP_SKIP_U32(t2buf);

                /* Z4 */
                NTLMSSP_SKIP_U32(t2buf);
                //uint32_t z4;
                //NTLMSSP_READ_U32(t2buf, &z4);
                //if (z4 != 0) ntlmsspFlowP->status |= NTLMSSP_STAT_MALFORMED;

                /* CustomData */
                NTLMSSP_SKIP_U64(t2buf);

                /* MachineID */
                NTLMSSP_SKIP_N(t2buf, 32);
                break;
            }

            case 0x0009: /* AvTargetName */
                NTLMSSP_READNSTR(t2buf, ntlmsspFlowP->aTargetN, avlen);
                break;

            case 0x000a: /* ChannelBindings (MD5 hash) */
                NTLMSSP_SKIP_N(t2buf, avlen);
                break;

            default:
#if DEBUG > 0
                T2_PERR(plugin_name, "packet %" PRIu64 " Unhandled AvId 0x%04" B2T_PRIX16, numPackets, avid);
#endif
                NTLMSSP_SKIP_N(t2buf, avlen);
                break;
        }
    }
}


void t2OnNewFlow(packet_t *packet UNUSED, unsigned long flowIndex) {
    ntlmsspFlow_t * const ntlmsspFlowP = &ntlmsspFlows[flowIndex];
    memset(ntlmsspFlowP, '\0', sizeof(*ntlmsspFlowP));
}


void t2OnLayer4(packet_t *packet, unsigned long flowIndex) {
    ntlmsspFlow_t * const ntlmsspFlowP = &ntlmsspFlows[flowIndex];

    // only 1. frag packet will be processed
    if (!t2_is_first_fragment(packet)) return;

    const uint16_t snaplen = packet->snapL7Len;
    const uint8_t * const l7HdrP = packet->l7HdrP;
    t2buf_t t2buf = t2buf_create(l7HdrP, snaplen);

    if (!t2buf_memmem(&t2buf, NTLMSSP, sizeof(NTLMSSP))) return;  // not a NTLMSSP packet

    /* Identifier (NTLMSSP\0) */
    NTLMSSP_SKIP_U64(&t2buf);

    ntlmsspFlowP->status |= NTLMSSP_STAT_NTLMSSP;
    numNTLMSSPPkts++;

    /* Message Type */
    uint32_t mt;
    NTLMSSP_READ_U32(&t2buf, &mt);

    switch (mt) {

        case NTLMSSP_NEGOTIATE:
            ntlmsspFlowP->status |= NTLMSSP_STAT_NEGOTIATE;
            ntlmssp_negotiate(&t2buf, flowIndex);
            break;

        case NTLMSSP_CHALLENGE:
            ntlmsspFlowP->status |= NTLMSSP_STAT_CHALLENGE;
            ntlmssp_challenge(&t2buf, flowIndex);
            break;

        case NTLMSSP_AUTHENTICATE:
            ntlmsspFlowP->status |= NTLMSSP_STAT_AUTHENTICATE;
            ntlmssp_authenticate(&t2buf, flowIndex);
            break;

        default:
            ntlmsspFlowP->status |= NTLMSSP_STAT_MALFORMED;
#if DEBUG > 0
            T2_PWRN(plugin_name, "packet %" PRIu64 ": Invalid NTLMSSP message type 0x%08" B2T_PRIX32, numPackets, mt);
#endif
            break;
    }
}


static inline void ntlmssp_negotiate(t2buf_t *t2buf, uint64_t flowIndex) {
    ntlmsspFlow_t * const ntlmsspFlowP = &ntlmsspFlows[flowIndex];

    const size_t start = t2buf_tell(t2buf) - 12; // start of NTLMSSP record (-12 for id and type)

    /* NegotiateFlags */
    uint32_t flags;
    NTLMSSP_READ_U32(t2buf, &flags);
    ntlmsspFlowP->negoFlags |= flags;

    /* DomainNameLen */
    uint16_t dlen;
    NTLMSSP_READ_U16(t2buf, &dlen);

    /* DomainNameMaxLen */
    NTLMSSP_SKIP_U16(t2buf);

    /* DomainNameBufferOffset */
    uint32_t doff;
    NTLMSSP_READ_U32(t2buf, &doff);

    /* WorkstationLen */
    uint16_t wlen;
    NTLMSSP_READ_U16(t2buf, &wlen);

    /* WorkstationMaxLen */
    NTLMSSP_SKIP_U16(t2buf);

    /* WorkstationBufferOffset */
    uint32_t woff;
    NTLMSSP_READ_U32(t2buf, &woff);

    /* Version */
    if (flags & NTLMSSP_NEGOTIATE_VERSION) {
        NTLMSSP_READ_U8(t2buf, &ntlmsspFlowP->version.major);
        NTLMSSP_READ_U8(t2buf, &ntlmsspFlowP->version.minor);
        NTLMSSP_READ_U16(t2buf, &ntlmsspFlowP->version.build);
        NTLMSSP_SKIP_N(t2buf, 3);
        NTLMSSP_READ_U8(t2buf, &ntlmsspFlowP->version.rev);
    }

    /* Payload (variable, no order) */

    /* DomainName */
    t2buf_seek(t2buf, start + doff, SEEK_SET);
    NTLMSSP_READNSTR(t2buf, ntlmsspFlowP->domain, dlen);

    long curr = t2buf_tell(t2buf);

    /* Workstation */
    t2buf_seek(t2buf, start + woff, SEEK_SET);
    NTLMSSP_READNSTR(t2buf, ntlmsspFlowP->workstation, wlen);

    if (t2buf_tell(t2buf) > curr) curr = t2buf_tell(t2buf);

    t2buf_seek(t2buf, curr, SEEK_SET);
}


static inline void ntlmssp_challenge(t2buf_t *t2buf, uint64_t flowIndex) {
    ntlmsspFlow_t * const ntlmsspFlowP = &ntlmsspFlows[flowIndex];

    const size_t start = t2buf_tell(t2buf) - 12; // start of NTLMSSP record (-12 for id and type)

    /* TargetNameLen */
    uint16_t tnlen;
    NTLMSSP_READ_U16(t2buf, &tnlen);

    /* TargetNameMaxLen */
    NTLMSSP_SKIP_U16(t2buf);

    /* TargetNameBufferOffset */
    uint32_t tnoff;
    NTLMSSP_READ_U32(t2buf, &tnoff);

    /* NegotiateFlags */
    uint32_t flags;
    NTLMSSP_READ_U32(t2buf, &flags);
    ntlmsspFlowP->negoFlags |= flags;

    /* ServerChallenge */
    uint_fast8_t i;
    for (i = 0; i < sizeof(uint64_t); i++) {
        uint8_t tmp;
        NTLMSSP_READ_U8(t2buf, &tmp);
        snprintf(&(ntlmsspFlowP->ntlmserverchallenge[2*i]), 3, "%02x", tmp);
    }
    ntlmsspFlowP->ntlmserverchallenge[2*i] = '\0';

    /* Reserved */
    uint64_t reserved;
    NTLMSSP_READ_U64(t2buf, &reserved);
    if (reserved != 0) ntlmsspFlowP->status |= NTLMSSP_STAT_MALFORMED;

    /* TargetInfoLen */
    uint16_t tilen;
    NTLMSSP_READ_U16(t2buf, &tilen);

    /* TargetInfoMaxLen */
    NTLMSSP_SKIP_U16(t2buf);

    /* TargetInfoBufferOffset */
    uint32_t tioff;
    NTLMSSP_READ_U32(t2buf, &tioff);

    /* Version */
    if (flags & NTLMSSP_NEGOTIATE_VERSION) {
        NTLMSSP_READ_U8(t2buf, &ntlmsspFlowP->version.major);
        NTLMSSP_READ_U8(t2buf, &ntlmsspFlowP->version.minor);
        NTLMSSP_READ_U16(t2buf, &ntlmsspFlowP->version.build);
        NTLMSSP_SKIP_N(t2buf, 3);
        NTLMSSP_READ_U8(t2buf, &ntlmsspFlowP->version.rev);
    }

    /* Payload (variable, no order) */

    /* TargetName */
    t2buf_seek(t2buf, start + tnoff, SEEK_SET);
    NTLMSSP_READNSTR(t2buf, ntlmsspFlowP->target, tnlen);

    /* TargetInfo */
    if (tioff > tnoff) {
        t2buf_seek(t2buf, start + tioff, SEEK_SET);
        // Array of AV_PAIR
        ntlmssp_read_av_pairs(t2buf, tilen, flowIndex);
    }
}


static inline void ntlmssp_authenticate(t2buf_t *t2buf, uint64_t flowIndex) {
    ntlmsspFlow_t * const ntlmsspFlowP = &ntlmsspFlows[flowIndex];

    const size_t start = t2buf_tell(t2buf) - 12; // start of NTLMSSP record (-12 for id and type)

    /* LmChallengeResponseLen */
    uint16_t lmlen;
    NTLMSSP_READ_U16(t2buf, &lmlen);

    /* LmChallengeResponseMaxLen */
    NTLMSSP_SKIP_U16(t2buf);

    /* LmChallengeResponseBufferOffset */
    uint32_t lmoff;
    NTLMSSP_READ_U32(t2buf, &lmoff);

    /* NtChallengeResponseLen */
    uint16_t ntlen;
    NTLMSSP_READ_U16(t2buf, &ntlen);

    /* NtChallengeResponseMaxLen */
    NTLMSSP_SKIP_U16(t2buf);

    /* NtChallengeResponseBufferOffset */
    uint32_t ntoff;
    NTLMSSP_READ_U32(t2buf, &ntoff);

    /* DomainNameLen */
    uint16_t dlen;
    NTLMSSP_READ_U16(t2buf, &dlen);

    /* DomainNameMaxLen */
    NTLMSSP_SKIP_U16(t2buf);

    /* DomainNameBufferOffset */
    uint32_t doff;
    NTLMSSP_READ_U32(t2buf, &doff);

    /* UserNameLen */
    uint16_t ulen;
    NTLMSSP_READ_U16(t2buf, &ulen);

    /* UserNameMaxLen */
    NTLMSSP_SKIP_U16(t2buf);

    /* UserNameBufferOffset */
    uint32_t uoff;
    NTLMSSP_READ_U32(t2buf, &uoff);

    /* WorkstationLen */
    uint16_t wlen;
    NTLMSSP_READ_U16(t2buf, &wlen);

    /* WorkstationMaxLen */
    NTLMSSP_SKIP_U16(t2buf);

    /* WorkstationBufferOffset */
    uint32_t woff;
    NTLMSSP_READ_U32(t2buf, &woff);

    /* EncryptedRandomSessionKeyLen */
    uint16_t elen;
    NTLMSSP_READ_U16(t2buf, &elen);

    /* EncryptedRandomSessionKeyMaxLen */
    NTLMSSP_SKIP_U16(t2buf);

    /* EncryptedRandomSessionKeyBufferOffset */
    uint32_t eoff;
    NTLMSSP_READ_U32(t2buf, &eoff);

    /* NegotiateFlags */
    uint32_t flags;
    NTLMSSP_READ_U32(t2buf, &flags);
    ntlmsspFlowP->negoFlags |= flags;

    /* Version */
    if (flags & NTLMSSP_NEGOTIATE_VERSION) {
        NTLMSSP_READ_U8(t2buf, &ntlmsspFlowP->version.major);
        NTLMSSP_READ_U8(t2buf, &ntlmsspFlowP->version.minor);
        NTLMSSP_READ_U16(t2buf, &ntlmsspFlowP->version.build);
        NTLMSSP_SKIP_N(t2buf, 3);
        NTLMSSP_READ_U8(t2buf, &ntlmsspFlowP->version.rev);
    }

    /* MIC */
    NTLMSSP_SKIP_N(t2buf, 16);

    /* Payload (variable, no order) */

    long curr = t2buf_tell(t2buf);

    /* LmChallengeResponse */
    t2buf_seek(t2buf, start + lmoff, SEEK_SET);

    if (t2buf_tell(t2buf) > curr) curr = t2buf_tell(t2buf);

    uint8_t tmp;
    uint_fast16_t i;
    if (ntlen == 24) { /* NetNTLMv1 */
        ntlmsspFlowP->atype = 1;
        for (i = 0; i < lmlen; i++) {
            NTLMSSP_READ_U8(t2buf, &tmp);
            snprintf(&(ntlmsspFlowP->ntproof[2*i]), 3, "%02x", tmp);
        }
        ntlmsspFlowP->ntproof[2*i] = '\0';

        for (i = 0; i < ntlen; i++) {
            NTLMSSP_READ_U8(t2buf, &tmp);
            snprintf(&(ntlmsspFlowP->ntlmclientchallenge[2*i]), 3, "%02x", tmp);
        }
        ntlmsspFlowP->ntlmclientchallenge[2*i] = '\0';

    } else if (ntlen > 60) { /* NetNTLMv2 */
        ntlmsspFlowP->atype = 2;

        NTLMSSP_SKIP_N(t2buf, lmlen);

        /* NtChallengeResponse */
        t2buf_seek(t2buf, start + ntoff, SEEK_SET);

        for (i = 0; i < 16; i++) {
            NTLMSSP_READ_U8(t2buf, &tmp);
            snprintf(&(ntlmsspFlowP->ntproof[2*i]), 3, "%02x", tmp);
            ntlen--;
        }
        ntlmsspFlowP->ntproof[2*i] = '\0';

        for (i = 0; i < ntlen/*28*/; i++) {
            NTLMSSP_READ_U8(t2buf, &tmp);
            snprintf(&(ntlmsspFlowP->ntlmclientchallenge[2*i]), 3, "%02x", tmp);
        }
        ntlmsspFlowP->ntlmclientchallenge[2*i] = '\0';

        // p.34
        // NTLMSSP_READ_U8();  // RespType (0x1)
        // NTLMSSP_READ_U8();  // HiRespType (0x1)
        // NTLMSSP_READ_U16(); // Reserved1 (0x0000)
        // NTLMSSP_READ_U32(); // Reserved2 (0x00000000)
        // NTLMSSP_READ_U64(); // Timestamp
        // NTLMSSP_READ_U64(); // ClientChallenge
        // NTLMSSP_READ_U32(); // Reserved3 (0x00000000)

        t2buf_seek(t2buf, start + ntoff + 44, SEEK_SET);
        ntlen -= 28;

        /* AvPairs */
        ntlmssp_read_av_pairs(t2buf, ntlen, flowIndex);
        if (t2buf_left(t2buf) <= 0) return;
    }

    if (t2buf_tell(t2buf) > curr) curr = t2buf_tell(t2buf);

    /* DomainName */
    t2buf_seek(t2buf, start + doff, SEEK_SET);
    NTLMSSP_READNSTR(t2buf, ntlmsspFlowP->domain, dlen);

    if (t2buf_tell(t2buf) > curr) curr = t2buf_tell(t2buf);

    /* UserName */
    t2buf_seek(t2buf, start + uoff, SEEK_SET);
    NTLMSSP_READNSTR(t2buf, ntlmsspFlowP->user, ulen);

    if (t2buf_tell(t2buf) > curr) curr = t2buf_tell(t2buf);

    /* Workstation */
    t2buf_seek(t2buf, start + woff, SEEK_SET);
    NTLMSSP_READNSTR(t2buf, ntlmsspFlowP->workstation, wlen);

    if (t2buf_tell(t2buf) > curr) curr = t2buf_tell(t2buf);

    /* EncryptedRandomSessionKey */
    t2buf_seek(t2buf, start + eoff, SEEK_SET);
    if (elen != 16) {
        NTLMSSP_SKIP_N(t2buf, elen);
    } else {
        for (i = 0; i < elen; i++) {
            NTLMSSP_READ_U8(t2buf, &tmp);
            snprintf(&(ntlmsspFlowP->sesskey[2*i]), 3, "%02x", tmp);
        }
        ntlmsspFlowP->sesskey[2*i] = '\0';
    }

    if (t2buf_tell(t2buf) > curr) curr = t2buf_tell(t2buf);

    t2buf_seek(t2buf, curr, SEEK_SET);
}


void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {

    const ntlmsspFlow_t * const ntlmsspFlowP = &ntlmsspFlows[flowIndex];

#if NTLMSSP_SAVE_AUTH > 0
    const flow_t * const flowP = &flows[flowIndex];
    if (FLOW_IS_A(flowP) && FLOW_HAS_OPPOSITE(flowP)) {
        ntlmsspFlow_t * const ntlmsspFlowP = &ntlmsspFlows[flowIndex];
        const uint64_t reverseFlowIndex = flowP->oppositeFlowIndex;
        const ntlmsspFlow_t * const reverseFlow = &ntlmsspFlows[reverseFlowIndex];
        if (strlen(ntlmsspFlowP->user) &&
            strlen(ntlmsspFlowP->domain) &&
            strlen(reverseFlow->ntlmserverchallenge) &&
            strlen(ntlmsspFlowP->ntlmclientchallenge) &&
            strlen(ntlmsspFlowP->ntproof))
        {
            if (ntlmsspFlowP->atype == 1) {
#if NTLMSSP_SAVE_AUTH_V1 == 1
#if NTLMSSP_SAVE_INFO == 1
                fprintf(ntlmsspAuthV1File, "# Flow %" PRIu64 "\n", flowP->findex);
#endif
                fprintf(ntlmsspAuthV1File, "%s::%s:%s:%s:%s\n",
                        ntlmsspFlowP->user,
                        ntlmsspFlowP->domain,
                        ntlmsspFlowP->ntproof,
                        ntlmsspFlowP->ntlmclientchallenge,
                        reverseFlow->ntlmserverchallenge);
                ntlmsspFlowP->status |= NTLMSSP_STAT_HASH_V1;
                ntlmsspNumAuthV1++;
#endif
            } else {
#if NTLMSSP_SAVE_AUTH_V2 == 1
#if NTLMSSP_SAVE_INFO == 1
                fprintf(ntlmsspAuthV2File, "# Flow %" PRIu64 "\n", flowP->findex);
#endif
                fprintf(ntlmsspAuthV2File, "%s::%s:%s:%s:%s\n",
                        ntlmsspFlowP->user,
                        ntlmsspFlowP->domain,
                        reverseFlow->ntlmserverchallenge,
                        ntlmsspFlowP->ntproof,
                        ntlmsspFlowP->ntlmclientchallenge);
                ntlmsspFlowP->status |= NTLMSSP_STAT_HASH_V2;
                ntlmsspNumAuthV2++;
#endif
            }
        }
    }
#endif // NTLMSSP_SAVE_AUTH > 0

    ntlmsspStat |= ntlmsspFlowP->status;

    OUTBUF_APPEND_U8(buf , ntlmsspFlowP->status);              // ntlmsspStat
    OUTBUF_APPEND_STR(buf, ntlmsspFlowP->target);              // ntlmsspTarget
    OUTBUF_APPEND_STR(buf, ntlmsspFlowP->domain);              // ntlmsspDomain
    OUTBUF_APPEND_STR(buf, ntlmsspFlowP->user);                // ntlmsspUser
    OUTBUF_APPEND_STR(buf, ntlmsspFlowP->workstation);         // ntlmsspHost
    OUTBUF_APPEND_U32(buf, ntlmsspFlowP->negoFlags);           // ntlmsspNegotiateFlags
    OUTBUF_APPEND_STR(buf, ntlmsspFlowP->sesskey);             // ntlmsspSessKey
    OUTBUF_APPEND_STR(buf, ntlmsspFlowP->ntproof);             // ntlmsspNTProofStr
    OUTBUF_APPEND_STR(buf, ntlmsspFlowP->ntlmserverchallenge); // ntlmsspServChallenge

#if NTLMSSP_CLI_CHALL == 1
    OUTBUF_APPEND_STR(buf, ntlmsspFlowP->ntlmclientchallenge); // ntlmsspCliChallenge
#endif

#if NTLMSSP_VERSION == 1
    // ntlmsspVersion
    char version[NTLMSSP_NAME_LEN+1] = {};
    snprintf(version, sizeof(version), "Version %" PRIu8 ".%" PRIu8 " (Build %" PRIu16 "); NTLM Current Revision %" PRIu8,
            ntlmsspFlowP->version.major, ntlmsspFlowP->version.minor, ntlmsspFlowP->version.build, ntlmsspFlowP->version.rev);
    OUTBUF_APPEND_STR(buf, version);
#elif NTLMSSP_VERSION == 2
    // ntlmsspVersionMajor_Minor_Build_Rev
    OUTBUF_APPEND_U8(buf, ntlmsspFlowP->version.major);
    OUTBUF_APPEND_U8(buf, ntlmsspFlowP->version.minor);
    OUTBUF_APPEND_U16(buf, ntlmsspFlowP->version.build);
    OUTBUF_APPEND_U8(buf, ntlmsspFlowP->version.rev);
#endif // NTLMSSP_VERSION == 2

#if NTLMSSP_NETBIOS == 1
    OUTBUF_APPEND_STR(buf, ntlmsspFlowP->nbComputer); // ntlmsspNbComputer
    OUTBUF_APPEND_STR(buf, ntlmsspFlowP->nbDomain);   // ntlmsspNbDomain
#endif

#if NTLMSSP_DNS == 1
    OUTBUF_APPEND_STR(buf, ntlmsspFlowP->dnsComputer); // ntlmsspDnsComputer
    OUTBUF_APPEND_STR(buf, ntlmsspFlowP->dnsDomain);   // ntlmsspDnsDomain
    OUTBUF_APPEND_STR(buf, ntlmsspFlowP->dnsTree);     // ntlmsspDnsTree
#endif

    OUTBUF_APPEND_STR(buf, ntlmsspFlowP->aTargetN);       // ntlmsspAttrTarget
    OUTBUF_APPEND_TIME_SEC(buf, ntlmsspFlowP->timestamp); // ntlmsspTimestamp
}


void t2PluginReport(FILE *stream) {
    if (ntlmsspStat) {
        T2_FPLOG_AGGR_HEX0(stream, plugin_name, ntlmsspStat);
        T2_FPLOG_NUMP(stream, plugin_name, "Number of NTLMSSP packets", numNTLMSSPPkts, numPackets);
#if NTLMSSP_SAVE_AUTH > 0
        char hrnum[64];

#if NTLMSSP_SAVE_AUTH_V1 == 1
        if (ntlmsspNumAuthV1 > 0) {
            T2_CONV_NUM(ntlmsspNumAuthV1, hrnum);
            T2_FPLOG(stream, plugin_name, "Number of NetNTLMv1 hashes extracted: %" PRIu32 "%s", ntlmsspNumAuthV1, hrnum);
        }
#endif // NTLMSSP_SAVE_AUTH_V1 == 1

#if NTLMSSP_SAVE_AUTH_V2 == 1
        if (ntlmsspNumAuthV2 > 0) {
            T2_CONV_NUM(ntlmsspNumAuthV2, hrnum);
            T2_FPLOG(stream, plugin_name, "Number of NetNTLMv2 hashes extracted: %" PRIu32 "%s", ntlmsspNumAuthV2, hrnum);
        }
#endif // NTLMSSP_SAVE_AUTH_V2 == 1

#endif // NTLMSSP_SAVE_AUTH > 0
    }
}


void t2Finalize() {

#if NTLMSSP_SAVE_AUTH_V1 == 1
    if (ntlmsspAuthV1File) fclose(ntlmsspAuthV1File);
#endif // NTLMSSP_SAVE_AUTH_V1 == 1

#if NTLMSSP_SAVE_AUTH_V2 == 1
    if (ntlmsspAuthV2File) fclose(ntlmsspAuthV2File);
#endif // NTLMSSP_SAVE_AUTH_V2 == 1

    free(ntlmsspFlows);
}
