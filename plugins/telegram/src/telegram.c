/*
 * telegram.c
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

#include "telegram.h"

#include <errno.h>
#include <math.h>

#include "memdebug.h"

#if TG_DEOBFUSCATE != 0
#include <openssl/modes.h>
#ifndef __APPLE__
#include <endian.h>
#else // __APPLE__
#include "missing/missing.h"
#endif // __APPLE__
#endif // TG_DEOBFUSCATE != 0


// print debug messages only on DEBUG or TG_DEBUG_MESSAGES
#define TG_DEBUG (DEBUG | TG_DEBUG_MESSAGES)
#if TG_DEBUG != 0
#define debug_print(format, args...) T2_PINF(plugin_name, format, ##args)
#else // TG_DEBUG == 0
#define debug_print(format, args...)
#endif // TG_DEBUG != 0


// plugin variables

tgFlow_t *tgFlows;


// Static variables

static uint64_t numTGPkts;
static uint16_t tgStat;

#if TG_DEOBFUSCATE != 0
static uint8_t deobfuscated[MAX_PKT_SIZE];
#endif // TG_DEOBFUSCATE != 0


// Tranalyzer functions
T2_PLUGIN_INIT("telegram", "0.9.3", 0, 9);


// helper functions

#if TG_DEOBFUSCATE != 0
/**
 * @brief Setup the AES decryption key and IV for current flow and opposite flow
 *
 * @param  flow_index  tranalyzer flow index of client->server flow
 * @param  key         256-bit AES key
 * @param  iv          128-bit AES initialization vector
 * @return true on key setup success; false on failure
 */
static bool key_setup(unsigned long flow_index, const uint8_t key[KEY_LENGTH], \
        const uint8_t iv[BLOCK_SIZE]) {
    // setup iv and key for current flow
    ctr_crypt *crypt = &tgFlows[flow_index].crypt;
    memcpy(crypt->iv, iv, BLOCK_SIZE);
    if (AES_set_encrypt_key(key, KEY_LENGTH * 8, &crypt->key) != 0) {
        return false;
    }

    // setup iv and key for opposite flow
    const unsigned long opposite_flow_index = flows[flow_index].oppositeFlowIndex;
    if (opposite_flow_index == HASHTABLE_ENTRY_NOT_FOUND) {
        return true; // no opposite flow
    }

    crypt = &tgFlows[opposite_flow_index].crypt;
    uint8_t opposite_key[KEY_LENGTH];
    for (int i = 0; i < BLOCK_SIZE; ++i) {
        opposite_key[i] = iv[BLOCK_SIZE - 1 - i];
        opposite_key[i+BLOCK_SIZE] = key[KEY_LENGTH - 1 - i];
        crypt->iv[i] = key[BLOCK_SIZE - 1 - i];
    }
    return AES_set_encrypt_key(opposite_key, KEY_LENGTH * 8, &crypt->key) == 0;
}

/**
 * @brief Compute ivec from start IV and stream position.
 *
 * @param  iv    initialization vector at the start of the CTR stream
 * @param  ivec  resulting initialization vector (nonce+counter) at position pos in the CTR stream
 * @param  pos   position in the CTR stream for which we want to compute the ivec
 */
static void compute_ivec(const uint8_t iv[BLOCK_SIZE], uint8_t ivec[BLOCK_SIZE], uint32_t pos) {
    // from last ivec byte to first
    uint32_t start = pos / BLOCK_SIZE;
    int carry = 0;
    for (int i = BLOCK_SIZE - 1; i >= 0; --i) {
        uint16_t sum = (start & 0xff) + carry + iv[i];
        ivec[i] = sum & 0xff;
        carry = sum > 0xff ? 1 : 0;
        start >>= 8;
    }
}

/**
 * @brief Increment initialization vector (stored in big-endian) by 1.
 */
static void inc_ivec(uint8_t ivec[BLOCK_SIZE]) {
    for (int i = BLOCK_SIZE - 1; i >= 0; --i) {
        uint8_t c = ivec[i] + 1;
        ivec[i] = c;
        if (c != 0) {
            break;
        }
    }
}

/**
 * @brief Decrypt AES CTR ciphertext
 *
 * @param  in    ciphertext to decrypt
 * @param  out   buffer to store the decrypted bytes
 * @param  len   length of the ciphertext, out buffer is assumed to be at least len bytes long
 * @param  pos   position in the CTR stream where ciphertext is located
 * @param  crypt structure containing the AES decryption key and IV
 */
static void decrypt(const uint8_t *in, uint8_t *out, uint32_t len, uint32_t pos, \
        const ctr_crypt *crypt) {
    uint8_t ivec[BLOCK_SIZE];
    compute_ivec(crypt->iv, ivec, pos);

    uint32_t start_byte = pos % BLOCK_SIZE;
    uint8_t tmp[BLOCK_SIZE];
    // CRYPTO_ctr128_encrypt assumes that tmp already contains current block stream if starting
    // to decrypt in the middle of a block
    if (start_byte > 0) {
        AES_encrypt(ivec, tmp, &crypt->key);
        inc_ivec(ivec);
    }
    CRYPTO_ctr128_encrypt(in, out, len, &crypt->key, ivec, tmp, &start_byte, \
            (block128_f)AES_encrypt);
}
#endif // TG_DEOBFUSCATE != 0

/**
 * @brief Flag flow as not telegram.
 *
 * This function also deletes the extracted files and cancel deobfuscation. It does it
 * for the flow itself and also the opposite flow if it exists.
 */
static void unset_telegram(unsigned long flow_index) {
    unsigned long flow_indexes[2];
    flow_indexes[0] = flow_index;
    flow_indexes[1] = flows[flow_index].oppositeFlowIndex;

    // unset telegram for both directions
    for (int i = 0; i < 2; ++i) {
        flow_index = flow_indexes[i];
        if (flow_index == HASHTABLE_ENTRY_NOT_FOUND) {
            continue;
        }

        tgFlow_t *flow = &tgFlows[flow_index];
        flow->stat = 0;
        numTGPkts -= flow->numTpkts;
        flow->numTpkts = 0;

    #if TG_SAVE == 1
        if (flow->fd) {
            file_manager_close(t2_file_manager, flow->fd);
            flow->fd = NULL;
            // remove extracted file
            if (UNLIKELY(remove(flow->tgName))) {
                T2_PERR(plugin_name, "Failed to remove file '%s': %s", flow->tgName, \
                        strerror(errno));
            }
            free(flow->tgName);
            flow->tgName = NULL;
        }
    #endif // TG_SAVE == 1

    # if TG_DEOBFUSCATE != 0
        flow->auth_key_id = 0;
        flow->obf_state = OBFUSC_NOPE;
    # endif // TG_DEOBFUSCATE != 0
    }
}


// Tranalyzer functions

void t2Init() {
    T2_PLUGIN_STRUCT_NEW(tgFlows);

    if (sPktFile) {
        fputs("tgStat" SEP_CHR, sPktFile);
    }
}


binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;
    BV_APPEND_H16(bv, "tgStat", "telegram status");
#if TG_DEOBFUSCATE != 0
    BV_APPEND_H64(bv, "tgAuthKeyId", "telegram auth key id");
#endif // TG_DEOBFUSCATE != 0
    return bv;
}


void t2OnNewFlow(packet_t *packet UNUSED, unsigned long flowIndex) {
    tgFlow_t * const tgFlowP = &tgFlows[flowIndex];
    memset(tgFlowP, '\0', sizeof(tgFlow_t));

    const flow_t * const flowP = &flows[flowIndex];
    if (flowP->status & L2_FLOW) {
        return; // Layer 2 flow. No L3/4 pointers, so return
    }

    tgFlowP->l7LenMin = 65535;
    if (flowP->l4Proto == L3_TCP && (
                flowP->srcPort == 443 || flowP->dstPort == 443 ||
                flowP->srcPort ==  80 || flowP->dstPort ==  80 ||
                flowP->srcPort ==  25 || flowP->dstPort ==  25))
    {
        tgFlowP->stat |= TG_INIT;
#if SUBNET_INIT != 0
        const uint_fast8_t ipver = FLOW_IPVER(flowP);
        uint32_t srcNetID, dstNetID;
        SUBNET_NETID(srcNetID, ipver, flowP->subnetNrSrc);
        SUBNET_NETID(dstNetID, ipver, flowP->subnetNrDst);
        if ((srcNetID & 0x00ffffff) == TG_ORGCODE ||
            (dstNetID & 0x00ffffff) == TG_ORGCODE)
        {
            tgFlowP->stat |= TG_ADTCT;
        }
#endif // SUBNET_INIT != 0
    } else if (flowP->l4Proto == L3_UDP && (flowP->srcPort > 525 && flowP->dstPort > 525)) {
        tgFlowP->stat |= TG_INIT;
    }
}


#if ETH_ACTIVATE > 0
void t2OnLayer2(packet_t *packet UNUSED, unsigned long flowIndex) {
    if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;
    if (sPktFile) fputs(/* tgStat */ SEP_CHR, sPktFile);
}
#endif // ETH_ACTIVATE > 0


void t2OnLayer4(packet_t *packet, unsigned long flowIndex) {
    tgFlow_t * const tgFlowP = &tgFlows[flowIndex];
    const flow_t * const flowP = &flows[flowIndex];

    if (sPktFile) fprintf(sPktFile, "%" B2T_PRIX16 /* tgStat */ SEP_CHR, tgFlowP->stat);

    if (!tgFlowP->stat) return; // not a telegram packet

    int32_t i = 0;
    const uint16_t l7Len = packet->l7Len;
#if TG_SAVE == 1 || TG_DEOBFUSCATE != 0
    uint16_t payload_len = packet->snapL7Len;
    const uint8_t *payload = packet->l7HdrP;
    uint32_t tcpSeq = 0;
#endif // TG_SAVE == 1 || TG_DEOBFUSCATE != 0

    // only 1. frag packet will be processed
    if (!t2_is_first_fragment(packet)) return;

#if TG_DEOBFUSCATE != 0
    const unsigned long opposite_flow_index = flowP->oppositeFlowIndex;
    // deobfuscation state machine
    switch (tgFlowP->obf_state) {
        case OBFUSC_UNDEF: {
            const tcpHeader_t * const tcpHeaderP = TCP_HEADER(packet);
            if (flowP->l4Proto == L3_TCP && (tcpHeaderP->flags & TH_SYN)) {
                tgFlowP->obf_state = OBFUSC_SYN;
                tgFlowP->seqInit = ntohl(tcpHeaderP->seq) + 1;
                tgFlowP->client_flow = ((tcpHeaderP->flags & TH_ACK) == 0);
            } else {
                tgFlowP->obf_state = OBFUSC_NOPE;
            }
            break;
        }
        case OBFUSC_SYN: {
            if (l7Len >= OBFUSC_HDR_LEN && tgFlowP->client_flow) {
                if (payload_len >= OBFUSC_HDR_LEN) {
                    if (!key_setup(flowIndex, payload + 8, payload + 8 + KEY_LENGTH)) {
                        // failed to setup AES key and IV
                        tgFlowP->obf_state = OBFUSC_NOPE;
                        if (opposite_flow_index != HASHTABLE_ENTRY_NOT_FOUND) {
                            tgFlows[opposite_flow_index].obf_state = OBFUSC_NOPE;
                        }
                        break;
                    }
                    tgFlowP->next_msg_seq = tgFlowP->seqInit + OBFUSC_HDR_LEN;
                    tgFlowP->obf_state = OBFUSC_KEY;
                    debug_print("Flow %" PRIu64 ": deobfuscation enabled", flowP->findex);
                    // fall through to OBFUSC_KEY case
                } else {
                    // packet is snapped in the middle of key + iv, deobfuscation impossible
                    tgFlowP->obf_state = OBFUSC_NOPE;
                    break;
                }
            } else if (l7Len != 0 && !tgFlowP->client_flow) {
                if (opposite_flow_index == HASHTABLE_ENTRY_NOT_FOUND) {
                    // cannot deobfuscate without client flow
                    tgFlowP->obf_state = OBFUSC_NOPE;
                    break;
                }
                const tgFlow_t * const opposite_tg_flow = &tgFlows[opposite_flow_index];
                if (opposite_tg_flow->obf_state == OBFUSC_KEY) {
                    tgFlowP->next_msg_seq = tgFlowP->seqInit;
                    tgFlowP->obf_state = OBFUSC_KEY;
                    // fall through to OBFUSC_KEY case
                } else if (opposite_tg_flow->obf_state == OBFUSC_SYN) {
                    break; // client flow is still waiting for decryption key and IV
                } else {
                    // something went wrong in client flow, cannot deobfuscate
                    tgFlowP->obf_state = OBFUSC_NOPE;
                    break;
                }
            } else if (l7Len != 0) {
                // TODO: handle case where key and IV are split in multiple packets
                tgFlowP->obf_state = OBFUSC_NOPE;
                break;
            }
        }
        /* FALLTHRU */
        case OBFUSC_KEY: {
            if (payload_len > 0) {
                if (payload_len > MAX_PKT_SIZE) {
                    T2_PWRN(plugin_name, "Flow %" PRIu64 ": decryption buffer too small: %u", \
                            flowP->findex, payload_len);
                    break;
                }
                tcpSeq = ntohl(TCP_HEADER(packet)->seq);
                uint32_t pos = tcpSeq - tgFlowP->seqInit; // position in CTR stream
                decrypt(payload, deobfuscated, payload_len, pos, &tgFlowP->crypt);
            #if TG_4_9_OR_NEWER == 1
                // Telegram 4.9.0 and newer place a special value in bytes[56:60]
                // of the 1st packet before encrypting it to indicate which kind
                // of encryption / obfuscation is used.
                // https://github.com/DrKLO/Telegram/blob/d073b80063c568f31d81cc88c927b47c01a1dbf4/TMessagesProj/jni/tgnet/Connection.cpp#L494
                if (pos == 0 && tgFlowP->client_flow) {
                    uint32_t obf_type = *(uint32_t *)&deobfuscated[56];
                    // only EF encryption does not use any shared secret and can be deobfuscated
                    // https://github.com/DrKLO/Telegram/blob/d073b80063c568f31d81cc88c927b47c01a1dbf4/TMessagesProj/jni/tgnet/Connection.cpp#L429
                    if (obf_type != 0xefefefef) {
                        debug_print("Flow %" PRIu64 "_%c: obfuscation_type = %04x",
                                flowP->findex, FLOW_DIR_C(flowP), obf_type);
                        tgFlowP->obf_state = OBFUSC_NOPE;
                        if (opposite_flow_index != HASHTABLE_ENTRY_NOT_FOUND) {
                            tgFlows[opposite_flow_index].obf_state = OBFUSC_NOPE;
                        }
                        break;
                    }
                }
            #endif // TG_4_9_OR_NEWER == 1
            #if TG_SAVE == 1
                payload = deobfuscated; // save deobfuscated payload
            #endif // TG_SAVE == 1

                // check if next message starts in current packet
                pos = tgFlowP->next_msg_seq - tcpSeq; // position in packet
                // TODO: handle case where message header is split in multiple packets
                #define MSG_HDR_SIZE (1 + 8 + 16) // length + auth_key_id + msg_key
                while (pos < payload_len && pos + MSG_HDR_SIZE <= payload_len) {
                    // extract message size
                    if (!tgFlowP->client_flow) { // server to client
                        // skip reportAck
                        while (pos < payload_len && deobfuscated[pos] & 0x80) {
                            pos += 4;
                        }
                        if (pos >= payload_len) {
                            break;
                        }
                    } else { // client to server
                        deobfuscated[pos] &= 0x7f;
                    }
                    uint32_t size;
                    if (deobfuscated[pos] != 0x7f) {
                        size = ((uint32_t)deobfuscated[pos++]) * 4;
                    } else {
                        size = (((uint32_t)deobfuscated[pos+1]) | \
                                ((uint32_t)deobfuscated[pos+2] << 8) | \
                                ((uint32_t)deobfuscated[pos+3] << 16)) * 4;
                        pos += 4;
                    }
                    // check again if enough bytes left for auth_key_id + msg_key
                    if (pos + MSG_HDR_SIZE - 1 >= payload_len) {
                        break;
                    }
                    tgFlowP->next_msg_seq = tcpSeq + pos + size;
                    debug_print("Flow %" PRIu64 "_%c: message length = %u",
                            flowP->findex, FLOW_DIR_C(flowP), size);

                    // extract auth_key_id
                    uint64_t auth_key_id;
                    memcpy(&auth_key_id, &deobfuscated[pos], sizeof(auth_key_id));
                    auth_key_id = be64toh(auth_key_id);

                    // check that auth_key_id does not change during flow
                    if (tcpSeq != tgFlowP->seqInit && auth_key_id != tgFlowP->auth_key_id) {
                        debug_print("Flow %" PRIu64 "_%c: auth_key_id change: %" B2T_PRIX64
                                " -> %" B2T_PRIX64, flowP->findex, FLOW_DIR_C(flowP),
                                tgFlowP->auth_key_id, auth_key_id);
                        // this is not a valid telegram flow
                        unset_telegram(flowIndex);
                        return;
                    }
                    tgFlowP->auth_key_id = auth_key_id;
                    debug_print("Flow %" PRIu64 "_%c: auth_key_id = %" B2T_PRIX64,
                            flowP->findex, FLOW_DIR_C(flowP), auth_key_id);
                    pos += size;
                }
            }
            break;
        }
        case OBFUSC_NOPE:
            break; // deobfuscation impossible
    }
#endif // TG_DEOBFUSCATE != 0

    numTGPkts++;
    tgFlowP->numTpkts++;

    if (l7Len) {
        tgFlowP->numTbytes += l7Len;
        if (tgFlowP->l7LenMin > l7Len) tgFlowP->l7LenMin = l7Len;

        if (flowP->l4Proto == L3_UDP) {
            if (PACKET_IS_IPV6(packet)) {
                const ip6Header_t * const ip6HeaderP = IPV6_HEADER(packet);
                if ((ip6HeaderP->vtc_flw_lbl & TG_TC6M) == TG_INT6CTRL) tgFlowP->stat |= TG_TOSD; // Internetwork Control on?
            } else { // IPv4
                const ipHeader_t * const ip4HeaderP = IPV4_HEADER(packet);
                if (ip4HeaderP->ip_tos == TG_INTCTRL) tgFlowP->stat |= TG_TOSD; // Internetwork Control on?
            }
            if (l7Len % 8) {
                tgFlowP->modCnt--;
                unset_telegram(flowIndex);
                return;
            } else {
                tgFlowP->modCnt++;
                tgFlowP->stat |= TG_DETECT; // advance one step in state machine
            }
        } else {
            i = l7Len % 16;
            if (l7Len > TG_MTULIMIT) tgFlowP->stat |= TG_PLIGN1;
            else {
                if (tgFlowP->stat & TG_VOICE) tgFlowP->stat &= ~(TG_PLIGN1 | TG_PLIGN2);
                if (tgFlowP->stat & TG_PLIGN1) tgFlowP->stat |= TG_PLIGN2;
            }

            if (i == 9 ) {
            //if (i == 9 || i == 12) {
                tgFlowP->modCnt++;
                tgFlowP->stat |= TG_DETECT; // advance one step in state machine
            } else if (!(tgFlowP->stat & TG_PLIGN1) && l7Len != 4) {
                tgFlowP->modCnt--;
                if (tgFlowP->numTpkts > 3 && tgFlowP->modCnt < MODLIMIT) {
                    if (!(tgStat & TG_ADTCT) && (tgFlowP->stat & TG_PLNFLG)) {
                    //if (tgFlowP->stat & TG_PLNFLG) {
                        unset_telegram(flowIndex);
                        //return;
                    } else tgFlowP->stat |= TG_PLNFLG;
                }
            }
#if TG_SAVE == 1
            const tcpHeader_t * const tcpHeaderP = TCP_HEADER(packet);
            tcpSeq = ntohl(tcpHeaderP->seq);
#endif // TG_SAVE == 1
        }

//          IAT = tgFlowP->lastSeen.tv_sec - tgFlowP->IATInit.tv_sec + ((float)tgFlowP->lastSeen.tv_usec - (float)tgFlowP->lastSeen.tv_usec) / 1000000.0f;
//          IAT - tgFlowP->IATInit
//          if (IAT - tgFlowP->IATInit > tgFlowP->IATInit) tgFlowP->IATMax = IAT;

#if TG_SAVE == 1
        if (!tgFlowP->fd) {
            tgFlowP->tgName = t2_strdup_printf("%s_%" PRIu64 "_%c.dat", baseFileName, flowP->findex, FLOW_DIR_C(flowP));

            tgFlowP->fd = file_manager_open(t2_file_manager, tgFlowP->tgName, "w+b");
            if (!tgFlowP->fd) {
                T2_PERR(plugin_name, "Failed to open file '%s': %s", tgFlowP->tgName, strerror(errno));
                tgFlowP->stat |= TG_PWFERR;
                return;
            }
            tgFlowP->seqInit = tcpSeq;
            tgFlowP->stat |= TG_FLS;
        }
        i = tcpSeq - tgFlowP->seqInit;
        FILE * const fp = file_manager_fp(t2_file_manager, tgFlowP->fd);
        if (flowP->l4Proto == L3_TCP) fseek(fp, i, SEEK_SET);
        fwrite(payload, 1, payload_len, fp);
#endif // TG_SAVE == 1
    }
}


void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {

    // NOTE: cannot use unset_telegram instead of stat = 0x0 because most flows will end up
    //       misclassified (stat set to 0x0 is then reset to other value).

    tgFlow_t * const tgFlowP = &tgFlows[flowIndex];
    const flow_t * const flowP = &flows[flowIndex];
    float basym = 0.0f;

    const tgFlow_t * const tgFlowPO = (FLOW_HAS_OPPOSITE(flowP) ? &tgFlows[flowP->oppositeFlowIndex] : NULL);

    if (!(tgFlowP->numTbytes || (tgFlowPO && tgFlowPO->numTbytes))) if (!(tgFlowP->stat & (TG_DETECT | TG_ADTCT))) tgFlowP->stat = 0x00;

    if ((tgFlowP->stat & TG_INIT) && tgFlowP->numTpkts > 2 && tgFlowP->l7LenMin >= 32) { // check state machine
        if (tgFlowPO) basym = fabsf((float)(tgFlowP->numTbytes - tgFlowPO->numTbytes) / (float)(tgFlowP->numTbytes + tgFlowPO->numTbytes));

        if (flowP->l4Proto == L3_UDP) {
            if (basym < 0.2 && !(tgFlowP->l7LenMin % 8) && !(tgFlowP->numTbytes % 8)) {
                if (tgFlowP->stat & TG_DETECT) {
                    if (tgFlowP->l7LenMin == 88) tgFlowP->stat |= TG_VOICE;
                    else if (tgFlowP->l7LenMin < 88) tgFlowP->stat |= TG_CNTRL;
                    else if (!(tgFlowP->stat & TG_ADTCT)) tgFlowP->stat = 0x00;
                } else if (tgFlowPO && (tgFlowPO->stat & TG_DETECT)) tgFlowP->stat |= (TG_DETECT | TG_CNTRL);
                else if (!(tgFlowP->stat & (TG_DETECT | TG_ADTCT))) tgFlowP->stat = 0x00;
            } else if (!(tgFlowP->stat & (TG_DETECT | TG_ADTCT))) tgFlowP->stat = 0x00;
        } else if (flowP->l4Proto == L3_TCP) {
            if (tgFlowP->l7LenMin > 350 && !(tgFlowP->stat & (TG_DETECT | TG_ADTCT))) tgFlowP->stat = 0x00;
        }
    } else if (!(tgFlowP->stat & (TG_DETECT | TG_ADTCT))) tgFlowP->stat = 0x00;

#if TG_SAVE == 1
    if (tgFlowP->fd) {
        file_manager_close(t2_file_manager, tgFlowP->fd);
        tgFlowP->fd = NULL;
    }

    if (tgFlowP->tgName) {
        free(tgFlowP->tgName);
        tgFlowP->tgName = NULL;
    }
#endif // TG_SAVE == 1

    if (tgFlowP->stat) {
        tgStat |= tgFlowP->stat;
    } else {
        if (numTGPkts >= tgFlowP->numTpkts) numTGPkts -= tgFlowP->numTpkts;
#if TG_SAVE == 1
        if (UNLIKELY(!remove(tgFlowP->tgName))) {
            T2_PERR(plugin_name, "Failed to remove file '%s': %s", tgFlowP->tgName, strerror(errno));
        }
        file_manager_close(t2_file_manager, tgFlowP->fd);
        tgFlowP->fd = NULL;
#endif // TG_SAVE == 1
    }

    OUTBUF_APPEND_U16(buf, tgFlowP->stat);

#if TG_DEOBFUSCATE != 0
    OUTBUF_APPEND_U64(buf, tgFlowP->auth_key_id);
#endif //TG_DEOBFUSCATE != 0
}


void t2PluginReport(FILE *stream) {
    if (numTGPkts) {
        T2_FPLOG_AGGR_HEX(stream, plugin_name, tgStat);
        T2_FPLOG_NUMP0(stream, plugin_name, "Number of Telegram packets", numTGPkts, numPackets);
    }
}


void t2Finalize() {
    free(tgFlows);
}
