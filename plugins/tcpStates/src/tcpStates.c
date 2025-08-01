/*
 * tcpStates.c
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

#include "tcpStates.h"


// Global variables

tcp_connection_t *tcpConn;


// Static variables

static uint8_t tcpStatesAFlags;


// Tranalyzer Plugin functions

T2_PLUGIN_INIT("tcpStates", "0.9.3", 0, 9);


void t2Init() {

    T2_PLUGIN_STRUCT_NEW(tcpConn);

    // register timeouts
    timeout_handler_add(TIMEOUT_RESET);
    timeout_handler_add(TIMEOUT_NEW);
    timeout_handler_add(TIMEOUT_ESTABLISHED);
    timeout_handler_add(TIMEOUT_CLOSING);
    timeout_handler_add(TIMEOUT_CLOSED);

    // Packet mode
    if (sPktFile) fputs("tcpStatesAFlags" SEP_CHR, sPktFile);
}


binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;
    BV_APPEND_H8(bv, "tcpStatesAFlags", "TCP state machine anomalies");
    return bv;
}


void t2OnNewFlow(packet_t *packet UNUSED, unsigned long flowIndex) {
    memset(&tcpConn[flowIndex], '\0', sizeof(tcp_connection_t));
}


#if ETH_ACTIVATE > 0
void t2OnLayer2(packet_t *packet UNUSED, unsigned long flowIndex) {
    if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;

    // This packet does not have a layer 4.
    // Print tabs to keep the packet file aligned
    if (sPktFile) fputs("0x00" /* tcpStatesAFlags */ SEP_CHR, sPktFile);
}
#endif // ETH_ACTIVATE > 0


/*
 * The general state machine approach, not optimized
 * WHY our state machine differs from the "normal" TCP state machine?
 * Because we're sitting somewhere in the middle.
 * This leads to several special cases like
 * - recognizing already opened connections
 * - getting not every packet
 * - seeing only on side of a connection
 * and the most important one:
 * - We don't know the behavior of the internal tcp state machines inside the hosts
 */
void t2OnLayer4(packet_t *packet, unsigned long flowIndex) {

    if (packet->l4Proto != L3_TCP) {
        if (sPktFile) fputs("0x00" /* tcpStatesAFlags */ SEP_CHR, sPktFile);
        return;
    }

    // Only 1. frag packet will be processed
    if (!t2_is_first_fragment(packet) || packet->snapL4Len < 13) {
        if (sPktFile) fputs("0x00" /* tcpStatesAFlags */ SEP_CHR, sPktFile);
        return;
    }

    flow_t *flowP = &flows[flowIndex];
    tcp_connection_t *connP = &tcpConn[flowIndex];

    // Reverse flow
    flow_t *revFlowP;
    tcp_connection_t *revConnP;
    if (FLOW_HAS_OPPOSITE(flowP)) {
        revFlowP = &flows[flowP->oppositeFlowIndex];
        revConnP = &tcpConn[flowP->oppositeFlowIndex];
    } else {
        revFlowP = NULL;
        revConnP = NULL;
    }

    const tcpHeader_t * const tcpHdrP = TCP_HEADER(packet);
    const uint8_t tcpFlags = *((uint8_t*)tcpHdrP + 13);

    // Null / Christmas scan
    if (((tcpFlags & TH_ALL_FLAGS) == TH_XMAS) || ((tcpFlags & TH_ALL_FLAGS) == TH_NULL)) connP->anomalies |= EVIL;

    switch (connP->state) {

        case STATE_NEW:

            // SYN
            if ((tcpFlags & TH_SYN_FIN_RST) == TH_SYN) {
                connP->syn_seen = 1;
                connP->syn_seq_num = ntohl(tcpHdrP->seq);
                flowP->timeout = TIMEOUT_NEW;

                // SYN-ACK
                if ((tcpFlags & TH_ACK) == TH_ACK) {
                    // packet ACKs a SYN from the opposite flow
                    if (revFlowP) {
                        // check ACK number
                        if (ntohl(tcpHdrP->ack_seq) == revConnP->syn_seq_num+1) {
                            revConnP->syn_ackd = 1;
                        } else {
                            // ACK number is wrong -> bogus connection establishment
                            // go into STATE ESTABLISHED and set bogus bit zero
                            connP->state = STATE_ESTABLISHED;
                            flowP->timeout = TIMEOUT_ESTABLISHED;
                            connP->anomalies |= MAL_CON_EST;

                            revConnP->state = STATE_ESTABLISHED;
                            revFlowP->timeout = TIMEOUT_ESTABLISHED;
                            revConnP->anomalies |= MAL_CON_EST;
                        }
                    } else {
                        // There is no opposite flow, maybe we don't see it
                        // -> set bogus flag zero and set the connection to established
                        connP->state = STATE_ESTABLISHED;
                        flowP->timeout = TIMEOUT_ESTABLISHED;
                        connP->anomalies |= MAL_CON_EST;
                    }
                }
                break;
            }

            // ACK - Last part of 3 way or simultaneous handshake
            if (revFlowP && (tcpFlags & TH_ARSF) == TH_ACK) {
                if (ntohl(tcpHdrP->ack_seq) == revConnP->syn_seq_num+1) {
                    // correct ACK
                    revConnP->syn_ackd = 1;
                    // check if own SYN packet was ACKed
                    if (connP->syn_ackd == 1) {
                        // connection successfully established -> change to state ESTABLISHED
                        connP->state = STATE_ESTABLISHED;
                        flowP->timeout = TIMEOUT_ESTABLISHED;
                        revConnP->state = STATE_ESTABLISHED;
                        revFlowP->timeout = TIMEOUT_ESTABLISHED;
                    }
                } else {
                    // there's something wrong with the ACK number:
                    // set anomaly flag and set flow to state ESTABLISHED
                    connP->state = STATE_ESTABLISHED;
                    flowP->timeout = TIMEOUT_ESTABLISHED;
                    connP->anomalies |= MAL_CON_EST;

                    revConnP->state = STATE_ESTABLISHED;
                    revFlowP->timeout = TIMEOUT_ESTABLISHED;
                    revConnP->anomalies |= MAL_CON_EST;
                }
                break;
            }

            /*
             * RST, ACK flags set, opposite flow
             * Normal connection rejection
             */
            if (revFlowP && ((tcpFlags & TH_ARSF) == TH_RST_ACK)) {
                // reset flow
                connP->state = STATE_RESET;
                flowP->timeout = TIMEOUT_RESET;
                connP->anomalies |= RST_TRANS; // Reset from sender seen
                // reset opposite flow
                revConnP->state = STATE_RESET;
                revFlowP->timeout = TIMEOUT_RESET;
                break;
            }

            // Every other combination with RST flag
            if ((tcpFlags & TH_RST) == TH_RST) {
                // Reset from sender seen, malformed connection establishment
                connP->anomalies |= (RST_TRANS | MAL_CON_EST);
                connP->state = STATE_RESET;
                flowP->timeout = TIMEOUT_RESET;

                if (revFlowP) {
                    // malformed connection establishment
                    // Some strange reset
                    revConnP->anomalies |= MAL_CON_EST;
                    revConnP->state = STATE_RESET;
                    revFlowP->timeout = TIMEOUT_RESET;
                } else {
                    // Possible RST scan
                    connP->anomalies |= EVIL;
                }
                break;
            }

            /*
             * A flow starts with a teardown. Possible reasons:
             * - We didn't see the previous packets of this connection.
             * - A FIN scan
             */
            if ((tcpFlags & TH_ARSF) == TH_FIN_ACK) {
                connP->fin_seen = 1;
                connP->fin_seq_num = ntohl(tcpHdrP->seq);
                // The connection establishment is definitely malicious or was not seen
                connP->anomalies |= MAL_CON_EST;
                connP->state = STATE_CLOSING;
                flowP->timeout = TIMEOUT_CLOSING;

                if (revFlowP) {
                    revConnP->anomalies |= MAL_CON_EST; // malformed connection establishment

                    if (revConnP->fin_seen && (revConnP->fin_seq_num+1 == ntohl(tcpHdrP->ack_seq))) {
                        revConnP->fin_ackd = 1;
                    }
                } else {
                    // No opposite flow and this FIN packet is the first packet we see?
                    // That might be a FIN scan
                    connP->fin_scan = 1;
                }
                break;
            }

            if ((tcpFlags & TH_ARSF) == TH_FIN) {
                // This IS a FIN scan!
                connP->anomalies |= EVIL;
                break;
            }

            // Every other combination is bogus.
            // We set the state to ESTABLISHED, because there could be something interesting in the flows :)
            // TODO: Distinction between more states

            // Malformed connection establishment
            connP->state = STATE_ESTABLISHED;
            flowP->timeout = TIMEOUT_ESTABLISHED;
            connP->anomalies |= MAL_CON_EST;

            if (revFlowP) {
                // Malformed connection establishment
                revConnP->state = STATE_ESTABLISHED;
                revFlowP->timeout = TIMEOUT_ESTABLISHED;
                revConnP->anomalies |= MAL_CON_EST;
            }
            break;

        case STATE_ESTABLISHED:
            // In this state should be no SYN flag seen or no ACK missing (even RST packets should ack)
            if ((tcpFlags & TH_SYN_ACK) != TH_ACK) {
                connP->anomalies |= MAL_FLGS_EST; // Malformed flags during established connection

                // Malformed flags during established connection
                if (revConnP) revConnP->anomalies |= MAL_FLGS_EST;
            }

            // sender initiates a teardown
            if ((tcpFlags & TH_FIN) == TH_FIN) {
                connP->fin_seen = 1;
                connP->fin_seq_num = ntohl(tcpHdrP->seq);
                connP->state = STATE_CLOSING;
                flowP->timeout = TIMEOUT_CLOSING;

                //if (tcpHdrP->ack && revConnP && revConnP->fin_seen &&
                if ((tcpHdrP->flags & TH_ACK) && revConnP && revConnP->fin_seen &&
                    ntohl(tcpHdrP->ack_seq) == revConnP->fin_seq_num+1)
                {
                    revConnP->fin_ackd = 1;
                }
            }

            // Connection has been reset
            if ((tcpFlags & TH_RST) == TH_RST) {
                // Reset from sender seen, malformed connection teardown
                connP->state = STATE_RESET;
                flowP->timeout = TIMEOUT_RESET;
                connP->anomalies |= (RST_TRANS | MAL_TEARDWN);

                if (revFlowP) {
                    // Malformed connection teardown
                    revConnP->state = STATE_RESET;
                    revFlowP->timeout = TIMEOUT_RESET;
                    revConnP->anomalies |= MAL_TEARDWN;
                }
            }
            break;

        case STATE_CLOSING:

            // Connection has been reset
            if ((tcpFlags & TH_RST) == TH_RST) {
                // Reset from sender seen, malformed connection teardown
                connP->state = STATE_RESET;
                flowP->timeout = TIMEOUT_RESET;
                connP->anomalies |= (RST_TRANS | MAL_TEARDWN);

                if (revFlowP) {
                    // Malformed connection teardown
                    revConnP->state = STATE_RESET;
                    revFlowP->timeout = TIMEOUT_RESET;
                    revConnP->anomalies |= MAL_TEARDWN;
                }
            }

            if ((tcpFlags & TH_ACK) == TH_ACK && revConnP && revConnP->fin_seen &&
                 ntohl(tcpHdrP->ack_seq) == revConnP->fin_seq_num+1)
            {
                revConnP->fin_ackd = 1;
            }

            // Test if teardown is complete
            if (connP->fin_seen && connP->fin_ackd && revConnP &&
                revConnP->fin_seen && revConnP->fin_ackd && revFlowP)
            {
                connP->state = STATE_CLOSED;
                flowP->timeout = TIMEOUT_CLOSED;
                revConnP->state = STATE_CLOSED;
                revFlowP->timeout = TIMEOUT_CLOSED;
            }
            break;

        case STATE_CLOSED:
            // more packets from sender after connection closing seen
            // A "normal" connection should not enter this state
            connP->anomalies |= PKTS_TERM;

            // Connection has been reset
            if ((tcpFlags & TH_RST) == TH_RST) {
                // Reset from sender seen, malformed connection teardown
                connP->state = STATE_RESET;
                flowP->timeout = TIMEOUT_RESET;
                connP->anomalies |= (RST_TRANS | MAL_TEARDWN);

                if (revFlowP && revConnP) {
                    // Malformed connection teardown
                    revConnP->state = STATE_RESET;
                    revFlowP->timeout = TIMEOUT_RESET;
                    revConnP->anomalies |= MAL_TEARDWN;
                }
            }
            break;

        case STATE_RESET:
            // More packets after reset seen
            connP->anomalies |= PKTS_RST;
            break;

        default:
            T2_PWRN(plugin_name, "Unhandled state '%hhu'", connP->state);
            break;
    }

    if (sPktFile) fprintf(sPktFile, "0x%02" B2T_PRIX8 /* tcpStatesAFlags */ SEP_CHR, connP->anomalies);
}


void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {
    const flow_t * const flowP = &flows[flowIndex];
    tcp_connection_t * const connP = &tcpConn[flowIndex];

    if (flowP->l4Proto != L3_TCP) {
        OUTBUF_APPEND_U8(buf, connP->anomalies);
        return;
    }

    if (!FLOW_HAS_OPPOSITE(flowP)) {
        // Malformed connection establishment and teardown
        connP->anomalies |= (MAL_CON_EST | MAL_TEARDWN);
    } else {
        tcp_connection_t *revConnP = &tcpConn[flowP->oppositeFlowIndex];

        // Malformed connection establishment
        if (!(connP->syn_seen && revConnP->syn_seen &&
              connP->syn_ackd && revConnP->syn_ackd))
        {
            connP->anomalies |= MAL_CON_EST;
        }

        // Malformed connection teardown
        if (!(connP->fin_seen && revConnP->fin_seen &&
              connP->fin_ackd && revConnP->fin_ackd))
        {
            connP->anomalies |= MAL_TEARDWN;
        } else {
            // A correct teardown implies that no fin scan was performed (see state NEW)
            connP->fin_scan = 0;
            revConnP->fin_scan = 0;
        }
    }

    // If the fin scan bit is still set, set the possible evil behavior bit
    if (connP->fin_scan) connP->anomalies |= EVIL;

    tcpStatesAFlags |= connP->anomalies;

    // tcpStatesAFlags
    OUTBUF_APPEND_U8(buf, connP->anomalies);
}


void t2PluginReport(FILE *stream) {
    T2_FPLOG_AGGR_HEX(stream, plugin_name, tcpStatesAFlags);
}


void t2Finalize() {
    free(tcpConn);
}
