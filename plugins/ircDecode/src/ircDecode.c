/*
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

#include "ircDecode.h"

#include <errno.h>  // for errno, EEXIST


// Global variables

ircFlow_t *ircFlows;


// Static variables

static uint8_t ircStat;
static uint64_t ircPktCnt;

#if IRC_SAVE == 1
#if ENVCNTRL > 0
static const char *ircFPath;
#else // ENVCNTRL == 0
static const char * const ircFPath = IRC_F_PATH;
#endif // ENVCNTRL
#endif // IRC_SAVE == 1

// Keep ircCom synchronized with enum
static const char ircCom[61][9] = {
    "ADMIN",    // 0
    "AWAY",
    "CAP",
    "CNOTICE",
    "CONNECT",
    "CPRIVMSG", // 5
    "DIE",
    "ENCAP",
    "ERROR",
    "HELP",
    "INFO",     // 10
    "INVITE",
    "ISON",
    "JOIN",
    "KICK",
    "KILL",     // 15
    "KNOCK",
    "LINKS",
    "LIST",
    "LUSERS",
    "MODE",     // 20
    "MOTD",
    "NAMES",
    "NAMESX",
    "NICK",
    "NJOIN",    // 25
    "NOTICE",
    "OPER",
    "PART",
    "PASS",
    "PING",     // 30
    "PONG",
    "PRIVMSG",
    "QUIT",
    "REHASH",
    "RESTART",  // 35
    "RULES",
    "SERVER",
    "SERVICE",
    "SERVLIST",
    "SETNAME",  // 40
    "SILENCE",
    "SQUERY",
    "SQUIT",
    "STATS",
    "SUMMON",   // 45
    "TIME",
    "TOPIC",
    "TRACE",
    "UHNAMES",
    "USER",     // 50
    "USERHOST",
    "USERIP",
    "USERS",
    "VERSION",
    "WALLOPS",  // 55
    "WATCH",
    "WHO",
    "WHOIS",
    "WHOWAS",
};


// Tranalyzer functions

T2_PLUGIN_INIT("ircDecode", "0.9.3", 0, 9);


void t2Init() {
    T2_PLUGIN_STRUCT_NEW(ircFlows);

#if IRC_SAVE == 1
#if ENVCNTRL > 0
    static t2_env_t env[ENV_IRC_N];
    t2_get_env(PLUGIN_SRCH, ENV_IRC_N, env);
    const uint8_t rmdir = T2_ENV_VAL_UINT(IRC_RMDIR);
    ircFPath = T2_STEAL_ENV_VAL(IRC_F_PATH);
    t2_free_env(ENV_IRC_N, env);
#else // ENVCNTRL == 0
    const uint8_t rmdir = IRC_RMDIR;
#endif // ENVCNTRL

    T2_MKPATH(ircFPath, rmdir);
#endif // IRC_SAVE == 1
}


binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;
    BV_APPEND_H8(bv    , "ircStat"   , "IRC status");
#if IRC_BITFIELD == 1
    BV_APPEND_H64(bv   , "ircCBF"    , "IRC commands");
    //BV_APPEND_H32(bv   , "ircRBF"    , "IRC Response Bit Field");
#endif // IRC_BITFIELD == 1
    BV_APPEND_STRC_R(bv, "ircCC"     , "IRC command codes");
    BV_APPEND_U16_R(bv , "ircRC"     , "IRC response codes");
    BV_APPEND_U8(bv    , "ircNumUser", "IRC number of users");
    BV_APPEND_STR_R(bv , "ircUser"   , "IRC users");
    BV_APPEND_U8(bv    , "ircNumPass", "IRC number of passwords");
    BV_APPEND_STR_R(bv , "ircPass"   , "IRC passwords");
    BV_APPEND_U8(bv    , "ircNumNick", "IRC number of nicknames");
    BV_APPEND_STR_R(bv , "ircNick"   , "IRC nicknames");
    BV_APPEND_U8(bv    , "ircNumC"   , "IRC number of parameters");
    BV_APPEND_STR_R(bv , "ircC"      , "IRC content");
    return bv;
}


void t2OnNewFlow(packet_t* packet UNUSED, unsigned long flowIndex) {
    ircFlow_t * const ircFlowP = &ircFlows[flowIndex];
    memset(ircFlowP, '\0', sizeof(*ircFlowP));

    const flow_t * const flowP = &flows[flowIndex];
    if (flowP->l4Proto != L3_TCP) return;

    const uint_fast16_t srcPort = flowP->srcPort;
    const uint_fast16_t dstPort = flowP->dstPort;
    if (srcPort == IRC_PORT || dstPort == IRC_PORT ||
        (IRC_PORT_MIN <= dstPort && dstPort <= IRC_PORT_MAX) ||
        (IRC_PORT_MIN <= srcPort && srcPort <= IRC_PORT_MAX))
    {
        ircFlowP->stat = IRC_INIT;
    }
}


void t2OnLayer4(packet_t* packet, unsigned long flowIndex) {
    ircFlow_t *ircFlowP = &ircFlows[flowIndex];
    if (!ircFlowP->stat) return;

    ircPktCnt++;

    int32_t l7Len = packet->snapL7Len;
    if (l7Len < 4) return;

    char *l7HdrP = (char*)packet->l7HdrP;
    const flow_t * const flowP = &flows[flowIndex];

#if IRC_SAVE == 1
    const tcpHeader_t * const tcpHdrP = TCP_HEADER(packet);
    const uint32_t tcpSeq = ntohl(tcpHdrP->seq);

    if (!ircFlowP->fd) {
        char filepath[MAX_FILENAME_LEN] = {};
        const size_t len = snprintf(filepath, sizeof(filepath), "%sirc_flow_%" PRIu64 "_%c.txt",
                ircFPath, flowP->findex, FLOW_DIR_C(flowP));
        if (len >= sizeof(filepath)) {
            // filename was truncated...
            ircFlowP->stat |= IRC_OVFL;
        }

        ircFlowP->fd = file_manager_open(t2_file_manager, filepath, "w+");
        if (!ircFlowP->fd) {
            T2_PERR(plugin_name, "Failed to open file '%s': %s", filepath, strerror(errno));
            ircFlowP->stat |= IRC_PPWFERR;
            return;
        }

        ircFlowP->seqInit = tcpSeq;
    }

    FILE * const fp = file_manager_fp(t2_file_manager, ircFlowP->fd);
    const long seqDiff = tcpSeq - ircFlowP->seqInit;
    fseek(fp, seqDiff, SEEK_SET);
    fwrite(l7HdrP, 1, l7Len , fp);
#endif // IRC_SAVE == 1

    const char *cr, *lf, *crlf;

    while ((crlf = memmem(l7HdrP, l7Len, "\r\n", 2)) != NULL ||
           (cr   = memchr(l7HdrP, '\r'  , l7Len))    != NULL ||
           (lf   = memchr(l7HdrP, '\n'  , l7Len))    != NULL)
    {
        const char * const eol = ((crlf) ? crlf : (cr ? cr : lf));

        // skip optional prefix
        if (l7HdrP[0] == ':') {
            char * const space = memchr(l7HdrP, ' ', l7Len);
            if (!space) {
                // Invalid format
                ircFlowP->stat |= IRC_MALFORMED;
                return;
            }

            l7Len -= (space + 1 - l7HdrP);
            l7HdrP = space + 1;
        }

        const char *space = memchr(l7HdrP, ' ', l7Len);
        const size_t lineLen = (eol - l7HdrP + (crlf ? 2 : 1));
        size_t cmdLen = ((space) ? (space - l7HdrP) : (eol - l7HdrP));

        const uint64_t l7Hdr64 = *(uint64_t*)l7HdrP;

        if (FLOW_IS_B(flowP)) {  // Response
            const uint32_t l7Hdr32 = l7Hdr64 & 0x00000000ffffffff;
            const unsigned long resCode = strtoul((char*)&l7Hdr32, NULL, 10);
            switch (resCode) {
                case 0:
                    // TODO process command as for request?
                    l7Len -= lineLen;
                    l7HdrP += lineLen;
                    continue;
                case 1: /* FALLTHRU */
                case 2: /* FALLTHRU */
                case 3: /* FALLTHRU */
                case 4:
                    ircFlowP->stat |= IRC_REG_SUCC;
                    break;
                case 464:
                    ircFlowP->stat |= IRC_LOG_ERR;
                    break;
                default:
                    break;
            }

            if (ircFlowP->rCCnt >= IRC_MAXCNM) {
                ircFlowP->stat |= IRC_OVFL;
            } else {
#if IRC_CMD_AGGR == 1
                uint_fast32_t i = 0;
                for (i = 0; i < ircFlowP->rCCnt; i++) {
                    if (ircFlowP->recCode[i] == resCode) break;
                }
                if (i == ircFlowP->rCCnt)
#endif // IRC_CMD_AGGR == 1
                    ircFlowP->recCode[ircFlowP->rCCnt++] = resCode;
            }
        } else { // Request
            irc_cmd_t sC = IRC_UNKNOWN;

            uint64_t mask;
            switch (cmdLen) {
                case  0:
                    l7Len -= lineLen;
                    l7HdrP += lineLen;
                    continue;
                case  1: mask = 0x00000000000000ff; break;
                case  2: mask = 0x000000000000ffff; break;
                case  3: mask = 0x0000000000ffffff; break;
                case  4: mask = 0x00000000ffffffff; break;
                case  5: mask = 0x000000ffffffffff; break;
                case  6: mask = 0x0000ffffffffffff; break;
                case  7: mask = 0x00ffffffffffffff; break;
                default: mask = 0xffffffffffffffff; break;
            }

            switch (l7Hdr64 & mask) {
                case I_ADMIN:    sC = IRC_ADMIN;    break; // ADMIN [<server>]
                case I_AWAY:     sC = IRC_AWAY;     break; // AWAY [message]
                case I_CAP:      sC = IRC_CAP;      break;
                case I_CNOTICE:  sC = IRC_CNOTICE;  break;
                case I_CONNECT:  sC = IRC_CONNECT;  break; // CONNECT <target server> [<port> [<remote server>]]
                case I_CPRIVMSG: sC = IRC_CPRIVMSG; break;
                case I_DIE:      sC = IRC_DIE;      break;
                case I_ENCAP:    sC = IRC_ENCAP;    break;
                case I_ERROR:    sC = IRC_ERROR;    break; // ERROR <error message>
                case I_HELP:     sC = IRC_HELP;     break;
                case I_INFO:     sC = IRC_INFO;     break; // INFO [<server>]
                case I_INVITE:   sC = IRC_INVITE;   break; // INVITE <nickname> <channel>
                case I_ISON:     sC = IRC_ISON;     break; // ISON <nickname>{<space><nickname>}
                case I_JOIN:     sC = IRC_JOIN;     break; // JOIN <channel>{,<channel>} [<key>{,<key>}]
                case I_KICK:     sC = IRC_KICK;     break; // KICK <channel> <user> [<comment>]
                case I_KILL:     sC = IRC_KILL;     break; // KILL <nickname> <comment>
                case I_KNOCK:    sC = IRC_KNOCK;    break;
                case I_LINKS:    sC = IRC_LINKS;    break; // LINKS [[<remote server>] <server mask>]
                case I_LIST:     sC = IRC_LIST;     break; // LIST [<channel>{,<channel>} [<server>]]
                case I_LUSERS:   sC = IRC_LUSERS;   break;
                case I_MODE:     sC = IRC_MODE;     break; // MODE <channel> {[+|-]|o|p|s|i|t|n|b|v} [<limit>] [<user>] [<ban mask>]
                                                           // MODE <nickname> {[+|-]|i|w|s|o}
                case I_MOTD:     sC = IRC_MOTD;     break;
                case I_NAMES:    sC = IRC_NAMES;    break; // NAMES [<channel>{,<channel>}]
                case I_NAMESX:   sC = IRC_NAMESX;   break;
                case I_NICK: { // NICK <nickname> [<hopcount]
                    sC = IRC_NICK;
                    if (ircFlowP->nameNCnt >= IRC_MAXNNM) {
                        ircFlowP->stat |= IRC_OVFL;
                        break;
                    }
                    if (l7Len <= 7) break;
                    const char * const nick = l7HdrP + 5;
                    const size_t len = (eol - nick);
                    const char * const space = memchr(nick, ' ', len);
                    const size_t slen = ((space) ? (size_t)(space - nick) : len);
                    memcpy(ircFlowP->nameN[ircFlowP->nameNCnt++], nick, MIN(slen, IRC_NXNMLN));
                    break;
                }
                case I_NJOIN:  sC = IRC_NJOIN;  break;
                case I_NOTICE: sC = IRC_NOTICE; break; // NOTICE <nickname> <text>
                case I_OPER:   sC = IRC_OPER;   break; // OPER <username> <password> TODO
                case I_PART:   sC = IRC_PART;   break; // PART <channel>{,<channel>}
                case I_PASS: { // PASS <password>
                    sC = IRC_PASS;
                    if (ircFlowP->namePCnt >= IRC_MAXPNM) {
                        ircFlowP->stat |= IRC_OVFL;
                        break;
                    }
                    if (l7Len <= 7) break;
                    const char * const pass = l7HdrP + 5;
                    const size_t len = (eol - pass);
                    memcpy(ircFlowP->nameP[ircFlowP->namePCnt++], pass, MIN(len, IRC_PXNMLN));
                    break;
                }
                case I_PING:     sC = IRC_PING;     break; // PING <server1> [<server2>]
                case I_PONG:     sC = IRC_PONG;     break; // PONG <daemon> [<daemon2>]
                case I_PRIVMSG:  sC = IRC_PRIVMSG;  break; // PRIVMSG <receiver>{,<receiver>} <text to be sent>
                case I_QUIT:     sC = IRC_QUIT;     break; // QUIT [<message>]
                case I_REHASH:   sC = IRC_REHASH;   break; // REHASH
                case I_RESTART:  sC = IRC_RESTART;  break; // RESTART
                case I_RULES:    sC = IRC_RULES;    break;
                case I_SERVER:   sC = IRC_SERVER;   break; // SERVER <servername> <hopcount> <info>
                case I_SERVICE:  sC = IRC_SERVICE;  break;
                case I_SERVLIST: sC = IRC_SERVLIST; break;
                case I_SETNAME:  sC = IRC_SETNAME;  break;
                case I_SILENCE:  sC = IRC_SILENCE;  break;
                case I_SQUERY:   sC = IRC_SQUERY;   break;
                case I_SQUIT:    sC = IRC_SQUIT;    break; // SQUIT <server> <comment>
                case I_STATS:    sC = IRC_STATS;    break; // STATS [<query> [<server>]]
                case I_SUMMON:   sC = IRC_SUMMON;   break; // SUMMON <user> [<server>]
                case I_TIME:     sC = IRC_TIME;     break; // TIME [<server>]
                case I_TOPIC:    sC = IRC_TOPIC;    break; // TOPIC <channel> [<topic>]
                case I_TRACE:    sC = IRC_TRACE;    break; // TRACE [<server>]
                case I_UHNAMES:  sC = IRC_UHNAMES;  break;
                case I_USER: {  // USER <username> <hostname> <servername> <realname>
                    sC = IRC_USER;
                    if (ircFlowP->nameUCnt >= IRC_MAXUNM) {
                        ircFlowP->stat |= IRC_OVFL;
                        break;
                    }
                    if (l7Len <= 7) break;
                    const char * const user = l7HdrP + 5;
                    const size_t len = (eol - user);
                    const char * const space = memchr(user, ' ', len);
                    const size_t slen = ((space) ? (size_t)(space - user) : len);
                    memcpy(ircFlowP->nameU[ircFlowP->nameUCnt++], user, MIN(slen, IRC_UXNMLN));
                    break;
                }
                case I_USERHOST: sC = IRC_USERHOST; break; // USERHOST <nickname>{<space><nickname>}
                case I_USERIP:   sC = IRC_USERIP;   break;
                case I_USERS:    sC = IRC_USERS;    break; // USERS [<server>]
                case I_VERSION:  sC = IRC_VERSION;  break; // VERSION [<server>]
                case I_WALLOPS:  sC = IRC_WALLOPS;  break; // WALLOPS <text to be sent to all operators currently online>
                case I_WHO:      sC = IRC_WHO;      break; // WHO [<name> [<o>]]
                case I_WHOIS:    sC = IRC_WHOIS;    break; // WHOIS [<server>] <nickmask>[,<nickmask>[,...]]
                case I_WHOWAS:   sC = IRC_WHOWAS;   break; // WHOWAS <nickname> [<count> [<server>]]
                default:
                    break;
            }

            if (sC == IRC_UNKNOWN) {
                ircFlowP->stat |= IRC_SENDCODE;
#if IRC_BITFIELD == 1
                ircFlowP->sendCode |= (1L << 63);
#endif // IRC_BITFIELD == 1
            } else {
#if IRC_BITFIELD == 1
                ircFlowP->sendCode |= (1 << sC);
#endif // IRC_BITFIELD == 1
                if (ircFlowP->tCCnt >= IRC_MAXCNM) {
                    ircFlowP->stat |= IRC_OVFL;
                } else {
#if IRC_CMD_AGGR == 1
                    uint_fast32_t i = 0;
                    for (i = 0; i < ircFlowP->tCCnt; i++) {
                        if (ircFlowP->tCode[i] == sC) return;
                    }
                    if (i == ircFlowP->tCCnt)
#endif // IRC_CMD_AGGR == 1
                        ircFlowP->tCode[ircFlowP->tCCnt++] = sC;
                }
            }
        } // end for request

        l7Len -= lineLen;
        l7HdrP += lineLen;
    } // end while
}


void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {
    ircFlow_t *ircFlowP = &ircFlows[flowIndex];

    ircStat |= ircFlowP->stat;

#if IRC_SAVE == 1
    if (ircFlowP->fd) {
        file_manager_close(t2_file_manager, ircFlowP->fd);
        ircFlowP->fd = NULL;
    }
#endif // IRC_SAVE == 1

    OUTBUF_APPEND_U8(buf, ircFlowP->stat);  // ircStat

#if IRC_BITFIELD == 1
    OUTBUF_APPEND_U64(buf, ircFlowP->sendCode);  // ircCBF
    //OUTBUF_APPEND_U32(buf, ircFlowP->recCode);  // ircRBF
#endif // IRC_BITFIELD == 1

    // ircCC
    uint32_t cnt = ircFlowP->tCCnt;
    OUTBUF_APPEND_NUMREP(buf, cnt);
    for (uint_fast32_t i = 0; i < cnt; i++) {
        OUTBUF_APPEND_STR(buf, ircCom[ircFlowP->tCode[i]]);
    }

    // ircRC
    OUTBUF_APPEND_ARRAY_U16(buf, ircFlowP->recCode, ircFlowP->rCCnt);

    // ircNumUser
    OUTBUF_APPEND_U8(buf, ircFlowP->nameUCnt);

    // ircUser
    OUTBUF_APPEND_ARRAY_STR(buf, ircFlowP->nameU, ircFlowP->nameUCnt);

    // ircNumPass
    OUTBUF_APPEND_U8(buf, ircFlowP->namePCnt);

    // ircPass
    OUTBUF_APPEND_ARRAY_STR(buf, ircFlowP->nameP, ircFlowP->namePCnt);

    // ircNumNick
    OUTBUF_APPEND_U8(buf, ircFlowP->nameNCnt);

    // ircNick
    OUTBUF_APPEND_ARRAY_STR(buf, ircFlowP->nameN, ircFlowP->nameNCnt);

    // ircNumC
    OUTBUF_APPEND_U8(buf, ircFlowP->nameCCnt);

    // ircC
    OUTBUF_APPEND_ARRAY_STR(buf, ircFlowP->nameC, ircFlowP->nameCCnt);
}


void t2PluginReport(FILE *stream) {
    if (ircStat) {
        T2_FPLOG_AGGR_HEX0(stream, plugin_name, ircStat);
        T2_FPLOG_NUMP0(stream, plugin_name, "Number of IRC packets", ircPktCnt, numPackets);
    }
}


void t2Finalize() {
#if (IRC_SAVE == 1 && ENVCNTRL > 0)
    free((char*)ircFPath);
#endif // (IRC_SAVE == 1 && ENVCNTRL > 0)

    free(ircFlows);
}
