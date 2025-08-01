/*
 * ircDecode.h
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

#ifndef __IRC_DECODE_H__
#define __IRC_DECODE_H__

#include "t2Plugin.h"


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define IRC_SAVE       0 // save content to IRC_F_PATH

#define IRC_CMD_AGGR   1 // Aggregate IRC commands/response codes
#define IRC_BITFIELD   0 // Bitfield coding of IRC commands

#define IRC_UXNMLN    10 // maximal username length
#define IRC_PXNMLN    10 // maximal password length
#define IRC_NXNMLN    10 // maximal nickname length
#define IRC_MXNMLN    50 // maximal name length

#define IRC_MAXUNM     5 // Maximal number of users
#define IRC_MAXPNM     5 // Maximal number of passwords
#define IRC_MAXNNM     5 // Maximal number of nicknames
#define IRC_MAXCNM    20 // Maximal number of parameters

/* +++++++++++++++++++++ ENV / RUNTIME - conf Variables +++++++++++++++++++++ */

#define IRC_RMDIR                 1 // empty IRC_F_PATH before starting (require IRC_SAVE=1)
#define IRC_F_PATH "/tmp/IRCFILES/" // Path for extracted content

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// Environment var vector
// The elements in the enum below MUST be in the same order as above
enum {
    ENV_IRC_RMDIR,
    ENV_IRC_F_PATH,
    ENV_IRC_N
};


// IRC ports
#define IRC_PORT      194
#define IRC_PORT_MIN 6665
#define IRC_PORT_MAX 6669


// IRC commands
#define I_ADMIN    0x0000004e494d4441 // Get information about the administrator of a server
#define I_AWAY     0x0000000059415741 // Set an automatic reply string for any PRIVMSG commands
#define I_CAP      0x0000000000504143 // Capability negotiation
#define I_CNOTICE  0x00454349544f4e43 // Send a channel NOTICE message
#define I_CONNECT  0x005443454e4e4f43 // Request a new connection to another server immediately
#define I_CPRIVMSG 0x47534d5649525043 // Send a private message that bypasses flood protection limits
#define I_DIE      0x0000000000454944 // Shutdown the server
#define I_ENCAP    0x0000005041434e45 // Encapsulate commands
#define I_ERROR    0x000000524f525245 // Report a serious or fatal error to a peer
#define I_HELP     0x00000000504c4548 // Request the server to display the help file
#define I_INFO     0x000000004f464e49 // Get information describing a server
#define I_INVITE   0x0000455449564e49 // Invite a user to a channel
#define I_ISON     0x000000004e4f5349 // Determine if a nickname is currently on IRC
#define I_JOIN     0x000000004e494f4a // Join a channel
#define I_KICK     0x000000004b43494b // Request the forced removal of a user from a channel
#define I_KILL     0x000000004c4c494b // Close a client-server connection by the server which has the actual connection
#define I_KNOCK    0x0000004b434f4e4b // Send a NOTICE to an invitation-only <channel> with an optional <message>, requesting an invite
#define I_LINKS    0x000000534b4e494c // List all server names which are known by the server answering the query
#define I_LIST     0x000000005453494c // List channels and their topics
#define I_LUSERS   0x000053524553554c // Get statistics about the size of the IRC network
#define I_MODE     0x0000000045444f4d // User mode
#define I_MOTD     0x0000000044544f4d // Get the Message of the Day
#define I_NAMES    0x00000053454d414e // List all visible nicknames
#define I_NAMESX   0x00005853454d414e // Instructs the server to send names in an RPL_NAMES reply prefixed with all their respective channel statuses instead of just the highest one
#define I_NICK     0x000000004b43494e // Define a nickname
#define I_NJOIN    0x0000004e494f4a4e // Exchange the list of channel members for each channel between servers
#define I_NOTICE   0x0000454349544f4e // This command works similarly to PRIVMSG, except automatic replies must never be sent in reply to NOTICE messages (RFC 1459)
#define I_OPER     0x000000005245504f // Obtain operator privileges
#define I_PART     0x0000000054524150 // Leave a channel
#define I_PASS     0x0000000053534150 // Set a connection password
#define I_PING     0x00000000474e4950 // Test for the presence of an active client or server
#define I_PONG     0x00000000474e4f50 // Reply to a PING message
#define I_PRIVMSG  0x0047534d56495250 // Send private messages between users, as well as to send messages to channels
#define I_QUIT     0x0000000054495551 // Terminate the client session
#define I_REHASH   0x0000485341484552 // Force the server to re-read and process its configuration file
#define I_RESTART  0x0054524154534552 // Force the server to restart itself
#define I_RULES    0x00000053454c5552 // Request the server rules
#define I_SERVER   0x0000524556524553 // Register a new server
#define I_SERVICE  0x0045434956524553 // Register a new service
#define I_SERVLIST 0x5453494c56524553 // List services currently connected to the network
#define I_SETNAME  0x00454d414e544553 // Allow a client to change the "real name" specified when registering a connection
#define I_SILENCE  0x0045434e454c4953 // Add or remove a host mask to a server-side ignore list that prevents matching users from sending the client messages
#define I_SQUERY   0x0000595245555153 // Identical to PRIVMSG except the recipient must be a service (RFC 2812)
#define I_SQUIT    0x0000005449555153 // Break a local or remote server link
#define I_STATS    0x0000005354415453 // Get server statistics
#define I_SUMMON   0x00004e4f4d4d5553 // Ask a user to join IRC
#define I_TIME     0x00000000454d4954 // Get the local time from the specified server
#define I_TOPIC    0x0000004349504f54 // Change or view the topic of a channel
#define I_TRACE    0x0000004543415254 // Find the route to a server and information about it's peers
#define I_UHNAMES  0x0053454d414e4855 // Instruct the server to send names in an RPL_NAMES reply in the long format
#define I_USER     0x0000000052455355 // Specify the username, hostname and realname of a new user
#define I_USERHOST 0x54534f4852455355 // Get a list of information about up to 5 nicknames
#define I_USERIP   0x0000504952455355 // Request the direct IP address of the user with the specified nickname
#define I_USERS    0x0000005352455355 // Get a list of users logged into the server
#define I_VERSION  0x004e4f4953524556 // Get the version of the server program
#define I_WALLOPS  0x0053504f4c4c4157 // Send a message to all currently connected users who have set the 'w' user mode
#define I_WATCH    0x0000004843544157 // Adds or removes a user to a client's server-side friends list
#define I_WHO      0x00000000004f4857 // List a set of users
#define I_WHOIS    0x00000053494f4857 // Get information about a specific user
#define I_WHOWAS   0x00005341574f4857 // Get information about a nickname which no longer exists


// plugin defines

// ircStat status variable
#define IRC_INIT       0x01 // IRC port found
#define IRC_REG_SUCC   0x02 // IRC registration successful
#define IRC_LOG_ERR    0x04 // IRC password incorrect
#define IRC_SENDCODE   0x10 // Unrecognized IRC command
#define IRC_PPWFERR    0x20 // File error, IRC_SAVE == 1
#define IRC_OVFL       0x40 // Array, string or filename overflow
#define IRC_MALFORMED  0x80 // Invalid format or parsing error


// ircCBF
// Keep enum synchronized with ircCom[][]
typedef enum {
    IRC_ADMIN = 0,
    IRC_AWAY,
    IRC_CAP,
    IRC_CNOTICE,
    IRC_CONNECT,
    IRC_CPRIVMSG, // 5
    IRC_DIE,
    IRC_ENCAP,
    IRC_ERROR,
    IRC_HELP,
    IRC_INFO,     // 10
    IRC_INVITE,
    IRC_ISON,
    IRC_JOIN,
    IRC_KICK,
    IRC_KILL,     // 15
    IRC_KNOCK,
    IRC_LINKS,
    IRC_LIST,
    IRC_LUSERS,
    IRC_MODE,     // 20
    IRC_MOTD,
    IRC_NAMES,
    IRC_NAMESX,
    IRC_NICK,
    IRC_NJOIN,    // 25
    IRC_NOTICE,
    IRC_OPER,
    IRC_PART,
    IRC_PASS,
    IRC_PING,     // 30
    IRC_PONG,
    IRC_PRIVMSG,
    IRC_QUIT,
    IRC_REHASH,
    IRC_RESTART,  // 35
    IRC_RULES,
    IRC_SERVER,
    IRC_SERVICE,
    IRC_SERVLIST,
    IRC_SETNAME,  // 40
    IRC_SILENCE,
    IRC_SQUERY,
    IRC_SQUIT,
    IRC_STATS,    // 45
    IRC_SUMMON,
    IRC_TIME,
    IRC_TOPIC,
    IRC_TRACE,
    IRC_UHNAMES,  // 50
    IRC_USER,
    IRC_USERHOST,
    IRC_USERIP,
    IRC_USERS,
    IRC_VERSION,  // 55
    IRC_WALLOPS,
    IRC_WATCH,
    IRC_WHO,
    IRC_WHOIS,
    IRC_WHOWAS,   // 60
    IRC_UNKNOWN = 255,
} irc_cmd_t;


// Structs

typedef struct {
#if IRC_BITFIELD == 1
    uint64_t sendCode;
#endif // IRC_BITFIELD == 1
#if IRC_SAVE == 1
    file_object_t *fd;          // file descriptor per flow
    uint32_t seqInit;
#endif // IRC_SAVE == 1
    uint16_t recCode[IRC_MAXCNM];
    irc_cmd_t tCode[IRC_MAXCNM];
    char nameU[IRC_MAXUNM][IRC_UXNMLN+1];  // ircUser
    char nameP[IRC_MAXPNM][IRC_PXNMLN+1];  // ircPass
    char nameN[IRC_MAXNNM][IRC_NXNMLN+1];  // ircNick
    char nameC[IRC_MAXCNM][IRC_MXNMLN+1];  // ircC
    uint8_t tCCnt;
    uint8_t rCCnt;
    uint8_t nameUCnt;  // ircNumUser
    uint8_t namePCnt;  // ircNumPass
    uint8_t nameNCnt;  // ircNumNick
    uint8_t nameCCnt;  // ircNumC
    uint8_t stat;
} ircFlow_t;

// plugin struct pointer for potential dependencies
extern ircFlow_t *ircFlows;

#endif // __IRC_DECODE_H__
