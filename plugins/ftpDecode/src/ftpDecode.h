/*
 * ftpDecode.h
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

#ifndef __FTP_DECODE_H__
#define __FTP_DECODE_H__

#include "t2Plugin.h"


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define FTP_SAVE       0 // save content to FTP_F_PATH

#define FTP_CMD_AGGR   1 // Aggregate FTP commands/response codes
#define FTP_BTFLD      0 // Bitfield coding of FTP commands

#define FTP_UXNMLN    10 // maximal username length
#define FTP_PXNMLN    15 // maximal password length
#define FTP_MXNMLN    50 // maximal name length

#define FTP_MAXCPFI   10 // Maximal number of pfi
#define FTP_MAXUNM     5 // Maximal number of users
#define FTP_MAXPNM     5 // Maximal number of passwords
#define FTP_MAXCNM    20 // Maximal number of parameters

/* +++++++++++++++++++++ ENV / RUNTIME - conf Variables +++++++++++++++++++++ */

#define FTP_RMDIR                 1 // empty FTP_F_PATH before starting (require FTP_SAVE=1)
#define FTP_F_PATH "/tmp/FTPFILES/" // Path for extracted content
#define FTP_NONAME          "nudel" // No name file name

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// Environment var vector
// The elements in the enum below MUST be in the same order as above
enum {
    ENV_FTP_RMDIR,
    ENV_FTP_F_PATH,
    ENV_FTP_NONAME,
    ENV_FTP_N
};


// FTP ports
#define FTP_CTRL_PORT 21
#define FTP_DATA_PORT 20


// FTP commands
#define ABOR 0x524f4241 // Abort an active file transfer
#define ACCT 0x54434341 // Account information
#define ADAT 0x54414441 // Authentication/Security Data (RFC 2228)
#define ALLO 0x4f4c4c41 // Allocate sufficient disk space to receive a file
#define APPE 0x45505041 // Append (with create)
#define AUTH 0x48545541 // Authentication/Security Mechanism (RFC 2228)
//#define AVBL 0x4c425641 // Get the available space (Streamlined FTP Command Extensions)
#define CCC  0x20434343 // Clear Command Channel (RFC 2228)
#define CDUP 0x50554443 // Change to Parent Directory
#define CLNT 0x544e4c43 // Used to identify the client software to the server
#define CONF 0x464e4f43 // Confidentiality Protection Command (RFC 2228)
//#define CSID 0x44495343 // Client / Server Identification (Streamlined FTP Command Extensions)
#define CWD  0x20445743 // Change working directory (RFC 697)
#define DELE 0x454c4544 // Delete file
//#define DSIZ 0x5a495344 // Get the directory size (Streamlined FTP Command Extensions)
#define ENC  0x20434e45 // Privacy Protected Channel (RFC 2228)
#define EPRT 0x54525045 // Specifies an extended address and port to which the server should connect (RFC 2428)
#define EPSV 0x56535045 // Enter extended passive mode (RFC 2428)
#define FEAT 0x54414546 // Get the feature list implemented by the server (RFC 2389)
#define HELP 0x504c4548 // Returns usage documentation on a command if specified, else a general help document is returned
//#define HOST 0x54534f48 // Identify desired virtual host on server, by name (RFC 7151)
#define LANG 0x474e414c // Language Negotiation (RFC 2640)
#define LIST 0x5453494c // Returns information of a file or directory if specified, else information of the current working directory is returned
#define LPRT 0x5452504c // Specifies a long address and port to which the server should connect (RFC 1639)
#define LPSV 0x5653504c // Enter long passive mode (RFC 1639)
#define MDTM 0x4d54444d // Return the last-modified time of a specified file (RFC 3659)
//#define MFCT 0x5443464d // Modify the creation time of a file (The 'MFMT', 'MFCT', and 'MFF' Command Extensions for FTP)
//#define MFF  0x2046464d // Modify fact (the last modification time, creation time, UNIX group/owner/mode of a file) (The 'MFMT', 'MFCT', and 'MFF' Command Extensions for FTP)
//#define MFMT 0x544d464d // Modify the last modification time of a file (The 'MFMT', 'MFCT', and 'MFF' Command Extensions for FTP)
#define MIC  0x2043494d // Integrity Protected Command (RFC 2228)
#define MKD  0x20444b4d // Make directory
#define MLSD 0x44534c4d // Lists the contents of a directory if a directory is named (RFC 3659)
#define MLST 0x54534c4d // Provides data about exactly the object named on its command line, and no others (RFC 3659)
#define MODE 0x45444f4d // Sets the transfer mode (Stream, Block, or Compressed)
#define NLST 0x54534c4e // Returns a list of file names in a specified directory
#define NOOP 0x504f4f4e // No operation (dummy packet; used mostly on keepalives)
#define OPTS 0x5354504f // Select options for a feature (for example OPTS UTF8 ON) (RFC 2389)
#define PASS 0x53534150 // Authentication password
#define PASV 0x56534150 // Enter passive mode
#define PBSZ 0x5a534250 // Protection Buffer Size (RFC 2228)
#define PORT 0x54524f50 // Specifies an address and port to which the server should connect
#define PROT 0x544f5250 // Data Channel Protection Level (RFC 2228)
#define PWD  0x20445750 // Print working directory. Returns the current directory of the host
#define QUIT 0x54495551 // Disconnect
#define REIN 0x4e494552 // Re initializes the connection
#define REST 0x54534552 // Restart transfer from the specified point (RFC 3659)
#define RETR 0x52544552 // Retrieve a copy of the file
#define RMD  0x20444d52 // Remove a directory
//#define RMDA 0x41444d52 // Remove a directory tree (Streamlined FTP Command Extensions)
#define RNFR 0x52464e52 // Rename from
#define RNTO 0x4f544e52 // Rename to
#define SITE 0x45544953 // Sends site specific commands to remote server (like SITE IDLE 60 or SITE UMASK 002). Inspect SITE HELP output for complete list of supported commands
#define SIZE 0x455a4953 // Return the size of a file (RFC 3659)
#define SMNT 0x544e4d53 // Mount file structure
//#define SPSV 0x56535053 // Use single port passive mode (only one TCP port number for both control connections and passive-mode data connections) (FTP Extension Allowing IP Forwarding (NATs))
#define STAT 0x54415453 // Returns information on the server status, including the status of the current connection
#define STOR 0x524f5453 // Accept the data and to store the data as a file at the server site
#define STOU 0x554f5453 // Store file uniquely
#define STRU 0x55525453 // Set file transfer structure
#define SYST 0x54535953 // Return system type
//#define THMB 0x424d4854 // Get a thumbnail of a remote image file (Streamlined FTP Command Extensions)
#define TYPE 0x45505954 // Sets the transfer mode (ASCII/Binary)
#define USER 0x52455355 // Authentication username
#define XCUP 0x50554358 // Change to the parent of the current working directory (RFC 775)
#define XMKD 0x444b4d58 // Make a directory (RFC 775)
#define XPWD 0x44575058 // Print the current working directory (RFC 775)
#define XRCP 0x50435258 // Recipient specification (RFC 743)
#define XRMD 0x444d5258 // Remove the directory (RFC 775)
#define XRSQ 0x51535258 // Scheme selection (RFC 743)
#define XSEM 0x4d455358 // Send, mail if cannot (RFC 737)
#define XSEN 0x4e455358 // Send to terminal (RFC 737)


/*
Return code Explanation
110     Restart marker replay
120     Service ready in nnn minutes.
125     Data connection already open; transfer starting.
150     File status okay; about to open data connection.
202     Command not implemented, superfluous at this site.
211     System status, or system help reply.
212     Directory status.
213     File status.
214     Help message.
215     NAME system type.
220     Service ready for new user.
221     Service closing control connection.
225     Data connection open; no transfer in progress.
226     Closing data connection. Requested file action successful.
227     Entering Passive Mode (h1,h2,h3,h4,p1,p2).
228     Entering Long Passive Mode (long address, port).
229     Entering Extended Passive Mode (|||port|).
230     User logged in, proceed. Logged out if appropriate.
231     User logged out; service terminated.
232     Logout command noted, will complete when transfer done.
234     Specifies that the server accepts the authentication mechanism specified by the client, and the exchange of security data is complete.
250     Requested file action okay, completed.
257     "PATHNAME" created.
331     User name okay, need password.
332     Need account for login.
350     Requested file action pending further information
421     Service not available, closing control connection.
425     Can't open data connection.
426     Connection closed; transfer aborted.
430     Invalid username or password
434     Requested host unavailable.
450     Requested file action not taken.
451     Requested action aborted. Local error in processing.
452     Requested action not taken. Insufficient storage space in system.
501     Syntax error in parameters or arguments.
502     Command not implemented.
503     Bad sequence of commands.
504     Command not implemented for that parameter.
530     Not logged in.
532     Need account for storing files.
534     Could Not Connect to Server - Policy Requires SSL
550     Requested action not taken. File unavailable.
551     Requested action aborted. Page type unknown.
552     Requested file action aborted. Exceeded storage allocation.
553     Requested action not taken. File name not allowed.
631     Integrity protected reply.
632     Confidentiality and integrity protected reply.
633     Confidentiality protected reply.
10054   Connection reset by peer. The connection was forcibly closed by the remote host.
10060   Cannot connect to remote server.
10061   Cannot connect to remote server. The connection is actively refused by the server.
10066   Directory not empty.
10068   Too many users, server is full.
*/

// plugin defines

// ftpCBF
#define FTP_ABOR 0x0000000000000001 //  0
#define FTP_ACCT 0x0000000000000002 //  1
#define FTP_ADAT 0x0000000000000004 //  2
#define FTP_ALLO 0x0000000000000008 //  3
#define FTP_APPE 0x0000000000000010 //  4
#define FTP_AUTH 0x0000000000000020 //  5
#define FTP_CCC  0x0000000000000040 //  6
#define FTP_CDUP 0x0000000000000080 //  7
#define FTP_CONF 0x0000000000000100 //  8
#define FTP_CWD  0x0000000000000200 //  9
#define FTP_DELE 0x0000000000000400 // 10
#define FTP_ENC  0x0000000000000800 // 11
#define FTP_EPRT 0x0000000000001000 // 12
#define FTP_EPSV 0x0000000000002000 // 13
#define FTP_FEAT 0x0000000000004000 // 14
#define FTP_HELP 0x0000000000008000 // 15
#define FTP_LANG 0x0000000000010000 // 16
#define FTP_LIST 0x0000000000020000 // 17
#define FTP_LPRT 0x0000000000040000 // 18
#define FTP_LPSV 0x0000000000080000 // 19
#define FTP_MDTM 0x0000000000100000 // 20
#define FTP_MIC  0x0000000000200000 // 21
#define FTP_MKD  0x0000000000400000 // 22
#define FTP_MLSD 0x0000000000800000 // 23
#define FTP_MLST 0x0000000001000000 // 24
#define FTP_MODE 0x0000000002000000 // 25
#define FTP_NLST 0x0000000004000000 // 26
#define FTP_NOOP 0x0000000008000000 // 27
#define FTP_OPTS 0x0000000010000000 // 28
#define FTP_PASS 0x0000000020000000 // 29
#define FTP_PASV 0x0000000040000000 // 30
#define FTP_PBSZ 0x0000000080000000 // 31
#define FTP_PORT 0x0000000100000000 // 32
#define FTP_PROT 0x0000000200000000 // 33
#define FTP_PWD  0x0000000400000000 // 34
#define FTP_QUIT 0x0000000800000000 // 35
#define FTP_REIN 0x0000001000000000 // 36
#define FTP_REST 0x0000002000000000 // 37
#define FTP_RETR 0x0000004000000000 // 38
#define FTP_RMD  0x0000008000000000 // 39
#define FTP_RNFR 0x0000010000000000 // 40
#define FTP_RNTO 0x0000020000000000 // 41
#define FTP_SITE 0x0000040000000000 // 42
#define FTP_SIZE 0x0000080000000000 // 43
#define FTP_SMNT 0x0000100000000000 // 44
#define FTP_STAT 0x0000200000000000 // 45
#define FTP_STOR 0x0000400000000000 // 46
#define FTP_STOU 0x0000800000000000 // 47
#define FTP_STRU 0x0001000000000000 // 48
#define FTP_SYST 0x0002000000000000 // 49
#define FTP_TYPE 0x0004000000000000 // 50
#define FTP_USER 0x0008000000000000 // 51
#define FTP_XCUP 0x0010000000000000 // 52
#define FTP_XMKD 0x0020000000000000 // 53
#define FTP_XPWD 0x0040000000000000 // 54
#define FTP_XRCP 0x0080000000000000 // 55
#define FTP_XRMD 0x0100000000000000 // 56
#define FTP_XRSQ 0x0200000000000000 // 57
#define FTP_XSEM 0x0400000000000000 // 58
#define FTP_XSEN 0x0800000000000000 // 59
#define FTP_CLNT 0x1000000000000000 // 60


// ftpStat status variable
#define FTP_INIT    0x01  // FTP control port found
#define FTP_PPRNT   0x02  // FTP passive parent flow
#define FTP_PPWF    0x04  // FTP passive parent flow length overrun, possibly by dupACK/retransmits
#define FTP_APRNT   0x08  // FTP active parent flow
#define FTP_HSHMFLL 0x10  // FTP Hash map full
#define FTP_PPWFERR 0x20  // File error, FTP_SAVE == 1
#define FTP_NDFLW   0x40  // Data flow not detected
#define FTP_OVFL    0x80  // Array, string or filename overflow


// plugin structures

//typedef struct {
//#if IPV6_ACTIVATE == 1
//  uint64_t srcIP[2], dstIP[2];
//#else // IPV6_ACTIVATE == 0
//  uint32_t srcIP, dstIP;
//#endif // IPV6_ACTIVATE == 0
//  uint16_t sdPort, vlan;
//  uint8_t l4Proto;
//} __attribute__((packed)) ftpID_t;

typedef struct {
    uint64_t pfi[FTP_MAXCPFI];
    uint64_t sendCode;
    int64_t cLen;           // last declared ftp-Content-Length
#if FTP_SAVE == 1
    file_object_t *fd;      // file descriptor per flow
    int64_t dwLen;          // Amount of data written
    uint32_t seqInit;
#endif // FTP_SAVE == 1
    uint32_t pslAddr;
    uint16_t pcrPort;       // passive mode: client rec port
    uint16_t recCode[FTP_MAXCNM];
    uint8_t tCode[FTP_MAXCNM];
    char nameU[FTP_MAXUNM][FTP_UXNMLN+1];
    char nameP[FTP_MAXPNM][FTP_PXNMLN+1];
    char nameC[FTP_MAXCNM][FTP_MXNMLN+1];
    uint8_t pfiCnt;
    uint8_t tCCnt;
    uint8_t rCCnt;
    uint8_t nameUCnt;
    uint8_t namePCnt;
    uint8_t nameCCnt;
    uint8_t stat;
} ftpFlow_t;

// plugin struct pointer for potential dependencies
extern ftpFlow_t *ftpFlows;

#endif // __FTP_DECODE_H__
