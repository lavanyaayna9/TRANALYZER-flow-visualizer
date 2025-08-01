/*
 * smtpDecode.h
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

#ifndef SMTP_DECODE_H_
#define SMTP_DECODE_H_

#include "t2Plugin.h"


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define SMTP_SAVE      0 // save content to SMTP_F_PATH

#define SMTP_BTFLD     0 // Bitfield coding of SMTP commands
#define SMTP_RCTXT     1 // 1: print response code text

#define SMTP_MXNMLN   70 // maximal name length
#define SMTP_MXUNMLN  25 // maximal user length
#define SMTP_MXPNMLN  15 // maximal PW length

#define SMTP_MAXCNM    8 // maximal number of rec,trans codes
#define SMTP_MAXUNM    5 // maximal number of Users
#define SMTP_MAXPNM    5 // maximal number of PWs
#define SMTP_MAXSNM    8 // maximal number of server addresses
#define SMTP_MAXRNM    8 // maximal number of rec EMail addresses
#define SMTP_MAXTNM    8 // maximal number of trans EMail addresses

/* +++++++++++++++++++++ ENV / RUNTIME - conf Variables +++++++++++++++++++++ */

#define SMTP_RMDIR     1 // empty SMTP_F_PATH before starting (require SMTP_SAVE=1)
#define SMTP_F_PATH "/tmp/SMTPFILES/" // Path for extracted content
#define SMTP_NONAME "nudel"           // no name file name

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// Environment var vector
// The elements in the enum below MUST be in the same order as above
enum {
    ENV_SMTP_RMDIR,
    ENV_SMTP_F_PATH,
    ENV_SMTP_NONAME,
    ENV_SMTP_N
};


// def & Calculate name lengths
#define SMTP_FNDX_LEN     20 // string length of findex in decimal format
#define SMTP_MXPL         (SMTP_MXNMLN + SMTP_FNDX_LEN + 4)

// All chars not allowed in an eMail address.
// See RFC 822, section 3.3 and 6.1
//#define SMTP_MAIL_ADDRESS_DELIMITERS "()<>,;:\\\"[] \a\b\f\n\r\t\v"


// Definition of command fields for client
#define CONN 0x4e4e4f43
#define HELO 0x4f4c4548
#define EHLO 0x4f4c4845
#define MAIL 0x4c49414d
#define RCPT 0x54504352
#define DATA 0x41544144
#define RSET 0x54455352
#define SEND 0x444e4553
#define SOML 0x4c4d4f53
#define SAML 0x4c4d4153
#define VRFY 0x59465256
#define EXPN 0x4e505845
#define HELP 0x504c4548
#define NOOP 0x504f4f4e
#define QUIT 0x54495551
#define TURN 0x4e525554
#define AUTH 0x48545541
#define STAR 0x52415453


// receive codes
/*
const uint16_t smtpRec[44] = {
    101,    // The server is unable to connect.
    111,    // Connection refused or inability to open an SMTP stream
    200,    // nonstandard success response, see rfc876
    211,    // System status, or system help reply
    214,    // Help message
    220,    // <domain> Service ready
    221,    // <domain> Service closing transmission channel
    250,    // Requested mail action okay, completed
    251,    // User not local; will forward to <forward-path>
    252,    // Cannot VRFY user, but will accept message and attempt delivery
    354,    // Start mail input; end with <CRLF>.<CRLF>
    421,    // <domain> Service not available, closing transmission channel
    422,    // The recipient's mailbox has exceeded its storage limit
    431,    // Not enough space on the disk, or an "out of memory" condition due to a file overload
    432,    // Typical side-message: "The recipient's Exchange Server incoming mail queue has been stopped"
    441,    // The recipient's server is not responding
    442,    // The connection was dropped during the transmission
    446,    // The maximum hop count was exceeded for the message: an internal loop has occurred
    447,    // Your outgoing message timed out because of issues concerning the incoming server
    449,    // A routing error
    450,    // Requested mail action not taken: mailbox unavailable
    451,    // Requested action aborted: local error in processing
    452,    // Requested action not taken: insufficient system storage
    471,    // An error of your mail server, often due to an issue of the local anti-spam filter.
    500,    // Syntax error, command unrecognized
    501,    // Syntax error in parameters or arguments
    502,    // Command not implemented
    503,    // Bad sequence of commands
    504,    // Command parameter not implemented
    505,    // Your domain has not DNS/MX entries
    510,    // Bad email address
    511,    // Bad email address
    512,    // A DNS error: the host server for the recipient's domain name cannot be found
    513,    // Address type is incorrect": another problem concerning address misspelling. In few cases, however, it's related to an authentication issue
    521,    // <domain> does not accept mail (see rfc1846)
    523,    // The total size of your mailing exceeds the recipient server's limits
    530,    // Normally, an authentication problem. But sometimes it's about the recipient's server blacklisting yours, or an invalid email address.
    541,    // The recipient address rejected your message: normally, it's an error caused by an anti-spam filter.
    550,    // Requested action not taken: mailbox unavailable
    551,    // User not local; please try <forward-path>
    552,    // Requested mail action aborted: exceeded storage allocation
    553,    // Requested action not taken: mailbox name not allowed
    554,    // Transaction failed
    557,    // Access denied
}
*/


// smtpCBF
#define SMTP_HELO 0x0001
#define SMTP_EHLO 0x0002
#define SMTP_MAIL 0x0004
#define SMTP_RCPT 0x0008
#define SMTP_DATA 0x0010
#define SMTP_RSET 0x0020
#define SMTP_SEND 0x0040
#define SMTP_SOML 0x0080
#define SMTP_SAML 0x0100
#define SMTP_VRFY 0x0200
#define SMTP_EXPN 0x0400
#define SMTP_HELP 0x0800
#define SMTP_NOOP 0x1000
#define SMTP_QUIT 0x2000
#define SMTP_TURN 0x4000
#define SMTP_AUTH 0x8000


// smtpStat
#define SMTP_INIT 0x01 // SMTP port found
#define SMTP_AUTP 0x02 // Authentication pending
#define SMTP_DTP  0x04 // Data download pending
#define SMTP_PWP  0x08 // User PW pending
#define SMTP_PWF  0x10 // Flow write finished
#define SMTP_FERR 0x40 // File error, SMTP_SAVE == 1
#define SMTP_OVFL 0x80 // Array overflow


// Structs

typedef struct {
#if SMTP_SAVE == 1
    file_object_t *fd;     // file descriptor per flow
    uint32_t seqInit;
#endif // SMTP_SAVE == 1
    //uint32_t tCode[SMTP_MAXCNM];
    uint16_t sendCode;
    uint16_t recCode[SMTP_MAXCNM];
    uint8_t tCode[SMTP_MAXCNM];
    char nameU[SMTP_MAXUNM][SMTP_MXUNMLN+1];
    char nameP[SMTP_MAXPNM][SMTP_MXPNMLN+1];
    char nameS[SMTP_MAXSNM][SMTP_MXNMLN+1];
    char nameR[SMTP_MAXRNM][SMTP_MXNMLN+1];
    char nameT[SMTP_MAXTNM][SMTP_MXPL+1];
    uint8_t tCCnt;
    uint8_t rCCnt;
    uint8_t nameUCnt;
    uint8_t namePCnt;
    uint8_t nameSCnt;
    uint8_t nameRCnt;
    uint8_t nameTCnt;
    uint8_t smtpStat;
} smtpFlow_t;

// global pointer in case of dependency export
extern smtpFlow_t *smtpFlow;

#endif // SMTP_DECODE_H_
