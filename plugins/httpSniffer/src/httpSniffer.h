/*
 * httpSniffer.h
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

#ifndef _HTTP_SNIFFER_H
#define _HTTP_SNIFFER_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif // _GNU_SOURCE

#include "t2Plugin.h"


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define HTTP_MIME      1 // 1: print mime type in flow file; 0: print # of mime types only
#define HTTP_STAT      1 // 1: print response status code in flow file; 0: print # of status codes only
#define HTTP_MCNT      1 // 1: method counts: GET, POST
#define HTTP_HOST      1 // 1: print hosts in flow file; 0: print # of hosts only
#define HTTP_URL       1 // 1: print URL in flow file; 0: print # of URL only
#define HTTP_COOKIE    1 // 1: print cookies in flow file; 0: print # of cookies only
#define HTTP_IMAGE     1 // 1: print image name in flow file; 0: print # of images only
#define HTTP_VIDEO     1 // 1: print video name in flow file; 0: print # of videos only
#define HTTP_AUDIO     1 // 1: print audio name in flow file; 0: print # of audios only
#define HTTP_MSG       1 // 1: print message name in flow file; 0: print # of messages only
#define HTTP_APPL      1 // 1: print application name in flow file; 0: print # of applications only
#define HTTP_TEXT      1 // 1: print text name in flow file; 0: print # of texts only
#define HTTP_PUNK      1 // 1: print POST/unknown and all else name in flow file; 0: print # of POST/unknown/else only
#define HTTP_BODY      1 // 1: content body exam, print anomaly bits in flow file; 0: none
#define HTTP_BDURL     1 // 1: print body url name in flow file; 0: none
#define HTTP_USRAG     1 // 1: print User-Agents in flow file; 0: none
#define HTTP_XFRWD     1 // 1: print X-Forward-For in flow file; 0: none
#define HTTP_REFRR     1 // 1: print Referer in flow file; 0: none
#define HTTP_VIA       1 // 1: print Via in flow file; 0: none
#define HTTP_LOC       1 // 1: print Location in flow file; 0: none
#define HTTP_SERV      1 // 1: print Server in flow file; 0: none
#define HTTP_PWR       1 // 1: print X-Powered-By in flow file; 0: none
#define HTTP_ANTVIR    0 // 1: print Antivirus info in flow file; 0: none
#define HTTP_AVAST_CID 0 // 1: print Avast client ID; 0: do not print
#define HTTP_ESET_UID  0 // 1: print ESET update ID; 0: do not print

#define HTTP_STATAGA   1 // 1: aggregate stat response in flow file; 0: dont
#define HTTP_MIMEAGA   1 // 1: aggregate mime response in flow file; 0: dont
#define HTTP_HOSTAGA   1 // 1: aggregate Host in flow file; 0: dont
#define HTTP_URLAGA    1 // 1: aggregate URL in flow file; 0: dont
#define HTTP_USRAGA    1 // 1: aggregate User-Agents in flow file; 0: dont
#define HTTP_XFRWDA    1 // 1: aggregate X-Forwarded-For in flow file; 0: dont
#define HTTP_REFRRA    1 // 1: aggregate Referer in flow file; 0: dont
#define HTTP_VIAA      1 // 1: aggregate Via in flow file; 0: dont
#define HTTP_LOCA      1 // 1: aggregate Location in flow file; 0: dont
#define HTTP_SERVA     1 // 1: aggregate Server in flow file; 0: dont
#define HTTP_PWRA      1 // 1: aggregate X-Powered-By in flow file; 0: dont

//#define HTTP_ENT  0    // entropy calculation, not implemented yet

// data carving modes
#define HTTP_SAVE_IMAGE   0 // 1: Save images in files under HTTP_IMAGE_PATH; 0: Don't save images
#define HTTP_SAVE_VIDEO   0 // 1: Save videos in files under HTTP_VIDEO_PATH; 0: Don't save videos
#define HTTP_SAVE_AUDIO   0 // 1: Save audios in files under HTTP_TEXT_PATH; 0: Don't save audios
#define HTTP_SAVE_MSG     0 // 1: Save messages in files under HTTP_MSG_PATH; 0: Don't save pdfs
#define HTTP_SAVE_TEXT    0 // 1: Save texts in files under HTTP_TEXT_PATH; 0: Don't save text
#define HTTP_SAVE_APPL    0 // 1: Save applications in files under HTTP_TEXT_PATH; 0: Don't save applications
#define HTTP_SAVE_PUNK    0 // 1: Save PUT/else content in files under HTTP_PUNK_PATH; 0: Don't save PUT content
#define HTTP_PUNK_AV_ONLY 0 // 1: HTTP_SAVE_PUNK only saves antivirus related files; 0: All PUNK files are saved

#define HTTP_DATA_C_MAX  40 // Maximum dimension of storage arrays per flow
#define HTTP_MXFILE_LEN  80 // Maximum storage name length
#define HTTP_MXUA_LEN   400 // User-Agent length
#define HTTP_MXXF_LEN    80 // X-Forwarded-For length
#define HTTP_AVID_LEN    32 // antivirus ID max length
//#define HTTP_MXCK_LEN   150 // maximum cookie

//#define HTTP_MAXPBIN (1 << 8)

/* +++++++++++++++++++++ ENV / RUNTIME - conf Variables +++++++++++++++++++++ */

#define HTTP_RMDIR        1 // empty HTTP_*_PATH before starting (require at least one of HTTP_SAVE*=1)

// User defined storage boundary conditions
#define HTTP_PATH       "/tmp"        // Root path for extracted files

#define HTTP_IMAGE_PATH "httpPicture" // Path for pictures
#define HTTP_VIDEO_PATH "httpVideo"   // Path for videos
#define HTTP_AUDIO_PATH "httpAudio"   // Path for audios
#define HTTP_MSG_PATH   "httpMSG"     // Path for messages
#define HTTP_TEXT_PATH  "httpText"    // Path for texts
#define HTTP_APPL_PATH  "httpAppl"    // Path for applications
#define HTTP_PUNK_PATH  "httpPunk"    // Path for POST / else / unknown content

#define HTTP_NONAME     "nudel"       // name of files without name

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// Environment var vector
// The elements in the enum below MUST be in the same order as above
enum {
    ENV_HTTP_RMDIR,
    ENV_HTTP_PATH,
    ENV_HTTP_IMAGE_PATH,
    ENV_HTTP_VIDEO_PATH,
    ENV_HTTP_AUDIO_PATH,
    ENV_HTTP_MSG_PATH,
    ENV_HTTP_TEXT_PATH,
    ENV_HTTP_APPL_PATH,
    ENV_HTTP_PUNK_PATH,
    ENV_HTTP_NONAME,
    ENV_HTTP_N
};

#define HTTP_DATA ( \
    HTTP_IMAGE | \
    HTTP_VIDEO | \
    HTTP_AUDIO | \
    HTTP_MSG   | \
    HTTP_TEXT  | \
    HTTP_APPL  | \
    HTTP_PUNK    \
)

#define HTTP_SAVE ( \
    HTTP_SAVE_IMAGE | \
    HTTP_SAVE_VIDEO | \
    HTTP_SAVE_AUDIO | \
    HTTP_SAVE_MSG   | \
    HTTP_SAVE_TEXT  | \
    HTTP_SAVE_APPL  | \
    HTTP_SAVE_PUNK    \
)

// def & Calculate name lengths
#define HTTP_CNT_LEN     13 // Max # of cnt digits attached to file name
#define HTTP_FINDEX_LEN  20 // String length of findex in decimal format
#define HTTP_NONAME_LEN (sizeof(HTTP_NONAME) + HTTP_CNT_LEN + HTTP_FINDEX_LEN)            // Standard name of files without name: name_findex_pkt_num
#define HTTP_MXIMNM_LEN (sizeof(HTTP_IMAGE_PATH) + HTTP_NONAME_LEN + HTTP_MXFILE_LEN + 1) // maximum name length

// httpStat status variable
#define HTTP_F_OVRFLW     0x0001 // More data in flow than HTTP_DATA_C_MAX can save
#define HTTP_F_FNM_LN     0x0002 // Filename larger than HTTP_MXIMNM_LEN
#define HTTP_F_GET        0x0004 // Internal state: pending URL name
#define HTTP_F_HTTP       0x0008 // HTTP flow
#define HTTP_F_CHKD       0x0010 // Internal state: Chunked transfer
#define HTTP_F_DETECT     0x0020 // Internal state: HTTP flow detected
#define HTTP_F_HTTP_HDR   0x0040 // Internal state: HTTP header in process
#define HTTP_F_SEQ_INIT   0x0080 // Internal state: sequence number init
#define HTTP_F_SHFT       0x0100 // Internal state: header shift
#define HTTP_F_PLD_PUNK_S 0x0200 // Internal state: PUT payload sniffing
#define HTTP_F_PLD_IMG_S  0x0400 // Internal state: image payload sniffing
#define HTTP_F_PLD_VID_S  0x0800 // Internal state: video payload sniffing
#define HTTP_F_PLD_AUD_S  0x1000 // Internal state: audio payload sniffing
#define HTTP_F_PLD_MSG_S  0x2000 // Internal state: message payload sniffing
#define HTTP_F_PLD_TXT_S  0x4000 // Internal state: text payload sniffing
#define HTTP_F_PLD_APP_S  0x8000 // Internal state: application payload sniffing

#define HTTP_F_PLD_S      0xfe00 // Internal states mask: Payload sniffing
#define HTTP_F_S          0xfff0 // Internal states mask: Internal state

// httpAFlags
#define HTTP_A_PST        0x0001 // POST | ? anomaly
#define HTTP_A_HNUM       0x0002 // Host is IPv4, e.g., Host: 1.2.3.4
#define HTTP_A_DGA        0x0004 // Possible DGA
#define HTTP_A_MCTYP      0x0008 // Mismatched content-type
#define HTTP_F_SQ_NM      0x0010 // Sequence number violation
#define HTTP_F_PRS_ERR    0x0020 // Parse error
#define HTTP_A_HDR_WO_VAL 0x0040 // Header without value, e.g., Content-Type: [missing] (TODO currently only implemented for content-type)
#define HTTP_A_XSSP       0x0100 // X-Site Scripting protection
#define HTTP_A_CSP        0x0200 // Content Security Policy
#define HTTP_A_DNT        0x0400 // Do not track
#define HTTP_A_DEXE       0x1000 // EXE download
#define HTTP_A_DELF       0x2000 // ELF download
#define HTTP_A_1_0        0x4000 // HTTP 1.0

// httpCFlags
#define HTTP_STCOOKIE  0x0001 // HTTP set cookie
#define HTTP_REFRESH   0x0002 // HTTP refresh
#define HTTP_HOSTNME   0x0004 // Hostname
#define HTTP_BOUND     0x0008 // Boundary
#define HTTP_PCNT      0x0010 // Potential HTTP content
#define HTTP_STRM      0x0020 // Stream
#define HTTP_QUARA     0x0040 // Quarantine virus upload
#define HTTP_AV_SAMPLE 0x0080 // Antivirus sample upload
#define HTTP_AVIRA     0x0100 // Antivirus Avira
#define HTTP_AVAST     0x0200 // Antivirus Avast
#define HTTP_AVG       0x0400 // Antivirus AVG
#define HTTP_BITDF     0x0800 // Antivirus Bit Defender
#define HTTP_ESET      0x1000 // Antivirus ESET
#define HTTP_MSEC      0x2000 // Antivirus Microsoft sec
#define HTTP_SYM       0x4000 // Antivirus Sym, nortorn, etc
#define HTTP_STRM1     0x8000 // Stream1

#define HTTP_AVIR      0x7f00 // Antivirus

#define HTTP_IDN 0x50545448
#define HTTP_ID "HTTP/1." // detect all HTTP/1.* - protocols
#define SIP_ID  "SIP/"    // detect all SIP/ - protocols

#define HTTP_HEADER_LINEEND { '\r', '\n' }
#define HTTP_HEADER_CRLF "\r\n"
#define HTTP_COOKIE_VALSEPARATOR_C 2
#define HTTP_COOKIE_VALSEPARATOR ";"
#define HTTP_COOKIE_SEPARATOR '='

// definition of content types
#define CONTENT_TYPE     "Content-type:"
#define CONTENT_DISP     "Content-Disposition:"
#define CONTENT_LENGTH   "Content-Length:"
#define CONTENT_ENCODING "Content-Encoding:"
#define TRANS_ENCODING   "Transfer-Encoding:"
#define SET_COOKIE       "Cookie:"
#define USER_AGENT       "User-Agent:"
#define HOST             "Host:"
#define X_FORWRD_FOR     "X-Forwarded-For:"
#define REFERER          "Referer:"
#define VIA              "Via:"
#define LOC              "Location:"
#define SERVER           "Server:"
#define CONTTRNSECDG     "Content-Transfer-Encoding:"
#define POWERED          "X-Powered-By:"
#define XXSSPROT         "X-XSS-Protection:"
#define CONTSECPOL       "Content-Security-Policy:"
#define AVAST_CID        "X-AVAST-Client-Id-0:"
#define ESET_UID         "X-ESET-UpdateID:"
#define FILENAME         "filename="
#define BOUNDARY         "boundary="
#define QUARANTINE       "quarantine"
#define UPLOAD           "upload"
#define STREAM           "#EXTM3U"
#define DNT              "DNT: 1"
#define STREAM_INF       "#EXT-X-STREAM-INF:"

// httpMethods
#define OPTIONS  0x01
#define GET      0x02
#define HEAD     0x04
#define POST     0x08
#define PUT      0x10
#define DELETE   0x20
#define TRACE    0x40
#define CONNECT  0x80

#define SOPTIONS  "OPTIONS"
#define SGET      "GET"
#define SHEAD     "HEAD"
#define SPOST     "POST"
#define SPUT      "PUT"
#define SDELETE   "DELETE"
#define STRACE    "TRACE"
#define SCONNECT  "CONNECT"

// httpHeadMimes
typedef enum {
    HTTP_C_APPL   = 0x0001, // Application
    HTTP_C_AUDIO  = 0x0002, // Audio
    HTTP_C_IMAGE  = 0x0004, // Image
    HTTP_C_MSG    = 0x0008, // Message
    HTTP_C_MODEL  = 0x0010, // Model
    HTTP_C_MLTPRT = 0x0020, // Multipart
    HTTP_C_TEXT   = 0x0040, // Text
    HTTP_C_VIDEO  = 0x0080, // Video
    HTTP_C_VND    = 0x0100, // VND
    HTTP_C_X      = 0x0200, // X
    HTTP_C_XPKCS  = 0x0400, // XPKCS
    //HTTP_C_PDF    = 0x1000, // PDF
    //HTTP_C_JAVA   = 0x2000, // Java
    HTTP_C_OTHER  = 0x8000, // All else
} http_mimetype;

// Antivirus URL signatures
#define UAVIRA         "avira"
#define UAVAST         ".avast"
#define UAVG           ".avcdn"
#define UBITDF         ".bitdefender"
#define UESET          ".eset"
#define UMSECD         "/MicSecSerCA"
#define UMSEC          "/nis_engine_"
#define USYM           ".symantec"
#define USYMD          "virus"
#define AVIRA_SND_HOST "spsubmit.avira.com"
#define AVAST_SND_MIME "iavs4/upload"


// plugin structs

typedef struct {
#if HTTP_SAVE == 1
    file_object_t *fd;       // File descriptor per flow
#endif // HTTP_SAVE == 1
    uint64_t aggContLen;
    uint32_t pktcnt;         // Packet count for stored info
    uint32_t tcpSeqInit;     // Initial TCP sequence number if in sniff-content
    uint32_t seq;            // Last TCP sequence number if in sniff-content
    uint32_t contentLength;  // Last HTTP Content-Length field
    uint32_t sniffedContent; // Amount of sniffed content
    uint32_t hdr_len;        // Header length
    uint16_t mimeTypes;      // Mime types in flow
    uint16_t getCnt;
    uint16_t pstCnt;
    uint16_t host_c;         // # of hostnames in flow
    uint16_t stat_c;         // # of status codes in flow
    uint16_t url_c;          // # of url names in flow
    uint16_t via_c;          // # of Via proxies in flow
    uint16_t loc_c;          // # of Location in flow
    uint16_t serv_c;         // # of Server in flow
    uint16_t pwr_c;          // # of X-Powered-By in flow
    uint16_t usrAg_c;        // # of User-Agent info in flow
    uint16_t xFor_c;         // # of X-Forwarded-For in flow
    uint16_t refrr_c;        // # of Referer in flow
    uint16_t cookie_c;       // # of cookies in flow
    uint16_t mime_c;         // # of mime types in flow
    uint16_t image_c;        // # of images in flow
    uint16_t video_c;        // # of videos in flow
    uint16_t audio_c;        // # of audios in flow
    uint16_t msg_c;          // # of msgs in flow
    uint16_t text_c;         // # of texts in flow
    uint16_t appl_c;         // # of applications in flow
    uint16_t unknwn_c;       // # of unknown in flow
#if HTTP_BDURL == 1
    uint16_t refURL_c;
#endif // HTTP_BDURL == 1
    uint16_t flags;          // httpStat (see above)
    uint16_t aFlags;         // httpAFlags anomaly flags (see above)
    uint16_t cFlags;         // httpCFlags content flags (see above)
#if HTTP_STAT == 1
    uint16_t stat[HTTP_DATA_C_MAX]; // status code
#endif // HTTP_STAT == 1
#if HTTP_HOST == 1
    char *host[HTTP_DATA_C_MAX];    // hostnames
#endif // HTTP_HOST == 1
#if HTTP_URL == 1
    char *url[HTTP_DATA_C_MAX];     // url names
#endif // HTTP_URL == 1
#if HTTP_MIME == 1
    char *mime[HTTP_DATA_C_MAX];    // Mimetypes
#endif // HTTP_MIME == 1
#if HTTP_COOKIE == 1
    char *cookie[HTTP_DATA_C_MAX];  // cookie names
#endif // HTTP_COOKIES == 1
#if (HTTP_IMAGE == 1 || HTTP_SAVE_IMAGE == 1)
    char *image[HTTP_DATA_C_MAX];   // image names
#endif // (HTTP_IMAGES == 1 || HTTP_SAVE_IMAGES == 1)
#if (HTTP_VIDEO == 1 || HTTP_SAVE_VIDEO == 1)
    char *video[HTTP_DATA_C_MAX];   // video names
#endif // (HTTP_VIDEO == 1 || HTTP_SAVE_VIDEO == 1)
#if (HTTP_AUDIO == 1 || HTTP_SAVE_AUDIO == 1)
    char *audio[HTTP_DATA_C_MAX];   // audio names
#endif // (HTTP_AUDIO == 1 || HTTP_SAVE_AUDIO == 1)
#if (HTTP_MSG == 1 || HTTP_SAVE_MSG == 1)
    char *msg[HTTP_DATA_C_MAX];     // message names
#endif // (HTTP_MSG == 1 || HTTP_SAVE_MSG == 1)
#if (HTTP_TEXT == 1 || HTTP_SAVE_TEXT == 1)
    char *text[HTTP_DATA_C_MAX];    // text names
#endif // (HTTP_TEXT == 1 || HTTP_SAVE_TEXT == 1)
#if (HTTP_APPL == 1 || HTTP_SAVE_APPL == 1)
    char *appl[HTTP_DATA_C_MAX];    // application names
#endif // (HTTP_APPL == 1 || HTTP_SAVE_APPL == 1)
#if (HTTP_PUNK == 1 || HTTP_SAVE_PUNK == 1)
    char *punk[HTTP_DATA_C_MAX];    // punk names
#endif // (HTTP_PUNK == 1 || HTTP_SAVE_PUNK == 1)
#if HTTP_BDURL == 1
    char *refURL[HTTP_DATA_C_MAX];  // reference url names
#endif // HTTP_BDURL == 1
#if HTTP_USRAG == 1
    char *usrAg[HTTP_DATA_C_MAX];   // user-agent names
#endif // HTTP_USRAG == 1
#if HTTP_XFRWD == 1
    char *xFor[HTTP_DATA_C_MAX];    // x-Forwarded-For names
#endif // HTTP_XFRWD == 1
#if HTTP_REFRR == 1
    char *refrr[HTTP_DATA_C_MAX];   // Referer names
#endif // HTTP_REFRR == 1
#if HTTP_VIA == 1
    char *via[HTTP_DATA_C_MAX];     // via proxy names
#endif // HTTP_VIA == 1
#if HTTP_LOC == 1
    char *loc[HTTP_DATA_C_MAX];     // location names
#endif // HTTP_LOC == 1
#if HTTP_SERV == 1
    char *serv[HTTP_DATA_C_MAX];    // server names
#endif // HTTP_SERV == 1
#if HTTP_PWR == 1
    char *pwr[HTTP_DATA_C_MAX];     // powered by application
#endif // HTTP_PWR == 1
#if HTTP_AVAST_CID == 1
    char avastCid[HTTP_AVID_LEN];   // http X-AVAST-Client-Id-0 header
#endif // HTTP_AVAST_CID == 1
#if HTTP_ESET_UID == 1
    char esetUid[HTTP_AVID_LEN];    // http X-ESET-UpdateID header
#endif // HTTP_ESET_UID == 1
//#if HTTP_ENT == 1
//    uint8_t eBinCnt[HTTP_MAXPBIN];
//#endif // HTTP_ENT == 1
    char getFile[HTTP_MXIMNM_LEN+1];  // File requested by HTTP GET
    //char *bound;
    uint8_t httpMethods;            // Bitfield seen HTTP methods in that flow
    uint8_t httpLastMeth;           // Last HTTP method in that flow
} http_flow_t;

#endif // _HTTPSNIFFER_H
