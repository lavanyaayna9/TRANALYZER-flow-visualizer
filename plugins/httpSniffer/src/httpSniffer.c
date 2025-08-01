/*
 * httpSniffer.c
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

// local includes

#include "httpSniffer.h"

#include <arpa/inet.h>  // for inet_pton
#include <errno.h>      // for errno

#include "memdebug.h"


// Append a repetitive string to the output buffer.
// Every repetition is freed once appended to the buffer.
#define HTTP_APPEND_REP_STR(field, count) { \
    const uint32_t j = MIN(count, HTTP_DATA_C_MAX); \
    OUTBUF_APPEND_NUMREP(buf, j); \
    for (uint_fast32_t i = 0; i < j; i++) { \
        OUTBUF_APPEND_STR(buf, field[i]); \
        free(field[i]); \
    } \
}

// Build a filename with flow/packet information
#define HTTP_BUILD_FILENAME(dest, str, count) { \
    const size_t len = (*str ? strlen(str) : 0); \
    dest = t2_strdup_printf("%s_%" PRIu64 "_%c_%" PRIu32 "_%" PRIu16, \
            (len == 0 ? HTTP_NONAME : str), flowP->findex, FLOW_DIR_C(flowP), httpFlowP->pktcnt, (count)); \
    if (len > 0) { \
        /* replace all '/' and '?' with '_' */ \
        for (uint_fast32_t i = 0; i <= len; i++) { \
            if (dest[i] == '/' || dest[i] == '?') dest[i] = '_'; \
        } \
    } \
}

// Build a filepath from a directory and filename
#define HTTP_BUILD_FILEPATH(dest, path, fname) t2_build_filename(dest, sizeof(dest), T2_ENV_VAL(HTTP_PATH), env[path].val, fname, NULL)

#define HTTP_SPKTMD_PRI(httpFlowP) \
    if (sPktFile) { \
        fprintf(sPktFile, \
                "0x%04" B2T_PRIX16 /* httpStat      */ SEP_CHR \
                "0x%04" B2T_PRIX16 /* httpAFlags    */ SEP_CHR \
                "0x%02" B2T_PRIX8  /* httpMethods   */ SEP_CHR \
                "0x%04" B2T_PRIX16 /* httpHeadMimes */ SEP_CHR \
                , (uint16_t)((httpFlowP)->flags & ~HTTP_F_HTTP_HDR) \
                , (httpFlowP)->aFlags \
                , (httpFlowP)->httpMethods \
                , (httpFlowP)->mimeTypes \
        ); \
        if (HTTP_BODY) { \
            fprintf(sPktFile, \
                    "0x%04" B2T_PRIX16 /* httpCFlags */ SEP_CHR \
                    , (httpFlowP)->cFlags); \
        } \
    }


// Static variables

static http_flow_t *http_flow;
static uint64_t totalHttpPktCnt, totalHttpPktCnt0;
static uint64_t httpGetCnt, httpPstCnt;
static uint16_t httpAStat, httpAFlags, httpCFlags, httpHeadMimes;
static uint32_t imageCnt, videoCnt, audioCnt, textCnt, msgCnt, applCnt, unkCnt;

#if HTTP_SAVE == 1
static t2_env_t env[ENV_HTTP_N];

static int32_t http_fd_cnt, http_fd_max;

static struct {
    int save;
    char *path;
} http_dirs[] = {
    { HTTP_SAVE_IMAGE, HTTP_IMAGE_PATH, },
    { HTTP_SAVE_VIDEO, HTTP_VIDEO_PATH, },
    { HTTP_SAVE_AUDIO, HTTP_AUDIO_PATH, },
    { HTTP_SAVE_MSG  , HTTP_MSG_PATH,   },
    { HTTP_SAVE_TEXT , HTTP_TEXT_PATH,  },
    { HTTP_SAVE_APPL , HTTP_APPL_PATH   },
    { HTTP_SAVE_PUNK , HTTP_PUNK_PATH,  },
    { INT_MAX        , NULL             }
};
#endif // HTTP_SAVE == 1

typedef struct {
    const char    *name;
    const size_t   len;
    const uint8_t  hex;
} http_method_t;

static const http_method_t http_methods[] = {
    { SGET    , sizeof(SGET)    , GET     },
    { SPOST   , sizeof(SPOST)   , POST    },
    { SOPTIONS, sizeof(SOPTIONS), OPTIONS },
    { SDELETE , sizeof(SDELETE) , DELETE  },
    { SPUT    , sizeof(SPUT)    , PUT     },
    { SHEAD   , sizeof(SHEAD)   , HEAD    },
    { SCONNECT, sizeof(SCONNECT), CONNECT },
    { STRACE  , sizeof(STRACE)  , TRACE   },
    { /* NULL */ }
};


// local function prototype declarations

/* Return size of HTTP header line
 * Arguments:
 *  - data    : the packet data
 *  - data_len: length of packet (data-field)
 */
static char* http_get_linesize(char *data, int32_t data_len);

/* Analyze HTTP method
 * Return the found method
 * Arguments:
 *  - data: the packet data
 *  - data_len: length of packet (data-field)
 */
static http_mimetype http_read_mimetype(const char *data, size_t data_len);

/* Read header-field
 * Return data of the specified header field in header
 * Arguments:
 *  - data   : the packet data
 *  - header : the lookup-header field
 */
static char* http_read_header_data(char* data, uint16_t data_len, const char *header, uint16_t header_len);


// Tranalyzer functions

T2_PLUGIN_INIT("httpSniffer", "0.9.3", 0, 9);


void t2Init() {
    T2_PLUGIN_STRUCT_NEW(http_flow);

#if HTTP_SAVE == 1
#if ENVCNTRL > 0
    t2_get_env(PLUGIN_SRCH, ENV_HTTP_N, env);
    const uint8_t http_rmdir = T2_ENV_VAL_UINT(HTTP_RMDIR);
#else // ENVCNTRL == 0
    const uint8_t http_rmdir = HTTP_RMDIR;
    T2_SET_ENV_STR(HTTP_PATH);
    //T2_SET_ENV_NUM(HTTP_RMDIR);
    T2_SET_ENV_STR(HTTP_IMAGE_PATH);
    T2_SET_ENV_STR(HTTP_VIDEO_PATH);
    T2_SET_ENV_STR(HTTP_AUDIO_PATH);
    T2_SET_ENV_STR(HTTP_MSG_PATH);
    T2_SET_ENV_STR(HTTP_TEXT_PATH);
    T2_SET_ENV_STR(HTTP_APPL_PATH);
    T2_SET_ENV_STR(HTTP_PUNK_PATH);
#endif // ENVCNTRL

    for (uint_fast8_t i = ENV_HTTP_IMAGE_PATH, j = 0; i != ENV_HTTP_N; i++, j++) {
        http_dirs[j].path = env[i].val;
    }

    char path[FILENAME_MAX];
    for (uint_fast8_t i = 0; http_dirs[i].save != INT_MAX && http_dirs[i].path != NULL; i++) {
        if (http_dirs[i].save == 0) continue;

        t2_build_filename(path, sizeof(path), T2_ENV_VAL(HTTP_PATH), http_dirs[i].path, NULL);
        T2_MKPATH(path, http_rmdir);
    }
#endif // HTTP_SAVE == 1

    if (sPktFile) {
        fputs("httpStat"      SEP_CHR
              "httpAFlags"    SEP_CHR
              "httpMethods"   SEP_CHR
              "httpHeadMimes" SEP_CHR

#if HTTP_BODY == 1
              "httpCFlags"    SEP_CHR
#endif // HTTP_BODY == 1
              , sPktFile);
    }
}


binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;

    BV_APPEND_H16(bv, "httpStat"     , "HTTP status");
    BV_APPEND_H16(bv, "httpAFlags"   , "HTTP anomaly flags");
    BV_APPEND_H8( bv, "httpMethods"  , "HTTP methods in flow");
    BV_APPEND_H16(bv, "httpHeadMimes", "HTTP HEADMIME-TYPES in flow");

#if HTTP_BODY == 1
    BV_APPEND_H16(bv, "httpCFlags", "HTTP content info in flow");
#endif // HTTP_BODY == 1

#if HTTP_MCNT == 1
    BV_APPEND(bv, "httpGet_Post", "HTTP number of GET and POST requests", 2, bt_uint_16, bt_uint_16);
#endif // HTTP_MCNT == 1

#if HTTP_STAT == 1
    BV_APPEND_U16(bv  , "httpRSCnt" , "HTTP response status count");
    BV_APPEND_U16_R(bv, "httpRSCode", "HTTP response status code");
#endif // HTTP_STAT == 1

    BV_APPEND(bv, "httpURL_Via_Loc_Srv_Pwr_UAg_XFr_Ref_Cky_Mim", "HTTP number of URLs, Via, Location, Server, Powered By, User-Agent, X-Forwarded-For, Referer, Cookie and Mime-Type", 10, bt_uint_16, bt_uint_16, bt_uint_16, bt_uint_16, bt_uint_16, bt_uint_16, bt_uint_16, bt_uint_16, bt_uint_16, bt_uint_16);

    BV_APPEND(bv, "httpImg_Vid_Aud_Msg_Txt_App_Unk", "HTTP number of images, videos, audios, messages, texts, applications and unknown", 7, bt_uint_16, bt_uint_16, bt_uint_16, bt_uint_16, bt_uint_16, bt_uint_16, bt_uint_16);

#if HTTP_HOST == 1
    BV_APPEND_STR_R(bv, "httpHosts", "HTTP Host names");
#endif // HTTP_HOST == 1

#if HTTP_URL == 1
    BV_APPEND_STR_R(bv, "httpURL", "HTTP URLs");
#endif // HTTP_URL == 1

#if HTTP_MIME == 1
    BV_APPEND_STR_R(bv, "httpMimes", "HTTP MIME-types");
#endif // HTTP_MIME == 1

#if HTTP_COOKIE == 1
    BV_APPEND_STR_R(bv, "httpCookies", "HTTP cookies");
#endif // HTTP_COOKIE == 1

#if HTTP_IMAGE == 1
    BV_APPEND_STR_R(bv, "httpImages", "HTTP images");
#endif // HTTP_IMAGE == 1

#if HTTP_VIDEO == 1
    BV_APPEND_STR_R(bv, "httpVideos", "HTTP videos");
#endif // HTTP_VIDEO == 1

#if HTTP_AUDIO == 1
    BV_APPEND_STR_R(bv, "httpAudios", "HTTP audios");
#endif // HTTP_AUDIO == 1

#if HTTP_MSG == 1
    BV_APPEND_STR_R(bv, "httpMsgs", "HTTP messages");
#endif // HTTP_MSG == 1

#if HTTP_APPL == 1
    BV_APPEND_STR_R(bv, "httpAppl", "HTTP applications");
#endif // HTTP_APPL == 1

#if HTTP_TEXT == 1
    BV_APPEND_STR_R(bv, "httpText", "HTTP texts");
#endif // HTTP_TEXT == 1

#if HTTP_PUNK == 1
    BV_APPEND_STR_R(bv, "httpPunk", "HTTP payload unknown");
#endif // HTTP_PUNK == 1

#if (HTTP_BODY == 1 && HTTP_BDURL == 1)
    BV_APPEND_STR_R(bv, "httpBdyURL", "HTTP body: Refresh, Set-Cookie URL");
#endif // (HTTP_BODY == 1 && HTTP_BDURL == 1)

#if HTTP_USRAG == 1
    BV_APPEND_STR_R(bv, "httpUsrAg", "HTTP User-Agent");
#endif // HTTP_USRAG

#if HTTP_XFRWD == 1
    BV_APPEND_STR_R(bv, "httpXFor", "HTTP X-Forwarded-For");
#endif // HTTP_XFRWD

#if HTTP_REFRR == 1
    BV_APPEND_STR_R(bv, "httpRefrr", "HTTP Referer");
#endif // HTTP_REFRR

#if HTTP_VIA == 1
    BV_APPEND_STR_R(bv, "httpVia", "HTTP Via (Proxy)");
#endif // HTTP_VIA

#if HTTP_LOC == 1
    BV_APPEND_STR_R(bv, "httpLoc", "HTTP Location (Redirection)");
#endif // HTTP_LOC

#if HTTP_SERV == 1
    BV_APPEND_STR_R(bv, "httpServ", "HTTP Server");
#endif // HTTP_SERV

#if HTTP_PWR == 1
    BV_APPEND_STR_R(bv, "httpPwr", "HTTP Powered By");
#endif // HTTP_PWR == 1

#if HTTP_AVAST_CID == 1
    BV_APPEND_STR(bv, "httpAvastCid", "HTTP Avast Client ID");
#endif // HTTP_AVAST_CID

#if HTTP_ESET_UID == 1
    BV_APPEND_STR(bv, "httpEsetUid", "HTTP ESET Update ID");
#endif // HTTP_ESET_UID

    return bv;
}


void t2OnNewFlow(packet_t *packet, unsigned long flowIndex) {
    http_flow_t * const httpFlowP = &http_flow[flowIndex];
    memset(httpFlowP, '\0', sizeof(http_flow_t));

    httpFlowP->flags = HTTP_F_HTTP_HDR;

    const uint_fast8_t proto = packet->l4Proto;
    const flow_t * const flowP = &flows[flowIndex];

    if (proto == L3_TCP
#if SCTP_ACTIVATE > 0
        || proto == L3_SCTP
#endif // SCTP_ACTIVATE > 0
        || (proto == L3_UDP && (flowP->srcPort > 1024 || flowP->dstPort > 1024)))
    {
        httpFlowP->cFlags |= HTTP_PCNT;
    }
}


#if ETH_ACTIVATE > 0
void t2OnLayer2(packet_t *packet UNUSED, unsigned long flowIndex) {
    if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;
    http_flow_t * const httpFlowP = &http_flow[flowIndex];
    HTTP_SPKTMD_PRI(httpFlowP);
}
#endif // ETH_ACTIVATE > 0


void t2OnLayer4(packet_t* packet, unsigned long flowIndex) {
    http_flow_t * const httpFlowP = &http_flow[flowIndex];
    if (!(httpFlowP->cFlags & HTTP_PCNT)) {
        HTTP_SPKTMD_PRI(httpFlowP);
        return;
    }

    uint16_t data_len = packet->snapL7Len; // length of http_data (if there is)
    if (data_len == 0) {
        HTTP_SPKTMD_PRI(httpFlowP);
        return;
    }

    char *data_ptr = (char*)packet->l7HdrP;
    if (!data_ptr) {
        HTTP_SPKTMD_PRI(httpFlowP);
        return;
    }

    // size of current line (if 0 header is completely read)
    char *line_eptr = http_get_linesize(data_ptr, data_len);
    uint16_t line_size = ((line_eptr) ? (uint16_t)(line_eptr - data_ptr) : 0);

    httpFlowP->pktcnt++;
    if (httpFlowP->flags & (HTTP_F_DETECT | HTTP_F_HTTP_HDR | HTTP_F_HTTP)) totalHttpPktCnt++;

    if ((httpFlowP->flags & HTTP_F_DETECT) && data_len >= 2 && *(uint16_t*)data_ptr == 0x5a4d) httpFlowP->aFlags |= HTTP_A_DEXE;

    if (!(httpFlowP->flags & HTTP_F_PLD_S) && !line_eptr) {
        HTTP_SPKTMD_PRI(httpFlowP);
        return;
    }

    uint32_t i, k;
    uint16_t linesz;
    char *http_header_data = NULL, *p = NULL;
    const flow_t * const flowP = &flows[flowIndex];

#if HTTP_SAVE == 1 || HTTP_DATA == 1 || HTTP_URL == 1 || \
    (HTTP_BODY == 1 && HTTP_TEXT == 1 && HTTP_BDURL == 1)
    char *name_p = NULL;
#endif

#if HTTP_SAVE == 1
    char imfilename[HTTP_MXIMNM_LEN+1] = {};
#endif // HTTP_SAVE == 1

    // check whether opposite flow exists
    http_flow_t * const httpFlowPO = (FLOW_HAS_OPPOSITE(flowP) ? &(http_flow[flowP->oppositeFlowIndex]) : NULL);

    // HTTP-HEADER-Parsing
#if HTTP_SAVE == 1
hdrbgn:
#endif // HTTP_SAVE == 1

    if (line_size > 0 && httpFlowP->flags & HTTP_F_HTTP_HDR) {
#if HTTP_STAT == 1
        uint_fast8_t stat_code_pos = 9; // Expected position of status code: HTTP/1.x 200 OK
#endif // HTTP_STAT == 1                                                          ^
        // first line: identify http-flow, e.g., HTTP/1.x 200 OK or SIP/x.x 200 OK or GET / HTTP/1.x, ...
        if (data_len >= sizeof(HTTP_ID)) { // Is there enough data for HTTP/1.x?
            http_header_data = memmem(data_ptr, data_len, HTTP_ID, sizeof(HTTP_ID)-1); // find end of url
            if (http_header_data) { // HTTP/1.x found
                if (http_header_data[7] == '0') httpFlowP->aFlags |= HTTP_A_1_0; // HTTP/1.0
            } else { // HTTP/1. not found... search for SIP (for simplicity, we assume the header contains one more character than SIP/1.x)
                http_header_data = memmem(data_ptr, data_len, SIP_ID, sizeof(SIP_ID)-1); // find end of url
                if (http_header_data) { // SIP/x.x found
                    packet->status |= L7_SIPRTP;
                    globalWarn |= L7_SIPRTP;
#if HTTP_STAT == 1
                    stat_code_pos = 8;
#endif // HTTP_STAT == 1
                }
            }
        }

        if (!http_header_data || http_header_data - data_ptr >= data_len) { // HTTP or SIP not found
            // no HTTP or SIP header present
            if (!(httpFlowP->flags & HTTP_F_DETECT)) {
                httpFlowP->flags |= HTTP_F_HTTP_HDR;
            }
        } else { // HTTP or SIP found
            httpFlowP->flags &= ~HTTP_F_S;
            httpFlowP->flags |= (HTTP_F_DETECT | HTTP_F_HTTP_HDR | HTTP_F_HTTP);

#if HTTP_STAT == 1
            // HTTP status (response)
            // TODO make sure there is enough data to read
            if (http_header_data[stat_code_pos-1] == ' ') {
                char h[4] = {};
                memcpy(h, http_header_data + stat_code_pos, 3);
                const uint16_t j = strtoul(h, NULL, 0);
                k = httpFlowP->stat_c;

#if HTTP_STATAGA == 1
                for (i = 0; i < k; i++) {
                    // Status code already exists
                    if (httpFlowP->stat[i] == j) break;
                }

                if (i == k) {
#endif // HTTP_STATAGA == 1
                    if (k >= HTTP_DATA_C_MAX) {
                        httpFlowP->flags |= HTTP_F_OVRFLW;
                    } else {
                        httpFlowP->stat[httpFlowP->stat_c] = j;
                    }

                    httpFlowP->stat_c++;
#if HTTP_STATAGA == 1
                }
#endif // HTTP_STATAGA == 1
            }
#endif // HTTP_STAT == 1

            // look for HTTP methods
            uint_fast8_t method = 0;
            for (i = 0; http_methods[i].name; i++) {
                if (memcmp(data_ptr, http_methods[i].name, http_methods[i].len-1) == 0) {
                    p = data_ptr + http_methods[i].len;
                    method = http_methods[i].hex;
                    httpFlowP->httpMethods |= method;
                    if (method == GET) httpFlowP->getCnt++;
                    else if (method == POST) httpFlowP->pstCnt++;
                    break;
                }
            }

            httpFlowP->httpLastMeth = method;

            if (method) {
                // search for space after URL
                uint32_t namelen = 0;
                while (namelen < data_len - (p - data_ptr) && p[namelen] != ' ') ++namelen;
                //if (!namelen) namelen = data_len;
                if (namelen > 0) {
#if HTTP_URL == 0
                    httpFlowP->url_c++;
#else // HTTP_URL == 1
                    k = httpFlowP->url_c;

                    if (k >= HTTP_DATA_C_MAX) {
                        httpFlowP->flags |= HTTP_F_OVRFLW;
                    } else {
#if HTTP_URLAGA == 1
                        for (i = 0; i < k; i++) {
                            // URL already exists
                            if (namelen == strlen(httpFlowP->url[i]) && memcmp(httpFlowP->url[i], p, namelen) == 0) break;
                        }

                        if (i == k) { // Not found
#endif // HTTP_URLAGA == 1
                            name_p = httpFlowP->url[k] = t2_malloc_fatal(namelen + 1);
                            memcpy(name_p, p, namelen);
                            name_p[namelen] = '\0';
                            if (method == POST && !(httpFlowP->aFlags & HTTP_A_PST) && memchr(name_p, '?', namelen)) httpFlowP->aFlags |= HTTP_A_PST;
#if HTTP_ANTVIR == 1
                            if (!(httpFlowP->cFlags & HTTP_MSEC)) {
                                if (memmem(name_p, namelen, UMSECD, sizeof(UMSECD)-1) ||
                                    memmem(name_p, namelen, UMSEC , sizeof(UMSEC) -1))
                                {
                                    httpFlowP->cFlags |= HTTP_MSEC;
                                }
                            }
#endif // HTTP_ANTVIR == 1
                            httpFlowP->url_c++;
#if HTTP_URLAGA == 1
                        }
#endif // HTTP_URLAGA == 1
                    }
#endif // HTTP_URL == 1

                    //if (method == GET) {
                        if (namelen >= HTTP_MXFILE_LEN) {
                            namelen = HTTP_MXFILE_LEN;
                            httpFlowP->flags |= HTTP_F_FNM_LN;
                        }

                        // copy getfile
                        memcpy(httpFlowP->getFile, p, namelen);
                        httpFlowP->getFile[namelen] = '\0';

                        httpFlowP->flags |= HTTP_F_GET; // finally set hasget-flag to true
                    //}
                }
            }
        } // end if HTTP or SIP found
    }

    while (line_size > 0 && httpFlowP->flags & HTTP_F_HTTP_HDR && line_eptr) {
        // continue parsing http-header
        if (httpFlowP->flags & HTTP_F_HTTP_HDR) {

            if (httpFlowP->cFlags & HTTP_BOUND && !(httpFlowP->cFlags & HTTP_QUARA)) {
                if (memmem(data_ptr, data_len, QUARANTINE, sizeof(QUARANTINE)-1)) httpFlowP->cFlags |= HTTP_QUARA;
            }

            // Mime-Type-sniffing
            http_header_data = http_read_header_data(data_ptr, data_len, CONTENT_TYPE, sizeof(CONTENT_TYPE)-1);

            if (http_header_data) {
                // save mime type and boundary marker
#if HTTP_MIME == 1
                if (httpFlowP->mime_c >= HTTP_DATA_C_MAX) {
                    httpFlowP->flags |= HTTP_F_OVRFLW;
                } else {
                    linesz = (uint16_t)(line_eptr - http_header_data);
                    for (i = 0; i < linesz; i++) {
                        if (http_header_data[i] == ';') {
                            //if (http_header_data[i+1] == '\r') {
                            //  i += 2;
                            //  k = ;
                            //}
                            p = memmem(&http_header_data[i+1], linesz, BOUNDARY, sizeof(BOUNDARY)-1);
                            if (p) {
                                /*httpFlowP->bound = t2_malloc_fatal(linesz + 1);
                                k = (int)(line_eptr-p) - sizeof(BOUNDARY) -1;
                                memcpy(httpFlowP->bound, p+sizeof(BOUNDARY)+1, k);
                                httpFlowP->bound[k] = '\0';*/
                                httpFlowP->cFlags |= HTTP_BOUND;
                            }

                            linesz = i;
                            break;
                        }
                    }

#if HTTP_MIMEAGA == 1
                    k = httpFlowP->mime_c;
                    for (i = 0; i < k; i++) {
                        if (!strncmp(httpFlowP->mime[i], http_header_data, linesz)) break;
                    }

                    if (i == k) {
#endif // HTTP_MIMEAGA == 1
                        httpFlowP->mime[httpFlowP->mime_c] = t2_malloc_fatal(linesz + 1); // alloc space for mime-type
                        memcpy(httpFlowP->mime[httpFlowP->mime_c], http_header_data, linesz); // copy mime type..
                        httpFlowP->mime[httpFlowP->mime_c++][linesz] = '\0';
                        if (strlen(httpFlowP->mime[httpFlowP->mime_c-1]) == 0) httpFlowP->aFlags |= HTTP_A_HDR_WO_VAL;
#if HTTP_MIMEAGA == 1
                    }
#endif // HTTP_MIMEAGA == 1
                }
#endif // HTTP_MIME == 1

                // do mimetype based actions
                const http_mimetype mimetype = http_read_mimetype(http_header_data, line_eptr - http_header_data);
                httpFlowP->mimeTypes |= mimetype; // add to seen mimetypes

                if (httpFlowPO && (httpFlowPO->flags & HTTP_F_GET)) {
                    //if (httpFlowPO->httpLastMeth == POST) goto dshdr;
                    p = httpFlowPO->getFile;
                } else {
                    p = httpFlowP->getFile;
                }

#if HTTP_SAVE_PUNK == 1
                if (strncmp(http_header_data, AVAST_SND_MIME, line_eptr - http_header_data) == 0) {
                    httpFlowP->cFlags |= HTTP_AV_SAMPLE;
                }
#endif // HTTP_SAVE_PUNK == 1

                switch (mimetype) {
                    case HTTP_C_IMAGE:
#if (HTTP_IMAGE == 1 || HTTP_SAVE_IMAGE == 1)
                        if (httpFlowP->image_c >= HTTP_DATA_C_MAX) {
                            httpFlowP->flags |= HTTP_F_OVRFLW;
                        } else {
                            HTTP_BUILD_FILENAME(name_p, p, httpFlowP->image_c);
                            httpFlowP->image[httpFlowP->image_c] = name_p;
#if HTTP_SAVE_IMAGE == 1
                            remove(name_p);
                            httpFlowP->flags |= HTTP_F_PLD_IMG_S; // start sniffing content..
#endif // HTTP_SAVE_IMAGE == 1
                        }
#endif // (HTTP_IMAGE == 1 || HTTP_SAVE_IMAGE == 1)

                        httpFlowP->image_c++;
                        break;

                    case HTTP_C_MSG:
#if (HTTP_MSG == 1 || HTTP_SAVE_MSG == 1)
                        if (httpFlowP->msg_c >= HTTP_DATA_C_MAX) {
                            httpFlowP->flags |= HTTP_F_OVRFLW;
                        } else {
                            HTTP_BUILD_FILENAME(name_p, p, httpFlowP->msg_c);
                            httpFlowP->msg[httpFlowP->msg_c] = name_p;
#if HTTP_SAVE_MSG == 1
                            remove(name_p);
                            httpFlowP->flags |= HTTP_F_PLD_MSG_S; // start sniffing content..
#endif // HTTP_SAVE_MSG == 1
                        }
#endif // (HTTP_MSG == 1 || HTTP_SAVE_MSG == 1)

                        httpFlowP->msg_c++;
                        break;

                    case HTTP_C_TEXT:
#if (HTTP_TEXT == 1 || HTTP_SAVE_TEXT == 1)
                        if (httpFlowP->text_c >= HTTP_DATA_C_MAX) {
                            httpFlowP->flags |= HTTP_F_OVRFLW;
                        } else {
                            HTTP_BUILD_FILENAME(name_p, p, httpFlowP->text_c);
                            httpFlowP->text[httpFlowP->text_c] = name_p;
#if HTTP_SAVE_TEXT == 1
                            remove(name_p);
                            httpFlowP->flags |= HTTP_F_PLD_TXT_S; // start sniffing content..
#endif // HTTP_SAVE_TEXT == 1
                        }
#endif // (HTTP_TEXT == 1 || HTTP_SAVE_TEXT == 1)

                        httpFlowP->text_c++;
                        break;

                    case HTTP_C_VIDEO:
#if (HTTP_VIDEO == 1 || HTTP_SAVE_VIDEO == 1)
                        if (httpFlowP->cFlags & HTTP_STRM1) {
                            httpFlowP->flags |= HTTP_F_PLD_VID_S; // start sniffing content..
                            break;
                        }

                        if (httpFlowP->video_c >= HTTP_DATA_C_MAX) {
                            httpFlowP->flags |= HTTP_F_OVRFLW;
                        } else {
                            HTTP_BUILD_FILENAME(name_p, p, httpFlowP->video_c);
                            httpFlowP->video[httpFlowP->video_c] = name_p;
#if HTTP_SAVE_VIDEO == 1
                            remove(name_p);
                            httpFlowP->flags |= HTTP_F_PLD_VID_S; // start sniffing content..
#endif // HTTP_SAVE_VIDEO == 1
                        }

                        if (httpFlowP->cFlags & HTTP_STRM) httpFlowP->cFlags |= HTTP_STRM1;
#endif // (HTTP_VIDEO == 1 || HTTP_SAVE_VIDEO == 1)

                        httpFlowP->video_c++;
                        break;

                    case HTTP_C_AUDIO:
#if (HTTP_AUDIO == 1 || HTTP_SAVE_AUDIO == 1)
                        if (httpFlowP->audio_c >= HTTP_DATA_C_MAX) {
                            httpFlowP->flags |= HTTP_F_OVRFLW;
                        } else {
                            HTTP_BUILD_FILENAME(name_p, p, httpFlowP->audio_c);
                            httpFlowP->audio[httpFlowP->audio_c] = name_p;
#if HTTP_SAVE_AUDIO == 1
                            remove(name_p);
                            httpFlowP->flags |= HTTP_F_PLD_AUD_S; // start sniffing content..
#endif // HTTP_SAVE_AUDIO == 1
                        }
#endif // (HTTP_AUDIO == 1 || HTTP_SAVE_AUDIO == 1)

                        httpFlowP->audio_c++;
                        break;

                    case HTTP_C_APPL:
#if (HTTP_APPL == 1 || HTTP_SAVE_APPL == 1)
                        if (httpFlowP->appl_c >= HTTP_DATA_C_MAX) {
                            httpFlowP->flags |= HTTP_F_OVRFLW;
                        } else {
                            HTTP_BUILD_FILENAME(name_p, p, httpFlowP->appl_c);
                            httpFlowP->appl[httpFlowP->appl_c] = name_p;
#if HTTP_SAVE_APPL == 1
                            remove(name_p);
                            httpFlowP->flags |= HTTP_F_PLD_APP_S; // start sniffing content..
#endif // HTTP_SAVE_APPL == 1
                        }
#endif // (HTTP_APPL == 1 || HTTP_SAVE_APPL == 1)

                        httpFlowP->appl_c++;
                        break;

                    default:
#if (HTTP_PUNK == 1 || HTTP_SAVE_PUNK == 1)
                        if (memmem(data_ptr, data_len, UPLOAD, sizeof(UPLOAD)-1)) httpFlowP->cFlags |= HTTP_QUARA;

                        if (httpFlowP->unknwn_c >= HTTP_DATA_C_MAX) {
                            httpFlowP->flags |= HTTP_F_OVRFLW;
                        } else {
                            HTTP_BUILD_FILENAME(name_p, p, httpFlowP->unknwn_c);
                            httpFlowP->punk[httpFlowP->unknwn_c] = name_p;
#if HTTP_SAVE_PUNK == 1
                            remove(name_p);
                            httpFlowP->flags |= HTTP_F_PLD_PUNK_S; // start sniffing content..
#endif // HTTP_SAVE_PUNK == 1
                        }
#endif // (HTTP_PUNK == 1 || HTTP_SAVE_PUNK == 1)

                        httpFlowP->unknwn_c++;
                        break;
                }
            }

//dshdr:
            // Content Disposition
            http_header_data = http_read_header_data(data_ptr, data_len, CONTENT_DISP, sizeof(CONTENT_DISP)-1);
            if (http_header_data) {
                linesz = (uint16_t)(line_eptr - http_header_data);
                p = memmem(http_header_data, linesz, FILENAME, sizeof(FILENAME)-1);
                if (p) {
                    k = linesz - sizeof(FILENAME);
                    *line_eptr = '\0';
                    uint8_t *start = (uint8_t*)&p[sizeof(FILENAME)-1];

                    // skip optional leading quote
                    if (*start == '"') {
                        start++;
                        k--;
                    }

                    // Remove optional trailing quote
                    bool requote = false;
                    if (*(line_eptr-1) == '"') {
                        requote = true;
                        *(line_eptr-1) = '\0';
                        k--;
                    }

                    if (k >= HTTP_MXFILE_LEN) k = HTTP_MXFILE_LEN;

                    memcpy(httpFlowP->getFile, start, k);
                    httpFlowP->getFile[HTTP_MXFILE_LEN] = '\0';

                    // Put back optional trailing quote
                    if (requote) *(line_eptr-1) = '"';
                    *line_eptr = '\r';

                    // replace forward and backward slashes with underscores
                    for (i = 0; i <= k; i++) {
                        if (httpFlowP->getFile[i] == '/' || httpFlowP->getFile[i] == '\\') httpFlowP->getFile[i] = '_';
                    }
                }
            }

            // Content-Length extraction
            http_header_data = http_read_header_data(data_ptr, data_len, CONTENT_LENGTH, sizeof(CONTENT_LENGTH)-1);
            if (http_header_data) {
                *line_eptr = '\0';
                httpFlowP->contentLength = atoi(http_header_data);
                *line_eptr = '\r';
            }

            // Transfer-Encoding extraction
            http_header_data = http_read_header_data(data_ptr, data_len, TRANS_ENCODING, sizeof(TRANS_ENCODING)-1);
            if (http_header_data) {
                *line_eptr = '\0';
                if (strstr(http_header_data, "chunked")) httpFlowP->flags |= HTTP_F_CHKD;
                *line_eptr = '\r';
            }

            // host extraction
            if (httpFlowP->host_c >= HTTP_DATA_C_MAX) { // host limit?
                httpFlowP->flags |= HTTP_F_OVRFLW;
            } else {
                http_header_data = http_read_header_data(data_ptr, data_len, HOST, sizeof(HOST)-1);
                if (http_header_data) {
#if HTTP_HOST == 1 || HTTP_SAVE_PUNK == 1
                    linesz = (uint16_t)(line_eptr - http_header_data);
#if HTTP_SAVE_PUNK == 1
                    if (memmem(http_header_data, linesz, AVIRA_SND_HOST, sizeof(AVIRA_SND_HOST)-1)) {
                        httpFlowP->cFlags |= HTTP_AV_SAMPLE;
                    }
#endif // HTTP_SAVE_PUNK == 1
#endif // HTTP_HOST == 1 || HTTP_SAVE_PUNK == 1
#if HTTP_HOST == 0
                    httpFlowP->host_c++;
#else // HTTP_HOST == 1
#if HTTP_ANTVIR == 1
                         if (!(httpFlowP->cFlags & HTTP_AVIRA) && memmem(http_header_data, linesz, UAVIRA, sizeof(UAVIRA)-1)) httpFlowP->cFlags |= HTTP_AVIRA;
                    else if (!(httpFlowP->cFlags & HTTP_AVAST) && memmem(http_header_data, linesz, UAVAST, sizeof(UAVAST)-1)) httpFlowP->cFlags |= HTTP_AVAST;
                    else if (!(httpFlowP->cFlags & HTTP_AVG)   && memmem(http_header_data, linesz, UAVG  , sizeof(UAVG)  -1)) httpFlowP->cFlags |= HTTP_AVG;
                    else if (!(httpFlowP->cFlags & HTTP_BITDF) && memmem(http_header_data, linesz, UBITDF, sizeof(UBITDF)-1)) httpFlowP->cFlags |= HTTP_BITDF;
                    else if (!(httpFlowP->cFlags & HTTP_ESET)  && memmem(http_header_data, linesz, UESET , sizeof(UESET) -1)) httpFlowP->cFlags |= HTTP_ESET;
                    else if (!(httpFlowP->cFlags & HTTP_SYM)   && memmem(http_header_data, linesz, USYM  , sizeof(USYM)  -1)) httpFlowP->cFlags |= HTTP_SYM;
#endif // HTTP_ANTVIR == 1

                    k = httpFlowP->host_c;

#if HTTP_HOSTAGA == 1
                    for (i = 0; i < k; i++) {
                        if (!strncmp(httpFlowP->host[i], http_header_data, linesz)) break;
                    }

                    if (i == k) {
#endif // HTTP_HOSTAGA == 1
                        httpFlowP->host[k] = t2_malloc_fatal(linesz + 1);
                        memcpy(httpFlowP->host[k], http_header_data, linesz);
                        httpFlowP->host[k][linesz] = '\0';

                        struct sockaddr_in s;
                        if (!(httpFlowP->aFlags & HTTP_A_HNUM) && inet_pton(AF_INET, httpFlowP->host[k], &(s.sin_addr))) {
                            httpFlowP->aFlags |= HTTP_A_HNUM;
                        }

                        httpFlowP->host_c++;
#if HTTP_HOSTAGA == 1
                    }
#endif // HTTP_HOSTAGA == 1
#endif // HTTP_HOST == 1
                }
            }

            // location extraction
            if (httpFlowP->loc_c >= HTTP_DATA_C_MAX) { // location limit?
                httpFlowP->flags |= HTTP_F_OVRFLW;
            } else {
                http_header_data = http_read_header_data(data_ptr, data_len, LOC, sizeof(LOC)-1);
                if (http_header_data) {
#if HTTP_LOC == 0
                    httpFlowP->loc_c++;
#else // HTTP_LOC == 1
                    linesz = (uint16_t)(line_eptr - http_header_data);
                    k = httpFlowP->loc_c;
#if HTTP_LOCA == 1
                    for (i = 0; i < k; i++) {
                        if (!strncmp(httpFlowP->loc[i], http_header_data, linesz)) break;
                    }

                    if (i == k) {
#endif // HTTP_LOCA == 1
                        httpFlowP->loc[k] = t2_malloc_fatal(linesz + 1);
                        memcpy(httpFlowP->loc[k], http_header_data, linesz);
                        httpFlowP->loc[k][linesz] = '\0';
                        httpFlowP->loc_c++;
#if HTTP_LOCA == 1
                    }
#endif // HTTP_LOCA == 1
#endif // HTTP_LOC == 1
                }
            }

            // via extraction
            if (httpFlowP->via_c >= HTTP_DATA_C_MAX) { // via limit?
                httpFlowP->flags |= HTTP_F_OVRFLW;
            } else {
                http_header_data = http_read_header_data(data_ptr, data_len, VIA, sizeof(VIA)-1);
                if (http_header_data) {
#if HTTP_VIA == 0
                    httpFlowP->via_c++;
#else // HTTP_VIA == 1
                    linesz = (uint16_t)(line_eptr - http_header_data);
                    k = httpFlowP->via_c;
#if HTTP_VIAA == 1
                    for (i = 0; i < k; i++) {
                        if (!strncmp(httpFlowP->via[i], http_header_data, linesz)) break;
                    }

                    if (i == k) {
#endif // HTTP_VIAA == 1
                        httpFlowP->via[k] = t2_malloc_fatal(linesz + 1);
                        memcpy(httpFlowP->via[k], http_header_data, linesz);
                        httpFlowP->via[k][linesz] = '\0';
                        httpFlowP->via_c++;
#if HTTP_VIAA == 1
                    }
#endif // HTTP_VIAA == 1
#endif // HTTP_VIA == 1
                }
            }

            // serv extraction
            if (httpFlowP->serv_c >= HTTP_DATA_C_MAX) { // serv limit?
                httpFlowP->flags |= HTTP_F_OVRFLW;
            } else {
                http_header_data = http_read_header_data(data_ptr, data_len, SERVER, sizeof(SERVER)-1);
                if (http_header_data) {
#if HTTP_SERV == 0
                    httpFlowP->serv_c++;
#else // HTTP_SERV == 1
                    linesz = (uint16_t)(line_eptr - http_header_data);
                    k = httpFlowP->serv_c;
#if HTTP_SERVA == 1
                    for (i = 0; i < k; i++) {
                        if (!strncmp(httpFlowP->serv[i], http_header_data, linesz)) break;
                    }

                    if (i == k) {
#endif // HTTP_SERVA == 1
                        httpFlowP->serv[k] = t2_malloc_fatal(linesz + 1);
                        memcpy(httpFlowP->serv[k], http_header_data, linesz);
                        httpFlowP->serv[k][linesz] = '\0';
                        httpFlowP->serv_c++;
#if HTTP_SERVA == 1
                    }
#endif // HTTP_SERVA == 1
#endif // HTTP_SERV == 1
                }
            }

            // poweredby extraction
            if (httpFlowP->pwr_c >= HTTP_DATA_C_MAX) { // poweredby limit?
                httpFlowP->flags |= HTTP_F_OVRFLW;
            } else {
                http_header_data = http_read_header_data(data_ptr, data_len, POWERED, sizeof(POWERED)-1);
                if (http_header_data) {
#if HTTP_PWR == 0
                    httpFlowP->pwr_c++;
#else // HTTP_PWR == 1
                    linesz = (uint16_t)(line_eptr - http_header_data);
                    k = httpFlowP->pwr_c;
#if HTTP_PWRA == 1
                    for (i = 0; i < k; i++) {
                        if (!strncmp(httpFlowP->pwr[i], http_header_data, linesz)) break;
                    }

                    if (i == k) {
#endif // HTTP_PWRA == 1
                        httpFlowP->pwr[k] = t2_malloc_fatal(linesz + 1);
                        memcpy(httpFlowP->pwr[k], http_header_data, linesz);
                        httpFlowP->pwr[k][linesz] = '\0';
                        httpFlowP->pwr_c++;
#if HTTP_PWRA == 1
                    }
#endif // HTTP_PWRA == 1
#endif // HTTP_PWR == 1
                }
            }

            // referer extraction
            if (httpFlowP->refrr_c >= HTTP_DATA_C_MAX) { // referer limit?
                httpFlowP->flags |= HTTP_F_OVRFLW;
            } else {
                http_header_data = http_read_header_data(data_ptr, data_len, REFERER, sizeof(REFERER)-1);
                if (http_header_data) {
#if HTTP_REFRR == 0
                    httpFlowP->refrr_c++;
#else // HTTP_REFRR == 1
                    linesz = (uint16_t)(line_eptr - http_header_data);
                    k = httpFlowP->refrr_c;
#if HTTP_REFRRA == 1
                    for (i = 0; i < k; i++) {
                        if (!strncmp(httpFlowP->refrr[i], http_header_data, linesz)) break;
                    }

                    if (i == k) {
#endif // HTTP_REFRRA == 1
                        httpFlowP->refrr[k] = t2_malloc_fatal(linesz + 1);
                        memcpy(httpFlowP->refrr[k], http_header_data, linesz);
                        httpFlowP->refrr[k][linesz] = '\0';
                        httpFlowP->refrr_c++;
#if HTTP_REFRRA == 1
                    }
#endif // HTTP_REFRRA == 1
#endif // HTTP_REFRR == 1
                }
            }

            // X-Site Scripting protection
            http_header_data = http_read_header_data(data_ptr, data_len, XXSSPROT, sizeof(XXSSPROT)-1);
            if (http_header_data) httpFlowP->aFlags |= HTTP_A_XSSP;

            // Content Security Policy
            http_header_data = http_read_header_data(data_ptr, data_len, CONTSECPOL, sizeof(CONTSECPOL)-1);
            if (http_header_data) httpFlowP->aFlags |= HTTP_A_CSP;

            // Do not track
            http_header_data = http_read_header_data(data_ptr, data_len, DNT, sizeof(DNT)-1);
            if (http_header_data) httpFlowP->aFlags |= HTTP_A_DNT;

        //} // if (httpFlowP->flags & HTTP_F_HTTP_HDR)

        // Cookie sniffing
        http_header_data = http_read_header_data(data_ptr, data_len, SET_COOKIE, sizeof(SET_COOKIE)-1);
        if (http_header_data) {
#if HTTP_COOKIE == 1
            // save cookie
            if (httpFlowP->cookie_c >= HTTP_DATA_C_MAX) { // cookie limit?
                httpFlowP->flags |= HTTP_F_OVRFLW;
            } else {
                linesz = (uint16_t)(line_eptr - http_header_data);
                httpFlowP->cookie[httpFlowP->cookie_c] = t2_malloc_fatal(linesz + 1);
                memcpy(httpFlowP->cookie[httpFlowP->cookie_c], http_header_data, linesz);
                httpFlowP->cookie[httpFlowP->cookie_c][linesz] = '\0';
#endif // HTTP_COOKIE = 1
                httpFlowP->cookie_c++;
#if HTTP_COOKIE == 1
            }
#endif // HTTP_COOKIE = 1
        }

        // User Agent
        http_header_data = http_read_header_data(data_ptr, data_len, USER_AGENT, sizeof(USER_AGENT)-1);
        if (http_header_data) {
#if HTTP_USRAG == 0
            httpFlowP->usrAg_c++;
#else // HTTP_USRAG == 1
            if (httpFlowP->usrAg_c >= HTTP_DATA_C_MAX) {
                httpFlowP->flags |= HTTP_F_OVRFLW;
            } else {
                linesz = MIN((uint16_t)(line_eptr - http_header_data), HTTP_MXUA_LEN);
                k = httpFlowP->usrAg_c;
#if HTTP_USRAGA == 1
                for (i = 0; i < k; i++) {
                    if (!strncmp(httpFlowP->usrAg[i], http_header_data, linesz)) break;
                }

                if (i == k) {
#endif // HTTP_USRAGA == 1
                    httpFlowP->usrAg[k] = t2_malloc_fatal(linesz + 1);
                    memcpy(httpFlowP->usrAg[k], http_header_data, linesz);
                    httpFlowP->usrAg[k][linesz] = '\0';
                    httpFlowP->usrAg_c++;
#if HTTP_USRAGA == 1
                }
#endif // HTTP_USRAGA == 1
            }
#endif // HTTP_USRAG == 1
        }

        // x-forward-for
        http_header_data = http_read_header_data(data_ptr, data_len, X_FORWRD_FOR, sizeof(X_FORWRD_FOR)-1);
        if (http_header_data) {
#if HTTP_XFRWD == 0
            httpFlowP->xFor_c++;
#else // HTTP_XFRWD == 1
            if (httpFlowP->xFor_c >= HTTP_DATA_C_MAX) {
                httpFlowP->flags |= HTTP_F_OVRFLW;
            } else {
                linesz = MIN((uint16_t)(line_eptr - http_header_data), HTTP_MXXF_LEN);
                k = httpFlowP->xFor_c;
#if HTTP_XFRWDA == 1
                for (i = 0; i < k; i++) {
                    if (!strncmp(httpFlowP->xFor[i], http_header_data, linesz)) break;
                }

                if (i == k) {
#endif // HTTP_XFRWDA == 1
                    httpFlowP->xFor[k] = t2_malloc_fatal(linesz + 1);
                    memcpy(httpFlowP->xFor[k], http_header_data, linesz);
                    httpFlowP->xFor[k][linesz] = '\0';
                    httpFlowP->xFor_c++;
#if HTTP_XFRWDA == 1
                }
#endif // HTTP_XFRWDA == 1
            }
#endif // HTTP_XFRWD == 1
        }

#if HTTP_AVAST_CID == 1
        // Avast client ID header
        if (httpFlowP->avastCid[0] == '\0') {
            http_header_data = http_read_header_data(data_ptr, data_len, AVAST_CID, sizeof(AVAST_CID)-1);
            if (http_header_data) {
                linesz = MIN((uint16_t)(line_eptr - http_header_data), HTTP_AVID_LEN-1);
                memcpy(httpFlowP->avastCid, http_header_data, linesz);
                httpFlowP->avastCid[linesz] = '\0';
            }
        }
#endif // HTTP_AVAST_CID == 1

#if HTTP_ESET_UID == 1
        // ESET update ID header
        if (httpFlowP->esetUid[0] == '\0') {
            http_header_data = http_read_header_data(data_ptr, data_len, ESET_UID, sizeof(ESET_UID)-1);
            if (http_header_data) {
                linesz = MIN((uint16_t)(line_eptr - http_header_data), HTTP_AVID_LEN-1);
                memcpy(httpFlowP->esetUid, http_header_data, linesz);
                httpFlowP->esetUid[linesz] = '\0';
            }
        }
#endif // HTTP_ESET_UID == 1

        } // if (httpFlowP->flags & HTTP_F_HTTP_HDR)

        // go to next line
        if (httpFlowP->flags & HTTP_F_HTTP_HDR) {
            data_ptr += (line_size + 2); // +2 skip line ending \r\n
            data_len -= (line_size + 2);

            // Get new linesize
            line_eptr = http_get_linesize(data_ptr, data_len);
            if (line_eptr) line_size = (uint16_t)(line_eptr - data_ptr); // size of current line (if 0 header is completely read)
            else line_size = 0;
        }
    } // end while

    // skip \r\n at end of http-header
    if (httpFlowP->flags & HTTP_F_HTTP_HDR) { // was in HTTP-Header
        if (data_len == 0 || line_eptr == NULL) {
            HTTP_SPKTMD_PRI(httpFlowP);
            return;
        }

        if (data_len < 2) {
            httpFlowP->aFlags |= HTTP_F_PRS_ERR; // Parse Error
        } else {
            data_ptr += 2; // skip \r\n
            data_len -= 2; // length of all body payload to come
        }

#if HTTP_SAVE == 1
        if (httpFlowP->fd) {
            file_manager_close(t2_file_manager, httpFlowP->fd);
            httpFlowP->fd = NULL;
            http_fd_cnt--;
        }

        if (httpFlowPO && httpFlowPO->httpLastMeth == HEAD) goto chkbdy;

        if (httpFlowP->flags & HTTP_F_CHKD) {
            line_eptr = http_get_linesize(data_ptr, data_len); // size of current line (if 0 header is completely read)
            if (line_eptr) line_size = (uint16_t)(line_eptr - data_ptr); // size of current line (if 0 header is completely read)
            else line_size = 0;
            if (line_eptr) {
                *line_eptr = '\0';
                int read = -1;
                sscanf(data_ptr, "%x%n", &(httpFlowP->contentLength), &read);
                // check for garbage after chunk length
                if (read != line_size) httpFlowP->contentLength = 0;
                *line_eptr = '\r';
                data_ptr += (line_size + 2); // +2 skip line ending \r\n
                data_len -= (line_size + 2); // +2 skip line ending \r\n
            }
        }

        httpFlowP->sniffedContent = 0;

        httpAStat |= httpFlowP->flags; // temp fix

        //if (httpFlowP->flags & HTTP_F_PLD_S && data_len <= (httpFlowP->contentLength - httpFlowP->sniffedContent)) {
        if (httpFlowP->flags & HTTP_F_PLD_S) {
            switch (httpFlowP->flags & HTTP_F_PLD_S) {
#if HTTP_SAVE_IMAGE == 1
                case HTTP_F_PLD_IMG_S:
                    if (httpFlowP->image_c > HTTP_DATA_C_MAX) {
                        HTTP_SPKTMD_PRI(httpFlowP);
                        return;
                    }

                    HTTP_BUILD_FILEPATH(imfilename, ENV_HTTP_IMAGE_PATH, httpFlowP->image[httpFlowP->image_c-1]);
                    break;
#endif // HTTP_SAVE_IMAGE == 1

#if HTTP_SAVE_VIDEO == 1
                case HTTP_F_PLD_VID_S:
                    if (httpFlowP->video_c > HTTP_DATA_C_MAX) {
                        HTTP_SPKTMD_PRI(httpFlowP);
                        return;
                    }

                    HTTP_BUILD_FILEPATH(imfilename, ENV_HTTP_VIDEO_PATH, httpFlowP->video[httpFlowP->video_c-1]);
                    break;
#endif // HTTP_SAVE_VIDEO == 1

#if HTTP_SAVE_AUDIO == 1
                case HTTP_F_PLD_AUD_S:
                    if (httpFlowP->audio_c > HTTP_DATA_C_MAX) {
                        HTTP_SPKTMD_PRI(httpFlowP);
                        return;
                    }

                    HTTP_BUILD_FILEPATH(imfilename, ENV_HTTP_AUDIO_PATH, httpFlowP->audio[httpFlowP->audio_c-1]);
                    break;
#endif // HTTP_SAVE_AUDIO == 1

#if HTTP_SAVE_MSG == 1
                case HTTP_F_PLD_MSG_S:
                    if (httpFlowP->msg_c > HTTP_DATA_C_MAX) {
                        HTTP_SPKTMD_PRI(httpFlowP);
                        return;
                    }

                    HTTP_BUILD_FILEPATH(imfilename, ENV_HTTP_MSG_PATH, httpFlowP->msg[httpFlowP->msg_c-1]);
                    break;
#endif // HTTP_SAVE_MSG == 1

#if HTTP_SAVE_TEXT == 1
                case HTTP_F_PLD_TXT_S:
                    if (httpFlowP->text_c > HTTP_DATA_C_MAX) {
                        HTTP_SPKTMD_PRI(httpFlowP);
                        return;
                    }

                    HTTP_BUILD_FILEPATH(imfilename, ENV_HTTP_TEXT_PATH, httpFlowP->text[httpFlowP->text_c-1]);
                    break;
#endif // HTTP_SAVE_TEXT == 1

#if HTTP_SAVE_APPL == 1
                case HTTP_F_PLD_APP_S:
                    if (httpFlowP->appl_c > HTTP_DATA_C_MAX) {
                        HTTP_SPKTMD_PRI(httpFlowP);
                        return;
                    }

                    HTTP_BUILD_FILEPATH(imfilename, ENV_HTTP_APPL_PATH, httpFlowP->appl[httpFlowP->appl_c-1]);
                    break;
#endif // HTTP_SAVE_APPL == 1

#if HTTP_SAVE_PUNK == 1
                case HTTP_F_PLD_PUNK_S:
                    if (httpFlowP->unknwn_c > HTTP_DATA_C_MAX) {
                        HTTP_SPKTMD_PRI(httpFlowP);
                        return;
                    }

#if HTTP_PUNK_AV_ONLY == 1
                    if (!(httpFlowP->cFlags & HTTP_AV_SAMPLE)) {
                        httpFlowP->flags &= ~HTTP_F_PLD_S;
                        goto chkbdy;
                    }
#endif // HTTP_PUNK_AV_ONLY == 1

                    HTTP_BUILD_FILEPATH(imfilename, ENV_HTTP_PUNK_PATH, httpFlowP->punk[httpFlowP->unknwn_c-1]);
                    break;
#endif // HTTP_SAVE_PUNK == 1

                default:
                    httpFlowP->flags &= ~HTTP_F_PLD_S;
                    goto chkbdy;
            }

            if (httpFlowP->cFlags & HTTP_STRM1) {
                if ((httpFlowP->fd = file_manager_open(t2_file_manager, imfilename, "r+b")) == NULL) {
                    httpFlowP->fd = file_manager_open(t2_file_manager, imfilename, "w+b");
                }
            } else {
                httpFlowP->fd = file_manager_open(t2_file_manager, imfilename, "w+b");
            }

            if (httpFlowP->fd == NULL) {
                static uint8_t svStat = 0;
                if (!svStat) {
                    T2_PERR(plugin_name, "Failed to open file '%s': %s", imfilename, strerror(errno));
                    svStat = 1;
                }
                HTTP_SPKTMD_PRI(httpFlowP);
                return;
            }

            httpFlowP->flags |= HTTP_F_SEQ_INIT;
            if (data_len) httpFlowP->flags |= HTTP_F_SHFT;
            httpFlowP->flags &= ~HTTP_F_HTTP_HDR;

            if (++http_fd_cnt > http_fd_max) http_fd_max = http_fd_cnt;
        }
#endif // HTTP_SAVE == 1
    }

#if HTTP_SAVE == 1
chkbdy:
#endif // HTTP_SAVE == 1

#if (HTTP_BODY == 1 && HTTP_TEXT == 1)
    if ((httpFlowP->mimeTypes & HTTP_C_TEXT)
#if HTTP_BDURL == 1
        && (httpFlowP->refURL_c < HTTP_DATA_C_MAX)
#endif // HTTP_BDURL == 1
    ) { // text
        char *dp;
        if ((dp = strnstr(data_ptr, "\"Refresh\"", data_len))) {
            for (i = 9; i < data_len - (dp - data_ptr); i++) {
                if (dp[i] == '>') {
                    char *dp1;
                    if ((dp1 = strnstr(dp + 9, "URL", i - 9))) {
                        httpFlowP->cFlags |= HTTP_REFRESH;
#if HTTP_BDURL == 1
                        char *dp2;
                        if ((dp2 = memchr(dp1 + 4, '"', dp + i - dp1 - 4))) {
                            const int32_t j = dp2 - dp1 - 4;
                            if (j > 0) {
                                name_p = t2_malloc_fatal(j + 1);
                                memcpy(name_p, dp1 + 4, j);
                                name_p[j] = '\0';
                                httpFlowP->refURL[httpFlowP->refURL_c++] = name_p;
                            }
                        }
#endif // HTTP_BDURL == 1
                    }
                    break;
                } // dp[i] == '>'
            }
        }
    }
#endif // (HTTP_BODY == 1 && HTTP_TEXT == 1)

    if (httpFlowP->flags & HTTP_F_DETECT) {
        if (data_len >= 2 && *(uint16_t*)data_ptr == 0x5a4d) httpFlowP->aFlags |= HTTP_A_DEXE;
        if (data_len >= 4 && *(uint32_t*)data_ptr == 0x464c4547) httpFlowP->aFlags |= HTTP_A_DELF;
        if (strnstr(data_ptr, STREAM_INF, data_len)) {
            httpFlowP->cFlags |= HTTP_STRM;
            if (httpFlowPO) httpFlowPO->cFlags |= HTTP_STRM;
        }
    }

    if (httpFlowPO && httpFlowPO->httpLastMeth == HEAD) {
        HTTP_SPKTMD_PRI(httpFlowP);
        return;
    }

#if HTTP_SAVE == 1

    // if Http-Flow do analyze data
    if ((httpFlowP->flags & HTTP_F_PLD_S) && data_len > 0) {
        int64_t tcpSeqDiff = 0;
        uint32_t tcpSeq = 0; // absolute / relative TSN
        const uint32_t * const hdp = (uint32_t*)data_ptr;
        const uint_fast8_t proto = packet->l4Proto;
        uint16_t http_data_len_chkd;

#if SCTP_ACTIVATE > 0
        if (proto == L3_SCTP) {
            const sctpChunk_t * const sctpChunkP = (sctpChunk_t*)packet->l7SctpHdrP;
            tcpSeq = ntohl(sctpChunkP->tsn_it_cta); // absolute / relative TSN
        } else
#endif // SCTP_ACTIVATE > 0
        if (proto == L3_TCP) {
            const tcpHeader_t * const tcpHdrP = TCP_HEADER(packet);
            tcpSeq = ntohl(tcpHdrP->seq); // absolute / relative TCP sequence number
        } else if (!(httpFlowP->flags & HTTP_F_SEQ_INIT)) {
            tcpSeq = httpFlowP->sniffedContent;
        }

        if (*hdp == HTTP_IDN) {
            if (httpFlowP->fd) {
                file_manager_close(t2_file_manager, httpFlowP->fd);
                httpFlowP->fd = NULL;
                http_fd_cnt--;
            }

            httpFlowP->flags &= ~HTTP_F_S; // content processing finished
            httpFlowP->flags |= HTTP_F_HTTP_HDR;
            httpFlowP->aggContLen += httpFlowP->contentLength;
            httpFlowP->sniffedContent = 0;
            httpFlowP->contentLength = 0;
            httpFlowP->tcpSeqInit = 0;
            httpFlowP->hdr_len = 0;
            goto hdrbgn;
        }

        if (data_len > (httpFlowP->contentLength - httpFlowP->sniffedContent)) {
            http_data_len_chkd = httpFlowP->contentLength - httpFlowP->sniffedContent;
        } else {
            http_data_len_chkd = data_len;
        }

        if (httpFlowP->flags & HTTP_F_SEQ_INIT) {
            httpFlowP->tcpSeqInit = tcpSeq;
            if (proto == L3_SCTP) httpFlowP->seq = http_data_len_chkd;
            httpFlowP->hdr_len = packet->snapL7Len - http_data_len_chkd;
            httpFlowP->flags &= ~HTTP_F_SEQ_INIT;
        } else if (httpFlowP->flags & HTTP_F_CHKD) {
            line_eptr = http_get_linesize(data_ptr, http_data_len_chkd); // size of current line (if 0 header is completely read)
            if (line_eptr) {
                line_size = (uint16_t)(line_eptr - data_ptr); // size of current line (if 0 header is completely read)
                i = 0;
                int read = -1;
                if (line_eptr[2] == '\r') {
                    p = memchr(line_eptr+4, '\r', http_data_len_chkd - line_size);
                    if (p) {
                        *p = '\0';
                        sscanf(line_eptr, "%x%n", &i, &read);
                        *p = '\r';
                        // check for garbage after chunk length
                        if (read != line_size) i = 0;
                    }
                } else {
                    *line_eptr = '\0';
                    sscanf(data_ptr, "%x%n", &i, &read);
                    *line_eptr = '\r';
                    // check for garbage after chunk length
                    if (read != line_size) i = 0;
                }

                if (i) {
                    data_ptr += (line_size + 2); // +2 skip line ending \r\n
                    data_len -= (line_size + 2);
                    if (data_len < i) http_data_len_chkd = data_len;
                    else http_data_len_chkd = i;
                    httpFlowP->contentLength = i;
                    //httpFlowP->sniffedContent = 0;
                }
            }
        }

        tcpSeqDiff = tcpSeq - httpFlowP->tcpSeqInit;
        if (proto == L3_SCTP) tcpSeqDiff *= httpFlowP->seq;

        int32_t j = tcpSeqDiff - httpFlowP->sniffedContent;
        if (tcpSeqDiff && httpFlowP->flags & HTTP_F_SHFT) j -= httpFlowP->hdr_len; // remove header part

        if (proto == L3_UDP) j = 0;

        FILE * const fp = file_manager_fp(t2_file_manager, httpFlowP->fd);

        if (!(httpFlowP->flags & HTTP_F_CHKD)) {
            if (j) { // appropriate transmission j == 0
                httpFlowP->aFlags |= HTTP_F_SQ_NM;
                if (httpFlowP->cFlags & HTTP_STRM1) {
                    fseek(fp, httpFlowP->aggContLen + tcpSeqDiff - httpFlowP->hdr_len, SEEK_SET);
                } else {
                    fseek(fp, tcpSeqDiff - httpFlowP->hdr_len, SEEK_SET);
                }
            } else if (httpFlowP->cFlags & HTTP_STRM1) {
                fseek(fp, 0, SEEK_END);
            } else {
                fseek(fp, tcpSeqDiff - httpFlowP->hdr_len, SEEK_SET);
            }
        }

        if (UNLIKELY(http_data_len_chkd != fwrite(data_ptr, 1, http_data_len_chkd, fp))) {
            T2_PERR(plugin_name, "Failed to write to file '%s': %s", imfilename, strerror(errno));
            file_manager_close(t2_file_manager, httpFlowP->fd);
            terminate();
        }

        if (j >= 0) httpFlowP->sniffedContent += http_data_len_chkd; // more sniffed content

        if (proto == L3_SCTP) {
            httpFlowP->seq = http_data_len_chkd;
        } else {
            httpFlowP->seq = tcpSeq;
        }

        if (httpFlowP->contentLength <= httpFlowP->sniffedContent) {
            if (httpFlowP->flags & HTTP_F_CHKD) {
                int read;
                do {
                    i = http_data_len_chkd + 2;
                    data_ptr += i;
                    line_eptr = http_get_linesize(data_ptr, data_len - i); // size of current line (if 0 header is completely read)
                    if (!line_eptr) {
                        httpFlowP->contentLength = 0;
                        HTTP_SPKTMD_PRI(httpFlowP);
                        return;
                    }

                    line_size = (uint16_t)(line_eptr - data_ptr);

                    read = -1;
                    *line_eptr = '\0';
                    sscanf(data_ptr, "%x%n", &(httpFlowP->contentLength), &read);
                    *line_eptr = '\r';

                    if (httpFlowP->contentLength == 0 || read != line_size) break;

                    i = line_size + 2; // +2 skip line ending \r\n
                    data_ptr += i;
                    data_len -= (http_data_len_chkd + i);
                    fwrite(data_ptr, 1, data_len, fp);
                    httpFlowP->sniffedContent += http_data_len_chkd; // more sniffed content
                } while (httpFlowP->contentLength < httpFlowP->sniffedContent);

                if (httpFlowP->contentLength) {
                    httpFlowP->flags &= ~HTTP_F_SHFT;
                    httpFlowP->sniffedContent = data_len;
                    httpFlowP->tcpSeqInit = tcpSeq;
                    HTTP_SPKTMD_PRI(httpFlowP);
                    return;
                }
            }

            if (httpFlowP->fd) {
                file_manager_close(t2_file_manager, httpFlowP->fd);
                httpFlowP->fd = NULL;
                http_fd_cnt--;
            }

            httpFlowP->flags &= ~HTTP_F_S; // content processing finished
            httpFlowP->flags |= HTTP_F_HTTP_HDR;
            httpFlowP->aggContLen += httpFlowP->contentLength;
            httpFlowP->sniffedContent = 0;
            httpFlowP->contentLength = 0;
            httpFlowP->tcpSeqInit = 0;
            httpFlowP->hdr_len = 0;
            data_len = 0;
        }
    }
#endif // HTTP_SAVE == 1

    HTTP_SPKTMD_PRI(httpFlowP);
}


void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {
    http_flow_t * const httpFlowP = &(http_flow[flowIndex]);

#if HTTP_SAVE == 1
    if (httpFlowP->fd) {
        file_manager_close(t2_file_manager, httpFlowP->fd);
        httpFlowP->fd = NULL;
        http_fd_cnt--;
    }
#endif // HTTP_SAVE == 1

    if (!(httpFlowP->flags & HTTP_F_HTTP)) {
        httpFlowP->flags = 0;
        httpFlowP->cFlags = 0;
        httpFlowP->aFlags = 0;
        totalHttpPktCnt -= httpFlowP->pktcnt;
    }

    httpAStat     |= httpFlowP->flags;
    httpHeadMimes |= httpFlowP->mimeTypes;
    httpAFlags    |= httpFlowP->aFlags;
    httpCFlags    |= httpFlowP->cFlags;

    imageCnt   += httpFlowP->image_c;
    videoCnt   += httpFlowP->video_c;
    audioCnt   += httpFlowP->audio_c;
    textCnt    += httpFlowP->text_c;
    msgCnt     += httpFlowP->msg_c;
    applCnt    += httpFlowP->appl_c;
    unkCnt     += httpFlowP->unknwn_c;

    httpGetCnt += httpFlowP->getCnt;
    httpPstCnt += httpFlowP->pstCnt;

    OUTBUF_APPEND_U16(buf, httpFlowP->flags);       // httpStat
    OUTBUF_APPEND_U16(buf, httpFlowP->aFlags);      // httpAFlags
    OUTBUF_APPEND_U8(buf , httpFlowP->httpMethods); // httpMethods
    OUTBUF_APPEND_U16(buf, httpFlowP->mimeTypes);   // httpHeadMimes

#if HTTP_BODY == 1
    OUTBUF_APPEND_U16(buf, httpFlowP->cFlags);     // httpCFlags
#endif // HTTP_BODY

#if HTTP_MCNT == 1
    OUTBUF_APPEND(buf, httpFlowP->getCnt, 2 * sizeof(uint16_t)); // httpGet_Post
#endif // HTTP_MCNT == 1

#if HTTP_STAT == 1
    OUTBUF_APPEND_U16(buf, httpFlowP->stat_c);     // httpRSCnt

    // httpRSCode
    const uint32_t j = MIN(httpFlowP->stat_c, HTTP_DATA_C_MAX);
    OUTBUF_APPEND_ARRAY_U16(buf, httpFlowP->stat, j);
#endif // HTTP_STAT == 1

    OUTBUF_APPEND(buf, httpFlowP->url_c, 17 * sizeof(uint16_t)); // httpURL_Via_Loc_Srv_Pwr_UAg_XFr_Ref_Cky_Mim,
                                                                 // httpImg_Vid_Aud_Msg_Txt_App_Unk

#if HTTP_HOST == 1
    HTTP_APPEND_REP_STR(httpFlowP->host, httpFlowP->host_c);     // httpHosts
#endif // HTTP_HOST == 1

#if HTTP_URL == 1
    HTTP_APPEND_REP_STR(httpFlowP->url, httpFlowP->url_c);       // httpURL
#endif // HTTP_URL == 1

#if HTTP_MIME == 1
    HTTP_APPEND_REP_STR(httpFlowP->mime, httpFlowP->mime_c);     // httpMimes
#endif // HTTP_MINE == 1

#if HTTP_COOKIE == 1
    HTTP_APPEND_REP_STR(httpFlowP->cookie, httpFlowP->cookie_c); // httpCookies
#endif // HTTP_COOKIE == 1

#if HTTP_IMAGE == 1
    HTTP_APPEND_REP_STR(httpFlowP->image, httpFlowP->image_c);   // httpImages
#endif // HTTP_IMAGE == 1

#if HTTP_VIDEO == 1
    HTTP_APPEND_REP_STR(httpFlowP->video, httpFlowP->video_c);   // httpVideos
#endif // HTTP_VIDEO == 1

#if HTTP_AUDIO == 1
    HTTP_APPEND_REP_STR(httpFlowP->audio, httpFlowP->audio_c);   // httpAudios
#endif // HTTP_AUDIO == 1

#if HTTP_MSG == 1
    HTTP_APPEND_REP_STR(httpFlowP->msg, httpFlowP->msg_c);       // httpMsgs
#endif // HTTP_MSG == 1

#if HTTP_APPL == 1
    HTTP_APPEND_REP_STR(httpFlowP->appl, httpFlowP->appl_c);     // httpAppl
#endif // HTTP_APPL == 1

#if HTTP_TEXT == 1
    HTTP_APPEND_REP_STR(httpFlowP->text, httpFlowP->text_c);     // httpText
#endif // HTTP_TEXT == 1

#if HTTP_PUNK == 1
    HTTP_APPEND_REP_STR(httpFlowP->punk, httpFlowP->unknwn_c);   // httpPunk
#endif // HTTP_PUNK == 1

#if (HTTP_BODY == 1 && HTTP_BDURL == 1)
    HTTP_APPEND_REP_STR(httpFlowP->refURL, httpFlowP->refURL_c); // httpBdyURL
#endif // (HTTP_BODY == 1 && HTTP_BDURL == 1)

#if HTTP_USRAG == 1
    HTTP_APPEND_REP_STR(httpFlowP->usrAg, httpFlowP->usrAg_c);   // httpUsrAg
#endif // HTTP_USRAG == 1

#if HTTP_XFRWD == 1
    HTTP_APPEND_REP_STR(httpFlowP->xFor, httpFlowP->xFor_c);     // httpXFor
#endif // HTTP_XFRWD == 1

#if HTTP_REFRR == 1
    HTTP_APPEND_REP_STR(httpFlowP->refrr, httpFlowP->refrr_c);   // httpRefrr
#endif // HTTP_REFRR == 1

#if HTTP_VIA == 1
    HTTP_APPEND_REP_STR(httpFlowP->via, httpFlowP->via_c);       // httpVia
#endif // HTTP_VIA == 1

#if HTTP_LOC == 1
    HTTP_APPEND_REP_STR(httpFlowP->loc, httpFlowP->loc_c);       // httpLoc
#endif // HTTP_LOC == 1

#if HTTP_SERV == 1
    HTTP_APPEND_REP_STR(httpFlowP->serv, httpFlowP->serv_c);     // httpServ
#endif // HTTP_SERV == 1

#if HTTP_PWR == 1
    HTTP_APPEND_REP_STR(httpFlowP->pwr, httpFlowP->pwr_c);       // httpPwr
#endif // HTTP_PWR == 1

#if HTTP_AVAST_CID == 1
    OUTBUF_APPEND_STR(buf, httpFlowP->avastCid);                 // httpAvastCid
#endif // HTTP_AVAST_CID == 1

#if HTTP_ESET_UID == 1
    OUTBUF_APPEND_STR(buf, httpFlowP->esetUid);                  // httpEsetUid
#endif // HTTP_ESET_UID == 1
}


void t2PluginReport(FILE *stream) {
    if (totalHttpPktCnt == 0) return;

    const uint16_t httpStat = (uint16_t)(httpAStat & ~HTTP_F_HTTP_HDR);
    T2_FPLOG_AGGR_HEX(stream, plugin_name, httpStat);
    T2_FPLOG_AGGR_HEX(stream, plugin_name, httpAFlags);
#if HTTP_BODY == 1
    T2_FPLOG_AGGR_HEX(stream, plugin_name, httpCFlags);
#endif
    T2_FPLOG_AGGR_HEX(stream, plugin_name, httpHeadMimes);

    const bool has_cnt = (imageCnt || videoCnt || audioCnt || textCnt || msgCnt || applCnt || unkCnt);
    if (has_cnt) {
        T2_FPLOG(stream, plugin_name, "Number of files img_vid_aud_msg_txt_app_unk: "
                "%" PRIu32 "_%" PRIu32 "_%" PRIu32 "_%" PRIu32 "_%" PRIu32 "_%" PRIu32 "_%" PRIu32,
                imageCnt, videoCnt, audioCnt, msgCnt, textCnt, applCnt, unkCnt);
    }

#if HTTP_SAVE == 1
    T2_FPLOG_NUM(stream, plugin_name, "Max number of file handles", http_fd_max);
#endif // HTTP_SAVE == 1
    T2_FPLOG_NUMP(stream, plugin_name, "Number of HTTP packets", totalHttpPktCnt, numPackets);
    T2_FPLOG_NUMP(stream, plugin_name, "Number of HTTP GET  requests", httpGetCnt, totalHttpPktCnt);
    if (httpPstCnt) {
        T2_FPLOG_NUMP0(stream, plugin_name, "Number of HTTP POST requests", httpPstCnt, totalHttpPktCnt);
        T2_FPLOG(stream, plugin_name, "HTTP GET/POST ratio: %.2f", httpGetCnt/(double)httpPstCnt);
    }
}


void t2Monitoring(FILE *stream, uint8_t state) {

    switch (state) {

        case T2_MON_PRI_HDR:
            fputs("httpPkts" SEP_CHR
                  , stream);
            return;

        case T2_MON_PRI_VAL:
            fprintf(stream,
                    "%" PRIu64 /* httpPkts */ SEP_CHR
                    , totalHttpPktCnt - totalHttpPktCnt0);
            break;

        case T2_MON_PRI_REPORT: {
            const uint16_t httpStat = (uint16_t)(httpAStat & ~HTTP_F_HTTP_HDR);
            T2_FPLOG_AGGR_HEX(stream, plugin_name, httpStat);
            T2_FPLOG_AGGR_HEX(stream, plugin_name, httpAFlags);
#if HTTP_BODY == 1
            T2_FPLOG_AGGR_HEX(stream, plugin_name, httpCFlags);
#endif
            T2_FPLOG_AGGR_HEX(stream, plugin_name, httpHeadMimes);
            T2_FPLOG_DIFFNUMP(stream, plugin_name, "Number of HTTP packets", totalHttpPktCnt, numPackets);
            break;
        }

        // Invalid state, do nothing
        default:
            return;
    }

#if DIFF_REPORT == 1
    totalHttpPktCnt0 = totalHttpPktCnt;
#endif // DIFF_REPORT == 1
}


void t2Finalize() {
#if HTTP_SAVE == 1 && ENVCNTRL > 0
    t2_free_env(ENV_HTTP_N, env);
#endif // HTTP_SAVE == 1 && ENVCNTRL > 0

    free(http_flow);
}


static inline char* http_read_header_data(char* data, uint16_t data_len, const char *header, uint16_t header_len) {
    if (strncasecmp(data, header, header_len) != 0) return 0; // data not found..

    while (header_len < data_len && data[header_len] == ' ') header_len++;

    return &data[header_len];
}


static inline char* http_get_linesize(char *data, int32_t data_len) {
    if (data_len < 2) return NULL;
    return memmem(data, data_len, HTTP_HEADER_CRLF, sizeof(HTTP_HEADER_CRLF)-1);
}


static inline http_mimetype http_read_mimetype(const char *data, size_t data_size) {
    size_t mime_size = 0;
    while (mime_size < data_size && data[mime_size] != '/') ++mime_size;

    if (strncmp(data, "application"   , mime_size) == 0) return HTTP_C_APPL;
    else if (strncmp(data, "audio"    , mime_size) == 0) return HTTP_C_AUDIO;
    else if (strncmp(data, "image"    , mime_size) == 0) return HTTP_C_IMAGE;
    else if (strncmp(data, "message"  , mime_size) == 0) return HTTP_C_MSG;
    else if (strncmp(data, "model"    , mime_size) == 0) return HTTP_C_MODEL;
    else if (strncmp(data, "multipart", mime_size) == 0) return HTTP_C_MLTPRT;
    else if (strncmp(data, "text"     , mime_size) == 0) return HTTP_C_TEXT;
    else if (strncmp(data, "video"    , mime_size) == 0) return HTTP_C_VIDEO;
    else if (strncmp(data, "vnd"      , mime_size) == 0) return HTTP_C_VND;
    else if (strncmp(data, "x-pkcs"   , mime_size) == 0) return HTTP_C_XPKCS;
    else if (strncmp(data, "x"        , mime_size) == 0) return HTTP_C_X;

    return HTTP_C_OTHER;
}
