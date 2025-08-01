/*
 * wechatDecode.h
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

#ifndef __WECHAT_DECODE_H__
#define __WECHAT_DECODE_H__

#include "t2Plugin.h"


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define WECHAT_JSON_SUFFIX              "_wechat.json"
#define WECHAT_JSON_ARRAY               0
#define WECHAT_INITIAL_JSON_BUFFER_SIZE 2048
#define WECHAT_MAX_HTTP_HDR_FIELD_LEN   1024 // whole header field including \r\n
#define WECHAT_MAX_QUA_MATCH_LEN        255
#define WECHAT_VERBOSITY_LEVEL          0 // 0: quiet; 1: debug output

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


typedef enum {
    BODY_TYPE_UNKNOWN = 0,
    BODY_TYPE_REPORT_LOG,
    BODY_TYPE_GET_SETTINGS,
    BODY_TYPE_GET_APP_UPDATE,
    BODY_TYPE_GET_AUTHORIZED,
    BODY_TYPE_GET_APP_SIMPLE_DETAIL,
    BODY_TYPE_GET_CALLER_SETTING,
    BODY_TYPE_GET_CONFIG,
    BODY_TYPE_GET_PUSH,
    BODY_TYPE_STAT_REPORT,
    BODY_TYPE_GET_HALLEY_URL
} body_type_t;

typedef struct {
    struct timeval firstSeen;
    uint_fast16_t  vlanId;
    uint_fast8_t   l4Proto;
    char           srcIP[INET6_ADDRSTRLEN];
    char           dstIP[INET6_ADDRSTRLEN];
    uint_fast16_t  srcPort;
    uint_fast16_t  dstPort;
} flow_tuple_t;

typedef struct {
    uint8_t status;
} wechatFlow_t;

extern wechatFlow_t *wechatFlows;

#endif // __WECHAT_DECODE_H__
