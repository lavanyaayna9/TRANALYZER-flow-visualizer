/*
 * wechatDecode.c
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

#include "t2buf.h"
#include "t2log.h"
#include "t2Plugin.h"

#include <errno.h>
#include <regex.h>
#include <zlib.h>

#include "jce.h"
#include "wechatDecode.h"


#define HTTP_HEADER_MIN_LEN        20
#define JCE_ENCRYPT_WITH_PACK_FLAG 1
#define PATTERN_QUA                "TMASDK_([0-9]+)(_([0-9]+))?\\/([0-9]+)&NA" \
                                   "\\/[0-9]+&([0-9.]+)_([0-9]+)_(0|1)&([0-9]+)" \
                                   "_([0-9]+)_14&([^&_]+)_([^&_]+)&([^&]+)&NA&V3"
#define PATTERN_QUA_MATCHES        (12 + 1) // must be N+1 to process N matching groups.
#define WECHAT_STAT_HTTP           0x01 // potential HTTP content

#define DUMP_PROPERTY_JSON(BUF, OBJECT, TAG, JCE_TYPE, TYPE, PROPERTY_VALUE, FMT, NAME, IS_FIRST) \
        { \
            TYPE *prop = jce_get_tagged_typed_item(OBJECT, TAG, JCE_TYPE); \
            if (prop) { \
                if (IS_FIRST) { \
                    IS_FIRST = false; \
                } else { \
                    json_printf(BUF, ","); \
                } \
                json_printf(BUF, FMT, NAME, prop->PROPERTY_VALUE); \
            } \
        }

#define READ_TYPED_FIELD(JCE, VAR, TYPE, JCE_TYPE) \
    { \
        jce_field_t *field; \
        if (!jce_read_field(JCE, &field)) { \
            VAR = NULL; \
        } else if (field->header.type != JCE_TYPE) { \
            jce_free(field); \
            VAR = NULL; \
        } else { \
            VAR = (TYPE *)field; \
        } \
    }


// Global variables

wechatFlow_t*  wechatFlows;


// Static variables

static FILE*   jsonOutput;
#if WECHAT_JSON_ARRAY > 0
static bool    first_json_object = true;
#endif
static char*   json_buf;
static size_t  json_buf_size     = WECHAT_INITIAL_JSON_BUFFER_SIZE;
static regex_t re_qua;


// Function prototypes
bool decode               (jce_t *jce, struct json_out *jbuf, flow_tuple_t ft);
bool decodeReqHead        (jce_t *jce, struct json_out *jbuf, bool *out_compressed, body_type_t *out_body_type);
bool decodeBody           (jce_t *jce, struct json_out *jbuf, bool compressed, body_type_t body_type);
bool decodeBodyFields     (jce_t* jce, struct json_out *jbuf, body_type_t body_type);
bool decodeBodyReportLog  (jce_t* jce, struct json_out *jbuf);
bool decodeBodyGetSettings(jce_t* jce, struct json_out *jbuf);
bool decodeBodyGetConfig  (jce_t* jce, struct json_out *jbuf);
bool decodeBodyStatReport (jce_t* jce, struct json_out *jbuf);
bool decodeQua            (jce_short_string_t *qua, struct json_out *jbuf, bool *first);

bool decompress(uint8_t *in, size_t in_len, uint8_t **outP, size_t *out_lenP);
int json_printf_jce_field(struct json_out* out, va_list *ap);
void copyMatch(char *match, regmatch_t const *matches, int index, int nmatches, char const *input);
flow_tuple_t getFlowTuple(flow_t const * const flowP);
bool dump_jce_fields(jce_t *jce, struct json_out *jbuf);
void increase_json_buffer_size(struct json_out *out, size_t old_len);


T2_PLUGIN_INIT("wechatDecode", "0.9.3", 0, 9)


void t2Init() {
    T2_PLUGIN_STRUCT_NEW(wechatFlows);

    // global json_buf
    json_buf = t2_calloc_fatal(json_buf_size, 1);

    // set up QUA regex
    int const re_ret = regcomp(&re_qua, PATTERN_QUA, REG_EXTENDED);
    if (UNLIKELY(re_ret != 0)) {
        char buf[255];
        regerror(re_ret, &re_qua, buf, sizeof(buf));
        T2_PERR(plugin_name, "failed to compile QUA regex: %s", buf);
    }

    jsonOutput = t2_fopen_with_suffix(baseFileName, WECHAT_JSON_SUFFIX, "w+");
    if (UNLIKELY(!jsonOutput)) exit(EXIT_FAILURE);

#if WECHAT_JSON_ARRAY > 0
    // write opening JSON array bracket to ensure proper format.
    // closing bracket is written in t2Finalize().
    char const open_bracket[2] = "[";
    size_t const written = fwrite(open_bracket, 1, 1, jsonOutput);
    if (written != 1) {
        T2_PWRN(plugin_name, "failed to write opening array bracket to JSON output file");
    }
#endif
}


void t2OnNewFlow(packet_t *packet UNUSED, unsigned long flowIndex) {
    wechatFlow_t * const wdFlowP = &wechatFlows[flowIndex];
    memset(wdFlowP, '\0', sizeof(*wdFlowP));

    flow_t const * const flowP = &flows[flowIndex];
    if (flowP->status & L2_FLOW) return;

    uint_fast8_t const proto = packet->l4Proto;
    if (proto == L3_TCP
        || (proto == L3_UDP && (flowP->srcPort > 1024 || flowP->dstPort > 1024)))
    {
        wdFlowP->status |= WECHAT_STAT_HTTP ;
    }
}


void t2OnLayer4(packet_t *packet, unsigned long flowIndex) {
    wechatFlow_t const * const wdFlowP = &wechatFlows[flowIndex];
    flow_t       const * const flowP   = &flows[flowIndex];

    if (!(wdFlowP->status & WECHAT_STAT_HTTP)) {
        return;
    }

    char const * const data = (const char *)packet->l7HdrP;
    size_t const       len  = packet->snapL7Len;

    // check if HTTP packet with header
    if (len < HTTP_HEADER_MIN_LEN || (
            strncmp(data, "GET ", 4)     &&
            strncmp(data, "POST ", 5)    &&
            strncmp(data, "HEAD ", 5)    &&
            strncmp(data, "OPTIONS ", 8) &&
            strncmp(data, "PUT ", 4)     &&
            strncmp(data, "DELETE ", 7))) {
        return;
    }

    t2buf_t t2buf = t2buf_create((uint8_t const *)data, len);
    uint8_t line[WECHAT_MAX_HTTP_HDR_FIELD_LEN];

    // check if first line looks like HTTP
    long ret = t2buf_readline(&t2buf, line, WECHAT_MAX_HTTP_HDR_FIELD_LEN, true);
    char const * const httpNeedle = "HTTP/1.";
    if (ret < 14 ||
            strncmp((char const *)(line + ret - (strlen(httpNeedle) + 1)),
                httpNeedle,
                strlen(httpNeedle))) {
        return;
    }

    // read the different fields in the HTTP header
    ret = t2buf_readline(&t2buf, line, WECHAT_MAX_HTTP_HDR_FIELD_LEN, true);
    while (ret > 0 && strcmp((char const*)line, "\r\n")) {
#if WECHAT_VERBOSITY_LEVEL > 0
        char const * const field_name = strtok((char *)line, ":");
        if (field_name) {
            char const * const field_value = strtok(NULL, ":");
            if (field_value) {
                printf("HTTP header \"%s\": \"%s\"\n", field_name, field_value);
            }
        }
#endif
        ret = t2buf_readline(&t2buf, line, WECHAT_MAX_HTTP_HDR_FIELD_LEN, true);
    }

    long const httpPayloadPos = t2buf_tell(&t2buf);
    char const * const wechatNeedle = "TMASDK_";
    if (!t2buf_memmem(&t2buf, wechatNeedle, strlen(wechatNeedle))) {
        // not JCE payload
        return;
    }

    if (!t2buf_seek(&t2buf, httpPayloadPos, SEEK_SET)) {
        T2_PERR(plugin_name, "failed to seek t2buf back to start of HTTP payload!");
        return;
    }

    // prepare flow tuple for JSON output
    flow_tuple_t ft = getFlowTuple(flowP);

    // decode JCE data and dump to json
    jce_t jce = jce_create(&t2buf);
    // global json_buf
    // global json_buf_size
    memset(json_buf, '\0', json_buf_size);
    struct json_out jbuf = JSON_OUT_BUF(json_buf, json_buf_size);

#if WECHAT_JSON_ARRAY > 0
    if (UNLIKELY(first_json_object)) {
        first_json_object = false;
    } else {
        json_printf(&jbuf, ",");
    }
#endif

    // Decode the JCE stream and write it to the JSON buffer.
    // If the buffer is too small, resize it and try again until success.
    bool buffer_too_small;
    do {
        size_t const old_len = jbuf.u.buf.len;
        long const old_t2buf_pos = t2buf_tell(jce.buf);

        // The decode() function is expected to be pure, so it can be called
        // multiple times with varying buffer lengths.
        if (!decode(&jce, &jbuf, ft)) {
            T2_PERR(plugin_name, "failed to decode JCE stream for this packet");
            return;
        }

        buffer_too_small = (jbuf.u.buf.len == jbuf.u.buf.size);
        if (buffer_too_small) {
            T2_PWRN(plugin_name,
                    "JSON buffer was too small (%lu bytes), increasing size and retrying parse",
                    json_buf_size);

            // revert incomplete data and increase buffer size for next decoding attempt
            increase_json_buffer_size(&jbuf, old_len);

            // reset t2buf buffer position to position before failed decoding attempt
            if (!t2buf_seek(jce.buf, old_t2buf_pos, SEEK_SET)) {
                // This can only happen if the buffer position is outside the bounds of the buffer.
                // Since we get the buffer position from t2buf_tell(), this should never fail.
                T2_PERR(plugin_name,
                        "failed to reset t2buf position after increasing JSON buffer size;"
                        "this packet will not be parsed properly!");
            }
        }
    } while (buffer_too_small);

    size_t const written = fwrite(jbuf.u.buf.buf, 1, jbuf.u.buf.len, jsonOutput);
    if (written != jbuf.u.buf.len) {
        T2_PERR(plugin_name,
                "failed to write all %lu bytes of JSON data to output file! (written: %lu)",
                jbuf.u.buf.len, written);
    }
}


/*
 * This function may be called multiple times on the same packet in the same
 * position. Therefore, this function *must* be pure, i.e. only consume output
 * from the JCE stream and dump JSON into the JSON output buffer. There may be
 * no side effects apart from producing JSON.
 */
bool decode(jce_t *jce, struct json_out *jbuf, flow_tuple_t ft) {
    bool        compressed = false;
    body_type_t body_type  = 0;

    char const * const flow_fmt = "%Q: {"
            "%Q: \"%ld.%06d\","
            "%Q: %d,"
            "%Q: %d,"
            "%Q: %Q,"
            "%Q: %d,"
            "%Q: %Q,"
            "%Q: %d"
        "}";
    json_printf(jbuf, "{");
    json_printf(jbuf, flow_fmt,
        "flow",
        "timeFirst", ft.firstSeen.tv_sec, ft.firstSeen.tv_usec,
        "ethVlanID", ft.vlanId,
        "l4Proto", ft.l4Proto,
        "srcIP", ft.srcIP,
        "srcPort", ft.srcPort,
        "dstIP", ft.dstIP,
        "dstPort", ft.dstPort);

    json_printf(jbuf, ",");

    if (!decodeReqHead(jce, jbuf, &compressed, &body_type)) {
        T2_PERR(plugin_name, "failed to decode request header, skipping packet");
        return false;
    }

    json_printf(jbuf, ", ");

    if (!decodeBody(jce, jbuf, compressed, body_type)) {
        T2_PERR(plugin_name, "failed to decode request body, skipping packet");
        return false;
    }

    json_printf(jbuf, "}");

    return true;
}


void increase_json_buffer_size(struct json_out *out, size_t old_len) {
    // global json_buf
    // global json_buf_size

    json_buf_size = out->u.buf.size * 2;
    json_buf      = realloc(json_buf, json_buf_size);

    out->u.buf.buf  = json_buf;
    out->u.buf.size = json_buf_size;
    out->u.buf.len  = old_len;
}


// Instance of json_printf_callback_t to serialize arbitrary JCE field into JSON, recursively.
int json_printf_jce_field(struct json_out* out, va_list *ap) {
    jce_field_t *field = va_arg(*ap, jce_field_t*);

    switch (field->header.type) {
        case JCE_TYPE_START: {
            jce_object_t *object = (jce_object_t *)field;
            jce_object_item_t *item = object->head;
            json_printf(out, "{");
            while (item) {
                json_printf(out, "\"%d\": %M", item->field->header.tag, json_printf_jce_field, item->field);
                if (item->next) {
                    json_printf(out, ",");
                }
                item = item->next;
            }
            json_printf(out, "}");
            break;
        }

#define JCE_CASE_TYPE_JSON_MACRO(JCE_TYPE_NAME, JCE_TYPE) \
        case JCE_TYPE_ ## JCE_TYPE_NAME: { \
            JCE_TYPE *val = (JCE_TYPE *)field; \
            json_printf(out, "%lu", (uint64_t)val->value); \
            break; \
        }

        JCE_CASE_TYPE_JSON_MACRO(BYTE,  jce_byte_t)
        JCE_CASE_TYPE_JSON_MACRO(SHORT, jce_short_t)
        JCE_CASE_TYPE_JSON_MACRO(INT,   jce_int_t)
        JCE_CASE_TYPE_JSON_MACRO(LONG,  jce_long_t)

        case JCE_TYPE_ARRAY: {
            jce_array_t *arr = (jce_array_t *)field;
            jce_array_item_t *item = arr->head;
            json_printf(out, "[");
            while (item) {
                json_printf(out, "%M", json_printf_jce_field, item->field);
                if (item->next) {
                    json_printf(out, ",");
                }
                item = item->next;
            }
            json_printf(out, "]");
            break;
        }

        case JCE_TYPE_BYTE_ARRAY: {
            jce_byte_array_t *barr = (jce_byte_array_t *)field;
            json_printf(out, "[");
            for (uint64_t i = 0; i < barr->len; i++) {
                json_printf(out, "%d", barr->values[i]);
                if (i < (barr->len - 1)) {
                    json_printf(out, ",");
                }
            }
            json_printf(out, "]");
            break;
        }

        case JCE_TYPE_MAP: {
            jce_map_t *map = (jce_map_t *)field;
            jce_map_item_t *item = map->head;
            json_printf(out, "[");
            while (item) {
                json_printf(out, "{ %Q: %M, %Q: %M }",
                        "key", json_printf_jce_field, item->key,
                        "value", json_printf_jce_field, item->value);
                if (item->next) {
                    json_printf(out, ",");
                }
                item = item->next;
            }
            json_printf(out, "]");
            break;
        }

        case JCE_TYPE_SHORT_STRING: {
            jce_short_string_t *sstr = (jce_short_string_t *)field;
            json_printf(out, "%Q", sstr->value);
            break;
        }

        default:
            printf("printing unknown JSON type %d!\n", field->header.type);
    }

    return true;
}


void dump_json_sep(struct json_out *jbuf) {
    json_printf(jbuf, ",");
}


void dump_json(struct json_out *jbuf, jce_field_t const *field, int id) {
    json_printf(jbuf, "\"%d\": %M", id, json_printf_jce_field, field);
}


bool decodeReqHead(jce_t *jce, struct json_out *jbuf, bool *out_compressed, body_type_t *out_body_type) {
    jce_field_t *reqHeadField;
    bool ret = jce_read_field(jce, &reqHeadField);
    if (!ret) {
        T2_PWRN(plugin_name, "failed to read ReqHead, skipping packet");
        return false;
    }

    if (reqHeadField->header.type != JCE_TYPE_START) {
        T2_PWRN(plugin_name, "expected ReqHead to be of type JCE START, skipping packet");
        jce_free(reqHeadField);
        return false;
    }

    jce_object_t * const reqHead = (jce_object_t *)reqHeadField;
    jce_byte_t * const encryptWithPack = jce_get_tagged_typed_item(reqHead, 4, JCE_TYPE_BYTE);
    if (encryptWithPack) {
        *out_compressed = (encryptWithPack->value & JCE_ENCRYPT_WITH_PACK_FLAG);
    }

    jce_byte_t *cmdId = jce_get_tagged_typed_item(reqHead, 1, JCE_TYPE_BYTE);
    if (cmdId) {
        *out_body_type = cmdId->value;
    } else {
        *out_body_type = BODY_TYPE_UNKNOWN;
    }

    json_printf(jbuf, "%Q: {", "requestHeader");
    bool first = true;

    // phone GUID
    jce_short_string_t *phoneGuid = jce_get_tagged_typed_item(reqHead, 2, JCE_TYPE_SHORT_STRING);
    if (phoneGuid) {
        if (first) {
            first = false;
        } else {
            json_printf(jbuf, ",");
        }
        json_printf(jbuf, "%Q: %Q", "phoneGuid", phoneGuid->value);
    }

    // QUA string
    jce_short_string_t *qua = jce_get_tagged_typed_item(reqHead, 3, JCE_TYPE_SHORT_STRING);
    bool qua_present = false;
    if (qua) {
        qua_present = decodeQua(qua, jbuf, &first);
    }

    // optional Terminal struct
    jce_object_t *terminal = jce_get_tagged_typed_item(reqHead, 5, JCE_TYPE_START);
    if (terminal) {
        if (qua_present) {
            json_printf(jbuf, ", ");
        }
        json_printf(jbuf, "%Q: {", "terminal");
        bool terminal_first = true;

        DUMP_PROPERTY_JSON(jbuf, terminal, 0, JCE_TYPE_SHORT_STRING, jce_short_string_t, value, "%Q: %Q", "IMEI", terminal_first)
        DUMP_PROPERTY_JSON(jbuf, terminal, 1, JCE_TYPE_SHORT_STRING, jce_short_string_t, value, "%Q: %Q", "MAC", terminal_first)
        DUMP_PROPERTY_JSON(jbuf, terminal, 2, JCE_TYPE_SHORT_STRING, jce_short_string_t, value, "%Q: %Q", "androidId", terminal_first)
        DUMP_PROPERTY_JSON(jbuf, terminal, 4, JCE_TYPE_SHORT_STRING, jce_short_string_t, value, "%Q: %Q", "IMSI", terminal_first)

        json_printf(jbuf, "}");
    }

    // optional Net struct
    jce_object_t *net = jce_get_tagged_typed_item(reqHead, 8, JCE_TYPE_START);
    if (net) {
        json_printf(jbuf, ", ");
        json_printf(jbuf, "%Q: {", "net");
        bool net_first = true;

        DUMP_PROPERTY_JSON(jbuf, net, 0, JCE_TYPE_BYTE, jce_byte_t, value, "%Q: %d", "netType", net_first)
        DUMP_PROPERTY_JSON(jbuf, net, 3, JCE_TYPE_BYTE, jce_byte_t, value, "%Q: %d", "isWap", net_first)
        DUMP_PROPERTY_JSON(jbuf, net, 4, JCE_TYPE_SHORT_STRING, jce_short_string_t, value, "%Q: %Q", "wifiSsid", net_first)
        DUMP_PROPERTY_JSON(jbuf, net, 5, JCE_TYPE_SHORT_STRING, jce_short_string_t, value, "%Q: %Q", "wifiBssid", net_first)

        json_printf(jbuf, "}");
    }

    json_printf(jbuf, "}"); // end requestHeader

    jce_free(reqHeadField);

    return true;
}


/*
 * Note that this function prints numbers as quoted JSON string as there is no
 * static guarantee on the bounds of the numeric matches. This avoids potential
 * integer overflows and subsequently incorrect results.
 */
bool decodeQua(jce_short_string_t *qua, struct json_out *jbuf, bool *firstP) {
    regmatch_t matches[PATTERN_QUA_MATCHES];
    char const* const s = qua->value;
    int ret = regexec(&re_qua, s, PATTERN_QUA_MATCHES, matches, REG_EXTENDED);
    if (ret == REG_NOMATCH) {
        return false;
    } else if (ret) {
        char buf[255];
        regerror(ret, &re_qua, buf, sizeof(buf));
        T2_PERR(plugin_name, "failed to execute QUA regex: %s", buf);
        return false;
    }

    char match[WECHAT_MAX_QUA_MATCH_LEN] = {'\0'};

    copyMatch(match, matches, 1, WECHAT_MAX_QUA_MATCH_LEN, s);
    if (!(*firstP)) {
        json_printf(jbuf, ",");
    }
    *firstP = false;
    json_printf(jbuf, "%Q: %Q", "versionName", match);

    json_printf(jbuf, ",");

    copyMatch(match, matches, 3, WECHAT_MAX_QUA_MATCH_LEN, s);
    json_printf(jbuf, "%Q: %Q", "channel", match);
    json_printf(jbuf, ",");

    copyMatch(match, matches, 4, WECHAT_MAX_QUA_MATCH_LEN, s);
    json_printf(jbuf, "%Q: %Q", "appSpec", match);

    json_printf(jbuf, ",");

    copyMatch(match, matches, 5, WECHAT_MAX_QUA_MATCH_LEN, s);
    json_printf(jbuf, "%Q: %Q", "androidVersion", match);

    json_printf(jbuf, ",");

    copyMatch(match, matches, 6, WECHAT_MAX_QUA_MATCH_LEN, s);
    json_printf(jbuf, "%Q: %Q", "androidApiLevel", match);

    json_printf(jbuf, ",");

    copyMatch(match, matches, 7, WECHAT_MAX_QUA_MATCH_LEN, s);
    json_printf(jbuf, "%Q: %Q", "rootStatus", match);

    json_printf(jbuf, ",");

    copyMatch(match, matches, 8, WECHAT_MAX_QUA_MATCH_LEN, s);
    json_printf(jbuf, "%Q: %Q", "deviceWidth/16", match);

    json_printf(jbuf, ",");

    copyMatch(match, matches, 9, WECHAT_MAX_QUA_MATCH_LEN, s);
    json_printf(jbuf, "%Q: %Q", "deviceHeight/16", match);

    json_printf(jbuf, ",");

    copyMatch(match, matches, 10, WECHAT_MAX_QUA_MATCH_LEN, s);
    json_printf(jbuf, "%Q: %Q", "brand", match);

    json_printf(jbuf, ",");

    copyMatch(match, matches, 11, WECHAT_MAX_QUA_MATCH_LEN, s);
    json_printf(jbuf, "%Q: %Q", "model", match);

    json_printf(jbuf, ",");

    copyMatch(match, matches, 12, WECHAT_MAX_QUA_MATCH_LEN, s);
    json_printf(jbuf, "%Q: %Q", "channelId", match);

    return true;
}

void copyMatch(char *match, regmatch_t const *matches, int index, int max_match_len, char const *input) {
    int len = matches[index].rm_eo - matches[index].rm_so;
    if (len >= max_match_len) {
        T2_PWRN(plugin_name,
                "when processing QUA regex match %d: "
                "max length %d exceeded (%d)! truncating",
                index, WECHAT_MAX_QUA_MATCH_LEN, len);
        len = max_match_len - 1; // NUL terminator
    }
    memcpy(match, input + matches[index].rm_so, len);
    match[len] = '\0';
}


bool decodeBody(jce_t *jce, struct json_out *jbuf, bool compressed, body_type_t body_type) {
    jce_field_t *body;
    bool ret = jce_read_field(jce, &body);
    if (!ret) {
        T2_PWRN(plugin_name, "failed to read JCE body");
        return false;
    }

    if (body->header.tag != 1) {
        T2_PWRN(plugin_name, "body: invalid tag %d", body->header.tag);
        jce_free(body);
        return false;
    }

    if (body->header.type != JCE_TYPE_BYTE_ARRAY) {
        T2_PWRN(plugin_name, "body: invalid type %d", body->header.type);
        jce_free(body);
        return false;
    }

    jce_byte_array_t* arr = (jce_byte_array_t *)body;
    uint8_t const key[] = {
        'j', 'i', '*', '9', '^', '&', '4', '3',
        'U', '0', 'X', '-', '~', '.', '/', '('
    };

    if (!jce_decrypt_tea(arr->values, arr->len, (uint32_t *)key)) {
        T2_PWRN(plugin_name, "failed to decrypt body!");
        jce_free(body);
        return false;
    }

    size_t pos, len;
    if (!jce_unpad(arr->values, arr->len, &pos, &len)) {
        T2_PWRN(plugin_name, "failed to unpad");
        jce_free(body);
        return false;
    }

    // handle optional compression
    uint8_t *body_bytes;
    size_t body_len;
    if (compressed) {
        if (!decompress(arr->values + pos, len, &body_bytes, &body_len)) {
            T2_PWRN(plugin_name,
                    "failed to inflate gzip compressed body! skipping packet");
            if (body_bytes) {
                free(body_bytes);
            }
            jce_free(body);
            return false;
        }
    } else {
        body_bytes = arr->values + pos;
        body_len = len;
    }

    // create new jce wrapper around the decrypted body payload.
    t2buf_t t2buf_body = t2buf_create(body_bytes, body_len);
    jce_t   jce_body   = jce_create(&t2buf_body);

    json_printf(jbuf, "%Q: {", "body");
    ret = decodeBodyFields(&jce_body, jbuf, body_type);
    json_printf(jbuf, "}");

    if (compressed) {
        free(body_bytes);
    }
    jce_free(body);

    return ret;
}


char const * getBodyTypeName(body_type_t body_type) {
    // case BODY_TYPE_UNKNOWN is covered in default case at the bottom.
    switch (body_type) {
        case BODY_TYPE_REPORT_LOG:
            return "ReportLog";

        case BODY_TYPE_GET_SETTINGS:
            return "GetSettings";

        case BODY_TYPE_GET_APP_UPDATE:
            return "GetAppUpdate";

        case BODY_TYPE_GET_AUTHORIZED:
            return "GetAuthorized";

        case BODY_TYPE_GET_APP_SIMPLE_DETAIL:
            return "AppSimpleDetail";

        case BODY_TYPE_GET_CALLER_SETTING:
            return "SimpleDetail";

        case BODY_TYPE_GET_CONFIG:
            return "GetConfig";

        case BODY_TYPE_GET_PUSH:
            return "GetPush";

        case BODY_TYPE_STAT_REPORT:
            return "StatReport";

        case BODY_TYPE_GET_HALLEY_URL:
            return "GetHalleyURL";

        default:
            break;
    }

    return "UnknownBodyType";
}


bool decodeBodyFields(jce_t* jce, struct json_out *jbuf, body_type_t body_type) {
    json_printf(jbuf, "%Q: {", getBodyTypeName(body_type));

    // NOTE: Do not return early from this function, the JSON object must first
    //       be closed to ensure a valid JSON format!

    bool success = false;

    switch (body_type) {
        case BODY_TYPE_REPORT_LOG:
            success = decodeBodyReportLog(jce, jbuf);
            break;

        case BODY_TYPE_GET_SETTINGS:
            success = decodeBodyGetSettings(jce, jbuf);
            break;

        case BODY_TYPE_GET_CONFIG:
            success = decodeBodyGetConfig(jce, jbuf);
            break;

        case BODY_TYPE_STAT_REPORT:
            success = decodeBodyStatReport(jce, jbuf);
            break;

        default:
            T2_PWRN(plugin_name, "Unsupported body type %d", body_type);
            break;
    }

    json_printf(jbuf, "}");

    return success;
}


flow_tuple_t getFlowTuple(flow_t const * const flowP) {
    flow_tuple_t ft;

    ft.firstSeen = flowP->firstSeen;
    ft.vlanId = flowP->vlanId;
    ft.l4Proto = flowP->l4Proto;

    ft.srcPort = flowP->srcPort;
    ft.dstPort = flowP->dstPort;

    uint_fast8_t const ipver = PACKET_IS_IPV6(flowP) ? 6 : 4;
    T2_IP_TO_STR(flowP->srcIP, ipver, ft.srcIP, INET6_ADDRSTRLEN);
    T2_IP_TO_STR(flowP->dstIP, ipver, ft.dstIP, INET6_ADDRSTRLEN);

    return ft;
}


bool decodeBodyReportLog(jce_t* jce, struct json_out *jbuf) {
    // logType
    jce_byte_t *logType;
    READ_TYPED_FIELD(jce, logType, jce_byte_t, JCE_TYPE_BYTE);
    if (!logType) {
        T2_PWRN(plugin_name, "failed to read logType from ReportLog body");
        return false;
    }

    json_printf(jbuf, "%Q: %d", "logType", logType->value);
    jce_free(&logType->base);

    // logData
    jce_byte_array_t *logData;
    READ_TYPED_FIELD(jce, logData, jce_byte_array_t, JCE_TYPE_BYTE_ARRAY);
    if (!logData) {
        T2_PWRN(plugin_name, "failed to read logData from ReportLog body");
        return false;
    }

    t2buf_t t2buf = t2buf_create(logData->values, logData->len);
    jce_t jce_logData = jce_create(&t2buf);
    json_printf(jbuf, ",");
    json_printf(jbuf, "%Q: {", "logData");
    dump_jce_fields(&jce_logData, jbuf);
    json_printf(jbuf, "}");
    jce_free(&logData->base);

    // hostUserId
    jce_short_string_t *hostUserId;
    READ_TYPED_FIELD(jce, hostUserId, jce_short_string_t, JCE_TYPE_SHORT_STRING);
    if (!hostUserId) {
        T2_PWRN(plugin_name, "failed to read hostUserId from ReportLog body");
        return false;
    }

    json_printf(jbuf, ",");
    json_printf(jbuf, "%Q: %Q", "hostUserId", hostUserId->value);
    jce_free(&hostUserId->base);

    // hostAppName
    jce_short_string_t *hostAppName;
    READ_TYPED_FIELD(jce, hostAppName, jce_short_string_t, JCE_TYPE_SHORT_STRING);
    if (!hostAppName) {
        T2_PWRN(plugin_name, "failed to read hostAppName from ReportLog body");
        return false;
    }

    json_printf(jbuf, ",");
    json_printf(jbuf, "%Q: %Q", "hostAppName", hostAppName->value);
    jce_free(&hostAppName->base);

    return true;
}

bool decodeBodyGetConfig(jce_t* jce, struct json_out *jbuf) {
    // typeList
    jce_array_t *typeList;
    READ_TYPED_FIELD(jce, typeList, jce_array_t, JCE_TYPE_ARRAY);
    if (!typeList) {
        T2_PWRN(plugin_name, "failed to read typeList from GetConfig body");
        return false;
    }

    // parse array of objects
    jce_array_item_t *cur = typeList->head;
    bool first_in_array = true;
    json_printf(jbuf, "%Q: [", "typeList");
    while (cur) {
        if (first_in_array) {
            first_in_array = false;
        } else {
            json_printf(jbuf, ",");
        }

        if (cur->field->header.type != JCE_TYPE_BYTE) {
            T2_PWRN(plugin_name, "failed to decode array element of GetConfig body typeList");
        } else {
            jce_byte_t *byte = (jce_byte_t *)cur->field;
            json_printf(jbuf, "%d", byte->value);
        }

        cur = cur->next;
    }
    json_printf(jbuf, "]");

    jce_free(&typeList->base);

    return true;
}


bool decodeBodyGetSettings(jce_t* jce, struct json_out *jbuf) {
    // reserve
    jce_short_string_t *reserve;
    READ_TYPED_FIELD(jce, reserve, jce_short_string_t, JCE_TYPE_SHORT_STRING);
    if (!reserve) {
        T2_PWRN(plugin_name, "failed to read reserve from GetSettings body");
        return false;
    }

    json_printf(jbuf, "%Q: %Q", "reserve", reserve->value);
    jce_free(&reserve->base);

    return true;
}

bool decodeBodyStatReport(jce_t* jce, struct json_out *jbuf) {
    // records
    jce_array_t *data;
    READ_TYPED_FIELD(jce, data, jce_array_t, JCE_TYPE_ARRAY);
    if (!data) {
        T2_PWRN(plugin_name, "failed to read records from StatReport body");
        return false;
    }

    // parse array of objects
    jce_array_item_t *cur = data->head;
    bool first_in_array = true;
    json_printf(jbuf, "%Q: [", "data");
    while (cur) {
        if (first_in_array) {
            first_in_array = false;
        } else {
            json_printf(jbuf, ",");
        }
        json_printf(jbuf, "{");

        // each array element is an object with properties type (tag=0) and records (tag=1). records again is an array of strings.
        jce_object_t *obj;
        if (cur->field->header.type == JCE_TYPE_START) {
            obj = (jce_object_t *)cur->field;
        } else {
            T2_PWRN(plugin_name, "failed to get object in records array");
            break;
        }
        bool first_in_element = true;
        DUMP_PROPERTY_JSON(jbuf, obj, 0, JCE_TYPE_BYTE, jce_byte_t, value, "%Q: %d", "type", first_in_element)

        jce_array_t *records = jce_get_tagged_typed_item(obj, 1, JCE_TYPE_ARRAY);
        jce_array_item_t *record = records->head;
        if (first_in_element) {
            first_in_element = false;
        } else {
            json_printf(jbuf, ",");
        }

        json_printf(jbuf, "%Q: [", "records");
        bool first_in_record = true;
        while (record) {
            if (first_in_record) {
                first_in_record = false;
            } else {
                json_printf(jbuf, ",");
            }

            if (record->field->header.type == JCE_TYPE_SHORT_STRING) {
                jce_short_string_t *record_str = (jce_short_string_t *)record->field;
                json_printf(jbuf, "%Q", record_str->value);
            }

            record = record->next;
        }
        json_printf(jbuf, "]");

        cur = cur->next;

        json_printf(jbuf, "}");
    }
    json_printf(jbuf, "]");

    jce_free(&data->base);

    return true;
}


bool decompress(uint8_t *in, size_t in_len, uint8_t **outP, size_t *out_lenP) {
    z_stream stream;
    stream.zalloc = Z_NULL;
    stream.zfree = Z_NULL;
    stream.opaque = Z_NULL;
    stream.avail_in = in_len;
    stream.next_in = in;
    int ret = inflateInit(&stream);
    if (ret != Z_OK) {
        T2_PWRN(plugin_name, "zlib inflateInit() failed, unable to decompress payload");
        (*outP) = NULL;
        (*out_lenP) = 0;
        return false;
    }

    size_t const inflated_size = sizeof(uint8_t) * in_len * 2;
    uint8_t *inflated = calloc(inflated_size, 1);

    stream.next_out = inflated;
    stream.avail_out = inflated_size;

    do {
        ret = inflate(&stream, Z_SYNC_FLUSH);
        if (ret == Z_STREAM_ERROR || ret == Z_NEED_DICT || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR || ret == Z_BUF_ERROR) {
            T2_PERR(plugin_name, "zlib encountered error inflating gzip stream, aborting");
            inflateEnd(&stream);
            (*outP) = inflated;
            (*out_lenP) = stream.total_out;
            return false;
        }

        if (stream.avail_out == 0 && ret != Z_STREAM_END) { // buffer full, not done yet
            size_t const new_inflated_size = 2 * inflated_size;
            inflated = realloc(inflated, new_inflated_size);
            stream.next_out = inflated + inflated_size;
            stream.avail_out = new_inflated_size + stream.total_out;
        }

    } while (ret != Z_STREAM_END);

    inflateEnd(&stream);

    (*outP) = inflated;
    (*out_lenP) = stream.total_out;

    return true;
}


bool dump_jce_fields(jce_t *jce, struct json_out *jbuf) {
    bool first = true;
    while (t2buf_left(jce->buf) > 0) {
        jce_field_t *field;
        bool const ret = jce_read_field(jce, &field);
        if (!ret) {
            T2_PWRN(plugin_name, "failed to dump JCE fields, %" PRId64 " bytes left", t2buf_left(jce->buf));
            return false;
        }

        if (first) {
            first = false;
        } else {
            dump_json_sep(jbuf);
        }

        dump_json(jbuf, field, field->header.tag);
        jce_free(field);
    }
    return true;
}

void t2Finalize() {
#if WECHAT_JSON_ARRAY > 0
    if (jsonOutput) {
        char const close_bracket[2] = "]";
        const size_t ret = fwrite(close_bracket, 1, 1, jsonOutput);
        if (ret != 1) {
            T2_PWRN(plugin_name, "failed to write closing array bracket to JSON output file");
        }
    }
#endif
    fclose(jsonOutput);
    regfree(&re_qua);
    free(json_buf);
    free(wechatFlows);
}
