/*
 * jce.c
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
 * * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include "jce.h"

#include "missing/missing.h"
#include "t2buf.h"
#include "t2log.h"

#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

#define JCE_TEA_DECRYPT_DEBUG 0
#define JCE_DEBUG_LEVEL 0

#define JCE_TAG_MASK         0xF0
#define JCE_TYPE_MASK        0x0F
#define JCE_TAG_IN_NEXT_BYTE 0xF0

#define JCE_TYPE_CODE_BYTE           0x00
#define JCE_TYPE_CODE_SHORT          0x01
#define JCE_TYPE_CODE_INT            0x02
#define JCE_TYPE_CODE_LONG           0x03
#define JCE_TYPE_CODE_FLOAT          0x04
#define JCE_TYPE_CODE_DOUBLE         0x05
#define JCE_TYPE_CODE_SHORT_STRING   0x06
#define JCE_TYPE_CODE_LONG_STRING    0x07
#define JCE_TYPE_CODE_MAP            0x08
#define JCE_TYPE_CODE_ARRAY          0x09
#define JCE_TYPE_CODE_START          0x0A
#define JCE_TYPE_CODE_END            0x0B
#define JCE_TYPE_CODE_NULL           0x0C
#define JCE_TYPE_CODE_BYTE_ARRAY     0x0D

bool jce_read_header       (jce_t *jce, jce_header_t *out_header);
bool jce_read_object_fields(jce_t *jce, jce_object_t *object);
bool jce_read_array        (jce_t *jce, jce_array_t *arr);

bool jce_read_byte_array(jce_t *jce, jce_byte_array_t *array);

void xor_lhs_with(char *a, char const *b, size_t const len);

jce_t jce_create(t2buf_t *buf) {
    jce_t newbuf = {
        .buf = buf,
    };
    return newbuf;
}

void jce_free(jce_field_t *field) {
    if (!field) {
        return;
    }

    switch (field->header.type) {
        case JCE_TYPE_BYTE:
        case JCE_TYPE_SHORT:
        case JCE_TYPE_INT:
        case JCE_TYPE_LONG:
        case JCE_TYPE_FLOAT:
        case JCE_TYPE_DOUBLE:
        case JCE_TYPE_SHORT_STRING:
            free(field);
            break;

        case JCE_TYPE_LONG_STRING: {
            jce_long_string_t *str = (jce_long_string_t *)field;
            if (str->value) {
                free(str->value);
            }
            free(field);
            break;
        }

        case JCE_TYPE_MAP: {
            jce_map_t *map = (jce_map_t *)field;
            jce_map_item_t *item = map->head;
            while (item) {
                jce_map_item_t * const next = item->next;
                jce_free(item->key);
                jce_free(item->value);
                free(item);
                item = next;
            }
            free(field);
            break;
        }

        case JCE_TYPE_START: {
            jce_object_t *object = (jce_object_t *)field;
            jce_object_item_t *item = object->head;
            while (item) {
                jce_object_item_t * const next = item->next;
                jce_free(item->field);
                free(item);
                item = next;
            }
            free(field);
            break;
        }

        case JCE_TYPE_ARRAY: {
            jce_array_t *arr = (jce_array_t *)field;
            jce_array_item_t *item = arr->head;
            while (item) {
                jce_array_item_t * const next = item->next;
                jce_free(item->field);
                free(item);
                item = next;
            }
            free(field);
            break;
        }

        case JCE_TYPE_BYTE_ARRAY: {
            jce_byte_array_t *arr = (jce_byte_array_t *)field;
            if (arr->values) {
                free(arr->values);
            }
            free(field);
            break;
        }

        case JCE_TYPE_END:
        case JCE_TYPE_NULL:
            T2_ERR("jce_free(): impossible type %d, skipping", field->header.type);
            break;
    }
}

bool jce_read_field(jce_t *jce, jce_field_t **out_field) {
    jce_header_t header;
    if (!jce_read_header(jce, &header)) {
        printf("failed to read JCE header!\n");
        return false;
    }

#if JCE_DEBUG_LEVEL > 1
    printf("read JCE header: (%d, %d)\n", header.tag, header.type);
#endif

    switch (header.type) {
        case JCE_TYPE_START: {
#if JCE_DEBUG_LEVEL > 1
            printf("read JCE START\n");
#endif
            jce_object_t *field = malloc(sizeof(*field));
            field->base.header = header;
            (*out_field) = &field->base;
            if (!jce_read_object_fields(jce, field)) {
                printf("failed to read all object fields! partial result will be returned.\n");
                return false;
            }
            break;
        }

        case JCE_TYPE_END: {
#if JCE_DEBUG_LEVEL > 1
            printf("read JCE END\n");
#endif
            jce_end_t *field = malloc(sizeof(*field));
            field->base.header = header;
            (*out_field) = &field->base;
            break;
        }

        case JCE_TYPE_BYTE_ARRAY: {
#if JCE_DEBUG_LEVEL > 1
            printf("read JCE BYTE ARRAY\n");
#endif
            jce_byte_array_t *field = malloc(sizeof(*field));
            field->base.header = header;
            (*out_field) = &field->base;
            if (!jce_read_byte_array(jce, field)) {
                printf("failed to read all byte array values! partial result will be returned.\n");
                return false;
            }
#if JCE_DEBUG_LEVEL > 1
            printf("successfully read JCE byte array");
#endif
            break;
        }

        case JCE_TYPE_ARRAY: {
#if JCE_DEBUG_LEVEL > 1
            printf("read JCE ARRAY\n");
#endif
            jce_array_t *arr = malloc(sizeof(*arr));
            arr->base.header = header;
            (*out_field) = &arr->base;
            jce_field_t *field;
            if (!jce_read_field(jce, &field)) {
                printf("failed to read array length!\n");
                return false;
            }
            if (field->header.type != JCE_TYPE_BYTE) {
                printf("array length is not an integer!\n");
                return false;
            }
            arr->len = ((jce_byte_t *)field)->value;
            arr->head = NULL;
            jce_free(field);
#if JCE_DEBUG_LEVEL > 1
            printf("array length is %d\n", arr->len);
#endif
            if (!jce_read_array(jce, arr)) {
                printf("failed to read all array elements! partial result will be returned.\n");
                return false;
            }
            break;
        }

#define JCE_CASE_TYPE_READ_MACRO(JCE_TYPE_NAME, JCE_TYPE, TYPE, T2BUF_TYPE) \
        case JCE_TYPE_ ## JCE_TYPE_NAME: { \
            TYPE value; \
            if (!t2buf_read_##T2BUF_TYPE (jce->buf, &value)) { \
                printf("failed to read jce data from t2buf!\n"); \
                return false; \
            } \
            JCE_TYPE *field = malloc(sizeof(*field)); \
            field->base.header = header; \
            field->value = value; \
            (*out_field) = &field->base; \
            break; \
        }

        JCE_CASE_TYPE_READ_MACRO(BYTE,  jce_byte_t,  uint8_t,  u8)
        JCE_CASE_TYPE_READ_MACRO(SHORT, jce_short_t, uint16_t, u16)
        JCE_CASE_TYPE_READ_MACRO(INT,   jce_int_t,   uint32_t, u32)
        JCE_CASE_TYPE_READ_MACRO(LONG,  jce_long_t,  uint64_t, u64)

        case JCE_TYPE_FLOAT: {
#if JCE_DEBUG_LEVEL > 1
            printf("read JCE FLOAT\n");
#endif
            header.type = JCE_TYPE_FLOAT;
            jce_double_t *field = malloc(sizeof(*field));
            field->base.header = header;
            uint32_t value;
            if (!t2buf_read_u32(jce->buf, &value)) {
                printf("failed to read jce float\n");
                return false;
            }
            value = be32toh(value);
            //value = ((value & 0x000000ffu) << 24)
            //      | ((value & 0x0000ff00u) << 8)
            //      | ((value & 0x00ff0000u) >> 8)
            //      | ((value & 0xff000000u) >> 24);
            memcpy((void *) &field->value, (void *) &value, sizeof(float));
#if JCE_DEBUG_LEVEL > 1
            printf("read float: %f (from bytes %d)\n", field->value, value);
#endif
            (*out_field) = &field->base;
            break;
        }

        case JCE_TYPE_DOUBLE: {
#if JCE_DEBUG_LEVEL > 1
            printf("read JCE DOUBLE\n");
#endif
            header.type = JCE_TYPE_DOUBLE;
            jce_double_t *field = malloc(sizeof(*field));
            field->base.header = header;
            uint64_t value;
            if (!t2buf_read_u64(jce->buf, &value)) {
                printf("failed to read jce double\n");
                return false;
            }
            value = be64toh(value);
            //value = ((value & 0x00000000000000ffu) << 56)
            //      | ((value & 0x000000000000ff00u) << 40)
            //      | ((value & 0x0000000000ff0000u) << 24)
            //      | ((value & 0x00000000ff000000u) << 8)
            //      | ((value & 0x000000ff00000000u) >> 8)
            //      | ((value & 0x0000ff0000000000u) >> 24)
            //      | ((value & 0x00ff000000000000u) >> 40)
            //      | ((value & 0xff00000000000000u) >> 56);
            memcpy((void *) &field->value, (void *) &value, sizeof(double));
#if JCE_DEBUG_LEVEL > 1
            printf("read double: %f (from bytes %lu)\n", field->value, value);
#endif
            (*out_field) = &field->base;
            break;
        }

        case JCE_TYPE_SHORT_STRING: {
#if JCE_DEBUG_LEVEL > 1
            printf("read JCE SHORT STRING\n");
#endif
            uint8_t length;
            char value[255];
            if (!t2buf_read_u8(jce->buf, &length)) {
                printf("failed to read jce short string length from t2buf!\n");
                return false;
            }
#if JCE_DEBUG_LEVEL > 1
            printf("short str len = %d\n", length);
#endif
            if (!t2buf_readstr(jce->buf, (uint8_t *)value, length + 1, T2BUF_UTF8, true)) {
                printf("failed to read jce short string length from t2buf!\n");
                return false;
            }
#if JCE_DEBUG_LEVEL > 1
            printf("short str = %s\n", value);
#endif
            jce_short_string_t *field = malloc(sizeof(*field));
            field->base.header = header;
            field->len = length;
            memcpy(field->value, value, length + 1);
            (*out_field) = &field->base;
            break;
        }

        case JCE_TYPE_LONG_STRING: {
#if JCE_DEBUG_LEVEL > 1
            printf("read JCE LONG STRING\n");
#endif
            uint32_t length;
            if (!t2buf_read_u32(jce->buf, &length)) {
                printf("failed to read jce short string length from t2buf!\n");
                return false;
            }
#if JCE_DEBUG_LEVEL > 1
            printf("long str len = %d\n", length);
#endif
            char *value = malloc(sizeof(char) * length + 1);
            if (!t2buf_readstr(jce->buf, (uint8_t *)value, length + 1, T2BUF_UTF8, true)) {
                printf("failed to read jce long string length from t2buf!\n");
                return false;
            }
#if JCE_DEBUG_LEVEL > 1
            printf("long str = %s\n", value);
#endif
            jce_long_string_t *field = malloc(sizeof(*field));
            field->base.header = header;
            field->len = length;
            field->value = value;
            (*out_field) = &field->base;
            break;
        }

        case JCE_TYPE_MAP: {
            jce_map_t *map = malloc(sizeof(*map));
            jce_field_t *length_field;
            if (!jce_read_field(jce, &length_field)) {
                printf("length field map read fail");
                free(map);
                return false;
            }
            if (length_field->header.type != JCE_TYPE_BYTE) {
                printf("failed to read map length, expected byte but got %d\n", length_field->header.type);
                // TODO: clean up memory
                return false;
            }
            map->len = ((jce_byte_t *)length_field)->value;
            jce_map_item_t *prev = NULL;
            for (size_t i = 0; i < map->len; i++) {
                jce_map_item_t *item = malloc(sizeof(*item));
                jce_field_t *key;
                jce_field_t *value;
                // not enforcing tag values of 0 and 1 for the key and value, respectively.
                if (!jce_read_field(jce, &key)) {
                    printf("failed to read map item key at index %lu\n", i);
                    // TODO: clean up memory
                    return false;
                }
                if (!jce_read_field(jce, &value)) {
                    printf("failed to read map item value at index %lu\n", i);
                    // TODO: clean up memory
                    return false;
                }
                item->key = key;
                item->value = value;
                item->next = NULL;
                if (prev) {
                    prev->next = item;
                } else {
                    prev = item;
                }
            }
            (*out_field) = &map->base;

            break;
        }

        case JCE_TYPE_NULL: {
            // A null is converted into a zero byte on the fly.
#if JCE_DEBUG_LEVEL > 1
            printf("read JCE NULL -> treat as JCE_BYTE with value of 0\n");
#endif
            header.type = JCE_TYPE_BYTE;
            jce_byte_t *field = malloc(sizeof(*field));
            field->base.header = header;
            field->value = 0;
            (*out_field) = &field->base;
            break;
        }
    }

    return true;
}

bool jce_extract_integer(jce_field_t *field, uint64_t *out_result) {

    switch (field->header.type) {
        case JCE_TYPE_BYTE:
            *out_result = (uint64_t)((jce_byte_t *)field)->value;
            break;
        case JCE_TYPE_SHORT:
            *out_result = (uint64_t)((jce_short_t *)field)->value;
            break;
        case JCE_TYPE_INT:
            *out_result = (uint64_t)((jce_int_t *)field)->value;
            break;
        case JCE_TYPE_LONG:
            *out_result = (uint64_t)((jce_long_t *)field)->value;
            break;
        default:
            return false;
    }

#if JCE_DEBUG_LEVEL > 1
    printf("extracted value: %lu\n", *out_result);
#endif
    return true;
}

bool jce_read_byte_array(jce_t *jce, jce_byte_array_t *array) {
    uint8_t value;
    uint64_t length;
    if (!t2buf_read_u8(jce->buf, &value)) {
        printf("failed to read byte array null byte\n");
        return false;
    }
    if (value != 0) {
        printf("byte array null byte is not 0! (value: %d)\n", value);
        return false;
    }

#if JCE_DEBUG_LEVEL > 1
    printf("reading byte array length\n");
#endif
    jce_field_t *field;
    if (!jce_read_field(jce, &field)) {
        printf("failed to read byte array length\n");
        return false;
    }
    if (!jce_extract_integer(field, &length)) {
        printf("failed to convert byte array length\n");
        free(field);
        field = NULL;
        return false;
    }
    free(field);
    field = NULL;

#if JCE_DEBUG_LEVEL > 1
    printf("byte array length: %lu\n", length);
#endif
    array->len = length;
    array->values = (uint8_t *)malloc(sizeof(uint8_t) * length);

#if JCE_DEBUG_LEVEL > 1
    printf("printing byte array raw bytes:\n  ");
    for (size_t i = 0; i < length; i++) {
        printf("%02x ", *(jce->buf->buffer + jce->buf->pos + i));
    }
    printf("\n");
#endif

    for (uint_fast64_t i = 0; i < length; i++) {
        if (!t2buf_read_u8(jce->buf, &value)) {
            printf("failed to read byte %" PRIuFAST64 "\n", i);
            return false;
        }

#if JCE_DEBUG_LEVEL > 1
        printf("read byte array value at pos %lu: %02x (%d)\n", i, value, value);
#endif
        array->values[i] = value;
    }
    return true;
}

bool jce_read_object_fields(jce_t *jce, jce_object_t *object) {
    jce_field_t *field;
    jce_object_item_t *prev = NULL;
    while (true) {
#if JCE_DEBUG_LEVEL > 1
        printf("reading object field\n");
#endif
        bool ret = jce_read_field(jce, &field);
        if (!ret) {
           printf("failed to read field\n");
           return false;
        }
        if (field->header.type == JCE_TYPE_END) {
#if JCE_DEBUG_LEVEL > 1
            printf("done reading object fields, read JCE_END\n");
#endif
            free(field);
            break;
        }

        jce_object_item_t *current = malloc(sizeof(*current));
        current->next = NULL;
        current->field = field;

        if (prev) {
            prev->next = current;
        } else {
            object->head = current;
        }

        prev = current;
    }

    return true;
}

bool jce_read_array(jce_t *jce, jce_array_t *arr) {
    jce_field_t *field;
    jce_array_item_t *prev = NULL;
    jce_type element_type;
    for (uint_fast32_t i = 0; i < arr->len; i++) {
#if JCE_DEBUG_LEVEL > 1
        printf("reading array element\n");
#endif
        bool ret = jce_read_field(jce, &field);
        if (!ret) {
           printf("failed to read array element\n");
           return false;
        }

        // sanity checks
        if (field->header.tag != 0) {
           printf("expected array element tag to be 0, was: %d\n", field->header.tag);
        }
        if (i == 0) {
            element_type = field->header.type;
#if JCE_DEBUG_LEVEL > 1
            printf("first array element has type %d\n", element_type);
#endif
        } else if (field->header.type != element_type) {
           printf("expected array element type to be %d, was: %d\n", element_type, field->header.type);
        }

        jce_array_item_t *current = malloc(sizeof(*current));
        current->next = NULL;
        current->field = field;

        if (prev) {
            prev->next = current;
        } else {
            arr->head = current;
        }

        prev = current;
    }
#if JCE_DEBUG_LEVEL > 1
    printf("done reading array elements\n");
#endif

    return true;
}

bool jce_read_header(jce_t *jce, jce_header_t *out_header) {
    // TODO: return error code in case of failure. store error code in jce_t.err?

    uint8_t byte;
    if (!t2buf_read_u8(jce->buf, &byte)) {
        printf("failed to read byte from t2buf");
        return false;
    }

    // read type
#define JCE_CASE_TYPE_MACRO(TYPE_NAME, RESULT) \
        case JCE_TYPE_CODE_ ## TYPE_NAME: \
            RESULT = JCE_TYPE_ ## TYPE_NAME; \
            break;

    jce_type type;
    switch (byte & JCE_TYPE_MASK) {
        JCE_CASE_TYPE_MACRO(BYTE,         type)
        JCE_CASE_TYPE_MACRO(SHORT,        type)
        JCE_CASE_TYPE_MACRO(INT,          type)
        JCE_CASE_TYPE_MACRO(LONG,         type)
        JCE_CASE_TYPE_MACRO(FLOAT,        type)
        JCE_CASE_TYPE_MACRO(DOUBLE,       type)
        JCE_CASE_TYPE_MACRO(SHORT_STRING, type)
        JCE_CASE_TYPE_MACRO(LONG_STRING,  type)
        JCE_CASE_TYPE_MACRO(MAP,          type)
        JCE_CASE_TYPE_MACRO(ARRAY,        type)
        JCE_CASE_TYPE_MACRO(START,        type)
        JCE_CASE_TYPE_MACRO(END,          type)
        JCE_CASE_TYPE_MACRO(NULL,         type)
        JCE_CASE_TYPE_MACRO(BYTE_ARRAY,   type)

        default:
            printf("unknown type encountered when reading field: %d\n", byte & JCE_TYPE_MASK);
            return false;
    }

    // read tag
    uint8_t tag = (byte & JCE_TAG_MASK);
    if (tag == JCE_TAG_IN_NEXT_BYTE) { // indicates large 8-bit tag in following byte.
        if (!t2buf_read_u8(jce->buf, &byte)) {
            printf("failed to read extra long tag byte from t2buf");
            return false;
        }
        tag = byte;
    } else { // regular 4-bit tag in most significant bits.
        tag = tag >> 4;
    }

    out_header->tag  = tag;
    out_header->type = type;

    return true;
}

bool jce_print_field(jce_field_t const *field) {
    switch (field->header.type) {
        case JCE_TYPE_START: {
            printf("JCE_START\n");
            jce_object_t *object = (jce_object_t *)field;
            jce_object_item_t *item = object->head;
            while (item) {
                printf("  object item\n");
                jce_print_field(item->field);
                item = item->next;
            }
            break;
         }

#define JCE_CASE_TYPE_PRINT_MACRO(JCE_TYPE_NAME, JCE_TYPE) \
        case JCE_TYPE_ ## JCE_TYPE_NAME: { \
            JCE_TYPE *val = (JCE_TYPE *)field; \
            printf("JCE_" #JCE_TYPE_NAME); \
            printf("  value = %" PRIu64 "\n", (uint64_t)val->value); \
            break; \
        }

        JCE_CASE_TYPE_PRINT_MACRO(BYTE,  jce_byte_t)
        JCE_CASE_TYPE_PRINT_MACRO(SHORT, jce_short_t)
        JCE_CASE_TYPE_PRINT_MACRO(INT,   jce_int_t)
        JCE_CASE_TYPE_PRINT_MACRO(LONG,  jce_long_t)

        case JCE_TYPE_BYTE_ARRAY: {
            printf("JCE_BYTE_ARRAY\n");
            jce_byte_array_t *arr = (jce_byte_array_t *)field;
            printf("  len = %" PRIu64 "\n", arr->len);
            for (uint_fast64_t i = 0; i < arr->len; i++) {
                printf("   [%" PRIuFAST64 "] = %d\n", i, arr->values[i]);
            }
            break;
        }

        case JCE_TYPE_ARRAY: {
            jce_array_t *arr = (jce_array_t *)field;
            printf("JCE_ARRAY (len = %d)\n", arr->len);
            jce_array_item_t *item = arr->head;
            while (item) {
                printf("  array element\n");
                jce_print_field(item->field);
                item = item->next;
            }
            break;
         }

        case JCE_TYPE_MAP: {
            jce_map_t *map = (jce_map_t *)field;
            printf("JCE_MAP (len = %d)\n", map->len);
            jce_map_item_t *item = map->head;
            while (item) {
                printf("  key:");
                jce_print_field(item->key);
                printf("  value:");
                jce_print_field(item->value);
                item = item->next;
            }
            break;
         }

        case JCE_TYPE_SHORT_STRING: {
            printf("JCE_SHORT_STRING\n");
            jce_short_string_t *sstr = (jce_short_string_t *)field;
            printf("  str (len = %d) = %s\n", sstr->len, sstr->value);
            break;
        }

        case JCE_TYPE_NULL: {
            printf("JCE_NULL\n");
            printf("  null\n");
            break;
        }

        default:
            printf("! printing unknown type (%d) !\n", field->header.type);
    }
    return true;
}

void* jce_get_tagged_typed_item(jce_object_t const *obj, uint8_t tag, jce_type type) {
    jce_object_item_t *cur = obj->head;
    while (cur) {
        if (cur->field->header.tag == tag && cur->field->header.type == type) {
            return cur->field;
        }
        cur = cur->next;
    }
    return NULL;
}

jce_field_t* jce_get_tagged_item(jce_object_t const *obj, uint8_t tag) {
    jce_object_item_t *cur = obj->head;
    while (cur) {
        if (cur->field->header.tag == tag) {
            return cur->field;
        }
        cur = cur->next;
    }
    return NULL;
}

bool jce_decrypt_tea(uint8_t * const data, size_t const len, uint32_t const key_bigendian[4]) {
    // Probably not the most efficient way of implementing this, but good enough for now.
    if (len % 8 != 0) {
        printf("invalid encrypted data length %lu (must be multiple of 8)\n", len);
        return false;
    }

    uint32_t key[4];
    //memcpy_2u32((char *) key,     (char *) key_bigendian);
    //memcpy_2u32((char *) &key[2], (char *) &key_bigendian[2]);
    key[0] = be32toh(key_bigendian[0]);
    key[1] = be32toh(key_bigendian[1]);
    key[2] = be32toh(key_bigendian[2]);
    key[3] = be32toh(key_bigendian[3]);

#if JCE_TEA_DECRYPT_DEBUG > 0
    printf("starting TEA decrypt (len = %lu) ...\n", len);

    printf("key bigendian bytes: %08" PRIx32 " %08" PRIx32 " %08" PRIx32  " %08" PRIx32 "\n", key_bigendian[0], key_bigendian[1], key_bigendian[2], key_bigendian[3]);
    printf("key           bytes: %08" PRIx32 " %08" PRIx32 " %08" PRIx32  " %08" PRIx32 "\n", key[0], key[1], key[2], key[3]);
#endif

    uint32_t block[2];
    uint32_t cipher_block_tmp[2] = {};
    uint32_t previous_plaintext_block[2]  = {};
    uint32_t previous_ciphertext_block[2] = {};
    for (size_t offset = 0; offset < len; offset += 8) {
#if JCE_TEA_DECRYPT_DEBUG > 0
        printf("decrypting bytes %lu - %lu\n", offset, offset + 8);
#endif
        // load current ciphertext block of encrypted data into buffer
        // and keep a copy around for the next iterations block
        //memcpy_2u32((char *) block, data + offset);
        block[0] = be32toh(*(uint32_t *) (data + offset));
        block[1] = be32toh(*(uint32_t *) (data + offset + 4));

        // TOOD: need to do this later, needs to be zero after first round before xor.
        memcpy((void *) cipher_block_tmp, (void *) block, 8);

#if JCE_TEA_DECRYPT_DEBUG > 0
        printf("cipher bytes: %08" PRIx32 " %08" PRIx32 "\n", block[0], block[1]);
#endif

        // xor and decrypt in-place
#if JCE_TEA_DECRYPT_DEBUG > 0
        printf("previous plain bytes: %08" PRIx32 " %08" PRIx32 "\n", previous_plaintext_block[0], previous_plaintext_block[1]);
#endif
        xor_lhs_with((char *) block, (char *) previous_plaintext_block, 8);
#if JCE_TEA_DECRYPT_DEBUG > 0
        printf("in decrypt_block: key bytes: %08" PRIx32 " %08" PRIx32 " %08" PRIx32  " %08" PRIx32 "\n", key[0], key[1], key[2], key[3]);
#endif
        jce_decrypt_tea_block(block, key);
#if JCE_TEA_DECRYPT_DEBUG > 0
        printf("plain bytes: %08" PRIx32 " %08" PRIx32 "\n", block[0], block[1]);
        printf("last  bytes: %08" PRIx32 " %08" PRIx32 "\n", previous_ciphertext_block[0], previous_ciphertext_block[1]);
#endif
        memcpy((void *) previous_plaintext_block, (void *) block, 8);
        xor_lhs_with((char *) block, (char *) previous_ciphertext_block, 8);
#if JCE_TEA_DECRYPT_DEBUG > 0
        printf("plain xored bytes: %08" PRIx32 " %08" PRIx32 "\n", block[0], block[1]);
#endif

        // write plaintext back into buffer
        memcpy((void *) previous_ciphertext_block, (void *) cipher_block_tmp, 8);
        //memcpy_2u32(data + offset, (char *) block);
        *((uint32_t *) (data + offset))     = htobe32(block[0]);
        *((uint32_t *) (data + offset + 4)) = htobe32(block[1]);
#if JCE_TEA_DECRYPT_DEBUG > 0
        printf("\n");
#endif
    }

    //  last = bytes(8)
    //  ptblock = bytes(8)
    //  pt = b''
    //  for block in [data[i:i+8] for i in range(0, len(data), 8)]:
    //      ctblock = bytes(a ^ b for a, b in zip(block, ptblock))
    //      ptblock = decrypt_block(ctblock, key, 16)
    //      newbytes = bytes(a ^ b for a, b in zip(last, ptblock))
    //      pt += newbytes
    //      last = block
    //  return pt


#if JCE_TEA_DECRYPT_DEBUG > 0
    printf("done TEA decrypt\n");
#endif
    return true;
}

/*
 * Copy 4 bytes from big-endian byte array to little-endian uint32.
 */
//void memcpy_2u32(char * const dst, char * const src) {
//    // manually unrolled loop
//    // TODO: Use shifts to be independent of system endianness and portable.
//    dst[0] = src[3];
//    dst[1] = src[2];
//    dst[2] = src[1];
//    dst[3] = src[0];
//
//    dst[4] = src[7];
//    dst[5] = src[6];
//    dst[6] = src[5];
//    dst[7] = src[4];
//}

void jce_decrypt_tea_block(uint32_t block[2], uint32_t const key[4]) {
    uint32_t b0 = block[0], b1 = block[1];
    uint32_t k0 = key[0], k1 = key[1], k2 = key[2], k3 = key[3];
    uint32_t const delta = 0x9e3779b9;
#if JCE_TEA_DECRYPT_DEBUG > 1
    printf("in decrypt_block: key bytes: %08" PRIx32 " %08" PRIx32 " %08" PRIx32  " %08" PRIx32 "\n", key[0], key[1], key[2], key[3]);
    printf("b0 = %lu, b1 = %lu\n", b0, b1);
    printf("k0 = %lu, k1 = %lu, k2 = %lu, k3 = %lu\n", k0, k1, k2, k3);
#endif
    uint32_t sum = delta * 16;
    for (uint_fast8_t round = 0; round < 16; round++) {
        b1 -= ((b0 << 4) + k2) ^ (b0 + sum) ^ ((b0 >> 5) + k3);
        b0 -= ((b1 << 4) + k0) ^ (b1 + sum) ^ ((b1 >> 5) + k1);
        sum -= delta;
#if JCE_TEA_DECRYPT_DEBUG > 0
        printf("round %" PRIuFAST8 ": b0 = %lu, b1 = %lu, sum = %lu, delta = %lu\n", round, b0, b1, sum, delta);
#endif
    }
    block[0] = b0;
    block[1] = b1;
}

void xor_lhs_with(char *a, char const *b, size_t const len) {
    for (size_t i = 0; i < len; i++) {
        a[i] ^= b[i];
    }
}

bool jce_unpad(uint8_t *data, size_t len, size_t* out_pos, size_t* out_len) {
    size_t pos = data[0] & 0x7;
    int const length = len - pos - 10;
#if JCE_DEBUG_LEVEL > 1
    printf("jce_unpad: pos = %lu\n", pos);
    printf("jce_unpad: data[0] = %d\n", data[0]);
    printf("jce_unpad: data[0] & 0x7 = %d\n", data[0] & 0x7);
#endif
    if (length < 0) {
        printf("unpad length is negative!\n");
        return false;
    }
    pos += 3;

    *out_pos = pos;
    *out_len = length;

    return true;
}
