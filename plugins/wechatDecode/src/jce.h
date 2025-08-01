/*
 * jce.h
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

#ifndef __WECHAT_JCE_H__
#define __WECHAT_JCE_H__

#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include "t2buf.h"
#include "lib/frozen/frozen.h"

typedef enum {
    JCE_TYPE_BYTE,
    JCE_TYPE_SHORT,
    JCE_TYPE_INT,
    JCE_TYPE_LONG,
    JCE_TYPE_FLOAT,
    JCE_TYPE_DOUBLE,
    JCE_TYPE_SHORT_STRING,
    JCE_TYPE_LONG_STRING,
    JCE_TYPE_MAP,
    JCE_TYPE_ARRAY,
    JCE_TYPE_START,
    JCE_TYPE_END,
    JCE_TYPE_NULL,
    JCE_TYPE_BYTE_ARRAY,
} jce_type;

typedef uint8_t jce_tag;

/* The header preceding any JCE field. Contains a tag and a field type. */
typedef struct {
    jce_tag  tag;
    jce_type type;
} jce_header_t;

typedef struct {
    t2buf_t *buf;
} jce_t;


/*
 * The base field type.
 *
 * It is embedded in each specialized field subtype, which allows a basic form
 * of polymorphism. The type field of the header determines the runtime type
 * of the field.
 */
typedef struct jce_field_s {
    jce_header_t header;
} jce_field_t;


/*
 * Some helper types used by various field subtypes.
 */

/* Wrapper type to store multiple fields in a composite parent field. */
typedef struct jce_object_item_s {
    jce_field_t *field;
    struct jce_object_item_s *next;
} jce_object_item_t;

/* Wrapper type to store multiple fields in an array field. */
typedef struct jce_array_item_s {
    jce_field_t *field;
    struct jce_array_item_s *next;
} jce_array_item_t;

/* Wrapper type to store a list of key-value pair of a map. */
typedef struct jce_map_item_s {
    jce_field_t *key;
    jce_field_t *value;
    struct jce_map_item_s *next;
} jce_map_item_t;


/*
 * The different types of fields found in a JCE stream.
 */
typedef struct {
    jce_field_t base;
    jce_object_item_t *head;
} jce_object_t;

typedef struct {
    jce_field_t base;
    uint8_t value;
} jce_byte_t;

typedef struct {
    jce_field_t base;
    uint16_t value;
} jce_short_t;

typedef struct {
    jce_field_t base;
    uint32_t value;
} jce_int_t;

typedef struct {
    jce_field_t base;
    uint64_t value;
} jce_long_t;

typedef struct {
    jce_field_t base;
    float value;
} jce_float_t;

typedef struct {
    jce_field_t base;
    double value;
} jce_double_t;

typedef struct {
    jce_field_t base;
} jce_null_t;

typedef struct {
    jce_field_t base;
} jce_end_t;

typedef struct {
    jce_field_t base;
    uint8_t len;
    char value[255];
} jce_short_string_t;

typedef struct {
    jce_field_t base;
    uint32_t len;
    char *value;
} jce_long_string_t;

typedef struct {
    jce_field_t base;
    uint64_t len;
    uint8_t *values;
} jce_byte_array_t;

typedef struct {
    jce_field_t base;
    uint32_t len;
    jce_array_item_t *head;
} jce_array_t;

typedef struct {
    jce_field_t base;
    uint32_t len;
    jce_map_item_t *head;
} jce_map_t;


/*
 * Function prototypes.
 */
jce_t jce_create(t2buf_t* buf);
void jce_free(jce_field_t *field);
bool jce_read_field(jce_t *jce, jce_field_t **out_field);
bool jce_print_field(jce_field_t const *field);
jce_field_t* jce_get_tagged_item      (jce_object_t const *obj, uint8_t tag);
void*        jce_get_tagged_typed_item(jce_object_t const *obj, uint8_t tag, jce_type type);


/*
 * TEA cipher decryption functions.
 */
bool jce_decrypt_tea(uint8_t *data, size_t const len, uint32_t const key[4]);
void jce_decrypt_tea_block(uint32_t block[2], uint32_t const key[4]);
bool jce_unpad(uint8_t *data, size_t len, size_t* out_pos, size_t* out_len);

#endif
