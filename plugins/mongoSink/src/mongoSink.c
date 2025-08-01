/*
 * mongoSink.c
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

#include "mongoSink.h"

#include <assert.h>
#include <bson.h>
#include <mongoc.h>
#include <string.h>


#if BLOCK_BUF == 0

// Static variables

static uint64_t num_docs;
static bson_t *documents[MONGO_NUM_DOCS];
static mongoc_client_t *client;
static mongoc_database_t *database;
static mongoc_collection_t *collection;
#if !MONGOC_CHECK_VERSION(1,9,0) && MONGO_NUM_DOCS > 1
static mongoc_bulk_operation_t *bulk;
#endif

#if MONGO_SELECT == 1
static bool *feature_active;
#endif


// Function prototypes

static inline void db_cleanup();
static bool parse_binary2bson(outputBuffer_t *buf, binary_value_t * const bv);
static bool parse_subval_bson(outputBuffer_t *buf, const binary_subvalue_t *sv, const char *name, bson_t *parent
#if MONGO_SELECT == 1
    , bool print
#endif
);
static bool parse_binary_value_bson(outputBuffer_t *buf, binary_type_t type, const char *name, bson_t *parent
#if MONGO_SELECT == 1
    , bool print
#endif
);
static bool mongo_sanitize_utf8(outputBuffer_t *buf, char *qry, int *pos
#if MONGO_SELECT == 1
    , bool print
#endif
);
static inline bool mongo_get_val_func(outputBuffer_t *buf, void *dest, size_t size, size_t n);
#if MONGO_SELECT == 1
// Returned value MUST be free'd
static inline bool *mongo_select_load(binary_value_t *bv, const char *filename);
#endif


// Defines

// Wrapper for snprintf.
// Increases pos by the number of bytes written
#define MONGO_SNPRINTF(pos, str, size, format, args...) { \
    const int n = snprintf(str, (size), format, ##args); \
    if (UNLIKELY(n >= (size))) { \
        T2_PERR(plugin_name, "query truncated... increase MONGO_QRY_LEN"); \
        db_cleanup(); \
        exit(EXIT_FAILURE); \
    } \
    pos += n; \
}

#endif // BLOCK_BUF == 0


// Tranalyzer functions

T2_PLUGIN_INIT("mongoSink", "0.9.3", 0, 9);


void t2Init() {
#if BLOCK_BUF == 1
    T2_PWRN(plugin_name, "BLOCK_BUF is set in 'tranalyzer.h', no output will be produced");
#else // BLOCK_BUF == 0

#if TSTAMP_PREC == 1
    T2_PWRN(plugin_name, "timestamps with nanosecond precision not supported (truncated to millisecond precision)");
    T2_PINF(plugin_name, "Run 't2conf tranalyzer2 -D TSTAMP_PREC=0' to silence this warning");
#endif // TSTAMP_PREC == 1

#if ENVCNTRL > 0
    t2_env_t env[ENV_MONGO_N] = {};
    t2_get_env(PLUGIN_SRCH, ENV_MONGO_N, env);
    const char * const host = T2_ENV_VAL(MONGO_HOST);
    const uint16_t port = T2_ENV_VAL_UINT(MONGO_PORT);
    const char * const dbName = T2_ENV_VAL(MONGO_DBNAME);
    const char * const tableName = T2_ENV_VAL(MONGO_TABLE_NAME);
#if MONGO_SELECT == 1
    const char * const selectFile = T2_ENV_VAL(MONGO_SELECT_FILE);
#endif // MONGO_SELECT == 1
#else // ENVCNTRL == 0
    const char * const host = MONGO_HOST;
    const uint16_t port = MONGO_PORT;
    const char * const dbName = MONGO_DBNAME;
    const char * const tableName = MONGO_TABLE_NAME;
#if MONGO_SELECT == 1
    const char * const selectFile = MONGO_SELECT_FILE;
#endif // MONGO_SELECT == 1
#endif // ENVCNTRL

    mongoc_init();

    char * const addr = t2_strdup_printf("mongodb://%s:%" PRIu16, host, port);

    if (UNLIKELY(!(client = mongoc_client_new(addr)))) {
        T2_PERR(plugin_name, "Failed to connect to DB on '%s'", addr);
        free(addr);
        exit(EXIT_FAILURE);
    }

    mongoc_client_set_appname(client, dbName);

    if (UNLIKELY(!(database = mongoc_client_get_database(client, dbName)))) {
        T2_PERR(plugin_name, "Failed to connect to DB '%s' on '%s'", dbName, addr);
        free(addr);
        db_cleanup();
        exit(EXIT_FAILURE);
    }

    if (UNLIKELY(!(collection = mongoc_client_get_collection(client, dbName, tableName)))) {
        T2_PERR(plugin_name, "Failed to get collection '%s' from DB '%s' on '%s'", tableName, dbName, addr);
        free(addr);
        db_cleanup();
        exit(EXIT_FAILURE);
    }

    free(addr);

#if !MONGOC_CHECK_VERSION(1,9,0) && MONGO_NUM_DOCS > 1
    bulk = mongoc_collection_create_bulk_operation(collection, false, NULL);
#endif

    for (uint_fast64_t i = 0; i < MONGO_NUM_DOCS; i++) {
        if (UNLIKELY(!(documents[i] = bson_new()))) {
            T2_PERR(plugin_name, "Failed to create new BSON document");
            db_cleanup();
            exit(EXIT_FAILURE);
        }
    }

#if MONGO_SELECT == 1
    feature_active = mongo_select_load(main_header_bv, selectFile);
#endif // MONGO_SELECT == 1

#if ENVCNTRL > 0
    t2_free_env(ENV_MONGO_N, env);
#endif // ENVCNTRL > 0

#endif // BLOCK_BUF == 0
}


// If BLOCK_BUF == 1, the plugin does not produce any output.
// All the code below is therefore not activated.


#if BLOCK_BUF == 0

void t2Finalize() {
    db_cleanup();
}


static inline void db_cleanup() {
    for (uint_fast64_t i = 0; i < MONGO_NUM_DOCS; i++) {
        if (LIKELY(documents[i] != NULL)) bson_destroy(documents[i]);
    }
#if !MONGOC_CHECK_VERSION(1,9,0) && MONGO_NUM_DOCS > 1
    if (LIKELY(bulk != NULL)) mongoc_bulk_operation_destroy(bulk);
#endif
    if (LIKELY(collection != NULL)) mongoc_collection_destroy(collection);
    if (LIKELY(database != NULL)) mongoc_database_destroy(database);
    if (LIKELY(client != NULL)) mongoc_client_destroy(client);
    mongoc_cleanup();
#if MONGO_SELECT == 1
    free(feature_active);
#endif
}


static inline bool mongo_get_val_func(outputBuffer_t *buf, void *dest, size_t size, size_t n) {
    const size_t sn = size * n;
    if (UNLIKELY(buf->size < buf->pos + sn)) {
        // TODO count number of corrupt flows and return an error (see jsonSink.c)
        const size_t required = buf->pos + sn;
        T2_PERR(plugin_name, "Buffer overflow: %zu increase MAIN_OUTBUF_SIZE in tranalyzer.h", required);
        return false;
    }

    memcpy(dest, buf->buffer + buf->pos, sn);
    buf->pos += sn;
    return true;
}


#if !MONGOC_CHECK_VERSION(1,9,0) && MONGO_NUM_DOCS > 1
static inline void mongo_insert_doc(mongoc_collection_t *collection UNUSED, bson_t **documents UNUSED, uint64_t num_docs UNUSED) {
#else // !MONGOC_CHECK_VERSION(1,9,0) && MONGO_NUM_DOCS > 1
static inline void mongo_insert_doc(mongoc_collection_t *collection, bson_t **documents, uint64_t num_docs) {
#endif // !MONGOC_CHECK_VERSION(1,9,0) && MONGO_NUM_DOCS > 1
    bson_error_t error;
#if MONGOC_CHECK_VERSION(1,9,0)
#if MONGO_NUM_DOCS <= 1
    assert(num_docs == 0);
    if (UNLIKELY(!mongoc_collection_insert_one(collection, documents[num_docs], NULL, NULL, &error))) {
#else // MONGO_NUM_DOCS > 1
    if (UNLIKELY(!mongoc_collection_insert_many(collection, documents, num_docs, NULL, NULL, &error))) {
#endif // MONGO_NUM_DOCS > 1
#else // MONGOC_VERSION < 1.9.0
#if MONGO_NUM_DOCS <= 1
    assert(num_docs == 0);
    if (UNLIKELY(!mongoc_collection_insert(collection, 0, documents[num_docs], NULL, &error))) {
#else // MONGO_NUM_DOCS > 1
    if (UNLIKELY(!mongoc_bulk_operation_execute(bulk, NULL, &error))) {
#endif // MONGO_NUM_DOCS > 1
#endif // MONGOC_VERSION < 1.9.0
        T2_PERR(plugin_name, "Failed to insert document into collection: %s", error.message);
        db_cleanup();
        exit(EXIT_FAILURE);
    }
}


void t2BufferToSink(outputBuffer_t *buf, binary_value_t *bv) {

    bson_reinit(documents[num_docs]);

    const uint32_t bufpos = buf->pos;
    buf->pos = 0;

    parse_binary2bson(buf, bv);

    buf->pos = bufpos;

#if BSON_DEBUG == 1
    bson_error_t err;
    if (UNLIKELY(!bson_validate_with_error(documents[num_docs], 0, &err))) {
        T2_PERR(plugin_name, "Failed to validate BSON document: %s", err.message);
    }
    char *str = bson_as_canonical_extended_json(documents[num_docs], NULL);
    if (LIKELY(str != NULL)) {
        T2_PINF(plugin_name, "%s", str);
    }
    bson_free(str);
#endif // BSON_DEBUG == 1

#if !MONGOC_CHECK_VERSION(1,9,0) && MONGO_NUM_DOCS > 1
    mongoc_bulk_operation_insert(bulk, documents[num_docs]);
#endif

#if MONGO_NUM_DOCS > 1
    if (++num_docs == MONGO_NUM_DOCS) {
#endif
        mongo_insert_doc(collection, documents, num_docs);
#if MONGO_NUM_DOCS > 1
        num_docs = 0;
    }
#endif

}


static bool parse_binary2bson(outputBuffer_t *buf, binary_value_t *bv) {
    uint32_t num_repeat;
    uint_fast32_t rep, val;

    bson_t child1, child2;
    bson_t *parent = documents[num_docs];
    bson_t *child = &child1;
    bson_t *doc = documents[num_docs];

#if MONGO_SELECT == 1
    uint32_t feature_id = UINT32_MAX;
#endif

    while (bv) {
#if MONGO_SELECT == 1
        feature_id++;
        const bool print = feature_active[feature_id];
#endif
        // check if output can be repeated
        // If yes, read amount of repeats, if no set num_repeat to 1
        if (bv->is_repeating) {
            if (UNLIKELY(!mongo_get_val_func(buf, &num_repeat, sizeof(uint32_t), 1))) {
                return false;
            }
#if BSON_SUPPRESS_EMPTY_ARRAY == 1
            if (num_repeat == 0) {
                bv = bv->next;
                continue;
            }
#endif
#if MONGO_SELECT == 1
            if (print) {
#endif
                if (UNLIKELY(!BSON_APPEND_ARRAY_BEGIN(doc, bv->name, &child1))) {
                    T2_PERR(plugin_name, "Failed to append array begin for %s", bv->name);
                    return false;
                }
                parent = &child1;
                child = &child1;
#if MONGO_SELECT == 1
            }
#endif
        } else {
#if MONGO_SELECT == 1
            if (print) {
#endif
                parent = doc;
                child = doc;
#if MONGO_SELECT == 1
            }
#endif
            num_repeat = 1;
        }
        for (rep = 0; rep < num_repeat; rep++) {
            if (bv->num_values > 1) {
#if MONGO_SELECT == 1
                if (print) {
#endif
                    child = &child2;
                    if (UNLIKELY(!BSON_APPEND_ARRAY_BEGIN(parent, bv->name, child))) {
                        T2_PERR(plugin_name, "Failed to append array begin for %s", bv->name);
                        return false;
                    }
#if MONGO_SELECT == 1
                }
#endif
            }

            // for each output val:
            // check type and write it out, if zero then it contains subvals
            for (val = 0; val < bv->num_values; val++) {
                if (bv->subval[val].type == bt_compound) {
                    if (UNLIKELY(!parse_subval_bson(buf, &bv->subval[val], bv->name, child
#if MONGO_SELECT == 1
                        , print
#endif
                    ))) {
                        return false;
                    }
                } else {
                    if (UNLIKELY(!parse_binary_value_bson(buf, bv->subval[val].type, bv->name, child
#if MONGO_SELECT == 1
                        , print
#endif
                    ))) {
                        return false;
                    }
                }
            }

#if MONGO_SELECT == 1
            if (print)
#endif
            // Repeat value separator
            if (bv->num_values > 1) {
                if (UNLIKELY(!bson_append_array_end(parent, child))) {
                    T2_PERR(plugin_name, "Failed to append array end for %s", bv->name);
                    return false;
                }
            }
        }

#if MONGO_SELECT == 1
        if (print)
#endif
#if BSON_SUPPRESS_EMPTY_ARRAY == 1
        if (bv->is_repeating == 1 && num_repeat > 0) {
#else // BSON_SUPPRESS_EMPTY_ARRAY == 0
        if (bv->is_repeating == 1) {
#endif // BSON_SUPPRESS_EMPTY_ARRAY == 0
            if (UNLIKELY(!bson_append_array_end(doc, &child1))) {
                T2_PERR(plugin_name, "Failed to append array end for %s", bv->name);
                return false;
            }
        }

        bv = bv->next;
    }

    return true;
}


static bool parse_subval_bson(outputBuffer_t *buf, const binary_subvalue_t *sv, const char *name, bson_t *parent
#if MONGO_SELECT == 1
    , bool print
#endif
) {
    bson_t *p = parent;
    bson_t *child = parent;
    bson_t child1, child2;
    // check if output can be repeated. If yes, read amount of repeats, if no set num_repeat to 1
    uint32_t num_repeat = 1;
    if (sv->is_repeating) {
        if (UNLIKELY(!mongo_get_val_func(buf, &num_repeat, sizeof(uint32_t), 1))) {
            return false;
        }

        if (num_repeat == 0) {
            return true;
        }

#if MONGO_SELECT == 1
        if (print) {
#endif
            if (UNLIKELY(!BSON_APPEND_ARRAY_BEGIN(parent, name, &child1))) {
                T2_PERR(plugin_name, "Failed to append array begin for %s", name);
                return false;
            }

            p = &child1;
            child = &child1;
#if MONGO_SELECT == 1
        }
#endif
    }

    for (uint_fast32_t i = 0; i < num_repeat; i++) {
        if (sv->num_values > 1 || sv->subval[0].type == bt_compound) {
#if MONGO_SELECT == 1
            if (print) {
#endif
                child = &child2;
                if (UNLIKELY(!BSON_APPEND_ARRAY_BEGIN(p, name, child))) {
                    T2_PERR(plugin_name, "Failed to append array begin for %s", name);
                    return false;
                }
#if MONGO_SELECT == 1
            }
#endif
        }

        for (uint_fast32_t j = 0; j < sv->num_values; j++) {
            if (sv->subval[j].type == bt_compound) {
                if (UNLIKELY(!parse_subval_bson(buf, &sv->subval[j], name, child
#if MONGO_SELECT == 1
                    , print
#endif
                ))) {
                    return false;
                }
            } else {
                if (UNLIKELY(!parse_binary_value_bson(buf, sv->subval[j].type, name, child
#if MONGO_SELECT == 1
                    , print
#endif
                ))) {
                    return false;
                }
            }
        }

#if MONGO_SELECT == 1
        if (print)
#endif
        if (sv->num_values > 1 || sv->subval[0].type == bt_compound) {
            if (UNLIKELY(!bson_append_array_end(p, child))) {
                T2_PERR(plugin_name, "Failed to append array end for %s", name);
                return false;
            }
        }
    }

#if MONGO_SELECT == 1
    if (print)
#endif
    if (sv->is_repeating) {
        if (UNLIKELY(!bson_append_array_end(parent, &child1))) {
            T2_PERR(plugin_name, "Failed to append array end for %s", name);
            return false;
        }
    }

    return true;
}


static bool parse_binary_value_bson(outputBuffer_t *buf, binary_type_t type, const char *name, bson_t *parent
#if MONGO_SELECT == 1
    , bool print
#endif
) {
    switch (type) {
        case bt_int_8: {
            int8_t val;
            if (UNLIKELY(!mongo_get_val_func(buf, &val, sizeof(int8_t), 1))) {
                return false;
            }
#if MONGO_SELECT == 1
            if (!print) break;
#endif
            if (UNLIKELY(!BSON_APPEND_INT32(parent, name, val))) {
                T2_PERR(plugin_name, "Failed to append '%s' to BSON", name);
                return false;
            }
            break;
        }

        case bt_int_16: {
            int16_t val;
            if (UNLIKELY(!mongo_get_val_func(buf, &val, sizeof(int16_t), 1))) {
                return false;
            }
#if MONGO_SELECT == 1
            if (!print) break;
#endif
            if (UNLIKELY(!BSON_APPEND_INT32(parent, name, val))) {
                T2_PERR(plugin_name, "Failed to append '%s' to BSON", name);
                return false;
            }
            break;
        }

        case bt_int_32: {
            int32_t val;
            if (UNLIKELY(!mongo_get_val_func(buf, &val, sizeof(int32_t), 1))) {
                return false;
            }
#if MONGO_SELECT == 1
            if (!print) break;
#endif
            if (UNLIKELY(!BSON_APPEND_INT32(parent, name, val))) {
                T2_PERR(plugin_name, "Failed to append '%s' to BSON", name);
                return false;
            }
            break;
        }

        case bt_int_64: {
            int64_t val;
            if (UNLIKELY(!mongo_get_val_func(buf, &val, sizeof(int64_t), 1))) {
                return false;
            }
#if MONGO_SELECT == 1
            if (!print) break;
#endif
            if (UNLIKELY(!BSON_APPEND_INT64(parent, name, val))) {
                T2_PERR(plugin_name, "Failed to append '%s' to BSON", name);
                return false;
            }
            break;
        }

        case bt_uint_8: {
            uint8_t val;
            if (UNLIKELY(!mongo_get_val_func(buf, &val, sizeof(uint8_t), 1))) {
                return false;
            }
#if MONGO_SELECT == 1
            if (!print) break;
#endif
            if (UNLIKELY(!BSON_APPEND_INT32(parent, name, val))) {
                T2_PERR(plugin_name, "Failed to append '%s' to BSON", name);
                return false;
            }
            break;
        }

        case bt_uint_16: {
            uint16_t val;
            if (UNLIKELY(!mongo_get_val_func(buf, &val, sizeof(uint16_t), 1))) {
                return false;
            }
#if MONGO_SELECT == 1
            if (!print) break;
#endif
            if (UNLIKELY(!BSON_APPEND_INT32(parent, name, val))) {
                T2_PERR(plugin_name, "Failed to append '%s' to BSON", name);
                return false;
            }
            break;
        }

        case bt_uint_32: {
            uint32_t val;
            if (UNLIKELY(!mongo_get_val_func(buf, &val, sizeof(uint32_t), 1))) {
                return false;
            }
#if MONGO_SELECT == 1
            if (!print) break;
#endif
            if (UNLIKELY(!BSON_APPEND_INT64(parent, name, val))) {
                T2_PERR(plugin_name, "Failed to append '%s' to BSON", name);
                return false;
            }
            break;
        }

        case bt_uint_64: {
            uint64_t val;
            if (UNLIKELY(!mongo_get_val_func(buf, &val, sizeof(uint64_t), 1))) {
                return false;
            }
#if MONGO_SELECT == 1
            if (!print) break;
#endif
            if (UNLIKELY(!BSON_APPEND_INT64(parent, name, val))) {
                T2_PERR(plugin_name, "Failed to append '%s' to BSON", name);
                return false;
            }
            break;
        }

        case bt_hex_8: {
            uint8_t val;
            if (UNLIKELY(!mongo_get_val_func(buf, &val, sizeof(uint8_t), 1))) {
                return false;
            }
#if MONGO_SELECT == 1
            if (!print) break;
#endif
            if (UNLIKELY(!BSON_APPEND_INT32(parent, name, val))) {
                T2_PERR(plugin_name, "Failed to append '%s' to BSON", name);
                return false;
            }
            break;
        }

        case bt_hex_16: {
            uint16_t val;
            if (UNLIKELY(!mongo_get_val_func(buf, &val, sizeof(uint16_t), 1))) {
                return false;
            }
#if MONGO_SELECT == 1
            if (!print) break;
#endif
            if (UNLIKELY(!BSON_APPEND_INT32(parent, name, val))) {
                T2_PERR(plugin_name, "Failed to append '%s' to BSON", name);
                return false;
            }
            break;
        }

        case bt_hex_32: {
            uint32_t val;
            if (UNLIKELY(!mongo_get_val_func(buf, &val, sizeof(uint32_t), 1))) {
                return false;
            }
#if MONGO_SELECT == 1
            if (!print) break;
#endif
            if (UNLIKELY(!BSON_APPEND_INT64(parent, name, val))) {
                T2_PERR(plugin_name, "Failed to append '%s' to BSON", name);
                return false;
            }
            break;
        }

        case bt_hex_64: {
            uint64_t val;
            if (UNLIKELY(!mongo_get_val_func(buf, &val, sizeof(uint64_t), 1))) {
                return false;
            }
#if MONGO_SELECT == 1
            if (!print) break;
#endif
            if (UNLIKELY(!BSON_APPEND_INT64(parent, name, val))) {
                T2_PERR(plugin_name, "Failed to append '%s' to BSON", name);
                return false;
            }
            break;
        }

        case bt_float: {
            float val;
            if (UNLIKELY(!mongo_get_val_func(buf, &val, sizeof(float), 1))) {
                return false;
            }
#if MONGO_SELECT == 1
            if (!print) break;
#endif
            if (UNLIKELY(!BSON_APPEND_DOUBLE(parent, name, val))) {
                T2_PERR(plugin_name, "Failed to append '%s' to BSON", name);
                return false;
            }
            break;
        }

        case bt_double: {
            double val;
            if (UNLIKELY(!mongo_get_val_func(buf, &val, sizeof(double), 1))) {
                return false;
            }
#if MONGO_SELECT == 1
            if (!print) break;
#endif
            if (UNLIKELY(!BSON_APPEND_DOUBLE(parent, name, val))) {
                T2_PERR(plugin_name, "Failed to append '%s' to BSON", name);
                return false;
            }
            break;
        }

        case bt_long_double: {
            long double val;
            if (UNLIKELY(!mongo_get_val_func(buf, &val, sizeof(long double), 1))) {
                return false;
            }
#if MONGO_SELECT == 1
            if (!print) break;
#endif
            if (UNLIKELY(!BSON_APPEND_DOUBLE(parent, name, val))) {
                T2_PERR(plugin_name, "Failed to append '%s' to BSON", name);
                return false;
            }
            break;
        }

        case bt_char: {
            uint8_t val;
            if (UNLIKELY(!mongo_get_val_func(buf, &val, sizeof(uint8_t), 1))) {
                return false;
            }
#if MONGO_SELECT == 1
            if (!print) break;
#endif
            char str[2];
            snprintf(str, sizeof(str), "%c", val);
            if (UNLIKELY(!BSON_APPEND_UTF8(parent, name, str))) {
                T2_PERR(plugin_name, "Failed to append '%s' to BSON", name);
                return false;
            }
            break;
        }

        case bt_string_class:
        case bt_string: {
            char str[MONGO_QRY_LEN] = {};
            int pos = 0;
            if (UNLIKELY(!mongo_sanitize_utf8(buf, str, &pos
#if MONGO_SELECT == 1
                , print
#endif
            ))) {
                return false;
            }
#if MONGO_SELECT == 1
            if (!print) break;
#endif
            if (UNLIKELY(!BSON_APPEND_UTF8(parent, name, str))) {
                T2_PERR(plugin_name, "Failed to append '%s' to BSON", name);
                return false;
            }
            break;
        }

        case bt_mac_addr: {
            uint8_t val[l_bt_mac_addr];
            if (UNLIKELY(!mongo_get_val_func(buf, val, l_bt_mac_addr * sizeof(uint8_t), 1))) {
                return false;
            }
#if MONGO_SELECT == 1
            if (!print) break;
#endif
            char addr[20];
#if MAC_FORMAT == 1
            snprintf(addr, sizeof(addr), "0x%016" B2T_PRIX64,
                    ((uint64_t)val[0] << 40) | ((uint64_t)val[1] << 32) | ((uint64_t)val[2] << 24) |
                    ((uint64_t)val[3] << 16) | ((uint64_t)val[4] << 8)  |  (uint64_t)val[5]);
#elif MAC_FORMAT == 2
            const uint64_t mac64 = t2_mac_to_uint64(val);
            snprintf(addr, sizeof(addr), "%" PRIu64, mac64);
#else // MAC_FORMAT == 0
            snprintf(addr, sizeof(addr),
                    "%02" B2T_PRIX8 "%s%02" B2T_PRIX8 "%s%02" B2T_PRIX8 "%s"
                    "%02" B2T_PRIX8 "%s%02" B2T_PRIX8 "%s%02" B2T_PRIX8,
                    val[0], MAC_SEP, val[1], MAC_SEP, val[2], MAC_SEP,
                    val[3], MAC_SEP, val[4], MAC_SEP, val[5]);
#endif // MAC_FORMAT == 0
            if (UNLIKELY(!BSON_APPEND_UTF8(parent, name, addr))) {
                T2_PERR(plugin_name, "Failed to append '%s' to BSON", name);
                return false;
            }
            break;
        }

        case bt_ip4_addr: {
b2t_ip4:;
            uint8_t val[l_bt_ip4_addr];
            if (UNLIKELY(!mongo_get_val_func(buf, val, l_bt_ip4_addr * sizeof(uint8_t), 1))) {
                return false;
            }
#if MONGO_SELECT == 1
            if (!print) break;
#endif
#if IP4_FORMAT == 3
            const uint32_t addr32 = (val[0] << 24) | (val[1] << 16) | (val[2] << 8) | val[3];
            if (UNLIKELY(!BSON_APPEND_INT64(parent, name, addr32))) {
#else // IP4_FORMAT != 3
            char addr[INET_ADDRSTRLEN];
            snprintf(addr, sizeof(addr),
#if IP4_FORMAT == 1
                "%03" PRIu8 ".%03" PRIu8 ".%03" PRIu8 ".%03" PRIu8,
#elif IP4_FORMAT == 2
                "0x%02" B2T_PRIX8 "%02" B2T_PRIX8 "%02" B2T_PRIX8 "%02" B2T_PRIX8,
#else // IP4_FORMAT == 0
                "%" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8,
#endif // IP4_FORMAT == 0
                val[0], val[1], val[2], val[3]);
            if (UNLIKELY(!BSON_APPEND_UTF8(parent, name, addr))) {
#endif // IP4_FORMAT != 3
                T2_PERR(plugin_name, "Failed to append '%s' to BSON", name);
                return false;
            }
            break;
        }

        case bt_ip6_addr: {
b2t_ip6:;
            uint8_t val[l_bt_ip6_addr];
            if (UNLIKELY(!mongo_get_val_func(buf, val, l_bt_ip6_addr * sizeof(uint8_t), 1))) {
                return false;
            }
#if MONGO_SELECT == 1
            if (!print) break;
#endif
            char addr[INET6_ADDRSTRLEN];
#if IP6_FORMAT == 1
            const uint16_t * const val16 = (uint16_t*)val;
            snprintf(addr, sizeof(addr),
                    "%04" B2T_PRIX16 ":%04" B2T_PRIX16 ":%04" B2T_PRIX16 ":%04" B2T_PRIX16 ":"
                    "%04" B2T_PRIX16 ":%04" B2T_PRIX16 ":%04" B2T_PRIX16 ":%04" B2T_PRIX16,
                    ntohs(val16[0]), ntohs(val16[1]), ntohs(val16[2]), ntohs(val16[3]),
                    ntohs(val16[4]), ntohs(val16[5]), ntohs(val16[6]), ntohs(val16[7]));
#elif IP6_FORMAT == 2
            snprintf(addr, sizeof(addr),
                    "0x%02" B2T_PRIX8 "%02" B2T_PRIX8 "%02" B2T_PRIX8 "%02" B2T_PRIX8
                      "%02" B2T_PRIX8 "%02" B2T_PRIX8 "%02" B2T_PRIX8 "%02" B2T_PRIX8
                      "%02" B2T_PRIX8 "%02" B2T_PRIX8 "%02" B2T_PRIX8 "%02" B2T_PRIX8
                      "%02" B2T_PRIX8 "%02" B2T_PRIX8 "%02" B2T_PRIX8 "%02" B2T_PRIX8,
                    val[0], val[1], val[2], val[3], val[4], val[5], val[6], val[7],
                    val[8], val[9], val[10], val[11], val[12], val[13], val[14], val[15]);
#elif IP6_FORMAT == 3
            snprintf(addr, sizeof(addr),
                    "0x%02" B2T_PRIX8 "%02" B2T_PRIX8 "%02" B2T_PRIX8 "%02" B2T_PRIX8
                      "%02" B2T_PRIX8 "%02" B2T_PRIX8 "%02" B2T_PRIX8 "%02" B2T_PRIX8 "_"
                    "0x%02" B2T_PRIX8 "%02" B2T_PRIX8 "%02" B2T_PRIX8 "%02" B2T_PRIX8
                      "%02" B2T_PRIX8 "%02" B2T_PRIX8 "%02" B2T_PRIX8 "%02" B2T_PRIX8,
                    val[0], val[1], val[2], val[3], val[4], val[5], val[6], val[7],
                    val[8], val[9], val[10], val[11], val[12], val[13], val[14], val[15]);
#else // IP6_FORMAT == 0
            inet_ntop(AF_INET6, val, addr, INET6_ADDRSTRLEN);
#endif // IP6_FORMAT == 0
            if (UNLIKELY(!BSON_APPEND_UTF8(parent, name, addr))) {
                T2_PERR(plugin_name, "Failed to append '%s' to BSON", name);
                return false;
            }
            break;
        }

        case bt_ipx_addr: {
            uint8_t version;
            if (UNLIKELY(!mongo_get_val_func(buf, &version, sizeof(uint8_t), 1))) {
                return false;
            }
            if (version == 4) goto b2t_ip4;
            else if (version == 6) goto b2t_ip6;
            else if (version == 0) {
#if BSON_SUPPRESS_EMPTY_ARRAY == 0
#if MONGO_SELECT == 1
                if (!print) break;
#endif
                if (UNLIKELY(!BSON_APPEND_UTF8(parent, name, B2T_NON_IP_STR))) {
                    T2_PERR(plugin_name, "Failed to append '%s' to BSON", name);
                    return false;
                }
#endif // BSON_SUPPRESS_EMPTY_ARRAY == 0
            } else {
                T2_ERR("Invalid IP version %" PRIu8, version);
                return false;
            }
            break;
        }

        case bt_timestamp:
        case bt_duration: {
            // read seconds
            uint64_t val;
            if (UNLIKELY(!mongo_get_val_func(buf, &val, sizeof(uint64_t), 1))) {
                return false;
            }

            // read nanoseconds
            uint32_t ns;
            if (UNLIKELY(!mongo_get_val_func(buf, &ns, sizeof(uint32_t), 1))) {
                return false;
            }

#if MONGO_SELECT == 1
            if (!print) break;
#endif

//#if TSTAMP_PREC == 0
            ns /= 1000;
//#endif

            struct timeval t = {
                .tv_sec = val,
                .tv_usec = ns,
            };

            if (UNLIKELY(!BSON_APPEND_TIMEVAL(parent, name, &t))) {
                T2_PERR(plugin_name, "Failed to append '%s' to BSON", name);
                return false;
            }
            break;
        }

        case bt_flow_direction: {
            uint8_t val;
            if (UNLIKELY(!mongo_get_val_func(buf, &val, sizeof(uint8_t), 1))) {
                return false;
            }
#if MONGO_SELECT == 1
            if (!print) break;
#endif
            char str[2];
            snprintf(str, sizeof(str), "%c", (val == 0) ? 'A' : 'B');
            if (UNLIKELY(!BSON_APPEND_UTF8(parent, name, str))) {
                T2_PERR(plugin_name, "Failed to append '%s' to BSON", name);
                return false;
            }
            break;
        }

        default:
            T2_PERR(plugin_name, "unhandled type %" PRIu32, type);
            return false;
    }

    return true;
}


/*
 * Skip invalid multi-bytes UTF-8 chars
 * Returns true on successful UTF-8 sanitization, false on error
 */
static bool mongo_sanitize_utf8(outputBuffer_t *buf, char *qry, int *pos
#if MONGO_SELECT == 1
    , bool print
#endif
) {
    uint8_t val, b2, b3, b4; // variables for multi-bytes characters

    while (1) {
        if (UNLIKELY(!mongo_get_val_func(buf, &val, sizeof(val), 1))) {
            return false;
        }

continue_decode:
        if (val == '\0') {
            break;
        }

        if (val < 0x80) { // single byte char
#if MONGO_SELECT == 1
            if (print)
#endif
            switch (val) {
                case '\b':  // backspace
                    MONGO_SNPRINTF(*pos, &qry[*pos], MONGO_QRY_LEN - *pos, "\\b");
                    break;
                case '\f':  // form feed
                    MONGO_SNPRINTF(*pos, &qry[*pos], MONGO_QRY_LEN - *pos, "\\f");
                    break;
                case '\n':  // line feed
                    MONGO_SNPRINTF(*pos, &qry[*pos], MONGO_QRY_LEN - *pos, "\\n");
                    break;
                case '\r':  // carriage return
                    MONGO_SNPRINTF(*pos, &qry[*pos], MONGO_QRY_LEN - *pos, "\\r");
                    break;
                case '\t':  // horizontal tab
                    MONGO_SNPRINTF(*pos, &qry[*pos], MONGO_QRY_LEN - *pos, "\\t");
                    break;
                case '\v':  // vertical tab
                    MONGO_SNPRINTF(*pos, &qry[*pos], MONGO_QRY_LEN - *pos, "\\v");
                    break;
                case '\\':  // backslash
                    MONGO_SNPRINTF(*pos, &qry[*pos], MONGO_QRY_LEN - *pos, "\\%c", val);
                    break;
                default:
                    // In order to be valid BSON, control characters in 0x00-0x1f
                    // must be escaped (see: https://tools.ietf.org/html/rfc7159#page-8)
                    // Most parsers also want the DEL (0x7f) escaped even though not in RFC
                    if (val <= 0x1f || val == 0x7f) {
                        MONGO_SNPRINTF(*pos, &qry[*pos], MONGO_QRY_LEN - *pos, "\\u00%02X", val);
                    } else {
                        MONGO_SNPRINTF(*pos, &qry[*pos], MONGO_QRY_LEN - *pos, "%c", val);
                    }
                    break;
            }
        } else if (val < 0xc2) { // 0xc0 and 0xc1 are invalid first byte (overlong sequence)
            T2_DBG("UTF-8: Overlong sequence!");
#if MONGO_SELECT == 1
            if (print)
#endif
            MONGO_SNPRINTF(*pos, &qry[*pos], MONGO_QRY_LEN - *pos, ".");
        } else if (val < 0xe0) { // 2 bytes char
            if (UNLIKELY(!mongo_get_val_func(buf, &b2, sizeof(uint8_t), 1))) {
                return false;
            }

            if (b2 == '\0') {
                T2_DBG("UTF-8: string terminator at second byte of two bytes char!");
#if MONGO_SELECT == 1
                if (print)
#endif
                MONGO_SNPRINTF(*pos, &qry[*pos], MONGO_QRY_LEN - *pos, ".");
                break;
            }

            if ((b2 & 0xc0) != 0x80) { // second byte must start with 0b10...
                T2_DBG("UTF-8: invalid second byte in two byte char (was 0x%" B2T_PRIX8 ")!", b2);
#if MONGO_SELECT == 1
                if (print)
#endif
                MONGO_SNPRINTF(*pos, &qry[*pos], MONGO_QRY_LEN - *pos, ".");
                val = b2;
                goto continue_decode;
            }

            // valid UTF-8 char! -> write it out
#if MONGO_SELECT == 1
            if (print)
#endif
            MONGO_SNPRINTF(*pos, &qry[*pos], MONGO_QRY_LEN - *pos, "%c%c", val, b2);
        } else if (val < 0xf0) { // 3 bytes char
            if (UNLIKELY(!mongo_get_val_func(buf, &b2, sizeof(uint8_t), 1))) {
                return false;
            }

            if (b2 == '\0') {
                T2_DBG("UTF-8: string terminator at second byte of two bytes char!");
#if MONGO_SELECT == 1
                if (print)
#endif
                MONGO_SNPRINTF(*pos, &qry[*pos], MONGO_QRY_LEN - *pos, ".");
                break;
            }

            if ((b2 & 0xc0) != 0x80) { // second byte must start with 0b10...
                T2_DBG("UTF-8: invalid second byte in three byte char (was 0x%" B2T_PRIX8 ")!", b2);
#if MONGO_SELECT == 1
                if (print)
#endif
                MONGO_SNPRINTF(*pos, &qry[*pos], MONGO_QRY_LEN - *pos, ".");
                val = b2;
                goto continue_decode;
            }

            if (val == 0xe0 && b2 < 0xa0) { // invalid overlong
                T2_DBG("UTF-8: Overlong three byte sequence!");
#if MONGO_SELECT == 1
                if (print)
#endif
                MONGO_SNPRINTF(*pos, &qry[*pos], MONGO_QRY_LEN - *pos, ".");
                continue;
            }

            // check third byte
            if (UNLIKELY(!mongo_get_val_func(buf, &b3, sizeof(uint8_t), 1))) {
                return false;
            }

            if (b3 == '\0') {
                T2_DBG("UTF-8: string terminator at third byte of three bytes char!");
#if MONGO_SELECT == 1
                if (print)
#endif
                MONGO_SNPRINTF(*pos, &qry[*pos], MONGO_QRY_LEN - *pos, ".");
                break;
            }

            if ((b3 & 0xc0) != 0x80) { // third byte must start with 0b10...
                T2_DBG("UTF-8: invalid third byte in three byte char (was 0x%" B2T_PRIX8 ")!", b3);
#if MONGO_SELECT == 1
                if (print)
#endif
                MONGO_SNPRINTF(*pos, &qry[*pos], MONGO_QRY_LEN - *pos, ".");
                val = b3;
                goto continue_decode;
            }

            // check that code point is not in the surrogate range
            uint16_t tmp = ((uint16_t) (val & 0x0f) << 12) |
                           ((uint16_t) (b2  & 0x3f) <<  6) |
                                       (b3  & 0x3f);
            if (tmp >= 0xd800 && tmp <= 0xdfff) {
                T2_DBG("UTF-8: code point is in the surrogate range!");
#if MONGO_SELECT == 1
                if (print)
#endif
                MONGO_SNPRINTF(*pos, &qry[*pos], MONGO_QRY_LEN - *pos, ".");
                continue;
            }

            // valid UTF-8 char! -> write it out
#if MONGO_SELECT == 1
            if (print)
#endif
            MONGO_SNPRINTF(*pos, &qry[*pos], MONGO_QRY_LEN - *pos, "%c%c%c", val, b2, b3);
        } else if (val < 0xf5) { // 4 bytes char
            if (UNLIKELY(!mongo_get_val_func(buf, &b2, sizeof(uint8_t), 1))) {
                return false;
            }

            if (b2 == '\0') {
                T2_DBG("UTF-8: string terminator at second byte of four bytes char!");
#if MONGO_SELECT == 1
                if (print)
#endif
                MONGO_SNPRINTF(*pos, &qry[*pos], MONGO_QRY_LEN - *pos, ".");
                break;
            }

            if ((b2 & 0xc0) != 0x80) {
                T2_DBG("UTF-8: invalid second byte in four byte char (was 0x%" B2T_PRIX8 ")!", b2);
#if MONGO_SELECT == 1
                if (print)
#endif
                MONGO_SNPRINTF(*pos, &qry[*pos], MONGO_QRY_LEN - *pos, "."); // second byte must start with 0b10...
                val = b2;
                goto continue_decode;
            }

            if (val == 0xf0 && b2 < 0x90) { // invalid overlong
                T2_DBG("UTF-8: Overlong four byte sequence!\n");
#if MONGO_SELECT == 1
                if (print)
#endif
                MONGO_SNPRINTF(*pos, &qry[*pos], MONGO_QRY_LEN - *pos, ".");
                continue;
            }

            if (val == 0xf4 && b2 >= 0x90) { // code point > U+10FFFF
                T2_DBG("UTF-8: Code point > U+10FFFF!");
#if MONGO_SELECT == 1
                if (print)
#endif
                MONGO_SNPRINTF(*pos, &qry[*pos], MONGO_QRY_LEN - *pos, ".");
                continue;
            }

            // check third byte
            if (UNLIKELY(!mongo_get_val_func(buf, &b3, sizeof(uint8_t), 1))) {
                return false;
            }

            if (b3 == '\0') {
                T2_DBG("UTF-8: string terminator at third byte of four bytes char!");
#if MONGO_SELECT == 1
                if (print)
#endif
                MONGO_SNPRINTF(*pos, &qry[*pos], MONGO_QRY_LEN - *pos, ".");
                break;
            }

            if ((b3 & 0xc0) != 0x80) {  // third byte must start with 0b10...
                T2_DBG("UTF-8: invalid third byte in four byte char (was 0x%" B2T_PRIX8 ")!", b3);
#if MONGO_SELECT == 1
                if (print)
#endif
                MONGO_SNPRINTF(*pos, &qry[*pos], MONGO_QRY_LEN - *pos, ".");
                val = b3;
                goto continue_decode;
            }

            // check fourth byte
            if (UNLIKELY(!mongo_get_val_func(buf, &b4, sizeof(uint8_t), 1))) {
                return false;
            }

            if (b4 == '\0') {
                T2_DBG("UTF-8: string terminator at fourth byte of four bytes char!");
#if MONGO_SELECT == 1
                if (print)
#endif
                MONGO_SNPRINTF(*pos, &qry[*pos], MONGO_QRY_LEN - *pos, ".");
                break;
            }

            if ((b4 & 0xc0) != 0x80) { // fourth byte must start with 0b10...
                T2_DBG("UTF-8: invalid fourth byte in four byte char (was 0x%" B2T_PRIX8 ")!", b4);
#if MONGO_SELECT == 1
                if (print)
#endif
                MONGO_SNPRINTF(*pos, &qry[*pos], MONGO_QRY_LEN - *pos, ".");
                val = b4;
                goto continue_decode;
            }

            // valid UTF-8 char! -> write it out
#if MONGO_SELECT == 1
            if (print)
#endif
            MONGO_SNPRINTF(*pos, &qry[*pos], MONGO_QRY_LEN - *pos, "%c%c%c%c", val, b2, b3, b4);
        } else { // invalid first byte >= 0xf5
            T2_DBG("UTF-8: invalid first byte (was 0x%" B2T_PRIX8 ")!", val);
#if MONGO_SELECT == 1
            if (print)
#endif
            MONGO_SNPRINTF(*pos, &qry[*pos], MONGO_QRY_LEN - *pos, ".");
        }
    }

    return true;
}


#if MONGO_SELECT == 1
// Returned value MUST be free'd
static inline bool *mongo_select_load(binary_value_t *bv, const char *filename) {
    assert(filename);

    FILE * const file = t2_fopen_in_dir(filename[0] == '/' ? NULL : pluginFolder, filename, "r");
    if (UNLIKELY(!file)) exit(EXIT_FAILURE);

    uint_fast32_t feature_id = 0;
    binary_value_t *bvp = bv;
    while (bvp) {
        feature_id++;
        bvp = bvp->next;
    }

    bool * const feature_active = t2_malloc_fatal(feature_id * sizeof(*feature_active));

    feature_id = 0;
    bvp = bv;
    char *line = NULL;

#if VERBOSE > 0
    uint_fast32_t num_active = 0;
#endif
    while (bvp) {
        bool active = false;
        size_t len;
        ssize_t read;
        while ((read = getline(&line, &len, file)) != -1) {
            if (line[0] == '#') continue; // skip comments
            if (line[read-1] == '\n') line[--read] = '\0';
            if (strcmp(bvp->name, line) == 0) {
#if VERBOSE > 0
                num_active++;
#endif
                active = true;
                break;
            }
        }
        feature_active[feature_id] = active;
        bvp = bvp->next;
        feature_id++;
        rewind(file);
    }

    free(line);
    fclose(file);

#if VERBOSE > 0
    T2_PINF(plugin_name, "only inserting %" PRIuFAST32 " columns listed in '%s'", num_active, filename);
#endif

    return feature_active;
}
#endif // MONGO_SELECT == 1

#endif // BLOCK_BUF == 0
