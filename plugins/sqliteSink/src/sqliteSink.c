/*
 * sqliteSink.c
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

#include "sqliteSink.h"

#if T2_SQLITE_SELECT == 1
#include <assert.h>         // for assert
#endif

#include <arpa/inet.h>      // for inet_ntop
#include <netinet/in.h>     // for INET_ADDRSTRLEN, INET6_ADDRSTRLEN
#include <sqlite3.h>        // for sqlite3_close, sqlite3, sqlite3_finalize
#include <stdbool.h>        // for bool, true, false
#include <stdint.h>         // for uint8_t, uint16_t, uint32_t, uint_fast32_t
#include <stdio.h>          // for snprintf, fclose, getline, rewind, FILE
#include <stdlib.h>         // for exit, free
#include <string.h>         // for size_t, strdup, strlen, NULL, memcmp, memcpy
#include <sys/socket.h>     // for AF_INET, AF_INET6
#include <sys/types.h>      // for ssize_t, time_t
#include <time.h>           // for gmtime, strftime

#include "t2Plugin.h"


#if BLOCK_BUF == 0

// Static variables

#if ENVCNTRL > 0
static t2_env_t env[ENV_SQLITE_N];
static const char *tableName;
static int qryMaxLen;
#else // ENVCNTRL == 0
static const char * const tableName = SQLITE_TABLE_NAME;
static const int qryMaxLen = SQLITE_QRY_MAXLEN;
#endif // ENVCNTRL

static sqlite_qry_t qry;
static sqlite3 *db_conn;
static uint32_t corrupt_flows;

static char * const db_types[] = {
    "TEXT",           // bt_compound
    "INT",            // bt_int_8
    "INT",            // bt_int_16
    "INT",            // bt_int_32
    "INT",            // bt_int_64
    "INT",            // bt_int_128 (XXX precision loss)
    "INT",            // bt_int_256 (XXX precision loss)
    "INT",            // bt_uint_8
    "INT",            // bt_uint_16
    "INT",            // bt_uint_32
    "INT",            // bt_uint_64
    "INT",            // bt_uint_128 (XXX precision loss)
    "INT",            // bt_uint_256 (XXX precision loss)
    SQLITE_HEX_TYPE,  // bt_hex_8
    SQLITE_HEX_TYPE,  // bt_hex_16
    SQLITE_HEX_TYPE,  // bt_hex_32
    SQLITE_HEX_TYPE,  // bt_hex_64
    SQLITE_HEX_TYPE,  // bt_hex_128 (XXX precision loss)
    SQLITE_HEX_TYPE,  // bt_hex_256 (XXX precision loss)
    "REAL",           // bt_float
    "REAL",           // bt_double
    "REAL",           // bt_long_double (XXX precision loss)
    "TEXT",           // bt_char
    "TEXT",           // bt_string
    "TEXT",           // bt_flow_direction
    "TEXT",           // bt_timestamp
    "REAL",           // bt_duration
    "TEXT",           // bt_mac_addr
    "TEXT",           // bt_ip4_addr
    "TEXT",           // bt_ip6_addr
    "TEXT",           // bt_ipx_addr
    "TEXT",           // bt_string_class
};

#if SQLITE_TRANSACTION_NFLOWS > 1
static uint64_t flows_to_commit;
#endif // SQLITE_TRANSACTION_NFLOWS > 1

#if T2_SQLITE_SELECT == 1
static bool *feature_active;
#endif


// Function prototypes

static inline sqlite3 *db_connect(const char *dbname);
static inline void db_query(sqlite3 *conn, const char *qry);
static inline void db_create_flow_table(sqlite_qry_t *qry, sqlite3 *conn, const char *name, binary_value_t *bv);
// Returned value MUST be free'd
static inline char *db_create_flow_table_qry(sqlite_qry_t *qry, sqlite3 *conn, const char *name, binary_value_t *bv);
// Returned value MUST be free'd
static inline char *db_get_table_schema(sqlite_qry_t *qry, sqlite3 *conn, const char *table_name);
#if SQLITE_OVERWRITE == 1
static inline void db_drop_table(sqlite_qry_t *qry, sqlite3 *conn, const char *name);
#endif // SQLITE_OVERWRITE == 1
static inline bool db_table_exists(sqlite_qry_t *qry, sqlite3 *conn, const char *name);
static inline bool sqlite_get_val_func(outputBuffer_t *buf, void *dest, size_t size, size_t n);
static bool sqlite_parse_sv_type(outputBuffer_t *buf, sqlite_qry_t *qry, binary_type_t type
#if T2_SQLITE_SELECT == 1
    , bool print
#endif
);
static bool sqlite_parse_sv(outputBuffer_t *buf, sqlite_qry_t *qry, binary_subvalue_t *sv
#if T2_SQLITE_SELECT == 1
    , bool print
#endif
);
static bool sqlite_sanitize_utf8(outputBuffer_t *buf, sqlite_qry_t *qry
#if T2_SQLITE_SELECT == 1
    , bool print
#endif
);
#if T2_SQLITE_SELECT == 1
// Returned value MUST be free'd
static inline bool *sqlite_select_load(binary_value_t *bv, const char *filename);
#endif


// Defines

#define SQLITE_REALLOC_QRY(qry, to_write) { \
    int new_size = (qry)->size << 1; \
    while (new_size <= ((qry)->pos + (to_write))) { \
        new_size <<= 1; \
        if (new_size > qryMaxLen) { \
            T2_PFATAL(plugin_name, "Failed to reallocate memory for query (reached max size of SQLITE_QRY_MAXLEN = '%d')", qryMaxLen); \
        } \
    } \
    T2_REALLOC((qry)->buf, new_size); \
    (qry)->size = new_size; \
}

// Wrapper for snprintf.
// Increases pos by the number of bytes written
#define SQLITE_SNPRINTF(qry, format, args...) { \
    const int left = (qry)->size - (qry)->pos; \
    const int n = snprintf(&(qry)->buf[(qry)->pos], left, format, ##args); \
    if (UNLIKELY(n >= left)) { \
        SQLITE_REALLOC_QRY((qry), n); \
        snprintf(&(qry)->buf[(qry)->pos], (qry)->size - (qry)->pos, format, ##args); \
    } \
    (qry)->pos += n; \
}

#endif // BLOCK_BUF == 0


// Tranalyzer functions

T2_PLUGIN_INIT("sqliteSink", "0.9.3", 0, 9);


void t2Init() {
#if BLOCK_BUF == 1
    T2_PWRN(plugin_name, "BLOCK_BUF is set in 'tranalyzer.h', no output will be produced");
#else // BLOCK_BUF == 0

#if ENVCNTRL > 0
    t2_get_env(PLUGIN_SRCH, ENV_SQLITE_N, env);
    const char * const dbSuffix = T2_ENV_VAL(SQLITE_DB_SUFFIX);
    tableName = T2_ENV_VAL(SQLITE_TABLE_NAME);
#if T2_SQLITE_SELECT == 1
    const char * const selectFile = T2_ENV_VAL(SQLITE_SELECT_FILE);
#endif // T2_SQLITE_SELECT == 1
    qry.size = T2_ENV_VAL_INT(SQLITE_QRY_LEN);
    qryMaxLen = T2_ENV_VAL_INT(SQLITE_QRY_MAXLEN);
#else // ENVCNTRL == 0
    const char * const dbSuffix = SQLITE_DB_SUFFIX;
#if T2_SQLITE_SELECT == 1
    const char * const selectFile = SQLITE_SELECT_FILE;
#endif // T2_SQLITE_SELECT == 1
    qry.size = SQLITE_QRY_LEN;
#endif // ENVCNTRL

#ifdef SQLITE_DBNAME
    db_conn = db_connect(SQLITE_DBNAME);
#else
    char * const dbname = t2_strdup_printf("%s%s", baseFileName, dbSuffix);
    db_conn = db_connect(dbname);
    free(dbname);
#endif

    qry.buf = t2_malloc_fatal(qry.size);
    qry.pos = 0;

    bool exists = db_table_exists(&qry, db_conn, tableName);
#if SQLITE_OVERWRITE != 2
    if (exists) {
#if SQLITE_OVERWRITE == 0
        T2_PERR(plugin_name, "Table '%s' already exists", tableName);
        sqlite3_close(db_conn);
        exit(EXIT_FAILURE);
#elif SQLITE_OVERWRITE == 1
        db_drop_table(&qry, db_conn, tableName);
        exists = false;
#endif // SQLITE_OVERWRITE == 1
    }
#endif // SQLITE_OVERWRITE != 2

#if T2_SQLITE_SELECT == 1
    feature_active = sqlite_select_load(main_header_bv, selectFile);
#endif // T2_SQLITE_SELECT == 1

    if (!exists) {
        db_create_flow_table(&qry, db_conn, tableName, main_header_bv);
    } else {
        // test that schema matches
        char * const new_schema = db_create_flow_table_qry(&qry, db_conn, tableName, main_header_bv);
        char * const old_schema = db_get_table_schema(&qry, db_conn, tableName);
        const size_t new_len = strlen(new_schema) - 1; // new schema has a trailing semicolon
        const size_t old_len = strlen(old_schema);
        const bool differ = (new_len != old_len || memcmp(new_schema, old_schema, new_len) != 0);
        free(new_schema);
        free(old_schema);
        if (differ) {
            T2_PERR(plugin_name, "Cannot append to existing table: schemas differ");
            sqlite3_close(db_conn);
            exit(EXIT_FAILURE);
        }
    }

#if SQLITE_TRANSACTION_NFLOWS != 1
    db_query(db_conn, "BEGIN TRANSACTION");
#endif // SQLITE_TRANSACTION_NFLOWS != 1

#endif // BLOCK_BUF == 0
}


// If BLOCK_BUF == 1, the plugin does not produce any output.
// All the code below is therefore not activated.


#if BLOCK_BUF == 0

void t2PluginReport(FILE *stream) {
    T2_FPWRN_NUMP_NP(stream, plugin_name, "Number of flows discarded due to main buffer problems", corrupt_flows, totalFlows);
}


void t2Finalize() {
#if SQLITE_TRANSACTION_NFLOWS > 1
    if (flows_to_commit > 0)
#endif // SQLITE_TRANSACTION_NFLOWS > 1
        db_query(db_conn, "END TRANSACTION");
    sqlite3_close(db_conn);
    free(qry.buf);
#if T2_SQLITE_SELECT == 1
    free(feature_active);
#endif

#if ENVCNTRL > 0
    t2_free_env(ENV_SQLITE_N, env);
#endif // ENVCNTRL > 0
}


static inline sqlite3 *db_connect(const char *dbname) {
    sqlite3 *db;
    if (UNLIKELY(sqlite3_open(dbname, &db) != SQLITE_OK)) {
        T2_PERR(plugin_name, "Failed to open DB '%s': %s", dbname, sqlite3_errmsg(db));
        sqlite3_close(db);
        exit(EXIT_FAILURE);
    }
#if VERBOSE > 2
    T2_PINF(plugin_name, "Saving database to '%s'", dbname);
#endif
    return db;
}


static inline void db_query(sqlite3 *conn, const char *qry) {
    char *err;
    if (UNLIKELY(sqlite3_exec(conn, qry, 0, 0, &err) != SQLITE_OK)) {
        T2_PERR(plugin_name, "Failed to execute query '%s': %s", qry, err);
        sqlite3_free(err);
        sqlite3_close(conn);
        exit(EXIT_FAILURE);
    }
}


// Returned value MUST be free'd
static inline char *db_create_flow_table_qry(sqlite_qry_t *qry, sqlite3 *conn, const char *name, binary_value_t *bv) {
    qry->pos = 0;

#if T2_SQLITE_SELECT == 1
    uint32_t feature_id = UINT32_MAX;
#endif

    SQLITE_SNPRINTF(qry, "CREATE TABLE %s (", name);

    while (bv) {
#if T2_SQLITE_SELECT == 1
        feature_id++;
        if (!feature_active[feature_id]) {
            bv = bv->next;
            continue;
        }
#endif
        SQLITE_SNPRINTF(qry, "\"%s\"", bv->name);
        char *type;
        if (bv->is_repeating || bv->num_values > 1) {
            type = "TEXT";
        } else {
            const binary_type_t t = bv->subval[0].type;
            if (t > bt_string_class) {
                T2_PERR(plugin_name, "Unhandled type %u", t);
                sqlite3_close(conn);
                exit(EXIT_FAILURE);
            }
            type = db_types[t];
        }
        SQLITE_SNPRINTF(qry, " %s%s", type, bv->next ? ", " : ");");
        bv = bv->next;
    }

    return strdup(qry->buf);
}


static inline void db_create_flow_table(sqlite_qry_t *qry, sqlite3 *conn, const char *name, binary_value_t *bv) {
    char * const query = db_create_flow_table_qry(qry, conn, name, bv);
    db_query(conn, query);
    free(query);
}


#if SQLITE_OVERWRITE == 1
static inline void db_drop_table(sqlite_qry_t *qry, sqlite3 *conn, const char *name) {
    qry->pos = 0;
    SQLITE_SNPRINTF(qry, "DROP TABLE %s;", name);
    db_query(conn, qry->buf);
}
#endif // SQLITE_OVERWRITE == 1


static inline bool db_table_exists(sqlite_qry_t *qry, sqlite3 *conn, const char *name) {
    qry->pos = 0;
    SQLITE_SNPRINTF(qry, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='%s';", name);

    sqlite3_stmt *res;
    if (UNLIKELY(sqlite3_prepare_v2(conn, qry->buf, -1, &res, 0) != SQLITE_OK)) {
        T2_PERR(plugin_name, "Failed to prepare query '%s'", qry->buf);
        sqlite3_close(conn);
        exit(EXIT_FAILURE);
    }

    int rc = sqlite3_step(res);
    if (UNLIKELY(rc != SQLITE_ROW)) {
        T2_PERR(plugin_name, "Failed to execute query '%s'", qry->buf);
        sqlite3_close(conn);
        exit(EXIT_FAILURE);
    }

    const bool exists = sqlite3_column_int(res, 0) ? true : false;

    sqlite3_finalize(res);

    return exists;
}


// Returned value MUST be free'd
static inline char *db_get_table_schema(sqlite_qry_t *qry, sqlite3 *conn, const char *table_name) {
    qry->pos = 0;
    SQLITE_SNPRINTF(qry, "SELECT sql FROM sqlite_master WHERE type='table' AND name='%s';", table_name);

    sqlite3_stmt *res;
    if (UNLIKELY(sqlite3_prepare_v2(conn, qry->buf, -1, &res, 0) != SQLITE_OK)) {
        T2_PERR(plugin_name, "Failed to prepare query '%s'", qry->buf);
        sqlite3_close(conn);
        exit(EXIT_FAILURE);
    }

    int rc = sqlite3_step(res);
    if (UNLIKELY(rc != SQLITE_ROW)) {
        T2_PERR(plugin_name, "Failed to execute query '%s'", qry->buf);
        sqlite3_close(conn);
        exit(EXIT_FAILURE);
    }

    const char *schema = (char*)sqlite3_column_text(res, 0);
    char *ret = schema ? strdup(schema) : NULL;

    sqlite3_finalize(res);

    return ret;
}


static inline bool sqlite_get_val_func(outputBuffer_t *buf, void *dest, size_t size, size_t n) {
    const size_t sn = size * n;
    if (UNLIKELY(buf->size < buf->pos + sn)) {
        const size_t required = buf->pos + sn;
        T2_PERR(plugin_name, "Buffer overflow: %zu increase MAIN_OUTBUF_SIZE in tranalyzer.h", required);
        return false;
    }

    memcpy(dest, buf->buffer + buf->pos, sn);
    buf->pos += sn;
    return true;
}


static bool sqlite_parse_sv_type(outputBuffer_t *buf, sqlite_qry_t *qry, binary_type_t type
#if T2_SQLITE_SELECT == 1
    , bool print
#endif
) {
    switch (type) {
        case bt_int_8: {
            int8_t val;
            if (UNLIKELY(!sqlite_get_val_func(buf, &val, sizeof(val), 1))) {
                return false;
            }
#if T2_SQLITE_SELECT == 1
            if (!print) break;
#endif
            SQLITE_SNPRINTF(qry, "%" PRId8, val);
            break;
        }

        case bt_int_16: {
            int16_t val;
            if (UNLIKELY(!sqlite_get_val_func(buf, &val, sizeof(val), 1))) {
                return false;
            }
#if T2_SQLITE_SELECT == 1
            if (!print) break;
#endif
            SQLITE_SNPRINTF(qry, "%" PRId16, val);
            break;
        }

        case bt_int_32: {
            int32_t val;
            if (UNLIKELY(!sqlite_get_val_func(buf, &val, sizeof(val), 1))) {
                return false;
            }
#if T2_SQLITE_SELECT == 1
            if (!print) break;
#endif
            SQLITE_SNPRINTF(qry, "%" PRId32, val);
            break;
        }

        case bt_int_64: {
            int64_t val;
            if (UNLIKELY(!sqlite_get_val_func(buf, &val, sizeof(val), 1))) {
                return false;
            }
#if T2_SQLITE_SELECT == 1
            if (!print) break;
#endif
            SQLITE_SNPRINTF(qry, "%" PRId64, val);
            break;
        }

        //case bt_int_128:
        //case bt_int_256:

        case bt_uint_8: {
            uint8_t val;
            if (UNLIKELY(!sqlite_get_val_func(buf, &val, sizeof(val), 1))) {
                return false;
            }
#if T2_SQLITE_SELECT == 1
            if (!print) break;
#endif
            SQLITE_SNPRINTF(qry, "%" PRIu8, val);
            break;
        }

        case bt_uint_16: {
            uint16_t val;
            if (UNLIKELY(!sqlite_get_val_func(buf, &val, sizeof(val), 1))) {
                return false;
            }
#if T2_SQLITE_SELECT == 1
            if (!print) break;
#endif
            SQLITE_SNPRINTF(qry, "%" PRIu16, val);
            break;
        }

        case bt_uint_32: {
            uint32_t val;
            if (UNLIKELY(!sqlite_get_val_func(buf, &val, sizeof(val), 1))) {
                return false;
            }
#if T2_SQLITE_SELECT == 1
            if (!print) break;
#endif
            SQLITE_SNPRINTF(qry, "%" PRIu32, val);
            break;
        }

        case bt_uint_64: {
            uint64_t val;
            if (UNLIKELY(!sqlite_get_val_func(buf, &val, sizeof(val), 1))) {
                return false;
            }
#if T2_SQLITE_SELECT == 1
            if (!print) break;
#endif
            SQLITE_SNPRINTF(qry, "%" PRIu64, val);
            break;
        }

        //case bt_uint_128:
        //case bt_uint_256:

        case bt_hex_8: {
            uint8_t val;
            if (UNLIKELY(!sqlite_get_val_func(buf, &val, sizeof(val), 1))) {
                return false;
            }
#if T2_SQLITE_SELECT == 1
            if (!print) break;
#endif
            SQLITE_SNPRINTF(qry, SQLITE_PRI_HEX8, val);
            break;
        }

        case bt_hex_16: {
            uint16_t val;
            if (UNLIKELY(!sqlite_get_val_func(buf, &val, sizeof(val), 1))) {
                return false;
            }
#if T2_SQLITE_SELECT == 1
            if (!print) break;
#endif
            SQLITE_SNPRINTF(qry, SQLITE_PRI_HEX16, val);
            break;
        }

        case bt_hex_32: {
            uint32_t val;
            if (UNLIKELY(!sqlite_get_val_func(buf, &val, sizeof(val), 1))) {
                return false;
            }
#if T2_SQLITE_SELECT == 1
            if (!print) break;
#endif
            SQLITE_SNPRINTF(qry, SQLITE_PRI_HEX32, val);
            break;
        }

        case bt_hex_64: {
            uint64_t val;
            if (UNLIKELY(!sqlite_get_val_func(buf, &val, sizeof(val), 1))) {
                return false;
            }
#if T2_SQLITE_SELECT == 1
            if (!print) break;
#endif
            SQLITE_SNPRINTF(qry, SQLITE_PRI_HEX64, val);
            break;
        }

        //case bt_hex_128:
        //case bt_hex_256:

        case bt_float: {
            float val;
            if (UNLIKELY(!sqlite_get_val_func(buf, &val, sizeof(val), 1))) {
                return false;
            }
#if T2_SQLITE_SELECT == 1
            if (!print) break;
#endif
            SQLITE_SNPRINTF(qry, "%f", val);
            break;
        }

        case bt_double: {
            double val;
            if (UNLIKELY(!sqlite_get_val_func(buf, &val, sizeof(val), 1))) {
                return false;
            }
#if T2_SQLITE_SELECT == 1
            if (!print) break;
#endif
            SQLITE_SNPRINTF(qry, "%f", val);
            break;
        }

        case bt_long_double: {
            long double val;
            if (UNLIKELY(!sqlite_get_val_func(buf, &val, sizeof(val), 1))) {
                return false;
            }
#if T2_SQLITE_SELECT == 1
            if (!print) break;
#endif
            SQLITE_SNPRINTF(qry, "%Lf", val);
            break;
        }

        case bt_char: {
            uint8_t val;
            if (UNLIKELY(!sqlite_get_val_func(buf, &val, sizeof(val), 1))) {
                return false;
            }
#if T2_SQLITE_SELECT == 1
            if (!print) break;
#endif
            SQLITE_SNPRINTF(qry, "%c", val);
            break;
        }

        case bt_string_class:
        case bt_string: {
            return sqlite_sanitize_utf8(buf, qry
#if T2_SQLITE_SELECT == 1
                , print
#endif
            );
            break;
        }

        case bt_flow_direction: {
            uint8_t val;
            if (UNLIKELY(!sqlite_get_val_func(buf, &val, sizeof(val), 1))) {
                return false;
            }
#if T2_SQLITE_SELECT == 1
            if (!print) break;
#endif
            SQLITE_SNPRINTF(qry, "%c", (val == 0) ? FLOW_DIR_C_A : FLOW_DIR_C_B);
            break;
        }

        case bt_timestamp:
        case bt_duration: {
            // read seconds
            uint64_t val;
            if (UNLIKELY(!sqlite_get_val_func(buf, &val, sizeof(val), 1))) {
                return false;
            }

            // read nanoseconds
            uint32_t ns;
            if (UNLIKELY(!sqlite_get_val_func(buf, &ns, sizeof(ns), 1))) {
                return false;
            }

#if T2_SQLITE_SELECT == 1
            if (!print) break;
#endif

#if TSTAMP_PREC == 0
            ns /= 1000;
#endif // TSTAMP_PREC == 0

            if (type == bt_duration) {
                SQLITE_SNPRINTF(qry, "%" PRIu64 ".%" B2T_TPFRMT, val, ns);
            } else {
                const struct tm *t;
#if TSTAMP_UTC == 1
                t = gmtime((time_t*)&val);
#else // TSTAMP_UTC == 0
                t = localtime((time_t*)&val);
#endif // TSTAMP_UTC == 0
                char timeBuf[30];
                // ISO 8601 time format
                // <year>-<month>-<day>T<hours>:<minutes>:<seconds>.<micro/nano-seconds><+/-offset>
                strftime(timeBuf, sizeof(timeBuf), B2T_TIMEFRMT, t);
                SQLITE_SNPRINTF(qry, "%s.%" B2T_TPFRMT, timeBuf, ns); // micro/nano-seconds
#if TSTAMP_UTC == 1 && defined(__APPLE__)
                SQLITE_SNPRINTF(qry, "+00:00");
#else // TSTAMP_UTC == 0 || !defined(__APPLE__)
                const size_t oldpos = qry->pos;
                strftime(timeBuf, sizeof(timeBuf), "%z", t); // time offset
                SQLITE_SNPRINTF(qry, "%s", timeBuf);
                // SQLite does not understand offset formatted as +0100
                // but requires a colon to separate hours from minutes (+01:00)
                if (qry->pos - oldpos == 5 && (qry->buf[oldpos] == '+' || qry->buf[oldpos] == '-')) {
                    if (qry->pos + 1 >= qry->size) {
                        SQLITE_REALLOC_QRY(qry, 1);
                    }
                    memmove(&qry->buf[oldpos+4], &qry->buf[oldpos+3], 2);
                    qry->buf[oldpos+3] = ':';
                    qry->pos++;
                    qry->buf[qry->pos] = '\0';
                }
#endif // TSTAMP_UTC == 0 || !defined(__APPLE__)
            }
            break;
        }

        case bt_mac_addr: {
            uint8_t val[l_bt_mac_addr];
            if (UNLIKELY(!sqlite_get_val_func(buf, &val, l_bt_mac_addr * sizeof(uint8_t), 1))) {
                return false;
            }
#if T2_SQLITE_SELECT == 1
            if (!print) break;
#endif
            SQLITE_SNPRINTF(qry,
                    "%02" B2T_PRIX8 "%s%02" B2T_PRIX8 "%s%02" B2T_PRIX8 "%s"
                    "%02" B2T_PRIX8 "%s%02" B2T_PRIX8 "%s%02" B2T_PRIX8,
                    val[0], MAC_SEP, val[1], MAC_SEP, val[2], MAC_SEP,
                    val[3], MAC_SEP, val[4], MAC_SEP, val[5]);
            break;
        }

        case bt_ip4_addr: {
sqlite_bt_ip4:;
            uint8_t val[l_bt_ip4_addr];
            if (UNLIKELY(!sqlite_get_val_func(buf, &val, l_bt_ip4_addr * sizeof(uint8_t), 1))) {
                return false;
            }
#if T2_SQLITE_SELECT == 1
            if (!print) break;
#endif
            char addr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, val, addr, INET_ADDRSTRLEN);
            SQLITE_SNPRINTF(qry, "%s", addr);
            break;
        }

        case bt_ip6_addr: {
sqlite_bt_ip6:;
            uint8_t val[l_bt_ip6_addr];
            if (UNLIKELY(!sqlite_get_val_func(buf, &val, l_bt_ip6_addr * sizeof(uint8_t), 1))) {
                return false;
            }
#if T2_SQLITE_SELECT == 1
            if (!print) break;
#endif
            char addr[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, val, addr, INET6_ADDRSTRLEN);
            SQLITE_SNPRINTF(qry, "%s", addr);
            break;
        }

        case bt_ipx_addr: {
            uint8_t version;
            if (UNLIKELY(!sqlite_get_val_func(buf, &version, sizeof(version), 1))) {
                return false;
            }
            if (version == 4) {
                goto sqlite_bt_ip4;
            } else if (version == 6) {
                goto sqlite_bt_ip6;
            } else if (version == 0) {
#if T2_SQLITE_SELECT == 1
                if (!print) break;
#endif
                SQLITE_SNPRINTF(qry, "%s", B2T_NON_IP_STR);
            } else {
                T2_PERR(plugin_name, "invalid IP version %" PRIu8, version);
                return false;
            }
            break;
        }

        default:
            T2_PERR(plugin_name, "unhandled output type %" PRIu32, type);
            return false;
    }

    return true;
}


static bool sqlite_parse_sv(outputBuffer_t *buf, sqlite_qry_t *qry, binary_subvalue_t *sv
#if T2_SQLITE_SELECT == 1
        , bool print
#endif
) {
    if (sv->type) {
        return sqlite_parse_sv_type(buf, qry, sv->type
#if T2_SQLITE_SELECT == 1
            , print
#endif
        );
    }

#if T2_SQLITE_SELECT == 1
    if (print)
#endif
    SQLITE_SNPRINTF(qry, "(");
    uint32_t nr = 1;
    if (sv->is_repeating) {
        if (UNLIKELY(!sqlite_get_val_func(buf, &nr, sizeof(nr), 1))) {
            return false;
        }
    }
    const uint_fast32_t nv = sv->num_values;
    for (uint_fast32_t i = 0; i < nr; i++) {
        for (uint_fast32_t j = 0; j < nv; j++) {
            if (UNLIKELY(!sqlite_parse_sv(buf, qry, &sv->subval[j]
#if T2_SQLITE_SELECT == 1
            , print
#endif
            ))) return false;
            // write value delim
#if T2_SQLITE_SELECT == 1
            if (print)
#endif
            if (j < nv - 1) {
                SQLITE_SNPRINTF(qry, "_");
            }
        }

        // write repeat delim
#if T2_SQLITE_SELECT == 1
        if (print)
#endif
        if (i < nr - 1) {
            SQLITE_SNPRINTF(qry, ";");
        }
    }

#if T2_SQLITE_SELECT == 1
    if (print)
#endif
    SQLITE_SNPRINTF(qry, ")");

    return qry->pos;
}


void t2BufferToSink(outputBuffer_t *buf, binary_value_t *bv) {
    const uint32_t bufpos = buf->pos;
    buf->pos = 0;
    qry.pos = 0;
    SQLITE_SNPRINTF(&qry, "INSERT INTO %s VALUES ('", tableName);
#if T2_SQLITE_SELECT == 1
    uint32_t feature_id = UINT32_MAX;
#endif

    while (bv) {
#if T2_SQLITE_SELECT == 1
        feature_id++;
        const bool print = feature_active[feature_id];
#endif
        uint32_t nr = 1;
        if (bv->is_repeating) {
            if (UNLIKELY(!sqlite_get_val_func(buf, &nr, sizeof(nr), 1))) {
                corrupt_flows++;
                return;
            }
        }

        const uint_fast32_t nv = bv->num_values;
        for (uint_fast32_t i = 0; i < nr; i++) {
            for (uint_fast32_t j = 0; j < nv; j++) {
                if (UNLIKELY(!sqlite_parse_sv(buf, &qry, &bv->subval[j]
#if T2_SQLITE_SELECT == 1
                    , print
#endif
                ))) {
                    corrupt_flows++;
                    return;
                }
#if T2_SQLITE_SELECT == 1
                if (print)
#endif
                if (j < nv - 1) {
                    SQLITE_SNPRINTF(&qry, "_");
                }
            }

#if T2_SQLITE_SELECT == 1
            if (print)
#endif
            if (i < nr - 1) {
                SQLITE_SNPRINTF(&qry, ";");
            }
        }

#if T2_SQLITE_SELECT == 1
        if (print)
#endif
        SQLITE_SNPRINTF(&qry, "'%s", bv->next ? ", '" : ");");

        bv = bv->next;
    }

    db_query(db_conn, qry.buf);
    buf->pos = bufpos;
#if SQLITE_TRANSACTION_NFLOWS > 1
    if (++flows_to_commit == SQLITE_TRANSACTION_NFLOWS) {
        db_query(db_conn, "END TRANSACTION;");
        db_query(db_conn, "BEGIN TRANSACTION;");
        flows_to_commit = 0;
    }
#endif // SQLITE_TRANSACTION_NFLOWS > 1
}


/*
 * Skip invalid multi-bytes UTF-8 chars
 * Returns true on successful UTF-8 sanitization, false on error
 */
static bool sqlite_sanitize_utf8(outputBuffer_t *buf, sqlite_qry_t *qry
#if T2_SQLITE_SELECT == 1
    , bool print
#endif
) {
    uint8_t val, b2, b3, b4; // variables for multi-bytes characters

    while (1) {
        if (UNLIKELY(!sqlite_get_val_func(buf, &val, sizeof(val), 1))) {
            return false;
        }

continue_decode:
        if (val == '\0') {
            break;
        }

        if (val < 0x80) { // single byte char
#if T2_SQLITE_SELECT == 1
            if (print)
#endif
            switch (val) {
                case '\b':  // backspace
                    SQLITE_SNPRINTF(qry, "\\b");
                    break;
                case '\f':  // form feed
                    SQLITE_SNPRINTF(qry, "\\f");
                    break;
                case '\n':  // line feed
                    SQLITE_SNPRINTF(qry, "\\n");
                    break;
                case '\r':  // carriage return
                    SQLITE_SNPRINTF(qry, "\\r");
                    break;
                case '\t':  // horizontal tab
                    SQLITE_SNPRINTF(qry, "\\t");
                    break;
                case '\v':  // vertical tab
                    SQLITE_SNPRINTF(qry, "\\v");
                    break;
                case '\\':  // backslash
                case '"':   // dobule quote
                    SQLITE_SNPRINTF(qry, "\\%c", val);
                    break;
                case '\'':  // single quote
                    SQLITE_SNPRINTF(qry, "''");
                    break;
                default:
                    // In order to be valid JSON, control characters in 0x00-0x1f
                    // must be escaped (see: https://tools.ietf.org/html/rfc7159#page-8)
                    // Most parsers also want the DEL (0x7f) escaped even though not in RFC
                    if (val <= 0x1f || val == 0x7f) {
                        SQLITE_SNPRINTF(qry, "\\u00%02X", val);
                    } else {
                        SQLITE_SNPRINTF(qry, "%c", val);
                    }
                    break;
            }
        } else if (val < 0xc2) { // 0xc0 and 0xc1 are invalid first byte (overlong sequence)
            T2_DBG("UTF-8: Overlong sequence!");
#if T2_SQLITE_SELECT == 1
            if (print)
#endif
            SQLITE_SNPRINTF(qry, ".");
        } else if (val < 0xe0) { // 2 bytes char
            if (UNLIKELY(!sqlite_get_val_func(buf, &b2, sizeof(uint8_t), 1))) {
                return false;
            }

            if (b2 == '\0') {
                T2_DBG("UTF-8: string terminator at second byte of two bytes char!");
#if T2_SQLITE_SELECT == 1
                if (print)
#endif
                SQLITE_SNPRINTF(qry, ".");
                break;
            }

            if ((b2 & 0xc0) != 0x80) { // second byte must start with 0b10...
                T2_DBG("UTF-8: invalid second byte in two byte char (was 0x%" B2T_PRIX8 ")!", b2);
#if T2_SQLITE_SELECT == 1
                if (print)
#endif
                SQLITE_SNPRINTF(qry, ".");
                val = b2;
                goto continue_decode;
            }

            // valid UTF-8 char! -> write it out
#if T2_SQLITE_SELECT == 1
            if (print)
#endif
            SQLITE_SNPRINTF(qry, "%c%c", val, b2);
        } else if (val < 0xf0) { // 3 bytes char
            if (UNLIKELY(!sqlite_get_val_func(buf, &b2, sizeof(uint8_t), 1))) {
                return false;
            }

            if (b2 == '\0') {
                T2_DBG("UTF-8: string terminator at second byte of two bytes char!");
#if T2_SQLITE_SELECT == 1
                if (print)
#endif
                SQLITE_SNPRINTF(qry, ".");
                break;
            }

            if ((b2 & 0xc0) != 0x80) { // second byte must start with 0b10...
                T2_DBG("UTF-8: invalid second byte in three byte char (was 0x%" B2T_PRIX8 ")!", b2);
#if T2_SQLITE_SELECT == 1
                if (print)
#endif
                SQLITE_SNPRINTF(qry, ".");
                val = b2;
                goto continue_decode;
            }

            if (val == 0xe0 && b2 < 0xa0) { // invalid overlong
                T2_DBG("UTF-8: Overlong three byte sequence!");
#if T2_SQLITE_SELECT == 1
                if (print)
#endif
                SQLITE_SNPRINTF(qry, ".");
                continue;
            }

            // check third byte
            if (UNLIKELY(!sqlite_get_val_func(buf, &b3, sizeof(uint8_t), 1))) {
                return false;
            }

            if (b3 == '\0') {
                T2_DBG("UTF-8: string terminator at third byte of three bytes char!");
#if T2_SQLITE_SELECT == 1
                if (print)
#endif
                SQLITE_SNPRINTF(qry, ".");
                break;
            }

            if ((b3 & 0xc0) != 0x80) { // third byte must start with 0b10...
                T2_DBG("UTF-8: invalid third byte in three byte char (was 0x%" B2T_PRIX8 ")!", b3);
#if T2_SQLITE_SELECT == 1
                if (print)
#endif
                SQLITE_SNPRINTF(qry, ".");
                val = b3;
                goto continue_decode;
            }

            // check that code point is not in the surrogate range
            uint16_t tmp = ((uint16_t) (val & 0x0f) << 12) |
                           ((uint16_t) (b2  & 0x3f) <<  6) |
                                       (b3  & 0x3f);
            if (tmp >= 0xd800 && tmp <= 0xdfff) {
                T2_DBG("UTF-8: code point is in the surrogate range!");
#if T2_SQLITE_SELECT == 1
                if (print)
#endif
                SQLITE_SNPRINTF(qry, ".");
                continue;
            }

            // valid UTF-8 char! -> write it out
#if T2_SQLITE_SELECT == 1
            if (print)
#endif
            SQLITE_SNPRINTF(qry, "%c%c%c", val, b2, b3);
        } else if (val < 0xf5) { // 4 bytes char
            if (UNLIKELY(!sqlite_get_val_func(buf, &b2, sizeof(uint8_t), 1))) {
                return false;
            }

            if (b2 == '\0') {
                T2_DBG("UTF-8: string terminator at second byte of four bytes char!");
#if T2_SQLITE_SELECT == 1
                if (print)
#endif
                SQLITE_SNPRINTF(qry, ".");
                break;
            }

            if ((b2 & 0xc0) != 0x80) {
                T2_DBG("UTF-8: invalid second byte in four byte char (was 0x%" B2T_PRIX8 ")!", b2);
#if T2_SQLITE_SELECT == 1
                if (print)
#endif
                SQLITE_SNPRINTF(qry, "."); // second byte must start with 0b10...
                val = b2;
                goto continue_decode;
            }

            if (val == 0xf0 && b2 < 0x90) { // invalid overlong
                T2_DBG("UTF-8: Overlong four byte sequence!\n");
#if T2_SQLITE_SELECT == 1
                if (print)
#endif
                SQLITE_SNPRINTF(qry, ".");
                continue;
            }

            if (val == 0xf4 && b2 >= 0x90) { // code point > U+10FFFF
                T2_DBG("UTF-8: Code point > U+10FFFF!");
#if T2_SQLITE_SELECT == 1
                if (print)
#endif
                SQLITE_SNPRINTF(qry, ".");
                continue;
            }

            // check third byte
            if (UNLIKELY(!sqlite_get_val_func(buf, &b3, sizeof(uint8_t), 1))) {
                return false;
            }

            if (b3 == '\0') {
                T2_DBG("UTF-8: string terminator at third byte of four bytes char!");
#if T2_SQLITE_SELECT == 1
                if (print)
#endif
                SQLITE_SNPRINTF(qry, ".");
                break;
            }

            if ((b3 & 0xc0) != 0x80) {  // third byte must start with 0b10...
                T2_DBG("UTF-8: invalid third byte in four byte char (was 0x%" B2T_PRIX8 ")!", b3);
#if T2_SQLITE_SELECT == 1
                if (print)
#endif
                SQLITE_SNPRINTF(qry, ".");
                val = b3;
                goto continue_decode;
            }

            // check fourth byte
            if (UNLIKELY(!sqlite_get_val_func(buf, &b4, sizeof(uint8_t), 1))) {
                return false;
            }

            if (b4 == '\0') {
                T2_DBG("UTF-8: string terminator at fourth byte of four bytes char!");
#if T2_SQLITE_SELECT == 1
                if (print)
#endif
                SQLITE_SNPRINTF(qry, ".");
                break;
            }

            if ((b4 & 0xc0) != 0x80) { // fourth byte must start with 0b10...
                T2_DBG("UTF-8: invalid fourth byte in four byte char (was 0x%" B2T_PRIX8 ")!", b4);
#if T2_SQLITE_SELECT == 1
                if (print)
#endif
                SQLITE_SNPRINTF(qry, ".");
                val = b4;
                goto continue_decode;
            }

            // valid UTF-8 char! -> write it out
#if T2_SQLITE_SELECT == 1
            if (print)
#endif
            SQLITE_SNPRINTF(qry, "%c%c%c%c", val, b2, b3, b4);
        } else { // invalid first byte >= 0xf5
            T2_DBG("UTF-8: invalid first byte (was 0x%" B2T_PRIX8 ")!", val);
#if T2_SQLITE_SELECT == 1
            if (print)
#endif
            SQLITE_SNPRINTF(qry, ".");
        }
    }

    return true;
}


#if T2_SQLITE_SELECT == 1
// Returned value MUST be free'd
static inline bool *sqlite_select_load(binary_value_t *bv, const char *filename) {
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
#endif // T2_SQLITE_SELECT == 1

#endif // BLOCK_BUF == 0
