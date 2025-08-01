/*
 * mysqlSink.c
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

#include "mysqlSink.h"

#if MYSQL_SELECT == 1
#include <assert.h>         // for assert
#endif

#include <arpa/inet.h>      // for inet_ntop
#include <inttypes.h>       // for PRIu32, PRIu64, PRIu8, PRIu16, PRId16, PRId32, ...
#include <mysql.h>          // for mysql_init, mysql_close, mysql_query, ...
#include <netinet/in.h>     // for INET_ADDRSTRLEN, INET6_ADDRSTRLEN
#include <stdbool.h>        // for bool, true, false
#include <stdint.h>         // for uint8_t, uint16_t, uint32_t, uint64_t, uint_fast32_t
#include <stdio.h>          // for snprintf, fclose, getline, rewind, FILE
#include <stdlib.h>         // for free, exit
#include <string.h>         // for memcpy, strcmp, NULL, size_t
#include <sys/socket.h>     // for AF_INET, AF_INET6
#include <sys/types.h>      // for ssize_t, time_t
#include <time.h>           // for gmtime, strftime

#include "t2Plugin.h"


#if BLOCK_BUF == 0

// Static variables

#if ENVCNTRL > 0
static t2_env_t env[ENV_MYSQL_N];
static uint16_t mysqlPort;
static const char *mysqlHost;
static const char *mysqlUser;
static const char *mysqlPass;
static const char *mysqlTblNm;
#else // ENVCNTRL == 0
static const uint16_t mysqlPort = MYSQL_DBPORT;
static const char * const mysqlHost = MYSQL_HOST;
static const char * const mysqlUser = MYSQL_USER;
static const char * const mysqlPass = MYSQL_PASS;
static const char * const mysqlTblNm = MYSQL_TABLE_NAME;
#endif // ENVCNTRL

static MYSQL *db_conn;
static char * const db_types[] = {
    "TEXT",              // bt_compound
    "TINYINT",           // bt_int_8
    "SMALLINT",          // bt_int_16
    "INT",               // bt_int_32
    "BIGINT",            // bt_int_64
    "BIGINT",            // bt_int_128 (XXX precision loss)
    "BIGINT",            // bt_int_256 (XXX precision loss)
    "TINYINT UNSIGNED",  // bt_uint_8
    "SMALLINT UNSIGNED", // bt_uint_16
    "INT UNSIGNED",      // bt_uint_32
    "BIGINT UNSIGNED",   // bt_uint_64
    "BIGINT UNSIGNED",   // bt_uint_128 (XXX precision loss)
    "BIGINT UNSIGNED",   // bt_uint_256 (XXX precision loss)
    "TINYINT UNSIGNED",  // bt_hex_8
    "SMALLINT UNSIGNED", // bt_hex_16
    "INT UNSIGNED",      // bt_hex_32
    "BIGINT UNSIGNED",   // bt_hex_64
    "BIGINT UNSIGNED",   // bt_hex_128 (XXX precision loss)
    "BIGINT UNSIGNED",   // bt_hex_256 (XXX precision loss)
    //"BIT(8)",            // bt_hex_8
    //"BIT(16)",           // bt_hex_16
    //"BIT(32)",           // bt_hex_32
    //"BIT(64)",           // bt_hex_64
    //"BIT(128)",          // bt_hex_128
    //"BIT(256)",          // bt_hex_256
    "FLOAT",             // bt_float
    "DOUBLE",            // bt_double
    "DOUBLE",            // bt_long_double (XXX precision loss)
    "CHAR(1)",           // bt_char
    "TEXT",              // bt_string
    "CHAR(1)",           // bt_flow_direction
    "DATETIME(6)",       // bt_timestamp
    //"DECIMAL",           // bt_duration
    "TIME",              // bt_duration
    "TEXT",              // bt_mac_addr
    "TEXT",              // bt_ip4_addr
    "TEXT",              // bt_ip6_addr
    "TEXT",              // bt_ipx_addr
    "TEXT",              // bt_string_class
};
#if MYSQL_TRANSACTION_NFLOWS > 1
static uint64_t flows_to_commit;
#endif // MYSQL_TRANSACTION_NFLOWS > 1

#if MYSQL_SELECT == 1
static bool *feature_active;
#endif


// Function prototypes

static inline void db_connect(MYSQL *conn, const char *dbname);
static inline void db_create(MYSQL *conn, const char *dbname);
static inline void db_query(MYSQL *conn, const char *qry);
static inline void db_create_flow_table(MYSQL *conn, const char *name, binary_value_t *bv);
static inline char *db_create_flow_table_qry(MYSQL *conn, const char *name, binary_value_t *bv);
#if MYSQL_OVERWRITE_DB == 1
static inline void db_drop(MYSQL *conn, const char *name);
#endif // MYSQL_OVERWRITE_DB == 1
#if MYSQL_OVERWRITE_TABLE == 1
static inline void db_drop_table(MYSQL *conn, const char *name);
#endif // MYSQL_OVERWRITE_TABLE == 1
static inline bool db_exists(MYSQL *conn, const char *name);
static inline bool db_table_exists(MYSQL *conn, const char *name);
static inline bool mysql_get_val_func(outputBuffer_t *buf, void *dest, size_t size, size_t n);
static int mysql_parse_sv_type(outputBuffer_t *buf, char *qry, int pos, binary_type_t type
#if MYSQL_SELECT == 1
    , bool print
#endif
);
static int mysql_parse_sv(outputBuffer_t *buf, char *qry, int pos, binary_subvalue_t *sv
#if MYSQL_SELECT == 1
    , bool print
#endif
);
static bool mysql_sanitize_utf8(outputBuffer_t *buf, char *qry, int *pos
#if MYSQL_SELECT == 1
    , bool print
#endif
);
#if MYSQL_SELECT == 1
// Returned value MUST be free'd
static inline bool *mysql_select_load(binary_value_t *bv, const char *filename);
#endif


// Defines

// Wrapper for snprintf.
// Increases pos by the number of bytes written
#define MYSQL_SNPRINTF(pos, str, size, format, args...) { \
    const int n = snprintf(str, (size), format, ##args); \
    if (UNLIKELY(n >= (size))) { \
        T2_PERR(plugin_name, "query truncated... increase MYSQL_QRY_LEN"); \
        mysql_close(db_conn); \
        exit(EXIT_FAILURE); \
    } \
    pos += n; \
}

#endif // BLOCK_BUF == 0


// Tranalyzer functions

T2_PLUGIN_INIT("mysqlSink", "0.9.3", 0, 9);


void t2Init() {
#if BLOCK_BUF == 1
    T2_PWRN(plugin_name, "BLOCK_BUF is set in 'tranalyzer.h', no output will be produced");
#else // BLOCK_BUF == 0

#if ENVCNTRL > 0
    t2_get_env(PLUGIN_SRCH, ENV_MYSQL_N, env);
    const char * const dbname = T2_ENV_VAL(MYSQL_DBNAME);
    mysqlHost = T2_ENV_VAL(MYSQL_HOST);
    mysqlPort = T2_ENV_VAL_UINT(MYSQL_DBPORT);
    mysqlUser = T2_ENV_VAL(MYSQL_USER);
    mysqlPass = T2_ENV_VAL(MYSQL_PASS);
    mysqlTblNm = T2_ENV_VAL(MYSQL_TABLE_NAME);
#if MYSQL_SELECT == 1
    const char * const selectFile = T2_ENV_VAL(MYSQL_SELECT_FILE);
#endif
#else // ENVCNTRL == 0
    const char * const dbname = MYSQL_DBNAME;
#if MYSQL_SELECT == 1
    const char * const selectFile = MYSQL_SELECT_FILE;
#endif
#endif // ENVCNTRL

    if (UNLIKELY(!(db_conn = mysql_init(NULL)))) {
        T2_PERR(plugin_name, "Failed to initialize DB: %s", mysql_error(db_conn));
        exit(EXIT_FAILURE);
    }

    db_connect(db_conn, NULL);

    if (db_exists(db_conn, dbname)) {
#if MYSQL_OVERWRITE_DB == 0
        T2_PERR(plugin_name, "Database '%s' already exists", dbname);
        mysql_close(db_conn);
        exit(EXIT_FAILURE);
#elif MYSQL_OVERWRITE_DB == 1
        db_drop(db_conn, dbname);
#endif // MYSQL_OVERWRITE_DB == 1
    }

    db_create(db_conn, dbname);
    if (UNLIKELY(mysql_select_db(db_conn, dbname) != 0)) {
        T2_PERR(plugin_name, "Failed to select DB '%s': %s", dbname, mysql_error(db_conn));
        mysql_close(db_conn);
        exit(EXIT_FAILURE);
    }

#if MYSQL_SELECT == 1
    feature_active = mysql_select_load(main_header_bv, selectFile);
#endif

    if (db_table_exists(db_conn, mysqlTblNm)) {
#if MYSQL_OVERWRITE_TABLE == 0
        T2_PERR(plugin_name, "Table '%s' already exists", mysqlTblNm);
        mysql_close(db_conn);
        exit(EXIT_FAILURE);
#elif MYSQL_OVERWRITE_TABLE == 1
        db_drop_table(db_conn, mysqlTblNm);
#else // MYSQL_OVERWRITE_TABLE == 2
        // TODO test that schema matches
#endif // MYSQL_OVERWRITE_TABLE == 2
    }

    db_create_flow_table(db_conn, mysqlTblNm, main_header_bv);

#if MYSQL_TRANSACTION_NFLOWS != 1
    db_query(db_conn, "START TRANSACTION;");
#endif // MYSQL_TRANSACTION_NFLOWS != 1

#endif // BLOCK_BUF == 0
}


// If BLOCK_BUF == 1, the plugin does not produce any output.
// All the code below is therefore not activated.


#if BLOCK_BUF == 0

void t2Finalize() {
#if MYSQL_TRANSACTION_NFLOWS > 1
    if (flows_to_commit > 0)
#endif // MYSQL_TRANSACTION_NFLOWS > 1
        db_query(db_conn, "COMMIT;");
    mysql_close(db_conn);
#if MYSQL_SELECT == 1
    free(feature_active);
#endif
#if ENVCNTRL > 0
    t2_free_env(ENV_MYSQL_N, env);
#endif // ENVCNTRL > 0
}


static inline void db_connect(MYSQL *conn, const char *dbname) {
    if (UNLIKELY(!(mysql_real_connect(conn, mysqlHost, mysqlUser, mysqlPass, dbname, mysqlPort, NULL, 0)))) {
        T2_PERR(plugin_name, "Failed to connect to DB on '%s:%d' with user '%s': %s", mysqlHost, mysqlPort, mysqlUser, mysql_error(conn));
        mysql_close(conn);
        exit(EXIT_FAILURE);
    }
}


static inline void db_query(MYSQL *conn, const char *qry) {
    if (UNLIKELY(mysql_query(conn, qry) != 0)) {
        T2_PERR(plugin_name, "Failed to execute query '%s': %s", qry, mysql_error(conn));
        mysql_close(conn);
        exit(EXIT_FAILURE);
    }
}


static inline void db_create(MYSQL *conn, const char *dbname) {
    char qry[MYSQL_QRY_LEN];
    snprintf(qry, MYSQL_QRY_LEN, "CREATE DATABASE IF NOT EXISTS %s CHARACTER SET utf8 COLLATE utf8_general_ci;", dbname);
    db_query(conn, qry);
}


// Returned value MUST be free'd
static inline char *db_create_flow_table_qry(MYSQL *conn, const char *name, binary_value_t *bv) {
    char *qry = t2_malloc_fatal(MYSQL_QRY_LEN);
#if MYSQL_SELECT == 1
    uint32_t feature_id = UINT32_MAX;
#endif
    int pos = snprintf(qry, MYSQL_QRY_LEN, "CREATE TABLE IF NOT EXISTS %s (", name);
    while (bv) {
#if MYSQL_SELECT == 1
        feature_id++;
        if (!feature_active[feature_id]) {
            bv = bv->next;
            continue;
        }
#endif
        MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "%s", bv->name);
        char *type;
        if (bv->is_repeating || bv->num_values > 1) {
            type = "TEXT";
        } else {
            const binary_type_t t = bv->subval[0].type;
            if (t > bt_string_class) {
                T2_PERR(plugin_name, "Unhandled type %u", t);
                mysql_close(conn);
                exit(EXIT_FAILURE);
            }
            type = db_types[t];
        }
        MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, " %s%s", type, bv->next ? ", " : ");");
        bv = bv->next;
    }

    return qry;
}


static inline void db_create_flow_table(MYSQL *conn, const char *name, binary_value_t *bv) {
    char *qry = db_create_flow_table_qry(conn, name, bv);
    db_query(conn, qry);
    free(qry);
}


#if MYSQL_OVERWRITE_DB == 1
static inline void db_drop(MYSQL *conn, const char *name) {
    char qry[MYSQL_QRY_LEN];
    snprintf(qry, MYSQL_QRY_LEN, "DROP DATABASE %s;", name);
    db_query(conn, qry);
}
#endif // MYSQL_OVERWRITE_DB == 1


#if MYSQL_OVERWRITE_TABLE == 1
static inline void db_drop_table(MYSQL *conn, const char *name) {
    char qry[MYSQL_QRY_LEN];
    snprintf(qry, MYSQL_QRY_LEN, "DROP TABLE %s;", name);
    db_query(conn, qry);
}
#endif // MYSQL_OVERWRITE_TABLE == 1


static inline bool db_exists(MYSQL *conn, const char *name) {
    char qry[MYSQL_QRY_LEN];
    snprintf(qry, MYSQL_QRY_LEN, "SHOW DATABASES LIKE '%s';", name);
    db_query(conn, qry);
    MYSQL_RES *res = mysql_store_result(conn);
    const bool exists = (res && mysql_num_rows(res) > 0);
    mysql_free_result(res);
    return exists;
}


static inline bool db_table_exists(MYSQL *conn, const char *name) {
    char qry[MYSQL_QRY_LEN];
    snprintf(qry, MYSQL_QRY_LEN, "SHOW TABLES LIKE '%s';", name);
    db_query(conn, qry);
    MYSQL_RES *res = mysql_store_result(conn);
    const bool exists = (res && mysql_num_rows(res) > 0);
    mysql_free_result(res);
    return exists;
}


static inline bool mysql_get_val_func(outputBuffer_t *buf, void *dest, size_t size, size_t n) {
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


static int mysql_parse_sv_type(outputBuffer_t *buf, char *qry, int pos, binary_type_t type
#if MYSQL_SELECT == 1
    , bool print
#endif
) {
    switch (type) {
        case bt_int_8: {
            int8_t val;
            if (UNLIKELY(!mysql_get_val_func(buf, &val, sizeof(val), 1))) {
                exit(EXIT_FAILURE);
            }
#if MYSQL_SELECT == 1
            if (!print) break;
#endif
            MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "%" PRId8, val);
            break;
        }

        case bt_int_16: {
            int16_t val;
            if (UNLIKELY(!mysql_get_val_func(buf, &val, sizeof(val), 1))) {
                exit(EXIT_FAILURE);
            }
#if MYSQL_SELECT == 1
            if (!print) break;
#endif
            MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "%" PRId16, val);
            break;
        }

        case bt_int_32: {
            int32_t val;
            if (UNLIKELY(!mysql_get_val_func(buf, &val, sizeof(val), 1))) {
                exit(EXIT_FAILURE);
            }
#if MYSQL_SELECT == 1
            if (!print) break;
#endif
            MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "%" PRId32, val);
            break;
        }

        case bt_int_64: {
            int64_t val;
            if (UNLIKELY(!mysql_get_val_func(buf, &val, sizeof(val), 1))) {
                exit(EXIT_FAILURE);
            }
#if MYSQL_SELECT == 1
            if (!print) break;
#endif
            MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "%" PRId64, val);
            break;
        }

        //case bt_int_128:
        //case bt_int_256:

        case bt_uint_8: {
            uint8_t val;
            if (UNLIKELY(!mysql_get_val_func(buf, &val, sizeof(val), 1))) {
                exit(EXIT_FAILURE);
            }
#if MYSQL_SELECT == 1
            if (!print) break;
#endif
            MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "%" PRIu8, val);
            break;
        }

        case bt_uint_16: {
            uint16_t val;
            if (UNLIKELY(!mysql_get_val_func(buf, &val, sizeof(val), 1))) {
                exit(EXIT_FAILURE);
            }
#if MYSQL_SELECT == 1
            if (!print) break;
#endif
            MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "%" PRIu16, val);
            break;
        }

        case bt_uint_32: {
            uint32_t val;
            if (UNLIKELY(!mysql_get_val_func(buf, &val, sizeof(val), 1))) {
                exit(EXIT_FAILURE);
            }
#if MYSQL_SELECT == 1
            if (!print) break;
#endif
            MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "%" PRIu32, val);
            break;
        }

        case bt_uint_64: {
            uint64_t val;
            if (UNLIKELY(!mysql_get_val_func(buf, &val, sizeof(val), 1))) {
                exit(EXIT_FAILURE);
            }
#if MYSQL_SELECT == 1
            if (!print) break;
#endif
            MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "%" PRIu64, val);
            break;
        }

        //case bt_uint_128:
        //case bt_uint_256:

        case bt_hex_8: {
            uint8_t val;
            if (UNLIKELY(!mysql_get_val_func(buf, &val, sizeof(val), 1))) {
                exit(EXIT_FAILURE);
            }
#if MYSQL_SELECT == 1
            if (!print) break;
#endif
            //MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "0x%02" B2T_PRIX8, val);
            MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "%" PRIu8, val);
            break;
        }

        case bt_hex_16: {
            uint16_t val;
            if (UNLIKELY(!mysql_get_val_func(buf, &val, sizeof(val), 1))) {
                exit(EXIT_FAILURE);
            }
#if MYSQL_SELECT == 1
            if (!print) break;
#endif
            //MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "0x%04" B2T_PRIX16, val);
            MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "%" PRIu16, val);
            break;
        }

        case bt_hex_32: {
            uint32_t val;
            if (UNLIKELY(!mysql_get_val_func(buf, &val, sizeof(val), 1))) {
                exit(EXIT_FAILURE);
            }
#if MYSQL_SELECT == 1
            if (!print) break;
#endif
            //MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "0x%08" B2T_PRIX32, val);
            MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "%" PRIu32, val);
            break;
        }

        case bt_hex_64: {
            uint64_t val;
            if (UNLIKELY(!mysql_get_val_func(buf, &val, sizeof(val), 1))) {
                exit(EXIT_FAILURE);
            }
#if MYSQL_SELECT == 1
            if (!print) break;
#endif
            //MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "0x%016" B2T_PRIX64, val);
            MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "%" PRIu64, val);
            break;
        }

        //case bt_hex_128:
        //case bt_hex_256:

        case bt_float: {
            float val;
            if (UNLIKELY(!mysql_get_val_func(buf, &val, sizeof(val), 1))) {
                exit(EXIT_FAILURE);
            }
#if MYSQL_SELECT == 1
            if (!print) break;
#endif
            MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "%f", val);
            break;
        }

        case bt_double: {
            double val;
            if (UNLIKELY(!mysql_get_val_func(buf, &val, sizeof(val), 1))) {
                exit(EXIT_FAILURE);
            }
#if MYSQL_SELECT == 1
            if (!print) break;
#endif
            MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "%f", val);
            break;
        }

        case bt_long_double: {
            long double val;
            if (UNLIKELY(!mysql_get_val_func(buf, &val, sizeof(val), 1))) {
                exit(EXIT_FAILURE);
            }
#if MYSQL_SELECT == 1
            if (!print) break;
#endif
            MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "%Lf", val);
            break;
        }

        case bt_char: {
            uint8_t val;
            if (UNLIKELY(!mysql_get_val_func(buf, &val, sizeof(val), 1))) {
                exit(EXIT_FAILURE);
            }
#if MYSQL_SELECT == 1
            if (!print) break;
#endif
            MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "%c", val);
            break;
        }

        case bt_string_class:
        case bt_string: {
            if (UNLIKELY(!mysql_sanitize_utf8(buf, qry, &pos
#if MYSQL_SELECT == 1
                , print
#endif
            ))) {
                exit(EXIT_FAILURE);
            }
            break;
        }

        case bt_flow_direction: {
            uint8_t val;
            if (UNLIKELY(!mysql_get_val_func(buf, &val, sizeof(val), 1))) {
                exit(EXIT_FAILURE);
            }
#if MYSQL_SELECT == 1
            if (!print) break;
#endif
            MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "%c", (val == 0) ? FLOW_DIR_C_A : FLOW_DIR_C_B);
            break;
        }

        case bt_timestamp:
        case bt_duration: {
            // read seconds
            uint64_t val;
            if (UNLIKELY(!mysql_get_val_func(buf, &val, sizeof(val), 1))) {
                exit(EXIT_FAILURE);
            }

            // read nanoseconds
            uint32_t ns;
            if (UNLIKELY(!mysql_get_val_func(buf, &ns, sizeof(ns), 1))) {
                exit(EXIT_FAILURE);
            }

#if MYSQL_SELECT == 1
            if (!print) break;
#endif

#if TSTAMP_PREC == 0
            ns /= 1000;
#endif // TSTAMP_PREC == 0

            if (type == bt_duration) {
                MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "%" PRIu64 ".%" B2T_TPFRMT, val, ns);
            } else {
                const struct tm * const t = gmtime((time_t*)&val);
                char timeBuf[30];
                // ISO 8601 time format
                // <year>-<month>-<day> <hours>:<minutes>:<seconds>.<micro/nano-seconds>
                strftime(timeBuf, sizeof(timeBuf), "%F %T", t);
                MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "%s.%" B2T_TPFRMT, timeBuf, ns); // micro/nano-seconds
            }
            break;
        }

        case bt_mac_addr: {
            uint8_t val[l_bt_mac_addr];
            if (UNLIKELY(!mysql_get_val_func(buf, &val, l_bt_mac_addr * sizeof(uint8_t), 1))) {
                exit(EXIT_FAILURE);
            }
#if MYSQL_SELECT == 1
            if (!print) break;
#endif
            // TODO use t2_mac_to_str
#if MAC_FORMAT == 1
            MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "0x%016" B2T_PRIX64,
                    ((uint64_t)val[0] << 40) | ((uint64_t)val[1] << 32) | ((uint64_t)val[2] << 24) |
                    ((uint64_t)val[0] << 40) | ((uint64_t)val[1] << 32) | ((uint64_t)val[2] << 24) |
                    ((uint64_t)val[3] << 16) | ((uint64_t)val[4] << 8)  |  (uint64_t)val[5]);
#elif MAC_FORMAT == 2
            const uint64_t mac64 = t2_mac_to_uint64(val);
            MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "%" PRIu64, mac64);
#else // MAC_FORMAT == 0
            MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos,
                    "%02" B2T_PRIX8 "%s%02" B2T_PRIX8 "%s%02" B2T_PRIX8 "%s"
                    "%02" B2T_PRIX8 "%s%02" B2T_PRIX8 "%s%02" B2T_PRIX8,
                    val[0], MAC_SEP, val[1], MAC_SEP, val[2], MAC_SEP,
                    val[3], MAC_SEP, val[4], MAC_SEP, val[5]);
#endif // MAC_FORMAT == 0
            break;
        }

        case bt_ip4_addr: {
mysql_bt_ip4:;
            uint8_t val[l_bt_ip4_addr];
            if (UNLIKELY(!mysql_get_val_func(buf, &val, l_bt_ip4_addr * sizeof(uint8_t), 1))) {
                exit(EXIT_FAILURE);
            }
#if MYSQL_SELECT == 1
            if (!print) break;
#endif
#if IP4_FORMAT == 1
            MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos,
                "%03" PRIu8 ".%03" PRIu8 ".%03" PRIu8 ".%03" PRIu8,
                val[0], val[1], val[2], val[3]);
#elif IP4_FORMAT == 2
            MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos,
                "0x%02" B2T_PRIX8 "%02" B2T_PRIX8 "%02" B2T_PRIX8 "%02" B2T_PRIX8,
                val[0], val[1], val[2], val[3]);
#elif IP4_FORMAT == 3
            const uint32_t addr32 = (val[0] << 24) | (val[1] << 16) | (val[2] << 8) | val[3];
            MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "%" PRIu32, addr32);
#else // IP4_FORMAT == 0
            MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos,
                "%" PRIu8 ".%" PRIu8 ".%" PRIu8 ".%" PRIu8,
                val[0], val[1], val[2], val[3]);
#endif // IP4_FORMAT == 0
            break;
        }

        case bt_ip6_addr: {
mysql_bt_ip6:;
            uint8_t val[l_bt_ip6_addr];
            if (UNLIKELY(!mysql_get_val_func(buf, &val, l_bt_ip6_addr * sizeof(uint8_t), 1))) {
                exit(EXIT_FAILURE);
            }
#if MYSQL_SELECT == 1
            if (!print) break;
#endif
#if IP6_FORMAT == 1
            const uint16_t * const val16 = (uint16_t*)val;
            MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos,
                    "%04" B2T_PRIX16 ":%04" B2T_PRIX16 ":%04" B2T_PRIX16 ":%04" B2T_PRIX16 ":"
                    "%04" B2T_PRIX16 ":%04" B2T_PRIX16 ":%04" B2T_PRIX16 ":%04" B2T_PRIX16,
                    ntohs(val16[0]), ntohs(val16[1]), ntohs(val16[2]), ntohs(val16[3]),
                    ntohs(val16[4]), ntohs(val16[5]), ntohs(val16[6]), ntohs(val16[7]));
#elif IP6_FORMAT == 2
            MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos,
                    "0x%02" B2T_PRIX8 "%02" B2T_PRIX8 "%02" B2T_PRIX8 "%02" B2T_PRIX8
                      "%02" B2T_PRIX8 "%02" B2T_PRIX8 "%02" B2T_PRIX8 "%02" B2T_PRIX8
                      "%02" B2T_PRIX8 "%02" B2T_PRIX8 "%02" B2T_PRIX8 "%02" B2T_PRIX8
                      "%02" B2T_PRIX8 "%02" B2T_PRIX8 "%02" B2T_PRIX8 "%02" B2T_PRIX8,
                    val[0], val[1], val[2], val[3], val[4], val[5], val[6], val[7],
                    val[8], val[9], val[10], val[11], val[12], val[13], val[14], val[15]);
#elif IP6_FORMAT == 3
            MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos,
                    "0x%02" B2T_PRIX8 "%02" B2T_PRIX8 "%02" B2T_PRIX8 "%02" B2T_PRIX8
                      "%02" B2T_PRIX8 "%02" B2T_PRIX8 "%02" B2T_PRIX8 "%02" B2T_PRIX8 "_"
                    "0x%02" B2T_PRIX8 "%02" B2T_PRIX8 "%02" B2T_PRIX8 "%02" B2T_PRIX8
                      "%02" B2T_PRIX8 "%02" B2T_PRIX8 "%02" B2T_PRIX8 "%02" B2T_PRIX8,
                    val[0], val[1], val[2], val[3], val[4], val[5], val[6], val[7],
                    val[8], val[9], val[10], val[11], val[12], val[13], val[14], val[15]);
#else // IP6_FORMAT == 0
            char addr[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, val, addr, INET6_ADDRSTRLEN);
            MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "%s", addr);
#endif // IP6_FORMAT == 0
            break;
        }

        case bt_ipx_addr: {
            uint8_t version;
            if (UNLIKELY(!mysql_get_val_func(buf, &version, sizeof(version), 1))) {
                exit(EXIT_FAILURE);
            }
            if (version == 4) {
                goto mysql_bt_ip4;
            } else if (version == 6) {
                goto mysql_bt_ip6;
            } else if (version == 0) {
#if MYSQL_SELECT == 1
                if (!print) break;
#endif
                MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "%s", B2T_NON_IP_STR);
            } else {
                T2_PERR(plugin_name, "invalid IP version %" PRIu8, version);
                exit(EXIT_FAILURE);
            }
            break;
        }

        default:
            T2_PERR(plugin_name, "unhandled output type %" PRIu32, type);
            exit(EXIT_FAILURE);
    }

    return pos;
}


static int mysql_parse_sv(outputBuffer_t *buf, char *qry, int pos, binary_subvalue_t *sv
#if MYSQL_SELECT == 1
        , bool print
#endif
) {
    if (sv->type) {
        return mysql_parse_sv_type(buf, qry, pos, sv->type
#if MYSQL_SELECT == 1
            , print
#endif
        );
    }

#if MYSQL_SELECT == 1
    if (print)
#endif
    MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "(");
    uint32_t nr = 1;
    if (sv->is_repeating) {
        if (UNLIKELY(!mysql_get_val_func(buf, &nr, sizeof(nr), 1))) {
            exit(EXIT_FAILURE);
        }
    }
    const uint_fast32_t nv = sv->num_values;
    for (uint_fast32_t i = 0; i < nr; i++) {
        for (uint_fast32_t j = 0; j < nv; j++) {
            pos = mysql_parse_sv(buf, qry, pos, &sv->subval[j]
#if MYSQL_SELECT == 1
            , print
#endif
            );
            // write value delim
#if MYSQL_SELECT == 1
            if (print)
#endif
            if (j < nv - 1) {
                MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "_");
            }
        }

        // write repeat delim
#if MYSQL_SELECT == 1
        if (print)
#endif
        if (i < nr - 1) {
            MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, ";");
        }
    }

#if MYSQL_SELECT == 1
    if (print)
#endif
    MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, ")");

    return pos;
}


void t2BufferToSink(outputBuffer_t *buf, binary_value_t *bv) {
    const uint32_t bufpos = buf->pos;
    buf->pos = 0;
    char qry[MYSQL_QRY_LEN];
    int pos = snprintf(qry, MYSQL_QRY_LEN, "INSERT INTO %s VALUES ('", mysqlTblNm);
#if MYSQL_SELECT == 1
    uint32_t feature_id = UINT32_MAX;
#endif

    while (bv) {
#if MYSQL_SELECT == 1
        feature_id++;
        const bool print = feature_active[feature_id];
#endif
        uint32_t nr = 1;
        if (bv->is_repeating) {
            if (UNLIKELY(!mysql_get_val_func(buf, &nr, sizeof(nr), 1))) {
                exit(EXIT_FAILURE);
            }
        }

        const uint_fast32_t nv = bv->num_values;
        for (uint_fast32_t i = 0; i < nr; i++) {
            for (uint_fast32_t j = 0; j < nv; j++) {
                pos = mysql_parse_sv(buf, qry, pos, &bv->subval[j]
#if MYSQL_SELECT == 1
                    , print
#endif
                );
#if MYSQL_SELECT == 1
                if (print)
#endif
                if (j < nv - 1) {
                    MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "_");
                }
            }

#if MYSQL_SELECT == 1
            if (print)
#endif
            if (i < nr - 1) {
                MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, ";");
            }
        }

#if MYSQL_SELECT == 1
        if (print)
#endif
        MYSQL_SNPRINTF(pos, &qry[pos], MYSQL_QRY_LEN - pos, "'%s", bv->next ? ", '" : ");");

        bv = bv->next;
    }

    db_query(db_conn, qry);
    buf->pos = bufpos;
#if MYSQL_TRANSACTION_NFLOWS > 1
    if (++flows_to_commit == MYSQL_TRANSACTION_NFLOWS) {
        db_query(db_conn, "COMMIT;");
        db_query(db_conn, "START TRANSACTION;");
        flows_to_commit = 0;
    }
#endif // MYSQL_TRANSACTION_NFLOWS > 1
}


/*
 * Skip invalid multi-bytes UTF-8 chars
 * Returns true on successful UTF-8 sanitization, false on error
 */
static bool mysql_sanitize_utf8(outputBuffer_t *buf, char *qry, int *pos
#if MYSQL_SELECT == 1
    , bool print
#endif
) {
    uint8_t val, b2, b3, b4; // variables for multi-bytes characters

    while (1) {
        if (UNLIKELY(!mysql_get_val_func(buf, &val, sizeof(val), 1))) {
            return false;
        }

continue_decode:
        if (val == '\0') {
            break;
        }

        if (val < 0x80) { // single byte char
#if MYSQL_SELECT == 1
            if (print)
#endif
            switch (val) {
                case '\b':  // backspace
                    MYSQL_SNPRINTF(*pos, &qry[*pos], MYSQL_QRY_LEN - *pos, "\\b");
                    break;
                case '\f':  // form feed
                    MYSQL_SNPRINTF(*pos, &qry[*pos], MYSQL_QRY_LEN - *pos, "\\f");
                    break;
                case '\n':  // line feed
                    MYSQL_SNPRINTF(*pos, &qry[*pos], MYSQL_QRY_LEN - *pos, "\\n");
                    break;
                case '\r':  // carriage return
                    MYSQL_SNPRINTF(*pos, &qry[*pos], MYSQL_QRY_LEN - *pos, "\\r");
                    break;
                case '\t':  // horizontal tab
                    MYSQL_SNPRINTF(*pos, &qry[*pos], MYSQL_QRY_LEN - *pos, "\\t");
                    break;
                case '\v':  // vertical tab
                    MYSQL_SNPRINTF(*pos, &qry[*pos], MYSQL_QRY_LEN - *pos, "\\v");
                    break;
                case '\\':  // backslash
                case '"':   // double quote
                case '\'':  // single quote
                    MYSQL_SNPRINTF(*pos, &qry[*pos], MYSQL_QRY_LEN - *pos, "\\%c", val);
                    break;
                default:
                    // In order to be valid JSON, control characters in 0x00-0x1f
                    // must be escaped (see: https://tools.ietf.org/html/rfc7159#page-8)
                    // Most parsers also want the DEL (0x7f) escaped even though not in RFC
                    if (val <= 0x1f || val == 0x7f) {
                        MYSQL_SNPRINTF(*pos, &qry[*pos], MYSQL_QRY_LEN - *pos, "\\u00%02X", val);
                    } else {
                        MYSQL_SNPRINTF(*pos, &qry[*pos], MYSQL_QRY_LEN - *pos, "%c", val);
                    }
                    break;
            }
        } else if (val < 0xc2) { // 0xc0 and 0xc1 are invalid first byte (overlong sequence)
            T2_DBG("UTF-8: Overlong sequence!");
#if MYSQL_SELECT == 1
            if (print)
#endif
            MYSQL_SNPRINTF(*pos, &qry[*pos], MYSQL_QRY_LEN - *pos, ".");
        } else if (val < 0xe0) { // 2 bytes char
            if (UNLIKELY(!mysql_get_val_func(buf, &b2, sizeof(uint8_t), 1))) {
                return false;
            }

            if (b2 == '\0') {
                T2_DBG("UTF-8: string terminator at second byte of two bytes char!");
#if MYSQL_SELECT == 1
                if (print)
#endif
                MYSQL_SNPRINTF(*pos, &qry[*pos], MYSQL_QRY_LEN - *pos, ".");
                break;
            }

            if ((b2 & 0xc0) != 0x80) { // second byte must start with 0b10...
                T2_DBG("UTF-8: invalid second byte in two byte char (was 0x%" B2T_PRIX8 ")!", b2);
#if MYSQL_SELECT == 1
                if (print)
#endif
                MYSQL_SNPRINTF(*pos, &qry[*pos], MYSQL_QRY_LEN - *pos, ".");
                val = b2;
                goto continue_decode;
            }

            // valid UTF-8 char! -> write it out
#if MYSQL_SELECT == 1
            if (print)
#endif
            MYSQL_SNPRINTF(*pos, &qry[*pos], MYSQL_QRY_LEN - *pos, "%c%c", val, b2);
        } else if (val < 0xf0) { // 3 bytes char
            if (UNLIKELY(!mysql_get_val_func(buf, &b2, sizeof(uint8_t), 1))) {
                return false;
            }

            if (b2 == '\0') {
                T2_DBG("UTF-8: string terminator at second byte of two bytes char!");
#if MYSQL_SELECT == 1
                if (print)
#endif
                MYSQL_SNPRINTF(*pos, &qry[*pos], MYSQL_QRY_LEN - *pos, ".");
                break;
            }

            if ((b2 & 0xc0) != 0x80) { // second byte must start with 0b10...
                T2_DBG("UTF-8: invalid second byte in three byte char (was 0x%" B2T_PRIX8 ")!", b2);
#if MYSQL_SELECT == 1
                if (print)
#endif
                MYSQL_SNPRINTF(*pos, &qry[*pos], MYSQL_QRY_LEN - *pos, ".");
                val = b2;
                goto continue_decode;
            }

            if (val == 0xe0 && b2 < 0xa0) { // invalid overlong
                T2_DBG("UTF-8: Overlong three byte sequence!");
#if MYSQL_SELECT == 1
                if (print)
#endif
                MYSQL_SNPRINTF(*pos, &qry[*pos], MYSQL_QRY_LEN - *pos, ".");
                continue;
            }

            // check third byte
            if (UNLIKELY(!mysql_get_val_func(buf, &b3, sizeof(uint8_t), 1))) {
                return false;
            }

            if (b3 == '\0') {
                T2_DBG("UTF-8: string terminator at third byte of three bytes char!");
#if MYSQL_SELECT == 1
                if (print)
#endif
                MYSQL_SNPRINTF(*pos, &qry[*pos], MYSQL_QRY_LEN - *pos, ".");
                break;
            }

            if ((b3 & 0xc0) != 0x80) { // third byte must start with 0b10...
                T2_DBG("UTF-8: invalid third byte in three byte char (was 0x%" B2T_PRIX8 ")!", b3);
#if MYSQL_SELECT == 1
                if (print)
#endif
                MYSQL_SNPRINTF(*pos, &qry[*pos], MYSQL_QRY_LEN - *pos, ".");
                val = b3;
                goto continue_decode;
            }

            // check that code point is not in the surrogate range
            uint16_t tmp = ((uint16_t) (val & 0x0f) << 12) |
                           ((uint16_t) (b2  & 0x3f) <<  6) |
                                       (b3  & 0x3f);
            if (tmp >= 0xd800 && tmp <= 0xdfff) {
                T2_DBG("UTF-8: code point is in the surrogate range!");
#if MYSQL_SELECT == 1
                if (print)
#endif
                MYSQL_SNPRINTF(*pos, &qry[*pos], MYSQL_QRY_LEN - *pos, ".");
                continue;
            }

            // valid UTF-8 char! -> write it out
#if MYSQL_SELECT == 1
            if (print)
#endif
            MYSQL_SNPRINTF(*pos, &qry[*pos], MYSQL_QRY_LEN - *pos, "%c%c%c", val, b2, b3);
        } else if (val < 0xf5) { // 4 bytes char
            if (UNLIKELY(!mysql_get_val_func(buf, &b2, sizeof(uint8_t), 1))) {
                return false;
            }

            if (b2 == '\0') {
                T2_DBG("UTF-8: string terminator at second byte of four bytes char!");
#if MYSQL_SELECT == 1
                if (print)
#endif
                MYSQL_SNPRINTF(*pos, &qry[*pos], MYSQL_QRY_LEN - *pos, ".");
                break;
            }

            if ((b2 & 0xc0) != 0x80) {
                T2_DBG("UTF-8: invalid second byte in four byte char (was 0x%" B2T_PRIX8 ")!", b2);
#if MYSQL_SELECT == 1
                if (print)
#endif
                MYSQL_SNPRINTF(*pos, &qry[*pos], MYSQL_QRY_LEN - *pos, "."); // second byte must start with 0b10...
                val = b2;
                goto continue_decode;
            }

            if (val == 0xf0 && b2 < 0x90) { // invalid overlong
                T2_DBG("UTF-8: Overlong four byte sequence!\n");
#if MYSQL_SELECT == 1
                if (print)
#endif
                MYSQL_SNPRINTF(*pos, &qry[*pos], MYSQL_QRY_LEN - *pos, ".");
                continue;
            }

            if (val == 0xf4 && b2 >= 0x90) { // code point > U+10FFFF
                T2_DBG("UTF-8: Code point > U+10FFFF!");
#if MYSQL_SELECT == 1
                if (print)
#endif
                MYSQL_SNPRINTF(*pos, &qry[*pos], MYSQL_QRY_LEN - *pos, ".");
                continue;
            }

            // check third byte
            if (UNLIKELY(!mysql_get_val_func(buf, &b3, sizeof(uint8_t), 1))) {
                return false;
            }

            if (b3 == '\0') {
                T2_DBG("UTF-8: string terminator at third byte of four bytes char!");
#if MYSQL_SELECT == 1
                if (print)
#endif
                MYSQL_SNPRINTF(*pos, &qry[*pos], MYSQL_QRY_LEN - *pos, ".");
                break;
            }

            if ((b3 & 0xc0) != 0x80) {  // third byte must start with 0b10...
                T2_DBG("UTF-8: invalid third byte in four byte char (was 0x%" B2T_PRIX8 ")!", b3);
#if MYSQL_SELECT == 1
                if (print)
#endif
                MYSQL_SNPRINTF(*pos, &qry[*pos], MYSQL_QRY_LEN - *pos, ".");
                val = b3;
                goto continue_decode;
            }

            // check fourth byte
            if (UNLIKELY(!mysql_get_val_func(buf, &b4, sizeof(uint8_t), 1))) {
                return false;
            }

            if (b4 == '\0') {
                T2_DBG("UTF-8: string terminator at fourth byte of four bytes char!");
#if MYSQL_SELECT == 1
                if (print)
#endif
                MYSQL_SNPRINTF(*pos, &qry[*pos], MYSQL_QRY_LEN - *pos, ".");
                break;
            }

            if ((b4 & 0xc0) != 0x80) { // fourth byte must start with 0b10...
                T2_DBG("UTF-8: invalid fourth byte in four byte char (was 0x%" B2T_PRIX8 ")!", b4);
#if MYSQL_SELECT == 1
                if (print)
#endif
                MYSQL_SNPRINTF(*pos, &qry[*pos], MYSQL_QRY_LEN - *pos, ".");
                val = b4;
                goto continue_decode;
            }

            // valid UTF-8 char! -> write it out
#if MYSQL_SELECT == 1
            if (print)
#endif
            MYSQL_SNPRINTF(*pos, &qry[*pos], MYSQL_QRY_LEN - *pos, "%c%c%c%c", val, b2, b3, b4);
        } else { // invalid first byte >= 0xf5
            T2_DBG("UTF-8: invalid first byte (was 0x%" B2T_PRIX8 ")!", val);
#if MYSQL_SELECT == 1
            if (print)
#endif
            MYSQL_SNPRINTF(*pos, &qry[*pos], MYSQL_QRY_LEN - *pos, ".");
        }
    }

    return true;
}


#if MYSQL_SELECT == 1
// Returned value MUST be free'd
static inline bool *mysql_select_load(binary_value_t *bv, const char *filename) {
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
#endif // MYSQL_SELECT == 1

#endif // BLOCK_BUF == 0
