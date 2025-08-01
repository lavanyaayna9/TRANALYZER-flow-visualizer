/*
 * psqlSink.c
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

#include "psqlSink.h"

#if PSQL_SELECT == 1
#include <assert.h>         // for assert
#endif

#include <arpa/inet.h>      // for inet_ntop
#include <inttypes.h>       // for PRIu32, PRIu64, PRIu8, PRIu16, PRId16
#include <libpq-fe.h>       // for PGconn, PQclear, PGresult, PQfinish, PQg...
#include <netinet/in.h>     // for INET6_ADDRSTRLEN, INET_ADDRSTRLEN
#include <stdbool.h>        // for bool, false, true
#include <stdint.h>         // for uint8_t, uint32_t, uint16_t, uint64_t
#include <stdio.h>          // for snprintf
#include <stdlib.h>         // for exit
#include <string.h>         // for size_t, memcpy, strlen
#include <strings.h>        // for strcasecmp
#include <sys/socket.h>     // for AF_INET, AF_INET6
#include <sys/types.h>      // for time_t
#include <time.h>           // for gmtime, strftime


#if BLOCK_BUF == 0

// Static variables

static PGconn *db_conn;
static char * const db_types[] = {
    "text",                     // bt_compound
    "smallint",                 // bt_int_8
    "smallint",                 // bt_int_16
    "integer",                  // bt_int_32
    "bigint",                   // bt_int_64
    "numeric",                  // bt_int_128
    "numeric",                  // bt_int_256
    "smallint",                 // bt_uint_8
    "integer",                  // bt_uint_16
    "bigint",                   // bt_uint_32
    "numeric",                  // bt_uint_64   XXX bigint?
    "numeric",                  // bt_uint_128
    "numeric",                  // bt_uint_256
    //"bit(8)",                   // bt_hex_8
    //"bit(16)",                  // bt_hex_16
    //"bit(32)",                  // bt_hex_32
    //"bit(64)",                  // bt_hex_64
    //"bit(128)",                 // bt_hex_128
    //"bit(256)",                 // bt_hex_256
    "smallint",                 // bt_hex_8
    "integer",                  // bt_hex_16
    "bigint",                   // bt_hex_32
    "numeric",                  // bt_hex_64
    "numeric",                  // bt_hex_128
    "numeric",                  // bt_hex_256
    "real",                     // bt_float
    "double precision",         // bt_double
    "double precision",         // bt_long_double (XXX precision loss)
    "char",                     // bt_char
    "text",                     // bt_string
    "char",                     // bt_flow_direction
    "timestamp with time zone", // bt_timestamp
    "interval",                 // bt_duration
    "macaddr",                  // bt_mac_addr
    "inet",                     // bt_ip4_addr
    "inet",                     // bt_ip6_addr
    "inet",                     // bt_ipx_addr
    "text",                     // bt_string_class
};
#if PSQL_TRANSACTION_NFLOWS > 1
static uint64_t flows_to_commit;
#endif // PSQL_TRANSACTION_NFLOWS > 1

#if PSQL_SELECT == 1
static bool *feature_active;
#endif

static t2_env_t env[ENV_PSQL_N];
#if ENVCNTRL > 0
static uint16_t psqlPort;
static const char *psqlHost;
static const char *psqlUser;
static const char *psqlPass;
static const char *psqlTableName;
#else // ENVCNTRL == 0
static const uint16_t psqlPort = PSQL_PORT;
static const char * const psqlHost = PSQL_HOST;
static const char * const psqlUser = PSQL_USER;
static const char * const psqlPass = PSQL_PASS;
static const char * const psqlTableName = PSQL_TABLE_NAME;
#endif // ENVCNTRL


// Function prototypes

static inline PGconn *db_connect(const char *dbname);
static inline void db_cleanup(PGconn *conn);
static inline PGresult *db_query_res(PGconn *conn, const char *qry);
static inline void db_query(PGconn *conn, const char *qry);
static inline void db_create(PGconn *conn, const char *dbname);
static inline void db_create_flow_table(PGconn *conn, const char *name, binary_value_t *bv);
#if PSQL_OVERWRITE_DB == 1
static inline void db_drop(PGconn *conn, const char *dbname);
#endif // PSQL_OVERWRITE_DB == 1
#if PSQL_OVERWRITE_TABLE == 1
static inline void db_drop_table(PGconn *conn, const char *name);
#endif // PSQL_OVERWRITE_TABLE == 1
static inline bool db_exists(PGconn *conn, const char *dbname);
static inline bool db_table_exists(PGconn *conn, const char *name);
static inline bool psql_get_val_func(outputBuffer_t *buf, void *dest, size_t size, size_t n);
static int psql_parse_sv_type(outputBuffer_t *buf, char *qry, int pos, binary_type_t type
#if PSQL_SELECT == 1
    , bool print
#endif
);
static int psql_parse_sv(outputBuffer_t *buf, char *qry, int pos, binary_subvalue_t *sv
#if PSQL_SELECT == 1
    , bool print
#endif
);
static bool psql_sanitize_utf8(outputBuffer_t *buf, char *qry, int *pos
#if PSQL_SELECT == 1
    , bool print
#endif
);
#if PSQL_SELECT == 1
// Returned value MUST be free'd
static inline bool *psql_select_load(binary_value_t *bv, const char *filename);
#endif


// Defines

// Wrapper for snprintf.
// Increases pos by the number of bytes written
#define PSQL_SNPRINTF(pos, str, size, format, args...) { \
    const int n = snprintf(str, (size), format, ##args); \
    if (UNLIKELY(n >= (size))) { \
        T2_PERR(plugin_name, "query truncated... increase PSQL_QRY_LEN"); \
        db_cleanup(db_conn); \
        exit(EXIT_FAILURE); \
    } \
    pos += n; \
}

#endif // BLOCK_BUF == 0


// Tranalyzer functions

T2_PLUGIN_INIT("psqlSink", "0.9.3", 0, 9);


void t2Init() {
#if BLOCK_BUF == 1
    T2_PWRN(plugin_name, "BLOCK_BUF is set in 'tranalyzer.h', no output will be produced");
#else // BLOCK_BUF == 0

#if TSTAMP_PREC == 1
    T2_PWRN(plugin_name, "timestamps with nanosecond precision not supported (truncated to microsecond precision)");
    T2_PINF(plugin_name, "Run 't2conf tranalyzer2 -D TSTAMP_PREC=0' to silence this warning");
#endif // TSTAMP_PREC == 1

#if ENVCNTRL > 0
    t2_get_env(PLUGIN_SRCH, ENV_PSQL_N, env);
    const char * const dbname = T2_ENV_VAL(PSQL_DBNAME);
    psqlPort = T2_ENV_VAL_UINT(PSQL_PORT);
    psqlHost = T2_ENV_VAL(PSQL_HOST);
    psqlUser = T2_ENV_VAL(PSQL_USER);
    psqlPass = T2_ENV_VAL(PSQL_PASS);
    psqlTableName = T2_ENV_VAL(PSQL_TABLE_NAME);
#else // ENVCNTRL == 0
    const char * const dbname = PSQL_DBNAME;
    T2_SET_ENV_STR(PSQL_SELECT_FILE);
#endif // ENVCNTRL

    // Connect to the DB
    db_conn = db_connect("postgres");

    // Create DB
    bool exists = db_exists(db_conn, dbname);
    if (exists) {
#if PSQL_OVERWRITE_DB == 0
        T2_PERR(plugin_name, "Database '%s' already exists", dbname);
        db_cleanup(db_conn);
        exit(EXIT_FAILURE);
#elif PSQL_OVERWRITE_DB == 1
        db_drop(db_conn, dbname);
        exists = false;
#endif // PSQL_OVERWRITE_DB == 1
    }

    if (!exists) {
        db_create(db_conn, dbname);
    }

    db_cleanup(db_conn);

#if PSQL_SELECT == 1
    feature_active = psql_select_load(main_header_bv, T2_ENV_VAL(PSQL_SELECT_FILE));
#endif

    // Connect to the DB
    db_conn = db_connect(dbname);

    // Create table
    exists = db_table_exists(db_conn, psqlTableName);
    if (exists) {
#if PSQL_OVERWRITE_TABLE == 0
        T2_PERR(plugin_name, "Database '%s' already exists", dbname);
        db_cleanup(db_conn);
        exit(EXIT_FAILURE);
#elif PSQL_OVERWRITE_TABLE == 1
        db_drop_table(db_conn, psqlTableName);
        exists = false;
#else // PSQL_OVERWRITE_TABLE == 2
        // TODO test that schema matches
#endif // PSQL_OVERWRITE_TABLE == 2
    }

    if (!exists) {
        db_create_flow_table(db_conn, psqlTableName, main_header_bv);
    }

    // Begin the transaction
#if PSQL_TRANSACTION_NFLOWS != 1
    db_query(db_conn, "BEGIN");
#endif // PSQL_TRANSACTION_NFLOWS != 1

#endif // BLOCK_BUF == 0
}


// If BLOCK_BUF == 1, the plugin does not produce any output.
// All the code below is therefore not activated.


#if BLOCK_BUF == 0

void t2Finalize() {
    // End the transaction
#if PSQL_TRANSACTION_NFLOWS > 1
    if (flows_to_commit > 0)
#endif // PSQL_TRANSACTION_NFLOWS > 1
        db_query(db_conn, "COMMIT");

    db_cleanup(db_conn);

#if PSQL_SELECT == 1
    free(feature_active);
#endif // PSQL_SELECT == 1

#if ENVCNTRL > 0
    t2_free_env(ENV_PSQL_N, env);
#endif // ENVCNTRL > 0
}


static inline PGconn *db_connect(const char *dbname) {
    char qry[PSQL_QRY_LEN];
    snprintf(qry, sizeof(qry), "host=%s port=%d dbname=%s user=%s password=%s connect_timeout=10 sslmode=disable", psqlHost, psqlPort, dbname, psqlUser, psqlPass);
    PGconn *conn = PQconnectdb(qry);
    if (UNLIKELY(PQstatus(conn) == CONNECTION_BAD)) {
        T2_PERR(plugin_name, "Failed to connect to DB '%s' on '%s' with user '%s'", dbname, psqlHost, psqlUser);
        PQfinish(conn);
        exit(EXIT_FAILURE);
    }
    return conn;
}


static inline void db_cleanup(PGconn *conn) {
    PQfinish(conn);
}


// Returned value must be free'd with PQclear()
static inline PGresult *db_query_res(PGconn *conn, const char *qry) {
    PGresult *res = PQexec(conn, qry);
    if (UNLIKELY(strlen(PQresultErrorMessage(res)))) {
        T2_PERR(plugin_name, "Failed to execute query '%s': %s", qry, PQresultErrorMessage(res));
        PQclear(res);
        db_cleanup(conn);
        exit(EXIT_FAILURE);
    }
    return res;
}


static inline void db_query(PGconn *conn, const char *qry) {
    PGresult *res = db_query_res(conn, qry);
    PQclear(res);
}


static inline void db_create(PGconn *conn, const char *dbname) {
    char qry[PSQL_QRY_LEN];
    snprintf(qry, PSQL_QRY_LEN, "CREATE DATABASE %s;", dbname);
    db_query(conn, qry);
}


static inline void db_create_flow_table(PGconn *conn, const char *name, binary_value_t *bv) {
    char qry[PSQL_QRY_LEN];
#if PSQL_SELECT == 1
    uint32_t feature_id = UINT32_MAX;
#endif
    int pos = snprintf(qry, PSQL_QRY_LEN, "CREATE TABLE %s (id bigserial", name);
    while (bv) {
#if PSQL_SELECT == 1
        feature_id++;
        if (!feature_active[feature_id]) {
            bv = bv->next;
            continue;
        }
#endif
        PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, ", \"%s\"", bv->name);
        char *type, *type2;
        if (bv->num_values > 1) {
            type = "text";
        } else {
            const binary_type_t t = bv->subval[0].type;
            if (t > bt_string_class) {
                T2_PERR(plugin_name, "Unhandled type %u", t);
                db_cleanup(conn);
                exit(EXIT_FAILURE);
            }
            type = db_types[t];
        }
        type2 = bv->is_repeating ? "[]" : "";
        PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, " %s%s", type, type2);
        bv = bv->next;
    }
    PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, ");");
    db_query(conn, qry);
}


#if PSQL_OVERWRITE_DB == 1
static inline void db_drop(PGconn *conn, const char *dbname) {
    char qry[PSQL_QRY_LEN];
    snprintf(qry, PSQL_QRY_LEN, "DROP DATABASE %s;", dbname);
    db_query(conn, qry);
}
#endif // PSQL_OVERWRITE_DB == 1


#if PSQL_OVERWRITE_TABLE == 1
static inline void db_drop_table(PGconn *conn, const char *name) {
    char qry[PSQL_QRY_LEN];
    snprintf(qry, PSQL_QRY_LEN, "DROP TABLE %s;", name);
    db_query(conn, qry);
}
#endif // PSQL_OVERWRITE_TABLE == 1


static inline bool db_exists(PGconn *conn, const char *dbname) {
    PGresult *res = db_query_res(conn, "SELECT datname FROM pg_database;");
    if (UNLIKELY(!res)) {
        db_cleanup(conn);
        exit(EXIT_FAILURE);
    }

    bool exists = false;
    const int num_rows = PQntuples(res);
    for (int_fast32_t i = 0; i < num_rows; i++) {
        if (strcasecmp(PQgetvalue(res, i, 0), dbname) == 0) {
            exists = true;
            break;
        }
    }

    PQclear(res);
    return exists;
}


static inline bool db_table_exists(PGconn *conn, const char *name) {
    PGresult *res = db_query_res(conn, "SELECT tablename FROM pg_tables WHERE schemaname = 'public';");
    if (UNLIKELY(!res)) {
        db_cleanup(conn);
        exit(EXIT_FAILURE);
    }

    bool exists = false;
    const int num_rows = PQntuples(res);
    for (int_fast32_t i = 0; i < num_rows; i++) {
        if (strcasecmp(PQgetvalue(res, i, 0), name) == 0) {
            exists = true;
            break;
        }
    }

    PQclear(res);
    return exists;
}


static inline bool psql_get_val_func(outputBuffer_t *buf, void *dest, size_t size, size_t n) {
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


static int psql_parse_sv_type(outputBuffer_t *buf, char *qry, int pos, binary_type_t type
#if PSQL_SELECT == 1
    , bool print
#endif
) {
    switch (type) {
        case bt_int_8: {
            int8_t val;
            if (UNLIKELY(!psql_get_val_func(buf, &val, sizeof(val), 1))) {
                exit(EXIT_FAILURE);
            }
#if PSQL_SELECT == 1
            if (!print) break;
#endif
            PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, "%" PRId8, val);
            break;
        }

        case bt_int_16: {
            int16_t val;
            if (UNLIKELY(!psql_get_val_func(buf, &val, sizeof(val), 1))) {
                exit(EXIT_FAILURE);
            }
#if PSQL_SELECT == 1
            if (!print) break;
#endif
            PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, "%" PRId16, val);
            break;
        }

        case bt_int_32: {
            int32_t val;
            if (UNLIKELY(!psql_get_val_func(buf, &val, sizeof(val), 1))) {
                exit(EXIT_FAILURE);
            }
#if PSQL_SELECT == 1
            if (!print) break;
#endif
            PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, "%" PRId32, val);
            break;
        }

        case bt_int_64: {
            int64_t val;
            if (UNLIKELY(!psql_get_val_func(buf, &val, sizeof(val), 1))) {
                exit(EXIT_FAILURE);
            }
#if PSQL_SELECT == 1
            if (!print) break;
#endif
            PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, "%" PRId64, val);
            break;
        }

        //case bt_int_128:
        //case bt_int_256:

        case bt_uint_8: {
            uint8_t val;
            if (UNLIKELY(!psql_get_val_func(buf, &val, sizeof(val), 1))) {
                exit(EXIT_FAILURE);
            }
#if PSQL_SELECT == 1
            if (!print) break;
#endif
            PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, "%" PRIu8, val);
            break;
        }

        case bt_uint_16: {
            uint16_t val;
            if (UNLIKELY(!psql_get_val_func(buf, &val, sizeof(val), 1))) {
                exit(EXIT_FAILURE);
            }
#if PSQL_SELECT == 1
            if (!print) break;
#endif
            PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, "%" PRIu16, val);
            break;
        }

        case bt_uint_32: {
            uint32_t val;
            if (UNLIKELY(!psql_get_val_func(buf, &val, sizeof(val), 1))) {
                exit(EXIT_FAILURE);
            }
#if PSQL_SELECT == 1
            if (!print) break;
#endif
            PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, "%" PRIu32, val);
            break;
        }

        case bt_uint_64: {
            uint64_t val;
            if (UNLIKELY(!psql_get_val_func(buf, &val, sizeof(val), 1))) {
                exit(EXIT_FAILURE);
            }
#if PSQL_SELECT == 1
            if (!print) break;
#endif
            PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, "%" PRIu64, val);
            break;
        }

        //case bt_uint_128:
        //case bt_uint_256:

        case bt_hex_8: {
            uint8_t val;
            if (UNLIKELY(!psql_get_val_func(buf, &val, sizeof(val), 1))) {
                exit(EXIT_FAILURE);
            }
#if PSQL_SELECT == 1
            if (!print) break;
#endif
            PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, "%" PRIu8, val);
            break;
        }

        case bt_hex_16: {
            uint16_t val;
            if (UNLIKELY(!psql_get_val_func(buf, &val, sizeof(val), 1))) {
                exit(EXIT_FAILURE);
            }
#if PSQL_SELECT == 1
            if (!print) break;
#endif
            PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, "%" PRIu16, val);
            break;
        }

        case bt_hex_32: {
            uint32_t val;
            if (UNLIKELY(!psql_get_val_func(buf, &val, sizeof(val), 1))) {
                exit(EXIT_FAILURE);
            }
#if PSQL_SELECT == 1
            if (!print) break;
#endif
            PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, "%" PRIu32, val);
            break;
        }

        case bt_hex_64: {
            uint64_t val;
            if (UNLIKELY(!psql_get_val_func(buf, &val, sizeof(val), 1))) {
                exit(EXIT_FAILURE);
            }
#if PSQL_SELECT == 1
            if (!print) break;
#endif
            PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, "%" PRIu64, val);
            break;
        }

        //case bt_hex_128:
        //case bt_hex_256:

        case bt_float: {
            float val;
            if (UNLIKELY(!psql_get_val_func(buf, &val, sizeof(val), 1))) {
                exit(EXIT_FAILURE);
            }
#if PSQL_SELECT == 1
            if (!print) break;
#endif
            PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, "%f", val);
            break;
        }

        case bt_double: {
            double val;
            if (UNLIKELY(!psql_get_val_func(buf, &val, sizeof(val), 1))) {
                exit(EXIT_FAILURE);
            }
#if PSQL_SELECT == 1
            if (!print) break;
#endif
            PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, "%f", val);
            break;
        }

        case bt_long_double: {
            long double val;
            if (UNLIKELY(!psql_get_val_func(buf, &val, sizeof(val), 1))) {
                exit(EXIT_FAILURE);
            }
#if PSQL_SELECT == 1
            if (!print) break;
#endif
            PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, "%Lf", val);
            break;
        }

        case bt_char: {
            uint8_t val;
            if (UNLIKELY(!psql_get_val_func(buf, &val, sizeof(val), 1))) {
                exit(EXIT_FAILURE);
            }
#if PSQL_SELECT == 1
            if (!print) break;
#endif
            PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, "%c", val);
            break;
        }

        case bt_string_class:
        case bt_string: {
            if (UNLIKELY(!psql_sanitize_utf8(buf, qry, &pos
#if PSQL_SELECT == 1
                , print
#endif
            ))) {
                exit(EXIT_FAILURE);
            }
            break;
        }

        case bt_flow_direction: {
            uint8_t val;
            if (UNLIKELY(!psql_get_val_func(buf, &val, sizeof(val), 1))) {
                exit(EXIT_FAILURE);
            }
#if PSQL_SELECT == 1
            if (!print) break;
#endif
            PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, "%c", (val == 0) ? FLOW_DIR_C_A : FLOW_DIR_C_B);
            break;
        }

        case bt_timestamp:
        case bt_duration: {
            // read seconds
            uint64_t val;
            if (UNLIKELY(!psql_get_val_func(buf, &val, sizeof(val), 1))) {
                exit(EXIT_FAILURE);
            }

            // read nanoseconds
            uint32_t ns;
            if (UNLIKELY(!psql_get_val_func(buf, &ns, sizeof(ns), 1))) {
                exit(EXIT_FAILURE);
            }

#if PSQL_SELECT == 1
            if (!print) break;
#endif

#if TSTAMP_PREC == 0
            ns /= 1000;
#endif // TSTAMP_PREC == 0

            if (type == bt_duration) {
                PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, "%" PRIu64 ".%" B2T_TPFRMT, val, ns);
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
                PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, "%s.%" B2T_TPFRMT, timeBuf, ns); // micro/nano-seconds
#if TSTAMP_UTC == 1 && defined(__APPLE__)
                PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, "+0000");
#else // TSTAMP_UTC == 0 || !defined(__APPLE__)
                strftime(timeBuf, sizeof(timeBuf), "%z", t); // time offset
                PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, "%s", timeBuf);
#endif // TSTAMP_UTC == 0 || !defined(__APPLE__)
            }
            break;
        }

        case bt_mac_addr: {
            uint8_t val[l_bt_mac_addr];
            if (UNLIKELY(!psql_get_val_func(buf, &val, l_bt_mac_addr * sizeof(uint8_t), 1))) {
                exit(EXIT_FAILURE);
            }
#if PSQL_SELECT == 1
            if (!print) break;
#endif
            // TODO use t2_mac_to_str
            PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos,
                    "%02" B2T_PRIX8 "%s%02" B2T_PRIX8 "%s%02" B2T_PRIX8 "%s"
                    "%02" B2T_PRIX8 "%s%02" B2T_PRIX8 "%s%02" B2T_PRIX8,
                    val[0], MAC_SEP, val[1], MAC_SEP, val[2], MAC_SEP,
                    val[3], MAC_SEP, val[4], MAC_SEP, val[5]);
            break;
        }

        case bt_ip4_addr: {
psql_bt_ip4:;
            uint8_t val[l_bt_ip4_addr];
            if (UNLIKELY(!psql_get_val_func(buf, &val, l_bt_ip4_addr * sizeof(uint8_t), 1))) {
                exit(EXIT_FAILURE);
            }
#if PSQL_SELECT == 1
            if (!print) break;
#endif
            char addr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, val, addr, INET_ADDRSTRLEN);
            PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, "%s", addr);
            break;
        }

        case bt_ip6_addr: {
psql_bt_ip6:;
            uint8_t val[l_bt_ip6_addr];
            if (UNLIKELY(!psql_get_val_func(buf, &val, l_bt_ip6_addr * sizeof(uint8_t), 1))) {
                exit(EXIT_FAILURE);
            }
#if PSQL_SELECT == 1
            if (!print) break;
#endif
            char addr[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, val, addr, INET6_ADDRSTRLEN);
            PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, "%s", addr);
            break;
        }

        case bt_ipx_addr: {
            uint8_t version;
            if (UNLIKELY(!psql_get_val_func(buf, &version, sizeof(version), 1))) {
                exit(EXIT_FAILURE);
            }
            if (version == 4) {
                goto psql_bt_ip4;
            } else if (version == 6) {
                goto psql_bt_ip6;
            } else if (version == 0) {
#if PSQL_SELECT == 1
                if (!print) break;
#endif
#if IPV6_ACTIVATE == 1
                PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, "%s", "::");
#else
                PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, "%s", "0.0.0.0");
#endif
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


static int psql_parse_sv(outputBuffer_t *buf, char *qry, int pos, binary_subvalue_t *sv
#if PSQL_SELECT == 1
        , bool print
#endif
) {
    if (sv->type) {
        return psql_parse_sv_type(buf, qry, pos, sv->type
#if PSQL_SELECT == 1
            , print
#endif
        );
    }

#if PSQL_SELECT == 1
    if (print)
#endif
    PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, "(");
    uint32_t nr = 1;
    if (sv->is_repeating) {
        if (UNLIKELY(!psql_get_val_func(buf, &nr, sizeof(nr), 1))) {
            exit(EXIT_FAILURE);
        }
    }
    const uint_fast32_t nv = sv->num_values;
    for (uint_fast32_t i = 0; i < nr; i++) {
        for (uint_fast32_t j = 0; j < nv; j++) {
            pos = psql_parse_sv(buf, qry, pos, &sv->subval[j]
#if PSQL_SELECT == 1
            , print
#endif
            );
            // write value delim
#if PSQL_SELECT == 1
            if (print)
#endif
            if (j < nv - 1) {
                PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, "_");
            }
        }

        // write repeat delim
#if PSQL_SELECT == 1
        if (print)
#endif
        if (i < nr - 1) {
            PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, ";");
        }
    }

#if PSQL_SELECT == 1
    if (print)
#endif
    PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, ")");

    return pos;
}


void t2BufferToSink(outputBuffer_t *buf, binary_value_t *bv) {
    const uint32_t bufpos = buf->pos;
    buf->pos = 0;
    char qry[PSQL_QRY_LEN];
    int pos = snprintf(qry, PSQL_QRY_LEN, "INSERT INTO %s VALUES (nextval('%s_id_seq')", psqlTableName, psqlTableName);
#if PSQL_SELECT == 1
    uint32_t feature_id = UINT32_MAX;
#endif

    while (bv) {
#if PSQL_SELECT == 1
        feature_id++;
        const bool print = feature_active[feature_id];
        if (print)
#endif
        PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, ", '");
        uint32_t nr = 1;
        if (bv->is_repeating) {
            if (UNLIKELY(!psql_get_val_func(buf, &nr, sizeof(nr), 1))) {
                exit(EXIT_FAILURE);
            }
#if PSQL_SELECT == 1
            if (print)
#endif
            PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, "{%s", (nr > 0) ? "\"" : "");
        }

        const uint_fast32_t nv = bv->num_values;
        for (uint_fast32_t i = 0; i < nr; i++) {
            for (uint_fast32_t j = 0; j < nv; j++) {
                pos = psql_parse_sv(buf, qry, pos, &bv->subval[j]
#if PSQL_SELECT == 1
                    , print
#endif
                );
#if PSQL_SELECT == 1
                if (print)
#endif
                if (j < nv - 1) {
                    PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, "_");
                }
            }

#if PSQL_SELECT == 1
            if (print)
#endif
            if (i < nr - 1) {
                PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, (bv->is_repeating) ? "\", \"" : ";");
            }
        }

        if (bv->is_repeating) {
#if PSQL_SELECT == 1
            if (print)
#endif
            PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, "%s}'", (nr > 0) ? "\"" : "");
        } else {
#if PSQL_SELECT == 1
            if (print)
#endif
            PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, "'");
        }

        bv = bv->next;
    }

    PSQL_SNPRINTF(pos, &qry[pos], PSQL_QRY_LEN - pos, ");");

    db_query(db_conn, qry);
    buf->pos = bufpos;

#if PSQL_TRANSACTION_NFLOWS > 1
    if (++flows_to_commit == PSQL_TRANSACTION_NFLOWS) {
        db_query(db_conn, "COMMIT;");
        db_query(db_conn, "BEGIN;");
        flows_to_commit = 0;
    }
#endif // PSQL_TRANSACTION_NFLOWS > 1
}


/*
 * Skip invalid multi-bytes UTF-8 chars
 * Returns true on successful UTF-8 sanitization, false on error
 */
static bool psql_sanitize_utf8(outputBuffer_t *buf, char *qry, int *pos
#if PSQL_SELECT == 1
    , bool print
#endif
) {
    uint8_t val, b2, b3, b4; // variables for multi-bytes characters

    while (1) {
        if (UNLIKELY(!psql_get_val_func(buf, &val, sizeof(val), 1))) {
            return false;
        }

continue_decode:
        if (val == '\0') {
            break;
        }

        if (val < 0x80) { // single byte char
#if PSQL_SELECT == 1
            if (print)
#endif
            switch (val) {
                case '\b':  // backsapce
                    PSQL_SNPRINTF(*pos, &qry[*pos], PSQL_QRY_LEN - *pos, "\\b");
                    break;
                case '\f':  // form feed
                    PSQL_SNPRINTF(*pos, &qry[*pos], PSQL_QRY_LEN - *pos, "\\f");
                    break;
                case '\n':  // line feed
                    PSQL_SNPRINTF(*pos, &qry[*pos], PSQL_QRY_LEN - *pos, "\\n");
                    break;
                case '\r':  // carriage return
                    PSQL_SNPRINTF(*pos, &qry[*pos], PSQL_QRY_LEN - *pos, "\\r");
                    break;
                case '\t':  // horizontal tab
                    PSQL_SNPRINTF(*pos, &qry[*pos], PSQL_QRY_LEN - *pos, "\\t");
                    break;
                case '\v':  // vertical tab
                    PSQL_SNPRINTF(*pos, &qry[*pos], PSQL_QRY_LEN - *pos, "\\v");
                    break;
                case '\\':  // backslash
                case '"':   // double quote
                    PSQL_SNPRINTF(*pos, &qry[*pos], PSQL_QRY_LEN - *pos, "\\%c", val);
                    break;
                case '\'':  // single quote
                    PSQL_SNPRINTF(*pos, &qry[*pos], PSQL_QRY_LEN - *pos, "''");
                    break;
                default:
                    // In order to be valid JSON, control characters in 0x00-0x1f
                    // must be escaped (see: https://tools.ietf.org/html/rfc7159#page-8)
                    // Most parsers also want the DEL (0x7f) escaped even though not in RFC
                    if (val <= 0x1f || val == 0x7f) {
                        PSQL_SNPRINTF(*pos, &qry[*pos], PSQL_QRY_LEN - *pos, "\\\\u00%02X", val);
                    } else {
                        PSQL_SNPRINTF(*pos, &qry[*pos], PSQL_QRY_LEN - *pos, "%c", val);
                    }
                    break;
            }
        } else if (val < 0xc2) { // 0xc0 and 0xc1 are invalid first byte (overlong sequence)
            T2_DBG("UTF-8: Overlong sequence!");
#if PSQL_SELECT == 1
            if (print)
#endif
            PSQL_SNPRINTF(*pos, &qry[*pos], PSQL_QRY_LEN - *pos, ".");
        } else if (val < 0xe0) { // 2 bytes char
            if (UNLIKELY(!psql_get_val_func(buf, &b2, sizeof(uint8_t), 1))) {
                return false;
            }

            if (b2 == '\0') {
                T2_DBG("UTF-8: string terminator at second byte of two bytes char!");
#if PSQL_SELECT == 1
                if (print)
#endif
                PSQL_SNPRINTF(*pos, &qry[*pos], PSQL_QRY_LEN - *pos, ".");
                break;
            }

            if ((b2 & 0xc0) != 0x80) { // second byte must start with 0b10...
                T2_DBG("UTF-8: invalid second byte in two byte char (was 0x%" B2T_PRIX8 ")!", b2);
#if PSQL_SELECT == 1
                if (print)
#endif
                PSQL_SNPRINTF(*pos, &qry[*pos], PSQL_QRY_LEN - *pos, ".");
                val = b2;
                goto continue_decode;
            }

            // valid UTF-8 char! -> write it out
#if PSQL_SELECT == 1
            if (print)
#endif
            PSQL_SNPRINTF(*pos, &qry[*pos], PSQL_QRY_LEN - *pos, "%c%c", val, b2);
        } else if (val < 0xf0) { // 3 bytes char
            if (UNLIKELY(!psql_get_val_func(buf, &b2, sizeof(uint8_t), 1))) {
                return false;
            }

            if (b2 == '\0') {
                T2_DBG("UTF-8: string terminator at second byte of two bytes char!");
#if PSQL_SELECT == 1
                if (print)
#endif
                PSQL_SNPRINTF(*pos, &qry[*pos], PSQL_QRY_LEN - *pos, ".");
                break;
            }

            if ((b2 & 0xc0) != 0x80) { // second byte must start with 0b10...
                T2_DBG("UTF-8: invalid second byte in three byte char (was 0x%" B2T_PRIX8 ")!", b2);
#if PSQL_SELECT == 1
                if (print)
#endif
                PSQL_SNPRINTF(*pos, &qry[*pos], PSQL_QRY_LEN - *pos, ".");
                val = b2;
                goto continue_decode;
            }

            if (val == 0xe0 && b2 < 0xa0) { // invalid overlong
                T2_DBG("UTF-8: Overlong three byte sequence!");
#if PSQL_SELECT == 1
                if (print)
#endif
                PSQL_SNPRINTF(*pos, &qry[*pos], PSQL_QRY_LEN - *pos, ".");
                continue;
            }

            // check third byte
            if (UNLIKELY(!psql_get_val_func(buf, &b3, sizeof(uint8_t), 1))) {
                return false;
            }

            if (b3 == '\0') {
                T2_DBG("UTF-8: string terminator at third byte of three bytes char!");
#if PSQL_SELECT == 1
                if (print)
#endif
                PSQL_SNPRINTF(*pos, &qry[*pos], PSQL_QRY_LEN - *pos, ".");
                break;
            }

            if ((b3 & 0xc0) != 0x80) { // third byte must start with 0b10...
                T2_DBG("UTF-8: invalid third byte in three byte char (was 0x%" B2T_PRIX8 ")!", b3);
#if PSQL_SELECT == 1
                if (print)
#endif
                PSQL_SNPRINTF(*pos, &qry[*pos], PSQL_QRY_LEN - *pos, ".");
                val = b3;
                goto continue_decode;
            }

            // check that code point is not in the surrogate range
            uint16_t tmp = ((uint16_t) (val & 0x0f) << 12) |
                           ((uint16_t) (b2  & 0x3f) <<  6) |
                                       (b3  & 0x3f);
            if (tmp >= 0xd800 && tmp <= 0xdfff) {
                T2_DBG("UTF-8: code point is in the surrogate range!");
#if PSQL_SELECT == 1
                if (print)
#endif
                PSQL_SNPRINTF(*pos, &qry[*pos], PSQL_QRY_LEN - *pos, ".");
                continue;
            }

            // valid UTF-8 char! -> write it out
#if PSQL_SELECT == 1
            if (print)
#endif
            PSQL_SNPRINTF(*pos, &qry[*pos], PSQL_QRY_LEN - *pos, "%c%c%c", val, b2, b3);
        } else if (val < 0xf5) { // 4 bytes char
            if (UNLIKELY(!psql_get_val_func(buf, &b2, sizeof(uint8_t), 1))) {
                return false;
            }

            if (b2 == '\0') {
                T2_DBG("UTF-8: string terminator at second byte of four bytes char!");
#if PSQL_SELECT == 1
                if (print)
#endif
                PSQL_SNPRINTF(*pos, &qry[*pos], PSQL_QRY_LEN - *pos, ".");
                break;
            }

            if ((b2 & 0xc0) != 0x80) {
                T2_DBG("UTF-8: invalid second byte in four byte char (was 0x%" B2T_PRIX8 ")!", b2);
#if PSQL_SELECT == 1
                if (print)
#endif
                PSQL_SNPRINTF(*pos, &qry[*pos], PSQL_QRY_LEN - *pos, "."); // second byte must start with 0b10...
                val = b2;
                goto continue_decode;
            }

            if (val == 0xf0 && b2 < 0x90) { // invalid overlong
                T2_DBG("UTF-8: Overlong four byte sequence!\n");
#if PSQL_SELECT == 1
                if (print)
#endif
                PSQL_SNPRINTF(*pos, &qry[*pos], PSQL_QRY_LEN - *pos, ".");
                continue;
            }

            if (val == 0xf4 && b2 >= 0x90) { // code point > U+10FFFF
                T2_DBG("UTF-8: Code point > U+10FFFF!");
#if PSQL_SELECT == 1
                if (print)
#endif
                PSQL_SNPRINTF(*pos, &qry[*pos], PSQL_QRY_LEN - *pos, ".");
                continue;
            }

            // check third byte
            if (UNLIKELY(!psql_get_val_func(buf, &b3, sizeof(uint8_t), 1))) {
                return false;
            }

            if (b3 == '\0') {
                T2_DBG("UTF-8: string terminator at third byte of four bytes char!");
#if PSQL_SELECT == 1
                if (print)
#endif
                PSQL_SNPRINTF(*pos, &qry[*pos], PSQL_QRY_LEN - *pos, ".");
                break;
            }

            if ((b3 & 0xc0) != 0x80) {  // third byte must start with 0b10...
                T2_DBG("UTF-8: invalid third byte in four byte char (was 0x%" B2T_PRIX8 ")!", b3);
#if PSQL_SELECT == 1
                if (print)
#endif
                PSQL_SNPRINTF(*pos, &qry[*pos], PSQL_QRY_LEN - *pos, ".");
                val = b3;
                goto continue_decode;
            }

            // check fourth byte
            if (UNLIKELY(!psql_get_val_func(buf, &b4, sizeof(uint8_t), 1))) {
                return false;
            }

            if (b4 == '\0') {
                T2_DBG("UTF-8: string terminator at fourth byte of four bytes char!");
#if PSQL_SELECT == 1
                if (print)
#endif
                PSQL_SNPRINTF(*pos, &qry[*pos], PSQL_QRY_LEN - *pos, ".");
                break;
            }

            if ((b4 & 0xc0) != 0x80) { // fourth byte must start with 0b10...
                T2_DBG("UTF-8: invalid fourth byte in four byte char (was 0x%" B2T_PRIX8 ")!", b4);
#if PSQL_SELECT == 1
                if (print)
#endif
                PSQL_SNPRINTF(*pos, &qry[*pos], PSQL_QRY_LEN - *pos, ".");
                val = b4;
                goto continue_decode;
            }

            // valid UTF-8 char! -> write it out
#if PSQL_SELECT == 1
            if (print)
#endif
            PSQL_SNPRINTF(*pos, &qry[*pos], PSQL_QRY_LEN - *pos, "%c%c%c%c", val, b2, b3, b4);
        } else { // invalid first byte >= 0xf5
            T2_DBG("UTF-8: invalid first byte (was 0x%" B2T_PRIX8 ")!", val);
#if PSQL_SELECT == 1
            if (print)
#endif
            PSQL_SNPRINTF(*pos, &qry[*pos], PSQL_QRY_LEN - *pos, ".");
        }
    }

    return true;
}


#if PSQL_SELECT == 1
// Returned value MUST be free'd
static inline bool *psql_select_load(binary_value_t *bv, const char *filename) {
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
#endif // PSQL_SELECT == 1

#endif // BLOCK_BUF == 0
