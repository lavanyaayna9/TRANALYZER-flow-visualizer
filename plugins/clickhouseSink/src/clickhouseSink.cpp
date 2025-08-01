/*
 * clickhouseSink.cpp
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

#include "clickhouseSink.hpp"

#include <clickhouse/client.h>
#include <iostream>
#include <string_view>

#include "t2Plugin.h"   // for T2_PLUGIN_INIT, main_header_bv, ...

#ifdef __APPLE__
#include <MacTypes.h>

typedef Float32 _Float32;
typedef Float64 _Float64;
#endif


using namespace clickhouse;


/*
 * Static variables
 */

#if BLOCK_BUF == 0
static Block block;

#if ENVCNTRL > 0
static t2_env_t env[ENV_CLICKHOUSE_N];
static uint16_t clkPort;
static const char *clkHost;
static const char *clkUser;
static const char *clkPass;
static const char *clkDbName;
static const char *clkTableName;
#else // ENVCNTRL == 0
static const char * const clkHost = CLICKHOUSE_HOST;
static const uint16_t clkPort = CLICKHOUSE_DBPORT;
static const char * const clkUser = CLICKHOUSE_USER;
static const char * const clkPass = CLICKHOUSE_PASSWORD;
static const char * const clkDbName = CLICKHOUSE_DBNAME;
static const char * const clkTableName = CLICKHOUSE_TABLE_NAME;
#endif // ENVCNTRL
#endif // BLOCK_BUF == 0


/*
 * Function prototypes
 */

#if BLOCK_BUF == 0
static inline Client newClickHouseClient();
static inline ColumnRef t2Type2ColumnRef(binary_type_t type);
static inline ColumnRef subvalueToColumn(const binary_subvalue_t * const bsv, uint32_t size, bool isArray);
static inline Block generateColumnScheme(const binary_value_t *bv);
template <typename Tt, typename Tc> static inline void appendToColumn(ColumnRef col, outputBuffer_t* buf);
static inline void appendToStringColumn(ColumnRef col, outputBuffer_t* buf);
static inline void appendToFixedStringColumn(ColumnRef col, outputBuffer_t* buf, uint32_t size);
static inline void appendToIpV6Column(ColumnRef col, outputBuffer_t* buf);
static inline void appendIpV4ToIpV6Column(ColumnRef col, outputBuffer_t* buf);
static inline void appendToTimestampColumn(ColumnRef col, outputBuffer_t* buf);
static inline void appendArray(ColumnRef col, const binary_subvalue_t * const bsv, uint32_t size, outputBuffer_t* buf);
static inline void appendData(ColumnRef col, binary_type_t dataType, outputBuffer_t* buf);
static inline void appendData(ColumnRef col, const binary_subvalue_t * const bsv, u_int32_t size, bool isArray, outputBuffer_t* buf);
static inline void insertBlock(const Block block);

static void createDatabase(Client &client);
static void createTable(Client &client, const binary_value_t *bv);
#endif // BLOCK_BUF == 0


// Tranalyzer functions

T2_PLUGIN_INIT("clickhouseSink", "0.9.3", 0, 9);


T2_API void t2Init() {
#if BLOCK_BUF == 1
    T2_PWRN(plugin_name, "BLOCK_BUF is set in 'tranalyzer.h', no output will be produced");
#else // BLOCK_BUF == 0

#if ENVCNTRL > 0
    t2_get_env(PLUGIN_SRCH, ENV_CLICKHOUSE_N, env);
    clkHost = T2_ENV_VAL(CLICKHOUSE_HOST);
    clkPort = T2_ENV_VAL_UINT(CLICKHOUSE_DBPORT);
    clkUser = T2_ENV_VAL(CLICKHOUSE_USER);
    clkPass = T2_ENV_VAL(CLICKHOUSE_PASSWORD);
    clkDbName = T2_ENV_VAL(CLICKHOUSE_DBNAME);
    clkTableName = T2_ENV_VAL(CLICKHOUSE_TABLE_NAME);
#endif // ENVCNTRL > 0

    try {
        Client client = newClickHouseClient();
        createDatabase(client);
        createTable(client, main_header_bv);
    } catch (const std::exception& e) {
        T2_PFATAL(plugin_name, "%s", e.what());
    }
#endif // BLOCK_BUF == 0
}


// If BLOCK_BUF == 1, the plugin does not produce any output.
// All the code below is therefore not activated.


#if BLOCK_BUF == 0

T2_API void t2BufferToSink(outputBuffer_t *buf, binary_value_t *bv) {
    // parse the buffer and dump it somewhere...
    binary_value_t *bvp = bv;
    buf->pos = 0;
    for (uint_fast32_t i = 0; bvp != nullptr; i++, bvp = bvp->next) {
        appendData(block[i], bvp->subval, bvp->num_values, bvp->is_repeating, buf);
    }

#if CLICKHOUSE_TRANSACTION_NFLOWS > 0
    if (block.RefreshRowCount() >= CLICKHOUSE_TRANSACTION_NFLOWS) {
        insertBlock(block);
        block = generateColumnScheme(bv);
    }
#endif // CLICKHOUSE_TRANSACTION_NFLOWS > 0
}


T2_API void t2Finalize() {
    insertBlock(block);

#if ENVCNTRL > 0
    t2_free_env(ENV_CLICKHOUSE_N, env);
#endif // ENVCNTRL > 0
}


static inline Client newClickHouseClient() {
    static const ClientOptions options = ClientOptions()
            .SetHost(clkHost)
            .SetPort(clkPort)
            .SetUser(clkUser)
            .SetPassword(clkPass);
    return Client(options);
}


static inline ColumnRef t2Type2ColumnRef(binary_type_t type) {
    switch (type) {

        case bt_compound:
            break;

        /* bt_int_* */

        case bt_int_8:
            return std::make_shared<ColumnInt8>();
        case bt_int_16:
            return std::make_shared<ColumnInt16>();
        case bt_int_32:
            return std::make_shared<ColumnInt32>();
        case bt_int_64:
            return std::make_shared<ColumnInt64>();
        case bt_int_128:
            return std::make_shared<ColumnInt64>(); // FIXME
        case bt_int_256:
            return std::make_shared<ColumnInt64>(); // FIXME

        /* bt_uint_* */

        case bt_uint_8:
            return std::make_shared<ColumnUInt8>();
        case bt_uint_16:
            return std::make_shared<ColumnUInt16>();
        case bt_uint_32:
            return std::make_shared<ColumnUInt32>();
        case bt_uint_64:
            return std::make_shared<ColumnUInt64>();
        case bt_uint_128:
            return std::make_shared<ColumnUInt64>(); // FIXME
        case bt_uint_256:
            return std::make_shared<ColumnUInt64>(); // FIXME

        /* bt_hex_* */

        case bt_hex_8:
            return std::make_shared<ColumnUInt8>();
        case bt_hex_16:
            return std::make_shared<ColumnUInt16>();
        case bt_hex_32:
            return std::make_shared<ColumnUInt32>();
        case bt_hex_64:
            return std::make_shared<ColumnUInt64>();
        case bt_hex_128:
            return std::make_shared<ColumnTuple>(
                    std::vector<ColumnRef>({
                            std::make_shared<ColumnUInt64>(),
                            std::make_shared<ColumnUInt64>()
                    })
            );
        case bt_hex_256:
            return std::make_shared<ColumnTuple>(
                    std::vector<ColumnRef>({
                            std::make_shared<ColumnUInt64>(),
                            std::make_shared<ColumnUInt64>(),
                            std::make_shared<ColumnUInt64>(),
                            std::make_shared<ColumnUInt64>()
                    })
            );

        /* float/double */

        case bt_float:
            return std::make_shared<ColumnFloat32>();
        case bt_double:
            return std::make_shared<ColumnFloat64>();
        case bt_long_double:
            return std::make_shared<ColumnFloat64>();

        /* char/string */

        case bt_char:
            return std::make_shared<ColumnFixedString>(1);
        case bt_flow_direction:
            return std::make_shared<ColumnFixedString>(1);
        case bt_string:
            return std::make_shared<ColumnString>();
        case bt_string_class:
            return std::make_shared<ColumnString>();

        /* Time */

        case bt_timestamp:
            return std::make_shared<ColumnDateTime64>(6 + TSTAMP_PREC * 3);
        case bt_duration:
            return std::make_shared<ColumnDateTime64>(6 + TSTAMP_PREC * 3);

        /* MAC/IP addresses */

        case bt_mac_addr:
            return std::make_shared<ColumnFixedString>(6);
        case bt_ip4_addr:
            return std::make_shared<ColumnIPv4>();
        case bt_ip6_addr:
            return std::make_shared<ColumnIPv6>();
        case bt_ipx_addr:
            return std::make_shared<ColumnTuple>(
                    std::vector<ColumnRef>({
                            std::make_shared<ColumnUInt8>(),
                            std::make_shared<ColumnIPv6>()
                    })
            );

        default:
            return nullptr;
    }

    return nullptr;
}


static inline ColumnRef subvalueToColumn(const binary_subvalue_t * const bsv, uint32_t size, bool isArray) {
    ColumnRef col;
    if (size > 1) {
        std::vector<ColumnRef> tupleMembers;
        for (uint_fast32_t i = 0; i < size; i++) {
            tupleMembers.push_back(subvalueToColumn(&bsv[i], bsv[i].num_values, bsv[i].is_repeating));
        }
        col = std::make_shared<ColumnTuple>(tupleMembers);
    } else if (bsv->type == bt_compound) {
        col = subvalueToColumn(bsv->subval, bsv->num_values, bsv->is_repeating);
    } else {
        col = t2Type2ColumnRef(binary_type_t(bsv->type));
    }

    if (isArray) {
        return std::make_shared<ColumnArray>(col);
    } else {
        return col;
    }
}


static inline Block generateColumnScheme(const binary_value_t *bv) {
    if (UNLIKELY(bv == nullptr)) {
        T2_PFATAL(plugin_name, "binary subvalue invalid");
    }

    Block block;
    while (bv) {
        block.AppendColumn(bv->name, subvalueToColumn(bv->subval, bv->num_values, bv->is_repeating));
        bv = bv->next;
    }

    return block;
}


template <typename Tt, typename Tc> static inline void appendToColumn(ColumnRef col, outputBuffer_t* buf) {
    Tt data;
    memcpy(&data, buf->buffer + buf->pos, sizeof(Tt));
    buf->pos += sizeof(Tt);
    std::static_pointer_cast<Tc>(col)->Append(data);
}


static inline void appendToStringColumn(ColumnRef col, outputBuffer_t* buf) {
    std::string_view text(buf->buffer + buf->pos);
    std::static_pointer_cast<ColumnString>(col)->Append(text);
    buf->pos += text.length() + 1; // Add one for 0 termination
}


static inline void appendToFixedStringColumn(ColumnRef col, outputBuffer_t* buf, uint32_t size) {
    std::static_pointer_cast<ColumnFixedString>(col)->Append(
            std::basic_string_view<char>(buf->buffer + buf->pos, size)
    );
    buf->pos += size;
}


static inline void appendToIpV6Column(ColumnRef col, outputBuffer_t* buf) {
    unsigned char base[16];
    memcpy(base, buf->buffer + buf->pos, 16);
    in6_addr addr;
    memcpy(&addr, base, 16);
    std::static_pointer_cast<ColumnIPv6>(col)->Append(&addr);
    buf->pos += 16;
}


static inline void appendIpV4ToIpV6Column(ColumnRef col, outputBuffer_t* buf) {
    static unsigned char base[16] = {
        0, 0,    0,    0, 0, 0, 0, 0,
        0, 0, 0xff, 0xff, 0, 0, 0, 0
    };
    memcpy(&base[12], buf->buffer + buf->pos, 4);
    in6_addr addr;
    memcpy(&addr, base, 16);
    std::static_pointer_cast<ColumnIPv6>(col)->Append(&addr);
    buf->pos += 4;
}


static inline void appendToTimestampColumn(ColumnRef col, outputBuffer_t* buf) {
    uint64_t seconds;
    uint32_t subSeconds;
    int64_t timestamp;
    memcpy(&seconds, buf->buffer + buf->pos, sizeof(seconds));
    buf->pos += sizeof(seconds);
    memcpy(&subSeconds, buf->buffer + buf->pos, sizeof(subSeconds));
    buf->pos += sizeof(subSeconds);
#if TSTAMP_PREC == 0
    subSeconds /= 1000;
#endif
    timestamp = seconds * 1000000 * (TSTAMP_PREC * 999 + 1) + subSeconds;
    std::static_pointer_cast<ColumnDateTime64>(col)->Append(timestamp);
}


static inline void appendArray(ColumnRef col, const binary_subvalue_t * const bsv, uint32_t size, outputBuffer_t* buf) {
    uint32_t elements;
    memcpy(&elements, buf->buffer + buf->pos, sizeof(elements));
    buf->pos += sizeof(elements);
    auto array = subvalueToColumn(bsv, size, false);
    for (uint_fast32_t i = 0; i < elements; i++) {
        if (size > 1) {
            appendData(array, bsv, size, false, buf);
        } else if (bsv->type == bt_compound) {
            appendData(array, bsv->subval, bsv->num_values, bsv->is_repeating, buf);
        } else {
            appendData(array, binary_type_t(bsv->type), buf);
        }
    }
    std::static_pointer_cast<ColumnArray>(col)->AppendAsColumn(array);
}


static inline void appendData(ColumnRef col, binary_type_t dataType, outputBuffer_t* buf) {
    switch (dataType) {

        case bt_compound:
            break;

        /* bt_int_* */

        case bt_int_8:
            appendToColumn<int8_t, ColumnInt8>(col, buf);
            break;
        case bt_int_16:
            appendToColumn<int16_t, ColumnInt16>(col, buf);
            break;
        case bt_int_32:
            appendToColumn<int32_t, ColumnInt32>(col, buf);
            break;
        case bt_int_64:
            appendToColumn<int64_t, ColumnInt64>(col, buf);
            break;
        case bt_int_128:
            buf->pos += 8;
            appendToColumn<int64_t, ColumnInt64>(col, buf); // FIXME
            break;
        case bt_int_256:
            buf->pos += 24;
            appendToColumn<int64_t, ColumnInt64>(col, buf); // FIXME
            break;

        /*  bt_uint_* */

        case bt_uint_8:
            appendToColumn<uint8_t, ColumnUInt8>(col, buf);
            break;
        case bt_uint_16:
            appendToColumn<uint16_t, ColumnUInt16>(col, buf);
            break;
        case bt_uint_32:
            appendToColumn<uint32_t, ColumnUInt32>(col, buf);
            break;
        case bt_uint_64:
            appendToColumn<uint64_t, ColumnUInt64>(col, buf);
            break;
        case bt_uint_128:
            buf->pos += 8;
            appendToColumn<uint64_t, ColumnUInt64>(col, buf); // FIXME
            break;
        case bt_uint_256:
            buf->pos += 24;
            appendToColumn<uint64_t, ColumnUInt64>(col, buf); // FIXME
            break;

        /*  bt_hex_* */

        case bt_hex_8:
            appendToColumn<uint8_t, ColumnUInt8>(col, buf);
            break;
        case bt_hex_16:
            appendToColumn<uint16_t, ColumnUInt16>(col, buf);
            break;
        case bt_hex_32:
            appendToColumn<uint32_t, ColumnUInt32>(col, buf);
            break;
        case bt_hex_64:
            appendToColumn<uint64_t, ColumnUInt64>(col, buf);
            break;
        case bt_hex_128:
            appendToColumn<uint64_t, ColumnUInt64>(
                    std::static_pointer_cast<ColumnTuple>(col)->operator[](0), buf);
            appendToColumn<uint64_t, ColumnUInt64>(
                    std::static_pointer_cast<ColumnTuple>(col)->operator[](1), buf);
            break;
        case bt_hex_256:
            appendToColumn<uint64_t, ColumnUInt64>(
                    std::static_pointer_cast<ColumnTuple>(col)->operator[](0), buf);
            appendToColumn<uint64_t, ColumnUInt64>(
                    std::static_pointer_cast<ColumnTuple>(col)->operator[](1), buf);
            appendToColumn<uint64_t, ColumnUInt64>(
                    std::static_pointer_cast<ColumnTuple>(col)->operator[](2), buf);
            appendToColumn<uint64_t, ColumnUInt64>(
                    std::static_pointer_cast<ColumnTuple>(col)->operator[](3), buf);
            break;

        /*  float/double */

        case bt_float:
            appendToColumn<_Float32, ColumnFloat32>(col, buf);
            break;
        case bt_double:
            appendToColumn<_Float64, ColumnFloat64>(col, buf);
            break;
        case bt_long_double:
            appendToColumn<_Float64, ColumnFloat64>(col, buf);
            buf->pos += 2;
            break;

        /*  char/string */

        case bt_char:
            appendToFixedStringColumn(col, buf, 1);
            break;
        case bt_flow_direction: {
            char dir = (*(buf->buffer + buf->pos) + FLOW_DIR_C_A);
            std::static_pointer_cast<ColumnFixedString>(col)->Append(
                    std::basic_string_view<char>(&dir, 1));
            buf->pos++;
            break;
        }
        case bt_string:
            appendToStringColumn(col, buf);
            break;
        case bt_string_class:
            appendToStringColumn(col, buf);
            break;

        /* Time */

        case bt_timestamp:
            appendToTimestampColumn(col, buf);
            break;
        case bt_duration:
            appendToTimestampColumn(col, buf);
            break;

        /* MAC/IP addresses */

        case bt_mac_addr:
            appendToFixedStringColumn(col, buf, 6);
            break;
        case bt_ip4_addr:
            appendToColumn<uint32_t, ColumnIPv4>(col, buf);
            break;
        case bt_ip6_addr:
            appendToIpV6Column(col, buf);
            break;
        case bt_ipx_addr:
            switch (buf->buffer[buf->pos]) {
                case 4:
                    appendToColumn<uint8_t, ColumnUInt8>(
                            std::static_pointer_cast<ColumnTuple>(col)->operator[](0), buf);
                    appendIpV4ToIpV6Column(
                            std::static_pointer_cast<ColumnTuple>(col)->operator[](1), buf);
                    break;
                case 6:
                    appendToColumn<uint8_t, ColumnUInt8>(
                            std::static_pointer_cast<ColumnTuple>(col)->operator[](0), buf);
                    appendToIpV6Column(
                            std::static_pointer_cast<ColumnTuple>(col)->operator[](1), buf);
                    break;
                default: {
                    std::static_pointer_cast<ColumnUInt8>(std::static_pointer_cast<ColumnTuple>(col)->operator[](0))->Append(0);
                    in6_addr addr = IN6ADDR_ANY_INIT;
                    std::static_pointer_cast<ColumnIPv6>(
                            std::static_pointer_cast<ColumnTuple>(col)->operator[](1))->Append(&addr);
                    break;
                }
            }
            break;

        default:
            /* Should not happen */
            break;
    }
}


static inline void appendData(ColumnRef col, const binary_subvalue_t * const bsv, u_int32_t size, bool isArray, outputBuffer_t* buf) {
    if (isArray) {
        appendArray(col, bsv, size, buf);
    } else if (size > 1) {
        for (uint_fast32_t i = 0; i < size; i++) {
            appendData(std::static_pointer_cast<ColumnTuple>(col)->operator[](i),
                    &bsv[i], bsv[i].num_values, bsv[i].is_repeating, buf);
        }
    } else {
        appendData(col, binary_type_t(bsv->type), buf);
    }
}


static void createDatabase(Client &client) {
    bool exists = false;

    client.Select("SHOW DATABASES", [&exists] (const Block& block) {
        for (size_t i = 0; i < block.GetRowCount() && !exists; ++i) {
            exists |= (std::string(block[0]->As<ColumnString>()->At(i)) == std::string(clkDbName));
        }
    });

    if (exists and (CLICKHOUSE_OVERWRITE_DB == 0)) {
        T2_PFATAL(plugin_name, "Database '%s' already exists", clkDbName);
    }

    if (exists and (CLICKHOUSE_OVERWRITE_DB == 1)) {
        client.Execute(std::string("DROP DATABASE ") + std::string(clkDbName));
        exists = false;
    }

    if (!exists) {
        client.Execute(std::string("CREATE DATABASE ") + std::string(clkDbName));
    }
}


static void createTable(Client &client, const binary_value_t *bv) {
    bool exists = false;

    client.Select(std::string("SHOW TABLES FROM ") + std::string(clkDbName), [&exists] (const Block& block) {
        for (size_t i = 0; i < block.GetRowCount() && !exists; ++i) {
            exists |= (block[0]->As<ColumnString>()->At(i) == clkTableName);
        }
    });

    if (exists and (CLICKHOUSE_OVERWRITE_TABLE == 0)) {
        T2_PFATAL(plugin_name, "Table '%s' already exists", clkTableName);
    }

    if (exists and (CLICKHOUSE_OVERWRITE_TABLE == 1)) {
        client.Execute(std::string("DROP TABLE ") + std::string(clkDbName) + std::string(".") + std::string(clkTableName));
        exists = false;
    }

    if (exists and (CLICKHOUSE_OVERWRITE_TABLE == 2)) {
        block = generateColumnScheme(bv);
        std::unordered_map<std::string, std::string> newScheme;
        bool sameScheme = false;
        for (size_t i = 0; i < block.GetColumnCount(); i++) {
            newScheme[block.GetColumnName(i)] = block[i]->GetType().GetName();
        }

        client.Select(std::string("DESCRIBE TABLE ") + std::string(clkDbName) + std::string(".") + std::string(clkTableName),
                [newScheme, &sameScheme](const Block& oldBlock) {
                    bool result = (newScheme.size() == oldBlock.GetRowCount());
                    for (size_t i = 0; i < oldBlock.GetRowCount() && result; i++) {
                        result &= newScheme.at(std::string(oldBlock[0]->As<ColumnString>()->At(i))) == std::string(oldBlock[1]->As<ColumnString>()->At(i));
                    }
                    sameScheme |= result;

                });

        if (!sameScheme) {
            T2_PFATAL(plugin_name, "Cannot append to existing table '%s': schemas differ", clkTableName);
        }
    }

    if (!exists) {
        block = generateColumnScheme(bv);

        std::string query = "CREATE TABLE IF NOT EXISTS " + std::string(clkDbName) + "." + std::string(clkTableName) + " (\n";

        for (size_t i = 0; i < block.GetColumnCount(); i++) {
            query += std::string("\t") + block.GetColumnName(i) + std::string(" ") + block[i]->GetType().GetName() + std::string(" CODEC(ZSTD)");
            if (i+1 != block.GetColumnCount()) {
                query += ",\n";
            }
        }

        query += "\n)\n";
        query += "ENGINE=MergeTree()\n";
        query += "ORDER BY(flowInd);";
        client.Execute(query);
    }
}


static inline void insertBlock(const Block block) {
    Client client = newClickHouseClient();
    client.Insert(std::string(clkDbName) + std::string(".") + std::string(clkTableName), block);
}

#endif // BLOCK_BUF == 0
