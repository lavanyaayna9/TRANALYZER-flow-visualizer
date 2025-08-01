/*
 * t2log.h
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

#ifndef T2_T2LOG_H_INCLUDED
#define T2_T2LOG_H_INCLUDED


// includes

#include <inttypes.h>    // for PRIu64
#include <stdbool.h>     // for bool
#include <stdio.h>       // for stderr, FILE

#include "t2utils.h"     // for T2_CONV_NUM
#include "tranalyzer.h"  // for DEBUG


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define T2_LOG_COLOR 1 // Whether or not to color messages

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// Forward declarations

struct timeval;


// Variables

extern FILE *dooF;


// Explanation of the macros:
//  LOG  : log in black
//  INF  : log in blue
//  OK   : log in green
//  WRN  : log in black
//  ERR  : log in red
//  2    : log to stderr
//  F    : require a stream/file
//  P    : require a plugin name
//  NP   : no prefix (does not print [INF], [OK], [WRN] or [ERR] prefix
//  NUM  : print human readable numbers (only if num > 0): 1234 (1K)
//  NUMP : print human readable numbers and add the percentage (only if num > 0): 1234 (1K) [1.23%]
//  0    : print even if num = 0

// Buffer size for time conversion
#define MAX_TM_BUF 35

// Macro to change colors
#if T2_LOG_COLOR == 1
#define RED_BOLD    "\x1b[1;31m"
#define RED         "\x1b[0;31m"
#define GREEN_BOLD  "\x1b[1;32m"
#define GREEN       "\x1b[0;32m"
#define YELLOW_BOLD "\x1b[1;33m"
#define YELLOW      "\x1b[0;33m"
#define BLUE_BOLD   "\x1b[1;34m"
#define BLUE        "\x1b[0;34m"
#define BOLD        "\x1b[1m"
#define NOCOLOR     "\x1b[0m"
#else // T2_LOG_COLOR == 0
#define RED_BOLD
#define RED
#define GREEN_BOLD
#define GREEN
#define YELLOW_BOLD
#define YELLOW
#define BLUE_BOLD
#define BLUE
#define BOLD
#define NOCOLOR
#endif // T2_LOG_COLOR == 0


// Macros to print debug messages
#if DEBUG > 0
#define T2_DBG(format, args...) printf(BOLD "[DBG]" NOCOLOR " " format "\n", ##args)
#define T2_PDBG(plugin_name, format, args...) printf(BOLD "[DBG] %s:" NOCOLOR " " format "\n", plugin_name, ##args)
#else // DEBUG == 0
#define T2_DBG(format, args...)
#define T2_PDBG(plugin_name, format, args...)
#endif // DEBUG == 0


// Generic macro to print in colors
#define T2_FLOG_COLOR(stream, color, format, args...) fprintf(file, color format NOCOLOR "\n", ##args)


// Macro to print
//  - information (blue),
//  - ok (green) messages,
//  - warnings (yellow),
//  - errors (red)
#define T2_FLOG(stream, format, args...) fprintf(stream, format "\n", ##args)
#define T2_FINF(stream, format, args...) fprintf(stream, BLUE_BOLD   "[INF]" NOCOLOR " " BLUE   format NOCOLOR "\n", ##args)
#define T2_FOK( stream, format, args...) fprintf(stream, GREEN_BOLD  "[OK]"  NOCOLOR " " GREEN  format NOCOLOR "\n", ##args)
#define T2_FWRN(stream, format, args...) fprintf(stream, YELLOW_BOLD "[WRN]" NOCOLOR " " YELLOW format NOCOLOR "\n", ##args)
#define T2_FERR(stream, format, args...) fprintf(stream, RED_BOLD    "[ERR]" NOCOLOR " " RED    format NOCOLOR "\n", ##args)


// Same macros, but with implicit use of dooF (-l option)
#define T2_LOG(format, args...) T2_FLOG(dooF, format, ##args)
#define T2_INF(format, args...) T2_FINF(dooF, format, ##args)
#define T2_OK( format, args...) T2_FOK( dooF, format, ##args)
#define T2_WRN(format, args...) T2_FWRN(dooF, format, ##args)
// Errors are fatal, so always log them to stderr
#define T2_ERR(format, args...) T2_FERR(stderr, format, ##args)
// Same macros, but with implicit use of stderr
#define T2_LOG2(format, args...) T2_FINF(stderr, format, ##args)
#define T2_INF2(format, args...) T2_FINF(stderr, format, ##args)
#define T2_OK2( format, args...) T2_FINF(stderr, format, ##args)
#define T2_WRN2(format, args...) T2_FINF(stderr, format, ##args)


// Same macros, but for the plugins (add plugin_name to the message)
#define T2_FPLOG(stream, plugin_name, format, args...) \
    fprintf(stream, BOLD "%s:" NOCOLOR " " format "\n", plugin_name, ##args)
#define T2_FPINF(stream, plugin_name, format, args...) \
    fprintf(stream, BLUE_BOLD "[INF] %s:" NOCOLOR " " BLUE format NOCOLOR "\n", plugin_name, ##args)
#define T2_FPOK(stream, plugin_name, format, args...) \
    fprintf(stream, GREEN_BOLD "[OK] %s:" NOCOLOR " " GREEN format NOCOLOR "\n", plugin_name, ##args)
#define T2_FPWRN(stream, plugin_name, format, args...) \
    fprintf(stream, YELLOW_BOLD "[WRN] %s:" NOCOLOR " " YELLOW format NOCOLOR "\n", plugin_name, ##args)
#define T2_FPERR(stream, plugin_name, format, args...) { \
    fprintf(stream, RED_BOLD "[ERR] %s:" NOCOLOR " " RED format NOCOLOR "\n", plugin_name, ##args); \
    fflush(stream); \
}


// Same macros, but with implicit use of dooF (-l option)
#define T2_PLOG(plugin_name, format, args...) T2_FPLOG(dooF, plugin_name, format, ##args)
#define T2_POK( plugin_name, format, args...) T2_FPOK( dooF, plugin_name, format, ##args)
#define T2_PINF(plugin_name, format, args...) T2_FPINF(dooF, plugin_name, format, ##args)
#define T2_PWRN(plugin_name, format, args...) T2_FPWRN(dooF, plugin_name, format, ##args)
// Errors are fatal, so always log them to stderr
#define T2_PERR(plugin_name, format, args...) T2_FPERR(stderr, plugin_name, format, ##args)
// Same macros, but with implicit use of stderr
#define T2_PLOG2(plugin_name, format, args...) T2_FPINF(stderr, plugin_name, format, ##args)
#define T2_PINF2(plugin_name, format, args...) T2_FPINF(stderr, plugin_name, format, ##args)
#define T2_POK2( plugin_name, format, args...) T2_FPINF(stderr, plugin_name, format, ##args)
#define T2_PWRN2(plugin_name, format, args...) T2_FPINF(stderr, plugin_name, format, ##args)


// Variants of above macros, but without [INF], [OK], [WRN] or [ERR] prefix

#define T2_FINF_NP(stream, format, args...) T2_LOG_COLOR(stream, BLUE  , format, ##args)
#define T2_FOK_NP( stream, format, args...) T2_LOG_COLOR(stream, GREEN , format, ##args)
#define T2_FWRN_NP(stream, format, args...) T2_LOG_COLOR(stream, YELLOW, format, ##args)
#define T2_FERR_NP(stream, format, args...) T2_LOG_COLOR(stream, RED   , format, ##args)


// Same macros, but with implicit use of dooF (-l option)
#define T2_INF_NP(format, args...) T2_FINF_NP(dooF, format, ##args)
#define T2_OK_NP( format, args...) T2_FOK_NP( dooF, format, ##args)
#define T2_WRN_NP(format, args...) T2_FWRN_NP(dooF, format, ##args)
#define T2_ERR_NP(format, args...) T2_FERR_NP(dooF, format, ##args)


// Same macros, but for the plugins (add plugin_name to the message)
#define T2_FPOK_NP(stream, plugin_name, format, args...) \
    fprintf(stream, GREEN_BOLD "%s:" NOCOLOR " " GREEN format NOCOLOR "\n", plugin_name, ##args)
#define T2_FPINF_NP(stream, plugin_name, format, args...) \
    fprintf(stream, BLUE_BOLD "%s:" NOCOLOR " " BLUE format NOCOLOR "\n", plugin_name, ##args)
#define T2_FPWRN_NP(stream, plugin_name, format, args...) \
    fprintf(stream, YELLOW_BOLD "%s:" NOCOLOR " " YELLOW format NOCOLOR "\n", plugin_name, ##args)
#define T2_FPERR_NP(stream, plugin_name, format, args...) { \
    fprintf(stream, RED_BOLD "%s:" NOCOLOR " " RED format NOCOLOR "\n", plugin_name, ##args); \
    fflush(stream); \
}


// Same macros, but with implicit use of dooF (-l option)
#define T2_POK_NP(plugin_name, format, args...)  T2_FPOK_NP( dooF, plugin_name, format, ##args)
#define T2_PINF_NP(plugin_name, format, args...) T2_FPINF_NP(dooF, plugin_name, format, ##args)
#define T2_PWRN_NP(plugin_name, format, args...) T2_FPWRN_NP(dooF, plugin_name, format, ##args)
// Errors are fatal, so always log them to stderr
#define T2_PERR_NP(plugin_name, format, args...) T2_FPERR_NP(stderr, plugin_name, format, ##args)


// Logs num to stream
#define T2_FLOG_NUM0(stream, prefix, num) { \
    char str[64]; \
    T2_CONV_NUM((num), str); \
    fprintf(stream, "%s: %" PRIu64 "%s\n", prefix, (uint64_t)(num), str); \
}

// Logs num > 0 to stream
#define T2_FLOG_NUM(stream, prefix, num) \
    if ((num) > 0) T2_FLOG_NUM0(stream, prefix, num)

// Logs num and percentage to stream
#define T2_FLOG_NUMP0(stream, prefix, num, total) { \
    char str[64]; \
    T2_CONV_NUM(num, str); \
    fprintf(stream, "%s: %" PRIu64 "%s [%.2f%%]\n", \
            prefix, (uint64_t)(num), str, ((total == 0) ? 0 : (100.0*(num)/(double)(total)))); \
}

// Logs num > 0 and percentage to stream
#define T2_FLOG_NUMP(stream, prefix, num, total) \
    if ((num) > 0) T2_FLOG_NUMP0(stream, prefix, num, total)

// Logs num with plugin name and percentage to stream
#define T2_FPLOG_NUMP0(stream, plugin, prefix, num, total) { \
    char str[64]; \
    T2_CONV_NUM((num), str); \
    fprintf(stream, BOLD "%s:" NOCOLOR " %s: %" PRIu64 "%s [%.2f%%]\n", \
            plugin, prefix, (uint64_t)(num), str, ((total == 0) ? 0 : (100.0*(num)/(double)(total)))); \
}

// Logs num with plugin name and percentage to stream as warnings
#define T2_FPWRN_NUMP0(stream, plugin, prefix, num, total) { \
    char str[64]; \
    T2_CONV_NUM((num), str); \
    fprintf(stream, YELLOW_BOLD "[WRN] %s:" NOCOLOR " " YELLOW "%s: %" PRIu64 "%s [%.2f%%]" NOCOLOR "\n", \
            plugin, prefix, (uint64_t)(num), str, ((total == 0) ? 0 : (100.0*(num)/(double)(total)))); \
}

// Logs num with plugin name and percentage to stream as warnings (without [WRN] prefix)
#define T2_FPWRN_NUMP0_NP(stream, plugin, prefix, num, total) { \
    char str[64]; \
    T2_CONV_NUM((num), str); \
    fprintf(stream, YELLOW_BOLD "%s:" NOCOLOR " " YELLOW "%s: %" PRIu64 "%s [%.2f%%]" NOCOLOR "\n", \
            plugin, prefix, (uint64_t)(num), str, ((total == 0) ? 0 : (100.0*(num)/(double)(total)))); \
}

// Logs num to dooF (final report file/stdout)
#define T2_LOG_NUM0(prefix, num) T2_FLOG_NUM0(dooF, prefix, num)

// Logs num > 0 to dooF (final report file/stdout)
#define T2_LOG_NUM(prefix, num) T2_FLOG_NUM(dooF, prefix, num)

// Logs num and percentage to dooF (final report file/stdout)
#define T2_LOG_NUMP0(prefix, num, total) T2_FLOG_NUMP0(dooF, prefix, num, total)

// Logs num > 0 and percentage to dooF (final report file/stdout)
#define T2_LOG_NUMP(prefix, num, total) T2_FLOG_NUMP(dooF, prefix, num, total)

// Logs num with plugin name to stream
#define T2_FPLOG_NUM0(stream, plugin, prefix, num) { \
    char str[64]; \
    T2_CONV_NUM(num, str); \
    fprintf(stream, BOLD "%s:" NOCOLOR " %s: %" PRIu64 "%s\n", \
            plugin, prefix, (uint64_t)(num), str); \
}

// Logs num with plugin name to stream as warnings
#define T2_FPWRN_NUM0(stream, plugin, prefix, num) { \
    char str[64]; \
    T2_CONV_NUM(num, str); \
    fprintf(stream, YELLOW_BOLD "[WRN] %s:" NOCOLOR " " YELLOW "%s: %" PRIu64 "%s" NOCOLOR "\n", \
            plugin, prefix, (uint64_t)(num), str); \
}

// Logs num with plugin name to stream as warnings (without [WRN] prefix)
#define T2_FPWRN_NUM0_NP(stream, plugin, prefix, num) { \
    char str[64]; \
    T2_CONV_NUM(num, str); \
    fprintf(stream, YELLOW_BOLD "%s:" NOCOLOR " " YELLOW "%s: %" PRIu64 "%s" NOCOLOR "\n", \
            plugin, prefix, (uint64_t)(num), str); \
}

// Logs num with plugin name to dooF (final report file/stdout)
#define T2_PLOG_NUM0(plugin, prefix, num) \
    T2_FPLOG_NUM0(dooF, plugin, prefix, num)

// Logs num > 0 with plugin name to dooF (final report file/stdout)
#define T2_PLOG_NUM(plugin, prefix, num) \
    if ((num) > 0) T2_PLOG_NUM0(plugin, prefix, num)

// Logs num > 0 with plugin name to stream
#define T2_FPLOG_NUM(stream, plugin, prefix, num) \
    if ((num) > 0) T2_FPLOG_NUM0(stream, plugin, prefix, num)

// Logs num > 0 with plugin name to stream as warnings
#define T2_FPWRN_NUM(stream, plugin, prefix, num) \
    if ((num) > 0) T2_FPWRN_NUM0(stream, plugin, prefix, num)

// Logs num > 0 with plugin name to stream as warnings (without [WRN] prefix)
#define T2_FPWRN_NUM_NP(stream, plugin, prefix, num) \
    if ((num) > 0) T2_FPWRN_NUM0_NP(stream, plugin, prefix, num)

// Logs num with plugin name and percentage to dooF (final report file/stdout)
#define T2_PLOG_NUMP0(plugin, prefix, num, total) \
    T2_FPLOG_NUMP0(dooF, plugin, prefix, num, total)

// Logs num > 0 with plugin name and percentage to dooF (final report file/stdout)
#define T2_PLOG_NUMP(plugin, prefix, num, total) \
    if ((num) > 0) T2_PLOG_NUMP0(plugin, prefix, num, total)

// Logs num > 0 with plugin name and percentage to stream
#define T2_FPLOG_NUMP(stream, plugin, prefix, num, total) \
    if ((num) > 0) T2_FPLOG_NUMP0(stream, plugin, prefix, num, total)

// Logs num > 0 with plugin name and percentage to stream as warnings
#define T2_FPWRN_NUMP(stream, plugin, prefix, num, total) \
    if ((num) > 0) T2_FPWRN_NUMP0(stream, plugin, prefix, num, total)

// Logs num > 0 with plugin name and percentage to stream as warnings (without [WRN] prefix)
#define T2_FPWRN_NUMP_NP(stream, plugin, prefix, num, total) \
    if ((num) > 0) T2_FPWRN_NUMP0_NP(stream, plugin, prefix, num, total)

// Logs num with plugin name in diff mode, e.g., numOfPackets - numOfPackets0
#define T2_FPLOG_DIFFNUM0(stream, plugin, prefix, num) \
    T2_FPLOG_NUM0(stream, plugin, prefix, ((num)-(num##0)))

// Logs num > 0 with plugin name in diff mode, e.g., numOfPackets - numOfPackets0
#define T2_FPLOG_DIFFNUM(stream, plugin, prefix, num) \
    if ((num) > 0) T2_FPLOG_DIFFNUM0(stream, plugin, prefix, num)

// Logs num with plugin name and percentage in diff mode, e.g., numOfPackets - numOfPackets0
#define T2_FPLOG_DIFFNUMP0(stream, plugin, prefix, num, total) \
    T2_FPLOG_NUMP0(stream, plugin, prefix, ((num)-(num##0)), ((total)-(total##0)))

// Logs num > 0 with plugin name and percentage in diff mode, e.g., numOfPackets - numOfPackets0
#define T2_FPLOG_DIFFNUMP(stream, plugin, prefix, num, total) \
    if ((num) > 0) T2_FPLOG_DIFFNUMP0(stream, plugin, prefix, num, total)

// Logs numbers in diff mode, e.g., numOfPackets - numOfPackets0
#define T2_LOG_DIFFNUM0(stream, prefix, num) \
    T2_FLOG_NUM(stream, prefix, ((num)-(num##0)))

// Logs numbers > 0 in diff mode, e.g., numOfPackets - numOfPackets0
#define T2_LOG_DIFFNUM(stream, prefix, num) \
    if ((num) > 0) T2_LOG_DIFFNUM0(stream, prefix, num)

// Logs numbers and percentage in diff mode, e.g., numOfPackets - numOfPackets0
#define T2_LOG_DIFFNUMP0(stream, prefix, num, tot) \
    T2_FLOG_NUMP(stream, prefix, ((num)-(num##0)), ((tot)-(tot##0)))

// Logs numbers > 0 and percentage in diff mode, e.g., numOfPackets - numOfPackets0
#define T2_LOG_DIFFNUMP(stream, prefix, num, tot) \
    if ((num) > 0) T2_LOG_DIFFNUMP0(stream, prefix, num, tot)

// Logs plugin name, numbers and percentage in diff mode, e.g., numOfPackets - numOfPackets0
#define T2_PLOG_DIFFNUMP0(stream, plugin, prefix, num, tot) { \
    char str[64]; \
    T2_CONV_NUM(((num)-(num##0)), str); \
    fprintf(stream, BOLD "%s:" NOCOLOR " %s: %" PRIu64 "%s [%.2f%%]\n", \
            plugin, prefix, (uint64_t)((num)-(num##0)), str, ((((tot)-(tot##0)) == 0) ? 0 : (100.0*((num)-(num##0))/(double)((tot)-(tot##0))))); \
}

// Logs plugin name, numbers > 0 and percentage in diff mode, e.g., numOfPackets - numOfPackets0
#define T2_PLOG_DIFFNUMP(stream, plugin, prefix, num, tot) \
    if ((num) > 0) T2_PLOG_DIFFNUMP0(stream, plugin, prefix, num, tot)

// Assumes num is in Kb/s
#define T2_LOG_SPEED(stream, prefix, num) { \
    char str[64]; \
    const double numr = (num) * 8.0; \
    T2_CONV_NUM_SFX(numr, str, "b/s"); \
    fprintf(stream, "%s: %.0f b/s%s\n", prefix, numr, str); \
}

// Log aggregated bitfields
#define T2_FPLOG_AGGR_H8(stream,  plugin_name, var) if (var) T2_FPLOG(stream, plugin_name, "Aggregated " STR(var) "=0x%02"  B2T_PRIX8,  var);
#define T2_FPLOG_AGGR_H16(stream, plugin_name, var) if (var) T2_FPLOG(stream, plugin_name, "Aggregated " STR(var) "=0x%04"  B2T_PRIX16, var);
#define T2_FPLOG_AGGR_H32(stream, plugin_name, var) if (var) T2_FPLOG(stream, plugin_name, "Aggregated " STR(var) "=0x%08"  B2T_PRIX32, var);
#define T2_FPLOG_AGGR_H64(stream, plugin_name, var) if (var) T2_FPLOG(stream, plugin_name, "Aggregated " STR(var) "=0x%016" B2T_PRIX64, var);
#define T2_FPLOG_AGGR_HEX0(stream, plugin_name, var) { \
    const uint_fast64_t hex = var; \
    const int width = 2 * sizeof(var); \
    T2_FPLOG(stream, plugin_name, "Aggregated " STR(var) "=0x%0*" B2T_PRIXFAST64, width, hex); \
}
#define T2_FPLOG_AGGR_HEX(stream, plugin_name, var) if ((var) > 0) T2_FPLOG_AGGR_HEX0(stream, plugin_name, var);


// Functions

// Log date in unix timestamp and in a human readable way (UTC or localtime)
void t2_log_date(FILE *stream, const char *prefix, struct timeval date, bool utc) __attribute__((__nonnull__(1)));

// Log time in seconds and in a human readable way (days, hours, minutes and seconds)
void t2_log_time(FILE *stream, const char *prefix, struct timeval time) __attribute__((__nonnull__(1)));

#endif // T2_T2LOG_H_INCLUDED
