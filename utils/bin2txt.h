/*
 * bin2txt.h
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

#ifndef T2_BIN2TXT_H_INCLUDED
#define T2_BIN2TXT_H_INCLUDED

#include <inttypes.h>       // for PRIx8, PRIx16, PRIx32, ...
#include <stdarg.h>         // for ...
#include <stdbool.h>        // for bool
#include <stddef.h>         // for size_t
#include <stdio.h>          // for FILE

#include "binaryValue.h"    // for binary_value_t
#include "outputBuffer.h"   // for outputBuffer_t


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define IP4_FORMAT             0 // IPv4 addresses representation:
                                 //     0: normal
                                 //     1: normalized (padded with zeros)
                                 //     2: hexadecimal
                                 //     3: uint32

#define IP6_FORMAT             0 // IPv6 addresses representation:
                                 //     0: compressed
                                 //     1: uncompressed
                                 //     2: one 128-bits hex number
                                 //     3: two 64-bits hex numbers

#define MAC_FORMAT             0 // MAC addresses representation:
                                 //     0: normal (edit MAC_SEP to change the separator)
                                 //     1: one 64-bits hex number
                                 //     2: one 64-bits number

#define HEX_CAPITAL            0 // Hex output: 0: lower case; 1: upper case
#define TFS_EXTENDED_HEADER    0 // Extended header in flow file
#define TFS_NC_TYPE            2 // Types in header file: 0: none, 0: numbers, 1: C types
#define TFS_SAN_UTF8           1 // Activate the UTF-8 sanitizer for strings
#define B2T_TIMESTR            0 // Print Unix timestamps as human readable dates

// JSON
#define JSON_KEEP_EMPTY        0 // Output empty fields
#define JSON_PRETTY            0 // Add spaces to make the output more readable

/* +++++++++++++++++++++ ENV / RUNTIME - conf Variables +++++++++++++++++++++ */

#define MAC_SEP        ":"  // Separator to use in MAC addresses: 11:22:33:44:55:66
#define B2T_NON_IP_STR "-"  // Representation of non-IPv4/IPv6 addresses in IP columns
#define HDR_CHR        "%"  // start characters to label comments
#define SEP_CHR        "\t" // column separator in the flow file
                            // ; . _ and " should not be used

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// local defines

#if HEX_CAPITAL == 0
#define B2T_PRIX8       PRIx8
#define B2T_PRIX16      PRIx16
#define B2T_PRIX32      PRIx32
#define B2T_PRIX64      PRIx64
#define B2T_PRIXFAST8   PRIxFAST8
#define B2T_PRIXFAST16  PRIxFAST16
#define B2T_PRIXFAST32  PRIxFAST32
#define B2T_PRIXFAST64  PRIxFAST64
#else // HEX_CAPITAL == 1
#define B2T_PRIX8       PRIX8
#define B2T_PRIX16      PRIX16
#define B2T_PRIX32      PRIX32
#define B2T_PRIX64      PRIX64
#define B2T_PRIXFAST8   PRIXFAST8
#define B2T_PRIXFAST16  PRIXFAST16
#define B2T_PRIXFAST32  PRIXFAST32
#define B2T_PRIXFAST64  PRIXFAST64
#endif // HEX_CAPITAL

#if JSON_PRETTY == 1
#define JSON_PRETTY_STR " "
#else // JSON_PRETTY == 0
#define JSON_PRETTY_STR ""
#endif // JSON_PRETTY == 0

// ISO 8601 time format
// <year>-<month>-<day>T<hours>:<minutes>:<seconds>.<micro/nano-seconds><+/-offset>
#define B2T_TIMEFRMT "%FT%T"

#if TSTAMP_PREC != 0
#define B2T_TPFRMT "09" PRIu32
#else // TSTAMP_PREC == 0
#define B2T_TPFRMT "06" PRIu32
#endif // TSTAMP_PREC

// Typedefs
typedef int (*fclose_func_t)(void *stream);
typedef int (*fgetc_func_t)(void *stream);
typedef char * (*fgets_func_t)(char *str, int size, void *stream);
typedef void * (*fopen_func_t)(const char *path, const char *mode);
typedef int (*fprintf_func_t)(void *stream, const char *format, ...);
typedef int (*fputc_func_t)(int c, void *stream);
typedef int (*fputs_func_t)(const char *s, void *stream);
typedef size_t (*fread_func_t)(void *ptr, size_t size, size_t nmemb, void *stream);
typedef int (*fseek_func_t)(void *stream, off_t offset, int whence);
typedef off_t (*ftell_func_t)(void *stream);
typedef void (*rewind_func_t)(void *stream);
typedef int (*ungetc_func_t)(int c, void *stream);

typedef bool (*parse_binary_func_t)(void *input, binary_value_t * const bv, FILE *outfile, bool compress);


// Structs
typedef struct b2t_func_s {
    fclose_func_t  fclose;
    fgetc_func_t   fgetc;
    fgets_func_t   fgets;
    fopen_func_t   fopen;
    fprintf_func_t fprintf;
    fputc_func_t   fputc;
    fputs_func_t   fputs;
    fread_func_t   fread;
    fseek_func_t   fseek;
    ftell_func_t   ftell;
    rewind_func_t  rewind;
    ungetc_func_t  ungetc;
    bool (*get_val)(void*, void*, size_t, size_t, struct b2t_func_s funcs);
} b2t_func_t;


// Variables
extern const b2t_func_t b2t_funcs;
extern const b2t_func_t b2t_funcs_gz;


// Function prototypes
bool get_val_from_input_file(void *input, void *dest, size_t size, size_t n, b2t_func_t funcs) __attribute__((__nonnull__(1, 2)));

bool t2_get_bin_magic_offset(void *infile, b2t_func_t funcs, uint32_t *magic) __attribute__((__nonnull__(1, 3)));
uint32_t t2_get_bin_header_len_from_magic(void *infile, b2t_func_t funcs, uint32_t magic) __attribute__((__nonnull__(1)));
uint32_t t2_get_bin_header_len(void *infile, b2t_func_t funcs, uint32_t *preamble, uint32_t *dataShft, uint32_t *magicOff) __attribute__((__nonnull__(1, 3, 4)));

// Returned value MUST be free'd with bv_header_destroy()
binary_value_t *t2_read_bin_header(void *infile, uint32_t hdrlen, b2t_func_t funcs, uint32_t *offset, uint32_t *preamble) __attribute__((__nonnull__(1)));

bool parse_binary2text(void *input, binary_value_t * const bv, void *outfile, b2t_func_t funcs) __attribute__((__nonnull__(1, 3)));
bool parse_binary2json(void *input, binary_value_t * const bv, void *outfile, b2t_func_t funcs) __attribute__((__nonnull__(1, 3)));

bool parse_file_bin2txt(FILE *input, binary_value_t * const bv, FILE *outfile, bool compress) __attribute__((__nonnull__(1, 3)));
bool parse_file_bin2json(FILE *input, binary_value_t * const bv, FILE *outfile, bool compress) __attribute__((__nonnull__(1, 3)));

bool parse_buffer_bin2txt(outputBuffer_t *input, binary_value_t * const bv, void *outfile, b2t_func_t b2t_funcs) __attribute__((__nonnull__(1, 3)));
bool parse_buffer_bin2json(outputBuffer_t *input, binary_value_t * const bv, void *outfile, b2t_func_t b2t_funcs) __attribute__((__nonnull__(1, 3)));

void parse_binary_header2text(binary_value_t * const bv, void *outfile, b2t_func_t funcs) __attribute__((__nonnull__(2)));
void print_values_description(binary_value_t *bv, void *outfile, b2t_func_t funcs) __attribute__((__nonnull__(2)));

#endif // T2_BIN2TXT_H_INCLUDED
