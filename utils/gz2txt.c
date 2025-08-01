/*
 * gz2txt.c
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

#include "gz2txt.h"

#if USE_ZLIB != 0

#include "t2Plugin.h"


// Function prototypes

static inline int gzputc_wrapper(int c, gzFile file);
static inline char *gzgets_wrapper(char *str, int size, gzFile file);
static inline int gzputs_wrapper(const char *s, gzFile file);
static inline void gzrewind_wrapper(gzFile file);
static inline int gzseek_wrapper(gzFile file, off_t offset, int whence);

#if ZLIB_VERNUM < ZLIB_REQUIRED_VERSION
#define T2_ZLIB_ERROR "Cannot read from gzip-compressed files, zlib version 1.2.9 required, found " ZLIB_VERSION
size_t gzfread(void *ptr UNUSED, size_t size UNUSED, size_t nmemb UNUSED, gzFile stream UNUSED);
#endif // ZLIB_VERNUM < ZLIB_REQUIRED_VERSION


const b2t_func_t b2t_funcs_gz = {
    .fclose  = (fclose_func_t)gzclose,
    .fgetc   = (fgetc_func_t)gzgetc,
    .fgets   = (fgets_func_t)gzgets_wrapper,
    .fopen   = (fopen_func_t)gzopen,
    .fprintf = (fprintf_func_t)gzprintf,
    .fputc   = (fputc_func_t)gzputc_wrapper,
    .fputs   = (fputs_func_t)gzputs_wrapper,
    .fread   = (fread_func_t)gzfread,
    .fseek   = (fseek_func_t)gzseek_wrapper,
    .ftell   = (ftell_func_t)gztell,
    .rewind  = (rewind_func_t)gzrewind_wrapper,
    .ungetc  = (ungetc_func_t)gzungetc,
    .get_val = get_val_from_input_file,
};


static inline char *gzgets_wrapper(char *str, int size, gzFile file) {
    return gzgets(file, str, size);
}


static inline int gzputc_wrapper(int c, gzFile file) {
    return gzputc(file, c);
}


static inline int gzputs_wrapper(const char *s, gzFile file) {
    return gzputs(file, s);
}


static inline void gzrewind_wrapper(gzFile file) {
    gzrewind(file);
}


static inline int gzseek_wrapper(gzFile file, off_t offset, int whence) {
    if (whence == SEEK_END) {
        T2_FATAL("SEEK_END is not supported by gzseek...");
    }
    return gzseek(file, offset, whence);
}


#if ZLIB_VERNUM < ZLIB_REQUIRED_VERSION


size_t gzfread(void *ptr UNUSED, size_t size UNUSED, size_t nmemb UNUSED, gzFile stream UNUSED) {
    T2_FATAL("%s", T2_ZLIB_ERROR);
}


inline bool parse_file_gz2txt(gzFile input UNUSED, binary_value_t * const bv UNUSED, FILE *outfile UNUSED, bool compress UNUSED) {
    T2_ERR("%s", T2_ZLIB_ERROR);
    return false;
}


inline bool parse_file_gz2json(gzFile input UNUSED, binary_value_t * const bv UNUSED, FILE *outfile UNUSED, bool compress UNUSED) {
    T2_ERR("%s", T2_ZLIB_ERROR);
    return false;
}


#else // ZLIB_VERNUM >= ZLIB_REQUIRED_VERSION


inline bool parse_file_gz2txt(gzFile input, binary_value_t * const bv, FILE *outfile, bool compress) {
    b2t_func_t funcs;
    if (compress) {
        funcs = b2t_funcs_gz;
    } else {
        funcs = b2t_funcs;
        funcs.fread = (fread_func_t)gzfread;
    }
    return parse_binary2text(input, bv, outfile, funcs);
}


inline bool parse_file_gz2json(gzFile input, binary_value_t * const bv, FILE *outfile, bool compress) {
    b2t_func_t funcs;
    if (compress) {
        funcs = b2t_funcs_gz;
    } else {
        funcs = b2t_funcs;
        funcs.fread = (fread_func_t)gzfread;
    }
    return parse_binary2json(input, bv, outfile, funcs);
}


#endif // ZLIB_VERNUM >= ZLIB_REQUIRED_VERSION


#endif // USE_ZLIB != 0
