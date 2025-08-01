/*
 * t2b2t.c
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

// TODO
//  - read from stdin

#include <errno.h>                // for errno
#include <getopt.h>               // for getopt, optarg, optopt
#include <inttypes.h>             // for PRIu32
#include <stdbool.h>              // for bool, true, false
#include <stdint.h>               // for uint_fast32_t, uint32_t, uint64_t, intmax_t
#include <stdio.h>                // for FILE, printf, stdout, SEEK_SET, SEEK_CUR
#include <stdlib.h>               // for free, exit, EXIT_FAILURE, NULL, EXI...
#include <string.h>               // for strrchr, strcmp, strdup, strerror
#include <sys/time.h>             // for time_t, timeval
#include <time.h>                 // for strftime, gmtime, localtime
#include <zlib.h>                 // for gzdopen, ZLIB_VERNUM

#include "bin2txt.h"              // for b2t_func_t, parse_binary_func_t
#include "binaryValue.h"          // for bv_header_destroy, binary_value_t
#include "gz2txt.h"               // for parse_file_gz2json, parse_file_gz2txt
#include "t2log.h"                // for T2_ERR, MAX_TM_BUF, T2_FOK
#include "t2utils.h"              // for UNLIKELY, t2_alloc_strcat, t2_calloc_fatal
#include "tranalyzer.h"           // for TSTAMP_R_UTC


#define T2B2T "t2b2t"


static void print_usage() {
    printf("%s - Convert Tranalyzer binary flow files to json or txt\n\n"
            "Usage:\n"
            "    %s [OPTION...] -r <FILE>\n\n"
            "Input:\n"
            "    -r file            Tranalyzer flow file to convert\n\n"
            "Output:\n"
            "    -w file            Destination file (use '-' for stdout) [default: derived from input]\n\n"
            "Optional arguments:\n"
            "    -j                 Convert to JSON instead of txt\n"
            "    -c                 Compress (gzip) the output\n"
            "\n"
            "    -n                 Do not write column names as first row (txt only)\n"
            "\n"
            "    -p                 Extract the preamble (host info) as comments in the output\n"
            "    -P                 Extract the preamble (host info) in a separate '*_headers.txt' file\n"
            "\n"
            "    -l                 List the column names and exit\n"
            "\n"
            "    -?, -h             Show help options and exit\n",
            T2B2T, T2B2T);
}


static __attribute__((noreturn)) void abort_with_help() {
    printf("Try '%s -h' for more information.\n", T2B2T);
    exit(EXIT_FAILURE);
}


// Returned value MUST be free'd
static char *get_name_from_input(const char *in_name, bool has_gz, const char *suffix, bool json, bool compress) {
    // Find the last '.'
    char *dot = strrchr(in_name, '.');
    char *prefix;
    if (!dot) {
        prefix = strdup(in_name);
    } else {
        if (has_gz) {
            *dot = '\0';
            char * const dot2 = strrchr(in_name, '.');
            *dot = '.';
            if (dot2) dot = dot2;
        }
        *dot = '\0';
        prefix = strdup(in_name);
        *dot = '.';
    }

    if (suffix) {
        char * const tmp = t2_alloc_strcat(prefix, suffix, NULL);
        free(prefix);
        prefix = tmp;
    }

    const char * const ext = (json ? ".json" : ".txt");
    char *out_name = t2_alloc_strcat(prefix, ext, NULL);
    free(prefix);
    if (compress) {
        prefix = out_name;
        out_name = t2_alloc_strcat(prefix, ".gz", NULL);
        free(prefix);
    }

    if (strcmp(in_name, out_name) == 0) {
        T2_ERR("Failed to derive output filename from input filename: both are the same!");
        free(out_name);
        exit(EXIT_FAILURE);
    }

    return out_name;
}


static void log_date(FILE *stream, b2t_func_t out_funcs, const char *prefix, struct timeval date, int utc) {
    const time_t sec = date.tv_sec;
    const intmax_t usec = date.tv_usec;

    const struct tm * const t = utc ? gmtime(&sec) : localtime(&sec);
    if (UNLIKELY(!t)) {
        out_funcs.fprintf(stream, "%s%ld.%06jd sec (<invalid>)\n", prefix, sec, usec);
        return;
    }

    char time[MAX_TM_BUF];
    strftime(time, sizeof(time), "%a %d %b %Y %X", t);

    char offset[MAX_TM_BUF];
    strftime(offset, sizeof(offset), "%Z", t);

    out_funcs.fprintf(stream, "%s%ld.%06jd sec (%s %s)\n", prefix, sec, usec, time, offset);
}


static bool extract_preamble(FILE *infile, b2t_func_t in_funcs, FILE *outfile, b2t_func_t out_funcs, uint32_t offset, uint32_t preamble) {
    const long start = in_funcs.ftell(infile);
    in_funcs.fseek(infile, offset << 2, SEEK_SET);

    // read sensor ID and date
    uint32_t sensorID;
    uint64_t secs;
    uint32_t usecs;
    if (UNLIKELY(in_funcs.fread(&sensorID, sizeof(sensorID), 1, infile) != 1 ||
                 in_funcs.fread(&secs    , sizeof(secs)    , 1, infile) != 1 ||
                 in_funcs.fread(&usecs   , sizeof(usecs)   , 1, infile) != 1))
    {
        T2_ERR("Failed to read one of the mandatory field in the preamble");
        exit(EXIT_FAILURE);
    }

    struct timeval t = { .tv_sec = secs, .tv_usec = usecs };
    log_date(outfile, out_funcs, "# Date: ", t, TSTAMP_R_UTC);

    out_funcs.fprintf(outfile, "# sensorID: %u\n", sensorID);

    const size_t len = preamble - (offset << 2) - 16; // 16 = sensorID(4) + time(8+4)
    char *info = t2_calloc_fatal(len, sizeof(char));
    if (UNLIKELY(in_funcs.fread(info, len, 1, infile) != 1)) {
        T2_ERR("Failed to read info");
        free(info);
        exit(EXIT_FAILURE);
    }

    // discard trailing colon
    uint_fast32_t i = len;
    while (i > 0 && info[i] == '\0') i--;
    if (info[i] == ',') info[i] = '\0';

    // split hw info from network interfaces
    char *semicolon = strrchr(info, ';');
    char *net = semicolon;
    if (net) *semicolon = '\0';

    out_funcs.fprintf(outfile, "# HW info: %s\n", info);
    if (net) {
        out_funcs.fprintf(outfile, "# Network interfaces: %s\n", net+1);
        *semicolon = ';';
    }

    in_funcs.fseek(infile, start, SEEK_SET);

    free(info);

    return true;
}


int main(int argc, char *argv[]) {
    char *in_name = NULL;  // name of the input file
    char *out_name = NULL; // name for the output file

    bool json = false;
    bool compress = false;
    bool colnames = true;
    bool keep_preamble = false;
    bool header_file = false;
    bool list_cols = false;

    parse_binary_func_t parse_binary_func;

    int ch; // parameter option
    while ((ch = getopt(argc, argv, ":r:w:jcnpPlh?")) != EOF) {
        switch (ch) {
            case 'r':
                in_name = optarg;
                break;
            case 'w':
                out_name = optarg;
                break;
            case 'j':
                json = true;
                break;
            case 'c':
                compress = true;
                break;
            case 'n':
                colnames = false;
                break;
            case 'p':
                keep_preamble = true;
                break;
            case 'P':
                header_file = true;
                break;
            case 'l':
                list_cols = true;
                break;
            case 'h':
                print_usage();
                exit(EXIT_SUCCESS);
            case ':':
                T2_ERR("Option '-%c' requires an argument", optopt);
                abort_with_help();
            default:
                T2_ERR("Unknown option '-%c'", optopt);
                abort_with_help();
        }
    }

    // if no input file is given, print usage and terminate
    if (!in_name) {
        T2_ERR("Input file is required");
        abort_with_help();
    }

    if (out_name && strcmp(out_name, "-") != 0) {
        // Use out_name to figure out the required format (txt/json, compressed)
        char *dot = strrchr(out_name, '.');
        if (dot && strcmp(dot, ".gz") == 0) {
            compress = true;
            *dot = '\0';
            char * const dot2 = strrchr(out_name, '.');
            *dot = '.';
            dot = dot2;
        }
        if (dot && strncmp(dot, ".json", 5) == 0) {
            json = true;
        }
    }

    // Function pointers
    b2t_func_t in_funcs;
    b2t_func_t out_funcs = (compress ? b2t_funcs_gz : b2t_funcs);

    const char *has_gz = strstr(in_name, ".gz");
    if (has_gz) {
#if ZLIB_VERNUM < ZLIB_REQUIRED_VERSION
        T2_ERR("Cannot convert gzip-compressed files");
        printf(BLUE_BOLD "[INF] " BLUE "Try running gunzip %s first\n" NOCOLOR, in_name);
        exit(EXIT_FAILURE);
#else
        in_funcs = b2t_funcs_gz;
        if (json) {
            parse_binary_func = (parse_binary_func_t)parse_file_gz2json;
        } else {
            parse_binary_func = (parse_binary_func_t)parse_file_gz2txt;
        }
#endif
    } else {
        in_funcs = b2t_funcs;
        if (json) {
            parse_binary_func = (parse_binary_func_t)parse_file_bin2json;
        } else {
            parse_binary_func = (parse_binary_func_t)parse_file_bin2txt;
        }
    }

    // try to open input file in read mode
    void *infile;
    if (UNLIKELY(!(infile = in_funcs.fopen(in_name, "r")))) {
        T2_ERR("Failed to open input file %s: %s", in_name, strerror(errno));
        exit(EXIT_FAILURE);
    }

    // if no output file is given, extract out_name from in_name
    // else try to open output file in write mode
    // (except if -w - was specified, which means output to stdout)
    void *outfile;
    bool w_stdout;
    if (list_cols) {
        w_stdout = true;
        outfile = stdout;
    } else if (out_name && strcmp(out_name, "-") == 0) {
        w_stdout = true;

        out_name = get_name_from_input(in_name, has_gz, NULL, json, compress);
        if (!compress) {
            outfile = stdout;
        } else if (UNLIKELY(!(outfile = gzdopen(fileno(stdout), "w")))) {
            T2_ERR("Failed to open compressed stream: %s", strerror(errno));
            in_funcs.fclose(infile);
            free(out_name);
            exit(EXIT_FAILURE);
        }
    } else {
        w_stdout = false;

        if (out_name) {
            out_name = strdup(out_name);
        } else {
            out_name = get_name_from_input(in_name, has_gz, NULL, json, compress);
        }

        if (UNLIKELY(!(outfile = out_funcs.fopen(out_name, "w")))) {
            T2_ERR("Failed to open output file %s: %s", out_name, strerror(errno));
            in_funcs.fclose(infile);
            free(out_name);
            exit(EXIT_FAILURE);
        }
    }

    int ret = EXIT_SUCCESS;

    uint32_t offset = 0; // BUF_DATA_SHFT (number of uint32_t words before each flow)
    uint32_t preamble = 0;

    binary_value_t *bv = t2_read_bin_header(infile, 0, in_funcs, &offset, &preamble);
    if (!bv) {
        T2_ERR("Failed to read binary header");
        ret = EXIT_FAILURE;
        goto cleanup;
    }

    if (list_cols) {
        print_values_description(bv, stdout, b2t_funcs);
        ret = EXIT_SUCCESS;
        goto cleanup;
    }

    if (preamble && (keep_preamble || header_file)) {
        char *name;
        FILE *hdrfile;
        if (!header_file) {
            hdrfile = outfile;
            name = NULL;
        } else {
            name = get_name_from_input(out_name, compress, "_headers", false, compress);
            hdrfile = out_funcs.fopen(name, "w");
            if (UNLIKELY(!hdrfile)) {
                T2_ERR("Failed to open header file");
                exit(EXIT_FAILURE);
            }
        }

        if (!extract_preamble(infile, in_funcs, hdrfile, out_funcs, offset, preamble)) {
            T2_ERR("Failed to extract preamble");
            ret = EXIT_FAILURE;
            goto cleanup;
        }

        if (header_file) {
            if (colnames) {
                out_funcs.fputs("#\n", hdrfile);
                print_values_description(bv, hdrfile, out_funcs);
            }
            if (!w_stdout) T2_FOK(stdout, "Successfully created '%s'", name);
            out_funcs.fclose(hdrfile);
            free(name);
        }
    }

    if (!json && colnames) {
        parse_binary_header2text(bv, outfile, out_funcs);
    }

    int c;
    while ((c = in_funcs.fgetc(infile)) != EOF) {
        if (UNLIKELY(in_funcs.ungetc(c, infile) != c)) {
            T2_ERR("Failed to replace '0x%02x' into '%s'", c, in_name);
            ret = EXIT_FAILURE;
            break;
        }

        // Skip BUF_DATA_SHFT
        if (UNLIKELY(in_funcs.fseek(infile, offset << 2, SEEK_CUR) < 0)) {
            T2_ERR("Failed to skip BUF_DATA_SHFT (=%" PRIu32 ")", offset);
            ret = EXIT_FAILURE;
            goto cleanup;
        }

        if (UNLIKELY(!parse_binary_func(infile, bv, outfile, compress))) {
            ret = EXIT_FAILURE;
            break;
        }
    }

cleanup:
    if (ret == EXIT_FAILURE) {
        T2_ERR("Failed to convert '%s'", in_name);
    } else if (out_name && !w_stdout) {
        T2_FOK(stdout, "Successfully converted '%s' to '%s'", in_name, out_name);
    }

    in_funcs.fclose(infile);
    out_funcs.fclose(outfile);
    bv_header_destroy(bv);
    free(out_name);

    return ret;
}
