/*
 * binSink.c
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

#include "binSink.h"

#include <errno.h>  // for errno

#if BFS_GZ_COMPRESS == 1
#include "gz2txt.h"
#endif // BFS_GZ_COMPRESS == 0


#if BLOCK_BUF == 0

// Global Plugin Variables
static b2t_func_t funcs;
static binary_header_t *header;
static char bin_filename[MAX_FILENAME_LEN+1];

#if BFS_SFS_SPLIT == 1
// -W option
static uint64_t oFileNum, oFileLn;
static uint64_t binfIndex;
static char *oFileNumP;
#endif // BFS_SFS_SPLIT == 1

#if BFS_GZ_COMPRESS == 1
static gzFile outputFile;
#else // BFS_GZ_COMPRESS == 0
static FILE *outputFile;
#endif // BFS_GZ_COMPRESS == 0

#endif // BLOCK_BUF == 0


// Tranalyzer Plugin functions

T2_PLUGIN_INIT("binSink", "0.9.3", 0, 9);


void t2Init() {

#if BLOCK_BUF == 1
    T2_PWRN(plugin_name, "BLOCK_BUF is set in 'tranalyzer.h', no flow file will be produced");
#else // BLOCK_BUF == 0

#if ENVCNTRL > 0
    t2_env_t env[ENV_BFS_N] = {};
    t2_get_env(PLUGIN_SRCH, ENV_BFS_N, env);
    const char * const suffix = T2_ENV_VAL(BFS_FLOWS_SUFFIX);
#else // ENVCNTRL == 0
    const char * const suffix = BFS_FLOWS_SUFFIX;
#endif // ENVCNTRL

#if BFS_GZ_COMPRESS == 1
    funcs = b2t_funcs_gz;
#else // BFS_GZ_COMPRESS == 0
    funcs = b2t_funcs;
#endif // BFS_GZ_COMPRESS == 0

    // setup output file names
    if (capType & WSTDOUT) {
#if BFS_GZ_COMPRESS == 0
        outputFile = stdout;
#else // BFS_GZ_COMPRESS == 1
        if (UNLIKELY(!(outputFile = gzdopen(fileno(stdout), "w")))) {
            T2_PFATAL(plugin_name, "Failed to open compressed stream: %s", strerror(errno));
        }
#endif // BFS_GZ_COMPRESS == 1
    } else {
        const size_t blen = baseFileName_len;
        const size_t slen = strlen(suffix);
        size_t len = blen + slen + 1;
#if BFS_GZ_COMPRESS == 1
        len += sizeof(GZ_SUFFIX) - 1;
#endif
        if (UNLIKELY(len > sizeof(bin_filename))) {
            T2_PFATAL(plugin_name, "filename too long");
        }

        memcpy(bin_filename, baseFileName, blen+1);
        memcpy(bin_filename + blen, suffix, slen+1);
#if BFS_GZ_COMPRESS == 1
        memcpy(bin_filename + blen + slen, GZ_SUFFIX, sizeof(GZ_SUFFIX));
#endif

#if BFS_SFS_SPLIT == 1
        if (capType & OFILELN) {
            binfIndex = 0;
            oFileLn = (uint64_t)oFragFsz;
            oFileNumP = bin_filename + strlen(bin_filename);
            oFileNum = oFileNumB;
            sprintf(oFileNumP, "%" PRIu64, oFileNum);
        }
#endif // BFS_SFS_SPLIT == 1

        // open flow output file
        if (UNLIKELY(!(outputFile = funcs.fopen(bin_filename, "w")))) {
            T2_PFATAL(plugin_name, "Failed to open file '%s' for writing: %s", bin_filename, strerror(errno));
        }
    }

    // generate and write header in flow file
    // build binary header from binary values
    header = build_header(main_header_bv);

    uint32_t * const hdr = header->header;

#if BUF_DATA_SHFT > 0
    const uint32_t hdrlen = header->length << 2;
    hdr[0] = hdrlen;
#if BUF_DATA_SHFT > 1
    hdr[1] = 0;
    hdr[1] = Checksum32(hdr, hdrlen-4);
#endif
#endif // BUF_DATA_SHFT > 0

#if BFS_GZ_COMPRESS == 1
    gzwrite(outputFile, hdr, sizeof(uint32_t)*header->length);
#else // BFS_GZ_COMPRESS == 0
    fwrite(hdr, sizeof(uint32_t), header->length, outputFile);
#endif // BFS_GZ_COMPRESS == 0

#if ENVCNTRL > 0
    t2_free_env(ENV_BFS_N, env);
#endif // ENVCNTRL > 0

#endif // BLOCK_BUF == 0
}


// If BLOCK_BUF == 1, the plugin does not produce any output.
// All the code below is therefore not activated.


#if BLOCK_BUF == 0

void t2BufferToSink(outputBuffer_t *buf, binary_value_t *bv UNUSED) {

    char * const sbuf = buf->buffer - BUFFER_DATAP;
    const uint32_t buflen = buf->pos + BUFFER_DATAP;

#if BUF_DATA_SHFT > 0
    uint32_t * const buf32 = (uint32_t*)sbuf;
    buf32[0] = buf->pos;
#if BUF_DATA_SHFT > 1
    buf32[1] = 0;
    buf32[1] = Checksum32(buf32, buflen);
#endif
#endif // BUF_DATA_SHFT > 0

#if BFS_GZ_COMPRESS == 1
    gzwrite(outputFile, sbuf, buflen);
#else // BFS_GZ_COMPRESS == 0
    fwrite(sbuf, sizeof(*sbuf), buflen, outputFile);
#endif // BFS_GZ_COMPRESS == 0

#if BFS_SFS_SPLIT == 1
    if (capType & OFILELN) {
        const uint64_t offset = ((capType & WFINDEX) ? ++binfIndex : (uint64_t)funcs.ftell(outputFile));
        if (offset >= oFileLn) {
            funcs.fclose(outputFile);

            oFileNum++;
            sprintf(oFileNumP, "%" PRIu64, oFileNum);

            if (UNLIKELY((outputFile = funcs.fopen(bin_filename, "w")) == NULL)) {
                T2_PERR(plugin_name, "Failed to open file '%s' for writing: %s", bin_filename, strerror(errno));
                exit(EXIT_FAILURE);
            }

            // write the header
#if BFS_GZ_COMPRESS == 1
            gzwrite(outputFile, header->header, sizeof(uint32_t)*header->length);
#else // BFS_GZ_COMPRESS == 0
            fwrite(header->header, sizeof(uint32_t), header->length, outputFile);
#endif // BFS_GZ_COMPRESS == 0
            binfIndex = 0;
        }
    }
#endif // BFS_SFS_SPLIT == 1
}


void t2Finalize() {
    if (LIKELY(header != NULL)) {
        free(header->header);
        free(header);
    }

    if (LIKELY(outputFile != NULL)) funcs.fclose(outputFile);
}

#endif // BLOCK_BUF == 0
