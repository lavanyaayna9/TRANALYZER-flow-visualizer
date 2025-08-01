/*
 * p0f.c
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

#include "p0f.h"
#include <stdbool.h>


// static functions prototypes

static bool p0f_read_db(const char * const filename);


// static variables

static p0f_ssl_sig p0f_ssl_sigs[P0F_SSL_NSIG+1];


// variables from dependencies

extern sslFlow_t *sslFlow __attribute__((weak));


// Tranalyzer functions

T2_PLUGIN_INIT_WITH_DEPS("p0f", "0.9.3", 0, 9, "sslDecode");


void t2Init() {
#if ENVCNTRL > 0
    t2_env_t env[ENV_P0F_N] = {};
    t2_get_env(PLUGIN_SRCH, ENV_P0F_N, env);
    const char * const p0fSslDB = T2_ENV_VAL(P0F_SSL_DB);
#else // ENVCNTRL == 0
    const char * const p0fSslDB = P0F_SSL_DB;
#endif // ENVCNTRL

    if (UNLIKELY(!p0f_read_db(p0fSslDB))) {
        exit(EXIT_FAILURE);
    }

#if ENVCNTRL > 0
    t2_free_env(ENV_P0F_N, env);
#endif // ENVCNTRL > 0
}


binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;
    BV_APPEND_U16(bv, "p0fSSLRule"   , "p0f SSL fingerprint rule number");
    BV_APPEND_STR(bv, "p0fSSLOS"     , "p0f SSL OS fingerprint");
    BV_APPEND_STR(bv, "p0fSSLOS2"    , "p0f SSL OS fingerprint (2)");
    BV_APPEND_STR(bv, "p0fSSLBrowser", "p0f SSL browser fingerprint");
    BV_APPEND_STR(bv, "p0fSSLComment", "p0f SSL fingerprint comment");
    return bv;
}


#if BLOCK_BUF == 0
#if P0F_SSL_CIPHER  == 1 || P0F_SSL_EXT    == 1 || P0F_SSL_VER   == 1 || \
    P0F_SSL_NCIPHER == 1 || P0F_SSL_NUMEXT == 1 || P0F_SSL_FLAGS == 1
void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {
    sslFlow_t *sslFlowP = &sslFlow[flowIndex];
#else
void t2OnFlowTerminate(unsigned long flowIndex UNUSED, outputBuffer_t *buf) {
#endif

#if (P0F_SSL_CIPHER == 1 || P0F_SSL_EXT == 1)
    uint_fast16_t j;
    char str[P0F_SSL_ELEN];
#endif

    for (uint_fast16_t i = 0; i < P0F_SSL_NSIG; i++) {
        bool match = true;
        const p0f_ssl_sig s = p0f_ssl_sigs[i];
#if P0F_SSL_VER == 1
        match &= (s.version == sslFlowP->version);
#endif
#if P0F_SSL_NCIPHER == 1
        match &= (s.nciphers == sslFlowP->num_cipher);
#endif
#if P0F_SSL_NUMEXT == 1
        match &= (s.numext == sslFlowP->num_ext);
#endif
#if P0F_SSL_FLAGS == 1
        match &= (s.flags == sslFlowP->flags);
#endif

        if (!match) continue;

#if P0F_SSL_CIPHER == 1
        // ciphers
        for (j = 0; j < s.nciphers; j++) {
            if (strcmp(s.ciphers[j], "*") == 0) continue;
            snprintf(str, P0F_SSL_ELEN, "%x", sslFlowP->cipher_list[j]);
            // XXX for now if '?' is present, it is always the first character
            if (strstr(s.ciphers[j], "?")) {
                if (strlen(s.ciphers[j]) == strlen(str)) {
                    str[0] = '?';
                } else {
                    snprintf(str, P0F_SSL_ELEN, "?%x", sslFlowP->cipher_list[j]);
                }
            }

            if (strcmp(s.ciphers[j], str) != 0) {
                match = false;
                break;
            }
        }
        if (!match) continue;
#endif // P0F_SSL_CIPHER == 1

#if P0F_SSL_EXT == 1
        // extensions
        for (j = 0; j < s.numext; j++) {
            if (strcmp(s.ext[j], "*") == 0) continue;
            snprintf(str, P0F_SSL_ELEN, "%x", sslFlowP->ext_list[j]);
            // XXX for now if '?' is present, it is always the first character
            if (strstr(s.ext[j], "?")) {
                if (strlen(s.ext[j]) == strlen(str)) {
                    str[0] = '?';
                } else {
                    snprintf(str, P0F_SSL_ELEN, "?%x", sslFlowP->ext_list[j]);
                }
            }

            if (strcmp(s.ext[j], str) != 0) {
                match = false;
                break;
            }
        }
        if (!match) continue;
#endif // P0F_SSL_EXT == 1

        if (match) {
            OUTBUF_APPEND_U16(buf, s.rulenum);  // p0fSSLRule
            OUTBUF_APPEND_STR(buf, s.os);       // p0fSSLOS
            OUTBUF_APPEND_STR(buf, s.os2);      // p0fSSLOS2
            OUTBUF_APPEND_STR(buf, s.browser);  // p0fSSLBrowser
            OUTBUF_APPEND_STR(buf, s.comment);  // p0fSSLComment
            return;
        }
    }

    // no fingerprint match
    OUTBUF_APPEND_U16_ZERO(buf);   // p0fSSLRule
    OUTBUF_APPEND_STR_EMPTY(buf);  // p0fSSLOS
    OUTBUF_APPEND_STR_EMPTY(buf);  // p0fSSLOS2
    OUTBUF_APPEND_STR_EMPTY(buf);  // p0fSSLBrowser
    OUTBUF_APPEND_STR_EMPTY(buf);  // p0fSSLComment
}
#endif // BLOCK_BUF == 0


static bool p0f_read_db(const char * const filename) {
    FILE * const file = t2_fopen_in_dir(pluginFolder, filename, "r");
    if (UNLIKELY(!file)) return false;

    uint32_t i = 0;
    uint16_t maxciphers = 0, maxext = 0;

    char ciphers[SSL_MAX_CIPHER*P0F_SSL_ELEN];
    char exts[SSL_MAX_EXT*P0F_SSL_ELEN];

    size_t len;
    ssize_t read;
    char *line = NULL;
    while ((read = getline(&line, &len, file)) != -1) {

        // Skip comments and empty lines
        if (line[0] == '%' || line[0] == ' ' || line[0] == '\n' || line[0] == '\t') continue;

        if (i > P0F_SSL_NSIG) {
            i++;
            continue;
        }

        p0f_ssl_sig * const s = &p0f_ssl_sigs[i];
        sscanf(line, "%" SCNu16 "\t%" SCNx16 "\t"   // rulenum, version
                     "%" SCNu16 "\t%[^\t]"   "\t"   // nciphers, ciphers
                     "%" SCNu16 "\t%[^\t]"   "\t"   // numext, exts
                     "%" SCNx8  "\t%[^\t]"   "\t"   // flags, os
                     "%[^\t]"   "\t%[^\t]"   "\t"   // os2, browser
                     "%[^\t\n]",                    // comments
                &(s->rulenum) , &(s->version),
                &(s->nciphers), &ciphers[0],
                &(s->numext)  , &exts[0],
                &(s->flags)   , &(s->os[0]),
                &(s->os2[0])  , &(s->browser[0]),
                &(s->comment[0]));

        // max number of ciphers/extensions
        maxciphers = MAX(s->nciphers, maxciphers);
        maxext = MAX(s->numext, maxext);

        i++;

#if (P0F_SSL_CIPHER == 1 || P0F_SSL_EXT == 1)
        if (s->nciphers >= SSL_MAX_CIPHER || s->numext >= SSL_MAX_EXT) continue;
#endif

#if P0F_SSL_CIPHER == 1
        // split ciphers by ','
        if (s->nciphers > 0) {
            uint32_t j = 0;
            char *token = strtok(ciphers, ",");
            while (token) {
                t2_strcpy(s->ciphers[j], token, sizeof(s->ciphers[j]), T2_STRCPY_EXIT);
                token = strtok(NULL, ",");
                j++;
            }
        }
#endif // P0F_SSL_CIPHER == 1

#if P0F_SSL_EXT == 1
        // split extensions by ','
        if (s->numext > 0) {
            uint32_t j = 0;
            char *token = strtok(exts, ",");
            while (token) {
                t2_strcpy(s->ext[j], token, sizeof(s->ext[j]), T2_STRCPY_EXIT);
                token = strtok(NULL, ",");
                j++;
            }
        }
#endif // P0F_SSL_EXT == 1
    }

    free(line);
    fclose(file);

#if (P0F_SSL_CIPHER == 1 || P0F_SSL_EXT == 1)
    if (maxciphers >= SSL_MAX_CIPHER || maxext >= SSL_MAX_EXT) {
        T2_PERR(plugin_name, "Increase SSL_MAX_CIPHER to %" PRIu32 " and SSL_MAX_EXT to %" PRIu32 " in sslDecode.h", maxciphers+1, maxext+1);
        return false;
    }
#endif

    if (i > P0F_SSL_NSIG) {
        T2_PERR(plugin_name, "Increase P0F_SSL_NSIG to %u", i);
        return false;
    }

    return true;
}
