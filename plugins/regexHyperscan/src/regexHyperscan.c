/*
 * regexHyperscan.c
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

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <time.h>

#include "regexHyperscan.h"
#include "t2Plugin.h"
#include "memdebug.h"

#if RHS_RELOADING == 1
    #include <unistd.h>
    #include <sys/inotify.h>
#endif // RHS_RELOADING == 1

#if RHS_STREAMING == 1
    #define RHS_MODE HS_MODE_STREAM
#else // RHS_STREAMING == 0
    #define RHS_MODE HS_MODE_BLOCK
#endif // RHS_STREAMING == 1


// Structs

// set of regexes
struct regex_set_internal {
    hs_database_t *db;      // Hyperscan regexes database
    hs_scratch_t *scratch;  // Hyperscan scratch space
    char **regex_map;       // mapping from regex ID -> readable name (first column of regex file)
    bool *regex_extract;    // mapping from regex ID -> extract match with liveXtr?
    size_t count;           // number of regexes
#if RHS_RELOADING == 1
    size_t flow_count;      // number of flows associated to this regex set
                            // reference counting to know when the set can be freed
#endif // RHS_RELOADING == 1
};

// Global variables

rhs_flow_t *rhs_flows;  // array of per-flow plugin structures


// Static variables

static regex_set *set;  // currently used set of regexes

#if RHS_RELOADING == 1
static bool dynamic_reload = true;
static int inotify_fd, inotify_watch;
static char *regex_filename;
#endif // RHS_RELOADING == 1


// Tranalyzer functions

T2_PLUGIN_INIT("regexHyperscan", "0.9.3", 0, 9);


// helper functions

/**
 * @brief Removes the line return at the end of a line.
 *
 * @param  str   the string to strip.
 * @param  size  size of the string to strip.
 */
static void stripln(char *start, ssize_t *size) {
    char *end = start + *size - 1;
    while (*size > 0 && (*end == '\r' || *end == '\n')) {
        *end-- = '\0';
        --(*size);
    }
}


/**
 * @brief Split a string using a delimiter character.
 *
 * This function should be called repeatedly until it returns NULL in
 * order to split a line token by token with a char delimiter.
 * This function modifies the input string. The input string must be null-terminated.
 *
 * @param  str    the beginning of the input string to split
 * @param  delim  the delimiter character at which to split the input string
 * @return the start of next token; NULL if str was the last token
 */
static char *splitstr(char *str, char delim) {
    while (*str != delim && *str != '\0') {
        ++str;
    }
    if (*str == '\0') {
        return NULL;
    }
    *str++ = '\0';
    return str;
}


/**
 * @brief Split a string using a delimiter character starting at the end of the string.
 *
 * This function should be called repeatedly until it returns NULL in
 * order to split a line token by token with a char delimiter.
 * This function modifies the input string. The input string must be null-terminated.
 *
 * @param  str    the beginning of the input string to split
 * @param  delim  the delimiter character at which to split the input string
 * @return the start of next token; NULL if str was the last token
 */
static char *rsplitstr(char *str, char delim) {
    size_t len = strlen(str);
    char *end = str + len;
    while (*end != delim && end > str) {
        --end;
    }
    if (end == str) {
        return NULL;
    }
    *end++ = '\0';
    return end;
}


/**
 * @brief Free an array of strings (strdup or malloc) and free the array itself.
 *
 * @param array  the string array
 * @param len    number of strings stored in the array
 */
static void free_strings(char **array, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        free(array[i]);
    }
    free(array);
}


/**
 * @brief Clean and free a regex_set object.
 *
 * @param set  the set to free.
 */
static void free_regex_set(regex_set *set) {
    if (!set) {
        return;
    }
#if RHS_RELOADING == 1
    if (set->flow_count != 0) {
        T2_PWRN(plugin_name, "trying to free regex set which still has associated flows.");
    }
#endif // RHS_RELOADING == 1
    // free the regex map
    if (set->regex_map) {
        free_strings(set->regex_map, set->count);
    }
    if (set->regex_extract) {
        free(set->regex_extract);
        set->regex_extract = NULL;
    }
    // free the regex database
    if (set->db) {
        hs_free_database(set->db);
    }
    // free the scratch space
    if (set->scratch) {
        hs_free_scratch(set->scratch);
    }
    // free the set structure itself
    free(set);
}


/**
 * @brief Transforms text representation of regex flags to Hyperscan internal representation.
 */
static bool parse_flags(const char *s, unsigned int *f) {
    // set default flags
    unsigned int flags = HS_FLAG_SINGLEMATCH;
    // parse additional flags string
    while (*s) {
        switch (*s) {
            case 'i':
                flags |= HS_FLAG_CASELESS; break;
            case 'm':
                flags |= HS_FLAG_MULTILINE; break;
            case 's':
                flags |= HS_FLAG_DOTALL; break;
            case 'H':
                flags |= HS_FLAG_SINGLEMATCH; break;
            case 'V':
                flags |= HS_FLAG_ALLOWEMPTY; break;
            case '8':
                flags |= HS_FLAG_UTF8; break;
            case 'W':
                flags |= HS_FLAG_UCP; break;
            default:
                T2_PWRN(plugin_name, "invalid flag: %c", *s);
                return false;
        }
        ++s;
    }
    // flags successfully parsed;
    *f = flags;
    return true;
}


/**
 * @brief Parses a single line from the regex file.
 *
 * @param line     NULL terminated line to parse
 * @param name     where to store the regex name (1st column)
 * @param extract  should matching flows be extracted (3rd column)
 * @param regex    where to store the regex (2nd column between the /.../)
 * @param flags    where to store the flags (2nd column after the last /)
 * @return         true if line has a valid format, false otherwise.
 */
static bool parse_line(char *line, char **name, bool *extract, char **regex, unsigned int *flags) {
    char *reg = splitstr(line, '\t');
    if (!regex) {
        T2_PWRN(plugin_name, "line with only one column in regex file: %s", line);
        return false;
    }
    // check for optional 3rd column (extraction bit)
    char *ext_col = splitstr(reg, '\t');
    if (ext_col) {
        // check there isn't an additional column
        if (splitstr(ext_col, '\t')) {
            T2_PWRN(plugin_name, "line with more than three columns in regex file: %s", line);
            return false;
        }
    }
    // verify that regex starts with a /
    if (reg[0] != '/') {
        T2_PWRN(plugin_name, "invalid regex format, please check doc: %s", line);
        return false;
    }
    ++reg; // skip the slash

    // find the flags
    char *strflags = rsplitstr(reg, '/');
    if (!strflags) {
        T2_PWRN(plugin_name, "invalid regex format, please check doc: %s", line);
        return false;
    }
    // extract flags in integer form
    unsigned int intflags;
    if (!parse_flags(strflags, &intflags)) {
        T2_PWRN(plugin_name, "invalid flags, please check doc: %s", line);
        return false;
    }
    // parse the extraction bit (can only be "0" or "1");
    if (ext_col) {
        if (strlen(ext_col) != 1 || (ext_col[0] != '0' && ext_col[0] != '1')) {
            T2_PWRN(plugin_name, "invalid extraction value, please check doc: %s", line);
            return false;
        }
        *extract = ext_col[0] == '1';
    }

    // line was successfully parsed, store the extracted values.
    if (!(*name = strdup(line))) {
        T2_PWRN(plugin_name, "failed to copy regex name: %s", strerror(errno));
        return false;
    }
    if (!(*regex = strdup(reg))) {
        T2_PWRN(plugin_name, "failed to copy regex: %s", strerror(errno));
        return false;
    }
    *flags = intflags;

    return true;
}


/**
 * @brief Load regexes from a file into a set of regexes.
 *
 * Allocate memory for the returned regex_set structure. Caller has to free it with
 * the free_regex_set function.
 *
 * @param  filename  path to the file containing the regexes
 * @return a regex_set structure; NULL on error.
 */
static regex_set *load_regexes(const char *filename) {
    // open regex file
    FILE *fp = fopen(filename, "r");
    if (fp == NULL) {
        T2_PERR(plugin_name, "failed to open regex file: %s", filename);
        return NULL;
    }

    // allocate memory for the regex set structure itself
    regex_set *set = calloc(1, sizeof(*set));
    if (!set) {
        T2_PERR(plugin_name, "failed to allocate memory for regex set");
        fclose(fp);
        return NULL;
    }

    size_t allocated = 32;
    // temporarily store regexes and flags as they must all be compiled at once
    char **regexes = calloc(allocated, sizeof(*regexes));
    unsigned int *flags = calloc(allocated, sizeof(*flags));
    unsigned int *ids = calloc(allocated, sizeof(*ids));
    if (!(set->regex_map = calloc(allocated, sizeof(*set->regex_map))) ||
            !(set->regex_extract = calloc(allocated, sizeof(*set->regex_extract))) ||
            !regexes || !flags || !ids) {
        T2_PERR(plugin_name, "failed to allocate memory for regex file parsing");
        fclose(fp);
        free(regexes);
        free(flags);
        free(ids);
        free_regex_set(set);
        return NULL;
    }

    // parse each line of the regex file
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    while ((read = getline(&line, &len, fp)) != -1) {
        stripln(line, &read);
        // skip comments and empty lines
        if (strlen(line) == 0 || line[0] == '%') {
            continue;
        }

        // reallocate memory if arrays are full
        if (set->count >= allocated) {
            while (set->count >= allocated) {
                allocated *= 2;
            }

            char **tmp1 = realloc(set->regex_map, allocated * sizeof(*set->regex_map));
            bool  *tmp2 = realloc(set->regex_extract, allocated * sizeof(*set->regex_extract));
            char **tmp3 = realloc(regexes, allocated * sizeof(*regexes));
            unsigned int *tmp4 = realloc(flags, allocated * sizeof(*flags));
            unsigned int *tmp5 = realloc(ids, allocated * sizeof(*ids));
            if (!tmp1 || !tmp2 || !tmp3 || !tmp4 || !tmp5) {
                T2_PERR(plugin_name, "failed to re-allocate memory for regex file parsing");
                fclose(fp);
                free(line);
                free_strings(regexes, set->count);
                free(flags);
                free(ids);
                free_regex_set(set);

                free(tmp1);
                free(tmp2);
                free(tmp3);
                free(tmp4);
                free(tmp5);

                return NULL;
            }

            // successful realloc
            set->regex_map = tmp1;
            set->regex_extract = tmp2;
            regexes = tmp3;
            flags = tmp4;
            ids = tmp5;
        }

        // parse current line of regex file
        if (!parse_line(line, &set->regex_map[set->count], &set->regex_extract[set->count],
                &regexes[set->count], &flags[set->count])) {
            continue; // invalid line format, skip to next line
        }

        ids[set->count] = set->count;
        ++set->count;
    }
    // parsing of regex file done

    free(line);
    fclose(fp);

    // if regex file is empty, return a valid set but without database or scratch space
    size_t count = set->count;
    if (count == 0) {
        T2_PINF(plugin_name, "regex file did not contain any valid regex");
        // free temporary buffers
        free(regexes);
        free(flags);
        free(ids);

        return set;
    }

    // compile regex set and record compilation time
    hs_database_t *db;
    hs_compile_error_t *comp_err;
    clock_t start = clock();
    hs_error_t err = hs_compile_multi((const char *const *)regexes, flags, ids, count,
            RHS_MODE, NULL, &db, &comp_err);
    clock_t end = clock();

    // check for compilation errors
    if (err != HS_SUCCESS) {
        if (comp_err->expression < 0) {
            T2_PERR(plugin_name, "compilation error: %s", comp_err->message);
        } else {
            T2_PERR(plugin_name, "error in pattern: %s\n"
                    "      compilation error: %s", regexes[comp_err->expression], comp_err->message);
        }
        hs_free_compile_error(comp_err);

        // will return NULL at the end of the function
        free_regex_set(set);
        set = NULL;
    } else {
        double duration = (double)(end - start) / CLOCKS_PER_SEC;
        T2_PINF(plugin_name, "successfully compiled %zu regexes in %.03f seconds", count, duration);
        set->db = db;
    }

    // allocate memory for scratch space
    if (set && (err = hs_alloc_scratch(set->db, &set->scratch)) != HS_SUCCESS) {
        T2_PERR(plugin_name, "failed to allocate scratch space");
        free_regex_set(set);
        set = NULL;
    }

    // free temporary buffers
    free_strings(regexes, count);
    free(flags);
    free(ids);

    return set;
}


/**
 * @brief Match event handler: called each time Hyperscan finds a match.
 *
 * https://intel.github.io/hyperscan/dev-reference/api_files.html#c.match_event_handler
 *
 */
static int on_match(unsigned int id, unsigned long long from UNUSED,
                    unsigned long long to UNUSED,
                    unsigned int flags UNUSED, void *context) {
    // the context provided when parsing a packet is its associated flow structure
    rhs_flow_t *const rhs_flow = (rhs_flow_t *const)context;

    // check this regex already matched previously on this flow.
#if RHS_STREAMING != 1
    // NOTE: if the code is modified so the stream is restarted in the middle of a flow
    // (TCP packet drop for instance), this check should also be done if RHS_STREAMING == 1
    for (uint16_t i = 0; i < rhs_flow->count; ++i) {
        if (rhs_flow->matches[i] == id) {
            return 0;
        }
    }
#endif // RHS_STREAMING != 1

    // check if flow should be extracted
    if (rhs_flow->set && rhs_flow->set->regex_extract[id]) {
        flow_t * const t2flow = &flows[rhs_flow->flow_index];
        t2flow->status |= LIVEXTR;
    #if RHS_EXTRACT_OPPOSITE == 1
        // also extract opposite flow
        if (FLOW_HAS_OPPOSITE(t2flow)) {
            flows[t2flow->oppositeFlowIndex].status |= LIVEXTR;
        }
    #endif // RHS_EXTRACT_OPPOSITE == 1
    }

    // check that we have space to store current match
    if (rhs_flow->count >= RHS_MAX_FLOW_MATCH) {
        T2_PWRN(plugin_name, "RHS_MAX_FLOW_MATCH is too small, some matches were discarded");
        return 1; // do not continue parsing the stream / packet
    }
    // store match
    rhs_flow->matches[rhs_flow->count++] = id;
    return 0;
}


#if RHS_RELOADING == 1
/**
 * @brief Verifies if the regex file in the plugin folder was modified.
 *
 * @return  true if no modification or successful reload; false on error
 */
static bool check_regex_change() {
    bool file_moved = false;
    bool do_reload = false;

    // read all available events
    struct inotify_event event;
    while (read(inotify_fd, &event, sizeof(event)) != -1) {
        //debug_print("new inotify event: mask = 0x%08x", event.mask);
        // if file was remove or close, re-initialize inotify
        if (event.mask & IN_MOVE_SELF) {
            file_moved = true;
            do_reload = true;
        } else if (event.mask & IN_IGNORED) {
            file_moved = true;
        } else if (event.mask & IN_CLOSE_WRITE) {
            do_reload = true;
        }

        // skip optional name if present
        if (event.len > 0 && lseek(inotify_fd, event.len, SEEK_CUR) == -1) {
            T2_PWRN(plugin_name, "Failed to skip inotify event name");
            file_moved = true;
        }
    }

    // check the returned error
    switch (errno) {
        case EAGAIN:
            // expected result when file was not modified
            break;
        default:
            T2_PWRN(plugin_name, "Unexpected read error: %s", strerror(errno));
            break;
    }

    // if file was moved, re-initialize inotify
    if (file_moved) {
        //debug_print("file was moved, re-initialize inotify");
        close(inotify_fd);
        // wait until file is moved back to original location
        FILE *file;
        while ((file = fopen(regex_filename, "r")) == NULL) {
            usleep(10000);
        }
        fclose(file);
        // re-initialize inotify fd
        if ((inotify_fd = inotify_init1(IN_NONBLOCK)) < 0) {
            T2_PWRN(plugin_name, "failed to re-init inotify, dynamic reload disabled");
            return false;
        }
        // ugly hack because of vim race condition:
        // file might be here during above test, but get moved by vim in temp location during a few
        // milliseconds before being moved back to original location
        uint8_t try = 0;
        while ((inotify_watch = inotify_add_watch(inotify_fd, regex_filename, IN_CLOSE_WRITE | IN_MOVE_SELF)) < 0) {
            usleep(10000);
            if (++try > 100) {
                T2_PWRN(plugin_name, "failed to add inotify watch, dynamic reload disabled");
                return false;
            }
        }
    }

    // regex file was modified, let's reload it
    if (do_reload) {
        T2_PINF(plugin_name, "reloading regex file: %s", regex_filename);
        regex_set* new_set;
        // ugly hack because of vim race condition:
        // file might be here during above test, but get moved by vim in temp location during a few
        // milliseconds before being moved back to original location
        uint8_t try = 0;
        while ((new_set = load_regexes(regex_filename)) == NULL) {
            T2_PINF(plugin_name, "last error was not fatal, trying again in 10 ms");
            usleep(10000);
            if (++try > 100) {
                T2_PWRN(plugin_name, "failed to reload regexes, dynamic reloading disabled");
                return false;
            }
        }
        // free previous regex set and replace it with newly loaded one
        if (set->flow_count == 0) {
            free_regex_set(set);
        }
        set = new_set;
    }

    return true;
}
#endif // RHS_RELOADING == 1


// Tranalyzer functions


void t2Init() {
    // get the path to the regex file
    const size_t plen = pluginFolder_len;
    const size_t len = plen + sizeof(RHS_REGEX_FILE);
    if (len > MAX_FILENAME_LEN) {
        T2_PFATAL(plugin_name, "regex file path too long");
    }

    char filename[len+1];
    memcpy(filename, pluginFolder, plen);
    memcpy(filename + plen, RHS_REGEX_FILE, sizeof(RHS_REGEX_FILE));

    // load regexes from file
    if (!(set = load_regexes(filename))) {
        exit(EXIT_FAILURE);
    }

#if RHS_RELOADING == 1
    // store filename in global variable for reload
    if (!(regex_filename = strdup(filename))) {
        T2_PFATAL(plugin_name, "failed to allocate memory for regex filename");
    }

    // watch for changes in regex file
    if ((inotify_fd = inotify_init1(IN_NONBLOCK)) < 0) {
        T2_PFATAL(plugin_name, "failed to init inotify: %s", strerror(errno));
    }

    if ((inotify_watch = inotify_add_watch(inotify_fd, filename, IN_CLOSE_WRITE | IN_MOVE_SELF)) < 0) {
        T2_PFATAL(plugin_name, "failed to add inotify watch: %s", strerror(errno));
    }
#endif // RHS_RELOADING == 1

    // allocate struct for all flows and initialize to 0
    T2_PLUGIN_STRUCT_NEW(rhs_flows);
}


binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;

    // identifier (from 1st column of regex file) of regexes matching the flow
    BV_APPEND_STR_R(bv, "hsregexes", "Hyperscan regex matches");

    return bv;
}


void t2OnNewFlow(packet_t *packet UNUSED, unsigned long flowIndex) {
    rhs_flow_t *rhs_flow = &rhs_flows[flowIndex];
    memset(rhs_flow, 0, sizeof(*rhs_flow)); // set everything to 0

#if RHS_STREAMING == 1
    hs_error_t err = hs_open_stream(set->db, 0, &rhs_flow->stream);
    if (err != HS_SUCCESS) {
        T2_PERR(plugin_name, "failed to open stream");
        terminate();
    }
#endif // RHS_STREAMING == 1

#if RHS_RELOADING == 1
    // associate flow with current set of regexes
    rhs_flow->set = set;
    ++set->flow_count;
#endif // RHS_RELOADING == 1

    rhs_flow->flow_index = flowIndex;
}


void t2OnLayer4(packet_t *packet, unsigned long flowIndex) {
    rhs_flow_t *rhs_flow = &rhs_flows[flowIndex];

    // do not do anything if packet has no payload or if flow scan is terminated
    if (packet->snapL7Len == 0 || rhs_flow->terminated) {
        return;
    }

#if RHS_STREAMING == 1
    // only process packets which are in the correct order
    if (packet->l4Proto == L3_TCP) {
        const uint32_t seq = ntohl(TCP_HEADER(packet)->seq);
        if (seq <= rhs_flow->last_seq) {
            return;
        }
        rhs_flow->last_seq = seq;
    }
#endif // RHS_STREAMING == 1

#if RHS_RELOADING == 1
    // check if regex file was modified
    if (dynamic_reload) {
        if (!check_regex_change()) {
            dynamic_reload = false;
        }
    }
    // load the correct regex set when reloading is activated
    regex_set *local_set = set;
    // use set associated to flow instead of global set
    if (rhs_flow->set) {
        local_set = rhs_flow->set;
    }
#else // RHS_RELOADING == 0
    regex_set *local_set = set;
#endif // RHS_RELOADING == 1

    // do not do anything if regex set is empty
    if (local_set->count == 0) {
        return;
    }

#if RHS_STREAMING == 1
    hs_error_t err = hs_scan_stream(rhs_flow->stream, (const char *)packet->l7HdrP,
                                    packet->snapL7Len, 0, local_set->scratch, on_match, rhs_flow);
#else // RHS_STREAMING == 0
    hs_error_t err = hs_scan(local_set->db, (const char *)packet->l7HdrP, packet->snapL7Len,
                             0, local_set->scratch, on_match, rhs_flow);
#endif //RHS_STREAMING == 1
    if (err == HS_SCAN_TERMINATED) {
        rhs_flow->terminated = true;
    } else if (err != HS_SUCCESS) {
        T2_PERR(plugin_name, "failed to scan stream / packet");
        terminate();
    }
}


void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {
    rhs_flow_t *rhs_flow = &rhs_flows[flowIndex];

    regex_set *local_set = set;
#if RHS_RELOADING == 1
    // use set associated to flow instead of global set
    if (rhs_flow->set) {
        local_set = rhs_flow->set;
    }
#endif // RHS_RELOADING == 1

#if RHS_STREAMING == 1
    hs_error_t err = hs_close_stream(rhs_flow->stream, local_set->scratch, on_match, rhs_flow);
    if (err != HS_SUCCESS) {
        T2_PFATAL(plugin_name, "failed to close stream");
    }
#endif // RHS_STREAMING == 1

    const uint32_t count = rhs_flow->count;
    OUTBUF_APPEND_NUMREP(buf, count);
    // output all matches
    for (uint_fast32_t i = 0; i < count; ++i) {
        const char * const match = local_set->regex_map[rhs_flow->matches[i]];
        OUTBUF_APPEND_STR(buf, match);
    }

#if RHS_RELOADING == 1
    if (rhs_flow->set) {
        --rhs_flow->set->flow_count;
        // if the set has no more associated flows and is not the latest one: free it
        if (rhs_flow->set->flow_count == 0 && rhs_flow->set != set) {
            free_regex_set(rhs_flow->set);
        }
    }
#endif // RHS_RELOADING == 1
}


void t2Finalize() {
    // free global variables
    free_regex_set(set);
    // free the flow structures
    free(rhs_flows);

#if RHS_RELOADING == 1
    free(regex_filename);
    // clean inotify file descriptors
    inotify_rm_watch(inotify_fd, inotify_watch);
    close(inotify_fd);
#endif // RHS_RELOADING == 1
}
