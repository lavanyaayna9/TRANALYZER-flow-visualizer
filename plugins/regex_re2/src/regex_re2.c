/*
 * regex_re2.c
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
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifndef __APPLE__
#include <sys/inotify.h>
#endif // __APPLE__

#include "regex_re2.h"
#include "cre2.h"
#include "murmur.h"
#include "t2Plugin.h"

#define RE2_DEBUG (DEBUG | RE2_DEBUG_MESSAGES)

#if RE2_DEBUG != 0
/** if DEBUG is enabled, print file name, line and function + message*/
#define debug_print(format, args...) T2_PINF(plugin_name, format, ##args)
#else // RE2_DEBUG == 0
/** on DEBUG disabled, just ignore */
#define debug_print(format, args...)
#endif // RE2_DEBUG != 0

// Structs

// set of regexes
typedef struct {
#if RE2_MERGE == 1
    cre2_set *set;          // the wrapped RE2::Set object containing all the regexes
#else // RE2_MERGE == 0
    cre2_regexp_t** regexes;
#endif // RE2_MERGE == 1
    char **regex_map;       // mapping from regex ID -> readable name (first column of regex file)
    uint32_t *regex_hashes; // mapping from regex ID -> hash(readable name)
    size_t count;           // needed in order to free the strings in regex_map
} regex_set;


// Global variables

re2_flow_t *re2_flows;

// Static variables

static regex_set *set; // currently used set of regexes
static uint64_t num_match;
static uint64_t num_flows_match;

#if RE2_RELOADING == 1
static bool dynamic_reload = true;
static int inotify_fd, inotify_watch;
static char *regex_filename;
#endif // RE2_RELOADING


// Tranalyzer functions

T2_PLUGIN_INIT("regex_re2", "0.9.3", 0, 9);


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
 * @brief Append new regex match to a dynamic buffer.
 *
 * @param  buffer   the dynamic_buffer structure to which we append the new match
 * @param  name     the regex name to append
 * @return whether or not everything went fine
 */
static bool dynamic_buffer_append(dynamic_buffer *buffer, char *name) {
    // first check if the buffer was initialized
    if (buffer->allocated == 0) {
        const size_t alloc_default_size = 64;
        if (!(buffer->buffer = t2_malloc(alloc_default_size * sizeof(*buffer->buffer)))) {
            T2_PERR(plugin_name, "failed to allocated memory for dynamic buffer");
            return false;
        }
        buffer->allocated = alloc_default_size;
    }

    // compute the new size needed to append the name in the buffer
    const size_t len = strlen(name) + 1;
    const size_t new_size = buffer->size + len;

    // reallocate the memory in the buffer if necessary
    if (new_size >= buffer->allocated) {
        while (new_size >= buffer->allocated) {
            buffer->allocated *= 2;
        }
        char* tmp;
        if (!(tmp = realloc(buffer->buffer, buffer->allocated * sizeof(*buffer->buffer)))) {
            T2_PERR(plugin_name, "failed to re-allocated memory for dynamic buffer");
            free(buffer->buffer);
            buffer->buffer = NULL;
            return false;
        }
        buffer->buffer = tmp;
    }

    // append the name to the buffer
    memcpy(&buffer->buffer[buffer->size], name, len);
    buffer->size += len;
    ++buffer->count;

    return true;
}

/**
 * @brief Check if the buffer contains a string
 *
 * @param  buffer   a dynamic_buffer structure
 * @param  str      string to search in buffer
 * @return whether or not the string was found
 */
static bool str_in_buffer(dynamic_buffer *buffer, char *str) {
    return memmem(buffer->buffer, buffer->size, str, strlen(str)) != NULL;
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
#if RE2_MERGE == 1
    // destroy the regex set object
    if (set->set) {
        cre2_set_delete(set->set);
    }
#else // RE2_MERGE == 0
    if (set->regexes) {
        for (size_t i = 0; i < set->count; ++i) {
            cre2_delete(set->regexes[i]);
        }
        free(set->regexes);
    }
#endif // RE2_MERGE == 1
    // free the regex map
    if (set->regex_map) {
        for (size_t i = 0; i < set->count; ++i) {
            free(set->regex_map[i]);
        }
        free(set->regex_map);
    }
    // free regex hashes
    if (set->regex_hashes) {
        free(set->regex_hashes);
    }
    // free the set structure itself
    free(set);
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
    FILE *fp = fopen(filename, "r");
    if (fp == NULL) {
        T2_PERR(plugin_name, "couldn't open regex file: %s", filename);
        return NULL;
    }

    regex_set *set = t2_calloc(1, sizeof(*set));
    if (!set) {
        T2_PERR(plugin_name, "couldn't allocate memory for regex set");
        fclose(fp);
        return NULL;
    }

    cre2_options_t *opt = cre2_opt_new();
    cre2_opt_set_encoding(opt, CRE2_Latin1);
    cre2_opt_set_never_capture(opt, 1);
#if RE2_MERGE == 1
    cre2_opt_set_max_mem(opt, RE2_MAX_MEMORY);

    // initialize set of regexes
    if (!(set->set = cre2_set_new(opt, CRE2_UNANCHORED))) {
        T2_PERR(plugin_name, "failed to create regex set");
        fclose(fp);
        free_regex_set(set);
        return NULL;
    }
#endif // RE2_MERGE == 1

    int mapping_size = 64;
    if (!(set->regex_map = t2_calloc(mapping_size, sizeof(*set->regex_map))) ||
        #if RE2_MERGE != 1
           !(set->regexes = t2_calloc(mapping_size, sizeof(*set->regexes))) ||
        #endif // RE2_MERGE != 1
           !(set->regex_hashes = t2_calloc(mapping_size, sizeof(*set->regex_hashes)))) {
        T2_PERR(plugin_name, "couldn't allocate memory for regex mapping or hashes");
        fclose(fp);
        free_regex_set(set);
        return NULL;
    }

    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    while ((read = getline(&line, &len, fp)) != -1) {
        stripln(line, &read);
        // skip comments and empty lines
        if (strlen(line) == 0 || line[0] == '%') {
            continue;
        }
        char *regex = splitstr(line, '\t');
        if (!regex) {
            T2_PWRN(plugin_name, "line with only one column in regex file: %s", line);
            continue;
        }
        // check there isn't an additional column
        if (splitstr(regex, '\t')) {
            T2_PWRN(plugin_name, "line with more than two columns in regex file: %s", line);
            continue;
        }
        // add the regex to the set
    #if RE2_MERGE == 1
        int index = cre2_set_add_simple(set->set, regex);
    #else // RE2_MERGE == 0
        int index = set->count;
        cre2_regexp_t *re = cre2_new(regex, (int)strlen(regex), opt);
        if (cre2_error_code(re) != CRE2_NO_ERROR) {
            cre2_delete(re);
            index = -1;
        }
    #endif // RE2_MERGE == 1
        if (index < 0) {
            T2_PWRN(plugin_name, "regex with invalid format: %s", line);
        } else if ((size_t)index != set->count) {
            T2_PWRN(plugin_name, "cre2_set_add_simple returned non consecutive regex indices.");
        } else {
            // check if we need to increase the set size
            if (index >= mapping_size) {
                while (index >= mapping_size) {
                    mapping_size *= 2;
                }
                char **tmp1;
                uint32_t *tmp2;
            #if RE2_MERGE != 1
                char **tmp3;
            #endif // RE2_MERGE != 1
                // reallocate memory for regex_map and hashes
                if (!(tmp1 = realloc(set->regex_map, mapping_size * sizeof(*set->regex_map))) ||
                    #if RE2_MERGE != 1
                        !(tmp3 = realloc(set->regexes, mapping_size * sizeof(*set->regexes))) ||
                    #endif // RE2_MERGE != 1
                        !(tmp2 = realloc(set->regex_hashes, mapping_size * sizeof(*set->regex_hashes)))) {
                    T2_PERR(plugin_name, "couldn't re-allocate memory for regex mapping or hashes");
                    fclose(fp);
                    free(line);
                    free_regex_set(set);
                    return NULL;
                }
                set->regex_map = tmp1;
                set->regex_hashes = tmp2;
            }
            // add new regex name
            if (!(set->regex_map[index] = strdup(line))) {
                T2_PERR(plugin_name, "couldn't allocate memory for regex name");
                fclose(fp);
                free(line);
                free_regex_set(set);
                return NULL;
            }
            // compute hash of regex name
            set->regex_hashes[index] = murmur3_32(line, strlen(line), 0);

        #if RE2_MERGE != 1
            // add regex to list
            set->regexes[index] = re;
        #endif // RE2_MERGE != 1

            ++set->count;
        }
    }

    free(line);
    fclose(fp);

#if RE2_MERGE == 1
    // compile the regexes
    if (!cre2_set_compile(set->set)) {
        T2_PERR(plugin_name, "couldn't compile the set of regexes");
        free_regex_set(set);
        return NULL;
    }
#endif // RE2_MERGE == 1

#if VERBOSE > 0
    T2_PINF(plugin_name, "%zu regexes loaded", set->count);
#endif // VERBOSE > 0

    // delete the RE2::Options object
    cre2_opt_delete(opt);

    return set;
}

#if RE2_RELOADING == 1
static bool check_regex_change() {
    bool file_moved = false;
    bool do_reload = false;

    // read all available events
    struct inotify_event event;
    while (read(inotify_fd, &event, sizeof(event)) != -1) {
        debug_print("new inotify event: mask = 0x%08" B2T_PRIX32, event.mask);
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
            T2_PWRN(plugin_name, "Unexpected read error: %i", errno);
            perror("");
            break;
    }

    // if file was moved, re-initialize inotify
    if (file_moved) {
        debug_print("file was moved, re-initialize inotify");
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
            if (try++ > 100) {
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
            if (try++ > 100) {
                T2_PWRN(plugin_name, "failed to reload regexes, dynamic reloading disabled");
                return false;
            }
        }
        // free previous regex set and replace it with newly loaded one
        free_regex_set(set);
        set = new_set;
    }

    return true;
}
#endif // RE2_RELOADING

/*
 * Checks if a regex was not already matching previous packets in the flow. Add it if new.
 * Note: ideally should be re-implemented with an hash-set
 */
void add_match_to_flow(int match_index, re2_flow_t *flow) {
    char* match = set->regex_map[match_index];
    uint32_t hash = set->regex_hashes[match_index];
    for (int j = 0; j < flow->match_count; ++j) {
        if (flow->matches[j] == hash && str_in_buffer(&flow->buffer, match)) {
            return;
        }
    }
    // if match is a new result, add it to this flow matches
    // check if the match array of this flow is full
    if (flow->match_count >= RE2_MAX_MATCH_PER_FLOW) {
        T2_PWRN(plugin_name, "RE2_MAX_MATCH_PER_FLOW is too small, some matches were discarded");
        return;
    }
    flow->matches[flow->match_count] = hash;
    dynamic_buffer_append(&flow->buffer, match);
    ++flow->match_count;
}


// Tranalyzer functions


void t2Init() {
    // allocate struct for all flows and initialize to 0
    T2_PLUGIN_STRUCT_NEW(re2_flows);

    // get the path to the regex file
    char filename[MAX_FILENAME_LEN];
    t2_build_filename(filename, sizeof(filename), pluginFolder, RE2_REGEX_FILE, NULL);

#if RE2_RELOADING == 1
    // store filename in global variable for reload
    if (!(regex_filename = strdup(filename))) {
        T2_PFATAL(plugin_name, "couldn't allocate memory for regex filename");
    }
#endif // RE2_RELOADING

    // load regexes from file
    if (!(set = load_regexes(filename))) {
        exit(EXIT_FAILURE);
    }

#if RE2_RELOADING == 1
    // watch for changes in regex file
    if ((inotify_fd = inotify_init1(IN_NONBLOCK)) < 0) {
        T2_PFATAL(plugin_name, "failed to init inotify");
    }

    if ((inotify_watch = inotify_add_watch(inotify_fd, filename, IN_CLOSE_WRITE | IN_MOVE_SELF)) < 0) {
        T2_PERR(plugin_name, "failed to add inotify watch");
        perror("");
        exit(EXIT_FAILURE);
    }
#endif // RE2_RELOADING
}


binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;

    // identifier (from 1st column of regex file) of regexes matching the flow
    BV_APPEND_STR_R(bv, "re2match", "re2 regex matches");

    return bv;
}


void t2OnNewFlow(packet_t* packet UNUSED, unsigned long flowIndex) {
    re2_flow_t *re2_flow = &re2_flows[flowIndex];
    memset(re2_flow, 0, sizeof(*re2_flow)); // set everything to 0
}


void t2OnLayer4(packet_t* packet, unsigned long flowIndex) {
#if RE2_RELOADING == 1
    // check if regex file was modified
    if (dynamic_reload) {
        if (!check_regex_change()) {
            dynamic_reload = false;
        }
    }
#endif // RE2_RELOADING

    re2_flow_t *flow = &re2_flows[flowIndex];
    size_t size = (size_t) packet->snapL7Len;
    // nothing to do if there is no payload or if the maximum regex matches per flow has
    // already been reached.
    if (size == 0 || flow->match_count >= RE2_MAX_MATCH_PER_FLOW) {
        return;
    }

    const char * const payload = (const char * const)packet->l7HdrP;
#if RE2_MERGE == 1
    int matches[RE2_MAX_MATCH_PER_PACKET]; // temp buffer to store per packet matches
    int count = cre2_set_match(set->set, payload, size, matches, RE2_MAX_MATCH_PER_PACKET);
    if (count < 0) {
        T2_PWRN(plugin_name, "cre2_set_match error");
        return;
    }
    if (count == 0) {
        return;
    }
    // check if RE2_MAX_MATCH_PER_PACKET is big enough
    if (count > RE2_MAX_MATCH_PER_PACKET) {
        T2_PWRN(plugin_name, "RE2_MAX_MATCH_PER_PACKET is too small, some matches were discarded");
        count = RE2_MAX_MATCH_PER_PACKET;
    }
    for (int i = 0; i < count; ++i) {
        add_match_to_flow(matches[i], flow);
    }
#else // RE2_MERGE == 0
    cre2_string_t input = {
        .data   = payload,
        .length = size
    };
    for (size_t i = 0; i < set->count; ++i) {
        if (cre2_partial_match_re(set->regexes[i], &input, NULL, 0)) {
            add_match_to_flow(i, flow);
        }
    }
#endif // RE2_MERGE == 1
}


void t2PluginReport(FILE *stream) {
    T2_FPLOG_NUM(stream, plugin_name, "Number of signatures matched", num_match);
    T2_FPLOG_NUMP(stream, plugin_name, "Number of flows with matched signatures", num_flows_match, totalFlows);
}


void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {
    re2_flow_t *flow = &re2_flows[flowIndex];
    // number of matches
    const uint32_t match_count = flow->buffer.count;
    num_match += match_count;
    OUTBUF_APPEND_NUMREP(buf, match_count);
    // output all matches
    if (match_count > 0 && flow->buffer.size > 0 && flow->buffer.buffer) {
        num_flows_match++;
        outputBuffer_append(buf, flow->buffer.buffer, flow->buffer.size);
        // free buffer
        free(flow->buffer.buffer);
    }
}


void t2Finalize() {
    // free global variables
    free_regex_set(set);
    // free the flow structures
    free(re2_flows);
#if RE2_RELOADING == 1
    if (regex_filename) {
        free(regex_filename);
    }
    // clean inotify file descriptors
    inotify_rm_watch(inotify_fd, inotify_watch);
    close(inotify_fd);
#endif // RE2_RELOADING
}
