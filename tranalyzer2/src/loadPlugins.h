/*
 * loadPlugins.h
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

#ifndef T2_LOADPLUGINS_H_INCLUDED
#define T2_LOADPLUGINS_H_INCLUDED

#include <stdint.h>        // for uint8_t, uint16_t
#include <stdio.h>         // for FILE

#include "binaryValue.h"   // for binary_value_t
#include "outputBuffer.h"  // for outputBuffer_t
#include "packet.h"        // for packet_t
#include "tranalyzer.h"    // for USE_T2BUS, PLUGIN_REPORT, REPORT_HIST


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define USE_PLLIST   1 // Behavior of -b option (plugin loading list)
                       //   0: disable -b option and load all plugins from the plugin folder,
                       //   1: only load plugins present in the list (whitelist),
                       //   2: do not load plugins present in the list (blacklist)

#define PLLIST "plugins.txt" // default filename for plugin white-/black-list (-b option)

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// Current (max) version of plugin architecture
#define PL_V_MAJOR_MAX 0
#define PL_V_MINOR_MAX 9

// Supported (min) version of plugin architecture
#define PL_V_MAJOR_MIN 0 // when changed to a value >= 1, uncomment test in loadPlugins.c:187
#define PL_V_MINOR_MIN 9

#define PL_PATH_MAXLEN     512 // maximum length of plugin path
#define PL_DEPS_MAXLEN     256 // maximum length of plugin dependencies
#define PL_NAME_MAXLEN      32 // maximum length of plugin name
#define PL_VERSION_MAXLEN   16 // maximum length of plugin version

// State for monitoring callback
#define T2_MON_PRI_HDR    0 // print the header
#define T2_MON_PRI_VAL    1 // print the values to monitor
#define T2_MON_PRI_REPORT 2 // print the report
//#define T2_MON_UPDATE_VAL 3 // update the values to monitor (diff mode)
//#define T2_MON_RESET_VAL  4 // reset the values to monitor (diff mode)

// Call callback for every plugin
#define FOREACH_PLUGIN_DO(callback, ...) \
    for (uint_fast32_t i = 0; i < t2_plugins->num_plugins; i++) { \
        if (t2_plugins->plugin[i].callback) { \
            t2_plugins->plugin[i].callback(__VA_ARGS__); \
        } \
    }


/* Typedefs */

// Typedef for plugin functions
typedef const char* (*name_func)();
typedef const char* (*version_func)();
typedef const char* (*get_deps_func)();
typedef unsigned int (*v_major_func)();
typedef unsigned int (*v_minor_func)();
typedef void (*init_func)();
typedef binary_value_t* (*pri_hdr_func)();
typedef void (*on_flow_gen_func)(packet_t *packet, unsigned long flowInd);
typedef void (*claim_l2_func)(packet_t *packet, unsigned long flowInd);
typedef void (*claim_l4_func)(packet_t *packet, unsigned long flowInd);
typedef void (*on_flow_term_func)(unsigned long flowInd, outputBuffer_t *buf);
typedef void (*report_func)(FILE *stream);
typedef void (*on_app_term_func)();
typedef void (*buf_to_sink_func)(outputBuffer_t *buf, binary_value_t *bv);
typedef void (*monitoring_func)(FILE *stream, uint8_t state);
typedef void (*save_state_func)(FILE *stream);
typedef void (*restore_state_func)(const char *str);

#if USE_T2BUS == 1
typedef void (*t2Bus_callback)(uint32_t status);

/* t2Bus */
typedef struct {
    uint16_t       pl_num; // plugin number
    t2Bus_callback cb;     // callback
} t2Bus_cb_t;
#endif // USE_T2BUS == 1


/* Structs */

typedef struct {
    char      name[PL_NAME_MAXLEN];
    char      version[PL_VERSION_MAXLEN];
    uint16_t  number;

    void     *handle;

    // Pointers to plugin functions
    init_func          init;
    pri_hdr_func       priHdr;
    on_flow_gen_func   onFlowGen;
    claim_l2_func      claimL2Info;
    claim_l4_func      claimL4Info;
    on_flow_term_func  onFlowTerm;
#if PLUGIN_REPORT == 1
    report_func        report;
#endif // PLUGIN_REPORT == 1
    monitoring_func    monitoring;
    on_app_term_func   onAppTerm;
    buf_to_sink_func   bufToSink;
#if USE_T2BUS == 1
    t2Bus_cb_t         t2BusCb;
#endif // USE_T2BUS == 1
#if REPORT_HIST == 1
    save_state_func    saveState;
    restore_state_func restoreState;
#endif // REPORT_HIST == 1
} t2_plugin_t;

typedef struct {
    uint8_t      num_plugins;
    t2_plugin_t *plugin;
} t2_plugin_array_t;


/* Functions prototypes */

/*
 * Loads the plugins (dynamic libraries) from a given folder.
 */
t2_plugin_array_t* t2_load_plugins(const char *folder) __attribute__((__nonnull__(1)));

/*
 * Unloads all plugins from a t2_plugin_array_t struct.
 */
void t2_unload_plugins(t2_plugin_array_t *plugins);

#endif // T2_LOADPLUGINS_H_INCLUDED
