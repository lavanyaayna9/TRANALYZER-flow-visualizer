/*
 * t2Plugin.h
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

#ifndef T2_T2PLUGIN_H_INCLUDED
#define T2_T2PLUGIN_H_INCLUDED

#include "bin2txt.h"
#include "binaryValue.h"
#include "chksum.h"
#include "flow.h"
#include "fsutils.h"
#include "hashTable.h"
#include "ioBuffer.h"
#include "loadPlugins.h"
#include "main.h"
#include "missing/missing.h"
#include "networkHeaders.h"
#include "outputBuffer.h"
#include "packet.h"
#include "packetCapture.h"
#include "t2buf.h"
#include "t2log.h"
#include "t2stats.h"
#include "t2utils.h"
#include "tranalyzer.h"


#ifndef T2_API
#define T2_API
#endif


#define T2_PLUGIN_INIT(name, version, major, minor) \
    static const char * const plugin_name = name; \
    T2_API const char *t2PluginName() { return plugin_name; } \
    T2_API const char *t2PluginVersion() { return version; } \
    T2_API unsigned int t2SupportedT2Major() { return major; } \
    T2_API unsigned int t2SupportedT2Minor() { return minor; }

#define T2_PLUGIN_INIT_WITH_DEPS(name, version, major, minor, deps) \
    T2_PLUGIN_INIT(name, version, major, minor); \
    T2_API const char *t2Dependencies() { return deps; }

// 'plStruct' MUST be free'd in t2Finalize()
#define T2_PLUGIN_STRUCT_NEW(plStruct) \
    if (UNLIKELY(!(plStruct = t2_calloc(mainHashMap->hashChainTableSize, sizeof(*(plStruct)))))) { \
        T2_PFATAL(plugin_name, "failed to allocate memory for " STR(plStruct)); \
    }

#define T2_PLUGIN_STRUCT_RESET_ITEM(plStruct, flowIndex) \
    memset(&(plStruct)[flowIndex], '\0', sizeof(*(plStruct)))

#if ALARM_MODE == 1
#define T2_REPORT_ALARMS(num) { \
    numAlarmFlows++; \
    numAlarms += (num); \
    if (!ALARM_AND) { \
        if (num) supOut = 0; \
    } else { \
        if (!(num)) { \
            supOut = 1; \
            return; \
        } \
    } \
}
#else // ALARM_MODE == 0
#define T2_REPORT_ALARMS(num) { \
    numAlarmFlows++; \
    numAlarms += (num); \
}
#endif // ALARM_MODE == 0

#if FORCE_MODE == 1
#define T2_RM_FLOW(flowP) { \
    (flowP)->status |= RMFLOW; \
    globalWarn |= (RMFLOW); \
    rm_flows[num_rm_flows++] = flowP; \
    numForced++; \
}
#else // FORCE_MODE == 0
#define T2_RM_FLOW(flowP)
#endif // FORCE_MODE

#endif // T2_T2PLUGIN_H_INCLUDED
