/*
 * t2PSkel.c
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

#include "t2PSkel.h"


/*
 * Static variables are only visible in this file
 */


/*
 * Static functions prototypes
 */


// Tranalyzer functions

/*
 * This describes the plugin name, version, major and minor version of
 * Tranalyzer required and dependencies
 */
T2_PLUGIN_INIT("t2PSkel", "0.9.3", 0, 9);


/*
 * This function is called before processing any packet.
 */
void t2Init() {
}


/*
 * This callback is only required for sink plugins
 * Refer to parse_binary2text() in utils/bin2txt.c for an example
 */
void t2BufferToSink(outputBuffer_t *buf, binary_value_t *bv) {
    // parse the buffer and dump it somewhere...
}


/*
 * This function is called once all the packets have been processed.
 * Cleanup all used memory here.
 */
void t2Finalize() {
}
