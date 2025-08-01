/*
 * netflowSink.h
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

#ifndef NETFLOWSINK_H_
#define NETFLOWSINK_H_

/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define NF_SOCKTYPE 0           // Socket type: 0: UDP, 1: TCP
#define NF_VER      9           // NetFlow version 9 or 10 (IPFIX)

/* +++++++++++++++++++++ ENV / RUNTIME - conf Variables +++++++++++++++++++++ */

#define NF_NUM4FLWS 200         // Max # of IPv4 flows in one NetFlow message
#define NF_NUM6FLWS 100         // Max # of IPv6 flows in one NetFlow message
#define NF_SERVADD  "127.0.0.1" // Destination address
#define NF_DPORT    9995        // Destination port

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */

// Environment var vector
// The elements in the enum below MUST be in the same order as above
enum {
    ENV_NF_NUM4FLWS,
    ENV_NF_NUM6FLWS,
    ENV_NF_SERVADD,
    ENV_NF_DPORT,
    ENV_NF_N
};

#endif // NETFLOWSINK_H_
