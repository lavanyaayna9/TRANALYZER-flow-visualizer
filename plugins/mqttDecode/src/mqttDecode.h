/*
 * mqttDecode.h
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

#ifndef __MQTT_DECODE_H__
#define __MQTT_DECODE_H__

// Global includes
//#include <stdio.h>
//#include <string.h>

// Local includes
#include "t2Plugin.h"


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define MQTT_TOPIC_MSG      1 // Save topics and messages in a separate file
#define MQTT_PROTO_LEN     32 // Max length for protocol name
#define MQTT_CLIENT_ID_LEN 32 // Max length for client ID
#define MQTT_TOPIC_LEN     32 // Max length for topic
//#define MQTT_MSG_LEN       32 // Max length for message

/* +++++++++++++++++++++ ENV / RUNTIME - conf Variables +++++++++++++++++++++ */

#define MQTT_TOPIC_MSG_SUFFIX "_mqtt_msg.txt"

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// Environment var vector
// The elements in the enum below MUST be in the same order as above
enum {
    ENV_MQTT_TOPIC_MSG_SUFFIX,
    ENV_MQTT_N
};


// plugin defines
#define MQTT_MIN_HDRLEN       2 // Single byte control field and single byte packet length
#define MQTT_LEN_MAX    2097152 // Single byte control field and single byte packet length
#define MQTT_PORT          1883
#define MQTT_PROTONAME1 "MQIsdp"
#define MQTT_PROTONAME2 "MQTT"

// MQTT Control Packet type
#define MQTT_CPT(hdrflags) ((hdrflags & 0xf0) >> 4)

// MQTT Flags (specific to each MQTT Control Packet type)
#define MQTT_FLAGS(hdrflags) (hdrflags & 0x0f)

// MQTT Control Packet types
#define MQTT_CPT_RESERVED0    0 // Reserved
#define MQTT_CPT_CONNECT      1 // Client request to connect to server
#define MQTT_CPT_CONNACK      2 // Connect acknowledgment
#define MQTT_CPT_PUBLISH      3 // Publish message
#define MQTT_CPT_PUBACK       4 // Publish acknowledgment
#define MQTT_CPT_PUBREC       5 // Publish complete (assured delivery part 1)
#define MQTT_CPT_PUBREL       6 // Publish complete (assured delivery part 2)
#define MQTT_CPT_PUBCOMP      7 // Publish complete (assured delivery part 3)
#define MQTT_CPT_SUBSCRIBE    8 // Subscribe request
#define MQTT_CPT_SUBACK       9 // Subscribe acknowledgment
#define MQTT_CPT_UNSUBSCRIBE 10 // Unsubscribe request
#define MQTT_CPT_UNSUBACK    11 // Unsubscribe acknowledgment
#define MQTT_CPT_PINGREQ     12 // PING request
#define MQTT_CPT_PINGRESP    13 // PING response
#define MQTT_CPT_DISCONNECT  14 // Client is disconnecting
#define MQTT_CPT_RESERVED15  15 // Reserved

// MQTT Flags for PUBLISH message
#define MQTT_PUBLISH_F_DUP    0x08 // Duplicate delivery of a PUBLISH Control Packet
#define MQTT_PUBLISH_F_QOS    0x06 // PUBLISH Quality of Service
#define MQTT_PUBLISH_F_RETAIN 0x01 // PUBLISH Retain flag

// mqttStat
#define MQTT_STAT_MQTT 0x01 // Flow is MQTT
#define MQTT_STAT_RSVD 0x10 // Reserved Control Packet Type (0 or 15) was used
#define MQTT_STAT_SNAP 0x80 // Packet snapped (t2buf_read failed)


// Plugin structures

typedef struct {
    uint16_t cpt;
    uint8_t stat;
    uint8_t connect_flags;
    uint8_t conAck;
    uint8_t proto_level;
    char proto[MQTT_PROTO_LEN+1];
    char clientID[MQTT_CLIENT_ID_LEN+1];
    char topic[MQTT_TOPIC_LEN+1];
    //char message[MQTT_MSG_LEN+1];
} mqttFlow_t;


// plugin struct pointer for potential dependencies
extern mqttFlow_t *mqttFlows;

#endif // __MQTT_DECODE_H__
