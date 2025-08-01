/*
 * syslogDecode.h
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

#ifndef __SYSLOGDECODE_H__
#define __SYSLOGDECODE_H__

#include "t2Plugin.h"


/* ========================================================================== */
/* ------------------------ USER CONFIGURATION FLAGS ------------------------ */
/* ========================================================================== */

#define SYSL_FSN 0 // Format for Syslog severity/facility messages:
                   //   0: Numbers
                   //   1: Names

/* +++++++++++++++++++++ ENV / RUNTIME - conf Variables +++++++++++++++++++++ */

/*       No env / runtime configuration flags available for syslogDecode      */

/* ========================================================================== */
/* ------------------------- DO NOT EDIT BELOW HERE ------------------------- */
/* ========================================================================== */


// plugin defines

#define SYSLOG_PORT 514

// SYSLOG  types
//#define SYSLM_JAN 0x4a616e
//#define SYSLM_FEB 0x466562
//#define SYSLM_MAR 0x4d6172
//#define SYSLM_APR 0x417072
//#define SYSLM_MAI 0x4d6179
//#define SYSLM_JUN 0x4a756e
//#define SYSLM_JUL 0x4a756c
//#define SYSLM_AUG 0x417567
//#define SYSLM_SEP 0x536570
//#define SYSLM_OCT 0x4f6374
//#define SYSLM_NOV 0x4e6f76
//#define SYSLM_DEC 0x446563

// syslogStat status variable
#define SYS_DET     0x01 // Syslog detected
#define SYS_CNTOVRN 0x80 // Counter for severity/facility overflow


// Enums

enum SYSL_Fac {
    kernel = 0,
    user,
    mail,
    _system,
    authorization,
    internal,
    printer,
    network,
    UUCP,
    _clock,
    security,
    FTP,
    NTP,
    logaudit,
    logalert,
    clockdaemon,
    local0,
    local1,
    local2,
    local3,
    local4,
    local5,
    local6,
    local7,
    SYS_NUM_FAC
};

enum SYSL_Sev {
    Emergency = 0,
    Alert,
    Critical,
    Error,
    Warning,
    Notice,
    Informational,
    Debug,
    SYS_NUM_SEV
};


const char * const facType[] = { "kernel", "user", "mail", "_system", "authorization", "internal", "printer", "network", "UUCP", "_clock", "security", "FTP", "NTP", "logaudit", "logalert", "clockdaemon", "local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7" };
const char * const sevType[] = { "Emergency", "Alert", "Critical", "Error", "Warning", "Notice", "Informational", "Debug" };


// Structures

typedef struct {
    uint32_t sum;
    uint16_t cnt[SYS_NUM_SEV][SYS_NUM_FAC];
    uint8_t  syslogStat;
} syslogFlow_t;

// plugin struct pointer for potential dependencies
extern syslogFlow_t *syslogFlow;

#endif // __SYSLOGDECODE_H__
