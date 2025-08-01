/*
 * portClassifier.c
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

#include "portClassifier.h"


// Static variables

static portAppl_t portArray[65536]; // association port-application

#if PBC_STR == 1
#if ENVCNTRL > 0
static const char *pbcUnk;
#else // ENVCNTRL == 0
static const char * const pbcUnk = PBC_UNKNOWN;
#endif // ENVCNTRL
#endif // PBC_STR == 1


// Tranalyzer plugin functions

T2_PLUGIN_INIT("portClassifier", "0.9.3", 0, 9);


void t2Init() {

    t2_env_t env[ENV_PBC_N];

#if ENVCNTRL > 0
    t2_get_env(PLUGIN_SRCH, ENV_PBC_N, env);
#if PBC_STR == 1
    pbcUnk = T2_STEAL_ENV_VAL(PBC_UNKNOWN);
#endif // PBC_STR == 1
#else // ENVCNTRL == 0
    T2_SET_ENV_STR(PBC_CLASSFILE);
#endif // ENVCNTRL

    /* Open the ports file */
    FILE *file = t2_fopen_in_dir(pluginFolder, T2_ENV_VAL(PBC_CLASSFILE), "r");
    if (UNLIKELY(!file)) exit(EXIT_FAILURE);

    /* Parse the Input */

    char name[PBC_NMLENMAX+1];
    char proto[4];
    uint32_t port;
    int n;

    char *line = NULL;
    size_t len = 0;
    ssize_t read;

    while ((read = getline(&line, &len, file)) != -1) {
        // Skip comments and empty lines
        if (UNLIKELY(line[0] == '#' || line[0] == ' ' || line[0] == '\n' || line[0] == '\t')) continue;

        // scan the line (corrected port key files)
        n = sscanf(line, "%" SCNu32 "\t%3s\t%" STR(PBC_NMLENMAX) "s\t", &port, proto, name);
        if (UNLIKELY(n != 3)) {
            T2_PWRN(plugin_name, "failed to parse line '%s': expected port <tab> proto <tab> name", line);
            continue;
        }

        if (UNLIKELY(port > UINT16_MAX)) {
            T2_PWRN(plugin_name, "invalid port %" PRIu32, port);
            continue;
        }

        // TCP
        if (strncmp("tcp", proto, 3) == 0) {
            if (portArray[port].name_tcp[0] == '\0')
                memcpy(portArray[port].name_tcp, name, strlen(name)+1);
        // UDP
        } else if (strncmp("udp", proto, 3) == 0) {
            if (portArray[port].name_udp[0] == '\0')
                memcpy(portArray[port].name_udp, name, strlen(name)+1);
        // other:error. ignore it
        } else T2_PWRN(plugin_name, "invalid protocol '%s'", proto);
    }

    free(line);
    fclose(file);

#if ENVCNTRL > 0
    t2_free_env(ENV_PBC_N, env);
#endif // ENVCNTRL > 0

#if (PBC_NUM == 1 || PBC_STR == 1)
    if (sPktFile) {
#if PBC_NUM == 1
        fputs("dstPortClassN" SEP_CHR, sPktFile);
#endif // PBC_NUM == 1
#if PBC_STR == 1
        fputs("dstPortClass" SEP_CHR, sPktFile);
#endif // PBC_STR == 1
    }
#endif // (PBC_NUM == 1 || PBC_STR == 1)
}


binary_value_t* t2PrintHeader() {
    binary_value_t *bv = NULL;
#if PBC_NUM == 1
    BV_APPEND_U16(bv, "dstPortClassN", "Port based classification of the destination port number");
#endif
#if PBC_STR == 1
    BV_APPEND_STRC(bv, "dstPortClass", "Port based classification of the destination port name");
#endif
    return bv;
}


#if ETH_ACTIVATE > 0 && (PBC_NUM == 1 || PBC_STR == 1)
void t2OnLayer2(packet_t *packet UNUSED, unsigned long flowIndex) {
    if (flowIndex == HASHTABLE_ENTRY_NOT_FOUND) return;
    if (sPktFile) {
#if PBC_NUM == 1
        fputs(/* dstPortClassN */ SEP_CHR, sPktFile);
#endif // PBC_NUM == 1
#if PBC_STR == 1
        fprintf(sPktFile, "%s" /* dstPortClass */ SEP_CHR, pbcUnk);
#endif // PBC_STR == 1
    }
}
#endif // ETH_ACTIVATE > 0 && (PBC_NUM == 1 || PBC_STR == 1)


#if (PBC_NUM == 1 || PBC_STR == 1)
void t2OnLayer4(packet_t *packet UNUSED, unsigned long flowIndex) {
    if (!sPktFile) return;

    const flow_t * const flowP = &flows[flowIndex];
    const uint16_t dport = FLOW_IS_B(flowP) ? flowP->srcPort : flowP->dstPort;

#if PBC_NUM == 1
    fprintf(sPktFile, "%" PRIu16 /* dstPortClassN */ SEP_CHR, dport);
#endif

#if PBC_STR == 1
    char *proto_str;
    const uint_fast8_t proto = flowP->l4Proto;
    if (proto == L3_TCP || proto == L3_SCTP) proto_str = portArray[dport].name_tcp;
    else if (proto == L3_UDP || proto == L3_UDPLITE) proto_str = portArray[dport].name_udp;
    else proto_str = NULL;

    // dstPortClass
    if (proto_str && proto_str[0] != '\0') fprintf(sPktFile, "%s" /* dstPortClass */ SEP_CHR, proto_str);
    else fprintf(sPktFile, "%s" /* dstPortClass */ SEP_CHR, pbcUnk);
#endif // PBC_STR == 1
}
#endif // (PBC_NUM == 1 || PBC_STR == 1)


#if BLOCK_BUF == 0 && (PBC_NUM == 1 || PBC_STR == 1)
void t2OnFlowTerminate(unsigned long flowIndex, outputBuffer_t *buf) {

    const flow_t * const flowP = &flows[flowIndex];
    const uint16_t dport = FLOW_IS_B(flowP) ? flowP->srcPort : flowP->dstPort;

#if PBC_NUM == 1
    OUTBUF_APPEND_U16(buf, dport);
#endif

#if PBC_STR == 1
    char *proto_str;
    const uint_fast8_t proto = flowP->l4Proto;
    if (proto == L3_TCP || proto == L3_SCTP) {
        proto_str = portArray[dport].name_tcp;
    } else if (proto == L3_UDP || proto == L3_UDPLITE) {
        proto_str = portArray[dport].name_udp;
    } else {
        proto_str = NULL;
    }

    if (proto_str && proto_str[0] != '\0') {
        OUTBUF_APPEND_STR(buf, proto_str);
    } else {
        OUTBUF_APPEND_STR(buf, pbcUnk);
    }
#endif // PBC_STR == 1
}
#endif // BLOCK_BUF == 0 && (PBC_NUM == 1 || PBC_STR == 1)


#if ENVCNTRL > 0 && PBC_STR == 1
void t2Finalize() {
    free((char*)pbcUnk);
}
#endif // ENVCNTRL > 0 && PBC_STR == 1
