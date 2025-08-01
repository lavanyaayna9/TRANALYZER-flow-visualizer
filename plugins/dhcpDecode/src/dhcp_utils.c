/*
 * dhcp_utils.c
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

#include "dhcp_utils.h"


// IPv4

const char * const dhcpMsgTToStr[] = {
    "Discover",
    "Offer",
    "Request",
    "Decline",
    "ACK",
    "NAK",
    "Release",
    "Inform",
    "Force Renew",
    "Lease query",
    "Lease Unassigned",
    "Lease Unknown",
    "Lease Active",
    "Bulk Lease Query",
    "Lease Query Done",
    "Active Lease Query",
    "Lease Query Status",
    "TLS"
};

const char * const dhcpState53[] = {
    "Init",       //  0
    "Discover",   //  1
    "Offer",      //  2
    "Request",    //  3
    "Decline",    //  4
    "ACK",        //  5
    "NAK",        //  6
    "Release",    //  7
    "Inform",     //  8
    "ForceRenew", //  9
    "LsQuery",    // 10
    "LsUassgnd",  // 11
    "LsUnknwn",   // 12
    "LsActv",     // 13
    "BlkLsQry",   // 14
    "LsQryDne",   // 15
    "ActvLsQry",  // 16
    "LsQryStat",  // 17
    "TLS"         // 18
};

const char * const dhcpOptNm[] = {
    "Pad",                                  //   0
    "Subnet Mask",                          //   1
    "Time Offset",                          //   2
    "Router",                               //   3
    "Time Server",                          //   4
    "Name Server",                          //   5
    "Domain Server",                        //   6
    "Log Server",                           //   7
    "Quotes Server",                        //   8
    "LPR Server",                           //   9
    "Impress Server",                       //  10
    "RLP Server",                           //  11
    "Hostname",                             //  12
    "Boot File Size",                       //  13
    "Merit Dump File",                      //  14
    "Domain Name",                          //  15
    "Swap Server",                          //  16
    "Root Path",                            //  17
    "Extension File",                       //  18
    "Forward On/Off",                       //  19
    "SrcRte On/Off",                        //  20
    "Policy Filter",                        //  21
    "Max DG Assembly",                      //  22
    "Default IP TTL",                       //  23
    "MTU Timeout",                          //  24
    "MTU Plateau",                          //  25
    "MTU Interface",                        //  26
    "MTU Subnet",                           //  27
    "Broadcast Address",                    //  28
    "Mask Discovery",                       //  29
    "Mask Supplier",                        //  30
    "Router Discovery",                     //  31
    "Router Request",                       //  32
    "Static Route",                         //  33
    "Trailers",                             //  34
    "ARP Timeout",                          //  35
    "Ethernet",                             //  36
    "Default TCP TTL",                      //  37
    "Keepalive Time",                       //  38
    "Keepalive Data",                       //  39
    "NIS Domain",                           //  40
    "NIS Servers",                          //  41
    "NTP Servers",                          //  42
    "Vendor Specific",                      //  43
    "NETBIOS Name Srv",                     //  44
    "NETBIOS Dist Srv",                     //  45
    "NETBIOS Node Type",                    //  46
    "NETBIOS Scope",                        //  47
    "X Window Font",                        //  48
    "X Window Manager",                     //  49
    "Address Request",                      //  50
    "Address Time",                         //  51
    "Overload",                             //  52
    "DHCP Msg Type",                        //  53
    "DHCP Server Id",                       //  54
    "Parameter List",                       //  55
    "DHCP Message",                         //  56
    "DHCP Max Msg Size",                    //  57
    "Renewal Time",                         //  58
    "Rebinding Time",                       //  59
    "Class Id",                             //  60
    "Client Id",                            //  61
    "NetWare/IP Domain",                    //  62
    "NetWare/IP Option",                    //  63
    "NIS-Domain-Name",                      //  64
    "NIS-Server-Addr",                      //  65
    "Server-Name",                          //  66
    "Bootfile-Name",                        //  67
    "Home-Agent-Addrs",                     //  68
    "SMTP-Server",                          //  69
    "POP3-Server",                          //  70
    "NNTP-Server",                          //  71
    "WWW-Server",                           //  72
    "Finger-Server",                        //  73
    "IRC-Server",                           //  74
    "StreetTalk-Server",                    //  75
    "STDA-Server",                          //  76
    "User-Class",                           //  77
    "Directory Agent",                      //  78
    "Service Scope",                        //  79
    "Rapid Commit",                         //  80
    "Client FQDN",                          //  81
    "Relay Agent Information",              //  82
    "iSNS",                                 //  83
    "-",                                    //  84
    "NDS Servers",                          //  85
    "NDS Tree Name",                        //  86
    "NDS Context",                          //  87
    "BCMCS Controller Domain Name list",    //  88
    "BCMCS Controller IPv4 addr option",    //  89
    "Authentication",                       //  90
    "client-last-transaction-time option",  //  91
    "associated-ip option",                 //  92
    "Client System",                        //  93
    "Client NDI",                           //  94
    "LDAP",                                 //  95
    "-",                                    //  96
    "UUID/GUID",                            //  97
    "User-Auth",                            //  98
    "GEOCONF_CIVIC",                        //  99
    "PCode",                                // 100
    "TCode",                                // 101
    "-",                                    // 102
    "-",                                    // 103
    "-",                                    // 104
    "-",                                    // 105
    "-",                                    // 106
    "-",                                    // 107
    "IPv6-Only Preferred",                  // 108
    "OPTION_DHCP4O6_S46_SADDR",             // 109
    "-",                                    // 110
    "-",                                    // 111
    "Netinfo Address",                      // 112
    "Netinfo Tag",                          // 113
    "DHCP Captive-Portal",                  // 114
    "-",                                    // 115
    "Auto-Config",                          // 116
    "Name Service Search",                  // 117
    "Subnet Selection Option",              // 118
    "Domain Search",                        // 119
    "SIP Servers DHCP Option",              // 120
    "Classless Static Route Option",        // 121
    "CCC",                                  // 122
    "GeoConf Option",                       // 123
    "V-I Vendor Class",                     // 124
    "V-I Vendor-Specific Information",      // 125
    "-",                                    // 126
    "-",                                    // 127
    "PXE/Etherboot/DOCSIS/TFTP",            // 128
    "Kernel options",                       // 129
    "Ethernet interface",                   // 130
    "Remote statistics server IP address",  // 131
    "IEEE 802.1Q VLAN ID",                  // 132
    "Layer 2 Priority",                     // 133
    "DSCP for VoIP & media streams",        // 134
    "HTTP Proxy for phone-spec appl",       // 135
    "OPTION_PANA_AGENT",                    // 136
    "OPTION_V4_LOST",                       // 137
    "OPTION_CAPWAP_AC_V4",                  // 138
    "OPTION-IPv4_Address-MoS",              // 139
    "OPTION-IPv4_FQDN-MoS",                 // 140
    "SIP UA Config Service Domains",        // 141
    "OPTION-IPv4_Address-ANDSF",            // 142
    "OPTION_V4_SZTP_REDIRECT",              // 143
    "GeoLoc",                               // 144
    "FORCERENEW_NONCE_CAPABLE",             // 145
    "RDNSS Selection",                      // 146
    "OPTION_V4_DOTS_RI",                    // 147
    "OPTION_V4_DOTS_ADDRESS",               // 148
    "-",                                    // 149
    "TFTP/GRUB",                            // 150
    "status-code",                          // 151
    "base-time",                            // 152
    "start-time-of-state",                  // 153
    "query-start-time",                     // 154
    "query-end-time",                       // 155
    "dhcp-state",                           // 156
    "data-source",                          // 157
    "OPTION_V4_PCP_SERVER",                 // 158
    "OPTION_V4_PORTPARAMS",                 // 159
    "-",                                    // 160
    "OPTION_MUD_URL_V4",                    // 161
    "-",                                    // 162
    "-",                                    // 163
    "-",                                    // 164
    "-",                                    // 165
    "-",                                    // 166
    "-",                                    // 167
    "-",                                    // 168
    "-",                                    // 169
    "-",                                    // 170
    "-",                                    // 171
    "-",                                    // 172
    "-",                                    // 173
    "-",                                    // 174
    "Etherboot",                            // 175
    "IP Telephone",                         // 176
    "PacketCable and CableHome",            // 177
    "-",                                    // 178
    "-",                                    // 179
    "-",                                    // 180
    "-",                                    // 181
    "-",                                    // 182
    "-",                                    // 183
    "-",                                    // 184
    "-",                                    // 185
    "-",                                    // 186
    "-",                                    // 187
    "-",                                    // 188
    "-",                                    // 189
    "-",                                    // 190
    "-",                                    // 191
    "-",                                    // 192
    "-",                                    // 193
    "-",                                    // 194
    "-",                                    // 195
    "-",                                    // 196
    "-",                                    // 197
    "-",                                    // 198
    "-",                                    // 199
    "-",                                    // 200
    "-",                                    // 201
    "-",                                    // 202
    "-",                                    // 203
    "-",                                    // 204
    "-",                                    // 205
    "-",                                    // 206
    "-",                                    // 207
    "PXELINUX Magic",                       // 208
    "Configuration File",                   // 209
    "Path Prefix",                          // 210
    "Reboot Time",                          // 211
    "OPTION_6RD",                           // 212
    "OPTION_V4_ACCESS_DOMAIN",              // 213
    "-",                                    // 214
    "-",                                    // 215
    "-",                                    // 216
    "-",                                    // 217
    "-",                                    // 218
    "-",                                    // 219
    "Subnet Allocation Option",             // 220
    "VSS Option",                           // 221
    "-",                                    // 222
    "-",                                    // 223
    "Res",                                  // 224
    "Res",                                  // 225
    "Res",                                  // 226
    "Res",                                  // 227
    "Res",                                  // 228
    "Res",                                  // 229
    "Res",                                  // 230
    "Res",                                  // 231
    "Res",                                  // 232
    "Res",                                  // 233
    "Res",                                  // 234
    "Res",                                  // 235
    "Res",                                  // 236
    "Res",                                  // 237
    "Res",                                  // 238
    "Res",                                  // 239
    "Res",                                  // 240
    "Res",                                  // 241
    "Res",                                  // 242
    "Res",                                  // 243
    "Res",                                  // 244
    "Res",                                  // 245
    "Res",                                  // 246
    "Res",                                  // 247
    "Res",                                  // 248
    "Res",                                  // 249
    "Res",                                  // 250
    "Res",                                  // 251
    "Res",                                  // 252
    "Res",                                  // 253
    "Res",                                  // 254
    "End"                                   // 255
};

// IPv6

const char * const dhcpMsgT6ToStr[] = {
    // RFC5007
    //"Reserved", // 0
    "SOLICIT",
    "ADVERTISE",
    "REQUEST",
    "CONFIRM",
    "RENEW",
    "REBIND",
    "REPLY",
    "RELEASE",
    "DECLINE",
    "RECONFIGURE", // 10
    "INFORMATION-REQUEST",
    "RELAY-FORW",
    "RELAY-REPL",
    // RFC5007
    "LEASEQUERY",
    "LEASEQUERY-REPLY",
    // RFC5460
    "LEASEQUERY-DONE",
    "LEASEQUERY-DATA",
    // RFC6977
    "RECONFIGURE-REQUEST",
    "RECONFIGURE-REPLY",
    // RFC7341
    "DHCPV4-QUERY", // 20
    "DHCPV4-RESPONSE",
    // RFC7653
    "ACTIVELEASEQUERY",
    "STARTTLS",
    // https://www.iana.org/go/draft-ietf-dhc-dhcpv6-failover-protocol-06
    //"BNDUPD",
    //"BNDREPLY",
    //"POOLREQ",
    //"POOLRESP",
    //"UPDREQ",
    //"UPDREQALL",
    //"UPDDONE", // 30
    //"CONNECT",
    //"CONNECTREPLY",
    //"DISCONNECT",
    //"STATE",
    //"CONTACT", // 35
    //"Unassigned", // 36-255
};

const char * const dhcpMT6[] = {
    "Res",          //  0
    "Solicit",      //  1
    "Advrts",       //  2
    "Req",          //  3
    "Cnfrm",        //  4
    "Renw",         //  5
    "Rebnd",        //  6
    "Rply",         //  7
    "Release",      //  8
    "Decline",      //  9
    "Reconf",       // 10
    "Inf-Req",      // 11
    "Relay-Frwrd",  // 12
    "Relay-Rply",   // 13
    "LeaseQry",     // 14
    "LeaseQry-Rply" // 15
};
