/*
 * sslDefines.h
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

/*
 * References:
 *
 * https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
 */

#ifndef __SSL_DEFINES_H__
#define __SSL_DEFINES_H__

// WEAK:
//   - All NULL ciphers
//   - All RC4  ciphers
//   - All EXPORT ciphers
//   - All anon ciphers

// 0x00-0xbf,*: reserved for IETF Standards Track Protocols
// 0xc0-0xfe,*: reserved for non-Standards Track methods
// 0xff     ,*: reserved for private use

#define TLS_NULL_WITH_NULL_NULL                         0x0000 // WEAK
#define TLS_RSA_WITH_NULL_MD5                           0x0001 // WEAK
#define TLS_RSA_WITH_NULL_SHA                           0x0002 // WEAK
#define TLS_RSA_EXPORT_WITH_RC4_40_MD5                  0x0003 // WEAK
#define TLS_RSA_WITH_RC4_128_MD5                        0x0004 // WEAK
#define TLS_RSA_WITH_RC4_128_SHA                        0x0005 // WEAK
#define TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5              0x0006 // WEAK
#define TLS_RSA_WITH_IDEA_CBC_SHA                       0x0007 // MEDIUM
#define TLS_RSA_EXPORT_WITH_DES40_CBC_SHA               0x0008 // WEAK
#define TLS_RSA_WITH_DES_CBC_SHA                        0x0009 // LOW
#define TLS_RSA_WITH_3DES_EDE_CBC_SHA                   0x000a // HIGH
#define TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA            0x000b // WEAK
#define TLS_DH_DSS_WITH_DES_CBC_SHA                     0x000c // LOW
#define TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA                0x000d // HIGH
#define TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA            0x000e // WEAK
#define TLS_DH_RSA_WITH_DES_CBC_SHA                     0x000f // LOW
#define TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA                0x0010 // HIGH
#define TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA           0x0011 // WEAK
#define TLS_DHE_DSS_WITH_DES_CBC_SHA                    0x0012 // LOW
#define TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA               0x0013 // HIGH
#define TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA           0x0014 // WEAK
#define TLS_DHE_RSA_WITH_DES_CBC_SHA                    0x0015 // LOW
#define TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA               0x0016 // HIGH
#define TLS_DH_anon_EXPORT_WITH_RC4_40_MD5              0x0017 // WEAK
#define TLS_DH_anon_WITH_RC4_128_MD5                    0x0018 // WEAK
#define TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA           0x0019 // WEAK
#define TLS_DH_anon_WITH_DES_CBC_SHA                    0x001a // WEAK
#define TLS_DH_anon_WITH_3DES_EDE_CBC_SHA               0x001b // WEAK
#define TLS_FZA_DMS_NULL_SHA                            0x001c // WEAK
#define TLS_FZA_DMS_FZA_SHA                             0x001d // MEDIUM
#define TLS_KRB5_WITH_DES_CBC_SHA                       0x001e // WEAK
#define TLS_KRB5_WITH_3DES_EDE_CBC_SHA                  0x001f // HIGH
#define TLS_KRB5_WITH_RC4_128_SHA                       0x0020 // WEAK
#define TLS_KRB5_WITH_IDEA_CBC_SHA                      0x0021 // MEDIUM
#define TLS_KRB5_WITH_DES_CBC_MD5                       0x0022 // LOW
#define TLS_KRB5_WITH_3DES_EDE_CBC_MD5                  0x0023 // HIGH
#define TLS_KRB5_WITH_RC4_128_MD5                       0x0024 // WEAK
#define TLS_KRB5_WITH_IDEA_CBC_MD5                      0x0025 // MEDIUM
#define TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA             0x0026 // WEAK
#define TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA             0x0027 // WEAK
#define TLS_KRB5_EXPORT_WITH_RC4_40_SHA                 0x0028 // WEAK
#define TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5             0x0029 // WEAK
#define TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5             0x002a // WEAK
#define TLS_KRB5_EXPORT_WITH_RC4_40_MD5                 0x002b // WEAK
#define TLS_PSK_WITH_NULL_SHA                           0x002c
#define TLS_DHE_PSK_WITH_NULL_SHA                       0x002d
#define TLS_RSA_PSK_WITH_NULL_SHA                       0x002e
#define TLS_RSA_WITH_AES_128_CBC_SHA                    0x002f // HIGH
#define TLS_DH_DSS_WITH_AES_128_CBC_SHA                 0x0030 // MEDIUM
#define TLS_DH_RSA_WITH_AES_128_CBC_SHA                 0x0031 // MEDIUM
#define TLS_DHE_DSS_WITH_AES_128_CBC_SHA                0x0032 // HIGH
#define TLS_DHE_RSA_WITH_AES_128_CBC_SHA                0x0033 // HIGH
#define TLS_DH_anon_WITH_AES_128_CBC_SHA                0x0034 // WEAK
#define TLS_RSA_WITH_AES_256_CBC_SHA                    0x0035 // HIGH
#define TLS_DH_DSS_WITH_AES_256_CBC_SHA                 0x0036 // MEDIUM
#define TLS_DH_RSA_WITH_AES_256_CBC_SHA                 0x0037 // MEDIUM
#define TLS_DHE_DSS_WITH_AES_256_CBC_SHA                0x0038 // HIGH
#define TLS_DHE_RSA_WITH_AES_256_CBC_SHA                0x0039 // HIGH
#define TLS_DH_anon_WITH_AES_256_CBC_SHA                0x003a // WEAK
#define TLS_RSA_WITH_NULL_SHA256                        0x003b // WEAK
#define TLS_RSA_WITH_AES_128_CBC_SHA256                 0x003c // HIGH
#define TLS_RSA_WITH_AES_256_CBC_SHA256                 0x003d // HIGH
#define TLS_DH_DSS_WITH_AES_128_CBC_SHA256              0x003e // HIGH
#define TLS_DH_RSA_WITH_AES_128_CBC_SHA256              0x003f // HIGH
#define TLS_DHE_DSS_WITH_AES_128_CBC_SHA256             0x0040 // HIGH
#define TLS_RSA_WITH_CAMELLIA_128_CBC_SHA               0x0041 // HIGH
#define TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA            0x0042 // HIGH
#define TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA            0x0043 // HIGH
#define TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA           0x0044 // HIGH
#define TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA           0x0045 // HIGH
#define TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA           0x0046 // WEAK
#define TLS_RSA_EXPORT1024_WITH_RC4_56_MD5              0x0060 // WEAK
#define TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5          0x0061 // WEAK
#define TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA             0x0062 // WEAK
#define TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA         0x0063 // WEAK
#define TLS_RSA_EXPORT1024_WITH_RC4_56_SHA              0x0064 // WEAK
#define TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA          0x0065 // WEAK
#define TLS_DHE_DSS_WITH_RC4_128_SHA                    0x0066 // WEAK
#define TLS_DHE_RSA_WITH_AES_128_CBC_SHA256             0x0067 // HIGH
#define TLS_DH_DSS_WITH_AES_256_CBC_SHA256              0x0068 // HIGH
#define TLS_DH_RSA_WITH_AES_256_CBC_SHA256              0x0069 // HIGH
#define TLS_DHE_DSS_WITH_AES_256_CBC_SHA256             0x006a // HIGH
#define TLS_DHE_RSA_WITH_AES_256_CBC_SHA256             0x006b // HIGH
#define TLS_DH_anon_WITH_AES_128_CBC_SHA256             0x006c // WEAK
#define TLS_DH_anon_WITH_AES_256_CBC_SHA256             0x006d // WEAK
#define TLS_RSA_WITH_CAMELLIA_256_CBC_SHA               0x0084 // HIGH
#define TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA            0x0085 // HIGH
#define TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA            0x0086 // HIGH
#define TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA           0x0087 // HIGH
#define TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA           0x0088 // HIGH
#define TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA           0x0089 // WEAK
#define TLS_PSK_WITH_RC4_128_SHA                        0x008a // MEDIUM
#define TLS_PSK_WITH_3DES_EDE_CBC_SHA                   0x008b // HIGH
#define TLS_PSK_WITH_AES_128_CBC_SHA                    0x008c // HIGH
#define TLS_PSK_WITH_AES_256_CBC_SHA                    0x008d // HIGH
#define TLS_DHE_PSK_WITH_RC4_128_SHA                    0x008e
#define TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA               0x008f
#define TLS_DHE_PSK_WITH_AES_128_CBC_SHA                0x0090
#define TLS_DHE_PSK_WITH_AES_256_CBC_SHA                0x0091
#define TLS_RSA_PSK_WITH_RC4_128_SHA                    0x0092
#define TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA               0x0093
#define TLS_RSA_PSK_WITH_AES_128_CBC_SHA                0x0094
#define TLS_RSA_PSK_WITH_AES_256_CBC_SHA                0x0095
#define TLS_RSA_WITH_SEED_CBC_SHA                       0x0096 // MEDIUM
#define TLS_DH_DSS_WITH_SEED_CBC_SHA                    0x0097 // MEDIUM
#define TLS_DH_RSA_WITH_SEED_CBC_SHA                    0x0098 // MEDIUM
#define TLS_DHE_DSS_WITH_SEED_CBC_SHA                   0x0099 // MEDIUM
#define TLS_DHE_RSA_WITH_SEED_CBC_SHA                   0x009a // MEDIUM
#define TLS_DH_anon_WITH_SEED_CBC_SHA                   0x009b // WEAK
#define TLS_RSA_WITH_AES_128_GCM_SHA256                 0x009c // HIGH
#define TLS_RSA_WITH_AES_256_GCM_SHA384                 0x009d // HIGH
#define TLS_DHE_RSA_WITH_AES_128_GCM_SHA256             0x009e // HIGH
#define TLS_DHE_RSA_WITH_AES_256_GCM_SHA384             0x009f // HIGH
#define TLS_DH_RSA_WITH_AES_128_GCM_SHA256              0x00a0 // HIGH
#define TLS_DH_RSA_WITH_AES_256_GCM_SHA384              0x00a1 // HIGH
#define TLS_DHE_DSS_WITH_AES_128_GCM_SHA256             0x00a2 // HIGH
#define TLS_DHE_DSS_WITH_AES_256_GCM_SHA384             0x00a3 // HIGH
#define TLS_DH_DSS_WITH_AES_128_GCM_SHA256              0x00a4 // HIGH
#define TLS_DH_DSS_WITH_AES_256_GCM_SHA384              0x00a5 // HIGH
#define TLS_DH_anon_WITH_AES_128_GCM_SHA256             0x00a6 // WEAK
#define TLS_DH_anon_WITH_AES_256_GCM_SHA384             0x00a7 // WEAK
#define TLS_PSK_WITH_AES_128_GCM_SHA256                 0x00a8
#define TLS_PSK_WITH_AES_256_GCM_SHA384                 0x00a9
#define TLS_DHE_PSK_WITH_AES_128_GCM_SHA256             0x00aa
#define TLS_DHE_PSK_WITH_AES_256_GCM_SHA384             0x00ab
#define TLS_RSA_PSK_WITH_AES_128_GCM_SHA256             0x00ac
#define TLS_RSA_PSK_WITH_AES_256_GCM_SHA384             0x00ad
#define TLS_PSK_WITH_AES_128_CBC_SHA256                 0x00ae
#define TLS_PSK_WITH_AES_256_CBC_SHA384                 0x00af
#define TLS_PSK_WITH_NULL_SHA256                        0x00b0 // WEAK
#define TLS_PSK_WITH_NULL_SHA384                        0x00b1 // WEAK
#define TLS_DHE_PSK_WITH_AES_128_CBC_SHA256             0x00b2
#define TLS_DHE_PSK_WITH_AES_256_CBC_SHA384             0x00b3
#define TLS_DHE_PSK_WITH_NULL_SHA256                    0x00b4 // WEAK
#define TLS_DHE_PSK_WITH_NULL_SHA384                    0x00b5 // WEAK
#define TLS_RSA_PSK_WITH_AES_128_CBC_SHA256             0x00b6
#define TLS_RSA_PSK_WITH_AES_256_CBC_SHA384             0x00b7
#define TLS_RSA_PSK_WITH_NULL_SHA256                    0x00b8 // WEAK
#define TLS_RSA_PSK_WITH_NULL_SHA384                    0x00b9 // WEAK
#define TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256            0x00ba
#define TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256         0x00bb
#define TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256         0x00bc
#define TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256        0x00bd
#define TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256        0x00be
#define TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256        0x00bf // WEAK
#define TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256            0x00c0 // HIGH
#define TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256         0x00c1
#define TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256         0x00c2
#define TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256        0x00c3
#define TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256        0x00c4
#define TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256        0x00c5 // WEAK
#define TLS_EMPTY_RENEGOTIATION_INFO_SCSV               0x00ff
#define TLS_DES_64_CBC_WITH_SHA                         0x0140 // LOW
#define TLS_DES_64_CFB64_WITH_MD5_1                     0x0800 // WEAK
#define TLS_ECDH_ECDSA_WITH_NULL_SHA                    0xc001 // WEAK
#define TLS_ECDH_ECDSA_WITH_RC4_128_SHA                 0xc002 // WEAK
#define TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA            0xc003 // HIGH
#define TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA             0xc004 // HIGH
#define TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA             0xc005 // HIGH
#define TLS_ECDHE_ECDSA_WITH_NULL_SHA                   0xc006 // WEAK
#define TLS_ECDHE_ECDSA_WITH_RC4_128_SHA                0xc007 // WEAK
#define TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA           0xc008 // HIGH
#define TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA            0xc009 // HIGH
#define TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA            0xc00a // HIGH
#define TLS_ECDH_RSA_WITH_NULL_SHA                      0xc00b // WEAK
#define TLS_ECDH_RSA_WITH_RC4_128_SHA                   0xc00c // WEAK
#define TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA              0xc00d // HIGH
#define TLS_ECDH_RSA_WITH_AES_128_CBC_SHA               0xc00e // MEDIUM
#define TLS_ECDH_RSA_WITH_AES_256_CBC_SHA               0xc00f // MEDIUM
#define TLS_ECDHE_RSA_WITH_NULL_SHA                     0xc010 // WEAK
#define TLS_ECDHE_RSA_WITH_RC4_128_SHA                  0xc011 // WEAK
#define TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA             0xc012 // HIGH
#define TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA              0xc013 // HIGH
#define TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA              0xc014 // HIGH
#define TLS_ECDH_anon_WITH_NULL_SHA                     0xc015 // WEAK
#define TLS_ECDH_anon_WITH_RC4_128_SHA                  0xc016 // WEAK
#define TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA             0xc017 // WEAK
#define TLS_ECDH_anon_WITH_AES_128_CBC_SHA              0xc018 // WEAK
#define TLS_ECDH_anon_WITH_AES_256_CBC_SHA              0xc019 // WEAK
#define TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA               0xc01a // HIGH
#define TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA           0xc01b // HIGH
#define TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA           0xc01c // HIGH
#define TLS_SRP_SHA_WITH_AES_128_CBC_SHA                0xc01d // HIGH
#define TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA            0xc01e // HIGH
#define TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA            0xc01f // HIGH
#define TLS_SRP_SHA_WITH_AES_256_CBC_SHA                0xc020 // HIGH
#define TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA            0xc021 // HIGH
#define TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA            0xc022 // HIGH
#define TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256         0xc023 // HIGH
#define TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384         0xc024 // HIGH
#define TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256          0xc025 // HIGH
#define TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384          0xc026 // HIGH
#define TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256           0xc027 // HIGH
#define TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384           0xc028 // HIGH
#define TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256            0xc029 // HIGH
#define TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384            0xc02a // HIGH
#define TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256         0xc02b // HIGH
#define TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384         0xc02c // HIGH
#define TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256          0xc02d // HIGH
#define TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384          0xc02e // HIGH
#define TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256           0xc02f // HIGH
#define TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384           0xc030 // HIGH
#define TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256            0xc031 // HIGH
#define TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384            0xc032 // HIGH
#define TLS_ECDHE_PSK_WITH_RC4_128_SHA                  0xc033
#define TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA             0xc034
#define TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA              0xc035
#define TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA              0xc036
#define TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256           0xc037
#define TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384           0xc038
#define TLS_ECDHE_PSK_WITH_NULL_SHA                     0xc039 // WEAK
#define TLS_ECDHE_PSK_WITH_NULL_SHA256                  0xc03a // WEAK
#define TLS_ECDHE_PSK_WITH_NULL_SHA384                  0xc03b // WEAK
#define TLS_RSA_WITH_ARIA_128_CBC_SHA256                0xc03c
#define TLS_RSA_WITH_ARIA_256_CBC_SHA384                0xc03d
#define TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256             0xc03e
#define TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384             0xc03f
#define TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256             0xc040
#define TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384             0xc041
#define TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256            0xc042
#define TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384            0xc043
#define TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256            0xc044
#define TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384            0xc045
#define TLS_DH_anon_WITH_ARIA_128_CBC_SHA256            0xc046
#define TLS_DH_anon_WITH_ARIA_256_CBC_SHA384            0xc047
#define TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256        0xc048
#define TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384        0xc049
#define TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256         0xc04a
#define TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384         0xc04b
#define TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256          0xc04c
#define TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384          0xc04d
#define TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256           0xc04e
#define TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384           0xc04f
#define TLS_RSA_WITH_ARIA_128_GCM_SHA256                0xc050
#define TLS_RSA_WITH_ARIA_256_GCM_SHA384                0xc051
#define TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256            0xc052
#define TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384            0xc053
#define TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256             0xc054
#define TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384             0xc055
#define TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256            0xc056
#define TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384            0xc057
#define TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256             0xc058
#define TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384             0xc059
#define TLS_DH_anon_WITH_ARIA_128_GCM_SHA256            0xc05a // WEAK
#define TLS_DH_anon_WITH_ARIA_256_GCM_SHA384            0xc05b // WEAK
#define TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256        0xc05c
#define TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384        0xc05d
#define TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256         0xc05e
#define TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384         0xc05f
#define TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256          0xc060
#define TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384          0xc061
#define TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256           0xc062
#define TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384           0xc063
#define TLS_PSK_WITH_ARIA_128_CBC_SHA256                0xc064
#define TLS_PSK_WITH_ARIA_256_CBC_SHA384                0xc065
#define TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256            0xc066
#define TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384            0xc067
#define TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256            0xc068
#define TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384            0xc069
#define TLS_PSK_WITH_ARIA_128_GCM_SHA256                0xc06a
#define TLS_PSK_WITH_ARIA_256_GCM_SHA384                0xc06b
#define TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256            0xc06c
#define TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384            0xc06d
#define TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256            0xc06e
#define TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384            0xc06f
#define TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256          0xc070
#define TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384          0xc071
#define TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256    0xc072
#define TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384    0xc073
#define TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256     0xc074
#define TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384     0xc075
#define TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256      0xc076
#define TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384      0xc077
#define TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256       0xc078
#define TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384       0xc079
#define TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256            0xc07a
#define TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384            0xc07b
#define TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256        0xc07c
#define TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384        0xc07d
#define TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256         0xc07e
#define TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384         0xc07f
#define TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256        0xc080
#define TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384        0xc081
#define TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256         0xc082
#define TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384         0xc083
#define TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256        0xc084 // WEAK
#define TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384        0xc085 // WEAK
#define TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256    0xc086
#define TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384    0xc087
#define TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256     0xc088
#define TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384     0xc089
#define TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256      0xc08a
#define TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384      0xc08b
#define TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256       0xc08c
#define TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384       0xc08d
#define TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256            0xc08e
#define TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384            0xc08f
#define TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256        0xc090
#define TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384        0xc091
#define TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256        0xc092
#define TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384        0xc093
#define TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256            0xc094
#define TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384            0xc095
#define TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256        0xc096
#define TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384        0xc097
#define TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256        0xc098
#define TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384        0xc099
#define TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256      0xc09a
#define TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384      0xc09b
#define TLS_RSA_WITH_AES_128_CCM                        0xc09c // HIGH
#define TLS_RSA_WITH_AES_256_CCM                        0xc09d // HIGH
#define TLS_DHE_RSA_WITH_AES_128_CCM                    0xc09e // HIGH
#define TLS_DHE_RSA_WITH_AES_256_CCM                    0xc09f // HIGH
#define TLS_RSA_WITH_AES_128_CCM_8                      0xc0a0 // HIGH
#define TLS_RSA_WITH_AES_256_CCM_8                      0xc0a1 // HIGH
#define TLS_DHE_RSA_WITH_AES_128_CCM_8                  0xc0a2 // HIGH
#define TLS_DHE_RSA_WITH_AES_256_CCM_8                  0xc0a3 // HIGH
#define TLS_PSK_WITH_AES_128_CCM                        0xc0a4 // HIGH
#define TLS_PSK_WITH_AES_256_CCM                        0xc0a5 // HIGH
#define TLS_DHE_PSK_WITH_AES_128_CCM                    0xc0a6
#define TLS_DHE_PSK_WITH_AES_256_CCM                    0xc0a7
#define TLS_PSK_WITH_AES_128_CCM_8                      0xc0a8 // HIGH
#define TLS_PSK_WITH_AES_256_CCM_8                      0xc0a9 // HIGH
#define TLS_PSK_DHE_WITH_AES_128_CCM_8                  0xc0aa
#define TLS_PSK_DHE_WITH_AES_256_CCM_8                  0xc0ab
#define TLS_ECDHE_ECDSA_WITH_AES_128_CCM                0xc0ac // HIGH
#define TLS_ECDHE_ECDSA_WITH_AES_256_CCM                0xc0ad // HIGH
#define TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8              0xc0ae // HIGH
#define TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8              0xc0af // HIGH
#define TLS_RSA_FIPS_WITH_3DES_EDE_CBC_SHA_1            0xfee0 // HIGH
#define TLS_RSA_FIPS_WITH_DES_CBC_SHA_1                 0xfee1 // LOW
#define TLS_RSA_FIPS_WITH_DES_CBC_SHA_2                 0xfefe // LOW
#define TLS_RSA_FIPS_WITH_3DES_EDE_CBC_SHA_2            0xfeff // HIGH


#define SSL_RT_HDR_LEN           5 // type(1), version(2), length(2)
#define SSL_RT_MAX_LEN       16384
#define SSL_SESSION_ID_LEN      32
#define SSL_HELLO_RANDOM_LEN    32
#define SSL_AL_LEN               2 // level(1), description(1)
#define SSL_HB_MIN_PAD_LEN      16 // minimum padding length for heartbeat messages

#define SSL_CERT_COUNTRY_LEN     2
#define SSL_CERT_PK_TYPE_SLEN    5
#define SSL_CERT_PK_TYPE_LLEN   32
#define SSL_CERT_SHA1_LEN       40
#define SSL_CERT_NAME_MAXLEN    64 // CN, O, OU, SN, email
#define SSL_CERT_LOC_MAXLEN    128 // L, ST
#define SSL_SNI_MAX_LEN        255

// Protocol version
// SSL
#define SSLv2   0x0002 // TODO SSLv2 uses a different format
#define SSLv3   0x0300
// TLS
#define TLSv10  0x0301
#define TLSv11  0x0302
#define TLSv12  0x0303
#define TLSv13  0x0304
// DTLS
#define DTLSv10_OLD 0x0100 // pre standard version of DTLSv1.0 (OpenSSL pre 0.9.8f)
#define DTLSv10     0xfeff
// DTLSv11 does not exist
#define DTLSv12     0xfefd

#define SSL_V_MAJOR(v) ((v) >> 8)
#define SSL_V_MINOR(v) ((v) & 0x00ff)

#define SSL_V_IS_DTLS(v) (((v) == DTLSv10) || ((v) == DTLSv12) || ((v) == DTLSv10_OLD))
#define SSL_V_IS_SSL(v) (((v) >= SSLv3) && ((v) <= TLSv13))
#define SSL_V_IS_VALID(v) (SSL_V_IS_SSL((v)) || SSL_V_IS_DTLS((v)))

// Record types
#define SSL_RT_CHANGE_CIPHER_SPEC 0x14
#define SSL_RT_ALERT              0x15
#define SSL_RT_HANDSHAKE          0x16
#define SSL_RT_APPLICATION_DATA   0x17
#define SSL_RT_HEARTBEAT          0x18

// If record type is not valid, then it is probably not TLS
#define SSL_RT_IS_VALID(t) (((t) >= SSL_RT_CHANGE_CIPHER_SPEC) && ((t) <= SSL_RT_HEARTBEAT))

// SSL2 message types
#define SSL2_MT_ERROR               0x00
#define SSL2_MT_CLIENT_HELLO        0x01
#define SSL2_MT_CLIENT_MASTER_KEY   0x02
#define SSL2_MT_CLIENT_FINISHED     0x03
#define SSL2_MT_SERVER_HELLO        0x04
#define SSL2_MT_SERVER_VERIFY       0x05
#define SSL2_MT_SERVER_FINISHED     0x06
#define SSL2_MT_REQUEST_CERTIFICATE 0x07
#define SSL2_MT_CLIENT_CERTIFICATE  0x08

// If record type is not valid, then it is probably not SSLv2
#define SSL2_MT_IS_VALID(t) ((t) <= SSL2_MT_CLIENT_CERTIFICATE)

// Handshake types
#define SSL_HT_HELLO_REQUEST        0x00
#define SSL_HT_CLIENT_HELLO         0x01
#define SSL_HT_SERVER_HELLO         0x02
#define SSL_HT_HELLO_VERIFY_REQUEST 0x03 // RFC6347, DTLS only
#define SSL_HT_NEW_SESSION_TICKET   0x04 // RFC5077
#define SSL_HT_CERTIFICATE          0x0B
#define SSL_HT_SERVER_KEY_EXCHANGE  0x0C
#define SSL_HT_CERTIFICATE_REQUEST  0x0D
#define SSL_HT_SERVER_HELLO_DONE    0x0E
#define SSL_HT_CERTIFICATE_VERIFY   0x0F
#define SSL_HT_CLIENT_KEY_EXCHANGE  0x10
#define SSL_HT_FINISHED             0x14
#define SSL_HT_CERTIFICATE_URL      0x15 // RFC3546
#define SSL_HT_CERTIFICATE_STATUS   0x16 // RFC3546
#define SSL_HT_SUPPLEMENTAL_DATA    0x17 // RFC4680
//#define SSL_HT_NEXT_PROTOCOL 0x43 // https://tools.ietf.org/id/draft-agl-tls-nextprotoneg-03.html

// Hello extensions
#define SSL_HT_HELLO_EXT_SERVER_NAME            0x0000
#define SSL_HT_HELLO_EXT_MAX_FRAGMENT_LENGTH    0x0001
#define SSL_HT_HELLO_EXT_CLIENT_CERT_URL        0x0002
#define SSL_HT_HELLO_EXT_TRUSTED_CA_KEYS        0x0003
#define SSL_HT_HELLO_EXT_TRUNCATED_HMAC         0x0004
#define SSL_HT_HELLO_EXT_STATUS_REQUEST         0x0005
#define SSL_HT_HELLO_EXT_USER_MAPPING           0x0006
#define SSL_HT_HELLO_EXT_CLIENT_AUTH            0x0007
#define SSL_HT_HELLO_EXT_SERVER_AUTH            0x0008
#define SSL_HT_HELLO_EXT_CERT_TYPE              0x0009
#define SSL_HT_HELLO_EXT_ELLIPTIC_CURVES        0x000a
#define SSL_HT_HELLO_EXT_EC_POINT_FORMATS       0x000b
#define SSL_HT_HELLO_EXT_SRP                    0x000c
#define SSL_HT_HELLO_EXT_SIG_HASH_ALGS          0x000d
#define SSL_HT_HELLO_EXT_USE_SRTP               0x000e
#define SSL_HT_HELLO_EXT_HEARTBEAT              0x000f
#define SSL_HT_HELLO_EXT_ALPN                   0x0010
#define SSL_HT_HELLO_EXT_STATUS_REQUEST_V2      0x0011
#define SSL_HT_HELLO_EXT_SIGNED_CERT_TIMESTAMP  0x0012
#define SSL_HT_HELLO_EXT_CLIENT_CERT_TYPE       0x0013
#define SSL_HT_HELLO_EXT_SERVER_CERT_TYPE       0x0014
#define SSL_HT_HELLO_EXT_PADDING                0x0015
#define SSL_HT_HELLO_EXT_ENCRYPT_THEN_MAC       0x0016
#define SSL_HT_HELLO_EXT_EXT_MASTER_SECRET_TYPE 0x0017
#define SSL_HT_HELLO_EXT_SESSION_TICKET         0x0023
#define SSL_HT_HELLO_EXT_EXTENDED_RANDOM        0x0028
#define SSL_HT_HELLO_EXT_NPN                    0x3374
#define SSL_HT_HELLO_EXT_ORIGIN_BOUND_CERT      0x3377
#define SSL_HT_HELLO_EXT_ENCRYPTED_CLIENT_CERT  0x337c
#define SSL_HT_HELLO_EXT_CHANNEL_ID_OLD         0x754f
#define SSL_HT_HELLO_EXT_CHANNEL_ID             0x7550
#define SSL_HT_HELLO_EXT_RENEG_INFO             0xff01

// Compression methods
#define SSL_COMPRESSION_NULL     0
#define SSL_COMPRESSION_DEFLATE  1
#define SSL_COMPRESSION_LZS     64

// Alert level
#define SSL_AL_WARN  1
#define SSL_AL_FATAL 2

// Alert description
#define SSL_AD_CLOSE_NOTIFY            0x00
#define SSL_AD_UNEXPECTED_MSG          0x0a /* fatal */
#define SSL_AD_BAD_RECORD_MAC          0x14 /* fatal */
#define SSL_AD_DECRYPTION_FAIL         0x15 /* fatal */
#define SSL_AD_RECORD_OVERFLOW         0x16 /* fatal */
#define SSL_AD_DECOMPRESSION_FAIL      0x1e /* fatal */
#define SSL_AD_HANDSHAKE_FAIL          0x28 /* fatal */
#define SSL_AD_NO_CERT                 0x29
#define SSL_AD_BAD_CERT                0x2a
#define SSL_AD_UNSUPPORTED_CERT        0x2b
#define SSL_AD_CERT_REVOKED            0x2c
#define SSL_AD_CERT_EXPIRED            0x2d
#define SSL_AD_CERT_UNKNOWN            0x2e
#define SSL_AD_ILLEGAL_PARAM           0x2f /* fatal */
#define SSL_AD_UNKNOWN_CA              0x30 /* fatal */
#define SSL_AD_ACCESS_DENIED           0x31 /* fatal */
#define SSL_AD_DECODE_ERROR            0x32 /* fatal */
#define SSL_AD_DECRYPT_ERROR           0x33
#define SSL_AD_EXPORT_RESTRICTION      0x3c /* fatal */
#define SSL_AD_PROTOCOL_VERSION        0x46 /* fatal */
#define SSL_AD_INSUFFICIENT_SECURITY   0x47 /* fatal */
#define SSL_AD_INTERNAL_ERROR          0x50 /* fatal */
#define SSL_AD_INAPPROPRIATE_FALLBACK  0x56 /* fatal */
#define SSL_AD_USER_CANCELED           0x5a /* fatal */
#define SSL_AD_NO_RENEGOTIATION        0x64 /* warn  */
// 0x6e-0x73 - [RFC3546]
#define SSL_AD_UNSUPPORTED_EXTENSION   0x6e /* warn  */
#define SSL_AD_CERT_UNOBTAINABLE       0x6f /* warn  */
#define SSL_AD_UNRECOGNIZED_NAME       0x70
#define SSL_AD_BAD_CERT_STATUS_RESP    0x71 /* fatal */
#define SSL_AD_BAD_CERT_HASH_VALUE     0x72 /* fatal */
#define SSL_AD_UNKNOWN_PSK_IDENTITY    0x73 /* fatal */
#define SSL_AD_NO_APPLICATION_PROTOCOL 0x78 /* fatal */

// Heartbeat request/response
#define SSL_HB_REQ  0x1
#define SSL_HB_RESP 0x2

// Hello extension heartbeat
#define SSL_HB_EXT_ALLOWED     0x01 // peer allowed to send
#define SSL_HB_EXT_NOT_ALLOWED 0x02 // peer not allowed to send

#endif // __SSL_DEFINES_H__
