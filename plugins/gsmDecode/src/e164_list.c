/*
 * e164_list.c
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

#include "e164_list.h"

#include <stdint.h> // for uint_fast32_t
#include <stdlib.h> // for NULL
#include <string.h> // for strlen, memcmp


typedef struct {
    int num;
    const char * const country_code;
    const char * const country_name;
} e164_item_t;


static e164_item_t e164_country1[] = {
    //{  0, "??", "Reserved"                                       },
    //{  1, "AS", "American Samoa"                                 },
    //{  1, "AI", "Anguilla"                                       },
    //{  1, "AG", "Antigua and Barbuda"                            },
    //{  1, "BS", "Bahamas (Commonwealth of the)"                  },
    //{  1, "BB", "Barbados"                                       },
    //{  1, "BM", "Bermuda"                                        },
    //{  1, "VG", "British Virgin Islands"                         },
    //{  1, "CA", "Canada"                                         },
    //{  1, "KY", "Cayman Islands"                                 },
    //{  1, "DM", "Dominica (Commonwealth of)"                     },
    //{  1, "DO", "Dominican Republic"                             },
    //{  1, "GD", "Grenada"                                        },
    //{  1, "GU", "Guam"                                           },
    //{  1, "JM", "Jamaica"                                        },
    //{  1, "MS", "Montserrat"                                     },
    //{  1, "MP", "Northern Mariana Islands (Commonwealth of the)" },
    //{  1, "PR", "Puerto Rico"                                    },
    //{  1, "KN", "Saint Kitts and Nevis"                          },
    //{  1, "LC", "Saint Lucia"                                    },
    //{  1, "VC", "Saint Vincent and the Grenadines"               },
    //{  1, "TT", "Trinidad and Tobago"                            },
    //{  1, "TC", "Turks and Caicos Islands"                       },
    //{  1, "VI", "United States Virgin Islands"                   },
    {  1, "US", "United States of America"                       },
    //{  7, "KZ", "Kazakhstan (Republic of)"                       },
    {  7, "RU", "Russian Federation"                             },
    { -1, NULL, NULL                                             }
};


static e164_item_t e164_country2[] = {
    { 20, "EG", "Egypt (Arab Republic of)"                             },
    { 27, "ZA", "South Africa (Republic of)"                           },
    { 30, "GR", "Greece"                                               },
    { 31, "NL", "Netherlands (Kingdom of the)"                         },
    { 32, "BE", "Belgium"                                              },
    { 33, "FR", "France"                                               },
    { 34, "ES", "Spain"                                                },
    { 36, "HU", "Hungary (Republic of)"                                },
    { 39, "IT", "Italy"                                                },
    //{ 39, "IT", "Vatican City State"                                   },
    { 40, "RO", "Romania"                                              },
    { 41, "CH", "Switzerland (Confederation of)"                       },
    { 43, "AT", "Austria"                                              },
    { 44, "GB", "United Kingdom of Great Britain and Northern Ireland" },
    { 45, "DK", "Denmark"                                              },
    { 46, "SE", "Sweden"                                               },
    { 47, "NO", "Norway"                                               },
    { 48, "PL", "Poland (Republic of)"                                 },
    { 49, "DE", "Germany (Federal Republic of)"                        },
    { 51, "PE", "Peru"                                                 },
    { 52, "MX", "Mexico"                                               },
    { 53, "CU", "Cuba"                                                 },
    { 54, "AR", "Argentine Republic"                                   },
    { 55, "BR", "Brazil (Federative Republic of)"                      },
    { 56, "CL", "Chile"                                                },
    { 57, "CO", "Colombia (Republic of)"                               },
    { 58, "VE", "Venezuela (Bolivarian Republic of)"                   },
    { 60, "MY", "Malaysia"                                             },
    { 61, "AU", "Australia"                                            },
    { 62, "ID", "Indonesia (Republic of)"                              },
    { 63, "PH", "Philippines (Republic of the)"                        },
    { 64, "NZ", "New Zealand"                                          },
    { 65, "SG", "Singapore (Republic of)"                              },
    { 66, "TH", "Thailand"                                             },
    { 81, "JP", "Japan"                                                },
    { 82, "KR", "Korea (Republic of)"                                  },
    { 84, "VN", "Viet Nam (Socialist Republic of)"                     },
    { 86, "CN", "China (People's Republic of)"                         },
    { 90, "TR", "Turkey"                                               },
    { 91, "IN", "India (Republic of)"                                  },
    { 92, "PK", "Pakistan (Islamic Republic of)"                       },
    { 93, "AF", "Afghanistan"                                          },
    { 94, "LK", "Sri Lanka (Democratic Socialist Republic of)"         },
    { 95, "MM", "Myanmar (Union of)"                                   },
    { 98, "IR", "Iran (Islamic Republic of)"                           },
    { -1, NULL, NULL                                                   }
};


static e164_item_t e164_country3[] = {
    { 210, "??"           , "Spare code"                                                                                         },
    { 211, "??"           , "Spare code"                                                                                         },
    { 212, "MA"           , "Morocco (Kingdom of)"                                                                               },
    { 213, "DZ"           , "Algeria (People's Democratic Republic of)"                                                          },
    { 214, "??"           , "Spare code"                                                                                         },
    { 215, "??"           , "Spare code"                                                                                         },
    { 216, "TN"           , "Tunisia"                                                                                            },
    { 217, "??"           , "Spare code"                                                                                         },
    { 218, "LY"           , "Libya (Socialist People's Libyan Arab Jamahiriya)"                                                  },
    { 219, "??"           , "Spare code"                                                                                         },
    { 220, "GM"           , "Gambia (Republic of the)"                                                                           },
    { 221, "SN"           , "Senegal (Republic of)"                                                                              },
    { 222, "MR"           , "Mauritania (Islamic Republic of)"                                                                   },
    { 223, "ML"           , "Mali (Republic of)"                                                                                 },
    { 224, "GN"           , "Guinea (Republic of)"                                                                               },
    { 225, "CI"           , "Côte d'Ivoire (Republic of)"                                                                        },
    { 226, "BF"           , "Burkina Faso"                                                                                       },
    { 227, "NE"           , "Niger (Republic of the)"                                                                            },
    { 228, "TG"           , "Togolese Republic"                                                                                  },
    { 229, "BJ"           , "Benin (Republic of)"                                                                                },
    { 230, "MU"           , "Mauritius (Republic of)"                                                                            },
    { 231, "LR"           , "Liberia (Republic of)"                                                                              },
    { 232, "SL"           , "Sierra Leone"                                                                                       },
    { 233, "GH"           , "Ghana"                                                                                              },
    { 234, "NG"           , "Nigeria (Federal Republic of)"                                                                      },
    { 235, "TD"           , "Chad (Republic of)"                                                                                 },
    { 236, "CF"           , "Central African Republic"                                                                           },
    { 237, "CM"           , "Cameroon (Republic of)"                                                                             },
    { 238, "CV"           , "Cape Verde (Republic of)"                                                                           },
    { 239, "ST"           , "Sao Tome and Principe (Democratic Republic of)"                                                     },
    { 240, "GQ"           , "Equatorial Guinea (Republic of)"                                                                    },
    { 241, "GA"           , "Gabonese Republic"                                                                                  },
    { 242, "CG"           , "Congo (Republic of the)"                                                                            },
    { 243, "CD"           , "Democratic Republic of the Congo"                                                                   },
    { 244, "AO"           , "Angola (Republic of)"                                                                               },
    { 245, "GW"           , "Guinea-Bissau (Republic of)"                                                                        },
    { 246, "??"           , "Diego Garcia"                                                                                       },
    { 247, "SH"           , "Ascension"                                                                                          },
    { 248, "SC"           , "Seychelles (Republic of)"                                                                           },
    { 249, "SD"           , "Sudan (Republic of the)"                                                                            },
    { 250, "RW"           , "Rwanda (Republic of)"                                                                               },
    { 251, "ET"           , "Ethiopia (Federal Democratic Republic of)"                                                          },
    { 252, "SO"           , "Somali Democratic Republic"                                                                         },
    { 253, "DJ"           , "Djibouti (Republic of)"                                                                             },
    { 254, "KE"           , "Kenya (Republic of)"                                                                                },
    { 255, "TZ"           , "Tanzania (United Republic of)"                                                                      },
    { 256, "UG"           , "Uganda (Republic of)"                                                                               },
    { 257, "BI"           , "Burundi (Republic of)"                                                                              },
    { 258, "MZ"           , "Mozambique (Republic of)"                                                                           },
    { 259, "??"           , "Spare code"                                                                                         },
    { 260, "ZM"           , "Zambia (Republic of)"                                                                               },
    { 261, "MG"           , "Madagascar (Republic of)"                                                                           },
    { 262, "FR"           , "Reunion (French Department of)"                                                                     },
    { 263, "ZW"           , "Zimbabwe (Republic of)"                                                                             },
    { 264, "NA"           , "Namibia (Republic of)"                                                                              },
    { 265, "MW"           , "Malawi"                                                                                             },
    { 266, "LS"           , "Lesotho (Kingdom of)"                                                                               },
    { 267, "BW"           , "Botswana (Republic of)"                                                                             },
    { 268, "SZ"           , "Swaziland (Kingdom of)"                                                                             },
    { 269, "KM"           , "Comoros (Union of the)"                                                                             },
    { 269, "YT"           , "Mayotte"                                                                                            },
    { 280, "??"           , "Spare code"                                                                                         },
    { 281, "??"           , "Spare code"                                                                                         },
    { 282, "??"           , "Spare code"                                                                                         },
    { 283, "??"           , "Spare code"                                                                                         },
    { 284, "??"           , "Spare code"                                                                                         },
    { 285, "??"           , "Spare code"                                                                                         },
    { 286, "??"           , "Spare code"                                                                                         },
    { 287, "??"           , "Spare code"                                                                                         },
    { 288, "??"           , "Spare code"                                                                                         },
    { 289, "??"           , "Spare code"                                                                                         },
    { 290, "SH"           , "Saint Helena"                                                                                       },
    { 291, "ER"           , "Eritrea"                                                                                            },
    { 292, "??"           , "Spare code"                                                                                         },
    { 293, "??"           , "Spare code"                                                                                         },
    { 294, "??"           , "Spare code"                                                                                         },
    { 295, "??"           , "Spare code"                                                                                         },
    { 296, "??"           , "Spare code"                                                                                         },
    { 297, "AW"           , "Aruba"                                                                                              },
    { 298, "FO"           , "Faroe Islands"                                                                                      },
    { 299, "GL"           , "Greenland (Denmark)"                                                                                },
    { 350, "GI"           , "Gibraltar"                                                                                          },
    { 351, "PT"           , "Portugal"                                                                                           },
    { 352, "LU"           , "Luxembourg"                                                                                         },
    { 353, "IE"           , "Ireland"                                                                                            },
    { 354, "IS"           , "Iceland"                                                                                            },
    { 355, "AL"           , "Albania (Republic of)"                                                                              },
    { 356, "MT"           , "Malta"                                                                                              },
    { 357, "CY"           , "Cyprus (Republic of)"                                                                               },
    { 358, "FI"           , "Finland"                                                                                            },
    { 359, "BG"           , "Bulgaria (Republic of)"                                                                             },
    { 370, "LT"           , "Lithuania (Republic of)"                                                                            },
    { 371, "LV"           , "Latvia (Republic of)"                                                                               },
    { 372, "EE"           , "Estonia (Republic of)"                                                                              },
    { 373, "MD"           , "Moldova (Republic of)"                                                                              },
    { 374, "AM"           , "Armenia (Republic of)"                                                                              },
    { 375, "BY"           , "Belarus (Republic of)"                                                                              },
    { 376, "AD"           , "Andorra (Principality of)"                                                                          },
    { 377, "MC"           , "Monaco (Principality of)"                                                                           },
    { 378, "SM"           , "San Marino (Republic of)"                                                                           },
    { 379, "IT"           , "Vatican City State"                                                                                 },
    { 380, "UA"           , "Ukraine"                                                                                            },
    { 381, "RS/ME"        , "Serbia and Montenegro"                                                                              },
    { 382, "??"           , "Spare code"                                                                                         },
    { 383, "??"           , "Spare code"                                                                                         },
    { 384, "??"           , "Spare code"                                                                                         },
    { 385, "HR"           , "Croatia (Republic of)"                                                                              },
    { 386, "SI"           , "Slovenia (Republic of)"                                                                             },
    { 387, "BA"           , "Bosnia and Herzegovina"                                                                             },
    { 388, "??"           , "Group of countries, shared code"                                                                    },
    { 389, "MK"           , "The Former Yugoslav Republic of Macedonia"                                                          },
    { 420, "CZ"           , "Czech Republic"                                                                                     },
    { 421, "SK"           , "Slovak Republic"                                                                                    },
    { 422, "??"           , "Spare code"                                                                                         },
    { 423, "LI"           , "Liechtenstein (Principality of)"                                                                    },
    { 424, "??"           , "Spare code"                                                                                         },
    { 425, "??"           , "Spare code"                                                                                         },
    { 426, "??"           , "Spare code"                                                                                         },
    { 427, "??"           , "Spare code"                                                                                         },
    { 428, "??"           , "Spare code"                                                                                         },
    { 429, "??"           , "Spare code"                                                                                         },
    { 500, "FK"           , "Falkland Islands (Malvinas)"                                                                        },
    { 501, "BZ"           , "Belize"                                                                                             },
    { 502, "GT"           , "Guatemala (Republic of)"                                                                            },
    { 503, "SV"           , "El Salvador (Republic of)"                                                                          },
    { 504, "HN"           , "Honduras (Republic of)"                                                                             },
    { 505, "NI"           , "Nicaragua"                                                                                          },
    { 506, "CR"           , "Costa Rica"                                                                                         },
    { 507, "PA"           , "Panama (Republic of)"                                                                               },
    { 508, "PM"           , "Saint Pierre and Miquelon (Collectivité territoriale de la République française)"                   },
    { 509, "HT"           , "Haiti (Republic of)"                                                                                },
    { 590, "GP"           , "Guadeloupe (French Department of)"                                                                  },
    { 591, "BO"           , "Bolivia (Republic of)"                                                                              },
    { 592, "GY"           , "Guyana"                                                                                             },
    { 593, "EC"           , "Ecuador"                                                                                            },
    { 594, "GF"           , "French Guiana (French Department of)"                                                               },
    { 595, "PY"           , "Paraguay (Republic of)"                                                                             },
    { 596, "MQ"           , "Martinique (French Department of)"                                                                  },
    { 597, "SR"           , "Suriname (Republic of)"                                                                             },
    { 598, "UY"           , "Uruguay (Eastern Republic of)"                                                                      },
    { 599, "AN"           , "Netherlands Antilles"                                                                               },
    { 670, "TL"           , "Democratic Republic of Timor-Leste"                                                                 },
    { 671, "??"           , "Spare code"                                                                                         },
    { 672, "AU"           , "Australian External Territories"                                                                    },
    { 673, "BN"           , "Brunei Darussalam"                                                                                  },
    { 674, "NR"           , "Nauru (Republic of)"                                                                                },
    { 675, "PG"           , "Papua New Guinea"                                                                                   },
    { 676, "TO"           , "Tonga (Kingdom of)"                                                                                 },
    { 677, "SB"           , "Solomon Islands"                                                                                    },
    { 678, "VU"           , "Vanuatu (Republic of)"                                                                              },
    { 679, "FJ"           , "Fiji (Republic of)"                                                                                 },
    { 680, "PW"           , "Palau (Republic of)"                                                                                },
    { 681, "WF"           , "Wallis and Futuna (Territoire français d'outre-mer)"                                                },
    { 682, "CK"           , "Cook Islands"                                                                                       },
    { 683, "NU"           , "Niue"                                                                                               },
    { 684, "??"           , "Spare code"                                                                                         },
    { 685, "WS"           , "Samoa (Independent State of)"                                                                       },
    { 686, "KI"           , "Kiribati (Republic of)"                                                                             },
    { 687, "NC"           , "New Caledonia (Territoire français d'outre-mer)"                                                    },
    { 688, "TV"           , "Tuvalu"                                                                                             },
    { 689, "PF"           , "French Polynesia (Territoire français d'outre-mer)"                                                 },
    { 690, "TK"           , "Tokelau"                                                                                            },
    { 691, "FM"           , "Micronesia (Federated States of)"                                                                   },
    { 692, "MH"           , "Marshall Islands (Republic of the)"                                                                 },
    { 693, "??"           , "Spare code"                                                                                         },
    { 694, "??"           , "Spare code"                                                                                         },
    { 695, "??"           , "Spare code"                                                                                         },
    { 696, "??"           , "Spare code"                                                                                         },
    { 697, "??"           , "Spare code"                                                                                         },
    { 698, "??"           , "Spare code"                                                                                         },
    { 699, "??"           , "Spare code"                                                                                         },
    { 800, "IFS"          , "International Freephone Service"                                                                    },
    { 801, "??"           , "Spare code"                                                                                         },
    { 802, "??"           , "Spare code"                                                                                         },
    { 803, "??"           , "Spare code"                                                                                         },
    { 804, "??"           , "Spare code"                                                                                         },
    { 805, "??"           , "Spare code"                                                                                         },
    { 806, "??"           , "Spare code"                                                                                         },
    { 807, "??"           , "Spare code"                                                                                         },
    { 808, "ISCS"         , "International Shared Cost Service (ISCS)"                                                           },
    { 809, "??"           , "Spare code"                                                                                         },
    { 830, "??"           , "Spare code"                                                                                         },
    { 831, "??"           , "Spare code"                                                                                         },
    { 832, "??"           , "Spare code"                                                                                         },
    { 833, "??"           , "Spare code"                                                                                         },
    { 834, "??"           , "Spare code"                                                                                         },
    { 835, "??"           , "Spare code"                                                                                         },
    { 836, "??"           , "Spare code"                                                                                         },
    { 837, "??"           , "Spare code"                                                                                         },
    { 838, "??"           , "Spare code"                                                                                         },
    { 839, "??"           , "Spare code"                                                                                         },
    { 850, "KP"           , "Democratic People's Republic of Korea"                                                              },
    { 851, "??"           , "Spare code"                                                                                         },
    { 852, "HK"           , "Hong Kong, China"                                                                                   },
    { 853, "MO"           , "Macao, China"                                                                                       },
    { 854, "??"           , "Spare code"                                                                                         },
    { 855, "KH"           , "Cambodia (Kingdom of)"                                                                              },
    { 856, "LA"           , "Lao People's Democratic Republic"                                                                   },
    { 857, "??"           , "Spare code"                                                                                         },
    { 858, "??"           , "Spare code"                                                                                         },
    { 859, "??"           , "Spare code"                                                                                         },
    { 870, "Inmarsat-SNAC", "Inmarsat SNAC"                                                                                      },
    { 871, "Inmarsat-AOE" , "Inmarsat (Atlantic Ocean-East)"                                                                     },
    { 872, "Inmarsat-PO"  , "Inmarsat (Pacific Ocean)"                                                                           },
    { 873, "Inmarsat-IO"  , "Inmarsat (Indian Ocean)"                                                                            },
    { 874, "Inmarsat-AOW" , "Inmarsat (Atlantic Ocean-West)"                                                                     },
    { 875, "MMSA"         , "Reserved - Maritime Mobile Service Applications"                                                    },
    { 876, "MMSA"         , "Reserved - Maritime Mobile Service Applications"                                                    },
    { 877, "MMSA"         , "Reserved - Maritime Mobile Service Applications"                                                    },
    { 878, "UPT"          , "Universal Personal Telecommunication Service (UPT)"                                                 },
    { 879, "??"           , "Reserved for national non-commercial purposes"                                                      },
    { 880, "BD"           , "Bangladesh (People's Republic of)"                                                                  },
    { 881, "IntMob"       , "International Mobile, shared code"                                                                  },
    { 882, "IntNet"       , "International Networks, shared code"                                                                },
    { 883, "??"           , "Spare code"                                                                                         },
    { 884, "??"           , "Spare code"                                                                                         },
    { 885, "??"           , "Spare code"                                                                                         },
    { 886, "??"           , "Reserved"                                                                                           },
    { 887, "??"           , "Spare code"                                                                                         },
    { 888, "??"           , "Reserved for future global service"                                                                 },
    { 889, "??"           , "Spare code"                                                                                         },
    { 890, "??"           , "Spare code"                                                                                         },
    { 891, "??"           , "Spare code"                                                                                         },
    { 892, "??"           , "Spare code"                                                                                         },
    { 893, "??"           , "Spare code"                                                                                         },
    { 894, "??"           , "Spare code"                                                                                         },
    { 895, "??"           , "Spare code"                                                                                         },
    { 896, "??"           , "Spare code"                                                                                         },
    { 897, "??"           , "Spare code"                                                                                         },
    { 898, "??"           , "Spare code"                                                                                         },
    { 899, "??"           , "Spare code"                                                                                         },
    { 960, "MV"           , "Maldives (Republic of)"                                                                             },
    { 961, "LB"           , "Lebanon"                                                                                            },
    { 962, "JO"           , "Jordan (Hashemite Kingdom of)"                                                                      },
    { 963, "SY"           , "Syrian Arab Republic"                                                                               },
    { 964, "IQ"           , "Iraq (Republic of)"                                                                                 },
    { 965, "KW"           , "Kuwait (State of)"                                                                                  },
    { 966, "SA"           , "Saudi Arabia (Kingdom of)"                                                                          },
    { 967, "YE"           , "Yemen (Republic of)"                                                                                },
    { 968, "OM"           , "Oman (Sultanate of)"                                                                                },
    { 969, "??"           , "Reserved - reservation currently under investigation"                                               },
    { 970, "??"           , "Reserved"                                                                                           },
    { 971, "AE"           , "United Arab Emirates"                                                                               },
    { 972, "IL"           , "Israel (State of)"                                                                                  },
    { 973, "BH"           , "Bahrain (Kingdom of)"                                                                               },
    { 974, "QA"           , "Qatar (State of)"                                                                                   },
    { 975, "BT"           , "Bhutan (Kingdom of)"                                                                                },
    { 976, "MN"           , "Mongolia"                                                                                           },
    { 977, "NP"           , "Nepal"                                                                                              },
    { 978, "??"           , "Spare code"                                                                                         },
    { 979, "IPRS"         , "International Premium Rate Service (IPRS)"                                                          },
    { 990, "??"           , "Spare code"                                                                                         },
    { 991, "??"           , "Trial of a proposed new international telecommunication public correspondence service, shared code" },
    { 992, "TJ"           , "Tajikistan (Republic of)"                                                                           },
    { 993, "TM"           , "Turkmenistan"                                                                                       },
    { 994, "AZ"           , "Azerbaijani Republic"                                                                               },
    { 995, "GE"           , "Georgia"                                                                                            },
    { 996, "KG"           , "Kyrgyz Republic"                                                                                    },
    { 997, "??"           , "Spare code"                                                                                         },
    { 998, "UZ"           , "Uzbekistan (Republic of)"                                                                           },
    { 999, "TDR"          , "Reserved for possible future use within the Telecommunications for Disaster Relief (TDR) concept"   },
    {  -1, NULL           , NULL                                                                                                 }
};



const char *e164_country(char num[3], int len) {
    uint_fast32_t i;

    if (len == 0 || len == 3) {
        const int number = strtoul(num, NULL, 10);
        for (i = 0; e164_country3[i].country_name && e164_country3[i].num <= number; i++) {
            if (e164_country3[i].num == number) return e164_country3[i].GSM_E164_FIELD;
        }
    }

    if (len == 0 || len == 2) {
        num[2] = '\0';
        const int number = strtoul(num, NULL, 10);
        for (i = 0; e164_country2[i].country_name && e164_country2[i].num <= number; i++) {
            if (e164_country2[i].num == number) return e164_country2[i].GSM_E164_FIELD;
        }
    }

    if (len == 0 || len == 1) {
        num[2] = '\0';
        num[1] = '\0';
        const int number = strtoul(num, NULL, 0);
        for (i = 0; e164_country1[i].country_name && e164_country1[i].num <= number; i++) {
            if (e164_country1[i].num == number) return e164_country1[i].GSM_E164_FIELD;
        }
    }

    return "";
}


int e164_country_code(const char * const country) {
    uint_fast32_t i;

    const size_t len = strlen(country)+1;

    for (i = 0; e164_country3[i].country_name; i++) {
        if (memcmp(e164_country3[i].country_code, country, len) == 0) return e164_country3[i].num;
    }

    for (i = 0; e164_country2[i].country_name; i++) {
        if (memcmp(e164_country2[i].country_code, country, len) == 0) return e164_country2[i].num;
    }

    for (i = 0; e164_country1[i].country_name; i++) {
        if (memcmp(e164_country1[i].country_code, country, len) == 0) return e164_country1[i].num;
    }

    return 0;
}
