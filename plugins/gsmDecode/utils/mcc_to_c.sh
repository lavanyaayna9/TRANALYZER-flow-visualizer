#!/usr/bin/env bash

source "$(dirname "$0")/../../../scripts/t2utils.sh"

usage() {
    printf "Usage:\n"
    printf "    $SNAME [OPTION...]\n\n"
    printf "Optional arguments:\n"
    printf "    -a      update and generate all arrays\n"
    printf "    -g      generate all arrays\n"
    printf "    -u      update MCC/MNC list\n"
    printf "    -c      generate MCC array\n"
    printf "    -n      generate MNC array\n"
    printf "    -h      display this help, then exit\n"
}

FILENAME_JSON="mcc-mnc-list.json"
FILENAME_CSV="mcc-mnc-table.csv"
FILEPATH="$SHOME/$FILENAME_JSON"
MCC_LIST_C="$($READLINK -f "$SHOME/../src/mcc_list.c")"

while [ $# -gt 0 ]; do
    case "$1" in
        -a|--all)
            UPDATE=1
            MCC=1
            MNC=1
            ;;
        -g|--generate)
            MCC=1
            MNC=1
            ;;
        -u|--update)
            UPDATE=1
            ;;
        -c|--mcc)
            MCC=1
            ;;
        -n|--mnc)
            MNC=1
            ;;
        -h|-\?|--help)
            usage
            exit 0
            ;;
        *)
            abort_option_unknown "$1"
            ;;
    esac
    shift
done

if [ -z "${UPDATE}${MCC}${MNC}" ]; then
    printerr "One of -a/-g/-u/-c/-n option is required"
    abort_with_help
fi

check_dependency jq

if [[ $UPDATE -gt 0 ]]; then
    t2_wget_n "https://raw.githubusercontent.com/PodgroupConnectivity/mcc-mnc-list/master/$FILENAME_JSON" || exit 1
fi

if [ ! -f "$FILEPATH" ]; then
    printerr "Could not find required input file '$FILEPATH'"
    exit 1
fi

################################################################################
# MCC list
################################################################################

if [[ $MCC -gt 0 ]]; then
    TEMPFILE="$(mktemp)"
    jq -r '.[] | [.mcc, .countryCode, .countryName] | @csv' "$FILEPATH" \
        | sort -k1,1 -u \
        | AWK -F'","' '
            BEGIN {
                print "// Mobile Country Codes (MCC)"
                print "static struct {"
                print "    int mcc;"
                print "    const char * const countryCode;"
                print "    const char * const countryName;"
                print "} mcc_list[] = {"
            }

            {

                if ($1 ~ /^"/) $1 = substr($1, 2)
                if ($1 ~ /"$/) $1 = substr($1, 1, length($1)-1)
                $1 = strtonum($1)

                if (length($2) == 0 && length($3) == 0) {
                    switch ($1) {
                        case 1:
                            $2 = "\"Test\""
                            $3 = "\"Test\""
                            break
                        case 901:
                        case 902:
                        case 991:
                        case 999:
                            $2 = "\"WW\""
                            $3 = "\"Worldwide\""
                            break
                        default:
                            next
                    }
                }

                if ($1 != last_mcc) {
                    if ($2 ~ /,$/) $2 = substr($2, 1, length($2)-1)
                    if ($2 !~ /^"/) $2 = "\"" $2
                    if ($2 !~ /"$/) $2 = $2 "\""

                    if ($3 ~ /,$/) $3 = substr($3, 1, length($3)-1)
                    if ($3 !~ /^"/) $3 = "\"" $3
                    if ($3 !~ /"$/) $3 = $3 "\""

                    printf "    { %3d, %-16s, %-58s },\n", $1, $2, $3

                    last_mcc = $1
                }
            }

            END {
                printf "    { %3d, %-16s, %-58s }\n", -1, "NULL", "NULL"
                print "};"
            }' > "$TEMPFILE"

        # Update the array in the C file
        $SED -i "
            /^\/\/\s\+Mobile\s\+Country\s\+Codes\s\+(MCC)\s*$/, /^};\s*$/ {
                /^};\s*$/ {
                    r $TEMPFILE
                };
                d
            }" "$MCC_LIST_C"
        rm -f "$TEMPFILE"
fi

################################################################################
# MNC list
################################################################################

if [[ $MNC -gt 0 ]]; then
    TEMPFILE="$(mktemp)"
    jq -r '.[] | [.mcc, .mnc, .brand, .operator] | @csv' "$FILEPATH" \
        | sort -k1,2 -u \
        | AWK -F'","' '
            BEGIN {
                print "// Mobile Network Codes (MNC)"
                print "static struct {"
                print "    int mcc;"
                print "    int mnc;"
                print "    const char * const brand;"
                print "    const char * const operator;"
                print "} mnc_list[] = {"
            }

            $2 ~ /^\?$/ { next } # Ignore records with unknown MNC

            {
                if ($1 ~ /^"/) $1 = substr($1, 2)
                if ($1 ~ /"$/) $1 = substr($1, 1, length($1)-1)
                $1 = strtonum($1)

                if ($2 ~ /^"/) $2 = substr($2, 2)
                if ($2 ~ /"$/) $2 = substr($2, 1, length($2)-1)
                $2 = strtonum($2)

                if ($4 == "\"?\"" || length($4) == 0) {
                    if (length($3) != 0) {
                        $4 = $3
                    } else {
                        next
                    }
                }

                if ($1 != last_mcc || $2 != last_mnc) {
                    if ($3 ~ /,$/) $3 = substr($3, 1, length($3)-1)
                    if ($3 !~ /^"/) $3 = "\"" $3
                    if ($3 !~ /"$/) $3 = $3 "\""
                    gsub(/""/, "\\\"", $3)

                    if ($4 ~ /,$/) $4 = substr($4, 1, length($4)-1)
                    if ($4 !~ /^"/) $4 = "\"" $4
                    if ($4 !~ /"$/) $4 = $4 "\""
                    gsub(/""/, "\\\"", $4)

                    printf "    { %3d, %3d, %-50s, %-77s },\n", $1, $2, $3, $4

                    last_mcc = $1
                    last_mnc = $2
                }
            }

            END {
                printf "    { %3d, %3d, %-50s, %-77s }\n", -1, -1, "NULL", "NULL"
                print "};"
            }' > "$TEMPFILE"

        # Update the array in the C file
        $SED -i "
            /^\/\/\s\+Mobile\s\+Network\s\+Codes\s\+(MNC)\s*$/, /^};\s*$/ {
                /^};\s*$/ {
                    r $TEMPFILE
                };
                d
            }" "$MCC_LIST_C"
        rm -f "$TEMPFILE"
fi
