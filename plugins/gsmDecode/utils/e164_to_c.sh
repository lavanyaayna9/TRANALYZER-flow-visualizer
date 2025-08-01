#!/usr/bin/env bash

source "$(dirname "$0")/../../../scripts/t2utils.sh"

usage() {
    printf "Usage:\n"
    printf "    $SNAME [OPTION...]\n\n"
    printf "Optional arguments:\n"
    printf "    -g      generate all arrays\n"
    printf "    -1      generate e164_country1\n"
    printf "    -2      generate e164_country2\n"
    printf "    -3      generate e164_country3\n"
    printf "    -h      display this help, then exit\n"
}

E164_CSV="e164.csv"
FILEPATH="$SHOME/$E164_CSV"
E164_LIST_C="$($READLINK -f "$SHOME/../src/e164_list.c")"
MCC_MNC_LIST_JSON="$SHOME/mcc-mnc-list.json"

while [ $# -gt 0 ]; do
    case "$1" in
        -g|--generate)
            E164_LEN=(1 2 3)
            ;;
        -1)
            E164_LEN+=(1)
            ;;
        -2)
            E164_LEN+=(2)
            ;;
        -3)
            E164_LEN+=(3)
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

if [ -z "$E164_LEN" ]; then
    printerr "One of -g/-1/-2/-3 option is required"
    abort_with_help
fi

check_dependency jq

if [ ! -f "$FILEPATH" ]; then
    printerr "Could not find required input file '$FILEPATH'"
    exit 1
fi

TEMPFILE="$(mktemp)"

for i in ${E164_LEN[@]}; do
    FIRST_ROW="static e164_item_t e164_country$i"
    AWKF -v len=$i -v FIRST_ROW="$FIRST_ROW" -v SHOME="$SHOME" -v MCC_MNC_LIST_JSON="$MCC_MNC_LIST_JSON" '
        BEGIN {
            printf "%s[] = {\n", FIRST_ROW
        }
        length($1) == len {
            cc = ""
            _cmd = "jq \".[] | select(.countryName == \\\"" $2 "\\\") | .countryCode\" \"" MCC_MNC_LIST_JSON "\""
            _cmd | getline cc
            close(_cmd)
            if (length(cc) == 0) {
                country = gensub(/\s*\(.*$/, "", 1, $2)
                _cmd = "jq \".[] | select(.countryName == \\\"" country "\\\") | .countryCode\" \"" MCC_MNC_LIST_JSON "\""
                _cmd | getline cc
                close(_cmd)
            }
            if (!cc) cc = "\"??\""
            $2 = "\"" $2 "\""
            switch (len) {
                case 1:
                    printf "    { %2s, %s, %-48s },\n", $1, cc, $2
                    break
                case 2:
                    printf "    { %s, %s, %-54s },\n", $1, cc, $2
                    break
                case 3:
                    printf "    { %s, %-15s, %-100s },\n", $1, cc, $2
                    break
            }
        }
        END {
            switch (len) {
                case 1:
                    printf "    { %2s, %s, %-48s },\n", -1, "NULL", "NULL"
                    break
                case 2:
                    printf "    { %s, %s, %-54s },\n", -1, "NULL", "NULL"
                    break
                case 3:
                    printf "    { %s, %-15s, %-100s },\n", -1, "NULL", "NULL"
                    break
            }
            print "};\n"
        }' "$FILEPATH" > "$TEMPFILE"

        # Update the array in the C file
        $SED -i "
            /^$FIRST_ROW/, /^};\s*$/ {
                /^};\s*$/ {
                    r $TEMPFILE
                };
                d
            }" "$E164_LIST_C"
done

rm -f "$TEMPFILE"
