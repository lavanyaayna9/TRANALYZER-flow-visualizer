#!/usr/bin/env bash

source "$(dirname "$0")/../../../scripts/t2utils.sh"

usage() {
    printf "Usage:\n"
    printf "    $SNAME [OPTION...]\n\n"
    printf "Optional arguments:\n"
    printf "    -h      display this help, then exit\n"
}

FILENAME_CSV="tacdb_orig.csv"
FILEPATH="$SHOME/$FILENAME_CSV"
OUTFILE="$($READLINK -f "$SHOME/../tacdb.csv")"

while [ $# -gt 0 ]; do
    case "$1" in
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

if [ ! -f "$FILEPATH" ]; then
    printerr "Could not find required input file '$FILEPATH'"
    exit 1
fi

# Number of columns
NR="$(wc -l "$FILEPATH" | AWK '{ print $1 }')"
NR=$((NR-2))
echo "% $NR" > "$OUTFILE"

# Column names
printf "%% tac\tmanuf\tmodel\taka\n" >> "$OUTFILE"

$TAWK -F, 'NR > 2 {
    printf "%s", strtonum(chomp($1))
    for (i = 2; i <= NF; i++) {
        if ($i ~ /^\s*"/) {
            start = lstrip($i)
        } else if (start) {
            start = start "," $i
        }

        if (!start) {
            printf OFS "%s", chomp($i)
        } else if ($i ~ /"\s*$/) {
            gsub(/^\s*"\s*/, "", start)
            gsub(/\s*"\s*$/, "", start)
            printf OFS "%s", start
            start = 0
        }
    }
    printf "\n"
}' "$FILEPATH" | sort -n -k1,1 | AWKF '{
    print $1, $2, $3, $NF
}' >> "$OUTFILE"
