#!/usr/bin/env bash

source "$(dirname "$0")/../t2utils.sh"

set -euf -o pipefail

PUNKDIR="/tmp/httpPunk"

usage() {
    echo "Usage:"
    echo "    $SNAME -o OUTPUT_DIR [OPTION...] <FLOW_FILE>"
    echo
    echo "Optional arguments:"
    echo "    -o DIR        directory where malware samples are extracted"
    echo "    -p DIR        httpSniffer punk directorty (default: $PUNKDIR)"
    echo "    -h, --help    show this help, then exit"
}

# parse arguments
OUTDIR=""
while [ $# -ne 0 ]; do
    case "$1" in
        -o)
            validate_next_arg "$1" "$2"
            OUTDIR="$2"
            shift
            ;;
        -p)
            validate_next_dir "$1" "$2"
            PUNKDIR="$2"
            shift
            ;;
        -h|-\?|--help)
            usage
            exit 0
            ;;
        *)
            if [ ! -f "$1" ]; then
                abort_option_unknown "$1"
            fi
            FLOWFILE="$1"
            ;;
    esac
    shift
done

if [ ! -d "$OUTDIR" ]; then
    printerr "'-o' option is required"
    abort_with_help
fi

if [ ! -f "$FLOWFILE" ]; then
    abort_required_file
elif [ ! -r "$FLOWFILE" ]; then
    fatal "Cannot read flow file '$FLOWFILE'"
fi

if [ ! -d "$PUNKDIR" ]; then
    fatal "Punk directory '$PUNKDIR' does not exist"
fi

HDRFILE="${FLOWFILE%flows.txt}headers.txt"
if [ ! -r "$HDRFILE" ]; then
    fatal "Cannot read header file '$HDRFILE'"
fi

# get absolute path of extraction script and flow file before cd to output dir
avgext="$(dirname "$(realpath "$0")")/avg_extract.py"
[ -x "$avgext" ] || fatal "$avgext: script not found or not executable"

aviraext="$(dirname "$(realpath "$0")")/avira_extract.py"
[ -x "$aviraext" ] || fatal "$aviraext: script not found or not executable"

FLOWFILE="$(realpath "$FLOWFILE")"
PUNKDIR="$(realpath "$PUNKDIR")"
HDRFILE="$(realpath "$HDRFILE")"

cd "$OUTDIR"

# extract column numbers
COLS=(flowInd httpHosts httpPunk httpUsrAg httpURL httpMimes httpCFlags)
ARGS=()
for c in "${COLS[@]}"; do
    n="$(AWK -v col="$c" '$3 == col { print $1 }' "$HDRFILE")"
    if [ -z "$n" ]; then
        echo "Missing column in flow file: $c" >&2
        exit 1
    fi
    ARGS+=(-v "${c}=${n}")
done

# parse flow file
AWKF -v PDIR="$PUNKDIR" -v AVG="$avgext" -v AVIRA="$aviraext" ${ARGS[*]} '
    # avira extraction function
    function aviraext(flowInd, file,        cmd) {
        cmd = AVIRA " " PDIR "/" file " " flowInd
        if (system(cmd) == 0) {
            print "Avira sample extracted"
        }
    }

    # AVG / Avast extraction function
    function avgext(flowInd, file,        cmd) {
        cmd = AVG " " PDIR "/" file " " flowInd
        if (system(cmd) == 0) {
            print "AVG/Avast sample extracted"
        }
    }

    !(and(strtonum($httpCFlags), 0x80) && length($httpPunk)) {
        next
    }

    # Avira
    $httpHosts ~ /spsubmit.avira.com/ {
        aviraext($flowInd, $httpPunk)
    }

    # AVG
    $httpHosts ~ /submit5.avcdn.net/ && $httpURL ~ /submit50.cgi/ && $httpMimes ~ /iavs4\/upload/ {
        avgext($flowInd, $httpPunk)
    }

    # Avast
    $httpHosts ~ /submit5.avast.com/  && $httpURL ~ /submit50.cgi/ && $httpMimes ~ /iavs4\/upload/ {
        avgext($flowInd, $httpPunk)
    }
' "$FLOWFILE"
