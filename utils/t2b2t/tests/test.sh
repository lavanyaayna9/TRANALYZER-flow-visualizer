#!/usr/bin/env bash

source "$(dirname "$0")/../../../scripts/t2utils.sh"

usage() {
    echo "Usage:"
    echo "    $SNAME [OPTION...] <FILE>"
    echo
    echo "Optional arguments:"
    echo "    -s                Compress output from socketSink"
    echo "    -c                Compress output from t2b2t"
    echo "    -j                Produce JSON instead of text"
    echo "    -p                Print preamble as comment in output"
    echo "    -P                Print preamble in a separate fila separate file"
    echo "    -R                Change port for each test (required on some systems)"
    echo "    -v                Activate verbose output"
    echo "    -h, --help        Show this help, then exit"
}

abort() {
    [ "$1" ] && printerr "$1"
    exit 1
}

run_cmd() {
    if [ -z "$1" ]; then
        printerr "Usage: run_cmd command"
        exit 1
    fi
    local cmd=("$@")
    [ "$VERBOSE" ] && echo "${cmd[*]}"
    "${cmd[@]}" || abort "Command '${cmd[*]}' failed"
}

build_socketSink() {
    local cmd=("$T2BUILD" socketSink)
    [ "$VERBOSE" ] && echo "${cmd[*]}"
    "${cmd[@]}" &> /dev/null || abort "Command '${cmd[*]}' failed"
}

rebuild() {
    local cmd=("$T2BUILD" -R)
    if [ -z "$("${cmd[@]}" -l | grep socketSink)" ]; then
        build_socketSink
    fi
    [ "$VERBOSE" ] && echo "${cmd[*]}"
    "${cmd[@]}" &> /dev/null || abort "Command '${cmd[*]}' failed"
}

run_nc() {
    if [ -z "$1" ]; then
        printerr "Usage: run_nc file"
        exit 1
    fi
    local file="$1"
    local dport=$($T2CONF socketSink -G DPORT | AWK -F' = ' '{ print $2 }')
    # TODO FIXME some Linux systems require -p as well...
    [ "$(uname)" = "Darwin" ] && local nc_opt="-p"
    local cmd=(nc -l 127.0.0.1 $nc_opt $dport)
    [ "$VERBOSE" ] && echo "${cmd[*]} > $file &"
    "${cmd[@]}" > "$file" &
    [ $? -eq 0 ] || abort "Command '${cmd[*]}' failed"
}

T2B2T_OPTS=()
COMPRESS_IN=0

while [ $# -ne 0 ]; do
    case "$1" in
        -v) VERBOSE=1;;
        -s) COMPRESS_IN=1;;
        -R) ROTATE_PORTS=1;;
        -c|-j|-p|-P) T2B2T_OPTS+=($1);;
        -h|-\?|--help) usage; exit 0;;
        -*) abort_option_unknown "$1";;
        *)
            validate_pcap "$1"
            PCAP="$1"
            ;;
    esac
    shift
done

if [ ! -f "$PCAP" ]; then
    abort_required_file
fi

validate_pcap "$PCAP"

if [ ! -f "$(get_t2b2t_exec)" ]; then
    if ! make -C "$T2HOME/utils/t2b2t"; then
        printerr "Failed to build 't2b2t'"
        exit 1
    fi
    printok "Successfully built t2b2t"
fi

# configure socketSink
run_cmd "$T2CONF" socketSink -D CONTENT_TYPE=0 -D GZ_COMPRESS=$COMPRESS_IN
[ "$ROTATE_PORTS" ] && DPORT=$($T2CONF socketSink -G DPORT | AWK -F' = ' '{ print $2 }')

# suffix for nc output
SUFFIX=".bin"
[ $COMPRESS_IN -eq 1 ] && SUFFIX="$SUFFIX.gz"

for dataShft in $(seq 0 2) 16; do
    # configure tranalyzer2
    run_cmd "$T2CONF" tranalyzer2 -D BUF_DATA_SHFT=$dataShft
    for hostInfo in $(seq 0 1); do
        [ "$VERBOSE" ] && printinf "BUF_DATA_SHFT=$dataShft, PREAMBLE=$hostInfo"
        tmpfile="/tmp/x${dataShft}${hostInfo}${SUFFIX}"
        # configure socketSink
        if [ "$ROTATE_PORTS" ]; then
            run_cmd "$T2CONF" socketSink -D DPORT=$DPORT
            DPORT=$((DPORT+1))
        fi
        run_cmd "$T2CONF" socketSink -D HOST_INFO=$hostInfo
        rebuild
        # run nc and t2
        run_nc "$tmpfile"
        run_cmd "$(get_t2_exec)" -r "$PCAP" -w /tmp/x -l
        # make sure everything worked out
        [ -s "$tmpfile" ] || abort "Failed to receive '$tmpfile'"
        # convert
        run_cmd "$(get_t2b2t_exec)" "${T2B2T_OPTS[@]}" -r "$tmpfile"
        echo
    done
done

# reset
run_cmd "$T2CONF" --reset socketSink tranalyzer2
