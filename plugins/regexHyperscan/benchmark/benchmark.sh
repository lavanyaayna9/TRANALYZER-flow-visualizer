#!/usr/bin/env bash

source "$(dirname "$0")/../../../scripts/t2utils.sh"

usage() {
    echo "Usage:"
    echo "    $SNAME [OPTION...]"
    echo
    echo "Optional arguments:"
    echo "    -b                Build Tranalyzer2 and the required plugins"
    echo "    -r                PCAP file to use [default: $PCAP]"
    echo "    -o                Output folder [default: $OUTDIR]"
    echo "    -w                Benchmark stats filename [default: $BENCHMARK_LOG]"
    echo "    -a                Append logs to benchmark stats file instead of overwriting"
    echo "    -y                do not ask for confirmation before executing an action"
    echo "    -h, --help        Show this help, then exit"
}

cleanup() {
    local ret="$1"
    [ -z "$ret" ] && ret=0

    if [ "$(pgrep -P $$ | wc -l)" -gt 1 ]; then
        printinf "Killing all subprocesses..."
        kill -- -$$
    fi

    exit $ret
}

# Default values
PCAP='/tmp/regex_benchmark.pcap'
BENCHMARK_LOG='benchmark_stats.log'
OUTDIR='/tmp'

# Options
while [ $# -ne 0 ]; do
    case "$1" in
        -a)
            APPEND=1
            ;;
        -b)
            BUILD=1
            ;;
        -r)
            validate_next_pcap "$1" "$2"
            PCAP="$($READLINK -f "$2")"
            shift
            ;;
        -o)
            validate_next_arg "$1" "$2"
            OUTDIR="$($READLINK -f "$2")"
            shift
            ;;
        -w)
            validate_next_arg "$1" "$2"
            BENCHMARK_LOG="$($READLINK -f "$2")"
            shift
            ;;
        -y|--yes)
            YES="yes"
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

PLUGINS=(
    basicFlow
    regex_re2
    regexHyperscan
    txtSink
)

if [ $BUILD ]; then
    "$T2BUILD" -f tranalyzer2 "${PLUGINS[@]}" || exit 1
else
    abort_if_t2_exec_not_found
    for plugin in "${PLUGINS[@]}"; do
        if [ -z "$("$T2BUILD" -l | grep -Fw "$plugin")" ]; then
            printerr "Plugin '$plugin' not found in plugin folder"
            ABORT=1
        fi
    done
    if [ $ABORT ]; then
        printinf "Try using $SNAME '-b' option"
        exit 1
    fi
fi

validate_pcap "$PCAP" || exit 1

if [ ! -d "$OUTDIR" ]; then
    ask_default_yes "Output folder '$OUTDIR' does not exist... create it" "$YES"
    [ $? -ne 0 ] && exit 0
    mkdir -p "$OUTDIR"
    printf "Folder '$OUTDIR' created\n"
fi

if [ -z "$APPEND" ] && [ -f "$BENCHMARK_LOG" ]; then
    ask_default_no "Benchmark file '$BENCHMARK_LOG' already exists... overwrite it" "$YES"
    [ $? -ne 0 ] && exit 0
    echo > "$BENCHMARK_LOG"
fi

# Default Tranalyzer options
T2OPTS=(-f 4 -l -r "$PCAP")

# Work from this script location
cd "$SHOME"

# Setup signal handler
trap "trap - SIGTERM && cleanup 1" HUP INT QUIT TERM
trap "cleanup \$?" EXIT

# test with default regex files
cp re2_set1.txt ~/.tranalyzer/plugins/re2file.txt
cp hs_set1.txt ~/.tranalyzer/plugins/hsregexes.txt

echo "RE2: set1"
echo >> "$BENCHMARK_LOG"
echo -ne "RE2\tset1\t" >> "$BENCHMARK_LOG"
(time T2 "${T2OPTS[@]}" -b re2_plugins.txt -w "${OUTDIR}/re2_set1") 2>&1 | $SED -rne 's/real\s+(.*)/\1/p' >> "$BENCHMARK_LOG"

echo "Hyperscan: set1"
echo -ne "HS\tset1\t" >> "$BENCHMARK_LOG"
(time T2 "${T2OPTS[@]}" -b hs_plugins.txt -w "${OUTDIR}/hs_set1") 2>&1 | $SED -rne 's/real\s+(.*)/\1/p' >> "$BENCHMARK_LOG"

# test with different number of regexes
for count in 10 20 50 100 150 200 250 500 1000; do
    echo "RE2: ${count}"
    head -n $count all_re2.txt > ~/.tranalyzer/plugins/re2file.txt
    echo -ne "RE2\t${count}\t" >> "$BENCHMARK_LOG"
    (time T2 "${T2OPTS[@]}" -b re2_plugins.txt -w "${OUTDIR}/re2_${count}") 2>&1 | $SED -rne 's/real\s+(.*)/\1/p' >> "$BENCHMARK_LOG"

    echo "Hyperscan: ${count}"
    head -n $count all_hs.txt > ~/.tranalyzer/plugins/hsregexes.txt
    echo -ne "HS\t${count}\t" >> "$BENCHMARK_LOG"
    (time T2 "${T2OPTS[@]}" -b hs_plugins.txt -w "${OUTDIR}/hs_${count}") 2>&1 | $SED -rne 's/real\s+(.*)/\1/p' >> "$BENCHMARK_LOG"
done

tar czf "regex_benchmark_data_$(date +%s).tar.gz" "$BENCHMARK_LOG" "$OUTDIR"/re2_*.txt "$OUTDIR"/hs_*.txt
