#!/usr/bin/env bash

source "$(dirname "$0")/../t2utils.sh"

set -euf -o pipefail

usage() {
    echo "Usage:"
    echo "    $SNAME [OPTION...] <FLOW_FILE>"
    echo
    echo "Optional arguments:"
    echo "    -g            output GeoIP information"
    echo "    -d            only output IDs associated with multiple IPs"
    echo "    -h, --help    show this help, then exit"
}

# parse arguments
GEOIP=0
DUPLICATE=0
FLOWFILE=""

while [ $# -ne 0 ]; do
    case "$1" in
        -g) GEOIP=1;;
        -d) DUPLICATE=1;;
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

if [ ! -f "$FLOWFILE" ]; then
    abort_required_file
elif [ ! -r "$FLOWFILE" ]; then
    fatal "Cannot read flow file '$FLOWFILE'"
fi

# check that flow file and header file exist
HDRFILE="${FLOWFILE%flows.txt}headers.txt"
[ -r "$HDRFILE" ] || (echo "$HDRFILE: cannot read header file" >&2; exit 1)

# extract column numbers
COLS=(flowInd srcIP dstIP httpUsrAg httpAvastCid httpEsetUid httpMethods)

if [ "$GEOIP" -eq 1 ]; then
    if [ -n "$(AWK -v col="srcIpCountry" '$3 == col' "$HDRFILE")" ]; then
        COLS+=(srcIpCountry dstIpCountry srcIpCity dstIpCity)  # geoip plugin
    else  # basicFlow plugin
        COLS+=(srcIPCC dstIPCC)
        if [ -n "$(AWK -v col="srcIPCity" '$3 == col' "$HDRFILE")" ]; then
            COLS+=(ssrcIPCity dstIPCity)
        fi
    fi
fi
ARGS=()
for c in "${COLS[@]}"; do
    n="$(AWK -v col="$c" '$3 == col { print $1 }' "$HDRFILE")"
    if [ -z "$n" ]; then
        fatal "Missing column in flow file: $c"
    fi
    ARGS+=(-v "${c}=${n}")
done

# parse flow file
AWKF -v GEOIP="$GEOIP" -v DUPLICATE="$DUPLICATE" ${ARGS[*]} '
    # from tawk
    function strisempty(val) {
        return length(val) == 0 || val == "\"\""
    }

    # from tawk
    function unquote(s) {
        if (s ~ /^"/ || s ~ /"$/) {
            if (s ~ /^"/) s = substr(s, 2)
            if (s ~ /"$/) s = substr(s, 1, length(s) - 1)
            gsub(/\\"/, "\"", s)
        }
        return s
    }

    function printId(av, id,        _tmp) {
        # server -> client flow so switch src and dst
        if (!strtonum($httpMethods)) {
            # switch src/dst IP
            _tmp = $dstIP
            $dstIP = $srcIP
            $srcIP = _tmp
            if (GEOIP) {
                # switch src/dst country/city
                if (srcIpCountry) {
                    # switch src/dst country
                    _tmp = $dstIpCountry
                    $dstIpCountry = $srcIpCountry
                    $srcIpCountry = _tmp
                    # switch src/dst city
                    _tmp = $dstIpCity
                    $dstIpCity = $srcIpCity
                    $srcIpCity = _tmp
                } else {
                    # switch src/dst country
                    _tmp = $dstIPCC
                    $dstIPCC = $srcIPCC
                    $srcIPCC = _tmp
                    if (srcIPCity) {
                        # switch src/dst city
                        _tmp = $dstIPCity
                        $dstIPCity = $srcIPCity
                        $srcIPCity = _tmp
                    }
                }
            }
        }
        id = unquote(id)
        if (GEOIP) {
            if (srcIpCountry) {
                print $flowInd, $srcIP, $dstIP, $srcIpCountry, $srcIpCity, $dstIpCountry, $dstIpCity, av, id
            } else if (srcIPCity) {
                print $flowInd, $srcIP, $dstIP, $srcIPCC, $srcIPCity, $dstIPCC, $dstIPCity, av, id
            } else {
                print $flowInd, $srcIP, $dstIP, $srcIPCC, $dstIPCC, av, id
            }
        } else {
            print $flowInd, $srcIP, $dstIP, av, id
        }
    }

    function addId(av, id,        _ip) {
        if (strtonum($httpMethods)) {
            _ip = $srcIP
        } else {
            _ip = $dstIP
        }
        id = av "\t" unquote(id)
        if (!(id in unique)) {
            # first IP for this ID
            unique[id] = _ip
        } else if (!index(unique[id], _ip)) {
            # new IP for this ID
            unique[id] = _ip " " unique[id]
        }
    }

    function process(av, id) {
        if (DUPLICATE) {
            addId(av, id)
        } else {
            printId(av, id)
        }
    }

    BEGIN {
        if (DUPLICATE) {
            print "%antivirus", "ID", "clientIPs"
        } else {
            if (GEOIP) {
                if (srcIpCity || srcIPCity) {
                    print "%flowInd", "clientIp", "serverIp", "clientIpCountry", "clientIpCity", "serverIpCountry", "serverIpCity", "antivirus", "ID"
                } else {
                    print "%flowInd", "clientIp", "serverIp", "clientIpCountry", "serverIpCountry", "antivirus", "ID"
                }
            } else {
                print "%flowInd", "clientIp", "serverIp", "antivirus", "ID"
            }
        }
    }

    # skip flow header
    substr($0, 0, 1) == "%" { next }

    # Avira
    $httpUsrAg ~ /AntiVir-NGUpd/ {
        match($httpUsrAg, /([a-f0-9]{40}); [0-9]*-AVHOE/, id)
        process("Avira", id[1])
    }

    # AVG / Avira
    !strisempty($httpAvastCid) { process("Avast/AVG", $httpAvastCid) }

    # ESET
    !strisempty($httpEsetUid) { process("ESET", $httpEsetUid) }

    END {
        if (DUPLICATE) {
            for (_ip in unique) {
                tmp = unique[_ip]
                if (index(tmp, " ")) {
                    print _ip, tmp
                }
            }
        }
    }
' "$FLOWFILE"
