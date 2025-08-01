#!/usr/bin/env bash

T2FMDIR="$(dirname "${0}")/.."
source "${T2FMDIR}/../t2utils.sh"
T2FMDIR="$("${READLINK}" -f "${T2FMDIR}")"

# Default values for command line arguments
FLOWFILE="${T2FMDIR}/tests/x_flows.txt"
DBNAME="tranalyzer"

usage() {
    echo "Usage:"
    echo "    ${SNAME} [OPTION...] BACKEND_1 [BACKEND_2]"
    echo
    echo "Backends:"
    echo "    -C                  ClickHouse"
    echo "    -m                  MongoDB"
    echo "    -p                  PostgreSQL"
    echo "    -t                  Tawk"
    echo
    echo "Optional arguments:"
    echo "    -d                  Run vimdiff when a test fails"
    echo "    -f                  Abort as soon as a test fails"
    echo "    -F file             Flow file to use for tawk tests [default: x_flows.txt]"
    echo "    -T from to          Only consider data between from and to [default: all]"
    echo "    -n num              Compute top num statistics [default: all]"
    echo "    test_name           A list of tests to run [default: all]"
    echo
    echo "Help and documentation arguments:"
    echo "    -?, -h, --help      Show help options and exit"
}

while [[ "${#}" -gt 0 ]]; do
    case "${1}" in
        # Backends
        -C|--clickhouse)
            if ! grep -qFw clickhouse <<< "${BACKENDS[*]}"; then
                BACKENDS+=(clickhouse)
            fi
            ;;
        -m|--mongo)
            if ! grep -qFw mongo <<< "${BACKENDS[*]}"; then
                BACKENDS+=(mongo)
            fi
            ;;
        -p|--postgres)
            if ! grep -qFw psql <<< "${BACKENDS[*]}"; then
                BACKENDS+=(psql)
            fi
            ;;
        -t|--tawk)
            if ! grep -qFw tawk <<< "${BACKENDS[*]}"; then
                BACKENDS+=(tawk)
            fi
            ;;
        # Optional arguments
        -d|--diff) DIFF=1;;
        -f|--fatal) FATAL=1;;
        -F|--flow-file)
            validate_next_file "${1}" "${2}"
            if ! grep -qFw tawk <<< "${BACKENDS[*]}"; then
                BACKENDS+=(tawk)
            fi
            FLOWFILE="${2}"
            shift
            ;;
        -T)
            validate_next_num "${1}" "${2}"
            validate_next_num "${1}" "${3}"
            TIME_FROM="$("${TAWK}" '{ print timestamp($1) }' <<< "${2}")"
            TIME_TO="$("${TAWK}" '{ print timestamp($1) }' <<< "${3}")"
            shift  # TIME_FROM
            shift  # TIME_TO
            ;;
        -n|--top-n)
            validate_next_num "${1}" "${2}"
            TOP_N="${2}"
            shift
            ;;
        -\?|-h|--help)
            usage
            exit 0
            ;;
        *)
            if [[ -f "${T2FMDIR}/tawk/${1}" ]]; then
                TESTS+=("${1}")
            elif [[ -f "${1}" ]]; then
                _FNAME="$(AWK -F'/' '{ print $NF }' <<< "${1}")"
                TESTS+=("${_FNAME}")
            else
                _FOLDER="$(AWK -F'/' 'NF > 1 { print $(NF-1) }' <<< "${1}")"
                _FNAME="$(AWK -F'/' '{ print $NF }' <<< "${1}")"
                if [[ "${_FNAME}" != "bottom_"* ]]; then
                    abort_option_unknown "${1}"
                else
                    _TOPSCRIPT="$(AWK '{ gsub(/^bottom_/, "top_"); print }' <<< "${_FNAME}")"
                    if [[ -f "${T2FMDIR}/tawk/${_TOPSCRIPT}" ]]; then
                        TESTS+=("${1}")
                    elif [[ -f "${_FOLDER}/${_TOPSCRIPT}" ]]; then
                        TESTS+=("${_FNAME}")
                    else
                        abort_option_unknown "${1}"
                    fi
                fi
            fi
            ;;
    esac
    shift
done

NUM_BACKENDS="${#BACKENDS[*]}"
if [[ "${NUM_BACKENDS}" -eq 0 ]]; then
    printerr "One or two backends are required"
    abort_with_help
elif [[ "${NUM_BACKENDS}" -gt 2 ]]; then
    printerr "A maximal of two backends can be specified"
    abort_with_help
fi

if [[ "${#TESTS[@]}" -eq 0 ]]; then
    for backend in "${BACKENDS[@]}"; do
        TESTS+=($(ls -1 "${T2FMDIR}/${backend}/"))
    done
    TESTS=($(printf '%s\n' "${TESTS[@]}" | sort -u))
fi

setup_clickhouse() {
    local _exec=()
    if [[ -n "${IS_MACOS}" ]]; then
        _exec+=(clickhouse client)
    else
        _exec+=(clickhouse-client)
    fi

    check_dependency "${_exec[0]}"

    DBTYPE="ClickHouse"
    SCRIPTS="${T2FMDIR}/clickhouse"
    CMD_CLICKHOUSE=(${_exec[@]})

    local databases
    if ! databases="$("${CMD_CLICKHOUSE[@]}" -q 'SHOW DATABASES' 2> /dev/null)"; then
        fatal "${DBTYPE} server is not running"
    fi

    if ! grep "^${DBNAME}$" <<< "${databases[@]}" &> /dev/null; then
        fatal "${DBTYPE} database '${DBNAME}' not found"
    fi

    CMD_CLICKHOUSE+=(-d "$DBNAME")

    if ! "${CMD_CLICKHOUSE[@]}" -q 'SHOW TABLES' | grep -Fw flow &> /dev/null; then
        fatal "${DBTYPE} table 'flow' not found in database '${DBNAME}'"
    fi

    local count
    count="$("${CMD_CLICKHOUSE[@]}" -q 'SELECT COUNT(*) FROM flow')"
    if [[ "${count}" -eq 0 ]]; then
        fatal "${DBTYPE} table 'flow' from database '${DBNAME}' is empty"
    fi

    local top_n="${TOP_N}"
    if [[ -z "${top_n}" ]]; then
        top_n="$("${CMD_CLICKHOUSE[@]}" --query 'SELECT COUNT(*) FROM flow')"
    fi

    local time_from="${TIME_FROM}"
    if [[ -z "${time_from}" ]]; then
        time_from="$("${CMD_CLICKHOUSE[@]}" --queries-file "${SCRIPTS}/min_time")"
    fi

    local time_to="${TIME_TO}"
    if [[ -z "${time_to}" ]]; then
        time_to="$("${CMD_CLICKHOUSE[@]}" --queries-file "${SCRIPTS}/max_time")"
    fi

    CMD_CLICKHOUSE+=(
        --param_n="${top_n}"
        --param_time_from="${time_from}"
        --param_time_to="${time_to}"
    )

    CMD_BOTTOM_CLICKHOUSE=("${CMD_CLICKHOUSE[@]}" --param_sort_order="1" --queries-file)
    CMD_CLICKHOUSE+=(--param_sort_order="-1" --queries-file)
}

setup_mongo() {
    check_dependency mongosh

    DBTYPE="MongoDB"
    SCRIPTS="${T2FMDIR}/mongo"
    CMD_MONGO=(mongosh --quiet "${DBNAME}")

    if ! "${CMD_MONGO[@]}" --eval 'db.getName()' &> /dev/null; then
        fatal "${DBTYPE} server is not running"
    fi

    local count
    count="$("${CMD_MONGO[@]}" --eval 'db.flow.countDocuments()')"
    if [[ "${count}" -eq 0 ]]; then
        fatal "${DBTYPE} collection 'flow' from DB '${DBNAME}' is empty"
    fi

    local top_n="${TOP_N}"
    if [[ -z "${top_n}" ]]; then
        top_n="${count}"
    fi

    local time_from="${TIME_FROM}"
    if [[ -z "${time_from}" ]]; then
        time_from="$("${CMD_MONGO[@]}" "${SCRIPTS}/min_time")"
        time_from="$("${TAWK}" '{ print utc($1) }' <<< "${time_from}")"
    fi

    local time_to="${TIME_TO}"
    if [[ -z "${time_to}" ]]; then
        time_to="$("${CMD_MONGO[@]}" "${SCRIPTS}/max_time")"
        time_to="$("${TAWK}" '{ print utc($1) }' <<< "${time_to}")"
    fi

    CMD_MONGO+=(
        --eval "const n = ${top_n}, \
                      time_from = new ISODate('${time_from}'), \
                      time_to = new ISODate('${time_to}');"
    )

    CMD_BOTTOM_MONGO=("${CMD_MONGO[@]}" --eval "const sort_order = -1;")
    CMD_MONGO+=(--eval "const sort_order = 1;")
}

setup_psql() {
    check_dependency psql

    DBTYPE="PostgreSQL"
    SCRIPTS="${T2FMDIR}/psql"
    CMD_PSQL=(psql -U postgres)

    local databases
    if ! databases="$("${CMD_PSQL[@]}" -l 2> /dev/null)"; then
        fatal "${DBTYPE} server is not running"
    fi

    if [[ -z "$(AWK -F'|' "\$1 ~ /^\s*${DBNAME}\s*$/" <<< "${databases}")" ]]; then
        fatal "${DBTYPE} database '${DBNAME}' not found"
    fi

    CMD_PSQL+=(-d "${DBNAME}" -A -t -F $'\t')

    if ! "${CMD_PSQL[@]}" -c 'SELECT "tablename" FROM pg_catalog.pg_tables' | grep -Fw flow &> /dev/null; then
        fatal "${DBTYPE} table 'flow' not found in database '${DBNAME}'"
    fi

    local count
    count="$("${CMD_PSQL[@]}" -c 'SELECT COUNT(*) FROM flow')"
    if [[ "${count}" -eq 0 ]]; then
        fatal "${DBTYPE} table 'flow' from database '${DBNAME}' is empty"
    fi

    local top_n="${TOP_N}"
    if [[ -z "${top_n}" ]]; then
        top_n="${count}"
    fi

    local time_from="${TIME_FROM}"
    if [[ -z "${time_from}" ]]; then
        time_from="$("${CMD_PSQL[@]}" -f "${T2FMDIR}/psql/min_time")"
    fi

    local time_to="${TIME_TO}"
    if [[ -z "${time_to}" ]]; then
        time_to="$("${CMD_PSQL[@]}" -f "${T2FMDIR}/psql/max_time")"
    fi

    CMD_PSQL+=(
        -v n="${top_n}"
        -v time_from="${time_from}"
        -v time_to="${time_to}"
    )

    CMD_BOTTOM_PSQL=("${CMD_PSQL[@]}" -v sort_order="ASC" -f)
    CMD_PSQL+=(-v sort_order="DESC" -f)
}

setup_tawk() {
    if [[ ! -f "${FLOWFILE}" ]]; then
        fatal "Flow file '${FLOWFILE}' does not exist"
    fi

    CMD_TAWK=("${TAWK}" -I "${FLOWFILE}")

    local top_n="${TOP_N}"
    if [[ -z "${top_n}" ]]; then
        top_n="$("${CMD_TAWK[@]}" '!hdr() { flows++ } END { print flows }')"
    fi

    local time_from="${TIME_FROM}"
    if [[ -z "${time_from}" ]]; then
        time_from="$("${CMD_TAWK[@]}" -f "${T2FMDIR}/tawk/min_time")"
    fi

    local time_to="${TIME_TO}"
    if [[ -z "${time_to}" ]]; then
        time_to="$("${CMD_TAWK[@]}" -f "${T2FMDIR}/tawk/max_time")"
    fi

    CMD_TAWK+=(
        -v time_from="${time_from}"
        -v time_to="${time_to}"
    )

    CMD_BOTTOM_TAWK=("${CMD_TAWK[@]}" -v n="-${top_n}" -f)
    CMD_TAWK+=(-v n="${top_n}" -f)
}

setup_backends() {
    for backend in "${BACKENDS[@]}"; do
        case "${backend}" in
            clickhouse) setup_clickhouse;;
            mongo) setup_mongo;;
            psql) setup_psql;;
            tawk) setup_tawk;;
            *)
                fatal "Unknown backend '${backend}'"
                ;;
        esac
    done
}

run_test() {
    local backend="${1}"
    if [[ "${test_name}" != "bottom_"* ]]; then
        case "${backend}" in
            clickhouse) "${CMD_CLICKHOUSE[@]}" "${T2FMDIR}/${backend}/${test_name}";;
            mongo) "${CMD_MONGO[@]}" "${T2FMDIR}/${backend}/${test_name}";;
            psql) "${CMD_PSQL[@]}" "${T2FMDIR}/${backend}/${test_name}";;
            tawk) "${CMD_TAWK[@]}" "${T2FMDIR}/${backend}/${test_name}";;
        esac
    else
        local _topscript
        _topscript="$(AWK '{ gsub(/^bottom_/, "top_"); print }' <<< "${test_name}")"
        case "${backend}" in
            clickhouse) "${CMD_BOTTOM_CLICKHOUSE[@]}" "${T2FMDIR}/${backend}/${_topscript}";;
            mongo) "${CMD_BOTTOM_MONGO[@]}" "${T2FMDIR}/${backend}/${_topscript}";;
            psql) "${CMD_BOTTOM_PSQL[@]}" "${T2FMDIR}/${backend}/${_topscript}";;
            tawk) "${CMD_BOTTOM_TAWK[@]}" "${T2FMDIR}/${backend}/${_topscript}";;
        esac
    fi
}

setup_backends

count=0
total="${#TESTS[@]}"
for test_name in "${TESTS[@]}"; do
    count=$((count+1))
    error=0
    for backend in "${BACKENDS[@]}"; do
        _topscript="${test_name}"
        if [[ "${test_name}" == "bottom_"* ]]; then
            _topscript="$(AWK '{ gsub(/^bottom_/, "top_"); print }' <<< "${_topscript}")"
        fi
        if [[ ! -f "${T2FMDIR}/${backend}/${_topscript}" ]]; then
            printerr "Test '${T2FMDIR}/${backend}/${test_name}' does not exist"
            error=1
        fi
    done

    [[ ${error} -ne 0 ]] && continue

    OUT=()
    for backend in "${BACKENDS[@]}"; do
        OUT+=("$(run_test "${backend}")")
    done

    printf "${BLUE}Test '${test_name}' (${count}/${total}):${NOCOLOR} "
    if [[ ${NUM_BACKENDS} -eq 1 ]]; then
        printf "\n\n%s\n" "${OUT[0]}"
    elif [[ "${OUT[0]}" = "${OUT[1]}" ]]; then
        printok "PASS"
    else
        OUT_SORTED[0]="$(sort <<< "${OUT[0]}")"
        OUT_SORTED[1]="$(sort <<< "${OUT[1]}")"
        if [[ "${OUT_SORTED[0]}" = "${OUT_SORTED[1]}" ]]; then
            printok "PASS"
        else
            printerr "FAIL"
            if [[ -n "${DIFF}" ]]; then
                TMP=()
                for ((i = 0; i < NUM_BACKENDS; i++)); do
                    tmp="/tmp/t2fm_test_${test_name}_${BACKENDS[i]}"
                    echo "${OUT_SORTED[i]}" > "${tmp}"
                    TMP+=("${tmp}")
                done
                vimdiff "${TMP[@]}"
                rm -f "${TMP[@]}"
            fi
            [[ -n "${FATAL}" ]] && exit 1
        fi
    fi
done
