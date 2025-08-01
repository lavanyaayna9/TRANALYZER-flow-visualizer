#!/usr/bin/env bash

source "$(dirname "${0}")/../t2utils.sh"

test_get_define() {
    local _file="${T2HOME}/tranalyzer2/src/tranalyzer.h"
    local _macro="VERBOSE"
    printf "test_get_define '%s' %s\t" "${_macro}" "${_file}"
    if [ "$(get_define "${_macro}" "${_file}")" == "2" ]; then
        printok "OK"
    else
        printerr "FAIL"
    fi
}

test_has_define() {
    local _file="${T2HOME}/tranalyzer2/src/tranalyzer.h"
    local _macro="VERBOSE"
    printf "test_has_define '%s' %s\t" "${_file}" "${_macro}"
    if has_define "${_file}" "${_macro}"; then
        printok "OK"
    else
        printerr "FAIL"
    fi

    _macro="VERBOSE2"
    printf "test_has_define '%s' %s\t" "${_file}" "${_macro}"
    if has_define "${_file}" "${_macro}"; then
        printerr "FAIL"
    else
        printok "OK"
    fi
}

test_join_by() {
    local _array=(a b c d)
    local _sep=","
    local _expected="a${_sep}b${_sep}c${_sep}d"

    printf "join_by '%s' '%s'\t" "${_sep}" "${_array[*]}"
    local _found="$(join_by "${_sep}" "${_array[@]}")"
    if [ "$(join_by "${_sep}" "${_array[@]}")" == "${_expected}" ]; then
        printok "OK"
    else
        printerr "FAIL"
        echo "$_found"
    fi
}

test_replace_suffix() {
    local _filename="/tmp/file.txt"
    local _old_suffix=".txt"
    local _new_suffix="_txt.bak"
    local _expected="/tmp/file_txt.bak"

    printf "replace_suffix '%s' '%s' '%s'\t" "${_filename}" "${_old_suffix}" "${_new_suffix}"
    if [ "$(replace_suffix "${_filename}" "${_old_suffix}" "${_new_suffix}")" == "${_expected}" ]; then
        printok "OK"
    else
        printerr "FAIL"
    fi
}

test_test_min_version() {
    local _v1="1.2.3.4"
    local _v2="1.2.3.5"
    printf "test_min_version %-7s %-7s\t" "${_v1}" "${_v2}"
    if test_min_version "${_v1}" "${_v2}"; then
        printerr "FAIL"
    else
        printok "OK"
    fi

    _v1="1.2.3.4"
    _v2="1.2.3.4"
    printf "test_min_version %-7s %-7s\t" "${_v1}" "${_v2}"
    if test_min_version "${_v1}" "${_v2}"; then
        printok "OK"
    else
        printerr "FAIL"
    fi

    _v1="1.2.3.5"
    _v2="1.2.3.4"
    printf "test_min_version %-7s %-7s\t" "${_v1}" "${_v2}"
    if test_min_version "${_v1}" "${_v2}"; then
        printok "OK"
    else
        printerr "FAIL"
    fi

    _v1="1.2"
    _v2="1.2.3.4"
    printf "test_min_version %-7s %-7s\t" "${_v1}" "${_v2}"
    if test_min_version "${_v1}" "${_v2}"; then
        printerr "FAIL"
    else
        printok "OK"
    fi

    _v1="1.2.3.4"
    _v2="1.2"
    printf "test_min_version %-7s %-7s\t" "${_v1}" "${_v2}"
    if test_min_version "${_v1}" "${_v2}"; then
        printok "OK"
    else
        printerr "FAIL"
    fi
}

test_get_define
test_has_define
test_join_by
test_replace_suffix
test_test_min_version
