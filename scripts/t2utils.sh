#!/usr/bin/env bash
#
# Collection of bash functions and variables (readonly):
#
#   Functions:
#       - printbold, printerr, printinf, printok, printwrn
#       - printfbold, printferr, printfinf, printfok, printfwrn
#       - fatal
#       - check_dependency, check_dependency_linux, check_dependency_macos
#       - test_min_version
#       - has_define, get_define, set_define
#       - ask_default_no, ask_default_yes
#       - find_most_recent_dir, find_most_recent_file
#       - t2_build_exec
#       - get_t2_exec, get_t2b2t_exec, get_t2whois_exec
#       - abort_if_t2_exec_not_found, abort_if_t2b2t_exec_not_found,
#         abort_if_t2whois_exec_not_found
#       - t2_wget, t2_wget_n
#       - replace_suffix
#       - get_nproc
#       - arg_is_option
#       - validate_next_arg, validate_next_arg_exists,
#         validate_next_dir, validate_next_file, validate_next_file_or_dir,
#         validate_next_int, validate_next_float, validate_next_num,
#         validate_next_pcap,
#       - validate_float, validate_int, validate_ip, validate_num, validate_pcap
#       - abort_missing_arg, abort_option_unknown, abort_with_help,
#         abort_required_dir, abort_required_file, abort_required_file_or_dir
#
#   Scripts and programs (functions):
#       - AWK, AWKF
#       - T2, T2B2T, T2WHOIS
#
#   Scripts and programs (variables):
#       - ${AWK_EXEC}, ${OPEN}, ${PYTHON}, ${READLINK}, ${SED}
#       - ${T2BUILD}, ${T2CONF}, ${T2PLOT}, ${TAWK}
#
#   Folders:
#       - ${SHOME}, ${T2HOME}, ${T2PLHOME}
#
#   Colors:
#       - ${BLUE}, ${GREEN}, ${ORANGE}, ${RED}
#       - ${BLUE_BOLD}, ${GREEN_BOLD}, ${ORANGE_BOLD}, ${RED_BOLD}
#       - ${BLUE_ITALIC}, ${GREEN_ITALIC}, ${ORANGE_ITALIC}, ${RED_ITALIC}
#       - ${BLUE_UNDERLINE}, ${GREEN_UNDERLINE}, ${ORANGE_UNDERLINE},
#         ${RED_UNDERLINE}
#       - ${BOLD}, ${ITALIC}, ${STRIKETHROUGH}, ${UNDERLINE}
#       - ${NOCOLOR}
#
#   OS detection:
#       - ${IS_LINUX}
#       - ${IS_MACOS}

#   Variables:
#       - ${SNAME}
#
# Usage:
#
#   source this file in your script as follows:
#
#      source "$(dirname "${0}")/t2utils.sh"
#
#   Note that if your script is not in the scripts/ folder,
#   you will need to adapt the path to t2utils accordingly
#
#   [ZSH] If writing a script for ZSH, add the following line
#         BEFORE sourcing the script:
#
#           unsetopt function_argzero

# Colors
readonly BLUE="\e[0;34m"
readonly GREEN="\e[0;32m"
readonly ORANGE="\e[0;33m"
readonly RED="\e[0;31m"
readonly BLUE_BOLD="\e[1;34m"
readonly GREEN_BOLD="\e[1;32m"
readonly ORANGE_BOLD="\e[1;33m"
readonly RED_BOLD="\e[1;31m"
readonly BLUE_ITALIC="\e[3;34m"
readonly GREEN_ITALIC="\e[3;32m"
readonly ORANGE_ITALIC="\e[3;33m"
readonly RED_ITALIC="\e[3;31m"
readonly BLUE_UNDERLINE="\e[4;34m"
readonly GREEN_UNDERLINE="\e[4;32m"
readonly ORANGE_UNDERLINE="\e[4;33m"
readonly RED_UNDERLINE="\e[4;31m"
readonly BOLD="\e[1m"
readonly ITALIC="\e[3m"
readonly UNDERLINE="\e[4m"
readonly STRIKETHROUGH="\e[9m"
readonly NOCOLOR="\e[0m"

if [[ "$(uname)" == "Linux" ]]; then
    readonly IS_LINUX=true
elif [[ "$(uname)" == "Darwin" ]]; then
    readonly IS_MACOS=true
fi

# ---------------- #
# Public functions #
# ---------------- #

AWK() {
    "${AWK_EXEC}" "${AWK_OPTS[@]}" "${@}"
}

AWKF() {
    AWK -F'\t' -v OFS='\t' "${@}"
}

get_t2_exec() {
    find_most_recent_file "${T2HOME}/tranalyzer2" "tranalyzer"
}

get_t2b2t_exec() {
    find_most_recent_file "${T2HOME}/utils/t2b2t" "t2b2t"
}

get_t2whois_exec() {
    find_most_recent_file "${T2HOME}/utils/t2whois" "t2whois"
}

abort_if_t2_exec_not_found() {
    local t2_exec
    t2_exec="$(get_t2_exec)"
    if [[ ! -f "${t2_exec}" ]]; then
        printerr "Could not find tranalyzer executable."
        printinf "Try building it with 't2build tranalyzer2'"
        exit 1
    fi
}

abort_if_t2b2t_exec_not_found() {
    local t2b2t_exec
    t2b2t_exec="$(get_t2b2t_exec)"
    if [[ ! -f "${t2b2t_exec}" ]]; then
        printerr "Could not find t2b2t executable."
        printinf "Try building it with 'make -C ${T2HOME}/utils/t2b2t'"
        exit 1
    fi
}

abort_if_t2whois_exec_not_found() {
    local t2whois_exec
    t2whois_exec="$(get_t2whois_exec)"
    if [[ ! -f "${t2whois_exec}" ]]; then
        printerr "Could not find t2whois executable."
        printinf "Try building it with 'make -C ${T2HOME}/utils/t2whois'"
        exit 1
    fi
}

T2() {
    abort_if_t2_exec_not_found
    "$(get_t2_exec)" "${@}"
}

T2B2T() {
    abort_if_t2b2t_exec_not_found
    "$(get_t2b2t_exec)" "${@}"
}

T2WHOIS() {
    abort_if_t2whois_exec_not_found
    "$(get_t2whois_exec)" "${@}"
}

# $1: message
printbold() {
    _t2printf "${BOLD}${1}${NOCOLOR}\n"
}

# $1: message
printfbold() {
    _t2printf "${BOLD}${1}${NOCOLOR}"
}

# $1: message
printerr() {
    _t2printf "${RED}${1}${NOCOLOR}\n" >&2
}

# $1: message
printferr() {
    _t2printf "${RED}${1}${NOCOLOR}" >&2
}

# $1: message
printinf() {
    _t2printf "${BLUE}${1}${NOCOLOR}\n"
}

# $1: message
printfinf() {
    _t2printf "${BLUE}${1}${NOCOLOR}"
}

# $1: message
printok() {
    _t2printf "${GREEN}${1}${NOCOLOR}\n"
}

# $1: message
printfok() {
    _t2printf "${GREEN}${1}${NOCOLOR}"
}

# $1: message
printwrn() {
    _t2printf "${ORANGE}${1}${NOCOLOR}\n"
}

# $1: message
printfwrn() {
    _t2printf "${ORANGE}${1}${NOCOLOR}"
}

# $1: error message
fatal() {
    printerr "${1}"
    exit 1
}

abort_with_help() {
    _t2printf "Try '$SNAME --help' for more information.\n"
    exit 1
}

abort_required_file() {
    printerr "Input file is required"
    abort_with_help
}

abort_required_dir() {
    printerr "Input directory is required"
    abort_with_help
}

abort_required_file_or_dir() {
    printerr "Input file or directory is required"
    abort_with_help
}

# $1: name of the option
abort_missing_arg() {
    printerr "Option '${1}' requires an argument"
    abort_with_help
}

# $1: name of the option
abort_option_unknown() {
    printerr "Unknown option '${1}'"
    abort_with_help
}

# $1: argument to validate
arg_is_option() {
    if [[ -n "${1}" && "${1:0:1}" == "-" ]]; then
        return 0
    else
        return 1
    fi
}

# $1: name of the option
# $2: argument to validate
validate_next_arg() {
    if [[ -n "${2}" && "${2:0:1}" != "-" ]]; then
        return 0
    else
        abort_missing_arg "${1}"
    fi
}

# $1: name of the option
# $2: argument to validate
validate_next_arg_exists() {
    if [[ -n "${2}" ]]; then
        return 0
    else
        abort_missing_arg "${1}"
    fi
}

# $1: name of the option
# $2: argument to validate
validate_next_dir() {
    validate_next_arg "${1}" "${2}"
    if [[ -d "${2}" ]]; then
        return 0
    else
        printerr "Invalid argument for option '${1}': '${2}' is not a directory"
        abort_with_help
    fi
}

# $1: name of the option
# $2: argument to validate
validate_next_file() {
    validate_next_arg "${1}" "${2}"
    if [[ -f "${2}" ]]; then
        return 0
    else
        printerr "Invalid argument for option '${1}': '${2}' is not a regular file"
        abort_with_help
    fi
}

# $1: name of the option
# $2: argument to validate
validate_next_file_or_dir() {
    validate_next_arg "${1}" "${2}"
    if [[ -d "${2}" || -f "${2}" ]]; then
        return 0
    else
        printerr "Invalid argument for option '${1}': '${2}' is neither a regular file nor a directory"
        abort_with_help
    fi
}

# $1: name of the option
# $2: argument to validate
validate_next_num() {
    validate_next_arg "${1}" "${2}"
    if [[ -z "$(tr -d '0-9' <<< "${2}")" ]]; then
        return 0
    else
        printerr "Invalid argument for option '${1}': expected number; found '${2}'"
        abort_with_help
    fi
}

# $1: name of the option
# $2: argument to validate
validate_next_float() {
    validate_next_arg_exists "${1}" "${2}"
    if [[ -n "$(AWK '/^-?[0-9]+(\.[0-9]*)?$/' <<< "${2}")" ]]; then
        return 0
    else
        printerr "Invalid argument for option '${1}': expected float; found '${2}'"
        abort_with_help
    fi
}

# $1: name of the option
# $2: argument to validate
validate_next_int() {
    validate_next_arg_exists "${1}" "${2}"
    if [[ -n "$(AWK '/^-?[0-9]+$/' <<< "${2}")" ]]; then
        return 0
    else
        printerr "Invalid argument for option '${1}': expected integer; found '${2}'"
        abort_with_help
    fi
}

# $1: name of the option
# $2: argument to validate
validate_next_pcap() {
    validate_next_file "${1}" "${2}"
    if file -b "${2}" | grep -qwi 'capture file'; then
        return 0
    else
        printerr "Invalid argument for option '${1}': '${2}' is not a valid PCAP file"
        abort_with_help
    fi
}

# $1: float to validate
validate_float() {
    if [[ -n "${1}" && -n "$(AWK '/^-?[0-9]+(\.[0-9]*)?$/' <<< "${1}")" ]]; then
        return 0
    else
        printerr "'${1}' is not a valid floating point value"
        return 1
    fi
}

# $1: int to validate
validate_int() {
    if [[ -n "${1}" && -n "$(AWK '/^-?[0-9]+$/' <<< "${1}")" ]]; then
        return 0
    else
        printerr "'${1}' is not a valid integer"
        return 1
    fi
}

# $1: number to validate
validate_num() {
    if [[ -n "${1}" && -z "$(tr -d '0-9' <<< "${1}")" ]]; then
        return 0
    else
        printerr "'${1}' is not a valid number"
        return 1
    fi
}

# $1: IP address to validate
validate_ip() {
    if [[ -n "${1}" && -n "$(AWK '/^[0-9]{1,3}(\.[0-9]{1,3}){3}$/' <<< "${1}")" ]]; then
        return 0
    else
        printerr "'${1}' is not a valid IPv4 address"
        return 1
    fi
}

# $1: PCAP file to validate
validate_pcap() {
    if file -b "${1}" | grep -qwi 'capture file'; then
        return 0
    else
        printerr "'${1}' is not a valid PCAP file"
        return 1
    fi
}

# $1: name of the program
# $2: name of the package in which the program can be found (if omitted, use $1)
check_dependency_linux() {
    local cmd="${1}"
    local deps="${2:-${1}}"
    local pgrmname
    local pgrmcmd
    if ! type "${cmd}" &> /dev/null; then
        if hash apt-get 2> /dev/null; then
            pgrmname="apt-get"
            pgrmcmd="apt-get install"
        elif hash pacman 2> /dev/null; then
            pgrmname="pacman"
            pgrmcmd="pacman -S"
        elif hash yum 2> /dev/null; then
            pgrmname="yum"
            pgrmcmd="yum install"
        else
            pgrmname="your package utility"
        fi
        if [[ -n "${pgrmcmd}" ]]; then
            pgrmcmd=": ${pgrmcmd} ${deps}"
        fi
        printerr "Missing dependency: ${deps}"
        printinf "You may use ${pgrmname} to install it${pgrmcmd}"
        exit 1
    fi
}

# $1: name of the program
# $2: name of the package in which the program can be found (if omitted, use $1)
check_dependency_macos() {
    local cmd="${1}"
    local deps="${2:-${1}}"
    if ! type "${cmd}" &> /dev/null; then
        printerr "Missing dependency: ${deps}"
        printinf "You may use homebrew to install it: brew install ${deps}"
        exit 1
    fi
}

# $1: name of the program
# $2: name of the package in which the program can be found (if omitted, use $1)
check_dependency() {
    if [[ -n "${IS_MACOS}" ]]; then
        check_dependency_macos "${1}" "${2}"
    else
        check_dependency_linux "${1}" "${2}"
    fi
}

# $1: version to test
# $2: minimum version required
# Return 0 if the version '$1' is greater than or equal to '$2', 1 otherwise
test_min_version() {
    local ver="${1}"
    local req="${2}"

    AWK -v req="${req}" '{
        _v = split($1, _ver, ".")
        _r = split(req, _req, ".")
        _l = ((_v <= _r) ? _v : _r)
        for (_i = 1; _i <= _l; _i++) {
            if (_ver[_i] < _req[_i]) {
                exit 1
            }
        }
        exit (_v < _r)
    }' <<< "${ver}"

    return "${?}"
}

# $1: name of the file
# $2: name of the define
# Return 0 if the define '$2' exists in the file '$1', 1 otherwise
has_define() {
    local file="${1}"
    local name="${2}"

    if [[ ! -f "${file}" ]]; then
        fatal "Invalid argument \$1 for function 'has_define()': '${file}' is not a regular file"
    elif [[ -z "${name}" ]]; then
        fatal "Invalid argument \$2 for function 'has_define()': cannot give an empty macro name"
    fi

    if grep -q "^#define\s\+${name}\s\+" "${file}"; then
        return 0
    else
        return 1
    fi
}

# $1: name of the define
# $2: name of the file
get_define() {
    local name="${1}"
    local file="${2}"

    if [[ -z "${name}" ]]; then
        fatal "Invalid argument \$1 for function 'get_define()': cannot give an empty macro name"
    elif [[ ! -f "${file}" ]]; then
        fatal "Invalid argument \$2 for function 'get_define()': '${file}' is not a regular file"
    elif ! has_define "${file}" "${name}"; then
        fatal "Invalid argument for function 'get_define()': macro '${name}' does not exist in '${file}'"
    fi

    # Only return the first occurrence (the 'exit' is there to handle cases where a define is redefined, e.g., CS_GEOLOC in connStat)
    perl -nle "
        if (/^#define\s+${name}\s+([^\s]((?!\s*\/[\/\*]|\s*$).)*).*$/) {
            print \$1;
            exit;
        }" "${file}"
}

# $1: name of the define
# $2: value of the define
# $3: name of the file
set_define() {
    local name="${1}"
    local value="${2}"
    local file="${3}"

    if [[ -z "${name}" ]]; then
        fatal "Invalid argument \$1 for function 'set_define()': cannot give an empty macro name"
    elif [[ -z "${value}" ]]; then
        fatal "Invalid argument \$2 for function 'set_define()': cannot give an empty value to a define"
    elif [[ ! -f "${file}" ]]; then
        fatal "Invalid argument \$3 for function 'set_define()': '${file}' is not a regular file"
    elif ! has_define "${file}" "${name}"; then
        fatal "Invalid argument for function 'set_define()': macro '${name}' does not exist in '${file}'"
    fi

    # escape \, /, *, ", &, $ and . from $value
    local newval
    newval="$("${SED}" 's/\([\\/*"&$.]\)/\\\1/g' <<< "${value}")"

    # Only replace the first occurrence (the 'found' is there to handle cases where a define is redefined, e.g., CS_GEOLOC in connStat)
    perl -i -pe "!\$found && s/(^#define\s+${name}\s+)([^\s]((?!\s*\/[\/\*]|\s*$).)*)(.*$)/\${1}${newval}\${4}/p && (\$found = 1)" "${file}"
}

# $1: message
# $2: answer to give (force "yes" or "no") [optional]
ask_default_no() {
    if [[ -z "${1}" ]]; then
        fatal "Usage: ask_default_no msg [answer]"
    fi
    local msg="${1}"
    local ans="${2}"
    _t2printf "${msg} (Y/n)? "
    if [[ -z "${ans}" ]]; then
        read -r ans
    else
        echo "${ans}"
    fi
    echo
    case "${ans}" in
        [yY]|[yY][eE][sS]) return 0;;
                        *) return 1;;
    esac
}

# $1: message
# $2: answer to give (force "yes" or "no") [optional]
ask_default_yes() {
    if [[ -z "${1}" ]]; then
        fatal "Usage: ask_default_yes msg [answer]"
    fi
    local msg="${1}"
    local ans="${2}"
    _t2printf "${msg} (Y/n)? "
    if [[ -z "${ans}" ]]; then
        read -r ans
    else
        echo "${ans}"
    fi
    echo
    case "${ans}" in
        [nN]|[nN][oO]) return 1;;
                    *) return 0;;
    esac
}

# Recursively find the most recent directory in a directory
#   $1: dir: directory where to search (recursively)
#   $2: dirname: name of the directory to find
find_most_recent_dir() {
    if [[ ! -d "${1}" || -z "${2}" ]]; then
        fatal "Usage: find_most_recent_dir dir dirname"
    fi
    local dir="${1}"
    local dname="${2}"
    local dirs=()
    if hash readarray &> /dev/null; then
        readarray -t dirs < <(find "${dir}" -type d -name "${dname}")
    elif hash mapfile &> /dev/null; then
        mapfile -t dirs < <(find "${dir}" -type d -name "${dname}")
    else
        local dirname
        while IFS= read -r dirname; do
            dirs+=("${dirname}")
        done < <(find "${dir}" -type d -name "${dname}")
    fi
    if [[ "${#dirs[@]}" -le 1 ]]; then
        echo "${dirs[0]}"
    else
        ls -td1 "${dirs[@]}" | head -1
    fi
}

# Recursively find the most recent file in a directory
#   $1: dir: directory where to search (recursively)
#   $2: filename: name of the file to find
find_most_recent_file() {
    if [[ ! -d "${1}" || -z "${2}" ]]; then
        fatal "Usage: find_most_recent_file dir filename"
    fi
    local dir="${1}"
    local file="${2}"
    local files=()
    if hash readarray &> /dev/null; then
        readarray -t files < <(find "${dir}" -type f -name "${file}")
    elif hash mapfile &> /dev/null; then
        mapfile -t files < <(find "${dir}" -type f -name "${file}")
    else
        local filename
        while IFS= read -r filename; do
            files+=("${filename}")
        done < <(find "${dir}" -type f -name "${file}")
    fi
    if [[ "${#files[@]}" -le 1 ]]; then
        echo "${files[0]}"
    else
        ls -t1 "${files[@]}" | head -1
    fi
}

# Ask whether to build the given executable if it does not exist
#   $1: path to executable, e.g., /path/to/exec
#   $2: force the build (run make -C /path/to distclean all)
t2_build_exec() {
    local exec="${1}"
    local rebuild="${2}"
    if [[ -z "${exec}" ]]; then
        printerr "Usage: t2_build_exec /path/to/exec"
        return 1
    fi
    local exec_home
    local exec_name
    exec_home="$(dirname "${exec}")"
    exec_name="$(basename "${exec}")"
    if [[ ! -d "${exec_home}" || -z "${exec_name}" ]]; then
        fatal "t2_get_exec(): failed to extract exec_home and/or exec_name from '${exec}'"
    fi
    if [[ -f "${exec}" && -z "${rebuild}" ]]; then
        return 0
    fi
    if [[ ! -f "${exec}" && -z "${rebuild}" ]]; then
        if ! ask_default_yes "${ORANGE_BOLD}'${exec_name}'${NOCOLOR} executable does not exist... build it"; then
            return 1
        fi
    fi
    if [[ -n "${rebuild}" ]]; then
        make -C "${exec_home}" distclean
    fi
    make -C "${exec_home}" || return 1
    tput clear
}

# Download the data at 'url'
#   $1: url
#   $2: output file (optional)
#   $3: only download the file if it was modified (wget -N)
#       (does not work if $2 is specified)
t2_wget() {
    local url="${1}"
    local outfile="${2}"
    if [[ -z "${url}" ]]; then
        fatal "Invalid argument for function 't2_wget()': url (\$1) cannot be empty"
    fi
    if hash wget 2> /dev/null; then
        if [[ -n "${outfile}" ]]; then
            wget -q --show-progress "${url}" -O "${outfile}"
        else
            wget -q --show-progress ${3:+"-N"} "${url}"
        fi
    elif hash curl 2> /dev/null; then
        # TODO use curl -z option?
        if [[ -z "${outfile}" ]]; then
            outfile="$(basename "${url}")"
        fi
        curl -sS "${url}" -o "${outfile}"
    # TODO bsd uses ftp for file transfer
    else
        fatal "None of wget or curl could be found"
    fi
}

# Download the data at 'url' (same as t2_wget), but with timestamping turned on
#   $1: url
#   $2: output file (optional)
t2_wget_n() {
    t2_wget "${1}" "${2}" 1
}

# Replace the suffix of a filename
#   $1: filename
#   $2: old suffix to replace
#   $3: new suffix
replace_suffix() {
    local name="${1}"
    local old_suffix="${2}"
    local new_suffix="${3}"
    local prefix
    prefix="$(AWK -v suffix="${old_suffix}" '{
        gsub(suffix "$", "")
        print
    }' <<< "${name}")"
    if [[ "${prefix}" == "${name}" && -z "${new_suffix}" ]]; then
        fatal "replace_suffix: Suffix '${old_suffix}' not found in '${name}' and new suffix is empty"
    fi
    echo "${prefix}${new_suffix}"
}

# Join values with a separator
#   $1: separator
#   $*: values to join
# https://stackoverflow.com/a/17841619
join_by() {
    local IFS="${1}"
    shift
    echo "${*}"
}

get_nproc() {
    if hash nproc 2> /dev/null; then
        nproc
    elif hash lscpu 2> /dev/null; then
        lscpu | grep "^CPU(s):" | AWK '{ print $2 }'
    elif [[ -f "/proc/cpuinfo" ]]; then
        grep -c "^processor" /proc/cpuinfo
    elif [[ -n "${IS_MACOS}" ]]; then
        sysctl -an hw.ncpu
    else
        echo 1
    fi
}

# ----------------- #
# Private functions #
# ----------------- #

# $1: message
_t2printf() {
    local msg="${1}"
    local format
    if [[ "${msg}" =~ \\[enrt] ]]; then
        format="b"
    else
        format="s"
    fi
    printf "%${format}" "${msg}"
}

# $1: precision (0: full, 1: X, 2: X.Y, ...)
_get_awk_version() {
    local prec="${1}"

    local vopt
    if grep -q "^\s\+-V\s\+--version$" <<< "$(AWK -Whelp 2>&1)"; then
        vopt="--version"
    else
        vopt="-Wversion"
    fi

    local line
    line="$(AWK ${vopt} 2> /dev/null | head -1)"

    local field
    if [[ "$(wc -w <<< "${line}")" -eq 3 ]]; then
        field=2  # mawk version date
    else
        field=3  # GNU Awk version, ...
    fi

    AWK -v field="${field}" -v prec="${prec}" '{
        version = $field
        gsub(/,$/, "", version)
        if (!prec || prec + 0 != prec) {
            print version
        } else {
            n = split(version, v, /\./)
            n = ((n < prec) ? n : prec)
            printf "%s", v[1]
            for (i = 2; i <= n; i++) {
                printf ".%s", v[i]
            }
            printf "\n"
        }
    }' <<< "${line}"
}

_awk_has_bignum() {
    # Required for tawk IPv6 functions
    if AWK -Whelp 2>&1 | grep -q "^\s\+-M\s\+--bignum$"; then
        return 0
    else
        return 1
    fi
}

# Gawk version 4.1 required for tawk
_check_awk_version() {
    local req="4.1"
    local ver
    ver="$(_get_awk_version 2)"

    if ! test_min_version "${ver}" "${req}"; then
        fatal "Minimum gawk version required is ${req}, found '${ver}'"
    fi

    # Required for tawk IPv6 functions
    if ! _awk_has_bignum; then
        printwrn "Your gawk version does not support bignum: IPv6 handling may be buggy"
    fi
}

_check_dependencies_linux() {
    local cmds=(readlink gawk sed)
    local deps=(coreutils gawk sed)

    if hash pacman 2> /dev/null; then
        cmds+=(which)
        deps+=(which)
    fi

    for i in "${!cmds[@]}"; do
        check_dependency_linux "${cmds[i]}" "${deps[i]}"
    done

    AWK_EXEC="$(which gawk)"
    READLINK="$(which readlink)"
    SED="$(which sed)"
    OPEN="$(which xdg-open)"
}

_check_dependencies_osx() {
    local cmds=(greadlink gawk gsed)
    local deps=(coreutils gawk gnu-sed)
    for i in "${!cmds[@]}"; do
        check_dependency_macos "${cmds[i]}" "${deps[i]}"
    done

    AWK_EXEC="$(which gawk)"
    READLINK="$(which greadlink)"
    SED="$(which gsed)"
    OPEN="$(which open)"
}

_check_dependencies() {
    if [[ -n "${IS_MACOS}" ]]; then
        _check_dependencies_osx
    else
        _check_dependencies_linux
    fi
    # XXX This is only required for tawk... so let tawk do the testing
    # (Keep this commented out, so Ubuntu 14.04 can still use this script)
    #_check_awk_version
}

_set_awk_options() {
    local ver
    ver="$(_get_awk_version 1)"
    if [[ "${ver}" -lt 4 ]]; then
        # Intervals, i.e., /.{N}/ or /.{N,M}/, were standardized in gawk 4.
        # Older versions had a '--re-interval' option (which still appear
        # to be available on newer versions (last checked with gawk 5.3.0))
        AWK_OPTS=("--re-interval")
    fi
}

_t2utils_init() {
    # Check for required programs
    if [[ -z "${NO_DEPENDENCIES_CHECK}" ]]; then
        _check_dependencies
    elif ! hash which &> /dev/null; then
        if hash gawk &> /dev/null; then
            AWK_EXEC="gawk"
        else
            AWK_EXEC="awk"
        fi

        if hash greadlink &> /dev/null; then
            READLINK="greadlink"
        else
            READLINK="readlink"
        fi
    elif [[ -n "${IS_MACOS}" ]]; then
        AWK_EXEC="$( (which gawk awk 2> /dev/null || echo "awk") | head -1)"
        READLINK="$(which greadlink 2> /dev/null || echo "greadlink")"
    else
        AWK_EXEC="$( (which gawk awk 2> /dev/null || echo "awk") | head -1)"
        READLINK="$(which readlink 2> /dev/null || echo "readlink")"
    fi

    _set_awk_options

    PYTHON="$( (which python3 python python2 2> /dev/null || echo "python3") | head -1)"

    readonly AWK_EXEC
    readonly PYTHON
    readonly READLINK

    local readlink_f
    if [[ -z "${READLINK}" ]]; then
        readlink_f="echo"
    else
        readlink_f="${READLINK} -f"
    fi

    # Set script name and home
    SNAME="$(basename "${0}")"
    SHOME="$(${readlink_f} "$(dirname "${0}")")"
    readonly SNAME
    readonly SHOME

    # Set T2HOME and T2PLHOME
    if [[ -n "${ZSH_VERSION}" ]]; then
        T2HOME="$(dirname "${(%):-%x}")/.."
    else
        T2HOME="$(dirname "${BASH_SOURCE[0]}")/.."
    fi
    T2HOME="$(${readlink_f} "${T2HOME}")"
    readonly T2HOME
    readonly T2PLHOME="${T2HOME}/plugins"

    # Set path to scripts
    readonly TAWK="${T2HOME}/scripts/tawk/tawk"
    readonly T2BUILD="${T2HOME}/autogen.sh"
    readonly T2CONF="${T2HOME}/scripts/t2conf/t2conf"
    readonly T2PLOT="${T2HOME}/scripts/t2plot"
}

# -------------- #
# Initialization #
# -------------- #

_t2utils_init
