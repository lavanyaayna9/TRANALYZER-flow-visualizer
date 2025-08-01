#!/usr/bin/env bash

SNAME="$(basename "${0}")"

usage() {
    echo "Usage:"
    echo "    ${SNAME} [OPTION...] <target>"
    echo
    echo "Target:"
    if [[ "$(uname)" == "Darwin" ]]; then
        echo "    deps       install dependencies (gawk, gnu-sed, coreutils)"
    else
        echo "    deps       install dependencies (gawk, sed, coreutils)"
    fi
    echo "    man        install the man page in /usr/local/man/man1"
    echo "    tawk       install an alias for tawk"
    echo "    all        install deps, tawk and man"
    echo
    echo "Optional arguments:"
    echo "    -u         uninstall instead of install (alias and man pages only)"
    echo "    -y         do not ask for confirmation before executing an action"
    echo "    -h         display this help and exit"
}

setup_dirs() {
    local install_prefix="/usr/local"
    if [[ "$(uname)" == "Darwin" ]]; then
        install_prefix="${install_prefix}/share"
    fi
    MANDIR="${install_prefix}/man/man1"
}

install_deps() {
    local deps=()
    type gawk &> /dev/null || deps+=(gawk)
    if [[ "$(uname)" == "Darwin" ]]; then
        type greadlink &> /dev/null || deps+=(coreutils)
        type gsed &> /dev/null || deps+=(gnu-sed)
    else
        type readlink &> /dev/null || deps+=(coreutils)
        type sed &> /dev/null || deps+=(sed)
    fi

    if [[ "${#deps[@]}" -eq 0 ]]; then
        printok "No dependency to install"
        return
    fi

    local cmd
    if hash pacman 2> /dev/null; then
        cmd="sudo pacman -S"
        [[ -n "${YES}" ]] && cmd="${cmd} --noconfirm"
    elif hash emerge 2> /dev/null; then
        cmd="sudo emerge"
        # TODO yes???
    elif hash yum 2> /dev/null; then
        cmd="sudo yum install"
        [[ -n "${YES}" ]] && cmd="${cmd} -y"
    elif hash zypper 2> /dev/null; then
        cmd="sudo zypper install"
        [[ -n "${YES}" ]] && cmd="${cmd} -y"
    elif hash apt-get 2> /dev/null; then
        cmd="sudo apt-get install"
        [[ -n "${YES}" ]] && cmd="${cmd} -y"
    elif [[ "$(uname)" == "Darwin" ]]; then
        if ! hash brew 2> /dev/null; then
            printinf "Installing Homebrew..."
            if ! /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"; then
                fatal "Failed to install Homebrew"
            fi
        fi
        cmd="brew install"
        # TODO yes???
    else
        printerr "Failed to install dependencies: no package utility found"
        printinf "Required dependencies are: ${deps[*]}"
        printf "You may use your package utility to install them\n"
        exit 1
    fi

    printinf "Installing dependencies..."
    if [[ "$(uname)" != "Darwin" ]]; then
        printinf "You may be prompted for your password."
    fi

    if ! ${cmd} "${deps[@]}"; then
        fatal "Failed to install dependencies"
    fi

    printok "All dependencies installed"
}

install_man() {
    printinf "Installing '${PKG_NAME}' man pages\n"

    local destf
    for i in tawk t2nfdump; do
        destf="${MANDIR}/${i}.1.gz"
        if ! ${SUDO} sh -c "install -d \"${MANDIR}\" && gzip -c \"${TAWKDIR}/man/${i}.1\" > \"${destf}\" && chmod 755 \"${destf}\""; then
            printerr "Failed to install man page for '${i}'"
            continue
        fi

        printok "Man page for '${i}' successfully installed in '${MANDIR}'\n"
    done
}

uninstall_man() {
    printinf "Uninstalling '${PKG_NAME}' man pages\n"

    local destf
    for i in tawk t2nfdump; do
        destf="${MANDIR}/${i}.1.gz"
        if ! ${SUDO} rm -f "${destf}"; then
            printerr "Failed to remove man page for '${i}'"
            continue
        fi

        printok "Man page for '${i}' successfully removed from '${MANDIR}'\n"
    done
}

get_rc_files() {
    local destrc=()
    local rcfiles=(
        ".bash_aliases"
        ".bashrc"
        ".aliases"
        ".cshrc"
        ".kshrc"
        ".shrc"
        ".tcshrc"
        ".zshrc"
        ".profile"
    )

    local rc
    local target
    for rc in "${rcfiles[@]}"; do
        target="${HOME}/${rc}"
        if [[ -f "${target}" ]]; then
            destrc+=("${target}")
        fi
    done

    if [[ "${#rcfiles[@]}" == 0 ]]; then
        if [[ -z "${DOCKER_BUILD}" ]]; then
            printerr "Failed to install alias for '${PKG_NAME}': could not find a valid rc file"
            printinf "Copy the following alias to your rc file: alias tawk=\"${TAWKDIR}/tawk\""
            exit 1
        else
            rc="${HOME}/.bashrc"
            if [[ ! -f "${rc}" ]]; then
                touch "${rc}"
            fi
            destrc+=("${rc}")
        fi
    fi

    printf "%s\n" "${destrc[@]}"
}

install_tawk() {
    local rc
    local destrc=()
    if hash mapfile &> /dev/null; then
        mapfile -t destrc < <(get_rc_files)
    else
        local filename
        while IFS= read -r filename; do
            rc+=("${filename}")
        done < <(get_rc_files)
    fi
    for rc in "${destrc[@]}"; do
        if grep -qF 'alias tawk=' "${rc}"; then
            printinf "Alias for '${PKG_NAME}' already exists in '${rc}'"
            continue
        fi

        printf "Install ${PKG_NAME} alias in '${rc}'? "
        if [[ -z "${YES}" ]]; then
            read -r ans
        else
            ans="yes"
            echo "${ans}"
        fi
        case "${ans}" in
            [yY]|[yY][eE][sS]) ;;
            *) continue ;;
        esac

        if ! echo "alias tawk=\"${TAWKDIR}/tawk\"" >> "${rc}"; then
            printerr "Failed to install alias for '${PKG_NAME}' in '${rc}'"
            continue
        fi

        printok "Alias for '${PKG_NAME}' successfully installed in '${rc}'"
    done
}

uninstall_tawk() {
    local sed="sed"
    if [[ "$(uname)" == "Darwin" ]]; then
        sed="gsed"
    fi

    local rc
    local destrc=()
    if hash readarray &> /dev/null; then
        readarray -t destrc < <(get_rc_files)
    elif hash mapfile &> /dev/null; then
        mapfile -t destrc < <(get_rc_files)
    else
        local filename
        while IFS= read -r filename; do
            rc+=("${filename}")
        done < <(get_rc_files)
    fi
    for rc in "${destrc[@]}"; do
        if grep -qF 'alias tawk=' "${rc}"; then
            printf "Uninstall ${PKG_NAME} alias from '${rc}'? "
            if [[ -z "${YES}" ]]; then
                read -r ans
            else
                ans="yes"
                echo "${ans}"
            fi
            case "${ans}" in
                [yY]|[yY][eE][sS]) ;;
                *) continue ;;
            esac

            if ! "${sed}" -i '/alias tawk=".*"$/d' "${rc}" || grep -qF 'alias tawk=' "${rc}"; then
                printerr "Failed to uninstall alias for '${PKG_NAME}' from '${rc}'"
            else
                printok "Successfully uninstalled alias for '${PKG_NAME}' from '${rc}'"
            fi
        fi
    done
}

test_sudo() {
    if [[ "${EUID}" -ne 0 ]]; then
        echo "**************************************************"
        echo "* The 'install' option requires root privileges. *"
        echo "**************************************************"
        echo

        SUDO="$(which sudo)"
        if [[ -z "${SUDO}" ]]; then
            fatal "Failed to install '${PKG_NAME}': 'sudo' command not found"
        fi
    fi
}

# Colors
readonly BLUE="\e[0;34m"
readonly GREEN="\e[0;32m"
readonly ORANGE="\e[0;33m"
readonly RED="\e[0;31m"
readonly NOCOLOR="\e[0m"

# $1: message
printerr() {
    _printf "${RED}${1}${NOCOLOR}\n" >&2
}

# $1: message
printok() {
    _printf "${GREEN}${1}${NOCOLOR}\n"
}

# $1: message
printwrn() {
    _printf "${ORANGE}${1}${NOCOLOR}\n"
}

# $1: message
printinf() {
    _printf "${BLUE}${1}${NOCOLOR}\n"
}

_printf() {
    local msg="${1}"
    local format
    if [[ "${msg}" =~ \\[enrt] ]]; then
        format="b"
    else
        format="s"
    fi
    printf "%${format}" "${msg}"
}

abort_with_help() {
    echo "Try '${SNAME} --help' for more information."
    exit 1
}

abort_option_unknown() {
    printerr "${SNAME}: unknown option '${1}'"
    abort_with_help
}

if [[ "${#}" == 0 ]]; then
    usage
    exit 1
fi

if [[ "$(uname)" == "Darwin" ]]; then
    READLINK="$(which greadlink)"
    if [[ -z "${READLINK}" ]]; then
        fatal "${SNAME}: could not find greadlink"
    fi
else
    READLINK="$(which readlink)"
    if [[ -z "${READLINK}" ]]; then
        fatal "${SNAME}: could not find readlink"
    fi
fi

TAWKDIR="$(dirname "$("${READLINK}" -f "${0}")")"
PKG_NAME="$(basename "${TAWKDIR}")"

TO_INSTALL=()
while [[ "${#}" -gt 0 ]]; do
    case "${1}" in
        deps) TO_INSTALL+=(deps);;
        man) TO_INSTALL+=(man);;
        tawk) TO_INSTALL+=(tawk);;
        all) TO_INSTALL+=(deps man tawk);;
        -u|--uninstall) UNINSTALL=1;;
        -y|--yes) YES=1;;
        -\?|-h|--help) usage; exit 0;;
        *) abort_option_unknown "${1}";;
    esac
    shift
done

if [[ "${#TO_INSTALL[@]}" -eq 0 ]]; then
    printerr "At least one target must be specified"
    abort_with_help
fi

setup_dirs

for i in "${TO_INSTALL[@]}"; do
    case "${i}" in
        deps)
            if [[ -z "${UNINSTALL}" ]]; then
                install_deps
            fi
            ;;
        man)
            test_sudo
            if [[ -n "${UNINSTALL}" ]]; then
                uninstall_man
            else
                install_man
            fi
            ;;
        tawk)
            if [[ -n "${UNINSTALL}" ]]; then
                uninstall_tawk
            else
                install_tawk
            fi
            ;;
    esac
done
