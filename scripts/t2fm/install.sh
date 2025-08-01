#!/usr/bin/env bash

source "$(dirname "${0}")/../t2utils.sh"

PKG_NAME="$(basename "${SHOME}")"

usage() {
    echo "Usage:"
    echo "    ${SNAME} [OPTION...] <target>"
    echo
    echo "Target:"
    if [[ -n "{IS_MACOS}" ]]; then
        echo "    deps       install dependencies (gawk, gnu-sed, coreutils, mactex)"
    else
        echo "    deps       install dependencies (gawk, sed, coreutils, texlive-latex-extra)"
    fi
    echo "    man        install the man page in /usr/local/man/man1"
    echo "    t2fm       install an alias for t2fm"
    echo "    all        install deps, t2fm and man"
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
    if [[ -n "${IS_MACOS}" ]]; then
        type greadlink &> /dev/null || deps+=(coreutils)
        type gsed &> /dev/null || deps+=(gnu-sed)
        type pdflatex &> /dev/null || deps+=(mactex)
    else
        type readlink &> /dev/null || deps+=(coreutils)
        type sed &> /dev/null || deps+=(sed)
        type pdflatex &> /dev/null || deps+=(texlive-latex-extra)
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

    local destf="${MANDIR}/${PKG_NAME}.1.gz"
    if ! ${SUDO} sh -c "install -d \"${MANDIR}\" && gzip -c \"${SHOME}/man/${PKG_NAME}.1\" > \"${destf}\" && chmod 755 \"${destf}\""; then
        fatal "Failed to install man page for '${PKG_NAME}'"
    fi

    printok "Man page for '${PKG_NAME}' successfully installed in '${MANDIR}'\n"
}

uninstall_man() {
    printinf "Uninstalling '${PKG_NAME}' man pages\n"

    local destf="${MANDIR}/${PKG_NAME}.1.gz"
    if ! ${SUDO} rm -f "${destf}"; then
        fatal "Failed to remove man page for '${PKG_NAME}'"
    fi

    printok "Man page for '${PKG_NAME}' successfully removed from '${MANDIR}'\n"
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
            printinf "Copy the following alias to your rc file: alias t2fm=\"${SHOME}/t2fm\""
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

install_t2fm() {
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
        if grep -qF 'alias t2fm=' "${rc}"; then
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

        if ! echo "alias t2fm=\"${SHOME}/t2fm\"" >> "${rc}"; then
            printerr "Failed to install alias for '${PKG_NAME}' in '${rc}'"
            continue
        fi

        printok "Alias for '${PKG_NAME}' successfully installed in '${rc}'"
    done
}

uninstall_t2fm() {
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
        if grep -qF 'alias t2fm=' "${rc}"; then
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

            if ! "${SED}" -i '/alias t2fm=".*"$/d' "${rc}" || grep -qF 'alias t2fm=' "${rc}"; then
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

if [[ "${#}" -eq 0 ]]; then
    usage
    exit 1
fi

TO_INSTALL=()
while [[ "${#}" -gt 0 ]]; do
    case "${1}" in
        deps) TO_INSTALL+=(deps);;
        man) TO_INSTALL+=(man);;
        t2fm) TO_INSTALL+=(t2fm);;
        all) TO_INSTALL+=(deps man t2fm);;
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
        t2fm)
            if [[ -n "${UNINSTALL}" ]]; then
                uninstall_t2fm
            else
                install_t2fm
            fi
            ;;
    esac
done
