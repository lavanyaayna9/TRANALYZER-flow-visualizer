#!/usr/bin/env bash

source "$(dirname "$0")/../scripts/t2utils.sh"

INSTALL_PREFIX="/usr/local"
PKG_NAME="tranalyzer"

usage() {
    printf "Usage:\n"
    printf "    $SNAME [OPTION...] <target>\n\n"
    printf "Target:\n"
    printf "    man        install the man page in /usr/local/man/man1\n"
    printf "    tranalyzer install tranalyzer in /usr/local/bin\n"
    printf "    all        install tranalyzer and the man page\n"
    printf "\nOptional arguments:\n"
    printf "    -o folder  prefix to use for the installation [default: $INSTALL_PREFIX]\n"
    printf "    -u         uninstall instead of install\n"
    printf "    -y         do not ask for confirmation before executing an action\n"
    printf "    -h         display this help and exit\n"
}

setup_dirs() {
    BINDIR="$INSTALL_PREFIX/bin"
    if [ "$(uname)" = "Darwin" ]; then
        INSTALL_PREFIX="$INSTALL_PREFIX/share"
    fi
    MANDIR="$INSTALL_PREFIX/man/man1"
}

install_man() {
    printinf "Installing '$PKG_NAME' man pages\n"

    local destf
    for i in "$PKG_NAME"; do
        destf="$MANDIR/${i}.1.gz"
        $SUDO sh -c "install -d \"$MANDIR\" && gzip -c ${SHOME}/man/${i}.1 > \"$destf\" && chmod 755 \"$destf\""

        if [ $? -ne 0 ]; then
            printerr "Failed to install man page for '$i'"
            exit 1
        fi

        printok "Man page for '$i' successfully installed in '$MANDIR'\n"
    done
}

uninstall_man() {
    printinf "Uninstalling '$PKG_NAME' man pages\n"

    local destf
    for i in "$PKG_NAME"; do
        destf="$MANDIR/${i}.1.gz"
        $SUDO rm -f "$destf"
        if [ $? -ne 0 ]; then
            printerr "Failed to remove man page for '$i'"
            exit 1
        fi

        printok "Man page for '$i' successfully removed from '$MANDIR'\n"
    done
}

install_tranalyzer() {
    printinf "Installing '$PKG_NAME' executable\n"

    local t2="$(get_t2_exec)"

    if [ -f "$BINDIR/$PKG_NAME" ]; then
        cmp -s "$BINDIR/$PKG_NAME" "$t2" &> /dev/null
        if [ $? -eq 0 ]; then
            printok "'$PKG_NAME' already exists in '$BINDIR'"
            return 0
        else
            printwrn "A different version of '$PKG_NAME' already exists in '$BINDIR'"
            printf "Overwrite it (y/N)? "
            if [ -z "$YES" ]; then
                read ans
            else
                ans="yes"
                echo "$ans"
            fi
            case "$ans" in
                [yY]|[yY][eE][sS]) ;;
                *) exit 1
            esac
        fi
    fi

    if [ -f "$BINDIR" ]; then
        printerr "Failed to install '$PKG_NAME' to '$BINDIR': a file with the same name already exists"
        exit 1
    elif [ ! -d "$BINDIR" ]; then
        $SUDO mkdir -p "$BINDIR" || exit 1
    fi

    $SUDO cp "$t2" "$BINDIR"
    if [ $? -ne 0 ]; then
        printerr "Failed to copy '$PKG_NAME' to '$BINDIR'"
        exit 1
    fi

    printok "'$PKG_NAME' successfully installed in '$BINDIR'\n"
}

uninstall_tranalyzer() {
    printinf "Uninstalling '$PKG_NAME' executable\n"

    $SUDO rm -f "$BINDIR/$PKG_NAME"
    if [ $? -ne 0 ]; then
        printerr "Failed to remove '$PKG_NAME' from '$BINDIR'"
        exit 1
    fi

    printok "'$PKG_NAME' successfully removed from '$BINDIR'\n"
}

test_sudo() {
    if [[ $EUID -ne 0 ]] && [ ! -w "$INSTALL_PREFIX" ]; then
        printf "**************************************************\n"
        printf "* The 'install' option requires root privileges. *\n"
        printf "**************************************************\n\n"
        SUDO="$(which sudo)"
        if [ -z "$SUDO" ]; then
            printerr "Failed to install '$PKG_NAME': 'sudo' command not found"
            exit 1
        fi
    fi
}

if [ $# -eq 0 ]; then
    usage
    exit 1
fi

TO_INSTALL=()
while [ $# -gt 0 ]; do
    case "$1" in
        man) TO_INSTALL+=(man);;
        tranalyzer) TO_INSTALL+=(tranalyzer);;
        all) TO_INSTALL+=(man tranalyzer);;
        -u|--uninstall) UNINSTALL=1;;
        -y|--yes) YES=1;;
        -o)
            validate_next_arg "$1" "$2"
            INSTALL_PREFIX="$($READLINK -f "$2")"
            shift
            ;;
        -\?|-h|--help) usage; exit;;
        *) abort_option_unknown "$1";;
    esac
    shift
done

if [ -z "$TO_INSTALL" ]; then
    printerr "At least one target must be specified"
    abort_with_help
fi

test_sudo
setup_dirs

for i in "${TO_INSTALL[@]}"; do
    case "$i" in
        man)
            if [ "$UNINSTALL" ]; then
                uninstall_man
            else
                install_man
            fi
            ;;
        tranalyzer)
            if [ "$UNINSTALL" ]; then
                uninstall_tranalyzer
            else
                install_tranalyzer
            fi
            ;;
    esac
done
