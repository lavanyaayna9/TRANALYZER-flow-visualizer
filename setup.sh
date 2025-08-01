#!/usr/bin/env bash

NO_DEPENDENCIES_CHECK=1
source "$(dirname "$0")/scripts/t2utils.sh"

# TODO
#    - only build tranalyzer2
#    - build all the plugins

T2WWW_HOME="https://tranalyzer.com"

usage() {
    echo "Usage:"
    echo "    $SNAME [OPTION...]"
    echo
    echo "Optional arguments:"
    echo "    -C, --update          Check for a new version of Tranalyzer"
    echo "                          (and proceed with the update if requested)"
    echo
    echo "    -D, --no-deps         Do not install dependencies"
    echo "    -G, --no-gui          Do not install gui-dependencies"
    echo "    -T, --no-latex        Do not install LaTeX dependencies"
    echo "    -U, --no-db           Do not update databases"
    echo "    -N, --no-network      Do not install dependencies or update databases"
    echo "    -E, --no-empty        Do not empty the plugin folder"
    echo "    -B, --no-build        Do not build tranalyzer and the plugins"
    echo "    -M, --no-man          Do not install man pages"
    echo "    -L, --no-aliases      Do not install t2_aliases"
    echo
    echo "    -d, --deps            Only install the dependencies"
    echo "    -u, --db              Only update the databases"
    echo "    -e, --empty           Only empty the plugin folder"
    echo "    -b, --build           Only build tranalyzer and the plugins"
    echo "    -m, --man             Only install the man pages"
    echo "    -l, --aliases         Only install the aliases"
    echo
    echo "    -r, --refresh-keys    Refresh GPG keys (Arch/Manjaro/OpenSUSE only)"
    echo
    echo "    -a, --all             Build all the plugins instead of only the default ones"
    echo
    echo "    -i, --ask             Ask for confirmation before executing an action"
    #echo "    -y, --yes             Do not ask for confirmation before executing an action"
    echo
    echo "    -h, --help            Show this help, then exit"
}

get_rc_file() {
    local destrc=()

    local rcfiles=(
        ".cshrc"
        ".kshrc"
        ".shrc"
        ".tcshrc"
        ".zshrc"
    )

    local rc
    for rc in "${rcfiles[@]}"; do
        if [ -f "$HOME/$rc" ]; then
            destrc+=("$HOME/$rc")
        fi
    done

    if [ -f "$HOME/.bashrc" ]; then
        destrc+=("$HOME/.bashrc")
    elif [ -f "$HOME/.bash_profile" ] || [ "$(uname)" = "Darwin" ]; then
        destrc+=("$HOME/.bash_profile")
    fi

    if [ ${#rcfiles[*]} -eq 0 ]; then
        if [ -f "$HOME/.profile" ]; then
            destrc+=("$HOME/.profile")
        elif [ -n "$DOCKER_BUILD" ]; then
            rc="$HOME/.bashrc"
            destrc+=("$rc")
            if [ ! -f "$rc" ]; then
                touch "$rc"
            fi
        fi
    fi

    echo "${destrc[@]}"
}

alias_msg() {
    local rcfile=($(get_rc_file))
    [ ${#rcfile[*]} -gt 0 ] || rcfile=("$HOME/.bashrc")

    local cmd
    if [ ${#rcfile[*]} -eq 1 ]; then
        cmd="source '${rcfile[0]}'"
    else
        cmd="one of the following command (depending on your running shell):"
        local rc
        for rc in "${rcfile[@]}"; do
            cmd="$cmd\n    $ source '$rc'"
        done
    fi

    printwrn "${BOLD}To access all aliases, open a new terminal or run $cmd\n"
    printf "Run Tranalyzer as follows: t2 -r path/to/file.pcap\n"
    printf "For more details, run t2 --help or t2doc tranalyzer2\n"
}

noalias_msg() {
    local rcfile=($(get_rc_file))
    [ ${#rcfile[*]} -gt 0 ] || rcfile=("$HOME/.bashrc")

    printf "Tranalyzer can be run as follows:\n\n"
    printf "$T2HOME/tranalyzer2/src/tranalyzer -r path/to/file.pcap\n\n"
    printf "For more details, run $T2HOME/tranalyzer2/src/tranalyzer --help or refer to the documentation under $T2HOME/doc/documentation.pdf\n\n"

    local rcfiles="${rcfile[*]}"
    local rcformatted=${rcfiles// / or } # join rc files with ' or '
    printinf "To access all aliases, copy the following code into your shell startup file, e.g., $rcformatted:\n"
    cat << EOF
if [ -f "$T2HOME/scripts/t2_aliases" ]; then
    . "$T2HOME/scripts/t2_aliases"
fi

EOF
    printinf "Then open a new terminal or run: source $rcfiles\n"
}

install_deps() {
    local i
    # libpcap, texlive and zlib depend on distribution... (see below)
    local deps=(coreutils)
    if [ -n "$ZSH_VERSION" ]; then
        deps+=(zsh-completions)
    else
        deps+=(bash-completion)
    fi
    for i in autoconf autoconf-archive automake bzip2 dialog gawk libtool make; do
        hash "$i" 2> /dev/null || deps+=("$i")
    done
    # [g]readlink is provided by coreutils
    if [ "$(uname)" = "Darwin" ]; then
        hash gsed 2> /dev/null || deps+=(gnu-sed)
    else
        hash sed 2> /dev/null || deps+=(sed)
        if [ -z "$NOGUI" ]; then
            hash xdg-open 2> /dev/null || deps+=(xdg-utils)
        fi
    fi

    if ! hash curl 2> /dev/null && ! hash wget 2> /dev/null; then
        deps+=(wget)
    fi

    if [[ $EUID != 0 ]] && hash sudo 2> /dev/null; then
        local sudo="sudo"
    fi

    local cmd
    local cmd_search
    local cmd_install
    local cmd_update=()

    if hash pacman 2> /dev/null; then
        cmd="$sudo pacman -S"
        [ -n "$YES" ] && cmd="$cmd --noconfirm"
        cmd_search="pacman -Ss"
        cmd_install="$cmd"
        cmd_update=("$cmd -y")
        [ -n "$REFRESH_KEYS" ] && cmd_update+=("$cmd_install archlinux-keyring")

        hash gcc 2> /dev/null || deps+=(gcc)
        hash which 2> /dev/null || deps+=(which)
        if ! hash pkgconf 2> /dev/null && ! hash pkg-config 2> /dev/null; then
            deps+=(pkgconf)
        fi
        deps+=(libpcap zlib)
        [ -z "$NOLATEX" ] && deps+=(texlive-fontsrecommended texlive-latexextra)
        [ -n "$BUILD_ALL" ] && deps+=(
            jansson             # bayesClassifier
            libmaxminddb        # geoip
            #geoip              # geoip (legacy)
            librdkafka          # kafkaSink
            mongo-c-driver      # mongoSink
            mariadb-libs        # mysqlSink
            libgcrypt           # nDPI
            postgresql-libs     # psqlSink
            re2                 # regex_re2
            cmake               # regexHyperscan
            boost               # regexHyperscan
            ragel               # regexHyperscan
        )
    elif hash emerge 2> /dev/null; then
        cmd="$sudo emerge"
        [ -n "$YES" ] && cmd="$cmd --ask=n"
        cmd_search="emerge --search"
        cmd_install="$cmd"
        cmd_update=("$cmd --sync")

        deps+=(libpcap zlib)
        [ -z "$NOLATEX" ] && deps+=(texlive-fontsrecommended texlive-latexextra)
        [ -n "$BUILD_ALL" ] && deps+=(
            jansson             # bayesClassifier
            libmaxminddb        # geoip
            #geoip              # geoip (legacy)
            librdkafka          # kafkaSink
            mongo-c-driver      # mongoSink
            mariadb-connector-c # mysqlSink
            #mysql-connector-c  # mysqlSink (legacy)
            libgcrypt           # nDPI
            postgresql          # psqlSink
            re2                 # regex_re2
        )
    elif hash dnf 2> /dev/null || hash yum 2> /dev/null; then
        cmd="$sudo"
        if hash dnf 2> /dev/null; then
            cmd="$cmd dnf"
            cmd_search="dnf search"
        else
            cmd="$cmd yum"
            cmd_search="yum search"
        fi
        [ -n "$YES" ] && cmd="$cmd -y"
        cmd_update="$cmd check-update"
        cmd_install="$cmd install"

        # get OS variables
        if [ -e /etc/os-release ]; then
           . /etc/os-release
        elif [ -e /usr/lib/os-release ]; then
           . /usr/lib/os-release
        fi

        if [[ "$ID_LIKE" =~ "centos" ]]; then
            # CentOS/Rocky/... 8/9 do not have the necessary packages to build documentation
            [ -z "$NOLATEX" ] && printwrn "Missing texlive packages on CentOS: cannot build documentation or use t2fm"
            NOLATEX=1

            # Special handling for Rocky/Alma/CentOS container images which use coreutils-single instead
            # of the standard coreutils
            [ "$container" = "podman" ] && rpm --quiet -q coreutils-single && cmd_install="$cmd_install --allowerasing"

            # enable powertools/crb and EPEL repositories
            if [ "$PLATFORM_ID" = "platform:el8" ]; then
                CODEREPO=powertools
            else
                CODEREPO=crb
            fi
            $cmd_update
            $cmd_install dnf-plugins-core
            $cmd config-manager --set-enabled "$CODEREPO"
            $cmd_install epel-release
        fi

        deps+=(libbsd-devel libpcap-devel readline-devel zlib-devel)
        [ -z "$NOLATEX" ] && deps+=(texlive-collection-fontsrecommended texlive-collection-latexextra)

        [ -n "$BUILD_ALL" ] && deps+=(
            jansson                     # bayesClassifier
            libmaxminddb-devel          # geoip
            #GeoIP-devel                # geoip (legacy)
            librdkafka-devel            # kafkaSink
            mongo-c-driver-devel        # mongoSink
            mariadb-connector-c-devel   # mysqlSink
            #community-mysql-devel      # mysqlSink (legacy)
            libgcrypt-devel             # nDPI
            libpq-devel                 # psqlSink
            pcre-devel                  # regex_pcre
            re2-devel                   # regex_re2
            gcc-c++                     # regex_re2 / regexHyperscan
            cmake                       # regexHyperscan
            boost-devel                 # regexHyperscan
            ragel                       # regexHyperscan
            openssl-devel               # sshDecode, sslDecode
            sqlite-devel                # sqliteSink
        )
    elif hash zypper 2> /dev/null; then
        cmd="$sudo zypper"
        [ -n "$YES" ] && cmd="$cmd --non-interactive"

        # get OS variables
        if [ -e /etc/os-release ]; then
           . /etc/os-release
        elif [ -e /usr/lib/os-release ]; then
           . /usr/lib/os-release
        fi

        if [ "$ID" = "opensuse-tumbleweed" ]; then
            DISTRIB="openSUSE_Tumbleweed"
        elif [ "$ID" = "opensuse-leap" ]; then
            DISTRIB="$VERSION"
        fi

        cmd_search="zypper search --match-exact"
        cmd_install="$cmd install --allow-vendor-change"
        if ! $cmd repos | grep -qFw "server_database"; then
            cmd_update=("$cmd addrepo -f https://download.opensuse.org/repositories/server:database/$DISTRIB/server:database.repo")
        fi
        [ -n "$REFRESH_KEYS" ] && cmd_update+=("$cmd --gpg-auto-import-keys refresh")
        cmd_update+=("$cmd update")

        hash gcc 2> /dev/null || deps+=(gcc)
        deps+=(libbsd-devel libpcap-devel readline-devel zlib-devel)
        [ -z "$NOLATEX" ] && deps+=(texlive-collection-fontsrecommended texlive-collection-latexextra)
        [ -n "$BUILD_ALL" ] && deps+=(
            libjansson            # bayesClassifier
            libmaxminddb-devel    # geoip
            #libGeoIP-devel       # geoip (legacy)
            librdkafka-devel      # kafkaSink
            libmongoc-1_0-0-devel # mongoSink
            libmariadb-devel      # mysqlSink
            libgcrypt-devel       # nDPI
            postgresql-devel      # psqlSink
            pcre-devel            # regex_pcre
            re2-devel             # regex_re2
            libopenssl-devel      # sshDecode, sslDecode
            sqlite3-devel         # sqliteSink
        )
    elif hash apt-get 2> /dev/null; then
        cmd="$sudo apt-get"
        [ -n "$YES" ] && cmd="$cmd -y"
        cmd_update=("$cmd update")
        cmd_install="$cmd install"
        cmd_search="apt-cache search"

        deps+=(libbsd-dev libpcap-dev libreadline-dev zlib1g-dev)
        [ -z "$NOLATEX" ] && deps+=(texlive-fonts-recommended texlive-latex-extra)
        if [ -n "$BUILD_ALL" ]; then
            deps+=(
                libjansson-dev      # bayesClassifier
                libmaxminddb-dev    # geoip
                #libgeoip-dev       # geoip (legacy)
                librdkafka-dev      # kafkaSink
                libmongoc-dev       # mongoSink
                libmariadb-dev      # mysqlSink
                #libmysqlclient-dev # mysqlSink (legacy)
                libgcrypt20-dev     # nDPI
                libpq-dev           # psqlSink
                libpcre3-dev        # regex_pcre
                g++                 # regex_re2 / regexHyperscan
                cmake               # regexHyperscan
                libboost-dev        # regexHyperscan
                ragel               # regexHyperscan
                libssl-dev          # sshDecode, sslDecode
                libsqlite3-dev      # sqliteSink
            )

            local release
            if hash lsb_release 2> /dev/null; then
                release="$(lsb_release -r -s | tr -d '.')"
            elif [ -f "/etc/lsb-release" ]; then
                release="$(grep '^DISTRIB_RELEASE=' /etc/lsb-release | cut -d= -f2 | tr -d '.')"
            fi
            if [ -n "$release" ] && [ "$release" -gt 1510 ]; then
                deps+=(libre2-dev)  # regex_re2
            fi
        fi
    elif [ "$(uname)" = "Darwin" ]; then
        if ! hash brew 2> /dev/null; then
            printinf "Installing Homebrew..."
            if ! /usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"; then
                printerr "Failed to download or install brew"
                exit 1
            fi
        fi

        # TODO yes???
        cmd_install="brew install"
        cmd_update=("brew update")
        cmd_search="brew search"

        hash pidof 2> /dev/null || deps+=(pidof)
        hash watch 2> /dev/null || deps+=(watch)
        deps+=(libpcap readline zlib)
        local cmd_cask="$cmd_install --cask"
        [ -z "$NOLATEX" ] && local deps_cask=(mactex)
        [ -n "$BUILD_ALL" ] && deps+=(
            jansson             # bayesClassifier
            libmaxminddb        # geoip
            #geoip              # geoip (legacy)
            librdkafka          # kafkaSink
            mongo-c-driver      # mongoSink
            mariadb-connector-c # mysqlSink
            libgcrypt           # nDPI
            postgresql          # psqlSink
            pcre                # regex_pcre
            re2                 # regex_re2
            openssl             # sshDecode, sslDecode
            sqlite              # sqliteSink
        )
    else
        printerr "\nFailed to install dependencies: no package utility found"
        printinf "Required dependencies are: ${deps[*]}"
        printf "You may use your package utility to install them\n"
        exit 1
    fi

    printinf "Updating package list..."
    if [ "$(uname)" != "Darwin" ] && [[ $EUID != 0 ]]; then
        printinf "You may be prompted for your password."
    fi

    local OLDIFS="$IFS"
    IFS=$'\n'

    local last_cmd
    local ret=0
    for last_cmd in "${cmd_update[@]}"; do
        sh -c "$last_cmd"
        ret=$?
        if [ "$ret" -ne 0 ]; then
            # dnf/yum return 100 if updates are available...
            if ! grep -qFw -e dnf -e yum <<< "$last_cmd" || [ "$ret" -ne 100 ]; then
                printerr "Failed to update package list..."
                printinf "Command was: $last_cmd"
                exit 1
            fi
        fi
    done

    IFS="$OLDIFS"

    # Search for optional packages
    local optional=(meson)
    for i in "${optional[@]}"; do
        $cmd_search "$i" | grep -qFw "$i" && deps+=("$i")
    done

    printinf "Installing dependencies..."
    if [ "$(uname)" = "Darwin" ]; then
        if [ "${#deps_cask[@]}" -gt 0 ]; then
            if ! $cmd_cask "${deps_cask[@]}"; then
                printerr "Failed to install dependencies..."
                printinf "Command was: $cmd_cask ${deps_cask[*]}"
                exit 1
            fi
        fi
    fi

    if ! $cmd_install "${deps[@]}"; then
        printerr "Failed to install dependencies..."
        printinf "Command was: $cmd_install ${deps[*]}"
        exit 1
    fi

    if [ -z "$READLINK" ]; then
        # [g]readlink should exist now...
        # Make sure T2HOME is absolute!
        source "$(dirname "$0")/scripts/t2utils.sh"
    fi
}

update_databases() {
    if ! "$T2BUILD" -a -U $YES; then
        if grep -qFw "empty"   <<< "$ACTIONS" ||
           grep -qFw "build"   <<< "$ACTIONS" ||
           grep -qFw "man"     <<< "$ACTIONS" ||
           grep -qFw "aliases" <<< "$ACTIONS"
        then
            printerr "Failed to update some databases..."
            printinf "Try running '$SNAME -N' to skip the steps requiring network access"
            exit 1
        fi
    fi
}

empty_plugin_folder() {
    "$T2BUILD" -e $YES || exit 1
}

build_tranalyzer() {
    if ! "$T2BUILD" $BUILD_ALL -r -f "$YES"; then
        if grep -qFw "man" <<< "$ACTIONS"; then
            ask_default_yes "Install man pages anyway" && install_man
        fi
        if grep -qFw "aliases" <<< "$ACTIONS"; then
            ask_default_yes "Install aliases anyway" && install_aliases
        fi
        printf "\n${GREEN_BOLD}Setup complete ${ORANGE_BOLD}(but some plugins failed to build)${NOCOLOR}\n\n"
        if grep -qFw "aliases" <<< "$ACTIONS"; then
            alias_msg
        else
            noalias_msg
        fi
        exit 1
    fi
}

install_man() {
    "$T2HOME/scripts/t2conf/install.sh" man
    "$T2HOME/scripts/t2fm/install.sh" man
    "$T2HOME/scripts/tawk/install.sh" man
    "$T2HOME/tranalyzer2/install.sh" man
}

install_aliases() {
    local destrc=($(get_rc_file))
    if [ ${#destrc[@]} -eq 0 ]; then
        printerr "\nFailed to install t2_aliases: $HOME/.{bashrc,bash_profile,cshrc,kshrc,profile,shrc,tcshrc,zshrc} not found.\n"
        noalias_msg
        printwrn "Setup incomplete.\n"
        exit 1
    fi

    local ret=0
    for rc in "${destrc[@]}"; do
        if grep -q "^[^#]\s\+\.\s\+\"$T2HOME/scripts/t2_aliases\"" "$rc"; then
            printinf "\nt2_aliases already installed in '$rc'."
        elif grep -q "^[^#]\s\+\.\s\+\".*/t2_aliases\"" "$rc"; then
            local new_path="$T2HOME/scripts"
            local old_path="$(grep "^[^#]\s\+\.\s\+\".*/t2_aliases\"" "$rc")"
            old_path="$(perl -pe "s|^[^#]\s+\.\s+\"(.*)/t2_aliases\"|\${1}|" <<< "$old_path")"
            printwrn "\nt2_aliases already installed in '$rc' from '$old_path'"
            printf "Replace with '$new_path' (y/N)? "
            local ans
            if [ -z "$YES" ]; then
                read -r ans
            else
                ans="yes"
                echo "$ans"
            fi
            case "$ans" in
                [yY]|[yY][eE][sS])
                    perl -i -pe "s|(^\s*if\s+\[\s+-f\s+\").*(/t2_aliases\"\s+\];\s+then)|\${1}$new_path\${2}|p" "$rc"
                    perl -i -pe "s|(^[^#]\s+\.\s+\").*(/t2_aliases\")|\${1}$new_path\${2}|p" "$rc"
                    printok "\n\nt2_aliases successfully updated in '$rc'.\n"
                    ;;
                *)
                    noalias_msg
                    printwrn "\nSetup incomplete.\n"
                    ;;
            esac
        else
cat << EOF >> "$rc"

if [ -f "$T2HOME/scripts/t2_aliases" ]; then
    . "$T2HOME/scripts/t2_aliases"
fi
EOF
            printok "\nt2_aliases successfully installed in '$rc'.\n"
        fi
    done
}

download_latest_version() {
    if [ -z "$1" ]; then
        printerr "download_latest_version: $1 (\$1) is not a valid version"
        exit 1
    elif [ ! -d "$2" ]; then
        printerr "download_latest_version: $2 (\$2) is not a valid folder"
        exit 1
    fi

    local _latest_version="$1"
    local _outfolder="$2"
    local _package_name="tranalyzer2-${_latest_version}.tar.gz"
    local _url="$T2WWW_HOME/download/tranalyzer/${_package_name}"

    #ask_default_yes "Download ${_package_name}" || exit 0

    # TODO ask if _outname already exists?

    local _outname="$_outfolder/$_package_name"
    if ! t2_wget "$_url" "$_outname"; then
        printerr "Failed to download latest tranalyzer version."
        exit 1
    fi

    printok "Successfully downloaded '$_package_name'"
}

extract_latest_version() {
    if [ ! -f "$1" ]; then
        printerr "extract_latest_version: $1 (\$1) is not a valid file"
        exit 1
    fi

    local _archive="$1"

    local _extract_dir
    if [ -n "$2" ]; then
        _extract_dir="$2"
    else
        _extract_dir="$T2HOME"
    fi

    while [ -d "$_extract_dir" ]; do
        if ask_default_no "\nOverwrite '$_extract_dir'"; then
            rm -rf "$_extract_dir"
        else
            local ans=""
            while [ -z "$ans" ]; do
                read -r -p "Enter an alternate directory name or type 'q' to abort: " ans
                if [ -z "$ans" ]; then
                    printerr "directory name cannot be empty"
                elif [ "$ans" = "q" ]; then
                    exit 0
                else
                    _extract_dir="$ans"
                fi
            done
        fi
    done

    if [ ! -d "$_extract_dir" ]; then
        mkdir -p "$_extract_dir"
    fi

    if ! tar xzf "$_archive" -C "$_extract_dir" --strip-components 1; then
        printerr "Failed to extract '$_archive'"
        exit 1
    fi

    printok "'$_archive' successfully extracted under '$_extract_dir'"

    # TODO message about how to proceed
    #if [ -z "$2" ]; then
    #    # if aliases_installed: printf "open a new terminal"
    #    # else install t2_aliases?"
    #else
    #    # if aliases_installed: printf "use t2_aliases from latest version"
    #    # else install t2_aliases?"
    #fi
}

check_for_update() {
    check_dependency curl
    local _current_version="0.9.3lmw3"
    local _url="$T2WWW_HOME/download/tranalyzer/latest"
    local _latest_version="$(curl --head "$_url" 2> /dev/null | AWK -F'/' '/^[Ll]ocation:/ {
        gsub(/^tranalyzer2-/, "", $NF);
        gsub(/\.tar\.gz[\r\n]+$/, "", $NF);
        print $NF
    }')"
    if [ $? -ne 0 ] || [ -z "$_latest_version" ]; then
        curl --head "$_url"
        echo
        printerr "Failed to query '$T2WWW_HOME' for latest version"
        exit 1
    fi

    if [ "$_current_version" = "$_latest_version" ]; then
        printinf "Tranalyzer2 $_current_version is already the latest version available!"
        exit 0
    fi

    local _package_name="tranalyzer2-${_latest_version}"
    local _outfolder_default="$($READLINK -f "$T2HOME/..")"

    local ans=4
    while [ "$ans" = "4" ]; do
        printinf "Tranalyzer2 version $_latest_version is out!"
        printf "    1: Download and overwrite current version\n"
        printf "    2: Download and extract under '$_package_name'\n"
        printf "    3: Download\n"
        printf "    4: See the ChangeLog\n"
        printf "    *: Do nothing (exit) [default]\n"
        printf "What do you want to do? "
        read -r ans

        if [ -z "$ans" ] || [ -n "$(tr -d '1234' <<< "$ans")" ]; then
            exit 0
        fi

        if [ "$ans" = "4" ]; then
            curl "$T2WWW_HOME/download/tranalyzer/ChangeLog-${_latest_version}" 2> /dev/null | AWK '
                BEGIN {
                    bold = "\033[1m"
                    nocolor = "\033[0m"
                }
                NR == 1 {
                    print "\n" bold $0 nocolor
                    next
                }
                {
                    if (match($0, /^(\s*)(\*[^:]+:)(.*)$/, l) != 0) {
                        print l[1] bold l[2] nocolor l[3]
                    } else {
                        print
                    }
                }
                END {
                    printf "\n"
                }'
        fi
    done

    local _outfolder
    printf "Choose output folder (type enter to use '$_outfolder_default'): "
    read -r _outfolder
    [ -z "$_outfolder" ] && _outfolder="$_outfolder_default"
    [ ! -d "$_outfolder" ] && mkdir -p "$_outfolder"

    download_latest_version "$_latest_version" "$_outfolder"

    [ "$ans" = "3" ] && exit 0

    local _outfolder_pkg
    [ "$ans" = "2" ] && _outfolder_pkg="$_outfolder/${_package_name}"

    extract_latest_version "$_outfolder/$_package_name.tar.gz" "$_outfolder_pkg"
}

cleanup() {
    exit "$1"
}

trap "trap - SIGTERM && cleanup 1" HUP INT QUIT TERM
trap "cleanup \$?" EXIT

YES="-y"
ALL=(deps db empty build man aliases)

ARGS=("$@")

while [ $# -ne 0 ]; do
    case "$1" in
        -a|--all)           BUILD_ALL="-a";;

        -G|--no-gui)        NOGUI=1;;
        -T|--no-latex)      NOLATEX=1;;
        -r|--refresh-keys)  REFRESH_KEYS=1;;

        -D|--no-deps)       ALL=("${ALL[@]/deps/}");;
        -U|--no-db)         ALL=("${ALL[@]/db/}");;
        -N|--no-network)    ALL=("${ALL[@]/deps/}")
                            ALL=("${ALL[@]/db/}");;
        -E|--no-empty)      ALL=("${ALL[@]/empty/}");;
        -B|--no-build)      ALL=("${ALL[@]/build/}");;
        -M|--no-man)        ALL=("${ALL[@]/man/}");;
        -L|--no-aliases)    ALL=("${ALL[@]/aliases/}");;

        -d|--deps)          ACTIONS+=(deps);;
        -u|--db)            ACTIONS+=(db);;
        -e|--empty)         ACTIONS+=(empty);;
        -b|--build)         ACTIONS+=(build);;
        -m|--man)           ACTIONS+=(man);;
        -l|--aliases)       ACTIONS+=(aliases);;

        -i|--ask) unset YES;;
        #-y|--yes) YES="-y";;

        -C|--update)
            check_for_update
            exit 0
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

if [ -z "$READLINK" ] && [ "$(dirname "$0")" != "." ]; then
    printerr "$SNAME MUST be run from Tranalyzer root folder"
    printinf "Go to Tranalyzer root folder and run ./$SNAME ${ARGS[*]}"
    exit 1
fi

# Make sure all the commands are run from the root folder of Tranalyzer
cd "$T2HOME" || fatal "Failed to change directory to '$T2HOME'"

# Make sure the scripts are executable
if [ ! -x autogen.sh ]; then
    chmod +x autogen.sh ./*/autogen.sh plugins/*/autogen.sh scripts\
             scripts/tawk/tawk scripts/t2fm/t2fm scripts/t2conf/t2*conf \
             plugins/dnsDecode/utils/dmt plugins/macRecorder/utils/mconv \
             plugins/nDPI/clean.sh plugins/netflowSink/utils/ampls \
             scripts/*/install.sh utils/subnet/subconv \
             utils/subnet/tor/torldld tranalyzer2/install.sh
fi

if [ ${#ACTIONS[@]} -eq 0 ]; then
    ACTIONS="${ALL[*]}"
else
    ACTIONS="${ACTIONS[*]}"
fi

for action in "${ALL[@]}"; do
    if grep -qFw "$action" <<< "$ACTIONS"; then
        case "$action" in
            deps)    install_deps;;
            db)      update_databases;;
            empty)   empty_plugin_folder;;
            build)   build_tranalyzer;;
            man)     install_man;;
            aliases) install_aliases;;
        esac
    fi
done

printok "\n${BOLD}Setup complete.${NOCOLOR}\n"

if grep -qFw "aliases" <<< "$ACTIONS"; then
    alias_msg
else
    noalias_msg
fi
