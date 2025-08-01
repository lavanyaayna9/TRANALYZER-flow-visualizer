#!/usr/bin/env bash
#
# This script builds Tranalyzer2 and the plugins. If it is executed with the
# option '-i', then the Tranalyzer binary is copied to '/usr/local/bin'.
#
# If no options are provided, builds a default set of plugins.
# If the '-a' option is used, builds all the plugins
# If the '-b' option is used, build the plugins listed in 'plugins.build'
# If the '-b file' option is used, build the plugins listed in 'file'
# Alternatively, a list of plugin names can be passed to the script

source "$(dirname "${0}")/scripts/t2utils.sh"

usage() {
    echo "${SNAME} - Build Tranalyzer2 and the plugins"
    echo
    echo "Usage:"
    echo "    ${SNAME} [OPTION...] [plugin...]"
    echo
    echo "Optional arguments:"
    echo "    -a            Build all plugins"
    echo "    -b file       Build plugins listed in 'file'"
    echo "    -I file       Ignore plugins listed in 'file' (requires -a option)"
    echo "    -R            Rebuild Tranalyzer and all the plugins in the plugin folder"
    echo "    --no-sink     Do not build any sink plugin"
    echo
    echo "    plugin        A list of valid plugin names"
    echo
    echo "    -c            Execute make clean and remove automatically generated files"
    echo "    -d            Compile in debug mode"
    echo "    -P            Compile in profile mode"
    echo "    --iwyu        Run include-what-you-use"
    echo "    -O level      Compiler optimization level (0, g, 1, [2], 3, s)"
    echo "    --lto         Enable link time optimization (meson only)"
    echo "    -L            Lazy mode (run make all instead of make clean all)"
    echo "    -r            Force rebuild of makefiles"
    echo "    -f            Force the copy of extra files"
    echo
    echo "    -u            Unload/remove the plugin from the plugin folder"
    echo "    -e            Empty the plugin folder and exit"
    echo "    -l            List all plugins in the plugin folder and exit"
    echo
    echo "    -k[Jjtz]      Create one compressed archive per plugin"
    echo "    -K[Jjtz]      Create one compressed archive with the requested plugins"
    echo "                  (J: tar.xz, j: tar.bz2, t: tar, z: tar.gz [default])"
    echo
    echo "    -U            Update (download new blacklists, ...)"
    echo
    echo "    -1            Do not parallelize the build process (slow)"
    echo "    -X            Bypass the lock file at your own risks..."
    echo "                  (concurrent modifications may happen)"
    echo
    echo "    -D            Build the documentation for the plugin"
    echo
    echo "    -i            Install Tranalyzer binary in plugin directory"
    echo "    -p dir        Plugin installation directory [${PLUGIN_DIR}]"
    echo
    echo "    -y            Do not ask for confirmation before executing an action"
    echo
    echo "    -B backend    Use 'backend' (if available) instead of 'meson'"
    echo "                  (meson, cmake, autotools-out-of-tree, autotools [deprecated],"
    echo "                  cargo [rust plugins only])"
    echo
    echo "    -G name       Build system generator to use for CMake"
    echo
    echo "    -h, --help    Show help options and exit"
    echo
}

# $1: backend
validate_backend() {
    local backend="${1}"
    if [ -z "${backend}" ]; then
        fatal "Usage: validate_backend backend"
    fi

    case "${backend}" in
        cargo)
            check_dependency cargo cargo-c
            check_dependency rustc rust
            ;;
        cmake)
            check_dependency cmake
            ;;
        meson)
            check_dependency meson
            ;;
        autotools-out-of-tree)
            check_dependency autoreconf autoconf
            ;;
        autotools)
            check_dependency autoreconf autoconf
            printwrn "\nUsing the 'autotools' build backend is deprecated and discouraged..."
            printinf "Consider using 'meson', 'cmake' or 'autotools-out-of-tree' instead\n"
            ;;
        *)
            printerr "Unknown backend '${backend}'"
            abort_with_help
            ;;
    esac
}

build_tranalyzer() {
    printinf "\n'Tranalyzer2'\n"
    cd "${T2HOME}/tranalyzer2" || fatal "Failed to cd into '${T2HOME}/tranalyzer2'"
    VALIDATE_BACKEND=0 ./autogen.sh ${INSTALL} "${OPTS[@]}"
}

build_plugin() {
    local plugin="${1}"
    printinf "\nPlugin '${plugin}'\n"
    cd "${T2PLHOME}/${plugin}" || fatal "Failed to cd into '${T2PLHOME}/${plugin}'"
    if [ "${NCPUS}" -gt 1 ] && [ "${POLLINT}" -gt 0 ] && [ "${#PLUGINS[@]}" -gt 1 ]; then
        VALIDATE_BACKEND=0 ./autogen.sh "${OPTS[@]}" &> /dev/null
    else
        VALIDATE_BACKEND=0 ./autogen.sh "${OPTS[@]}"
    fi
    if [ $? -ne 0 ]; then
        echo "${plugin}" >> "${FAILED_FILE}"
    fi
}

list_plugins() {
    local plugins
    plugins="$(find "${PLUGIN_DIR}" -type f -name "[0-9][0-9][0-9]_*\.so" 2> /dev/null | perl -lpe 's!^.*/\d{3}_(.*)\.so$!\1!' | sort -u)"
    if [ -z "${plugins}" ]; then
        printf "No plugins in '${PLUGIN_DIR}'\n"
    else
        printf "${plugins}\n"
    fi
}

# Honour the t2_prepackage function
honour_t2_prepackage() {
    local path="${1}"
    if [ ! -d "${path}" ]; then
        fatal "Usage: honour_t2_prepackage path"
    fi

    if grep -q "^t2_prepackage()" "${path}/autogen.sh"; then
        _OLD_PWD="${PWD}"
        cd "${path}" || fatal "Failed to cd into '${path}'"
        TEMP="$(mktemp)"
        AWK -v file="${TEMP}" '
                /^t2_prepackage()/ { _func = 1 }
                !_func { next }
                _func { print >> file }
                /^\}$/ {
                    print "t2_prepackage" >> file
                    exit
                }' autogen.sh
        bash "${TEMP}"
        rm "${TEMP}"
        cd "${path}" || fatal "Failed to cd back into '${_OLD_PWD}'"
    fi
}

package_setup() {
    OPERATION="PACKAGING"
    OPERATION_PAST="packaged"
    # Force a clean before packaging
    OPTS+=("-c")
    POLLINT=0
    # Options for packaging
    PKGVERSION="$(AWK -F, '/^AC_INIT\(\[/ { print $2 }' "${T2HOME}/tranalyzer2/configure.ac" | tr -d '[][:blank:]')"
    PKGNAME="$(basename "${T2HOME}")-${PKGVERSION}"
    PKG="${PKGNAME}${PKGEXT}"
    # Extra files to include in the package
    PKGEXTRA=(
        autogen.sh
        plugins/autogen.sh
        ChangeLog
        doc
        plugins/t2PSkel
        README.md
        scripts
        setup.sh
        tests
        tranalyzer2
        utils
    )
    TMPDIR="/tmp"
    PKGTMP="${TMPDIR}/${PKGNAME}"
}

new_package() {
    if [ -f "${PKG}" ]; then
        rm -f "${PKG}"
    fi
    if [ -d "${PKGTMP}" ]; then
        rm -rf "${PKGTMP}"
    fi
    honour_t2_prepackage "${T2HOME}/tranalyzer2"
    mkdir -p "${PKGTMP}/plugins"
    for extra in "${PKGEXTRA[@]}"; do
        add_to_package "${extra}"
    done
}

add_to_package() {
    local file="${1}"

    # NOTE: this technique using symbolic links can be problematic if plugins contain
    # symbolic links which should NOT be dereferenced when creating the archive.
    # If this is the case in the future, a "cp -r" could replace the next line.
    if ! ln -s "${T2HOME}/${file}" "${PKGTMP}/${file}"; then
        fatal "\nFailed to add '${file}' to '${PKG}'\n"
    fi

    printok "\nSuccessfully added '${file}' to '${PKG}'\n"
}

empty_plugin_folder() {
    if [ ! -d "${PLUGIN_DIR}" ]; then
        printf "Plugin folder does not exist\n"
        if [ -z "${CLEAN}" ]; then
            exit 0
        else
            return
        fi

    fi

    printf "Are you sure you want to empty the plugin folder '${PLUGIN_DIR}' (y/N)? "
    if [ -z "${YES}" ]; then
        read -r ans
    else
        ans="yes"
        echo "${ans}"
    fi
    case "${ans}" in
        [yY]|[yY][eE][sS])
            rm -rf "${PLUGIN_DIR}"
            printok "Plugin folder emptied"
            [ -z "${CLEAN}" ] && exit 0
            ;;
        *)
            printwrn "Plugin folder not emptied"
            exit 1
            ;;
    esac
}

clean_extra() {
    make -C "${T2HOME}/doc" clean
    make -C "${T2HOME}/scripts/doc" clean
    make -C "${T2HOME}/scripts/tawk/doc" clean
    make -C "${T2HOME}/scripts/t2fm/doc" clean
    make -C "${T2HOME}/tests/t2tests" distclean
    make -C "${T2HOME}/utils/t2b2t" distclean
}

_cleanup() {
    local ret="${1}"

    if [[ "$(pgrep -P $$ | wc -l)" -gt 1 ]]; then
        printf "Killing all subprocesses...\n"
        kill -- -$$
    fi

    #echo "Cleaning temporary files"
    rm -f "${FAILED_FILE}" "${T2BUILD_LOCK}"

    exit "${ret}"
}

# Default values
OPERATION="BUILDING"
OPERATION_PAST="built"
POLLINT=1 # Poll interval

PLUGIN_DIR="${HOME}/.tranalyzer/plugins"

# Plugins to build:
#   - d: default
#   - b: file [plugins.build] (-b [file])
#   - a: all (recursive) (-a)
#   - r: rebuild (-R)
BUILD="d"

PLUGINS_BUILD="${T2HOME}/plugins.build"
PLUGINS_IGNORE="${T2HOME}/plugins.ignore"

PLUGINS_DEFAULT=(
    basicFlow
    basicStats
    connStat
    icmpDecode
    macRecorder
    portClassifier
    protoStats
    tcpFlags
    tcpStates
    txtSink
)

PLUGINS_BLACKLIST=(
    t2PSkel
    tcpWin
)

OPTS=()

CMDLINE_OPTS="$*"

# Process args
while [ $# -gt 0 ]; do
    case "${1}" in
        -i|--install)
            INSTALL="${1}"
            ;;
        # what to build: default(d), all(a), or file(b)
        -a|--all)
            BUILD="a"
            ;;
        --no-sink)
            NOSINK=1
            ;;
        -R|--rebuild)
            BUILD="r"
            ;;
        -b|--build)
            BUILD="b"
            validate_next_file "${1}" "${2}"
            PLUGINS_BUILD="${2}"
            #printf "\nBuilding plugins listed in '%s'\n" "$PLUGINS_BUILD"
            #AWK '!/^#/ { i++; printf("\t%3d) %s\n", i, $0) }' "$PLUGINS_BUILD"
            shift
            ;;
        -I|--ignore)
            validate_next_file "${1}" "${2}"
            PLUGINS_IGNORE="${2}"
            #printf "\nIgnoring plugins listed in '%s'\n" "$PLUGINS_IGNORE"
            #AWK '!/^#/ { i++; printf("\t%3d) %s\n", i, $0) }' "$PLUGINS_IGNORE"
            shift
            ;;
        -r|--configure)
            CONFIGURE=1
            # pass those options as-is to autogen
            OPTS+=("${1}")
            ;;
        -d|--debug|-P|--profile)
            # pass those options as-is to autogen
            OPTS+=("${1}")
            ;;
        -f|--force)
            FORCE=1
            # pass those options as-is to autogen
            OPTS+=("${1}")
            ;;
        -D|--doc)
            # pass those options as-is to autogen
            OPTS+=("${1}")
            ;;
        -B=*|--backend=*)
            validate_backend "${1#*=}"
            # pass those options as-is to autogen
            OPTS+=("${1}")
            ;;
        -B|--backend)
            validate_next_arg "${1}" "${2}"
            validate_backend "${2}"
            # pass those options as-is to autogen
            OPTS+=("${1}" "${2}")
            shift
            ;;
        -G)
            validate_next_arg "${1}" "${2}"
            # pass '-G' option as-is to autogen
            OPTS+=("${1}")
            CMAKE_GENERATOR="${2}"
            shift
            if [ -n "$(AWK '/^"/' <<< "${CMAKE_GENERATOR}")" ]; then
                while [ -z "$(AWK '/"$/' <<< "${CMAKE_GENERATOR}")" ]; do
                    CMAKE_GENERATOR="${CMAKE_GENERATOR} ${2}"
                    shift
                done
            fi
            # pass the reconstructed option as-is to autogen
            OPTS+=("\"${CMAKE_GENERATOR}\"")
            ;;
        -U|--update)
            OPERATION="UPDATING"
            OPERATION_PAST="updated"
            UPDATE=1
            # pass those options as-is to autogen
            OPTS+=("${1}")
            ;;
        -u|--unload)
            OPERATION="UNLOADING"
            OPERATION_PAST="unloaded"
            CHECK_T2=1
            POLLINT=0
            # pass those options as-is to autogen
            OPTS+=("${1}")
            ;;
        -L|--lazy)
            CHECK_T2=1
            POLLINT=0
            # pass those options as-is to autogen
            OPTS+=("${1}")
            ;;
        -c|--clean)
            CLEAN=1
            OPERATION="CLEANING"
            OPERATION_PAST="cleaned"
            POLLINT=0
            # pass those options as-is to autogen
            OPTS+=("${1}")
            ;;
        -k|-k[Jjtz]|--package|--package-bz2|--package-gz|--package-tar|--package-xz)
            OPERATION="PACKAGING"
            OPERATION_PAST="packaged"
            POLLINT=0
            PACKAGE=1
            # pass those options as-is to autogen
            OPTS+=("${1}")
            ;;
        -O)
            validate_next_arg "${1}" "${2}"
            case "${2}" in
                [0g123s]) ;;
                *)
                    printerr "Invalid argument for option '${1}': expected one of [0g123s]; found '${2}'"
                    abort_with_help
                    ;;
            esac
            OPTS+=("${1}" "${2}")
            shift
            ;;
        -O0|-Og|-01|-O2|-O3|-Os)
            # pass those options as-is to autogen
            OPTS+=("${1}")
            ;;
        --lto)
            # pass this option as-is to autogen
            OPTS+=("${1}")
            ;;
        -p|--plugin-dir)
            validate_next_arg "${1}" "${2}"
            OPTS+=("${1}" "${2}")
            PLUGIN_DIR="${2}"
            shift
            ;;
        -KJ|--package-all-xz)
            PKGEXT=".tar.xz"
            PACKAGE_ALL=1
            ;;
        -Kj|--package-all-bz2)
            PKGEXT=".tar.bz2"
            PACKAGE_ALL=1
            ;;
        -Kt|--package-all-tar)
            PKGEXT=".tar"
            PACKAGE_ALL=1
            ;;
        -K|--package-all|-Kz|--package-all-gz)
            PKGEXT=".tar.gz"
            PACKAGE_ALL=1
            ;;
        -1)
            NCPUS=1
            OPTS+=("${1}")
            ;;
        -X|--bypass-lock)
            BYPASS_LOCK=1
            ;;
        -y|--yes)
            YES=1
            OPTS+=("${1}")
            ;;
        --iwyu)
            if ! hash iwyu 2> /dev/null; then
                fatal "iwyu executable not found in '\$PATH'"
            fi
            OPTS+=("${1}")
            ;;
        -e|--empty)
            EMPTY=1
            ;;
        -l|--list)
            list_plugins
            exit 0
            ;;
        -\?|-h|--help)
            usage
            exit 0
            ;;
        --reset)
            printerr "Unknown option '${1}'"
            printinf "Did you mean to call 't2conf ${CMDLINE_OPTS}' instead?"
            exit 1
            ;;
        -*)
            abort_option_unknown "${1}"
            ;;
        *)
            PLUGINS+=("$("${SED}" 's/\/$//' <<< "${1}")")
            ;;
    esac
    shift
done

T2BUILD_LOCK="${T2HOME}/.t2build.lock"
if [ -f "${T2BUILD_LOCK}" ] && [ -z "${BYPASS_LOCK}" ]; then
    _pid="$(cat "${T2BUILD_LOCK}")"
    if ps -p "${_pid}" &> /dev/null; then
        printerr "Another t2build process is currently running"
        printinf "To avoid conflicts, wait until it has terminated"
        printinf "To proceed anyway, use 't2build -X' option or remove '${T2BUILD_LOCK}'"
        exit 1
    fi
    # Remove the leftover lock
    rm -f "${T2BUILD_LOCK}"
fi

if [ -z "${BYPASS_LOCK}" ]; then
    # Create a lock containing the PID
    echo $$ >> "${T2BUILD_LOCK}"
fi

trap "trap - SIGTERM && _cleanup 1" ABRT HUP INT QUIT TERM
trap "_cleanup \$?" EXIT

if [ -n "${PACKAGE_ALL}" ]; then
    package_setup
fi

if [ "${POLLINT}" -gt 0 -o -n "${CHECK_T2}" ] && [ -n "$(pgrep tranalyzer)" ]; then
    printf "\n${ORANGE}Tranalyzer is currently running...${NOCOLOR}\n"
    printf "Proceed anyway (y/N)? "
    if [ -z "${YES}" ]; then
        read -r ans
    else
        ans="yes"
        echo "${ans}"
    fi
    case "${ans}" in
        [yY]|[yY][eE][sS]) ;;
        *) printf "\n"; exit 1
    esac
fi

if [ -n "${EMPTY}" ]; then
    empty_plugin_folder
fi

if [[ "${EUID}" -eq 0 ]] && [[ -z "${DOCKER_BUILD}" ]]; then
    printwrn "\nRunning autogen.sh as root is not recommended..."
    printf "Proceed anyway (y/N)? "
    if [ -z "${YES}" ]; then
        read -r ans
    else
        ans="yes"
        echo "${ans}"
    fi
    case "${ans}" in
        [yY]|[yY][eE][sS]) ;;
        *) echo; exit 1;;
    esac
fi

if [ "${#PLUGINS[@]}" -eq 0 ]; then
    PLUGINS=(tranalyzer2)
    case "${BUILD}" in
        d) # default
            PLUGINS+=("${PLUGINS_DEFAULT[@]}")
            ;;
        b) # plugins.build
            PLUGINS+=($(AWK '!/^#/' "${PLUGINS_BUILD}" | perl -lpe 's!^\d{3}_(.*)\.so$!\1!'))
            ;;
        r) # rebuild
            if [ ! -d "${PLUGIN_DIR}" ]; then
                fatal "\nPlugin directory '${PLUGIN_DIR}' does not exist\n"
            fi
            PLUGINS+=($(find "${PLUGIN_DIR}" -type f -name "[0-9][0-9][0-9]_*\.so" 2> /dev/null | perl -lpe 's!^.*/\d{3}_(.*)\.so$!\1!' | sort))
            ;;
        a)
            [ -f "${PLUGINS_IGNORE}" ] && PLUGINS_BLACKLIST+=($(AWK '!/^#/' "${PLUGINS_IGNORE}" | perl -lpe 's!^\d{3}_(.*)\.so$!\1!'))
            for plugin in "${T2PLHOME}/"*; do
                plugin_name="$(basename "${plugin}")"
                BLACKLISTED=$(grep -Fw "${plugin_name}" <<< "${PLUGINS_BLACKLIST[*]}")
                if [ -d "${plugin}" ] && [ -f "${plugin}/autogen.sh" ] && [ ! "${BLACKLISTED}" ]; then
                    PLUGINS+=("$plugin_name")
                fi
            done
            ;;
        *)
            fatal "\nInvalid build target '${BUILD}'\n"
            ;;
    esac
    [ -n "${CLEAN}" ] && clean_extra
fi

if [ "${#PLUGINS[@]}" -eq 0 ] || grep -qFw "tranalyzer2" <<< "${PLUGINS[*]}"; then
    if ! build_tranalyzer; then
        # if Tranalyzer could not be built, no point in trying to build the plugins
        exit 1
    fi

    # Remove tranalyzer2 from the list of plugins to build
    for i in "${!PLUGINS[@]}"; do
        if [ "${PLUGINS[i]}" = 'tranalyzer2' ] ; then
            unset "PLUGINS[i]"
            break
        fi
    done
fi

if [ -n "${PACKAGE_ALL}" ]; then
    new_package
fi

FAILED_FILE="$(mktemp)"

if [ -z "${NCPUS}" ]; then
    NCPUS=$(get_nproc)
fi

if [ -n "${CLEAN}" ]; then
    target="clean"
else
    target="all"
fi

for plugin in "${PLUGINS[@]}"; do
    if [ -n "${NOSINK}" ]; then
        case "${plugin}" in
            *Sink|findexer|payloadDumper|pcapd) continue;;
        esac
    fi
    if [ "${plugin}" = "t2b2t" ] && [ -d "${T2HOME}/utils/t2b2t" ]; then
        make -C "${T2HOME}/utils/t2b2t" "${target}" || echo "${plugin}" >> "${FAILED_FILE}"
    elif [ "${plugin}" = "t2whois" ] && [ -d "${T2HOME}/utils/t2whois" ]; then
        make -C "${T2HOME}/utils/t2whois" "${target}" || echo "${plugin}" >> "${FAILED_FILE}"
    elif [ "${plugin}" = "fextractor" ] && [ -d "${T2PLHOME}/findexer/fextractor" ]; then
        make -C "${T2PLHOME}/findexer/fextractor" "${target}" || echo "${plugin}" >> "${FAILED_FILE}"
    elif [ ! -d "${T2PLHOME}/${plugin}" ]; then
        printerr "\nPlugin '${plugin}' could not be found\n"
        echo "${plugin}" >> "${FAILED_FILE}"
    elif [ ! -f "${T2PLHOME}/${plugin}/autogen.sh" ]; then
        printerr "${plugin} is not a valid Tranalyzer plugin: could not find autogen.sh"
        echo "${plugin}" >> "${FAILED_FILE}"
    else
        build_plugin "${plugin}" &
        if [ "${NCPUS}" -eq 1 ]; then
            wait
        elif [ "${POLLINT}" -gt 0 ]; then
            # Wait for one CPU to be free
            NPROC="$(jobs -p | wc -l)"
            while [ "${NPROC}" -eq "${NCPUS}" ]; do
                sleep "${POLLINT}"
                NPROC="$(jobs -p | wc -l)"
            done
        fi
        if [ -n "${PACKAGE_ALL}" ]; then
            honour_t2_prepackage "${T2PLHOME}/${plugin}"
            add_to_package "plugins/${plugin}"
        fi
    fi
done

# Wait for all processes to finish
wait < <(jobs -p)

if [ -n "${PACKAGE_ALL}" ] && [ -d "${PKGTMP}" ]; then
    if [ -n "${IS_MACOS}" ]; then
        case "${PKGEXT}" in
            *.tar.bz2) PKGFORMAT="j";;
            *.tar.gz) PKGFORMAT="z";;
            *.tar.xz) PKGFORMAT="J";;
            *.tar) PKGFORMAT="";;
            *)
                fatal "Unhandled archive format '${PKGEXT}'"
                ;;
        esac

        TAR_OPTS=(
            --no-mac-metadata
        )
    else
        PKGFORMAT="a"

        TAR_OPTS=(
            --exclude-vcs
            --exclude-vcs-ignore
            --exclude-backups
            --exclude-caches-under
            --exclude='*gitlab-ci*'
        )
    fi

    TAR_CMD+=(
        tar
        "${TAR_OPTS[@]}"
        -C "${TMPDIR}"
        -c"${PKGFORMAT}"f
        "${T2HOME}/${PKG}"
        -h "${PKGNAME}"
    )

    echo "${TAR_CMD[*]}"
    "${TAR_CMD[@]}"
    rm -rf "${PKGTMP}"
fi

# Adapt message if updating AND building/packaging were requested
if [ -n "${UPDATE}" ]; then
    if [ -n "${PACKAGE}" ] || [ -n "${PACKAGE_ALL}" ]; then
        OPERATION="UPDATING AND PACKAGING"
        OPERATION_PAST="packaged"
    elif [ -n "${FORCE}" ] || [ -n "${CONFIGURE}" ]; then
        OPERATION="UPDATING AND BUILDING"
        OPERATION_PAST="built"
    fi
fi

if [ -s "${FAILED_FILE}" ]; then
    printerr "\nThe following plugins could not be ${OPERATION_PAST}:"
    sort -o "${FAILED_FILE}" "${FAILED_FILE}"
    while read -r plugin; do
        printerr "    ${plugin}"
    done < "${FAILED_FILE}"
    exit 1
fi

printok "\n${OPERATION} SUCCESSFUL\n"
