#!/usr/bin/env bash
#
# Master autogen.sh file for plugins.
#
# Look into t2PSkel/autogen.sh for detailed usage instructions.
#
# Default values for PLUGIN_DIR and GCCOPT are defined in this file,
# but can be overwritten if a plugin chooses to define them. If the '-p' or
# '-o' options are used, their value take precedence.
#
# Every plugin MUST define PLUGINNAME and PLUGINORDER.
# EXTRAFILES, CFLAGS and DEPS are optional.
#
# The following functions (documented in t2PSkel/autogen.sh) can be used:
#   - t2_clean
#   - t2_prebuild
#   - t2_preinst
#   - t2_inst
#   - t2_postinst
#   - t2_prepackage
#   - t2_update
#
# Source this file from the plugins autogen.sh file.

if [ -z "$PLUGINNAME" ] || [ "$PLUGINNAME" != "tranalyzer2" -a -z "$PLUGINORDER" ]; then
    printf "\e[0;31mPLUGINNAME and PLUGINORDER MUST be defined\e[0m\n" >&2
    exit 1
fi

if [ "$PLUGINNAME" = "tranalyzer2" ]; then
    source "$(dirname "$0")/../scripts/t2utils.sh"
else
    source "$(dirname "$0")/../../scripts/t2utils.sh"
fi

# ---------------------------------------------------------------------------- #
# ------------------------------- FUNCTIONS ---------------------------------- #
# ---------------------------------------------------------------------------- #

usage() {
    echo "$SNAME - Build Tranalyzer2 and the plugins"
    echo
    echo "Usage:"
    echo "    $SNAME [OPTION...]"
    echo
    echo "Optional arguments:"
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
    echo "    -1            Do not parallelize the build process (slow)"
    echo
    if [ -n "$PLUGIN" ]; then
        echo "    -u            Unload/remove the plugin from the plugin folder"
        echo
    fi
    echo "    -U            Update (download new blacklists, ...)"
    echo
    echo "    -k[Jjtz]      Create a compressed archive"
    echo "                  (J: tar.xz, j: tar.bz2, t: tar, z: tar.gz [default])"
    echo
    if [ -z "$PLUGIN" ]; then
        echo "    -i            Install Tranalyzer binary in plugin directory"
    fi
    echo "    -p dir        Plugin installation directory [$PLUGIN_DIR]"
    echo
    echo "    -D            Build the documentation for the plugin"
    echo
    echo "    -y            Do not ask for confirmation before executing an action"
    echo
    echo "    -B backend    Use 'backend' (if available) instead of '$DEFAULT_BACKEND'"
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
    if [ -z "$1" ]; then
        fatal "Usage: validate_backend backend"
    fi

    if [ "$VALIDATE_BACKEND" = "0" ]; then
        return
    fi

    local backend="$1"
    case "$backend" in
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
            printerr "Unknown backend '$backend'"
            abort_with_help
            ;;
    esac

    VALIDATE_BACKEND=0
}

# $1: backend [optional]
set_backend() {
    local _verbose=1

    local backend="$1"
    if [ -z "$backend" ]; then
        local b="$(cut -d- -f1 <<< "$DEFAULT_BACKEND")"
        if type "$b" &> /dev/null; then
            backend="$DEFAULT_BACKEND"
        else
            backend="$FALLBACK_BACKEND"
            if [ "$FALLBACK_BACKEND" != "$DEFAULT_BACKEND" ]; then
                printwrn "Default backend '$DEFAULT_BACKEND' not available.\n"
                printinf "Reverting to fallback '$FALLBACK_BACKEND' backend.\n"
            fi
        fi
        unset _verbose
    fi

    local _makefile
    while [ -z "$_makefile" ]; do
        [ -z "$backend" ] && unset _verbose
        case "$backend" in
            cargo)
                check_dependency cargo cargo-c
                _makefile="Cargo.toml"
                ;;
            cmake)
                check_dependency cmake
                _makefile="CMakeLists.txt"
                ;;
            meson)
                check_dependency meson
                _makefile="meson.build"
                ;;
            autotools)
                check_dependency autoreconf autoconf
                if [ "$VALIDATE_BACKEND" != "0" ]; then
                    printwrn "\nUsing the 'autotools' build backend is deprecated and discouraged..."
                    printinf "Consider using 'meson', 'cmake' or 'autotools-out-of-tree' instead\n"
                fi
                _makefile="configure.ac"
                ;;
            autotools-out-of-tree)
                check_dependency autoreconf autoconf
                _makefile="configure.ac"
                ;;
            *)
                fatal "Unknown backend '$backend'"
                ;;
        esac

        if [ -f "$SHOME/$_makefile" ]; then
            [ -n "$_verbose" ] && printinf "Using '$backend' backend\n"
        else
            printwrn "No '$_makefile' found in '$SHOME'"
            if [ "$backend" = "$FALLBACK_BACKEND" ] || [ "$backend" = "cargo" ]; then
                exit 1
            elif [ "$backend" = "$DEFAULT_BACKEND" ]; then
                printinf "Reverting to fallback '$FALLBACK_BACKEND' backend.\n"
                backend="$FALLBACK_BACKEND"
                unset _makefile
                unset _verbose
            else
                printinf "Reverting to default '$DEFAULT_BACKEND' backend.\n"
                backend="$DEFAULT_BACKEND"
                unset _makefile
                unset _verbose
            fi
        fi
    done

    BACKEND="$backend"
    set_builddir
    set_cflags
}

set_builddir() {
    if [ "$BACKEND" = "cargo" ]; then
        BUILDDIR_DEBUG=target/debug
        BUILDDIR_RELEASE=target/release
    fi

    if [ "$BACKEND" = "autotools" ]; then
        unset BUILDDIR
    elif [ -n "${PROFILE}${DEBUG}" ]; then
        BUILDDIR="$BUILDDIR_DEBUG"
    else
        BUILDDIR="$BUILDDIR_RELEASE"
    fi

    if [ "$PLUGINNAME" = "tranalyzer2" ] && [ "$BACKEND" = "autotools-out-of-tree" ]; then
        BUILDDIR="$BUILDDIR/$PLUGINNAME"
    fi
}

set_cflags() {
    if [ -n "$PROFILE" ]; then
        if [[ "$BACKEND" != autotools* ]]; then
            fatal "Profiling support ('-P' option) not implemented for '$BACKEND' backend"
        else
            printinf "\nCompiling in profile mode...\n"
            CFLAGS=("${CFLAGS_PROFILE[@]}")
        fi
    elif [ -n "$DEBUG" ]; then
        printinf "\nCompiling in debug mode...\n"
        if [[ "$BACKEND" = autotools* ]]; then
            CFLAGS=("${CFLAGS_DEBUG[@]}")
        fi
    elif [[ "$BACKEND" = autotools* ]]; then
        CFLAGS=("${CFLAGS_DEFAULT[@]}" -O"$GCCOPT")
    fi
}

# Make sure the makefiles are up to date
need_rebuild() {
    if [[ "$BACKEND" = autotools* ]]; then
        local _builddir
        if [ -n "$BUILDDIR" ]; then
            _builddir="$BUILDDIR"
            # XXX only required if autotools/autotools-out-of-tree were both used
            [ -f "Makefile" ] && make distclean
        else
            _builddir="."
            # XXX only required if autotools/autotools-out-of-tree were both used
            [ -f "$BUILDDIR_RELEASE/Makefile" ] && make -C "$BUILDDIR_RELEASE" distclean
            [ -f "$BUILDDIR_DEBUG/Makefile" ]   && make -C "$BUILDDIR_DEBUG"   distclean
        fi
        if [ ! -f "$_builddir/Makefile" ]; then
            REBUILD=1
        elif ! grep -q "^CFLAGS\s\+=\s\+${CFLAGS[*]}$" "$_builddir/Makefile" ||
             ! grep -q "^LIBS\s\+=\s\+.*${LIBS}.*$" "$_builddir/Makefile"
        then
            REBUILD=1
        elif [ "$(uname)" != "Darwin" ]; then
            make -q -C "$_builddir" &> /dev/null
            if [ $? -eq 2 ]; then
                REBUILD=1
            fi
        fi
    elif [ "$BACKEND" = "cmake" ]; then
        if [ ! -f "$BUILDDIR/CMakeCache.txt" ]; then
            REBUILD=1
        fi
    elif [ "$BACKEND" = "meson" ]; then
        if [ ! -d "$BUILDDIR/meson-info" ] ||
           [ ! -f "$BUILDDIR/build.ninja" ]
        then
            REBUILD=1
        fi
    fi

    if [[ "$REBUILD" -eq 1 ]]; then
        return 0
    else
        return 1
    fi
}

cmake_version_ge() {
    if [ "$(tr -d '0-9' <<< "$1")" != "." ]; then
        fatal "Usage: cmake_version_ge vmajor_required.vminor_required"
    fi

    local v_min="$1"
    local vmajor_min=$(AWK -F '.' '{ print $1 }' <<< "$v_min")
    local vminor_min=$(AWK -F '.' '{ print $2 }' <<< "$v_min")
    local ver="$(cmake --version | head -1 | AWK '{ print $3 }')"
    local vmajor="$(AWK -F '.' '{ print $1 }' <<< "$ver")"
    local vminor="$(AWK -F '.' '{ print $2 }' <<< "$ver")"
    if [ "$vmajor" -gt "$vmajor_min" ] || [ "$vmajor" -eq "$vmajor_min" -a "$vminor" -ge "$vminor_min" ]; then
        echo "$ver"
    fi
}

configure_autotools() {
    cd "$SHOME" || fatal "Failed to cd into '$SHOME'"

    if [ ! -d "m4" ]; then
        mkdir m4
    fi

    autoreconf --install --force || exit 1

    if [ -n "$BUILDDIR" ]; then
        if [ ! -d "$BUILDDIR" ]; then
            mkdir -p "$BUILDDIR"
        fi
        cd "$BUILDDIR" || fatal "Failed to cd into '$BUILDDIR'"
    fi

    CFLAGS="${CFLAGS[*]}" LIBS="$LIBS" "$SHOME/configure" --disable-dependency-tracking
}

# Test if a define condition currently evaluates to true or false
function test_define() {
    cat << EOF | "$2" -E -I"$T2HOME/utils/" -I"$T2HOME/tranalyzer2/src/" - > /dev/null 2>&1
#include "tranalyzer.h"
#include "networkHeaders.h"
int main () {
    #if $1
    #else
    #error "not defined"
    #endif
    return 0;
}
EOF
}

configure_cargo() {
    cd "$SHOME" || fatal "Failed to cd into '$SHOME'"

    CARGO_FLAGS=()

    if [ -z "$DEBUG" ]; then
        CARGO_FLAGS+=(--release)
    fi

    if [ ! -w "Cargo.toml" ]; then
        fatal "Missing 'Cargo.toml' file"
    fi

    if [ ! -r "$T2HOME/tranalyzer2/src/networkHeaders.h" ]; then
        fatal "Could not find 'networkHeaders.h' file."
    fi

    if [ ! -r "$T2HOME/tranalyzer2/src/tranalyzer.h" ]; then
        fatal "Could not find 'tranalyzer.h' file."
    fi

    # check that feature key for t2plugin exists in Cargo.toml
    command grep -q '^t2plugin *= *{.*features *= *\[.*\] *}$' Cargo.toml || \
            fatal "Feature $f missing in Cargo.toml"

    # check that $CC or gcc or clang is present
    local compiler="$CC"
    if [[ -z "$compiler" ]]; then
        if hash gcc 2> /dev/null; then
            compiler=gcc
        elif hash clang 2> /dev/null; then
            compiler=clang
        else
            fatal "Neither 'gcc' nor 'clang' was found!"
        fi
    elif ! hash "$compiler" 2> /dev/null; then
        fatal "CC program '$CC' not found"
    fi

    local -A features=(
        [ETH_ACTIVATE]="ETH_ACTIVATE > 0"
        [IPV6_ACTIVATE]="IPV6_ACTIVATE == 1"
        [IPV6_DUALMODE]="IPV6_ACTIVATE == 2"
        [SCTP_ACTIVATE]="SCTP_ACTIVATE > 0"
        [SCTP_STREAM]="SCTP_ACTIVATE & 1"
        [SCTP_ASSOC]="SCTP_ACTIVATE & 2"
        [LAPD_ACTIVATE]="LAPD_ACTIVATE == 1"
        [SCTP_STATFINDEX]="SCTP_STATFINDEX == 1"
        [MULTIPKTSUP]="MULTIPKTSUP == 1"
        [T2_PRI_HDRDESC]="T2_PRI_HDRDESC == 1"
        [SUBNET_INIT]="SUBNET_INIT != 0"
        [FLOW_LIFETIME]="(FDURLIMIT > 0 && FDLSFINDEX == 1)"
        [FLOW_AGGREGATION]="((SUBNET_INIT != 0) || (AGGREGATIONFLAG & (SUBNET | SRCIP | DSTIP)))"
    )

    local features1=()
    local features2=()

    for f in "${!features[@]}"; do
        fcond="${features[f]}"
        if test_define "$fcond" "$compiler"; then
            features1+=('"'"$f"'"')
            features2+=("$f")
        fi
    done

    local tmp1="$(join_by , "${features1[@]}")"
    perl -i -pe 's/(^t2plugin *= *\{.*features *= *\[)[^\[\]]*(\] *\}$)/\1'"$tmp1"'\2/' Cargo.toml

    local tmp2="$(join_by ' ' "${features2[@]}")"
    if [ -n "$tmp2" ]; then
        CARGO_FLAGS+=("--features" "$tmp2")
    fi
}

configure_cmake() {
    cd "$SHOME" || fatal "Failed to cd into '$SHOME'"

    if [ ! -d "$BUILDDIR" ]; then
        mkdir -p "$BUILDDIR"
    fi

    local opts=()

    if [ "$CMAKE_GENERATOR" != "Ninja Multi-Config" ]; then
        if [ -n "$DEBUG" ]; then
            opts+=(-DCMAKE_BUILD_TYPE=Debug)
        else
            opts+=(-DCMAKE_BUILD_TYPE=Release)
        fi
    fi

    [ -n "$CMAKE_GENERATOR" ] && opts+=(-G"$CMAKE_GENERATOR")
    [ -n "$IWYU" ] && opts+=(-DCMAKE_C_INCLUDE_WHAT_YOU_USE="$IWYU")

    # cmake -B option only exists since 3.13
    if [ "$(cmake_version_ge "3.13")" ]; then
        cmake "${opts[@]}" -B "$BUILDDIR"
    else
        local _oldpwd="$PWD"
        cd "$BUILDDIR" || fatal "Failed to cd into '$BUILDDIR'"
        cmake "${opts[@]}" ..
        cd "$_oldpwd" || fatal "Failed to cd back into '$_oldpwd'"
    fi
}

configure_meson() {
    cd "$SHOME" || fatal "Failed to cd into '$SHOME'"

    local opts=()
    if [ -n "$DEBUG" ]; then
        opts+=(--buildtype debug)
    elif [ "$GCCOPT" != 2 ]; then
        opts+=(--optimization "$GCCOPT")
    fi

    if [ -n "$LTO" ]; then
        opts+=(-Db_lto=true)
    fi

    if [[ "$(meson --version)" < "0.36.0" ]] && [ ! -d "$BUILDDIR" ]; then
        mkdir -p "$BUILDDIR"
    fi

    if [ -f "$BUILDDIR/build.ninja" ]; then
        meson setup "$BUILDDIR" --reconfigure "${opts[@]}" || meson setup "$BUILDDIR" "${opts[@]}"
    else
        meson setup "$BUILDDIR" "${opts[@]}"
    fi
}

configure() {

    case "$BACKEND" in
        cargo) configure_cargo;;
        cmake) configure_cmake;;
        meson) configure_meson;;
            *) configure_autotools;;
    esac

    if [ $? -ne 0 ]; then
        printerr "\nFailed to configure $PLUGIN$PLUGINNAME"
        if [ -z "$DEPS" ]; then
            echo
        elif ! grep -qF ' ' <<< "$DEPS"; then
            printinf "Missing dependency $DEPS?\n"
        else
            printinf "Missing dependencies $DEPS?\n"
        fi
        exit 1
    fi
}

build_autotools() {
    local _builddir
    if [ -n "$BUILDDIR" ]; then
        _builddir="$BUILDDIR"
    else
        _builddir="."
    fi

    [ -n "$MAKE_CLEAN" ] && $MAKE_CLEAN -C "$_builddir" # XXX this should NOT be necessary

    local opts=(-j "$NCPUS")
    [ -n "$IWYU" ] && opts+=(-k CC="$IWYU")

    make -C "$_builddir" "${opts[@]}"
}

build_cargo() {
    configure_cargo
    cargo build "${CARGO_FLAGS[@]}"
}

build_cmake() {
    if [ "$CMAKE_GENERATOR" = "Ninja Multi-Config" ]; then
        local build_dot_ninja
        if [ "$DEBUG" ]; then
            build_dot_ninja="build-Debug.ninja"
        else
            build_dot_ninja="build-Release.ninja"
        fi
        ninja -C "$BUILDDIR" -f "$build_dot_ninja" -j "$NCPUS"
    else
        # cmake -j option only exists since 3.12
        if [ "$(cmake_version_ge "3.12")" ]; then
            cmake --build "$BUILDDIR" -j "$NCPUS"
        else
            cmake --build "$BUILDDIR"
        fi
    fi
}

build_meson() {
    if ! meson -h | grep -qFw compile; then
        ninja -C "$BUILDDIR" -j "$NCPUS"
    else
        # meson compile only exists since 0.54...
        meson compile -C "$BUILDDIR" -j "$NCPUS"
    fi

    local ret=$?
    if [ "$IWYU" ]; then
        local iwyu_tool="$(which iwyu_tool.py 2> /dev/null)"
        [ -z "$iwyu_tool" ] && iwyu_tool="$(dirname "$IWYU")/iwyu_tool.py"
        if [ ! -x "$iwyu_tool" ]; then
            printerr "iwyu_tool.py not found"
        else
            "$iwyu_tool" -p "$BUILDDIR"
        fi
    fi

    return "$ret"
}

prebuild() {
    cd "$SHOME" || fatal "Failed to cd into '$SHOME'"

    if type t2_prebuild &> /dev/null; then
        if ! t2_prebuild; then
            fatal "\nt2_prebuild failed for $PLUGIN$PLUGINNAME\n"
        fi
    fi
}

build() {
    cd "$SHOME" || fatal "Failed to cd into '$SHOME'"

    case "$BACKEND" in
        cmake) build_cmake;;
        cargo) build_cargo;;
        meson) build_meson;;
            *) build_autotools;;
    esac

    if [ $? -ne 0 ]; then
        fatal "\nFailed to build $PLUGIN$PLUGINNAME\n"
    else
        local pname="$PLUGINNAME"
        [ -z "$PLUGIN" ] && pname="$($SED 's/^./\U&/' <<< "$pname")"
        printok "\n$pname successfully built\n"
    fi
}

build_doc() {
    if ! make -j "$NCPUS" -C "$SHOME/doc"; then
        printerr "\nFailed to build $PLUGIN$PLUGINNAME documentation\n"
        exit 1
    fi

    local pname="$PLUGINNAME"
    [ -z "$PLUGIN" ] && pname="$($SED 's/^./\U&/' <<< "$pname")"
    printok "\n$pname documentation successfully built\n"
}

clean() {
    local _ret=0
    local clean_all="$1"

    cd "$SHOME" || fatal "Failed to cd into '$SHOME'"

    if [ -f "doc/Makefile" ]; then
        make -C doc clean || _ret=1
    fi

    if [ -f "Makefile" ]; then
        make distclean || _ret=1
    fi

    if [ -f "Cargo.toml" ] && hash cargo &> /dev/null; then
        cargo clean || _ret=1
    fi

    local _dirs=()
    [ "$clean_all" = "all" -o "$DEBUG"  = 1 ] && _dirs+=("$BUILDDIR_DEBUG")
    [ "$clean_all" = "all" -o "$DEBUG" != 1 ] && _dirs+=("$BUILDDIR_RELEASE")

    local _builddir
    for _builddir in "${_dirs[@]}"; do
        if [ -d "$_builddir" ]; then
            rm -rf "$_builddir" || _ret=1
        fi
    done

    rm -rf aclocal.m4 autom4te.cache/ build-aux/ compile config.* configure \
           depcomp INSTALL install-sh libtool m4/ Makefile Makefile.in \
           man/Makefile man/Makefile.in missing src/Makefile src/Makefile.in \
           src/deps/ src/.deps/ src/.dirstamp src/.libs stamp-h1 \
    || _ret=1

    rm -f "${PLUGINNAME}${PKGEXT}" || _ret=1

    if type t2_clean &> /dev/null; then
        if ! t2_clean; then
            fatal "\nt2_clean failed for $PLUGIN$PLUGINNAME\n"
        fi
    fi

    if [ $_ret -ne 0 ]; then
        fatal "\nFailed to clean $PLUGIN$PLUGINNAME\n"
    else
        local pname="$PLUGINNAME"
        [ -z "$PLUGIN" ] && pname="$($SED 's/^./\U&/' <<< "$pname")"
        printok "\n$pname successfully cleaned\n"
    fi
}

clean_doc() {
    make -j "$NCPUS" -C "$SHOME/doc" clean
}

install() {
    cd "$SHOME" || fatal "Failed to cd into '$SHOME'"

    if [ ! -d "$PLUGIN_DIR" ]; then
        mkdir -p "$PLUGIN_DIR"
    fi

    if [ -n "$PLUGIN" ]; then
        local parent="$(ps -ocommand= -p $PPID | AWK -F/ '{print $NF}' | AWK '{print $1}')"
        if [ "$parent" != "autogen.sh" ] && [ -f "$PLUGIN_DIR/${PLUGINORDER}_${PLUGINNAME}.so" ] && [ -n "$(pgrep tranalyzer)" ]; then
            printf "\n${ORANGE}Tranalyzer is currently running... Overwrite the $PLUGINNAME plugin anyway (y/N)? $NOCOLOR"
            if [ -z "$YES" ]; then
                read -r ans
            else
                ans="yes"
                echo "$ans"
            fi
            case $ans in
                [yY]|[yY][eE][sS]) ;;
                *) printf "\n"; exit 1
            esac
        fi

        local _plugin_dest="${PLUGINORDER}_${PLUGINNAME}.so"
        local _plugin_soname="lib${PLUGINNAME}.so"  # autotools* backends require -shrext .so on macOS

        local _builddir
        local _plugin_so_type
        if [[ "$BACKEND" != autotools* ]]; then
            _builddir="$BUILDDIR"
            _plugin_so_type="f"
        else
            if [ -n "$BUILDDIR" ]; then
                _builddir="$BUILDDIR/src/.libs"
            else
                _builddir="src/.libs"
            fi
            _plugin_so_type="l"
        fi

        local _plugin_so="$(find_most_recent_file "$_builddir" "$_plugin_soname" "${_plugin_so_type}")"
        if [ ! -f "$_plugin_so" ]; then
            fatal "Failed to find '$_plugin_soname'"
        fi

        if ! cp -L "$_plugin_so" "$PLUGIN_DIR/$_plugin_dest"; then
            fatal "\nFailed to copy plugin $PLUGINNAME into $PLUGIN_DIR\n"
        fi

        printok "\nPlugin $PLUGINNAME copied into $PLUGIN_DIR\n"
    fi

    if type t2_preinst &> /dev/null; then
        if ! t2_preinst; then
            fatal "\nt2_preinst failed for plugin $PLUGINNAME\n"
        fi
        echo
    fi

    if [ ${#EXTRAFILES[@]} -ne 0 ]; then
        for i in "${EXTRAFILES[@]}"; do
            if type t2_inst &> /dev/null; then
                t2_inst "$i"
                ret=$?
                if [ $ret -eq 0 ]; then
                    echo
                    continue
                elif [ $ret -ne 2 ]; then
                    fatal "\nt2_inst failed for file $i\n"
                fi
            fi

            if [[ "$i" =~ \.gz$ ]]; then
                DEST="${i%.gz}"
            elif [[ "$i" =~ \.bz2$ ]]; then
                DEST="${i%.bz2}"
            else
                DEST="$(basename "$i")"
            fi

            if [ -e "$PLUGIN_DIR/$DEST" ] && [ "$FORCE" != 1 ]; then

                if cmp -s "$PLUGIN_DIR/$DEST" "$i" &> /dev/null; then
                    printok "$DEST already exists in $PLUGIN_DIR"
                else
                    [ "$DEST" = "$i" ] && local different="different "
                    printwrn "A ${different}version of $DEST already exists in $PLUGIN_DIR"
                    printinf "Run './autogen.sh -f' to overwrite it"
                fi
            else
                if [[ "$i" =~ \.tar\.gz$ ]]; then
                    tar xzf "$i" -C "$PLUGIN_DIR/$DEST"
                elif [[ "$i" =~ \.gz$ ]]; then
                    gunzip -c "$i" > "$PLUGIN_DIR/$DEST"
                elif [[ "$i" =~ \.tar\.bz2$ ]]; then
                    tar xjf "$i" -C "$PLUGIN_DIR/$DEST"
                elif [[ "$i" =~ \.bz2$ ]]; then
                    bzcat "$i" > "$PLUGIN_DIR/$DEST"
                else
                    cp -r "$i" "$PLUGIN_DIR/$DEST"
                fi

                if [ $? -ne 0 ]; then
                    fatal "\nFailed to copy $DEST into $PLUGIN_DIR\n"
                else
                    printok "$DEST copied into $PLUGIN_DIR"
                fi
            fi
        done
        echo
    fi

    if type t2_postinst &> /dev/null; then
        if ! t2_postinst; then
            fatal "\nt2_postinst failed for $PLUGIN$PLUGINNAME\n"
        fi
    fi
}

unload() {
    if [ ! -d "$PLUGIN_DIR" ]; then
        # Nothing to do
        printwrn "Plugin folder '$PLUGIN_DIR' does no exist"
        return
    fi

    local _file
    local suffix="_${PLUGINNAME}.so"
    find "$PLUGIN_DIR" -type f -name "[0-9][0-9][0-9]$suffix" -delete 2> /dev/null
}

package() {
    cd "$SHOME" || fatal "Failed to cd into '$SHOME'"
    local destf="${PLUGINNAME}${PKGEXT}"
    local format="a"

    if [ "$(uname)" = "Darwin" ]; then
        case "$PKGEXT" in
            *.tar.bz2) format="j";;
            *.tar.gz) format="z";;
            *.tar.xz) format="J";;
            *.tar) format="";;
            *)
                fatal "Unhandled archive format '$PKGEXT'"
                ;;
        esac
    fi

    if type t2_prepackage &> /dev/null; then
        if ! t2_prepackage; then
            fatal "\nt2_prepackage failed for $PLUGIN$PLUGINNAME\n"
        fi
    fi

    local tar_opts
    if [ "$(uname)" = "Darwin" ]; then
        tar_opts=(
            --no-mac-metadata
        )
    else
        tar_opts=(
            --exclude-vcs
            --exclude-vcs-ignore
            --exclude-backups
            --exclude-caches-under
        )
    fi

    local tar_cmd=(
       tar
       "${tar_opts[@]}"
       --exclude=".*.swp"
       --exclude="*.lock"
       -C ..
       -c"${format}"f
       "../$destf"
       "$PLUGINNAME"
    )

    # TODO Move the archive to the directory from which the command was run?
    #[ $? -eq 0 ] && mv "$destf" .
    if ! "${tar_cmd[@]}"; then
        fatal "\nFailed to package $PLUGIN$PLUGINNAME\n"
    fi

    printok "\nPackage '$destf' successfully created\n"
}

update() {
    local pname="$PLUGINNAME"
    [ -z "$PLUGIN" ] && pname="$($SED 's/^./\U&/' <<< "$pname")"

    if ! type t2_update &> /dev/null; then
        printinf "\n$pname: nothing to update\n"
        return 0
    fi

    cd "$SHOME" || fatal "Failed to cd into '$SHOME'"
    if ! t2_update; then
        fatal "\nt2_update failed for $PLUGIN$PLUGINNAME\n"
    fi

    printok "\n$pname successfully updated\n"
}

# ---------------------------------------------------------------------------- #
# ---------------------------- DEFAULT OPTIONS ------------------------------- #
# ---------------------------------------------------------------------------- #

# Default build backend to use (cmake, meson, autotools-out-of-tree, autotools [deprecated])
DEFAULT_BACKEND="meson"

# Fallback build backend to use if DEFAULT_BACKEND could not be found
FALLBACK_BACKEND="autotools-out-of-tree"

# Default BUILDDIR for debug/release (BACKEND != autotools)
BUILDDIR_RELEASE="build"
BUILDDIR_DEBUG="debug"

# With autotools, always run make clean all (unless otherwise specified)
MAKE_CLEAN="make clean"

# Plugin installation directory (-p option)
[ -n "$PLUGIN_DIR" ] || PLUGIN_DIR="$HOME/.tranalyzer/plugins"

# Compiler optimization level [0, g, 1, 2, 3, s] (-O option)
[ -n "$GCCOPT" ] || GCCOPT="2"

# format of the compressed archive (-k option)
[ -n "$PKGEXT" ] || PKGEXT=".tar.gz"

# Folders where to look for header files
INCLUDE_DEFAULT=(
    -I"$T2HOME/utils/"
    -I"$T2HOME/tranalyzer2/src/"
)

if [ "$PLUGINNAME" != "tranalyzer2" ]; then
    INCLUDE_DEFAULT+=(
        -I"$SHOME/src/"
    )
fi

CFLAGS_DEFAULT=(
    "${CFLAGS[@]}"
    -Wall -Wextra -Wundef
    #-Wconversion
    "${INCLUDE_DEFAULT[@]}"
)

if [ -n "$PLUGINORDER" ]; then
    PLUGIN="plugin "  # better error report for Tranalyzer2 plugins
    #CFLAGS_DEFAULT+=(-DPLUGIN_NUMBER="'\"$PLUGINORDER\"'")
fi

if [ "$CC" = "clang" ] || [ "$(uname)" = "Darwin" ]; then
    CFLAGS_DEBUG=("${CFLAGS_DEFAULT[@]}" -O0 -g)
    CFLAGS_PROFILE=("${CFLAGS_DEBUG[@]}" -p)
else
#elif [[ $(gcc -v 2>&1 | grep '^gcc version ' | AWK '{ print $3 }') < 4.8 ]]; then
    CFLAGS_DEBUG=("${CFLAGS_DEFAULT[@]}" -O0 -g3 -ggdb3)
    CFLAGS_PROFILE=("${CFLAGS_DEBUG[@]}" -p -pg)
#else
#   CFLAGS_DEBUG=("${CFLAGS_DEFAULT[@]}" -Og -p -pg -g3 -ggdb3)
fi

# ---------------------------------------------------------------------------- #
# ------------------------------- SCRIPT PART -------------------------------- #
# ---------------------------------------------------------------------------- #

CMDLINE_OPTS="$*"

# Process args
while [ $# -gt 0 ]; do
    case "$1" in
        -c|--clean) CLEAN=1;;
        -d|--debug) DEBUG=1;;
        -P|--profile) PROFILE=1;;
        -f|--force) FORCE=1;;
        -L|--lazy) unset MAKE_CLEAN;;
        -r|--configure) REBUILD=1;;
        -u|--unload) UNLOAD=1;;
        -U|--update) UPDATE=1;;
        -D|--doc) DOC=1;;
        -y|--yes) YES=1;;
        --iwyu)
            IWYU="$(which iwyu 2> /dev/null)"
            if [ -z "$IWYU" ]; then
                fatal "iwyu executable not found in '\$PATH'"
            fi
            ;;
        -B=*|--backend=*)
            BACKEND="${1#*=}"
            validate_backend "$BACKEND"
            ;;
        -B|--backend)
            validate_next_arg "$1" "$2"
            BACKEND="$2"
            validate_backend "$BACKEND"
            shift
            ;;
        -G)
            validate_next_arg "$1" "$2"
            CMAKE_GENERATOR=("$2")
            shift
            if [ -n "$(AWK '/^"/' <<< "$CMAKE_GENERATOR")" ]; then
                while [ -z "$(AWK '/"$/' <<< "${CMAKE_GENERATOR[@]}")" ]; do
                    CMAKE_GENERATOR+=("$2")
                    shift
                done
            fi
            CMAKE_GENERATOR="$(AWK '{ gsub(/^"/, ""); gsub(/"$/, ""); print }' <<< "${CMAKE_GENERATOR[*]}")"
            if [ "$CMAKE_GENERATOR" = "Ninja Multi-Config" ]; then
                printwrn "Support for CMake generator '$CMAKE_GENERATOR' is only partial"
                printinf "All build-<Config>.ninja will be created independently in '$BUILDDIR_RELEASE' and '$BUILDDIR_DEBUG'"
                printinf "but only '$BUILDDIR_DEBUG/build-Debug.ninja' and '$BUILDDIR_RELEASE/build-Release.ninja' will be used.\n"
            fi
            ;;
        -1) NCPUS=1;;
        -i|--install)
            if [ -z "$PLUGIN" ]; then
                INSTALL="$1"
            #else
            #   abort_option_unknown "$1"
            fi
            ;;
        -p|--plugin-dir)
            validate_next_arg "$1" "$2"
            PLUGIN_DIR="$2"
            shift
            ;;
        -O)
            validate_next_arg "$1" "$2"
            case "$2" in
                [0g123s]) ;;
                *)
                    printerr "Invalid argument for option '$1': expected one of [0g123s]; found '$2'"
                    abort_with_help
                    ;;
            esac
            GCCOPT="$2"
            shift
            ;;
        -O0|-Og|-01|-O2|-O3|-Os)
            GCCOPT="${1:2:3}"
            ;;
        --lto)
            LTO=1
            ;;
        -kJ|--package-xz)
            PKGEXT=".tar.xz"
            PACKAGE=1
            ;;
        -kj|--package-bz2)
            PKGEXT=".tar.bz2"
            PACKAGE=1
            ;;
        -kt|--package-tar)
            PKGEXT=".tar"
            PACKAGE=1
            ;;
        -kz|--package-gz)
            PKGEXT=".tar.gz"
            PACKAGE=1
            ;;
        -k|--package)
            PACKAGE=1
            ;;
        --reset)
            printerr "Unknown option '$1'"
            printinf "Did you mean to call 't2conf $CMDLINE_OPTS' instead?"
            exit 1
            ;;
        -\?|-h|--help)
            usage
            exit 0
            ;;
        *)
            abort_option_unknown "$1"
            ;;
    esac
    shift
done

# Make sure the script was run from the plugin root folder
cd "$SHOME" || fatal "Failed to cd into '$SHOME'"

# Backend selection
if [ -n "$BACKEND" ]; then
    set_backend "$BACKEND"          # -B, --backend
elif [ -n "$T2BUILD_BACKEND" ]; then
    set_backend "$T2BUILD_BACKEND"  # T2BUILD_BACKEND environment variable
else
    set_backend                     # default backend
fi

if [ -n "$DOC" ]; then
    if [ -n "$CLEAN" ]; then
        clean_doc
    else
        build_doc
    fi
    exit 0
fi

if [ -n "$CLEAN" ]; then
    clean all
    exit 0
fi

if [ -n "$UNLOAD" ]; then
    unload
    exit 0
fi

if [ -n "$UPDATE" ]; then
    update
    if [ -z "${FORCE}${PACKAGE}${REBUILD}" ]; then
        exit 0
    fi
fi

if [ -n "$PACKAGE" ]; then
    clean all
    package
    exit 0
fi

if [ -z "$NCPUS" ]; then
    NCPUS=$(get_nproc)
fi

if [ -n "$REBUILD" ] || need_rebuild; then
    clean
    prebuild
    configure
else
    prebuild
fi

build
install
