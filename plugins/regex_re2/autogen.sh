#!/usr/bin/env bash

# Plugin name
PLUGINNAME=regex_re2

# Plugin execution order, as 3-digit decimal
PLUGINORDER=606

# Dependencies (use this to report missing deps)
DEPS="re2"

# Add necessary libraries here using -l option
CFLAGS="-Wundef"

# Dependencies (to be copied in PLUGIN_INSTALL_DIR)
EXTRAFILES=(re2file.txt)

t2_prebuild() {
    cd "$SHOME/src/cre2"
    [ ! -d build ] && mkdir build
    cd build
    # only regenerate the makefiles if necessary
    if [ ! -f "Makefile" ]; then
        [ "$(uname)" = "Darwin" ] && LIBTOOLIZE="glibtoolize"
        LIBTOOLIZE="$LIBTOOLIZE" ../prepare.sh || exit 1
    fi
    make || exit 1
    cd "$SHOME"
}

# clean RE2 C wrapper
t2_clean() {
    local CRE2DIR="src/cre2"
    ./"$CRE2DIR"/clean.sh
}

# Source the main autogen.sh
. "$(dirname "$0")/../autogen.sh"
