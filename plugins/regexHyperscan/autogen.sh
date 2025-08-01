#!/usr/bin/env bash

# Every autogen.sh MUST define PLUGINNAME and PLUGINORDER. The other variables
# and functions are optional (except for the last line, where the main script
# is invoked.

# ---------------------------------------------------------------------------- #
# ------------------------------- CONFIG PART -------------------------------- #
# ---------------------------------------------------------------------------- #

# Plugin name
PLUGINNAME=regexHyperscan

# Plugin execution order, as 3-digit decimal
PLUGINORDER=604

EXTRAFILES=(hsregexes.txt)

# Add extra compiler flags here
CFLAGS="-Wundef"

# Add necessary libraries here using -l option
LIBS="-lstdc++"

# ---------------------------------------------------------------------------- #
# ------------------------ PLUGIN SPECIFIC FUNCTIONS ------------------------- #
# ---------------------------------------------------------------------------- #

# Every function (but t2_clean) MUST return 0 on success and 1 on failure.
# If no specific actions are required, all the functions can be safely removed.

# This function is called if '-c' option was used
# and can be used, e.g., to clean dependencies
t2_clean() {
    rm -rf src/hyperscan/build
}

# This function is called before building the plugin
# and can be used, e.g., to build dependencies
t2_prebuild() {
    [ -d src/hyperscan/build ] || mkdir -p src/hyperscan/build
    cd src/hyperscan/build
    check_dependency cmake
    cmake -G 'Unix Makefiles' -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DFAT_RUNTIME=FALSE \
        -DCMAKE_BUILD_TYPE=MinSizeRel .. || exit 1
    make -j $(nproc) || exit 1
    cd ../../../
}

# ---------------------------------------------------------------------------- #
# ----------------- INVOKE THE MAIN AUTOGEN (DO NOT REMOVE) ------------------ #
# ---------------------------------------------------------------------------- #

# Source the main autogen.sh
. "$(dirname "$0")/../autogen.sh"
