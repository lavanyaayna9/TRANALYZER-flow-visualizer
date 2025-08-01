#!/usr/bin/env bash

# Plugin name
PLUGINNAME=findexer

# Plugin execution order, as 3-digit decimal
PLUGINORDER=961

# Also build fextractor
t2_prebuild() {
    make -C fextractor
}

# Also clean fextractor and doc
t2_clean() {
    make -C fextractor clean
    rm -rf scripts/cipaddress/build
}

# Source the main autogen.sh
. "$(dirname "$0")/../autogen.sh"
