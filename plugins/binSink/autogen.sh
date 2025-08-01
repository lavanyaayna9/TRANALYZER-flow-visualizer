#!/usr/bin/env bash

# Plugin name
PLUGINNAME=binSink

# Plugin execution order, as 3-digit decimal
PLUGINORDER=900

BFS_GZ_COMPRESS=$(perl -nle 'print $1 if /^#define\s+BFS_GZ_COMPRESS\s+(\d+).*$/' "$(dirname "$0")/src/binSink.h")

if [ "$BFS_GZ_COMPRESS" -eq 1 ]; then
    # Add necessary libraries here using -l option
    LIBS="-lz"

    # Dependencies (use this to report missing deps)
    DEPS="zlib"
fi

CFLAGS="-DUSE_ZLIB=$BFS_GZ_COMPRESS"

# Source the main autogen.sh
. "$(dirname "$0")/../autogen.sh"
