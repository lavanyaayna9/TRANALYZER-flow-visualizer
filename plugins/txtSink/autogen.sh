#!/usr/bin/env bash

# Plugin name
PLUGINNAME=txtSink

# Plugin execution order, as 3-digit decimal
PLUGINORDER=901

TFS_GZ_COMPRESS=$(perl -nle 'print $1 if /^#define\s+TFS_GZ_COMPRESS\s+(\d+).*$/' "$(dirname "$0")/src/txtSink.h")

if [ "$TFS_GZ_COMPRESS" -eq 1 ]; then
    # Add necessary libraries here using -l option
    LIBS="-lz"

    # Dependencies (use this to report missing deps)
    DEPS="zlib"
fi

CFLAGS="-DUSE_ZLIB=$TFS_GZ_COMPRESS"

# Source the main autogen.sh
. "$(dirname "$0")/../autogen.sh"
