#!/usr/bin/env bash

# Plugin name
PLUGINNAME=socketSink

# Plugin execution order, as 3-digit decimal
PLUGINORDER=910

PNAME="$(dirname "$0")"

SKS_GZ_COMPRESS=$(perl -nle 'print $1 if /^#define\s+SKS_GZ_COMPRESS\s+(\d+).*$/' "$PNAME/src/socketSink.h")

if [ "$SKS_GZ_COMPRESS" -eq 1 ]; then
    # Add necessary libraries here using -l option
    LIBS="-lz"

    # Dependencies (use this to report missing deps)
    DEPS="zlib"
fi

CFLAGS="-DUSE_ZLIB=$SKS_GZ_COMPRESS"

# Source the main autogen.sh
. "$(dirname "$0")/../autogen.sh"
