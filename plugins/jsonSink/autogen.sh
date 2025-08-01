#!/usr/bin/env bash

# Plugin name
PLUGINNAME=jsonSink

# Plugin execution order, as 3-digit decimal
PLUGINORDER=903

JSON_GZ_COMPRESS=$(perl -nle 'print $1 if /^#define\s+JSON_GZ_COMPRESS\s+(\d+).*$/' "$(dirname "$0")/src/jsonSink.h")

if [ "$JSON_GZ_COMPRESS" -eq 1 ]; then
    # Add necessary libraries here using -l option
    LIBS="-lz"

    # Dependencies (use this to report missing deps)
    DEPS="zlib"
fi

CFLAGS="-DUSE_ZLIB=$JSON_GZ_COMPRESS"

# Source the main autogen.sh
. "$(dirname "$0")/../autogen.sh"
