#!/usr/bin/env bash

# Plugin name
PLUGINNAME=pcapd

# Plugin execution order, as 3-digit decimal
PLUGINORDER=960

PD_LBSRCH=$(perl -nle 'print $1 if /^#define\s+PD_LBSRCH\s+(\d+).*$/' "$(dirname "$0")/src/pcapd.h")

if [ "$PD_LBSRCH" -eq 1 ]; then
    t2_prebuild() {
        make -C utils
    }
fi

t2_clean() {
    make -C utils distclean
}

# Source the main autogen.sh
. "$(dirname "$0")/../autogen.sh"
