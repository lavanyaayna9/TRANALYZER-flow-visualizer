#!/usr/bin/env bash

# Plugin name
PLUGINNAME=dnsDecode

# Plugin execution order, as 3-digit decimal
PLUGINORDER=251

DNS_MAL_TEST=$(perl -nle 'print $1 if /^#define\s+DNS_MAL_TEST\s+(\d+).*$/' "$(dirname "$0")/src/dnsDecode.h")

t2_update() {
    "$SHOME/utils/prepdl" -a
}

if [ "$DNS_MAL_TEST" -gt 0 ]; then
    t2_preinst() {
        if [ ! -f "$SHOME/maldm.txt" ] || [ "$FORCE" = 1 ]; then
            "$SHOME/utils/prepdl" -c
        fi
    }

    # Dependencies (to be copied in PLUGIN_DIR)
    EXTRAFILES=(maldm.txt)
fi

# Source the main autogen.sh
. "$(dirname "$0")/../autogen.sh"
