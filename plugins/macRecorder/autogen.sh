#!/usr/bin/env bash

# Plugin name
PLUGINNAME=macRecorder

# Plugin execution order, as 3-digit decimal
PLUGINORDER=110

MR_MACLBL=$(perl -nle 'print $1 if /^#define\s+MR_MACLBL\s+(\d+).*$/' "$(dirname "$0")/src/macRecorder.h")

t2_clean() {
    make -C utils distclean
    make -C "$SHOME/utils/" distclean
    rm -f "$SHOME/macEthlbl_HL.txt"  \
          "$SHOME/macEthlbl_HLP.bin" \
          "$SHOME/macEthlbl_HLP.txt"
}

t2_preinst() {
    if [ "$MR_MACLBL" -gt 0 ]; then
        # prepare mac label file
        if [ "$FORCE" = 1 ] || [ ! -f "$PLUGIN_DIR/macEtlbl_HLP.bin" ]; then
            if [ ! -f "$SHOME/macEthlbl_HL.txt" ]; then
                bzip2 -dfk "$SHOME/macEthlbl_HL.txt.bz2" || return 1
            fi
            make -C "$SHOME/utils/"
            "$SHOME/utils/aconv" "$SHOME/macEthlbl_HL.txt"
        fi
    fi
}

t2_update() {
    make -C "$SHOME/utils/"
    #"$SHOME/utils/update-manuf" -a
    "$SHOME/utils/nconv"
}

# Dependencies (to be copied in PLUGIN_DIR)
if [ "$MR_MACLBL" -gt 0 ]; then
    EXTRAFILES=(macEthlbl_HLP.bin)
fi

# Source the main autogen.sh
. "$(dirname "$0")/../autogen.sh"
