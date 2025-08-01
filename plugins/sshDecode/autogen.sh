#!/usr/bin/env bash

# Plugin name
PLUGINNAME=sshDecode

# Plugin execution order, as 3-digit decimal
PLUGINORDER=309

HASSH=$(perl -nle 'print $1 if /^#define\s+SSH_HASSH\s+(\d+).*$/' "$(dirname "$0")/src/sshDecode.h")

if [ "$HASSH" -gt 0 ]; then
    EXTRAFILES=(hassh_fingerprints.tsv)
fi

t2_update() {
    "$SHOME/scripts/ssh_hassh_to_tsv" -a
}

# Add necessary libraries here using -l option
if [ "$(uname)" = "Darwin" ]; then
    CFLAGS="-I/usr/local/opt/openssl/include"
    LIBS="-L/usr/local/opt/openssl/lib"
else
    LIBS="-lssl -lcrypto"
fi

# Dependencies (use this to report missing deps)
DEPS="libssl"

# Source the main autogen.sh
. "$(dirname "$0")/../autogen.sh"
