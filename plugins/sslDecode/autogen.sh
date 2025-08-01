#!/usr/bin/env bash

# Plugin name
PLUGINNAME=sslDecode

# Plugin execution order, as 3-digit decimal
PLUGINORDER=315

EXTRAFILES=(
    ja3fingerprint.tsv
    ja4fingerprints.tsv
    ja4sfingerprints.tsv
    sslblacklist.tsv
)

t2_update() {
    ./scripts/cert_blacklist_update -a
    ./scripts/ja3_fingerprints_update -a
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
