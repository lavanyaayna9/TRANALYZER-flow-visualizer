#!/usr/bin/env bash

# Plugin name
PLUGINNAME=telegram

# Plugin execution order, as 3-digit decimal
PLUGINORDER=620

TG_DEOBFUSCATE=$(perl -nle 'print $1 if /^#define\s+TG_DEOBFUSCATE\s+(\d+).*$/' src/telegram.h)

# Add necessary libraries here using -l option
if [ $TG_DEOBFUSCATE  -eq 1 ]; then
    if [ "$(uname)" = "Darwin" ]; then
        CFLAGS="-I/usr/local/opt/openssl/include"
        LIBS="-L/usr/local/opt/openssl/lib"
    else
        LIBS="-lssl -lcrypto"
    fi

    # Dependencies (use this to report missing deps)
    DEPS="libssl"
fi

# Source the main autogen.sh
. "$(dirname "$0")/../autogen.sh"
