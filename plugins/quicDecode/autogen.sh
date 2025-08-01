#!/usr/bin/env bash

# Plugin name
PLUGINNAME=quicDecode

# Plugin execution order, as 3-digit decimal
PLUGINORDER=313

QUIC_DECODE_TLS=$(perl -nle 'print $1 if /^#define\s+QUIC_DECODE_TLS\s+(\d+).*$/' src/quicDecode.h)

if [ $QUIC_DECODE_TLS -ne 0 ]; then
    if [ "$(uname)" = "Darwin" ]; then
        CFLAGS="-I/usr/local/opt/openssl@1.1/include \
                -I/usr/local/opt/openssl/include"
        LIBS="-L/usr/local/opt/openssl@1.1/lib \
              -L/usr/local/opt/openssl/lib"
    else
        LIBS="-lcrypto"
    fi

    # Dependencies (use this to report missing deps)
    DEPS="libssl"
fi


# Source the main autogen.sh
. "$(dirname "$0")/../autogen.sh"
