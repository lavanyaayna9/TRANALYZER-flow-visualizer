#!/bin/sh

cd "$(dirname "$0")"

[ -f Makefile ] && make clean

rm -rf Makefile Makefile.in aclocal.m4 autom4te.cache/ config.h config.h.in \
    config.cache config.log config.status configure libtool src/.deps/ \
    src/.dirstamp stamp-h1 'config.h.in~' src/deps

rm -rf build
