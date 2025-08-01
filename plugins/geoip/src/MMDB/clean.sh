#!/usr/bin/env bash

cd "$(dirname "$0")" || exit 1

if [ -f "Makefile" ]; then
    make distclean
fi

rm -rf  aclocal.m4      \
        autom4te.cache/ \
        compile         \
        config.*        \
        configure       \
        depcomp         \
        install-sh      \
        ltmain.sh       \
        Makefile.in     \
        missing
