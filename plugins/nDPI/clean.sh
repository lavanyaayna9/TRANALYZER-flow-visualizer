#!/usr/bin/env bash

cd "$(dirname "$0")/src/nDPI/" || exit 1

rm -rf  aclocal.m4                          \
        autom4te.cache/                     \
        compile                             \
        config.*                            \
        configure                           \
        depcomp                             \
        install-sh                          \
        libndpi.pc                          \
        libtool                             \
        ltmain.sh                           \
        m4/libtool.m4                       \
        m4/lt~obsolete.m4                   \
        m4/ltoptions.m4                     \
        m4/ltsugar.m4                       \
        m4/ltversion.m4                     \
        Makefile                            \
        Makefile.in                         \
        missing                             \
        src/lib/Makefile.in \               \
        src/include/ndpi_config.h*          \
        src/include/ndpi_define.h           \
        src/include/stamp-h1                \
        src/lib/.deps/                      \
        src/lib/*.la                        \
        src/lib/.libs/                      \
        src/lib/*.lo                        \
        src/lib/*.o                         \
        src/lib/Makefile                    \
        src/lib/libndpi.so*                 \
        src/lib/protocols/.deps/            \
        src/lib/protocols/.dirstamp         \
        src/lib/protocols/.libs/            \
        src/lib/protocols/*.lo              \
        src/lib/protocols/*.o               \
        src/lib/third_party/src/.deps/      \
        src/lib/third_party/src/.dirstamp   \
        src/lib/third_party/src/.libs/      \
        src/lib/third_party/src/*.lo        \
        src/lib/third_party/src/*.o         \
        src/lib/third_party/src/*/.libs     \
        src/lib/third_party/src/*/*.lo      \
        src/lib/third_party/src/*/*.o       \
        stamp-h1
