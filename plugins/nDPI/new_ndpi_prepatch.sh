#!/usr/bin/env bash

source "$(dirname "$0")/../../scripts/t2utils.sh"

merge_lines() {
    local hdr="$1"
    shift
    ls -1 "$@" | $SED -re "1s/^/${hdr} = /" -re '2,$s/^/    /' -re '$!s/$/ \\/'
}

fatal() {
    printerr "$@"
    exit 1
}

cd "$(dirname "$0")" || fatal "Failed to cd into '$(dirname "$0")"
cd src/nDPI/ || fatal "missing nDPI source directory"

# reduce size
rm -rf doc/ example/ fuzz/ influxdb/ packages/ python/ sonar-project.properties \
       tests/ utils/ windows/ wireshark/ .git/ .github/ .lgtm/ \
       .appveyor.yml .ci-ignore .gitattributes .gitignore .travis.yml || \
    fatal "failed to remove additional files/directories"

# create configure.ac from configure.seed
([ -e autogen.sh ] && [ -e configure.seed -o -e configure.ac ]) || fatal "nDPI autogen.sh and configure.seed or configure.ac not found"
$SED -i '/^autoreconf/,$d' autogen.sh
chmod 755 autogen.sh
./autogen.sh
[ -e configure.ac ] || fatal "failed to generate configure.ac"
rm -f autogen.sh configure.seed

# patch configure.ac
$SED -i "s/^\(\s\+AS_HELP_STRING\)(\[--disable-json-c\],\s\+\[Disable json-c support\])/\1([--enable-json-c], [Enable json-c support])/" configure.ac
$SED -i "s/^\(AS_IF(\[test \"x\$enable_json_c\"\s\+\)!=\s\+\"xno\"\],/\1= \"xyes\"],/" configure.ac
$SED -i "s/^AC_CONFIG_FILES(\[Makefile\s\+.*$/AC_CONFIG_FILES([Makefile libndpi.pc src\/include\/ndpi_define.h src\/lib\/Makefile])/" configure.ac
$SED -i "s/^AC_CONFIG_FILES(\[tests\//#AC_CONFIG_FILES([tests\//" configure.ac

# patch Makefile.am
$SED -i "s/^\(SUBDIRS\s\+=\s\+src\/lib\)\s\+.*$/\1/" Makefile.am

# remove nDPI .gitignore (when using git clone instead of archive)
[ -f .gitignore ] && rm .gitignore

# no need to build the fuzz targets
$SED -i '/^if BUILD_FUZZTARGETS$/,/endif/d' Makefile.am

# create the Makefile.am for nDPI static library
cd src/lib/ || fatal "nDPI library directory not found"
[ -e Makefile.in ] || fatal "missing Makefile.in"
rm Makefile.in

cat << EOF > Makefile.am
noinst_LTLIBRARIES = libndpi.la

CFLAGS += -w          # --silence nDPI warnings
CFLAGS += -fPIC -DPIC # --coverage
libndpi_la_CPPFLAGS = -I\$(top_srcdir)/src/include/  -I\$(top_srcdir)/src/lib/third_party/include/

libndpi_la_includedir = \$(includedir)/libndpi-@VERSION@/libndpi

EOF

merge_lines "libndpi_la_include_HEADERS" ../include/*.h third_party/include/*.h >> Makefile.am
echo >> Makefile.am
merge_lines "libndpi_la_SOURCES" ndpi_content_match.c.inc ./*.c protocols/*.c third_party/src/*.c third_party/src/hll/*.c >> Makefile.am
