#!/usr/bin/env bash

# Plugin name
PLUGINNAME=geoip

# Plugin execution order, as 3-digit decimal
PLUGINORDER=116

GEOIP_LIB=$(perl -nle 'print $1 if /^#define\s+GEOIP_LIB\s+(\d+).*$/' "$(dirname "$0")/src/geoip.h")

# Dependencies (to be copied in PLUGIN_DIR)
if [ "$GEOIP_LIB" -eq 0 ]; then
    EXTRAFILES=(GeoLiteCity.dat.gz GeoLiteCityv6.dat.gz)
else
    EXTRAFILES=(GeoLite2-City.mmdb.gz)
fi

if [ "$GEOIP_LIB" -eq 0 ]; then
    if hash pkg-config 2> /dev/null && pkg-config geoip; then
        CFLAGS="$(pkg-config --cflags geoip)"
        LIBS="$(pkg-config --libs geoip)"
    else
        CFLAGS="-lGeoIP"
    fi
    DEPS="GeoIP"
elif [ "$GEOIP_LIB" -eq 1 ]; then
    if hash pkg-config 2> /dev/null && pkg-config libmaxminddb; then
        CFLAGS="$(pkg-config --cflags libmaxminddb)"
        LIBS="$(pkg-config --libs libmaxminddb)"
    else
        CFLAGS="-lmaxminddb"
    fi
    DEPS="MaxMindDB"
fi

t2_clean() {
    "$SHOME/src/MMDB/clean.sh"
    make -C "$SHOME/utils/t2mmdb" distclean
}

if [ "$GEOIP_LIB" -ne 0 ]; then
    t2_preinst() {
        make -C "$SHOME/utils/t2mmdb" clean all
    }
fi

# As of 2020, updating the database requires a valid GeoLite2 account...
#t2_update() {
#    ./scripts/updatedb
#}

#t2_inst() {
#    local SRC="$1"
#    local DEST="${SRC%.gz}"
#    gunzip -c "$SRC" > "$PLUGIN_DIR/$DEST"
#    local RET=$?
#    if [ $RET -eq 0 ]; then
#        printf "\e[0;32m%s extracted into %s\e[0m\n" "$SRC" "$PLUGIN_DIR"
#    fi
#    return $RET
#}

# Source the main autogen.sh
. "$(dirname "$0")/../autogen.sh"
