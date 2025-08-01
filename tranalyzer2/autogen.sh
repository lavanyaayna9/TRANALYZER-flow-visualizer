#!/usr/bin/env bash

PLUGINNAME="tranalyzer2"

PHOME="$(dirname "$0")"

IPV6_ACTIVATE=$(perl -nle 'print $1 if /^#define\s+IPV6_ACTIVATE\s+(\d+).*$/' "$PHOME/src/networkHeaders.h")
SUBNET_ON=$(perl -nle 'print $1 if /^#define\s+SUBNET_ON\s+(\d+).*/' "$PHOME/src/tranalyzer.h")
AGGRFLAG=$(($(perl -nle 'print $1 if /^#define\s+AGGREGATIONFLAG\s+(0[xX][0-9a-fA-F][0-9a-fA-F]).*/' "$PHOME/src/tranalyzer.h") & 0x80))
T2_HASH_FUNC=$(perl -nle 'print $1 if /^#define\s+T2_HASH_FUNC\s+(\d+).*$/' "$PHOME/src/hashTable.h")
SALRM=$(perl -nle 'print $1 if /^#define\s+SALRM\s+(\d+).*$/' "$PHOME/src/packetCapture.h")
DPDK_MP=$(perl -nle 'print $1 if /^#define\s+DPDK_MP\s+(\d+).*$/' "$PHOME/src/main.h")

if [ $SUBNET_ON -eq 1 ] || [ $AGGRFLAG -eq $((0x80)) ]; then
    BUILD_SUBNET_FILE=1
else
    BUILD_SUBNET_FILE=0
fi

if [ $DPDK_MP -ne 0 ]; then
    CFLAGS="-msse4.2"
    LIBS="$(pkg-config --libs libdpdk)"
    # Dependencies (use this to report missing deps)
    DEPS="dpdk"
fi

t2_clean() {
    make -C ../utils/t2whois distclean
    make -C ../utils/subnet distclean
    make -C ../utils/subnet/tor distclean
    make -C src/hash/t1ha clean &> /dev/null
    rm -f ../utils/subnet/subnets4_HL* ../utils/subnet/subnets6_HL*
}

t2_prepackage() {
    # The Tor address file is not under revision control.
    # Make sure we have the latest version when packaging.
    ../utils/subnet/tor/torldld -a
    make -C ../utils/subnet/tor distclean
    rm -f ../utils/subnet/tor/torsub[46].txt
}

t2_update() {
    ../utils/subnet/tor/torldld -a
}

t2_prebuild() {
    if [ $T2_HASH_FUNC -eq 13 ] || [ $T2_HASH_FUNC -eq 14 ]; then
        make -C "$PHOME/src/hash/t1ha"
        if [ $? -ne 0 ]; then
            printerr "Failed to build libt1ha"
            printinf "Try using a different hash function, e.g., t2conf tranalyzer2 -D T2_HASH_FUNC=10"
            return 1
        fi
    fi
}

t2_preinst() {
    if [ $BUILD_SUBNET_FILE -eq 1 ]; then
        make -C ../utils/subnet distclean
        # prepare the subnet files
        local FILES=()
        [ $IPV6_ACTIVATE -ne 1 ] && FILES+=(../utils/subnet/subnets4.txt)
        [ $IPV6_ACTIVATE -ge 0 ] && FILES+=(../utils/subnet/subnets6.txt)

        for txt in "${FILES[@]}"; do
            local prefix="$(basename "$txt" .txt)"
            local bz2="$txt.bz2"
            if [ "$FORCE" != 1 ] && [ -f "$txt" ] && [ -f "$bz2" ]; then
                bz2_version="$(bzcat "$bz2" | head -1 | awk -F"\t" '{ print $2, $3 }')"
                txt_version="$(AWK -F"\t" 'NR == 1 { print $2, $3; exit }' "$txt")"
                # if "./autogen.sh -f" and subnets[46].txt.bz2 version+rev is different from subnets[46].txt version+rev
                if [ "$bz2_version" != "$txt_version" ]; then
                    printwrn "$txt(.bz2) files version differ"
                    printinf "Run 't2build -f tranalyzer2' to overwrite your '$txt'\n"
                fi
            fi
            if [ ! -f "$PLUGIN_DIR/${prefix}_HLP.bin" ] || [ "$FORCE" = 1 ]; then
                printinf "Converting '$txt' to binary, this may take a minute"
                if [ ! -f "$txt" ] || [ "$FORCE" = 1 ]; then
                    bzip2 -dfk "$bz2" || return 1
                fi
                if [ "$SALRM" = 1 ]; then
                    ../utils/subnet/subconv "$(basename "$txt")" || return 1
                else
                    ../utils/subnet/subconv -t "$(basename "$txt")" || return 1
                fi
            fi
        done
    fi

    if [ ! -f "$(get_t2whois_exec)" ] || [ "$FORCE" = 1 ]; then
        make -C "$T2HOME/utils/t2whois" clean all
        if [ $? -ne 0 ]; then
            printwrn "Failed to build 't2whois'"
            printinf "You may try building it later by typing 'make -C \"$T2HOME/utils/t2whois\"'\n"
        fi
    fi
}

t2_postinst() {
    if [ -n "$INSTALL" ]; then
        ./install.sh -o "$PLUGIN_DIR" tranalyzer
    fi
}

# Dependencies (to be copied in PLUGIN_DIR)
EXTRAFILES=(proto.txt)

if [ $BUILD_SUBNET_FILE -eq 1 ]; then
    # Dependencies (to be copied in PLUGIN_DIR)
    [ $IPV6_ACTIVATE -ne 1 ] && EXTRAFILES+=(../utils/subnet/subnets4_HLP.bin)
    [ $IPV6_ACTIVATE -gt 0 ] && EXTRAFILES+=(../utils/subnet/subnets6_HLP.bin)
fi

# Source the main autogen.sh
. "$(dirname "$0")/../plugins/autogen.sh"
