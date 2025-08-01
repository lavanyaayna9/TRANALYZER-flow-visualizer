#!/usr/bin/env bash

# Plugin name
PLUGINNAME=covertChannels

# Plugin execution order, as 3-digit decimal
PLUGINORDER=600

# Add necessary libraries here using -l option
#CFLAGS="-Wundef -Wcast-align"
CFLAGS="-Wundef"

# Dependencies (to be copied in PLUGIN_DIR)
EXTRAFILES=(cc_dns_whitelist.txt cc_ping_whitelist.txt)

# Source the main autogen.sh
. "$(dirname "$0")/../autogen.sh"
