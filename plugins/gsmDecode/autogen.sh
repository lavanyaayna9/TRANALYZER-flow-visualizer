#!/usr/bin/env bash

# Plugin name
PLUGINNAME=gsmDecode

# Plugin execution order, as 3-digit decimal
PLUGINORDER=555

EXTRAFILES=(tacdb.csv)

# Add extra compiler flags here
CFLAGS="-Wno-unused-but-set-variable -Wno-unused-const-variable -Wno-unused-variable"

# Add necessary libraries here using -l option
#LIBS="-ltalloc -losmogsm -losmocore"

# Dependencies (use this to report missing deps)
#DEPS="libosmocore"

# Source the main autogen.sh
. "$(dirname "$0")/../autogen.sh"
