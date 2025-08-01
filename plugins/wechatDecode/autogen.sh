#!/usr/bin/env bash

# Plugin name
PLUGINNAME=wechatDecode

# Plugin execution order, as 3-digit decimal
PLUGINORDER=311

# Add necessary libraries here using -l option
LIBS="-lz"

# Dependencies (use this to report missing deps)
DEPS="zlib"

# Source the main autogen.sh
. "$(dirname "$0")/../autogen.sh"
