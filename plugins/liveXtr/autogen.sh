#!/bin/bash

# Plugin name
PLUGINNAME=liveXtr

# Plugin execution order, as 3-digit decimal
PLUGINORDER=962

# Add extra compiler flags here
CFLAGS="-Wundef"

# Source the main autogen.sh
. "$(dirname "$0")/../autogen.sh"
