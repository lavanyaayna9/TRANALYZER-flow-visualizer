#!/usr/bin/env bash

# Plugin name
PLUGINNAME=sqliteSink

# Plugin execution order, as 3-digit decimal
PLUGINORDER=924

# Dependencies (use this to report missing deps)
DEPS="sqlite"

# Source the main autogen.sh
. "$(dirname "$0")/../autogen.sh"
