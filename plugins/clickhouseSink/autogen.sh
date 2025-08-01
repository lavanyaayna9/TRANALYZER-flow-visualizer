#!/usr/bin/env bash

# Plugin name
PLUGINNAME=clickhouseSink

# Plugin execution order, as 3-digit decimal
PLUGINORDER=927

# Dependencies (use this to report missing deps)
DEPS="clickhouse-cpp"

# Source the main autogen.sh
. "$(dirname "$0")/../autogen.sh"
