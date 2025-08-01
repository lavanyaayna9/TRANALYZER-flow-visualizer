#!/usr/bin/env bash
# Plugin name
PLUGINNAME=kafkaSink

# Plugin execution order, as 3-digit decimal
PLUGINORDER=928

# Dependencies (use this to report missing deps)
DEPS="rdkafka"

# Source the main autogen.sh
. "$(dirname "$0")/../autogen.sh"
