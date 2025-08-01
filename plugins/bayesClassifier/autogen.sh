#!/usr/bin/env bash

# Plugin name
PLUGINNAME=bayesClassifier

# Plugin execution order, as 3-digit decimal
PLUGINORDER=866

# Dependencies (to be copied in PLUGIN_DIR)
EXTRAFILES=(bayes_config.json)

# Add necessary libraries here using -l option
LIBS="-ljansson"

# Dependencies (use this to report missing deps)
DEPS="libjansson"

# Source the main autogen.sh
. "$(dirname "$0")/../autogen.sh"
