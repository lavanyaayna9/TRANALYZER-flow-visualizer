#!/bin/sh

basedir="$HOME/master-project/experiments"
cd "`dirname $0`/../../tranalyzer2/src/"

for cc in devcc dnstunnel hans hcovert icmptx iodine itun loki ptunnel; do
    echo "Processing $cc covert channel capture..." >&2
    ./tranalyzer -r $basedir/$cc/${cc}.dmp -w $basedir/$cc/tranalyzer-output/$cc
done
