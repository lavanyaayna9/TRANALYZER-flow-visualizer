#!/bin/sh

basedir="$HOME/master-project/stuff/storage/workshop1/dmps"
outdir="$HOME/tranalyzer-output"
cd "`dirname $0`/../../tranalyzer2/src/"

for i in dump0_1.dmp dump1.dmp dump2.dmp dump3.dmp dump4.dmp dump5.dmp; do
    echo "Processing capture $i" >&2
    ./tranalyzer -r "$basedir/$i" -w "$outdir/$i"
done
