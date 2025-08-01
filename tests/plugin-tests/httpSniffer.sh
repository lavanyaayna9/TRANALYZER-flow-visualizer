#!/usr/bin/env bash

shopt -s expand_aliases
source "$(dirname "$0")/../../scripts/t2_aliases"

PLUGIN_PATH="$(realpath "${1:-${HOME}/.tranalyzer/plugins}")"
printf '%s\n' basicFlow basicStats jsonSink httpSniffer > "${PLUGIN_PATH}/plugins.txt"

CA="$(realpath "$(dirname "$0")/../gitlab-ci/nudel-root-ca.crt")"

TMP="$(mktemp -d)"
cd "$TMP"

wget --ca-certificate="$CA" 'https://www.tranalyzer.com/download/data/2015-05-08-traffic-analysis-exercise.pcap'
t2 -p "$PLUGIN_PATH" -r 2015-05-08-traffic-analysis-exercise.pcap -w x

echo "DEBUG: ${TMP}"
# check for a few HTTP Hosts
for h in 62.75.195.236 ip-addr.es comarksecurity.com runlove.us 7oqnsnzwwnm6zb7y.gigapaysun.com; do
	cat x_flows.json | jq 'select(.dir == "A") | .httpHosts | select (. != null) | .[]' | jq -es 'sort | unique | index("'"$h"'")' || exit 1
done

# check for a few URLs
for u in '/wp-content/themes/grizzly/img5.php' '/img/flags/es.png' '/\\?b2566564b3ba1a38e61c83957a7dbcd5' '/picture.php\\?k=11iqmfg&b7f2a'; do
	cat x_flows.json | jq 'select(.dir == "A") | .httpURL | select (. != null) | .[]' | jq -es 'sort | unique | map(select(. | test("'"$u"'"))) | length != 0' || exit 1
done

# check for User Agents
for u in 'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)' 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; .NET CLR 3.5.30729; .NET CLR 3.0.30729; Media Center PC 6.0)'; do
	cat x_flows.json | jq '.httpUsrAg | select(. != null) | add' | jq -se 'sort | unique | index("'"$u"'")' || exit 1
done

# check Cookie value
cat x_flows.json | jq '.httpCookies | select(. != null) | .[]' | jq -se 'unique | .[] == "PHPSESSID=uqq1670l1pkd07vgdnsg98dee5"' || exit 1
