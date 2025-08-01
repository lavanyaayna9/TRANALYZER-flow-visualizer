#!/usr/bin/env bash

shopt -s expand_aliases
source "$(dirname "$0")/../../scripts/t2_aliases"

PLUGIN_PATH="$(realpath "${1:-${HOME}/.tranalyzer/plugins}")"
printf '%s\n' basicFlow basicStats jsonSink dnsDecode > "${PLUGIN_PATH}/plugins.txt"

CA="$(realpath "$(dirname "$0")/../gitlab-ci/nudel-root-ca.crt")"

TMP="$(mktemp -d)"
cd "$TMP"

wget --ca-certificate="$CA" 'https://www.tranalyzer.com/download/data/dnsgoogle.pcap'
t2 -p "$PLUGIN_PATH" -r dnsgoogle.pcap -w x

# check that all queries are for "www.google.com"
cat x_flows.json | jq '.dnsQname | add' | jq -es 'unique | .[] == "www.google.com"' || exit 1

# check for a few names in answers
for n in google.com www.google.com ns1.google.com ns2.google.com ns3.google.com ns4.google.com; do
	cat x_flows.json | jq 'select(.dir == "B") | .dnsAname | .[]' | jq -es 'sort | unique | index("'"$n"'")' || exit 1
done

# check for a few IPv4 in answers
for ip in 172.217.19.68 216.239.32.10 216.239.34.10 216.239.36.10 216.239.38.10; do
	cat x_flows.json | jq 'select(.dir == "B") | .dns4Aaddress | .[]' | jq -es 'sort | unique | index("'"$ip"'")' || exit 1
done

# check for a few IPv6 in answers
for ip in 2001:4860:4802:32::a 2001:4860:4802:34::a 2001:4860:4802:36::a 2001:4860:4802:38::a 2a00:1450:4005:80b::2004; do
	cat x_flows.json | jq 'select(.dir == "B") | .dns6Aaddress | .[]' | jq -es 'sort | unique | index("'"$ip"'")' || exit 1
done
