#!/usr/bin/env bash

# Parameters:
# $1 - data feed to download; example: 2012
#      default: recent

set -e
set -x

feed='modified'
[ -n "$1" ] && feed=$1

url="https://static.nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-$feed.json.gz"

curl -sL ${url} | gunzip - > nvdcve.json

echo "Successfully downloaded $feed NVD data feed."
