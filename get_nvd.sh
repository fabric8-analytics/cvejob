#!/usr/bin/env bash

# Parameters:
# $1 - data feed to download; example: 2012
#      default: recent

set -e
set -x

feed='modified'
[ -n "$1" ] && feed=$1

json_feed="nvdcve-1.0-${feed}.json"
metadata="nvdcve-1.0-${feed}.meta"

feed_dir='nvd-data'

mkdir -p "${feed_dir}"

meta_url="https://static.nvd.nist.gov/feeds/json/cve/1.0/${metadata}"
json_url="https://static.nvd.nist.gov/feeds/json/cve/1.0/${json_feed}.gz"

# metadata
meta_output_file="${feed_dir}/${metadata}"
curl -sL ${meta_url} > "${meta_output_file}"

# json
json_output_file="${feed_dir}/${json_feed}"
curl -sL ${json_url} | gunzip - > "${json_output_file}"

echo "Successfully downloaded $feed NVD data feed."
