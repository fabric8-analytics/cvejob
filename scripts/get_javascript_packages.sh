#!/bin/bash

set -e
set -x

npm install -U all-the-package-names

node node_modules/all-the-package-names/cli.js | sed -e 's/^/javascript,/'
